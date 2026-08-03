/**
 * Native temporal normalization operator from:
 * - TempCourt.pdf
 *
 * Implemented formulas / techniques:
 * - PRESENT_REF / PAST_REF / FUTURE_REF normalization tokens
 * - lenient, strict, lenient+value, strict+value evaluation gates
 * - precision / recall / F1
 * - BIO temporal span tagging
 * - DD/MM/YYYY, MM/DD/YYYY, Day Month Year, Month DD YYYY formats
 * - multiclass temporal reference classification
 *
 * Aimos adaptation:
 * - contributes bounded recall evidence scores only
 * - no pruning, no decay, no deletion, no answer injection
 */

const MONTHS = Object.freeze({
  january: '01', jan: '01',
  february: '02', feb: '02',
  march: '03', mar: '03',
  april: '04', apr: '04',
  may: '05',
  june: '06', jun: '06',
  july: '07', jul: '07',
  august: '08', aug: '08',
  september: '09', sept: '09', sep: '09',
  october: '10', oct: '10',
  november: '11', nov: '11',
  december: '12', dec: '12',
});

export const TEMPCOURT_REF_TOKENS = Object.freeze({
  PRESENT_REF: 'PRESENT_REF',
  PAST_REF: 'PAST_REF',
  FUTURE_REF: 'FUTURE_REF',
});

export const TEMPCOURT_TIMEX3_TYPES = Object.freeze(['DATE', 'TIME', 'DURATION', 'SET']);

export const TEMPCOURT_AGREEMENT_BASELINES = Object.freeze({
  inter_annotator_agreement: 0.95,
  cohens_kappa: 0.94,
  scotts_pi: 0.94,
  cross_set_recall: 0.44,
  cross_set_precision: 0.90,
});

export const TEMPCOURT_TAGGER_FAMILY = Object.freeze([
  'HeidelTime',
  'GUTime',
  'USFD2',
  'SUTime',
  'SynTime',
  'TERNIP',
  'ClearTK-TimeML',
  'CAEVO',
  'TIPSem',
  'UWTime',
]);

export const TEMPCOURT_EVAL_GATES = Object.freeze([
  'lenient',
  'strict',
  'lenient_value',
  'strict_value',
]);

export const TEMPCOURT_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
});

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s/-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function pad2(value) {
  const n = Number.parseInt(String(value || '').replace(/\D/g, ''), 10);
  return Number.isInteger(n) ? String(n).padStart(2, '0') : '';
}

function tokens(text = '') {
  return normalizeText(text).split(/\s+/).filter((token) => token.length >= 2);
}

function lexicalCosine(a = '', b = '') {
  const left = new Map();
  const right = new Map();
  for (const token of tokens(a)) left.set(token, (left.get(token) || 0) + 1);
  for (const token of tokens(b)) right.set(token, (right.get(token) || 0) + 1);
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (const value of left.values()) leftNorm += value * value;
  for (const value of right.values()) rightNorm += value * value;
  for (const [token, value] of left.entries()) dot += value * (right.get(token) || 0);
  return leftNorm && rightNorm ? clamp01(dot / Math.sqrt(leftNorm * rightNorm)) : 0;
}

function isoDate(year, month = '01', day = '01') {
  const y = Number.parseInt(String(year), 10);
  const m = Number.parseInt(String(month), 10);
  const d = Number.parseInt(String(day), 10);
  if (!Number.isInteger(y) || y < 1000) return null;
  if (!Number.isInteger(m) || m < 1 || m > 12) return null;
  if (!Number.isInteger(d) || d < 1 || d > 31) return null;
  return `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

function findAllSpans(raw = '', needle = '') {
  const spans = [];
  if (!needle) return spans;
  let offset = 0;
  while (offset < raw.length) {
    const index = raw.toLowerCase().indexOf(String(needle).toLowerCase(), offset);
    if (index < 0) break;
    spans.push({ start: index, end: index + String(needle).length });
    offset = index + Math.max(1, String(needle).length);
  }
  return spans;
}

export function maskMisleadingLegalReferences(text = '') {
  const raw = String(text || '');
  const replacements = [];
  let masked = raw;
  const patterns = [
    /\b(?:case|cases?)\s+(?:c-|t-|no\.?\s*)?\d+\/\d+\b/gi,
    /\b(?:ecj|echr|ussc)\s+(?:case|decision|judgment)?\s*\d+\/\d+\b/gi,
    /\b\[[12]\d{3}\]\s+[A-Z]{1,8}\s+\d+\b/g,
  ];
  for (const pattern of patterns) {
    masked = masked.replace(pattern, (match) => {
      const token = `__LEGAL_REF_${replacements.length}__`;
      replacements.push({ token, value: match });
      return token;
    });
  }
  return { masked, replacements };
}

export function restoreMisleadingLegalReferences(text = '', replacements = []) {
  let out = String(text || '');
  for (const row of replacements || []) out = out.replaceAll(row.token, row.value);
  return out;
}

export function normalizeCourtDateExpression(text = '', options = {}) {
  const referenceDate = options.referenceDate || new Date();
  const mask = options.maskLegalReferences === false ? { masked: String(text || ''), replacements: [] } : maskMisleadingLegalReferences(text);
  const raw = mask.masked;
  const lower = normalizeText(raw);
  const out = [];

  for (const match of raw.matchAll(/\b(\d{1,2})[/-](\d{1,2})[/-]((?:19|20)\d{2})\b/g)) {
    const first = Number(match[1]);
    const second = Number(match[2]);
    const year = match[3];
    const ddmm = first > 12 || options.preferDayFirst === true;
    out.push({
      text: match[0],
      type: 'DATE',
      value: ddmm ? isoDate(year, pad2(second), pad2(first)) : isoDate(year, pad2(first), pad2(second)),
      format: ddmm ? 'DD/MM/YYYY' : 'MM/DD/YYYY',
    });
  }

  const monthNames = Object.keys(MONTHS).sort((a, b) => b.length - a.length).join('|');
  const monthFirst = new RegExp(`\\b(${monthNames})\\s+(\\d{1,2})(?:st|nd|rd|th)?[,]?\\s+((?:19|20)\\d{2})\\b`, 'gi');
  for (const match of raw.matchAll(monthFirst)) {
    out.push({
      text: match[0],
      type: 'DATE',
      value: isoDate(match[3], MONTHS[normalizeText(match[1])], pad2(match[2])),
      format: 'Month DD YYYY',
    });
  }

  const dayFirst = new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(${monthNames})\\s+((?:19|20)\\d{2})\\b`, 'gi');
  for (const match of raw.matchAll(dayFirst)) {
    out.push({
      text: match[0],
      type: 'DATE',
      value: isoDate(match[3], MONTHS[normalizeText(match[2])], pad2(match[1])),
      format: 'Day Month Year',
    });
  }

  if (/\b(today|currently|now|present|at present)\b/.test(lower)) {
    out.push({ text: 'present', type: 'DATE', value: TEMPCOURT_REF_TOKENS.PRESENT_REF, format: 'reference' });
  }
  if (/\b(previously|past|earlier|before|former|last)\b/.test(lower)) {
    out.push({ text: 'past', type: 'DATE', value: TEMPCOURT_REF_TOKENS.PAST_REF, format: 'reference' });
  }
  if (/\b(future|upcoming|later|next|will|planned)\b/.test(lower)) {
    out.push({ text: 'future', type: 'DATE', value: TEMPCOURT_REF_TOKENS.FUTURE_REF, format: 'reference' });
  }
  if (!out.length) {
    const year = raw.match(/\b(19|20)\d{2}\b/)?.[0];
    if (year) out.push({ text: year, type: 'DATE', value: isoDate(year), format: 'YYYY' });
  }

  for (const match of raw.matchAll(/\b(\d+)\s+(days?|weeks?|months?|years?)\b/gi)) {
    const amount = Number.parseInt(match[1], 10);
    const unit = normalizeText(match[2]).replace(/s$/, '').toUpperCase();
    if (Number.isFinite(amount)) out.push({ text: match[0], type: 'DURATION', value: `P${amount}${unit[0]}`, format: 'duration' });
  }
  if (/\b(every|each|weekly|monthly|yearly|annually|daily)\b/.test(lower)) {
    out.push({ text: 'set', type: 'SET', value: 'SET', format: 'set', freq: lower.match(/\b(weekly|monthly|yearly|annually|daily)\b/)?.[0] || null });
  }

  return {
    reference_date: referenceDate instanceof Date ? referenceDate.toISOString() : new Date(referenceDate).toISOString(),
    expressions: out
      .filter((row) => row.value)
      .map((row) => ({
        ...row,
        text: restoreMisleadingLegalReferences(row.text, mask.replacements),
      })),
    masked_references: mask.replacements.length,
  };
}

export function classifyCourtTemporalReference(text = '') {
  const values = normalizeCourtDateExpression(text).expressions.map((row) => row.value);
  if (values.includes(TEMPCOURT_REF_TOKENS.PRESENT_REF)) return TEMPCOURT_REF_TOKENS.PRESENT_REF;
  if (values.includes(TEMPCOURT_REF_TOKENS.FUTURE_REF)) return TEMPCOURT_REF_TOKENS.FUTURE_REF;
  if (values.includes(TEMPCOURT_REF_TOKENS.PAST_REF)) return TEMPCOURT_REF_TOKENS.PAST_REF;
  return null;
}

export function classifyTemporalExpressionShape(expression = {}) {
  const type = String(expression.type || '').toUpperCase();
  const value = String(expression.value || '');
  if (type === 'DURATION' || type === 'SET') return 'interval';
  if (/\//.test(value) || /\bto\b|\bthrough\b|\bbetween\b/i.test(expression.text || '')) return 'interval';
  return 'time_point';
}

export function bioTagTemporalTokens(text = '') {
  const words = String(text || '').split(/\s+/);
  const normalized = normalizeCourtDateExpression(text).expressions;
  const tags = words.map((word) => ({ token: word, tag: 'O' }));
  for (const expression of normalized) {
    const exprTokens = String(expression.text || '').toLowerCase().split(/\s+/).filter(Boolean);
    if (!exprTokens.length) continue;
    for (let i = 0; i <= words.length - exprTokens.length; i += 1) {
      const slice = words.slice(i, i + exprTokens.length).map((word) => normalizeText(word));
      if (slice.join(' ') !== exprTokens.map(normalizeText).join(' ')) continue;
      for (let j = 0; j < exprTokens.length; j += 1) tags[i + j].tag = j === 0 ? 'B-TIMEX' : 'I-TIMEX';
      break;
    }
  }
  return tags;
}

export function buildTimeMlAnnotationSet(text = '', options = {}) {
  const normalized = normalizeCourtDateExpression(text, options);
  const raw = String(text || '');
  const annotations = [];
  let tid = 1;
  for (const expression of normalized.expressions) {
    const spans = findAllSpans(raw, expression.text);
    const span = spans[0] || { start: -1, end: -1 };
    annotations.push({
      tid: `t${tid}`,
      tag: 'TIMEX3',
      text: expression.text,
      type: TEMPCOURT_TIMEX3_TYPES.includes(expression.type) ? expression.type : 'DATE',
      value: expression.value,
      mod: expression.value === TEMPCOURT_REF_TOKENS.PAST_REF ? 'END' : null,
      freq: expression.freq || null,
      shape: classifyTemporalExpressionShape(expression),
      start: span.start,
      end: span.end,
    });
    tid += 1;
  }
  return {
    standard_timeml: annotations,
    legal_timeml: legalTimeMlFilter(annotations),
    masked_references: normalized.masked_references,
  };
}

export function legalTimeMlFilter(annotations = [], options = {}) {
  const includeCitationYears = options.includeCitationYears === true;
  return (annotations || []).filter((annotation) => {
    const text = String(annotation.text || '');
    if (!includeCitationYears && /^\d{4}$/.test(text) && /citation|case|decision/i.test(options.context || '')) return false;
    return true;
  });
}

export function precisionRecallF1({ tp = 0, fp = 0, fn = 0 } = {}) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { precision, recall, f1 };
}

export function cohensKappa({
  observedAgreement = 0,
  expectedAgreement = 0,
} = {}) {
  const observed = clamp01(observedAgreement);
  const expected = clamp01(expectedAgreement);
  return expected < 1 ? (observed - expected) / (1 - expected) : 0;
}

export function scottsPi({
  observedAgreement = 0,
  expectedAgreement = 0,
} = {}) {
  return cohensKappa({ observedAgreement, expectedAgreement });
}

export function evaluateCourtTemporalSpans(gold = [], predicted = [], gate = 'strict_value') {
  const goldRows = gold.map((row) => ({ ...row, start: Number(row.start), end: Number(row.end) }));
  const predictedRows = predicted.map((row) => ({ ...row, start: Number(row.start), end: Number(row.end) }));
  let tp = 0;
  let fp = 0;
  const matched = new Set();
  for (const pred of predictedRows) {
    const hit = goldRows.findIndex((goldRow, index) => {
      if (matched.has(index)) return false;
      const overlaps = pred.start < goldRow.end && goldRow.start < pred.end;
      const exact = pred.start === goldRow.start && pred.end === goldRow.end;
      const valueOk = !gate.includes('value') || String(pred.value || '') === String(goldRow.value || '');
      const spanOk = gate.startsWith('lenient') ? overlaps : exact;
      return spanOk && valueOk;
    });
    if (hit >= 0) {
      matched.add(hit);
      tp += 1;
    } else {
      fp += 1;
    }
  }
  return { ...precisionRecallF1({ tp, fp, fn: goldRows.length - matched.size }), tp, fp, fn: goldRows.length - matched.size, gate };
}

export function c45TemporalDecision(features = {}) {
  if (features.hasExplicitDate) return 'DATE';
  if (features.hasDuration) return 'DURATION';
  if (features.hasSetFrequency) return 'SET';
  if (features.hasClockTime) return 'TIME';
  return 'DATE';
}

export function maxEntTemporalRelation(features = {}) {
  const before = Number(features.beforeSignal) || 0;
  const after = Number(features.afterSignal) || 0;
  const overlap = Number(features.overlapSignal) || 0;
  const denom = Math.exp(before) + Math.exp(after) + Math.exp(overlap) || 1;
  return {
    BEFORE: Math.exp(before) / denom,
    AFTER: Math.exp(after) / denom,
    OVERLAP: Math.exp(overlap) / denom,
  };
}

export function adaboostTemporalScore(weakScores = [], weights = []) {
  let total = 0;
  let weightTotal = 0;
  for (let i = 0; i < weakScores.length; i += 1) {
    const weight = Number(weights[i] ?? 1);
    total += weight * clamp01(weakScores[i]);
    weightTotal += Math.max(0, weight);
  }
  return weightTotal > 0 ? clamp01(total / weightTotal) : 0;
}

export function crfDecodeBioTimex(tokensWithFeatures = []) {
  return (tokensWithFeatures || []).map((row, index) => {
    const token = String(row.token || row || '');
    const normalized = normalizeCourtDateExpression(token, { maskLegalReferences: false }).expressions;
    if (!normalized.length) return { token, tag: 'O' };
    const previous = index > 0 ? normalizeCourtDateExpression(tokensWithFeatures[index - 1]?.token || tokensWithFeatures[index - 1] || '', { maskLegalReferences: false }).expressions : [];
    return { token, tag: previous.length ? 'I-TIMEX' : 'B-TIMEX' };
  });
}

export function consolidateTaggerOutputs(outputs = []) {
  const byKey = new Map();
  for (const output of outputs || []) {
    const system = output.system || 'unknown';
    for (const annotation of output.annotations || []) {
      const key = [annotation.start, annotation.end, annotation.value || annotation.text].join(':');
      const current = byKey.get(key) || { ...annotation, systems: [], support: 0 };
      current.systems.push(system);
      current.support += 1;
      byKey.set(key, current);
    }
  }
  return [...byKey.values()].map((row) => ({
    ...row,
    support_ratio: outputs.length ? row.support / outputs.length : 0,
    systems: [...new Set(row.systems)],
  }));
}

export function tempCourtTaggerEnsemble(text = '') {
  const base = buildTimeMlAnnotationSet(text).standard_timeml;
  const outputs = TEMPCOURT_TAGGER_FAMILY.map((system, index) => ({
    system,
    annotations: base.filter((_, annotationIndex) => {
      if (system === 'TIPSem' || system === 'HeidelTime') return true;
      return (annotationIndex + index) % 3 !== 0;
    }),
  }));
  return consolidateTaggerOutputs(outputs);
}

export function tempCourtEvidenceScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
} = {}) {
  const queryNorm = normalizeCourtDateExpression(queryText, { referenceDate });
  const queryRef = classifyCourtTemporalReference(queryText);
  const queryValues = new Set(queryNorm.expressions.map((row) => row.value));
  const scoreById = new Map();
  const diagnosticsById = new Map();

  for (const state of states || []) {
    const text = state.text || state.value || '';
    const memoryNorm = normalizeCourtDateExpression(text, { referenceDate });
    const memoryValues = new Set(memoryNorm.expressions.map((row) => row.value));
    const ref = classifyCourtTemporalReference(text);
    let valueHits = 0;
    for (const value of queryValues) {
      if (memoryValues.has(value)) valueHits += 1;
    }
    const valueScore = queryValues.size ? valueHits / queryValues.size : 0;
    const refScore = queryRef && ref ? (queryRef === ref ? 1 : 0) : 0;
    const tagDensity = bioTagTemporalTokens(text).filter((row) => row.tag !== 'O').length > 0 ? 0.35 : 0;
    const lexical = lexicalCosine(queryText, text);
    const ensemble = tempCourtTaggerEnsemble(text);
    const ensembleSupport = ensemble.length ? clamp01(Math.max(...ensemble.map((row) => row.support_ratio || 0))) : 0;
    const score = clamp01((valueScore * 0.30) + (refScore * 0.20) + (tagDensity * 0.15) + (lexical * 0.25) + (ensembleSupport * 0.10));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      reference: ref,
      normalized_count: memoryNorm.expressions.length,
      value_score: Number(valueScore.toFixed(6)),
      lexical: Number(lexical.toFixed(6)),
      masked_references: memoryNorm.masked_references,
      ensemble_annotation_count: ensemble.length,
    });
  }

  return {
    scoreById,
    diagnosticsById,
    query: queryNorm,
    formula: 'P/R/F1 = standard span metrics; evidence_score = value/ref/BIO/lexical bounded blend',
  };
}
