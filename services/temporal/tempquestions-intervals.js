/**
 * Native temporal question interval operator from:
 * - TempQuestions.pdf
 *
 * Implemented formulas / techniques:
 * - Allen interval relation inventory
 * - coarse temporal relation mapping: BEFORE / AFTER / OVERLAP
 * - temporal question detection by temporal expression, signal, and answer type
 * - temporal signal-to-relation rules for before/after/during/while/when/until
 * - precision / recall / F-score
 *
 * Aimos adaptation:
 * - contributes bounded interval/signal recall scores only
 * - no pruning, no decay, no deletion, no answer injection
 */

export const ALLEN_RELATIONS = Object.freeze([
  'BEFORE',
  'MEETS',
  'OVERLAPS',
  'STARTS',
  'DURING',
  'FINISHES',
  'EQUALS',
  'FINISHED_BY',
  'CONTAINS',
  'STARTED_BY',
  'OVERLAPPED_BY',
  'MET_BY',
  'AFTER',
]);

export const TEMPQUESTIONS_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
});

const MONTH_RE = /\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\b/i;
const YEAR_RE = /\b(?:19|20)\d{2}\b/;
const RELATIVE_TIME_RE = /\b(today|now|currently|recently|last|next|previous|earlier|later|before|after|during|while|when|until|since|between|ago|weekend|week|month|year)\b/i;
const TEMPORAL_ANSWER_RE = /\b(when|what date|which day|how long|how many days|how many weeks|how many months|how many years|before or after|first|last|latest|earliest)\b/i;

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenSet(value = '') {
  const stop = new Set(['a', 'an', 'and', 'are', 'did', 'do', 'for', 'i', 'in', 'is', 'it', 'me', 'my', 'of', 'on', 'or', 'the', 'to', 'was', 'were', 'with']);
  return new Set(normalizeText(value).split(/\s+/).filter((token) => token.length >= 2 && !stop.has(token)));
}

function lexicalJaccard(a = '', b = '') {
  const left = tokenSet(a);
  const right = tokenSet(b);
  if (!left.size || !right.size) return 0;
  let hit = 0;
  for (const token of left) if (right.has(token)) hit += 1;
  return clamp01(hit / (left.size + right.size - hit));
}

export function coarsenAllenRelation(relation = '') {
  const rel = String(relation || '').toUpperCase().replace(/[^A-Z_]+/g, '_');
  if (['BEFORE', 'MEETS'].includes(rel)) return 'BEFORE';
  if (['AFTER', 'MET_BY'].includes(rel)) return 'AFTER';
  if (rel.includes('BEFORE')) return 'BEFORE';
  if (rel.includes('AFTER')) return 'AFTER';
  return 'OVERLAP';
}

export function detectTemporalQuestion(text = '') {
  const raw = String(text || '');
  const features = {
    has_temporal_expression: MONTH_RE.test(raw) || YEAR_RE.test(raw) || RELATIVE_TIME_RE.test(raw),
    has_temporal_signal: /\b(before|after|during|while|when|until|since|between|first|last|latest|earliest)\b/i.test(raw),
    expects_temporal_answer: TEMPORAL_ANSWER_RE.test(raw),
  };
  return {
    temporal: features.has_temporal_expression || features.has_temporal_signal || features.expects_temporal_answer,
    features,
  };
}

export function temporalSignalRelation(text = '') {
  const lower = normalizeText(text);
  const rows = [];
  if (/\b(before|prior to|earlier than|until)\b/.test(lower)) rows.push({ signal: 'before', relation: 'BEFORE' });
  if (/\b(after|following|later than|since)\b/.test(lower)) rows.push({ signal: 'after', relation: 'AFTER' });
  if (/\b(during|while|when|between|same time|at the time)\b/.test(lower)) rows.push({ signal: 'overlap', relation: 'OVERLAP' });
  if (/\b(first|earliest)\b/.test(lower)) rows.push({ signal: 'order_earliest', relation: 'BEFORE' });
  if (/\b(last|latest|most recent|currently|now)\b/.test(lower)) rows.push({ signal: 'order_latest', relation: 'AFTER' });
  return rows;
}

export function allenIntervalRelation(left = {}, right = {}) {
  const aStart = Number(left.start);
  const aEnd = Number(left.end);
  const bStart = Number(right.start);
  const bEnd = Number(right.end);
  if (![aStart, aEnd, bStart, bEnd].every(Number.isFinite)) return 'OVERLAPS';
  if (aEnd < bStart) return 'BEFORE';
  if (aEnd === bStart) return 'MEETS';
  if (aStart > bEnd) return 'AFTER';
  if (aStart === bStart && aEnd === bEnd) return 'EQUALS';
  if (aStart === bStart && aEnd < bEnd) return 'STARTS';
  if (aStart > bStart && aEnd === bEnd) return 'FINISHES';
  if (aStart > bStart && aEnd < bEnd) return 'DURING';
  if (aStart < bStart && aEnd > bEnd) return 'CONTAINS';
  if (aStart < bStart && aEnd < bEnd) return 'OVERLAPS';
  if (aStart > bStart && aEnd > bEnd) return 'OVERLAPPED_BY';
  return 'OVERLAPS';
}

export function tempQuestionsPrecisionRecall({ tp = 0, fp = 0, fn = 0 } = {}) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fscore = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { precision, recall, fscore, tp, fp, fn };
}

export function tempQuestionsEvidenceScores({
  queryText = '',
  states = [],
} = {}) {
  const queryDetection = detectTemporalQuestion(queryText);
  const querySignals = temporalSignalRelation(queryText);
  const queryRelations = new Set(querySignals.map((row) => row.relation));
  const scoreById = new Map();
  const diagnosticsById = new Map();

  for (const state of states || []) {
    const text = state.text || state.value || '';
    const detection = detectTemporalQuestion(text);
    const signals = temporalSignalRelation(text);
    const relations = new Set(signals.map((row) => row.relation));
    let relationHits = 0;
    for (const relation of queryRelations) {
      if (relations.has(relation)) relationHits += 1;
    }
    const relationScore = queryRelations.size ? relationHits / queryRelations.size : (relations.size ? 0.2 : 0);
    const temporalQuestionScore = queryDetection.temporal && detection.temporal ? 1 : 0;
    const lexicalScore = lexicalJaccard(queryText, text);
    const score = clamp01((relationScore * 0.44) + (temporalQuestionScore * 0.26) + (lexicalScore * 0.30));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      detection,
      signals,
      coarse_relations: [...relations],
      allen_to_coarse: [...relations].map((relation) => coarsenAllenRelation(relation)),
    });
  }

  return {
    scoreById,
    diagnosticsById,
    query_detection: queryDetection,
    query_signals: querySignals,
    formula: 'Allen interval relations are coarsened to BEFORE/AFTER/OVERLAP before temporal question recall scoring',
  };
}
