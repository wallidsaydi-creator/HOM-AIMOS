/**
 * Native time-aware representation operator from:
 * - Time-Aware Representation.pdf
 *
 * Implemented formulas / techniques:
 * - reading-comprehension cross entropy for answer start/end
 * - cosine distance between question representation vq and context representation vc
 * - contrastive objective with positive / negative labels
 * - TA = (|BC| + |TC|) / #questions
 * - CA = (|BC| + |CC|) / #questions
 * - TC-score = 2 * TA * CA / (TA + CA)
 * - L_total = L_RC + lambda_T * L_TCSE + lambda_C * L_Contrast
 * - max-logit context split selection
 *
 * Aimos adaptation:
 * - contributes bounded time/context representation scores in native recall
 * - no pruning, no decay, no deletion, no answer injection
 */

export const TIME_AWARE_REPRESENTATION_GUARDRAILS = Object.freeze({
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
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function vectorizeText(value = '', dims = 64) {
  const vector = Array.from({ length: dims }, () => 0);
  const text = normalizeText(value);
  for (const token of text.split(/\s+/).filter(Boolean)) {
    let hash = 2166136261;
    for (let i = 0; i < token.length; i += 1) {
      hash ^= token.charCodeAt(i);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    const index = hash % dims;
    vector[index] += 1;
  }
  return vector;
}

function dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let out = 0;
  for (let i = 0; i < n; i += 1) out += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return out;
}

function norm(vector = []) {
  return Math.sqrt(dot(vector, vector));
}

export function cosineSimilarity(left = [], right = []) {
  const denom = norm(left) * norm(right);
  return denom > 0 ? clamp01(dot(left, right) / denom) : 0;
}

export function cosineDistanceFromText(question = '', context = '') {
  return clamp01(1 - cosineSimilarity(vectorizeText(question), vectorizeText(context)));
}

function negativeLog(probability) {
  return -Math.log(Math.max(1e-12, Number(probability) || 0));
}

export function readingComprehensionLoss({
  startGold = 0,
  endGold = 0,
  startProbs = [],
  endProbs = [],
} = {}) {
  return negativeLog(startProbs[startGold]) + negativeLog(endProbs[endGold]);
}

export function contrastiveLoss(pairs = [], { wp = 1, wn = 1 } = {}) {
  let total = 0;
  for (const pair of pairs || []) {
    const y = Number(pair.y ?? pair.label ?? 0) ? 1 : 0;
    const distance = clamp01(pair.distance ?? pair.s ?? 0);
    total += (wp * y * Math.exp(distance)) + (wn * (1 - y) * Math.exp(1 - distance));
  }
  return total;
}

export function timeAccuracy({ BC = 0, TC = 0, total = 1 } = {}) {
  return total > 0 ? clamp01((Number(BC) + Number(TC)) / total) : 0;
}

export function contextAccuracy({ BC = 0, CC = 0, total = 1 } = {}) {
  return total > 0 ? clamp01((Number(BC) + Number(CC)) / total) : 0;
}

export function tcScore(ta = 0, ca = 0) {
  const t = clamp01(ta);
  const c = clamp01(ca);
  return t + c > 0 ? clamp01((2 * t * c) / (t + c)) : 0;
}

export function totalTimeAwareLoss({
  lrc = 0,
  ltcse = 0,
  lcontrast = 0,
  lambdaT = 1,
  lambdaC = 1,
} = {}) {
  return (Number(lrc) || 0) + ((Number(lambdaT) || 0) * (Number(ltcse) || 0)) + ((Number(lambdaC) || 0) * (Number(lcontrast) || 0));
}

export function selectMaxLogitContext(splits = []) {
  let best = null;
  for (const split of splits || []) {
    const maxStart = Math.max(...(split.startLogits || split.start_logits || [0]).map((x) => Number(x) || 0));
    const maxEnd = Math.max(...(split.endLogits || split.end_logits || [0]).map((x) => Number(x) || 0));
    const score = maxStart + maxEnd;
    if (!best || score > best.score) best = { ...split, score };
  }
  return best;
}

function temporalLexicalScore(queryText = '', contextText = '') {
  const temporalTerms = ['today', 'now', 'current', 'currently', 'recent', 'recently', 'last', 'next', 'before', 'after', 'during', 'while', 'when', 'march', 'april', 'year', 'month', 'week', 'day'];
  const q = normalizeText(queryText);
  const c = normalizeText(contextText);
  const queryHits = temporalTerms.filter((term) => q.includes(term));
  if (!queryHits.length) return temporalTerms.some((term) => c.includes(term)) ? 0.2 : 0;
  const hits = queryHits.filter((term) => c.includes(term)).length;
  return clamp01(hits / queryHits.length);
}

export function timeAwareRepresentationScores({
  queryText = '',
  contexts = [],
} = {}) {
  const scoreById = new Map();
  const diagnosticsById = new Map();
  const queryVector = vectorizeText(queryText);

  for (const context of contexts || []) {
    const id = String(context.id);
    const text = context.text || context.value || '';
    const contextVector = vectorizeText(text);
    const semantic = cosineSimilarity(queryVector, contextVector);
    const distance = clamp01(1 - semantic);
    const temporal = temporalLexicalScore(queryText, text);
    const ta = timeAccuracy({ BC: temporal > 0.45 ? 1 : 0, TC: temporal > 0 ? 1 : 0, total: 2 });
    const ca = contextAccuracy({ BC: semantic > 0.45 ? 1 : 0, CC: semantic > 0 ? 1 : 0, total: 2 });
    const score = clamp01((semantic * 0.50) + (tcScore(ta, ca) * 0.30) + ((1 - distance) * 0.20));
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      semantic: Number(semantic.toFixed(6)),
      cosine_distance: Number(distance.toFixed(6)),
      temporal_accuracy: Number(ta.toFixed(6)),
      context_accuracy: Number(ca.toFixed(6)),
      tc_score: Number(tcScore(ta, ca).toFixed(6)),
    });
  }

  return {
    scoreById,
    diagnosticsById,
    formula: 'L_total = L_RC + lambda_T * L_TCSE + lambda_C * L_Contrast; TC-score = harmonic mean of TA and CA',
  };
}
