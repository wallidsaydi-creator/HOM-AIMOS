/**
 * Native neuroplasticity stability-control recall operator from:
 * - Neuroplasticity in Artificial Intelligence.pdf
 *
 * Implemented formulas / techniques:
 * - convergence gate `Delta loss = |loss_epoch - loss_epoch-1| < delta`
 * - dropin activation for new data or stalled loss
 * - dropout mask `m(l) ~ Bernoulli(1-p)`
 * - dropout activation `h(l)=m(l) o f(W(l)h(l-1))`
 * - inference scaling `h(l)=f(W(l)h(l-1))*(1-p)`
 * - validation decrease gate and surprise-threshold plasticity gate
 * - LRP-style relevance thresholding as read diagnostics
 *
 * Aimos adaptation:
 * - dropout/pruning are diagnostic masks over transient candidate scores only
 * - no canonical memory is pruned, decayed, deleted, or rewritten
 * - dropin means adding transient explanatory capacity for scoring evidence
 */

import { createHash } from 'node:crypto';

export const NEUROPLASTICITY_CONSTANTS = Object.freeze({
  convergence_delta: 0.04,
  dropout_p: 0.18,
  surprise_threshold: 0.62,
  lrp_threshold: 0.08,
});

export const NEUROPLASTICITY_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  pruning_is_transient_mask_only: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'from', 'have', 'many', 'more', 'most',
  'that', 'their', 'there', 'these', 'this', 'those', 'through', 'what',
  'when', 'where', 'which', 'while', 'with', 'would',
]);

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

function tokens(value = '') {
  return normalizeText(value)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function hashUnit(value = '') {
  const digest = createHash('sha256').update(String(value || '')).digest();
  return digest.readUInt32BE(0) / 0xffffffff;
}

function lexicalOverlap(query = '', text = '') {
  const q = new Set(tokens(query));
  const t = new Set(tokens(text));
  if (!q.size || !t.size) return 0;
  let hits = 0;
  for (const token of q) if (t.has(token)) hits += 1;
  return hits / q.size;
}

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

export function convergenceDelta(currentLoss = 0, previousLoss = 0) {
  return Math.abs((Number(currentLoss) || 0) - (Number(previousLoss) || 0));
}

export function shouldDropin({ currentLoss = 0, previousLoss = 0, hasNewData = false, delta = NEUROPLASTICITY_CONSTANTS.convergence_delta } = {}) {
  const d = convergenceDelta(currentLoss, previousLoss);
  return Boolean(hasNewData) || d < delta;
}

export function bernoulliMask(values = [], keepProbability = 1 - NEUROPLASTICITY_CONSTANTS.dropout_p, seed = 'aimos') {
  const keep = clamp01(keepProbability);
  return values.map((_, index) => (hashUnit(`${seed}:${index}`) <= keep ? 1 : 0));
}

export function dropoutActivation(values = [], mask = [], activation = (x) => Math.max(0, Number(x) || 0)) {
  return values.map((value, index) => (Number(mask[index]) ? activation(value) : 0));
}

export function inferenceScaledActivation(values = [], p = NEUROPLASTICITY_CONSTANTS.dropout_p, activation = (x) => Math.max(0, Number(x) || 0)) {
  const scale = 1 - clamp01(p);
  return values.map((value) => activation(value) * scale);
}

export function lrpRelevantIndices(values = [], threshold = NEUROPLASTICITY_CONSTANTS.lrp_threshold) {
  return values
    .map((value, index) => ({ index, relevance: clamp01(value) }))
    .filter((row) => row.relevance >= threshold)
    .map((row) => row.index);
}

function validationDecreaseGate(values = []) {
  if (values.length < 2) return false;
  const first = values[0];
  const last = values[values.length - 1];
  return last < first;
}

export function neuroplasticityScores({ queryText = '', states = [] } = {}) {
  const base = (states || []).map((state) => lexicalOverlap(queryText, stateText(state)));
  const currentLoss = 1 - (base.reduce((sum, value) => sum + value, 0) / Math.max(1, base.length));
  const previousLoss = 1 - (base.slice(0, Math.max(1, base.length - 1)).reduce((sum, value) => sum + value, 0) / Math.max(1, base.length - 1));
  const dropinGate = shouldDropin({ currentLoss, previousLoss, hasNewData: /\b(new|recent|currently|now|last)\b/i.test(queryText) });
  const mask = bernoulliMask(base, 1 - NEUROPLASTICITY_CONSTANTS.dropout_p, queryText);
  const dropout = dropoutActivation(base, mask);
  const inference = inferenceScaledActivation(base);
  const relevant = new Set(lrpRelevantIndices(base));
  const validationDecreases = validationDecreaseGate(base);
  const scoreById = new Map();

  (states || []).forEach((state, index) => {
    const surprise = 1 - base[index];
    const plasticityBoost = dropinGate || surprise >= NEUROPLASTICITY_CONSTANTS.surprise_threshold ? 0.18 : 0;
    const relevanceBoost = relevant.has(index) ? 0.12 : 0;
    const stability = validationDecreases ? inference[index] : Math.max(inference[index], dropout[index]);
    scoreById.set(String(state.id), clamp01((0.58 * base[index]) + (0.24 * stability) + plasticityBoost + relevanceBoost));
  });

  return {
    scoreById,
    dropin_gate_count: dropinGate ? states.length : 0,
    dropout_mask_count: mask.filter(Boolean).length,
    relevant_index_count: relevant.size,
    plasticity_mode: dropinGate ? 'dropin_read_capacity' : 'stable_inference',
    validation_decrease_gate: validationDecreases,
    formula: 'Delta=|loss_t-loss_t-1|; h=m o f(Wh); inference=f(Wh)*(1-p)',
    guardrails: NEUROPLASTICITY_GUARDRAILS,
  };
}
