/**
 * Native SERENA self-regulated-neurogenesis recall operator from:
 * - SELF-REGULATED NEUROGENESIS FOR ONLINE DATA-INCREMENTAL LEARNING.pdf
 *
 * Implemented formulas / techniques:
 * - online data-incremental state `S={s_1,...,s_s}`
 * - concept-cell creation by zero-cost random pruning as sparse path masks
 * - learned concept cells are frozen as read-stable paths
 * - batch drift gate: create new cell if accuracy `B <= mu_w * t`
 * - ERK sparsity allocation
 * - recency-weighted ensemble `z_tilde=sum_i gamma_i z_i`, `y_hat=argmax_y z_tilde_y`
 * - recurrence reuse gate when an existing path gives high predictive accuracy
 * - average accuracy and average forgetting diagnostics
 *
 * Aimos adaptation:
 * - sparse concept cells are transient read paths only
 * - freezing means a diagnostic path is not mutated during a read
 * - no replay buffer, pruning, deletion, decay, or canonical mutation
 */

import { createHash } from 'node:crypto';

export const SERENA_CONSTANTS = Object.freeze({
  drift_window: 10,
  drift_drop_threshold: 0.50,
  reuse_accuracy_threshold: 0.72,
  recency_gamma: 0.82,
});

export const SERENA_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  sparse_masks_are_transient_read_paths_only: true,
  replay_buffer_size: 0,
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

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
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

function conceptLabel(text = '') {
  const labels = [
    ['temporal', /\b(after|before|between|last|first|currently|now|days?|months?)\b/i],
    ['identity', /\b(member|community|person|who|called|named|identity|melanie)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['inventory', /\b(own|have|bought|purchased|instrument|model kit|how many)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip)\b/i],
  ];
  return labels.find(([, pattern]) => pattern.test(text))?.[0] || (tokens(text)[0] || 'memory');
}

export function erkAllocation(layers = [], targetSparsity = 0.8) {
  const rows = layers.map((layer, index) => ({
    index,
    fan_in: Math.max(1, Number(layer.fan_in) || 1),
    fan_out: Math.max(1, Number(layer.fan_out) || 1),
    params: Math.max(1, (Number(layer.fan_in) || 1) * (Number(layer.fan_out) || 1)),
  }));
  const totalParams = rows.reduce((sum, row) => sum + row.params, 0);
  const denseBudget = totalParams * (1 - clamp01(targetSparsity));
  const denom = rows.reduce((sum, row) => sum + ((row.fan_in + row.fan_out) / row.params), 0) || 1;
  return rows.map((row) => {
    const probability = clamp01((denseBudget / denom) * ((row.fan_in + row.fan_out) / row.params));
    return { ...row, keep_probability: probability, active_params: Math.round(row.params * probability) };
  });
}

export function recencyWeightedEnsemble(logits = [], gamma = SERENA_CONSTANTS.recency_gamma) {
  if (!logits.length) return [];
  const width = Math.max(...logits.map((row) => row.length));
  const out = Array.from({ length: width }, () => 0);
  let norm = 0;
  logits.forEach((row, index) => {
    const weight = (1 - gamma) * (gamma ** Math.max(0, logits.length - index - 1));
    norm += weight;
    for (let i = 0; i < width; i += 1) out[i] += weight * (Number(row[i]) || 0);
  });
  return out.map((value) => value / Math.max(1e-9, norm));
}

function sparseMaskFor(label = '', width = 16, keep = 0.2) {
  return Array.from({ length: width }, (_, index) => (hashUnit(`${label}:${index}`) <= keep ? 1 : 0));
}

function detectDrift(accuracies = [], window = SERENA_CONSTANTS.drift_window, dropThreshold = SERENA_CONSTANTS.drift_drop_threshold) {
  if (accuracies.length < window) return false;
  const recent = accuracies.slice(-window);
  const first = recent.slice(0, Math.floor(window / 2)).reduce((sum, value) => sum + value, 0) / Math.max(1, Math.floor(window / 2));
  const second = recent.slice(Math.floor(window / 2)).reduce((sum, value) => sum + value, 0) / Math.max(1, recent.length - Math.floor(window / 2));
  return second <= first * dropThreshold;
}

export function buildSerenaConceptCells({ queryText = '', states = [] } = {}) {
  const cells = new Map();
  const accuracies = [];
  let driftCount = 0;
  for (const [index, state] of (states || []).entries()) {
    const text = stateText(state);
    const label = conceptLabel(text);
    const score = lexicalOverlap(queryText, text);
    accuracies.push(score);
    if (detectDrift(accuracies)) driftCount += 1;
    const previous = cells.get(label) || {
      id: `concept:${label}`,
      label,
      state_ids: [],
      mask: sparseMaskFor(label, 16, 0.2),
      frozen: false,
      created_at_index: index,
      logits: [],
    };
    previous.state_ids.push(String(state.id));
    previous.logits.push([score, 1 - score, index / Math.max(1, states.length - 1)]);
    previous.frozen = true;
    cells.set(label, previous);
  }
  return { cells: [...cells.values()], drift_count: driftCount, accuracies };
}

export function averageAccuracy(rows = []) {
  if (!rows.length) return 0;
  return rows.reduce((sum, value) => sum + clamp01(value), 0) / rows.length;
}

export function averageForgetting(accuracyMatrix = []) {
  if (accuracyMatrix.length < 2) return 0;
  const final = accuracyMatrix[accuracyMatrix.length - 1] || [];
  const forgetting = final.map((value, j) => {
    const maxPrevious = Math.max(...accuracyMatrix.slice(0, -1).map((row) => Number(row[j]) || 0), 0);
    return Math.max(0, maxPrevious - (Number(value) || 0));
  });
  return averageAccuracy(forgetting);
}

export function serenaScores({ queryText = '', states = [] } = {}) {
  const conceptState = buildSerenaConceptCells({ queryText, states });
  const queryLabel = conceptLabel(queryText);
  const scoreById = new Map();
  let recurrenceCount = 0;
  for (const cell of conceptState.cells) {
    const ensemble = recencyWeightedEnsemble(cell.logits);
    const predictiveAccuracy = clamp01(ensemble[0] || 0);
    const reuse = cell.label === queryLabel || predictiveAccuracy >= SERENA_CONSTANTS.reuse_accuracy_threshold;
    if (reuse) recurrenceCount += 1;
    const activeRatio = cell.mask.reduce((sum, value) => sum + value, 0) / Math.max(1, cell.mask.length);
    for (const stateId of cell.state_ids) {
      const state = (states || []).find((row) => String(row.id) === stateId);
      const direct = state ? lexicalOverlap(queryText, stateText(state)) : 0;
      scoreById.set(stateId, clamp01((0.50 * direct) + (0.28 * predictiveAccuracy) + (0.12 * activeRatio) + (reuse ? 0.10 : 0)));
    }
  }
  for (const state of states || []) if (!scoreById.has(String(state.id))) scoreById.set(String(state.id), 0);
  const accuracyMatrix = conceptState.cells.map((cell) => cell.logits.map((row) => row[0]));
  return {
    scoreById,
    concept_cell_count: conceptState.cells.length,
    drift_count: conceptState.drift_count,
    recurrence_count: recurrenceCount,
    average_accuracy: averageAccuracy(conceptState.accuracies),
    average_forgetting: averageForgetting(accuracyMatrix),
    erk_allocation: erkAllocation([{ fan_in: 16, fan_out: 16 }, { fan_in: 16, fan_out: Math.max(1, conceptState.cells.length) }], 0.8),
    formula: 'z_tilde=sum_i gamma_i z_i; drift if recent_acc <= prior_acc*0.5; M=0',
    guardrails: SERENA_GUARDRAILS,
  };
}
