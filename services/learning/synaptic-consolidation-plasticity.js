/**
 * Native synaptic consolidation and intelligent plasticity recall operator from:
 * - Theories of synaptic memory consolidation and intelligent plasticity for continual learning.pdf
 *
 * Implemented formulas / techniques:
 * - Hopfield connectivity `W_ij=(1/n) sum_mu xi_i^mu xi_j^mu`
 * - asynchronous sign update `s_i <- sign(sum_j W_ij s_j)`
 * - Hopfield energy `E=-1/2 sum_ij W_ij s_i s_j`
 * - finite capacity `alpha=p_max/n`, with approximate `alpha≈0.138`
 * - internal synaptic state over multiple timescales
 * - EWC surrogate `L_tilde=L_2+(lambda/2)sum_i Omega_i(theta_i-theta_i*)^2`
 * - SI path integral `omega_k=int g_k(theta(t))*theta'_k(t) dt`
 * - gradient simplification with `theta'=-eta*g`
 * - importance `Omega_k=omega_k/(Delta_k^2+epsilon)`
 * - sign-projected hidden weights `w_b=sign(w_h)`
 * - magnitude-dependent metaplastic attenuation
 *
 * Aimos adaptation:
 * - consolidation is a transient read-stability score over recall candidates
 * - power-law/exponential forgetting formulas are diagnostics only
 * - no pruning, decay, deletion, or canonical memory mutation
 */

export const SYNAPTIC_CONSOLIDATION_CONSTANTS = Object.freeze({
  hopfield_capacity_alpha: 0.138,
  ewc_lambda: 0.4,
  si_epsilon: 1e-3,
  eta: 0.05,
});

export const SYNAPTIC_CONSOLIDATION_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  forgetting_curves_are_diagnostics_only: true,
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

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function lexicalOverlap(query = '', text = '') {
  const q = new Set(tokens(query));
  const t = new Set(tokens(text));
  if (!q.size || !t.size) return 0;
  let hits = 0;
  for (const token of q) if (t.has(token)) hits += 1;
  return hits / q.size;
}

function sign(value = 0) {
  return (Number(value) || 0) >= 0 ? 1 : -1;
}

function vectorize(text = '', vocabulary = []) {
  const set = new Set(tokens(text));
  return vocabulary.map((token) => (set.has(token) ? 1 : -1));
}

export function hopfieldConnectivityMatrix(patterns = []) {
  const n = Math.max(1, patterns[0]?.length || 1);
  const matrix = Array.from({ length: n }, () => Array.from({ length: n }, () => 0));
  for (const pattern of patterns) {
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        if (i === j) continue;
        matrix[i][j] += ((Number(pattern[i]) || -1) * (Number(pattern[j]) || -1)) / n;
      }
    }
  }
  return matrix;
}

export function hopfieldAsyncUpdate(state = [], weights = hopfieldConnectivityMatrix([state]), index = 0) {
  const i = Math.max(0, Math.min(state.length - 1, Number(index) || 0));
  const drive = (weights[i] || []).reduce((sum, w, j) => sum + ((Number(w) || 0) * (Number(state[j]) || -1)), 0);
  const next = [...state];
  next[i] = sign(drive);
  return next;
}

export function hopfieldEnergy(state = [], weights = hopfieldConnectivityMatrix([state])) {
  let sum = 0;
  for (let i = 0; i < state.length; i += 1) {
    for (let j = 0; j < state.length; j += 1) {
      sum += (Number(weights[i]?.[j]) || 0) * (Number(state[i]) || -1) * (Number(state[j]) || -1);
    }
  }
  return -0.5 * sum;
}

export function hopfieldCapacity(patternCount = 0, neuronCount = 1) {
  return (Number(patternCount) || 0) / Math.max(1, Number(neuronCount) || 1);
}

export function ewcSurrogateLoss({
  taskLoss = 0,
  lambda = SYNAPTIC_CONSOLIDATION_CONSTANTS.ewc_lambda,
  omega = [],
  theta = [],
  thetaStar = [],
} = {}) {
  const penalty = omega.reduce((sum, value, index) => {
    const d = (Number(theta[index]) || 0) - (Number(thetaStar[index]) || 0);
    return sum + ((Number(value) || 0) * d * d);
  }, 0);
  return (Number(taskLoss) || 0) + ((lambda / 2) * penalty);
}

export function synapticImportance({ gradients = [], updates = [], epsilon = SYNAPTIC_CONSOLIDATION_CONSTANTS.si_epsilon } = {}) {
  return gradients.map((gradient, index) => {
    const update = Number(updates[index]) || 0;
    const omega = (Number(gradient) || 0) * update;
    return Math.abs(omega) / ((update * update) + epsilon);
  });
}

export function signProjectedWeight(hiddenWeight = 0) {
  return sign(hiddenWeight);
}

export function metaplasticAttenuation(hiddenWeight = 0) {
  return 1 / (1 + Math.abs(Number(hiddenWeight) || 0));
}

export function synapticConsolidationScores({ queryText = '', states = [] } = {}) {
  const vocabulary = unique([...(tokens(queryText)), ...(states || []).flatMap((state) => tokens(stateText(state)))]).slice(0, 32);
  const patterns = (states || []).map((state) => vectorize(stateText(state), vocabulary));
  const queryPattern = vectorize(queryText, vocabulary);
  const weights = hopfieldConnectivityMatrix(patterns.length ? patterns : [queryPattern]);
  const capacity = hopfieldCapacity(patterns.length, Math.max(1, vocabulary.length));
  const capacitySafety = capacity <= SYNAPTIC_CONSOLIDATION_CONSTANTS.hopfield_capacity_alpha ? 1 : clamp01(SYNAPTIC_CONSOLIDATION_CONSTANTS.hopfield_capacity_alpha / Math.max(1e-9, capacity));
  const queryEnergy = hopfieldEnergy(queryPattern, weights);
  const scoreById = new Map();
  const omega = synapticImportance({
    gradients: patterns.map((pattern) => lexicalOverlap(queryText, pattern.join(' '))),
    updates: patterns.map((pattern) => pattern.reduce((sum, value, index) => sum + (value === queryPattern[index] ? 1 : -1), 0) / Math.max(1, pattern.length)),
  });
  for (const [index, state] of (states || []).entries()) {
    const pattern = patterns[index] || queryPattern;
    const energy = hopfieldEnergy(pattern, weights);
    const attraction = clamp01(1 / (1 + Math.abs(energy - queryEnergy)));
    const importance = clamp01(omega[index] || 0);
    const hidden = lexicalOverlap(queryText, stateText(state)) * 2 - 1;
    const attenuation = metaplasticAttenuation(hidden);
    const surrogate = ewcSurrogateLoss({ taskLoss: 1 - attraction, omega: [importance], theta: [hidden], thetaStar: [signProjectedWeight(hidden)] });
    scoreById.set(String(state.id), clamp01((0.42 * attraction) + (0.22 * capacitySafety) + (0.20 * importance) + (0.16 * (1 / (1 + surrogate + attenuation)))));
  }
  return {
    scoreById,
    vocabulary_size: vocabulary.length,
    pattern_count: patterns.length,
    capacity_alpha: capacity,
    capacity_safe: capacity <= SYNAPTIC_CONSOLIDATION_CONSTANTS.hopfield_capacity_alpha,
    query_energy: queryEnergy,
    formula: 'W_ij=(1/n)sum_mu xi_i^mu xi_j^mu; E=-1/2 sum_ij W_ij s_i s_j; L~=L+(lambda/2)sum Omega_i(theta_i-theta_i*)^2',
    guardrails: SYNAPTIC_CONSOLIDATION_GUARDRAILS,
  };
}
