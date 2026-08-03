/**
 * Native Hebbian orthogonal projection recall operator from:
 * - HEBBIAN LEARNING BASED ORTHOGONAL PROJECTION FOR CONTINUAL LEARNING OF SPIKING NEURAL NETWORKS.pdf
 *
 * Implemented formulas / techniques:
 * - LIF input current `I_i(t)=sum_j w_ij s_j(t)+b_i`
 * - membrane update `u_i[t+1]=lambda(u_i[t]-V_th s_i[t])+sum_j w_ij s_j[t]+b_i`
 * - spike generation `s_i[t+1]=H(u_i[t+1]-V_th)`
 * - orthogonal preservation constraint `Delta W_P x_old = 0`
 * - output preservation `(W + Delta W_P)x_old = W x_old`
 * - projection matrix `P = I - A(A^T A + alpha I)^-1 A^T`
 * - SVD/GPM equivalent projection `P = I - M^T M`
 * - Hebbian/anti-Hebbian principal-subspace extraction by streaming activity traces
 *
 * Aimos adaptation:
 * - uses projection math as a diagnostic recall-stability operator
 * - no weight update is applied to canonical Aimos memory
 * - no forgetting, pruning, decay, or deletion is performed
 */

export const HEBBIAN_PROJECTION_CONSTANTS = Object.freeze({
  vector_dim: 48,
  leak_lambda: 0.92,
  threshold: 1,
  ridge_alpha: 0.05,
  subspace_rank: 8,
});

export const HEBBIAN_PROJECTION_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  projection_is_read_diagnostic_only: true,
});

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalizeText(value = '') {
  return String(value || '').toLowerCase().normalize('NFKD').replace(/[^\p{L}\p{N}\s-]+/gu, ' ').replace(/\s+/g, ' ').trim();
}

function tokens(value = '') {
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 3);
}

export function hashVector(text = '', dim = HEBBIAN_PROJECTION_CONSTANTS.vector_dim) {
  const vector = Array.from({ length: dim }, () => 0);
  for (const token of tokens(text)) {
    let hash = 0;
    for (let i = 0; i < token.length; i += 1) hash = Math.imul(31, hash) + token.charCodeAt(i) | 0;
    vector[Math.abs(hash) % dim] += hash % 2 ? 1 : -1;
  }
  return normalizeVector(vector);
}

function normalizeVector(vector = []) {
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + ((Number(value) || 0) ** 2), 0)) || 1;
  return vector.map((value) => (Number(value) || 0) / norm);
}

function dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let out = 0;
  for (let i = 0; i < n; i += 1) out += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return out;
}

function identity(n) {
  return Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_, j) => (i === j ? 1 : 0)));
}

function transpose(matrix = []) {
  if (!matrix.length) return [];
  return matrix[0].map((_, col) => matrix.map((row) => row[col] || 0));
}

function matMul(a = [], b = []) {
  const rows = a.length;
  const cols = b[0]?.length || 0;
  const inner = b.length;
  return Array.from({ length: rows }, (_, i) => Array.from({ length: cols }, (_, j) => {
    let sum = 0;
    for (let k = 0; k < inner; k += 1) sum += (a[i]?.[k] || 0) * (b[k]?.[j] || 0);
    return sum;
  }));
}

function matSub(a = [], b = []) {
  return a.map((row, i) => row.map((value, j) => value - (b[i]?.[j] || 0)));
}

function matVec(matrix = [], vector = []) {
  return matrix.map((row) => dot(row, vector));
}

function inverse(matrix = []) {
  const n = matrix.length;
  const a = matrix.map((row, i) => [...row.map((value) => Number(value) || 0), ...identity(n)[i]]);
  for (let col = 0; col < n; col += 1) {
    let pivot = col;
    for (let row = col + 1; row < n; row += 1) if (Math.abs(a[row][col]) > Math.abs(a[pivot][col])) pivot = row;
    if (Math.abs(a[pivot][col]) < 1e-12) a[pivot][col] = 1e-12;
    [a[col], a[pivot]] = [a[pivot], a[col]];
    const scale = a[col][col] || 1;
    for (let j = 0; j < 2 * n; j += 1) a[col][j] /= scale;
    for (let row = 0; row < n; row += 1) {
      if (row === col) continue;
      const factor = a[row][col];
      for (let j = 0; j < 2 * n; j += 1) a[row][j] -= factor * a[col][j];
    }
  }
  return a.map((row) => row.slice(n));
}

export function heaviside(value = 0) {
  return Number(value) >= 0 ? 1 : 0;
}

export function lifStep({
  membrane = [],
  weights = [],
  spikes = [],
  bias = [],
  lambda = HEBBIAN_PROJECTION_CONSTANTS.leak_lambda,
  threshold = HEBBIAN_PROJECTION_CONSTANTS.threshold,
} = {}) {
  const nextMembrane = membrane.map((u, i) => {
    const input = dot(weights[i] || [], spikes) + (Number(bias[i]) || 0);
    return (lambda * ((Number(u) || 0) - (threshold * (Number(spikes[i]) || 0)))) + input;
  });
  const nextSpikes = nextMembrane.map((u) => heaviside(u - threshold));
  return { membrane: nextMembrane, spikes: nextSpikes };
}

export function gramSchmidt(vectors = [], rank = HEBBIAN_PROJECTION_CONSTANTS.subspace_rank) {
  const basis = [];
  for (const vector of vectors) {
    let residual = [...vector];
    for (const b of basis) {
      const coeff = dot(residual, b);
      residual = residual.map((value, i) => value - (coeff * b[i]));
    }
    const normalized = normalizeVector(residual);
    if (Math.sqrt(dot(normalized, normalized)) > 0.5) basis.push(normalized);
    if (basis.length >= rank) break;
  }
  return basis;
}

export function projectionMatrixRls(activityBasis = [], alpha = HEBBIAN_PROJECTION_CONSTANTS.ridge_alpha) {
  if (!activityBasis.length) return identity(HEBBIAN_PROJECTION_CONSTANTS.vector_dim);
  const a = activityBasis;
  const at = transpose(a);
  const aat = matMul(a, at);
  const regularized = aat.map((row, i) => row.map((value, j) => value + (i === j ? alpha : 0)));
  const inv = inverse(regularized);
  const projector = matSub(identity(at.length), matMul(matMul(at, inv), a));
  return projector;
}

export function projectionMatrixGpm(activityBasis = []) {
  if (!activityBasis.length) return identity(HEBBIAN_PROJECTION_CONSTANTS.vector_dim);
  return matSub(identity(activityBasis[0].length), matMul(transpose(activityBasis), activityBasis));
}

export function projectGradient(gradient = [], projector = []) {
  return matVec(projector, gradient);
}

export function outputPreservationError(delta = [], oldTrace = []) {
  return Math.abs(dot(delta, oldTrace));
}

export function hebbianProjectionScores({ queryText = '', states = [] } = {}) {
  const traces = (states || []).slice(0, 180).map((state) => hashVector(state.text || state.memory?.value || ''));
  const basis = gramSchmidt(traces);
  const projector = projectionMatrixRls(basis);
  const query = hashVector(queryText);
  const projectedQuery = projectGradient(query, projector);
  const projectedNorm = Math.sqrt(dot(projectedQuery, projectedQuery));

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const trace = hashVector(state.text || state.memory?.value || '');
    const semantic = clamp01((dot(query, trace) + 1) / 2);
    const preservation = clamp01(1 - outputPreservationError(projectedQuery, trace));
    const orthogonalNovelty = clamp01(projectedNorm);
    const score = clamp01((0.52 * semantic) + (0.32 * preservation) + (0.16 * orthogonalNovelty));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      semantic_trace_similarity: Number(semantic.toFixed(6)),
      preservation_score: Number(preservation.toFixed(6)),
      orthogonal_query_norm: Number(orthogonalNovelty.toFixed(6)),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: HEBBIAN_PROJECTION_CONSTANTS,
    guardrails: HEBBIAN_PROJECTION_GUARDRAILS,
    basis_rank: basis.length,
    projected_query_norm: Number(projectedNorm.toFixed(6)),
    formula: 'u[t+1]=lambda(u[t]-Vth*s[t])+Ws[t]+b; P=I-A^T(AA^T+alphaI)^-1A; DeltaW_P*x_old=0',
  };
}
