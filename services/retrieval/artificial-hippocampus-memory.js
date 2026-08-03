/**
 * Native Artificial Hippocampus Network recall operator from:
 * - Artificial Hippocampus Networks for Efficient Long-Context Modeling.pdf
 *
 * Implemented formulas / techniques:
 * - fixed-size recurrent hidden memory for evicted/out-of-window context
 * - Transformer KV cache as lossless short-window memory
 * - AHN activation gate `L > W`
 * - QKV projections `Q=XW_Q`, `K=XW_K`, `V=XW_V`
 * - masked scaled dot-product attention `softmax(QK^T / sqrt(d_in) ⊙ M)V`
 * - causal mask `M_ij = 1 if j <= i else 0`
 * - AHN-GDN update
 *   `h_t = alpha(x)(I - beta(x)kk^T)h_{t-1} + beta(x)kv`
 * - AHN output fusion `y_t = y_AHN,t + Attention(window KV, q_t)`
 * - KL self-distillation loss `KL(p_teacher || p_student)`
 * - max/average pooling compression at 4x rate
 * - FLOP and cache-complexity accounting for full attention vs window+AHN
 *
 * Aimos adaptation:
 * - computes deterministic compressed-memory diagnostics over recalled evidence
 * - uses AHN-style fixed state as a bounded recall signal
 * - does not train model weights, discard canonical memory, prune, decay, or inject answers
 */

import { createHash } from 'node:crypto';

export const AHN_CONSTANTS = Object.freeze({
  paper_window_tokens: 32_000,
  paper_training_max_tokens: 24_000,
  compression_rate: 4,
  added_parameter_fraction: 0.004,
  default_dim: 32,
  default_heads_query: 32,
  default_heads_kv: 8,
});

export const AHN_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  trains_model_weights: false,
});

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
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
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

export function hashVector(text = '', dim = AHN_CONSTANTS.default_dim) {
  const vector = Array.from({ length: dim }, () => 0);
  for (const token of tokens(text)) {
    const digest = createHash('sha256').update(token).digest();
    const idx = digest.readUInt32BE(0) % dim;
    const sign = digest[4] % 2 ? 1 : -1;
    vector[idx] += sign;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return vector.map((value) => value / norm);
}

export function dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let total = 0;
  for (let i = 0; i < n; i += 1) total += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return total;
}

export function cosine(left = [], right = []) {
  const denom = (Math.sqrt(dot(left, left)) || 1) * (Math.sqrt(dot(right, right)) || 1);
  return denom ? dot(left, right) / denom : 0;
}

export function matrixVectorMultiply(matrix = [], vector = []) {
  if (!Array.isArray(matrix) || !Array.isArray(matrix[0])) return [];
  return matrix.map((row) => dot(row, vector));
}

export function qkvLinearProjections(inputVectors = [], weights = {}) {
  const identity = (dim) => Array.from({ length: dim }, (_, i) =>
    Array.from({ length: dim }, (_, j) => (i === j ? 1 : 0))
  );
  const dim = inputVectors[0]?.length || AHN_CONSTANTS.default_dim;
  const wq = weights.Wq || identity(dim);
  const wk = weights.Wk || identity(dim);
  const wv = weights.Wv || identity(dim);
  return {
    Q: inputVectors.map((x) => matrixVectorMultiply(wq, x)),
    K: inputVectors.map((x) => matrixVectorMultiply(wk, x)),
    V: inputVectors.map((x) => matrixVectorMultiply(wv, x)),
  };
}

export function causalMask(length = 0) {
  const n = Math.max(0, Math.trunc(Number(length) || 0));
  return Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (j <= i ? 1 : 0))
  );
}

export function softmax(values = []) {
  if (!values.length) return [];
  const max = Math.max(...values);
  const exps = values.map((value) => Math.exp((Number(value) || 0) - max));
  const total = exps.reduce((sum, value) => sum + value, 0) || 1;
  return exps.map((value) => value / total);
}

export function maskedScaledDotProductAttention(Q = [], K = [], V = [], mask = causalMask(Q.length)) {
  const dim = Math.max(1, K[0]?.length || Q[0]?.length || 1);
  return Q.map((query, i) => {
    const logits = K.map((key, j) => (mask?.[i]?.[j] ? dot(query, key) / Math.sqrt(dim) : Number.NEGATIVE_INFINITY));
    const probs = softmax(logits);
    const out = Array.from({ length: V[0]?.length || dim }, () => 0);
    for (let j = 0; j < V.length; j += 1) {
      for (let d = 0; d < out.length; d += 1) out[d] += (probs[j] || 0) * (V[j]?.[d] || 0);
    }
    return out;
  });
}

export function poolVectors(vectors = [], rate = AHN_CONSTANTS.compression_rate, mode = 'average') {
  const r = Math.max(1, Math.trunc(Number(rate) || 1));
  const out = [];
  for (let i = 0; i < vectors.length; i += r) {
    const chunk = vectors.slice(i, i + r);
    const dim = chunk[0]?.length || 0;
    out.push(Array.from({ length: dim }, (_, d) => {
      const values = chunk.map((row) => Number(row[d]) || 0);
      if (mode === 'max') return Math.max(...values);
      return values.reduce((sum, value) => sum + value, 0) / Math.max(1, values.length);
    }));
  }
  return out;
}

export function shouldActivateAHN(sequenceLength = 0, windowSize = AHN_CONSTANTS.paper_window_tokens) {
  return Math.max(0, Number(sequenceLength) || 0) > Math.max(1, Number(windowSize) || 1);
}

export function ahnGdnUpdate({
  previousState = [],
  key = [],
  value = [],
  input = [],
  alpha = null,
  beta = null,
} = {}) {
  const dim = Math.max(previousState.length, key.length, value.length, input.length, AHN_CONSTANTS.default_dim);
  const state = Array.from({ length: dim }, (_, i) => Number(previousState[i]) || 0);
  const k = Array.from({ length: dim }, (_, i) => Number(key[i]) || 0);
  const v = Array.from({ length: dim }, (_, i) => Number(value[i]) || 0);
  const x = Array.from({ length: dim }, (_, i) => Number(input[i]) || 0);
  const a = alpha ?? clamp01(0.5 + (dot(x, k) / (2 * dim)));
  const b = beta ?? clamp01(0.5 + (dot(x, v) / (2 * dim)));
  const kh = dot(k, state);
  const next = state.map((h, i) => (a * (h - (b * k[i] * kh))) + (b * k[i] * v[i]));
  const norm = Math.sqrt(dot(next, next)) || 1;
  return next.map((value) => value / norm);
}

export function ahnOutputFusion({
  query = [],
  state = [],
  windowKeys = [],
  windowValues = [],
  gamma = 1,
} = {}) {
  const q = [query];
  const attention = maskedScaledDotProductAttention(q, windowKeys, windowValues, [[...windowKeys.map(() => 1)]])[0] || [];
  const ahnValue = dot(query, state) * Number(gamma || 1);
  return attention.map((value, i) => value + (ahnValue * (state[i] || 0)));
}

export function klDivergence(teacher = [], student = []) {
  const eps = 1e-12;
  const t = softmax(teacher);
  const s = softmax(student);
  let total = 0;
  for (let i = 0; i < Math.min(t.length, s.length); i += 1) {
    total += t[i] * Math.log((t[i] + eps) / (s[i] + eps));
  }
  return total;
}

export function ahnComplexity({
  length = 1,
  window = AHN_CONSTANTS.paper_window_tokens,
  dim = 4096,
  hidden = 128,
  queryHeads = AHN_CONSTANTS.default_heads_query,
  kvHeads = AHN_CONSTANTS.default_heads_kv,
} = {}) {
  const L = Math.max(1, Number(length) || 1);
  const W = Math.max(1, Number(window) || 1);
  const D = Math.max(1, Number(dim) || 1);
  const H = Math.max(1, Number(hidden) || 1);
  const Nq = Math.max(1, Number(queryHeads) || 1);
  const Nkv = Math.max(1, Number(kvHeads) || 1);
  const fullFlops = (4 * L * D * H * (Nq + Nkv)) + (2 * H * Nq * L * L);
  const ahnFlops = (2 * L * D * H * (Nq + Nkv)) + (2 * Math.max(0, L - W) * ((2 * W * H * Nq) + (H * Nq) + (3 * D * Nq) + (H * Nq)));
  return {
    full_attention_flops: fullFlops,
    window_ahn_flops: ahnFlops,
    flop_ratio: fullFlops ? ahnFlops / fullFlops : 1,
    full_cache: 2 * L * H * Nkv,
    ahn_cache: (2 * W * H * Nkv) + (H * H * Nq),
    cache_ratio: (2 * L * H * Nkv) ? ((2 * W * H * Nkv) + (H * H * Nq)) / (2 * L * H * Nkv) : 1,
    activated: shouldActivateAHN(L, W),
  };
}

export function gradientUtilityScore(gradientMagnitudes = []) {
  if (!gradientMagnitudes.length) return 0;
  const avg = gradientMagnitudes.reduce((sum, value) => sum + Math.max(0, Number(value) || 0), 0) / gradientMagnitudes.length;
  return clamp01(avg / (avg + 1));
}

export function ahnCompressedState(text = '', { dim = AHN_CONSTANTS.default_dim, windowTokens = 128 } = {}) {
  const words = tokens(text);
  const vectors = words.map((word) => hashVector(word, dim));
  const window = vectors.slice(-windowTokens);
  const evicted = vectors.slice(0, Math.max(0, vectors.length - windowTokens));
  const pooled = poolVectors(evicted, AHN_CONSTANTS.compression_rate, 'average');
  let state = Array.from({ length: dim }, () => 0);
  for (const vector of pooled) state = ahnGdnUpdate({ previousState: state, key: vector, value: vector, input: vector });
  return {
    state,
    window,
    evicted_count: evicted.length,
    pooled_count: pooled.length,
    activated: evicted.length > 0,
  };
}

export function ahnRecallScores({
  queryText = '',
  states = [],
  contexts = [],
} = {}) {
  const query = hashVector(queryText);
  const rows = (states || []).slice(0, 180).map((state) => {
    const text = state.text || state.memory?.value || contexts.find((context) => context.id === state.id)?.text || '';
    const compressed = ahnCompressedState(text);
    const direct = cosine(query, hashVector(text));
    const compressedScore = compressed.activated ? cosine(query, compressed.state) : 0;
    const longContextNeed = clamp01(tokens(queryText).length / 24) || 0;
    const activationScore = compressed.activated ? 1 : clamp01(tokens(text).length / 128);
    const score = clamp01((0.52 * ((direct + 1) / 2)) + (0.28 * ((compressedScore + 1) / 2)) + (0.20 * activationScore * longContextNeed));
    return { state, score, direct, compressedScore, compressed };
  });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const row of rows) {
    scoreById.set(String(row.state.id), row.score);
    diagnosticsById.set(String(row.state.id), {
      direct_similarity: Number(row.direct.toFixed(6)),
      compressed_similarity: Number(row.compressedScore.toFixed(6)),
      evicted_count: row.compressed.evicted_count,
      pooled_count: row.compressed.pooled_count,
      ahn_activated: row.compressed.activated,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: AHN_CONSTANTS,
    guardrails: AHN_GUARDRAILS,
    complexity: ahnComplexity({ length: Math.max(1, contexts.reduce((sum, context) => sum + tokens(context.text || context.value || '').length, 0)) }),
    formula: 'h_t = alpha(x)(I - beta(x)kk^T)h_{t-1} + beta(x)kv; y_t = y_AHN,t + Attention(window KV, q_t)',
  };
}
