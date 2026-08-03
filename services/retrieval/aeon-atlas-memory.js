/**
 * Native Aeon/Atlas retrieval operator from:
 * - Aeon.pdf
 *
 * Implemented formulas / techniques:
 * - self-attention `O(N^2)` and flat scan `O(|V|)` baselines
 * - symmetric INT8 scale `s_q=max_i |v_i| / 127`
 * - quantization `q_i=clamp(round(v_i/s_q), -127, 127)`
 * - zero-vector edge case `s_q=1.0`
 * - raw dot product and dequantized similarity
 * - payload size, dynamic stride `align_up(64 + payload(D,Q) + M, 64)`
 * - Atlas descent complexity `O(log_B M)`, B=64
 * - semantic locality/inertia diagnostics
 * - SLB weighted latency `L_eff = hit*p_hit + miss*(1-p_hit)`
 * - deterministic shard routing `hash(session_id) mod 64`
 * - CSLS hub penalty before beam selection
 *
 * Aimos adaptation:
 * - uses quantized diagnostics and bounded similarity as native recall signal
 * - does not move storage to C++ or change canonical memory persistence
 * - no pruning, deletion, decay, or answer injection
 */

import { createHash } from 'node:crypto';

export const AEON_CONSTANTS = Object.freeze({
  branching_factor: 64,
  block_size: 1024,
  int8_ns: 4.70,
  fp32_ns: 26.5,
  int8_compression_ratio: 3.1,
  wal_overhead_bound: 0.01,
  slb_hit_rate: 0.85,
  slb_hit_us: 3.56,
  slb_miss_us: 10.5,
});

export const AEON_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
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

export function hashVector(text = '', dim = 64) {
  const out = Array.from({ length: dim }, () => 0);
  for (const token of normalizeText(text).split(/\s+/).filter(Boolean)) {
    const digest = createHash('sha256').update(token).digest();
    const idx = digest.readUInt32BE(0) % dim;
    const sign = digest[4] % 2 ? 1 : -1;
    out[idx] += sign;
  }
  const n = Math.sqrt(out.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return out.map((value) => value / n);
}

export function symmetricInt8Quantize(vector = []) {
  const maxAbs = Math.max(0, ...vector.map((value) => Math.abs(Number(value) || 0)));
  const scale = maxAbs === 0 ? 1 : maxAbs / 127;
  return {
    scale,
    q: vector.map((value) => clamp(Math.round((Number(value) || 0) / scale), -127, 127)),
  };
}

export function rawInt8Dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let total = 0;
  for (let i = 0; i < n; i += 1) total += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return total;
}

export function dequantizedSimilarity(query = {}, node = {}) {
  return rawInt8Dot(query.q || [], node.q || []) * (Number(query.scale) || 1) * (Number(node.scale) || 1);
}

export function alignUp(value = 0, alignment = 64) {
  const n = Math.max(0, Math.trunc(Number(value) || 0));
  const a = Math.max(1, Math.trunc(Number(alignment) || 1));
  return Math.ceil(n / a) * a;
}

export function payloadBytes(dim = 768, quantization = 'int8') {
  return Math.max(0, dim) * (quantization === 'fp32' ? 4 : 1);
}

export function dynamicStride({ dim = 768, quantization = 'int8', metadataBytes = 0 } = {}) {
  return alignUp(64 + payloadBytes(dim, quantization) + Math.max(0, metadataBytes), 64);
}

export function compressionRatio({ dim = 768, metadataBytes = 320 } = {}) {
  const fp = dynamicStride({ dim, quantization: 'fp32', metadataBytes });
  const q = dynamicStride({ dim, quantization: 'int8', metadataBytes });
  return q ? fp / q : 0;
}

export function atlasComplexity({ nodes = 1, branchingFactor = AEON_CONSTANTS.branching_factor } = {}) {
  const n = Math.max(1, Number(nodes) || 1);
  const b = Math.max(2, Number(branchingFactor) || 2);
  return {
    descent: Math.log(n) / Math.log(b),
    flat_scan: n,
    phase1: n / AEON_CONSTANTS.block_size,
    phase2_per_beam: AEON_CONSTANTS.block_size,
    expression: 'O(log_B M)',
  };
}

export function effectiveSlbLatency({
  hitRate = AEON_CONSTANTS.slb_hit_rate,
  hitUs = AEON_CONSTANTS.slb_hit_us,
  missUs = AEON_CONSTANTS.slb_miss_us,
} = {}) {
  const h = clamp01(hitRate);
  return (h * hitUs) + ((1 - h) * missUs);
}

export function deterministicShardRoute(sessionId = '', shardCount = 64) {
  const digest = createHash('sha256').update(String(sessionId || '')).digest();
  return digest.readUInt32BE(0) % Math.max(1, shardCount);
}

export function cslsAdjust(similarity = 0, queryHubness = 0, nodeHubness = 0) {
  return (2 * (Number(similarity) || 0)) - (Number(queryHubness) || 0) - (Number(nodeHubness) || 0);
}

export function aeonAtlasScores({
  queryText = '',
  contexts = [],
} = {}) {
  const query = symmetricInt8Quantize(hashVector(queryText));
  const nodeRows = (contexts || []).slice(0, 160).map((context) => {
    const text = context.text || context.value || '';
    const q = symmetricInt8Quantize(hashVector(text));
    const sim = dequantizedSimilarity(query, q);
    return { context, quantized: q, sim };
  });
  const avgHub = nodeRows.length ? nodeRows.reduce((sum, row) => sum + row.sim, 0) / nodeRows.length : 0;
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const row of nodeRows) {
    const adjusted = cslsAdjust(row.sim, avgHub, row.sim * 0.2);
    const bounded = clamp01((adjusted + 1) / 2);
    const shard = deterministicShardRoute(row.context.memory?.session_id || row.context.id);
    scoreById.set(String(row.context.id), bounded);
    diagnosticsById.set(String(row.context.id), {
      raw_similarity: Number(row.sim.toFixed(6)),
      csls_adjusted: Number(adjusted.toFixed(6)),
      shard_id: shard,
      int8_scale: Number(row.quantized.scale.toFixed(8)),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: AEON_CONSTANTS,
    latency_effective_us: Number(effectiveSlbLatency({}).toFixed(6)),
    compression_ratio_768: Number(compressionRatio({ dim: 768, metadataBytes: 320 }).toFixed(6)),
    complexity: atlasComplexity({ nodes: contexts.length || 1 }),
    formula: 'sim = raw_dot * sq(query) * sq(node); stride = align_up(64 + payload(D,Q) + M, 64); search = O(log_B M)',
  };
}
