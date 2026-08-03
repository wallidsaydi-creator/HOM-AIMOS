/**
 * turboquant-compat.js — Runtime Compatibility And PRF Diagnostics
 *
 * Additive Batch9 Wave1 authority: Pseudo Relevance Feedback and
 * RNNs Are Not Transformers (Yet). Aimos derives public PRF feature
 * diagnostics for save feedback only: keywords, public entities, summary,
 * source hints, and open-memory evidence card. No hidden chain-of-thought,
 * learned PRF weighting, canonical memory mutation, or ranking change is
 * enabled here.
 * Additive Batch9.5 Wave4 authority: Don't Waste Bits, AQPIM, EliteKV,
 * Stochastic KV Routing, Fractional RoPE, Two-Block Hadamard Rotations, and
 * HieraSparse. Aimos exposes memory I/O readiness diagnostics only; no live
 * KV quantization, PIM activation quantization, sparse attention, or recall
 * ranking mutation is enabled.
 */
import { query } from '../../db/connection.js';

const BATCH9_PRF_AUTHORITIES = [
  'Pseudo Relevance Feedback is Enough to Close the Gap Between Small and Large Dense Retrieval Models',
  'RNNs Are Not Transformers (Yet): The Key Bottleneck on In-Context Retrieval',
];
const BATCH9_5_MEMORY_IO_AUTHORITIES = [
  "Don't Waste Bits: Adaptive KV-Cache Quantization for Lightweight On-Device LLMs",
  'AQPIM: Breaking the PIM Capacity Wall for LLMs with In-Memory Activation Quantization',
  'EliteKV: Scalable KV Cache Compression via RoPE Frequency Selection and Joint Low-Rank Projection',
  'Stochastic KV Routing: Enabling Adaptive Depth-Wise Cache Sharing',
  'Fractional Rotation, Full Potential: Investigating Performance and Convergence of Partial RoPE',
  'Approximating Uniform Random Rotations by Two-Block Structured Hadamard Rotations in High Dimensions',
  'HieraSparse: Hierarchical Semi-Structured Sparse KV Attention',
];

let capabilityCache = null;
let capabilityCacheAt = 0;
const CAPABILITY_TTL_MS = 30_000;

function tokenize(value = '') {
  return String(value || '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_:-]+/gu, ' ')
    .split(/\s+/)
    .filter((token) => token.length >= 4 && !STOPWORDS.has(token));
}

const STOPWORDS = new Set([
  'about', 'after', 'also', 'because', 'before', 'between', 'could', 'every',
  'from', 'have', 'into', 'memory', 'aimos', 'paper', 'that', 'their', 'there',
  'these', 'this', 'through', 'with', 'would',
]);

function topTerms(tokens = [], limit = 12) {
  const counts = new Map();
  for (const token of tokens) counts.set(token, (counts.get(token) || 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([term, count]) => ({ term, count }));
}

function extractPublicEntities(text = '', limit = 10) {
  const entities = new Set();
  const value = String(text || '');
  for (const match of value.matchAll(/\b[A-Z][A-Za-z0-9_-]{2,}(?:\s+[A-Z][A-Za-z0-9_-]{2,}){0,3}\b/g)) {
    entities.add(match[0].trim());
    if (entities.size >= limit) break;
  }
  for (const match of value.matchAll(/\b\d{4}-\d{2}-\d{2}\b/g)) {
    entities.add(match[0]);
    if (entities.size >= limit) break;
  }
  return [...entities];
}

function summarizePublicClaim(key = '', value = '', max = 220) {
  const compact = String(value || '').replace(/\s+/g, ' ').trim();
  const sentence = compact.split(/(?<=[.!?])\s+/).find((part) => part.length >= 20) || compact;
  const source = sentence || String(key || '');
  return source.length > max ? `${source.slice(0, max - 1)}…` : source;
}

export function buildPrfFeatureDiagnostics({ key = '', value = '', memoryType = '', source = '' } = {}) {
  const text = `${key}\n${value}`;
  const tokens = tokenize(text);
  const keywords = topTerms(tokens, 12);
  const entities = extractPublicEntities(text, 10);
  const summary = summarizePublicClaim(key, value);

  return {
    source_papers: BATCH9_PRF_AUTHORITIES,
    diagnostic_only: true,
    feature_type: 'public_prf_memory_features',
    keywords,
    entities,
    summary,
    source_hints: [memoryType, source, key.split(':')[0]].filter(Boolean).slice(0, 5),
    evidence_card: {
      claim: summary,
      open_memory_handle: key ? `hom_open_memory:key:${key}` : null,
      memory_type: memoryType || null,
    },
    hidden_chain_of_thought_stored: false,
    canonical_memory_changed: false,
    ranking_math_changed: false,
    guarded_math: {
      prf_query_embedding_concat: false,
      learned_prf_weighting: false,
    },
  };
}

export async function getTurboQuantCapabilities() {
  const now = Date.now();
  if (capabilityCache && now - capabilityCacheAt < CAPABILITY_TTL_MS) {
    return capabilityCache;
  }

  try {
    const result = await query(
      `SELECT column_name
       FROM information_schema.columns
       WHERE table_name = 'aimos_memories'
         AND column_name IN ('quant_idx', 'residual_vector')`
    );

    const columns = new Set(result.rows.map((row) => row.column_name));
    capabilityCache = {
      quantColumns: columns.has('quant_idx') && columns.has('residual_vector'),
    };
  } catch {
    capabilityCache = { quantColumns: false };
  }

  capabilityCacheAt = now;
  return capabilityCache;
}

export function buildTurboQuantMemoryIoDiagnostics({
  capabilities = {},
  vectorCount = 0,
  memoryCount = 0,
  contextPressure = 0,
  evidencePrecisionLevel = 'claim_evidence',
  benchmark = {},
} = {}) {
  const baseline = Number(benchmark?.baselineRecallAt10);
  const compressed = Number(benchmark?.compressedRecallAt10);
  const hasBenchmark = Number.isFinite(baseline) && baseline > 0 && Number.isFinite(compressed);
  const lossPct = hasBenchmark ? Math.max(0, ((baseline - compressed) / baseline) * 100) : null;
  const pressure = Math.max(0, Math.min(1, Number(contextPressure || 0)));

  return {
    status: hasBenchmark && lossPct <= 2 ? 'diagnostic_ready' : 'benchmark_required',
    source_papers: BATCH9_5_MEMORY_IO_AUTHORITIES,
    diagnostic_only: true,
    memory_io_scope: 'context_views_and_runtime_cache_diagnostics_only',
    observed_inputs: {
      vector_count: Math.max(0, Number(vectorCount || 0)),
      memory_count: Math.max(0, Number(memoryCount || 0)),
      context_pressure: Number(pressure.toFixed(6)),
      evidence_precision_level: String(evidencePrecisionLevel || 'claim_evidence'),
      turboquant_columns_present: Boolean(capabilities?.quantColumns),
    },
    benchmark_gate: {
      benchmark_required: true,
      baseline_recall_at_10: hasBenchmark ? baseline : null,
      compressed_recall_at_10: hasBenchmark ? compressed : null,
      quality_loss_pct: lossPct == null ? null : Number(lossPct.toFixed(4)),
      passed: hasBenchmark && lossPct <= 2,
    },
    adaptive_precision_contract: {
      summary: true,
      claim_evidence: true,
      excerpt: true,
      raw_open_handle: true,
      canonical_memory_quantized: false,
      raw_memory_deleted: false,
    },
    guarded_math: {
      kv_quantization_enabled: false,
      rope_frequency_selection_enabled: false,
      low_rank_projection_enabled: false,
      stochastic_kv_routing_enabled: false,
      hadamard_rotation_enabled: false,
      pim_activation_quantization_enabled: false,
      sparse_kv_attention_enabled: false,
      recall_ranking_changed: false,
    },
  };
}

export function resetTurboQuantCapabilities() {
  capabilityCache = null;
  capabilityCacheAt = 0;
}


// ─── BATCH 10 LANE 2: KV CACHE QUANTIZATION ──────────────────────────────────
// Paper: Don't Waste Bits — Adaptive KV-Cache Quantization
// Formula: W_q = clamp(round(W / scale), -(2^(bits-1)-1), 2^(bits-1)-1)
//          scale = max(|W_group|) / (2^(bits-1)-1)
// Scale adaptation: bits = min(8, max(4, floor(4 + log2(N/14000))))
//   At 14K: 4-bit (saves most memory). At 100K+: 8-bit (more precision needed).
// Aladdin compliance: SAFE — quantization affects representation precision, not content.
// Guarded math: requires paper authority + benchmark gate (loss_pct <= 2)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute adaptive quantization bit-width based on memory pool size.
 * More memories → denser embedding space → higher precision needed.
 */
export function computeAdaptiveQuantBits(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  // More memories → denser embedding space → higher precision needed
  // 14K: log2(1)=0 → 4-bit. 56K: log2(4)=2 → 6-bit. 100K+: log2(~7)≈2.8 → 6-bit, clamped to 8 at higher counts
  return Math.min(8, Math.max(4, Math.floor(4 + Math.log2(N / 14000))));
}

/**
 * Group-wise KV cache quantization following "Don't Waste Bits".
 * Quantizes a vector to the specified bit-width using per-group scaling.
 *
 * @param {number[]} vector - The embedding vector to quantize
 * @param {object} [opts]
 * @param {number} [opts.bits=4] - Target bit width (4-8)
 * @param {number} [opts.groupSize=128] - Number of elements per quantization group
 * @returns {{ quantized: Int8Array, scales: Float32Array, bits: number, originalDim: number, compressionRatio: number }}
 */
export function quantizeKVVector(vector, opts = {}) {
  const bits = Math.min(8, Math.max(4, opts.bits || 4));
  const groupSize = Math.max(1, opts.groupSize || 128);
  const maxVal = (1 << (bits - 1)) - 1; // e.g., 7 for 4-bit, 127 for 8-bit

  if (!Array.isArray(vector) || vector.length === 0) {
    return { quantized: new Int8Array(0), scales: new Float32Array(0), bits, originalDim: 0, compressionRatio: 1 };
  }

  const numGroups = Math.ceil(vector.length / groupSize);
  const quantized = new Int8Array(vector.length);
  const scales = new Float32Array(numGroups);

  for (let g = 0; g < numGroups; g++) {
    const start = g * groupSize;
    const end = Math.min(start + groupSize, vector.length);

    // Find group max absolute value for scale
    let groupMax = 0;
    for (let i = start; i < end; i++) {
      const abs = Math.abs(vector[i]);
      if (abs > groupMax) groupMax = abs;
    }

    const scale = groupMax > 0 ? groupMax / maxVal : 1;
    scales[g] = scale;

    // Quantize: W_q = clamp(round(W / scale), -maxVal, maxVal)
    for (let i = start; i < end; i++) {
      const q = Math.round(vector[i] / scale);
      quantized[i] = Math.max(-maxVal, Math.min(maxVal, q));
    }
  }

  const compressionRatio = (32 / bits); // FP32 → bits compression
  return { quantized, scales, bits, originalDim: vector.length, compressionRatio: Number(compressionRatio.toFixed(2)) };
}

/**
 * Dequantize a previously quantized vector.
 * Reconstructs approximate original values from quantized data + scales.
 *
 * @param {Int8Array} quantized - Quantized integer values
 * @param {Float32Array} scales - Per-group scale factors
 * @param {number} groupSize - Group size used during quantization
 * @returns {number[]} Reconstructed floating-point vector
 */
export function dequantizeKVVector(quantized, scales, groupSize = 128) {
  if (!quantized || !scales || quantized.length === 0) return [];
  const result = new Array(quantized.length);
  for (let i = 0; i < quantized.length; i++) {
    const groupIdx = Math.floor(i / groupSize);
    const scale = scales[groupIdx] || 1;
    result[i] = quantized[i] * scale;
  }
  return result;
}

/**
 * Compute KV quantization quality: cosine similarity between original and round-tripped vector.
 * Must pass benchmark gate (loss_pct <= 2) before enabling in production.
 */
export function computeKVQuantizationQuality(original, reconstructed) {
  if (!Array.isArray(original) || !Array.isArray(reconstructed) || original.length !== reconstructed.length || original.length === 0) {
    return { cos_sim: 0, loss_pct: 100 };
  }
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < original.length; i++) {
    dot += original[i] * reconstructed[i];
    normA += original[i] * original[i];
    normB += reconstructed[i] * reconstructed[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  const cosSim = denom > 0 ? dot / denom : 0;
  const lossPct = Math.max(0, (1 - cosSim) * 100);
  return { cos_sim: Number(cosSim.toFixed(6)), loss_pct: Number(lossPct.toFixed(4)) };
}

// ─── BATCH 10 LANE 2: ATTENTION & KV CACHE SCALING FUNCTIONS ──────────────────
// All formulas scale with memory count N. Baseline at N=14000.
// Guarded math: diagnostic-only until benchmark gate passes (loss_pct <= 2).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A2: RoPE Frequency Selection — θ_base scaling
 * Paper: RoPE (Rotary Position Embeddings)
 * Formula: θ_base = 10000 * (N/14000)^0.1
 * At 14K: 10000 (standard). At 100K: ~12173 (wider positional resolution).
 */
export function computeRoPEBaseFrequency(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 10000 * Math.pow(N / 14000, 0.1);
}

/**
 * A2: Compute θ_i for each dimension given base frequency
 * Formula: θ_i = θ_base^(-2i/d)
 */
export function computeRoPEThetaI(dimension, baseFreq = 10000, d = 768) {
  return Math.pow(baseFreq, -2 * dimension / d);
}

/**
 * A3: Low-Rank Projection — rank r scaling
 * Paper: LoRA-style low-rank adaptation
 * Formula: r = max(4, min(64, floor(8 + 4*log2(N/14000))))
 * At 14K: r=8. At 100K: r≈19. Higher rank for denser embedding space.
 */
export function computeLowRankR(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(4, Math.min(64, Math.floor(8 + 4 * Math.log2(N / 14000))));
}

/**
 * A3: Low-rank projection W' = W + B*A
 * B ∈ R^(d×r), A ∈ R^(r×d), r << d
 */
export function lowRankProject(W, B, A) {
  const d = W.length;
  const r = B[0].length;
  const result = new Array(d).fill(0);
  for (let i = 0; i < d; i++) {
    result[i] = W[i];
    for (let k = 0; k < r; k++) {
      result[i] += B[i][k] * A[k][i];
    }
  }
  return result;
}

/**
 * A4: Stochastic KV Routing — temperature scaling
 * Paper: Stochastic routing for KV cache
 * Formula: τ = 0.5 + 0.1*log2(N/14000)
 * At 14K: τ=0.5 (near-deterministic). At 100K: τ≈0.78 (more exploration).
 */
export function computeRoutingTemperature(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 0.5 + 0.1 * Math.log2(N / 14000);
}

/**
 * A4: Softmax with temperature for routing probabilities
 * P(route_i) = softmax(relevance_i / τ)
 */
export function softmaxWithTemp(relevances, temperature = 1.0) {
  const maxR = Math.max(...relevances);
  const exps = relevances.map(r => Math.exp((r - maxR) / temperature));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map(e => e / sum);
}

/**
 * A5: Hadamard Rotation — dimension n scaling
 * Paper: Hadamard transform for orthogonal projection
 * Formula: n = max(64, min(512, floor(128 * (N/14000)^0.2)))
 * At 14K: n=128. At 100K: n≈189.
 */
export function computeHadamardDimension(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(64, Math.min(512, Math.floor(128 * Math.pow(N / 14000, 0.2))));
}

/**
 * A5: Hadamard-2 transform: H_2 * [a, b] = [(a+b)/√2, (a-b)/√2]
 */
export function hadamard2(a, b) {
  const s = 1 / Math.sqrt(2);
  return [s * (a + b), s * (a - b)];
}

/**
 * A6: PIM Activation Quantization — bits scaling
 * Paper: PIM architecture quantization
 * Formula: bits = max(4, min(8, floor(4 + 2*log2(N/14000))))
 * At 14K: 4-bit. At 100K: 8-bit.
 */
export function computePIMQuantBits(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(4, Math.min(8, Math.floor(4 + 2 * Math.log2(N / 14000))));
}

/**
 * A6: Quantize activations for PIM hardware
 * act_q = round(act / act_scale) * act_scale
 * act_scale = max(|act_channel|) / (2^(bits-1) - 1)
 */
export function quantizeActivations(activations, bits = 4) {
  const maxVal = (1 << (bits - 1)) - 1;
  const groupMax = Math.max(...activations.map(Math.abs));
  const scale = groupMax > 0 ? groupMax / maxVal : 1;
  return activations.map(a => {
    const q = Math.round(a / scale);
    return Math.max(-maxVal, Math.min(maxVal, q)) * scale;
  });
}

/**
 * A7: Sparse KV Attention — sparsity ratio scaling
 * Paper: Sparse attention patterns for KV cache
 * Formula: sparsity = min(0.9, max(0.5, 0.5 + 0.1*log2(N/14000)))
 * At 14K: 50% sparse. At 100K: ~78% sparse.
 */
export function computeSparsityRatio(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.min(0.9, Math.max(0.5, 0.5 + 0.1 * Math.log2(N / 14000)));
}

/**
 * Build comprehensive attention & KV cache diagnostic
 * All guarded_math fields are diagnostic-only until benchmark gate passes.
 */
export function buildAttentionKVDiagnostics(memoryCount = 14000, benchmark = {}) {
  const N = Math.max(1, memoryCount);
  const baseline = Number(benchmark?.baselineRecallAt10);
  const compressed = Number(benchmark?.compressedRecallAt10);
  const hasBenchmark = Number.isFinite(baseline) && baseline > 0 && Number.isFinite(compressed);
  const lossPct = hasBenchmark ? Math.max(0, ((baseline - compressed) / baseline) * 100) : null;
  const gatePassed = hasBenchmark && lossPct <= 2;

  return {
    diagnostic_only: true,
    source_papers: BATCH9_5_MEMORY_IO_AUTHORITIES,
    memory_count: N,
    scale_parameters: {
      kv_quant_bits: computeAdaptiveQuantBits(N),
      rope_base_frequency: Number(computeRoPEBaseFrequency(N).toFixed(2)),
      low_rank_r: computeLowRankR(N),
      routing_temperature: Number(computeRoutingTemperature(N).toFixed(4)),
      hadamard_dimension: computeHadamardDimension(N),
      pim_quant_bits: computePIMQuantBits(N),
      sparsity_ratio: Number(computeSparsityRatio(N).toFixed(4)),
    },
    benchmark_gate: {
      benchmark_required: true,
      baseline_recall_at_10: hasBenchmark ? baseline : null,
      compressed_recall_at_10: hasBenchmark ? compressed : null,
      quality_loss_pct: lossPct == null ? null : Number(lossPct.toFixed(4)),
      passed: gatePassed,
    },
    guarded_math: {
      kv_quantization_enabled: false,
      rope_frequency_selection_enabled: false,
      low_rank_projection_enabled: false,
      stochastic_kv_routing_enabled: false,
      hadamard_rotation_enabled: false,
      pim_activation_quantization_enabled: false,
      sparse_kv_attention_enabled: false,
      recall_ranking_changed: false,
    },
  };
}
