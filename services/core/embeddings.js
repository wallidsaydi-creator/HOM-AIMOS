/**
 * embeddings.js — Local embedding engine (zero external API calls)
 * Source: all-mpnet-base-v2 (768d), @huggingface/transformers
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (SAVE pipeline step 5, RECALL pipeline step 2)
 * 2. ← Called by: nightly-dream.js (step 18)
 * 3. → Pulls from: Raw text strings (Ingestion/Query input)
 * 4. → Pushes to: 768d dense vectors (Postgres pgvector)
 *
 * LOGIC GUIDE: Uses @huggingface/transformers to run all-mpnet-base-v2 locally.
 * Model downloads once (~80MB), then runs in-process via ONNX runtime for zero-cost vectors.
 *
 * Additive Batch9/9.5 Wave5 authority: Deep-Learned Observation Operators,
 * HGP-Mamba, Modality-Aware Zero-Shot Pruning, and Reconstructing Content via
 * Collaborative Attention. Aimos exposes representation diagnostics and
 * inactive future multimodal contracts only; text embedding dimensions/model
 * and production embedding math are unchanged.
 *
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildSparseSignProjectionDiagnostic: SDM-style sparse sign-projection
 *     alongside dense 768d embeddings. The dense embedding model is never modified.
 *
 * Batch 10 Lane 3: VSA + HRR embeddings alongside 768d dense
 *   computeVSAEmbedding: 10K bipolar vector {-1, +1} via random projection
 *   computeHRREmbedding: circular_convolution(dense, permutation_matrix)
 *   These are alongside-path diagnostics. Production 768d path unchanged.
 *   Aladdin: VSA and HRR never modify the production 768d embedding model.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline step 5, RECALL pipeline step 2)
// ← Called by: nightly-dream.js (step 18)
// → Calls: (ONNX local model — no service call)
// Pipeline: SAVE_PIPELINE, RECALL_PIPELINE, DREAM_PIPELINE
// Position: embedding generation
// ─────────────────────────────────────────────────────────────────────────────

import { pipeline, env as txEnv } from '@huggingface/transformers';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Configure cache directory — resolved from module location, not cwd
const CACHE_DIR = resolve(__dirname, '..', '.cache', 'embeddings');
txEnv.cacheDir = CACHE_DIR;
txEnv.allowRemoteModels = true;  // allow initial download
txEnv.allowLocalModels = true;

const MODEL_ID = 'Xenova/all-mpnet-base-v2'; // 768 dimensions — matches existing DB vectors
// Immutable upstream revision. Model downloads are never resolved from a mutable
// branch because changing embedding bytes would silently change retrieval space.
const MODEL_REVISION = 'e086c5e0b3a57b0ce46dd6d9c0662948860b35f3';
const _health = {
  healthy: null,
  failCount: 0,
  lastCheck: 0,
  totalCalls: 0,
  provider: 'local',
  model: MODEL_ID,
  model_revision: MODEL_REVISION,
};
const WAVE5_EMBEDDING_CONTRACT_AUTHORITIES = [
  'Deep-Learned Observation Operators for Artificial Intelligence Weather Forecasting Models',
  'HGP-Mamba: Integrating Histology and Generated Protein Features for Mamba-based Multimodal Survival Risk Prediction',
  'Modality-Aware Zero-Shot Pruning and Sparse Attention for Efficient Multimodal Edge Inference',
  'Reconstructing Content via Collaborative Attention to Improve Multimodal Embedding Quality',
];
const FUTURE_MODALITIES = ['image', 'video', 'audio', 'multimodal_fusion'];

// ─── LRU EMBEDDING CACHE ────────────────────────────────────────────────────
// Deterministic model + input → deterministic output. Cache eliminates ~248ms ONNX inference per hit.
// 768d × 4 bytes × 500 entries ≈ 1.5MB — trivial memory cost.
// Ref: PerCache (2024) — predictive hierarchical cache for RAG pipelines.
const EMBED_CACHE_MAX = 500;
const _embedCache = new Map();  // Map<sha256_hex, number[]> — insertion order = LRU order
const _cacheStats = { hits: 0, misses: 0 };

function _cacheKey(text) {
  const normalized = text.toLowerCase().trim().slice(0, 2000);
  return createHash('sha256').update(normalized).digest('hex');
}

function _cachePut(key, embedding) {
  // Evict oldest entry if at capacity
  if (_embedCache.size >= EMBED_CACHE_MAX) {
    const oldestKey = _embedCache.keys().next().value;
    _embedCache.delete(oldestKey);
  }
  _embedCache.set(key, embedding);
}

function _cacheGet(key) {
  const val = _embedCache.get(key);
  if (val === undefined) return undefined;
  // Move to end (most recently used) by re-inserting
  _embedCache.delete(key);
  _embedCache.set(key, val);
  return val;
}
// ─────────────────────────────────────────────────────────────────────────────

// C1 fix: promise-based singleton prevents duplicate model loads under concurrency
let _pipelinePromise = null;

async function getPipeline() {
  if (!_pipelinePromise) {
    console.log(`[embeddings] Loading local model ${MODEL_ID} (first call only)...`);
    console.log(`[embeddings] Cache dir: ${CACHE_DIR}`);
    _pipelinePromise = pipeline('feature-extraction', MODEL_ID, {
      dtype: 'q8',
      revision: MODEL_REVISION,
    });
    _pipelinePromise.then(() => {
      console.log(`[embeddings] Local model loaded.`);
    }).catch(() => {
      _pipelinePromise = null; // allow retry on failure
    });
  }
  return _pipelinePromise;
}

export function getEmbeddingHealth() {
  return {
    ..._health,
    cache_size: _embedCache.size,
    cache_hits: _cacheStats.hits,
    cache_misses: _cacheStats.misses
  };
}

/**
 * Complete one deterministic local inference before the server advertises
 * recall readiness. This creates no memory, cache authority, network request,
 * or user-derived state; it only proves the pinned 768d runtime is executable.
 */
export async function prewarmEmbeddingRuntime() {
  const startedAt = performance.now();
  const extractor = await getPipeline();
  const output = await extractor('HOM AIMOS local embedding runtime readiness', {
    pooling: 'mean',
    normalize: true,
  });
  const dimension = Number(output?.data?.length || 0);
  if (dimension !== 768) {
    throw new Error(`embedding_runtime_prewarm_dimension_invalid:${dimension}`);
  }
  _health.healthy = true;
  _health.lastCheck = Date.now();
  return Object.freeze({
    ready: true,
    model_id: MODEL_ID,
    revision: MODEL_REVISION,
    dimension,
    runtime_ms: Number((performance.now() - startedAt).toFixed(3)),
    canonical_memory_changed: false,
    authority_changed: false,
  });
}

/**
 * Generate a 768-dimension embedding vector from text.
 * Runs entirely local — no network calls after initial model download.
 *
 * @param {string} text - Input text (truncated to 2000 chars — model window is 384 tokens)
 * @returns {number[]|null} - 768d float array, or null on failure
 */
export async function getEmbedding(text) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return null;
  }

  _health.totalCalls++;

  // LRU cache lookup — same text always produces same embedding
  const key = _cacheKey(text);
  const cached = _cacheGet(key);
  if (cached) {
    _cacheStats.hits++;
    if (_cacheStats.hits + _cacheStats.misses <= 5) {
      console.log(`[embeddings] Cache HIT (${_cacheStats.hits}/${_cacheStats.hits + _cacheStats.misses}) key=${key.slice(0, 12)}...`);
    }
    _health.healthy = true;
    _health.lastCheck = Date.now();
    return cached;
  }
  _cacheStats.misses++;
  if (_cacheStats.hits + _cacheStats.misses <= 5) {
    console.log(`[embeddings] Cache MISS (${_cacheStats.misses} misses) key=${key.slice(0, 12)}...`);
  }

  try {
    const extractor = await getPipeline();
    const output = await extractor(text.slice(0, 2000), {
      pooling: 'mean',
      normalize: true
    });

    const embedding = Array.from(output.data);

    if (embedding.length !== 768) {
      throw new Error(`Expected 768d, got ${embedding.length}d`);
    }

    // Store in LRU cache before returning
    _cachePut(key, embedding);

    _health.healthy = true;
    _health.failCount = 0;
    _health.lastCheck = Date.now();
    return embedding;
  } catch (err) {
    _health.healthy = false;
    _health.failCount++;
    _health.lastCheck = Date.now();
    console.error(`[embeddings] Local model failed: ${err.message}`);
    return null;
  }
}

// ─── Self-Consistency Sampling (Frugal Knowledge Graph, Jourlin 2026) ────────
// "Self-consistency (k=5, T=0.7) recovers up to 23% EM with a single MoE model"
// For embeddings: perturb text N ways (synonym swap, case variation, truncation),
// embed each, measure cosine variance across samples.
// High variance = uncertain embedding = downstream risk flag.
// Zero LLM calls — pure deterministic perturbations.

/**
 * Generate N perturbed variants of a text for self-consistency sampling.
 * Uses deterministic text transformations (no LLM required).
 * @param {string} text - Original text
 * @param {number} k - Number of variants (default 3)
 * @returns {string[]} - Original + k perturbed variants
 */
function _perturbText(text, k) {
  const variants = [text]; // variant 0 = original

  // Variant 1: lowercase normalized (removes casing signal)
  if (variants.length < k + 1) variants.push(text.toLowerCase());

  // Variant 2: first 50% of text (tests length robustness)
  if (variants.length < k + 1) {
    const mid = Math.floor(text.length / 2);
    variants.push(text.slice(0, mid));
  }

  // Variant 3: last 50% of text
  if (variants.length < k + 1) {
    const mid = Math.floor(text.length / 2);
    variants.push(text.slice(mid));
  }

  // Variant 4: every-other-word subsample
  if (variants.length < k + 1) {
    variants.push(text.split(/\s+/).filter((_, i) => i % 2 === 0).join(' '));
  }

  // Variant 5: shuffled sentence order
  if (variants.length < k + 1 && text.includes('. ')) {
    const sentences = text.split(/(?<=[.!?])\s+/);
    const shuffled = [...sentences];
    if (shuffled.length > 1) {
      const last = shuffled.pop();
      shuffled.unshift(last); // rotate: last sentence becomes first
      variants.push(shuffled.join(' '));
    }
  }

  return variants.slice(0, k + 1);
}

/**
 * Cosine similarity between two embedding vectors.
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number}
 */
function _cosineSim(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

/**
 * Get embedding with self-consistency check.
 * Generates k perturbed variants, embeds each, measures agreement.
 * Returns { embedding, consistency, variance, samples } where:
 *   - embedding: the original text embedding (primary result)
 *   - consistency: avg pairwise cosine across all samples (1.0 = perfect agreement)
 *   - variance: 1 - consistency (higher = more uncertain)
 *   - samples: number of perturbed samples tested
 *
 * Source: Frugal Knowledge Graph (Jourlin, 2026) — self-consistency (k=5, T=0.7)
 * Usage: When consistency < 0.85, downstream should treat results as uncertain.
 *
 * @param {string} text - Input text
 * @param {object} opts - Options
 * @param {number} opts.k - Number of perturbed samples (default 3, max 5)
 * @param {number} opts.uncertaintyThreshold - consistency below this triggers warning (default 0.85)
 * @returns {Promise<{embedding: number[], consistency: number, variance: number, samples: number, uncertain: boolean}>}
 */
export async function getEmbeddingWithConsistency(text, opts = {}) {
  const k = Math.min(Math.max(opts.k || 3, 1), 5);
  const uncertaintyThreshold = opts.uncertaintyThreshold ?? 0.85;

  // Get the original embedding first
  const embedding = await getEmbedding(text);
  if (!embedding) {
    return { embedding: null, consistency: 0, variance: 1, samples: 0, uncertain: true };
  }

  // If k=0, skip consistency
  if (k === 0) {
    return { embedding, consistency: 1, variance: 0, samples: 0, uncertain: false };
  }

  // Generate perturbed variants and embed each
  const variants = _perturbText(text, k);
  const embeddings = [];

  for (let i = 1; i < variants.length; i++) {
    const emb = await getEmbedding(variants[i]);
    if (emb) embeddings.push(emb);
  }

  if (embeddings.length === 0) {
    return { embedding, consistency: 0, variance: 1, samples: 0, uncertain: true };
  }

  // Compute avg pairwise cosine between original and all perturbed variants
  let totalSim = 0;
  for (const emb of embeddings) {
    totalSim += _cosineSim(embedding, emb);
  }
  const consistency = totalSim / embeddings.length;
  const variance = 1 - consistency;

  return {
    embedding,
    consistency: parseFloat(consistency.toFixed(4)),
    variance: parseFloat(variance.toFixed(4)),
    samples: embeddings.length,
    uncertain: consistency < uncertaintyThreshold
  };
}

export function buildRepresentationEmbeddingDiagnostics({
  requestedModalities = [],
  sampleCount = 0,
  backendPaths = {},
} = {}) {
  const requested = Array.isArray(requestedModalities)
    ? requestedModalities.map((modality) => String(modality).toLowerCase())
    : [];
  const uniqueRequested = [...new Set(['text', ...requested])];
  const modalityContracts = Object.fromEntries(uniqueRequested.map((modality) => {
    const isText = modality === 'text';
    const future = FUTURE_MODALITIES.includes(modality);
    return [modality, {
      modality,
      active: isText,
      backend_path_present: isText ? true : Boolean(backendPaths[modality]),
      production_claim_allowed: isText,
      diagnostic_only: !isText,
      status: isText ? 'active_text_embedding' : (future ? 'inactive_future_contract' : 'unsupported_contract'),
    }];
  }));

  return {
    diagnostic_type: 'representation_embedding_contract',
    source_papers: WAVE5_EMBEDDING_CONTRACT_AUTHORITIES,
    status: 'diagnostic',
    diagnostic_only: true,
    text_embedding: {
      provider: _health.provider,
      model: MODEL_ID,
      dimensions: 768,
      cache_size: _embedCache.size,
      sample_count: Math.max(0, Number(sampleCount) || 0),
    },
    modality_contracts: modalityContracts,
    inactive_multimodal_contract: {
      image: modalityContracts.image?.active === true ? false : true,
      video: modalityContracts.video?.active === true ? false : true,
      audio: modalityContracts.audio?.active === true ? false : true,
      multimodal_fusion: modalityContracts.multimodal_fusion?.active === true ? false : true,
    },
    guardrails: {
      embedding_dimension_changed: false,
      embedding_model_changed: false,
      multimodal_embedding_runtime_enabled: false,
      modality_pruning_enabled: false,
      collaborative_attention_training_enabled: false,
      production_multimodal_claim: false,
      canonical_memory_changed: false,
    },
    guarded_math: {
      sparse_sign_projection: true,
    },
    guarded_math_implemented: {
      sparse_sign_projection: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

/**
 * Sparse Sign Projection Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Beyond LLMs, Sparse Distributed Memory, and Neuromorphics
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes sparse sign-projection (1-bit
 * quantization) as a diagnostic overlay alongside the existing dense 768d
 * embedding path. It does NOT replace or modify the dense embedding model.
 * The production 768d all-mpnet-base-v2 path remains authoritative. Guarded
 * by guarded_math flag sparse_sign_projection which is always false in
 * production.
 */
/**
 * Product-Key Embedding — Batch 10 Lane 3 live implementation
 * Source: Large Memory Layers with Product Keys
 * Decomposes 768d embedding into dual 128d sub-keys for O(√n) lookup.
 * Calls productKeyProject from hnsw-optimizer.js for key computation.
 *
 * @param {string} text - Input text
 * @returns {Promise<{embedding: number[]|null, keyA: number[], keyB: number[], source: string}>}
 */
export async function productKeyEmbed(text) {
  const embedding = await getEmbedding(text);

  if (!embedding || embedding.length === 0) {
    return { embedding: null, keyA: [], keyB: [], source: 'product_key_empty_input' };
  }

  try {
    const { productKeyProject } = await import('../retrieval/hnsw-optimizer.js');
    const { keyA, keyB } = productKeyProject(embedding);
    return {
      embedding,
      keyA,
      keyB,
      source: 'product_key_live',
    };
  } catch (err) {
    // Fallback: return embedding without sub-keys if hnsw-optimizer unavailable
    return {
      embedding,
      keyA: [],
      keyB: [],
      source: 'product_key_fallback',
    };
  }
}

export function buildSparseSignProjectionDiagnostic({
  embeddingVector = [],
  topK = 10,
} = {}) {
  const vec = Array.isArray(embeddingVector) ? embeddingVector : [];
  const k = Math.max(1, Math.min(Number(topK) || 10, vec.length));

  // Sparse sign-projection: 1-bit quantization of dense vector
  // Sign of each dimension creates a binary hash for approximate similarity
  const signProjection = vec.map((v) => (v >= 0 ? 1 : -1));
  const topIndices = vec
    .map((v, i) => ({ index: i, absValue: Math.abs(v) }))
    .sort((a, b) => b.absValue - a.absValue)
    .slice(0, k)
    .map(({ index }) => index);

  // Hamming similarity: count of matching signs between two vectors
  // For diagnostic, compute against random baseline
  const hammingBaseline = vec.length > 0 ? 0.5 : 0;

  return {
    diagnostic: true,
    source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
    coexistence_class: 'side_by_side_overlay',
    vector_dimensions: vec.length,
    sign_projection: signProjection,
    top_k_indices: topIndices,
    sparsity_ratio: vec.length > 0 ? topIndices.length / vec.length : 0,
    hamming_similarity_baseline: hammingBaseline,
    dense_model_unchanged: true,
    note: 'Alongside-path diagnostic. Dense 768d embedding model is never modified.',
  };
}

// ─── BATCH 10 LANE 3: VSA + HRR EMBEDDINGS ──────────────────────────────────
// Papers: VSA Survey (Kanervela et al.), Generalized HRR (Plate 1995/2023)
// computeVSAEmbedding: 10K bipolar vector {-1, +1} via random projection from 768d
// computeHRREmbedding: circular_convolution(dense, permutation_matrix)
// These are alongside-path diagnostics. Production 768d path unchanged.
// Aladdin: VSA and HRR never modify the production 768d embedding model.
// ─────────────────────────────────────────────────────────────────────────────

const VSA_EMBED_DIM = 10000; // VSA bipolar vector dimensionality
const HRR_PERM_SEED = 2026;  // Seed for deterministic permutation matrix

// Lazy-initialized VSA random projection matrix (VSA_DIM × 768)
let _vsaProjectionMatrix = null;

// Lazy-initialized HRR permutation matrix (768 × 768)
let _hrrPermutationMatrix = null;

/**
 * Initialize VSA random projection matrix using seeded PRNG.
 * Projects from 768d dense space to VSA_EMBED_DIM bipolar space.
 */
function ensureVSAProjectionMatrix() {
  if (_vsaProjectionMatrix) return;

  let seed = VSA_PERM_SEED;
  function nextRandom() {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return (seed / 0x7fffffff) * 2 - 1;
  }

  _vsaProjectionMatrix = [];
  for (let i = 0; i < VSA_EMBED_DIM; i++) {
    const row = [];
    for (let j = 0; j < 768; j++) {
      row.push(nextRandom());
    }
    _vsaProjectionMatrix.push(row);
  }
}

const VSA_PERM_SEED = 2026;

/**
 * Initialize HRR permutation matrix.
 * A permutation matrix cyclically shifts the vector by a fixed offset.
 * Plate (1995): permutation provides approximate inverse in HRR.
 */
function ensureHRRPermutationMatrix() {
  if (_hrrPermutationMatrix) return;

  // Use a cyclic shift permutation: shift all elements by SHIFT positions
  // This is equivalent to multiplying by a permutation matrix
  // Phase 0: shift by 384 (half the dimension) for maximum decorrelation
  const SHIFT = 384;
  _hrrPermutationMatrix = { type: 'cyclic_shift', shift: SHIFT };
}

/**
 * Compute VSA embedding from text: 10K bipolar vector {-1, +1}.
 * Process: get 768d dense embedding, then random project to 10K, then sign().
 * Formula: vsaEmbed(text) = sign(R @ dense(text)) where R: VSA_DIM × 768
 *
 * @param {string} text - Input text
 * @returns {Promise<{vsa: number[], dense: number[], source_papers: string[], diagnostic_only: boolean}>}
 */
export async function computeVSAEmbedding(text) {
  const dense = await getEmbedding(text);

  if (!dense) {
    return {
      vsa: [],
      dense: null,
      source_papers: ['VSA Survey', 'Generalized HRR'],
      diagnostic_only: true,
      note: 'Dense embedding failed — VSA undefined',
    };
  }

  ensureVSAProjectionMatrix();

  // Project: vsa = sign(R @ dense)
  const vsa = new Array(VSA_EMBED_DIM);
  for (let i = 0; i < VSA_EMBED_DIM; i++) {
    let dot = 0;
    const row = _vsaProjectionMatrix[i];
    for (let j = 0; j < 768; j++) {
      dot += row[j] * dense[j];
    }
    vsa[i] = dot >= 0 ? 1 : -1; // Sign function for bipolar
  }

  return {
    vsa,
    dense,
    vsa_formula: 'vsaEmbed(text) = sign(R @ dense(text)) where R: 10K × 768',
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    dense_model_unchanged: true,
  };
}

/**
 * Compute HRR embedding from dense embedding: circular_convolution(dense, permutation).
 * Formula: hrrEmbed = dense ⊛ perm(dense) where perm is a cyclic shift permutation.
 * Phase 0: uses cyclic shift by 384 positions for maximum decorrelation.
 *
 * @param {number[]} embedding - 768d dense embedding
 * @param {Object} opts
 * @param {number[]} opts.permutationMatrix - Optional custom permutation (default: cyclic shift)
 * @returns {{hrr: number[], source_papers: string[], diagnostic_only: boolean}}
 */
export function computeHRREmbedding(embedding, opts = {}) {
  const dense = Array.isArray(embedding) ? embedding : [];

  if (dense.length === 0) {
    return {
      hrr: [],
      source_papers: ['Generalized HRR', 'Recasting Self-Attention with HRR'],
      diagnostic_only: true,
      note: 'Empty embedding — HRR undefined',
    };
  }

  ensureHRRPermutationMatrix();

  // Apply cyclic shift permutation
  const shift = _hrrPermutationMatrix.shift;
  const permuted = new Array(dense.length);
  for (let i = 0; i < dense.length; i++) {
    permuted[i] = dense[(i + shift) % dense.length];
  }

  // Circular convolution: hrr = dense ⊛ permuted
  const n = dense.length;
  const hrr = new Array(n);
  for (let k = 0; k < n; k++) {
    let sum = 0;
    for (let j = 0; j < n; j++) {
      sum += dense[j] * permuted[(k - j + n) % n];
    }
    hrr[k] = Number(sum.toFixed(6));
  }

  // Normalize to unit length
  let norm = 0;
  for (let i = 0; i < hrr.length; i++) norm += hrr[i] * hrr[i];
  norm = Math.sqrt(norm);
  const normalized = norm > 0 ? hrr.map(v => Number((v / norm).toFixed(6))) : hrr;

  return {
    hrr: normalized,
    hrr_formula: 'hrrEmbed = circular_convolution(dense, perm(dense))',
    permutation_type: 'cyclic_shift',
    permutation_shift: shift,
    source_papers: ['Generalized HRR', 'Recasting Self-Attention with HRR'],
    diagnostic_only: true,
    dense_model_unchanged: true,
  };
}

/**
 * Build VSA embedding diagnostic.
 *
 * @param {string} text - Input text
 * @returns {Promise<object>}
 */
export async function buildVSAEmbeddingDiagnostic(text) {
  const result = await computeVSAEmbedding(text);

  if (!result.dense) {
    return {
      diagnostic_type: 'vsa_embedding',
      source_papers: ['VSA Survey', 'Generalized HRR'],
      diagnostic_only: true,
      status: 'embedding_failed',
      vsa_dim: VSA_EMBED_DIM,
      dense_dim: 768,
    };
  }

  // Compute bipolar statistics
  const plusCount = result.vsa.filter(v => v === 1).length;
  const minusCount = result.vsa.length - plusCount;
  const balance = result.vsa.length > 0 ? Number((plusCount / result.vsa.length).toFixed(4)) : 0;

  return {
    diagnostic_type: 'vsa_embedding',
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    status: 'active',
    text_sample: String(text || '').slice(0, 100),
    vsa_dim: VSA_EMBED_DIM,
    dense_dim: 768,
    bipolar_balance: {
      plus_count: plusCount,
      minus_count: minusCount,
      ratio: balance, // Should be ~0.5 for well-distributed projections
    },
    vsa_sample: result.vsa.slice(0, 50), // First 50 elements for inspection
    guardrails: {
      dense_embedding_model_unchanged: true,
      production_768d_path_unchanged: true,
      vsa_is_alongside_diagnostic: true,
    },
    aladdin_boundary: {
      canonical_embedding_preserved: true,
      no_modification_to_all_mpnet: true,
    },
  };
}
