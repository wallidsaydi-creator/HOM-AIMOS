/**
 * scale-baseline.js — Dynamic Scale Adaptation for Aimos Memory Services
 *
 * MEMORY_COUNT_BASELINE = 14000 is a reference point, NOT a hard cap.
 * All formulas adapt dynamically to the actual memory count via getScaleRatio().
 * At N=14000, every formula returns its original hardcoded value (backward compatible).
 *
 * Papers: MEMORYLLM (G-MemLLM block capacity, latent gate thresholds),
 *         Bridging Philosophy and Machine Learning (trust normalization ceilings, structural alignment),
 *         Coarsening Dynamics (dormancy thresholds, reactivation counts, LSM compaction),
 *         IM-PINN (intrinsic-metric retrieval distance, reaction-diffusion consolidation),
 *         Differentiable Hybrid Force Fields (calibration triggers, Bloom filter budgets),
 *         Differentiable Symbolic Planning (RRF weight rebalancing at scale),
 *         Epistemology of Generative AI (concentration of measure validates multi-signal RRF),
 *         From WiscKey to Bourbon (memtable batching, learned index scale),
 *         WiscKey / BVLSM (key/value separation thresholds, Bloom filter FPR)
 *
 * Aladdin: Scale formulas only affect activation weights, retrieval ordering,
 *           and compression ratios. No deletion, no suppression, no pruning.
 *           W_MIN = 0.1 floor on all weights; neutral reference = 1.0.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: plasticity-controller.js (BLOCK_CAPACITY)
 * 2. ← Called by: trust-score.js (normalization ceilings)
 * 3. ← Called by: dormancy-manager.js (DORMANCY_THRESHOLD, REACTIVATION_COUNT, ceilings)
 * 4. ← Called by: mvs-detector.js (MVS_THRESHOLD)
 * 5. ← Called by: persist-memory.js (MEMTABLE_BATCH_SIZE, BLOOM_FILTER_TARGET_FPR)
 * 6. ← Called by: adaptive-early-exit.js (scale ratio)
 * 7. ← Called by: multi-stage-retrieval.js (W_VEC, W_TXT, W_INFINI)
 * 8. ← Called by: context-builder.js (W_INFINI)
 * 9. → Reads from: db/connection.js (getMemoryCount)
 * Pipeline: SHARED | Position: scale adaptation (cross-cutting)
 *
 * Created: 2026-05-04 (Batch 10.7 Lane 7, Phase 1)
 */

import { query } from '../../db/connection.js';

// ─── REFERENCE BASELINE ───────────────────────────────────────────────────────
// 14000 is the calibration point where hardcoded constants were originally tuned.
// All scale-adaptive functions use getScaleRatio() = actual_count / 14000.
// At exactly 14000 memories, every formula returns its original value.

export const MEMORY_COUNT_BASELINE = 14000;

// ─── PROCESS-SCOPED CACHE ──────────────────────────────────────────────────────
// Refreshed periodically so formulas stay current without hitting DB every call.

let _cachedMemoryCount = 14000;
let _cachedAt = 0;
const CACHE_TTL_MS = 60_000; // Refresh every 60 seconds

/**
 * Get the current active memory count from the database.
 * Falls back to cached value or baseline on DB errors.
 *
 * @param {string} [companyId] - Optional company filter
 * @returns {Promise<number>} Active memory count
 */
export async function getMemoryCount(companyId) {
  const now = Date.now();
  if (now - _cachedAt < CACHE_TTL_MS) {
    return _cachedMemoryCount;
  }

  try {
    const result = await query(
      `SELECT COUNT(*) AS cnt FROM aimos_memories WHERE TRUE${
        companyId ? ' AND company_id = $1' : ''
      }`,
      companyId ? [companyId] : []
    );
    const count = parseInt(result.rows[0]?.cnt || 0, 10);
    if (count > 0) {
      _cachedMemoryCount = count;
      _cachedAt = now;
    }
  } catch (err) {
    // DB unavailable — use cached or baseline
    console.warn('[scale-baseline] getMemoryCount DB error, using cached:', err.message);
  }

  return _cachedMemoryCount;
}

/**
 * Get the scale ratio relative to the 14K baseline.
 * ratio = actual_count / 14000
 * At 14K memories → ratio = 1.0 (all formulas identical to hardcoded originals)
 * At 50K memories → ratio ≈ 3.57
 * At 100K memories → ratio ≈ 7.14
 *
 * @param {number} [memoryCount] - Override memory count (for testing or synchronous use)
 * @returns {number} Scale ratio ≥ 1.0
 */
export function getScaleRatio(memoryCount) {
  const count = Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE;
  return Math.max(1.0, count / MEMORY_COUNT_BASELINE);
}

// ─── BLOCK CAPACITY ────────────────────────────────────────────────────────────
// Paper: G-MemLLM, M+
// BLOCK_CAPACITY(L, N) = floor(BASE_CAPACITY[L] * max(1, sqrt(scaleRatio)))
// At 14K: L1=100, L2=50, L3=30, L4=10, L5=5 (unchanged)
// At 50K: L1=189, L2=95, L3=57, L4=19, L5=9
// At 100K: L1=267, L2=134, L3=80, L4=27, L5=13

const BASE_BLOCK_CAPACITY = Object.freeze({
  L1: 100,   // Short-term memory
  L2: 50,    // Working memory
  L3: 30,    // Episodic memory
  L4: 10,    // Semantic memory
  L5: 5,     // Long-term memory
});

/**
 * Get scale-adaptive block capacity for a memory level.
 * At N=14000, returns original hardcoded values.
 *
 * @param {string} level - L1, L2, L3, L4, or L5
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Block capacity for the given level
 */
export function getBlockCapacity(level, memoryCount) {
  const base = BASE_BLOCK_CAPACITY[level] || BASE_BLOCK_CAPACITY.L3;
  const scaleRatio = getScaleRatio(memoryCount);
  const scaleMultiplier = Math.max(1.0, Math.sqrt(scaleRatio));
  return Math.max(1, Math.floor(base * scaleMultiplier));
}

/**
 * Get the full scale-adaptive BLOCK_CAPACITY object.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {Object} { L1, L2, L3, L4, L5 }
 */
export function getBlockCapacityAll(memoryCount) {
  return {
    L1: getBlockCapacity('L1', memoryCount),
    L2: getBlockCapacity('L2', memoryCount),
    L3: getBlockCapacity('L3', memoryCount),
    L4: getBlockCapacity('L4', memoryCount),
    L5: getBlockCapacity('L5', memoryCount),
  };
}

// ─── TRUST NORMALIZATION CEILINGS ──────────────────────────────────────────────
// Paper: Bridging Philosophy and Machine Learning
// At 14K: access_ceil=100, crossref_ceil=20 (unchanged)
// At 50K: access_ceil=357, crossref_ceil=71
// At 100K: access_ceil=714, crossref_ceil=143

/**
 * Scale-adaptive maximum access frequency for normalization.
 * max(100, floor(N / 140))
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getMaxAccessNormalization(memoryCount) {
  const count = Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE;
  return Math.max(100, Math.floor(count / 140));
}

/**
 * Scale-adaptive maximum cross-reference count for normalization.
 * max(20, floor(N / 700))
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getMaxCrossRefNormalization(memoryCount) {
  const count = Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE;
  return Math.max(20, Math.floor(count / 700));
}

// ─── MVS THRESHOLD ──────────────────────────────────────────────────────────────
// Paper: G-MemLLM, Coarsening Dynamics
// At higher N, retrieval space is denser → lower threshold → more memories pass the gate.
// MVS_THRESHOLD(N) = 0.42 * max(0.85, min(1.0, 1.0 - 0.05 * log2(scaleRatio)))
// At 14K: 0.42 (unchanged)
// At 50K: ≈ 0.381
// At 100K: ≈ 0.363

/**
 * Scale-adaptive MVS threshold.
 * Decreases with N because denser space needs lower gate threshold.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} MVS threshold in [0.357, 0.42]
 */
export function getMVSThreshold(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  const factor = Math.max(0.85, Math.min(1.0, 1.0 - 0.05 * Math.log2(scaleRatio)));
  return 0.42 * factor;
}

// ─── DORMANCY THRESHOLD ────────────────────────────────────────────────────────
// Paper: Coarsening Dynamics, Bridging Philosophy
// At higher N, more candidates for modulation → higher threshold → fewer go dormant.
// DORMANCY_THRESHOLD(N) = 0.25 * max(0.85, min(1.15, 1.0 + 0.05 * log2(scaleRatio)))
// At 14K: 0.25 (unchanged)
// At 50K: ≈ 0.273
// At 100K: ≈ 0.284

/**
 * Scale-adaptive dormancy threshold.
 * Increases with N because more memories means more candidates for frequency modulation.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Dormancy threshold in [0.2125, 0.2875]
 */
export function getDormancyThreshold(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  const factor = Math.max(0.85, Math.min(1.15, 1.0 + 0.05 * Math.log2(scaleRatio)));
  return 0.25 * factor;
}

// ─── REACTIVATION COUNT ────────────────────────────────────────────────────────
// Paper: Coarsening Dynamics
// At higher N, more partial activations needed before reactivation.
// REACTIVATION_COUNT(N) = max(3, min(10, floor(3 * scaleRatio^0.3)))
// At 14K: 3 (unchanged)
// At 50K: 5
// At 100K: 6

/**
 * Scale-adaptive reactivation activation count.
 * More activations required at higher memory counts.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Reactivation count in [3, 10]
 */
export function getReactivationCount(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  return Math.max(3, Math.min(10, Math.floor(3 * Math.pow(scaleRatio, 0.3))));
}

// ─── LSM THRESHOLDS ─────────────────────────────────────────────────────────────
// Paper: WiscKey, BVLSM, Optimal Bloom Filters

/**
 * Scale-adaptive memtable batch size.
 * max(100, floor(100 * scaleRatio^0.5))
 * At 14K: 100 (unchanged)
 * At 50K: 189
 * At 100K: 267
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getMemtableBatchSize(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  return Math.max(100, Math.floor(100 * Math.pow(scaleRatio, 0.5)));
}

/**
 * Scale-adaptive Bloom filter target false positive rate.
 * max(0.005, min(0.02, 0.01 * scaleRatio^0.3))
 * At 14K: 0.01 (unchanged)
 * At 50K: ≈ 0.014
 * At 100K: ≈ 0.016
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getBloomFilterTargetFPR(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  return Math.max(0.005, Math.min(0.02, 0.01 * Math.pow(scaleRatio, 0.3)));
}

// ─── RRF WEIGHTS ────────────────────────────────────────────────────────────────
// Paper: Epistemology (concentration of measure), Infini-attention
// At higher N, Infini-attention linear memory becomes more valuable.
// W_INFINI(N) = 0.20 * min(1.5, max(1.0, scaleRatio^0.15))
// W_VEC(N) = 0.55 - (W_INFINI(N) - 0.20) * 0.6
// W_TXT() = 0.25 (constant)
// At 14K: W_VEC=0.55, W_TXT=0.25, W_INFINI=0.20 (unchanged, sum=1.0)
// At 50K: W_VEC≈0.52, W_TXT=0.25, W_INFINI≈0.23 (sum≈1.0)
// At 100K: W_VEC≈0.49, W_TXT=0.25, W_INFINI≈0.26 (sum≈1.0)

/**
 * Scale-adaptive Infini-attention RRF weight.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getW_INFINI(memoryCount) {
  const scaleRatio = getScaleRatio(memoryCount);
  return 0.20 * Math.min(1.5, Math.max(1.0, Math.pow(scaleRatio, 0.15)));
}

/**
 * Scale-adaptive vector search RRF weight.
 * Compensates for Infini-attention weight increase.
 * W_VEC = 0.75 - W_INFINI, so W_VEC + W_TXT + W_INFINI = 1.0 at all scales.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number}
 */
export function getW_VEC(memoryCount) {
  return 0.75 - getW_INFINI(memoryCount);
}

/**
 * Scale-adaptive BM25/text search RRF weight.
 * Constant at 0.25 regardless of scale.
 *
 * @returns {number}
 */
export function getW_TXT() {
  return 0.25;
}

// ─── DIAGNOSTIC HELPERS ─────────────────────────────────────────────────────────

/**
 * Build a diagnostic snapshot of all scale-adaptive parameters for a given memory count.
 * Useful for verifying backward compatibility and scale behavior.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {Object} All scale parameters at the given N
 */
export function buildScaleBaselineDiagnostic(memoryCount) {
  const count = Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE;
  const scaleRatio = getScaleRatio(count);

  return {
    source_papers: ['MEMORYLLM', 'Bridging Philosophy', 'Coarsening Dynamics', 'IM-PINN', 'Differentiable Hybrid Force Fields', 'Differentiable Symbolic Planning'],
    diagnostic_only: true,
    memory_count: count,
    memory_count_baseline: MEMORY_COUNT_BASELINE,
    scale_ratio: Number(scaleRatio.toFixed(6)),
    scale_multiplier_sqrt: Number(Math.sqrt(scaleRatio).toFixed(6)),
    parameters: {
      block_capacity: getBlockCapacityAll(count),
      max_access_normalization: getMaxAccessNormalization(count),
      max_cross_ref_normalization: getMaxCrossRefNormalization(count),
      mvs_threshold: Number(getMVSThreshold(count).toFixed(6)),
      dormancy_threshold: Number(getDormancyThreshold(count).toFixed(6)),
      reactivation_count: getReactivationCount(count),
      memtable_batch_size: getMemtableBatchSize(count),
      bloom_filter_target_fpr: Number(getBloomFilterTargetFPR(count).toFixed(6)),
      rrf_weights: {
        W_VEC: Number(getW_VEC(count).toFixed(6)),
        W_TXT: getW_TXT(),
        W_INFINI: Number(getW_INFINI(count).toFixed(6)),
        sum: Number((getW_VEC(count) + getW_TXT() + getW_INFINI(count)).toFixed(6)),
      },
      hybrid_recall_alphas: {
        recency: Number(getRecencyAlpha(count).toFixed(6)),
        semantic: Number(getSemanticAlpha(count).toFixed(6)),
        sum: Number((getRecencyAlpha(count) + getSemanticAlpha(count)).toFixed(6)),
      },
      event_window_hours: getEventWindowHours(count),
    },
    backward_compatible: count === MEMORY_COUNT_BASELINE,
    aladdin: 'scale_formulas_only_affect_activation_weights_and_retrieval_ordering_no_deletion',
  };
}

// ─── PROVIDER RESILIENCE SCALE PARAMETERS ───────────────────────────────────────
// Source: Circuit Breaker (Netflix Hystrix), Release It (Nygard), Google SRE
// Provider failure thresholds, cooldown periods, and latency neutral points
// scale with memory count. At N=14000, all formulas return original values.

/**
 * Provider circuit breaker failure threshold.
 * At 14K: 5 failures. At 100K: ~6-8 failures (more tolerant at scale).
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Failure threshold
 */
export function getProviderFailureThreshold(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  return Math.max(3, Math.min(10, Math.floor(5 * Math.pow(N / 14000, 0.1))));
}

/**
 * Provider circuit breaker cooldown in milliseconds.
 * At 14K: 30s. At 100K: ~42-60s (longer recovery window at scale).
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Cooldown in milliseconds
 */
export function getProviderCooldownMs(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  return Math.min(120_000, Math.max(15_000, Math.floor(30_000 * Math.pow(N / 14000, 0.2))));
}

/**
 * Provider health latency neutral point in milliseconds.
 * Below this latency, no penalty. Above, penalty increases quadratically.
 * At 14K: 2000ms. At 100K: 3000ms.
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Latency neutral point in ms
 */
export function getProviderLatencyNeutralMs(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  return Math.max(2000, 2000 + 1000 * Math.min(1, Math.log2(Math.max(1, N / 14000))));
}

// ─── HYBRID RECALL ALPHA WEIGHTS ──────────────────────────────────────────────
// Paper: RRF (Reciprocal Rank Fusion), MEMORYLLM (block capacity gating)
// At higher N, semantic similarity matters more because recency alone
// surfaces too many irrelevant recent memories in dense space.
// α_recency(N) = 0.35 * max(0.7, (14000/N)^0.1)
// At 14K: 0.35 (unchanged). At 50K: ~0.31. At 100K: ~0.30.
// α_semantic(N) = 1.0 - α_recency(N) — always sums to 1.0.

/**
 * Scale-adaptive recency alpha for hybrid recall scoring.
 * Decreases with N because semantic relevance matters more in dense spaces.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Recency weight in [0.245, 0.35]
 */
export function getRecencyAlpha(memoryCount) {
  const N = Math.max(1, Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE);
  return 0.35 * Math.max(0.7, Math.pow(14000 / N, 0.1));
}

/**
 * Scale-adaptive semantic alpha for hybrid recall scoring.
 * Increases with N because semantic relevance matters more in dense spaces.
 * Always satisfies: getRecencyAlpha(N) + getSemanticAlpha(N) = 1.0
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Semantic weight in [0.65, 0.755]
 */
export function getSemanticAlpha(memoryCount) {
  return 1.0 - getRecencyAlpha(memoryCount);
}

// ─── EVENT WINDOW HOURS ────────────────────────────────────────────────────────
// Gap 2: Aimos Events Bridge — memory-of-saving loop
// At higher N, more history is useful because the agent has more recent operations.
// getEventWindowHours(N) = min(72, max(24, floor(24 * (N/14000)^0.2)))
// At 14K: 24h. At 50K: ~30h. At 100K: ~36h. At 500K: ~48h.

/**
 * Scale-adaptive event lookback window in hours.
 * Increases with N because more history is useful at scale.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Hours to look back for recent events [24, 72]
 */
export function getEventWindowHours(memoryCount) {
  const N = Math.max(1, Number(memoryCount) || _cachedMemoryCount || MEMORY_COUNT_BASELINE);
  return Math.min(72, Math.max(24, Math.floor(24 * Math.pow(N / 14000, 0.2))));
}
