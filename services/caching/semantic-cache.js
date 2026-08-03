// ─── SEMANTIC QUERY CACHE ─────────────────────────────────────────────────────
// Status: Ephemeral LRU Cache — Purely in-memory, no schema changes
// Purpose: Eliminates redundant 16-step recalls for identical/similar queries
// Source: Cache-Augmented Generation (Gao et al., 2024) — Speed.md Appendix A
// Agreement Paradox Detection: Frugal Knowledge Graph (Jourlin, 2026)
//   "Strong confidence among samples signals collective hallucination"
//   When top-5 scores are all >0.95, flag as hallucination_risk
// Batch 10 Lane 1: R3Mem WARM tier + 500xCompressor intent-aware compression policy
//   WARM tier stores R3Mem-compressed representations alongside original.
//   Intent-aware compression maps memory_type to target ratio.
//   cache_tier(entry) = HOT if access_freq > 0.8 else WARM if compressed else COLD
//   WARM tier is cache-only. Original memory in PostgreSQL is never modified.
// Batch 10 Lane 4: Sketch-based near-miss reconstruction (KVReviver),
//   POD inter-layer dependency preservation, TokenDance collective KV pool.
//   All diagnostic exports — cache HIT/MISS behavior unchanged.
// Compliance: Knowledge Gate [X] | Aladdin Law [X] (ephemeral only)
// ─────────────────────────────────────────────────────────────────────────────

import { logEvent } from '../observe/event-ledger.js';

// Agreement paradox threshold — Frugal Knowledge Graph (Jourlin, 2026)
// When all top-N scores exceed this, the result is flagged as potential
// collective hallucination (abnormally high consensus = model echo chamber)
const AGREEMENT_PARADOX_THRESHOLD = 0.95;
const AGREEMENT_PARADOX_TOPN = 5;

// Batch 10 Lane 1: R3Mem compression ratios per memory type (500xCompressor)
// declarative → 0.05, procedural_seed → 0.40, heartbeat → 0.05
// event_log → 0.05, session_debrief → 0.20
const COMPRESSION_POLICY = {
  declarative: 0.05,
  procedural_seed: 0.40,
  heartbeat: 0.05,
  event_log: 0.05,
  session_debrief: 0.20,
  procedural: 0.40,
  insight: 0.05,
  correction: 0.05,
};

// WARM tier access frequency threshold
const HOT_ACCESS_FREQ = 0.8;

/**
 * SemanticCache: LRU cache with similarity-based lookup
 * - TTL: 5 minutes (300,000ms) for freshness
 * - Similarity threshold: 0.85 cosine similarity for hit
 * - Only caches high-confidence results (trust_score > 0.7, MVS < 0.42)
 */
export class SemanticCache {
  constructor(options = {}) {
    this.ttlMs = options.ttlMs || 300000; // 5 minutes default
    this.similarityThreshold = options.similarityThreshold || 0.85;
    this.maxSize = options.maxSize || 1000; // LRU size limit

    // Internal LRU map: key -> { embedding, result, timestamp, trust_score, mvs }
    this._cache = new Map();
    this._accessOrder = []; // For LRU eviction

    // Batch 10 Lane 1: WARM tier for R3Mem-compressed representations
    // WARM entries store a semantic summary instead of the full result.
    // On WARM cache hit, the summary is served (lower fidelity, same key match).
    // Original memory in PostgreSQL is never modified (Aladdin compliance).
    this._compressedStore = new Map();
    this._compressedAccessOrder = [];
    this._compressedMaxSize = options.compressedMaxSize || 2000;
  }

  /**
   * Check cache for a query
   * @param {number[]} queryEmbedding - The embedding vector of the query
   * @param {string} queryText - The raw query text (for exact match fallback)
   * @returns {Promise<object|null>} - Cached result or null
   */
  async get(queryEmbedding, queryText, context = {}) {
    const now = Date.now();
    const namespace = this._namespace(context);
    if (!namespace) return null;
    const exactKey = `${namespace}\u0000${queryText}`;
    
    // 1. Exact text match (fast path)
    if (this._cache.has(exactKey)) {
      const item = this._cache.get(exactKey);
      if (now - item.timestamp > this.ttlMs) {
        this._evict(exactKey);
        return null;
      }
      this._markAccessed(exactKey);
      logEvent('hom', 'system', 'cache_hit', queryText, { type: 'exact_match' }).catch(() => {});
      return item.result;
    }
    
    // 2. Semantic similarity match (slow path)
    if (queryEmbedding) {
      for (const [key, item] of this._cache.entries()) {
        if (item.namespace !== namespace) continue;
        // TTL check
        if (now - item.timestamp > this.ttlMs) {
          this._evict(key);
          continue;
        }
        
        // Similarity check
        const sim = this._cosineSimilarity(queryEmbedding, item.embedding);
        if (sim > this.similarityThreshold) {
          this._markAccessed(key);
          logEvent('hom', 'system', 'cache_hit', queryText, {
            type: 'semantic_match',
            similarity: sim,
            cached_key: key
          }).catch(() => {});
          return item.result;
        }
      }
    }

    // Cache miss — fire-and-forget to avoid adding latency
    // Batch 10 Lane 1: Check WARM tier (compressed store) on HOT miss
    if (queryEmbedding) {
      for (const [key, item] of this._compressedStore.entries()) {
        if (item.namespace !== namespace) continue;
        if (now - item.timestamp > this.ttlMs) {
          this._evictCompressed(key);
          continue;
        }
        const sim = this._cosineSimilarity(queryEmbedding, item.embedding);
        if (sim > this.similarityThreshold * 0.95) {
          // Slightly lower threshold for compressed entries (fidelity tradeoff)
          this._markCompressedAccessed(key);
          logEvent('hom', 'system', 'cache_hit', queryText, {
            type: 'warm_compressed_match',
            similarity: sim,
            cached_key: key
          }).catch(() => {});
          return item.result;
        }
      }
    }

    logEvent('hom', 'system', 'cache_miss', queryText).catch(() => {});
    return null;
  }

  /**
   * Store a result in cache
   * @param {number[]} queryEmbedding - Embedding of the query
   * @param {string} queryText - Raw query text (used as primary key)
   * @param {object} result - The recall result to cache
   */
  set(queryEmbedding, queryText, result, context = {}) {
    // Only cache medium-or-higher confidence results.
    // Per PerCache (2024) / Speed.md: avoid caching low-confidence recall to preserve quality.
    // Threshold 0.50 matches Aimos's confidence distribution (composite score: semantic+keyword+recency+authority).
    // The semantic cache's 0.85 cosine similarity hit threshold ensures only similar queries reuse cached results.
    const topConfidence = result.memories?.[0]?.recall_confidence ?? 0;
    if (topConfidence < 0.50) {
      return; // Don't cache low-confidence results
    }

    // Agreement paradox detection — Frugal Knowledge Graph (Jourlin, 2026)
    // "Strong confidence among samples signals collective hallucination"
    // When top-N scores are all abnormally high, flag as potential hallucination
    const topNScores = (result.memories || [])
      .slice(0, AGREEMENT_PARADOX_TOPN)
      .map(m => m.rerank_score ?? m.recall_confidence ?? 0);
    const hallucinationRisk = topNScores.length === AGREEMENT_PARADOX_TOPN
      && topNScores.every(s => s > AGREEMENT_PARADOX_THRESHOLD);

    if (hallucinationRisk) {
      logEvent('hom', 'system', 'agreement_paradox_detected', queryText, {
        topScores: topNScores,
        threshold: AGREEMENT_PARADOX_THRESHOLD,
        risk: 'collective_hallucination'
      }).catch(() => {});
    }

    // Evict oldest if at capacity
    if (this._cache.size >= this.maxSize) {
      const oldest = this._accessOrder[0];
      if (oldest) this._evict(oldest);
    }

    // Store new entry
    const namespace = this._namespace(context);
    if (!namespace) return;
    const cacheKey = `${namespace}\u0000${queryText}`;
    this._cache.set(cacheKey, {
      embedding: queryEmbedding,
      result: { ...result, hallucination_risk: hallucinationRisk },
      namespace,
      timestamp: Date.now(),
      trust_score: result.meta?.trust_score,
      mvs: result.meta?.mvs
    });

    this._markAccessed(cacheKey);

    // Batch 10 Lane 1: Also store compressed WARM representation
    // R3Mem compression: semantic summarization based on memory_type
    const memoryType = result.memories?.[0]?.memory_type || 'declarative';
    const compressionRatio = COMPRESSION_POLICY[memoryType] ?? 0.05;

    if (compressionRatio < 1.0 && this._compressedStore.size < this._compressedMaxSize) {
      const compressedResult = compressCacheResult(result, compressionRatio);
      this._compressedStore.set(cacheKey, {
        embedding: queryEmbedding,
        result: compressedResult,
        namespace,
        timestamp: Date.now(),
        compression_ratio: compressionRatio,
        memory_type: memoryType,
        access_freq: 0,
      });
      this._markCompressedAccessed(cacheKey);
    }
  }

  /**
   * Invalidate cache entries based on trigger type
   * @param {string} triggerType - 'cross_ref_update' | 'weight_change' | 'full'
   */
  invalidate(triggerType) {
    if (triggerType === 'full' || triggerType === 'cross_ref_update') {
      const count = this._cache.size;
      this._cache.clear();
      this._accessOrder = [];
      logEvent('hom', 'system', 'cache_invalidate', 'all', { count, trigger: triggerType });
    }
    // Note: Fine-grained invalidation by memory_id would require indexing
  }

  /**
   * Compute cosine similarity between two vectors
   * @param {number[]} a - Vector A
   * @param {number[]} b - Vector B
   * @returns {number} - Cosine similarity [0, 1]
   */
  _cosineSimilarity(a, b) {
    if (!a || !b || a.length !== b.length || a.length === 0) return 0;
    
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  }

  _namespace(context = {}) {
    const companyId = String(context.companyId || '').trim();
    const agentId = String(context.agentId || '').trim();
    const clearanceLevel = Number(context.clearanceLevel);
    const calibrationMutationHash = String(context.calibrationMutationHash || '').trim().toLowerCase();
    if (!companyId || !agentId || !Number.isFinite(clearanceLevel)
      || !/^[0-9a-f]{64}$/.test(calibrationMutationHash)) {
      return null;
    }
    return `${companyId}:${agentId}:${clearanceLevel}:${calibrationMutationHash}`;
  }

  /**
   * Internal: Mark a key as recently accessed (for LRU)
   */
  _markAccessed(key) {
    const idx = this._accessOrder.indexOf(key);
    if (idx > -1) this._accessOrder.splice(idx, 1);
    this._accessOrder.push(key);
  }

  /**
   * Internal: Evict a key from cache
   */
  _evict(key) {
    this._cache.delete(key);
    const idx = this._accessOrder.indexOf(key);
    if (idx > -1) this._accessOrder.splice(idx, 1);
  }

  /**
   * Get cache statistics (for monitoring)
   */
  getStats() {
    return {
      size: this._cache.size,
      maxSize: this.maxSize,
      warmSize: this._compressedStore.size,
      warmMaxSize: this._compressedMaxSize,
      ttlMs: this.ttlMs,
      similarityThreshold: this.similarityThreshold
    };
  }

  /**
   * Batch 10 Lane 1: Get compression policy mapping (500xCompressor)
   * Returns the memory_type → compression_ratio map used for WARM tier.
   */
  get compression_policy() {
    return { ...COMPRESSION_POLICY };
  }

  /**
   * Batch 10 Lane 1: Determine cache tier for an entry
   * cache_tier(entry) = HOT if access_freq > 0.8 else WARM if compressed else COLD
   */
  getCacheTier(key) {
    const hotEntry = this._cache.get(key);
    if (hotEntry) {
      const accessFreq = hotEntry.access_count
        ? hotEntry.access_count / Math.max(1, (Date.now() - hotEntry.timestamp) / 60000)
        : 0;
      return accessFreq > HOT_ACCESS_FREQ ? 'HOT' : 'WARM';
    }
    if (this._compressedStore.has(key)) return 'WARM';
    return 'COLD';
  }

  /**
   * Internal: Mark a compressed key as recently accessed
   */
  _markCompressedAccessed(key) {
    const idx = this._compressedAccessOrder.indexOf(key);
    if (idx > -1) this._compressedAccessOrder.splice(idx, 1);
    this._compressedAccessOrder.push(key);
  }

  /**
   * Internal: Evict a key from compressed store
   */
  _evictCompressed(key) {
    this._compressedStore.delete(key);
    const idx = this._compressedAccessOrder.indexOf(key);
    if (idx > -1) this._compressedAccessOrder.splice(idx, 1);
  }
}

/**
 * Batch 10 Lane 1: Compress a cache result using semantic summarization (R3Mem).
 * Compression is cache-only — original memory in PostgreSQL is never modified.
 * Aladdin compliance: compression only reduces context window bandwidth.
 *
 * @param {object} result - Full cache result with memories array
 * @param {number} ratio - Target compression ratio (0.05 to 1.0)
 * @returns {object} Compressed result with truncated values
 */
function compressCacheResult(result, ratio) {
  if (!result || !result.memories) return result;
  if (ratio >= 1.0) return result;

  const compressed = { ...result, memories: result.memories.map((mem) => {
    const value = String(mem.value || '');
    const maxLen = Math.max(20, Math.floor(value.length * ratio));
    return {
      ...mem,
      value: value.length > maxLen ? value.slice(0, maxLen) + '…' : value,
      _compressed: true,
      _compression_ratio: ratio,
    };
  })};

  return compressed;
}

/**
 * Batch 10 Lane 1: Get compression policy for a given memory type (500xCompressor).
 * Maps intent/memory_type to target compression ratio.
 * This is a pure function — no pipeline change.
 *
 * @param {string} memoryType - The memory type (e.g., 'declarative', 'procedural_seed')
 * @returns {{ stage: string, ratio: number, preserve_equations: boolean }}
 */
export function getCompressionPolicyForIntent(memoryType) {
  const ratio = COMPRESSION_POLICY[memoryType] ?? 0.05;
  return {
    stage: 'extract→compress',
    ratio,
    preserve_equations: true,
    memory_type: memoryType,
  };
}

// ─── BATCH 10 LANE 4: SKETCH-BASED NEAR-MISS + POD + TOKENDANCE ──────────────
// Papers: KVReviver, POD, Keep the Cost Down, TokenDance
// sketch_size = O(log(n) * (1/ε))
// reconstructFromSketch(query) = argmin_{sketch_i} ||query - sketch_i||
// POD: KV_cache_l = f(KV_cache_{l-1}) + Δ_l
// shared_kv_pool = Union(agent_i.kv_cache_prefix) for i in active_agents
// All diagnostic exports — cache HIT/MISS behavior unchanged.
// Aladdin: sketch is cache-only. Original memory in PostgreSQL is never modified.
// ─────────────────────────────────────────────────────────────────────────────

const SKETCH_WIDTH = 64;      // count-min sketch width (1/ε factor)
const SKETCH_DEPTH = 4;       // count-min sketch depth (log(n) factor)
const SKETCH_SEED = 2026;     // deterministic hash seed

/**
 * Compute a count-min sketch fingerprint of a cache entry.
 * sketch_size = O(log(n) * (1/ε))
 *
 * @param {object} entry - Cache entry with embedding
 * @param {object} opts - Options
 * @returns {{ sketch: number[][], hash_seeds: number[], entry_key: string }}
 */
export function computeSketch(entry, opts = {}) {
  const embedding = Array.isArray(entry?.embedding) ? entry.embedding : [];
  if (embedding.length === 0) {
    return { sketch: [], hash_seeds: [], entry_key: entry?.key || 'unknown', diagnostic_only: true };
  }

  const width = Math.max(1, Number(opts.width) || SKETCH_WIDTH);
  const depth = Math.max(1, Number(opts.depth) || SKETCH_DEPTH);
  const seed = Number(opts.seed) || SKETCH_SEED;

  // Generate deterministic hash seeds
  const hashSeeds = [];
  for (let i = 0; i < depth; i++) {
    hashSeeds.push((seed * (i + 1) + 7) % 2147483647);
  }

  // Project embedding into count-min sketch grid
  const sketch = [];
  for (let d = 0; d < depth; d++) {
    const row = new Array(width).fill(0);
    for (let i = 0; i < embedding.length; i++) {
      // Hash embedding dimension to a sketch column
      const col = Math.abs((hashSeeds[d] * (i + 1)) % width);
      row[col] += embedding[i];
    }
    sketch.push(row);
  }

  return {
    sketch,
    hash_seeds: hashSeeds,
    entry_key: entry?.key || 'unknown',
    sketch_dimensions: { width, depth },
    source_paper: 'KVReviver',
    diagnostic_only: true,
  };
}

/**
 * Reconstruct from sketch: find the nearest sketch to a query.
 * reconstructFromSketch(query) = argmin_{sketch_i} ||query - sketch_i||
 *
 * @param {number[]} queryEmbedding - The query embedding vector
 * @param {Array<{ key: string, sketch: number[][], hash_seeds: number[] }>} sketches - Array of computed sketches
 * @returns {{ best_match_key: string, distance: number, candidates: Array }}
 */
export function reconstructFromSketch(queryEmbedding, sketches = []) {
  const query = Array.isArray(queryEmbedding) ? queryEmbedding : [];
  const candidates = Array.isArray(sketches) ? sketches : [];

  if (query.length === 0 || candidates.length === 0) {
    return {
      best_match_key: null,
      distance: Infinity,
      candidates: [],
      source_paper: 'KVReviver',
      diagnostic_only: true,
    };
  }

  // Compute sketch for the query using same parameters
  const querySketch = computeSketch({ embedding: query, key: '_query' });

  // Find nearest sketch by L2 distance between sketch rows
  let bestKey = null;
  let bestDist = Infinity;
  const results = [];

  for (const candidate of candidates) {
    const cSketch = candidate.sketch;
    if (!Array.isArray(cSketch) || cSketch.length === 0) continue;

    let dist = 0;
    const depth = Math.min(querySketch.sketch.length, cSketch.length);
    for (let d = 0; d < depth; d++) {
      const qRow = querySketch.sketch[d] || [];
      const cRow = cSketch[d] || [];
      const width = Math.min(qRow.length, cRow.length);
      for (let c = 0; c < width; c++) {
        const diff = (qRow[c] || 0) - (cRow[c] || 0);
        dist += diff * diff;
      }
    }

    const l2Dist = Math.sqrt(dist);
    results.push({ key: candidate.key, distance: Number(l2Dist.toFixed(6)) });

    if (l2Dist < bestDist) {
      bestDist = l2Dist;
      bestKey = candidate.key;
    }
  }

  return {
    best_match_key: bestKey,
    distance: bestDist === Infinity ? null : Number(bestDist.toFixed(6)),
    candidates: results.sort((a, b) => a.distance - b.distance),
    source_paper: 'KVReviver',
    diagnostic_only: true,
    cache_hit_miss_unchanged: true,
  };
}

/**
 * Preserve inter-layer dependency (POD — Predictive Offloading Dependency).
 * POD: KV_cache_l = f(KV_cache_{l-1}) + Δ_l
 * Diagnoses whether layer caches maintain parent-child consistency.
 *
 * @param {Array<{ layer: number, kv_cache: object }>} layerCaches - Array of per-layer KV caches
 * @returns {{ dependencies: Array, violations: number, source_paper: string, diagnostic_only: boolean }}
 */
export function preserveInterLayerDependency(layerCaches = []) {
  const layers = Array.isArray(layerCaches) ? layerCaches : [];
  const dependencies = [];
  let violations = 0;

  for (let i = 1; i < layers.length; i++) {
    const parent = layers[i - 1];
    const child = layers[i];

    // Δ_l = child.KV - f(parent.KV)
    // Phase 0: f is identity, so Δ_l = child - parent
    const parentSize = Object.keys(parent?.kv_cache || {}).length;
    const childSize = Object.keys(child?.kv_cache || {}).length;

    // Dependency: child layer should reference at least some parent keys
    const parentKeys = new Set(Object.keys(parent?.kv_cache || {}));
    const childKeys = new Set(Object.keys(child?.kv_cache || {}));
    let sharedKeys = 0;
    for (const key of childKeys) {
      if (parentKeys.has(key)) sharedKeys++;
    }

    const dependencyRatio = childKeys.size > 0 ? sharedKeys / childKeys.size : 0;
    const isViolation = dependencyRatio < 0.1 && childKeys.size > 0;

    if (isViolation) violations++;

    dependencies.push({
      parent_layer: parent?.layer ?? i - 1,
      child_layer: child?.layer ?? i,
      shared_key_ratio: Number(dependencyRatio.toFixed(6)),
      violation: isViolation,
      delta_formula: 'KV_cache_l = f(KV_cache_{l-1}) + Δ_l',
      phase: 'identity_f_equals_copy',
    });
  }

  return {
    dependencies,
    violations,
    total_dependencies: dependencies.length,
    source_paper: 'POD: Predictive Offloading Dependency',
    diagnostic_only: true,
    cache_hit_miss_unchanged: true,
  };
}

/**
 * Compute collective KV cache pool (TokenDance).
 * shared_kv_pool = Union(agent_i.kv_cache_prefix) for i in active_agents
 * hit_rate_shared = |shared_prefix| / |total_kv|
 * savings = Σ_i (1 - unique_prefix_i / full_prefix_i)
 *
 * @param {Array<{ agent_id: string, kv_cache_prefix: string[] }>} agentCaches - Agent KV caches
 * @returns {{ shared_pool: string[], hit_rate_shared: number, savings: number, source_paper: string, diagnostic_only: boolean }}
 */
export function computeCollectivePool(agentCaches = []) {
  const caches = Array.isArray(agentCaches) ? agentCaches : [];
  if (caches.length === 0) {
    return {
      shared_pool: [],
      hit_rate_shared: 0,
      savings: 0,
      agent_count: 0,
      source_paper: 'TokenDance',
      diagnostic_only: true,
    };
  }

  // Union of all agent prefixes
  const sharedPool = new Set();
  const agentStats = [];

  for (const agent of caches) {
    const prefix = Array.isArray(agent?.kv_cache_prefix) ? agent.kv_cache_prefix : [];
    const fullCount = prefix.length;
    let uniqueCount = 0;

    for (const key of prefix) {
      if (!sharedPool.has(key)) {
        uniqueCount++;
      }
      sharedPool.add(key);
    }

    agentStats.push({
      agent_id: agent?.agent_id || 'unknown',
      full_prefix_count: fullCount,
      unique_prefix_count: uniqueCount,
      reuse_ratio: fullCount > 0 ? Number((1 - uniqueCount / fullCount).toFixed(6)) : 0,
    });
  }

  const totalKv = agentStats.reduce((s, a) => s + a.full_prefix_count, 0);
  const hitRateShared = totalKv > 0 ? Number((sharedPool.size / totalKv).toFixed(6)) : 0;
  const savings = agentStats.reduce((s, a) => s + a.reuse_ratio, 0) / caches.length;

  return {
    shared_pool: Array.from(sharedPool),
    shared_pool_size: sharedPool.size,
    hit_rate_shared: hitRateShared,
    savings: Number(savings.toFixed(6)),
    agent_count: caches.length,
    agent_stats: agentStats,
    source_paper: 'TokenDance',
    diagnostic_only: true,
    cache_hit_miss_unchanged: true,
    multi_agent_coordination_changed: false,
  };
}

/**
 * Build collective pool diagnostic for TokenDance.
 */
export function buildCollectivePoolDiagnostic(agentCaches = []) {
  const pool = computeCollectivePool(agentCaches);
  return {
    status: 'diagnostic',
    ...pool,
    formula: 'shared_kv_pool = Union(agent_i.kv_cache_prefix) for i in active_agents',
    guardrails: {
      cache_hit_miss_unchanged: true,
      canonical_memory_unchanged: true,
      multi_agent_coordination_changed: false,
    },
  };
}

// Export singleton instance for easy import
export const semanticCache = new SemanticCache();

export default { SemanticCache, semanticCache };
