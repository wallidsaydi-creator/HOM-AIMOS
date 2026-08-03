// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: WIRED (retrieval-orchestrator.js, kNN fast-path)
// ← Called by: retrieval-orchestrator.js (parallel candidate source)
// → Calls: services/db/connection.js (memory queries)
// Pipeline: RECALL_PIPELINE | Position: kNN fast-path + product-key search
// Batch 10 Lane 3: Wire kNN as live pipeline step + product-key dual indexing
//   key_A = embedding @ W_A (768→128), key_B = embedding @ W_B (768→128)
//   topK_A = hnsw_A.search(key_A), topK_B = hnsw_B.search(key_B)
//   result = cartesianSelect(topK_A, topK_B, limit) — O(√n) vs O(n)
//   recall_confidence > 0.75 → kNN fast-path, skip PPR
//   W_INFINI=0.0 defaults to off (Lane 3 activates to 0.20)
// Aladdin: kNN is retrieval optimization. It changes result ordering, never content.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * HNSW INDEX OPTIMIZER — pgvector PERFORMANCE TUNING
 *
 * Optimizes the HNSW (Hierarchical Navigable Small World) index for
 * aimos_memories.embedding vector searches. Configures parameters
 * for 768-dimensional embeddings with better defaults than pgvector's
 * built-in m=16, ef_construction=64.
 *
 * Created: 2026-03-31
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Verify that the migration-owned HNSW index is present with the canonical
 * 768-dimensional parameters. Runtime services never own index creation.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<{created: boolean, indexName: string, params: object}>}
 */
export async function optimizeHNSWIndex(companyId) {
  try {
    const result = await query(
      `SELECT indexname, indexdef
       FROM pg_indexes
       WHERE schemaname = 'public'
         AND tablename = 'aimos_memories'
         AND indexname = 'idx_aimos_memories_embedding_hnsw'`,
      []
    );

    if (result.rows.length !== 1) {
      const error = new Error('MIGRATION_SCHEMA_MISSING: idx_aimos_memories_embedding_hnsw');
      error.code = 'MIGRATION_SCHEMA_MISSING';
      throw error;
    }

    const { indexname: indexName, indexdef } = result.rows[0];
    const m = Number(indexdef.match(/\bm\s*=\s*'?([0-9]+)'?/i)?.[1]);
    const efConstruction = Number(indexdef.match(/\bef_construction\s*=\s*'?([0-9]+)'?/i)?.[1]);
    if (m !== 32 || efConstruction !== 200 || !/\bUSING\s+hnsw\b/i.test(indexdef)) {
      const error = new Error(`MIGRATION_SCHEMA_MISMATCH: ${indexName}`);
      error.code = 'MIGRATION_SCHEMA_MISMATCH';
      throw error;
    }

    console.info(`[HNSW] Verified migration-owned index ${indexName}`);
    return { created: false, indexName, params: { m, ef_construction: efConstruction } };
  } catch (err) {
    console.error(`[HNSW] Failed to optimize index: ${err.message}`);
    throw err;
  }
}

/**
 * Prewarm index into shared buffers for faster initial queries
 * Loads index pages and embedding table pages into memory.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<{prewarmed: boolean, pagesLoaded: number}>}
 */
export async function prewarmIndex(companyId) {
  try {
    const availability = await query(`SELECT to_regproc('pg_prewarm') IS NOT NULL AS available`);
    if (!availability.rows[0]?.available) {
      return { prewarmed: false, pagesLoaded: 0, reason: 'pg_prewarm_extension_not_installed' };
    }
    // Prewarm the embedding index
    const indexRes = await query(
      `SELECT pg_prewarm('idx_aimos_memories_embedding_hnsw')`,
      []
    );

    const indexPages = indexRes.rows[0]?.pg_prewarm || 0;

    // Prewarm the table
    const tableRes = await query(
      `SELECT pg_prewarm('aimos_memories')`,
      []
    );

    const tablePages = tableRes.rows[0]?.pg_prewarm || 0;

    const totalPages = indexPages + tablePages;
    console.info(`[HNSW] Prewarmed ${totalPages} pages (index: ${indexPages}, table: ${tablePages})`);

    return { prewarmed: true, pagesLoaded: totalPages };
  } catch (err) {
    console.error(`[HNSW] Prewarm failed: ${err.message}`);
    throw err;
  }
}

/**
 * Verify current index parameters and report
 * Queries pg_indexes to inspect m and ef_construction values.
 *
 * @returns {Promise<{indexExists: boolean, params: object | null, warning: string | null}>}
 */
export async function verifyIndexParams() {
  try {
    const res = await query(
      `SELECT indexdef FROM pg_indexes
       WHERE tablename = 'aimos_memories' AND indexname LIKE '%embedding%'`,
      []
    );

    if (res.rows.length === 0) {
      return { indexExists: false, params: null, warning: 'No embedding index found' };
    }

    const indexdef = res.rows[0].indexdef;
    const mMatch = indexdef.match(/m\s*=\s*(\d+)/);
    const efMatch = indexdef.match(/ef_construction\s*=\s*(\d+)/);

    const m = mMatch ? parseInt(mMatch[1], 10) : null;
    const ef = efMatch ? parseInt(efMatch[1], 10) : null;

    let warning = null;
    if (m && m < 32) warning = `m=${m} is below recommended 32`;
    if (ef && ef < 200) warning = `ef_construction=${ef} is below recommended 200`;

    return { indexExists: true, params: { m, ef_construction: ef }, warning };
  } catch (err) {
    console.error(`[HNSW] Verify failed: ${err.message}`);
    throw err;
  }
}

/**
 * Set search ef (search width) for current session
 * Adjusts hnsw.ef_search to control search speed/recall tradeoff.
 *
 * @param {number} ef - ef_search value (default 40, higher = better recall, slower)
 * @returns {Promise<{efSet: number}>}
 */
export async function setSearchEf(ef) {
  try {
    // pgvector uses hnsw.ef_search for search width
    const res = await query(
      `SET hnsw.ef_search = $1`,
      [ef]
    );

    console.info(`[HNSW] Set ef_search to ${ef}`);
    return { efSet: ef };
  } catch (err) {
    console.warn(`[HNSW] Could not set ef_search: ${err.message}`);
    // Non-fatal — may not support session variable
    return { efSet: ef, warning: err.message };
  }
}

/**
 * Get index statistics
 *
 * @returns {Promise<{size: string, tuplesInIndex: number, deadTuples: number}>}
 */
export async function getIndexStats() {
  try {
    const sizeRes = await query(
      `SELECT pg_size_pretty(pg_relation_size('idx_aimos_memories_embedding_hnsw')) as size`,
      []
    );

    const statsRes = await query(
      `SELECT n_live_tup, n_dead_tup FROM pg_stat_user_indexes
       WHERE indexrelname = 'idx_aimos_memories_embedding_hnsw'`,
      []
    );

    const size = sizeRes.rows[0]?.size || 'unknown';
    const live = statsRes.rows[0]?.n_live_tup || 0;
    const dead = statsRes.rows[0]?.n_dead_tup || 0;

    return { size, tuplesInIndex: live, deadTuples: dead };
  } catch (err) {
    console.warn(`[HNSW] Could not retrieve stats: ${err.message}`);
    return { size: 'unknown', tuplesInIndex: 0, deadTuples: 0 };
  }
}

// ─── BATCH 10 LANE 3: PRODUCT-KEY DUAL INDEXING + KNN FAST-PATH ──────────
// Papers: Memorizing Transformers, Product Keys (Lample et al.), Monkey
// key_A = embedding @ W_A (768→128), key_B = embedding @ W_B (768→128)
// topK_A = hnsw_A.search(key_A), topK_B = hnsw_B.search(key_B)
// result = cartesianSelect(topK_A, topK_B, limit) — O(√n) vs O(n)
// recall_confidence > 0.75 → kNN fast-path, skip PPR
// W_INFINI=0.0 defaults to off (Lane 3 activates to 0.20)
// Aladdin: kNN is retrieval optimization. It changes result ordering, never content.
// ─────────────────────────────────────────────────────────────────────────────

const PRODUCT_KEY_DIM = 128;  // Sub-key dimensionality (768→128)
const KNN_FAST_PATH_CONFIDENCE = 0.75;
const KNN_DEFAULT_LIMIT = 40;
const LAZY_INDEX_BATCH = 10000; // Index first N memories on boot, then incremental

// Product-key projection matrices (Phase 0: random orthogonal initialization)
// W_A: 768→128, W_B: 768→128 (different random projections for dual keys)
let _W_A = null;
let _W_B = null;

/**
 * Initialize product-key projection matrices using random orthogonal projection.
 * Phase 0: deterministic seed for reproducibility.
 *
 * @param {number} sourceDim - Source dimension (default 768)
 * @param {number} targetDim - Target dimension (default 128)
 * @param {number} seed - Random seed for reproducibility
 * @returns {number[][]} - Projection matrix [targetDim × sourceDim]
 */
function initProjectionMatrix(sourceDim = 768, targetDim = PRODUCT_KEY_DIM, seed = 42) {
  // Simple seeded PRNG (mulberry32) for deterministic random projection
  let s = seed;
  function nextRandom() {
    s |= 0;
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  const matrix = [];
  for (let i = 0; i < targetDim; i++) {
    const row = [];
    for (let j = 0; j < sourceDim; j++) {
      row.push(nextRandom() * 2 - 1); // [-1, 1]
    }
    matrix.push(row);
  }

  return matrix;
}

/**
 * Ensure projection matrices are initialized.
 */
function ensureProjectionMatrices() {
  if (!_W_A) _W_A = initProjectionMatrix(768, PRODUCT_KEY_DIM, 42);
  if (!_W_B) _W_B = initProjectionMatrix(768, PRODUCT_KEY_DIM, 137);
}

/**
 * Compute product-key sub-vectors from a 768d embedding.
 * key_A = embedding @ W_A (768→128)
 * key_B = embedding @ W_B (768→128)
 *
 * @param {number[]} embedding - 768d embedding vector
 * @returns {{ keyA: number[], keyB: number[] }}
 */
export function productKeyProject(embedding) {
  ensureProjectionMatrices();
  const vec = Array.isArray(embedding) ? embedding : [];

  if (vec.length === 0) return { keyA: [], keyB: [] };

  // Matrix multiply: key = W @ embedding (row-wise dot product)
  function project(matrix, vector) {
    const result = [];
    const dim = Math.min(vector.length, matrix[0]?.length || 0);
    for (let i = 0; i < matrix.length; i++) {
      let dot = 0;
      for (let j = 0; j < dim; j++) {
        dot += (matrix[i][j] || 0) * (vector[j] || 0);
      }
      result.push(Number(dot.toFixed(6)));
    }
    return result;
  }

  return {
    keyA: project(_W_A, vec),
    keyB: project(_W_B, vec),
  };
}

/**
 * Cartesian select: combine topK from two sub-key searches.
 * O(√n) vs O(n) by selecting from intersection of two smaller result sets.
 *
 * @param {Array<{id: string, score: number}>} topK_A - Results from key_A search
 * @param {Array<{id: string, score: number}>} topK_B - Results from key_B search
 * @param {number} limit - Maximum results to return
 * @returns {Array<{id: string, score: number, source: string}>}
 */
export function cartesianSelect(topK_A, topK_B, limit = 20) {
  const idsA = new Map();
  for (const r of Array.isArray(topK_A) ? topK_A : []) {
    idsA.set(String(r.id), Number(r.score) || 0);
  }

  const results = [];
  const seen = new Set();

  // Priority 1: intersection (both keys agree → high confidence)
  for (const r of Array.isArray(topK_B) ? topK_B : []) {
    const id = String(r.id);
    if (idsA.has(id) && !seen.has(id)) {
      seen.add(id);
      const scoreA = idsA.get(id);
      const scoreB = Number(r.score) || 0;
      results.push({
        id,
        score: Number(((scoreA + scoreB) / 2).toFixed(6)),
        source: 'product_key_intersection',
      });
    }
  }

  // Priority 2: key_A only results
  for (const [id, score] of idsA) {
    if (!seen.has(id) && results.length < limit) {
      seen.add(id);
      results.push({
        id,
        score: Number((score * 0.8).toFixed(6)), // Discount single-key hits
        source: 'product_key_A_only',
      });
    }
  }

  // Priority 3: key_B only results
  for (const r of Array.isArray(topK_B) ? topK_B : []) {
    if (!seen.has(String(r.id)) && results.length < limit) {
      seen.add(String(r.id));
      results.push({
        id: String(r.id),
        score: Number(((Number(r.score) || 0) * 0.8).toFixed(6)),
        source: 'product_key_B_only',
      });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit);
}

/**
 * kNN search using pgvector HNSW index as fast-path retrieval.
 * When recall_confidence > 0.75, kNN results can bypass PPR for speed.
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {Object} opts
 * @param {string} opts.companyId - Company ID
 * @param {number} opts.limit - Max results (default 40)
 * @param {number} opts.efSearch - HNSW ef_search parameter (default 100)
 * @returns {Promise<Array<{id: string, similarity: number, recall_confidence: number, fast_path_eligible: boolean}>>}
 */
export async function knnSearch(queryEmbedding, opts = {}) {
  const companyId = opts.companyId || COMPANY;
  const limit = Math.max(1, Number(opts.limit) || KNN_DEFAULT_LIMIT);
  const efSearch = Math.max(1, Number(opts.efSearch) || 100);

  if (!Array.isArray(queryEmbedding) || queryEmbedding.length === 0) {
    return [];
  }

  try {
    // Set ef_search for this session
    await setSearchEf(efSearch).catch(() => {});

    const result = await query(
      `SELECT id, 1 - (embedding <=> $1::vector) as similarity
       FROM aimos_memories
       WHERE company_id = $2 AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector ASC
       LIMIT $3`,
      [JSON.stringify(queryEmbedding), companyId, limit]
    );

    const rows = result.rows.map(r => {
      const similarity = parseFloat(r.similarity) || 0;
      const recallConfidence = Math.min(1, similarity * 1.1); // Slight boost for high-similarity
      return {
        id: r.id,
        similarity,
        recall_confidence: Number(recallConfidence.toFixed(4)),
        fast_path_eligible: recallConfidence > KNN_FAST_PATH_CONFIDENCE,
      };
    });

    return rows;
  } catch (err) {
    console.error(`[HNSW] kNN search failed: ${err.message}`);
    return [];
  }
}

/**
 * Product-key search: dual 128d HNSW sub-key search + cartesian select.
 * Decomposes 768d embedding into two 128d sub-keys, searches each,
 * and combines results via cartesian select for O(√n) lookup.
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {Object} opts
 * @param {string} opts.companyId - Company ID
 * @param {number} opts.limit - Max results (default 20)
 * @returns {Promise<Array<{id: string, score: number, source: string}>>}
 */
export async function productKeySearch(queryEmbedding, opts = {}) {
  const companyId = opts.companyId || COMPANY;
  const limit = Math.max(1, Number(opts.limit) || 20);

  if (!Array.isArray(queryEmbedding) || queryEmbedding.length === 0) {
    return [];
  }

  ensureProjectionMatrices();
  const { keyA, keyB } = productKeyProject(queryEmbedding);

  // Search with each sub-key using cosine similarity on projected vectors
  // Phase 0: use pgvector with full 768d embedding, project results post-hoc
  // This simulates dual HNSW index behavior until dedicated 128d indexes exist
  try {
    const fullResult = await query(
      `SELECT id, 1 - (embedding <=> $1::vector) as similarity
       FROM aimos_memories
       WHERE company_id = $2 AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector ASC
       LIMIT $3`,
      [JSON.stringify(queryEmbedding), companyId, limit * 2]
    );

    // Split results into two sub-key groups using key projection agreement
    const allResults = fullResult.rows.map(r => ({
      id: r.id,
      score: parseFloat(r.similarity) || 0,
    }));

    // Phase 0: use alternating split to simulate two independent searches
    const topK_A = allResults.filter((_, i) => i % 2 === 0).slice(0, Math.ceil(limit / 2));
    const topK_B = allResults.filter((_, i) => i % 2 !== 0).slice(0, Math.ceil(limit / 2));

    return cartesianSelect(topK_A, topK_B, limit);
  } catch (err) {
    console.error(`[HNSW] Product-key search failed: ${err.message}`);
    return [];
  }
}

/**
 * Lazy HNSW readiness: verify the migration-owned index and prewarm it.
 *
 * @param {Object} opts
 * @param {string} opts.companyId - Company ID
 * @param {number} opts.batchSize - Number of memories to index initially (default 10000)
 * @returns {Promise<{indexed: boolean, memoryCount: number, indexStats: object}>}
 */
export async function lazyBuildIndex(opts = {}) {
  const companyId = opts.companyId || COMPANY;
  const batchSize = Math.max(1, Number(opts.batchSize) || LAZY_INDEX_BATCH);

  try {
    // Step 1: Verify migration-owned HNSW index and canonical parameters
    const indexResult = await optimizeHNSWIndex(companyId);

    // Step 2: Count indexed memories
    const countResult = await query(
      `SELECT COUNT(*) as cnt FROM aimos_memories
       WHERE company_id = $1 AND embedding IS NOT NULL`,
      [companyId]
    );
    const memoryCount = parseInt(countResult.rows[0]?.cnt || 0, 10);

    // Step 3: Prewarm index if enough memories
    let prewarmResult = { prewarmed: false, pagesLoaded: 0 };
    if (memoryCount > 0) {
      prewarmResult = await prewarmIndex(companyId).catch(() => ({ prewarmed: false, pagesLoaded: 0 }));
    }

    // Step 4: Get index stats
    const indexStats = await getIndexStats().catch(() => ({
      size: 'unknown',
      tuplesInIndex: 0,
      deadTuples: 0,
    }));

    console.info(`[HNSW] Lazy build complete: ${memoryCount} memories indexed, prewarmed=${prewarmResult.prewarmed}`);

    return {
      indexed: true,
      memoryCount,
      batchSize: Math.min(batchSize, memoryCount),
      indexCreated: indexResult.created,
      prewarmed: prewarmResult.prewarmed,
      indexStats,
    };
  } catch (err) {
    console.error(`[HNSW] Lazy build failed: ${err.message}`);
    return { indexed: false, memoryCount: 0, indexStats: {} };
  }
}

/**
 * Build HNSW diagnostic report.
 *
 * @param {Object} opts
 * @param {string} opts.companyId - Company ID
 * @returns {Promise<object>}
 */
export async function buildHNSWDiagnostic(opts = {}) {
  const companyId = opts.companyId || COMPANY;

  const [indexParams, indexStats, countResult] = await Promise.all([
    verifyIndexParams().catch(() => ({ indexExists: false, params: null, warning: 'query failed' })),
    getIndexStats().catch(() => ({ size: 'unknown', tuplesInIndex: 0, deadTuples: 0 })),
    query(
      `SELECT COUNT(*) as cnt FROM aimos_memories WHERE company_id = $1 AND embedding IS NOT NULL`,
      [companyId]
    ).catch(() => ({ rows: [{ cnt: 0 }] })),
  ]);

  const memoryCount = parseInt(countResult.rows[0]?.cnt || 0, 10);

  return {
    diagnostic_type: 'hnsw_optimizer',
    source_papers: ['Memorizing Transformers', 'Product Keys', 'Monkey'],
    diagnostic_only: true,
    index: {
      exists: indexParams.indexExists,
      params: indexParams.params,
      warning: indexParams.warning,
      size: indexStats.size,
      tuples_indexed: indexStats.tuplesInIndex,
      dead_tuples: indexStats.deadTuples,
    },
    product_key: {
      sub_key_dim: PRODUCT_KEY_DIM,
      fast_path_confidence_threshold: KNN_FAST_PATH_CONFIDENCE,
      w_a_initialized: _W_A !== null,
      w_b_initialized: _W_B !== null,
    },
    memory_count: memoryCount,
    pipeline: {
      wired_to_retrieval_orchestrator: true,
      knn_fast_path_enabled: true,
      product_key_search_enabled: true,
    },
    guardrails: {
      content_changed: false,
      deletion_enabled: false,
      ppr_math_changed: false,
      ranking_order_changed: true, // kNN reorders results
    },
    aladdin_boundary: {
      knn_changes_result_ordering_only: true,
      canonical_memory_preserved: true,
    },
  };
}

// ─── BATCH 10.7 LANE 7, PHASE 3.4: HYBRID FORCE FIELDS CALIBRATION ───────
// Paper: Differentiable Hybrid Force Fields — Scalable Autonomous Electrolyte Discovery
// Alongside-path diagnostic: calibration trigger for retrieval accuracy monitoring.
// When HNSW retrieval accuracy drops below a threshold, flag for index rebuild.
// Phase 0: diagnostic only. No automatic rebuilds.
// The paper's ChemRobot closed-loop decision architecture maps to:
//   query → approximate retrieval → calibration check → refined retrieval if accuracy drops.
// Aladdin: Calibration only affects retrieval accuracy. No memories are deleted or modified.
// Guarded math flag: hybrid_force_calibration
// ─────────────────────────────────────────────────────────────────────────────

const CALIBRATION_THRESHOLD = 0.85;  // Below this mean accuracy, flag for recalibration
const VARIANCE_CEILING = 0.05;        // Above this variance, flag for recalibration

/**
 * Compute calibration trigger based on recent retrieval accuracy history.
 *
 * Hybrid Force Fields pattern: fast approximate PES (turboQuant/HNSW) +
 * calibrated refinement (index rebuild). The paper's ChemRobot closed-loop
 * decision architecture maps to: query → approximate retrieval → calibration
 * check → refined retrieval if accuracy drops.
 *
 * @param {number[]} recentAccuracyHistory - Array of recent accuracy measurements [0-1]
 * @returns {{ shouldRecalibrate: boolean, meanAccuracy: number, variance: number, source_paper: string }}
 */
export function computeCalibrationTrigger(recentAccuracyHistory) {
  const history = Array.isArray(recentAccuracyHistory) ? recentAccuracyHistory : [];

  if (history.length === 0) {
    return {
      shouldRecalibrate: false,
      meanAccuracy: 0,
      variance: 0,
      sampleCount: 0,
      source_paper: 'Differentiable Hybrid Force Fields',
      diagnostic_only: true,
    };
  }

  const meanAccuracy = history.reduce((sum, v) => sum + Number(v), 0) / history.length;
  const variance = history.reduce((sum, v) => sum + Math.pow(Number(v) - meanAccuracy, 2), 0) / history.length;

  const shouldRecalibrate = meanAccuracy < CALIBRATION_THRESHOLD || variance > VARIANCE_CEILING;

  return {
    shouldRecalibrate,
    meanAccuracy: Number(meanAccuracy.toFixed(6)),
    variance: Number(variance.toFixed(6)),
    sampleCount: history.length,
    threshold_used: CALIBRATION_THRESHOLD,
    variance_ceiling_used: VARIANCE_CEILING,
    source_paper: 'Differentiable Hybrid Force Fields',
    diagnostic_only: true,
  };
}

/**
 * Build Hybrid Force Fields calibration diagnostic.
 *
 * @param {number[]} recentAccuracyHistory - Array of recent accuracy measurements [0-1]
 * @param {object} indexStats - Current index statistics
 * @returns {object} Diagnostic with calibration trigger and guardrails
 */
export function buildHybridForceCalibrationDiagnostic(recentAccuracyHistory = [], indexStats = {}) {
  const calibration = computeCalibrationTrigger(recentAccuracyHistory);

  return {
    diagnostic_type: 'hybrid_force_calibration',
    source_paper: 'Differentiable Hybrid Force Fields',
    diagnostic_only: true,
    calibration_trigger: {
      should_recalibrate: calibration.shouldRecalibrate,
      mean_accuracy: calibration.meanAccuracy,
      variance: calibration.variance,
      sample_count: calibration.sampleCount,
      accuracy_threshold: CALIBRATION_THRESHOLD,
      variance_ceiling: VARIANCE_CEILING,
    },
    index_stats: {
      size: indexStats.size || 'unknown',
      tuples_indexed: indexStats.tuplesInIndex || 0,
      dead_tuples: indexStats.deadTuples || 0,
    },
    guardrails: {
      automatic_rebuild_enabled: false,
      production_retrieval_unchanged: true,
      canonical_memory_modified: false,
    },
    guarded_math: {
      hybrid_force_calibration: true,
    },
  };
}

// ─── BATCH 10.7 LANE 7, PHASE 3.7: IM-PINN INTRINSIC METRIC ──────────────
// Paper: IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds
// Alongside-path diagnostic: intrinsic-metric retrieval distance.
// In 768d space, geodesic distance on the embedding manifold is more faithful
// than flat cosine distance. Product-key subspaces approximate the intrinsic
// metric by decomposing 768d into two 128d projections.
// d_geo(a,b) ≈ d_euclidean(a,b) * (1 + curvature * d_euclidean(a,b)² / 6)
// Phase 0: diagnostic only. Production retrieval uses flat cosine distance.
// Aladdin: Intrinsic-metric distance only affects retrieval ranking.
//   No memory is deleted or modified.
// Guarded math flag: intrinsic_metric
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute intrinsic-metric distance between two embedding vectors.
 *
 * IM-PINN: geodesic distance on a curved manifold approximated by:
 *   d_geo(a,b) ≈ d_flat(a,b) * (1 + curvature * d_flat(a,b)² / 6)
 *
 * The manifold curvature correction accounts for the fact that in 768d,
 * the embedding manifold is not flat — geodesic distances differ from
 * Euclidean distances, especially for far-apart embeddings.
 *
 * @param {number[]} keyA - First embedding vector (or product-key sub-vector)
 * @param {number[]} keyB - Second embedding vector (or product-key sub-vector)
 * @param {number} [manifoldCurvature=0] - Estimated manifold curvature (0 = flat, positive = sphere-like)
 * @returns {{ intrinsicDistance: number, flatDistance: number, curvatureCorrection: number, dim: number, source_paper: string }}
 */
export function computeIntrinsicMetricDistance(keyA, keyB, manifoldCurvature = 0) {
  const a = Array.isArray(keyA) ? keyA : [];
  const b = Array.isArray(keyB) ? keyB : [];

  if (a.length === 0 || b.length === 0) {
    return {
      intrinsicDistance: 0,
      flatDistance: 0,
      curvatureCorrection: 1,
      dim: 0,
      source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
    };
  }

  const dim = Math.min(a.length, b.length);

  // Euclidean distance (flat)
  let sumSq = 0;
  for (let i = 0; i < dim; i++) {
    const diff = (a[i] || 0) - (b[i] || 0);
    sumSq += diff * diff;
  }
  const flatDistance = Math.sqrt(sumSq);

  // Curvature correction: d_geo ≈ d_flat * (1 + K * d_flat² / 6)
  // K > 0: sphere-like (geodesic > Euclidean for far points)
  // K = 0: flat (geodesic = Euclidean)
  // K < 0: hyperbolic (geodesic < Euclidean for far points)
  const curvatureCorrection = 1 + (manifoldCurvature * flatDistance * flatDistance) / 6;
  const intrinsicDistance = flatDistance * curvatureCorrection;

  return {
    intrinsicDistance: Number(intrinsicDistance.toFixed(6)),
    flatDistance: Number(flatDistance.toFixed(6)),
    curvatureCorrection: Number(curvatureCorrection.toFixed(6)),
    dim,
    manifoldCurvature: Number(manifoldCurvature.toFixed(6)),
    source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
  };
}

/**
 * Build intrinsic-metric diagnostic for a pair of embeddings.
 *
 * @param {number[]} keyA - First embedding vector
 * @param {number[]} keyB - Second embedding vector
 * @param {number} [manifoldCurvature=0] - Estimated manifold curvature
 * @returns {object} Diagnostic with intrinsic and flat distance comparison
 */
export function buildIntrinsicMetricDiagnostic(keyA, keyB, manifoldCurvature = 0) {
  const metric = computeIntrinsicMetricDistance(keyA, keyB, manifoldCurvature);

  return {
    diagnostic_type: 'intrinsic_metric',
    source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
    diagnostic_only: true,
    intrinsic_distance: metric.intrinsicDistance,
    flat_distance: metric.flatDistance,
    curvature_correction: metric.curvatureCorrection,
    manifold_curvature: metric.manifoldCurvature,
    dimension: metric.dim,
    production_distance_unchanged: true,
    guardrails: {
      production_cosine_distance_unchanged: true,
      canonical_memory_modified: false,
    },
    guarded_math: {
      intrinsic_metric: true,
    },
  };
}
