// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into DREAM embedding-stability audit
// Purpose: Fixed random projection for cross-version embedding stability (P1-B3-10);
//          prevents incompatible vector spaces across embedding model upgrades
// Called by: jobs/nightly-dream.js Stage 18
// Calls: db/connection.js, observe/event-ledger.js
// Pipeline: DREAM
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// EMBEDDING STABILITY (embedding-stability.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-10: Fixed Random Projection for Cross-Version Embedding Stability
//
// Problem: embedding model version upgrades produce incompatible vector spaces,
// making similarity comparisons across versions meaningless.
//
// Solution: Johnson-Lindenstrauss (JL) random projection into a fixed canonical
// subspace. The projection matrix R is generated once, persisted in DB, and
// never regenerated. All embeddings — regardless of origin model version — are
// compared in this canonical space.
//
// JL guarantee: for ε ∈ (0, 1) and k = O(log(n)/ε²), distances are preserved
// within factor (1 ± ε) with high probability.
//
// Storage table: embedding_projections(company_id, matrix_data JSONB, created_at)
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';

import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Default source dimension (matches aimos_memories embedding vector(768))
const DEFAULT_DIMENSIONS = 768;

// Default stable (projected) dimension — JL guarantee: k ≥ 4*ln(n)/ε²
const DEFAULT_STABLE_DIMENSIONS = 128;

function matrixHash(matrix) {
  return createHash('sha256').update(JSON.stringify(matrix), 'utf8').digest('hex');
}

function parseMatrix(matrixData) {
  return Array.isArray(matrixData) ? matrixData : JSON.parse(matrixData);
}

function parseEmbedding(value) {
  if (Array.isArray(value)) return value.map((n) => Number(n) || 0);
  if (typeof value !== 'string') return null;
  const body = value.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!body) return null;
  const parsed = body.split(',').map((part) => Number(part.trim()));
  return parsed.every((n) => Number.isFinite(n)) ? parsed : null;
}

// ─── Schema ─────────────────────────────────────────────────────────────────

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Generate a Gaussian random projection matrix R of shape [stableDims × sourceDims].
 * Entries drawn from N(0, 1/stableDims) for JL distance preservation.
 *
 * @param {number} sourceDims
 * @param {number} stableDims
 * @returns {number[][]} Matrix rows: stableDims × sourceDims
 */
function generateGaussianMatrix(sourceDims, stableDims) {
  const scale = 1 / Math.sqrt(stableDims);
  const matrix = [];
  for (let i = 0; i < stableDims; i++) {
    const row = [];
    for (let j = 0; j < sourceDims; j++) {
      // Box-Muller transform for standard normal
      const u1 = Math.random();
      const u2 = Math.random();
      const z = Math.sqrt(-2 * Math.log(Math.max(u1, 1e-12))) * Math.cos(2 * Math.PI * u2);
      row.push(z * scale);
    }
    matrix.push(row);
  }
  return matrix;
}

/**
 * Project an embedding vector through matrix R.
 * Result = R * embedding (matrix-vector product).
 *
 * @param {number[]} embedding - Source vector of length sourceDims
 * @param {number[][]} matrix - R of shape [stableDims × sourceDims]
 * @returns {number[]} Projected vector of length stableDims
 */
function matMulVec(matrix, embedding) {
  return matrix.map((row) =>
    row.reduce((sum, w, j) => sum + w * (embedding[j] || 0), 0)
  );
}

/**
 * Compute cosine similarity between two vectors.
 *
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number} Similarity in [-1, 1]
 */
function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom < 1e-12 ? 0 : dot / denom;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Create and persist a fixed random projection matrix for a company.
 * If a matrix already exists for these dimensions, returns the existing one.
 *
 * @param {number} [dimensions=768] - Source embedding dimensions
 * @param {number} [stableDimensions=128] - Target stable dimensions
 * @param {string} [companyId]
 * @returns {Promise<{matrix: number[][], sourceDims: number, stableDims: number, created: boolean}>}
 */
export async function initProjectionMatrix(
  dimensions = DEFAULT_DIMENSIONS,
  stableDimensions = DEFAULT_STABLE_DIMENSIONS,
  companyId
) {
  const cid = companyId || COMPANY;

  // Check for existing matrix
  try {
    const existing = await query(
      `SELECT id, matrix_data, source_dimensions, stable_dimensions, created_at
       FROM embedding_projections
       WHERE company_id = $1
         AND source_dimensions = $2
         AND stable_dimensions = $3
       LIMIT 1`,
      [cid, dimensions, stableDimensions]
    );

    if (existing.rows.length > 0) {
      const row = existing.rows[0];
      const matrix = parseMatrix(row.matrix_data);
      return {
        matrix,
        sourceDims: row.source_dimensions,
        stableDims: row.stable_dimensions,
        projectionId: row.id,
        createdAt: row.created_at,
        matrixHash: matrixHash(matrix),
        created: false,
      };
    }
  } catch (err) {
    console.error('[embedding-stability] initProjectionMatrix fetch error:', err.message);
  }

  // Generate new matrix
  const matrix = generateGaussianMatrix(dimensions, stableDimensions);
  const hash = matrixHash(matrix);
  let inserted;

  try {
    inserted = await query(
      `INSERT INTO embedding_projections
         (company_id, source_dimensions, stable_dimensions, matrix_data)
       VALUES ($1, $2, $3, $4::jsonb)
       ON CONFLICT (company_id, source_dimensions, stable_dimensions) DO NOTHING
       RETURNING id, created_at`,
      [cid, dimensions, stableDimensions, JSON.stringify(matrix)]
    );
  } catch (err) {
    console.error('[embedding-stability] initProjectionMatrix insert error:', err.message);
    throw err;
  }

  if (!inserted.rows.length) {
    return initProjectionMatrix(dimensions, stableDimensions, cid);
  }

  await logEvent(cid, 'embedding-stability', 'projection_matrix_initialized', `embedding_projection:${dimensions}:${stableDimensions}`, {
    reasoning: `Created fixed JL projection matrix for ${dimensions}->${stableDimensions} canonical embedding-space comparison.`,
    source_knowledge: 'Johnson-Lindenstrauss random projection: k = O(log(n)/epsilon^2), distances preserved within 1 +/- epsilon with high probability',
    sourceDims: dimensions,
    stableDims: stableDimensions,
    projection_id: inserted.rows[0].id,
    matrix_hash: hash,
    projection_table_mutated: true,
    canonical_memory_changed: false,
  }).catch(() => {});

  return {
    matrix,
    sourceDims: dimensions,
    stableDims: stableDimensions,
    projectionId: inserted.rows[0].id,
    createdAt: inserted.rows[0].created_at,
    matrixHash: hash,
    created: true
  };
}

/**
 * Project an embedding through the fixed random matrix into the canonical stable space.
 *
 * @param {number[]} embedding - Source embedding vector
 * @param {string} [companyId]
 * @returns {Promise<number[]>} Projected vector in stable space
 */
export async function projectEmbedding(embedding, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(embedding) || embedding.length === 0) {
    throw new Error('[embedding-stability] projectEmbedding: embedding must be a non-empty array');
  }

  const sourceDims = embedding.length;
  const { matrix } = await initProjectionMatrix(sourceDims, DEFAULT_STABLE_DIMENSIONS, cid);
  return matMulVec(matrix, embedding);
}

/**
 * Load the persisted projection matrix for a company.
 *
 * @param {string} [companyId]
 * @param {number} [sourceDims=768]
 * @param {number} [stableDims=128]
 * @returns {Promise<number[][]|null>}
 */
export async function getProjectionMatrix(companyId, sourceDims = DEFAULT_DIMENSIONS, stableDims = DEFAULT_STABLE_DIMENSIONS) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT matrix_data
       FROM embedding_projections
       WHERE company_id = $1
         AND source_dimensions = $2
         AND stable_dimensions = $3
       ORDER BY created_at DESC
       LIMIT 1`,
      [cid, sourceDims, stableDims]
    );

    if (result.rows.length === 0) return null;
    return parseMatrix(result.rows[0].matrix_data);
  } catch (err) {
    console.error('[embedding-stability] getProjectionMatrix error:', err.message);
    return null;
  }
}

/**
 * Compare two embeddings from potentially different model versions in the
 * canonical stable projection space.
 *
 * JL guarantee ensures distances are preserved within (1 ± ε) factor.
 *
 * @param {number[]} embeddingA - Embedding from version A
 * @param {string} versionA - Model version string
 * @param {number[]} embeddingB - Embedding from version B
 * @param {string} versionB - Model version string
 * @param {string} [companyId]
 * @returns {Promise<{similarity: number, versionA: string, versionB: string, canonical: boolean}>}
 */
export async function crossVersionCompare(embeddingA, versionA, embeddingB, versionB, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(embeddingA) || !Array.isArray(embeddingB)) {
    throw new Error('[embedding-stability] crossVersionCompare: both embeddings must be arrays');
  }

  const [projA, projB] = await Promise.all([
    projectEmbedding(embeddingA, cid),
    projectEmbedding(embeddingB, cid),
  ]);

  const similarity = cosineSimilarity(projA, projB);

  return {
    similarity: Math.round(similarity * 100000) / 100000,
    versionA: String(versionA || 'unknown'),
    versionB: String(versionB || 'unknown'),
    canonical: true,
    projectedDims: projA.length,
  };
}

export async function runEmbeddingStabilityAudit({
  companyId = COMPANY,
  sourceDims = DEFAULT_DIMENSIONS,
  stableDims = DEFAULT_STABLE_DIMENSIONS,
  sampleLimit = 10,
} = {}) {
  const cid = companyId || COMPANY;
  const projection = await initProjectionMatrix(sourceDims, stableDims, cid);
  const matrix = projection.matrix;
  const shapeValid = Array.isArray(matrix)
    && matrix.length === stableDims
    && matrix.every((row) => Array.isArray(row) && row.length === sourceDims);
  const limit = Math.max(1, Math.min(100, Number(sampleLimit) || 10));
  const sample = await query(
    `SELECT id, key, embedding::text AS embedding
     FROM aimos_memories
     WHERE company_id = $1 AND embedding IS NOT NULL
     ORDER BY created_at DESC
     LIMIT $2`,
    [cid, limit]
  );
  const projected = [];
  for (const row of sample.rows) {
    const embedding = parseEmbedding(row.embedding);
    if (!embedding || embedding.length !== sourceDims) continue;
    const vector = matMulVec(matrix, embedding);
    const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
    projected.push({
      id: row.id,
      key: row.key,
      projected_dims: vector.length,
      projected_norm: Math.round(norm * 100000) / 100000
    });
  }

  const summary = {
    projection_id: projection.projectionId,
    source_dimensions: projection.sourceDims,
    stable_dimensions: projection.stableDims,
    matrix_hash: projection.matrixHash,
    matrix_created: projection.created,
    projection_table_mutated: projection.created,
    shape_valid: shapeValid,
    sampled_memories: sample.rows.length,
    projected_memories: projected.length,
    canonical_memory_changed: false
  };

  const eventId = await logEvent(cid, 'embedding-stability', 'embedding_stability_audit', `embedding_stability:${Date.now()}`, {
    reasoning: `Embedding stability audited JL projection ${projection.sourceDims}->${projection.stableDims}, matrix_created=${projection.created}, projected ${projected.length}/${sample.rows.length} sampled memory embedding(s).`,
    source_knowledge: 'P1-B3-10 fixed random projection for cross-version embedding stability; Johnson-Lindenstrauss distance preservation',
    summary,
    projected,
    diagnostic_only: false,
    projection_table_mutated: projection.created,
    canonical_memory_changed: false,
    ranking_math_changed: false,
  });

  return {
    ...summary,
    projected,
    eventId,
  };
}
