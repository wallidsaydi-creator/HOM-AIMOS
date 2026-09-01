/**
 * similarity-stats.js — Embedding Anisotropy Correction (P0-2)
 * Source: D-MEM + Filter-Agnostic Vector Search (SIGMOD 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (SAVE step 8, RECALL step 15)
 * 2. ← Called by: nightly-dream.js (step 3)
 * 3. → Pulls from: services/db/connection.js (Sliding window stats)
 * 4. → Benefits: All semantic modules (Standardizes cosine thresholds)
 *
 * LOGIC GUIDE: Z-score normalizes cosine similarities using a sliding window. 
 * Corrects for 768d vector clustering ("cone effect") to ensure reliable confidence scores.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline step 8, RECALL pipeline step 15)
// ← Called by: nightly-dream.js (step 3)
// → Calls: services/db/connection.js (sliding window stats)
// Pipeline: SAVE_PIPELINE, RECALL_PIPELINE, DREAM_PIPELINE
// Position: similarity observation
// ─────────────────────────────────────────────────────────────────────────────

import { query } from '../../db/connection.js';

const WINDOW_SIZE = 1000;
const DEFAULT_MU = 0.75;   // typical mean cosine for 768d embeddings
const DEFAULT_SIGMA = 0.08; // typical std dev
const CACHE_TTL_MS = 300_000; // 5 min

// In-memory cache per company
const _statsCache = new Map();

/**
 * Load stats from DB or cache.
 * @param {string} companyId
 * @returns {{ mu: number, sigma: number, sampleCount: number }}
 */
async function getStats(companyId, { queryFn = query, useCache = true } = {}) {
  const cached = _statsCache.get(companyId);
  if (useCache && cached && Date.now() - cached.at < CACHE_TTL_MS) {
    return cached.stats;
  }

  const result = await queryFn(
    `SELECT window_mean, window_std, sample_count FROM similarity_statistics WHERE company_id = $1`,
    [companyId]
  );

  const stats = result.rows.length > 0
    ? {
        mu: parseFloat(result.rows[0].window_mean) || DEFAULT_MU,
        sigma: Math.max(parseFloat(result.rows[0].window_std) || DEFAULT_SIGMA, 0.01),
        sampleCount: parseInt(result.rows[0].sample_count, 10) || 0
      }
    : { mu: DEFAULT_MU, sigma: DEFAULT_SIGMA, sampleCount: 0 };

  if (useCache) _statsCache.set(companyId, { stats, at: Date.now() });
  return stats;
}

/**
 * Record a raw cosine similarity observation into the sliding window.
 * Updates running mean and std via Welford's online algorithm.
 * @param {string} companyId
 * @param {number} rawSimilarity - cosine similarity value (0-1 typical range)
 */
export async function recordSimilarityObservation(companyId, rawSimilarity) {
  void companyId; void rawSimilarity;
  return { recorded: false, reason: 'online_similarity_mutation_retired' };
}

/**
 * Compute z-score normalized surprise from raw cosine similarity.
 * Higher surprise = more novel/distant from the population mean.
 *
 * Surprise(x) = sigmoid((mu - raw_sim) / sigma)
 * Range: 0 (very typical/similar) to 1 (very surprising/distant)
 *
 * @param {number} rawSimilarity - raw cosine similarity (1 - distance)
 * @param {string} companyId
 * @returns {Promise<{ surprise: number, zScore: number, mu: number, sigma: number }>}
 */
export async function computeSurprise(rawSimilarity, companyId) {
  const stats = await getStats(companyId);
  const { mu, sigma } = stats;

  // Z-score: how many std devs is this from the mean?
  // Note: higher similarity = less surprising, so we invert: (mu - raw) / sigma
  const zScore = (mu - rawSimilarity) / sigma;

  // Sigmoid transform to [0, 1]
  const surprise = 1 / (1 + Math.exp(-zScore));

  return { surprise, zScore, mu, sigma };
}

/**
 * Normalize a raw cosine distance for recall scoring.
 * Replaces raw distance with z-score adjusted distance.
 *
 * @param {number} rawDistance - cosine distance (0 = identical, higher = more distant)
 * @param {string} companyId
 * @returns {Promise<number>} adjusted distance
 */
export async function normalizeDistance(rawDistance, companyId) {
  const rawSimilarity = 1 - rawDistance;
  const { surprise } = await computeSurprise(rawSimilarity, companyId);

  // Record this observation for future normalization

  // Return adjusted distance: surprise-weighted
  // High surprise = far from population = keep high distance
  // Low surprise = typical distance = compress toward mean
  return surprise;
}

/**
 * Batch-normalize distances for a recall result set.
 * More efficient than normalizeDistance() per-item since stats are loaded once.
 *
 * @param {{ id: string, raw_distance: number }[]} results
 * @param {string} companyId
 * @returns {Promise<Map<string, number>>} id → normalized surprise score
 */
export async function batchNormalize(results, companyId) {
  const stats = await getStats(companyId);
  const { mu, sigma } = stats;
  const normalized = new Map();

  for (const row of results) {
    const rawSim = 1 - (row.raw_distance || 0);
    const zScore = (mu - rawSim) / sigma;
    const surprise = 1 / (1 + Math.exp(-zScore));
    normalized.set(row.id, surprise);

    // Fire-and-forget observation recording (batched for efficiency)
  }

  return normalized;
}

/**
 * Get current anisotropy statistics for a company.
 * Useful for diagnostics and Dream v2 quality checks.
 *
 * @param {string} companyId
 * @returns {Promise<{ mu: number, sigma: number, sampleCount: number, isCalibrated: boolean }>}
 */
export async function getAnisotropyStats(companyId, options = {}) {
  const stats = await getStats(companyId, options);
  return {
    ...stats,
    isCalibrated: stats.sampleCount >= 100 // need at least 100 observations for reliable stats
  };
}
