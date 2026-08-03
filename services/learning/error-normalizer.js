// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into nightly-dream Stage 6 after failure replay
// Purpose: Normalizes raw error signals via two-pass whitening (P1-B3-14)
//          before feeding into learning-rate adjustments
// Wire into: jobs/nightly-dream.js -> runErrorNormalizationCycle()
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR NORMALIZER (error-normalizer.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-14: Normalized Error Signals
//
// Normalizes raw error signals from the learning loop using a two-pass
// whitening pipeline adapted from batch normalization theory:
//
//   Pass 1 (subtractive): subtract running mean μ to remove mean drift
//   Pass 2 (divisive):    divide by running variance σ² to scale by uncertainty
//
// The resulting whitened errors are decorrelated via pairwise Jacobi rotation,
// yielding near-independent components suitable for per-skill gradient updates.
//
// Stability objective separates two loss sources:
//   L_task  — mean-squared gradient magnitude (primary task error)
//   L_stab  — variance of update magnitudes across skills (instability penalty)
//
// Per-skill running statistics (Welford online algorithm) are persisted in DB
// and updated once per dream cycle to avoid catastrophic forgetting.
//
// Theoretical basis:
//   Ioffe & Szegedy (2015) Batch Normalization
//   Welford (1962) online mean/variance
//   Decorrelation in Predictive Coding (Rao & Ballard, 1999)
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Minimum variance floor — prevents division-by-zero
const MIN_VARIANCE = 1e-8;

// Outlier clip applied before any pass
const ERROR_CLIP = 10.0;

// ─── Schema ──────────────────────────────────────────────────────────────────

/**
 * Verify the migration-owned skill_running_stats contract without mutating schema.
 *
 * @returns {Promise<void>}
 */
let errorNormalizerSchemaVerified = false;
async function ensureErrorNormalizerSchema() {
  if (errorNormalizerSchemaVerified) return;
  await query(
    `SELECT id, company_id, skill_id, mu, variance, n_samples, updated_at, created_at
     FROM skill_running_stats
     WHERE false`
  );
  errorNormalizerSchemaVerified = true;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Clip a value symmetrically to [-clip, +clip].
 *
 * @param {number} v
 * @param {number} clip
 * @returns {number}
 */
function clipValue(v, clip) {
  return Math.max(-clip, Math.min(clip, Number(v) || 0));
}

/**
 * Arithmetic mean of an array.
 *
 * @param {number[]} arr
 * @returns {number}
 */
function arrayMean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((s, x) => s + x, 0) / arr.length;
}

/**
 * Population variance given a pre-computed mean.
 *
 * @param {number[]} arr
 * @param {number} mu
 * @returns {number}
 */
function arrayVariance(arr, mu) {
  if (arr.length < 2) return 1;
  const v = arr.reduce((s, x) => s + (x - mu) ** 2, 0) / arr.length;
  return Math.max(MIN_VARIANCE, v);
}

/**
 * Welford online mean/variance single-step update.
 *
 * @param {number} prevMu
 * @param {number} prevVar - Running population variance
 * @param {number} prevN
 * @param {number} newValue
 * @returns {{mu: number, variance: number, n: number}}
 */
function welfordUpdate(prevMu, prevVar, prevN, newValue) {
  const n = prevN + 1;
  const delta = newValue - prevMu;
  const mu = prevMu + delta / n;
  // Accumulate M2 and derive population variance
  const m2 = prevVar * prevN + delta * (newValue - mu);
  const newVar = Math.max(MIN_VARIANCE, n > 1 ? m2 / n : 1);
  return { mu, variance: newVar, n };
}

/**
 * Pairwise Jacobi rotation pass to decorrelate an error vector.
 * Applies one full sweep over all (i, j) pairs with i < j.
 *
 * After divisivePass the vector has unit batch variance; pairwise products
 * approximate covariance and the rotation nullifies the dominant off-diagonal
 * element in each pair.
 *
 * @param {number[]} errors - Variance-scaled error vector
 * @returns {number[]} Decorrelated error vector
 */
function decorrelate(errors) {
  if (!Array.isArray(errors) || errors.length < 2) return errors;

  const result = [...errors];
  const n = result.length;

  for (let i = 0; i < n - 1; i++) {
    for (let j = i + 1; j < n; j++) {
      const x = result[i];
      const y = result[j];
      const theta = 0.5 * Math.atan2(2 * x * y, x * x - y * y + MIN_VARIANCE);
      const cos = Math.cos(theta);
      const sin = Math.sin(theta);
      result[i] = cos * x + sin * y;
      result[j] = -sin * x + cos * y;
    }
  }

  return result;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Subtract the batch mean from each error signal (Pass 1).
 * Removes mean drift introduced by systematic bias in the task distribution.
 *
 * @param {number[]} errors - Raw error batch
 * @returns {number[]} Mean-centred errors
 */
export function subtractivePass(errors) {
  if (!Array.isArray(errors) || errors.length === 0) return [];
  const clipped = errors.map((e) => clipValue(e, ERROR_CLIP));
  const mu = arrayMean(clipped);
  return clipped.map((e) => e - mu);
}

/**
 * Scale mean-centred errors by batch standard deviation (Pass 2).
 * Produces unit-variance signals suitable for gradient computation.
 *
 * @param {number[]} errors - Original raw error batch (clipping applied internally)
 * @param {number[]} subtracted - Output of subtractivePass()
 * @returns {number[]} Variance-scaled errors
 */
export function divisivePass(errors, subtracted) {
  if (!Array.isArray(subtracted) || subtracted.length === 0) return [];
  const clipped = errors.map((e) => clipValue(e, ERROR_CLIP));
  const mu = arrayMean(clipped);
  const v = arrayVariance(clipped, mu);
  const std = Math.sqrt(v);
  return subtracted.map((e) => e / std);
}

/**
 * Full two-pass batch normalisation with decorrelation.
 *
 * Pipeline:
 *   1. Clip outliers to ±ERROR_CLIP
 *   2. subtractivePass  — remove batch mean
 *   3. divisivePass     — divide by batch std
 *   4. decorrelate      — pairwise Jacobi rotation
 *
 * @param {number[]} errors - Raw error signals from the learning loop
 * @returns {{
 *   normalised: number[],
 *   mu: number,
 *   variance: number,
 *   decorrelated: number[]
 * }}
 */
export function normalizeErrorBatch(errors) {
  if (!Array.isArray(errors) || errors.length === 0) {
    return { normalised: [], mu: 0, variance: 1, decorrelated: [] };
  }

  const clipped = errors.map((e) => clipValue(e, ERROR_CLIP));
  const mu = arrayMean(clipped);
  const v = arrayVariance(clipped, mu);
  const std = Math.sqrt(v);

  const subtracted = clipped.map((e) => e - mu);
  const scaled = subtracted.map((e) => e / std);
  const decorrelated = decorrelate(scaled);

  return {
    normalised: scaled,
    mu,
    variance: v,
    decorrelated,
  };
}

/**
 * Decompose skill update vectors into task loss and stability loss.
 *
 * Task loss     = mean squared L2 norm of update vectors (gradient descent objective)
 * Stability loss = variance of L2 norms across skills (high variance → chaotic updates)
 *
 * Separation lets the optimiser minimise task error while independently
 * penalising instability from concurrent skill updates — a critical invariant
 * for continual learning without interference.
 *
 * @param {Array<{skillId: string, delta: number[]}>} skillUpdates - Per-skill gradient vectors
 * @returns {{
 *   taskLoss: number,
 *   stabilityLoss: number,
 *   updateMagnitudes: number[],
 *   dominantSkillId: string|null
 * }}
 */
export function computeStabilityObjective(skillUpdates) {
  if (!Array.isArray(skillUpdates) || skillUpdates.length === 0) {
    return { taskLoss: 0, stabilityLoss: 0, updateMagnitudes: [], dominantSkillId: null };
  }

  const magnitudes = skillUpdates.map((u) => {
    if (!Array.isArray(u?.delta) || u.delta.length === 0) return 0;
    return Math.sqrt(u.delta.reduce((s, d) => s + (Number(d) || 0) ** 2, 0));
  });

  const taskLoss = magnitudes.reduce((s, m) => s + m * m, 0) / magnitudes.length;
  const muMag = arrayMean(magnitudes);
  const stabilityLoss = arrayVariance(magnitudes, muMag);

  let maxMag = -Infinity;
  let dominantIdx = -1;
  for (let i = 0; i < magnitudes.length; i++) {
    if (magnitudes[i] > maxMag) { maxMag = magnitudes[i]; dominantIdx = i; }
  }
  const dominantSkillId = dominantIdx >= 0 ? (skillUpdates[dominantIdx]?.skillId ?? null) : null;

  return {
    taskLoss: Math.round(taskLoss * 1e8) / 1e8,
    stabilityLoss: Math.round(stabilityLoss * 1e8) / 1e8,
    updateMagnitudes: magnitudes.map((m) => Math.round(m * 1e6) / 1e6),
    dominantSkillId,
  };
}

/**
 * Retrieve per-skill running statistics {μ, σ²} from DB.
 * Updated once per dream cycle via updateSkillRunningStats().
 *
 * Returns safe defaults (μ=0, σ²=1, n=0) when no history exists.
 *
 * @param {string} skillId - Skill identifier (aimos_memories.id or key)
 * @param {string} [companyId]
 * @returns {Promise<{mu: number, variance: number, nSamples: number}>}
 */
export async function getSkillRunningStats(skillId, companyId) {
  const cid = companyId || COMPANY;
  await ensureErrorNormalizerSchema();

  try {
    const result = await query(
      `SELECT mu, variance, n_samples
       FROM skill_running_stats
       WHERE company_id = $1 AND skill_id = $2
       LIMIT 1`,
      [cid, String(skillId)]
    );

    if (!result.rows.length) {
      return { mu: 0, variance: 1, nSamples: 0 };
    }

    const row = result.rows[0];
    return {
      mu: parseFloat(row.mu) || 0,
      variance: Math.max(MIN_VARIANCE, parseFloat(row.variance) || 1),
      nSamples: parseInt(row.n_samples, 10) || 0,
    };
  } catch (err) {
    console.error('[error-normalizer] getSkillRunningStats DB error:', err.message);
    return { mu: 0, variance: 1, nSamples: 0 };
  }
}

/**
 * Update per-skill running statistics with a new error observation.
 * Uses the Welford online algorithm for numerically stable incremental updates.
 * Designed to be called once per skill per dream cycle.
 *
 * @param {string} skillId
 * @param {number} newErrorValue - Latest normalised error observation
 * @param {string} [companyId]
 * @returns {Promise<{mu: number, variance: number, nSamples: number, updated: boolean}>}
 */
export async function updateSkillRunningStats(skillId, newErrorValue, companyId) {
  const cid = companyId || COMPANY;
  await ensureErrorNormalizerSchema();

  const prev = await getSkillRunningStats(skillId, cid);
  const clipped = clipValue(newErrorValue, ERROR_CLIP);
  const next = welfordUpdate(prev.mu, prev.variance, prev.nSamples, clipped);

  try {
    await query(
      `INSERT INTO skill_running_stats
         (company_id, skill_id, mu, variance, n_samples, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (company_id, skill_id)
       DO UPDATE SET mu = $3, variance = $4, n_samples = $5, updated_at = NOW()`,
      [cid, String(skillId), next.mu, next.variance, next.n]
    );

    await logEvent(cid, 'error-normalizer', 'skill_stats_updated', skillId, {
      reasoning: `Welford update for skill ${skillId}: μ=${next.mu.toFixed(4)}, σ²=${next.variance.toFixed(4)}, n=${next.n}`,
      mu: next.mu,
      variance: next.variance,
      nSamples: next.n,
    }).catch(() => {});

    return { mu: next.mu, variance: next.variance, nSamples: next.n, updated: true };
  } catch (err) {
    console.error('[error-normalizer] updateSkillRunningStats upsert error:', err.message);
    return { mu: next.mu, variance: next.variance, nSamples: next.n, updated: false };
  }
}

function clusterSkillId(cluster, index) {
  const raw = String(
    cluster?.skillId ||
    cluster?.skill_id ||
    cluster?.signature ||
    cluster?.key ||
    `cluster_${index + 1}`
  ).trim();
  const normalized = raw
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 96);
  return `failure_cluster:${normalized || `cluster_${index + 1}`}`;
}

function confidenceFromFailure(failure) {
  const metadata = failure?.metadata || failure || {};
  const value = Number(
    metadata.confidence ??
    metadata.confidence_score ??
    metadata.recall_confidence ??
    metadata.success_probability
  );
  return Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : null;
}

function clusterErrorSignal(cluster) {
  const failures = Array.isArray(cluster?.failures) ? cluster.failures : [];
  const count = Math.max(1, Number(cluster?.count || failures.length || 1));
  const confidences = failures
    .map(confidenceFromFailure)
    .filter((value) => value !== null);
  const avgConfidence = confidences.length
    ? confidences.reduce((sum, value) => sum + value, 0) / confidences.length
    : 0.5;
  const confidenceError = 1 - avgConfidence;
  const frequencySignal = Math.log1p(count);
  return clipValue(frequencySignal * (0.5 + confidenceError), ERROR_CLIP);
}

/**
 * Run the dream-stage error normalisation cycle.
 *
 * Native pipeline:
 *   failure clusters -> scalar error signals -> two-pass whitening ->
 *   Jacobi decorrelation -> Welford running-stat updates -> event ledger.
 *
 * This cycle is diagnostic/learning telemetry. It does not change retrieval
 * weights, ranking math, or canonical memory content.
 *
 * @param {Array<object>} failureClusters
 * @param {string} [companyId]
 * @param {{agentId?: string, eventKey?: string}} [options]
 * @returns {Promise<object>}
 */
export async function runErrorNormalizationCycle(failureClusters = [], companyId, options = {}) {
  const cid = companyId || COMPANY;
  const clusters = Array.isArray(failureClusters)
    ? failureClusters.filter((cluster) => cluster && typeof cluster === 'object')
    : [];
  const rawErrors = clusters.map(clusterErrorSignal);
  const normalized = normalizeErrorBatch(rawErrors);

  const updates = clusters.map((cluster, index) => {
    const normalisedValue = Number(normalized.normalised[index] || 0);
    const decorrelatedValue = Number(normalized.decorrelated[index] || normalisedValue || 0);
    return {
      skillId: clusterSkillId(cluster, index),
      rawError: rawErrors[index] || 0,
      normalisedError: normalisedValue,
      decorrelatedError: decorrelatedValue,
      delta: [normalisedValue, decorrelatedValue],
    };
  });

  let statsUpdated = 0;
  const statResults = [];
  for (const update of updates) {
    const stat = await updateSkillRunningStats(update.skillId, update.decorrelatedError, cid);
    if (stat.updated) statsUpdated += 1;
    statResults.push({
      skill_id: update.skillId,
      raw_error: Number(update.rawError.toFixed(6)),
      normalised_error: Number(update.normalisedError.toFixed(6)),
      decorrelated_error: Number(update.decorrelatedError.toFixed(6)),
      n_samples: stat.nSamples,
      updated: stat.updated,
    });
  }

  const stability = computeStabilityObjective(updates);
  const metadata = {
    reasoning: `Error normalizer processed ${clusters.length} failure clusters using subtractive/divisive whitening, Jacobi decorrelation, and Welford running statistics.`,
    source_knowledge: 'P1-B3-14 Normalized Error Signals; Ioffe & Szegedy Batch Normalization; Welford online variance; Rao & Ballard predictive coding decorrelation',
    processed: clusters.length,
    stats_updated: statsUpdated,
    batch_mu: normalized.mu,
    batch_variance: normalized.variance,
    stability,
    ranking_math_changed: false,
    retrieval_weight_changed: false,
    canonical_memory_changed: false,
  };

  const eventId = await logEvent(
    cid,
    options.agentId || 'error-normalizer',
    'error_normalization_cycle',
    options.eventKey || `error-normalizer:${new Date().toISOString().slice(0, 10)}`,
    metadata
  );

  return {
    status: 'processed',
    processed: clusters.length,
    statsUpdated,
    batch: {
      mu: normalized.mu,
      variance: normalized.variance,
    },
    stability,
    stats: statResults,
    event_id: eventId,
    ranking_math_changed: false,
    retrieval_weight_changed: false,
    canonical_memory_changed: false,
  };
}
