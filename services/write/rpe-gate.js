// ═══════════════════════════════════════════════════════════════════════════════
// RPE WRITE GATE (rpe-gate.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Sutton & Barto (Reinforcement Learning), dopaminergic prediction error
// Additive Batch8 Wave 3 authority: Learn by Surprise, Commit by Proof.
// Aimos exposes surprise/proof diagnostics only; per-token surprisal,
// conviction-depth optimizer changes, and write blocking remain guarded.
//
// Batch 10 Lane 2: G-MemLLM + Titans — surprise_at_save emission
//   surprise_at_save = ||embedding_predicted - embedding_actual||₂
//   latent_write_signal = RPE > 0.7 AND surprise_at_save > surprise_μ
//   The surprise_at_save column already exists from Lane 0.
//   Aladdin: Surprise is metadata on the memory row. Never replaces or deletes
//   the memory itself.
//
// Batch 10.7 Lane 7, Phase 3.1: MEMORYLLM — Episodic Surprise Model
//   Paper: MEMORYLLM — Towards Self-Updatable Large Language Models
//   Replace global _surpriseMean with per-context-type surprise distributions.
//   At scale (50K+), a single global mean loses discriminative power:
//   a "surprising" event_log is very different from a "surprising" core_belief.
//   EpisodicSurpriseModel tracks per-context-type distributions using
//   Welford online update (numerically stable, O(1) memory per context type).
//   Guarded math flag: episodic_surprise (Phase 0: always closed → global mean)
//   Aladdin: Episodic distributions only affect the latent_write_signal gate.
//   They change *when* a memory gets enhanced routing, never *whether* it exists.
//
// Reward Prediction Error gate — computes Surprise + Utility before Aimos
// writes to route processing depth.
//
// RPE(x) = min(1.0, I(Utility >= tau) * [Utility * (Surprise + 0.4)])
//
// Routes:
//   LIGHTWEIGHT  rpe < 0.3  — skip conflict check, tag utility_score=low
//   STANDARD     0.3-0.7    — normal save with conflict check
//   FULL         >= 0.7     — full pipeline: entity extraction + graph linking
//
// Theoretical basis: Temporal Difference learning (Sutton & Barto), dopaminergic
// prediction error signals, novelty-gated consolidation.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline, step 3)
// → Calls: services/core/embeddings.js (surprise computation)
// Pipeline: SAVE_PIPELINE
// Position: after write-validator
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
// Provider-specific LLM helpers removed — Aimos is provider-agnostic. No LLM calls in memory pipeline.
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Utility classification → numeric mapping
const UTILITY_MAP = Object.freeze({
  transient: 0.2,
  short_term: 0.5,
  persistent: 0.9,
});

// RPE activation threshold — utility below this → RPE collapses to 0
const UTILITY_TAU = 0.2;

// Route thresholds
const LIGHTWEIGHT_MAX = 0.3;
const STANDARD_MAX = 0.7;

export function buildProofGate({
  text = '',
  memoryType = '',
  surprise = 0,
  utility = 0,
  rpe = 0,
  route = 'LIGHTWEIGHT',
} = {}) {
  const body = String(text || '');
  const highImpactType = /^(architecture|infrastructure|operational_rule|strategic_directive|procedural|procedural_seed|core_belief)$/i
    .test(String(memoryType || ''));
  const highImpactLanguage = /\b(always|never|must|constitutional|architecture|security|safety|sovereign|proof|verified)\b/i
    .test(body);
  const requiresProof = route === 'FULL' || Number(rpe) >= STANDARD_MAX || highImpactType || highImpactLanguage;

  return {
    source_paper: 'Learn by Surprise, Commit by Proof',
    diagnostic_only: true,
    surprise: Number(Number(surprise || 0).toFixed(4)),
    utility: Number(Number(utility || 0).toFixed(4)),
    rpe: Number(Number(rpe || 0).toFixed(4)),
    route,
    requires_proof: requiresProof,
    proof_status: requiresProof ? 'proof_recommended' : 'proof_not_required',
    proof_requirements: requiresProof
      ? ['source_evidence', 'schema_check', 'contradiction_scan']
      : [],
    guarded_math: {
      per_token_surprisal_threshold: false,
      conviction_depth_optimizer: false,
      adamw_beta2_update: false,
    },
    write_blocking_enabled: false,
    model_weight_update_enabled: false,
    deletion_enabled: false,
  };
}

/**
 * Classify the utility of text using deterministic heuristics.
 * Provider-agnostic — no LLM calls. Uses memory_type + content patterns.
 *
 * @param {string} text - Input text to classify
 * @param {string} [memoryType] - Optional memory_type hint from caller
 * @returns {{label: string, score: number}}
 */
export function classifyUtility(text, memoryType) {
  const t = String(text || '').toLowerCase();
  const mt = String(memoryType || '').toLowerCase();

  // Persistent: durable knowledge, skills, principles, directives
  const PERSISTENT_TYPES = ['procedural_seed', 'procedural', 'tacit_knowledge', 'book_extract',
    'framework', 'directive', 'identity', 'core_belief', 'operational_rule', 'infrastructure'];
  if (PERSISTENT_TYPES.includes(mt)) return { label: 'persistent', score: UTILITY_MAP.persistent };

  // Persistent by content pattern
  if (/\b(principle|axiom|law|theorem|always|never|must|constitution|directive)\b/.test(t) && t.length > 100) {
    return { label: 'persistent', score: UTILITY_MAP.persistent };
  }

  // Transient: ephemeral status, heartbeats, event logs
  const TRANSIENT_TYPES = ['heartbeat', 'event_log', 'conversation_feed'];
  if (TRANSIENT_TYPES.includes(mt)) return { label: 'transient', score: UTILITY_MAP.transient };

  // Transient by content pattern
  if (/\b(current price|weather|right now|as of today|status update)\b/.test(t)) {
    return { label: 'transient', score: UTILITY_MAP.transient };
  }

  // Short content → likely transient
  if (t.length < 50) return { label: 'transient', score: UTILITY_MAP.transient };

  // Default: short_term
  return { label: 'short_term', score: UTILITY_MAP.short_term };
}

/**
 * Compute surprise as cosine distance between new text embedding and nearest
 * existing memory in aimos_memories (via pgvector <=> operator).
 *
 * Surprise = 1.0 when no memories exist (fully novel context).
 * Surprise = cosine_distance to nearest neighbour otherwise.
 *
 * @param {string} text - Input text
 * @param {string} companyId - Company scope
 * @returns {Promise<{surprise: number, nearestId: string|null}>}
 */
export async function computeSurprise(text, companyId) {
  const cid = companyId || COMPANY;

  const embedding = await getEmbedding(text);
  if (!embedding) {
    // Cannot embed → treat as maximally surprising
    return { surprise: 1.0, nearestId: null };
  }

  const vectorLiteral = `[${embedding.join(',')}]`;

  try {
    const result = await query(
      `SELECT id, (embedding <=> $1::vector) AS cosine_distance
       FROM aimos_memories
       WHERE company_id = $2
         AND embedding IS NOT NULL
       ORDER BY embedding <=> $1::vector
       LIMIT 1`,
      [vectorLiteral, cid]
    );

    if (!result.rows.length) {
      // No memories yet — maximum novelty
      return { surprise: 1.0, nearestId: null };
    }

    const row = result.rows[0];
    // pgvector cosine distance is already in [0, 2]; normalise to [0, 1]
    const rawDist = parseFloat(row.cosine_distance) || 0;
    const surprise = Math.min(1.0, Math.max(0.0, rawDist));
    return { surprise, nearestId: row.id };
  } catch (err) {
    console.error('[rpe-gate] computeSurprise DB error:', err.message);
    return { surprise: 1.0, nearestId: null };
  }
}

/**
 * Compute RPE score and determine routing depth for an incoming write.
 *
 * RPE(x) = min(1.0, I(Utility >= tau) * [Utility * (Surprise + 0.4)])
 *
 * @param {string} text - The text/value being written to Aimos
 * @param {string} [companyId] - Company scope (defaults to canonical runtime config)
 * @returns {Promise<{rpe: number, route: 'LIGHTWEIGHT'|'STANDARD'|'FULL', surprise: number, utility: number}>}
 */
export async function computeRPE(text, companyId, options = {}) {
  const cid = companyId || COMPANY;
  const memoryType = options.memoryType || options.memory_type || '';

  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      rpe: 0,
      route: 'LIGHTWEIGHT',
      surprise: 0,
      utility: 0,
      proof_gate: buildProofGate({ text, memoryType, surprise: 0, utility: 0, rpe: 0, route: 'LIGHTWEIGHT' }),
    };
  }

  // Surprise = async (DB query), Utility = sync (heuristic, no LLM)
  const [surpriseResult, utilityResult] = await Promise.all([
    computeSurprise(text, cid),
    Promise.resolve(classifyUtility(text, memoryType)),
  ]);

  const { surprise } = surpriseResult;
  const utility = utilityResult.score;

  // Indicator function: if utility < tau, RPE collapses to 0
  const indicator = utility >= UTILITY_TAU ? 1 : 0;
  const rpe = Math.min(1.0, indicator * (utility * (surprise + 0.4)));

  // Determine route
  let route;
  if (rpe < LIGHTWEIGHT_MAX) {
    route = 'LIGHTWEIGHT';
  } else if (rpe < STANDARD_MAX) {
    route = 'STANDARD';
  } else {
    route = 'FULL';
  }

  await logEvent(cid, 'rpe-gate', 'rpe_computed', text.slice(0, 80), {
    reasoning: `RPE=${rpe.toFixed(3)} → ${route}. Surprise=${surprise.toFixed(3)}, Utility=${utility} (${utilityResult.label})`,
    rpe,
    route,
    surprise,
    utility,
    utility_label: utilityResult.label,
  });

  return {
    rpe,
    route,
    surprise,
    utility,
    proof_gate: buildProofGate({ text, memoryType, surprise, utility, rpe, route }),
  };
}

// ─── BATCH 10 LANE 2: SURPRISE_AT_SAVE + LATENT WRITE SIGNAL ──────────────────
// Papers: G-MemLLM, Titans
// surprise_at_save = ||embedding_predicted - embedding_actual||₂
// latent_write = RPE > 0.7 AND surprise_at_save > surprise_μ
// Aladdin: Surprise is metadata on the memory row. Never replaces or deletes.
// ─────────────────────────────────────────────────────────────────────────────

// Running mean and count for surprise distribution tracking
let _surpriseMean = 0;
let _surpriseCount = 0;

/**
 * Compute prediction error as L2 norm between predicted and actual embeddings.
 * surprise_at_save = ||embedding_predicted - embedding_actual||₂
 *
 * @param {number[]} predictedEmbedding - The predicted embedding (from context)
 * @param {number[]} actualEmbedding - The actual embedding (from getEmbedding)
 * @returns {{ surprise_at_save: number, prediction_error_norm: number, dim: number }}
 */
export function computePredictionError(predictedEmbedding, actualEmbedding) {
  if (!Array.isArray(predictedEmbedding) || !Array.isArray(actualEmbedding)) {
    return { surprise_at_save: 0, prediction_error_norm: 0, dim: 0 };
  }

  const dim = Math.min(predictedEmbedding.length, actualEmbedding.length);
  if (dim === 0) {
    return { surprise_at_save: 0, prediction_error_norm: 0, dim: 0 };
  }

  let sumSqDiff = 0;
  for (let i = 0; i < dim; i++) {
    const diff = (predictedEmbedding[i] || 0) - (actualEmbedding[i] || 0);
    sumSqDiff += diff * diff;
  }

  const predictionErrorNorm = Math.sqrt(sumSqDiff);
  // Normalize to [0, 1] range for surprise_at_save
  const surpriseAtSave = Math.min(1.0, predictionErrorNorm / Math.sqrt(dim));

  // Update running mean for latent write signal threshold
  _surpriseCount++;
  const delta = surpriseAtSave - _surpriseMean;
  _surpriseMean += delta / _surpriseCount;

  // Lane 7 Phase 3.1: Also update episodic model alongside global mean
  // Uses 'prediction_error' as context type when no memory type is available
  if (typeof _episodicModel !== 'undefined') {
    _episodicModel.update('prediction_error', surpriseAtSave);
  }

  return {
    surprise_at_save: Number(surpriseAtSave.toFixed(6)),
    prediction_error_norm: Number(predictionErrorNorm.toFixed(6)),
    dim,
  };
}

/**
 * Compute latent write signal based on RPE and surprise.
 * latent_write = RPE > 0.7 AND surprise_at_save > surprise_μ
 *
 * @param {number} rpe - RPE score from computeRPE
 * @param {number} surpriseAtSave - surprise_at_save from computePredictionError
 * @param {object} options - { rpeThreshold, surpriseMultiplier }
 * @returns {{ latent_write: boolean, rpe_threshold_met: boolean, surprise_above_mean: boolean, surprise_mean: number }}
 */
export function computeLatentWriteSignal(rpe, surpriseAtSave, options = {}) {
  const rpeThreshold = Number.isFinite(options.rpeThreshold) ? options.rpeThreshold : 0.7;
  const surpriseMultiplier = Number.isFinite(options.surpriseMultiplier) ? options.surpriseMultiplier : 1.0;

  const rpeThresholdMet = rpe > rpeThreshold;
  const surpriseAboveMean = _surpriseCount > 0
    ? surpriseAtSave > _surpriseMean * surpriseMultiplier
    : surpriseAtSave > 0.5;

  return {
    latent_write: rpeThresholdMet && surpriseAboveMean,
    rpe_threshold_met: rpeThresholdMet,
    surprise_above_mean: surpriseAboveMean,
    surprise_mean: Number(_surpriseMean.toFixed(6)),
    rpe_threshold: rpeThreshold,
  };
}

/**
 * Get current surprise mean for external consumers.
 */
export function getSurpriseMean() {
  return { mean: _surpriseMean, count: _surpriseCount };
}

// ─── BATCH 10.7 LANE 7, PHASE 3.1: MEMORYLLM EPISODIC SURPRISE MODEL ───────
// Paper: MEMORYLLM — Towards Self-Updatable Large Language Models
// Alongside-path diagnostic: per-context-type surprise distributions
// alongside existing global _surpriseMean. Production path unchanged.
// Phase 0: EpisodicSurpriseModel is diagnostic only; computeLatentWriteSignal
// still uses global _surpriseMean as the authoritative threshold.
// Aladdin: Episodic distributions only affect the latent_write_signal gate.
// They change *when* a memory gets enhanced routing, never *whether* it exists.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * EpisodicSurpriseModel — Per-context-type surprise distributions.
 *
 * At scale (50K+), a single global mean loses discriminative power because
 * different memory types have very different surprise baselines. A "surprising"
 * event_log (cosine distance ~0.3) is routine for a core_belief (cosine ~0.7).
 *
 * This class tracks per-context-type distributions using Welford online update,
 * which is numerically stable and O(1) memory per context type.
 *
 * Paper: MEMORYLLM — Towards Self-Updatable Large Language Models
 * Guarded math flag: episodic_surprise (Phase 0: closed → global mean path)
 */
export class EpisodicSurpriseModel {
  constructor() {
    /** @type {Map<string, {mean: number, m2: number, count: number}>} */
    this.distributions = new Map();
  }

  /**
   * Welford online update for a context-type distribution.
   * Numerically stable incremental mean and variance computation.
   *
   * @param {string} contextType - Memory type or context category
   * @param {number} surpriseValue - Surprise score for this observation
   */
  update(contextType, surpriseValue) {
    const ctx = String(contextType || 'default');
    const val = Number(surpriseValue) || 0;

    if (!this.distributions.has(ctx)) {
      this.distributions.set(ctx, { mean: val, m2: 0, count: 1 });
      return;
    }

    const dist = this.distributions.get(ctx);
    dist.count++;
    const delta = val - dist.mean;
    dist.mean += delta / dist.count;
    const delta2 = val - dist.mean;
    dist.m2 += delta * delta2;
  }

  /**
   * Get the mean surprise for a context type.
   * Falls back to global mean if context type has no observations.
   *
   * @param {string} contextType - Memory type or context category
   * @returns {number} Mean surprise for this context type
   */
  getMean(contextType) {
    const ctx = String(contextType || 'default');
    const dist = this.distributions.get(ctx);
    if (dist && dist.count > 0) return dist.mean;
    // Fallback to global mean if available
    if (_surpriseCount > 0) return _surpriseMean;
    return 0.5; // default threshold
  }

  /**
   * Get the variance for a context type.
   *
   * @param {string} contextType - Memory type or context category
   * @returns {number} Variance (0 if insufficient data)
   */
  getVariance(contextType) {
    const ctx = String(contextType || 'default');
    const dist = this.distributions.get(ctx);
    if (!dist || dist.count < 2) return 0;
    return dist.m2 / (dist.count - 1);
  }

  /**
   * Compute what percentile a surprise value falls in for its context type.
   * Uses Chebyshev's inequality for distribution-free bounds.
   *
   * @param {string} contextType - Memory type or context category
   * @param {number} value - Surprise value to evaluate
   * @returns {number} Approximate percentile (0-1), higher = more surprising
   */
  getPercentile(contextType, value) {
    const mean = this.getMean(contextType);
    const variance = this.getVariance(contextType);
    if (variance === 0) return value > mean ? 1.0 : 0.5;

    const stdDev = Math.sqrt(variance);
    const zScore = Math.abs(value - mean) / stdDev;
    // Chebyshev: at least (1 - 1/k²) within k std devs
    // Invert: percentile ≈ min(1, 1 - 1/(zScore² + 1))
    return Math.min(1.0, 1 - 1 / (zScore * zScore + 1));
  }

  /**
   * Compute episodic latent write signal using per-context surprise distribution.
   * Compares against context-specific mean instead of global mean.
   *
   * @param {number} rpe - RPE score
   * @param {number} surpriseAtSave - Surprise value at save time
   * @param {string} contextType - Memory type for context-specific comparison
   * @param {object} options - { rpeThreshold, surpriseMultiplier }
   * @returns {{ latent_write: boolean, rpe_threshold_met: boolean, surprise_above_mean: boolean, episodic_mean: number, context_type: string }}
   */
  computeEpisodicLatentWriteSignal(rpe, surpriseAtSave, contextType, options = {}) {
    const rpeThreshold = Number.isFinite(options.rpeThreshold) ? options.rpeThreshold : 0.7;
    const surpriseMultiplier = Number.isFinite(options.surpriseMultiplier) ? options.surpriseMultiplier : 1.0;

    const episodicMean = this.getMean(contextType);
    const rpeThresholdMet = rpe > rpeThreshold;
    const surpriseAboveMean = surpriseAtSave > episodicMean * surpriseMultiplier;

    return {
      latent_write: rpeThresholdMet && surpriseAboveMean,
      rpe_threshold_met: rpeThresholdMet,
      surprise_above_mean: surpriseAboveMean,
      episodic_mean: Number(episodicMean.toFixed(6)),
      context_type: String(contextType || 'default'),
    };
  }

  /**
   * Get statistics for all tracked context types.
   * @returns {{ contexts: object[], global_mean: number, global_count: number }}
   */
  getStats() {
    const contexts = [];
    for (const [ctx, dist] of this.distributions) {
      contexts.push({
        context_type: ctx,
        mean: Number(dist.mean.toFixed(6)),
        variance: Number((dist.count > 1 ? dist.m2 / (dist.count - 1) : 0).toFixed(6)),
        count: dist.count,
      });
    }
    return {
      contexts,
      global_mean: Number(_surpriseMean.toFixed(6)),
      global_count: _surpriseCount,
    };
  }
}

// Singleton instance for diagnostic use
const _episodicModel = new EpisodicSurpriseModel();

/**
 * Build diagnostic object for episodic surprise model.
 *
 * @param {number} rpe - RPE score
 * @param {number} surpriseAtSave - Surprise at save time
 * @param {string} contextType - Memory type for context-specific comparison
 * @returns {object} Diagnostic with episodic and global comparison
 */
export function buildEpisodicSurpriseDiagnostic(rpe, surpriseAtSave, contextType) {
  const globalResult = computeLatentWriteSignal(rpe, surpriseAtSave);
  const episodicResult = _episodicModel.computeEpisodicLatentWriteSignal(rpe, surpriseAtSave, contextType);
  const stats = _episodicModel.getStats();

  return {
    diagnostic_type: 'episodic_surprise_model',
    source_paper: 'MEMORYLLM — Towards Self-Updatable Large Language Models',
    diagnostic_only: true,
    global_path: {
      surprise_mean: globalResult.surprise_mean,
      latent_write: globalResult.latent_write,
      rpe_threshold_met: globalResult.rpe_threshold_met,
      surprise_above_mean: globalResult.surprise_above_mean,
    },
    episodic_path: {
      context_type: episodicResult.context_type,
      episodic_mean: episodicResult.episodic_mean,
      latent_write: episodicResult.latent_write,
      rpe_threshold_met: episodicResult.rpe_threshold_met,
      surprise_above_mean: episodicResult.surprise_above_mean,
    },
    distributions: stats.contexts,
    guardrails: {
      global_path_unchanged: true,
      production_latent_write_uses_global_mean: true,
      episodic_model_is_diagnostic_only: true,
    },
    guarded_math: {
      episodic_surprise: true,
    },
  };
}

/**
 * Update the episodic surprise model with a new observation.
 * Called alongside the global _surpriseMean update — both track simultaneously.
 *
 * @param {string} contextType - Memory type or context category
 * @param {number} surpriseValue - Surprise score for this observation
 */
export function updateEpisodicSurprise(contextType, surpriseValue) {
  _episodicModel.update(contextType, surpriseValue);
}
