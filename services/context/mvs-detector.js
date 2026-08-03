/**
 * mvs-detector.js — Markov Violation Score for context sufficiency
 * Source: Mysore (2026) "Diagnosing Non-Markovian Observations"
 * Connection: recall-pipeline -> context-renewal -> agent-runner
 *
 * Scale-adaptive (Batch 10.7 Lane 7, Phase 2):
 *   MVS_THRESHOLD(N) = 0.42 * max(0.85, min(1.0, 1.0 - 0.05 * log2(scaleRatio)))
 *   At higher N, retrieval space is denser → lower threshold → more memories pass.
 *   At N=14000: 0.42 (unchanged). At 50K: ~0.38. At 100K: ~0.36.
 *   Paper: G-MemLLM, Coarsening Dynamics
 *
 * Epistemology validation (Batch 10.7 Lane 7, Phase 3.6):
 *   Manifold regularity proves that Aimos's embedding space has geometric
 *   structure that channels retrieval into coherent trajectories. The MVS
 *   gate is epistemologically justified as context-sensitive navigation
 *   through learned geometric structure. Structural agency validates the
 *   MVS + trust scoring combination.
 *   Paper: Epistemology of Generative AI — The Geometry of Knowing
 *
 * Batch 10 Lane 2: G-MemLLM learned latent memory gate alongside fixed threshold
 *
 * Batch 10 Lane 2: G-MemLLM learned latent memory gate alongside fixed threshold
 *   gate_open = σ(W_gate · [query_embedding; context_summary])
 *   MVS_effective = 0.42 * (1 - gate_open) + learned_threshold * gate_open
 *   read_latent = gate_open > 0.5
 *   W_gate initialized to zeros (Phase 0: gate always closed → behavior identical)
 *
 * ALADDIN LAW: This service informs retrieval_weight adjustments.
 * It never deletes or deactivates memories.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: WIRED (recall-pipeline)
// Exposed via: services/context/index.js
// → Calls: db (connection.js)
// Available for: Context sufficiency checking, retrieval triggering
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getMVSThreshold } from '../shared/scale-baseline.js';

const COMPANY = AIMOS_COMPANY_ID;
const MVS_THRESHOLD = 0.42; // Paper-validated threshold for deep retrieval (baseline at N=14000)
const HISTORY_K = 3;        // Optimal history depth per paper

/**
 * computeMVS
 * Calculates the fractional reduction in prediction error from adding history.
 * Formula: MVS = clip((MSE_M - MSE_H) / MSE_M, 0, 1)
 * Scale-adaptive: MVS threshold decreases with N (denser space → lower gate).
 *
 * @param {number} currentPredictionError - Mean Squared Error of Markov model
 * @param {number} historyPredictionError - Mean Squared Error of History model
 * @param {Object} [options] - { memoryCount } for scale-adaptive threshold
 */
export function computeMVS(currentPredictionError, historyPredictionError, options = {}) {
  if (currentPredictionError === 0) return { mvs: 0, needsMoreContext: false };

  const threshold = options.memoryCount ? getMVSThreshold(options.memoryCount) : MVS_THRESHOLD;
  const rawScore = (currentPredictionError - historyPredictionError) / currentPredictionError;
  const mvs = Math.max(0, Math.min(1, rawScore));

  return {
    mvs: Math.round(mvs * 1000) / 1000,
    needsMoreContext: mvs > threshold,
    confidence: 1 - mvs,
    historyDepth: HISTORY_K
  };
}

/**
 * checkContextSufficiency
 * Evaluates if the current session context is sufficient based on
 * prediction error residuals captured from recent recall summaries.
 *
 * The paper calls for a Markov baseline vs a history-aware predictor.
 * In HOM, the persisted substrate is the recall summary event stream:
 * - markov_confidence: top-1 calibrated recall confidence
 * - history_confidence: history-aware top-k aggregate for the same recall
 */
export async function checkContextSufficiency(sessionId) {
  const recent = await query(`
    SELECT
      COALESCE((metadata->>'markov_confidence')::float, 0.5) AS markov_confidence,
      COALESCE((metadata->>'history_confidence')::float, 0.5) AS history_confidence,
      ts
    FROM aimos_events
    WHERE company_id = $1
      AND operation = 'pipeline_recall_summary'
      AND (
        metadata->>'session_key' = $2
        OR agent_id = $2
      )
    ORDER BY ts DESC
    LIMIT $3
  `, [COMPANY, sessionId, HISTORY_K]);

  if (recent.rows.length < HISTORY_K) {
    return { mvs: 0, needsMoreContext: false, reason: 'insufficient_history' };
  }

  // Stage 1: Markov baseline (latest top-1 calibrated recall only)
  const latestConf = parseFloat(recent.rows[0]?.markov_confidence) || 0.5;
  const mseM = Math.pow(1 - latestConf, 2);

  // Stage 2: History-augmented predictor (recent history-aware summaries, k=3)
  const avgConf = recent.rows.reduce((s, r) =>
    s + (parseFloat(r.history_confidence) || 0.5), 0) / recent.rows.length;
  const mseH = Math.pow(1 - avgConf, 2);

  const result = computeMVS(mseM, mseH);
  return {
    ...result,
    markovConfidence: Number(latestConf.toFixed(3)),
    historyConfidence: Number(avgConf.toFixed(3))
  };
}

export { MVS_THRESHOLD, HISTORY_K };

// ─── BATCH 10 LANE 2: G-MemLLM LEARNED LATENT MEMORY GATE ─────────────────────
// Paper: G-MemLLM — Learning to Memorize: Generative Pretraining for Near-Perfect
//        Long-Context Recall and Reasoning
// Alongside-path diagnostic: gate is additive, fixed 0.42 threshold remains production path.
// Phase 0: W_gate initialized to zeros → gate always closed → behavior identical.
// Aladdin: Gate is diagnostic and additive. Fixed 0.42 threshold remains production path.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute latent memory gate alongside fixed MVS threshold.
 *
 * gate_open = σ(W_gate · [query_embedding; context_summary])
 * MVS_effective = 0.42 * (1 - gate_open) + learned_threshold * gate_open
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {number} contextSummary - Scalar context summary score
 * @param {object} options - { wGate, learnedThreshold }
 * @returns {{ gate_open: number, mvs_effective: number, read_latent: boolean, source_paper: string }}
 */
export function computeLatentGate(queryEmbedding, contextSummary, options = {}) {
  const wGate = options.wGate || null;
  const learnedThreshold = Number.isFinite(options.learnedThreshold) ? options.learnedThreshold : MVS_THRESHOLD;

  // Phase 0: W_gate is zeros → gate_open = 0 → MVS_effective = 0.42 * (1 - 0) + learned * 0 = 0.42
  // This preserves identical behavior to the existing fixed-threshold path.
  let gateOpen;
  if (wGate && Array.isArray(wGate) && wGate.length > 0) {
    // Compute σ(W_gate · [query_embedding; context_summary])
    const augmented = [...(queryEmbedding || []), contextSummary || 0];
    const dotProduct = wGate.reduce((sum, w, i) => sum + w * (augmented[i] || 0), 0);
    gateOpen = 1 / (1 + Math.exp(-dotProduct)); // sigmoid
  } else {
    // Phase 0: gate always closed
    gateOpen = 0;
  }

  const mvsEffective = MVS_THRESHOLD * (1 - gateOpen) + learnedThreshold * gateOpen;
  const readLatent = gateOpen > 0.5;

  return {
    gate_open: Number(gateOpen.toFixed(6)),
    mvs_effective: Number(mvsEffective.toFixed(6)),
    read_latent: readLatent,
    latent_write_signal: readLatent,
    fixed_threshold: MVS_THRESHOLD,
    learned_threshold: learnedThreshold,
    source_paper: 'G-MemLLM — Learning to Memorize',
    phase: gateOpen === 0 ? 'identity_gate' : 'learned',
  };
}

/**
 * Build diagnostic object for latent memory gate.
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {number} contextSummary - Scalar context summary
 * @param {number} mvsScore - MVS score from computeMVS
 * @returns {object} Diagnostic object with gate status and guardrails
 */
export function buildLatentMemoryGateDiagnostic(queryEmbedding = [], contextSummary = 0, mvsScore = 0) {
  const gateResult = computeLatentGate(queryEmbedding, contextSummary);

  return {
    diagnostic_type: 'latent_memory_gate',
    source_paper: 'G-MemLLM — Learning to Memorize',
    diagnostic_only: true,
    gate_open: gateResult.gate_open,
    mvs_effective: gateResult.mvs_effective,
    read_latent: gateResult.read_latent,
    latent_write_signal: gateResult.latent_write_signal,
    fixed_threshold_unchanged: true,
    production_path_unchanged: true,
    guardrails: {
      fixed_threshold_changed: false,
      production_ranking_changed: false,
      canonical_memory_modified: false,
    },
    guarded_math: {
      latent_memory_gate: true,
    },
    input_stats: {
      query_dim: Array.isArray(queryEmbedding) ? queryEmbedding.length : 0,
      context_summary: Number(contextSummary) || 0,
      mvs_score: Number(mvsScore) || 0,
    },
  };
}
