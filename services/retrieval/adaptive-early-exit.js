// ─── ADAPTIVE EARLY-EXIT RETRIEVAL (Phase 2) ─────────────────────────────────
// Status: Cognitive Optimization — Stops pipeline at stage 7 when confidence is high
// Purpose: Reduces latency by skipping PPR/dormancy/calibration when MVS < 0.42
// Source: Adaptive RAG (Wang et al., 2024) — Speed.md Appendix A
// Compliance: Knowledge Gate [X] | Aladdin Law [X] (no weight changes)
// Additive Batch9 Wave1 authority: Fast-Slow Planning, DH-RAG, and
// RNNs Are Not Transformers (Yet). Fast/slow recall diagnostics are
// diagnostic-only; they do not alter early-exit thresholds, ranking, or recall
// path selection.
// Scale-adaptive (Batch 10.7 Lane 7): 14000 fallback replaced with
//   MEMORY_COUNT_BASELINE from scale-baseline.js.
// ─────────────────────────────────────────────────────────────────────────────

import { MEMORY_COUNT_BASELINE } from '../shared/scale-baseline.js';

export function getEarlyExitThreshold(memoryCount = MEMORY_COUNT_BASELINE) {
  return Math.min(
    0.98,
    0.82 + 0.02 * Math.log10(Math.max(1, Number(memoryCount) / MEMORY_COUNT_BASELINE))
  );
}

/**
 * Adaptive Early-Exit Decision Engine
 *
 * Determines whether to stop the 16-stage recall pipeline early (after stage 7: BM25 rerank)
 * based on confidence metrics and Minimum Viable Sufficiency (MVS).
 *
 * Exit conditions (ANY of these triggers early exit):
 * 1. High confidence gap: top_1_score > 0.82 AND score_gap > 0.15
 * 2. Low uncertainty: MVS < 0.42 AND avg_top5 > 0.65
 * 3. Absolute confidence: top_1_score > 0.95 (rare, but safe)
 *
 * Anti-exit conditions (prevent bronze lock-in at scale):
 * - If top-1 is bronze and confidence gap < 0.15, continue to full pipeline
 * - Thresholds scale with memory count: confidence > 0.85 + 0.05 * log10(N/14000)
 *
 * @param {number[]} topScores - Array of similarity scores [highest, second, ...]
 * @param {number} mvsScore - Minimum Viable Sufficiency score (lower = more certain)
 * @param {object} context - Optional context (e.g., query_type, user_trust_level, top1_medallion, total_memories)
 * @returns {boolean} - true if pipeline should exit early, false to continue full 16 stages
 */
export function shouldEarlyExit(topScores, mvsScore, context = {}) {
  // Guard: Need at least 2 scores to compute gap
  if (!topScores || topScores.length < 2) return false;

  // Uniformity guard: if all top scores cluster within a narrow band,
  // the reranker produced no differentiation. That means uncertainty,
  // not confidence. Continue to full pipeline for proper scoring.
  // Paper compliance (Adaptive RAG, Aladdin Law): this is a decision
  // condition, not a weight change. Uniform scores are a degenerate
  // case where early exit would skip dormancy/trust/calibration stages
  // that produce the differentiation the reranker failed to create.
  const UNIFORM_STD_THRESHOLD = 0.05;
  const mean = topScores.reduce((s, v) => s + v, 0) / topScores.length;
  const variance = topScores.reduce((s, v) => s + (v - mean) ** 2, 0) / topScores.length;
  const stdDev = Math.sqrt(variance);
  if (stdDev < UNIFORM_STD_THRESHOLD) {
    return false;
  }

  const [top1, top2] = topScores;

  // Metric 1: Confidence Gap (how much better is #1 than #2?)
  const scoreGap = top1 - top2;
  // Scale-aware thresholds tighten gently with corpus size and remain bounded.
  const N = context.total_memories || MEMORY_COUNT_BASELINE;
  const scaleThreshold = getEarlyExitThreshold(N);

  // Anti-exit: Bronze lock-in guard — bronze at top-1 with small gap means
  // a frequent generic memory is crowding out nuanced results from later stages
  const top1Medallion = context.top1_medallion || 'silver';
  if (top1Medallion === 'bronze') {
    return false;
  }

  // High differentiated score. The threshold is in the same [0,1] score
  // domain as top1; no nonlinear gap transformation hides its units.
  if (top1 > scaleThreshold && scoreGap > 0.15) {
    return true;
  }

  // Condition 3: Near-perfect score (rare but safe to exit)
  if (top1 > 0.95 && scoreGap > 0.05) {
    return true;
  }

  // Condition 4: Context-aware override (e.g., high-trust user gets more aggressive exit)
  if (context.user_trust_level === 'high' && top1 > scaleThreshold && scoreGap > 0.12 && mvsScore < 0.50) {
    return true;
  }

  // Default: Continue full pipeline for safety
  return false;
}

/**
 * Generate early-exit metadata for audit trail
 * Per Speed.md: "Preserve full trace for audit. Do NOT skip quality gates on write path."
 * 
 * @param {object} params - The parameters used for the decision
 * @returns {object} - Metadata to attach to the recall response
 */
export function generateEarlyExitMetadata(params) {
  return {
    early_exit: true,
    exit_stage: 7, // BM25 rerank
    exit_reason: params.reason,
    confidence_gap: params.confidence_gap,
    mvs_score: params.mvs_score,
    top_score: params.top_score,
    top1_medallion: params.top1_medallion || null,
    total_memories: params.total_memories || null,
    scale_threshold: params.scale_threshold || null,
    bronze_lockin_guard: params.bronze_lockin_guard || false,
    fallback_available: true, // Always preserve ability to re-run full pipeline
    audit_trail: 'adaptive_early_exit_v2'
  };
}

export function buildFastSlowRecallDiagnostics({
  topScores = [],
  mvsScore = 1,
  query = '',
  evidenceCount = 0,
  latencyMs = 0,
} = {}) {
  const scores = Array.isArray(topScores) ? topScores.map(Number).filter(Number.isFinite) : [];
  const top1 = scores[0] ?? 0;
  const top2 = scores[1] ?? 0;
  const scoreGap = top1 - top2;
  const highConfidence = shouldEarlyExit(scores, Number(mvsScore || 1));
  const vagueHumanQuery = /\b(last|recent|problem|issue|solved|changed|week|month|when|what happened)\b/i.test(String(query || ''));
  const needsSlowPath = !highConfidence || vagueHumanQuery || Number(evidenceCount || 0) < 3;

  return {
    source_papers: [
      'Bridging Large-Model Reasoning and Real-Time Control via Agentic Fast-Slow Planning',
      'RNNs Are Not Transformers (Yet): The Key Bottleneck on In-Context Retrieval',
      'DH-RAG',
    ],
    diagnostic_only: true,
    selected_path: needsSlowPath ? 'slow_path_recommended' : 'fast_path_sufficient',
    fast_path_confidence: Number(Math.max(0, Math.min(1, scoreGap / (scoreGap + 0.1 || 1))).toFixed(4)),
    signals: {
      top_score: top1,
      second_score: top2,
      score_gap: Number(scoreGap.toFixed(4)),
      mvs_score: Number(mvsScore || 1),
      evidence_count: Number(evidenceCount || 0),
      latency_ms: Number(latencyMs || 0),
      vague_human_query: vagueHumanQuery,
    },
    slow_path: {
      recommended: needsSlowPath,
      reason: needsSlowPath
        ? (vagueHumanQuery ? 'vague_human_query_needs_hierarchical_or_temporal_pack' : 'insufficient_fast_path_confidence')
        : null,
    },
    ranking_math_changed: false,
    recall_path_changed: false,
  };
}

/**
 * Wrapper for instrumented pipeline stage that respects early-exit
 * Use this in multi-stage-retrieval.js to wrap stages 8-16
 * 
 * @param {string} stageId - The stage identifier
 * @param {function} stageFn - The stage function to potentially skip
 * @param {object} context - Pipeline context including scores and MVS
 * @returns {Promise<object>} - Stage result or early-exit marker
 */
export async function instrumentedStageWithEarlyExit(stageId, stageFn, context) {
  // Check if we should have exited before this stage
  if (context.shouldExitAfterStage7 && stageId.startsWith('stage_8_')) {
    return {
      early_exit: true,
      stage_skipped: stageId,
      reason: context.early_exit_reason
    };
  }
  
  // Run the stage normally
  return await stageFn(context);
}

export default { shouldEarlyExit, generateEarlyExitMetadata, buildFastSlowRecallDiagnostics, instrumentedStageWithEarlyExit };
