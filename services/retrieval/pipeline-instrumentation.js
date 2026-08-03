// ─── PIPELINE INSTRUMENTATION (Phase 0) ──────────────────────────────────────
// Status: Baseline Auditing — Tracks P50/P95 latency at every recall stage
// Purpose: Establishes exact "Speed Baseline" before optimizations
// Source: Speed.md Appendix C | architecture-authority.json
// Compliance: Knowledge Gate [X] | Brain Sovereignty [X]
// ─────────────────────────────────────────────────────────────────────────────

import { logEvent } from '../observe/event-ledger.js';

/**
 * Canonical list of the 16 recall pipeline stages
 * Used for consistent instrumentation across all recall paths
 */
export const RECALL_PIPELINE_STAGES = [
  { id: 'embedding_query', required: true, description: 'Generate query embedding via ONNX' },
  { id: 'hybrid_vector_bm25', required: true, description: 'Combined vector + BM25 retrieval' },
  { id: 'recursive_graph_walk', required: true, description: 'Traverse concept graph from seed memories' },
  { id: 'trust_scoring', required: true, description: 'Compute trust scores via learning/trust-score.js' },
  { id: 'concept_graph_ppr', required: true, description: 'Personalized PageRank augmentation' },
  { id: 'salience_frequency_evaluation', required: true, description: 'Annotate low-frequency salience via dormancy-manager.js compatibility file' },
  { id: 'recall_calibration', required: true, description: 'Bayesian calibration of belief/confidence' },
  { id: 'mnemonic_encoding', required: true, description: 'Tag encoding via mnemonic-encoder.js' },
  { id: 'context_building', required: true, description: 'Assemble final context for LLM' },
  { id: 'quality_gate_check', required: true, description: 'Final validation before response' },
  { id: 'response_formatting', required: true, description: 'Format output with reasoning trace' },
  { id: 'event_logging', required: true, description: 'Log recall event to aimos_events' },
  { id: 'cache_check', required: false, description: 'Semantic cache lookup (Phase 1)' },
  { id: 'early_exit_decision', required: false, description: 'Adaptive early-exit check (Phase 2)' },
  // speculative_prefetch and batched_stdp_enqueue removed — not runtime stages yet (Phase 2 future work)
  { id: 'entity_recall', required: false, description: 'Entity-aware memory recall (when entities detected)' },
  { id: 'bm25_rescue', required: false, description: 'BM25 keyword fallback for low-vector results' },
  { id: 'qmd_activation', required: false, description: 'Query-Memory Divergence mode switch' },
  { id: 'hyde_expansion', required: false, description: 'Hypothetical Document Embedding expansion' }
];

/**
 * Timing store: in-memory map of stage -> [durations in ms]
 * Note: In production, this would stream to a time-series DB
 */
const TIMINGS = new Map();

/**
 * Wrap a pipeline stage function with latency tracking
 * 
 * @param {string} stageId - The stage identifier from RECALL_PIPELINE_STAGES
 * @param {function} fn - The async function representing the stage
 * @param {object} context - The pipeline context (passed to fn)
 * @returns {Promise<any>} - The result of the stage function
 */
export async function instrumentedStage(stageId, fn, context) {
  const start = performance.now();
  let success = true;
  let error = null;
  
  try {
    const result = await fn(context);
    return result;
  } catch (err) {
    success = false;
    error = err.message;
    throw err;
  } finally {
    const duration = performance.now() - start;
    
    // Store timing for baseline reporting
    if (!TIMINGS.has(stageId)) {
      TIMINGS.set(stageId, []);
    }
    TIMINGS.get(stageId).push(duration);
    
    // Log to aimos_events for audit trail
    await logEvent('hom', 'system', 'pipeline_stage_timing', stageId, {
      duration_ms: Math.round(duration * 100) / 100, // 2 decimal places
      success,
      error: error || null,
      context_summary: context?.query_text?.slice(0, 50) || 'unknown'
    });
  }
}

/**
 * Generate a baseline report from collected timings
 * 
 * @param {string[]} stageFilter - Optional: only include these stages
 * @returns {object} - Report with P50, P95, count for each stage
 */
export function getBaselineReport(stageFilter = null) {
  const report = {};
  
  for (const [stage, timings] of TIMINGS.entries()) {
    // Apply filter if provided
    if (stageFilter && !stageFilter.includes(stage)) continue;
    
    if (timings.length === 0) continue;
    
    // Sort for percentile calculation
    const sorted = [...timings].sort((a, b) => a - b);
    const count = sorted.length;
    
    report[stage] = {
      p50: sorted[Math.floor(count * 0.5)],
      p95: sorted[Math.floor(count * 0.95)],
      p99: sorted[Math.floor(count * 0.99)],
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean: sorted.reduce((a, b) => a + b, 0) / count,
      count
    };
  }
  
  return report;
}

/**
 * Export timings for external analysis (e.g., save to file or send to monitoring)
 */
export function exportTimings() {
  return {
    collected_at: new Date().toISOString(),
    stages: Object.fromEntries(TIMINGS)
  };
}

/**
 * Clear timings (for fresh baseline collection)
 */
export function resetTimings() {
  TIMINGS.clear();
  logEvent('hom', 'system', 'pipeline_timings_reset', 'manual');
}

// Export for use in routes/aimos.js and services/retrieval/multi-stage-retrieval.js
export default { 
  RECALL_PIPELINE_STAGES, 
  instrumentedStage, 
  getBaselineReport, 
  exportTimings, 
  resetTimings 
};
