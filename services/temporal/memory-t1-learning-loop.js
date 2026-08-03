/**
 * memory-t1-learning-loop.js — Temporal recall outcome observation
 * Source: MEMORY-T1: Reinforcement Learning for Temporal Reasoning in
 * Multi-Session Agents (Du et al., arXiv:2512.20092, 2025)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: Chronos temporal recall branch in routes/aimos.js
 * 2. → Emits: coarse-to-fine temporal retrieval diagnostics
 * 3. ↔ Supports: future temporal policy learning without changing recall math
 *
 * LOGIC GUIDE:
 * MEMORY-T1 uses coarse-to-fine candidate generation and multi-level rewards:
 * answer accuracy, evidence grounding, and temporal consistency. This service
 * records the observation envelope only. It does not train RL, update policy,
 * or apply reward scores to ranking.
 */

function parseDate(value) {
  const ms = Date.parse(value || '');
  return Number.isFinite(ms) ? ms : null;
}

function inRange(ts, range = {}) {
  if (!Number.isFinite(ts)) return false;
  const start = parseDate(range.start || range.from);
  const end = parseDate(range.end || range.to);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return false;
  return ts >= start && ts <= end;
}

export function buildMemoryT1Observation({
  queryText = '',
  planner = {},
  chronos = {},
  memories = [],
  userFeedback = null,
} = {}) {
  const attemptedRange = chronos?.diagnostics?.attempted_range || planner?.temporal?.temporal_constraint || null;
  const timestamps = memories
    .map((memory) => parseDate(memory.created_at || memory.last_verified_at))
    .filter(Number.isFinite);
  const inScope = attemptedRange
    ? timestamps.filter((ts) => inRange(ts, attemptedRange)).length
    : 0;
  const temporalConsistencyProxy = timestamps.length && attemptedRange
    ? Number((inScope / timestamps.length).toFixed(3))
    : null;

  return {
    source_paper: 'MEMORY-T1',
    query: String(queryText || ''),
    coarse_to_fine: {
      temporal_filter_applied: Boolean((attemptedRange?.start || attemptedRange?.from) && (attemptedRange?.end || attemptedRange?.to)),
      attempted_range: attemptedRange,
      structured_event_candidates: Number(chronos?.diagnostics?.structured_event_count || 0),
      raw_turn_candidates: Number(chronos?.diagnostics?.raw_turn_count || 0),
      selected_memory_count: memories.length,
    },
    reward_channels: {
      answer_accuracy: {
        observed: userFeedback?.answer_accuracy ?? null,
        training_reward_applied: false,
      },
      evidence_grounding: {
        observed: userFeedback?.evidence_grounding ?? null,
        proxy_available: memories.length > 0,
        training_reward_applied: false,
      },
      temporal_consistency: {
        observed: userFeedback?.temporal_consistency ?? null,
        diagnostic_proxy: temporalConsistencyProxy,
        in_scope_memory_count: inScope,
        evaluated_memory_count: timestamps.length,
        training_reward_applied: false,
      },
    },
    guarded_math: {
      grpo_objective: false,
      reward_formula_5_10: false,
      policy_update: false,
      ranking_update: false,
    },
  };
}
