// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: governance-resolver.js
// Pipeline: GOVERNANCE | Position: Routing step monitor (early stopping)
// Source: Circuit Breaker pattern (Netflix Hystrix), Early Stopping (ML training)
// Wave 3 source: EvolveRouter — Co-Evolving Routing and Prompt for
// Multi-Agent Question Answering. This service exposes paper formulas as
// diagnostics/runtime contracts; RouterGNN training and prompt rewriting remain
// guarded until validation sets and candidate prompts exist.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildLocalGlobalCascadeDiagnostic: Local/global cascade routing metrics
//     alongside existing EvolveRouter soft-targets. Routing math unchanged.
// ─────────────────────────────────────────────────────────────────────────────
/**
 * ROUTING MONITOR — ROUTING-COUNT EARLY STOPPING
 *
 * Monitors routing steps and triggers FallbackResolver when:
 * - Routing count exceeds max (default 15)
 * - Too many routing steps without progress
 *
 * Progress = routing step produced new valid write to entity graph.
 *
 * Created: 2026-03-31
 */

export const EVOLVE_ROUTER_SOURCE = 'EvolveRouter: Co-Evolving Routing and Prompt for Multi-Agent Question Answering';
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const EVOLVE_ROUTER_ALPHA = 0.3;
export const EVOLVE_ROUTER_DEFAULT_AGREEMENT_TAU = 0.65;
export const EVOLVE_ROUTER_DEFAULT_K_MIN = 2;
export const EVOLVE_ROUTER_DEFAULT_K_MAX = 4;

function clampNumber(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function canonicalAnswer(value = '') {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stableSoftmax(values, temperature = 1) {
  const tau = Math.max(1e-6, Number(temperature) || 1);
  const scaled = values.map((v) => (Number(v) || 0) / tau);
  const max = Math.max(...scaled, 0);
  const exps = scaled.map((v) => Math.exp(v - max));
  const sum = exps.reduce((acc, v) => acc + v, 0) || 1;
  return exps.map((v) => v / sum);
}

export function computeEvolveRouterSoftTargets(agentScores = [], temperature = 0.5) {
  const rows = Array.isArray(agentScores) ? agentScores : [];
  const probabilities = stableSoftmax(rows.map((row) => row?.f1 ?? row?.score ?? 0), temperature);
  return rows.map((row, index) => ({
    agent_id: row?.agent_id || row?.agentId || `agent_${index + 1}`,
    f1: clampNumber(row?.f1 ?? row?.score ?? 0, 0, 1),
    soft_target_probability: Number(probabilities[index].toFixed(6)),
  }));
}

export function computeEvolveRouterPriority({ meanF1 = 0, averageRouterWeight = 0, alpha = EVOLVE_ROUTER_ALPHA } = {}) {
  const f1 = clampNumber(meanF1, 0, 1);
  const weight = clampNumber(averageRouterWeight, 0, 1);
  const baseAlpha = Math.max(0, Number(alpha) || EVOLVE_ROUTER_ALPHA);
  const severity = 1 - f1;
  const priority = severity * (baseAlpha + weight);
  return {
    source_paper: EVOLVE_ROUTER_SOURCE,
    formula: 'priority(a) = (1 - F1(a)) * (alpha + avg_router_weight(a))',
    mean_f1: f1,
    average_router_weight: weight,
    alpha: baseAlpha,
    severity: Number(severity.toFixed(6)),
    priority: Number(priority.toFixed(6)),
  };
}

export function computeRouterWeightedAgreement(rankedAnswers = [], options = {}) {
  const rows = (Array.isArray(rankedAnswers) ? rankedAnswers : [])
    .map((row, index) => ({
      agent_id: row?.agent_id || row?.agentId || `agent_${index + 1}`,
      answer: canonicalAnswer(row?.answer),
      raw_answer: String(row?.answer || ''),
      weight: Math.max(0, Number(row?.weight ?? row?.router_weight ?? 0)),
    }))
    .filter((row) => row.answer && row.weight > 0);

  const kMin = Math.max(1, Number(options.kMin || EVOLVE_ROUTER_DEFAULT_K_MIN));
  const kMax = Math.max(kMin, Number(options.kMax || EVOLVE_ROUTER_DEFAULT_K_MAX));
  const tau = clampNumber(options.tau ?? EVOLVE_ROUTER_DEFAULT_AGREEMENT_TAU, 0, 1);
  const maxK = Math.min(kMax, rows.length);
  const trace = [];
  let selectedK = maxK || 0;
  let stopped = false;
  let finalAgreement = 0;

  for (let k = 1; k <= maxK; k += 1) {
    const consulted = rows.slice(0, k);
    const totalWeight = consulted.reduce((acc, row) => acc + row.weight, 0) || 1;
    const byAnswer = new Map();
    for (const row of consulted) {
      byAnswer.set(row.answer, (byAnswer.get(row.answer) || 0) + row.weight);
    }
    const bestWeight = Math.max(...byAnswer.values(), 0);
    const agreement = bestWeight / totalWeight;
    trace.push({
      k,
      agreement: Number(agreement.toFixed(6)),
      total_weight: Number(totalWeight.toFixed(6)),
    });
    finalAgreement = agreement;
    if (k >= kMin && agreement >= tau) {
      selectedK = k;
      stopped = true;
      break;
    }
  }

  return {
    source_paper: EVOLVE_ROUTER_SOURCE,
    formula: 'A(k,q)=max_y sum_i^k p_i(q) 1[y_i(q)=y] / sum_i^k p_i(q)',
    tau,
    k_min: kMin,
    k_max: kMax,
    selected_k: selectedK,
    stopped_early: stopped,
    agreement: Number(finalAgreement.toFixed(6)),
    trace,
    consulted_agents: rows.slice(0, selectedK).map((row) => row.agent_id),
  };
}

export function buildEvolveRouterRuntimeSignal({
  agentId = 'unknown',
  model = 'unknown',
  taskType = 'chat',
  confidence = 0,
  fallbackUsed = false,
  responseChars = 0,
  promptChars = 0,
  toolCallCount = 0,
} = {}) {
  const conf = clampNumber(confidence, 0, 1);
  const lengthPressure = Math.min(1, Math.max(0, Number(responseChars || 0) / 4000));
  const promptPressure = Math.min(1, Math.max(0, Number(promptChars || 0) / 12000));
  const fallbackPenalty = fallbackUsed ? 0.12 : 0;
  const proxyF1 = clampNumber((0.72 * conf) + (0.12 * (1 - lengthPressure)) + (0.08 * (1 - promptPressure)) + (0.08 * Math.min(1, Number(toolCallCount || 0) / 4)) - fallbackPenalty, 0, 1);
  const priority = computeEvolveRouterPriority({
    meanF1: proxyF1,
    averageRouterWeight: conf,
  });

  return {
    source_paper: EVOLVE_ROUTER_SOURCE,
    status: 'wired',
    agent_id: agentId,
    model,
    task_type: taskType,
    route_quality_proxy: Number(proxyF1.toFixed(6)),
    refinement_priority: priority,
    outcome_signals: {
      confidence: conf,
      fallback_used: fallbackUsed,
      response_chars: Number(responseChars || 0),
      prompt_chars: Number(promptChars || 0),
      tool_call_count: Number(toolCallCount || 0),
    },
    guarded_math: {
      router_gnn_training: false,
      kl_router_finetuning: false,
      prompt_rewrite_generation: false,
      validation_gate_acceptance: false,
    },
  };
}

export function buildRuntimeRoutingPulse({
  agentId = 'unknown',
  model = 'unknown',
  taskType = 'chat',
  confidence = 0,
  fallbackUsed = false,
  responseChars = 0,
  promptChars = 0,
  toolCallCount = 0,
  streamState = 'initialized',
  safetyIntercepts = 0,
} = {}) {
  const signal = buildEvolveRouterRuntimeSignal({
    agentId,
    model,
    taskType,
    confidence,
    fallbackUsed,
    responseChars,
    promptChars,
    toolCallCount,
  });
  const safetyPressure = Math.min(1, Math.max(0, Number(safetyIntercepts || 0)) / 3);
  const routeQuality = clampNumber(signal.route_quality_proxy, 0, 1);
  const pulse = clampNumber(routeQuality - (0.18 * safetyPressure), 0, 1);

  return {
    status: pulse >= 0.65 ? 'stable' : pulse >= 0.4 ? 'watch' : 'degraded',
    source_papers: [EVOLVE_ROUTER_SOURCE, AGENTPULSE_SOURCE],
    diagnostic_only: true,
    route_signal: signal,
    runtime_pulse: {
      stream_state: String(streamState || 'initialized'),
      safety_intercepts: Math.max(0, Number(safetyIntercepts || 0)),
      pulse_score: Number(pulse.toFixed(6)),
    },
    action_contract: {
      routing_changed: false,
      prompt_rewrite_generated: false,
      automatic_model_switching_enabled: false,
    },
  };
}

export function buildEvolveRouterStatus() {
  const softTargets = computeEvolveRouterSoftTargets([
    { agent_id: 'cot', f1: 0.7 },
    { agent_id: 'react_reflect', f1: 0.5 },
    { agent_id: 'summary', f1: 0.3 },
  ], 0.5);
  const agreement = computeRouterWeightedAgreement([
    { agent_id: 'cot', answer: 'April 22', weight: 0.48 },
    { agent_id: 'react_reflect', answer: 'April 22', weight: 0.31 },
    { agent_id: 'summary', answer: 'April 23', weight: 0.21 },
  ]);
  return {
    status: 'wired',
    source_paper: EVOLVE_ROUTER_SOURCE,
    adaptive_collaboration: agreement,
    soft_targets: softTargets,
    prompt_refinement_priority: computeEvolveRouterPriority({ meanF1: 0.42, averageRouterWeight: 0.61 }),
    contract: {
      outcome_data_logged_by_agent_runner: true,
      routing_rules_mutated_automatically: false,
      prompt_rewrites_generated_automatically: false,
      governance_constraints_override_allowed: false,
    },
    guarded_math: {
      router_gnn_training: false,
      kl_router_finetuning: false,
      prompt_optimization_loop: false,
      validation_regression_gate: false,
      local_global_cascade: true,
    },
    guarded_math_implemented: {
      local_global_cascade: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Bridging Local and Global Knowledge — Cascaded MoE Path Routing',
        coexistence_class: 'side_by_side_independent',
      },
    },
  };
}

/**
 * Create routing counter with specified max
 *
 * @param {number} maxRouting - Maximum routing steps (default 15)
 * @returns {object}
 */
export function createRoutingCounter(maxRouting = 15) {
  return {
    maxRouting,
    total: 0,
    withProgress: 0,
    withoutProgress: 0,
    exhausted: false,
    steps: [],
    createdAt: new Date().toISOString()
  };
}

/**
 * Increment routing counter
 * Updates exhaustion status based on progress.
 *
 * @param {object} counter - Routing counter object
 * @param {boolean} hasProgress - True if routing step produced new valid write
 * @returns {{exhausted: boolean, count: number, progressCount: number, reason?: string}}
 */
export function incrementRouting(counter, hasProgress = false) {
  if (!counter) {
    throw new Error('Counter not initialized');
  }

  counter.total++;
  if (hasProgress) {
    counter.withProgress++;
  } else {
    counter.withoutProgress++;
  }

  // Log step
  counter.steps.push({
    count: counter.total,
    hasProgress,
    timestamp: new Date().toISOString()
  });

  // Check exhaustion
  let exhausted = false;
  let reason = null;

  if (counter.total >= counter.maxRouting) {
    exhausted = true;
    reason = `Exceeded max routing steps (${counter.total} / ${counter.maxRouting})`;
  }

  // If more than 50% of steps have no progress, consider exhausted
  if (counter.total >= 5) {
    const progressRatio = counter.withProgress / counter.total;
    if (progressRatio < 0.2) {
      exhausted = true;
      reason = `Low progress rate (${(progressRatio * 100).toFixed(1)}% with progress)`;
    }
  }

  counter.exhausted = exhausted;

  return {
    exhausted,
    count: counter.total,
    progressCount: counter.withProgress,
    reason
  };
}

/**
 * Get routing statistics
 *
 * @param {object} counter - Routing counter object
 * @returns {object}
 */
export function getRoutingStats(counter) {
  if (!counter) {
    return {
      total: 0,
      withProgress: 0,
      withoutProgress: 0,
      exhausted: false,
      progressRatio: 0
    };
  }

  const progressRatio = counter.total > 0 ? counter.withProgress / counter.total : 0;

  return {
    total: counter.total,
    withProgress: counter.withProgress,
    withoutProgress: counter.withoutProgress,
    exhausted: counter.exhausted,
    progressRatio,
    maxRouting: counter.maxRouting,
    remaining: Math.max(0, counter.maxRouting - counter.total),
    createdAt: counter.createdAt,
    steps: counter.steps.length
  };
}

/**
 * Check if counter is near exhaustion
 *
 * @param {object} counter - Routing counter object
 * @param {number} warningThreshold - Percentage threshold to warn (default 80)
 * @returns {boolean}
 */
export function isNearExhaustion(counter, warningThreshold = 0.8) {
  if (!counter) return false;

  const percentage = counter.total / counter.maxRouting;
  return percentage >= warningThreshold;
}

/**
 * Get detailed routing trace
 *
 * @param {object} counter - Routing counter object
 * @returns {Array<object>}
 */
export function getRoutingTrace(counter) {
  if (!counter) return [];

  return counter.steps || [];
}

/**
 * Reset counter for new orchestration run
 *
 * @param {object} counter - Routing counter object
 * @returns {void}
 */
export function resetRoutingCounter(counter) {
  if (!counter) return;

  counter.total = 0;
  counter.withProgress = 0;
  counter.withoutProgress = 0;
  counter.exhausted = false;
  counter.steps = [];
  counter.createdAt = new Date().toISOString();
}

/**
 * Get status summary
 *
 * @param {object} counter - Routing counter object
 * @returns {string}
 */
export function getRoutingStatus(counter) {
  if (!counter) return 'Uninitialized';

  const stats = getRoutingStats(counter);

  if (counter.exhausted) {
    return `EXHAUSTED: ${stats.total}/${stats.maxRouting} steps (${stats.withProgress} with progress)`;
  }

  if (isNearExhaustion(counter)) {
    return `WARNING: ${stats.total}/${stats.maxRouting} steps (${stats.progressRatio.toFixed(1)} progress rate)`;
  }

  return `ACTIVE: ${stats.total}/${stats.maxRouting} steps (${stats.withProgress} with progress)`;
}

/**
 * Analyze routing effectiveness
 *
 * @param {object} counter - Routing counter object
 * @returns {object}
 */
export function analyzeRoutingEffectiveness(counter) {
  if (!counter || counter.total === 0) {
    return {
      effectiveSteps: 0,
      effectiveness: 0,
      assessment: 'No routing yet'
    };
  }

  const stats = getRoutingStats(counter);
  const effectiveness = stats.progressRatio;

  let assessment = 'Poor';
  if (effectiveness > 0.8) assessment = 'Excellent';
  else if (effectiveness > 0.6) assessment = 'Good';
  else if (effectiveness > 0.4) assessment = 'Acceptable';
  else if (effectiveness > 0.2) assessment = 'Marginal';

  return {
    effectiveSteps: stats.withProgress,
    totalSteps: stats.total,
    effectiveness,
    assessment,
    recommendation: effectiveness < 0.2 ? 'Consider fallback early' : 'Acceptable progress'
  };
}

/**
 * Create snapshot for logging/auditing
 *
 * @param {object} counter - Routing counter object
 * @returns {object}
 */
export function createRoutingSnapshot(counter) {
  if (!counter) return null;

  const stats = getRoutingStats(counter);

  return {
    timestamp: new Date().toISOString(),
    stats,
    exhausted: counter.exhausted,
    nearExhaustion: isNearExhaustion(counter),
    effectiveness: analyzeRoutingEffectiveness(counter),
    stepTrace: getRoutingTrace(counter)
  };
}

/**
 * Check if should trigger fallback
 *
 * @param {object} counter - Routing counter object
 * @returns {{shouldFallback: boolean, reason?: string}}
 */
export function shouldTriggerFallback(counter) {
  if (!counter) {
    return { shouldFallback: false };
  }

  if (counter.exhausted) {
    return {
      shouldFallback: true,
      reason: `Routing exhausted at ${counter.total} steps`
    };
  }

  // Also trigger if progress ratio is critically low
  if (counter.total >= 5) {
    const ratio = counter.withProgress / counter.total;
    if (ratio < 0.1) {
      return {
        shouldFallback: true,
        reason: `Critical progress ratio (${(ratio * 100).toFixed(1)}%)`
      };
    }
  }

  return { shouldFallback: false };
}

/**
 * Compact counter for persistence
 *
 * @param {object} counter - Routing counter object
 * @returns {object}
 */
export function compactCounter(counter) {
  return {
    total: counter?.total || 0,
    withProgress: counter?.withProgress || 0,
    withoutProgress: counter?.withoutProgress || 0,
    exhausted: counter?.exhausted || false,
    maxRouting: counter?.maxRouting || 15,
    createdAt: counter?.createdAt
  };
}

/**
 * Restore counter from compact form
 *
 * @param {object} compact - Compacted counter
 * @returns {object}
 */
export function restoreCounter(compact) {
  if (!compact) {
    return createRoutingCounter();
  }

  const counter = createRoutingCounter(compact.maxRouting);
  counter.total = compact.total;
  counter.withProgress = compact.withProgress;
  counter.withoutProgress = compact.withoutProgress;
  counter.exhausted = compact.exhausted;
  counter.createdAt = compact.createdAt;

  return counter;
}

/**
 * Local/Global Cascade Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Bridging Local and Global Knowledge — Cascaded MoE Path Routing
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes local/global cascade distribution
 * metrics as a diagnostic alongside existing EvolveRouter soft-targets. It
 * does NOT modify routing policy or specialist dispatch. The production
 * routing-monitor path remains authoritative. Guarded by guarded_math flag
 * local_global_cascade which is guarded in production (knowledge-gated: paper understanding required).
 */
export function buildLocalGlobalCascadeDiagnostic({
  routeMetrics = {},
} = {}) {
  const metrics = typeof routeMetrics === 'object' && routeMetrics !== null ? routeMetrics : {};
  const localHits = Number(metrics.localHits) || 0;
  const globalHits = Number(metrics.globalHits) || 0;
  const total = Math.max(1, localHits + globalHits);

  return {
    diagnostic: true,
    source_paper: 'Bridging Local and Global Knowledge — Cascaded MoE Path Routing',
    coexistence_class: 'side_by_side_independent',
    local_hits: localHits,
    global_hits: globalHits,
    local_ratio: localHits / total,
    global_ratio: globalHits / total,
    routing_unchanged: true,
    note: 'Alongside-path diagnostic. Local/global cascade stays separate from active routing.',
  };
}
