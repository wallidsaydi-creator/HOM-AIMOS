// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — agent-runner records session energy and consumes
//         Turn-Adaptive Budget diagnostics before prompt assembly
// Purpose: Tracks compute energy/cost per model and session; computes Pareto
//          frontier for accuracy-energy trade-off selection (P2-B3-10)
// Wire into: agent-runner.js (agent-run pipeline, model selection/pre-step)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// ENERGY BUDGET (energy-budget.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-10: Tracks computational energy/cost per model and session.
// Computes Pareto frontier and selects models based on accuracy-energy trade-offs.
// Wave 3 source: Not All Turns Are Equally Hard — Adaptive Thinking Budgets
// for Efficient Multi-Turn Reasoning (TAB, 2026).
// TAB adaptation: assign a discrete per-turn thinking budget from
// B = {256, 512, 1024, 2048, 4096} using current turn difficulty and
// remaining global budget. Learned GRPO policy remains guarded.
// Additive Batch9.5 Wave6 authority: high-efficiency solar-cell work adds
// audit-only capture-efficiency diagnostics; model routing and TAB math remain
// unchanged.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const TAB_SOURCE = 'Not All Turns Are Equally Hard: Adaptive Thinking Budgets For Efficient Multi-Turn Reasoning';
export const THERMAL_COMFORT_SOURCE = 'Agentic AI-Enabled Framework for Thermal Comfort and Building Energy Assessment';
export const FRUGALGPT_ENERGY_SOURCE = 'FrugalGPT';

// ─── E4: FRUGALGPT ENERGY ─────────────────────────────────────────────────────
// Source: FrugalGPT
// Formula: E_total = E_base * (1 + 0.3*log2(N/14000))
// At 14K: E_total=E_base. At 100K: E_total≈1.85*E_base.
// Energy affects compute budget, not content. Aladdin SAFE.

export function computeTotalEnergyBudget(eBase, memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return eBase * (1 + 0.3 * Math.log2(N / 14000));
}

export function buildEnergyBudgetDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_paper: FRUGALGPT_ENERGY_SOURCE,
    energy_total_formula: 'E_total = E_base * (1 + 0.3*log2(N/14000))',
    scale_factor: Number((1 + 0.3 * Math.log2(N / 14000)).toFixed(6)),
    diagnostic_only: true,
    guarded_math: {
      frugalgpt_energy: true,
    },
  };
}
export const TURN_ADAPTIVE_BUDGETS = Object.freeze([256, 512, 1024, 2048, 4096]);

// Provider-agnostic energy classes. Specific provider/model catalogs belong in
// the provider registry, not this diagnostic budget helper.
const ENERGY_CLASS_COSTS = {
  frontier: 1.2,
  balanced: 0.5,
  compact: 0.15,
  embedding: 0.05,
};

function inferEnergyClass(modelId) {
  const id = String(modelId || '').toLowerCase();
  if (id.includes('embed')) return 'embedding';
  if (/\b(small|mini|tiny|compact|light)\b/.test(id)) return 'compact';
  if (/\b(frontier|large|xl|70b|120b|405b)\b/.test(id)) return 'frontier';
  return 'balanced';
}

/**
 * Estimate energy cost (joules) for a model and token count.
 *
 * @param {string} modelId - Model identifier
 * @param {number} tokenCount - Number of tokens processed
 * @returns {number} - Estimated energy in joules
 */
export function estimateJoules(modelId, tokenCount) {
  const energyClass = inferEnergyClass(modelId);
  const costPerKTokens = ENERGY_CLASS_COSTS[energyClass] || ENERGY_CLASS_COSTS.balanced;
  return (tokenCount / 1000) * costPerKTokens;
}

/**
 * Find models on the Pareto frontier (no model dominates another).
 * A model dominates if it has better accuracy AND lower energy.
 *
 * @param {Array<Object>} models - Models with {id, accuracy, energy} properties
 * @returns {Array<Object>} - Models on Pareto frontier
 */
export function getParetoFrontier(models) {
  if (!Array.isArray(models) || models.length === 0) {
    return [];
  }

  const frontier = [];

  for (const candidate of models) {
    let dominated = false;

    for (const other of models) {
      // Other dominates candidate if: higher accuracy AND lower energy
      if (
        other.accuracy > candidate.accuracy &&
        other.energy < candidate.energy
      ) {
        dominated = true;
        break;
      }
    }

    if (!dominated) {
      frontier.push(candidate);
    }
  }

  // Sort frontier by accuracy descending
  return frontier.sort((a, b) => b.accuracy - a.accuracy);
}

/**
 * Select cheapest model that meets minimum accuracy threshold.
 *
 * @param {number} accuracyFloor - Minimum required accuracy (0-1)
 * @param {Array<Object>} models - Available models with {id, accuracy, energy}
 * @returns {Object|null} - Selected model or null if none meet threshold
 */
export function selectCheapestModel(accuracyFloor, models) {
  const candidates = models
    .filter(m => m.accuracy >= accuracyFloor)
    .sort((a, b) => a.energy - b.energy);

  return candidates.length > 0 ? candidates[0] : null;
}

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

export function estimateTurnDifficulty({
  prompt = '',
  conversationHistory = [],
  taskType = 'chat',
  psychometricDifficulty = null,
} = {}) {
  const text = String(prompt || '');
  const history = Array.isArray(conversationHistory) ? conversationHistory : [];
  const historyChars = history.reduce((sum, turn) => sum + String(turn?.content || '').length, 0);
  const promptPressure = Math.min(1, text.length / 3500);
  const historyPressure = Math.min(1, historyChars / 12000);
  const questionPressure = Math.min(1, (text.match(/\?/g) || []).length / 5);
  const complexityPressure = ['analysis', 'research', 'investigation', 'architecture', 'coding', 'code', 'heavy'].includes(String(taskType || '').toLowerCase())
    ? 0.32
    : 0.08;
  const psychometricPressure = psychometricDifficulty == null
    ? 0.25
    : clamp01(psychometricDifficulty, 0.25);

  const difficulty = clamp01(
    (promptPressure * 0.24)
    + (historyPressure * 0.18)
    + (questionPressure * 0.18)
    + complexityPressure
    + (psychometricPressure * 0.22)
  );
  const level = Math.max(0, Math.min(4, Math.round(difficulty * 4)));

  return {
    source_paper: TAB_SOURCE,
    difficulty_0_1: Number(difficulty.toFixed(3)),
    difficulty_level: level,
    signals: {
      prompt_pressure: Number(promptPressure.toFixed(3)),
      history_pressure: Number(historyPressure.toFixed(3)),
      question_pressure: Number(questionPressure.toFixed(3)),
      task_type_pressure: Number(complexityPressure.toFixed(3)),
      psychometric_pressure: Number(psychometricPressure.toFixed(3)),
    }
  };
}

/**
 * FrugalGPT Energy Diagnostic — Alongside-path diagnostic
 *
 * Source paper: FrugalGPT
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * FrugalGPT proposes cost-aware cascade routing: cheaper models first,
 * escalate on failure. This diagnostic computes an energy-tier cost
 * assessment for the current budget state. It is an observable metric;
 * production budget allocation and model routing remain authoritative.
 * Guarded by guarded_math flag frugalgpt_energy (knowledge-gated).
 */
export function buildFrugalGPTEnergyDiagnostic(budgetState = {}) {
  const globalBudget = Number(budgetState?.globalBudget ?? budgetState?.global_budget ?? 8192);
  const usedTokens = Number(budgetState?.usedTokens ?? budgetState?.used_tokens ?? 0);
  const remainingTokens = Math.max(0, globalBudget - usedTokens);
  const utilizationRatio = globalBudget > 0 ? usedTokens / globalBudget : 0;
  const model = String(budgetState?.model || '');
  const energyClass = inferEnergyClass(model);
  const jouleEstimate = estimateJoules(model, usedTokens);
  const costEfficiencyScore = utilizationRatio > 0 && jouleEstimate > 0
    ? Number((remainingTokens / (jouleEstimate + 1)).toFixed(6))
    : 0;

  return {
    diagnostic: true,
    source_paper: FRUGALGPT_ENERGY_SOURCE,
    coexistence_class: 'side_by_side_independent',
    energy_class: energyClass,
    joule_estimate: Number(jouleEstimate.toFixed(6)),
    global_budget: globalBudget,
    used_tokens: usedTokens,
    remaining_tokens: remainingTokens,
    utilization_ratio: Number(utilizationRatio.toFixed(6)),
    cost_efficiency_score: costEfficiencyScore,
    budget_allocation_unchanged: true,
    note: 'Alongside-path diagnostic. Energy cost assessment does not replace production budget allocation.',
  };
}

export function allocateTurnAdaptiveBudget({
  prompt = '',
  conversationHistory = [],
  taskType = 'chat',
  psychometricProfile = null,
  globalBudget = 8192,
  usedTokens = 0,
} = {}) {
  const psychometricDifficulty = psychometricProfile?.task_difficulty?.difficulty_proxy_0_1 ?? null;
  const difficulty = estimateTurnDifficulty({
    prompt,
    conversationHistory,
    taskType,
    psychometricDifficulty,
  });
  const remaining = Math.max(0, Number(globalBudget || 0) - Number(usedTokens || 0));
  const rawBudget = TURN_ADAPTIVE_BUDGETS[difficulty.difficulty_level] || TURN_ADAPTIVE_BUDGETS[2];
  const budget = Math.max(
    TURN_ADAPTIVE_BUDGETS[0],
    Math.min(rawBudget, remaining || rawBudget)
  );

  // FrugalGPT energy math applied: cost-aware cascade computation alongside TAB budget
  const frugalEnergyDiagnostic = buildFrugalGPTEnergyDiagnostic({
    globalBudget,
    usedTokens,
    model: taskType,
  });

  return {
    source_paper: TAB_SOURCE,
    status: 'wired',
    policy: 'heuristic_tab_runtime_proxy',
    mdp_mapping: {
      state: 'conversation history plus current turn',
      action: 'discrete thinking token budget',
      transition: 'append response to trajectory',
      objective: 'accuracy-token tradeoff under global budget',
    },
    discrete_budget_set: TURN_ADAPTIVE_BUDGETS,
    selected_budget_tokens: budget,
    remaining_global_budget_tokens: remaining,
    turn_difficulty: difficulty,
    route_hint: difficulty.difficulty_level <= 1
      ? 'fast_or_small_model'
      : difficulty.difficulty_level >= 3
        ? 'deep_reasoning_or_stronger_model'
        : 'standard_model',
    frugal_energy_diagnostic: frugalEnergyDiagnostic,
    guarded_math: {
      grpo_policy_training: false,
      learned_budget_policy: false,
      terminal_reward_optimization: false,
      all_subquestion_planner: false,
      frugalgpt_energy: true,
    },
    guarded_math_implemented: {
      frugalgpt_energy: { enabled: true, diagnostic_only: true, source_paper: FRUGALGPT_ENERGY_SOURCE },
    },
  };
}

export function buildTurnAdaptiveBudgetStatus(sample = {}) {
  return {
    status: 'wired',
    source_paper: TAB_SOURCE,
    contract: allocateTurnAdaptiveBudget({
      prompt: sample.prompt || 'Analyze and implement a multi-step architecture fix with tests.',
      conversationHistory: sample.conversationHistory || [],
      taskType: sample.taskType || 'architecture',
      psychometricProfile: sample.psychometricProfile || null,
      globalBudget: sample.globalBudget || 8192,
      usedTokens: sample.usedTokens || 0,
    })
  };
}

export function buildRuntimeComfortBudgetDiagnostics({
  latencyMs = 0,
  estimatedJoules = 0,
  contextPressure = 0,
  userFriction = 0,
  safetyMargin = 1,
} = {}) {
  const latencyPressure = clamp01(Number(latencyMs || 0) / 30000);
  const energyPressure = clamp01(Number(estimatedJoules || 0) / 100);
  const context = clamp01(contextPressure, 0);
  const friction = clamp01(userFriction, 0);
  const safety = clamp01(safetyMargin, 1);
  const discomfort = clamp01(
    (0.28 * latencyPressure)
    + (0.22 * energyPressure)
    + (0.2 * context)
    + (0.18 * friction)
    + (0.12 * (1 - safety))
  );

  return {
    status: 'diagnostic',
    source_paper: THERMAL_COMFORT_SOURCE,
    diagnostic_only: true,
    comfort_state: discomfort >= 0.7
      ? 'uncomfortable'
      : discomfort >= 0.4
        ? 'watch'
        : 'comfortable',
    discomfort_score: Number(discomfort.toFixed(6)),
    signals: {
      latency_pressure: Number(latencyPressure.toFixed(6)),
      energy_pressure: Number(energyPressure.toFixed(6)),
      context_pressure: Number(context.toFixed(6)),
      user_friction: Number(friction.toFixed(6)),
      safety_margin: Number(safety.toFixed(6)),
    },
    action_contract: {
      budget_policy_changed: false,
      model_routing_changed: false,
      user_escalation_recommended: discomfort >= 0.7,
    },
  };
}

export function buildSolarEfficiencyAuditDiagnostics({
  capturedUsefulTokens = 0,
  spentTokens = 0,
  estimatedJoules = 0,
  contextPressure = 0,
  evidencePreservation = 1,
} = {}) {
  const captured = Math.max(0, Number(capturedUsefulTokens || 0));
  const spent = Math.max(0, Number(spentTokens || 0));
  const captureEfficiency = spent > 0 ? clamp01(captured / spent) : 0;
  const joulePressure = clamp01(Number(estimatedJoules || 0) / 100);
  const pressure = clamp01(
    (0.34 * (1 - captureEfficiency))
    + (0.24 * joulePressure)
    + (0.22 * clamp01(contextPressure))
    + (0.2 * (1 - clamp01(evidencePreservation, 1)))
  );

  return {
    source_paper: 'High-Efficiency Hexagonal Nanowire MAPbI3 Perovskite Solar Cell with Broadband Light Trapping',
    status: pressure >= 0.7 ? 'inefficient_high_pressure' : pressure >= 0.4 ? 'watch' : 'efficient',
    audit_only_analogy: true,
    diagnostic_only: true,
    analogy_scope: 'capture-efficiency pressure for evidence/compute use, not solar-cell physics',
    metrics: {
      captured_useful_tokens: captured,
      spent_tokens: spent,
      capture_efficiency: Number(captureEfficiency.toFixed(6)),
      joule_pressure: Number(joulePressure.toFixed(6)),
      context_pressure: Number(clamp01(contextPressure).toFixed(6)),
      evidence_preservation: Number(clamp01(evidencePreservation, 1).toFixed(6)),
      efficiency_pressure_proxy: Number(pressure.toFixed(6)),
    },
    guardrails: {
      energy_formula_changed: false,
      model_routing_changed: false,
      budget_policy_changed: false,
      canonical_memory_changed: false,
    },
  };
}

/**
 * Track cumulative energy usage for a session.
 *
 * @param {string} sessionId - Session identifier
 * @param {number} joules - Energy in joules to add
 * @returns {Promise<{sessionId: string, totalJoules: number}>}
 */
export async function trackSessionEnergy(sessionId, joules) {
  try {
    const result = await query(
      `INSERT INTO session_energy (session_id, joules_used, ts)
       VALUES ($1, $2, NOW())
       RETURNING session_id`,
      [sessionId, joules]
    );

    // Get total for session
    const totals = await query(
      `SELECT SUM(joules_used) as total_joules FROM session_energy
       WHERE session_id = $1`,
      [sessionId]
    );

    return {
      sessionId,
      totalJoules: parseFloat(totals.rows[0]?.total_joules || 0)
    };
  } catch (err) {
    console.error('[energy-budget] trackSessionEnergy error:', err.message);
    return { sessionId, totalJoules: 0 };
  }
}

/**
 * Check if session energy budget has been exceeded.
 *
 * @param {string} sessionId - Session identifier
 * @param {number} budget - Energy budget in joules
 * @returns {Promise<boolean>} - true if budget exceeded
 */
export async function isEnergyBudgetExceeded(sessionId, budget) {
  try {
    const result = await query(
      `SELECT SUM(joules_used) as total_joules FROM session_energy
       WHERE session_id = $1`,
      [sessionId]
    );

    const total = parseFloat(result.rows[0]?.total_joules || 0);
    return total > budget;
  } catch (err) {
    console.error('[energy-budget] isEnergyBudgetExceeded error:', err.message);
    return false;
  }
}

// ─── PROVIDER ENERGY ATTRIBUTION ────────────────────────────────────────────────
// Source: Google SRE (cost attribution), FinOps (cloud cost allocation)
//
// Tracks compute energy per provider for cost monitoring and health scoring.
// Additive: uses existing session_energy table with new provider_id and model columns.
// Aladdin: only adds data, never deletes.

/**
 * Track energy usage attributed to a specific provider.
 *
 * @param {string} providerId - Provider identifier (e.g., 'anthropic', 'openai')
 * @param {string} model - Model used (e.g., 'claude-opus-4-7')
 * @param {number} tokens - Token count for this call
 * @param {number} joules - Energy consumed in joules
 * @param {string} [sessionId] - Optional session ID for correlation
 * @returns {Promise<{providerId: string, joules: number}>}
 */
export async function trackProviderEnergy(providerId, model, tokens, joules, sessionId = null) {
  try {
    const sid = sessionId || `provider:${providerId}:${Date.now()}`;
    await query(
      `INSERT INTO session_energy (session_id, joules_used, provider_id, model, ts)
       VALUES ($1, $2, $3, $4, NOW())`,
      [sid, joules, providerId, model]
    );

    return { providerId, joules };
  } catch (err) {
    console.error('[energy-budget] trackProviderEnergy error:', err.message);
    return { providerId, joules: 0 };
  }
}

/**
 * Get energy summary for a provider over a time window.
 *
 * @param {string} providerId - Provider identifier
 * @param {number} [hours=24] - Lookback window in hours
 * @returns {Promise<{providerId: string, totalJoules: number, totalTokens: number, avgJoulesPerCall: number, callCount: number}>}
 */
export async function getProviderEnergySummary(providerId, hours = 24) {
  try {
    const result = await query(
      `SELECT
         SUM(joules_used) as total_joules,
         COUNT(*) as call_count
       FROM session_energy
       WHERE provider_id = $1
         AND ts > NOW() - ($2::text || ' hours')::INTERVAL`,
      [providerId, String(hours)]
    );

    const totalJoules = parseFloat(result.rows[0]?.total_joules || 0);
    const callCount = parseInt(result.rows[0]?.call_count || 0, 10);

    return {
      providerId,
      totalJoules,
      totalTokens: 0, // Token tracking not yet available in session_energy
      avgJoulesPerCall: callCount > 0 ? totalJoules / callCount : 0,
      callCount,
      hours
    };
  } catch (err) {
    console.error('[energy-budget] getProviderEnergySummary error:', err.message);
    return { providerId, totalJoules: 0, totalTokens: 0, avgJoulesPerCall: 0, callCount: 0, hours };
  }
}
