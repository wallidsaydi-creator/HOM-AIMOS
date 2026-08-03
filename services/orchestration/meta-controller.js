/**
 * meta-controller.js — System M: Meta-Reasoning and Novelty Detection
 * Source: Why AI Systems Don't Learn (META/FAIR, 2026)
 * Wave 3 source: Open-Loop Planning, Closed-Loop Verification:
 * Speculative Verification for VLA (SV-VLA, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (Pre-run step 6)
 * 2. → Pulls from: services/db/connection.js (Meta-state trajectory)
 * 3. ↔ Interacts with: recall-calibrator.js (Error adaptation)
 * 4. ↔ Interacts with: services/orchestration/symbolic-reasoner.js (Pre/Post checks)
 * 5. → Affects: agent-runner.js (Resolves APPLY_SKILL vs REASON_AND_PLAN)
 *
 * LOGIC GUIDE: Monitors meta-states (novelty, mastery, failure recurrence). 
 * Issues meta-actions to adapt execution strategy based on task complexity.
 * SV-VLA adaptation: high-confidence, low-novelty runs may use an
 * open-loop macro-plan only when paired with closed-loop deviation checks.
 * The paper formula is kept explicit: E_t = ||a'_t - a_t||_1; replan when
 * E_t > tau. Aimos does not claim the paper's trained VLA verifier here.
 * Batch8 Wave4 source: LLM-Agent-Controller, AI Agent Systems, GrandCode.
 * Adds controller stability diagnostics only; autonomous correction and RL
 * controller updates remain guarded.
 * Batch9.75 Wave 1 authority: Code Models Are Zero-Shot Precondition Reasoners,
 * FrugalGPT, Model-based RL — A Survey, OPTIONZERO — Planning With Learned
 * Options, PriPG-RL — Privileged Planner-Guided RL. Precondition checks,
 * cost-cascade observables, model-based planning taxonomy, option-tree
 * diagnostics, and privileged planner contracts are additive alongside-path
 * diagnostics; no production action selection, routing, or plan execution
 * is modified.
 *
 * Phase 6 guarded math (alongside paths, not replacements):
 * 6a. Parametric VLA Verifier
 *     Paper: SV-VLA (Speculative Verification for VLA)
 *     Formula: V(a_planned, a_reference) = σ(β_V * (1 - ||a_planned - a_reference||_1 / τ) + β_bias)
 *     Parameters: β_V = 5.0 (verifier slope), β_bias = 0.0, τ = 0.15 (base threshold)
 *     Diagnostic only: does NOT replace binary deviation check
 *
 * 6b. Adaptive Tau
 *     Paper: SV-VLA + Adaptive Threshold literature
 *     Formula: τ_t = τ_base * (1 + α_τ * (1 - confidence_trajectory_t))
 *     Parameters: τ_base = 0.15, α_τ = 0.3
 *     Diagnostic only: does NOT replace static τ
 *
 * 6c. PID Controller
 *     Paper: LLM-Agent-Controller (Batch9 Wave3)
 *     Formula: u(t) = K_p * e(t) + K_i * Σ e(τ)dτ + K_d * de/dt
 *     Parameters: K_p = 0.6, K_i = 0.1, K_d = 0.3
 *     Diagnostic only: does NOT replace stability classification
 *
 * 6d. RL Policy Update
 *     Paper: Sutton & Barto (RL) — same as RPE gate
 *     Formula: π(a|s) ← π(a|s) + α_RL * RPE * ∇log π(a|s)
 *     Parameters: α_RL = 0.001
 *     Diagnostic only: does NOT modify actual action selection
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 6)
// → Calls: services/db/connection.js (meta-state read/write)
// Pipeline: AGENT_RUN_PIPELINE
// Position: meta-state evaluation
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { symbolicPreCheck, symbolicPostCheck } from './symbolic-reasoner.js';

const COMPANY = AIMOS_COMPANY_ID;
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const PRECONDITION_SOURCE = 'Code Models Are Zero-Shot Precondition Reasoners';
export const FRUGALGPT_CASCADE_SOURCE = 'FrugalGPT';
export const MODEL_BASED_RL_SOURCE = 'Model-based RL — A Survey';
export const OPTION_ZERO_SOURCE = 'OPTIONZERO — Planning With Learned Options';
export const PRIPGR_SOURCE = 'PriPG-RL — Privileged Planner-Guided RL';

// ─── META-ACTION CONSTANTS ────────────────────────────────────────────────
export const META_ACTIONS = {
  APPLY_SKILL: 'APPLY_SKILL',
  REASON_AND_PLAN: 'REASON_AND_PLAN',
  ADAPT_SKILL: 'ADAPT_SKILL',
  EXPLORE: 'EXPLORE',
  FALLBACK: 'FALLBACK',
  CONSOLIDATE: 'CONSOLIDATE',
  REPLAY_FAILURE: 'REPLAY_FAILURE',
  DEPOSIT_PROVISIONAL: 'DEPOSIT_PROVISIONAL',
  PROMOTE_TO_STABLE: 'PROMOTE_TO_STABLE',
};

// ─── ACTION COST TABLE (CoALA: estimated compute cost) ──────────────────────
const ACTION_COST = {
  [META_ACTIONS.APPLY_SKILL]: 0.1,
  [META_ACTIONS.FALLBACK]: 0.1,
  [META_ACTIONS.ADAPT_SKILL]: 0.3,
  [META_ACTIONS.REASON_AND_PLAN]: 0.5,
  [META_ACTIONS.EXPLORE]: 0.5,
  [META_ACTIONS.REPLAY_FAILURE]: 0.4,
  [META_ACTIONS.CONSOLIDATE]: 0.3,
  [META_ACTIONS.DEPOSIT_PROVISIONAL]: 0.1,
  [META_ACTIONS.PROMOTE_TO_STABLE]: 0.2,
};

// ─── Tree-of-Thought Parameters (CoALA + ToT, Yao et al. 2023) ──────────
const TOT_MAX_BRANCHES = 3;          // Max branches per node
const TOT_MAX_DEPTH = 4;             // Max tree depth
const TOT_PRUNE_THRESHOLD = 0.15;    // Prune branches below this EV
const TOT_NOVELTY_TRIGGER = 0.7;     // Only use ToT when novelty >= this

// ─── SV-VLA: open-loop macro plan + closed-loop verification ───────────────
const SV_VLA_DEFAULT_THRESHOLD = 0.2; // Paper default tau for deviation replanning.
const SV_VLA_PAPER_CHUNK_SIZE = 64;   // Paper reference K; Aimos caps runtime chunks lower.
const AIMOS_OPEN_LOOP_MAX_CHUNK = 8; // Conservative orchestration chunk, not robot action K.
const OPEN_LOOP_ACTIONS = new Set([
  META_ACTIONS.APPLY_SKILL,
  META_ACTIONS.ADAPT_SKILL,
]);

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

function normalizeActionVector(action) {
  if (Array.isArray(action)) {
    const values = action.map(Number);
    return values.every(Number.isFinite) ? values : null;
  }

  if (action && typeof action === 'object') {
    const keys = Object.keys(action).sort();
    const values = keys.map((key) => Number(action[key]));
    return values.length > 0 && values.every(Number.isFinite) ? values : null;
  }

  return null;
}

function actionFingerprint(action) {
  return String(action ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function tokenMismatchDistance(plannedAction, referenceAction) {
  const planned = new Set(actionFingerprint(plannedAction));
  const reference = new Set(actionFingerprint(referenceAction));
  if (planned.size === 0 && reference.size === 0) return 0;
  const union = new Set([...planned, ...reference]);
  let intersection = 0;
  for (const token of planned) {
    if (reference.has(token)) intersection += 1;
  }
  return 1 - (intersection / Math.max(1, union.size));
}

/**
 * Paper-backed deviation verifier.
 *
 * Formula from SV-VLA:
 *   E_t = ||a'_t - a_t||_1
 *   replan when E_t > tau
 *
 * For numeric vectors, Aimos uses the exact L1 distance. For text/tool-step
 * labels, Aimos exposes a diagnostic token mismatch instead of pretending to
 * have the paper's trained action verifier.
 */
export function verifySpeculativeStep({
  plannedAction,
  referenceAction,
  threshold = SV_VLA_DEFAULT_THRESHOLD,
  stepIndex = 0,
} = {}) {
  const tau = Number.isFinite(Number(threshold)) ? Number(threshold) : SV_VLA_DEFAULT_THRESHOLD;
  const plannedVector = normalizeActionVector(plannedAction);
  const referenceVector = normalizeActionVector(referenceAction);

  let deviation = null;
  let metric = 'token_mismatch_diagnostic';
  let formulaApplied = false;

  if (plannedVector && referenceVector && plannedVector.length === referenceVector.length) {
    deviation = plannedVector.reduce((sum, value, index) => (
      sum + Math.abs(referenceVector[index] - value)
    ), 0);
    metric = 'l1_distance';
    formulaApplied = true;
  } else if (plannedAction != null && referenceAction != null) {
    deviation = tokenMismatchDistance(plannedAction, referenceAction);
  }

  const verifiable = Number.isFinite(deviation);
  const accepted = verifiable ? deviation <= tau : false;

  return {
    source_paper: 'Open-Loop Planning, Closed-Loop Verification: Speculative Verification for VLA',
    step_index: stepIndex,
    metric,
    formula: "E_t = ||a'_t - a_t||_1; replan when E_t > tau",
    formula_applied: formulaApplied,
    deviation: verifiable ? Number(deviation.toFixed(6)) : null,
    threshold: tau,
    accepted,
    should_replan: !accepted,
    rule: accepted ? 'execute_planned_action' : 'discard_remaining_chunk_and_replan',
    guarded_math: {
      trained_vla_verifier_claimed: false,
      robot_action_space_claimed: false,
      adaptive_tau_claimed: false,
    },
    guarded_math_implemented: {
      parametric_verifier: { enabled: false, requires: ['deviation history for trained verifier'], diagnostic_value: 'confidence_score' },
      adaptive_tau: { enabled: false, requires: ['recent verification trajectory'], diagnostic_value: 'adaptive_tau' },
    }
  };
}

/**
 * Decide whether a run is eligible for open-loop macro planning.
 * This is intentionally conservative: open-loop is only allowed for known,
 * low-novelty skills and must always carry a closed-loop verifier contract.
 */
export function selectSpeculativeExecutionMode(metaState = {}, decision = {}, options = {}) {
  const mastery = clamp01(metaState.mastery, 0.5);
  const novelty = clamp01(metaState.novelty, 0.5);
  const predictionError = clamp01(metaState.predictionError, 0);
  const resourceBudgetRemaining = clamp01(metaState.resourceBudgetRemaining, 1);
  const failureRecurrence = Math.max(0, Number(metaState.failureRecurrence || 0));
  const constraintViolations = Array.isArray(metaState.constraintViolations)
    ? metaState.constraintViolations
    : [];
  const expectedValue = Number(decision.expectedValue || 0);
  const action = decision.action || META_ACTIONS.REASON_AND_PLAN;
  const threshold = Number.isFinite(Number(options.threshold))
    ? Number(options.threshold)
    : SV_VLA_DEFAULT_THRESHOLD;
  const maxChunkSize = Math.max(1, Math.min(
    AIMOS_OPEN_LOOP_MAX_CHUNK,
    Number(options.maxChunkSize || AIMOS_OPEN_LOOP_MAX_CHUNK)
  ));

  const blockers = [];
  if (!OPEN_LOOP_ACTIONS.has(action)) blockers.push('selected_action_not_open_loop_safe');
  if (mastery < 0.65) blockers.push('mastery_below_open_loop_threshold');
  if (novelty > 0.35) blockers.push('novelty_above_open_loop_threshold');
  if (predictionError > 0.25) blockers.push('prediction_error_above_open_loop_threshold');
  if (failureRecurrence >= 2) blockers.push('recent_failure_recurrence');
  if (resourceBudgetRemaining < 0.2) blockers.push('resource_budget_too_low_for_verification');
  if (constraintViolations.length > 0) blockers.push('symbolic_constraint_violation');
  if (expectedValue <= 0) blockers.push('missing_positive_expected_value');

  const openLoopAllowed = blockers.length === 0;

  return {
    source_paper: 'Open-Loop Planning, Closed-Loop Verification: Speculative Verification for VLA',
    execution_mode: openLoopAllowed
      ? 'open_loop_with_closed_loop_verification'
      : 'closed_loop',
    macro_chunk_allowed: openLoopAllowed,
    max_chunk_size: openLoopAllowed ? maxChunkSize : 1,
    paper_reference_chunk_size: SV_VLA_PAPER_CHUNK_SIZE,
    safety_threshold_tau: threshold,
    replan_on_deviation: true,
    verifier: 'deterministic_deviation_contract',
    verifier_inputs_required: [
      'planned_action',
      'closed_loop_reference_action',
      'latest_observation_or_run_state',
      'planning_context'
    ],
    blockers,
    rationale: openLoopAllowed
      ? 'High-mastery low-novelty decision can use a macro-plan only with per-step closed-loop verification.'
      : `Closed-loop retained: ${blockers.join(', ') || 'open-loop eligibility not established'}.`,
    guarded_math: {
      trained_vla_verifier_claimed: false,
      robot_action_chunking_claimed: false,
      adaptive_tau_claimed: false,
      calibrated_ranking_changed: false,
    },
    guarded_math_implemented: {
      parametric_verifier: { enabled: false, requires: ['deviation history for trained verifier'], diagnostic_value: 'confidence_score' },
      adaptive_tau: { enabled: false, requires: ['recent verification trajectory'], diagnostic_value: 'adaptive_tau' },
      pid_controller: { enabled: false, requires: ['error history for proportional/integral/derivative terms'], diagnostic_value: 'correction_signal' },
      rl_policy_update: { enabled: false, requires: ['action probability distribution and RPE signal'], diagnostic_value: 'policy_deltas' },
    },
  };
}

export function buildSpeculativeVerificationContract({ metaState = {}, decision = {}, sample = null } = {}) {
  const execution = selectSpeculativeExecutionMode(metaState, decision);
  const sampleVerification = sample
    ? verifySpeculativeStep(sample)
    : verifySpeculativeStep({
        plannedAction: [0.1, 0.2],
        referenceAction: [0.12, 0.21],
        stepIndex: 0
      });

  return {
    status: 'wired',
    source_paper: execution.source_paper,
    implementation_scope: 'Aimos orchestration control contract',
    execution,
    verifier_contract: {
      formula: sampleVerification.formula,
      default_tau: SV_VLA_DEFAULT_THRESHOLD,
      replan_rule: 'discard remaining macro chunk and replan when deviation exceeds tau',
      latest_observation_required: true,
      planning_context_required: true,
    },
    sample_verification: sampleVerification,
    aladdin_boundary: {
      plans_are_operational_memory: true,
      failed_verifications_are_retained: true,
      physical_delete_allowed: false,
    }
  };
}

/**
 * Compute task novelty by measuring cosine distance from the nearest known skill.
 */
export async function computeTaskNovelty(taskPrompt, companyId = COMPANY) {
  try {
    const embedding = await getEmbedding(taskPrompt);
    if (!embedding || embedding._degraded) {
      return { novelty: 0.7, nearestSkillKey: null, nearestDistance: 1.0 };
    }

    const result = await query(
       `SELECT key, (embedding <=> $1::vector) as distance
       FROM aimos_memories
       WHERE company_id = $2
         AND memory_type = 'procedural'
       ORDER BY embedding <=> $1::vector ASC
       LIMIT 1`,
      [JSON.stringify(embedding), companyId]
    );

    if (result.rows.length === 0) {
      return { novelty: 1.0, nearestSkillKey: null, nearestDistance: 1.0 };
    }

    const distance = parseFloat(result.rows[0].distance);
    const novelty = 1 / (1 + Math.exp(-5 * (distance - 0.4)));

    return {
      novelty: Math.max(0, Math.min(1, novelty)),
      nearestSkillKey: result.rows[0].key,
      nearestDistance: distance
    };
  } catch (err) {
    console.warn('[meta-controller] novelty computation failed:', err.message);
    return { novelty: 0.5, nearestSkillKey: null, nearestDistance: 0.5 };
  }
}

/**
 * Compute mastery level for a task domain based on past success history.
 */
export async function computeMastery(agentId, taskDomain, companyId = COMPANY) {
  try {
    const result = await query(
      `SELECT
         COUNT(*) as total,
         COUNT(*) FILTER (WHERE value LIKE '%result: success%' OR value LIKE '%result: partial%') as successes
       FROM aimos_memories
       WHERE company_id = $1
         AND agent_id = $2
         AND memory_type = 'event_log'
         AND LOWER(value) LIKE $3`,
      [companyId, agentId, `%${taskDomain.toLowerCase()}%`]
    );

    const total = parseInt(result.rows[0]?.total || '0', 10);
    const successes = parseInt(result.rows[0]?.successes || '0', 10);

    if (total === 0) return { mastery: 0.1, totalRuns: 0, successRate: 0 };

    const successRate = successes / total;
    const volumeFactor = Math.min(1, total / 20);
    const mastery = successRate * 0.7 + volumeFactor * 0.3;

    return {
      mastery: Math.max(0, Math.min(1, mastery)),
      totalRuns: total,
      successRate
    };
  } catch {
    return { mastery: 0.3, totalRuns: 0, successRate: 0 };
  }
}

/**
 * Detect failure recurrence — how many times has this error pattern appeared?
 */
export async function detectFailureRecurrence(errorSignature, agentId, companyId = COMPANY) {
  try {
    const sig = String(errorSignature || '').toLowerCase().slice(0, 200);
    if (!sig) return { recurrenceCount: 0, isRecurring: false };

    const result = await query(
      `SELECT COUNT(*) as count FROM aimos_memories
       WHERE company_id = $1
         AND agent_id = $2
         AND memory_type = 'event_log'
         AND LOWER(value) LIKE $3`,
      [companyId, agentId, `%${sig.slice(0, 80)}%`]
    );

    const count = parseInt(result.rows[0]?.count || '0', 10);
    return { recurrenceCount: count, isRecurring: count >= 3 };
  } catch {
    return { recurrenceCount: 0, isRecurring: false };
  }
}

/**
 * Compute prediction error — divergence between expected and actual outcome.
 */
export function computePredictionError(statedConfidence, actualSuccess) {
  const expected = Math.max(0, Math.min(1, statedConfidence || 0.5));
  const actual = actualSuccess ? 1.0 : 0.0;
  const error = Math.abs(expected - actual);
  return {
    predictionError: error,
    calibrationGap: expected - actual
  };
}

// ─── PROPOSE: Generate candidate actions (CoALA deliberative cycle) ──────────
/**
 * Generate all applicable candidate actions for the given meta-state.
 * Unlike the old resolveMetaAction() which early-returns on the first match,
 * this collects ALL applicable actions with relevance scores.
 */
export function proposeActions(metaState) {
  const {
    novelty = 0.5,
    mastery = 0.5,
    failureRecurrence = 0,
    predictionError = 0,
    resourceBudgetRemaining = 1.0
  } = metaState || {};

  const candidates = [];

  // Resource exhaustion — always propose fallback
  if (resourceBudgetRemaining < 0.1) {
    candidates.push({
      action: META_ACTIONS.FALLBACK,
      rationale: `Resource budget at ${(resourceBudgetRemaining * 100).toFixed(0)}% — falling back to best available skill`,
      relevance: 0.95,
      cost: ACTION_COST[META_ACTIONS.FALLBACK]
    });
  }

  // Repeated failure — explore alternatives
  if (failureRecurrence >= 3) {
    candidates.push({
      action: META_ACTIONS.EXPLORE,
      rationale: `Error pattern recurring ${failureRecurrence} times — exploring structurally different approach`,
      relevance: 0.85 + Math.min(0.1, failureRecurrence * 0.02),
      cost: ACTION_COST[META_ACTIONS.EXPLORE]
    });
  }

  // Replay failures if prediction error is high + some recurrence
  if (predictionError > 0.5 && failureRecurrence >= 2) {
    candidates.push({
      action: META_ACTIONS.REPLAY_FAILURE,
      rationale: `High prediction error (${predictionError.toFixed(2)}) + recurring failures — replay for pattern extraction`,
      relevance: 0.75 + predictionError * 0.2,
      cost: ACTION_COST[META_ACTIONS.REPLAY_FAILURE]
    });
  }

  // High mastery + low novelty → habitual fast path
  if (mastery >= 0.5 && novelty < 0.4) {
    const relevance = mastery * (1 - novelty);
    candidates.push({
      action: META_ACTIONS.APPLY_SKILL,
      rationale: `High mastery (${mastery.toFixed(2)}) + low novelty (${novelty.toFixed(2)}) — applying known skill`,
      relevance,
      cost: ACTION_COST[META_ACTIONS.APPLY_SKILL]
    });
  }

  // Low mastery + high novelty → full deliberation
  if (mastery < 0.6 && novelty >= 0.4) {
    const relevance = novelty * (1 - mastery) * 0.8;
    candidates.push({
      action: META_ACTIONS.REASON_AND_PLAN,
      rationale: `Low mastery (${mastery.toFixed(2)}) + high novelty (${novelty.toFixed(2)}) — full deliberative reasoning`,
      relevance: Math.max(0.3, relevance),
      cost: ACTION_COST[META_ACTIONS.REASON_AND_PLAN]
    });
  }

  // High mastery + high novelty → adapt existing skill
  if (mastery >= 0.4 && novelty >= 0.4) {
    const relevance = (mastery + novelty) / 2 * 0.8;
    candidates.push({
      action: META_ACTIONS.ADAPT_SKILL,
      rationale: `Good mastery (${mastery.toFixed(2)}) + novel context (${novelty.toFixed(2)}) — adapting skill with reasoning overlay`,
      relevance,
      cost: ACTION_COST[META_ACTIONS.ADAPT_SKILL]
    });
  }

  // Always include a default reasoning option as fallback
  if (!candidates.length || !candidates.some(c => c.action === META_ACTIONS.REASON_AND_PLAN)) {
    candidates.push({
      action: META_ACTIONS.REASON_AND_PLAN,
      rationale: `Default mode — mastery: ${mastery.toFixed(2)}, novelty: ${novelty.toFixed(2)}`,
      relevance: 0.3,
      cost: ACTION_COST[META_ACTIONS.REASON_AND_PLAN]
    });
  }

  return candidates;
}

// ─── EVALUATE: Score candidates on expected value ────────────────────────────
/**
 * Score each candidate on relevance, cost, and historical risk.
 * expected_value = relevance * (1 - risk) / cost
 */
export function evaluateActions(candidates, metaState = {}) {
  const { failureRecurrence = 0, predictionError = 0 } = metaState;

  // Base risk from failure history
  const baseRisk = Math.min(0.8, failureRecurrence * 0.1 + predictionError * 0.2);

  return candidates.map(candidate => {
    // Actions that address failures get reduced risk
    let risk = baseRisk;
    if (candidate.action === META_ACTIONS.EXPLORE || candidate.action === META_ACTIONS.REPLAY_FAILURE) {
      risk = Math.max(0.05, baseRisk * 0.3); // these are designed to handle failures
    }
    if (candidate.action === META_ACTIONS.FALLBACK) {
      risk = 0.05; // fallback is always low risk
    }

    const cost = Math.max(0.05, candidate.cost);
    const expectedValue = candidate.relevance * (1 - risk) / cost;

    return {
      ...candidate,
      risk: Math.round(risk * 100) / 100,
      expectedValue: Math.round(expectedValue * 1000) / 1000
    };
  });
}

// ─── SELECT: Pick the best candidate ─────────────────────────────────────────
/**
 * Select the candidate with highest expected_value.
 * Ties broken by lower cost (prefer faster actions).
 */
export function selectBestAction(scoredCandidates) {
  if (!scoredCandidates.length) {
    return {
      action: META_ACTIONS.REASON_AND_PLAN,
      speed: 'medium',
      reasoning: 'No candidates generated — defaulting to deliberative reasoning',
      candidates: []
    };
  }

  const sorted = [...scoredCandidates].sort((a, b) => {
    if (Math.abs(b.expectedValue - a.expectedValue) > 0.001) {
      return b.expectedValue - a.expectedValue;
    }
    return a.cost - b.cost; // tie-break: prefer lower cost
  });

  const winner = sorted[0];
  const speed = winner.cost <= 0.1 ? 'fast' : winner.cost <= 0.3 ? 'medium' : 'slow';

  return {
    action: winner.action,
    speed,
    reasoning: winner.rationale,
    expectedValue: winner.expectedValue,
    candidates: sorted
  };
}

function finiteNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

/**
 * Batch8 Wave 4 diagnostic surface.
 *
 * This summarizes controller stability for audit/debug output only. It does not
 * change routing, action selection, ToT pruning, symbolic checks, or fallback
 * behavior.
 */
export function buildMetaControllerDiagnostics({
  metaState = {},
  candidates = [],
  decision = {},
  totResult = null,
  symbolicHints = null,
  fallbackReason = null,
} = {}) {
  const scoredCandidates = Array.isArray(candidates) ? candidates : [];
  const expectedValues = scoredCandidates
    .map((candidate) => finiteNumber(candidate?.expectedValue, NaN))
    .filter(Number.isFinite);
  const maxEV = expectedValues.length ? Math.max(...expectedValues) : null;
  const minEV = expectedValues.length ? Math.min(...expectedValues) : null;
  const evSpread = maxEV == null || minEV == null ? null : Number((maxEV - minEV).toFixed(3));
  const symbolicViolations = Array.isArray(symbolicHints?.violations)
    ? symbolicHints.violations
    : Array.isArray(metaState?.constraintViolations)
      ? metaState.constraintViolations
      : [];

  const resourceBudget = finiteNumber(metaState?.resourceBudgetRemaining, 1);
  const failureRecurrence = finiteNumber(metaState?.failureRecurrence, 0);
  const predictionError = finiteNumber(metaState?.predictionError, 0);
  const stable =
    resourceBudget >= 0.2
    && failureRecurrence < 3
    && predictionError <= 0.5
    && symbolicViolations.length === 0;

  return {
    source_papers: [
      'LLM-Agent-Controller — Universal Multi-Agent System as Control Engineer',
      'AI Agent Systems',
      'GrandCode',
    ],
    diagnostic_only: true,
    behavior_changed: false,
    frugal_cascade_diagnostic: buildFrugalGPTCascadeDiagnostic({ models: scoredCandidates }),
    precondition_diagnostic: buildPreconditionDiagnostic({ context: metaState?.planStep || decision?.action }),
    option_zero_diagnostic: buildOptionZeroMetaDiagnostic({ task: decision?.action, steps: metaState?.planSteps }),
    pripgr_diagnostic: buildPriPGRDiagnostic({ fullObservability: metaState?.fullObservability, partialObservability: metaState?.partialObservability }),
    selected_action: decision?.action || null,
    selected_speed: decision?.speed || null,
    candidate_count: scoredCandidates.length,
    expected_value_spread: evSpread,
    expected_value_max: maxEV,
    expected_value_min: minEV,
    controller_stability: stable ? 'stable' : 'watch',
    convergence_status: stable ? 'bounded' : 'needs_verification',
    tot_override: decision?.totOverride === true,
    symbolic_violation_count: symbolicViolations.length,
    symbolic_violations: symbolicViolations.slice(0, 5),
    resource_budget_remaining: Number(resourceBudget.toFixed(3)),
    fallback_reason: fallbackReason || null,
    benchmark_trace_hints: {
      tot_nodes: Number.isFinite(Number(totResult?.stats?.totalNodes)) ? Number(totResult.stats.totalNodes) : 0,
      tot_pruned: Number.isFinite(Number(totResult?.stats?.pruned)) ? Number(totResult.stats.pruned) : 0,
      best_path_length: Array.isArray(totResult?.bestPath) ? totResult.bestPath.length : 0,
    },
    guarded_control: {
      autonomous_correction_enabled: false,
      pid_controller_enabled: false,
      rl_policy_update_enabled: false,
      tool_unlock_enabled: false,
    },
    guarded_math: {
      precondition_check: true,
      frugalgpt_cascade: true,
      model_based_rl: true,
      option_zero: true,
      pripgr: true,
    },
    guarded_math_implemented: {
      parametric_verifier: { enabled: false, requires: ['deviation history for trained verifier'], diagnostic_value: 'confidence_score' },
      adaptive_tau: { enabled: false, requires: ['recent verification trajectory'], diagnostic_value: 'adaptive_tau' },
      pid_controller: { enabled: false, requires: ['error history for proportional/integral/derivative terms'], diagnostic_value: 'correction_signal' },
      rl_policy_update: { enabled: false, requires: ['action probability distribution and RPE signal'], diagnostic_value: 'policy_deltas' },
      precondition_check: { enabled: true, diagnostic_only: true, source_paper: PRECONDITION_SOURCE },
      frugalgpt_cascade: { enabled: true, diagnostic_only: true, source_paper: FRUGALGPT_CASCADE_SOURCE },
      model_based_rl: { enabled: true, diagnostic_only: true, source_paper: MODEL_BASED_RL_SOURCE },
      option_zero: { enabled: true, diagnostic_only: true, source_paper: OPTION_ZERO_SOURCE },
      pripgr: { enabled: true, diagnostic_only: true, source_paper: PRIPGR_SOURCE },
    },
  };
}

export function buildWave3ControllerRuntimeDiagnostics({
  metaState = {},
  candidates = [],
  decision = {},
  streamState = 'initialized',
  toolTruthStatus = 'unknown',
  latencyMs = 0,
} = {}) {
  const base = buildMetaControllerDiagnostics({ metaState, candidates, decision });
  const latencyPressure = Math.max(0, Math.min(1, Number(latencyMs || 0) / 30000));
  const predictionError = Math.max(0, Math.min(1, Number(metaState?.predictionError || 0)));
  const failureRecurrence = Math.max(0, Number(metaState?.failureRecurrence || 0));
  const toolPenalty = ['needs_intercept', 'failed', 'unavailable'].includes(String(toolTruthStatus || '').toLowerCase()) ? 0.2 : 0;
  const stabilityScore = Math.max(0, Math.min(1,
    1 - (0.35 * predictionError) - (0.25 * latencyPressure) - (0.15 * Math.min(1, failureRecurrence / 3)) - toolPenalty
  ));

  return {
    status: 'diagnostic',
    source_papers: [...base.source_papers, AGENTPULSE_SOURCE],
    diagnostic_only: true,
    controller_stability: base,
    runtime_pulse: {
      stream_state: String(streamState || 'initialized'),
      tool_truth_status: String(toolTruthStatus || 'unknown'),
      latency_ms: Math.max(0, Number(latencyMs || 0)),
      stability_score: Number(stabilityScore.toFixed(6)),
      stability_state: stabilityScore >= 0.7 ? 'stable' : stabilityScore >= 0.45 ? 'watch' : 'degraded',
    },
    guarded_control: {
      ...base.guarded_control,
      runtime_policy_mutation: false,
      automatic_replan_execution: false,
    },
    guarded_math: base.guarded_math,
    guarded_math_implemented: base.guarded_math_implemented,
  };
}

/**
 * Legacy single-action resolution — kept for backward compatibility.
 * Now delegates to the Propose→Evaluate→Select pipeline.
 */
export function resolveMetaAction(metaState) {
  const candidates = proposeActions(metaState);
  const scored = evaluateActions(candidates, metaState);
  const result = selectBestAction(scored);
  return {
    action: result.action,
    speed: result.speed,
    reasoning: result.reasoning
  };
}

// ---------------------------------------------------------------------------
// Phase 6: Guarded Math — Alongside-path implementations
// These functions run ALONGSIDE existing SV-VLA deterministic deviation contract
// and stability scoring for diagnostic comparison. They do NOT replace any
// existing computation.
// ---------------------------------------------------------------------------

// --- 6a. Parametric VLA Verifier ---
// Paper: SV-VLA (Speculative Verification for VLA)
// Current: Binary check — E_t = ||a'_t - a_t||_1; replan when E_t > τ
// New alongside: V(a_planned, a_reference) = σ(β_V * (1 - ||a_planned - a_reference||_1 / τ) + β_bias)
// Produces continuous confidence score rather than binary accept/reject

const VERIFIER_SLOPE = 5.0;    // β_V — steep sigmoid
const VERIFIER_BIAS = 0.0;     // β_bias
const VERIFIER_BASE_TAU = 0.15; // τ — base threshold for scaling

/**
 * Compute parametric verifier score for SV-VLA deviation.
 *
 * @param {number[]|object|string} plannedAction - planned action (numeric vector or action descriptor)
 * @param {number[]|object|string} referenceAction - reference (closed-loop) action
 * @param {object} [options] - { slope, bias, tau }
 * @returns {{ deviation: number|null, confidence: number, should_replan: boolean,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeVerifierScore(plannedAction, referenceAction, options = {}) {
  const betaV = Number.isFinite(options.slope) ? options.slope : VERIFIER_SLOPE;
  const betaBias = Number.isFinite(options.bias) ? options.bias : VERIFIER_BIAS;
  const tau = Number.isFinite(options.tau) ? options.tau : VERIFIER_BASE_TAU;

  const plannedVector = normalizeActionVector(plannedAction);
  const referenceVector = normalizeActionVector(referenceAction);

  let deviation = null;
  let metric = 'token_mismatch_diagnostic';

  if (plannedVector && referenceVector && plannedVector.length === referenceVector.length) {
    deviation = plannedVector.reduce((sum, value, index) => (
      sum + Math.abs(referenceVector[index] - value)
    ), 0);
    metric = 'l1_distance';
  } else if (plannedAction != null && referenceAction != null) {
    deviation = tokenMismatchDistance(plannedAction, referenceAction);
  }

  if (!Number.isFinite(deviation)) {
    return {
      deviation: null,
      confidence: 0,
      should_replan: true,
      metric,
      source_paper: 'SV-VLA (Speculative Verification for VLA)',
      diagnostic: true,
      note: 'Alongside path — does NOT replace binary deviation check',
    };
  }

  // V = σ(β_V * (1 - E_t / τ) + β_bias)
  const normalizedDeviation = tau > 0 ? deviation / tau : 1;
  const logit = betaV * (1 - normalizedDeviation) + betaBias;
  const confidence = 1 / (1 + Math.exp(-logit)); // sigmoid

  return {
    deviation: Number(deviation.toFixed(6)),
    confidence: Number(confidence.toFixed(6)),
    should_replan: confidence < 0.5,
    metric,
    formula: "V = σ(β_V * (1 - E_t / τ) + β_bias)",
    formula_applied: true,
    source_paper: 'SV-VLA (Speculative Verification for VLA)',
    diagnostic: true,
    note: 'Alongside path — does NOT replace binary deviation check',
  };
}

// --- 6b. Adaptive Tau ---
// Paper: SV-VLA + Adaptive Threshold literature
// Formula: τ_t = τ_base * (1 + α_τ * (1 - confidence_trajectory_t))
// Where confidence_trajectory_t = EMA of recent accept/reject decisions

const ADAPTIVE_TAU_BASE = 0.15;  // τ_base
const ADAPTIVE_TAU_ALPHA = 0.3;  // α_τ — adaptation rate

/**
 * Compute adaptive tau threshold based on recent verification trajectory.
 *
 * @param {Array<{ accepted: boolean, confidence?: number }>} recentVerifications
 * @param {object} [options] - { baseTau, alpha }
 * @returns {{ adaptive_tau: number, base_tau: number, confidence_trajectory: number,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeAdaptiveTau(recentVerifications = [], options = {}) {
  const baseTau = Number.isFinite(options.baseTau) ? options.baseTau : ADAPTIVE_TAU_BASE;
  const alpha = Number.isFinite(options.alpha) ? options.alpha : ADAPTIVE_TAU_ALPHA;

  if (!Array.isArray(recentVerifications) || recentVerifications.length === 0) {
    return {
      adaptive_tau: baseTau,
      base_tau: baseTau,
      confidence_trajectory: 1,
      source_paper: 'SV-VLA + Adaptive Threshold',
      diagnostic: true,
      note: 'Alongside path — does NOT replace static τ',
      insufficient_data: true,
    };
  }

  // EMA of confidence: start at 0.5, weight each new observation by α
  let ema = 0.5;
  for (const v of recentVerifications) {
    const signal = v.accepted ? (Number.isFinite(v.confidence) ? v.confidence : 1.0) : 0.0;
    ema = alpha * signal + (1 - alpha) * ema;
  }

  // τ_t = τ_base * (1 + α_τ * (1 - ema))
  const adaptiveTau = baseTau * (1 + alpha * (1 - ema));

  return {
    adaptive_tau: Number(adaptiveTau.toFixed(6)),
    base_tau: baseTau,
    confidence_trajectory: Number(ema.toFixed(6)),
    adaptation_direction: adaptiveTau > baseTau ? 'widened' : adaptiveTau < baseTau ? 'tightened' : 'unchanged',
    source_paper: 'SV-VLA + Adaptive Threshold',
    diagnostic: true,
    note: 'Alongside path — does NOT replace static τ',
  };
}

// --- 6c. PID Controller ---
// Paper: LLM-Agent-Controller (Batch9 Wave3)
// Formula: u(t) = K_p * e(t) + K_i * Σ e(τ)dτ + K_d * de/dt
// K_p = 0.6 (proportional gain, conservative)
// K_i = 0.1 (integral gain, slow accumulation)
// K_d = 0.3 (derivative gain, damp oscillations)

const PID_KP = 0.6;
const PID_KI = 0.1;
const PID_KD = 0.3;

/**
 * Compute PID correction signal for resource/stability control.
 *
 * @param {number[]} errorHistory - array of error signals (e.g., budget_remaining - target)
 * @param {number} target - target setpoint
 * @param {object} [options] - { kp, ki, kd }
 * @returns {{ correction: number, p_term: number, i_term: number, d_term: number,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computePIDCorrection(errorHistory = [], target = 0, options = {}) {
  const kp = Number.isFinite(options.kp) ? options.kp : PID_KP;
  const ki = Number.isFinite(options.ki) ? options.ki : PID_KI;
  const kd = Number.isFinite(options.kd) ? options.kd : PID_KD;

  if (!Array.isArray(errorHistory) || errorHistory.length === 0) {
    return {
      correction: 0,
      p_term: 0,
      i_term: 0,
      d_term: 0,
      target,
      source_paper: 'LLM-Agent-Controller (Batch9 Wave3)',
      diagnostic: true,
      note: 'Alongside path — does NOT replace stability classification',
      insufficient_data: true,
    };
  }

  const currentError = errorHistory[errorHistory.length - 1] - target;

  // P term: proportional to current error
  const pTerm = kp * currentError;

  // I term: integral (sum of errors)
  const integralSum = errorHistory.reduce((s, e) => s + (e - target), 0);
  const iTerm = ki * integralSum;

  // D term: derivative (rate of change of error)
  let dTerm = 0;
  if (errorHistory.length >= 2) {
    const prevError = errorHistory[errorHistory.length - 2] - target;
    dTerm = kd * (currentError - prevError);
  }

  // Total correction, clamped to [-1, 1]
  const correction = Math.max(-1, Math.min(1, pTerm + iTerm + dTerm));

  return {
    correction: Number(correction.toFixed(6)),
    p_term: Number(pTerm.toFixed(6)),
    i_term: Number(iTerm.toFixed(6)),
    d_term: Number(dTerm.toFixed(6)),
    target,
    current_error: Number(currentError.toFixed(6)),
    formula: "u(t) = K_p*e(t) + K_i*Σe(τ)dτ + K_d*de/dt",
    source_paper: 'LLM-Agent-Controller (Batch9 Wave3)',
    diagnostic: true,
    note: 'Alongside path — does NOT replace stability classification',
  };
}

// --- 6d. RL Policy Update ---
// Paper: Sutton & Barto (RL) — same as RPE gate
// Formula: π(a|s) ← π(a|s) + α_RL * RPE * ∇log π(a|s)
// α_RL = 0.001 (policy learning rate)
// Diagnostic only: does NOT modify actual action selection probabilities

const RL_POLICY_LR = 0.001;

/**
 * Compute RL policy gradient update for diagnostic comparison.
 *
 * @param {Array<{ action: string, probability: number }>} currentPolicy - action probabilities
 * @param {number} rpeSignal - reward prediction error
 * @param {object} [options] - { learningRate }
 * @returns {{ updated_policy: Array, policy_deltas: Array, rpe_signal: number,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeRLPolicyUpdate(currentPolicy = [], rpeSignal = 0, options = {}) {
  const alphaRL = Number.isFinite(options.learningRate) ? options.learningRate : RL_POLICY_LR;

  if (!Array.isArray(currentPolicy) || currentPolicy.length === 0) {
    return {
      updated_policy: [],
      policy_deltas: [],
      rpe_signal: rpeSignal,
      source_paper: 'Sutton & Barto (RL) — RPE gate',
      diagnostic: true,
      note: 'Alongside path — does NOT modify actual action selection',
      insufficient_data: true,
    };
  }

  // Normalize probabilities for numerical stability
  const totalProb = currentPolicy.reduce((s, a) => s + (Number.isFinite(a.probability) ? a.probability : 0), 0);
  const safeTotal = totalProb > 1e-10 ? totalProb : 1;

  // π(a|s) ← π(a|s) + α * RPE * ∇log π(a|s)
  // ∇log π(a|s) = 1/π(a|s) for the selected action, 0 for others
  // We compute the update for ALL actions as if each were selected:
  // Δπ(a) = α * RPE * (1/π(a))
  const updatedPolicy = currentPolicy.map(a => {
    const prob = (Number.isFinite(a.probability) ? a.probability : 0) / safeTotal;
    const safeProb = Math.max(prob, 1e-10);
    const gradient = 1 / safeProb;  // ∇log π(a|s)
    const delta = alphaRL * rpeSignal * gradient;
    const updated = Math.max(0, prob + delta);
    return {
      action: a.action,
      original_probability: Number(prob.toFixed(6)),
      updated_probability: Number(updated.toFixed(6)),
      delta: Number(delta.toFixed(6)),
    };
  });

  // Re-normalize updated probabilities
  const updatedTotal = updatedPolicy.reduce((s, a) => s + a.updated_probability, 0);
  const normFactor = updatedTotal > 1e-10 ? 1 / updatedTotal : 1;
  for (const a of updatedPolicy) {
    a.updated_probability = Number((a.updated_probability * normFactor).toFixed(6));
  }

  return {
    updated_policy: updatedPolicy,
    policy_deltas: updatedPolicy.map(a => ({ action: a.action, delta: a.delta })),
    rpe_signal: rpeSignal,
    formula: "π(a|s) ← π(a|s) + α * RPE * ∇log π(a|s)",
    source_paper: 'Sutton & Barto (RL) — RPE gate',
    diagnostic: true,
    note: 'Alongside path — does NOT modify actual action selection',
  };
}

// ─── TREE-OF-THOUGHT: Branching deliberation for high-novelty tasks ──────────

let _totNodeCounter = 0;

/**
 * Create a thought node for Tree-of-Thought search.
 * Each node represents a hypothetical action at a given depth in the tree.
 */
export function createThoughtNode(action, reasoning, expectedValue, depth = 0, parentId = null) {
  _totNodeCounter += 1;
  return {
    id: `tot-${Date.now()}-${_totNodeCounter}`,
    action,
    reasoning,
    expectedValue,
    depth,
    parentId,
    children: [],
    pruned: false,
    selected: false
  };
}

/**
 * Expand a thought node by simulating "what if we took this action?"
 * Generates child branches via proposeActions → evaluateActions on a modified metaState.
 */
export function expandBranch(node, metaState) {
  if (node.pruned) return [];

  // Simulate the effect of taking this action on the meta-state
  const simulatedState = { ...metaState };

  // Each action type shifts the meta-state differently
  switch (node.action) {
    case META_ACTIONS.APPLY_SKILL:
      simulatedState.mastery = Math.min(1, (simulatedState.mastery || 0.5) + 0.1);
      simulatedState.novelty = Math.max(0, (simulatedState.novelty || 0.5) - 0.15);
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.1);
      break;
    case META_ACTIONS.REASON_AND_PLAN:
      simulatedState.novelty = Math.max(0, (simulatedState.novelty || 0.5) - 0.2);
      simulatedState.predictionError = Math.max(0, (simulatedState.predictionError || 0) - 0.15);
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.25);
      break;
    case META_ACTIONS.ADAPT_SKILL:
      simulatedState.mastery = Math.min(1, (simulatedState.mastery || 0.5) + 0.05);
      simulatedState.novelty = Math.max(0, (simulatedState.novelty || 0.5) - 0.1);
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.15);
      break;
    case META_ACTIONS.EXPLORE:
      simulatedState.failureRecurrence = Math.max(0, (simulatedState.failureRecurrence || 0) - 2);
      simulatedState.novelty = Math.max(0, (simulatedState.novelty || 0.5) - 0.1);
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.2);
      break;
    case META_ACTIONS.REPLAY_FAILURE:
      simulatedState.predictionError = Math.max(0, (simulatedState.predictionError || 0) - 0.3);
      simulatedState.failureRecurrence = Math.max(0, (simulatedState.failureRecurrence || 0) - 1);
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.15);
      break;
    case META_ACTIONS.FALLBACK:
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.05);
      break;
    default:
      simulatedState.resourceBudgetRemaining = Math.max(0, (simulatedState.resourceBudgetRemaining || 1) - 0.1);
      break;
  }

  // Generate children via the existing propose→evaluate pipeline
  const childCandidates = proposeActions(simulatedState);
  const scored = evaluateActions(childCandidates, simulatedState);

  // Sort by expectedValue descending, take top TOT_MAX_BRANCHES
  const topCandidates = [...scored]
    .sort((a, b) => b.expectedValue - a.expectedValue)
    .slice(0, TOT_MAX_BRANCHES);

  const children = [];
  for (const candidate of topCandidates) {
    if (candidate.expectedValue < TOT_PRUNE_THRESHOLD) {
      // Below threshold — create but mark as pruned
      const child = createThoughtNode(
        candidate.action,
        candidate.rationale,
        candidate.expectedValue,
        node.depth + 1,
        node.id
      );
      child.pruned = true;
      children.push(child);
    } else {
      const child = createThoughtNode(
        candidate.action,
        candidate.rationale,
        candidate.expectedValue,
        node.depth + 1,
        node.id
      );
      children.push(child);
    }
  }

  node.children = children;
  return children;
}

/**
 * Tree-of-Thought search: builds a branching thought tree, prunes weak branches,
 * and selects the path with the highest cumulative value.
 *
 * 1. Root level = all candidates from proposeActions → evaluateActions
 * 2. Expand each root recursively up to maxDepth
 * 3. Prune at each level (expectedValue < TOT_PRUNE_THRESHOLD)
 * 4. Score each leaf by cumulative path value (sum of EVs along path / depth)
 * 5. Return the best path
 */
export function totSearch(metaState, maxDepth = TOT_MAX_DEPTH) {
  // Reset counter for deterministic-ish IDs within a search
  _totNodeCounter = 0;

  let totalNodes = 0;
  let pruned = 0;
  let maxDepthReached = 0;

  // Step 1: Generate root-level nodes
  const rootCandidates = proposeActions(metaState);
  const scoredRoots = evaluateActions(rootCandidates, metaState);

  const rootNodes = scoredRoots.map(candidate =>
    createThoughtNode(candidate.action, candidate.rationale, candidate.expectedValue, 0, null)
  );
  totalNodes += rootNodes.length;

  // Step 2: Recursive expansion with depth limit
  function expandRecursive(node, currentMetaState, currentDepth) {
    if (currentDepth >= maxDepth) return;
    if (node.pruned) {
      pruned++;
      return;
    }

    const children = expandBranch(node, currentMetaState);
    totalNodes += children.length;

    for (const child of children) {
      if (child.depth > maxDepthReached) maxDepthReached = child.depth;
      if (child.pruned) {
        pruned++;
        continue;
      }

      // Build simulated state for this child's expansion
      const childState = { ...currentMetaState };
      childState.resourceBudgetRemaining = Math.max(0,
        (childState.resourceBudgetRemaining || 1) - (ACTION_COST[child.action] || 0.1)
      );

      expandRecursive(child, childState, currentDepth + 1);
    }
  }

  for (const root of rootNodes) {
    expandRecursive(root, metaState, 0);
  }

  // Step 3: Collect all leaf paths and score them
  const allPaths = [];

  function collectPaths(node, currentPath) {
    const path = [...currentPath, node];

    if (node.children.length === 0 || node.children.every(c => c.pruned)) {
      // This is a leaf — compute cumulative path score
      const depth = path.length;
      const sumEV = path.reduce((sum, n) => sum + n.expectedValue, 0);
      const cumulativeValue = sumEV / depth;
      allPaths.push({ path, cumulativeValue });
    } else {
      for (const child of node.children) {
        if (!child.pruned) {
          collectPaths(child, path);
        }
      }
    }
  }

  for (const root of rootNodes) {
    if (!root.pruned) {
      collectPaths(root, []);
    }
  }

  // Step 4: Select best path
  let bestPath = [];
  let bestValue = -Infinity;

  for (const { path, cumulativeValue } of allPaths) {
    if (cumulativeValue > bestValue) {
      bestValue = cumulativeValue;
      bestPath = path;
    }
  }

  // Mark selected path
  for (const node of bestPath) {
    node.selected = true;
  }

  return {
    bestPath,
    tree: rootNodes,
    stats: {
      totalNodes,
      pruned,
      depth: maxDepthReached
    }
  };
}

/**
 * Full meta-controller evaluation for a run.
 * Called at the start of each agent run to determine execution strategy.
 * Now uses Propose→Evaluate→Select deliberative cycle (CoALA).
 * Extended with Tree-of-Thought search for high-novelty tasks.
 */
export async function evaluateMetaState(taskPrompt, agentId, taskDomain, runContext = {}) {
  const companyId = COMPANY;

  const [noveltyResult, masteryResult, recurrenceResult] = await Promise.all([
    computeTaskNovelty(taskPrompt, companyId),
    computeMastery(agentId, taskDomain, companyId),
    runContext.errorSignature
      ? detectFailureRecurrence(runContext.errorSignature, agentId, companyId)
      : Promise.resolve({ recurrenceCount: 0, isRecurring: false })
  ]);

  const { predictionError } = computePredictionError(
    runContext.statedConfidence || 0.5,
    runContext.lastRunSuccess !== false
  );

  const metaState = {
    novelty: noveltyResult.novelty,
    mastery: masteryResult.mastery,
    failureRecurrence: recurrenceResult.recurrenceCount,
    predictionError,
    resourceBudgetRemaining: runContext.resourceBudget || 1.0,
    nearestSkill: noveltyResult.nearestSkillKey,
    successRate: masteryResult.successRate,
    totalRuns: masteryResult.totalRuns
  };

  // Neuro-symbolic pre-check: constraint validation + causal hints
  let symbolicHints = null;
  try {
    symbolicHints = await symbolicPreCheck(taskPrompt, metaState);
    if (symbolicHints && !symbolicHints.constraintsSatisfied) {
      metaState.constraintViolations = symbolicHints.violations;
    }
    if (symbolicHints?.causalHints?.length) {
      metaState.causalHints = symbolicHints.causalHints;
    }
  } catch { /* symbolic pre-check is best-effort */ }

  // Propose→Evaluate→Select
  const candidates = proposeActions(metaState);
  const scored = evaluateActions(candidates, metaState);
  const decision = selectBestAction(scored);

  // Tree-of-Thought: for high-novelty tasks, explore branching paths
  let totResult = null;
  if (metaState.novelty >= TOT_NOVELTY_TRIGGER && (runContext.resourceBudget || 1.0) >= 0.3) {
    try {
      totResult = totSearch(metaState);
      // If ToT found a better path than single-step selection, use it
      if (totResult.bestPath.length > 0) {
        const totBestEV = totResult.bestPath[totResult.bestPath.length - 1].expectedValue;
        if (totBestEV > decision.expectedValue * 1.1) {
          // ToT path is >10% better — override
          decision.action = totResult.bestPath[0].action;
          decision.reasoning = `[ToT d=${totResult.bestPath.length}] ${totResult.bestPath.map(n => n.action).join(' → ')} | ${totResult.bestPath[0].reasoning}`;
          decision.expectedValue = totBestEV;
          decision.totOverride = true;
        }
      }
    } catch (totErr) {
      console.warn('[meta-controller:ToT] search failed:', totErr.message);
    }
  }

  const speculativeExecution = selectSpeculativeExecutionMode(metaState, decision, {
    taskDomain,
    threshold: runContext.openLoopThreshold,
    maxChunkSize: runContext.openLoopMaxChunkSize,
  });
  const controllerDiagnostics = buildMetaControllerDiagnostics({
    metaState,
    candidates: decision.candidates || scored,
    decision,
    totResult,
    symbolicHints,
  });

  return {
    action: decision.action,
    speed: decision.speed,
    reasoning: decision.reasoning,
    expectedValue: decision.expectedValue,
    candidates: decision.candidates,
    executionMode: speculativeExecution.execution_mode,
    speculativeExecution,
    metaState,
    totResult,
    symbolicHints,
    controllerDiagnostics
  };
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Alongside-path diagnostics
// These functions compute diagnostic overlays. They do NOT replace production
// action selection, routing, or plan execution.
// ---------------------------------------------------------------------------

/**
 * Precondition Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Code Models Are Zero-Shot Precondition Reasoners
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Code-precondition models infer execution preconditions from plan steps.
 * This diagnostic assesses whether a plan step has identifiable preconditions
 * that should be verified before execution. The production action selection
 * pipeline remains authoritative. Guarded by guarded_math flag
 * precondition_check (knowledge-gated).
 */
export function buildPreconditionDiagnostic(planStep = {}) {
  const step = String(planStep?.action || planStep?.step || '');
  const context = String(planStep?.context || planStep?.description || '');
  const hasPreconditionHint = /\b(requires?|needs?|depends?|precondition|assumes?|prerequisite|before)\b/i.test(context);
  const hasConstraintReference = /\b(must|shall|constraint|boundary|limit|threshold)\b/i.test(context);
  const preconditionConfidence = hasPreconditionHint ? 0.8 : hasConstraintReference ? 0.5 : 0.2;

  return {
    diagnostic: true,
    source_paper: PRECONDITION_SOURCE,
    coexistence_class: 'side_by_side_independent',
    plan_step: step,
    precondition_detected: hasPreconditionHint || hasConstraintReference,
    precondition_confidence: Number(preconditionConfidence.toFixed(6)),
    constraint_keywords: hasConstraintReference,
    action_selection_unchanged: true,
    note: 'Alongside-path diagnostic. Precondition assessment does not modify production action selection.',
  };
}

/**
 * FrugalGPT Cascade Diagnostic — Alongside-path diagnostic
 *
 * Source paper: FrugalGPT
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * FrugalGPT proposes cost-aware cascade routing: try cheap models first,
 * escalate only on failure. This diagnostic computes a cost-cascade score
 * for model options. It is an observable metric; production routing via
 * EvolveRouter and Niyama QoS is unchanged. Guarded by guarded_math flag
 * frugalgpt_cascade (knowledge-gated).
 */
export function buildFrugalGPTCascadeDiagnostic(modelOptions = {}) {
  const options = Array.isArray(modelOptions?.options) ? modelOptions.options
    : Array.isArray(modelOptions) ? modelOptions : [];
  const sorted = [...options].sort((a, b) => {
    const costA = Number(a?.cost ?? a?.price ?? Infinity);
    const costB = Number(b?.cost ?? b?.price ?? Infinity);
    return costA - costB;
  });
  const totalOptions = sorted.length;
  const costs = sorted.map(o => Number(o?.cost ?? o?.price ?? 0)).filter(Number.isFinite);
  const avgCost = costs.length > 0 ? costs.reduce((s, c) => s + c, 0) / costs.length : 0;
  const minCost = costs.length > 0 ? Math.min(...costs) : 0;
  const maxCost = costs.length > 0 ? Math.max(...costs) : 0;
  const costRange = maxCost - minCost;
  const cascadeScore = totalOptions >= 2 && costRange > 0
    ? Number((1 - (avgCost - minCost) / costRange).toFixed(6))
    : 0;

  return {
    diagnostic: true,
    source_paper: FRUGALGPT_CASCADE_SOURCE,
    coexistence_class: 'side_by_side_independent',
    total_options: totalOptions,
    cost_cascade_score: cascadeScore,
    avg_cost: Number(avgCost.toFixed(6)),
    min_cost: Number(minCost.toFixed(6)),
    max_cost: Number(maxCost.toFixed(6)),
    cost_range: Number(costRange.toFixed(6)),
    routing_unchanged: true,
    note: 'Alongside-path diagnostic. Cost-cascade observable does not replace production routing.',
  };
}

/**
 * Model-based RL Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Model-based RL — A Survey
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Model-based RL uses a learned world model for planning. This diagnostic
 * provides an audit-only taxonomy of model-based planning strategies
 * (Dyna-style, MBPO, PETS, etc.) as a reference classification. Aimos's
 * reactive meta-controller pipeline remains authoritative. No world model
 * is trained or queried. Guarded by guarded_math flag model_based_rl
 * (knowledge-gated).
 */
export function buildModelBasedRLDiagnostic() {
  return {
    diagnostic: true,
    source_paper: MODEL_BASED_RL_SOURCE,
    coexistence_class: 'audit_only_analogy',
    taxonomy: [
      { strategy: 'Dyna-style', description: 'Learned model generates simulated experience for policy update' },
      { strategy: 'MBPO', description: 'Model-based policy optimization with short-horizon model rollouts' },
      { strategy: 'PETS', description: 'Probabilistic ensembles for trajectory sampling' },
      { strategy: 'AlphaZero-style', description: 'MCTS with learned value/policy network' },
    ],
    aimos_uses_reactive_meta_controller: true,
    world_model_trained: false,
    world_model_queried: false,
    planning_pipeline_unchanged: true,
    note: 'Alongside-path diagnostic. Audit-only taxonomy; no world model training or querying.',
  };
}

/**
 * Option-Zero Meta Diagnostic — Alongside-path diagnostic
 *
 * Source paper: OPTIONZERO — Planning With Learned Options
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * OPTIONZERO discovers and uses options (temporally extended actions) for
 * hierarchical planning. This diagnostic assesses whether the current task
 * context can be decomposed into option-like sub-tasks. It does NOT execute
 * any option or modify the production plan pipeline. Guarded by guarded_math
 * flag option_zero (knowledge-gated).
 */
export function buildOptionZeroMetaDiagnostic(taskContext = {}) {
  const prompt = String(taskContext?.prompt || taskContext?.task || '');
  const steps = Array.isArray(taskContext?.steps) ? taskContext.steps : [];
  const stepCount = steps.length;
  const hasSubTasks = stepCount >= 2 || /\b(then|next|after|before|finally|step \d)\b/i.test(prompt);
  const optionDepthEstimate = hasSubTasks ? Math.min(stepCount || 2, 5) : 1;
  const decomposabilityScore = hasSubTasks ? 0.7 : 0.2;

  return {
    diagnostic: true,
    source_paper: OPTION_ZERO_SOURCE,
    coexistence_class: 'side_by_side_independent',
    task_decomposable: hasSubTasks,
    decomposability_score: Number(decomposabilityScore.toFixed(6)),
    option_depth_estimate: optionDepthEstimate,
    step_count: stepCount,
    task_execution_unchanged: true,
    note: 'Alongside-path diagnostic. Option-tree diagnostic only; no task execution or option discovery.',
  };
}

/**
 * PriPGR Diagnostic — Alongside-path diagnostic
 *
 * Source paper: PriPG-RL — Privileged Planner-Guided RL
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * PriPG-RL uses a privileged planner with full observability to guide a
 * partially-observable agent. This diagnostic assesses the information gap
 * between what the Aimos can observe (full recall history) vs what the
 * agent sees (current context only). The production meta-controller pipeline
 * remains authoritative. Guarded by guarded_math flag pripgr (knowledge-gated).
 */
export function buildPriPGRDiagnostic(observations = {}) {
  const fullObservability = Boolean(observations?.fullHistoryAvailable);
  const partialObservability = Boolean(observations?.currentContextOnly);
  const infoGap = fullObservability && !partialObservability ? 0.1
    : !fullObservability && partialObservability ? 0.8
    : fullObservability && partialObservability ? 0.0
    : 0.5;
  const availableSignals = Object.keys(observations || {}).length;

  return {
    diagnostic: true,
    source_paper: PRIPGR_SOURCE,
    coexistence_class: 'side_by_side_independent',
    raw_gap_visible: true,
    full_observability: fullObservability,
    partial_observability: partialObservability,
    information_gap: Number(infoGap.toFixed(6)),
    available_signals: availableSignals,
    privileged_planner_active: false,
    planning_pipeline_unchanged: true,
    note: 'Alongside-path diagnostic. Privileged planner contract only; production pipeline unchanged.',
  };
}

// ─── BATCH 10 LANE 4: ORCHESTRATION & CONTROL SCALING FUNCTIONS ────────────
// All formulas scale with memory count N. Baseline at N=14000.
// Guarded math: diagnostic-only until benchmark gate passes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * C1: Parametric Verifier — β bias scaling
 * Paper: Batch9.75 Wave1 guarded math
 * Formula: V(p) = σ(α·logit(p) + β), where β = -0.1 * log2(N/14000)
 * At 14K: β=0 (neutral). At 100K: β≈-0.284 (more skepticism for denser recall).
 */
export function computeVerifierBeta(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return -0.1 * Math.log2(N / 14000);
}

/**
 * C1: Parametric confidence verification
 * V(p) = σ(α · logit(p) + β)
 */
export function parametricVerify(p, alpha = 1.0, beta = 0) {
  const epsilon = 1e-10;
  const pClamped = Math.max(epsilon, Math.min(1 - epsilon, p));
  const logitP = Math.log(pClamped / (1 - pClamped));
  return 1 / (1 + Math.exp(-(alpha * logitP + beta)));
}

/**
 * C2: Adaptive Tau — threshold τ_base scaling
 * Paper: Batch9.75 Wave1 guarded math
 * Formula: τ_base = 0.5 + 0.1 * log2(N/14000)
 * At 14K: τ=0.5. At 100K: τ≈0.784 (stricter at scale).
 */
export function computeAdaptiveTauBase(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 0.5 + 0.1 * Math.log2(N / 14000);
}

/**
 * C3: PID Controller — gain scaling
 * Paper: Batch9.75 Wave1 guarded math
 * Formula: Kp=1.0, Ki=0.1*(14000/N)^0.5, Kd=0.05*(N/14000)^0.3
 * At 14K: Kp=1.0, Ki=0.1, Kd=0.05. At 100K: Ki≈0.037, Kd≈0.09.
 */
export function computePIDGains(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    Kp: 1.0,
    Ki: Number((0.1 * Math.pow(14000 / N, 0.5)).toFixed(6)),
    Kd: Number((0.05 * Math.pow(N / 14000, 0.3)).toFixed(6)),
  };
}

/**
 * C3: PID output u(t) = Kp·e(t) + Ki·∫e(τ)dτ + Kd·de/dt
 */
export function pidOutput(error, integral, derivative, gains) {
  return gains.Kp * error + gains.Ki * integral + gains.Kd * derivative;
}

/**
 * Build orchestration & control diagnostic with scale-adaptive parameters.
 */
export function buildOrchestrationDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  const pidGains = computePIDGains(N);

  return {
    diagnostic_only: true,
    memory_count: N,
    scale_parameters: {
      verifier_beta: Number(computeVerifierBeta(N).toFixed(6)),
      adaptive_tau_base: Number(computeAdaptiveTauBase(N).toFixed(6)),
      pid_kp: pidGains.Kp,
      pid_ki: pidGains.Ki,
      pid_kd: pidGains.Kd,
    },
    guarded_math: {
      parametric_verifier_enabled: false,
      adaptive_tau_enabled: false,
      pid_controller_enabled: false,
      production_pipeline_changed: false,
    },
  };
}
