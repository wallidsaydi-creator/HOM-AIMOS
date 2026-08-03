// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: Actor-Reflector architecture for continuous self-improvement;
//          Reflector labels trajectory steps offline via verbal reflection
// Wire into: the native offline dream/reflection pipeline
// Additive Batch9 Wave6 authority: Verifiable Self-Correcting AI Physicists
// adds supersession/counter-evidence diagnostics only. Existing canonical
// memory is never overwritten, deleted, soft-deleted, or TTL'd.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildDPODiagnostic: DPO preference signal alongside existing KTO
//     preferences. Log-prob-gated: type='dpo_unscored' without log-probs.
//   - buildDualAxisFinetuneDiagnostic: Two-axis (semantic + turn-taking)
//     reward diagnostic alongside existing reflection. Reflection unchanged.
//   - buildLoRAAdapterDiagnostic: Inactive low-rank adaptation contract.
//     Aimos does not fine-tune. No fine-tune execution path.
//   - buildRewardHackingFinetuneDiagnostic: Reward-hacking detector on
//     self-improvement loops alongside existing reflection. Reflection unchanged.
//   - buildRLAIFDiagnostic: RLAIF preference signal alongside existing KTO.
//     Log-prob-gated: type='rlaif_unscored' without log-probs.
//   - buildRLHFDiagnostic: Foundational RLHF preference-shape contract.
//     Audit-only reference; Aimos does not train.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * REFLECTION FINETUNER — SELF-FINETUNING AGENT VIA R-MDP
 *
 * Source: "Self-Finetuning Agent via Reflective Markov Decision Process" (2026)
 *
 * Implements the Actor-Reflector architecture for continuous agent self-improvement.
 * The lightweight Actor executes in real-time while the heavyweight Reflector runs
 * offline, labeling trajectory steps as effective/suboptimal via verbal reflection.
 * Suboptimal steps trigger Refine-from-Reflection (RfR) rollouts to generate
 * positive alternatives. KTO preference training uses prospect-theory asymmetric
 * loss to handle the natural imbalance between effective and suboptimal labels.
 *
 * Key concepts:
 *   - R-MDP extends standard MDP with reflection spaces (Psi step-level, Phi trajectory-level)
 *   - Bi-perspective reflection: step-level in-context learning + trajectory-level retrospective
 *   - Transaction history serves dual purpose: short-term in-context + long-term parametric
 *
 * Created: 2026-04-01
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// R-MDP reflection thresholds
const CONFIDENCE_HIGH = 0.85;
const CONFIDENCE_LOW = 0.40;
const DEFAULT_ROLLOUT_COUNT = 3;

// KTO prospect-theory constants (Ethayarajh et al., 2024 adapted for R-MDP)
const KTO_LAMBDA_DESIRABLE = 1.0;
const KTO_LAMBDA_UNDESIRABLE = 2.25; // Loss aversion: penalize suboptimal harder
const KTO_BETA = 0.1;

const ALADDIN_CORRECTION_MODES = new Set([
  'supersession',
  'counter_evidence',
  'repair_overlay',
  'low_frequency_overlay',
  'quarantine',
  'salience_change',
]);

/**
 * Step-level reflection (Psi space).
 * The Reflector evaluates a single step within its execution context,
 * producing a verbal reflection label and confidence score.
 *
 * @param {object} step - Step to reflect on: {action, observation, reward, timestamp}
 * @param {object} context - Surrounding context: {goal, previousSteps, environmentState}
 * @returns {Promise<{label: 'effective'|'suboptimal'|'neutral', reflection: string, confidence: number}>}
 */
export async function reflectOnStep(step, context) {
  if (!step || !step.action) {
    return { label: 'neutral', reflection: 'No action to evaluate.', confidence: 0 };
  }

  const goalAlignment = computeGoalAlignment(step, context);
  const progressDelta = computeProgressDelta(step, context);
  const sideEffects = detectSideEffects(step, context);

  // Composite confidence from multiple reflection signals
  const confidence = Math.min(1, Math.max(0,
    0.4 * goalAlignment.score +
    0.35 * progressDelta.score +
    0.25 * (1 - sideEffects.severity)
  ));

  let label = 'neutral';
  let reflection = '';

  if (confidence >= CONFIDENCE_HIGH) {
    label = 'effective';
    reflection = `Step "${step.action}" advanced goal "${context.goal || 'unknown'}" ` +
      `with progress delta ${progressDelta.delta.toFixed(3)}. ` +
      `Goal alignment: ${goalAlignment.reason}. No significant side effects.`;
  } else if (confidence <= CONFIDENCE_LOW) {
    label = 'suboptimal';
    reflection = `Step "${step.action}" was suboptimal: ` +
      `goal alignment ${goalAlignment.score.toFixed(2)}, ` +
      `progress delta ${progressDelta.delta.toFixed(3)}. ` +
      `Issues: ${sideEffects.issues.join('; ') || 'low goal relevance'}.`;
  } else {
    label = 'neutral';
    reflection = `Step "${step.action}" had mixed results: ` +
      `alignment ${goalAlignment.score.toFixed(2)}, ` +
      `delta ${progressDelta.delta.toFixed(3)}.`;
  }

  return { label, reflection, confidence };
}

/**
 * Trajectory-level reflection (Phi space).
 * Retrospective analysis across all steps, identifying patterns of
 * effectiveness and suboptimality in the full trajectory.
 *
 * @param {Array<object>} trajectory - Full trajectory: [{action, observation, reward, timestamp}, ...]
 * @returns {Promise<{effectiveSteps: Array<number>, suboptimalSteps: Array<number>, analysis: string}>}
 */
export async function reflectOnTrajectory(trajectory) {
  if (!Array.isArray(trajectory) || trajectory.length === 0) {
    return { effectiveSteps: [], suboptimalSteps: [], analysis: 'Empty trajectory.' };
  }

  const effectiveSteps = [];
  const suboptimalSteps = [];
  const stepLabels = [];
  let cumulativeReward = 0;

  // First pass: compute cumulative reward baseline
  const totalReward = trajectory.reduce((sum, s) => sum + (s.reward || 0), 0);
  const meanReward = totalReward / trajectory.length;

  // Second pass: label each step relative to trajectory context
  for (let i = 0; i < trajectory.length; i++) {
    const step = trajectory[i];
    const reward = step.reward || 0;
    cumulativeReward += reward;

    // Temporal credit assignment: steps early in high-reward trajectories get bonus
    const positionWeight = 1 - (i / trajectory.length) * 0.3;
    const adjustedReward = reward * positionWeight;

    // Steps that contribute above-average reward are effective
    if (adjustedReward > meanReward * 1.2) {
      effectiveSteps.push(i);
      stepLabels.push({ index: i, label: 'effective', score: adjustedReward });
    } else if (adjustedReward < meanReward * 0.5 || reward < 0) {
      suboptimalSteps.push(i);
      stepLabels.push({ index: i, label: 'suboptimal', score: adjustedReward });
    } else {
      stepLabels.push({ index: i, label: 'neutral', score: adjustedReward });
    }
  }

  // Detect repeated suboptimal patterns
  const repeatedPatterns = detectRepeatedPatterns(trajectory, suboptimalSteps);

  const analysis = buildTrajectoryAnalysis({
    totalSteps: trajectory.length,
    effectiveCount: effectiveSteps.length,
    suboptimalCount: suboptimalSteps.length,
    totalReward,
    meanReward,
    repeatedPatterns
  });

  return { effectiveSteps, suboptimalSteps, analysis };
}

/**
 * Refine-from-Reflection (RfR): generate m alternative rollouts for a suboptimal step.
 * Each alternative proposes a different action that could have yielded better outcomes.
 *
 * @param {object} suboptimalStep - The step labeled suboptimal: {action, observation, reward, context}
 * @param {object} context - Environment context at the time of the step
 * @param {number} m - Number of alternative rollouts to generate (default: 3)
 * @returns {Promise<Array<{action: string, expectedReward: number, reasoning: string}>>}
 */
export async function generateAlternatives(suboptimalStep, context, m = DEFAULT_ROLLOUT_COUNT) {
  if (!suboptimalStep || !suboptimalStep.action) {
    return [];
  }

  const alternatives = [];
  const existingActions = new Set([suboptimalStep.action]);
  const availableActions = context.availableActions || [];
  const goalState = context.goal || '';

  for (let i = 0; i < m; i++) {
    // Strategy rotation: diversify alternative generation
    const strategy = i % 3;
    let candidate;

    if (strategy === 0 && availableActions.length > 0) {
      // Direct alternative: pick from available actions not yet tried
      const unused = availableActions.filter(a => !existingActions.has(a));
      if (unused.length > 0) {
        const action = unused[Math.floor(Math.random() * unused.length)];
        candidate = {
          action,
          expectedReward: estimateReward(action, context),
          reasoning: `Direct alternative: "${action}" was available but not chosen. ` +
            `Expected better alignment with goal "${goalState}".`
        };
      }
    } else if (strategy === 1) {
      // Decomposition: break the suboptimal step into smaller sub-steps
      candidate = {
        action: `decompose(${suboptimalStep.action})`,
        expectedReward: (suboptimalStep.reward || 0) * 1.3,
        reasoning: `Decomposition: the original action "${suboptimalStep.action}" ` +
          `may have been too coarse. Breaking into sub-steps could yield incremental progress.`
      };
    } else {
      // Deferral: delay action and gather more information first
      candidate = {
        action: `observe_then(${suboptimalStep.action})`,
        expectedReward: (suboptimalStep.reward || 0) * 1.15,
        reasoning: `Deferral: gathering more context before executing ` +
          `"${suboptimalStep.action}" could reduce uncertainty and improve outcome.`
      };
    }

    if (candidate) {
      existingActions.add(candidate.action);
      alternatives.push(candidate);
    }
  }

  return alternatives;
}

/**
 * Build KTO preference dataset from trajectory reflections.
 * Uses prospect-theory asymmetric loss: suboptimal examples weighted by lambda > 1
 * to account for natural imbalance (most steps are effective in successful trajectories).
 *
 * @param {Array<object>} trajectory - Full trajectory steps
 * @param {object} reflections - Output from reflectOnTrajectory
 * @returns {Promise<Array<{input: string, output: string, label: 'desirable'|'undesirable', weight: number}>>}
 */
export async function buildPreferenceDataset(trajectory, reflections) {
  if (!Array.isArray(trajectory) || !reflections) {
    return [];
  }

  const pairs = [];
  const { effectiveSteps = [], suboptimalSteps = [] } = reflections;

  // Compute imbalance ratio for KTO weighting
  const totalLabeled = effectiveSteps.length + suboptimalSteps.length;
  if (totalLabeled === 0) return [];

  const desirableRatio = effectiveSteps.length / totalLabeled;
  const undesirableRatio = suboptimalSteps.length / totalLabeled;

  // Build desirable pairs from effective steps
  for (const idx of effectiveSteps) {
    const step = trajectory[idx];
    if (!step) continue;

    const contextWindow = trajectory.slice(Math.max(0, idx - 2), idx);
    const input = formatContextForTraining(contextWindow, step);

    // KTO weight: z_desirable = lambda_d * sigma(beta * (reward - baseline))
    const baseline = computeImplicitBaseline(trajectory, effectiveSteps, 'desirable');
    const reward = step.reward || 0;
    const ktoScore = KTO_LAMBDA_DESIRABLE * sigmoid(KTO_BETA * (reward - baseline));

    pairs.push({
      input,
      output: step.action,
      label: 'desirable',
      weight: ktoScore * (1 / Math.max(0.1, desirableRatio))
    });
  }

  // Build undesirable pairs from suboptimal steps
  for (const idx of suboptimalSteps) {
    const step = trajectory[idx];
    if (!step) continue;

    const contextWindow = trajectory.slice(Math.max(0, idx - 2), idx);
    const input = formatContextForTraining(contextWindow, step);

    // KTO weight: z_undesirable = lambda_u * sigma(beta * (baseline - reward))
    // lambda_u > lambda_d models loss aversion
    const baseline = computeImplicitBaseline(trajectory, suboptimalSteps, 'undesirable');
    const reward = step.reward || 0;
    const ktoScore = KTO_LAMBDA_UNDESIRABLE * sigmoid(KTO_BETA * (baseline - reward));

    pairs.push({
      input,
      output: step.action,
      label: 'undesirable',
      weight: ktoScore * (1 / Math.max(0.1, undesirableRatio))
    });
  }

  return pairs;
}

/**
 * Persist a full transaction (trajectory + reflections) to aimos_memories.
 * Serves dual purpose: short-term retrieval for in-context learning,
 * long-term storage for parametric finetuning.
 *
 * @param {string} agentId - Agent identifier
 * @param {Array<object>} trajectory - Full trajectory
 * @param {object} reflections - Reflection output
 * @param {string} companyId - Company ID
 * @returns {Promise<{saved: boolean, transactionId: string}>}
 */
export async function saveTransaction(agentId, trajectory, reflections, companyId = COMPANY) {
  const transactionId = `txn_${agentId}_${Date.now()}`;

  try {
    const payload = JSON.stringify({
      transactionId,
      agentId,
      trajectory,
      reflections,
      stepCount: trajectory.length,
      effectiveCount: reflections.effectiveSteps?.length || 0,
      suboptimalCount: reflections.suboptimalSteps?.length || 0,
      createdAt: new Date().toISOString()
    });

    await persistMemory({
      company_id: companyId,
      agent_id: agentId,
      mutation_authority: 'housekeeper',
      key: transactionId,
      value: payload,
      scope: 'agent',
      memory_type: 'reflection_transaction',
      memory_tier: 'long-term',
      clearance_level: 5
    });

    return { saved: true, transactionId };
  } catch (err) {
    console.error(`[REFLECTION-FINETUNER] Failed to save transaction: ${err.message}`);
    return { saved: false, transactionId };
  }
}

/**
 * Retrieve recent reflections for in-context learning.
 * Returns the most recent transactions for an agent, ordered by recency.
 *
 * @param {string} agentId - Agent identifier
 * @param {number} limit - Max transactions to retrieve (default: 5)
 * @param {string} companyId - Company ID
 * @returns {Promise<Array<object>>}
 */
export async function getRecentReflections(agentId, limit = 5, companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT key, value FROM aimos_memories
       WHERE company_id = $1 AND agent_id = $2
         AND memory_type = 'reflection_transaction'
       ORDER BY updated_at DESC
       LIMIT $3`,
      [companyId, agentId, limit]
    );

    return res.rows.map(row => {
      try {
        return JSON.parse(row.value);
      } catch {
        return { transactionId: row.key, parseError: true };
      }
    });
  } catch (err) {
    console.warn(`[REFLECTION-FINETUNER] Failed to retrieve reflections for ${agentId}: ${err.message}`);
    return [];
  }
}

export function buildSupersessionCorrectionDiagnostics({
  originalClaim = '',
  counterEvidence = [],
  proposedCorrection = '',
  correctionMode = 'supersession',
} = {}) {
  const evidence = Array.isArray(counterEvidence) ? counterEvidence.filter(Boolean) : [counterEvidence].filter(Boolean);
  const mode = String(correctionMode || '').trim().toLowerCase();
  const allowedMode = ALADDIN_CORRECTION_MODES.has(mode);
  const hasCorrection = String(proposedCorrection || '').trim().length > 0;
  const hasOriginal = String(originalClaim || '').trim().length > 0;
  const allowed = allowedMode && hasCorrection && hasOriginal && evidence.length > 0;

  return {
    source_paper: 'Towards Verifiable and Self-Correcting AI Physicists for Quantum Many-Body Simulations',
    status: allowed ? 'correction_allowed_as_supersession' : 'blocked_until_counter_evidence',
    diagnostic_only: true,
    correction_mode: mode || 'unspecified',
    verification_loop: [
      'generate_candidate_correction',
      'verify_against_counter_evidence',
      'persist_as_superseding_or_counter_evidence_record',
      'verify_existing_canonical_memory_was_not_removed',
    ],
    evidence_count: evidence.length,
    missing: {
      original_claim: !hasOriginal,
      counter_evidence: evidence.length === 0,
      proposed_correction: !hasCorrection,
      allowed_correction_mode: !allowedMode,
    },
    aladdin_boundary: {
      overwrite_enabled: false,
      deletion_enabled: false,
      soft_delete_enabled: false,
      ttl_enabled: false,
      canonical_memory_removed: false,
      existing_canonical_memory_mutated: false,
      new_superseding_record_required: allowed,
    },
    guarded_math: {
      dpo: true,
      dual_axis_finetune: true,
      lora_adapter: true,
      reward_hacking_finetune: true,
      rlaif: true,
      rlhf: true,
    },
    guarded_math_implemented: {
      dpo: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Direct Preference Optimization: Your Language Model is Secretly a Reward Model',
        coexistence_class: 'side_by_side_independent',
      },
      dual_axis_finetune: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Dual-Axis Generative Reward Model',
        coexistence_class: 'side_by_side_overlay',
      },
      lora_adapter: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'LoRA: Low-Rank Adaptation of Large Language Models',
        coexistence_class: 'side_by_side_independent',
      },
      reward_hacking_finetune: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Reward Hacking in the Era of Large Models',
        coexistence_class: 'side_by_side_independent',
      },
      rlaif: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'RLAIF vs RLHF: Comparing Reinforcement Learning from AI and Human Feedback',
        coexistence_class: 'side_by_side_overlay',
      },
      rlhf: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'InstructGPT: Training language models to follow instructions with human feedback',
        coexistence_class: 'audit_only_analogy',
      },
    },
  };
}

export const DPO_SOURCE = 'Direct Preference Optimization: Your Language Model is Secretly a Reward Model';
export const DUAL_AXIS_SOURCE = 'Dual-Axis Generative Reward Model';
export const LORA_SOURCE = 'LoRA: Low-Rank Adaptation of Large Language Models';
export const REWARD_HACKING_FINETUNE_SOURCE = 'Reward Hacking in the Era of Large Models';
export const RLAIF_SOURCE = 'RLAIF vs RLHF: Comparing Reinforcement Learning from AI and Human Feedback';
export const RLHF_SOURCE = 'InstructGPT: Training language models to follow instructions with human feedback';

/**
 * DPO Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Direct Preference Optimization
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * DPO paper: bypasses reward model; directly optimizes policy from preferences.
 * Δ_DPO = β[log p_θ(y_w) − log p_θ(y_l)] − β[log p_ref(y_w) − log p_ref(y_l)]
 * Log-prob-gated: numeric score ONLY when provider log-probs available.
 * Without log-probs: emits type='dpo_unscored'. Aimos does not train.
 * Reflection math unchanged. Guarded by guarded_math flag dpo
 * (knowledge-gated: paper understanding required).
 */
export function buildDPODiagnostic({
  preferenceData = [],
  logProbsAvailable = false,
  beta = 0.1,
} = {}) {
  const pairs = Array.isArray(preferenceData) ? preferenceData : [];

  if (!logProbsAvailable) {
    return {
      diagnostic: true,
      source_paper: DPO_SOURCE,
      coexistence_class: 'side_by_side_independent',
      type: 'dpo_unscored',
      reason: 'Provider log-probs not available; cannot compute Δ_DPO',
      preference_pair_count: pairs.length,
      log_probs_available: false,
      reflection_math_unchanged: true,
      note: 'Alongside-path diagnostic. DPO preference signal does not modify reflection math.',
    };
  }

  // DPO formula: Δ_DPO = β[log p_θ(y_w) - log p_θ(y_l)] - β[log p_ref(y_w) - log p_ref(y_l)]
  const deltas = pairs.map((pair) => {
    const logPThetaW = Number(pair?.log_p_theta_winning || pair?.log_p_policy_w || 0);
    const logPThetaL = Number(pair?.log_p_theta_losing || pair?.log_p_policy_l || 0);
    const logPRefW = Number(pair?.log_p_ref_winning || pair?.log_p_reference_w || 0);
    const logPRefL = Number(pair?.log_p_ref_losing || pair?.log_p_reference_l || 0);
    const deltaDPO = beta * (logPThetaW - logPThetaL) - beta * (logPRefW - logPRefL);
    return Number(deltaDPO.toFixed(6));
  });

  const meanDelta = deltas.length > 0
    ? deltas.reduce((s, d) => s + d, 0) / deltas.length
    : 0;

  return {
    diagnostic: true,
    source_paper: DPO_SOURCE,
    coexistence_class: 'side_by_side_independent',
    type: 'dpo_scored',
    formula: 'Δ_DPO = β[log p_θ(y_w) − log p_θ(y_l)] − β[log p_ref(y_w) − log p_ref(y_l)]',
    beta,
    preference_pair_count: pairs.length,
    log_probs_available: true,
    dpo_deltas: deltas,
    mean_dpo_delta: Number(meanDelta.toFixed(6)),
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. DPO preference signal does not modify reflection math.',
  };
}

/**
 * Dual-Axis Finetune Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Dual-Axis Generative Reward Model
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper: two-axis reward model with semantic quality + turn-taking coherence.
 * This diagnostic computes a two-axis assessment of feedback quality alongside
 * existing KTO reflection signals. Reflection math unchanged. Guarded by
 * guarded_math flag dual_axis_finetune (knowledge-gated: paper understanding
 * required).
 */
export function buildDualAxisFinetuneDiagnostic({
  feedback = [],
} = {}) {
  const fb = Array.isArray(feedback) ? feedback : [];

  // Semantic axis: content quality (goal alignment, information quality)
  const semanticScores = fb.map((f) => {
    const goalAlign = Number(f?.goal_alignment || f?.quality || 0.5);
    const infoQuality = Number(f?.information_quality || f?.relevance || 0.5);
    return (goalAlign + infoQuality) / 2;
  });

  // Turn-taking axis: conversational coherence
  const turnTakingScores = fb.map((f) => {
    const coherence = Number(f?.coherence || f?.consistency || 0.5);
    const responsiveness = Number(f?.responsiveness || f?.engagement || 0.5);
    return (coherence + responsiveness) / 2;
  });

  const meanSemantic = semanticScores.length > 0
    ? semanticScores.reduce((s, v) => s + v, 0) / semanticScores.length
    : 0;
  const meanTurnTaking = turnTakingScores.length > 0
    ? turnTakingScores.reduce((s, v) => s + v, 0) / turnTakingScores.length
    : 0;

  return {
    diagnostic: true,
    source_paper: DUAL_AXIS_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    feedback_count: fb.length,
    dual_axis: {
      semantic_quality: Number(meanSemantic.toFixed(6)),
      turn_taking_coherence: Number(meanTurnTaking.toFixed(6)),
      combined: Number(((meanSemantic + meanTurnTaking) / 2).toFixed(6)),
    },
    semantic_scores: semanticScores.map((s) => Number(s.toFixed(6))),
    turn_taking_scores: turnTakingScores.map((s) => Number(s.toFixed(6))),
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. Dual-axis reward does not modify reflection math.',
  };
}

/**
 * LoRA Adapter Diagnostic — Alongside-path diagnostic
 *
 * Source paper: LoRA — Low-Rank Adaptation of Large Language Models
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * LoRA paper: low-rank adaptation matrices for efficient fine-tuning.
 * This is an inactive adaptation contract only — Aimos does NOT fine-tune.
 * No fine-tune execution path exists. Guarded by guarded_math flag
 * lora_adapter (knowledge-gated: paper understanding required).
 */
export function buildLoRAAdapterDiagnostic({
  adapterConfig = {},
} = {}) {
  const config = adapterConfig && typeof adapterConfig === 'object' ? adapterConfig : {};

  return {
    diagnostic: true,
    source_paper: LORA_SOURCE,
    coexistence_class: 'side_by_side_independent',
    inactive_contract: true,
    aimos_does_not_finetune: true,
    adapter_rank: config.rank || config.r || null,
    adapter_alpha: config.alpha || config.lora_alpha || null,
    target_modules: config.target_modules || [],
    fine_tune_execution_path_exists: false,
    no_weight_modification: true,
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. LoRA adapter contract is inactive; Aimos does not fine-tune.',
  };
}

/**
 * Reward Hacking Finetune Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Reward Hacking in the Era of Large Models
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper: models game their reward signal. This diagnostic detects patterns
 * where self-improvement loops may be reward-hacking the reflection system
 * (e.g., labeling all steps as effective regardless of quality). The
 * reflection math remains authoritative. Guarded by guarded_math flag
 * reward_hacking_finetune (knowledge-gated: paper understanding required).
 */
export function buildRewardHackingFinetuneDiagnostic({
  improvementLoop = [],
} = {}) {
  const loop = Array.isArray(improvementLoop) ? improvementLoop : [];

  const effectiveCount = loop.filter((entry) => {
    const label = String(entry?.label || entry?.verdict || '').toLowerCase();
    return /\b(effective|pass|good|positive|desirable)\b/.test(label);
  }).length;
  const total = loop.length;
  const effectiveRate = total > 0 ? effectiveCount / total : 0;

  // Reward hacking signal: suspiciously high effective rate
  const suspiciouslyHighEffective = total >= 5 && effectiveRate > 0.9;

  // Easy-path detection: all "effective" labels with low confidence
  const lowConfidenceEffective = loop.filter((entry) => {
    const label = String(entry?.label || entry?.verdict || '').toLowerCase();
    const confidence = Number(entry?.confidence || entry?.score || 1);
    return /\b(effective|pass|good|positive)\b/.test(label) && confidence < 0.5;
  }).length;

  return {
    diagnostic: true,
    source_paper: REWARD_HACKING_FINETUNE_SOURCE,
    coexistence_class: 'side_by_side_independent',
    loop_iteration_count: total,
    effective_count: effectiveCount,
    effective_rate: Number(effectiveRate.toFixed(6)),
    reward_hacking_suspected: suspiciouslyHighEffective,
    low_confidence_effective_count: lowConfidenceEffective,
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. Reward-hacking detection does not modify reflection math.',
  };
}

/**
 * RLAIF Diagnostic — Alongside-path diagnostic
 *
 * Source paper: RLAIF vs RLHF
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * RLAIF paper: AI feedback as substitute for human feedback.
 * Log-prob-gated: numeric score ONLY when provider log-probs available.
 * Without log-probs: emits type='rlaif_unscored'. Aimos does not train.
 * Reflection math unchanged. Guarded by guarded_math flag rlaif
 * (knowledge-gated: paper understanding required).
 */
export function buildRLAIFDiagnostic({
  preferenceData = [],
  logProbsAvailable = false,
} = {}) {
  const pairs = Array.isArray(preferenceData) ? preferenceData : [];

  if (!logProbsAvailable) {
    return {
      diagnostic: true,
      source_paper: RLAIF_SOURCE,
      coexistence_class: 'side_by_side_overlay',
      type: 'rlaif_unscored',
      reason: 'Provider log-probs not available; cannot compute RLAIF score',
      preference_pair_count: pairs.length,
      log_probs_available: false,
      reflection_math_unchanged: true,
      note: 'Alongside-path diagnostic. RLAIF signal does not modify reflection math.',
    };
  }

  // RLAIF scoring with log-probs: AI preference consistency
  const scores = pairs.map((pair) => {
    const aiPreferred = Number(pair?.ai_preference_score || pair?.rlaif_score || 0);
    return Number(aiPreferred.toFixed(6));
  });

  const meanScore = scores.length > 0
    ? scores.reduce((s, v) => s + v, 0) / scores.length
    : 0;

  return {
    diagnostic: true,
    source_paper: RLAIF_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    type: 'rlaif_scored',
    preference_pair_count: pairs.length,
    log_probs_available: true,
    rlaif_scores: scores,
    mean_rlaif_score: Number(meanScore.toFixed(6)),
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. RLAIF signal does not modify reflection math.',
  };
}

/**
 * RLHF Diagnostic — Alongside-path diagnostic
 *
 * Source paper: InstructGPT — RLHF
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Foundational preference-shape contract; diagnostic-only.
 * Aimos does not train. Audit-only reference. Guarded by guarded_math
 * flag rlhf (knowledge-gated: paper understanding required).
 */
export function buildRLHFDiagnostic({
  preferenceSignals = [],
} = {}) {
  const signals = Array.isArray(preferenceSignals) ? preferenceSignals : [];

  return {
    diagnostic: true,
    source_paper: RLHF_SOURCE,
    coexistence_class: 'audit_only_analogy',
    audit_only: true,
    aimos_does_not_train: true,
    preference_signal_count: signals.length,
    no_reward_model_training: true,
    no_policy_optimization: true,
    foundational_reference_only: true,
    reflection_math_unchanged: true,
    note: 'Alongside-path diagnostic. RLHF contract is audit-only; Aimos does not train.',
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function computeGoalAlignment(step, context) {
  if (!context.goal) {
    return { score: 0.5, reason: 'No goal specified' };
  }

  // Keyword overlap heuristic between action description and goal
  const actionTokens = new Set(String(step.action).toLowerCase().split(/\s+/));
  const goalTokens = String(context.goal).toLowerCase().split(/\s+/);
  const overlap = goalTokens.filter(t => actionTokens.has(t)).length;
  const score = Math.min(1, overlap / Math.max(1, goalTokens.length));

  return {
    score,
    reason: score > 0.6
      ? `Strong keyword alignment (${overlap}/${goalTokens.length})`
      : `Weak keyword alignment (${overlap}/${goalTokens.length})`
  };
}

function computeProgressDelta(step, context) {
  const prevSteps = context.previousSteps || [];
  const prevReward = prevSteps.length > 0
    ? prevSteps[prevSteps.length - 1].reward || 0
    : 0;
  const currentReward = step.reward || 0;
  const delta = currentReward - prevReward;

  return {
    delta,
    score: Math.min(1, Math.max(0, 0.5 + delta * 2))
  };
}

function detectSideEffects(step, context) {
  const issues = [];
  let severity = 0;

  // Check for resource exhaustion signals
  if (step.observation && typeof step.observation === 'string') {
    const obs = step.observation.toLowerCase();
    if (obs.includes('error') || obs.includes('failure')) {
      issues.push('Error in observation');
      severity += 0.4;
    }
    if (obs.includes('timeout') || obs.includes('limit')) {
      issues.push('Resource limit hit');
      severity += 0.3;
    }
    if (obs.includes('rollback') || obs.includes('reverted')) {
      issues.push('State rollback detected');
      severity += 0.5;
    }
  }

  return { issues, severity: Math.min(1, severity) };
}

function detectRepeatedPatterns(trajectory, suboptimalIndices) {
  if (suboptimalIndices.length < 2) return [];

  const patterns = [];
  const actionCounts = {};

  for (const idx of suboptimalIndices) {
    const action = trajectory[idx]?.action || '';
    actionCounts[action] = (actionCounts[action] || 0) + 1;
  }

  for (const [action, count] of Object.entries(actionCounts)) {
    if (count >= 2) {
      patterns.push(`Action "${action}" was suboptimal ${count} times`);
    }
  }

  return patterns;
}

function buildTrajectoryAnalysis({ totalSteps, effectiveCount, suboptimalCount, totalReward, meanReward, repeatedPatterns }) {
  const effectiveRate = ((effectiveCount / totalSteps) * 100).toFixed(1);
  const suboptimalRate = ((suboptimalCount / totalSteps) * 100).toFixed(1);

  let analysis = `Trajectory of ${totalSteps} steps: ` +
    `${effectiveCount} effective (${effectiveRate}%), ` +
    `${suboptimalCount} suboptimal (${suboptimalRate}%). ` +
    `Total reward: ${totalReward.toFixed(3)}, mean: ${meanReward.toFixed(3)}.`;

  if (repeatedPatterns.length > 0) {
    analysis += ` Repeated issues: ${repeatedPatterns.join('; ')}.`;
  }

  return analysis;
}

function estimateReward(action, context) {
  if (!context.goal) return 0.5;
  const actionTokens = new Set(String(action).toLowerCase().split(/\s+/));
  const goalTokens = String(context.goal).toLowerCase().split(/\s+/);
  const overlap = goalTokens.filter(t => actionTokens.has(t)).length;
  return Math.min(1, 0.3 + overlap * 0.2);
}

function formatContextForTraining(contextWindow, step) {
  const history = contextWindow
    .map((s, i) => `[${i}] action=${s.action} obs=${s.observation || ''}`)
    .join('\n');
  return `Context:\n${history}\nCurrent state: ${step.observation || 'none'}\nGoal: ${step.context?.goal || 'unknown'}`;
}

function computeImplicitBaseline(trajectory, indices, type) {
  // KL-constrained implicit baseline: mean reward of the reference group
  const rewards = indices.map(i => trajectory[i]?.reward || 0);
  if (rewards.length === 0) return 0;
  return rewards.reduce((a, b) => a + b, 0) / rewards.length;
}

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}
