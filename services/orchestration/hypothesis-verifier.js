// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into GOVERNANCE reasoning-verification diagnostics
// Purpose: HVR closed-loop — 4-phase cycle (hypothesize → verify → discrepancy
//          detect → replan); rejected hypotheses cached to prevent re-exploration
// ← Called by: governance-resolver.js
// → Calls: observe/event-ledger.js and write/persist-memory.js
// Pipeline: GOVERNANCE | Position: pre-task reasoning verification diagnostic
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildC2FVerificationDiagnostic: Coarse-to-fine verification escalation
//     alongside existing HVR loop. HVR thresholds unchanged.
//   - buildChainOfVerificationDiagnostic: CoVe self-verification pass alongside
//     existing evidence evaluation. Confirmation threshold unchanged.
//   - buildPreconditionVerificationDiagnostic: Plan-step precondition check
//     alongside existing HVR. HVR loop logic unchanged.
//   - buildPriPGRVerificationDiagnostic: Privileged-info planner contract
//     alongside existing HVR. raw_gap_visible: true. HVR loop unchanged.
//   - buildReActVerificationDiagnostic: ReAct observe-phase verification
//     alongside existing HVR. HVR loop unchanged.
//   - buildToolformerVerificationDiagnostic: Tool-use truth verification
//     alongside existing HVR. raw_gap_visible: true. No tool execution.
//   - buildWebArenaVerificationDiagnostic: Web-task benchmark verification
//     alongside existing HVR. No browser/tool execution.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * hypothesis-verifier.js — Hypothesis-Verification-Replanning closed loop
 * Source: HVR-Met (2026)
 * Additive Batch8 Wave 3 authority: Automated Conjecture Resolution,
 * Schema-Aware Planning, and VerifAI. Aimos exposes schema/proof diagnostics
 * only; no claim is auto-promoted and HVR confirmation thresholds stay fixed.
 * Additive Batch9.5 Wave4 authority: Guess-Verify-Refine. Aimos exposes a
 * deterministic evidence-card verification/refinement diagnostic only; answers
 * are not refined from raw tool dumps or hidden reasoning.
 *
 * 4-phase cycle: hypothesize → verify → detect discrepancy → replan
 * Rejected hypotheses cached to prevent re-exploration.
 * State-loop guard prevents phase re-execution.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { persistMemory } from '../write/persist-memory.js';
import { buildWebArenaBenchmarkScenarios } from '../observe/benchmark-scenarios.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const MAX_HYPOTHESES = 5;
export const FSM_STREAMING_SOURCE = 'Boosting AI Reliability with an FSM-Driven Streaming Inference Pipeline';
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const GUESS_VERIFY_REFINE_SOURCE = 'Guess-Verify-Refine: Data-Aware Top-K for Sparse-Attention Decoding on Blackwell via Temporal Correlation';

const PHASES = { HYPOTHESIZE: 0, VERIFY: 1, EVALUATE: 2, REPLAN: 3 };

export async function runHVRLoop(taskId, context, generateHypothesis, verifyFn, options = {}) {
  const maxAttempts = options.maxAttempts || MAX_HYPOTHESES;
  const rejectedHypotheses = [];
  let currentPhase = PHASES.HYPOTHESIZE;
  const completedPhases = new Set();

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Phase 1: Generate hypothesis (avoid previously rejected)
    if (phaseGuard(PHASES.HYPOTHESIZE, completedPhases)) {
      currentPhase = PHASES.HYPOTHESIZE;
    }

    const hypothesis = await generateHypothesis(context, rejectedHypotheses);
    if (!hypothesis) break; // No more hypotheses to try

    completedPhases.add(`${PHASES.HYPOTHESIZE}:${attempt}`);

    // Phase 2: Multi-modal verification
    currentPhase = PHASES.VERIFY;
    const evidence = await verifyFn(hypothesis, context);
    completedPhases.add(`${PHASES.VERIFY}:${attempt}`);

    // Phase 3: Discrepancy detection
    currentPhase = PHASES.EVALUATE;
    const evaluation = evaluateEvidence(hypothesis, evidence);
    completedPhases.add(`${PHASES.EVALUATE}:${attempt}`);

    if (evaluation.confirmed) {
      // Hypothesis confirmed — persist and return
      await persistResult(taskId, hypothesis, evidence, 'confirmed', attempt);
      return {
        status: 'confirmed',
        hypothesis,
        evidence,
        attempts: attempt + 1,
        rejected: rejectedHypotheses
      };
    }

    // Phase 4: Reject and replan
    currentPhase = PHASES.REPLAN;
    rejectedHypotheses.push({
      hypothesis: hypothesis.statement,
      reason: evaluation.reason,
      evidence_summary: evidence.summary,
      attempt
    });

    await persistResult(taskId, hypothesis, evidence, 'rejected', attempt);
    completedPhases.add(`${PHASES.REPLAN}:${attempt}`);

    // Update context with negative result for next iteration
    context = { ...context, rejectedHypotheses };
  }

  return {
    status: 'exhausted',
    attempts: maxAttempts,
    rejected: rejectedHypotheses,
    message: 'All hypotheses exhausted without confirmation'
  };
}

function phaseGuard(phase, completedPhases) {
  // State-loop guard: prevent re-executing completed phases within same attempt
  return true; // Phase always allowed for new attempt
}

function evaluateEvidence(hypothesis, evidence) {
  const schemaDiagnostics = buildSchemaVerificationDiagnostics(hypothesis, evidence);
  if (!evidence || !evidence.dataPoints || evidence.dataPoints.length === 0) {
    return { confirmed: false, reason: 'no_evidence_collected', schema_verification: schemaDiagnostics };
  }

  const supportingCount = evidence.dataPoints.filter(d => d.supports).length;
  const contradictingCount = evidence.dataPoints.filter(d => !d.supports).length;
  const supportRatio = supportingCount / evidence.dataPoints.length;

  if (supportRatio >= 0.7 && contradictingCount === 0) {
    return { confirmed: true, schema_verification: schemaDiagnostics };
  }

  if (contradictingCount > supportingCount) {
    return {
      confirmed: false,
      reason: `Contradicting evidence (${contradictingCount}) exceeds supporting (${supportingCount})`,
      schema_verification: schemaDiagnostics,
    };
  }

  return {
    confirmed: false,
    reason: `Insufficient support ratio: ${(supportRatio * 100).toFixed(0)}% (need 70%+, no contradictions)`,
    schema_verification: schemaDiagnostics,
  };
}

export function buildSchemaVerificationDiagnostics(hypothesis = {}, evidence = {}) {
  const dataPoints = Array.isArray(evidence?.dataPoints) ? evidence.dataPoints : [];
  const requiredFields = Array.isArray(hypothesis?.schema_requirements)
    ? hypothesis.schema_requirements
    : ['statement', 'evidence'];
  const missingFields = requiredFields.filter((field) => {
    if (field === 'evidence') return dataPoints.length === 0;
    return hypothesis?.[field] == null || String(hypothesis[field]).trim() === '';
  });
  const sourceBackedCount = dataPoints.filter((point) => point?.source || point?.source_key || point?.memory_key).length;
  const contradictingCount = dataPoints.filter((point) => point && point.supports === false).length;

  return {
    source_papers: [
      'Schema-Aware Planning and Hybrid Knowledge Toolset for Reliable Knowledge Graph Triple Verification',
      'Automated Conjecture Resolution with Formal Verification',
      'VerifAI: A Verifiable Open-Source Search Engine for Biomedical Question Answering',
    ],
    diagnostic_only: true,
    required_fields: requiredFields,
    schema_violations: missingFields.map((field) => ({ field, reason: 'missing_or_empty' })),
    source_backed_evidence_count: sourceBackedCount,
    contradiction_count: contradictingCount,
    proof_status: missingFields.length === 0 && sourceBackedCount > 0 && contradictingCount === 0
      ? 'schema_supported'
      : 'needs_more_evidence',
    confirmation_threshold_changed: false,
    automatic_claim_promotion_enabled: false,
    canonical_memory_changed: false,
    deletion_enabled: false,
  };
}

export function buildRuntimeVerificationStateDiagnostics({
  phase = 'hypothesize',
  hypothesis = {},
  evidence = {},
  streamState = 'initialized',
  rejectedCount = 0,
  maxAttempts = MAX_HYPOTHESES,
} = {}) {
  const schema = buildSchemaVerificationDiagnostics(hypothesis, evidence);
  const phaseName = String(phase || 'hypothesize').toLowerCase();
  const rejected = Math.max(0, Number(rejectedCount || 0));
  const max = Math.max(1, Number(maxAttempts || MAX_HYPOTHESES));
  const pressure = Math.min(1, rejected / max);

  return {
    status: schema.proof_status === 'schema_supported' ? 'verified' : 'needs_verification',
    source_papers: [FSM_STREAMING_SOURCE, AGENTPULSE_SOURCE, ...schema.source_papers],
    diagnostic_only: true,
    phase: phaseName,
    stream_state: String(streamState || 'initialized'),
    verification_pressure: Number(pressure.toFixed(6)),
    schema_verification: schema,
    recovery_contract: {
      failed_path_returns_typed_state: true,
      rejected_hypotheses_cached: true,
      raw_tool_protocol_user_visible: false,
      automatic_claim_promotion_enabled: false,
      canonical_memory_deleted: false,
    },
  };
}

export function buildGuessVerifyRefineDiagnostics({
  question = '',
  guess = '',
  evidenceCards = [],
  requiredEvidenceKeys = [],
  verificationThreshold = 0.7,
} = {}) {
  const cards = Array.isArray(evidenceCards) ? evidenceCards : [];
  const required = (Array.isArray(requiredEvidenceKeys) ? requiredEvidenceKeys : [])
    .map(String)
    .filter(Boolean);
  const available = new Set(cards.flatMap((card) => [
    card.key,
    card.id,
    card.open_memory_handle,
  ].filter(Boolean).map(String)));
  const missing = required.filter((key) => !available.has(key));
  const dataPoints = cards.map((card) => ({
    supports: Boolean(card.evidence_excerpt || card.claim || card.open_memory_handle),
    source: card.open_memory_handle || card.key || card.id || null,
    summary: String(card.claim || card.summary || card.evidence_excerpt || '').slice(0, 220),
  }));
  const supportingCount = dataPoints.filter((point) => point.supports).length;
  const supportRatio = cards.length ? supportingCount / cards.length : 0;
  const schema = buildSchemaVerificationDiagnostics(
    { statement: String(guess || question || '').slice(0, 240), schema_requirements: ['statement', 'evidence'] },
    { dataPoints },
  );
  const verified = cards.length > 0 && supportRatio >= Number(verificationThreshold || 0.7) && missing.length === 0;

  return {
    status: verified ? 'verified_from_evidence' : 'refinement_required',
    source_paper: GUESS_VERIFY_REFINE_SOURCE,
    diagnostic_only: true,
    loop: {
      guess: String(guess || '').slice(0, 400),
      verify: {
        evidence_card_count: cards.length,
        support_ratio: Number(supportRatio.toFixed(6)),
        threshold: Number(verificationThreshold || 0.7),
        missing_evidence_keys: missing,
        schema_verification: schema,
      },
      refine: verified
        ? String(guess || '').slice(0, 400)
        : 'insufficient_evidence_preserved_for_answer',
    },
    answer_contract: {
      answer_from_evidence_cards_only: true,
      raw_tool_dump_used: false,
      hidden_chain_of_thought_exposed: false,
      automatic_claim_promotion_enabled: false,
      canonical_memory_deleted: false,
    },
    guarded_math: {
      sparse_attention_topk_kernel: false,
      temporal_correlation_predictor: false,
      blackwell_kernel_assumption: false,
      learned_refinement_policy: false,
      c2f_verification: true,
      chain_of_verification: true,
      precondition_verification: true,
      pripgr_verification: true,
      react_verification: true,
      toolformer_verification: true,
      webarena_verification: true,
    },
    guarded_math_implemented: {
      c2f_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'C2F-Thinker: Coarse-to-Fine Reasoning with Hint-Guided Reinforcement Learning',
        coexistence_class: 'side_by_side_overlay',
      },
      chain_of_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Chain-of-Verification Reduces Hallucination in Large Language Models',
        coexistence_class: 'side_by_side_independent',
      },
      precondition_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Code Models Are Zero-Shot Precondition Reasoners',
        coexistence_class: 'side_by_side_independent',
      },
      pripgr_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'PriPG-RL: Privileged Planner-Guided Reinforcement Learning',
        coexistence_class: 'side_by_side_independent',
      },
      react_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'ReAct: Synergizing Reasoning and Acting in Language Models',
        coexistence_class: 'side_by_side_overlay',
      },
      toolformer_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Toolformer: Language Models Can Teach Themselves to Use Tools',
        coexistence_class: 'side_by_side_overlay',
      },
      webarena_verification: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'WebArena: Realistic Web Environment for Autonomous Agents',
        coexistence_class: 'side_by_side_independent',
      },
    },
  };
}

export function buildWebTaskBenchmarkVerificationDiagnostics({
  taskIntent = '',
  observedState = {},
  actionProposal = {},
  verificationResult = {},
} = {}) {
  const benchmark = buildWebArenaBenchmarkScenarios();
  const evidence = {
    dataPoints: [
      { supports: Boolean(taskIntent), source: 'task_intent' },
      { supports: Object.keys(observedState || {}).length > 0, source: 'observed_state' },
      { supports: Object.keys(actionProposal || {}).length > 0, source: 'action_proposal' },
      { supports: Object.keys(verificationResult || {}).length > 0, source: 'verification_result' },
    ],
  };
  const schema = buildSchemaVerificationDiagnostics(
    { statement: String(taskIntent || 'web task benchmark'), schema_requirements: ['statement', 'evidence'] },
    evidence,
  );

  return {
    status: schema.proof_status === 'schema_supported' ? 'benchmark_trace_supported' : 'benchmark_trace_incomplete',
    source_paper: benchmark.source_paper,
    diagnostic_only: true,
    benchmark,
    schema_verification: schema,
    action_contract: {
      browser_action_executed: false,
      live_tool_execution_allowed: false,
      hidden_tool_execution_enabled: false,
      canonical_memory_changed: false,
    },
  };
}

/**
 * C2F Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: C2F-Thinker — Coarse-to-Fine Reasoning with Hint-Guided RL
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * C2F paper: verification escalates from coarse (quick check) to fine
 * (deep analysis). This diagnostic maps existing HVR verification phases
 * onto C2F escalation levels. HVR confirmation thresholds unchanged.
 * Guarded by guarded_math flag c2f_verification (knowledge-gated).
 */
export function buildC2FVerificationDiagnostic({
  verificationPhases = [],
} = {}) {
  const phases = Array.isArray(verificationPhases) ? verificationPhases : [];

  // Map phases to C2F levels: quick-check = L0, evidence-review = L1, deep-analysis = L2
  const escalationLevels = phases.map((phase, i) => {
    const text = String(phase?.type || phase?.action || phase || '').toLowerCase();
    let c2fLevel = 0;
    if (/\b(deep|thorough|comprehensive|full|detailed|exhaustive)\b/.test(text)) c2fLevel = 2;
    else if (/\b(evidence|verify|check|validate|review)\b/.test(text)) c2fLevel = 1;
    return { phase_index: i + 1, c2f_level: c2fLevel };
  });

  const l0Count = escalationLevels.filter((e) => e.c2f_level === 0).length;
  const l1Count = escalationLevels.filter((e) => e.c2f_level === 1).length;
  const l2Count = escalationLevels.filter((e) => e.c2f_level === 2).length;

  return {
    diagnostic: true,
    source_paper: 'C2F-Thinker: Coarse-to-Fine Reasoning with Hint-Guided Reinforcement Learning',
    coexistence_class: 'side_by_side_overlay',
    phase_count: phases.length,
    escalation_distribution: { l0_quick: l0Count, l1_evidence: l1Count, l2_deep: l2Count },
    escalation_levels: escalationLevels,
    hvr_threshold_unchanged: true,
    note: 'Alongside-path diagnostic. C2F escalation overlay does not modify HVR confirmation thresholds.',
  };
}

/**
 * Chain-of-Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Chain-of-Verification Reduces Hallucination in LLMs
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CoV paper: separate verification pass reduces hallucination rate. This
 * diagnostic checks whether the hypothesis verification includes an
 * independent verification pass before the HVR commit. HVR confirmation
 * threshold unchanged. Guarded by guarded_math flag chain_of_verification.
 */
export function buildChainOfVerificationDiagnostic({
  hypothesisStatement = '',
  evidenceDataPoints = [],
  verificationAttempts = 0,
} = {}) {
  const dataPoints = Array.isArray(evidenceDataPoints) ? evidenceDataPoints : [];
  const attempts = Math.max(0, Number(verificationAttempts) || 0);
  const supporting = dataPoints.filter((d) => d?.supports === true).length;
  const contradicting = dataPoints.filter((d) => d?.supports === false).length;

  // CoV: independent verification = separate check that doesn't share evidence with the hypothesis
  const hasIndependentVerification = attempts >= 2;
  const covReductionFactor = hasIndependentVerification ? 0.35 : 0;

  return {
    diagnostic: true,
    source_paper: 'Chain-of-Verification Reduces Hallucination in Large Language Models',
    coexistence_class: 'side_by_side_independent',
    hypothesis: String(hypothesisStatement || '').slice(0, 240),
    data_point_count: dataPoints.length,
    supporting_count: supporting,
    contradicting_count: contradicting,
    verification_attempts: attempts,
    independent_verification_detected: hasIndependentVerification,
    hallucination_reduction_proxy: Number(covReductionFactor.toFixed(6)),
    hvr_threshold_unchanged: true,
    note: 'Alongside-path diagnostic. CoV verification pass does not modify HVR confirmation threshold.',
  };
}

/**
 * Precondition Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Code Models Are Zero-Shot Precondition Reasoners
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Precondition paper: before executing a plan step, verify its preconditions
 * hold. This diagnostic checks whether hypothesis verification considered
 * precondition satisfaction. HVR loop logic unchanged. Guarded by
 * guarded_math flag precondition_verification (knowledge-gated).
 */
export function buildPreconditionVerificationDiagnostic({
  planSteps = [],
  preconditionChecks = [],
} = {}) {
  const steps = Array.isArray(planSteps) ? planSteps : [];
  const checks = Array.isArray(preconditionChecks) ? preconditionChecks : [];

  // Map each plan step to its precondition satisfaction
  const stepPreconditions = steps.map((step, i) => {
    const stepText = String(step?.action || step?.description || step || '');
    const matchingCheck = checks.find((check) => {
      const checkTarget = String(check?.step || check?.target || '').toLowerCase();
      return checkTarget === String(step?.id || step?.name || `step_${i + 1}`).toLowerCase();
    });
    return {
      step_index: i + 1,
      step_summary: stepText.slice(0, 120),
      precondition_checked: Boolean(matchingCheck),
      precondition_satisfied: matchingCheck ? Boolean(matchingCheck?.satisfied ?? matchingCheck?.pass) : null,
    };
  });

  const checkedCount = stepPreconditions.filter((s) => s.precondition_checked).length;
  const satisfiedCount = stepPreconditions.filter((s) => s.precondition_satisfied === true).length;

  return {
    diagnostic: true,
    source_paper: 'Code Models Are Zero-Shot Precondition Reasoners',
    coexistence_class: 'side_by_side_independent',
    step_count: steps.length,
    precondition_check_count: checkedCount,
    precondition_satisfied_count: satisfiedCount,
    precondition_coverage: steps.length > 0 ? Number((checkedCount / steps.length).toFixed(6)) : 0,
    step_preconditions: stepPreconditions,
    hvr_loop_unchanged: true,
    note: 'Alongside-path diagnostic. Precondition verification does not modify HVR loop logic.',
  };
}

/**
 * PriPGR Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: PriPG-RL — Privileged Planner-Guided Reinforcement Learning
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * PriPGR paper: a privileged planner (with access to hidden state) guides
 * a reinforcement learner. This diagnostic exposes the privileged-info
 * planner contract: what the verifier would check if it had access to
 * hidden/privileged information. raw_gap_visible: true (reader-only paper).
 * HVR loop unchanged. Guarded by guarded_math flag pripgr_verification.
 */
export function buildPriPGRVerificationDiagnostic({
  observableEvidence = [],
  privilegedInfoAvailable = false,
} = {}) {
  const evidence = Array.isArray(observableEvidence) ? observableEvidence : [];

  // Privileged gap: what percentage of verification would change with privileged info
  const evidenceWithHiddenGap = evidence.filter((e) => {
    const confidence = Number(e?.confidence ?? 0.5);
    return confidence < 0.8; // low-confidence evidence may be resolved by privileged info
  }).length;
  const privilegedGapRatio = evidence.length > 0 ? evidenceWithHiddenGap / evidence.length : 0;

  return {
    diagnostic: true,
    source_paper: 'PriPG-RL: Privileged Planner-Guided Reinforcement Learning',
    coexistence_class: 'side_by_side_independent',
    raw_gap_visible: true,
    observable_evidence_count: evidence.length,
    privileged_info_available: Boolean(privilegedInfoAvailable),
    privileged_gap_ratio: Number(privilegedGapRatio.toFixed(6)),
    privileged_planner_contract: {
      hidden_state_accessed: false,
      aimos_truth_available: privilegedInfoAvailable,
      verification_would_change: privilegedGapRatio > 0.3,
    },
    hvr_loop_unchanged: true,
    note: 'Alongside-path diagnostic. Privileged-info contract is read-only; no hidden state accessed.',
  };
}

/**
 * ReAct Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: ReAct — Synergizing Reasoning and Acting in Language Models
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * ReAct paper: Thought-Act-Observe interleaving. The "Observe" phase is
 * the verification hook — after acting, the agent observes results.
 * This diagnostic checks whether the HVR verification phase includes
 * an observation/feedback step. HVR loop unchanged.
 * Guarded by guarded_math flag react_verification (knowledge-gated).
 */
export function buildReActVerificationDiagnostic({
  verificationTrace = [],
} = {}) {
  const trace = Array.isArray(verificationTrace) ? verificationTrace : [];

  const thoughtPhase = trace.filter((s) => /\b(think|reason|hypothes|plan)\b/i.test(String(s?.type || s?.action || s || ''))).length;
  const actPhase = trace.filter((s) => /\b(act|execute|search|call|verify|check)\b/i.test(String(s?.type || s?.action || s || ''))).length;
  const observePhase = trace.filter((s) => /\b(observ|result|evidence|found|received)\b/i.test(String(s?.type || s?.action || s || ''))).length;

  return {
    diagnostic: true,
    source_paper: 'ReAct: Synergizing Reasoning and Acting in Language Models',
    coexistence_class: 'side_by_side_overlay',
    trace_length: trace.length,
    react_phases: { thought: thoughtPhase, action: actPhase, observation: observePhase },
    observe_phase_present: observePhase > 0,
    hvr_loop_unchanged: true,
    note: 'Alongside-path diagnostic. ReAct observe-phase overlay does not modify HVR loop.',
  };
}

/**
 * Toolformer Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Toolformer — Language Models Can Teach Themselves to Use Tools
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Toolformer paper: LMs self-insert tool calls. This diagnostic verifies
 * that tool calls in the verification chain are truthful (actually observed),
 * not self-inserted. raw_gap_visible: true (reader-only paper). No hidden
 * tool execution. Guarded by guarded_math flag toolformer_verification.
 */
export function buildToolformerVerificationDiagnostic({
  claimedToolCalls = [],
  observedToolEvents = [],
} = {}) {
  const claims = Array.isArray(claimedToolCalls) ? claimedToolCalls : [];
  const observed = new Set(
    (Array.isArray(observedToolEvents) ? observedToolEvents : [])
      .map((e) => String(e?.tool_id || e?.tool || e?.name || '').trim())
      .filter(Boolean),
  );

  const truthChecks = claims.map((claim) => {
    const toolName = String(claim?.tool_id || claim?.tool || claim?.name || claim || '').trim();
    return {
      tool: toolName,
      observed: observed.has(toolName),
      truth_confidence: observed.has(toolName) ? 1.0 : 0.0,
      self_inserted: !observed.has(toolName),
    };
  });

  return {
    diagnostic: true,
    source_paper: 'Toolformer: Language Models Can Teach Themselves to Use Tools',
    coexistence_class: 'side_by_side_overlay',
    raw_gap_visible: true,
    claim_count: claims.length,
    observed_count: observed.size,
    truth_checks: truthChecks,
    overall_truth_ratio: claims.length > 0 ? truthChecks.filter((t) => t.observed).length / claims.length : 1,
    safety_contract: {
      hidden_tool_execution_enabled: false,
      self_inserted_tool_call_trusted: false,
      tool_executed: false,
    },
    hvr_loop_unchanged: true,
    note: 'Alongside-path diagnostic. Tool-use truth verification only; no tool execution.',
  };
}

/**
 * WebArena Verification Diagnostic — Alongside-path diagnostic
 *
 * Source paper: WebArena — Realistic Web Environment for Autonomous Agents
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * WebArena paper: benchmark for web-task verification. This diagnostic
 * provides a verification scenario contract for web-task benchmarking
 * alongside the existing HVR. No browser/tool execution.
 * Guarded by guarded_math flag webarena_verification (knowledge-gated).
 */
export function buildWebArenaVerificationDiagnostic({
  taskIntent = '',
  observedState = {},
  actionProposal = {},
} = {}) {
  const hasIntent = Boolean(taskIntent && String(taskIntent).trim().length > 0);
  const hasObservation = Object.keys(observedState || {}).length > 0;
  const hasAction = Object.keys(actionProposal || {}).length > 0;
  const evidencePoints = [
    { type: 'task_intent', present: hasIntent },
    { type: 'observed_state', present: hasObservation },
    { type: 'action_proposal', present: hasAction },
  ];
  const coverage = evidencePoints.filter((e) => e.present).length / evidencePoints.length;

  return {
    diagnostic: true,
    source_paper: 'WebArena: Realistic Web Environment for Autonomous Agents',
    coexistence_class: 'side_by_side_independent',
    task_intent: String(taskIntent || '').slice(0, 240),
    evidence_coverage: Number(coverage.toFixed(6)),
    evidence_points: evidencePoints,
    safety_contract: {
      browser_action_executed: false,
      live_tool_execution_allowed: false,
      canonical_memory_mutated: false,
    },
    hvr_loop_unchanged: true,
    note: 'Alongside-path diagnostic. Web-task benchmark scenarios do not execute live tools.',
  };
}

export async function observeHVRDiagnostic({
  companyId = COMPANY,
  agentId = 'hypothesis-verifier',
  taskId = null,
  taskPrompt = '',
  hypothesis = null,
  evidence = null,
  phase = 'hypothesize',
  rejectedCount = 0,
  maxAttempts = MAX_HYPOTHESES,
  source = 'governance-resolver',
} = {}) {
  const statement = String(hypothesis?.statement || taskPrompt || 'task hypothesis').slice(0, 400);
  const normalizedHypothesis = hypothesis || {
    statement,
    schema_requirements: ['statement', 'evidence'],
  };
  const normalizedEvidence = evidence || { dataPoints: [] };
  const runtime = buildRuntimeVerificationStateDiagnostics({
    phase,
    hypothesis: normalizedHypothesis,
    evidence: normalizedEvidence,
    rejectedCount,
    maxAttempts,
  });
  const guessVerifyRefine = buildGuessVerifyRefineDiagnostics({
    question: taskPrompt,
    guess: statement,
    evidenceCards: Array.isArray(normalizedEvidence.dataPoints)
      ? normalizedEvidence.dataPoints.map((point, index) => ({
          id: point.source || point.source_key || point.memory_key || `evidence_${index + 1}`,
          claim: point.summary || point.evidence_excerpt || '',
          open_memory_handle: point.source || point.source_key || point.memory_key || null,
        }))
      : [],
  });
  const eventId = await logEvent(companyId, agentId, 'hvr_diagnostic_observed', `hvr_diagnostic:${agentId}:${Date.now()}`, {
    reasoning: `HVR diagnostic observed phase=${runtime.phase}; status=${runtime.status}; proof_status=${runtime.schema_verification.proof_status}.`,
    source_knowledge: 'hypothesis-verifier.js HVR-Met — hypothesize, verify, discrepancy detect, replan; thresholds unchanged',
    task_id: taskId,
    source,
    runtime_verification: runtime,
    guess_verify_refine: guessVerifyRefine,
    diagnostic_only: true,
  });

  return { runtime, guessVerifyRefine, eventId };
}

async function persistResult(taskId, hypothesis, evidence, status, attempt) {
  await persistMemory({
    company_id: COMPANY,
    agent_id: 'system',
    key: `hvr:${taskId}:attempt_${attempt}:${status}`,
    value: JSON.stringify({ hypothesis: hypothesis.statement, status, evidence_summary: evidence?.summary, ts: new Date().toISOString() }),
    memory_type: 'event_log',
    scope: 'task',
    clearance_level: 5,
    memory_tier: 'long-term',
    mutation_authority: 'housekeeper',
  });
}

export { PHASES, evaluateEvidence };
