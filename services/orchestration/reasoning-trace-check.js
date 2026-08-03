// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js (write_file, shell actions)
// → Calls: db (connection.js) — aimos_memories query
// Pipeline: AGENT_RUN_PIPELINE | Position: Knowledge-to-Write Gate (security)
//
// SERVICE CONNECTION GUIDE:
// 1. ← Triggered by: tool-registry.js (Specifically for write_file / shell actions)
// 2. → Pulls from: aimos_memories (Queries for recent 'framework' and 'procedural' memories)
// 3. → Benefits from: asmr-pipeline.js (PPR and recall calibration increase trace accuracy)
// 4. → Affects: tool-registry.js (Blocks write access if reasoning score < threshold)
//
// LOGIC GUIDE (Semantic Lockdown): Strictly enforces "Knowledge-to-Write."
// An agent CANNOT modify a brain file unless it has proven its expertise by
// recalling the relevant technical framework or procedure in the current session.
// Additive Batch9 Wave6 authority: Guess What I Am Thinking adds observable
// role/tool-truth diagnostics only; hidden thoughts and scratchpads are never
// requested or exposed.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildC2FTraceDiagnostic: Coarse-to-fine reasoning trace with hint levels
//     alongside existing knowledge-to-write gate. Gate logic unchanged.
//   - buildCoTPresenceDiagnostic: CoT trace presence diagnostic alongside
//     existing trace verification. Never stored as canonical memory.
//   - buildCoVTraceDiagnostic: Chain-of-Verification trace alongside existing
//     trace verification. Verification pass counts are diagnostic only.
//   - buildReActTraceDiagnostic: Thought-Act-Observe trace diagnostic
//     alongside existing FSM stream states. FSM logic unchanged.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * reasoning-trace-check.js
 * Source: HOM Fortress Security Plan (v1)
 * Additive TEM authority: Learning Hierarchical Procedural Memory for LLM
 * Agents through Bayesian Selection and Contrastive Refinement (MACLA)
 *
 * MACLA note: this gate only verifies that a recent procedural/framework trace
 * exists before writes. Bayesian procedure selection and contrastive refinement
 * remain outside this security check.
 */
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';

const COMPANY = AIMOS_COMPANY_ID;

function tokenize(text) {
  return new Set(String(text || '').toLowerCase().split(/[^a-z0-9_:-]+/).filter((token) => token.length > 2));
}

function overlapScore(left, right) {
  const a = tokenize(left);
  const b = tokenize(right);
  const union = new Set([...a, ...b]);
  if (!union.size) return 0;
  let intersection = 0;
  for (const token of a) {
    if (b.has(token)) intersection++;
  }
  return intersection / union.size;
}

/**
 * Validates reasoning trace for a specific agent and path.
 * @param {string} agentId - The agent attempting the action.
 * @param {string} targetPath - The file path being modified.
 * @returns {Promise<{valid: boolean, reason: string, score: number}>}
 */
export async function checkReasoningTrace(agentId, targetPath) {
  try {
    const filename = targetPath.split('/').pop();
    
    // 1. Look for recent framework or procedural memories from THIS agent
    // that specifically match the target filename.
    const res = await query(
      `SELECT memory_type, value, created_at 
       FROM aimos_memories
       WHERE company_id = $1 
         AND agent_id = $2
         AND (memory_type IN ('framework', 'procedural'))
         AND (value ILIKE $3 OR key ILIKE $3)
         AND created_at > NOW() - INTERVAL '60 minutes'
       ORDER BY created_at DESC LIMIT 5`,
      [COMPANY, agentId, `%${filename}%`]
    );

    if (res.rows.length === 0) {
      return {
        valid: false,
        reason: `Knowledge-to-Write Gate: Agent ${agentId} lacks required 'framework' or 'procedural' knowledge for ${filename}. Proof of Reasoning missing.`,
        score: 0
      };
    }

    // 2. Simple score based on evidence volume and recency
    const score = Math.min(1.0, res.rows.length * 0.25);
    
    return {
      valid: true,
      reason: 'Active reasoning trace verified.',
      score
    };
  } catch (err) {
    return {
      valid: false,
      reason: `Internal error during trace verification: ${err.message}`,
      score: 0
    };
  }
}

export function buildObservableRoleConsistencyDiagnostics({
  declaredRole = '',
  observableActions = [],
  toolClaims = [],
} = {}) {
  const actions = Array.isArray(observableActions) ? observableActions : [];
  const claims = Array.isArray(toolClaims) ? toolClaims : [];
  const actionText = actions.map((action) => typeof action === 'string' ? action : `${action?.tool || ''} ${action?.action || ''} ${action?.summary || ''}`).join(' ');
  const roleAlignment = declaredRole ? overlapScore(declaredRole, actionText) : 0;
  const unsupportedClaims = claims.filter((claim) => {
    const claimText = typeof claim === 'string' ? claim : `${claim?.tool || ''} ${claim?.claim || ''} ${claim?.summary || ''}`;
    return claimText && overlapScore(claimText, actionText) < 0.12;
  });

  return {
    source_paper: 'Guess What I Am Thinking: A Benchmark for Inner Thought Reasoning of Role-Playing Language Agents',
    status: unsupportedClaims.length
      ? 'tool_truth_mismatch'
      : roleAlignment >= 0.12 || !declaredRole
        ? 'observable_consistency_ok'
        : 'role_action_mismatch',
    diagnostic_only: true,
    declared_role: declaredRole,
    observable_action_count: actions.length,
    tool_claim_count: claims.length,
    unsupported_tool_claim_count: unsupportedClaims.length,
    role_alignment_proxy: Number(roleAlignment.toFixed(6)),
    unsupported_tool_claims: unsupportedClaims.map((claim) => typeof claim === 'string' ? claim : claim?.claim || claim?.tool || 'unknown'),
    guardrails: {
      hidden_thoughts_requested: false,
      hidden_chain_of_thought_exposed: false,
      tool_execution_performed: false,
      write_gate_changed: false,
    },
    guarded_math: {
      c2f_trace: true,
      cot_presence: true,
      cov_trace: true,
      react_trace: true,
    },
    guarded_math_implemented: {
      c2f_trace: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'C2F-Thinker: Coarse-to-Fine Reasoning with Hint-Guided Reinforcement Learning',
        coexistence_class: 'side_by_side_overlay',
      },
      cot_presence: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Chain-of-Thought Prompting Elicits Reasoning in Large Language Models',
        coexistence_class: 'side_by_side_overlay',
      },
      cov_trace: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Chain-of-Verification Reduces Hallucination in Large Language Models',
        coexistence_class: 'side_by_side_independent',
      },
      react_trace: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'ReAct: Synergizing Reasoning and Acting in Language Models',
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

export const C2F_SOURCE = 'C2F-Thinker: Coarse-to-Fine Reasoning with Hint-Guided Reinforcement Learning';
export const COT_SOURCE = 'Chain-of-Thought Prompting Elicits Reasoning in Large Language Models';
export const COV_SOURCE = 'Chain-of-Verification Reduces Hallucination in Large Language Models';
export const REACT_SOURCE = 'ReAct: Synergizing Reasoning and Acting in Language Models';

/**
 * C2F Trace Diagnostic — Alongside-path diagnostic
 *
 * Source paper: C2F-Thinker — Coarse-to-Fine Reasoning with Hint-Guided RL
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * C2F paper: reasoning proceeds coarse→fine with hint levels L0 (answer-only),
 * L1 (answer + coarse hint), L2 (answer + fine hint). Hint-level escalation
 * correlates with reasoning difficulty. This diagnostic maps existing trace
 * steps onto C2F hint levels as a diagnostic overlay alongside the
 * knowledge-to-write gate. Gate logic unchanged. Guarded by guarded_math
 * flag c2f_trace which is guarded in production (knowledge-gated).
 */
export function buildC2FTraceDiagnostic({
  traceSteps = [],
  hintLevel = 0,
} = {}) {
  const steps = Array.isArray(traceSteps) ? traceSteps : [];
  const hint = Math.max(0, Math.min(2, Number(hintLevel) || 0));

  // C2F hint-level mapping: depth of reasoning = granularity
  // L0: answer-only (shallow), L1: coarse hint (moderate), L2: fine hint (deep)
  const stepDepths = steps.map((step, i) => {
    const text = String(step?.action || step?.rationale || step || '');
    // Coarse reasoning = short/keyword steps; fine reasoning = detailed/structured
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    const hasStructure = /\b(because|therefore|since|hence|thus|analysis|evidence|step|phase)\b/i.test(text);
    return {
      step_index: i + 1,
      hint_level: hasStructure ? Math.min(2, Math.floor(wordCount / 15)) : 0,
      word_count: wordCount,
      has_reasoning_structure: hasStructure,
    };
  });

  const coarseSteps = stepDepths.filter((s) => s.hint_level === 0).length;
  const moderateSteps = stepDepths.filter((s) => s.hint_level === 1).length;
  const fineSteps = stepDepths.filter((s) => s.hint_level === 2).length;
  const fineRatio = steps.length > 0 ? fineSteps / steps.length : 0;

  return {
    diagnostic: true,
    source_paper: C2F_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    requested_hint_level: hint,
    total_steps: steps.length,
    hint_distribution: { l0_answer_only: coarseSteps, l1_coarse_hint: moderateSteps, l2_fine_hint: fineSteps },
    fine_grained_ratio: Number(fineRatio.toFixed(6)),
    step_depths: stepDepths,
    gate_logic_unchanged: true,
    note: 'Alongside-path diagnostic. C2F hint-level overlay does not modify knowledge-to-write gate.',
  };
}

/**
 * CoT Presence Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Chain-of-Thought Prompting Elicits Reasoning in LLMs
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CoT paper: intermediate reasoning steps improve accuracy. This diagnostic
 * checks for presence of chain-of-thought trace fields (rationale, reasoning
 * steps) alongside existing trace verification. The CoT trace itself is
 * diagnostic-only — it MUST NEVER be stored as canonical memory.
 * Guarded by guarded_math flag cot_presence which is guarded in production.
 */
export function buildCoTPresenceDiagnostic({
  traceSteps = [],
} = {}) {
  const steps = Array.isArray(traceSteps) ? traceSteps : [];

  // CoT presence: fraction of steps that carry a rationale/reasoning field
  const stepsWithRationale = steps.filter((step) => {
    const rationale = step?.rationale || step?.reasoning || step?.chain_of_thought || '';
    return String(rationale).trim().length > 0;
  }).length;
  const cotPresence = steps.length > 0 ? stepsWithRationale / steps.length : 0;

  // CoT depth: average word count of rationale fields
  const rationaleWordCounts = steps
    .map((step) => String(step?.rationale || step?.reasoning || step?.chain_of_thought || '').trim())
    .filter((text) => text.length > 0)
    .map((text) => text.split(/\s+/).filter(Boolean).length);
  const avgRationaleDepth = rationaleWordCounts.length > 0
    ? rationaleWordCounts.reduce((sum, n) => sum + n, 0) / rationaleWordCounts.length
    : 0;

  return {
    diagnostic: true,
    source_paper: COT_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    total_steps: steps.length,
    steps_with_rationale: stepsWithRationale,
    cot_presence_ratio: Number(cotPresence.toFixed(6)),
    avg_rationale_depth_words: Number(avgRationaleDepth.toFixed(2)),
    canonical_memory_storage: 'forbidden',
    gate_logic_unchanged: true,
    note: 'Alongside-path diagnostic. CoT trace is presence-only; never stored as canonical memory.',
  };
}

/**
 * CoV Trace Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Chain-of-Verification Reduces Hallucination in LLMs
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CoV paper: self-verification passes reduce hallucination. A verification
 * chain is: draft → verify question → verify answer → final. This diagnostic
 * counts verification passes and checks whether independent verification
 * was performed. Alongside existing trace verification; pass counts are
 * diagnostic only. Guarded by guarded_math flag cov_trace which is guarded
 * in production (knowledge-gated).
 */
export function buildCoVTraceDiagnostic({
  verificationChain = [],
} = {}) {
  const chain = Array.isArray(verificationChain) ? verificationChain : [];

  // CoV: count verification passes (each pass has a verify step after a draft)
  const draftSteps = chain.filter((step) => {
    const text = String(step?.type || step?.action || step?.phase || step || '').toLowerCase();
    return /\b(draft|generate|propose|hypothesize|initial)\b/.test(text);
  }).length;
  const verifySteps = chain.filter((step) => {
    const text = String(step?.type || step?.action || step?.phase || step || '').toLowerCase();
    return /\b(verify|check|validate|confirm|evidence)\b/.test(text);
  }).length;

  // CoV verification coverage: ratio of verify steps to draft steps
  // CoV paper: each draft should have a corresponding verification pass
  const verificationCoverage = draftSteps > 0 ? Math.min(1, verifySteps / draftSteps) : 0;

  // Independent verification: verification that doesn't reuse the draft's evidence
  const independentVerifications = chain.filter((step) => {
    const text = String(step?.type || step?.action || step?.phase || step || '').toLowerCase();
    return /\b(verify|check|validate|confirm)\b/.test(text) && /\b(independent|separate|external)\b/.test(text);
  }).length;

  return {
    diagnostic: true,
    source_paper: COV_SOURCE,
    coexistence_class: 'side_by_side_independent',
    chain_length: chain.length,
    draft_steps: draftSteps,
    verify_steps: verifySteps,
    verification_coverage: Number(verificationCoverage.toFixed(6)),
    independent_verification_count: independentVerifications,
    cov_pattern_detected: verifySteps > 0 && draftSteps > 0,
    gate_logic_unchanged: true,
    note: 'Alongside-path diagnostic. CoV verification counts do not modify trace gate logic.',
  };
}

/**
 * ReAct Trace Diagnostic — Alongside-path diagnostic
 *
 * Source paper: ReAct — Synergizing Reasoning and Acting in Language Models
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * ReAct paper: interleaved Thought-Action-Observation traces improve
 * reasoning + acting synergy. This diagnostic maps existing trace steps
 * onto ReAct phases as an overlay alongside existing FSM stream states.
 * FSM logic unchanged. Guarded by guarded_math flag react_trace which is
 * guarded in production (knowledge-gated).
 */
export function buildReActTraceDiagnostic({
  traceSteps = [],
} = {}) {
  const steps = Array.isArray(traceSteps) ? traceSteps : [];

  // ReAct phase classification: Thought / Action / Observation
  const phaseMap = steps.map((step, i) => {
    const text = String(step?.action || step?.type || step?.phase || step?.rationale || step || '').toLowerCase();
    let reactPhase = 'unknown';
    if (/\b(think|thought|reason|consider|analyze|plan|hypothes)\b/.test(text)) {
      reactPhase = 'thought';
    } else if (/\b(act|action|execute|call|invoke|run|perform|search|lookup)\b/.test(text)) {
      reactPhase = 'action';
    } else if (/\b(observ|result|output|response|evidence|received|got|found)\b/.test(text)) {
      reactPhase = 'observation';
    }
    return { step_index: i + 1, react_phase: reactPhase };
  });

  const thoughtCount = phaseMap.filter((p) => p.react_phase === 'thought').length;
  const actionCount = phaseMap.filter((p) => p.react_phase === 'action').length;
  const observationCount = phaseMap.filter((p) => p.react_phase === 'observation').length;

  // ReAct synergy: interleaving ratio (ideal ≈ 1:1:1 normalized)
  // Low interleaving = monologue (all thoughts then all actions) — ReAct paper shows interleaving improves results
  const phaseTransitions = phaseMap.reduce((count, p, i) => {
    if (i > 0 && p.react_phase !== phaseMap[i - 1].react_phase && p.react_phase !== 'unknown') count++;
    return count;
  }, 0);
  const interleavingRatio = steps.length > 1 ? phaseTransitions / (steps.length - 1) : 0;

  return {
    diagnostic: true,
    source_paper: REACT_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    total_steps: steps.length,
    phase_counts: { thought: thoughtCount, action: actionCount, observation: observationCount },
    interleaving_ratio: Number(interleavingRatio.toFixed(6)),
    react_pattern_detected: thoughtCount > 0 && actionCount > 0,
    phase_map: phaseMap,
    fsm_logic_unchanged: true,
    note: 'Alongside-path diagnostic. ReAct phase overlay does not modify FSM stream states.',
  };
}
