// ═══════════════════════════════════════════════════════════════════════════════
// COOPERATIVE ACTION ARBITRATION (cooperative-action-arbitration.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Batch9 Wave3 authority: Towards Interactive and Learnable Cooperative Driving
// Automation.
// Batch9.75 authority: Toolformer- Language Models Can Teach Themselves to Use
// Tools.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildToolformerTruthDiagnostic: Tool-use truth diagnostic alongside
//     existing cooperative arbitration. No hidden tool execution.
//
// Diagnostic-only arbitration for proposed actions. This module never executes
// tools and never unlocks hidden tool use. Toolformer is represented as a
// tool-truth diagnostic for self-inserted tool claims only.
// ═══════════════════════════════════════════════════════════════════════════════

export const COOPERATIVE_DRIVING_SOURCE = 'Towards Interactive and Learnable Cooperative Driving Automation';
export const TOOLFORMER_SOURCE = 'Toolformer- Language Models Can Teach Themselves to Use Tools';

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value || 0)));
}

function defaultFailureEscalation(failureInfo) {
  if (!failureInfo || typeof failureInfo !== 'object') return false;
  if (['no_results', 'parse_error', 'timeout'].includes(String(failureInfo.type || ''))) return true;
  if (typeof failureInfo.confidence === 'number' && failureInfo.confidence < 0.4) return true;
  return Boolean(failureInfo.error);
}

export function buildToolformerToolTruthDiagnostics({
  claimedToolCalls = [],
  observedToolEvents = [],
} = {}) {
  const claims = Array.isArray(claimedToolCalls) ? claimedToolCalls : [];
  const observed = new Set(
    (Array.isArray(observedToolEvents) ? observedToolEvents : [])
      .map((event) => String(event?.tool_id || event?.tool || event?.name || '').trim())
      .filter(Boolean),
  );
  const unsupported = claims
    .map((claim) => String(claim?.tool_id || claim?.tool || claim?.name || claim || '').trim())
    .filter(Boolean)
    .filter((tool) => !observed.has(tool));

  return {
    status: unsupported.length ? 'tool_claim_mismatch' : 'tool_claims_observed',
    source_paper: TOOLFORMER_SOURCE,
    diagnostic_only: true,
    claimed_tool_count: claims.length,
    observed_tool_count: observed.size,
    unsupported_claims: unsupported,
    safety_contract: {
      hidden_tool_execution_enabled: false,
      self_inserted_tool_call_trusted: false,
      tool_executed: false,
      canonical_memory_mutated: false,
    },
  };
}

export function buildCooperativeActionArbitrationDiagnostics({
  action = '',
  riskLevel = 'low',
  toolConfidence = 0,
  userApprovalPresent = false,
  laneState = 'clear',
  failureInfo = null,
  claimedToolCalls = [],
  observedToolEvents = [],
  shouldEscalateFailure = defaultFailureEscalation,
} = {}) {
  const risk = String(riskLevel || 'low').toLowerCase();
  const confidence = clamp01(toolConfidence);
  const lane = String(laneState || 'clear').toLowerCase();
  const blockedByRisk = ['high', 'critical'].includes(risk) && !userApprovalPresent;
  const blockedByLane = ['blocked', 'unknown', 'conflict'].includes(lane);
  const blockedByFailure = Boolean(shouldEscalateFailure?.(failureInfo));
  const toolTruth = buildToolformerToolTruthDiagnostics({ claimedToolCalls, observedToolEvents });
  const blockedByToolTruth = toolTruth.status === 'tool_claim_mismatch';
  const needsHuman = blockedByRisk || blockedByLane || blockedByFailure || blockedByToolTruth;

  return {
    status: 'diagnostic',
    source_papers: [COOPERATIVE_DRIVING_SOURCE, TOOLFORMER_SOURCE],
    diagnostic_only: true,
    action: String(action || 'unknown'),
    arbitration_state: needsHuman ? 'human_in_loop_required' : 'autonomous_safe_to_consider',
    signals: {
      risk_level: risk,
      tool_confidence: confidence,
      user_approval_present: Boolean(userApprovalPresent),
      lane_state: lane,
      failure_type: failureInfo?.type || null,
      tool_truth_status: toolTruth.status,
    },
    tool_truth: toolTruth,
    safety_contract: {
      tool_executed: false,
      automatic_tool_unlock_enabled: false,
      user_approval_required: needsHuman,
      hidden_tool_execution_enabled: false,
      canonical_memory_mutated: false,
    },
    guarded_math: {
      toolformer_truth: true,
    },
    guarded_math_implemented: {
      toolformer_truth: {
        enabled: true,
        diagnostic_only: true,
        source_paper: TOOLFORMER_SOURCE,
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

/**
 * Toolformer Truth Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Toolformer — Language Models Can Teach Themselves to Use Tools
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function produces a tool-use truth diagnostic
 * alongside existing cooperative arbitration. It does NOT enable hidden
 * tool execution or modify the cooperative driving arbitration path. The
 * existing buildToolformerToolTruthDiagnostics production path remains
 * authoritative. Guarded by guarded_math flag toolformer_truth which is
 * guarded in production (knowledge-gated: paper understanding required). Reader-only/no-raw: raw_gap_visible is true.
 */
export function buildToolformerTruthDiagnostic({
  claimedToolCalls = [],
  observedToolEvents = [],
} = {}) {
  const claims = Array.isArray(claimedToolCalls) ? claimedToolCalls : [];
  const observed = new Set(
    (Array.isArray(observedToolEvents) ? observedToolEvents : [])
      .map((event) => String(event?.tool_id || event?.tool || event?.name || '').trim())
      .filter(Boolean),
  );
  const unsupported = claims
    .map((claim) => String(claim?.tool_id || claim?.tool || claim?.name || claim || '').trim())
    .filter(Boolean)
    .filter((tool) => !observed.has(tool));

  const truthScores = claims.map((claim) => {
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
    source_paper: TOOLFORMER_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    raw_gap_visible: true,
    claim_count: claims.length,
    observed_count: observed.size,
    unsupported_claims: unsupported,
    truth_scores: truthScores,
    overall_truth_ratio: claims.length > 0 ? truthScores.filter((s) => s.observed).length / claims.length : 1,
    safety_contract: {
      hidden_tool_execution_enabled: false,
      self_inserted_tool_call_trusted: false,
      tool_executed: false,
      canonical_memory_mutated: false,
    },
    note: 'Alongside-path diagnostic. Tool-use truth diagnostic only; no hidden tool execution.',
  };
}
