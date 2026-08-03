// ─── KNOWLEDGE GATE ENFORCER ─────────────────────────────────────────────────
// Status: L0 Sovereign Guardrail — Hard-blocks architectural changes without source recall
// Purpose: Ensures no component is modified without a retrieved academic source.
// Compliance: Speed.md Appendix A | Aladdin Law | Brain Sovereignty
// Additive Batch8 Wave 3 authority: Schema-Aware Planning, VerifAI, and
// Learn by Surprise Commit by Proof. Aimos exposes auditable source-evidence
// requirements only; no destructive memory action or auto-canonical overwrite.
// Additive Batch9 Wave2 authority: Sum-of-Checks, Governing What You Cannot
// Observe, and Security Considerations for AI Agents. Source-integrity
// diagnostics are additive and preserve the hard gate.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildCuraLightGateDiagnostic: CuraLight debate-guided gate diagnostic
//     alongside existing knowledge gate. Gate logic unchanged.
//   - buildRewardHackingGateDiagnostic: Reward-hacking detector diagnostic
//     on self-improvement loops alongside existing gate. Gate unchanged.
// ─────────────────────────────────────────────────────────────────────────────

// Knowledge Gate retired 2026-07-07 — gating functions removed; diagnostics below are pure-data (no DB/event-ledger imports).

const ALLOWED_SOURCE_TYPES = [
  'tacit_knowledge',
  'procedural',
  'procedural_seed',
  'book_extract',
  'bibliographic_reference',
  'framework',
];

export function buildSourceEvidenceRequirements({
  component = '',
  rows = [],
  proposedChange = {},
  contradictions = [],
} = {}) {
  const evidenceRows = Array.isArray(rows) ? rows : [];
  const topCredit = evidenceRows.reduce((max, row) => Math.max(max, Number(row.credit_score || 0)), 0);
  const hasCitation = evidenceRows.some((row) => row.source || row.key);
  const isArchitectureSensitive = /\b(architecture|security|governance|memory|recall|write|delete|unlearn|ranking|calibration)\b/i
    .test(`${component} ${proposedChange?.description || ''}`);

  return {
    source_papers: [
      'Schema-Aware Planning and Hybrid Knowledge Toolset for Reliable Knowledge Graph Triple Verification',
      'VerifAI: A Verifiable Open-Source Search Engine for Biomedical Question Answering',
      'Learn by Surprise, Commit by Proof',
    ],
    diagnostic_only: true,
    component,
    min_source_count: isArchitectureSensitive ? 2 : 1,
    actual_source_count: evidenceRows.length,
    allowed_memory_types: ALLOWED_SOURCE_TYPES,
    citation_present: hasCitation,
    contradiction_count: Array.isArray(contradictions) ? contradictions.length : 0,
    top_source_confidence: Number(topCredit.toFixed(3)),
    high_impact_change: isArchitectureSensitive,
    status: evidenceRows.length >= (isArchitectureSensitive ? 2 : 1) && hasCitation && !contradictions.length
      ? 'source_requirements_satisfied'
      : 'source_requirements_need_review',
    source_integrity: buildKnowledgeSourceIntegrityDiagnostics({ component, rows: evidenceRows, proposedChange, contradictions }),
    write_blocking_changed: false,
    canonical_memory_changed: false,
    deletion_enabled: false,
    guarded_math: {
      curalight_gate: true,
      reward_hacking_gate: true,
    },
    guarded_math_implemented: {
      curalight_gate: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
        coexistence_class: 'side_by_side_overlay',
      },
      reward_hacking_gate: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Reward Hacking in the Era of Large Models',
        coexistence_class: 'side_by_side_independent',
      },
    },
  };
}

export function buildKnowledgeSourceIntegrityDiagnostics({
  component = '',
  rows = [],
  proposedChange = {},
  contradictions = [],
} = {}) {
  const evidenceRows = Array.isArray(rows) ? rows : [];
  const changeText = String(proposedChange?.description || proposedChange?.summary || '');
  const destructiveIntent = /\b(delete|drop|erase|remove canonical|hard delete|soft delete|ttl|expire|unlearn as removal)\b/i.test(changeText);
  const sourceTypes = [...new Set(evidenceRows.map((row) => row.memory_type || row.type || 'unknown'))];
  const missingSourceRows = evidenceRows.filter((row) => !row.source && !row.key).length;
  const authorityRows = evidenceRows.filter((row) => ALLOWED_SOURCE_TYPES.includes(row.memory_type || row.type)).length;
  const contradictionCount = Array.isArray(contradictions) ? contradictions.length : 0;

  return {
    source_papers: [
      'Sum-of-Checks: Structured Reasoning for Surgical Safety with Large Vision-Language Models',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
      'Security Considerations for Artificial Intelligence Agents',
    ],
    diagnostic_only: true,
    component,
    evidence_rows: evidenceRows.length,
    authority_rows: authorityRows,
    source_types: sourceTypes,
    missing_source_rows: missingSourceRows,
    contradiction_count: contradictionCount,
    destructive_intent_detected: destructiveIntent,
    integrity_status: destructiveIntent || missingSourceRows > 0 || contradictionCount > 0
      ? 'needs_review'
      : 'source_integrity_ok',
    gate_threshold_changed: false,
    canonical_memory_changed: false,
    deletion_enabled: false,
  };
}

// Knowledge Gate retired 2026-07-07 — gating functions removed; only alongside-path diagnostics remain.

export default { buildSourceEvidenceRequirements };

/**
 * CuraLight Gate Diagnostic — Alongside-path diagnostic
 *
 * Source paper: CuraLight — Debate-Guided Data Curation for Medical Image Analysis
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CuraLight paper: debate-guided curation improves data quality. This
 * diagnostic assesses whether the knowledge gate decision has been vetted
 * through multi-perspective debate. Debate signals do NOT override or lower
 * the hard gate. The knowledge gate's source-evidence requirements remain
 * authoritative. Guarded by guarded_math flag curalight_gate (knowledge-gated).
 */
export function buildCuraLightGateDiagnostic({
  gateResult = {},
  debatePerspectives = [],
} = {}) {
  const perspectives = Array.isArray(debatePerspectives) ? debatePerspectives : [];
  const status = String(gateResult?.status || 'unknown');

  const agreeing = perspectives.filter((p) => /\b(agree|support|accept|pass)\b/i.test(String(p?.verdict || p?.stance || ''))).length;
  const disagreeing = perspectives.filter((p) => /\b(disagree|reject|fail|oppose)\b/i.test(String(p?.verdict || p?.stance || ''))).length;
  const agreementRatio = perspectives.length > 0 ? agreeing / perspectives.length : 1;

  return {
    diagnostic: true,
    source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
    coexistence_class: 'side_by_side_overlay',
    gate_status: status,
    perspective_count: perspectives.length,
    agreement_ratio: Number(agreementRatio.toFixed(6)),
    dissent_count: disagreeing,
    debate_does_not_override_hard_gate: true,
    gate_logic_unchanged: true,
    note: 'Alongside-path diagnostic. CuraLight debate signal does not override knowledge gate requirements.',
  };
}

/**
 * Reward Hacking Gate Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Reward Hacking in the Era of Large Models
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Reward hacking paper: models game their reward signal. This diagnostic
 * detects patterns where self-improvement loops may be reward-hacking the
 * knowledge gate (e.g., proposing only easy changes that auto-approve).
 * The hard gate's source-evidence requirements remain authoritative.
 * Guarded by guarded_math flag reward_hacking_gate (knowledge-gated).
 */
export function buildRewardHackingGateDiagnostic({
  gateResult = {},
  recentGateDecisions = [],
} = {}) {
  const decisions = Array.isArray(recentGateDecisions) ? recentGateDecisions : [];
  const status = String(gateResult?.status || 'unknown');

  // Reward hacking signal: unusually high approval rate suggests gaming
  const approvals = decisions.filter((d) => String(d?.status || d?.gate_status || '') === 'approved').length;
  const blocks = decisions.filter((d) => String(d?.status || d?.gate_status || '') === 'blocked').length;
  const total = decisions.length;
  const approvalRate = total > 0 ? approvals / total : 0;

  // High approval rate (>0.9) with many decisions (>5) = potential reward hacking
  const suspiciouslyHighApproval = total >= 5 && approvalRate > 0.9;

  // Easy-path detection: all approved changes target non-architecture components
  const architectureSensitiveChanges = decisions.filter((d) => {
    const component = String(d?.component || '').toLowerCase();
    return /\b(architecture|security|governance|memory|recall|write|ranking)\b/.test(component);
  }).length;
  const easyPathRatio = total > 0 ? 1 - (architectureSensitiveChanges / total) : 0;

  return {
    diagnostic: true,
    source_paper: 'Reward Hacking in the Era of Large Models',
    coexistence_class: 'side_by_side_independent',
    gate_status: status,
    recent_decision_count: total,
    approval_rate: Number(approvalRate.toFixed(6)),
    block_rate: total > 0 ? Number((blocks / total).toFixed(6)) : 0,
    reward_hacking_suspected: suspiciouslyHighApproval,
    easy_path_ratio: Number(easyPathRatio.toFixed(6)),
    architecture_sensitive_count: architectureSensitiveChanges,
    gate_logic_unchanged: true,
    note: 'Alongside-path diagnostic. Reward-hacking detection does not modify knowledge gate logic.',
  };
}
