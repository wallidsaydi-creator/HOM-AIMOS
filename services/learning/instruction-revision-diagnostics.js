// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: meta-improvement.js, tests
// Pipeline: GOVERNANCE
// Position: proposal-only instruction revision diagnostics
// Batch8 Wave4 sources: Automated Instruction Revision, Reflection-Enhanced
// Meta-Optimization, Readable Minds. Proposals are auditable drafts only.
// ─────────────────────────────────────────────────────────────────────────────

function normalizeString(value) {
  return String(value || '').trim();
}

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function uniqueStrings(values = []) {
  return Array.from(new Set((Array.isArray(values) ? values : []).map((value) => normalizeString(value)).filter(Boolean)));
}

export function buildInstructionRevisionProposalArtifact({
  objective = '',
  affectedInstructionPaths = [],
  rationale = '',
  evidence = {},
  proposedRevision = '',
  createdBy,
} = {}) {
  const affectedPaths = uniqueStrings(affectedInstructionPaths);
  const createdByNormalized = normalizeString(createdBy);
  if (!createdByNormalized) throw new Error('buildInstructionRevisionProposalArtifact: createdBy is required (no default)');
  return {
    source_papers: [
      'Automated Instruction Revision',
      'Reflection-Enhanced Meta-Optimization',
      'Readable Minds'
    ],
    artifactKind: 'instruction_revision_proposal',
    status: 'draft',
    proposalOnly: true,
    objective: normalizeString(objective),
    affectedPaths,
    operations: [],
    rationale: normalizeString(rationale),
    evidence: isPlainObject(evidence) ? evidence : { note: normalizeString(evidence) },
    proposedRevision: normalizeString(proposedRevision),
    createdBy: createdByNormalized,
    diagnostic_only: true,
    mutation_applied: false,
    auto_activation_enabled: false,
    guarded_control: {
      silent_prompt_mutation_enabled: false,
      automatic_rule_induction_deployment: false,
      self_modifying_prompt_deployment: false
    }
  };
}
