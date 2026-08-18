/** Independent read-only R6 verifier. No runtime, database, or signer imports. */
import { createHash } from 'node:crypto';

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('r6_verifier_non_finite_number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('r6_verifier_non_canonical_type');
}

function hash(value) {
  return createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

function without(object, key) {
  return Object.fromEntries(Object.entries(object || {}).filter(([name]) => name !== key));
}

function assert(condition, reason) {
  if (!condition) throw new Error(`content_state_r6_verifier:${reason}`);
}

export function verifyR6EvidenceScopeDecision(decision, { projection = null } = {}) {
  assert(decision?.schema === 'hom-aimos/request-epistemic-evidence-scope/v1', 'scope_schema_invalid');
  assert(hash(without(decision, 'decision_sha256')) === decision.decision_sha256, 'scope_decision_hash_invalid');
  assert(hash(decision.records || []) === decision.records_root_sha256,
    'scope_records_root_invalid');
  assert(hash(decision.blocked_records || []) === decision.retained_blocked_decision_set_sha256,
    'scope_blocked_root_invalid');
  const records = Array.isArray(decision.blocked_records) ? decision.blocked_records : [];
  assert(new Set(records.map((record) => record.memory_id)).size === records.length,
    'scope_blocked_identity_duplicate');
  assert(records.every((record) => record.projection_rank_eligible === false),
    'scope_blocked_record_eligible');
  const evidenceRoots = [...new Set((decision.records || [])
    .map((record) => record.evidence_root_sha256)
    .filter(Boolean))].sort();
  assert((decision.evidence_root_sha256s || []).every((root) => /^[0-9a-f]{64}$/.test(root)),
    'scope_evidence_root_invalid');
  assert(canonical(evidenceRoots) === canonical(decision.evidence_root_sha256s || []),
    'scope_evidence_root_mismatch');
  assert(decision.no_exoneration === true && decision.label_history_changed === false,
    'scope_non_exoneration_invalid');

  if (projection) {
    assert(decision.content_state_projection_decision_sha256 === projection.decision.decision_sha256,
      'scope_projection_decision_mismatch');
    assert(decision.state_view_root_sha256 === projection.decision.state_view_root_sha256,
      'scope_state_root_mismatch');
    assert(decision.occurrence_view_root_sha256 === projection.decision.occurrence_view_root_sha256,
      'scope_occurrence_root_mismatch');
    const blockedIds = projection.occurrence_view
      .filter((occurrence) => occurrence.rank_eligible !== true)
      .map((occurrence) => occurrence.memory_id)
      .sort();
    assert(canonical(blockedIds) === canonical(records.map((record) => record.memory_id).sort()),
      'scope_blocked_membership_mismatch');
  }
  return Object.freeze({ valid: true, decision_sha256: decision.decision_sha256 });
}

export function verifyR6SecurityComposition({
  evidenceScopeDecision,
  cleanSelectionDecision,
  epistemicDecision,
  finalClosureDecision,
  projection = null,
} = {}) {
  verifyR6EvidenceScopeDecision(evidenceScopeDecision, { projection });
  assert(cleanSelectionDecision?.schema === 'hom-aimos/canary-clean-selection/v2-epistemic-withholding',
    'clean_selection_schema_invalid');
  assert(cleanSelectionDecision.selected_top_k_subseteq_clean_eligible_evidence === true,
    'clean_selection_subset_invalid');
  assert(cleanSelectionDecision.retained_evidence_canonical_state_unchanged === true,
    'clean_selection_retention_invalid');
  assert(new Set(cleanSelectionDecision.selected_clean_memory_ids || []).size
    === (cleanSelectionDecision.selected_clean_memory_ids || []).length,
  'clean_selection_duplicate');
  assert(finalClosureDecision?.schema === 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
    'closure_schema_invalid');
  assert(hash(without(finalClosureDecision, 'decision_sha256'))
    === finalClosureDecision.decision_sha256, 'closure_decision_hash_invalid');
  assert(finalClosureDecision.content_state_evidence_scope_decision_sha256
    === evidenceScopeDecision.decision_sha256, 'closure_scope_binding_invalid');
  assert(finalClosureDecision.authorized_class_commitment_sha256
    === evidenceScopeDecision.authorized_class_commitment_sha256,
  'closure_class_commitment_invalid');
  assert(finalClosureDecision.retained_blocked_decision_set_sha256
    === evidenceScopeDecision.retained_blocked_decision_set_sha256,
  'closure_blocked_set_invalid');
  assert(finalClosureDecision.clean_selection_decision_sha256
    === cleanSelectionDecision.decision_sha256, 'closure_clean_selection_invalid');
  assert(finalClosureDecision.epistemic_decision_sha256
    === epistemicDecision.decision_sha256, 'closure_epistemic_invalid');
  assert(finalClosureDecision.no_epistemic_exoneration === true,
    'closure_non_exoneration_invalid');
  assert(finalClosureDecision.canonical_memory_mutated === false
    && finalClosureDecision.retention_changed === false,
  'closure_retention_invalid');
  return Object.freeze({
    valid: true,
    evidence_scope_decision_sha256: evidenceScopeDecision.decision_sha256,
    clean_selection_decision_sha256: cleanSelectionDecision.decision_sha256,
    final_closure_decision_sha256: finalClosureDecision.decision_sha256,
  });
}
