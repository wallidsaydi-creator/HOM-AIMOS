import test from 'node:test';
import assert from 'node:assert/strict';

import { proveCr7R7AggregateAudit } from '../../scripts/verification/prove-cr7-r7-aggregate-audit.mjs';

test('R7 independently aggregates R0-R6 without erasing historical roots', () => {
  const proof = proveCr7R7AggregateAudit();
  assert.equal(proof.aggregate_static_verdict, 'PASSED');
  assert.equal(proof.current_effect_count, 104);
  assert.equal(proof.current_open_effect_count, 0);
  assert.equal(proof.recovery_family_count, 6);
  assert.equal(Object.keys(proof.historical_roots_preserved).length, 9);
  assert.equal(Object.keys(proof.current_roots).length, 9);
  assert.match(proof.aggregate_audit_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.preclosure_proof_root_sha256, /^[0-9a-f]{64}$/);
});

test('R7 transfers the inadmissible disposable proof to CR11 without representing it as passed', () => {
  const proof = proveCr7R7AggregateAudit();
  assert.equal(proof.isolated_database.required_in_r7, false);
  assert.equal(proof.isolated_database.required_global, true);
  assert.equal(proof.isolated_database.executed, false);
  assert.equal(proof.isolated_database.transferred_to, 'CR11');
  assert.equal(proof.isolated_database.current_runner_admissible, false);
  assert.equal(proof.fresh_disposable_brain_created, false);
  assert.equal(proof.live_database_mutated, false);
  assert.equal(proof.cr7_closed, true);
  assert.equal(proof.ready_for_cr7_closure, true);
  assert.deepEqual(proof.blocking_conditions, []);
  assert.deepEqual(proof.transferred_global_conditions, [
    'admissible_isolated_zero_memory_database_not_executed',
    'controlled_isolated_process_restart_not_executed',
    'signed_cleanup_and_global_residue_census_not_executed',
  ]);
});

test('R7 changes no reviewed mathematical formula', () => {
  const proof = proveCr7R7AggregateAudit();
  assert.equal(proof.paper_authority.formulas_changed, false);
  assert.equal(proof.paper_authority.consultation_required, false);
  for (const value of [
    proof.paper_authority.inhibitory_error_normalization_sha256,
    proof.paper_authority.kahneman_reference_point_sha256,
    proof.paper_authority.tbsp_sha256,
  ]) assert.match(value, /^[0-9a-f]{64}$/);
});
