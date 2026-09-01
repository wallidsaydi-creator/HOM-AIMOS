import test from 'node:test';
import assert from 'node:assert/strict';
import {
  summarizeCertifiedTrajectory,
  controlCertifiedTrajectoryProposal,
  NEUROPLASTICITY_GUARDRAILS,
} from '../../services/learning/neuroplasticity-stability-control.js';

const HASH_A = '11'.repeat(32);
const HASH_B = '22'.repeat(32);

test('certified neuroplasticity controller starts from a verified empty chain', () => {
  const trajectory = summarizeCertifiedTrajectory([], {
    currentWeight: 1,
    expectedChainLength: 0,
  });
  assert.equal(trajectory.head_projection_hash, '0'.repeat(64));
  assert.equal(trajectory.total_log_variation_ppm, 0);
  const control = controlCertifiedTrajectoryProposal({
    memoryId: '11111111-1111-4111-8111-111111111111',
    currentWeight: 1,
    proposedWeight: 1.3,
    trajectory,
    mutationOwner: 'SPICED_CONSOLIDATION',
  });
  assert.equal(control.controlled_weight, 1.3);
  assert.equal(control.changed_by_controller, false);
  assert.match(control.decision_sha256, /^[0-9a-f]{64}$/);
});

test('real reversal history contracts but never zeros the next trust region', () => {
  const trajectory = summarizeCertifiedTrajectory([
    { old_weight_milli: 1000, new_weight_milli: 1300, projection_hash: HASH_A },
    { old_weight_milli: 1300, new_weight_milli: 1000, projection_hash: HASH_B },
  ], { currentWeight: 1, expectedChainLength: 2 });
  assert.equal(trajectory.reversal_count, 1);
  assert.ok(trajectory.total_log_variation_ppm > 0);
  const control = controlCertifiedTrajectoryProposal({
    memoryId: '11111111-1111-4111-8111-111111111111',
    currentWeight: 1,
    proposedWeight: 1.3,
    trajectory,
    mutationOwner: 'HEBBIAN_CONSENSUS',
  });
  assert.ok(control.controlled_weight > 1);
  assert.ok(control.controlled_weight < 1.3);
  assert.equal(control.changed_by_controller, true);
  assert.equal(control.decision.trajectory_head_projection_hash, HASH_B);
  assert.equal(control.decision.canonical_content, 'immutable');
  assert.equal(control.decision.memory_existence, 'immutable');
  assert.equal(control.decision.controlled_state, 'retrieval_weight_only');
});

test('trajectory discontinuity and terminal mismatch fail closed', () => {
  assert.throws(() => summarizeCertifiedTrajectory([
    { old_weight_milli: 1000, new_weight_milli: 1200, projection_hash: HASH_A },
    { old_weight_milli: 1100, new_weight_milli: 900, projection_hash: HASH_B },
  ], { currentWeight: 0.9, expectedChainLength: 2 }), /continuity_invalid/);
  assert.throws(() => summarizeCertifiedTrajectory([
    { old_weight_milli: 1000, new_weight_milli: 1200, projection_hash: HASH_A },
  ], { currentWeight: 1, expectedChainLength: 1 }), /terminal_mismatch/);
});

test('mutation control surface contains no destructive capability', () => {
  assert.deepEqual(NEUROPLASTICITY_GUARDRAILS, {
    canonical_content: 'immutable',
    memory_existence: 'immutable',
    controlled_state: 'retrieval_weight_only',
    direct_database_write: false,
    input_requires_verified_cognitive_trajectory: true,
  });
});
