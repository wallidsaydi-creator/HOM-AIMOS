import test from 'node:test';
import assert from 'node:assert/strict';

import {
  advanceHageEpisode,
  createHageEpisode,
  hageEpisodeActions,
} from '../../services/retrieval/hage-native/mdp.js';
import {
  addGradientSets,
  adamStep,
  assertGroupedSplitIsolation,
  clipGradients,
  createAdamState,
  deterministicUniformSequence,
  discountedReturns,
  edgeAnchorLoss,
  emaBaselineTransition,
  globalGradientNorm,
  policyGradientLoss,
  policyLogitGradients,
  reinforceTrajectory,
  sampleCategorical,
} from '../../services/retrieval/hage-native/reinforce.js';

const hex = (value) => String(value).repeat(64).slice(0, 64);

function unit(index = 0) {
  const vector = Array(768).fill(0);
  vector[index] = 1;
  return vector;
}

function graphFixture({ includeCausalExit = true } = {}) {
  const a = hex('a');
  const b = hex('b');
  const c = hex('c');
  const edges = [
    { id: hex('1'), from: a, to: b, relation: 'temporal', initial_feature: [1, 0, 0, 0], evidence_sha256: hex('e') },
    { id: hex('2'), from: b, to: a, relation: 'semantic', initial_feature: [0, 1, 0, 0], evidence_sha256: hex('f') },
  ];
  if (includeCausalExit) {
    edges.push({ id: hex('3'), from: b, to: c, relation: 'causal', initial_feature: [0, 0, 1, 0], evidence_sha256: hex('9') });
  }
  return {
    schema_version: 1,
    source_manifest_sha256: hex('4'),
    source_commit: hex('5'),
    embedding_model_id: 'Xenova/all-mpnet-base-v2',
    embedding_model_revision: 'e086c5e0b3a57b0ce46dd6d9c0662948860b35f3',
    nodes: [
      { id: a, content_sha256: hex('6'), timestamp_unix_ms: 1, embedding: unit(0), metadata_sha256: hex('7') },
      { id: b, content_sha256: hex('8'), timestamp_unix_ms: 2, embedding: unit(1), metadata_sha256: hex('9') },
      { id: c, content_sha256: hex('0'), timestamp_unix_ms: 3, embedding: unit(2), metadata_sha256: hex('1') },
    ],
    edges,
  };
}

test('HAGE-N3 selects a deterministic cosine anchor and preserves immutable episode state', () => {
  const episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('c')],
  });
  assert.equal(episode.current_node_id, hex('a'));
  assert.deepEqual(episode.visited_node_ids, [hex('a')]);
  assert.equal(Object.isFrozen(episode), true);
  assert.equal(Object.isFrozen(episode.visited_node_ids), true);
  assert.equal(episode.done, false);
});

test('HAGE-N3 visited masking terminates cycles and reaches multi-hop evidence', () => {
  let episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('c')],
    start_node_id: hex('a'),
  });
  const first = advanceHageEpisode(episode, 0);
  assert.equal(first.reward, -0.05);
  assert.equal(first.state.current_node_id, hex('b'));
  assert.deepEqual(hageEpisodeActions(first.state).map((edge) => edge.to), [hex('c')]);
  const second = advanceHageEpisode(first.state, 0);
  assert.equal(second.reward, 9.95);
  assert.equal(second.state.success, true);
  assert.equal(second.state.termination, 'targets_satisfied');
  assert.deepEqual(second.state.visited_node_ids, [hex('a'), hex('b'), hex('c')]);
});

test('HAGE-N3 applies a terminal failure cost at an unvisited-neighbor dead end', () => {
  const episode = createHageEpisode({
    snapshot: graphFixture({ includeCausalExit: false }),
    query_embedding: unit(0),
    target_node_ids: [hex('c')],
    start_node_id: hex('a'),
  });
  const result = advanceHageEpisode(episode, 0);
  assert.equal(result.reward, -1.05);
  assert.equal(result.terminal_failure, true);
  assert.equal(result.state.done, true);
  assert.equal(result.state.termination, 'dead_end');
});

test('HAGE-N3 handles spawn-on-target without fabricating an action', () => {
  const episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('a')],
  });
  assert.equal(episode.done, true);
  assert.equal(episode.success, true);
  assert.equal(episode.steps, 0);
  assert.deepEqual(hageEpisodeActions(episode), []);
  assert.throws(() => advanceHageEpisode(episode, 0), /episode_done/);
});

test('HAGE-N3 accumulates unique multi-target evidence across the bounded path', () => {
  let episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('a'), hex('c')],
    start_node_id: hex('a'),
  });
  assert.deepEqual(episode.found_node_ids, [hex('a')]);
  episode = advanceHageEpisode(episode, 0).state;
  const final = advanceHageEpisode(episode, 0);
  assert.deepEqual(final.state.found_node_ids, [hex('a'), hex('c')]);
  assert.equal(final.state.success, true);
});

test('HAGE-N3 applies timeout independently of dead-end termination', () => {
  const episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('c')],
    start_node_id: hex('a'),
    max_hops: 1,
  });
  const result = advanceHageEpisode(episode, 0);
  assert.equal(result.state.termination, 'hop_budget_exhausted');
  assert.equal(result.reward, -1.05);
  assert.equal(result.state.success, false);
});

test('HAGE-N3 discounted returns match the hand-computed Equation (12) oracle', () => {
  const returns = discountedReturns([-0.05, -0.05, 9.95], 0.99);
  const expected = [9.652495, 9.8005, 9.95];
  assert.equal(returns.every((value, index) => Math.abs(value - expected[index]) < 1e-12), true);
  assert.deepEqual(discountedReturns([], 0.99), []);
});

test('HAGE-N3 uses the pre-trajectory baseline and updates EMA afterward', () => {
  const trajectory = reinforceTrajectory({
    rewards: [-0.05, 9.95],
    log_probabilities: [Math.log(0.5), Math.log(0.8)],
    baseline_before: 2,
    gamma: 0.99,
    baseline_decay: 0.99,
  });
  assert.equal(trajectory.baseline_before, 2);
  assert.deepEqual(trajectory.advantages, trajectory.returns.map((value) => value - 2));
  const expectedObservation = trajectory.returns.reduce((sum, value) => sum + value, 0) / 2;
  assert.equal(Math.abs(trajectory.baseline_after - ((0.99 * 2) + (0.01 * expectedObservation))) < 1e-12, true);
  assert.equal(Number.isFinite(trajectory.policy_loss), true);
});

test('HAGE-N3 policy gradients are zero-sum across action logits', () => {
  const gradients = policyLogitGradients({ probabilities: [0.25, 0.75], action_index: 1, advantage: 2 });
  assert.deepEqual(gradients, [0.5, -0.5]);
  assert.equal(gradients.reduce((sum, value) => sum + value, 0), 0);
  const loss = policyGradientLoss({ log_probabilities: [Math.log(0.75)], returns: [4], baseline_before: 1 });
  assert.equal(Math.abs(loss.loss - (-Math.log(0.75) * 3)) < 1e-12, true);
});

test('HAGE-N3 anchor loss is summed squared L2, not reference-code MSE', () => {
  const anchor = edgeAnchorLoss({
    current_features: [[1, 0, 0, 0]],
    initial_features: [[0, 1, 0, 0]],
    lambda: 1,
  });
  assert.equal(anchor.loss, 2);
  assert.deepEqual(anchor.gradients, [[2, -2, 0, 0]]);
});

test('HAGE-N3 clips the global gradient norm without changing direction', () => {
  const gradients = { a: [3, 4], b: [0] };
  assert.equal(globalGradientNorm(gradients), 5);
  const clipped = clipGradients(gradients, 1);
  assert.equal(clipped.norm_before, 5);
  assert.equal(clipped.norm_after, 1);
  assert.deepEqual(clipped.gradients.a, [0.6000000000000001, 0.8]);
});

test('HAGE-N3 Adam performs the independently calculable first update', () => {
  const parameters = { weight: [1, -1] };
  const state = createAdamState(parameters);
  const result = adamStep({
    parameters,
    gradients: { weight: [2, -2] },
    state,
    learning_rate: 0.1,
  });
  const expectedDelta = 0.1 * 2 / (Math.sqrt(4) + 1e-8);
  assert.equal(Math.abs(result.parameters.weight[0] - (1 - expectedDelta)) < 1e-12, true);
  assert.equal(Math.abs(result.parameters.weight[1] - (-1 + expectedDelta)) < 1e-12, true);
  assert.equal(result.state.step, 1);
});

test('HAGE-N3 categorical sampling requires an explicit deterministic uniform variate', () => {
  assert.equal(sampleCategorical([0.2, 0.3, 0.5], 0), 0);
  assert.equal(sampleCategorical([0.2, 0.3, 0.5], 0.2), 1);
  assert.equal(sampleCategorical([0.2, 0.3, 0.5], 0.999), 2);
  assert.throws(() => sampleCategorical([0.2, 0.2], 0.1), /probabilities_sum/);
});

test('HAGE-N3 deterministic replay is identical for an explicit seed', () => {
  const first = deterministicUniformSequence(20260805, 8);
  const second = deterministicUniformSequence(20260805, 8);
  const third = deterministicUniformSequence(20260806, 8);
  assert.deepEqual(first, second);
  assert.notDeepEqual(first, third);
  assert.deepEqual(first.map((value) => sampleCategorical([0.25, 0.75], value)),
    second.map((value) => sampleCategorical([0.25, 0.75], value)));
  assert.throws(() => deterministicUniformSequence(0, 1), /seed_range/);
});

test('HAGE-N3 grouped split gate prevents session leakage across all partitions', () => {
  const isolated = assertGroupedSplitIsolation({
    train_group_ids: ['session-c', 'session-a'],
    validation_group_ids: ['session-b'],
    test_group_ids: ['session-z'],
  });
  assert.deepEqual(isolated.train_group_ids, ['session-a', 'session-c']);
  assert.equal(isolated.total_group_count, 4);
  assert.throws(() => assertGroupedSplitIsolation({
    train_group_ids: ['session-a'],
    validation_group_ids: ['session-a'],
    test_group_ids: ['session-z'],
  }), /split_overlap_train_validation/);
});

test('HAGE-N3 combines policy and anchor gradient sets shape-safely', () => {
  assert.deepEqual(addGradientSets({ W: [1, 2], b: [3] }, { W: [4, 5], b: [6] }), {
    W: [5, 7],
    b: [9],
  });
  assert.throws(() => addGradientSets({ W: [1] }, { b: [1] }), /gradient_names_mismatch/);
});

test('HAGE-N3 rejects missing targets, invalid actions, and unsafe numerical input', () => {
  assert.throws(() => createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('f')],
  }), /target_node_missing/);
  const episode = createHageEpisode({
    snapshot: graphFixture(),
    query_embedding: unit(0),
    target_node_ids: [hex('c')],
  });
  assert.throws(() => advanceHageEpisode(episode, 4), /action_index_range/);
  assert.throws(() => advanceHageEpisode({ ...episode, steps: -1 }, 0), /state_not_native/);
  assert.throws(() => emaBaselineTransition({ baseline_before: 0, returns: [Number.NaN] }), /returns_non_finite/);
  assert.throws(() => edgeAnchorLoss({ current_features: [[0, 0, 0]], initial_features: [[0, 0, 0]] }), /current_features_dimension/);
});
