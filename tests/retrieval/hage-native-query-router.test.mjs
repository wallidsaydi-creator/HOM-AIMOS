import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  HAGE_QUERY_ROUTER_PARAMETER_COUNT,
  HAGE_QUERY_ROUTER_SHAPES,
  createQueryRouterParameters,
  hageTransitionPolicy,
  initializeQueryRouterParameters,
  queryRouterForward,
  queryRouterForwardBackward,
  stableSoftmax,
  stableSoftplus,
} from '../../services/retrieval/hage-native/query-router.js';

const parityFixture = JSON.parse(readFileSync(
  new URL('../fixtures/hage-native-query-router-parity-v1.json', import.meta.url),
  'utf8',
));

function unit(index = 0) {
  const vector = Array(768).fill(0);
  vector[index] = 1;
  return vector;
}

function zeroParameters() {
  return {
    W1: Array(128 * 778).fill(0),
    b1: Array(128).fill(0),
    W2: Array(64 * 128).fill(0),
    b2: Array(64).fill(0),
    W3: Array(64).fill(0),
    b3: [0],
  };
}

function sparseParityParameters() {
  const parameters = zeroParameters();
  parameters.W1[0] = 0.5;
  parameters.b1[0] = 0.1;
  parameters.W2[0] = 2;
  parameters.b2[0] = 0.2;
  parameters.W3[0] = 1.5;
  parameters.b3[0] = -0.1;
  return parameters;
}

function fixtureInput() {
  return {
    query_embedding: unit(0),
    edge_feature: [1, 0, 0, 0],
    relation_intent: [0, 1, 0, 0],
    source_embedding: unit(0),
    target_embedding: unit(1),
  };
}

function perturb(parameters, name, index, delta) {
  const copy = Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, [...value]]));
  copy[name][index] += delta;
  return copy;
}

test('HAGE-N2 fixes the native QueryRouter dimensions and exact parameter count', () => {
  assert.deepEqual(HAGE_QUERY_ROUTER_SHAPES, { input: 778, hidden_1: 128, hidden_2: 64, output: 1 });
  const parameters = createQueryRouterParameters(zeroParameters());
  const count = Object.values(parameters).reduce((sum, values) => sum + values.length, 0);
  assert.equal(count, HAGE_QUERY_ROUTER_PARAMETER_COUNT);
  assert.equal(count, 108_033);
  assert.equal(Object.isFrozen(parameters.W1), true);
});

test('HAGE-N2 deterministic Xavier initialization is seed-bound', () => {
  const first = initializeQueryRouterParameters(42);
  const second = initializeQueryRouterParameters(42);
  const third = initializeQueryRouterParameters(43);
  assert.deepEqual(first, second);
  assert.notDeepEqual(first.W1.slice(0, 16), third.W1.slice(0, 16));
  assert.throws(() => initializeQueryRouterParameters(0), /seed_range/);
});

test('HAGE-N2 stable primitives remain finite at extreme logits', () => {
  assert.equal(Number.isFinite(stableSoftplus(1_000)), true);
  assert.equal(Number.isFinite(stableSoftplus(-1_000)), true);
  assert.equal(Math.abs(stableSoftplus(2) - Math.log1p(Math.exp(2))) < 1e-12, true);
  const probabilities = stableSoftmax([0, Math.log(2)]);
  assert.equal(Math.abs(probabilities[0] - (1 / 3)) < 1e-12, true);
  assert.equal(Math.abs(probabilities[1] - (2 / 3)) < 1e-12, true);
  assert.throws(() => stableSoftmax([]), /softmax_empty/);
});

test('HAGE-N2 forward pass matches the independent sparse parity oracle', () => {
  const result = queryRouterForward(sparseParityParameters(), fixtureInput());
  const expected = parityFixture.expected.structural_weight;
  assert.equal(Math.abs(result.structural_weight - expected) < 1e-12, true);
  assert.equal(result.source_similarity, 1);
  assert.equal(result.target_similarity, 0);
  assert.equal(result.structural_weight > 0, true);
  const gradients = queryRouterForwardBackward(sparseParityParameters(), fixtureInput()).parameter_gradients;
  for (const [name, index, fixtureKey] of [
    ['W1', 0, 'W1_0'],
    ['b1', 0, 'b1_0'],
    ['W2', 0, 'W2_0'],
    ['b2', 0, 'b2_0'],
    ['W3', 0, 'W3_0'],
    ['b3', 0, 'b3_0'],
  ]) {
    assert.equal(Math.abs(gradients[name][index] - parityFixture.expected.gradients[fixtureKey]) < 1e-12, true);
  }
});

test('HAGE-N2 analytical gradients match centered finite differences for every tensor', () => {
  const raw = sparseParityParameters();
  const analytic = queryRouterForwardBackward(raw, fixtureInput());
  const epsilon = 1e-5;
  const probes = [
    ['W1', 0],
    ['b1', 0],
    ['W2', 0],
    ['b2', 0],
    ['W3', 0],
    ['b3', 0],
  ];
  for (const [name, index] of probes) {
    const plus = queryRouterForward(perturb(raw, name, index, epsilon), fixtureInput()).structural_weight;
    const minus = queryRouterForward(perturb(raw, name, index, -epsilon), fixtureInput()).structural_weight;
    const numeric = (plus - minus) / (2 * epsilon);
    const observed = analytic.parameter_gradients[name][index];
    assert.equal(Math.abs(numeric - observed) < 1e-7, true, `${name}[${index}] ${numeric} != ${observed}`);
  }
});

test('HAGE-N2 transition policy implements Equations (9) and (10)', () => {
  const result = hageTransitionPolicy({
    query_embedding: unit(0),
    target_embeddings: [unit(0), unit(1)],
    structural_weights: [0.2, 1.4],
    lambda: 0.5,
  });
  assert.deepEqual(result.similarities, [1, 0]);
  assert.deepEqual(result.logits, [0.6, 0.7]);
  assert.equal(Math.abs(result.probabilities.reduce((sum, value) => sum + value, 0) - 1) < 1e-12, true);
  assert.equal(result.probabilities[1] > result.probabilities[0], true);
});

test('HAGE-N2 rejects malformed tensors, non-unit embeddings, and unsafe mixtures', () => {
  const badInput = fixtureInput();
  badInput.query_embedding = Array(768).fill(0);
  assert.throws(() => queryRouterForward(zeroParameters(), badInput), /query_embedding_unit_norm/);
  assert.throws(() => createQueryRouterParameters({}), /W1_not_vector/);
  const coerced = zeroParameters();
  coerced.W1[0] = '0';
  assert.throws(() => createQueryRouterParameters(coerced), /W1_non_finite/);
  assert.throws(() => hageTransitionPolicy({
    query_embedding: unit(0),
    target_embeddings: [unit(1)],
    structural_weights: [1],
    lambda: 1.1,
  }), /lambda_range/);
  assert.throws(() => hageTransitionPolicy({
    query_embedding: unit(0),
    target_embeddings: [unit(1)],
    structural_weights: [0],
  }), /structural_weight_non_positive/);
});
