/**
 * reinforce.js — Pure HAGE REINFORCE and optimizer mathematics.
 *
 * Paper authority: HAGE.pdf, Equations (12)–(15).
 * Baseline subtraction uses the pre-trajectory baseline. The EMA update occurs
 * only after the trajectory loss has been formed.
 */

export const HAGE_REINFORCE_DEFAULTS = Object.freeze({
  gamma: 0.99,
  baseline_decay: 0.99,
  anchor_lambda: 1,
  gradient_clip_norm: 1,
  adam_beta_1: 0.9,
  adam_beta_2: 0.999,
  adam_epsilon: 1e-8,
});

function fail(code) {
  throw new Error(`hage_reinforce:${code}`);
}

function finiteNumber(value, code) {
  if (typeof value !== 'number' || !Number.isFinite(value)) fail(code);
  return Object.is(value, -0) ? 0 : value;
}

function finiteVector(value, code, { nonempty = false } = {}) {
  if (!Array.isArray(value) && !ArrayBuffer.isView(value)) fail(`${code}_not_vector`);
  if (nonempty && value.length === 0) fail(`${code}_empty`);
  return [...value].map((entry) => finiteNumber(entry, `${code}_non_finite`));
}

function probabilityVector(value, code) {
  const probabilities = finiteVector(value, code, { nonempty: true });
  if (probabilities.some((probability) => probability < 0 || probability > 1)) fail(`${code}_range`);
  const sum = probabilities.reduce((total, probability) => total + probability, 0);
  if (Math.abs(sum - 1) > 1e-9) fail(`${code}_sum`);
  return probabilities;
}

function unitInterval(value, code, { upperInclusive = true } = {}) {
  const number = finiteNumber(value, code);
  if (number < 0 || (upperInclusive ? number > 1 : number >= 1)) fail(`${code}_range`);
  return number;
}

function freezeVector(values) {
  return Object.freeze([...values]);
}

export function discountedReturns(rewards, gamma = HAGE_REINFORCE_DEFAULTS.gamma) {
  const values = finiteVector(rewards, 'rewards');
  const discount = unitInterval(gamma, 'gamma');
  const returns = Array(values.length).fill(0);
  let running = 0;
  for (let index = values.length - 1; index >= 0; index -= 1) {
    running = values[index] + (discount * running);
    if (!Number.isFinite(running)) fail('return_non_finite');
    returns[index] = running;
  }
  return freezeVector(returns);
}

export function emaBaselineTransition({
  baseline_before: baselineBefore,
  returns,
  decay = HAGE_REINFORCE_DEFAULTS.baseline_decay,
} = {}) {
  const before = finiteNumber(baselineBefore, 'baseline_before');
  const values = finiteVector(returns, 'returns');
  const beta = unitInterval(decay, 'baseline_decay', { upperInclusive: false });
  const observation = values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : before;
  const after = (beta * before) + ((1 - beta) * observation);
  if (!Number.isFinite(after)) fail('baseline_after_non_finite');
  return Object.freeze({ baseline_before: before, observation, baseline_after: after });
}

export function policyGradientLoss({ log_probabilities: logProbabilities, returns, baseline_before: baseline } = {}) {
  const logs = finiteVector(logProbabilities, 'log_probabilities');
  const values = finiteVector(returns, 'returns');
  const before = finiteNumber(baseline, 'baseline_before');
  if (logs.length !== values.length) fail('trajectory_length_mismatch');
  let loss = 0;
  const advantages = new Array(values.length);
  for (let index = 0; index < values.length; index += 1) {
    const advantage = values[index] - before;
    advantages[index] = advantage;
    loss += -logs[index] * advantage;
  }
  if (!Number.isFinite(loss)) fail('policy_loss_non_finite');
  return Object.freeze({ loss, advantages: freezeVector(advantages) });
}

export function policyLogitGradients({ probabilities, action_index: actionIndex, advantage } = {}) {
  const probs = probabilityVector(probabilities, 'probabilities');
  if (!Number.isSafeInteger(actionIndex) || actionIndex < 0 || actionIndex >= probs.length) {
    fail('action_index_range');
  }
  const scale = finiteNumber(advantage, 'advantage');
  return freezeVector(probs.map((probability, index) => (
    scale * (probability - (index === actionIndex ? 1 : 0))
  )));
}

export function reinforceTrajectory({
  rewards,
  log_probabilities: logProbabilities,
  baseline_before: baselineBefore,
  gamma = HAGE_REINFORCE_DEFAULTS.gamma,
  baseline_decay: baselineDecay = HAGE_REINFORCE_DEFAULTS.baseline_decay,
} = {}) {
  const returns = discountedReturns(rewards, gamma);
  const policy = policyGradientLoss({
    log_probabilities: logProbabilities,
    returns,
    baseline_before: baselineBefore,
  });
  const baseline = emaBaselineTransition({
    baseline_before: baselineBefore,
    returns,
    decay: baselineDecay,
  });
  return Object.freeze({
    returns,
    advantages: policy.advantages,
    policy_loss: policy.loss,
    baseline_before: baseline.baseline_before,
    baseline_observation: baseline.observation,
    baseline_after: baseline.baseline_after,
  });
}

function featureMatrix(value, code) {
  if (!Array.isArray(value)) fail(`${code}_not_matrix`);
  return value.map((row) => {
    const vector = finiteVector(row, code);
    if (vector.length !== 4) fail(`${code}_dimension`);
    return vector;
  });
}

export function edgeAnchorLoss({
  current_features: current,
  initial_features: initial,
  lambda = HAGE_REINFORCE_DEFAULTS.anchor_lambda,
} = {}) {
  const currentRows = featureMatrix(current, 'current_features');
  const initialRows = featureMatrix(initial, 'initial_features');
  const weight = finiteNumber(lambda, 'anchor_lambda');
  if (weight < 0) fail('anchor_lambda_range');
  if (currentRows.length !== initialRows.length) fail('anchor_row_count');
  let loss = 0;
  const gradients = currentRows.map((row, rowIndex) => row.map((value, columnIndex) => {
    const difference = value - initialRows[rowIndex][columnIndex];
    loss += weight * difference * difference;
    return 2 * weight * difference;
  }));
  if (!Number.isFinite(loss)) fail('anchor_loss_non_finite');
  return Object.freeze({
    loss,
    gradients: Object.freeze(gradients.map(freezeVector)),
  });
}

function gradientObject(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${code}_not_object`);
  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) fail(`${code}_empty`);
  return Object.fromEntries(entries.map(([name, vector]) => [name, finiteVector(vector, `${code}_${name}`)]));
}

export function globalGradientNorm(gradients) {
  const rows = gradientObject(gradients, 'gradients');
  let sum = 0;
  for (const vector of Object.values(rows)) {
    for (const value of vector) sum += value * value;
  }
  const norm = Math.sqrt(sum);
  if (!Number.isFinite(norm)) fail('gradient_norm_non_finite');
  return norm;
}

export function clipGradients(gradients, maxNorm = HAGE_REINFORCE_DEFAULTS.gradient_clip_norm) {
  const rows = gradientObject(gradients, 'gradients');
  const maximum = finiteNumber(maxNorm, 'gradient_clip_norm');
  if (maximum <= 0) fail('gradient_clip_norm_range');
  const observedNorm = globalGradientNorm(rows);
  const scale = observedNorm > maximum ? maximum / observedNorm : 1;
  const clipped = Object.fromEntries(Object.entries(rows).map(([name, vector]) => [
    name,
    freezeVector(vector.map((value) => value * scale)),
  ]));
  return Object.freeze({
    gradients: Object.freeze(clipped),
    norm_before: observedNorm,
    norm_after: observedNorm * scale,
    scale,
  });
}

export function createAdamState(parameters) {
  const values = gradientObject(parameters, 'parameters');
  const zeros = (vector) => freezeVector(Array(vector.length).fill(0));
  return Object.freeze({
    step: 0,
    first_moment: Object.freeze(Object.fromEntries(Object.entries(values).map(([name, vector]) => [name, zeros(vector)]))),
    second_moment: Object.freeze(Object.fromEntries(Object.entries(values).map(([name, vector]) => [name, zeros(vector)]))),
  });
}

export function adamStep({
  parameters,
  gradients,
  state,
  learning_rate: learningRate,
  beta_1: beta1 = HAGE_REINFORCE_DEFAULTS.adam_beta_1,
  beta_2: beta2 = HAGE_REINFORCE_DEFAULTS.adam_beta_2,
  epsilon = HAGE_REINFORCE_DEFAULTS.adam_epsilon,
} = {}) {
  const values = gradientObject(parameters, 'parameters');
  const grads = gradientObject(gradients, 'gradients');
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('adam_state_not_object');
  if (!Number.isSafeInteger(state.step) || state.step < 0) fail('adam_state_step');
  const first = gradientObject(state.first_moment, 'adam_first_moment');
  const second = gradientObject(state.second_moment, 'adam_second_moment');
  const names = Object.keys(values);
  if (JSON.stringify(names) !== JSON.stringify(Object.keys(grads))
    || JSON.stringify(names) !== JSON.stringify(Object.keys(first))
    || JSON.stringify(names) !== JSON.stringify(Object.keys(second))) fail('adam_parameter_names');
  const lr = finiteNumber(learningRate, 'learning_rate');
  const b1 = unitInterval(beta1, 'adam_beta_1', { upperInclusive: false });
  const b2 = unitInterval(beta2, 'adam_beta_2', { upperInclusive: false });
  const eps = finiteNumber(epsilon, 'adam_epsilon');
  if (lr <= 0 || eps <= 0) fail('adam_positive_constants');
  const step = state.step + 1;
  const nextParameters = {};
  const nextFirst = {};
  const nextSecond = {};
  for (const name of names) {
    if (values[name].length !== grads[name].length
      || values[name].length !== first[name].length
      || values[name].length !== second[name].length) fail('adam_shape_mismatch');
    const parameterRow = new Array(values[name].length);
    const firstRow = new Array(values[name].length);
    const secondRow = new Array(values[name].length);
    for (let index = 0; index < values[name].length; index += 1) {
      const m = (b1 * first[name][index]) + ((1 - b1) * grads[name][index]);
      const v = (b2 * second[name][index]) + ((1 - b2) * grads[name][index] * grads[name][index]);
      const mHat = m / (1 - (b1 ** step));
      const vHat = v / (1 - (b2 ** step));
      const parameter = values[name][index] - (lr * mHat / (Math.sqrt(vHat) + eps));
      if (![m, v, parameter].every(Number.isFinite)) fail('adam_non_finite');
      firstRow[index] = m;
      secondRow[index] = v;
      parameterRow[index] = parameter;
    }
    nextParameters[name] = freezeVector(parameterRow);
    nextFirst[name] = freezeVector(firstRow);
    nextSecond[name] = freezeVector(secondRow);
  }
  return Object.freeze({
    parameters: Object.freeze(nextParameters),
    state: Object.freeze({
      step,
      first_moment: Object.freeze(nextFirst),
      second_moment: Object.freeze(nextSecond),
    }),
  });
}

export function sampleCategorical(probabilities, uniform) {
  const probs = probabilityVector(probabilities, 'probabilities');
  const sample = unitInterval(uniform, 'uniform', { upperInclusive: false });
  let cumulative = 0;
  for (let index = 0; index < probs.length; index += 1) {
    cumulative += probs[index];
    if (sample < cumulative || index === probs.length - 1) return index;
  }
  fail('categorical_unreachable');
}

export function deterministicUniformSequence(seed, length) {
  if (!Number.isSafeInteger(seed) || seed <= 0 || seed > 0xffffffff) fail('seed_range');
  if (!Number.isSafeInteger(length) || length < 0 || length > 1_000_000) fail('sequence_length_range');
  let state = seed >>> 0;
  const values = new Array(length);
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    values[index] = (state >>> 0) / 0x1_0000_0000;
  }
  return freezeVector(values);
}

function splitGroups(value, code) {
  if (!Array.isArray(value) || value.length === 0) fail(`${code}_empty`);
  const groups = value.map((entry) => {
    if (typeof entry !== 'string') fail(`${code}_group_type`);
    const normalized = entry.trim();
    if (!normalized || normalized.length > 256) fail(`${code}_group_value`);
    return normalized;
  });
  if (new Set(groups).size !== groups.length) fail(`${code}_duplicate`);
  return [...groups].sort();
}

export function assertGroupedSplitIsolation({
  train_group_ids: train,
  validation_group_ids: validation,
  test_group_ids: test,
} = {}) {
  const splits = {
    train: splitGroups(train, 'train'),
    validation: splitGroups(validation, 'validation'),
    test: splitGroups(test, 'test'),
  };
  const owner = new Map();
  for (const [split, groups] of Object.entries(splits)) {
    for (const group of groups) {
      if (owner.has(group)) fail(`split_overlap_${owner.get(group)}_${split}`);
      owner.set(group, split);
    }
  }
  return Object.freeze({
    train_group_ids: freezeVector(splits.train),
    validation_group_ids: freezeVector(splits.validation),
    test_group_ids: freezeVector(splits.test),
    total_group_count: owner.size,
  });
}

export function addGradientSets(left, right) {
  const a = gradientObject(left, 'left_gradients');
  const b = gradientObject(right, 'right_gradients');
  const names = Object.keys(a);
  if (JSON.stringify(names) !== JSON.stringify(Object.keys(b))) fail('gradient_names_mismatch');
  const result = {};
  for (const name of names) {
    if (a[name].length !== b[name].length) fail('gradient_shape_mismatch');
    result[name] = freezeVector(a[name].map((value, index) => value + b[name][index]));
  }
  return Object.freeze(result);
}
