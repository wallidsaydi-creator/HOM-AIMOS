/**
 * query-router.js — Pure Node-native HAGE QueryRouter numerical kernel.
 *
 * Paper authority: HAGE.pdf, Equations (7)–(10).
 * This module is dormant and side-effect free. It performs no I/O and owns no
 * database, network, identity, signing, configuration, or model-load authority.
 */

import { HAGE_NATIVE_CONTRACT } from './graph-contract.js';

export const HAGE_QUERY_ROUTER_SHAPES = Object.freeze({
  input: HAGE_NATIVE_CONTRACT.query_router_input_dimensions,
  hidden_1: 128,
  hidden_2: 64,
  output: 1,
});

export const HAGE_QUERY_ROUTER_PARAMETER_COUNT = 108_033;

const validatedParameters = new WeakSet();

function fail(code) {
  throw new Error(`hage_query_router:${code}`);
}

function finiteNumber(value, code) {
  if (typeof value !== 'number' || !Number.isFinite(value)) fail(code);
  return Object.is(value, -0) ? 0 : value;
}

function finiteVector(value, dimensions, code, { unit = false } = {}) {
  if (!Array.isArray(value) && !ArrayBuffer.isView(value)) fail(`${code}_not_vector`);
  if (value.length !== dimensions) fail(`${code}_dimension`);
  const result = new Array(dimensions);
  let squaredNorm = 0;
  for (let index = 0; index < dimensions; index += 1) {
    const number = finiteNumber(value[index], `${code}_non_finite`);
    result[index] = number;
    squaredNorm += number * number;
  }
  if (unit && Math.abs(Math.sqrt(squaredNorm) - 1) > HAGE_NATIVE_CONTRACT.unit_norm_tolerance) {
    fail(`${code}_unit_norm`);
  }
  return result;
}

function freezeVector(value) {
  return Object.freeze([...value]);
}

function parameterVector(value, dimensions, code) {
  return freezeVector(finiteVector(value, dimensions, code));
}

export function createQueryRouterParameters(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('parameters_not_object');
  if (validatedParameters.has(raw)) return raw;
  const { input, hidden_1: hidden1, hidden_2: hidden2 } = HAGE_QUERY_ROUTER_SHAPES;
  const parameters = Object.freeze({
    W1: parameterVector(raw.W1, hidden1 * input, 'W1'),
    b1: parameterVector(raw.b1, hidden1, 'b1'),
    W2: parameterVector(raw.W2, hidden2 * hidden1, 'W2'),
    b2: parameterVector(raw.b2, hidden2, 'b2'),
    W3: parameterVector(raw.W3, hidden2, 'W3'),
    b3: parameterVector(raw.b3, 1, 'b3'),
  });
  const count = Object.values(parameters).reduce((sum, values) => sum + values.length, 0);
  if (count !== HAGE_QUERY_ROUTER_PARAMETER_COUNT) fail('parameter_count');
  validatedParameters.add(parameters);
  return parameters;
}

function xorshift32(seed) {
  let state = seed >>> 0;
  if (state === 0) fail('seed_zero');
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function xavierVector(length, fanIn, fanOut, random) {
  const bound = Math.sqrt(6 / (fanIn + fanOut));
  return Array.from({ length }, () => ((random() * 2) - 1) * bound);
}

export function initializeQueryRouterParameters(seed) {
  if (!Number.isSafeInteger(seed) || seed <= 0 || seed > 0xffffffff) fail('seed_range');
  const random = xorshift32(seed);
  const { input, hidden_1: hidden1, hidden_2: hidden2 } = HAGE_QUERY_ROUTER_SHAPES;
  return createQueryRouterParameters({
    W1: xavierVector(hidden1 * input, input, hidden1, random),
    b1: Array(hidden1).fill(0),
    W2: xavierVector(hidden2 * hidden1, hidden1, hidden2, random),
    b2: Array(hidden2).fill(0),
    W3: xavierVector(hidden2, hidden2, 1, random),
    b3: [0],
  });
}

export function stableSoftplus(value) {
  const z = finiteNumber(value, 'softplus_non_finite');
  return Math.max(z, 0) + Math.log1p(Math.exp(-Math.abs(z)));
}

function stableSigmoid(value) {
  const z = finiteNumber(value, 'sigmoid_non_finite');
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const exp = Math.exp(z);
  return exp / (1 + exp);
}

export function stableSoftmax(values) {
  const logits = finiteVector(values, values?.length, 'softmax');
  if (logits.length === 0) fail('softmax_empty');
  const maximum = Math.max(...logits);
  const exponentials = logits.map((value) => Math.exp(value - maximum));
  const denominator = exponentials.reduce((sum, value) => sum + value, 0);
  if (!Number.isFinite(denominator) || denominator <= 0) fail('softmax_denominator');
  return freezeVector(exponentials.map((value) => value / denominator));
}

export function cosineSimilarity(left, right) {
  const a = finiteVector(left, HAGE_NATIVE_CONTRACT.embedding_dimensions, 'cosine_left', { unit: true });
  const b = finiteVector(right, HAGE_NATIVE_CONTRACT.embedding_dimensions, 'cosine_right', { unit: true });
  let dot = 0;
  for (let index = 0; index < a.length; index += 1) dot += a[index] * b[index];
  if (!Number.isFinite(dot)) fail('cosine_non_finite');
  if (dot > 1 && dot <= 1 + 1e-6) return 1;
  if (dot < -1 && dot >= -1 - 1e-6) return -1;
  if (dot < -1 || dot > 1) fail('cosine_range');
  return dot;
}

function dense(input, weights, bias, outputDimensions) {
  const output = new Array(outputDimensions);
  for (let row = 0; row < outputDimensions; row += 1) {
    let value = bias[row];
    const offset = row * input.length;
    for (let column = 0; column < input.length; column += 1) {
      value += weights[offset + column] * input[column];
    }
    if (!Number.isFinite(value)) fail('dense_non_finite');
    output[row] = value;
  }
  return output;
}

function normalizeRouterInput(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('input_not_object');
  const query = finiteVector(raw.query_embedding, 768, 'query_embedding', { unit: true });
  const edge = finiteVector(raw.edge_feature, 4, 'edge_feature');
  const intent = finiteVector(raw.relation_intent, 4, 'relation_intent', { unit: true });
  const source = finiteVector(raw.source_embedding, 768, 'source_embedding', { unit: true });
  const target = finiteVector(raw.target_embedding, 768, 'target_embedding', { unit: true });
  const simSource = cosineSimilarity(query, source);
  const simTarget = cosineSimilarity(query, target);
  const vector = [...query, ...edge, ...intent, simSource, simTarget];
  if (vector.length !== HAGE_QUERY_ROUTER_SHAPES.input) fail('input_dimension');
  return { vector, simSource, simTarget };
}

function forwardWithCache(parameters, rawInput) {
  const p = createQueryRouterParameters(parameters);
  const input = normalizeRouterInput(rawInput);
  const z1 = dense(input.vector, p.W1, p.b1, HAGE_QUERY_ROUTER_SHAPES.hidden_1);
  const h1 = z1.map((value) => Math.max(0, value));
  const z2 = dense(h1, p.W2, p.b2, HAGE_QUERY_ROUTER_SHAPES.hidden_2);
  const h2 = z2.map((value) => Math.max(0, value));
  const z3 = dense(h2, p.W3, p.b3, 1)[0];
  const structuralWeight = stableSoftplus(z3);
  return { p, input, z1, h1, z2, h2, z3, structuralWeight };
}

export function queryRouterForward(parameters, input) {
  const result = forwardWithCache(parameters, input);
  return Object.freeze({
    structural_weight: result.structuralWeight,
    source_similarity: result.input.simSource,
    target_similarity: result.input.simTarget,
  });
}

export function queryRouterForwardBackward(parameters, input, upstream = 1) {
  const cache = forwardWithCache(parameters, input);
  const scale = finiteNumber(upstream, 'upstream_non_finite');
  const dz3 = stableSigmoid(cache.z3) * scale;
  const dW3 = cache.h2.map((value) => dz3 * value);
  const db3 = [dz3];
  const dh2 = cache.p.W3.map((weight) => weight * dz3);
  const dz2 = dh2.map((value, index) => (cache.z2[index] > 0 ? value : 0));
  const dW2 = new Array(cache.p.W2.length);
  const db2 = [...dz2];
  const dh1 = Array(HAGE_QUERY_ROUTER_SHAPES.hidden_1).fill(0);
  for (let row = 0; row < HAGE_QUERY_ROUTER_SHAPES.hidden_2; row += 1) {
    const offset = row * HAGE_QUERY_ROUTER_SHAPES.hidden_1;
    for (let column = 0; column < HAGE_QUERY_ROUTER_SHAPES.hidden_1; column += 1) {
      dW2[offset + column] = dz2[row] * cache.h1[column];
      dh1[column] += cache.p.W2[offset + column] * dz2[row];
    }
  }
  const dz1 = dh1.map((value, index) => (cache.z1[index] > 0 ? value : 0));
  const dW1 = new Array(cache.p.W1.length);
  const db1 = [...dz1];
  const dx = Array(HAGE_QUERY_ROUTER_SHAPES.input).fill(0);
  for (let row = 0; row < HAGE_QUERY_ROUTER_SHAPES.hidden_1; row += 1) {
    const offset = row * HAGE_QUERY_ROUTER_SHAPES.input;
    for (let column = 0; column < HAGE_QUERY_ROUTER_SHAPES.input; column += 1) {
      dW1[offset + column] = dz1[row] * cache.input.vector[column];
      dx[column] += cache.p.W1[offset + column] * dz1[row];
    }
  }
  return Object.freeze({
    structural_weight: cache.structuralWeight,
    input_gradient: freezeVector(dx),
    parameter_gradients: Object.freeze({
      W1: freezeVector(dW1),
      b1: freezeVector(db1),
      W2: freezeVector(dW2),
      b2: freezeVector(db2),
      W3: freezeVector(dW3),
      b3: freezeVector(db3),
    }),
  });
}

export function hageTransitionPolicy({
  query_embedding: query,
  target_embeddings: targets,
  structural_weights: structuralWeights,
  lambda = 0.5,
} = {}) {
  const mixture = finiteNumber(lambda, 'lambda_non_finite');
  if (mixture < 0 || mixture > 1) fail('lambda_range');
  if (!Array.isArray(targets) || targets.length === 0) fail('targets_empty');
  const weights = finiteVector(structuralWeights, targets.length, 'structural_weights');
  if (weights.some((weight) => weight <= 0)) fail('structural_weight_non_positive');
  const similarities = targets.map((target) => cosineSimilarity(query, target));
  const logits = similarities.map((similarity, index) => (
    (mixture * similarity) + ((1 - mixture) * weights[index])
  ));
  const probabilities = stableSoftmax(logits);
  return Object.freeze({
    similarities: freezeVector(similarities),
    logits: freezeVector(logits),
    probabilities,
  });
}
