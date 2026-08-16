/**
 * mdp.js — Immutable HAGE graph-traversal Markov decision process.
 *
 * Paper authority: HAGE.pdf, Equations (10)–(12).
 * No state escapes this module mutably and no canonical memory is changed.
 */

import {
  HAGE_NATIVE_CONTRACT,
  createHageGraphSnapshot,
  eligibleHageNeighbors,
} from './graph-contract.js';
import { cosineSimilarity } from './query-router.js';

export const HAGE_MDP_DEFAULTS = Object.freeze({
  max_hops: 5,
  hit_reward: 10,
  step_cost: 0.05,
  terminal_failure_cost: 1,
});

const validatedStates = new WeakSet();

function fail(code) {
  throw new Error(`hage_mdp:${code}`);
}

function finiteNumber(value, code) {
  if (typeof value !== 'number' || !Number.isFinite(value)) fail(code);
  return Object.is(value, -0) ? 0 : value;
}

function sha256(value, code) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail(code);
  return value;
}

function finiteUnitVector(value, code) {
  if (!Array.isArray(value) && !ArrayBuffer.isView(value)) fail(`${code}_not_vector`);
  if (value.length !== HAGE_NATIVE_CONTRACT.embedding_dimensions) fail(`${code}_dimension`);
  const vector = new Array(value.length);
  let squaredNorm = 0;
  for (let index = 0; index < value.length; index += 1) {
    const number = finiteNumber(value[index], `${code}_non_finite`);
    vector[index] = number;
    squaredNorm += number * number;
  }
  if (Math.abs(Math.sqrt(squaredNorm) - 1) > HAGE_NATIVE_CONTRACT.unit_norm_tolerance) {
    fail(`${code}_unit_norm`);
  }
  return Object.freeze(vector);
}

function uniqueSortedIds(values, code) {
  if (!Array.isArray(values) || values.length === 0) fail(`${code}_empty`);
  return Object.freeze([...new Set(values.map((value) => sha256(value, code)))].sort());
}

function normalizeMaxHops(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 64) fail('max_hops_range');
  return value;
}

function normalizeRewardConfig(raw = HAGE_MDP_DEFAULTS) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('reward_config_not_object');
  const hit = finiteNumber(raw.hit_reward ?? HAGE_MDP_DEFAULTS.hit_reward, 'hit_reward');
  const step = finiteNumber(raw.step_cost ?? HAGE_MDP_DEFAULTS.step_cost, 'step_cost');
  const terminal = finiteNumber(
    raw.terminal_failure_cost ?? HAGE_MDP_DEFAULTS.terminal_failure_cost,
    'terminal_failure_cost',
  );
  if (hit <= 0 || step < 0 || terminal < 0) fail('reward_config_range');
  return Object.freeze({ hit_reward: hit, step_cost: step, terminal_failure_cost: terminal });
}

function chooseAnchor(snapshot, query) {
  if (snapshot.nodes.length === 0) fail('snapshot_empty');
  let best = null;
  for (const node of snapshot.nodes) {
    const similarity = cosineSimilarity(query, node.embedding);
    if (!best || similarity > best.similarity
      || (similarity === best.similarity && node.id < best.id)) {
      best = { id: node.id, similarity };
    }
  }
  return best.id;
}

function freezeState(raw) {
  const state = Object.freeze({
    snapshot: raw.snapshot,
    query_embedding: raw.query_embedding,
    target_node_ids: raw.target_node_ids,
    found_node_ids: Object.freeze([...raw.found_node_ids].sort()),
    current_node_id: raw.current_node_id,
    visited_node_ids: Object.freeze([...raw.visited_node_ids]),
    steps: raw.steps,
    max_hops: raw.max_hops,
    done: raw.done,
    success: raw.success,
    termination: raw.termination,
  });
  validatedStates.add(state);
  return state;
}

export function createHageEpisode({
  snapshot,
  query_embedding: query,
  target_node_ids: targets,
  start_node_id: requestedStart,
  max_hops: maxHops = HAGE_MDP_DEFAULTS.max_hops,
} = {}) {
  const normalizedSnapshot = createHageGraphSnapshot(snapshot);
  const normalizedQuery = finiteUnitVector(query, 'query_embedding');
  const normalizedTargets = uniqueSortedIds(targets, 'target_node_id');
  const nodeIds = new Set(normalizedSnapshot.nodes.map((node) => node.id));
  if (normalizedTargets.some((target) => !nodeIds.has(target))) fail('target_node_missing');
  const start = requestedStart === undefined
    ? chooseAnchor(normalizedSnapshot, normalizedQuery)
    : sha256(requestedStart, 'start_node_id');
  if (!nodeIds.has(start)) fail('start_node_missing');
  const found = normalizedTargets.includes(start) ? [start] : [];
  const success = found.length === normalizedTargets.length;
  return freezeState({
    snapshot: normalizedSnapshot,
    query_embedding: normalizedQuery,
    target_node_ids: normalizedTargets,
    found_node_ids: found,
    current_node_id: start,
    visited_node_ids: [start],
    steps: 0,
    max_hops: normalizeMaxHops(maxHops),
    done: success,
    success,
    termination: success ? 'targets_satisfied_at_anchor' : null,
  });
}

export function hageEpisodeActions(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('state_not_object');
  if (!validatedStates.has(state)) fail('state_not_native');
  if (state.done) return Object.freeze([]);
  return eligibleHageNeighbors({
    snapshot: state.snapshot,
    current_node_id: state.current_node_id,
    visited_node_ids: state.visited_node_ids,
  });
}

export function advanceHageEpisode(state, actionIndex, rewardConfig = HAGE_MDP_DEFAULTS) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('state_not_object');
  if (!validatedStates.has(state)) fail('state_not_native');
  if (state.done) fail('episode_done');
  const rewards = normalizeRewardConfig(rewardConfig);
  const actions = hageEpisodeActions(state);

  if (actions.length === 0) {
    const terminalState = freezeState({
      ...state,
      done: true,
      success: false,
      termination: 'dead_end',
    });
    return Object.freeze({
      state: terminalState,
      reward: -rewards.terminal_failure_cost,
      transitioned: false,
      edge: null,
      new_target_count: 0,
      terminal_failure: true,
    });
  }

  if (!Number.isSafeInteger(actionIndex) || actionIndex < 0 || actionIndex >= actions.length) {
    fail('action_index_range');
  }
  const edge = actions[actionIndex];
  const steps = state.steps + 1;
  const found = new Set(state.found_node_ids);
  const isNewTarget = state.target_node_ids.includes(edge.to) && !found.has(edge.to);
  if (isNewTarget) found.add(edge.to);
  const success = found.size === state.target_node_ids.length;
  const visited = [...state.visited_node_ids, edge.to];
  const exhausted = steps >= state.max_hops;
  const candidateState = freezeState({
    ...state,
    found_node_ids: [...found],
    current_node_id: edge.to,
    visited_node_ids: visited,
    steps,
    done: success || exhausted,
    success,
    termination: success ? 'targets_satisfied' : exhausted ? 'hop_budget_exhausted' : null,
  });
  const deadEnd = !candidateState.done && hageEpisodeActions(candidateState).length === 0;
  const terminalFailure = !success && (exhausted || deadEnd);
  const nextState = deadEnd
    ? freezeState({ ...candidateState, done: true, success: false, termination: 'dead_end' })
    : candidateState;
  const reward = ((isNewTarget ? 1 : 0) * rewards.hit_reward)
    - rewards.step_cost
    - (terminalFailure ? rewards.terminal_failure_cost : 0);
  return Object.freeze({
    state: nextState,
    reward,
    transitioned: true,
    edge,
    new_target_count: isNewTarget ? 1 : 0,
    terminal_failure: terminalFailure,
  });
}
