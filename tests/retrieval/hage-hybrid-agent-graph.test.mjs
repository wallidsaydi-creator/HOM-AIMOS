import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HAGE_CONSTANTS,
  HAGE_GUARDRAILS,
  HAGE_TRAINED_ARM_REQUIREMENTS,
  buildHageGraph,
  hageScores,
  hageTraversalScores,
  queryConditionedEdgeWeight,
  relationalIntent,
} from '../../services/retrieval/hage-hybrid-agent-graph.js';

function fixtureStates() {
  return [
    {
      id: 'a',
      text: 'Alice booked the Alpine hotel after skiing',
      memory: { created_at: '2026-01-01T00:00:00Z', session_id: 's1' },
    },
    {
      id: 'b',
      text: 'Alice prefers Alpine skiing holidays',
      memory: { created_at: '2026-01-02T00:00:00Z', session_id: 's1' },
    },
    {
      id: 'c',
      memory: { value: 'Database encryption protects records', created_at: '2026-06-01T00:00:00Z', session_id: 's2' },
    },
  ];
}

test('HAGE adaptation normalizes malformed and duplicate states without mutation', () => {
  const states = [null, {}, ...fixtureStates(), { id: 'a', text: 'duplicate must not replace first' }];
  const snapshot = structuredClone(states);
  const graph = buildHageGraph(states);

  assert.deepEqual(states, snapshot);
  assert.deepEqual(graph.nodes.map((node) => node.id), ['a', 'b', 'c']);
  assert.equal(graph.nodes.find((node) => node.id === 'a').text, fixtureStates()[0].text);
  assert.equal(graph.nodes.find((node) => node.id === 'c').text, 'Database encryption protects records');
});

test('HAGE graph construction is deterministic and adjacency matches capped edges', () => {
  const first = buildHageGraph(fixtureStates());
  const second = buildHageGraph(fixtureStates());
  assert.deepEqual(first, second);
  assert.doesNotThrow(() => JSON.stringify(first));
  assert.equal('lexical_tokens' in first.nodes[0], false);
  assert.equal(first.nodes.length <= HAGE_CONSTANTS.max_nodes, true);
  assert.equal(first.edges.length <= first.nodes.length * HAGE_CONSTANTS.max_edges_per_node, true);

  for (const node of first.nodes) {
    const outgoing = first.edges.filter((edge) => edge.from === node.id);
    assert.deepEqual(first.adjacency[node.id], outgoing);
    assert.equal(outgoing.length <= HAGE_CONSTANTS.max_edges_per_node, true);
  }
});

test('HAGE traversal uses visited masks and never repeats a node within a path', () => {
  const graph = {
    nodes: [
      { id: 'a', text: 'alpha query' },
      { id: 'b', text: 'beta bridge' },
      { id: 'c', text: 'gamma evidence' },
    ],
    edges: [
      { from: 'a', to: 'b', base_weight: 1, feature: { semantic: 1 } },
      { from: 'b', to: 'a', base_weight: 1, feature: { semantic: 1 } },
      { from: 'b', to: 'c', base_weight: 1, feature: { semantic: 1 } },
      { from: 'c', to: 'b', base_weight: 1, feature: { semantic: 1 } },
    ],
  };

  const result = hageTraversalScores({ queryText: 'alpha query', graph });
  assert.equal(result.steps_executed <= HAGE_CONSTANTS.traversal_steps, true);
  assert.equal(result.beam.length <= HAGE_CONSTANTS.beam_width, true);
  assert.equal(result.beam.every((row) => new Set(row.path).size === row.path.length), true);
});

test('HAGE traversal fails closed on malformed graph records', () => {
  assert.doesNotThrow(() => hageTraversalScores({ queryText: 'query', graph: null }));
  assert.deepEqual(hageTraversalScores({ queryText: 'query', graph: null }).score, new Map());
  assert.doesNotThrow(() => hageTraversalScores({
    queryText: 'query',
    graph: { nodes: [null, {}, { id: 'a', text: 'query' }], edges: [null, {}, { from: 'a', to: 'missing' }] },
  }));
  assert.deepEqual(buildHageGraph(null).nodes, []);
  assert.deepEqual(hageScores({ queryText: 'query', states: [null, {}, { id: '' }] }).scoreById, new Map());
});

test('HAGE deterministic weights and intents remain finite and bounded', () => {
  const intent = relationalIntent('What did Alice say before the next session?');
  assert.deepEqual(intent, { semantic: 1, temporal: 1, entity: 1, session: 1, preference: 0.2 });
  assert.equal(queryConditionedEdgeWeight({ base_weight: Number.POSITIVE_INFINITY }, { semantic: Number.NaN }), 0);
  assert.equal(queryConditionedEdgeWeight(null, null), 0);
  const weight = queryConditionedEdgeWeight(
    { base_weight: 0.5, feature: { semantic: 0.8, temporal: 0.2 } },
    { semantic: 1, temporal: 1 },
  );
  assert.equal(Number.isFinite(weight) && weight >= 0 && weight <= 1, true);
});

test('HAGE does not invent temporal affinity when timestamps are absent', () => {
  const graph = buildHageGraph([
    { id: 'x', text: 'alpha', memory: { session_id: 's1' } },
    { id: 'y', text: 'beta', memory: { session_id: 's2' } },
  ]);
  assert.deepEqual(graph.edges, []);
});

test('HAGE caps nodes, edges, beam width, and traversal steps', () => {
  const states = Array.from({ length: HAGE_CONSTANTS.max_nodes + 20 }, (_, index) => ({
    id: `n-${String(index).padStart(3, '0')}`,
    text: `shared entity memory ${index}`,
    memory: { created_at: '2026-01-01T00:00:00Z', session_id: 'shared' },
  }));
  const graph = buildHageGraph(states);
  const traversal = hageTraversalScores({ queryText: 'shared entity memory', graph });

  assert.equal(graph.nodes.length, HAGE_CONSTANTS.max_nodes);
  assert.equal(graph.edges.length <= HAGE_CONSTANTS.max_nodes * HAGE_CONSTANTS.max_edges_per_node, true);
  assert.equal(traversal.beam.length <= HAGE_CONSTANTS.beam_width, true);
  assert.equal(traversal.steps_executed <= HAGE_CONSTANTS.traversal_steps, true);
});

test('HAGE identity is explicitly an inactive adaptation, not a trained policy', () => {
  assert.equal(HAGE_GUARDRAILS.implements_trained_hage_policy, false);
  assert.equal(HAGE_GUARDRAILS.requires_bound_checkpoint_for_hage_claim, true);
  assert.equal(HAGE_GUARDRAILS.applies_decay, false);
  assert.equal(HAGE_GUARDRAILS.deletes_memory, false);
  assert.equal(HAGE_TRAINED_ARM_REQUIREMENTS.length, 8);

  const result = hageScores({ queryText: 'Alice skiing', states: fixtureStates() });
  assert.match(result.formula, /^AIMOS deterministic adaptation:/);
  assert.deepEqual(result.trained_hage_requirements, HAGE_TRAINED_ARM_REQUIREMENTS);
});
