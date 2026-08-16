import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  GAAMA_CONSTANTS,
  GAAMA_EDGE_TYPE_WEIGHTS,
  GAAMA_GUARDRAILS,
  buildGaamaCandidatePool,
  buildGaamaGraph,
  buildGaamaTransitions,
  cosineSimilarityGaama,
  expandGaamaSubgraph,
  personalizedPageRankGaama,
  runGaamaDormantCandidate,
  scoreGaamaCandidates,
} from '../../services/core/gaama-candidate/gaama-dormant-candidate.js';

function nodes() {
  return [
    { id: 'a', node_type: 'episode', content: 'Alpha', embedding: [1, 0] },
    { id: 'b', node_type: 'concept', content: 'Bridge', embedding: [0.8, 0.6] },
    { id: 'c', node_type: 'fact', content: 'Cause', embedding: [0, 1] },
    { id: 'd', node_type: 'reflection', content: 'Distant', embedding: [-1, 0] },
    { id: 'x', node_type: 'fact', content: 'Graph only', embedding: [0.6, 0.8] },
  ];
}

function edges() {
  return [
    { id: 'ab', source_id: 'a', target_id: 'b', edge_type: 'HAS_CONCEPT' },
    { id: 'bc', source_id: 'b', target_id: 'c', edge_type: 'DERIVED_FROM_FACT' },
    { id: 'cx', source_id: 'c', target_id: 'x', edge_type: 'DERIVED_FROM' },
  ];
}

test('GAAMA candidate is native, dormant, pure, and full-retention bounded', () => {
  assert.equal(GAAMA_GUARDRAILS.dormant, true);
  assert.equal(GAAMA_GUARDRAILS.canonical_caller, false);
  assert.equal(GAAMA_GUARDRAILS.database_access, false);
  assert.equal(GAAMA_GUARDRAILS.persistent_writes, false);
  assert.equal(GAAMA_GUARDRAILS.environment_authority, false);
  assert.equal(GAAMA_GUARDRAILS.retention_policy, 'full_retention_no_decay_no_suppression');
  assert.equal(GAAMA_CONSTANTS.alpha, 0.6);
  assert.equal(GAAMA_CONSTANTS.max_iterations, 200);
});

test('Equation 1 preserves the 2B pool and squares the top-k nonnegative similarities', () => {
  const result = buildGaamaCandidatePool({
    retrievalBudget: 2,
    seedCount: 2,
    candidates: [
      { id: 'd', similarity: -1 },
      { id: 'c', similarity: 0.2 },
      { id: 'b', similarity: 0.4 },
      { id: 'a', similarity: 0.8 },
      { id: 'e', similarity: 0.1 },
      { id: 'b', similarity: 0.3 },
    ],
  });
  assert.equal(result.expected_pool_size, 4);
  assert.equal(result.pool.length, 4);
  assert.equal(result.pool_complete, true);
  assert.deepEqual(result.pool.map((row) => row.id), ['a', 'b', 'c', 'e']);
  assert.ok(Math.abs(result.seeds[0].seed_weight - 0.64) < 1e-12);
  assert.ok(Math.abs(result.seeds[1].seed_weight - 0.16) < 1e-12);
  assert.ok(Math.abs(result.teleport.get('a') - 0.8) < 1e-12);
  assert.ok(Math.abs(result.teleport.get('b') - 0.2) < 1e-12);
});

test('candidate normalization is deterministic, immutable, and fail-closed', () => {
  const candidates = [
    { id: 'b', similarity: Number.POSITIVE_INFINITY, embedding: [1, 0] },
    null,
    {},
    { id: 'a', similarity: 2, embedding: [0, 1] },
  ];
  const before = structuredClone(candidates);
  const first = buildGaamaCandidatePool({ candidates, retrievalBudget: 2 });
  const second = buildGaamaCandidatePool({ candidates, retrievalBudget: 2 });
  assert.deepEqual(first.pool, second.pool);
  assert.deepEqual(candidates, before);
  assert.deepEqual(first.pool.map((row) => [row.id, row.similarity]), [['a', 1], ['b', 0]]);
  assert.equal(first.pool_complete, false);
});

test('graph construction admits only supported typed edges and does not mutate input', () => {
  const rawNodes = nodes();
  const rawEdges = [
    ...edges(),
    null,
    { id: 'self', source_id: 'a', target_id: 'a', edge_type: 'NEXT' },
    { id: 'unknown', source_id: 'a', target_id: 'b', edge_type: 'LIKES' },
    { id: 'missing', source_id: 'a', target_id: 'missing', edge_type: 'NEXT' },
    { id: 'duplicate', source_id: 'a', target_id: 'b', edge_type: 'HAS_CONCEPT' },
  ];
  const before = { nodes: structuredClone(rawNodes), edges: structuredClone(rawEdges) };
  const graph = buildGaamaGraph({ nodes: rawNodes, edges: rawEdges });
  assert.deepEqual(rawNodes, before.nodes);
  assert.deepEqual(rawEdges, before.edges);
  assert.equal(graph.edges.length, 3);
  assert.deepEqual(graph.rejected_edges.map((row) => row.reason), [
    'malformed_edge',
    'self_edge',
    'unsupported_edge_type',
    'unknown_endpoint',
    'duplicate_edge',
  ]);
});

test('depth-two expansion is exact, bounded, and terminates on cycles', () => {
  const graph = buildGaamaGraph({
    nodes: nodes(),
    edges: [...edges(), { id: 'ca', source_id: 'c', target_id: 'a', edge_type: 'NEXT' }],
  });
  const expanded = expandGaamaSubgraph({ graph, seedIds: ['a'], depth: 2 });
  assert.deepEqual(expanded.layers, [['a'], ['b', 'c'], ['x']]);
  assert.deepEqual(expanded.node_ids, ['a', 'b', 'c', 'x']);
  assert.equal(expanded.expansion_depth, 2);
  assert.equal(new Set(expanded.node_ids).size, expanded.node_ids.length);
});

test('Equation 2 applies exact edge-type weights and produces row-stochastic transitions', () => {
  const transition = buildGaamaTransitions({
    nodeIds: ['a', 'b', 'c'],
    edges: [
      { source_id: 'a', target_id: 'b', edge_type: 'NEXT' },
      { source_id: 'a', target_id: 'c', edge_type: 'DERIVED_FROM_FACT' },
    ],
  });
  const row = transition.transitions.get('a');
  assert.equal(GAAMA_EDGE_TYPE_WEIGHTS.NEXT, 0.8);
  assert.equal(GAAMA_EDGE_TYPE_WEIGHTS.DERIVED_FROM_FACT, 0.5);
  assert.ok(Math.abs(row.find((entry) => entry.target_id === 'b').probability - (8 / 13)) < 1e-12);
  assert.ok(Math.abs(row.find((entry) => entry.target_id === 'c').probability - (5 / 13)) < 1e-12);
  assert.equal(transition.row_stochastic, true);
});

test('published Equation 3 hub multiplier is applied and its row-normalization cancellation is explicit', () => {
  const hubNodes = ['hub', ...Array.from({ length: 51 }, (_, index) => `n${index}`)];
  const hubEdges = hubNodes.slice(1).map((id, index) => ({
    id: `e${index}`,
    source_id: 'hub',
    target_id: id,
    edge_type: 'HAS_CONCEPT',
  }));
  const at50 = buildGaamaTransitions({ nodeIds: hubNodes, edges: hubEdges, hubThreshold: 50 });
  const at1 = buildGaamaTransitions({ nodeIds: hubNodes, edges: hubEdges, hubThreshold: 1 });
  const diagnostic = at50.diagnostics.find((row) => row.source_id === 'hub');
  assert.equal(diagnostic.degree, 51);
  assert.ok(Math.abs(diagnostic.hub_scale - (50 / 51)) < 1e-12);
  assert.equal(diagnostic.hub_scale_cancels_under_row_normalization, true);
  assert.equal(at50.published_hub_dampening_effective, false);
  const rowAt50 = at50.transitions.get('hub');
  const rowAt1 = at1.transitions.get('hub');
  assert.deepEqual(rowAt50.map((row) => row.target_id), rowAt1.map((row) => row.target_id));
  for (let index = 0; index < rowAt50.length; index += 1) {
    assert.ok(Math.abs(rowAt50[index].probability - rowAt1[index].probability) < 1e-12);
  }
});

test('Equation 4 matches the two-node hand solution and conserves probability mass', () => {
  const transitions = new Map([
    ['a', [{ target_id: 'b', probability: 1 }]],
    ['b', [{ target_id: 'a', probability: 1 }]],
  ]);
  const result = personalizedPageRankGaama({
    nodeIds: ['a', 'b'],
    transitions,
    teleport: new Map([['a', 1], ['b', 0]]),
  });
  assert.equal(result.converged, true);
  assert.ok(Math.abs(result.scores.get('a') - 0.625) < 1e-6);
  assert.ok(Math.abs(result.scores.get('b') - 0.375) < 1e-6);
  assert.ok(Math.abs(result.probability_mass - 1) < 1e-12);
  assert.equal(result.normalized_scores.get('a'), 1);
  assert.ok(Math.abs(result.normalized_scores.get('b') - 0.6) < 1e-6);
});

test('Equation 4 redistributes sink mass through teleport and handles disconnected nodes', () => {
  const result = personalizedPageRankGaama({
    nodeIds: ['a', 'b'],
    transitions: new Map([['a', []], ['b', []]]),
    teleport: new Map([['a', 1], ['b', 0]]),
  });
  assert.equal(result.converged, true);
  assert.equal(result.scores.get('a'), 1);
  assert.equal(result.scores.get('b'), 0);
  assert.equal(result.probability_mass, 1);
});

test('zero seed mass terminates explicitly without NaN or fabricated relevance', () => {
  const result = personalizedPageRankGaama({
    nodeIds: ['a'],
    transitions: new Map([['a', []]]),
    teleport: new Map([['a', 0]]),
  });
  assert.equal(result.termination_reason, 'no_positive_seed_mass');
  assert.equal(result.normalized_scores.get('a'), 0);
  assert.equal(Number.isFinite(result.normalized_scores.get('a')), true);
});

test('Equation 5 max-normalizes both signals and computes graph-only similarity on demand', () => {
  const graph = buildGaamaGraph({ nodes: nodes(), edges: edges() });
  const ranked = scoreGaamaCandidates({
    candidateIds: ['a', 'b'],
    candidateSimilarity: new Map([['a', 0.5]]),
    graph,
    queryEmbedding: [1, 0],
    pprScores: new Map([['a', 1], ['b', 0.5]]),
  });
  const a = ranked.find((row) => row.id === 'a');
  const b = ranked.find((row) => row.id === 'b');
  assert.equal(a.similarity, 0.625);
  assert.equal(a.score, 0.725);
  assert.equal(b.similarity, 1);
  assert.equal(b.score, 1.05);
  assert.equal(b.graph_discovered, true);
  assert.deepEqual(ranked.map((row) => row.id), ['b', 'a']);
});

test('complete candidate retains the 2B universe and adds depth-two graph discoveries', () => {
  const candidates = [
    { id: 'a', similarity: 1, embedding: [1, 0] },
    { id: 'b', similarity: 0.8, embedding: [0.8, 0.6] },
    { id: 'c', similarity: 0.5, embedding: [0, 1] },
    { id: 'd', similarity: 0.1, embedding: [-1, 0] },
  ];
  const before = { candidates: structuredClone(candidates), nodes: nodes(), edges: edges() };
  const first = runGaamaDormantCandidate({
    candidates,
    nodes: before.nodes,
    edges: before.edges,
    queryEmbedding: [1, 0],
    retrievalBudget: 2,
    seedCount: 1,
  });
  const second = runGaamaDormantCandidate({
    candidates,
    nodes: before.nodes,
    edges: before.edges,
    queryEmbedding: [1, 0],
    retrievalBudget: 2,
    seedCount: 1,
  });
  assert.deepEqual(first.ranking, second.ranking);
  assert.deepEqual(candidates, before.candidates);
  assert.equal(first.candidate_pool.pool.length, 4);
  assert.deepEqual(first.subgraph.node_ids, ['a', 'b', 'c']);
  assert.deepEqual(first.ranking.map((row) => row.id).sort(), ['a', 'b', 'c', 'd']);
  assert.equal(first.transition.row_stochastic, true);
  assert.ok(Math.abs(first.ppr.probability_mass - 1) < 1e-12);
});

test('source contains no database, server, environment, deletion, or live-recall authority', () => {
  const source = readFileSync(new URL('../../services/core/gaama-candidate/gaama-dormant-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"].*db\/connection/);
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /persistMemory|app\.listen|hybridRetrieve\s*\(/);
  assert.doesNotMatch(source, /DELETE FROM|DROP TABLE|expires_at|age_decay/i);
});

test('cosine boundaries and malformed vectors are finite and exact', () => {
  assert.equal(cosineSimilarityGaama([1, 0], [1, 0]), 1);
  assert.equal(cosineSimilarityGaama([1, 0], [0, 1]), 0);
  assert.equal(cosineSimilarityGaama([1, 0], [-1, 0]), -1);
  assert.equal(cosineSimilarityGaama([1], [1, 0]), 0);
  assert.equal(cosineSimilarityGaama([Number.NaN], [1]), 0);
  assert.equal(cosineSimilarityGaama([0, 0], [1, 0]), 0);
});
