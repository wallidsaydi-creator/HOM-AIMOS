import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MAGMA_CONSTANTS,
  MAGMA_GUARDRAILS,
  adaptiveMagmaBeamTraversal,
  buildBoundedAssociativeEdgeCandidates,
  buildMagmaGraph,
  cosineSimilarityMagma,
  identifyMagmaAnchors,
  linearizeMagmaGraph,
  reciprocalRankFusionMagma,
  relationIntentVectorMagma,
  retrieveMagmaLineage,
  runMagmaRetrievalKernel,
  structuralAlignmentMagma,
  transitionScoreMagma,
} from '../../services/retrieval/magma-lineage-retriever.js';

function fixtureNodes() {
  return [
    { id: 'a', content: 'Alice approved Project Quasar.', timestamp: '2026-01-01T00:00:00Z', embedding: [1, 0], reference_id: 'ref-a' },
    { id: 'b', content: 'The approval caused the launch.', timestamp: '2026-01-02T00:00:00Z', embedding: [0.8, 0.2], reference_id: 'ref-b' },
    { id: 'c', content: 'The launch produced the report.', timestamp: '2026-01-03T00:00:00Z', embedding: [0, 1], reference_id: 'ref-c' },
    { id: 'd', content: 'A separate travel memory.', timestamp: '2026-01-04T00:00:00Z', embedding: [-1, 0], reference_id: 'ref-d' },
  ];
}

function fixtureEdges() {
  return [
    { id: 'cause-ab', source_id: 'a', target_id: 'b', relation: 'causal' },
    { id: 'cause-bc', source_id: 'b', target_id: 'c', relation: 'causal' },
    { id: 'semantic-ad', source_id: 'a', target_id: 'd', relation: 'semantic' },
    { id: 'temporal-ab', source_id: 'a', target_id: 'b', relation: 'temporal' },
  ];
}

test('MAGMA graph normalization is deterministic, immutable, bounded, and fail-closed', () => {
  const nodes = fixtureNodes();
  const edges = fixtureEdges();
  const beforeNodes = structuredClone(nodes);
  const beforeEdges = structuredClone(edges);
  const first = buildMagmaGraph({ nodes, edges });
  const second = buildMagmaGraph({ nodes, edges });

  assert.deepEqual(first.nodes, second.nodes);
  assert.deepEqual(first.edges, second.edges);
  assert.deepEqual(nodes, beforeNodes);
  assert.deepEqual(edges, beforeEdges);
  assert.equal(first.nodes.length, 4);
  assert.equal(first.edges.length, 4);
  assert.equal(first.adjacency.get('d').some((entry) => entry.target_id === 'a'), true);

  const malformed = buildMagmaGraph({
    nodes: [null, {}, { id: 'x', content: 'valid', timestamp: '2026-01-02' }, { id: 'x', content: 'duplicate' }],
    edges: [
      null,
      { id: 'missing', source_id: 'x', target_id: 'nope', relation: 'causal' },
      { id: 'self', source_id: 'x', target_id: 'x', relation: 'semantic' },
      { id: 'bad-relation', source_id: 'x', target_id: 'x2', relation: 'unknown' },
    ],
  });
  assert.equal(malformed.nodes.length, 1);
  assert.equal(malformed.edges.length, 0);
  assert.equal(malformed.rejected_edges.length, 4);
});

test('temporal graph edges require strict timestamp order', () => {
  const graph = buildMagmaGraph({
    nodes: [
      { id: 'later', content: 'later', timestamp: '2026-02-02' },
      { id: 'earlier', content: 'earlier', timestamp: '2026-02-01' },
      { id: 'unknown', content: 'unknown' },
    ],
    edges: [
      { id: 'valid', source_id: 'earlier', target_id: 'later', relation: 'temporal' },
      { id: 'reverse', source_id: 'later', target_id: 'earlier', relation: 'temporal' },
      { id: 'missing-time', source_id: 'earlier', target_id: 'unknown', relation: 'temporal' },
    ],
  });
  assert.deepEqual(graph.edges.map((edge) => edge.id), ['valid']);
  assert.deepEqual(graph.rejected_edges.map((edge) => edge.reason), ['temporal_order_not_strict', 'temporal_order_not_strict']);
});

test('cosine uses the exact natural range and rejects malformed vectors', () => {
  assert.equal(cosineSimilarityMagma([1, 0], [1, 0]), 1);
  assert.equal(cosineSimilarityMagma([1, 0], [0, 1]), 0);
  assert.equal(cosineSimilarityMagma([1, 0], [-1, 0]), -1);
  assert.equal(cosineSimilarityMagma([1], [1, 0]), 0);
  assert.equal(cosineSimilarityMagma([0, 0], [1, 0]), 0);
});

test('Equation 4 RRF is exact, channel-local duplicates cannot inflate it, and anchors are capped', () => {
  const fused = reciprocalRankFusionMagma([
    [{ id: 'a' }, { id: 'a' }, { id: 'b' }],
    [{ id: 'b' }, { id: 'a' }],
    [{ id: 'a' }],
  ], 60);
  const a = fused.find((row) => row.id === 'a');
  const b = fused.find((row) => row.id === 'b');
  assert.equal(a.score, (1 / 61) + (1 / 62) + (1 / 61));
  assert.equal(b.score, (1 / 63) + (1 / 61));
  assert.deepEqual(a.channels, [0, 1, 2]);

  const anchors = identifyMagmaAnchors({
    vectorRanks: ['a', 'b'],
    lexicalRanks: ['b', 'a'],
    temporalRanks: ['a'],
    topK: 1,
  });
  assert.equal(anchors.length, 1);
  assert.equal(anchors[0].id, 'a');
});

test('Equations 5 and 6 match a hand-computed oracle', () => {
  const weights = { semantic: 1, temporal: 2, causal: 3, entity: 4 };
  assert.equal(structuralAlignmentMagma('causal', weights), 3);
  assert.equal(structuralAlignmentMagma('unknown', weights), 0);
  const expected = Math.exp((2 * 3) + (0.5 * 1));
  const observed = transitionScoreMagma({
    relation: 'causal',
    intentWeights: weights,
    neighborEmbedding: [1, 0],
    queryEmbedding: [1, 0],
    lambdaStructure: 2,
    lambdaSemantic: 0.5,
  });
  assert.ok(Math.abs(observed - expected) < 1e-12);
  assert.equal(transitionScoreMagma({ relation: 'causal', intentWeights: weights, lambdaStructure: Number.POSITIVE_INFINITY }), 0);
  assert.equal(
    transitionScoreMagma({
      relation: 'causal',
      intentWeights: weights,
      neighborEmbedding: [1, 0],
      queryEmbedding: [1, 0],
      semanticSimilarity: 1,
    }),
    transitionScoreMagma({
      relation: 'causal',
      intentWeights: weights,
      neighborEmbedding: [1, 0],
      queryEmbedding: [1, 0],
    }),
  );
});

test('intent relation vectors are explicit, immutable, and safely overrideable', () => {
  const why = relationIntentVectorMagma('WHY');
  assert.equal(why.causal, 5);
  assert.equal(why.temporal, 0.5);
  assert.equal(Object.isFrozen(why), true);
  const custom = relationIntentVectorMagma('WHY', { causal: 1.25, temporal: -1, unknown: 99 });
  assert.equal(custom.causal, 1.25);
  assert.equal(custom.temporal, 0.5);
  assert.deepEqual(Object.keys(custom).sort(), ['causal', 'entity', 'semantic', 'temporal']);
});

test('Algorithm 1 beam traversal reaches multi-hop evidence with cumulative exact scores', () => {
  const graph = buildMagmaGraph({ nodes: fixtureNodes(), edges: fixtureEdges() });
  const weights = { semantic: 0, temporal: 0, causal: 1, entity: 0 };
  const transition = Math.exp(1);
  const traversal = adaptiveMagmaBeamTraversal({
    graph,
    anchors: [{ id: 'a', score: 0.25 }],
    queryEmbedding: [0, 0],
    intent: 'WHY',
    intentWeights: weights,
    lambdaStructure: 1,
    lambdaSemantic: 0,
    maxDepth: 5,
    beamWidth: 1,
    budget: 3,
  });
  assert.deepEqual(traversal.selected.map((entry) => entry.id), ['a', 'b', 'c']);
  assert.ok(Math.abs(traversal.selected[1].cumulative_score - (0.25 + transition)) < 1e-12);
  assert.ok(Math.abs(traversal.selected[2].cumulative_score - (0.25 + transition + transition)) < 1e-12);
  assert.deepEqual(traversal.selected[2].path_edge_ids, ['cause-ab', 'cause-bc']);
  assert.equal(traversal.carry_policy, 'full_retention_additive_path_score');
  assert.equal(traversal.termination_reason, 'budget_reached');
});

test('beam traversal rejects cycles, applies depth/beam/budget caps, and is deterministic', () => {
  const graph = buildMagmaGraph({
    nodes: fixtureNodes(),
    edges: [
      ...fixtureEdges(),
      { id: 'cycle-ca', source_id: 'c', target_id: 'a', relation: 'causal' },
    ],
  });
  const input = {
    graph,
    anchors: [{ id: 'a', score: 1 }],
    queryEmbedding: [1, 0],
    intent: 'WHY',
    maxDepth: 500,
    beamWidth: 500,
    budget: 500,
  };
  const first = adaptiveMagmaBeamTraversal(input);
  const second = adaptiveMagmaBeamTraversal(input);
  assert.deepEqual(first, second);
  assert.equal(first.visited_ids.length, new Set(first.visited_ids).size);
  assert.ok(first.trace.length <= MAGMA_CONSTANTS.max_depth);
  assert.ok(first.visited_ids.length <= MAGMA_CONSTANTS.max_nodes);
  assert.ok(first.trace.some((row) => row.cycle_rejections > 0));

  const anchorBudget = adaptiveMagmaBeamTraversal({ graph, anchors: ['a', 'b'], budget: 1 });
  assert.deepEqual(anchorBudget.visited_ids, ['a']);
  assert.equal(anchorBudget.termination_reason, 'budget_reached');
});

test('temporal linearization is chronological and preserves every selected reference', () => {
  const graph = buildMagmaGraph({ nodes: fixtureNodes(), edges: fixtureEdges() });
  const result = linearizeMagmaGraph({ graph, selectedIds: ['c', 'a', 'b'], intent: 'WHEN' });
  assert.deepEqual(result.ordered_nodes.map((node) => node.id), ['a', 'b', 'c']);
  assert.equal(result.cycle_detected, false);
  assert.match(result.context, /<ref:ref-a>/);
  assert.match(result.context, /<ref:ref-b>/);
  assert.match(result.context, /<ref:ref-c>/);
});

test('causal linearization is topological and reports cycles explicitly', () => {
  const acyclic = buildMagmaGraph({ nodes: fixtureNodes(), edges: fixtureEdges() });
  const ordered = linearizeMagmaGraph({ graph: acyclic, selectedIds: ['c', 'b', 'a'], intent: 'WHY' });
  assert.deepEqual(ordered.ordered_nodes.map((node) => node.id), ['a', 'b', 'c']);
  assert.equal(ordered.cycle_detected, false);

  const cyclic = buildMagmaGraph({
    nodes: fixtureNodes(),
    edges: [
      { id: 'ab', source_id: 'a', target_id: 'b', relation: 'causal' },
      { id: 'ba', source_id: 'b', target_id: 'a', relation: 'causal' },
    ],
  });
  const cycleResult = linearizeMagmaGraph({ graph: cyclic, selectedIds: ['a', 'b'], intent: 'WHY' });
  assert.equal(cycleResult.cycle_detected, true);
  assert.deepEqual(cycleResult.cycle_node_ids, ['a', 'b']);
  assert.equal(cycleResult.ordered_nodes.length, 2);
});

test('native mathematical kernel remains injected-evidence-only and provenance-addressable', () => {
  const nodes = fixtureNodes();
  const edges = fixtureEdges();
  const before = { nodes: structuredClone(nodes), edges: structuredClone(edges) };
  const first = runMagmaRetrievalKernel({
    nodes,
    edges,
    vectorRanks: ['a', 'd'],
    lexicalRanks: ['a', 'b'],
    temporalRanks: ['b', 'a'],
    queryEmbedding: [1, 0],
    intent: 'WHY',
    topK: 1,
    maxDepth: 5,
    beamWidth: 2,
    budget: 4,
  });
  const second = runMagmaRetrievalKernel({
    nodes,
    edges,
    vectorRanks: ['a', 'd'],
    lexicalRanks: ['a', 'b'],
    temporalRanks: ['b', 'a'],
    queryEmbedding: [1, 0],
    intent: 'WHY',
    topK: 1,
    maxDepth: 5,
    beamWidth: 2,
    budget: 4,
  });
  assert.deepEqual(first, second);
  assert.deepEqual(nodes, before.nodes);
  assert.deepEqual(edges, before.edges);
  assert.equal(first.guardrails.injected_evidence_only, true);
  assert.equal(first.guardrails.accesses_database_in_pure_kernel, false);
  assert.ok(first.linearization.ordered_nodes.every((node) => first.linearization.context.includes(`<ref:${node.reference_id}>`)));
  assert.equal(first.implementation_profile.paper_faithful.length, 4);
  assert.equal(first.implementation_profile.deferred.length, 2);
});

test('associative diagnostic accumulates without loss, persistence, ranking, or PPR changes', () => {
  const source = { id: 'a', key: 'a', table: 'aimos_memories' };
  const target = { id: 'b', key: 'b', table: 'aimos_memories' };
  const [candidate] = buildBoundedAssociativeEdgeCandidates([
    { source, target, confidence: 0.8, edge_type: 'causal', graph_view: 'causal', source_metadata: { table: 'concept_edges' } },
  ]);
  assert.equal(candidate.observed_strength, 0.8);
  assert.equal(candidate.hebbian_strength, 0.95);
  assert.ok(candidate.hebbian_strength >= candidate.observed_strength);
  assert.equal(candidate.persistence_changed, false);
  assert.equal(candidate.ranking_math_changed, false);
  assert.equal(candidate.ppr_math_changed, false);
});

test('legacy lineage reader retains its injected read-only no-anchor boundary', async () => {
  const calls = [];
  const queryFn = async (statement, params) => {
    calls.push({ statement, params });
    return { rows: [] };
  };
  const result = await retrieveMagmaLineage({
    queryText: 'causal temporal entity semantic lineage',
    companyId: 'hom',
    agentId: 'auditor',
    queryFn,
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0].statement.trim(), /^SELECT\b/i);
  assert.equal(calls[0].params[0], 'hom');
  assert.deepEqual(result.memories, []);
  assert.equal(result.diagnostics.fallback_reason, 'no_anchor_nodes');
});

test('source has no environment authority and pure kernel declares all retention boundaries', () => {
  const source = readFileSync(new URL('../../services/retrieval/magma-lineage-retriever.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /HELA_MEM_DECAY|\(1\s*-\s*lambda\)/);
  assert.equal(MAGMA_GUARDRAILS.native_retrieval_kernel, true);
  assert.equal(MAGMA_GUARDRAILS.dormant, false);
  assert.equal(MAGMA_GUARDRAILS.uses_environment_authority, false);
  assert.equal(MAGMA_GUARDRAILS.accesses_database_in_pure_kernel, false);
  assert.equal(MAGMA_GUARDRAILS.applies_decay, false);
  assert.equal(MAGMA_GUARDRAILS.deletes_memory, false);
  assert.equal(MAGMA_GUARDRAILS.suppresses_memory, false);
});
