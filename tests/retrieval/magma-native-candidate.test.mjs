import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  MAGMA_NATIVE_CANDIDATE_CONTRACT,
  composeMagmaNativeCandidate,
} from '../../services/retrieval/magma-native-candidate.js';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const D = '44444444-4444-4444-8444-444444444444';
const E = '55555555-5555-4555-8555-555555555555';
const F = '66666666-6666-4666-8666-666666666666';
const G = '77777777-7777-4777-8777-777777777777';
const H = '88888888-8888-4888-8888-888888888888';
const I = '99999999-9999-4999-8999-999999999999';

const proof = Object.freeze({ version_status: 'current', binding_event_id: 'binding' });
const memory = (id, value, embedding, createdAt) => ({
  id,
  key: `memory:${id}`,
  value,
  embedding,
  created_at: createdAt,
  source: 'fixture',
  memory_type: 'session',
  data_class: 'public',
  provenance_proof: proof,
});

test('MAGMA native candidate is a permanent non-owning gear with no runtime mode', () => {
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.native_retrieval_gear, true);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.runtime_mode, false);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.canonical_caller, 'native-recall-pipeline');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.architecture_authority, 'code_and_manifest_bound_native_retrieval');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.calibration_authority, 'master_signed_system_config_optional_override');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.execution_authority, 'verified_agent_or_role_identity_envelope');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.governance_owner, 'housekeeper');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.maximum_frontier_width, 5);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.maximum_nodes, 200);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.maximum_graph_result_budget, 50);
  assert.equal(
    MAGMA_NATIVE_CANDIDATE_CONTRACT.graph_baseline_capacity_rule,
    'max_nodes_minus_result_budget',
  );
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.maximum_incremental_output_candidates, 50);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.candidate_set_authority, false);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.output_policy, 'rank_evidence_for_central_native_rrf');
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.grant_authority, false);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.disclosure_authority, false);
  assert.equal(MAGMA_NATIVE_CANDIDATE_CONTRACT.saber_runtime_authority, false);
});

test('MAGMA native candidate expands only through provenance-admitted endpoints', async () => {
  const memories = new Map([
    [B, memory(B, 'bridge evidence', [0.9, 0.1], '2026-01-02T00:00:00.000Z')],
    [C, memory(C, 'answer evidence', [1, 0], '2026-01-03T00:00:00.000Z')],
  ]);
  const result = await composeMagmaNativeCandidate({
    recallAuthority: { companyId: 'hom' },
    admittedMemories: [memory(A, 'query anchor', [1, 0], '2026-01-01T00:00:00.000Z')],
    queryEmbedding: [1, 0],
    queryText: 'why answer evidence',
    limit: 3,
    maxDepth: 3,
    readTopologyFn: async ({ frontierIds }) => {
      if (frontierIds.includes(A)) {
        return { edges: [{ relation: 'semantic', source_id: A, target_id: B, qualifier: null }], decision: { depth: 0 } };
      }
      if (frontierIds.includes(B)) {
        return { edges: [{ relation: 'entity', source_id: B, target_id: C, qualifier: 'answer' }], decision: { depth: 1 } };
      }
      return { edges: [], decision: { depth: 2 } };
    },
    readEvidenceFn: async ({ candidateIds }) => ({
      memories: candidateIds.map((id) => memories.get(id)).filter(Boolean),
      decision: { admitted: candidateIds.length },
    }),
  });

  assert.deepEqual(new Set(result.ranks.map((row) => row.id)), new Set([A, B, C]));
  assert.deepEqual(new Set(result.discovered_memories.map((row) => row.id)), new Set([B, C]));
  assert.match(result.decision.edge_commitment_sha256, /^[0-9a-f]{64}$/);
  assert.match(result.decision.decision_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(result.decision.traversal_selected_memory_ids, result.ranks.map((row) => row.id));
  assert.equal(result.decision.discovered_count, 2);
  assert.equal(result.decision.graph_nodes, 3);
  assert.equal(result.decision.graph_edges, 2);
  assert.equal(result.decision.canonical_memory_mutated, false);
});

test('MAGMA native gear emits only bounded ranks and never assumes baseline ownership', async () => {
  const admitted = [A, B, C, D, E, F, G, H].map((id, index) => memory(
    id,
    `baseline evidence ${index}`,
    [1, index / 10],
    `2026-01-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`,
  ));
  const result = await composeMagmaNativeCandidate({
    recallAuthority: { companyId: 'hom' },
    admittedMemories: admitted,
    queryEmbedding: [1, 0],
    queryText: 'baseline evidence',
    limit: 8,
    readTopologyFn: async () => ({ edges: [], decision: { empty: true } }),
    readEvidenceFn: async () => ({ memories: [], decision: { admitted: 0 } }),
  });

  assert.equal(result.ranks.length, 5);
  assert.equal(result.discovered_memories.length, 0);
  assert.equal(result.decision.traversal_selected_count, 5);
  assert.deepEqual(result.decision.traversal_selected_memory_ids, result.ranks.map((row) => row.id));
  assert.equal(result.decision.canonical_memory_mutated, false);
  assert.equal(result.decision.retention_changed, false);
  assert.equal(result.decision.candidate_set_authority, false);
  assert.equal(result.decision.baseline_candidate_set_changed, false);
});

test('MAGMA native gear rank budget cannot truncate the centrally owned admitted baseline', async () => {
  const admitted = [A, B, C, D, E, F, G, H].map((id, index) => memory(
    id,
    `baseline evidence ${index}`,
    [1, index / 10],
    `2026-03-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`,
  ));
  const result = await composeMagmaNativeCandidate({
    recallAuthority: { companyId: 'hom' },
    admittedMemories: admitted,
    queryEmbedding: [1, 0],
    queryText: 'baseline evidence',
    limit: 3,
    readTopologyFn: async () => ({ edges: [], decision: { empty: true } }),
    readEvidenceFn: async () => ({ memories: [], decision: { admitted: 0 } }),
  });

  assert.equal(result.decision.graph_result_budget, 3);
  assert.ok(result.ranks.length <= 3);
  assert.equal(result.decision.initial_admitted_count, admitted.length);
  assert.equal(result.decision.baseline_candidate_set_changed, false);
  assert.equal(result.decision.candidate_set_authority, false);
});

test('MAGMA native candidate preserves a baseline above 200 while bounding its graph workspace', async () => {
  const admitted = Array.from({ length: 201 }, (_, index) => memory(
    `candidate-${String(index).padStart(3, '0')}`,
    `evidence ${index}`,
    [1, 0],
    '2026-01-01T00:00:00.000Z',
  ));
  const result = await composeMagmaNativeCandidate({
    recallAuthority: { companyId: 'hom' },
    admittedMemories: admitted,
    queryEmbedding: [1, 0],
    queryText: 'evidence',
    limit: 20,
    readTopologyFn: async () => ({ edges: [], decision: {} }),
    readEvidenceFn: async () => ({ memories: [], decision: {} }),
  });

  assert.ok(result.ranks.length <= 20);
  assert.equal(result.decision.initial_admitted_count, 201);
  assert.equal(result.decision.graph_workspace_baseline_count, 180);
  assert.equal(result.decision.graph_workspace_reserved_capacity, 20);
  assert.equal(result.decision.graph_admitted_count, 180);
  assert.equal(result.decision.maximum_graph_workspace_nodes, 200);
  assert.equal(result.decision.maximum_incremental_output_candidates, 20);
  assert.equal(result.decision.maximum_output_candidates, 221);
  assert.equal(result.decision.baseline_candidate_set_changed, false);
});

test('MAGMA native candidate bounds each next frontier to the paper beam width using Equation 5', async () => {
  const discovered = [
    [B, [1, 0]],
    [C, [0.98, 0.2]],
    [D, [0.9, 0.4]],
    [E, [0.8, 0.6]],
    [F, [0.7, 0.7]],
    [G, [0.4, 0.9]],
    [H, [0.2, 0.98]],
    [I, [0, 1]],
  ];
  const evidence = new Map(discovered.map(([id, embedding], index) => [
    id,
    memory(id, `discovered ${index}`, embedding, `2026-02-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`),
  ]));
  const observedFrontiers = [];
  const result = await composeMagmaNativeCandidate({
    recallAuthority: { companyId: 'hom' },
    admittedMemories: [memory(A, 'anchor', [1, 0], '2026-01-01T00:00:00.000Z')],
    queryEmbedding: [1, 0],
    queryText: 'semantic bridge',
    limit: 9,
    maxDepth: 2,
    readTopologyFn: async ({ frontierIds }) => {
      observedFrontiers.push([...frontierIds]);
      if (frontierIds.includes(A)) {
        return {
          edges: discovered.map(([id]) => ({ relation: 'semantic', source_id: A, target_id: id })),
          decision: { expanded: discovered.length },
        };
      }
      return { edges: [], decision: { expanded: 0 } };
    },
    readEvidenceFn: async ({ candidateIds }) => ({
      memories: candidateIds.map((id) => evidence.get(id)).filter(Boolean),
      decision: { admitted: candidateIds.length },
    }),
  });

  assert.equal(observedFrontiers.length, 2);
  assert.deepEqual(observedFrontiers[1], [B, C, D, E, F]);
  assert.deepEqual(result.decision.observed_frontier_widths, [1, 5]);
  assert.equal(Math.max(...result.decision.observed_frontier_widths), 5);
});

test('MAGMA native candidate rejects an unadmitted anchor and topology source', async () => {
  await assert.rejects(
    composeMagmaNativeCandidate({
      recallAuthority: { companyId: 'hom' },
      admittedMemories: [{ id: A, value: 'unsigned anchor', embedding: [1, 0] }],
      queryEmbedding: [1, 0],
      queryText: 'query',
    }),
    /magma_native_candidate:unadmitted_anchor/,
  );
  await assert.rejects(
    composeMagmaNativeCandidate({
      recallAuthority: { companyId: 'hom' },
      admittedMemories: [memory(A, 'anchor', [1, 0], '2026-01-01T00:00:00.000Z')],
      queryEmbedding: [1, 0],
      queryText: 'query',
      readTopologyFn: async () => ({
        edges: [{ relation: 'semantic', source_id: B, target_id: C }],
        decision: {},
      }),
    }),
    /magma_native_candidate:topology_source_not_admitted/,
  );
});

test('MAGMA native candidate source is side-effect free and retains downstream security ownership', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/magma-native-candidate.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /process\.env/);
  assert.doesNotMatch(source, /\b(?:INSERT\s+INTO|UPDATE\s+aimos_|DELETE\s+FROM|TRUNCATE\s+)\b/i);
  assert.doesNotMatch(source, /logEvent\(/);
  assert.match(source, /readMagmaNativeEvidence/);
  assert.match(source, /readMagmaNativeTopology/);
});
