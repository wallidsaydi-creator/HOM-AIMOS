import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildDenseHierarchicalMemory,
  hmemDenseCandidate,
  recursiveDenseTopK,
} from '../../services/retrieval/hmem-hierarchical-reasoning.js';

const vectors = new Map([
  ['car', [1, 0, 0]],
  ['automobile', [1, 0, 0]],
  ['database', [0, 1, 0]],
]);

function embedText(text) {
  const value = String(text || '').toLowerCase();
  if (value.includes('car') || value.includes('automobile') || value.includes('vehicle')) return vectors.get('car');
  if (value.includes('database') || value.includes('security')) return vectors.get('database');
  return [0, 0, 1];
}

function fixtureStates() {
  return [
    {
      id: 'm-car',
      text: 'The preferred vehicle is a car',
      embedding: [1, 0, 0],
      memory: { session_id: 's1', source: 'chat', memory_type: 'preference', key: 'preference:vehicle' },
    },
    {
      id: 'm-db',
      text: 'Database encryption protects records',
      embedding: [0, 1, 0],
      memory: { session_id: 's2', source: 'paper', memory_type: 'fact', key: 'security:database' },
    },
  ];
}

test('H-MEM dense hierarchy uses supplied content embeddings and injected parent embeddings', async () => {
  const states = fixtureStates();
  const snapshot = structuredClone(states);
  const hierarchy = await buildDenseHierarchicalMemory(states, { embedText, expectedDimension: 3 });

  assert.deepEqual(states, snapshot);
  assert.deepEqual(hierarchy.levels.content[0].vector, [1, 0, 0]);
  assert.equal(hierarchy.levels.section.every((node) => node.vector.length === 3), true);
  assert.deepEqual(hierarchy.vector_contract, {
    representation: 'dense_unit_vector',
    dimension: 3,
    training_required: false,
    hierarchy_source: 'aimos_deterministic_heuristic',
    paper_hierarchy_parity: false,
    index_backend: 'in_memory_exact_sort',
    paper_faiss_parity: false,
  });
});

test('H-MEM dense routing resolves semantic equivalence missed by lexical identity', async () => {
  const candidate = await hmemDenseCandidate({
    queryVector: vectors.get('automobile'),
    states: fixtureStates(),
    embedText,
    expectedDimension: 3,
    topK: 1,
  });

  assert.deepEqual(candidate.selected_memory_ids, ['m-car']);
  assert.equal(candidate.ranked[0].cosine_similarity, 1);
  assert.equal(candidate.ranked[0].confidence_reference, 1);
  assert.equal(candidate.vector_contract.training_required, false);
  assert.equal(candidate.guardrails.applies_decay, false);
  assert.equal(candidate.guardrails.deletes_memory, false);
});

test('H-MEM dense routing ignores positional indices during similarity', async () => {
  const hierarchy = await buildDenseHierarchicalMemory(fixtureStates(), { embedText, expectedDimension: 3 });
  const first = recursiveDenseTopK([1, 0, 0], hierarchy.roots, 1, { expectedDimension: 3 });
  for (const level of Object.values(hierarchy.levels)) {
    for (const node of level) node.position_index = [999_999];
  }
  const second = recursiveDenseTopK([1, 0, 0], hierarchy.roots, 1, { expectedDimension: 3 });
  assert.deepEqual(
    first.map((row) => [row.node.id, row.score]),
    second.map((row) => [row.node.id, row.score]),
  );
});

test('H-MEM dense routing fails closed on missing or malformed vectors', async () => {
  await assert.rejects(
    buildDenseHierarchicalMemory(fixtureStates(), { expectedDimension: 3 }),
    /hmem_dense_embedder_required/,
  );
  await assert.rejects(
    hmemDenseCandidate({
      queryVector: [1, 0],
      states: fixtureStates(),
      embedText,
      expectedDimension: 3,
    }),
    /hmem_dense_query_vector_invalid/,
  );
  assert.throws(
    () => recursiveDenseTopK([1, 0, 0], [{ id: 'bad', vector: [1, 0], children: [] }], 1, { expectedDimension: 3 }),
    /hmem_dense_node_vector_invalid:bad/,
  );
});
