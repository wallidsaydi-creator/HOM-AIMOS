import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  HAGE_D_CONTRACT,
  rerankHageDeterministic,
} from '../../services/retrieval/hage-native-candidate/deterministic-reranker.js';

const memory = (id, value, embedding, createdAt = '2026-01-01T00:00:00.000Z') => ({
  id,
  value,
  embedding,
  created_at: createdAt,
});

function fixture() {
  return [
    memory('a', 'Alice project bridge evidence', [1, 0, 0]),
    memory('b', 'unrelated cooking note', [0.5, 0.8660254038, 0]),
    memory('c', 'Alice project final evidence', [0.96, 0.28, 0]),
  ];
}

test('HAGE-D owns no runtime authority and preserves full retention', () => {
  assert.equal(HAGE_D_CONTRACT.identity, 'HAGE-inspired deterministic proxy');
  assert.equal(HAGE_D_CONTRACT.environment_authority, false);
  assert.equal(HAGE_D_CONTRACT.database_authority, false);
  assert.equal(HAGE_D_CONTRACT.persistence_authority, false);
  assert.equal(HAGE_D_CONTRACT.disclosure_authority, false);
  assert.equal(HAGE_D_CONTRACT.saber_runtime_authority, false);
  assert.equal(HAGE_D_CONTRACT.changes_candidate_set, false);
  assert.equal(HAGE_D_CONTRACT.applies_decay, false);
  assert.equal(HAGE_D_CONTRACT.deletes_memory, false);
  assert.equal(HAGE_D_CONTRACT.suppresses_memory, false);
});

test('HAGE-D is deterministic, immutable, and preserves the exact MAGMA set', () => {
  const memories = fixture();
  const before = structuredClone(memories);
  const first = rerankHageDeterministic({ queryText: 'Alice project evidence', queryEmbedding: [1, 0, 0], memories });
  const second = rerankHageDeterministic({ queryText: 'Alice project evidence', queryEmbedding: [1, 0, 0], memories });
  assert.deepEqual(first, second);
  assert.deepEqual(memories, before);
  assert.deepEqual(new Set(first.ranked.map((row) => row.id)), new Set(memories.map((row) => row.id)));
  assert.equal(first.ranked.length, memories.length);
  assert.equal(first.decision.candidate_set_preserved, true);
  assert.match(first.decision.graph_commitment_sha256, /^[0-9a-f]{64}$/);
  assert.match(first.decision.decision_sha256, /^[0-9a-f]{64}$/);
});

test('HAGE-D propagates relational bridge evidence without inventing a node', () => {
  const result = rerankHageDeterministic({
    queryText: 'Alice project evidence',
    queryEmbedding: [1, 0, 0],
    memories: fixture(),
  });
  const bridgeTarget = result.ranked.find((row) => row.id === 'c');
  assert.ok(bridgeTarget.propagated_signal > 0);
  assert.ok(result.diagnostics.graph_edges > 0);
  assert.equal(result.ranked.every((row) => ['a', 'b', 'c'].includes(row.id)), true);
});

test('HAGE-D temporal contribution is exactly zero for a non-temporal query', () => {
  const result = rerankHageDeterministic({
    queryText: 'Alice project evidence',
    queryEmbedding: [1, 0, 0],
    memories: fixture(),
  });
  assert.equal(result.diagnostics.temporal_enabled, false);
  assert.equal(result.diagnostics.temporal_edge_contribution_count, 0);
});

test('HAGE-D enables bounded temporal evidence only for a temporal query', () => {
  const memories = fixture().map((row, index) => ({
    ...row,
    created_at: `2026-01-0${index + 1}T00:00:00.000Z`,
  }));
  const result = rerankHageDeterministic({
    queryText: 'When did Alice work on the project?',
    queryEmbedding: [1, 0, 0],
    memories,
  });
  assert.equal(result.diagnostics.temporal_enabled, true);
  assert.ok(result.diagnostics.temporal_edge_contribution_count > 0);
});

test('HAGE-D enforces node and edge caps', () => {
  const memories = Array.from({ length: HAGE_D_CONTRACT.maximum_nodes }, (_, index) =>
    memory(`id-${index}`, 'shared evidence', [1, 0]));
  const result = rerankHageDeterministic({ queryText: 'shared evidence', queryEmbedding: [1, 0], memories });
  assert.ok(result.diagnostics.graph_edges <= HAGE_D_CONTRACT.maximum_nodes * HAGE_D_CONTRACT.maximum_edges_per_node);
  assert.throws(() => rerankHageDeterministic({
    queryText: 'shared evidence',
    queryEmbedding: [1, 0],
    memories: [...memories, memory('overflow', 'shared evidence', [1, 0])],
  }), /node_cap_exceeded/);
});

test('HAGE-D fails closed on malformed identifiers and embeddings', () => {
  assert.throws(() => rerankHageDeterministic({
    queryText: 'query',
    queryEmbedding: [1, 0],
    memories: [memory('a', 'one', [1, 0]), memory('a', 'two', [0, 1])],
  }), /memory_id_invalid/);
  assert.throws(() => rerankHageDeterministic({
    queryText: 'query',
    queryEmbedding: [1, 0],
    memories: [memory('a', 'one', [1, 0]), memory('b', 'two', [1])],
  }), /memory_embedding_1_dimension/);
});

test('HAGE-D source contains no environment, database-write, or deletion authority', async () => {
  const source = await readFile(
    new URL('../../services/retrieval/hage-native-candidate/deterministic-reranker.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /process\.env|dotenv|Deno\.env|Bun\.env/);
  assert.doesNotMatch(source, /\b(?:INSERT\s+INTO|UPDATE\s+aimos_|DELETE\s+FROM|TRUNCATE\s+)\b/i);
  assert.doesNotMatch(source, /\b(?:unlink|rmSync|rmdir|expires_at|decay_factor)\b/);
});

