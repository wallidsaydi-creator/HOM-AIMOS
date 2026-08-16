import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MNEMIS_GROUNDED_SYSTEM1_CONTRACT,
  buildMnemisGroundedScope,
  rankMnemisGroundedSystem1,
} from '../../services/retrieval/mnemis-grounded-system1-candidate.js';

const HASH = 'a'.repeat(64);

function memory(id, value, embedding) {
  return {
    id,
    value,
    created_at: '2026-08-01T00:00:00.000Z',
    embedding,
    content_hash: HASH,
    provenance_proof: { live_content_hash: HASH },
    canary_admitted: true,
  };
}

function fixture() {
  return [
    memory('a', 'Alice joined Project Quasar after a security review.', [1, 0, 0]),
    memory('b', 'Alice documented a cryptographic provenance audit.', [0.9, 0.1, 0]),
    memory('c', 'Caroline visited Berlin for an art exhibition.', [0, 0, 1]),
  ];
}

test('grounded scope requires canonical provenance, Canary admission, and finite embeddings', () => {
  assert.throws(() => buildMnemisGroundedScope([]), /scope_required/);
  assert.throws(() => buildMnemisGroundedScope([{ ...fixture()[0], provenance_proof: null }]), /canonical_provenance_required/);
  assert.throws(() => buildMnemisGroundedScope([{ ...fixture()[0], canary_admitted: false }]), /canary_admission_required/);
  assert.throws(() => buildMnemisGroundedScope([{ ...fixture()[0], embedding: null }]), /scope_embedding_invalid/);
});

test('grounded graph derives every entity and edge from admitted Episodes', () => {
  const scope = buildMnemisGroundedScope(fixture());
  assert.equal(scope.diagnostics.sources, 3);
  assert.equal(scope.diagnostics.episodes, 3);
  assert.ok(scope.diagnostics.entities > 0);
  assert.ok(scope.diagnostics.edges > 0);
  assert.equal(scope.diagnostics.unsupported_entities, 0);
  assert.equal(scope.diagnostics.unsupported_edges, 0);
  assert.ok(scope.hierarchy.categories.length > 0);
  assert.match(scope.graph_sha256, /^[a-f0-9]{64}$/);
  assert.ok(scope.graph.entities.some((entity) => Array.isArray(entity.embedding)));
  assert.ok(scope.graph.edges.every((edge) => Array.isArray(edge.embedding)));
});

test('System-1 candidate is deterministic and System-2 has zero rank influence', () => {
  const memories = fixture();
  const scope = buildMnemisGroundedScope(memories);
  const input = {
    scope,
    queryText: 'Alice security provenance',
    queryEmbedding: [1, 0, 0],
    baselineMemories: [memories[2], memories[0]],
    limit: 3,
  };
  const first = rankMnemisGroundedSystem1(input);
  const second = rankMnemisGroundedSystem1(input);
  assert.deepEqual(first, second);
  assert.equal(first.decision.system2_rank_influence, 0);
  assert.equal(first.diagnostics.system2_is_unordered, true);
  assert.ok(first.memories.some((row) => row.mnemis_graph_only));
  assert.ok(first.memories.every((row) => scope.memoryById.has(row.id)));
  assert.equal(first.diagnostics.unsupported_entity_ratio, 0);
  assert.equal(first.diagnostics.unsupported_edge_ratio, 0);
});

test('candidate rejects baseline identities outside the admitted scope', () => {
  const scope = buildMnemisGroundedScope(fixture());
  assert.throws(() => rankMnemisGroundedSystem1({
    scope,
    queryText: 'security',
    queryEmbedding: [1, 0, 0],
    baselineMemories: [memory('outside', 'Outside retained memory.', [1, 0, 0])],
  }), /baseline_outside_admitted_scope/);
});

test('candidate contains no database, network, environment, model, or persistence authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/mnemis-grounded-system1-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+aimos_memories|DELETE\s+FROM/i);
  assert.equal(MNEMIS_GROUNDED_SYSTEM1_CONTRACT.environment_authority, false);
  assert.equal(MNEMIS_GROUNDED_SYSTEM1_CONTRACT.database_access, false);
  assert.equal(MNEMIS_GROUNDED_SYSTEM1_CONTRACT.graph_persistence, false);
  assert.equal(MNEMIS_GROUNDED_SYSTEM1_CONTRACT.model_authority, false);
});
