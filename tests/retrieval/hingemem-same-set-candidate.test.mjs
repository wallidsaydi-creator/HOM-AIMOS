import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  HINGEMEM_R_GUARDRAILS,
  rerankHingeMemSameSet,
} from '../../services/retrieval/hingemem-same-set-candidate.js';

function memory(id, content, embedding, boundaryElements = {}, extra = {}) {
  return {
    id,
    key: `key:${id}`,
    value: JSON.stringify({ content, boundary_elements: boundaryElements }),
    embedding,
    source: 'fixed-scope',
    created_at: '2026-08-10T00:00:00.000Z',
    provenance_proof: { binding_event_id: `proof:${id}` },
    ...extra,
  };
}

function fixture() {
  return [
    memory('a', 'Routine project status meeting.', [0.5, 0.5], {
      person: ['Alice'], topic: ['routine project'], location: ['Office'],
    }),
    memory('b', 'Alice approved Project Quasar in Rome.', [1, 0], {
      person: ['Alice'], topic: ['project quasar'], location: ['Rome'],
    }),
    memory('c', 'Museum exhibition planning in Paris.', [0, 1], {
      person: ['Caroline'], topic: ['museum exhibition'], location: ['Paris'],
    }),
  ];
}

test('HingeMem-R is deterministic, actionable, and exact-set preserving', () => {
  const memories = fixture();
  const before = structuredClone(memories);
  const input = { queryText: 'Where did Alice approve Project Quasar?', queryEmbedding: [1, 0], memories };
  const first = rerankHingeMemSameSet(input);
  const second = rerankHingeMemSameSet(input);
  assert.deepEqual(first, second);
  assert.deepEqual(memories, before);
  assert.deepEqual(first.ranked.map((row) => row.id).sort(), ['a', 'b', 'c']);
  assert.equal(first.ranked[0].id, 'b');
  assert.ok(first.diagnostics.rank_changes > 0);
  assert.equal(first.decision.input_set_sha256, first.decision.output_set_sha256);
});

test('transient merge retains every admitted identity', () => {
  const memories = [
    memory('a', 'Alice approved Quasar.', [1, 0], { person: ['Alice'], topic: ['Quasar'] }),
    memory('b', 'Alice confirmed Quasar.', [0.9, 0.1], { person: ['Alice'], topic: ['Quasar'] }),
  ];
  const result = rerankHingeMemSameSet({ queryText: 'Alice Quasar', queryEmbedding: [1, 0], memories });
  assert.equal(result.diagnostics.hyperedge_count, 1);
  assert.deepEqual(result.ranked.map((row) => row.id).sort(), ['a', 'b']);
  assert.equal(result.decision.input_set_sha256, result.decision.output_set_sha256);
});

test('candidate rejects unadmitted, duplicate, malformed, and empty inputs', () => {
  const valid = fixture()[0];
  assert.throws(
    () => rerankHingeMemSameSet({ queryText: 'query', queryEmbedding: [1, 0], memories: [{ ...valid, provenance_proof: null }] }),
    /unadmitted_memory/,
  );
  assert.throws(
    () => rerankHingeMemSameSet({ queryText: 'query', queryEmbedding: [1, 0], memories: [valid, structuredClone(valid)] }),
    /duplicate_memory_id/,
  );
  assert.throws(
    () => rerankHingeMemSameSet({ queryText: 'query', queryEmbedding: [1, 0], memories: [{ ...valid, embedding: [1, Number.NaN] }] }),
    /memory_shape_invalid/,
  );
  assert.throws(() => rerankHingeMemSameSet({ queryText: '', queryEmbedding: [1, 0], memories: [valid] }), /query_text_required/);
  assert.throws(() => rerankHingeMemSameSet({ queryText: 'query', queryEmbedding: [], memories: [valid] }), /query_embedding_invalid/);
  assert.throws(() => rerankHingeMemSameSet({ queryText: 'query', queryEmbedding: [1, 0], memories: [] }), /memories_required/);
});

test('adaptive stop remains diagnostic and owns no disclosure authority', () => {
  const result = rerankHingeMemSameSet({
    queryText: 'Where did Alice approve Project Quasar?',
    queryEmbedding: [1, 0],
    memories: fixture(),
  });
  assert.equal(result.guardrails.adaptive_stop_diagnostic_only, true);
  assert.equal(result.guardrails.disclosure_authority, false);
  assert.equal(result.diagnostics.adaptive_stop_has_disclosure_authority, false);
  assert.equal(result.ranked.length, 3);
});

test('candidate source owns no database, server, network, persistence, or ENV path', () => {
  const source = readFileSync(new URL('../../services/retrieval/hingemem-same-set-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.match(source, /uses_environment_authority:\s*false/);
  assert.equal(HINGEMEM_R_GUARDRAILS.uses_database, false);
  assert.equal(HINGEMEM_R_GUARDRAILS.mutates_memory, false);
  assert.equal(HINGEMEM_R_GUARDRAILS.persists_hypergraph, false);
  assert.equal(HINGEMEM_R_GUARDRAILS.merges_canonical_memory, false);
});
