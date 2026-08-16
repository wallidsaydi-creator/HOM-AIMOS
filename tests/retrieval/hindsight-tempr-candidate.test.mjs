import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  TEMPR_D_GUARDRAILS,
  rerankHindsightTemprDeterministic,
} from '../../services/retrieval/hindsight-tempr-candidate.js';

function memories() {
  return [
    {
      id: 'a', key: 'first', value: 'Alice met Bob in Rome.', embedding: [1, 0],
      entities: ['Alice', 'Bob'], created_at: '2026-01-01T00:00:00.000Z',
      provenance_proof: { binding_event_id: 'proof-a' },
    },
    {
      id: 'b', key: 'second', value: 'Bob later founded Acme.', embedding: [0.8, 0.2],
      entities: ['Bob', 'Acme'], created_at: '2026-01-02T00:00:00.000Z',
      provenance_proof: { binding_event_id: 'proof-b' },
    },
    {
      id: 'c', key: 'third', value: 'Gardening notes for Sunday.', embedding: [0, 1],
      entities: ['Garden'], created_at: '2026-02-01T00:00:00.000Z',
      provenance_proof: { binding_event_id: 'proof-c' },
    },
  ];
}

test('TEMPR-D is deterministic, actionable, and exact-set preserving', () => {
  const input = memories();
  const before = structuredClone(input);
  const args = { queryText: 'Who founded Acme?', queryEmbedding: [1, 0], memories: input };
  const first = rerankHindsightTemprDeterministic(args);
  const second = rerankHindsightTemprDeterministic(args);

  assert.deepEqual(first, second);
  assert.deepEqual(input, before);
  assert.deepEqual(first.ranked.map((row) => row.id).sort(), ['a', 'b', 'c']);
  assert.equal(first.decision.input_set_sha256, first.decision.output_set_sha256);
  assert.equal(first.diagnostics.exact_candidate_set_preserved, true);
  assert.equal(first.guardrails.dormant, true);
});

test('TEMPR-D rejects unadmitted, duplicate, and malformed inputs', () => {
  assert.throws(
    () => rerankHindsightTemprDeterministic({ queryText: 'query', queryEmbedding: [1], memories: [{ id: 'x', value: 'text', embedding: [1] }] }),
    /unadmitted_memory/,
  );
  const duplicate = memories();
  duplicate[1] = { ...duplicate[1], id: 'a' };
  assert.throws(
    () => rerankHindsightTemprDeterministic({ queryText: 'query', queryEmbedding: [1, 0], memories: duplicate }),
    /duplicate_memory_id/,
  );
  assert.throws(() => rerankHindsightTemprDeterministic(), /query_text_required/);
});

test('TEMPR-D source owns no database, environment, server, or persistence path', () => {
  const source = readFileSync(new URL('../../services/retrieval/hindsight-tempr-candidate.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+aimos_|DELETE\s+FROM/i);
  assert.equal(TEMPR_D_GUARDRAILS.uses_database, false);
  assert.equal(TEMPR_D_GUARDRAILS.uses_environment_authority, false);
  assert.equal(TEMPR_D_GUARDRAILS.mutates_memory, false);
  assert.equal(TEMPR_D_GUARDRAILS.persists_opinions, false);
});

