import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildOccurrenceSessionBindingV1,
  verifyOccurrenceSessionBindingV1,
} from '../../services/security/protocol/occurrence-session-binding-v1.js';

const input = Object.freeze({
  company_id: 'hom',
  memory_id: '11111111-1111-4111-8111-111111111111',
  occurrence_event_id: '22222222-2222-4222-8222-222222222222',
  occurrence_commitment: 'a'.repeat(64),
  request_body_sha256: 'b'.repeat(64),
  session_id: 'longmemeval-s:0123456789abcdef',
  source_dataset_sha256: 'c'.repeat(64),
  source_session_sha256: 'd'.repeat(64),
  source_session_ordinal: 17,
});

test('occurrence session binding is deterministic, prefix-free, and self-verifying', () => {
  const first = buildOccurrenceSessionBindingV1(input);
  const second = buildOccurrenceSessionBindingV1({ ...input });
  assert.deepEqual(first, second);
  assert.match(first.binding_sha256, /^[0-9a-f]{64}$/);
  assert.equal(verifyOccurrenceSessionBindingV1(first).valid, true);
});

test('occurrence session binding rejects substitution and unsafe ordinal input', () => {
  const value = buildOccurrenceSessionBindingV1(input);
  assert.equal(verifyOccurrenceSessionBindingV1({ ...value, session_id: 'substituted' }).valid, false);
  assert.throws(
    () => buildOccurrenceSessionBindingV1({ ...input, source_session_ordinal: Number.MAX_SAFE_INTEGER + 1 }),
    /occurrence_session_binding_v1_encoding_invalid/,
  );
});
