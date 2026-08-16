import test from 'node:test';
import assert from 'node:assert/strict';

import { redactAimosValue } from '../../services/write/persist-memory.js';
import { detectCanaries } from '../../services/security/canary-tracker.js';

test('nested Canary evidence is serialized faithfully before retained persistence', () => {
  const value = {
    summary: 'Signed cross-transport evidence remains retained.',
    evidence: { marker: 'SECRET-DEADBEEF', disposition: 'retained quarantine' },
  };
  const rendered = redactAimosValue(value);
  assert.deepEqual(JSON.parse(rendered), value);
  assert.deepEqual(detectCanaries(rendered), ['SECRET-DEADBEEF']);
  assert.notEqual(rendered, '[object Object]');
});

test('credential redaction remains exact for object-valued saves', () => {
  const rendered = redactAimosValue({ access_token: 'a'.repeat(24), note: 'retained reference' });
  const parsed = JSON.parse(rendered);
  assert.equal(parsed.access_token, '[REDACTED]');
  assert.equal(parsed.note, 'retained reference');
});
