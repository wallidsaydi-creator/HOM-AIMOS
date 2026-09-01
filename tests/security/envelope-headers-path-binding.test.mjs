import assert from 'node:assert/strict';
import test from 'node:test';

import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';

test('canonical envelope builder keeps filesystem path ownership distinct from request path', async () => {
  await assert.rejects(
    buildEnvelopeHeaders('__missing_envelope_test_identity__', 'POST', '/aimos/recall', {}),
    (error) => {
      assert.match(String(error?.message || ''), /loadAgentPrivkey: key not found/);
      assert.doesNotMatch(String(error?.message || ''), /path\.join is not a function/);
      return true;
    },
  );
});
