import test from 'node:test';
import assert from 'node:assert/strict';

import { extractValidFromIso } from '../../services/security/housekeeper-signer.js';

test('housekeeper epoch extraction reads the signed certificate body', () => {
  const cert = Buffer.from(JSON.stringify({
    body: { agent_id: 'housekeeper', valid_from: 1_783_701_741 }
  })).toString('base64url');
  assert.equal(extractValidFromIso(cert), '2026-07-10T16:42:21.000Z');
});

test('housekeeper epoch extraction fails closed when the claim is absent', () => {
  const cert = Buffer.from(JSON.stringify({ body: { agent_id: 'housekeeper' } })).toString('base64url');
  assert.throws(() => extractValidFromIso(cert), /no parseable valid_from/);
});
