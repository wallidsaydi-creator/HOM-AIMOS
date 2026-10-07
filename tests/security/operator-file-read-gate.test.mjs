import test from 'node:test';
import assert from 'node:assert/strict';

import { inspectOperatorFileReadRequest } from '../../services/security/operator-file-read-gate.js';

const epoch = '2026-10-06T12:00:00.000Z';
const filepath = '/private/tmp/owner-only/report.txt';
const proof = Object.freeze({ body: Object.freeze({
  company_id: 'hom', subject_agent_id: 'operator',
  subject_valid_from: epoch, target_file: filepath,
}) });
const authority = Object.freeze({
  actorAgentId: 'operator', actorValidFromIso: epoch, companyId: 'hom',
  authSource: 'envelope', identityTier: 'T1',
  signedMethod: 'POST', signedPath: '/tools/files/read',
  requestReceiptId: '8ddcf181-364f-4fba-ae0c-13bc9fdaf5f1',
  requestReceiptMutationHash: 'a'.repeat(64),
});
const base = Object.freeze({
  authority, requestAgentId: 'operator', operatorAgentId: 'operator',
  originalUrl: '/tools/files/read',
  body: { filepath, purpose_authorization: proof },
});

test('operator file-read admission forwards only the exact signed actor epoch and verified grant clearance', async () => {
  const calls = [];
  const result = await inspectOperatorFileReadRequest({
    ...base,
    getGrant: async (query) => { calls.push(query); return { allowed: true, clearanceCeiling: 10 }; },
  });
  assert.equal(result.ok, true);
  assert.equal(result.actor, 'operator');
  assert.equal(result.filepath, filepath);
  assert.equal(result.purposeAuthorization, proof);
  assert.equal(result.clearanceLevel, 10);
  assert.deepEqual(calls, [{ companyId: 'hom', subjectAgentId: 'operator', subjectValidFrom: epoch }]);
});

test('wrong actor, certificate epoch, method, path, body, target, and missing operator fail before grant lookup', async () => {
  const variants = [
    { requestAgentId: 'other-agent' },
    { operatorAgentId: null },
    { authority: { ...authority, actorAgentId: 'other-agent' } },
    { authority: { ...authority, actorValidFromIso: '2026-10-06T12:01:00.000Z' } },
    { authority: { ...authority, signedMethod: 'GET' } },
    { authority: { ...authority, signedPath: '/tools/other' } },
    { authority: { ...authority, requestReceiptMutationHash: null } },
    { originalUrl: '/tools/files/read?x=1' },
    { body: { filepath, purpose_authorization: proof, extra: true } },
    { body: { filepath: '/private/tmp/owner-only/other.txt', purpose_authorization: proof } },
  ];
  for (const variant of variants) {
    let grantRead = false;
    const result = await inspectOperatorFileReadRequest({
      ...base, ...variant,
      getGrant: async () => { grantRead = true; return { allowed: true, clearanceCeiling: 10 }; },
    });
    assert.equal(result.ok, false, JSON.stringify(variant));
    assert.equal(grantRead, false, JSON.stringify(variant));
  }
});

test('no grant, insufficient clearance, and unavailable grant fail closed', async () => {
  for (const grant of [null, { allowed: false, clearanceCeiling: 10 },
    { allowed: true, clearanceCeiling: 2 }, { allowed: true, clearanceCeiling: 13 }]) {
    const result = await inspectOperatorFileReadRequest({ ...base, getGrant: async () => grant });
    assert.equal(result.ok, false);
    assert.equal(result.status, 403);
  }
  const unavailable = await inspectOperatorFileReadRequest({
    ...base, getGrant: async () => { throw new Error('database unavailable'); },
  });
  assert.deepEqual(unavailable, {
    ok: false, status: 503, error: 'local_file_authorization_unavailable',
  });
});
