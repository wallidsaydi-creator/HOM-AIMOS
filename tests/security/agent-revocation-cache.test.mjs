import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAgentRevocationProof,
  generateKeypair,
  pubkeyFingerprint,
} from '../../services/security/agent-identity.js';
import { createAgentRevocationCache } from '../../services/security/agent-revocation-cache.js';

function terminalRow() {
  const master = generateKeypair();
  const cert = 'cached-revocation-target-cert';
  const agentValidFrom = '2026-07-11T09:30:00.000Z';
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const proof = createAgentRevocationProof(master.privkey, {
    agentId: 'agent-a',
    agentValidFrom,
    targetCert: cert,
    masterFingerprint,
  }, {
    nowFn: () => 1_783_764_000,
    nonceFn: () => 'cache-proof-nonce',
  });
  return {
    agent_id: 'agent-a',
    agent_valid_from: agentValidFrom,
    cert,
    master_fingerprint: masterFingerprint,
    enrolled_master_fingerprint: masterFingerprint,
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
    master_pubkey: master.pubkey,
  };
}

test('active and missing epochs are never cached', async () => {
  let calls = 0;
  const active = createAgentRevocationCache({
    queryFn: async () => {
      calls += 1;
      return { rows: [{ agent_id: 'agent-a', signed_body: null }] };
    },
  });
  assert.equal((await active.lookup('agent-a', '2026-07-11T09:30:00.000Z')).revoked, false);
  assert.equal((await active.lookup('agent-a', '2026-07-11T09:30:00.000Z')).revoked, false);
  assert.equal(calls, 2);

  let missingCalls = 0;
  const missing = createAgentRevocationCache({
    queryFn: async () => { missingCalls += 1; return { rows: [] }; },
  });
  await missing.lookup('missing', '2026-07-11T09:30:00.000Z');
  await missing.lookup('missing', '2026-07-11T09:30:00.000Z');
  assert.equal(missingCalls, 2);
});

test('mutable legacy revoked_at metadata cannot terminate an identity epoch', async () => {
  const active = createAgentRevocationCache({
    queryFn: async () => ({
      rows: [{
        agent_id: 'agent-a',
        revoked_at: '2026-07-11T09:31:00.000Z',
        signed_body: null,
      }],
    }),
  });
  assert.deepEqual(
    await active.lookup('agent-a', '2026-07-11T09:30:00.000Z'),
    { found: true, revoked: false, proofVerified: false },
  );
});

test('only a verified terminal revocation is cached', async () => {
  let calls = 0;
  const row = terminalRow();
  const cache = createAgentRevocationCache({
    queryFn: async () => { calls += 1; return { rows: [row] }; },
  });

  const first = await cache.lookup(row.agent_id, row.agent_valid_from);
  const second = await cache.lookup(row.agent_id, row.agent_valid_from);
  assert.deepEqual(first, { found: true, revoked: true, proofVerified: true });
  assert.deepEqual(second, first);
  assert.equal(calls, 1);
});

test('invalid revocation proof fails closed and is not cached', async () => {
  let calls = 0;
  const row = terminalRow();
  row.mutation_hash = Buffer.alloc(32);
  const cache = createAgentRevocationCache({
    queryFn: async () => { calls += 1; return { rows: [row] }; },
  });

  assert.equal((await cache.lookup(row.agent_id, row.agent_valid_from)).proofInvalid, true);
  assert.equal((await cache.lookup(row.agent_id, row.agent_valid_from)).proofInvalid, true);
  assert.equal(calls, 2);
});
