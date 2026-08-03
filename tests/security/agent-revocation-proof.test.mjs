import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAgentRevocationProof,
  generateKeypair,
  pubkeyFingerprint,
  verifyAgentRevocationProof,
} from '../../services/security/agent-identity.js';

function fixture() {
  const master = generateKeypair();
  const validFrom = '2026-07-11T09:30:00.000Z';
  const cert = 'retained-target-certificate-envelope';
  const proof = createAgentRevocationProof(master.privkey, {
    agentId: 'codex-auditor',
    agentValidFrom: validFrom,
    targetCert: cert,
    masterFingerprint: pubkeyFingerprint(master.pubkey),
    reasonCode: 'release_test_complete',
  }, {
    nowFn: () => 1_783_764_000,
    nonceFn: () => 'revocation-proof-nonce',
  });
  const row = {
    agent_id: 'codex-auditor',
    agent_valid_from: validFrom,
    master_fingerprint: pubkeyFingerprint(master.pubkey),
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
  };
  return { master, cert, proof, row };
}

test('master-signed revocation proof verifies independently of request freshness', () => {
  const { master, cert, proof, row } = fixture();
  const result = verifyAgentRevocationProof(row, master.pubkey, cert);

  assert.equal(result.valid, true);
  assert.equal(proof.body.agent_id, 'codex-auditor');
  assert.equal(proof.body.agent_valid_from, '2026-07-11T09:30:00.000Z');
  assert.equal(proof.sigBytes.length, 64);
  assert.equal(proof.contentHash.length, 32);
  assert.equal(proof.mutationHash.length, 32);
});

test('revocation proof fails when target, body, master, or mutation commitment changes', () => {
  const { master, cert, row } = fixture();
  const wrongMaster = generateKeypair();

  assert.equal(verifyAgentRevocationProof(row, master.pubkey, `${cert}-tampered`).valid, false);
  assert.equal(verifyAgentRevocationProof({ ...row, signed_body: { ...row.signed_body, agent_id: 'other' } }, master.pubkey, cert).valid, false);
  assert.equal(verifyAgentRevocationProof(row, wrongMaster.pubkey, cert).valid, false);
  assert.equal(verifyAgentRevocationProof({ ...row, mutation_hash: Buffer.alloc(32) }, master.pubkey, cert).valid, false);
});
