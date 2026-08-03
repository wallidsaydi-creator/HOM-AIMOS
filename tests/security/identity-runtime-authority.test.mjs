import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createAgentRevocationProof,
  generateKeypair,
  getAgentCert,
  issueCert,
  pubkeyFingerprint,
} from '../../services/security/agent-identity.js';

function identityFixture() {
  const master = generateKeypair();
  const agent = generateKeypair();
  const validFrom = 1_783_764_000;
  const validUntil = 1_783_850_400;
  const cert = issueCert(master.privkey, {
    v: 1,
    agent_id: 'agent-a',
    pubkey: agent.pubkey,
    device_fp: 'identity-runtime-authority-device',
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: pubkeyFingerprint(master.pubkey),
    issued_at: validFrom,
  });
  return {
    master,
    cert,
    row: {
      agent_id: 'agent-a',
      cert,
      pubkey: agent.pubkey,
      agent_valid_from: new Date(validFrom * 1000).toISOString(),
      valid_until: new Date(validUntil * 1000).toISOString(),
      revoked_at: new Date((validFrom + 1) * 1000).toISOString(),
      master_pubkey: master.pubkey,
      enrolled_master_fingerprint: pubkeyFingerprint(master.pubkey),
      signed_body: null,
    },
  };
}

test('certificate selection verifies the signed epoch and ignores mutable revoked_at metadata', async () => {
  const { cert, row } = identityFixture();
  const selected = await getAgentCert('agent-a', {
    nowFn: () => 1_783_764_500_000,
    queryFn: async () => ({ rows: [row] }),
  });
  assert.equal(selected, cert);
});

test('only a valid master-signed revocation event terminates certificate selection', async () => {
  const { master, cert, row } = identityFixture();
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const proof = createAgentRevocationProof(master.privkey, {
    agentId: 'agent-a',
    agentValidFrom: row.agent_valid_from,
    targetCert: cert,
    masterFingerprint,
  }, {
    nowFn: () => 1_783_764_600,
    nonceFn: () => 'identity-runtime-revocation',
  });
  const revoked = {
    ...row,
    master_fingerprint: masterFingerprint,
    target_cert_hash: proof.targetCertHash,
    prior_identity_hash: proof.priorIdentityHash,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
  };

  await assert.rejects(
    getAgentCert('agent-a', {
      nowFn: () => 1_783_764_700_000,
      queryFn: async () => ({ rows: [revoked] }),
    }),
    /no active cert/,
  );
});
