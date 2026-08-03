import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  generateKeypair,
  issueCert,
  signPayload,
} from '../../services/security/agent-identity.js';
import { contentHash } from '../../services/security/identity-chain.js';
import { verifyGovernorConfigChain } from '../../services/governance/governor-config-ledger.js';
import { readFile } from 'node:fs/promises';

function mutationHash(bodyHash, previousHash, nonce, signedTs) {
  const parts = previousHash
    ? [bodyHash, previousHash, Buffer.from(nonce), Buffer.from(String(signedTs))]
    : [bodyHash, Buffer.from(nonce), Buffer.from(String(signedTs))];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

function fixture() {
  const signer = generateKeypair();
  const validFrom = 1_700_000_000;
  const validUntil = 2_000_000_000;
  const cert = issueCert(signer.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'test-device',
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: 'housekeeper',
    issued_at: validFrom,
  });
  const identity = {
    cert,
    pubkey: signer.pubkey,
    valid_from: new Date(validFrom * 1000),
    valid_until: new Date(validUntil * 1000),
    revoked_at: null,
    revocation_ts_signed: null,
  };
  const certFingerprint = createHash('sha256').update(cert, 'utf8').digest('hex');

  const makeRow = ({ enabled, previous, previousEnabled, signedTs, nonce, id }) => {
    const body = {
      config_key: 'OJA_NORMALIZATION_GOVERNOR',
      enabled,
      reason: `test-${id}`,
      operator: 'test',
      identity_tier: 'T1_SYSTEM_SELF',
      prev_enabled: previousEnabled,
      ts_signed: signedTs,
    };
    const bodyHash = contentHash(body);
    const nextHash = mutationHash(bodyHash, previous, nonce, signedTs);
    return {
      config_id: id,
      config_key: body.config_key,
      enabled,
      cert_fingerprint: certFingerprint,
      content_hash: bodyHash,
      mutation_hash: nextHash,
      prev_mutation_hash: previous,
      ts_signed: signedTs,
      nonce,
      sig: Buffer.from(signPayload(signer.privkey, body, nonce, signedTs), 'base64url'),
      is_genesis: previous === null,
      body_json: body,
      created_at: new Date(signedTs * 1000),
    };
  };

  const first = makeRow({
    enabled: false,
    previous: null,
    previousEnabled: null,
    signedTs: 1_800_000_000,
    nonce: 'governor-proof-1',
    id: 1,
  });
  const second = makeRow({
    enabled: true,
    previous: first.mutation_hash,
    previousEnabled: false,
    signedTs: 1_800_000_001,
    nonce: 'governor-proof-2',
    id: 2,
  });
  return { rows: [first, second], identities: [identity] };
}

test('governor authority requires the complete signed chain', () => {
  const proof = fixture();
  const verified = verifyGovernorConfigChain(proof.rows, proof.identities, null);
  assert.equal(verified.verified, true);
  assert.equal(verified.rowCount, 2);
  assert.equal(verified.enabled, true);

  assert.throws(
    () => verifyGovernorConfigChain([{ ...proof.rows[1], prev_mutation_hash: null }], proof.identities, null),
    /governor_config_chain_row_mismatch/,
  );
  assert.throws(
    () => verifyGovernorConfigChain([proof.rows[0], { ...proof.rows[1], enabled: false }], proof.identities, null),
    /governor_config_chain_row_mismatch/,
  );
  assert.throws(
    () => verifyGovernorConfigChain([proof.rows[0], { ...proof.rows[1], sig: Buffer.alloc(64) }], proof.identities, null),
    /governor_config_signature_invalid/,
  );
});

test('live governor commit binds the actual housekeeper certificate tier before signing', async () => {
  const source = await readFile(
    new URL('../../services/governance/governor-config-ledger.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /HOUSEKEEPER_SIGNER_CONSTANTS\.IDENTITY_TIER\b/);
  assert.match(source, /const certificate = await getHousekeeperCert\(\)/);
  assert.match(source, /const identityTier = detectTierFromCert\(certificate\)/);
  assert.match(source, /identity_tier: identityTier/);
  assert.match(source, /signed\.certString !== certificate \|\| signed\.identityTier !== identityTier/);
  assert.match(source, /contentHash\(signed\.body\)/);
  assert.match(source, /JSON\.stringify\(signed\.body\)/);
});
