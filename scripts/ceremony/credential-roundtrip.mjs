#!/usr/bin/env node

// Noninteractive credential proof. The generated plaintext exists only in this
// process and macOS Keychain; stdout contains hashes and ledger metadata only.

import { randomBytes } from 'node:crypto';
import { pool, query } from '../../db/connection.js';
import { credentialLedger } from '../../services/security/credential-ledger.js';
import {
  computeCredentialHash,
  credentialSlotId,
  readCredential,
  storeCredential
} from '../../services/security/credential-store.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { verifyPayloadSig } from '../../services/security/agent-identity.js';

const service = 'ceremony_probe';
const slotId = credentialSlotId(service);

async function commit(eventType, body) {
  const signed = await signAsHousekeeper(body);
  const result = await credentialLedger.commitCredentialLifecycle({
    serviceName: service,
    slotId,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType,
    bodyJson: signed.body
  });
  if (!result.ok) throw new Error(`${eventType} ledger commit failed: ${result.reason}`);
  return result;
}

try {
  const prior = await credentialLedger.getLatestStoreForSlot(slotId);
  const plaintext = randomBytes(48).toString('base64url');
  const expectedHash = computeCredentialHash(plaintext);
  const stored = await storeCredential(service, plaintext);
  const eventType = prior ? 'ROTATE' : 'STORE';

  const lifecycle = await commit(eventType, {
    event_type: eventType,
    service,
    slot_id: slotId,
    credential_hash: expectedHash,
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: null,
    rotated_from: prior?.provenance_id || null,
    rotated_from_hash: prior?.body_json?.credential_hash || null,
    reason: 'release_credential_roundtrip_ceremony',
    operator: 'housekeeper',
    signer_agent_id: 'housekeeper'
  });

  const recalled = await readCredential(service);
  const recalledHash = recalled ? computeCredentialHash(recalled.value) : null;
  if (!recalled || recalledHash !== expectedHash || stored.hash !== expectedHash) {
    throw new Error('credential recall hash mismatch');
  }

  const verification = await commit('VERIFY', {
    event_type: 'VERIFY',
    service,
    slot_id: slotId,
    credential_hash: recalledHash,
    verified_lifecycle_mutation_hash: Buffer.from(lifecycle.mutationHash).toString('hex'),
    reason: 'release_credential_roundtrip_ceremony',
    operator: 'housekeeper',
    signer_agent_id: 'housekeeper'
  });

  const latestRows = await credentialLedger.getSlotChain(slotId, 2);
  const pub = await query(
    `SELECT pubkey FROM agent_identity identity
      WHERE agent_id = 'housekeeper'
        AND NOT EXISTS (
          SELECT 1 FROM aimos_agent_revocation_events revocation
           WHERE revocation.agent_id = identity.agent_id
             AND revocation.agent_valid_from = identity.valid_from
        )
      ORDER BY valid_from DESC LIMIT 1`
  );
  const verificationRow = latestRows.find((row) => row.event_type === 'VERIFY');
  const cryptoProof = await credentialLedger.verifyCredentialLifecycle(
    verificationRow,
    pub.rows[0]?.pubkey,
    (pubkey, body, nonce, ts, sig) => verifyPayloadSig(pubkey, body, nonce, ts, sig)
  );
  if (!cryptoProof.overall_ok) throw new Error(`credential proof verification failed: ${JSON.stringify(cryptoProof)}`);

  console.log(JSON.stringify({
    service,
    slot_id: slotId,
    keychain_version_slot: stored.versionSlot,
    lifecycle_event: eventType,
    credential_hash: expectedHash,
    recall_hash_match: recalledHash === expectedHash,
    lifecycle_content_hash: Buffer.from(lifecycle.contentHash).toString('hex'),
    lifecycle_mutation_hash: Buffer.from(lifecycle.mutationHash).toString('hex'),
    verify_content_hash: Buffer.from(verification.contentHash).toString('hex'),
    verify_mutation_hash: Buffer.from(verification.mutationHash).toString('hex'),
    cryptographic_verification: cryptoProof
  }, null, 2));
} finally {
  await pool.end();
}
