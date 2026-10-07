import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { generateKeypair, issueCert, pubkeyFingerprint } from
  '../../services/security/agent-identity.js';
import { createRecallAuthorizationProof } from
  '../../services/security/recall-authorization.js';
import { preflightCutoverActor } from '../../scripts/db/preflight-cutover-actor.mjs';
import { assertActorAuthorityPreserved } from '../../scripts/db/cutover-canonical.mjs';

function fixture({ writeAllowed = true, validUntilOffset = 3600,
  clearanceCeiling = 5 } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const master = generateKeypair();
  const agent = generateKeypair();
  const validFrom = new Date((now - 60) * 1000).toISOString();
  const validUntil = new Date((now + validUntilOffset) * 1000).toISOString();
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const cert = issueCert(master.privkey, {
    v: 1, agent_id: 'cutover_actor', pubkey: agent.pubkey,
    device_fp: 'cutover-test-device', valid_from: now - 60,
    valid_until: now + validUntilOffset, issuer: 'aimos-master',
    issued_at: now - 60,
  });
  const proof = createRecallAuthorizationProof(master.privkey, {
    companyId: 'hom', subjectAgentId: 'cutover_actor',
    subjectValidFrom: validFrom, allowed: true, writeAllowed,
    clearanceCeiling, dataClassCeiling: 'restricted',
    masterFingerprint, reason: 'cutover signed SAVE probe',
  });
  const identity = {
    agent_id: 'cutover_actor', cert, pubkey: agent.pubkey,
    device_fp: 'cutover-test-device', valid_from: validFrom,
    valid_until: validUntil, is_system_role: false,
    master_pubkey: master.pubkey, master_fingerprint: masterFingerprint,
  };
  const grant = {
    recall_authorization_event_id: 'grant-1',
    company_id: 'hom', subject_agent_id: 'cutover_actor',
    subject_valid_from: validFrom, allowed: true,
    write_allowed: writeAllowed, clearance_ceiling: clearanceCeiling,
    data_class_ceiling: 'restricted', master_fingerprint: masterFingerprint,
    signed_body: proof.body, content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    prev_mutation_hash: null, ts_signed: proof.signedTs,
    nonce: proof.nonce, sig: proof.sigBytes, is_genesis: true,
    master_pubkey: master.pubkey,
  };
  const directory = mkdtempSync(path.join(os.tmpdir(), 'aimos-cutover-actor-'));
  const keyPath = path.join(directory, 'cutover_actor.key');
  writeFileSync(keyPath, `${agent.privkey}\n`, { mode: 0o600 });
  const sql = [];
  const client = { async query(statement) {
    sql.push(statement);
    assert.match(statement.trim(), /^SELECT /);
    if (statement.includes('LEFT JOIN aimos_agent_revocation_events')) {
      return { rows: [{ agent_id: identity.agent_id, cert,
        pubkey: identity.pubkey, agent_valid_from: validFrom,
        valid_until: validUntil, master_pubkey: master.pubkey,
        enrolled_master_fingerprint: masterFingerprint,
        signed_body: null }] };
    }
    if (statement.includes('FROM public.agent_identity')) {
      return { rowCount: 1, rows: [identity] };
    }
    if (statement.includes('FROM public.aimos_recall_authorization_events')) {
      return { rows: [grant] };
    }
    throw new Error('unexpected_query');
  } };
  return { client, keyPath, sql, directory };
}

test('cutover actor preflight verifies the active key, certificate and signed exact-epoch write grant without writes', async () => {
  const f = fixture();
  try {
    const proof = await preflightCutoverActor({ client: f.client,
      actor: 'cutover_actor', keyPath: f.keyPath });
    assert.equal(proof.write_allowed, true);
    assert.equal(proof.clearance_ceiling, 5);
    assert.match(proof.grant_mutation_sha256, /^[0-9a-f]{64}$/);
    assert.equal(f.sql.length, 3);
    assert.equal(assertActorAuthorityPreserved(proof, { ...proof }), true);
    assert.throws(() => assertActorAuthorityPreserved(proof, {
      ...proof, grant_mutation_sha256: 'f'.repeat(64),
    }), /canonical_cutover_actor_authority_changed_across_restore/);
  } finally { rmSync(f.directory, { recursive: true, force: true }); }
});

test('cutover actor preflight denies a read-only exact-epoch grant', async () => {
  const f = fixture({ writeAllowed: false });
  try {
    await assert.rejects(preflightCutoverActor({ client: f.client,
      actor: 'cutover_actor', keyPath: f.keyPath }),
    /canonical_cutover_actor_exact_epoch_write_grant_insufficient/);
  } finally { rmSync(f.directory, { recursive: true, force: true }); }
});

test('cutover actor preflight denies an expired certificate', async () => {
  const f = fixture({ validUntilOffset: -1 });
  try {
    await assert.rejects(preflightCutoverActor({ client: f.client,
      actor: 'cutover_actor', keyPath: f.keyPath }),
    /canonical_cutover_actor_certificate_invalid_or_revoked/);
  } finally { rmSync(f.directory, { recursive: true, force: true }); }
});
