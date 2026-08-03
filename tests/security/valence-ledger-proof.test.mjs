import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  signPayload,
} from '../../services/security/agent-identity.js';
import { createValenceLedger } from '../../services/governance/valence-ledger.js';

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

test('valence writer refuses to operate outside the owning weight transaction', async () => {
  const ledger = createValenceLedger({ queryFn: async () => ({ rows: [] }) });
  assert.deepEqual(
    await ledger.appendValence({
      memoryId: '11111111-1111-4111-8111-111111111111',
      rewardSign: 1,
      contextHash: 'a'.repeat(64),
    }),
    { ok: false, reason: 'transaction_client_required' },
  );
});

test('valence chain verifies its certificate, signed body, hash, and signature', async () => {
  const signer = generateKeypair();
  const validFrom = 1_700_000_000;
  const signedTs = 1_800_000_000;
  const cert = issueCert(signer.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'valence-proof-device',
    valid_from: validFrom,
    valid_until: 2_000_000_000,
    issuer: 'housekeeper',
    issued_at: validFrom,
  });
  const certFingerprint = sha256(Buffer.from(cert, 'utf8')).toString('hex');
  const nonce = 'valence-proof-nonce';
  const body = {
    event_type: 'VALENCE',
    memory_id: '11111111-1111-4111-8111-111111111111',
    company_id: 'hom',
    reward_sign: -1,
    context_hash: 'b'.repeat(64),
    signer_agent_id: 'housekeeper',
    signer_valid_from: new Date(validFrom * 1000).toISOString(),
    cert_fingerprint: certFingerprint,
    identity_tier: 'T1_SYSTEM_SELF',
    ts_signed: signedTs,
  };
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const rowHash = sha256(Buffer.concat([
    contentHash,
    Buffer.from(nonce),
    Buffer.from(String(signedTs)),
  ]));
  const row = {
    id: 1,
    memory_id: body.memory_id,
    company_id: body.company_id,
    reward_sign: body.reward_sign,
    context_hash: body.context_hash,
    body_json: body,
    content_hash: contentHash,
    prev_hash: null,
    row_hash: rowHash,
    ts_signed: signedTs,
    nonce,
    sig: Buffer.from(signPayload(signer.privkey, body, nonce, signedTs), 'base64url'),
    proof_required: true,
    signer_agent_id: body.signer_agent_id,
    signer_valid_from: body.signer_valid_from,
    cert_fingerprint: certFingerprint,
    identity_tier: body.identity_tier,
    pubkey: signer.pubkey,
    cert,
    revoked_at: null,
    revocation_ts_signed: null,
  };
  const ledger = createValenceLedger({ queryFn: async () => ({ rows: [row] }) });
  const verified = await ledger.verifyValenceChain(body.memory_id);
  assert.equal(verified.ok, true);
  assert.equal(verified.length, 1);
  assert(Buffer.from(verified.head).equals(rowHash));

  const tamperedLedger = createValenceLedger({
    queryFn: async () => ({ rows: [{ ...row, reward_sign: 1 }] }),
  });
  assert.equal((await tamperedLedger.verifyValenceChain(body.memory_id)).ok, false);
});

test('STDP outcome, weight mutation, provenance, and event share one transaction', async () => {
  const [stdp, migration] = await Promise.all([
    readFile(new URL('../../services/learning/stdp-kernel.js', import.meta.url), 'utf8'),
    readFile(new URL('../../migrations/062-valence-ledger-atomic-proof.sql', import.meta.url), 'utf8'),
  ]);
  // One restricted transaction binds: valence ledger append → signed governor
  // mutation → signed reweight (apply_signed_cognitive_reweight, which consumes
  // the mutation hash, so it MUST follow commitGovernorMutation) → event log.
  // The weight is never changed by a raw UPDATE — migration 080 revoked that
  // privilege from agent_runtime.
  assert.match(stdp, /withTransaction\(async \(client\) => \{[\s\S]+appendValence\(\{[\s\S]+client,[\s\S]+commitGovernorMutation\(\{[\s\S]+client[\s\S]+apply_signed_cognitive_reweight[\s\S]+logEvent\([\s\S]+\{ client \}/);
  assert.match(stdp, /Math\.round\(newWeight \* 1000\) === Math\.round\(oldWeight \* 1000\)[\s\S]+cognitive_weight_unchanged[\s\S]+projection_appended:\s*false/);
  assert.match(migration, /proof_required boolean/);
  assert.match(migration, /ON DELETE RESTRICT/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public\.memory_valence_ledger FROM agent_runtime/);
});
