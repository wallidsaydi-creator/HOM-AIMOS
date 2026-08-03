import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  EVENT_LEDGER_VERSION,
  eventGenesisHash,
  eventMutationHash,
  verifyEventLedgerChain,
  verifyEventProof,
} from '../../services/observe/event-ledger.js';

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function fixture() {
  const signer = generateKeypair();
  const signerValidFrom = '2026-07-11T09:30:00.000Z';
  const signerValidFromUnix = Math.floor(new Date(signerValidFrom).getTime() / 1000);
  const cert = issueCert(signer.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'event-proof-device',
    valid_from: signerValidFromUnix,
    valid_until: 2_000_000_000,
    issuer: 'housekeeper',
    issued_at: signerValidFromUnix,
  });
  const prev = eventGenesisHash('hom', 'housekeeper', signerValidFrom);
  const signedTs = 1_783_764_000;
  const nonce = 'event-proof-nonce';
  const body = {
    ledger_version: 1,
    event_id: '11111111-1111-4111-8111-111111111111',
    company_id: 'hom',
    subject_agent_id: 'recall-calibrator',
    actor_agent_id: null,
    actor_valid_from: null,
    signer_agent_id: 'housekeeper',
    signer_valid_from: signerValidFrom,
    cert_fingerprint: sha256(Buffer.from(cert, 'utf8')).toString('hex'),
    identity_tier: 'T1_SYSTEM_SELF',
    authority_kind: 'housekeeper_autonomous',
    request_envelope_digest: null,
    operation: 'calibration_observed',
    key: 'recall:proof',
    metadata: { reasoning: 'A deterministic proof fixture exercises the event receipt.' },
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: prev.toString('hex'),
    ts_signed: signedTs,
  };
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = eventMutationHash(prev, contentHash, nonce, signedTs);
  const sig = Buffer.from(signPayload(signer.privkey, body, nonce, signedTs), 'base64url');
  const row = {
    id: body.event_id,
    ts: new Date(signedTs * 1000),
    company_id: body.company_id,
    agent_id: body.subject_agent_id,
    operation: body.operation,
    key: body.key,
    metadata: body.metadata,
    parent_event_id: null,
    proof_required: true,
    ledger_version: EVENT_LEDGER_VERSION,
    ledger_seq: 1,
    signer_agent_id: body.signer_agent_id,
    signer_valid_from: body.signer_valid_from,
    cert_fingerprint: body.cert_fingerprint,
    identity_tier: body.identity_tier,
    authority_kind: body.authority_kind,
    signed_body: body,
    content_hash: contentHash,
    mutation_hash: mutationHash,
    prev_mutation_hash: prev,
    ts_signed: signedTs,
    nonce,
    sig,
    cert,
    pubkey: signer.pubkey,
  };
  return { signer, cert, body, row, prev, contentHash, mutationHash };
}

test('event proof uses deterministic domain-separated genesis and verifies offline', () => {
  const { signer, row, prev, contentHash, mutationHash } = fixture();
  const result = verifyEventProof(row, signer.pubkey);
  assert.equal(result.valid, true);
  assert.equal(prev.length, 32);
  assert.equal(contentHash.length, 32);
  assert.equal(mutationHash.length, 32);
  assert.equal(row.sig.length, 64);
  assert(eventGenesisHash('hom', 'housekeeper', '2026-07-11T09:30:00.000Z').equals(prev));
  assert(!eventGenesisHash('other', 'housekeeper', '2026-07-11T09:30:00.000Z').equals(prev));
});

test('event proof rejects content, order, predecessor, signature, and signer tampering', () => {
  const { signer, row } = fixture();
  const wrongSigner = generateKeypair();
  assert.equal(verifyEventProof({ ...row, operation: 'tampered' }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, metadata: { reasoning: 'tampered' } }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, signer_agent_id: 'forged-signer' }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, authority_kind: 'housekeeper_observation_of_verified_request' }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, proof_required: null }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, ledger_seq: 2 }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, prev_mutation_hash: Buffer.alloc(32) }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof({ ...row, sig: Buffer.alloc(64) }, signer.pubkey).valid, false);
  assert.equal(verifyEventProof(row, wrongSigner.pubkey).valid, false);
});

test('complete event chain verifies identity, links, and an exported head checkpoint', () => {
  const { signer, cert, row: first } = fixture();
  const signedTs = Number(first.ts_signed) + 1;
  const nonce = 'event-proof-nonce-2';
  const body = {
    ...first.signed_body,
    event_id: '22222222-2222-4222-8222-222222222222',
    operation: 'calibration_fitted',
    key: 'recall:proof:fit',
    ledger_seq: 2,
    prev_mutation_hash: Buffer.from(first.mutation_hash).toString('hex'),
    ts_signed: signedTs,
  };
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = eventMutationHash(first.mutation_hash, contentHash, nonce, signedTs);
  const second = {
    ...first,
    id: body.event_id,
    ts: new Date(signedTs * 1000),
    operation: body.operation,
    key: body.key,
    ledger_seq: 2,
    signed_body: body,
    content_hash: contentHash,
    mutation_hash: mutationHash,
    prev_mutation_hash: first.mutation_hash,
    ts_signed: signedTs,
    nonce,
    sig: Buffer.from(signPayload(signer.privkey, body, nonce, signedTs), 'base64url'),
    cert,
    pubkey: signer.pubkey,
  };
  const verified = verifyEventLedgerChain([first, second], {
    expectedHeadSequence: 2,
    expectedHeadMutationHash: mutationHash,
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.rowCount, 2);
  assert(Buffer.from(verified.headMutationHash).equals(mutationHash));
  assert.throws(
    () => verifyEventLedgerChain([first], { expectedHeadSequence: 2, expectedHeadMutationHash: mutationHash }),
    /checkpoint_sequence_mismatch/,
  );
  assert.throws(
    () => verifyEventLedgerChain([first, { ...second, prev_mutation_hash: Buffer.alloc(32) }]),
    /chain_link_invalid/,
  );
});
