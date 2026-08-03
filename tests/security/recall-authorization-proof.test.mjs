import test from 'node:test';
import assert from 'node:assert/strict';

import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import {
  createRecallAuthorizationProof,
  verifyRecallAuthorizationChain,
  verifyRecallAuthorizationProof,
} from '../../services/security/recall-authorization.js';

function rowFrom(proof, fields) {
  return {
    company_id: fields.companyId,
    subject_agent_id: fields.subjectAgentId,
    subject_valid_from: fields.subjectValidFrom,
    allowed: fields.allowed,
    write_allowed: Boolean(fields.writeAllowed),
    clearance_ceiling: fields.clearanceCeiling,
    data_class_ceiling: fields.dataClassCeiling,
    master_fingerprint: fields.masterFingerprint,
    signed_body: proof.body,
    content_hash: proof.contentHash,
    mutation_hash: proof.mutationHash,
    prev_mutation_hash: proof.prevMutationHash,
    ts_signed: proof.signedTs,
    nonce: proof.nonce,
    sig: proof.sigBytes,
    is_genesis: !proof.prevMutationHash,
  };
}

test('master-signed memory-access grant binds read/write authority, company, exact epoch, clearance, and data class', () => {
  const master = generateKeypair();
  const fields = {
    companyId: 'hom',
    subjectAgentId: 'recall-agent',
    subjectValidFrom: '2026-07-11T09:30:00.000Z',
    allowed: true,
    writeAllowed: true,
    clearanceCeiling: 10,
    dataClassCeiling: 'restricted',
    masterFingerprint: pubkeyFingerprint(master.pubkey),
    reason: 'Authorize the release ceremony agent to exercise native recall.',
  };
  const proof = createRecallAuthorizationProof(master.privkey, fields, {
    signedTs: 1_783_764_000,
    nonce: 'recall-grant-proof-nonce',
  });
  const row = rowFrom(proof, fields);
  assert.deepEqual(verifyRecallAuthorizationProof(row, master.pubkey), { valid: true, reason: null });
  assert.equal(proof.sigBytes.length, 64);
  assert.equal(proof.contentHash.length, 32);
  assert.equal(proof.mutationHash.length, 32);

  assert.equal(verifyRecallAuthorizationProof({ ...row, company_id: 'other' }, master.pubkey).valid, false);
  assert.equal(verifyRecallAuthorizationProof({ ...row, write_allowed: false }, master.pubkey).valid, false);
  assert.equal(verifyRecallAuthorizationProof({ ...row, clearance_ceiling: 12 }, master.pubkey).valid, false);
  assert.equal(verifyRecallAuthorizationProof({ ...row, subject_valid_from: '2026-07-12T09:30:00.000Z' }, master.pubkey).valid, false);
  assert.equal(verifyRecallAuthorizationProof({ ...row, sig: Buffer.alloc(64) }, master.pubkey).valid, false);
});

test('recall revocation links to the prior grant and remains independently verifiable', () => {
  const master = generateKeypair();
  const base = {
    companyId: 'hom',
    subjectAgentId: 'recall-agent',
    subjectValidFrom: '2026-07-11T09:30:00.000Z',
    writeAllowed: true,
    clearanceCeiling: 10,
    dataClassCeiling: 'restricted',
    masterFingerprint: pubkeyFingerprint(master.pubkey),
  };
  const grant = createRecallAuthorizationProof(master.privkey, {
    ...base,
    allowed: true,
    reason: 'Initial native recall grant.',
  }, { signedTs: 1_783_764_000, nonce: 'recall-grant' });
  const revoke = createRecallAuthorizationProof(master.privkey, {
    ...base,
    allowed: false,
    writeAllowed: false,
    clearanceCeiling: 0,
    dataClassCeiling: 'public',
    reason: 'Terminal effective recall revocation event.',
    prevMutationHash: grant.mutationHash,
  }, { signedTs: 1_783_764_100, nonce: 'recall-revoke' });
  const grantRow = rowFrom(grant, { ...base, allowed: true });
  const revokeRow = rowFrom(revoke, {
    ...base,
    allowed: false,
    writeAllowed: false,
    clearanceCeiling: 0,
    dataClassCeiling: 'public',
  });
  grantRow.master_pubkey = master.pubkey;
  revokeRow.master_pubkey = master.pubkey;
  assert.deepEqual(verifyRecallAuthorizationProof(revokeRow, master.pubkey), { valid: true, reason: null });
  const verification = verifyRecallAuthorizationChain([revokeRow, grantRow]);
  assert.equal(verification.latest.allowed, false);
  assert.deepEqual(verification.orderedRows, [grantRow, revokeRow]);
  assert.throws(
    () => verifyRecallAuthorizationChain([revokeRow]),
    /recall_authorization_chain_genesis_invalid/,
  );
  assert.throws(
    () => verifyRecallAuthorizationChain([grantRow, { ...revokeRow, prev_mutation_hash: Buffer.alloc(32) }]),
    /recall_authorization_chain_disconnected/,
  );

  const alternate = createRecallAuthorizationProof(master.privkey, {
    ...base,
    allowed: true,
    reason: 'Independent successor must be rejected as a second chain head.',
    prevMutationHash: grant.mutationHash,
  }, { signedTs: 1_783_764_200, nonce: 'recall-alternate-head' });
  const alternateRow = rowFrom(alternate, { ...base, allowed: true });
  alternateRow.master_pubkey = master.pubkey;
  assert.throws(
    () => verifyRecallAuthorizationChain([grantRow, revokeRow, alternateRow]),
    /recall_authorization_chain_head_invalid/,
  );

  const disconnected = createRecallAuthorizationProof(master.privkey, {
    ...base,
    allowed: true,
    reason: 'Missing predecessor must fail closed.',
    prevMutationHash: Buffer.alloc(32, 9),
  }, { signedTs: 1_783_764_300, nonce: 'recall-disconnected' });
  const disconnectedRow = rowFrom(disconnected, { ...base, allowed: true });
  disconnectedRow.master_pubkey = master.pubkey;
  assert.throws(
    () => verifyRecallAuthorizationChain([grantRow, disconnectedRow]),
    /recall_authorization_chain_disconnected/,
  );
  assert.throws(
    () => verifyRecallAuthorizationChain([]),
    /recall_authorization_chain_head_invalid/,
  );
});
