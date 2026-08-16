import assert from 'node:assert/strict';
import {
  createHash,
  randomUUID,
} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  canonicalJson,
  generateKeypair,
  issueCert,
  pubkeyFingerprint,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  eventGenesisHash,
  eventMutationHash,
} from '../../services/security/protocol/mutmem-protocol.js';
import {
  HOUSEKEEPER_CUSTODY,
  buildHousekeeperCustodyApprovalBody,
  buildHousekeeperCustodyEventMetadata,
  createHousekeeperCustodyApproval,
  housekeeperCustodyAuthorityDigest,
  issueHousekeeperSuccessorCertificate,
  sha256Hex,
  verifyHousekeeperCustodyApproval,
  verifyHousekeeperCustodyContinuity,
  verifyHousekeeperCustodyReceipt,
} from '../../scripts/identity/housekeeper-custody-contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MASTER_EPOCH = '2026-07-10T19:06:32.984Z';
const PREDECESSOR_FROM = 1_700_000_000;
const SUCCESSOR_FROM = 1_800_000_000;

function fixture() {
  const master = generateKeypair();
  const housekeeper = generateKeypair();
  const predecessorBody = {
    v: 1,
    agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    pubkey: housekeeper.pubkey,
    device_fp: 'fixture-device-binding',
    valid_from: PREDECESSOR_FROM,
    valid_until: HOUSEKEEPER_CUSTODY.CERTIFICATE_VALID_UNTIL,
    issuer: HOUSEKEEPER_CUSTODY.AGENT_ID,
    issued_at: PREDECESSOR_FROM,
  };
  const predecessor = issueCert(housekeeper.privkey, predecessorBody);
  const issued = issueHousekeeperSuccessorCertificate({
    predecessorCert: predecessor,
    validFrom: SUCCESSOR_FROM,
    masterPrivkeyB64u: master.privkey,
    masterPubkeyB64u: master.pubkey,
  });
  const approvalBody = buildHousekeeperCustodyApprovalBody({
    predecessorCert: predecessor,
    successorCert: issued.certificate,
    masterFingerprint: pubkeyFingerprint(master.pubkey),
    masterEpoch: MASTER_EPOCH,
    reason: 'Fixture authorization for exact housekeeper key-continuity custody promotion.',
    signedTs: SUCCESSOR_FROM,
  });
  const approval = createHousekeeperCustodyApproval({
    body: approvalBody,
    masterPrivkeyB64u: master.privkey,
    masterPubkeyB64u: master.pubkey,
    nonce: 'fixture-master-approval-nonce',
  });
  const signerValidFrom = new Date(SUCCESSOR_FROM * 1000).toISOString();
  const prevMutationHash = eventGenesisHash(
    HOUSEKEEPER_CUSTODY.COMPANY_ID,
    HOUSEKEEPER_CUSTODY.AGENT_ID,
    signerValidFrom,
  );
  const eventId = randomUUID();
  const eventNonce = 'fixture-housekeeper-event-nonce';
  const certFingerprint = sha256Hex(Buffer.from(issued.certificate, 'utf8'));
  const eventBody = {
    ledger_version: 1,
    event_id: eventId,
    company_id: HOUSEKEEPER_CUSTODY.COMPANY_ID,
    subject_agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    actor_agent_id: HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID,
    actor_valid_from: MASTER_EPOCH,
    signer_agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    signer_valid_from: signerValidFrom,
    cert_fingerprint: certFingerprint,
    identity_tier: 'T1',
    authority_kind: 'housekeeper_observation_of_verified_request',
    request_envelope_digest: housekeeperCustodyAuthorityDigest(approval),
    operation: HOUSEKEEPER_CUSTODY.EVENT_OPERATION,
    key: certFingerprint,
    metadata: buildHousekeeperCustodyEventMetadata(approval),
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: prevMutationHash.toString('hex'),
    ts_signed: SUCCESSOR_FROM,
  };
  const contentHash = createHash('sha256').update(Buffer.from(canonicalJson(eventBody), 'utf8')).digest();
  const mutationHash = eventMutationHash(prevMutationHash, contentHash, eventNonce, SUCCESSOR_FROM);
  const eventSignature = signPayload(housekeeper.privkey, eventBody, eventNonce, SUCCESSOR_FROM);
  const event = {
    event_id: eventId,
    proof_required: true,
    ledger_version: 1,
    ledger_seq: 1,
    signed_body: eventBody,
    content_hash: contentHash.toString('hex'),
    mutation_hash: mutationHash.toString('hex'),
    prev_mutation_hash: prevMutationHash.toString('hex'),
    signer_agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
    signer_valid_from: signerValidFrom,
    cert_fingerprint: certFingerprint,
    signer_certificate: issued.certificate,
    identity_tier: 'T1',
    ts_signed: SUCCESSOR_FROM,
    nonce: eventNonce,
    signature: eventSignature,
  };
  const receipt = {
    schema: HOUSEKEEPER_CUSTODY.RECEIPT_SCHEMA,
    master_public_key: master.pubkey,
    master_fingerprint: pubkeyFingerprint(master.pubkey),
    predecessor_certificate: predecessor,
    successor_certificate: issued.certificate,
    master_approval: approval,
    housekeeper_event: event,
  };
  return { master, housekeeper, predecessor, issued, approval, receipt };
}

test('master-signed successor preserves the exact Genesis key and device binding', () => {
  const value = fixture();
  const proof = verifyHousekeeperCustodyContinuity({
    predecessorCert: value.predecessor,
    successorCert: value.issued.certificate,
    masterPubkeyB64u: value.master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(value.master.pubkey),
    now: SUCCESSOR_FROM,
  });
  assert.equal(proof.valid, true);
  assert.equal(proof.predecessor.pubkey_fingerprint, proof.successor.pubkey_fingerprint);
  assert.equal(proof.predecessor.device_fp_sha256, proof.successor.device_fp_sha256);
});

test('a different successor key is rejected even when the master signs it', () => {
  const value = fixture();
  const replacement = generateKeypair();
  const body = {
    ...value.issued.body,
    pubkey: replacement.pubkey,
  };
  const certificate = issueCert(value.master.privkey, body);
  assert.throws(() => verifyHousekeeperCustodyContinuity({
    predecessorCert: value.predecessor,
    successorCert: certificate,
    masterPubkeyB64u: value.master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(value.master.pubkey),
    now: SUCCESSOR_FROM,
  }), /stable_key_continuity_broken/);
});

test('a self-signed successor is rejected', () => {
  const value = fixture();
  const body = { ...value.issued.body, issuer: HOUSEKEEPER_CUSTODY.AGENT_ID };
  const certificate = issueCert(value.housekeeper.privkey, body);
  assert.throws(() => verifyHousekeeperCustodyContinuity({
    predecessorCert: value.predecessor,
    successorCert: certificate,
    masterPubkeyB64u: value.master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(value.master.pubkey),
    now: SUCCESSOR_FROM,
  }), /successor_not_master_signed/);
});

test('the master approval binds both certificate hashes and the no-authority scope', () => {
  const value = fixture();
  const proof = verifyHousekeeperCustodyApproval(value.approval, {
    predecessorCert: value.predecessor,
    successorCert: value.issued.certificate,
    masterPubkeyB64u: value.master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(value.master.pubkey),
  });
  assert.equal(proof.valid, true);
  const tampered = structuredClone(value.approval);
  tampered.body.successor.certificate_sha256 = '0'.repeat(64);
  assert.equal(verifyHousekeeperCustodyApproval(tampered, {
    predecessorCert: value.predecessor,
    successorCert: value.issued.certificate,
    masterPubkeyB64u: value.master.pubkey,
    expectedMasterFingerprint: pubkeyFingerprint(value.master.pubkey),
  }).valid, false);
});

test('native and standalone verifiers accept the same complete receipt', () => {
  const value = fixture();
  assert.equal(verifyHousekeeperCustodyReceipt(value.receipt).valid, true);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-housekeeper-custody-'));
  const filename = path.join(directory, 'receipt.json');
  fs.writeFileSync(filename, `${JSON.stringify(value.receipt, null, 2)}\n`, { mode: 0o600 });
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts', 'verification', 'verify-housekeeper-custody-transition.mjs'),
    '--receipt', filename,
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(JSON.parse(result.stdout).valid, true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test('receipt tampering fails both native and standalone verification', () => {
  const value = fixture();
  const tampered = structuredClone(value.receipt);
  tampered.housekeeper_event.signed_body.metadata.genesis_certificate_retained = false;
  assert.equal(verifyHousekeeperCustodyReceipt(tampered).valid, false);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-housekeeper-custody-'));
  const filename = path.join(directory, 'receipt.json');
  fs.writeFileSync(filename, `${JSON.stringify(tampered, null, 2)}\n`, { mode: 0o600 });
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts', 'verification', 'verify-housekeeper-custody-transition.mjs'),
    '--receipt', filename,
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.equal(JSON.parse(result.stderr).valid, false);
  fs.rmSync(directory, { recursive: true, force: true });
});

test('ceremony is transactional, idempotent, explicit-account, and never rotates the reserved key', () => {
  const ceremony = fs.readFileSync(
    path.join(ROOT, 'scripts', 'ceremony', 'promote-housekeeper-custody.mjs'),
    'utf8',
  );
  const contract = fs.readFileSync(
    path.join(ROOT, 'scripts', 'identity', 'housekeeper-custody-contract.mjs'),
    'utf8',
  );
  const eventLedger = fs.readFileSync(
    path.join(ROOT, 'services', 'observe', 'event-ledger.js'),
    'utf8',
  );
  assert.match(ceremony, /BEGIN/);
  assert.match(ceremony, /FOR UPDATE/);
  assert.match(ceremony, /pg_advisory_xact_lock/);
  assert.match(ceremony, /successor_already_present/);
  assert.match(ceremony, /recoverExistingPromotion/);
  assert.match(ceremony, /exclusiveOperationKey:\s*true/);
  assert.match(ceremony, /argument\('--keychain-account'\) \|\| master\.keychain_account/);
  assert.match(eventLedger, /identityQueryFn/);
  assert.doesNotMatch(ceremony, /process\.env/);
  assert.doesNotMatch(contract, /process\.env/);
  assert.doesNotMatch(ceremony, /generateKeypair|enrollAgent|revokeAgent/);
  assert.doesNotMatch(contract, /generateKeypair|enrollAgent|revokeAgent/);
  assert.doesNotMatch(ceremony, /writeFileSync\([^\n]*HOUSEKEEPER_KEY_PATH/);
});
