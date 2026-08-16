#!/usr/bin/env node

/**
 * Promote the retained Genesis housekeeper key to master-signed T1 custody.
 *
 * Default mode is read-only. --live requires the master passphrase and an exact
 * confirmation. The existing private key and Genesis certificate are retained;
 * no key generation, overwrite, revocation, policy activation, or migration is
 * performed. Identity insertion and the first successor-epoch event are atomic.
 */

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { pool, agentPool } from '../../db/connection.js';
import {
  canonicalJson,
  loadAgentPrivkey,
  pubkeyEquals,
  pubkeyFingerprint,
  verifyCertChain,
} from '../../services/security/agent-identity.js';
import {
  HOUSEKEEPER_SIGNER_CONSTANTS,
} from '../../services/security/housekeeper-signer.js';
import { logEvent, readVerifiedEventHistory } from '../../services/observe/event-ledger.js';
import { keychainGet } from '../identity/keychain.js';
import { decryptMasterPrivkey, KC_SERVICE } from '../identity/lib.js';
import { readLine, readPassphrase } from '../identity/passphrase.js';
import {
  HOUSEKEEPER_CUSTODY,
  buildHousekeeperCustodyApprovalBody,
  buildHousekeeperCustodyEventMetadata,
  buildSuccessorCertificateBody,
  createHousekeeperCustodyApproval,
  decodeCertificate,
  housekeeperCustodyAuthorityContext,
  issueHousekeeperSuccessorCertificate,
  publicKeyFromPrivate,
  sha256Hex,
  verifyHousekeeperCustodyContinuity,
  verifyHousekeeperCustodyReceipt,
} from '../identity/housekeeper-custody-contract.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUTPUT_ROOT = path.join(ROOT, 'artifacts', 'security', 'identity', 'housekeeper-custody');
const LIVE = process.argv.includes('--live');
const REASON = 'Promote the retained HOM-AIMOS housekeeper key from Genesis self-signed custody to an operator-master-signed T1 certificate without rotating key material, deleting history, or activating runtime policy.';

function fail(code, detail = '') {
  throw new Error(`housekeeper_custody_ceremony_${code}${detail ? `:${detail}` : ''}`);
}

function assert(condition, code, detail = '') {
  if (!condition) fail(code, detail);
}

function argument(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function keyGuard() {
  const filename = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_KEY_PATH;
  const stat = fs.lstatSync(filename, { bigint: true });
  assert(stat.isFile() && !stat.isSymbolicLink(), 'housekeeper_key_not_regular');
  const privateKey = loadAgentPrivkey(filename);
  return Object.freeze({
    filename,
    stat: Object.freeze({
      dev: stat.dev,
      ino: stat.ino,
      size: stat.size,
      mode: stat.mode,
      uid: stat.uid,
      mtimeNs: stat.mtimeNs,
      ctimeNs: stat.ctimeNs,
    }),
    publicKey: publicKeyFromPrivate(privateKey),
  });
}

function assertKeyGuardUnchanged(before) {
  const after = keyGuard();
  for (const field of Object.keys(before.stat)) {
    assert(before.stat[field] === after.stat[field], 'housekeeper_key_changed', field);
  }
  assert(pubkeyEquals(before.publicKey, after.publicKey), 'housekeeper_key_changed', 'public_key');
}

async function loadIdentityState(client = pool) {
  const [masterResult, housekeeperResult] = await Promise.all([
    client.query(
      `SELECT master_pubkey, fingerprint, keychain_service, keychain_account, created_at
         FROM aimos_master_identity
        WHERE id = 1`,
    ),
    client.query(
      `SELECT agent_id, pubkey, cert, device_fp, valid_from, valid_until,
              issued_at, is_system_role
         FROM agent_identity
        WHERE agent_id = $1
        ORDER BY valid_from DESC`,
      [HOUSEKEEPER_CUSTODY.AGENT_ID],
    ),
  ]);
  const master = masterResult.rows[0];
  const identities = housekeeperResult.rows;
  assert(master, 'master_identity_missing');
  assert(identities.length > 0, 'housekeeper_identity_missing');
  assert(pubkeyFingerprint(master.master_pubkey) === master.fingerprint,
    'master_fingerprint_invalid');
  return Object.freeze({ master, identities });
}

function verifyStoredIdentity(row, { masterPubkey, at } = {}) {
  const envelope = decodeCertificate(row.cert);
  const body = envelope.body;
  const authority = body.issuer === HOUSEKEEPER_CUSTODY.AGENT_ID ? row.pubkey : masterPubkey;
  assert(authority, 'certificate_authority_missing');
  const proof = verifyCertChain(row.cert, authority, { nowFn: () => Number(at) });
  assert(proof.valid === true, 'stored_certificate_invalid', proof.reason || 'unknown');
  assert(body.agent_id === row.agent_id
    && body.pubkey === row.pubkey
    && body.device_fp === row.device_fp
    && Number(body.valid_from) === Math.floor(new Date(row.valid_from).getTime() / 1000)
    && Number(body.valid_until) === Math.floor(new Date(row.valid_until).getTime() / 1000)
    && row.is_system_role === true,
  'stored_identity_mismatch');
  return body;
}

function retainedEventReceipt(row) {
  return Object.freeze({
    event_id: row.id,
    proof_required: row.proof_required,
    ledger_version: Number(row.ledger_version),
    ledger_seq: Number(row.ledger_seq),
    signed_body: typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body,
    content_hash: Buffer.from(row.content_hash).toString('hex'),
    mutation_hash: Buffer.from(row.mutation_hash).toString('hex'),
    prev_mutation_hash: Buffer.from(row.prev_mutation_hash).toString('hex'),
    signer_agent_id: row.signer_agent_id,
    signer_valid_from: new Date(row.signer_valid_from).toISOString(),
    cert_fingerprint: row.cert_fingerprint,
    signer_certificate: row.cert,
    identity_tier: row.identity_tier,
    ts_signed: Number(row.ts_signed),
    nonce: row.nonce,
    signature: Buffer.from(row.sig).toString('base64url'),
  });
}

function receiptPath(successorCertificateSha256) {
  return path.join(OUTPUT_ROOT, `housekeeper-custody-${successorCertificateSha256}.json`);
}

function writeExclusiveReceipt(filename, receipt) {
  fs.mkdirSync(OUTPUT_ROOT, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT_ROOT, 0o700);
  assert(!fs.existsSync(filename), 'receipt_exists');
  const descriptor = fs.openSync(filename, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`, 'utf8'));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.chmodSync(filename, 0o600);
  const directory = fs.openSync(OUTPUT_ROOT, fs.constants.O_RDONLY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

function stableReadReceipt(filename) {
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    assert(before.isFile() && !before.isSymbolicLink(), 'receipt_not_regular');
    for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) {
      assert(before[field] === after[field], 'receipt_changed_while_reading');
    }
    return JSON.parse(bytes.toString('utf8'));
  } finally {
    fs.closeSync(descriptor);
  }
}

function runIndependentVerifier(filename) {
  const result = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts', 'verification', 'verify-housekeeper-custody-transition.mjs'),
    '--receipt', filename,
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  assert(result.status === 0, 'independent_verifier_failed',
    String(result.stderr || result.stdout || '').trim().slice(0, 1000));
  try {
    const parsed = JSON.parse(result.stdout);
    assert(parsed.valid === true, 'independent_verifier_invalid');
    return parsed;
  } catch (error) {
    if (String(error?.message || '').startsWith('housekeeper_custody_ceremony_')) throw error;
    fail('independent_verifier_output_invalid');
  }
}

async function recoverExistingPromotion({ master, identities, keyState }) {
  const latest = identities[0];
  const latestBody = verifyStoredIdentity(latest, {
    masterPubkey: master.master_pubkey,
    at: Math.floor(Date.now() / 1000),
  });
  if (latestBody.issuer !== HOUSEKEEPER_CUSTODY.MASTER_ACTOR_ID) return null;
  assert(identities.length >= 2, 'promoted_identity_predecessor_missing');
  const predecessor = identities[1];
  verifyStoredIdentity(predecessor, {
    masterPubkey: master.master_pubkey,
    at: Math.floor(new Date(predecessor.valid_from).getTime() / 1000),
  });
  const continuity = verifyHousekeeperCustodyContinuity({
    predecessorCert: predecessor.cert,
    successorCert: latest.cert,
    masterPubkeyB64u: master.master_pubkey,
    expectedMasterFingerprint: master.fingerprint,
    now: Math.floor(Date.now() / 1000),
  });
  assert(pubkeyEquals(keyState.publicKey, continuity.successor.pubkey),
    'live_key_successor_mismatch');
  const history = await readVerifiedEventHistory(HOUSEKEEPER_CUSTODY.COMPANY_ID);
  const matches = history.filter((row) => row.operation === HOUSEKEEPER_CUSTODY.EVENT_OPERATION
    && row.key === continuity.successor.certificate_sha256);
  assert(matches.length === 1, matches.length === 0
    ? 'promoted_identity_custody_event_missing'
    : 'duplicate_custody_events');
  const event = retainedEventReceipt(matches[0]);
  const approval = event.signed_body?.metadata?.master_approval;
  const receipt = Object.freeze({
    schema: HOUSEKEEPER_CUSTODY.RECEIPT_SCHEMA,
    master_public_key: master.master_pubkey,
    master_fingerprint: master.fingerprint,
    predecessor_certificate: predecessor.cert,
    successor_certificate: latest.cert,
    master_approval: approval,
    housekeeper_event: event,
  });
  const verification = verifyHousekeeperCustodyReceipt(receipt);
  assert(verification.valid === true, 'retained_receipt_invalid', verification.reason || 'unknown');
  const filename = receiptPath(continuity.successor.certificate_sha256);
  if (fs.existsSync(filename)) {
    const retained = stableReadReceipt(filename);
    assert(canonicalJson(retained) === canonicalJson(receipt), 'retained_receipt_conflict');
  } else if (LIVE) {
    writeExclusiveReceipt(filename, receipt);
  }
  const receiptPresent = fs.existsSync(filename);
  const independent = receiptPresent ? runIndependentVerifier(filename) : null;
  return Object.freeze({ receipt, verification, independent, filename, receiptPresent });
}

async function decryptVerifiedMaster(master) {
  const account = argument('--keychain-account') || master.keychain_account;
  assert(account, 'master_keychain_account_missing');
  const encrypted = await keychainGet(master.keychain_service || KC_SERVICE, account);
  assert(encrypted, 'master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase: ');
  const privateKey = decryptMasterPrivkey(passphrase, encrypted);
  assert(privateKey, 'master_passphrase_invalid');
  assert(pubkeyEquals(publicKeyFromPrivate(privateKey), master.master_pubkey),
    'master_private_key_mismatch');
  return Object.freeze({ privateKey, account });
}

async function appendPromotionAtomically({
  predecessor,
  successorCertificate,
  successorBody,
  approval,
  keyState,
} = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      ['hom-aimos:housekeeper-custody-promotion:v1'],
    );
    const locked = await client.query(
      `SELECT agent_id, pubkey, cert, device_fp, valid_from, valid_until,
              issued_at, is_system_role
         FROM agent_identity
        WHERE agent_id = $1
        ORDER BY valid_from DESC
        FOR UPDATE`,
      [HOUSEKEEPER_CUSTODY.AGENT_ID],
    );
    assert(locked.rows.length > 0 && locked.rows[0].cert === predecessor.cert,
      'identity_changed_before_commit');
    assert(!locked.rows.some((row) => row.cert === successorCertificate),
      'successor_already_present');
    await client.query(
      `INSERT INTO agent_identity
         (agent_id, pubkey, cert, device_fp, valid_from, valid_until, issued_at, is_system_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,TRUE)`,
      [
        HOUSEKEEPER_CUSTODY.AGENT_ID,
        successorBody.pubkey,
        successorCertificate,
        successorBody.device_fp,
        new Date(successorBody.valid_from * 1000),
        new Date(successorBody.valid_until * 1000),
        new Date(successorBody.issued_at * 1000),
      ],
    );
    const successorSha256 = sha256Hex(Buffer.from(successorCertificate, 'utf8'));
    const event = await logEvent(
      HOUSEKEEPER_CUSTODY.COMPANY_ID,
      HOUSEKEEPER_CUSTODY.AGENT_ID,
      HOUSEKEEPER_CUSTODY.EVENT_OPERATION,
      successorSha256,
      buildHousekeeperCustodyEventMetadata(approval),
      null,
      {
        client,
        identityQueryFn: (sql, parameters = []) => client.query(sql, parameters),
        authority: housekeeperCustodyAuthorityContext(approval),
        signerConstraint: {
          agent_id: HOUSEKEEPER_CUSTODY.AGENT_ID,
          valid_from: new Date(successorBody.valid_from * 1000).toISOString(),
          cert_fingerprint: successorSha256,
          identity_tier: 'T1',
        },
        exclusiveOperationKey: true,
        returnReceipt: true,
      },
    );
    assert(Number(event.ledger_seq) === 1, 'successor_event_not_genesis');
    await client.query('COMMIT');
    assertKeyGuardUnchanged(keyState);
    return event;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    throw error;
  } finally {
    client.release();
  }
}

async function main() {
  const keyState = keyGuard();
  const state = await loadIdentityState();
  const recovered = await recoverExistingPromotion({
    master: state.master,
    identities: state.identities,
    keyState,
  });
  if (recovered) {
    console.log(JSON.stringify({
      success: true,
      mode: LIVE ? 'LIVE_RECOVERY' : 'DRY_RUN_EXISTING',
      state: 'MASTER_SIGNED_T1',
      stable_key_reused: true,
      genesis_certificate_retained: true,
      receipt: recovered.receiptPresent ? recovered.filename : null,
      receipt_reconstruction_available: !recovered.receiptPresent,
      verification: recovered.verification,
      independent_verification: recovered.independent,
      next: 'Run the ECR-4C dry preflight; it must bind this exact T1 certificate epoch.',
    }, null, 2));
    return;
  }

  const predecessor = state.identities[0];
  const predecessorBody = verifyStoredIdentity(predecessor, {
    masterPubkey: state.master.master_pubkey,
    at: Math.floor(Date.now() / 1000),
  });
  assert(predecessorBody.issuer === HOUSEKEEPER_CUSTODY.AGENT_ID,
    'predecessor_not_genesis_self_signed');
  assert(pubkeyEquals(predecessor.pubkey, keyState.publicKey), 'stable_key_preflight_mismatch');

  const proposedValidFrom = Math.floor(Date.now() / 1000);
  const proposedBody = buildSuccessorCertificateBody({
    predecessorCert: predecessor.cert,
    validFrom: proposedValidFrom,
  });
  console.log(JSON.stringify({
    mode: LIVE ? 'LIVE' : 'DRY_RUN',
    state: 'GENESIS_SELF_SIGNED',
    current_tier: 'T1_SYSTEM_SELF',
    target_tier: 'T1',
    predecessor_certificate_sha256: sha256Hex(Buffer.from(predecessor.cert, 'utf8')),
    stable_pubkey_fingerprint: pubkeyFingerprint(keyState.publicKey),
    successor_certificate_body_sha256: sha256Hex(Buffer.from(canonicalJson(proposedBody), 'utf8')),
    successor_valid_until: new Date(HOUSEKEEPER_CUSTODY.CERTIFICATE_VALID_UNTIL * 1000).toISOString(),
    genesis_certificate_retained: true,
    stable_key_reused: true,
    key_file_modified: false,
    migration_required: false,
    automatic_policy_activation: false,
    live_requirements: [
      'explicit --keychain-account because no locator is retained in the master row',
      'interactive master passphrase',
      'exact confirmation phrase derived from the signed successor and transition approval',
    ],
  }, null, 2));
  if (!LIVE) return;

  const masterKeys = await decryptVerifiedMaster(state.master);
  const validFrom = Math.floor(Date.now() / 1000);
  const issued = issueHousekeeperSuccessorCertificate({
    predecessorCert: predecessor.cert,
    validFrom,
    masterPrivkeyB64u: masterKeys.privateKey,
    masterPubkeyB64u: state.master.master_pubkey,
  });
  const continuity = verifyHousekeeperCustodyContinuity({
    predecessorCert: predecessor.cert,
    successorCert: issued.certificate,
    masterPubkeyB64u: state.master.master_pubkey,
    expectedMasterFingerprint: state.master.fingerprint,
    now: validFrom,
  });
  assert(pubkeyEquals(continuity.successor.pubkey, keyState.publicKey),
    'successor_live_key_mismatch');
  const approvalBody = buildHousekeeperCustodyApprovalBody({
    predecessorCert: predecessor.cert,
    successorCert: issued.certificate,
    masterFingerprint: state.master.fingerprint,
    masterEpoch: state.master.created_at,
    reason: REASON,
    signedTs: validFrom,
  });
  const approval = createHousekeeperCustodyApproval({
    body: approvalBody,
    masterPrivkeyB64u: masterKeys.privateKey,
    masterPubkeyB64u: state.master.master_pubkey,
  });
  const expected = `PROMOTE AIMOS HOUSEKEEPER CUSTODY ${approval.approval_sha256}`;
  const confirmation = await readLine(`Type exactly "${expected}"`);
  assert(confirmation === expected, 'confirmation_mismatch');

  const event = await appendPromotionAtomically({
    predecessor,
    successorCertificate: issued.certificate,
    successorBody: issued.body,
    approval,
    keyState,
  });
  const receipt = Object.freeze({
    schema: HOUSEKEEPER_CUSTODY.RECEIPT_SCHEMA,
    master_public_key: state.master.master_pubkey,
    master_fingerprint: state.master.fingerprint,
    predecessor_certificate: predecessor.cert,
    successor_certificate: issued.certificate,
    master_approval: approval,
    housekeeper_event: event,
  });
  const verification = verifyHousekeeperCustodyReceipt(receipt);
  assert(verification.valid === true, 'native_receipt_verification_failed', verification.reason || 'unknown');
  const filename = receiptPath(continuity.successor.certificate_sha256);
  writeExclusiveReceipt(filename, receipt);
  const independent = runIndependentVerifier(filename);
  console.log(JSON.stringify({
    success: true,
    state: 'MASTER_SIGNED_T1',
    stable_key_reused: true,
    genesis_certificate_retained: true,
    successor_certificate_sha256: continuity.successor.certificate_sha256,
    receipt: filename,
    receipt_sha256: createHash('sha256').update(fs.readFileSync(filename)).digest('hex'),
    verification,
    independent_verification: independent,
    next: 'Run the independent receipt verifier, then the ECR-4C dry preflight.',
  }, null, 2));
}

main().catch(async (error) => {
  console.error(`[FATAL] ${error?.message || error}`);
  process.exitCode = 1;
}).finally(async () => {
  try { await Promise.allSettled([pool.end(), agentPool.end()]); } catch { /* ignore */ }
});
