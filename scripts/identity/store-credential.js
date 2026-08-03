#!/usr/bin/env node
// scripts/identity/store-credential.js
// Credential Lifecycle Ledger CLI — STORE / ROTATE / REVOKE subcommands.
//
// Credentials live in macOS keychain at
// `com.aimos.credentials.<service>`; their lifecycle (store/rotate/revoke)
// is signed by the housekeeper identity and committed to
// aimos_credential_lifecycle. The plaintext is NEVER in the ledger —
// only sha256(plaintext) (the cryptographic closure that lets the auditor
// detect rotations even if a ROTATE event was missed).
//
// Trust boundary:
//   . Operator (master) invokes this CLI with the master passphrase
//   . Housekeeper signs the lifecycle row (server-side system identity)
//   . Ordinary agents do NOT invoke this CLI — they can only add new
//     credentials via the same housekeeper-signed path (append-only, full
//     retention makes append safe). ROTATE/REVOKE are operator/housekeeper only.
//
// There is no environment-variable fallback for the credential value;
// interactive readPassphrase is the only input path.
//
// Usage:
//   node scripts/identity/store-credential.js STORE --service=brave --reason="initial enrollment"
//   node scripts/identity/store-credential.js ROTATE --service=brave --reason="quarterly rotation"
//   node scripts/identity/store-credential.js REVOKE --service=brave --reason="leak response 2026-07-08"
//
// Optional:
//   --operator=<username>   override the recorded operator (defaults to os.userInfo().username)

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from '../../db/connection.js';
import { credentialLedger } from '../../services/security/credential-ledger.js';
import {
  credentialSlotId,
  computeCredentialHash,
  storeCredential,
  readCredential,
  revokeCredential,
  credentialExists,
  parseIdentityVaultCredentialService,
} from '../../services/security/credential-store.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';
import { readPassphrase } from './passphrase.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
const subcommand = args.find(a => !a.startsWith('--'));
const serviceArg = args.find(a => a.startsWith('--service='));
const reasonArg = args.find(a => a.startsWith('--reason='));
const operatorArg = args.find(a => a.startsWith('--operator='));

function usage() {
  console.error('Usage: store-credential.js <STORE|ROTATE|REVOKE> --service=<name> --reason=<text> [--operator=<username>]');
  console.error('  STORE   — place a new credential in keychain + sign lifecycle row');
  console.error('  ROTATE  — supersede old credential with new (old row stays, new row references it)');
  console.error('  REVOKE  — mark credential unusable; encrypted historical version remains retained');
  console.error('');
  console.error('  --service=<name>    required, lowercase letters/digits/_/- only');
  console.error('  --reason=<text>     required, auditability');
  console.error('  --operator=<name>   optional, defaults to OS username');
  console.error('');
  console.error('Credential value is interactive-only.');
  console.error('Re-run via `! node ...` so the prompt can read from the TTY.');
  process.exit(64);
}

if (!subcommand || !['STORE', 'ROTATE', 'REVOKE'].includes(subcommand.toUpperCase())) {
  console.error(`[FATAL] subcommand required: STORE | ROTATE | REVOKE (got "${subcommand || '<missing>'}")`);
  usage();
}

if (!serviceArg) {
  console.error('[FATAL] --service=<name> is required');
  usage();
}

if (!reasonArg || reasonArg.split('=').slice(1).join('=').length === 0) {
  console.error('[FATAL] --reason=<text> is required for auditability');
  usage();
}

const eventType = subcommand.toUpperCase();
const service = serviceArg.split('=')[1].trim().toLowerCase();
const reason = reasonArg.split('=').slice(1).join('=');
const operator = operatorArg
  ? operatorArg.split('=').slice(1).join('=')
  : os.userInfo().username;

async function promptCredentialValue(prompt) {
  const value = await readPassphrase(prompt);
  if (!value) {
    console.error('[FATAL] empty credential value — nothing to store');
    process.exit(64);
  }
  return value;
}

function identityVaultBinding() {
  const parsed = parseIdentityVaultCredentialService(service);
  if (!parsed) return {};
  return {
    identity_vault: {
      namespace: 'identity_vault',
      company_id: AIMOS_COMPANY_ID,
      provider: parsed.provider,
      credential_kind: parsed.credentialKind,
      expires_at: null,
      metadata: {},
      auth_type: 'oauth',
      cluster_id: 'identity_vault.auth',
      initiating_subject_agent_id: 'housekeeper',
      credential_use_evidence: [],
    },
  };
}

async function doStore() {
  if (await credentialExists(service)) {
    console.error(`[FATAL] credential already exists for service "${service}" — use ROTATE to supersede, not STORE`);
    console.error('        STORE is for new slots only (append-only law — never overwrite)');
    process.exit(2);
  }

  console.log('Credential Lifecycle Ledger — STORE');
  console.log('==================================');
  console.log(`Service:          ${service}`);
  console.log(`Slot:             ${credentialSlotId(service)}`);
  console.log(`Reason:           ${reason}`);
  console.log(`Operator:         ${operator}`);
  console.log(`Brain root:       ${BRAIN_ROOT}`);
  console.log(`Signer:           housekeeper (T1 system operational identity)`);
  console.log();

  const value = await promptCredentialValue(`Enter credential value for ${service}: `);
  const hash = computeCredentialHash(value);

  console.log();
  console.log('[OK] credential value read (will not echo)');
  console.log(`     sha256 hash:  ${hash}`);
  console.log();

  // Store in keychain first — if this fails, no ledger row is written.
  const stored = await storeCredential(service, value);
  console.log(`[OK] plaintext stored in keychain at ${stored.slot}`);
  console.log();

  // Sign + commit the lifecycle row.
  const body = {
    event_type: 'STORE',
    service,
    slot_id: credentialSlotId(service),
    credential_hash: hash,
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: null,
    rotated_from: null,
    reason,
    operator,
    signer_agent_id: 'housekeeper',
    ...identityVaultBinding(),
    // ts_signed injected by signAsHousekeeper
  };

  const signed = await signAsHousekeeper(body);
  const commit = await credentialLedger.commitCredentialLifecycle({
    serviceName: service,
    slotId: body.slot_id,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType: 'STORE',
    bodyJson: signed.body
  });

  if (!commit.ok) {
    console.error(`[FATAL] ledger commit failed: ${commit.reason}`);
    console.error('        Plaintext is already in keychain — re-run with REVOKE to undo, or investigate the ledger.');
    await pool.end();
    process.exit(1);
  }

  const mutHex = Buffer.from(commit.mutationHash).toString('hex');
  const prevHex = commit.prevMutationHash ? Buffer.from(commit.prevMutationHash).toString('hex') : '<genesis>';
  console.log('[OK] credential lifecycle STORE row committed');
  console.log(`  service:           ${service}`);
  console.log(`  slot_id:           ${body.slot_id}`);
  console.log(`  credential_hash:   ${hash}`);
  console.log(`  is_genesis:        ${commit.isGenesis}`);
  console.log(`  ts_signed:         ${signed.signedTs}`);
  console.log(`  mutation_hash:     ${mutHex}`);
  console.log(`  prev_mutation_hash: ${prevHex}`);
  console.log();
  console.log('To verify: SELECT service_name, event_type, body_json->>\'credential_hash\' AS hash, ts_signed');
  console.log('             FROM aimos_credential_lifecycle WHERE slot_id = \'' + body.slot_id + '\' ORDER BY created_at DESC;');
  console.log('To reload a live AIMOS server only: kill -SIGHUP "$(lsof -tiTCP:9100 -sTCP:LISTEN)"');

  await pool.end();
}

async function doRotate() {
  const existing = await readCredential(service);
  if (!existing) {
    console.error(`[FATAL] no credential exists for service "${service}" — use STORE to create a new slot`);
    process.exit(2);
  }

  // Fetch the prior STORE/ROTATE row for rotated_from reference.
  const priorRow = await credentialLedger.getLatestStoreForSlot(credentialSlotId(service));
  if (!priorRow) {
    console.error(`[FATAL] no prior STORE/ROTATE ledger row for slot "${credentialSlotId(service)}"`);
    console.error('        Run backfill-credentials.mjs first to backfill existing credentials, or investigate.');
    process.exit(3);
  }

  console.log('Credential Lifecycle Ledger — ROTATE');
  console.log('====================================');
  console.log(`Service:          ${service}`);
  console.log(`Slot:             ${credentialSlotId(service)}`);
  console.log(`Reason:           ${reason}`);
  console.log(`Operator:         ${operator}`);
  console.log(`Rotating from:    provenance_id=${priorRow.provenance_id} (hash=${priorRow.body_json?.credential_hash?.slice(0,16)}...)`);
  console.log();

  const newValue = await promptCredentialValue(`Enter NEW credential value for ${service}: `);
  const newHash = computeCredentialHash(newValue);

  console.log();
  console.log('[OK] new credential value read (will not echo)');
  console.log(`     new sha256 hash:  ${newHash}`);
  console.log();

  // Append the new version and atomically move the logical Keychain pointer.
  // Prior encrypted versions and every lifecycle row remain retained.
  const stored = await storeCredential(service, newValue);
  console.log(`[OK] new plaintext version stored in keychain at ${stored.versionSlot}; logical pointer=${stored.slot}`);
  console.log();

  const body = {
    event_type: 'ROTATE',
    service,
    slot_id: credentialSlotId(service),
    credential_hash: newHash,
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: null,
    rotated_from: priorRow.provenance_id,
    rotated_from_hash: priorRow.body_json?.credential_hash || null,
    reason,
    operator,
    signer_agent_id: 'housekeeper',
    ...identityVaultBinding(),
  };

  const signed = await signAsHousekeeper(body);
  const commit = await credentialLedger.commitCredentialLifecycle({
    serviceName: service,
    slotId: body.slot_id,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType: 'ROTATE',
    bodyJson: signed.body
  });

  if (!commit.ok) {
    console.error(`[FATAL] ledger commit failed: ${commit.reason}`);
    console.error('        New plaintext is already in keychain — the old row is still in the ledger (audit intact).');
    console.error('        Investigate the ledger, then re-run ROTATE.');
    await pool.end();
    process.exit(1);
  }

  const mutHex = Buffer.from(commit.mutationHash).toString('hex');
  console.log('[OK] credential lifecycle ROTATE row committed');
  console.log(`  service:           ${service}`);
  console.log(`  slot_id:           ${body.slot_id}`);
  console.log(`  new credential_hash: ${newHash}`);
  console.log(`  rotated_from:      ${priorRow.provenance_id}`);
  console.log(`  ts_signed:         ${signed.signedTs}`);
  console.log(`  mutation_hash:     ${mutHex}`);
  console.log();
  console.log('The old credential is superseded but not deleted from the ledger (append-only law).');
  console.log('Auditors can prove: before ts_signed, the old hash was active; after, the new hash is active.');

  await pool.end();
}

async function doRevoke() {
  const existing = await readCredential(service);
  if (!existing) {
    console.error(`[FATAL] no credential exists for service "${service}" — nothing to revoke`);
    process.exit(2);
  }

  const priorRow = await credentialLedger.getLatestStoreForSlot(credentialSlotId(service));
  if (!priorRow) {
    console.error(`[FATAL] no prior STORE/ROTATE ledger row for slot "${credentialSlotId(service)}" — cannot revoke cleanly`);
    process.exit(3);
  }

  console.log('Credential Lifecycle Ledger — REVOKE');
  console.log('====================================');
  console.log(`Service:          ${service}`);
  console.log(`Slot:             ${credentialSlotId(service)}`);
  console.log(`Reason:           ${reason}`);
  console.log(`Operator:         ${operator}`);
  console.log(`Revoking row:     provenance_id=${priorRow.provenance_id} (hash=${priorRow.body_json?.credential_hash?.slice(0,16)}...)`);
  console.log();

  const body = {
    event_type: 'REVOKE',
    service,
    slot_id: credentialSlotId(service),
    credential_hash: priorRow.body_json?.credential_hash || null,
    valid_from: priorRow.body_json?.valid_from || null,
    valid_until: Math.floor(Date.now() / 1000),
    revoked_provenance_id: priorRow.provenance_id,
    reason,
    operator,
    signer_agent_id: 'housekeeper'
  };

  const signed = await signAsHousekeeper(body);
  const commit = await credentialLedger.commitCredentialLifecycle({
    serviceName: service,
    slotId: body.slot_id,
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    eventType: 'REVOKE',
    bodyJson: signed.body
  });

  if (!commit.ok) {
    console.error(`[FATAL] ledger commit failed: ${commit.reason}`);
    console.error('        Plaintext is still in keychain — investigate the ledger, then re-run REVOKE.');
    await pool.end();
    process.exit(1);
  }

  console.log('[OK] credential lifecycle REVOKE row committed');
  console.log('     Revoking the logical Keychain pointer while retaining encrypted history ...');

  const revoked = await revokeCredential(service);
  if (!revoked.revoked) {
    console.error(`[WARN] Keychain pointer was already revoked or absent.`);
  } else {
    console.log(`[OK] logical Keychain pointer revoked at ${revoked.slot}; prior version remains retained.`);
  }

  const mutHex = Buffer.from(commit.mutationHash).toString('hex');
  console.log();
  console.log(`  service:           ${service}`);
  console.log(`  slot_id:           ${body.slot_id}`);
  console.log(`  revoked_hash:      ${body.credential_hash}`);
  console.log(`  valid_until:       ${body.valid_until}`);
  console.log(`  ts_signed:         ${signed.signedTs}`);
  console.log(`  mutation_hash:     ${mutHex}`);
  console.log();
  console.log('The credential is now revoked and unusable. Its encrypted historical version remains retained under Aladdin Law.');

  await pool.end();
}

async function main() {
  try {
    if (eventType === 'STORE') await doStore();
    else if (eventType === 'ROTATE') await doRotate();
    else if (eventType === 'REVOKE') await doRevoke();
    else {
      console.error(`[FATAL] unknown subcommand: ${eventType}`);
      usage();
    }
  } catch (err) {
    console.error(`[FATAL] ${err?.message || err}`);
    if (err?.stack) console.error(err.stack);
    try { await pool.end(); } catch { /* ignore */ }
    process.exit(2);
  }
}

main();
