#!/usr/bin/env node
// scripts/identity/enroll-master.js
// One-time master enrollment ceremony. Generates an Ed25519 master keypair,
// encrypts the private key with a user-chosen passphrase, stores the
// ciphertext in the macOS Keychain, and writes the public key + fingerprint
// to aimos_master_identity.
//
// Usage:
//   node scripts/identity/enroll-master.js
//   node scripts/identity/enroll-master.js --dry-run
//
// Refuses if a master is already enrolled. Manual rotation requires direct
// DB intervention and is intentionally NOT exposed as a CLI flag.

import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { enrollMasterWithDeps, KC_SERVICE, KC_ACCOUNT_DEFAULT } from './lib.js';
import { keychainGet, keychainSet } from './keychain.js';
import * as identityDb from './db.js';
import { readPassphrase, readLine } from './passphrase.js';
import { pool } from '../../db/connection.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const DRY_RUN = process.argv.includes('--dry-run');

async function main() {
  // Resolve the keychain account name. No hardcoded operator default —
  // the reviewer types their own account name (default: their OS username).
  const osUser = (os.userInfo().username || '').trim() || null;
  const kcAccount = KC_ACCOUNT_DEFAULT
    ? KC_ACCOUNT_DEFAULT
    : await readLine('Keychain account name', { default: osUser });
  if (!kcAccount) {
    console.error('[ERR] keychain account name is required (no default — pick one)');
    process.exit(7);
  }

  console.log('Aimos master enrollment');
  console.log('========================');
  console.log(`Brain root:    ${BRAIN_ROOT}`);
  console.log(`KC service:    ${KC_SERVICE}`);
  console.log(`KC account:    ${kcAccount}`);
  console.log(`Mode:          ${DRY_RUN ? 'DRY-RUN (no side effects)' : 'LIVE'}`);
  console.log();

  // Pre-check: master already exists?
  const existing = await identityDb.getMaster();
  if (existing) {
    console.error(`[ERR] master already enrolled (fingerprint: ${existing.fingerprint})`);
    console.error('      Manual rotation requires direct DB intervention.');
    process.exit(2);
  }

  // A Keychain entry without a DB row is a recoverable interrupted ceremony.
  // The enrollment primitive decrypts it, derives the public key, and resumes
  // the DB commit without deleting or replacing key material.
  const existingBlob = await keychainGet(KC_SERVICE, kcAccount);
  if (existingBlob) {
    console.log(`[RECOVERY] encrypted master key found at ${KC_SERVICE}/${kcAccount}; enrollment will resume.`);
  }

  const pass1 = await readPassphrase('Choose master passphrase: ');
  if (pass1.length < 8) {
    console.error('[ERR] passphrase must be at least 8 characters');
    process.exit(4);
  }
  const pass2 = await readPassphrase('Confirm passphrase:        ');
  if (pass1 !== pass2) {
    console.error('[ERR] passphrases do not match');
    process.exit(5);
  }

  if (DRY_RUN) {
    console.log('[DRY-RUN] inputs validated; would now generate keypair, encrypt,');
    console.log('[DRY-RUN] write keychain entry, and INSERT aimos_master_identity row.');
    console.log('[DRY-RUN] no side effects performed.');
    await pool.end();
    return;
  }

  const result = await enrollMasterWithDeps(pass1, {
    keychain: { get: keychainGet, set: keychainSet },
    db: identityDb,
    kcService: KC_SERVICE,
    kcAccount,
    brainRoot: BRAIN_ROOT
  });

  if (!result.ok) {
    console.error(`[ERR] ${result.reason}`);
    process.exit(6);
  }

  console.log();
  console.log('[OK] master enrolled');
  if (result.recovered) console.log('     ceremony: recovered interrupted Keychain→DB commit');
  console.log(`     fingerprint: ${result.fingerprint}`);
  console.log();
  console.log('Next: enroll an agent with');
  console.log('  node scripts/identity/enroll-agent.js <agent_id>');

  await pool.end();
}

main().catch(async (e) => {
  console.error('[FATAL]', e?.message || e);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
