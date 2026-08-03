#!/usr/bin/env node
// scripts/identity/revoke-agent.js
// Revoke one exact agent enrollment with a retained master-signed terminal
// event. The identity row, certificate, and key history are never deleted.
//
// Usage:
//   node scripts/identity/revoke-agent.js <agent_id>
//   node scripts/identity/revoke-agent.js <agent_id> --dry-run

import os from 'node:os';
import { revokeAgentWithDeps, KC_SERVICE, KC_ACCOUNT_DEFAULT } from './lib.js';
import { keychainGet, keychainSet } from './keychain.js';
import * as identityDb from './db.js';
import { readPassphrase, readLine } from './passphrase.js';
import { pool } from '../../db/connection.js';

const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const positional = args.filter(a => !a.startsWith('--'));
const agentId = positional[0];

if (!agentId) {
  console.error('Usage: revoke-agent.js <agent_id> [--dry-run]');
  process.exit(64);
}

async function main() {
  const masterRow = await identityDb.getMaster();
  if (!masterRow) {
    console.error('[ERR] no master enrolled');
    process.exit(2);
  }
  // Migration 048 persists the selected locator. Prompt only for a legacy
  // master row that predates that non-secret metadata.
  const osUser = (os.userInfo().username || '').trim() || null;
  const kcService = masterRow.keychain_service || KC_SERVICE;
  const kcAccount = masterRow.keychain_account || KC_ACCOUNT_DEFAULT
    || await readLine('Keychain account name', { default: osUser });
  if (!kcAccount) {
    console.error('[ERR] keychain account name is required (no default — pick one)');
    process.exit(7);
  }

  console.log('Aimos agent revocation');
  console.log('=======================');
  console.log(`Agent ID:  ${agentId}`);
  console.log(`Mode:      ${DRY_RUN ? 'DRY-RUN (no side effects)' : 'LIVE'}`);
  console.log();

  const existing = await identityDb.getAgent(agentId);
  if (!existing) {
    console.error(`[ERR] no active enrollment for ${agentId}`);
    process.exit(2);
  }
  console.log(`[OK] active enrollment found (valid_from=${existing.valid_from})`);

  const passphrase = await readPassphrase('Master passphrase: ');

  const result = await revokeAgentWithDeps(agentId, passphrase, {
    keychain: { get: keychainGet, set: keychainSet },
    db: identityDb,
    kcService,
    kcAccount
  }, { dryRun: DRY_RUN });

  if (!result.ok) {
    console.error(`[ERR] ${result.reason}`);
    process.exit(3);
  }

  if (DRY_RUN) {
    console.log('[DRY-RUN] master passphrase and revocation proof verified.');
    console.log(`          content_hash:  ${result.contentHash.toString('hex')}`);
    console.log(`          mutation_hash: ${result.mutationHash.toString('hex')}`);
    console.log('[DRY-RUN] no side effects performed.');
    await pool.end();
    return;
  }

  console.log();
  console.log('[OK] agent revoked');
  console.log(`     agent_id:       ${result.agentId}`);
  console.log(`     valid_from:     ${new Date(result.agentValidFrom).toISOString()}`);
  console.log(`     revoked_at:     ${new Date(result.revokedAt).toISOString()}`);
  console.log(`     event_id:       ${result.revocationEventId}`);
  console.log(`     content_hash:   ${result.contentHash.toString('hex')}`);
  console.log(`     mutation_hash:  ${result.mutationHash.toString('hex')}`);

  await pool.end();
}

main().catch(async (e) => {
  console.error('[FATAL]', e?.message || e);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
