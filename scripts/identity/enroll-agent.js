#!/usr/bin/env node
// scripts/identity/enroll-agent.js
// Enroll an agent under the master. Prompts master passphrase, generates
// agent keypair, signs a 30-day cert, stores agent privkey at
// ~/.aimos/agents/<agent_id>.key (mode 0600), writes row to agent_identity.
//
// Usage:
//   node scripts/identity/enroll-agent.js <agent_id>
//   node scripts/identity/enroll-agent.js <agent_id> --validity-days=30
//   node scripts/identity/enroll-agent.js <agent_id> --dry-run

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import os from 'node:os';
import {
  enrollAgentWithDeps,
  KC_SERVICE,
  KC_ACCOUNT_DEFAULT
} from './lib.js';
import { keychainGet, keychainSet } from './keychain.js';
import * as identityDb from './db.js';
import { readPassphrase, readLine } from './passphrase.js';
import { pool } from '../../db/connection.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const validityArg = args.find(a => a.startsWith('--validity-days='));
const validityDays = validityArg ? parseInt(validityArg.split('=')[1], 10) : 30;
const positional = args.filter(a => !a.startsWith('--'));
const agentId = positional[0];

if (!agentId) {
  console.error('Usage: enroll-agent.js <agent_id> [--validity-days=N] [--dry-run]');
  process.exit(64);
}

const AGENTS_DIR = path.join(os.homedir(), '.aimos', 'agents');
const AGENT_KEY_PATH = path.join(AGENTS_DIR, `${agentId}.key`);

async function main() {
  // The master ceremony permits a custom Keychain account. Agent enrollment
  // must ask for the same account; KC_ACCOUNT_DEFAULT is intentionally null.
  const osUser = (os.userInfo().username || '').trim() || null;
  const kcAccount = KC_ACCOUNT_DEFAULT
    ? KC_ACCOUNT_DEFAULT
    : await readLine('Keychain account name', { default: osUser });
  if (!kcAccount) {
    console.error('[ERR] keychain account name is required');
    process.exit(7);
  }

  console.log('Aimos agent enrollment');
  console.log('=======================');
  console.log(`Agent ID:       ${agentId}`);
  console.log(`Validity:       ${validityDays} days`);
  console.log(`Brain root:     ${BRAIN_ROOT}`);
  console.log(`KC account:     ${kcAccount}`);
  console.log(`Key path:       ${AGENT_KEY_PATH}`);
  console.log(`Mode:           ${DRY_RUN ? 'DRY-RUN (no side effects)' : 'LIVE'}`);
  console.log();

  // Pre-check: master exists?
  const masterRow = await identityDb.getMaster();
  if (!masterRow) {
    console.error('[ERR] no master enrolled. Run enroll-master.js first.');
    process.exit(2);
  }
  console.log(`[OK] master found (fingerprint: ${masterRow.fingerprint})`);

  // Pre-check: agent privkey file already exists?
  if (!DRY_RUN && existsSync(AGENT_KEY_PATH)) {
    console.error(`[ERR] ${AGENT_KEY_PATH} already exists. Move or delete first.`);
    process.exit(3);
  }

  // Pre-check: active agent row already exists?
  const existingAgent = await identityDb.getAgent(agentId);
  if (existingAgent) {
    console.error(`[ERR] active agent_identity row exists for ${agentId} (valid_from=${existingAgent.valid_from})`);
    console.error('      Revoke first with: node scripts/identity/revoke-agent.js ' + agentId);
    process.exit(4);
  }

  const passphrase = await readPassphrase('Master passphrase: ');

  if (DRY_RUN) {
    console.log('[DRY-RUN] inputs validated; would now decrypt master, generate agent');
    console.log('[DRY-RUN] keypair, sign 30-day cert, write key file, and INSERT row.');
    console.log('[DRY-RUN] no side effects performed.');
    await pool.end();
    return;
  }

  const result = await enrollAgentWithDeps(agentId, passphrase, {
    keychain: { get: keychainGet, set: keychainSet },
    db: identityDb,
    kcService: KC_SERVICE,
    kcAccount,
    brainRoot: BRAIN_ROOT
  }, { validityDays });

  if (!result.ok) {
    console.error(`[ERR] ${result.reason}${result.detail ? ': ' + result.detail : ''}`);
    process.exit(5);
  }

  // Write agent privkey to disk, mode 0600.
  if (!existsSync(AGENTS_DIR)) {
    mkdirSync(AGENTS_DIR, { recursive: true, mode: 0o700 });
  }
  writeFileSync(AGENT_KEY_PATH, result.agentPrivkey, { mode: 0o600 });
  chmodSync(AGENT_KEY_PATH, 0o600);

  console.log();
  console.log('[OK] agent enrolled');
  console.log(`     agent_id:      ${agentId}`);
  console.log(`     fingerprint:   ${result.fingerprint}`);
  console.log(`     device_fp:     ${result.deviceFp.slice(0, 16)}...`);
  console.log(`     valid_from:    ${new Date(result.validFrom * 1000).toISOString()}`);
  console.log(`     valid_until:   ${new Date(result.validUntil * 1000).toISOString()}`);
  console.log(`     key file:      ${AGENT_KEY_PATH} (mode 0600)`);

  await pool.end();
}

main().catch(async (e) => {
  console.error('[FATAL]', e?.message || e);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
