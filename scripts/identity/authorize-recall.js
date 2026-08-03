#!/usr/bin/env node
// Append a master-signed memory read/write grant or revoke for one exact agent epoch.
// No agent can self-grant memory access authority.

import os from 'node:os';
import { pool } from '../../db/connection.js';
import { recallAuthorizationService } from '../../services/security/recall-authorization.js';
import { decryptMasterPrivkey, KC_ACCOUNT_DEFAULT, KC_SERVICE } from './lib.js';
import { keychainGet } from './keychain.js';
import * as identityDb from './db.js';
import { readLine, readPassphrase } from './passphrase.js';

const args = process.argv.slice(2);
const positional = args.filter((arg) => !arg.startsWith('--'));
const agentId = positional[0];
const revoke = args.includes('--revoke');
const writeAllowed = args.includes('--write');
const dryRun = args.includes('--dry-run');
const clearanceArg = args.find((arg) => arg.startsWith('--clearance='));
const dataClassArg = args.find((arg) => arg.startsWith('--data-class='));
const reasonArg = args.find((arg) => arg.startsWith('--reason='));

function valueOf(arg) {
  return arg ? arg.split('=').slice(1).join('=') : null;
}

if (!agentId || !reasonArg || (!revoke && (!clearanceArg || !dataClassArg))) {
  console.error('Usage: authorize-recall.js <agent_id> --clearance=0..12 --data-class=public|internal|confidential|restricted --reason=<text> [--write] [--revoke] [--dry-run]');
  process.exit(64);
}

async function main() {
  const master = await identityDb.getMaster();
  if (!master) throw new Error('no_master_enrolled');
  const agent = await identityDb.getAgent(agentId);
  if (!agent) throw new Error('agent_epoch_not_active');
  if (agent.agent_id === 'housekeeper') throw new Error('system_role_recall_authority_is_intrinsic');

  const osUser = (os.userInfo().username || '').trim() || null;
  const keychainService = master.keychain_service || KC_SERVICE;
  const keychainAccount = master.keychain_account || KC_ACCOUNT_DEFAULT
    || await readLine('Keychain account name', { default: osUser });
  if (!keychainAccount) throw new Error('master_keychain_account_required');
  const blob = await keychainGet(keychainService, keychainAccount);
  if (!blob) throw new Error('master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase: ');
  const masterPrivkeyB64u = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkeyB64u) throw new Error('wrong_passphrase_or_tampered_keychain_blob');

  const result = await recallAuthorizationService.commit({
    companyId: 'hom',
    subjectAgentId: agentId,
    subjectValidFrom: agent.valid_from,
    allowed: !revoke,
    writeAllowed: revoke ? false : writeAllowed,
    clearanceCeiling: revoke ? 0 : Number(valueOf(clearanceArg)),
    dataClassCeiling: revoke ? 'public' : valueOf(dataClassArg),
    masterPrivkeyB64u,
    masterFingerprint: master.fingerprint,
    reason: valueOf(reasonArg),
    dryRun,
  });

  console.log(dryRun ? '[DRY-RUN] recall authorization proof verified' : '[OK] recall authorization event appended');
  console.log(`     agent_id:       ${agentId}`);
  console.log(`     valid_from:     ${new Date(agent.valid_from).toISOString()}`);
  console.log(`     allowed:        ${!revoke}`);
  console.log(`     write_allowed:  ${revoke ? false : writeAllowed}`);
  console.log(`     clearance:      ${revoke ? 0 : Number(valueOf(clearanceArg))}`);
  console.log(`     data_class:     ${revoke ? 'public' : valueOf(dataClassArg)}`);
  console.log(`     content_hash:   ${Buffer.from(result.contentHash).toString('hex')}`);
  console.log(`     mutation_hash:  ${Buffer.from(result.mutationHash).toString('hex')}`);
  if (result.recall_authorization_event_id) {
    console.log(`     event_id:       ${result.recall_authorization_event_id}`);
  }
  await pool.end();
}

main().catch(async (error) => {
  console.error('[ERR]', error?.message || error);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
