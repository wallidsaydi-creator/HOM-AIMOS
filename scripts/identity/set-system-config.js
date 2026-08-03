#!/usr/bin/env node
// scripts/identity/set-system-config.js
// Set a system config value (OPERATOR_AGENT_ID, etc.) via a cert-enveloped,
// hash-chained append to aimos_system_config (migration 028). The delegation
// is signed by the operator's MASTER identity (the trust root, encrypted in
// macOS keychain) — NOT by an agent, NOT by a system identity. Any operator
// can enroll a master and delegate their own operator agent.
//
// Replaces legacy mutable and hardcoded system-level configuration. This CLI
// puts operator delegation in the same audit plane as the mutations it
// authorizes.
//
// Usage:
//   node scripts/identity/set-system-config.js <CONFIG_KEY> <VALUE> --reason=<text>
//   node scripts/identity/set-system-config.js OPERATOR_AGENT_ID alice --reason="designate alice as operator agent"
//   node scripts/identity/set-system-config.js OPERATOR_AGENT_ID "" --reason="unset operator agent (autonomous tasks skip)"
//
// Optional:
//   --operator=<username>   override the recorded operator (defaults to os.userInfo().username)
//   --kc-account=<name>     override the keychain account name (defaults to KC_ACCOUNT_DEFAULT)
//
// There is no environment-variable fallback for the master passphrase;
// interactive input is mandatory.

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from '../../db/connection.js';
import {
  systemConfigLedger,
  SYSTEM_CONFIG_CONSTANTS
} from '../../services/security/system-config-ledger.js';
import {
  KC_SERVICE,
  KC_ACCOUNT_DEFAULT,
  decryptMasterPrivkey
} from './lib.js';
import { keychainGet } from './keychain.js';
import * as identityDb from './db.js';
import { readPassphrase } from './passphrase.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith('--'));
const reasonArg = args.find(a => a.startsWith('--reason='));
const operatorArg = args.find(a => a.startsWith('--operator='));
const kcAccountArg = args.find(a => a.startsWith('--kc-account='));

const configKey = positional[0];
const value = positional.slice(1).join(' ');

function usage() {
  console.error('Usage: set-system-config.js <CONFIG_KEY> <VALUE> --reason=<text> [--operator=<username>] [--kc-account=<name>]');
  console.error('Allowed CONFIG_KEY values:');
  for (const k of SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS) {
    console.error('  ' + k);
  }
  console.error('Use an empty VALUE ("") to unset (append a row with empty string — Aladdin-compliant, no UPDATE/DELETE).');
  process.exit(64);
}

if (!configKey) {
  usage();
}

if (!SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes(configKey)) {
  console.error(`[FATAL] unknown CONFIG_KEY: "${configKey}"`);
  console.error('        Allowed values:');
  for (const k of SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS) {
    console.error('          ' + k);
  }
  process.exit(64);
}

if (positional.length < 2) {
  console.error('[FATAL] VALUE argument required (use "" to unset)');
  usage();
}

if (!reasonArg || reasonArg.split('=')[1]?.length === 0) {
  console.error('[FATAL] --reason=<text> is required for auditability');
  process.exit(64);
}
const reason = reasonArg.split('=').slice(1).join('=');
const operator = operatorArg
  ? operatorArg.split('=').slice(1).join('=')
  : os.userInfo().username;
const kcAccount = kcAccountArg
  ? kcAccountArg.split('=').slice(1).join('=')
  : KC_ACCOUNT_DEFAULT;

async function main() {
  console.log('Aimos system config delegation');
  console.log('===============================');
  console.log(`Config key:       ${configKey}`);
  console.log(`Value:            "${value}"`);
  console.log(`Reason:           ${reason}`);
  console.log(`Operator:         ${operator}`);
  console.log(`Brain root:       ${BRAIN_ROOT}`);
  console.log(`Keychain account: ${kcAccount}`);
  console.log(`Signer:           operator's master identity (T0 trust root)`);
  console.log();

  // Pre-check: master exists?
  const masterRow = await identityDb.getMaster();
  if (!masterRow) {
    console.error('[FATAL] no master enrolled. Run enroll-master.js first.');
    process.exit(2);
  }
  console.log(`[OK] master found (fingerprint: ${masterRow.fingerprint})`);

  // Pre-check: keychain blob exists?
  const blob = await keychainGet(KC_SERVICE, kcAccount);
  if (!blob) {
    console.error(`[FATAL] master privkey blob not found in keychain`);
    console.error(`        service="${KC_SERVICE}" account="${kcAccount}"`);
    console.error('        Re-run enroll-master.js, or pass --kc-account=<name>');
    process.exit(3);
  }
  console.log('[OK] master privkey blob present in keychain');
  console.log();

  // Prompt passphrase (interactive-only, no env fallback).
  const passphrase = await readPassphrase('Master passphrase: ');

  const masterPrivkeyB64u = decryptMasterPrivkey(passphrase, blob);
  if (!masterPrivkeyB64u) {
    console.error('[FATAL] wrong passphrase or tampered keychain blob');
    process.exit(4);
  }
  console.log('[OK] master privkey decrypted');
  console.log();

  console.log('Signing + committing to aimos_system_config ...');
  const result = await systemConfigLedger.commitConfigValue({
    configKey,
    value,
    reason,
    operator,
    masterPrivkeyB64u,
    masterFingerprint: masterRow.fingerprint
  });

  if (!result.ok) {
    console.error(`[FATAL] commit failed: ${result.reason}`);
    if (result.detail) console.error(`        detail: ${result.detail}`);
    await pool.end();
    process.exit(1);
  }

  const mutHex = Buffer.from(result.mutationHash).toString('hex');
  const prevHex = result.prevMutationHash ? Buffer.from(result.prevMutationHash).toString('hex') : '<genesis>';
  console.log();
  console.log('[OK] system config delegation committed');
  console.log(`  config_key:        ${configKey}`);
  console.log(`  value_text:        "${value}"`);
  console.log(`  is_genesis:        ${result.isGenesis}`);
  console.log(`  ts_signed:         ${result.tsSigned}`);
  console.log(`  cert_fingerprint:  ${result.certFingerprint}`);
  console.log(`  mutation_hash:     ${mutHex}`);
  console.log(`  prev_mutation_hash: ${prevHex}`);
  console.log();
  console.log('The systemConfigStore picks up the new state on next SIGHUP or restart.');
  console.log('To reload the live AIMOS server only: kill -SIGHUP "$(lsof -tiTCP:9100 -sTCP:LISTEN)"');
  console.log('To verify: SELECT config_key, value_text, is_genesis, ts_signed FROM aimos_system_config ORDER BY created_at DESC;');

  await pool.end();
}

main().catch(async (err) => {
  console.error(`[FATAL] unexpected error: ${err?.message || err}`);
  if (err?.stack) console.error(err.stack);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(2);
});
