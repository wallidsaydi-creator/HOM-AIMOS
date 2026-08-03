#!/usr/bin/env node
// scripts/identity/toggle-governor-flag.js
// Toggle a governor flag ON or OFF via a cert-enveloped, hash-chained
// append to aimos_governor_config (migration 025). The toggle is signed
// by the `housekeeper` system operational identity — the same identity
// that signs governor REWEIGHT mutations + corpus mutations. The flag
// state is the latest signed row per config_key; readers in the governor
// modules pull from this ledger via a 30s TTL cache
// (governor-config-ledger.js).
//
// Replaces `process.env.X === 'ON'` toggling via .env — env vars are
// silently editable, unsigned, unchained, and invisible to the audit
// ledger. This CLI puts the toggle in the same audit plane as the
// mutations it gates.
//
// Usage:
//   node scripts/identity/toggle-governor-flag.js <CONFIG_KEY> <ON|OFF> --reason=<text>
//   node scripts/identity/toggle-governor-flag.js COHEN_GROSSBERG_GOVERNOR ON --reason=initial_activation_2026-07-04
//   node scripts/identity/toggle-governor-flag.js OJA_NORMALIZATION_GOVERNOR ON --reason=initial_activation_2026-07-04
//   node scripts/identity/toggle-governor-flag.js COHEN_GROSSBERG_GOVERNOR OFF --reason=rollback_after_regression
//
// Optional:
//   --operator=<username>   override the recorded operator (defaults to os.userInfo().username)

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from '../../db/connection.js';
import {
  governorConfigLedger,
  GOVERNOR_CONFIG_CONSTANTS
} from '../../services/governance/governor-config-ledger.js';
import { HOUSEKEEPER_SIGNER_CONSTANTS } from '../../services/security/housekeeper-signer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BRAIN_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
const positional = args.filter(a => !a.startsWith('--'));
const reasonArg = args.find(a => a.startsWith('--reason='));
const operatorArg = args.find(a => a.startsWith('--operator='));

const configKey = positional[0];
const enabledStr = positional[1];

function usage() {
  console.error('Usage: toggle-governor-flag.js <CONFIG_KEY> <ON|OFF> --reason=<text> [--operator=<username>]');
  console.error('Allowed CONFIG_KEY values:');
  for (const k of GOVERNOR_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS) {
    console.error('  ' + k);
  }
  process.exit(64);
}

if (!configKey || !enabledStr) {
  usage();
}

if (!GOVERNOR_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes(configKey)) {
  console.error(`[FATAL] unknown CONFIG_KEY: "${configKey}"`);
  console.error('        Allowed values:');
  for (const k of GOVERNOR_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS) {
    console.error('          ' + k);
  }
  process.exit(64);
}

const enabledUpper = enabledStr.toUpperCase();
if (enabledUpper !== 'ON' && enabledUpper !== 'OFF') {
  console.error(`[FATAL] second argument must be ON or OFF (got "${enabledStr}")`);
  process.exit(64);
}
const enabled = enabledUpper === 'ON';

if (!reasonArg || reasonArg.split('=')[1]?.length === 0) {
  console.error('[FATAL] --reason=<text> is required for auditability');
  process.exit(64);
}
const reason = reasonArg.split('=').slice(1).join('=');
const operator = operatorArg
  ? operatorArg.split('=').slice(1).join('=')
  : os.userInfo().username;

async function main() {
  console.log('Aimos governor flag toggle');
  console.log('=========================');
  console.log(`Config key:    ${configKey}`);
  console.log(`Enabled:       ${enabled}`);
  console.log(`Reason:        ${reason}`);
  console.log(`Operator:      ${operator}`);
  console.log(`Brain root:    ${BRAIN_ROOT}`);
  console.log(`Signing agent: ${HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID}`);
  console.log(`Key path:      ${HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_KEY_PATH}`);
  console.log();

  // Pre-check: privkey exists?
  const keyPath = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_KEY_PATH;
  const { existsSync, statSync } = await import('node:fs');
  if (!existsSync(keyPath)) {
    console.error(`[FATAL] housekeeper privkey not found at ${keyPath}`);
    console.error('        Enroll it first: node scripts/identity/init-architecture-authority.js (provisions housekeeper as part of deployment bootstrap)');
    process.exit(3);
  }
  const stat = statSync(keyPath);
  const mode = stat.mode & 0o777;
  if (mode !== 0o600) {
    console.error(`[FATAL] ${keyPath} mode is 0${mode.toString(8)} — expected 0600`);
    process.exit(3);
  }
  console.log(`[OK] privkey present (mode 0600, ${(stat.size)} bytes)`);
  console.log();

  console.log('Signing + committing to aimos_governor_config ...');
  const result = await governorConfigLedger.commitConfigFlag({
    configKey,
    enabled,
    reason,
    operator
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
  console.log('[OK] governor flag toggled');
  console.log(`  config_key:        ${configKey}`);
  console.log(`  enabled:           ${enabled}`);
  console.log(`  is_genesis:        ${result.isGenesis}`);
  console.log(`  ts_signed:         ${result.tsSigned}`);
  console.log(`  mutation_hash:     ${mutHex}`);
  console.log(`  prev_mutation_hash: ${prevHex}`);
  console.log();
  console.log('The governor modules will pick up the new state within ~30s (cache TTL).');
  console.log('To verify: SELECT config_key, enabled, is_genesis, ts_signed FROM aimos_governor_config ORDER BY created_at DESC;');

  await pool.end();
}

main().catch(async (err) => {
  console.error(`[FATAL] unexpected error: ${err?.message || err}`);
  if (err?.stack) console.error(err.stack);
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(2);
});