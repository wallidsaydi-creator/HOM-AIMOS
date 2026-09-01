#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  access,
  lstat,
  mkdir,
  readFile,
  rm,
  rmdir,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveAimosInstallationContext } from '../../services/installation-context.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { listCredentialKeychainItemsSync } from '../../services/security/credential-store.js';
import {
  defaultOnboardingKeychainAccount,
  normalizeOnboardingAgentId,
  normalizeOnboardingModelPreference,
} from '../identity/onboarding-contract.mjs';
import { keychainDeleteSync, keychainItemExistsSync } from '../identity/keychain.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
if (git.status !== 0) throw new Error('p3_installer_source_commit_unavailable');
const sourceCommit = git.stdout.trim();
const qualificationId = sourceCommit.slice(0, 8);
const INSTANCE = `installer_qual_${qualificationId}`;
const DATABASE = `aimos_installer_qual_${qualificationId}`;
const HTTP_PORT = 19303;
const POSTGRES_PORT = 25432;
const NODE = '/opt/homebrew/bin/node';
const PG_BIN = '/opt/homebrew/opt/postgresql@18/bin';
const context = resolveAimosInstallationContext([
  '--aimos-instance', INSTANCE,
  '--aimos-postgres-port', String(POSTGRES_PORT),
]);
const stateRoot = context.state_root;
const sourceRoot = path.join(stateRoot, 'source');
const postgresRoot = path.join(stateRoot, 'postgres');
const postgresSocket = path.join(stateRoot, 'socket');
const outputArgument = process.argv.find((value) => value.startsWith('--output='))?.slice(9);
const outputPath = outputArgument
  ? path.resolve(outputArgument)
  : path.join(stateRoot, 'evidence', 'p3-clean-installer-qualification.json');
const LIVE = process.argv.includes('--live');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const exactPath = [path.dirname(NODE), PG_BIN, '/opt/homebrew/bin', '/usr/bin', '/bin'].join(':');

function cli(name) {
  const inline = process.argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

const selectedAgentId = cli('--agent-id') ? normalizeOnboardingAgentId(cli('--agent-id')) : null;
const selectedModel = normalizeOnboardingModelPreference(cli('--model-provider'), cli('--model'));
const masterKeychainAccount = defaultOnboardingKeychainAccount(context);

function run(command, args, {
  cwd = ROOT,
  input = null,
  allowFailure = false,
  maxBuffer = 128 * 1024 * 1024,
  binary = false,
  interactive = false,
} = {}) {
  const result = spawnSync(command, args, {
    cwd,
    input,
    encoding: interactive || binary ? null : 'utf8',
    maxBuffer,
    stdio: interactive ? 'inherit' : undefined,
    env: { ...process.env, PATH: exactPath },
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`p3_installer_command_failed:${command}:${result.status}:${String(result.stderr || result.stdout || '').trim().slice(0, 800)}`);
  }
  return result;
}

function psql(port, database, sql) {
  return run(path.join(PG_BIN, 'psql'), [
    '-h', '127.0.0.1', '-p', String(port), '-d', database,
    '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql,
  ]).stdout.trim();
}

async function exists(target) {
  try { await access(target); return true; } catch { return false; }
}

function credentialInventory(prefix = null) {
  const rows = listCredentialKeychainItemsSync();
  return rows
    .filter((row) => !prefix || row.service === prefix || row.service.startsWith(`${prefix}.`))
    .sort((left, right) => `${left.service}\0${left.account}`.localeCompare(`${right.service}\0${right.account}`));
}

function exactCredentialInventory(service) {
  return listCredentialKeychainItemsSync()
    .filter((row) => row.service === service)
    .sort((left, right) => `${left.service}\0${left.account}`.localeCompare(`${right.service}\0${right.account}`));
}

function canonicalHealth() {
  const body = JSON.parse(run('/usr/bin/curl', [
    '-fsS', '--max-time', '8', 'http://127.0.0.1:9100/health',
  ]).stdout);
  if (body?.ready !== true
      || body?.runtime?.database_name !== 'aimos'
      || body?.runtime?.server_port !== 9100) {
    throw new Error('p3_canonical_health_invalid');
  }
  return body;
}

async function canonicalFingerprint() {
  const key = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key');
  const serviceManifest = path.join(os.homedir(), '.aimos', 'service', 'service.json');
  const [keyBytes, serviceBytes] = await Promise.all([readFile(key), readFile(serviceManifest)]);
  const memoryRows = psql(5432, 'aimos',
    'SELECT row_to_json(row_data)::text FROM (SELECT * FROM aimos_memories ORDER BY id) row_data');
  const identityRows = psql(5432, 'aimos',
    'SELECT row_to_json(row_data)::text FROM (SELECT * FROM agent_identity ORDER BY agent_id, valid_from) row_data');
  const masterRows = psql(5432, 'aimos',
    'SELECT row_to_json(row_data)::text FROM (SELECT * FROM aimos_master_identity ORDER BY id) row_data');
  // A full row_to_json projection can exceed spawnSync's bounded output on a
  // mature ledger. The mutation hash commits the signed event body and its
  // predecessor, so this compact tuple set proves preservation of every
  // retained cryptographic checkpoint in O(n) time and O(n) bounded space.
  const eventCheckpointsText = psql(5432, 'aimos', `SELECT concat_ws('|',
      company_id, signer_agent_id, signer_valid_from::text, ledger_seq::text,
      encode(mutation_hash, 'hex'))
    FROM aimos_events
    ORDER BY company_id, signer_agent_id, signer_valid_from, ledger_seq`);
  const eventCheckpoints = eventCheckpointsText ? eventCheckpointsText.split('\n') : [];
  const inventory = exactCredentialInventory('com.aimos.credentials.agent_runtime_db_password');
  return {
    fingerprint: {
      housekeeper_key_sha256: sha(keyBytes),
      service_manifest_sha256: sha(serviceBytes),
      database_invariant_sha256: sha(Buffer.from(canonicalJson({
        memories: sha(Buffer.from(memoryRows)),
        identities: sha(Buffer.from(identityRows)),
        masters: sha(Buffer.from(masterRows)),
      }))),
      event_checkpoint_root_sha256: sha(Buffer.from(eventCheckpointsText)),
      event_count: eventCheckpoints.length,
      keychain_inventory_sha256: sha(Buffer.from(canonicalJson(inventory))),
    },
    eventCheckpoints,
  };
}

function canonicalInvariant(fingerprint) {
  const { event_checkpoint_root_sha256, event_count, ...invariant } = fingerprint;
  return invariant;
}

function eventPrefixPreserved(beforeCheckpoints, afterCheckpoints) {
  if (afterCheckpoints.length < beforeCheckpoints.length) return false;
  const after = new Set(afterCheckpoints);
  return beforeCheckpoints.every((checkpoint) => after.has(checkpoint));
}

function combineFailure(primary, secondary, message) {
  if (!primary) return secondary;
  return new AggregateError([primary, secondary], message);
}

async function preflight() {
  const health = canonicalHealth();
  const checks = {
    node26: run(NODE, ['--version']).stdout.trim().startsWith('v26.'),
    state_root_absent: !(await exists(stateRoot)),
    database_port_unused: run('/usr/sbin/lsof', ['-nP', `-iTCP:${POSTGRES_PORT}`, '-sTCP:LISTEN'], { allowFailure: true }).status !== 0,
    http_port_unused: run('/usr/sbin/lsof', ['-nP', `-iTCP:${HTTP_PORT}`, '-sTCP:LISTEN'], { allowFailure: true }).status !== 0,
    canonical_instance: context.canonical === false,
    named_credential_absent: credentialInventory(
      `com.aimos.credentials.${context.runtime_credential_service}`,
    ).length === 0,
    master_slot_absent: !keychainItemExistsSync('aimos.master', masterKeychainAccount),
    generic_agent_selected: selectedAgentId != null,
    clean_worktree: run('git', ['status', '--porcelain'], { cwd: ROOT }).stdout.trim() === '',
    canonical_ready: health.ready === true,
  };
  return { checks, passed: Object.values(checks).every(Boolean) };
}

function launchdLoaded(label) {
  return run('/bin/launchctl', [
    'print', `gui/${process.getuid()}/${label}`,
  ], { allowFailure: true }).status === 0;
}

function portUnused(port) {
  return run('/usr/sbin/lsof', [
    '-nP', `-iTCP:${port}`, '-sTCP:LISTEN',
  ], { allowFailure: true }).status !== 0;
}

async function disposableCensus() {
  const manifest = path.join(context.service_state_root, 'service.json');
  const unit = path.join(os.homedir(), 'Library', 'LaunchAgents', `${context.user_service_label}.plist`);
  const credentials = credentialInventory(`com.aimos.credentials.${context.runtime_credential_service}`);
  const census = {
    state_root_absent: !(await exists(stateRoot)),
    service_manifest_absent: !(await exists(manifest)),
    service_unit_absent: !(await exists(unit)),
    service_unloaded: !launchdLoaded(context.user_service_label),
    postgres_port_unused: portUnused(POSTGRES_PORT),
    http_port_unused: portUnused(HTTP_PORT),
    credential_items_absent: credentials.length === 0,
    master_slot_absent: !keychainItemExistsSync('aimos.master', masterKeychainAccount),
  };
  return { ...census, clean: Object.values(census).every(Boolean) };
}

async function retainedInstallationCensus() {
  const manifest = path.join(context.service_state_root, 'service.json');
  const unit = path.join(os.homedir(), 'Library', 'LaunchAgents', `${context.user_service_label}.plist`);
  const credentials = credentialInventory(`com.aimos.credentials.${context.runtime_credential_service}`);
  const census = {
    state_root_present: await exists(stateRoot),
    source_root_present: await exists(sourceRoot),
    postgres_root_present: await exists(path.join(postgresRoot, 'PG_VERSION')),
    service_manifest_present: await exists(manifest),
    service_unit_present: await exists(unit),
    service_loaded: launchdLoaded(context.user_service_label),
    postgres_port_listening: !portUnused(POSTGRES_PORT),
    http_port_listening: !portUnused(HTTP_PORT),
    credential_items_present: credentials.length > 0,
    master_slot_present: keychainItemExistsSync('aimos.master', masterKeychainAccount),
  };
  return { ...census, ready: Object.values(census).every(Boolean) };
}

async function cleanup() {
  const failures = [];
  const serviceOwner = path.join(sourceRoot, 'scripts/service/manage-user-service.mjs');
  const serviceManifest = path.join(context.service_state_root, 'service.json');
  const serviceUnit = path.join(os.homedir(), 'Library', 'LaunchAgents', `${context.user_service_label}.plist`);
  if (await exists(serviceOwner) && await exists(serviceManifest)) {
    try {
      run(NODE, [serviceOwner, 'uninstall', '--instance', INSTANCE], { cwd: sourceRoot });
    } catch (error) { failures.push(error); }
  }
  if (launchdLoaded(context.user_service_label)) {
    try {
      run('/bin/launchctl', ['bootout', `gui/${process.getuid()}/${context.user_service_label}`]);
    } catch (error) { failures.push(error); }
  }
  if (await exists(serviceUnit) && !launchdLoaded(context.user_service_label)) {
    try { await rm(serviceUnit); } catch (error) { failures.push(error); }
  }
  if (await exists(path.join(postgresRoot, 'PG_VERSION'))) {
    const status = run(path.join(PG_BIN, 'pg_ctl'), ['-D', postgresRoot, 'status'], { allowFailure: true });
    if (status.status === 0) {
      try {
        run(path.join(PG_BIN, 'pg_ctl'), ['-D', postgresRoot, '-m', 'fast', '-w', 'stop']);
      } catch (error) { failures.push(error); }
    }
  }
  const prefix = `com.aimos.credentials.${context.runtime_credential_service}`;
  for (const item of credentialInventory(prefix)) {
    try { keychainDeleteSync(item.service, item.account); } catch (error) { failures.push(error); }
  }
  try { keychainDeleteSync('aimos.master', masterKeychainAccount); } catch (error) { failures.push(error); }
  if (!launchdLoaded(context.user_service_label) && portUnused(POSTGRES_PORT) && portUnused(HTTP_PORT)) {
    try { await rm(stateRoot, { recursive: true, force: true }); } catch (error) { failures.push(error); }
  } else {
    failures.push(new Error('p3_disposable_process_survived_cleanup'));
  }
  try { await rmdir(path.dirname(stateRoot)); } catch (error) {
    if (!['ENOENT', 'ENOTEMPTY'].includes(error?.code)) failures.push(error);
  }
  const census = await disposableCensus();
  if (!census.clean) failures.push(new Error(`p3_disposable_cleanup_incomplete:${JSON.stringify(census)}`));
  if (failures.length) throw new AggregateError(failures, 'p3_disposable_cleanup_failed');
  return census;
}

const initial = await preflight();
if (!initial.passed) throw new Error(`p3_installer_preflight_failed:${JSON.stringify(initial.checks)}`);
if (!LIVE) {
  console.log(JSON.stringify({
    mode: 'PREFLIGHT',
    instance: INSTANCE,
    installation_context_sha256: context.context_sha256,
    source_commit: sourceCommit,
    ...initial,
  }, null, 2));
  process.exit(0);
}
const canonicalBefore = await canonicalFingerprint();
const canonicalHealthBefore = canonicalHealth();
let receipt = null;
let failure = null;
let failedAttemptCleanup = null;
try {
  await mkdir(path.dirname(stateRoot), { recursive: true, mode: 0o700 });
  await mkdir(stateRoot, { recursive: false, mode: 0o700 });
  await mkdir(postgresSocket, { recursive: true, mode: 0o700 });
  const archive = run('git', ['archive', sourceCommit], {
    cwd: ROOT,
    maxBuffer: 256 * 1024 * 1024,
    binary: true,
  });
  await mkdir(sourceRoot, { recursive: true, mode: 0o700 });
  run('tar', ['-x', '-C', sourceRoot], {
    input: archive.stdout,
    maxBuffer: 256 * 1024 * 1024,
    binary: true,
  });
  run(path.join(PG_BIN, 'initdb'), [
    '-D', postgresRoot, '--username', os.userInfo().username,
    '--auth-local=trust', '--auth-host=trust', '--encoding=UTF8', '--no-locale',
  ]);
  run(path.join(PG_BIN, 'pg_ctl'), [
    '-D', postgresRoot, '-o', `-p ${POSTGRES_PORT} -h 127.0.0.1 -k ${postgresSocket}`,
    '-l', path.join(stateRoot, 'postgres.log'),
    '-w', 'start',
  ]);
  run('bash', [
    'install-macos.sh', '--yes',
    '--aimos-db', DATABASE,
    '--aimos-port', String(HTTP_PORT),
    '--aimos-instance', INSTANCE,
    '--postgres-port', String(POSTGRES_PORT),
    '--agent-id', selectedAgentId,
    ...(selectedModel ? ['--model-provider', selectedModel.provider, '--model', selectedModel.model] : []),
  ], { cwd: sourceRoot, maxBuffer: 256 * 1024 * 1024, interactive: true });
  const statusBefore = JSON.parse(run(NODE, [
    'scripts/service/manage-user-service.mjs', 'status', '--instance', INSTANCE,
  ], { cwd: sourceRoot }).stdout);
  const restart = JSON.parse(run(NODE, [
    'scripts/service/manage-user-service.mjs', 'restart', '--instance', INSTANCE,
  ], { cwd: sourceRoot }).stdout);
  const terminal = JSON.parse(run(NODE, [
    'scripts/verification/commit-p3-installer-terminal.mjs',
    '--aimos-db', DATABASE,
    '--aimos-port', String(HTTP_PORT),
    '--aimos-instance', INSTANCE,
    '--aimos-postgres-port', String(POSTGRES_PORT),
    '--source-commit', sourceCommit,
  ], { cwd: sourceRoot }).stdout);
  const counts = JSON.parse(psql(POSTGRES_PORT, DATABASE, `SELECT json_build_object(
    'memories',(SELECT count(*)::int FROM aimos_memories),
    'guide_memories',(SELECT count(*)::int FROM aimos_memories WHERE source='guide:genesis-install'),
    'experimental_memories',(SELECT count(*)::int FROM aimos_memories WHERE source ~* '(benchmark|eval|longmemeval|locomo|poisonedrag)'),
    'identities',(SELECT count(*)::int FROM agent_identity),
    'housekeepers',(SELECT count(*)::int FROM agent_identity WHERE agent_id='housekeeper'),
    'masters',(SELECT count(*)::int FROM aimos_master_identity)
    ,'selected_grant_clearance',(SELECT clearance_ceiling::int
       FROM aimos_recall_authorization_events
      WHERE company_id='hom' AND subject_agent_id='${selectedAgentId}'
      ORDER BY created_at DESC,recall_authorization_event_id DESC LIMIT 1)
    ,'selected_grant_data_class',(SELECT data_class_ceiling
       FROM aimos_recall_authorization_events
      WHERE company_id='hom' AND subject_agent_id='${selectedAgentId}'
      ORDER BY created_at DESC,recall_authorization_event_id DESC LIMIT 1)
  )::text`));
  receipt = {
    schema: 'hom.aimos.p3-clean-installer-qualification/v3',
    source_commit: sourceCommit,
    node_version: run(NODE, ['--version']).stdout.trim(),
    node_executable_sha256: sha(await readFile(NODE)),
    installation_context_sha256: context.context_sha256,
    instance: INSTANCE,
    database: DATABASE,
    postgres_port: POSTGRES_PORT,
    http_port: HTTP_PORT,
    installer_invocation_sha256: sha(Buffer.from(canonicalJson({
      source_commit: sourceCommit,
      instance: INSTANCE,
      database: DATABASE,
      postgres_port: POSTGRES_PORT,
      http_port: HTTP_PORT,
      selected_agent_id: selectedAgentId,
      selected_model: selectedModel,
    }))),
    service_configuration_sha256: statusBefore.definition.configuration_sha256,
    first_ready: statusBefore.health?.ready === true,
    restart_ready: restart.health?.ready === true,
    scheduler_ready: restart.health?.readiness?.scheduler?.ready === true,
    counts,
    selected_agent_id: selectedAgentId,
    selected_model: selectedModel,
    public_agent_clearance_maximum: 10,
    signed_terminal: terminal,
    canonical_runtime_not_manipulated: true,
    canonical_health_before: canonicalHealthBefore,
    canonical_before: canonicalBefore.fingerprint,
  };
} catch (error) {
  failure = error;
}
if (failure) {
  try { failedAttemptCleanup = await cleanup(); } catch (cleanupError) {
    failure = combineFailure(failure, cleanupError, 'p3_qualification_and_cleanup_failed');
  }
}
let canonicalAfter = null;
let canonicalHealthAfter = null;
try {
  canonicalHealthAfter = canonicalHealth();
  canonicalAfter = await canonicalFingerprint();
} catch (fingerprintError) {
  failure = combineFailure(failure, fingerprintError, 'p3_qualification_and_canonical_continuity_failed');
}
if (failure) throw failure;
const retainedInstallation = await retainedInstallationCensus();
receipt.canonical_after = canonicalAfter.fingerprint;
receipt.canonical_health_after = canonicalHealthAfter;
receipt.canonical_invariants_unchanged = canonicalJson(canonicalInvariant(canonicalBefore.fingerprint))
  === canonicalJson(canonicalInvariant(canonicalAfter.fingerprint));
receipt.canonical_event_prefix_preserved = eventPrefixPreserved(
  canonicalBefore.eventCheckpoints,
  canonicalAfter.eventCheckpoints,
);
receipt.canonical_event_delta = canonicalAfter.eventCheckpoints.length
  - canonicalBefore.eventCheckpoints.length;
receipt.canonical_unchanged = receipt.canonical_invariants_unchanged
  && receipt.canonical_event_prefix_preserved;
receipt.retained_installation = retainedInstallation;
receipt.retained_installation_ready = retainedInstallation.ready === true;
receipt.failed_attempt_cleanup = failedAttemptCleanup;
receipt.qualified = receipt.first_ready && receipt.restart_ready && receipt.scheduler_ready
  && receipt.counts.experimental_memories === 0
  && receipt.counts.identities === 2 && receipt.counts.housekeepers === 1
  && receipt.counts.masters === 1
  && receipt.counts.selected_grant_clearance === 10
  && receipt.counts.selected_grant_data_class === 'confidential'
  && receipt.signed_terminal.independently_verified === true
  && receipt.signed_terminal.portable_proof_complete === true
  && receipt.canonical_runtime_not_manipulated === true
  && receipt.canonical_health_before.ready === true
  && receipt.canonical_health_after.ready === true
  && receipt.canonical_unchanged && receipt.retained_installation_ready;
const unsigned = { ...receipt };
receipt.qualification_sha256 = sha(Buffer.from(canonicalJson(unsigned)));
await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
await writeFile(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify(receipt, null, 2));
if (!receipt.qualified) process.exitCode = 1;
