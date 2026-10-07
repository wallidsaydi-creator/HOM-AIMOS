#!/usr/bin/env node

// Persistent canonical PostgreSQL cutover. `plan` is read-only. `apply` is a
// maintenance operation: it stages a separate private cluster, proves retained
// authority and signed application behavior with a temporary named instance,
// then uses the existing reversible service manager to switch port 9100.
// `apply` preserves the shared source database and HBA. The separate
// `retire-source` phase drops only the old AIMOS database after private-service
// restart and signed proof; unrelated shared databases and HBA remain intact.

import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { runMigrations } from '../../migrations/run.js';
import { resolveAimosInstallationContext } from '../../services/installation-context.js';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { credentialSlotId, readCredentialSync, storeCredentialSync,
  CREDENTIAL_KEYCHAIN_ACCOUNT } from '../../services/security/credential-store.js';
import { RESERVED_LEGACY_PORTS } from '../../services/core/runtime-config.js';
import { assertPrivatePostgresServingBoundary } from '../../services/security/postgres-serving-boundary.js';
import { keychainDeleteSync } from '../identity/keychain.js';
import { synchronizeRuntimeRoleCredential } from '../bootstrap-db.mjs';
import {
  buildUserServiceDefinition, buildUserServiceManifest,
  installUserService, manageInstalledUserService,
  readInstalledUserServiceDefinition,
  serviceReadinessMatches, validateUserServiceManifest,
} from '../service/manage-user-service.mjs';
import { activateServingRoles } from './activate-serving-roles.mjs';
import { freezeVerifyAndDropDatabase,
  reenableFrozenDatabase } from './retirement-freeze.mjs';
import { preflightCutoverActorConnection } from './preflight-cutover-actor.mjs';
import { CLUSTER_ADMIN_ROLE, clusterAdminCredentialService,
  initializeSecureCluster, secureClusterPaths, secureHbaText,
  verifyExistingSecureCluster } from './secure-cluster.mjs';
import {
  prepareArchivePair, proveBoundaryPolicies, provePrivileges,
  runPgRestore, sampleIdentity, stageArchiveRoles,
} from './rehearse-acl-restore.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DATABASE = 'aimos';
const SERVICE_PORT = 9100;
const LEGACY_POSTGRES_PORT = 5432;
const TARGET_POSTGRES_PORT = 55432;
const PROBE_PORT = 9205;
export const AUTHORITY_TABLES = Object.freeze([
  'aimos_master_identity', 'agent_identity',
  'aimos_agent_revocation_events', 'aimos_system_config',
  'aimos_credential_lifecycle', 'aimos_events',
  'aimos_request_receipts', 'aimos_recall_authorization_events',
]);
const SCRATCH_CREDENTIAL_BASES = Object.freeze([
  'agent_runtime_db_password', 'aimos_service_reader_db_password',
  'aimos_identity_writer_db_password',
]);

function fail(reason) { throw new Error(`canonical_cutover_${reason}`); }
function cliValue(argv, name) {
  const index = argv.indexOf(name);
  return index < 0 ? null : argv[index + 1];
}
function privateDirectory(directory, { create = false } = {}) {
  if (create) fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) fail('directory_custody_invalid');
}
function atomicJson(file, value) {
  privateDirectory(path.dirname(file), { create: true });
  if (fs.existsSync(file)) fail('receipt_already_exists');
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`,
    { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, file);
}
function replaceOwnerOnlyJson(file, value) {
  readOwnerOnlyJson(file, 'receipt_custody_invalid');
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`,
    { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, file);
}
function sha256File(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) fail('archive_custody_invalid');
  const hash = createHash('sha256');
  const fd = fs.openSync(file, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let count;
    while ((count = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      hash.update(buffer.subarray(0, count));
    }
  } finally { fs.closeSync(fd); }
  return hash.digest('hex');
}
function serviceOptions(definition) {
  return {
    sourceRoot: definition.source_root, nodePath: definition.node_path,
    database: definition.database, port: definition.port,
    instance: definition.instance, postgresPort: definition.postgres_port,
    postgresBin: definition.postgres_bin,
    platform: definition.platform, homeDirectory: os.homedir(),
  };
}

export function validateServiceTransition(previous, next) {
  if (previous?.instance !== 'canonical' || next?.instance !== 'canonical'
      || previous?.postgres_port !== LEGACY_POSTGRES_PORT
      || next?.postgres_port !== TARGET_POSTGRES_PORT
      || previous?.port !== SERVICE_PORT || next?.port !== SERVICE_PORT
      || previous?.database !== DATABASE || next?.database !== DATABASE
      || previous?.label !== next?.label || previous?.source_root !== next?.source_root
      || previous?.node_path !== next?.node_path
      || previous?.unit_path !== next?.unit_path
      || previous?.manifest_path !== next?.manifest_path) {
    fail('service_transition_invalid');
  }
  return true;
}

export async function switchWithRollback(previous, next, {
  install = installUserService, verifyAfterSwitch = async () => true,
} = {}) {
  validateServiceTransition(previous, next);
  try {
    const result = await install(serviceOptions(next));
    if (!serviceReadinessMatches(next, result?.health)) fail('target_readiness_invalid');
    const proof = await verifyAfterSwitch(result);
    return Object.freeze({ switched: true, health: result.health, proof });
  } catch (error) {
    // installUserService restores the prior files on failure, but does not
    // start a source service that was intentionally stopped for a consistent
    // final archive. Start and verify it explicitly for every failed switch.
    try {
      const rollback = await install(serviceOptions(previous));
      if (!serviceReadinessMatches(previous, rollback?.health)) {
        fail('rollback_readiness_invalid');
      }
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError],
        'canonical_cutover_switch_and_rollback_failed');
    }
    throw error;
  }
}

async function authorityFingerprint(client) {
  const result = {};
  for (const table of AUTHORITY_TABLES) {
    const row = (await client.query(`SELECT count(*)::integer AS count,
      md5(coalesce(string_agg(md5(to_jsonb(x)::text), ''
        ORDER BY md5(to_jsonb(x)::text)), '')) AS hash
      FROM public.${table} x`)).rows[0];
    result[table] = { count: row.count, hash: row.hash };
  }
  return Object.freeze(result);
}

async function sourceAuthorityFingerprint() {
  const client = new pg.Client({
    host: '127.0.0.1', port: LEGACY_POSTGRES_PORT, database: DATABASE,
    user: os.userInfo().username, ssl: false, connectionTimeoutMillis: 5000,
    statement_timeout: 20_000,
  });
  try {
    await client.connect();
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const result = await authorityFingerprint(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end().catch(() => {}); }
}

async function sourceLedgerCounts() {
  const client = new pg.Client({ host: '127.0.0.1',
    port: LEGACY_POSTGRES_PORT, database: DATABASE,
    user: os.userInfo().username, ssl: false,
    connectionTimeoutMillis: 5000, statement_timeout: 10_000 });
  try {
    await client.connect();
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const row = (await client.query(`SELECT
      (SELECT count(*)::integer FROM public.aimos_events) AS events,
      (SELECT count(*)::integer FROM public.aimos_request_receipts) AS request_receipts`)).rows[0];
    await client.query('COMMIT');
    return row;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end().catch(() => {}); }
}

export async function preflightCanonicalCutoverActor(actor, postgresPort) {
  const keyPath = path.join(resolveAimosInstallationContext([]).agent_key_root,
    `${actor}.key`);
  let connection;
  if (postgresPort === LEGACY_POSTGRES_PORT) {
    connection = { host: '127.0.0.1', port: LEGACY_POSTGRES_PORT,
      database: DATABASE, user: os.userInfo().username, ssl: false,
      connectionTimeoutMillis: 5000 };
  } else if (postgresPort === TARGET_POSTGRES_PORT) {
    const secret = readCredentialSync(clusterAdminCredentialService('canonical'));
    if (!secret?.value) fail('target_admin_credential_unavailable');
    connection = { host: '127.0.0.1', port: TARGET_POSTGRES_PORT,
      database: DATABASE, user: CLUSTER_ADMIN_ROLE, password: secret.value,
      ssl: false, connectionTimeoutMillis: 5000 };
  } else {
    fail('actor_preflight_postgres_port_invalid');
  }
  return preflightCutoverActorConnection({ connection, actor, keyPath });
}

export function assertActorAuthorityPreserved(source, target) {
  if (!source || !target || source.actor !== target.actor
      || source.valid_from !== target.valid_from
      || source.valid_until !== target.valid_until
      || source.certificate_sha256 !== target.certificate_sha256
      || source.grant_event_id !== target.grant_event_id
      || source.grant_mutation_sha256 !== target.grant_mutation_sha256
      || source.write_allowed !== true || target.write_allowed !== true
      || source.clearance_ceiling < 5 || target.clearance_ceiling < 5) {
    fail('actor_authority_changed_across_restore');
  }
  return true;
}

async function sourceDatabaseIdentity() {
  const client = new pg.Client({ host: '127.0.0.1',
    port: LEGACY_POSTGRES_PORT, database: 'postgres',
    user: os.userInfo().username, ssl: false,
    connectionTimeoutMillis: 5000, statement_timeout: 10_000 });
  try {
    await client.connect();
    const result = await client.query(`SELECT oid::text AS oid,
      datname, pg_get_userbyid(datdba) AS owner, datallowconn
      FROM pg_database WHERE datname=$1`, [DATABASE]);
    if (result.rowCount !== 1 || !/^\d+$/.test(result.rows[0].oid)) {
      fail('source_database_identity_invalid');
    }
    return result.rows[0];
  } finally { await client.end().catch(() => {}); }
}

async function targetAuthorityFingerprint(context) {
  const secret = readCredentialSync(clusterAdminCredentialService('canonical'));
  if (!secret?.value) fail('target_admin_credential_unavailable');
  const client = new pg.Client({ host: '127.0.0.1',
    port: context.postgres_port, database: DATABASE,
    user: CLUSTER_ADMIN_ROLE, password: secret.value,
    ssl: false, connectionTimeoutMillis: 5000, statement_timeout: 20_000 });
  try {
    await client.connect();
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const result = await authorityFingerprint(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { await client.end().catch(() => {}); }
}

export function assertAuthorityFingerprintEqual(left, right, reason = 'authority_changed') {
  for (const table of AUTHORITY_TABLES) {
    const a = left?.[table];
    const b = right?.[table];
    if (!Number.isInteger(a?.count) || a.count < 0
        || !Number.isInteger(b?.count) || b.count < 0
        || !/^[0-9a-f]{32}$/.test(String(a?.hash || ''))
        || !/^[0-9a-f]{32}$/.test(String(b?.hash || ''))
        || a.count !== b.count || a.hash !== b.hash) {
      fail(`${reason}:${table}`);
    }
  }
  return true;
}

export function validatedRehearsalReceipt(file, prepared) {
  if (!path.isAbsolute(String(file || ''))) fail('rehearsal_receipt_required');
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0 || stat.size > 16 * 1024) {
    fail('rehearsal_receipt_custody_invalid');
  }
  const receipt = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (receipt.result !== 'isolated_restore_pass'
      || receipt.archive_sha256 !== prepared.archiveSha256
      || receipt.acl_archive_sha256 !== prepared.aclArchiveSha256
      || receipt.schema_sha256 !== prepared.schemaSha256
      || receipt.archive_acl_entries
        !== (prepared.companion?.count || prepared.preflight.aclEntries)
      || receipt.applied_migrations < 4
      || !Number.isInteger(receipt.retained_rows?.events)
      || receipt.retained_rows.events < 0
      || !Number.isInteger(receipt.retained_rows?.request_receipts)
      || receipt.retained_rows.request_receipts < 0
      || receipt.identity?.master_count !== 1
      || receipt.identity?.agent_count < 1
      || !/^[0-9a-f]{32}$/.test(String(receipt.identity.master_hash || ''))
      || !/^[0-9a-f]{32}$/.test(String(receipt.identity.agent_hash || ''))
      || receipt.boundary?.force_rls_tables < 17
      || receipt.boundary?.reader_restrictive_policies !== 17
      || receipt.boundary?.legacy_login_retired !== true
      || !['agent_runtime', 'aimos_service_reader', 'aimos_identity_writer']
        .every((role) => receipt.serving_roles?.includes(role))
      || receipt.scratch_cleaned !== true) {
    fail('rehearsal_receipt_invalid');
  }
  return receipt;
}

export function assertSourceLedgerCountsMatch(rehearsal, source) {
  if (!Number.isInteger(source?.events)
      || !Number.isInteger(source?.request_receipts)
      || source.events !== rehearsal?.retained_rows?.events
      || source.request_receipts !== rehearsal?.retained_rows?.request_receipts) {
    fail('source_signed_ledger_count_diverged');
  }
  return true;
}

function keyFileInfo(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o777) !== 0o600 || stat.size < 32 || stat.size > 8192) {
    fail('agent_key_custody_invalid');
  }
  return { size: stat.size };
}

function copyAgentKey(source, destination) {
  keyFileInfo(source);
  const input = fs.openSync(source, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let bytes;
  try {
    const stat = fs.fstatSync(input);
    if (!stat.isFile() || stat.uid !== process.getuid()
        || (stat.mode & 0o777) !== 0o600) fail('agent_key_descriptor_invalid');
    bytes = fs.readFileSync(input);
  } finally { fs.closeSync(input); }
  const output = fs.openSync(destination,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW, 0o600);
  try {
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(output, bytes, offset, bytes.length - offset);
    }
  }
  finally { fs.closeSync(output); bytes.fill(0); }
  keyFileInfo(destination);
}

async function waitForScratchHealth(port, postgresPort, child) {
  const deadline = Date.now() + 900_000;
  while (Date.now() < deadline) {
    if (child.spawnError || child.exitCode !== null || child.signalCode !== null) {
      fail('scratch_server_exited_before_readiness');
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      const body = await response.json();
      if (response.ok && body?.ready === true
          && Number(body?.runtime?.server_port) === port
          && Number(body?.runtime?.postgres_port) === postgresPort) return body;
    } catch { /* bounded retry */ }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  fail('scratch_server_readiness_timeout');
}

async function stopScratchServer(child) {
  if (!child || child.spawnError || child.exitCode !== null
      || child.signalCode !== null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise((resolve) => child.once('exit', () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), 45_000)),
  ]);
  if (!exited) {
    child.kill('SIGKILL');
    const killed = await Promise.race([
      new Promise((resolve) => child.once('exit', () => resolve(true))),
      new Promise((resolve) => setTimeout(() => resolve(false), 10_000)),
    ]);
    if (!killed) fail('scratch_server_stop_failed');
  }
}

async function proveRestoredIdentityWithScratchInstance({ actor, postgresPort,
  serverPort = PROBE_PORT } = {}) {
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))
      || serverPort === SERVICE_PORT || serverPort === postgresPort) {
    fail('scratch_probe_inputs_invalid');
  }
  const instance = `cutoverproof${randomBytes(4).toString('hex')}`;
  const context = resolveAimosInstallationContext([
    '--aimos-instance', instance, '--aimos-postgres-port', String(postgresPort),
  ]);
  if (fs.existsSync(context.state_root)) fail('scratch_instance_collision');
  privateDirectory(context.state_root, { create: true });
  privateDirectory(context.agent_key_root, { create: true });
  const canonical = resolveAimosInstallationContext([]);
  const credentialSlots = [];
  let child;
  let proof;
  let failure;
  try {
    for (const id of new Set([actor, 'housekeeper'])) {
      copyAgentKey(path.join(canonical.agent_key_root, `${id}.key`),
        path.join(context.agent_key_root, `${id}.key`));
    }
    for (const base of SCRATCH_CREDENTIAL_BASES) {
      const source = readCredentialSync(base);
      const scratchService = `${base}-${instance}`;
      if (!source?.value || readCredentialSync(scratchService)) {
        fail('scratch_credential_precondition_invalid');
      }
      const slot = credentialSlotId(scratchService);
      credentialSlots.push({ slot, versionSlot: `${slot}.${source.hash}` });
      storeCredentialSync(scratchService, source.value);
      const readback = readCredentialSync(scratchService);
      if (readback?.hash !== source.hash) fail('scratch_credential_readback_invalid');
    }
    const args = [path.join(ROOT, 'server.js'),
      '--aimos-instance', instance, '--aimos-db', DATABASE,
      '--aimos-postgres-port', String(postgresPort),
      '--aimos-port', String(serverPort)];
    child = spawn(process.execPath, args, {
      cwd: ROOT, stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.on('error', (error) => { child.spawnError = error; });
    await waitForScratchHealth(serverPort, postgresPort, child);
    const output = execFileSync(process.execPath, [
      path.join(ROOT, 'scripts', 'test', 'probe-restored-identity.mjs'),
      '--disposable', '--aimos-instance', instance,
      '--aimos-db', DATABASE, '--aimos-postgres-port', String(postgresPort),
      '--aimos-port', String(serverPort), '--agent-id', actor,
    ], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 900_000, maxBuffer: 16 * 1024 });
    proof = JSON.parse(output);
    if (proof.result !== 'restored_identity_signed_proof_pass'
        || proof.instance !== instance || proof.postgres_port !== postgresPort
        || proof.server_port !== serverPort || proof.agent_id !== actor
        || proof.signed_status !== 200 || proof.signed_recall !== 200
        || proof.signed_save !== 200 || !proof.terminal_event_id) {
      fail('scratch_signed_proof_invalid');
    }
  } catch (error) {
    failure = error;
  } finally {
    const cleanupFailures = [];
    try { await stopScratchServer(child); }
    catch (error) { cleanupFailures.push(error); }
    for (const entry of credentialSlots.reverse()) {
      for (const slot of [entry.slot, entry.versionSlot]) {
        try { keychainDeleteSync(slot, CREDENTIAL_KEYCHAIN_ACCOUNT); }
        catch (error) { cleanupFailures.push(error); }
      }
    }
    if (cleanupFailures.length === 0) {
      try { fs.rmSync(context.state_root, { recursive: true, force: true }); }
      catch (error) { cleanupFailures.push(error); }
    }
    if (cleanupFailures.length) {
      throw new AggregateError([...(failure ? [failure] : []), ...cleanupFailures],
        'scratch_probe_cleanup_failed');
    }
  }
  if (failure) throw failure;
  return proof;
}

function canonicalTargetDefinition(previous, pgBin, postgresPort) {
  const next = buildUserServiceDefinition({
    ...serviceOptions(previous), postgresPort, postgresBin: pgBin,
  });
  validateServiceTransition(previous, next);
  return next;
}

function assertTargetAbsent(context) {
  const paths = secureClusterPaths(context.state_root);
  if (fs.existsSync(paths.data)) fail('persistent_target_already_exists');
  return paths;
}

async function stagePersistentTarget({ archive, aclArchive, pgBin,
  sourceOwnerRole, context, prepared } = {}) {
  assertTargetAbsent(context);
  const adminService = clusterAdminCredentialService('canonical');
  if (readCredentialSync(adminService)) fail('admin_credential_already_exists');
  const stored = storeCredentialSync(adminService, randomBytes(48).toString('base64url'));
  const adminSecret = readCredentialSync(adminService);
  if (!adminSecret?.value || adminSecret.hash !== stored.hash) {
    fail('admin_credential_readback_invalid');
  }
  await initializeSecureCluster({
    stateRoot: context.state_root, port: context.postgres_port,
    pgBin, adminPassword: adminSecret.value,
  });
  const config = { host: '127.0.0.1', port: context.postgres_port,
    database: 'postgres', user: CLUSTER_ADMIN_ROLE,
    password: adminSecret.value, ssl: false, connectionTimeoutMillis: 5000 };
  const admin = new pg.Client(config);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-cutover-restore-'));
  fs.chmodSync(scratch, 0o700);
  try {
    await admin.connect();
    const existing = await admin.query('SELECT 1 FROM pg_database WHERE datname=$1', [DATABASE]);
    if (existing.rowCount) fail('persistent_database_already_exists');
    await stageArchiveRoles(admin, sourceOwnerRole);
    await admin.query(`CREATE DATABASE ${DATABASE}`);
    await admin.end();
    await runPgRestore({ pgBin, archive, port: context.postgres_port,
      password: adminSecret.value, database: DATABASE, scratch });
    if (prepared.companion) {
      const aclList = path.join(scratch, 'acl-only.list');
      fs.writeFileSync(aclList, prepared.companion.list,
        { mode: 0o600, flag: 'wx' });
      await runPgRestore({ pgBin, archive: aclArchive, port: context.postgres_port,
        password: adminSecret.value, database: DATABASE, scratch,
        listFile: aclList });
    }
    const target = new pg.Client({ ...config, database: DATABASE });
    await target.connect();
    try {
      const before = await sampleIdentity(target);
      const migrationPool = new pg.Pool({ ...config, database: DATABASE,
        options: '-c pgsodium.enable_event_trigger=off' });
      try { await runMigrations(migrationPool, { verbose: false }); }
      finally { await migrationPool.end(); }
      // A logical restore carries rows and indexes but no planner statistics.
      // The signed recovery query must plan against the retained event count.
      await target.query('ANALYZE public.aimos_events');
      const after = await sampleIdentity(target);
      if (before.master_hash !== after.master_hash
          || before.agent_hash !== after.agent_hash
          || before.agent_count !== after.agent_count) fail('restored_identity_changed');
      const restoredAuthority = await authorityFingerprint(target);
      await synchronizeRuntimeRoleCredential({
        databaseUrl: resolveAimosDatabaseUrl([
          '--aimos-db', DATABASE,
          '--aimos-postgres-port', String(context.postgres_port),
        ]),
        databaseName: DATABASE,
        maintenanceConfig: config,
      });
      await activateServingRoles({
        argv: ['--aimos-postgres-port', String(context.postgres_port)],
        database: DATABASE,
      });
      const ledgerOutput = execFileSync(process.execPath, [
        path.join(ROOT, 'scripts', 'db', 'ledger-serving-credentials.mjs'),
        '--aimos-postgres-port', String(context.postgres_port),
      ], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 120_000, maxBuffer: 16 * 1024 });
      const credentialLedgerReceipt = JSON.parse(ledgerOutput);
      if (credentialLedgerReceipt.result !== 'serving_credentials_signed'
          || credentialLedgerReceipt.services?.length !== 2
          || credentialLedgerReceipt.services.some((entry) =>
            !['first_store_signed', 'existing_verified'].includes(entry.disposition))) {
        fail('serving_credential_ledger_invalid');
      }
      const acl = await provePrivileges(target);
      const policies = await proveBoundaryPolicies(target);
      await assertPrivatePostgresServingBoundary({
        argv: ['--aimos-postgres-port', String(context.postgres_port)],
      });
      return Object.freeze({
        identity: after, restoredAuthority,
        authority: await authorityFingerprint(target), credentialLedgerReceipt,
        acl_relation_count: acl.relation_acl_count,
        force_rls_tables: policies.force_rls_count,
      });
    } finally { await target.end().catch(() => {}); }
  } finally {
    await admin.end().catch(() => {});
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function cutoverReceiptPath(context) {
  return path.join(context.state_root, 'cutover', 'pre-switch-service.json');
}

function stagingMarkerPath(context) {
  return path.join(context.state_root, 'cutover', 'staging-marker.json');
}

export function validateStagingMarker(marker, { context, previous,
  generation } = {}) {
  const expectedData = secureClusterPaths(context.state_root).data;
  if (marker?.schema !== 'hom.aimos.canonical-cutover-staging/v1'
      || !/^[0-9a-f]{32}$/.test(String(marker.generation || ''))
      || marker.generation !== generation
      || marker.target_data !== expectedData
      || marker.target_postgres_port !== TARGET_POSTGRES_PORT
      || marker.source_service_sha256
        !== buildUserServiceManifest(previous).configuration_sha256
      || !Array.isArray(marker.created_credential_services)
      || marker.created_credential_services.some((service) =>
        ![
          clusterAdminCredentialService('canonical'),
          'aimos_service_reader_db_password',
          'aimos_identity_writer_db_password',
        ].includes(service))
      || !marker.created_credential_services.includes(
        clusterAdminCredentialService('canonical'))) {
    fail('staging_marker_invalid');
  }
  return true;
}

function readOwnerOnlyJson(file, reason) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0 || stat.size > 16 * 1024) fail(reason);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function assertSourceServiceReady(definition) {
  const response = await fetch(`http://127.0.0.1:${SERVICE_PORT}/health`, {
    signal: AbortSignal.timeout(5000),
  });
  const body = await response.json();
  if (!response.ok || !serviceReadinessMatches(definition, body)) {
    fail('source_service_not_ready');
  }
}

async function assertPrivateServiceReady(definition) {
  const response = await fetch(`http://127.0.0.1:${SERVICE_PORT}/health`, {
    signal: AbortSignal.timeout(5000),
  });
  const body = await response.json();
  if (!response.ok || !serviceReadinessMatches(definition, body)
      || definition.postgres_port !== TARGET_POSTGRES_PORT) {
    fail('private_service_not_ready');
  }
}

async function assertSourceServiceQuiesced(definition) {
  const status = await manageInstalledUserService('status');
  if (status.definition?.configuration_sha256
        !== buildUserServiceManifest(definition).configuration_sha256
      || status.supervisor?.loaded || status.health?.ready === true) {
    fail('source_service_not_quiesced');
  }
}

async function recoverSourceServiceIfInstalled(previous) {
  const installed = readInstalledUserServiceDefinition('canonical');
  if (buildUserServiceManifest(installed).configuration_sha256
      !== buildUserServiceManifest(previous).configuration_sha256) return false;
  const status = await manageInstalledUserService('status');
  if (status.success) return true;
  const started = await manageInstalledUserService('start');
  if (!serviceReadinessMatches(previous, started.health)) {
    fail('source_recovery_readiness_invalid');
  }
  return true;
}

function provePostSwitchSignedTraffic(actor, postgresPort) {
  const output = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'test', 'probe-cutover-serving.mjs'),
    '--aimos-db', DATABASE,
    '--aimos-postgres-port', String(postgresPort),
    '--aimos-port', String(SERVICE_PORT), '--agent-id', actor,
  ], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 120_000, maxBuffer: 16 * 1024 });
  const receipt = JSON.parse(output);
  if (receipt.result !== 'cutover_serving_signed_proof_pass'
      || receipt.agent_id !== actor || receipt.postgres_port !== postgresPort
      || receipt.server_port !== SERVICE_PORT || receipt.signed_status !== 200
      || receipt.signed_recall !== 200 || receipt.signed_save !== 200
      || !receipt.terminal_event_id || receipt.recall_receipt !== true) {
    fail('post_switch_signed_proof_invalid');
  }
  const audit = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'db', 'audit-serving-roles.mjs'),
    '--aimos-postgres-port', String(postgresPort), '--observe-ms', '5000',
  ], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 20_000, maxBuffer: 16 * 1024 });
  const sessions = JSON.parse(audit);
  if (sessions.database !== DATABASE || !Array.isArray(sessions.sessions)) {
    fail('post_switch_role_audit_invalid');
  }
  return receipt;
}

async function plan(options) {
  const prepared = prepareArchivePair(options);
  const rehearsal = options.rehearsalReceipt
    ? validatedRehearsalReceipt(options.rehearsalReceipt, prepared) : null;
  const sourceCounts = rehearsal ? await sourceLedgerCounts() : null;
  const previous = readInstalledUserServiceDefinition('canonical');
  const next = canonicalTargetDefinition(previous, options.pgBin, options.postgresPort);
  const context = resolveAimosInstallationContext([
    '--aimos-postgres-port', String(options.postgresPort),
  ]);
  const keyRoot = resolveAimosInstallationContext([]).agent_key_root;
  const actorKey = keyFileInfo(path.join(keyRoot, `${options.actor}.key`));
  keyFileInfo(path.join(keyRoot, 'housekeeper.key'));
  const actorAuthority = await preflightCanonicalCutoverActor(
    options.actor, LEGACY_POSTGRES_PORT);
  return Object.freeze({
    result: 'canonical_cutover_plan_only',
    archive_sha256: prepared.archiveSha256,
    acl_archive_sha256: prepared.aclArchiveSha256,
    schema_sha256: prepared.schemaSha256,
    archive_acl_entries: prepared.companion?.count || prepared.preflight.aclEntries,
    source_service: buildUserServiceManifest(previous),
    target_service: buildUserServiceManifest(next),
    target_pgdata_exists: fs.existsSync(secureClusterPaths(context.state_root).data),
    staging_marker_exists: fs.existsSync(stagingMarkerPath(context)),
    actor_key_size: actorKey.size,
    actor_authority: actorAuthority,
    authority_tables: AUTHORITY_TABLES,
    probe_port: options.probePort,
    rehearsal_qualified: Boolean(rehearsal),
    archive_ledger_counts: rehearsal ? rehearsal.retained_rows : null,
    source_ledger_counts: sourceCounts,
    ledger_counts_match: rehearsal ? (
      sourceCounts.events === rehearsal.retained_rows.events
      && sourceCounts.request_receipts === rehearsal.retained_rows.request_receipts
    ) : null,
    stage_and_switch_executed: false,
  });
}

async function apply(options) {
  const prepared = prepareArchivePair(options);
  const rehearsal = validatedRehearsalReceipt(options.rehearsalReceipt, prepared);
  const previous = readInstalledUserServiceDefinition('canonical');
  const next = canonicalTargetDefinition(previous, options.pgBin, options.postgresPort);
  const context = resolveAimosInstallationContext([
    '--aimos-postgres-port', String(options.postgresPort),
  ]);
  assertTargetAbsent(context);
  const receiptPath = cutoverReceiptPath(context);
  if (fs.existsSync(receiptPath)) fail('prior_cutover_receipt_exists');
  const markerPath = stagingMarkerPath(context);
  if (fs.existsSync(markerPath)) fail('prior_staging_marker_exists');
  if (readCredentialSync(clusterAdminCredentialService('canonical'))) {
    fail('admin_credential_already_exists');
  }
  await preflightCanonicalCutoverActor(options.actor, LEGACY_POSTGRES_PORT);
  await assertSourceServiceQuiesced(previous);
  try {
  const sourceActorAuthority = await preflightCanonicalCutoverActor(
    options.actor, LEGACY_POSTGRES_PORT);
  assertSourceLedgerCountsMatch(rehearsal, await sourceLedgerCounts());
  const sourceDatabase = await sourceDatabaseIdentity();
  const sourceBefore = await sourceAuthorityFingerprint();
  const createdCredentialServices = [clusterAdminCredentialService('canonical')];
  for (const service of [
    'aimos_service_reader_db_password', 'aimos_identity_writer_db_password',
  ]) {
    if (!readCredentialSync(service)) createdCredentialServices.push(service);
  }
  atomicJson(markerPath, {
    schema: 'hom.aimos.canonical-cutover-staging/v1',
    generation: randomBytes(16).toString('hex'),
    target_data: secureClusterPaths(context.state_root).data,
    target_postgres_port: context.postgres_port,
    source_service_sha256: buildUserServiceManifest(previous).configuration_sha256,
    archive_sha256: prepared.archiveSha256,
    acl_archive_sha256: prepared.aclArchiveSha256,
    created_credential_services: createdCredentialServices,
  });
  const staged = await stagePersistentTarget({
    ...options, context, prepared,
  });
  if (staged.identity.master_hash !== rehearsal.identity.master_hash
      || staged.identity.agent_hash !== rehearsal.identity.agent_hash
      || staged.identity.agent_count !== rehearsal.identity.agent_count) {
    fail('persistent_identity_differs_from_rehearsal');
  }
  assertAuthorityFingerprintEqual(sourceBefore, staged.restoredAuthority,
    'restored_authority_differs_from_source');
  const targetActorAuthority = await preflightCanonicalCutoverActor(
    options.actor, TARGET_POSTGRES_PORT);
  assertActorAuthorityPreserved(sourceActorAuthority, targetActorAuthority);
  const signedProof = await proveRestoredIdentityWithScratchInstance({
    actor: options.actor, postgresPort: options.postgresPort,
    serverPort: options.probePort,
  });
  const targetAfterProof = await targetAuthorityFingerprint(context);
  const sourceBeforeSwitch = await sourceAuthorityFingerprint();
  assertAuthorityFingerprintEqual(sourceBeforeSwitch, sourceBefore,
    'source_authority_changed_before_switch');
  const targetBeforeSwitch = await targetAuthorityFingerprint(context);
  assertAuthorityFingerprintEqual(targetBeforeSwitch, targetAfterProof,
    'target_authority_changed_before_switch');
  const rollbackDefinition = buildUserServiceManifest(previous);
  atomicJson(receiptPath, {
    schema: 'hom.aimos.canonical-cutover-rollback/v1',
    status: 'pending_switch',
    previous: rollbackDefinition,
    target: buildUserServiceManifest(next),
    archive_path: options.archive,
    source_database: sourceDatabase,
    archive_sha256: prepared.archiveSha256,
    acl_archive_sha256: prepared.aclArchiveSha256,
    schema_sha256: prepared.schemaSha256,
    source_authority: sourceBefore,
    actor_authority: sourceActorAuthority,
    target_authority_after_proof: targetAfterProof,
    signed_proof: signedProof,
    serving_credential_ledger: staged.credentialLedgerReceipt,
    rehearsal_archive_sha256: rehearsal.archive_sha256,
  });
  let result;
  try {
    result = await switchWithRollback(previous, next, {
      verifyAfterSwitch: async () => {
        return provePostSwitchSignedTraffic(options.actor, options.postgresPort);
      },
    });
  } catch (error) {
    // The manager's rollback (or switchWithRollback's post-check rollback)
    // must be independently visible before reopening the abandoned-target
    // reset path. Preserve the receipt if rollback is uncertain.
    try {
      const installed = readInstalledUserServiceDefinition('canonical');
      if (buildUserServiceManifest(installed).configuration_sha256
          === rollbackDefinition.configuration_sha256) {
        await assertSourceServiceReady(previous);
        fs.unlinkSync(receiptPath);
      }
    } catch { /* preserve receipt for manual recovery */ }
    throw error;
  }
  const switchedReceipt = {
    ...readOwnerOnlyJson(receiptPath, 'rollback_receipt_custody_invalid'),
    status: 'switched', switched_at: new Date().toISOString(),
    post_switch_proof: result.proof,
  };
  try {
    replaceOwnerOnlyJson(receiptPath, switchedReceipt);
  } catch (error) {
    try {
      const rollback = await installUserService(serviceOptions(previous));
      if (!serviceReadinessMatches(previous, rollback.health)) {
        fail('receipt_failure_rollback_readiness_invalid');
      }
      fs.unlinkSync(receiptPath);
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError],
        'canonical_cutover_receipt_and_rollback_failed');
    }
    throw error;
  }
  return Object.freeze({
    result: 'canonical_cutover_switched', receipt_path: receiptPath,
    postgres_port: options.postgresPort,
    identity: staged.identity, signed_proof: signedProof,
    health: { ready: result.health.ready,
      postgres_port: result.health.runtime.postgres_port },
  });
  } catch (error) {
    try { await recoverSourceServiceIfInstalled(previous); }
    catch (recoveryError) {
      throw new AggregateError([error, recoveryError],
        'canonical_cutover_apply_and_source_recovery_failed');
    }
    throw error;
  }
}

async function rollback() {
  const context = resolveAimosInstallationContext([]);
  const receiptPath = cutoverReceiptPath(context);
  const stat = fs.lstatSync(receiptPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) fail('rollback_receipt_custody_invalid');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  if (receipt.schema !== 'hom.aimos.canonical-cutover-rollback/v1') {
    fail('rollback_receipt_invalid');
  }
  if (['retirement_pending', 'source_retired'].includes(receipt.status)) {
    fail('rollback_source_retirement_started');
  }
  const previous = validateUserServiceManifest(receipt.previous);
  const next = validateUserServiceManifest(receipt.target);
  validateServiceTransition(previous, next);
  const installed = readInstalledUserServiceDefinition('canonical');
  const installedHash = buildUserServiceManifest(installed).configuration_sha256;
  if (installedHash === receipt.previous.configuration_sha256) {
    await assertSourceServiceReady(previous);
    return Object.freeze({ result: 'canonical_cutover_already_rolled_back',
      postgres_port: LEGACY_POSTGRES_PORT, source_database_retained: true });
  }
  if (installedHash !== receipt.target.configuration_sha256) {
    fail('rollback_current_service_mismatch');
  }
  const sourceDatabase = await sourceDatabaseIdentity();
  if (sourceDatabase.oid !== receipt.source_database?.oid
      || sourceDatabase.owner !== receipt.source_database?.owner
      || sourceDatabase.datallowconn !== true) {
    fail('rollback_source_database_unavailable_or_frozen');
  }
  const result = await installUserService(serviceOptions(previous));
  if (!serviceReadinessMatches(previous, result.health)) fail('rollback_readiness_invalid');
  return Object.freeze({ result: 'canonical_cutover_rolled_back',
    postgres_port: result.health.runtime.postgres_port,
    source_database_retained: true });
}

export function validateRetirementReceipt(receipt, installed,
  nowMs = Date.now()) {
  const switchedAt = Date.parse(receipt?.switched_at || '');
  if (receipt?.schema !== 'hom.aimos.canonical-cutover-rollback/v1'
      || !['switched', 'retirement_pending'].includes(receipt.status)
      || !Number.isFinite(switchedAt)
      || !Number.isFinite(nowMs) || nowMs < switchedAt
      || receipt.target?.configuration_sha256
        !== buildUserServiceManifest(installed).configuration_sha256
      || installed?.postgres_port !== TARGET_POSTGRES_PORT
      || receipt.source_database?.datname !== DATABASE
      || receipt.source_database?.datallowconn !== true
      || !/^\d+$/.test(String(receipt.source_database?.oid || ''))
      || !/^[a-z][a-z0-9_]{0,62}$/.test(
        String(receipt.source_database?.owner || ''))
      || !path.isAbsolute(String(receipt.archive_path || ''))
      || !/^[0-9a-f]{64}$/.test(String(receipt.archive_sha256 || ''))
      || receipt.signed_proof?.result !== 'restored_identity_signed_proof_pass'
      || receipt.actor_authority?.actor !== receipt.signed_proof?.agent_id
      || receipt.actor_authority?.write_allowed !== true
      || receipt.actor_authority?.clearance_ceiling < 5
      || receipt.post_switch_proof?.result !== 'cutover_serving_signed_proof_pass'
      || receipt.post_switch_proof?.signed_save !== 200
      || !receipt.post_switch_proof?.terminal_event_id) {
    fail('retirement_receipt_invalid');
  }
  assertAuthorityFingerprintEqual(receipt.source_authority,
    receipt.source_authority, 'retirement_source_fingerprint_invalid');
  return true;
}

async function retireSource() {
  const context = resolveAimosInstallationContext([]);
  const receiptPath = cutoverReceiptPath(context);
  const receipt = readOwnerOnlyJson(receiptPath,
    'retirement_receipt_custody_invalid');
  const installed = readInstalledUserServiceDefinition('canonical');
  validateRetirementReceipt(receipt, installed);
  if (sha256File(receipt.archive_path) !== receipt.archive_sha256) {
    fail('retirement_archive_hash_changed');
  }
  await assertPrivateServiceReady(installed);
  const restarted = await manageInstalledUserService('restart');
  if (!serviceReadinessMatches(installed, restarted.health)) {
    fail('retirement_private_restart_invalid');
  }
  const currentActorAuthority = await preflightCanonicalCutoverActor(
    receipt.signed_proof.agent_id, TARGET_POSTGRES_PORT);
  assertActorAuthorityPreserved(receipt.actor_authority,
    currentActorAuthority);
  provePostSwitchSignedTraffic(receipt.signed_proof.agent_id,
    TARGET_POSTGRES_PORT);
  const admin = new pg.Client({ host: '127.0.0.1',
    port: LEGACY_POSTGRES_PORT, database: 'postgres',
    user: os.userInfo().username, ssl: false,
    connectionTimeoutMillis: 5000 });
  try {
    await admin.connect();
    const database = (await admin.query(`SELECT oid::text AS oid, datname,
      pg_get_userbyid(datdba) AS owner, datallowconn
      FROM pg_database WHERE datname=$1`,
    [DATABASE])).rows[0] || null;
    if (!database) {
      if (receipt.status !== 'retirement_pending') {
        fail('retirement_source_database_missing_unexpectedly');
      }
    } else {
      if (database.oid !== receipt.source_database.oid
          || database.owner !== receipt.source_database.owner) {
        fail('retirement_source_database_identity_changed');
      }
      if (database.datallowconn !== true) {
        fail('retirement_source_already_frozen_use_unfreeze_source');
      }
      await freezeVerifyAndDropDatabase({
        admin, name: DATABASE,
        oid: receipt.source_database.oid,
        owner: receipt.source_database.owner,
        openKeeper: async () => {
          const keeper = new pg.Client({ host: '127.0.0.1',
            port: LEGACY_POSTGRES_PORT, database: DATABASE,
            user: os.userInfo().username, ssl: false,
            connectionTimeoutMillis: 5000, statement_timeout: 120_000 });
          await keeper.connect();
          return keeper;
        },
        readFingerprint: authorityFingerprint,
        compareFingerprint: (currentAuthority) =>
          assertAuthorityFingerprintEqual(currentAuthority,
            receipt.source_authority, 'retirement_source_authority_changed'),
        onFrozenVerified: async () => {
          replaceOwnerOnlyJson(receiptPath, {
            ...receipt, status: 'retirement_pending',
            frozen_verified_at: new Date().toISOString(),
          });
        },
        onReenabled: async () => {
          const { frozen_verified_at: _discard, ...rest } = receipt;
          replaceOwnerOnlyJson(receiptPath, {
            ...rest, status: 'switched',
          });
        },
      });
    }
    replaceOwnerOnlyJson(receiptPath, {
      ...receipt, status: 'source_retired',
      retired_at: new Date().toISOString(),
    });
    return Object.freeze({ result: 'canonical_old_database_retired',
      database: DATABASE, shared_postgres_port: LEGACY_POSTGRES_PORT,
      unrelated_databases_preserved: true,
      rollback_to_shared_database_available: false });
  } finally { await admin.end().catch(() => {}); }
}

async function unfreezeSource() {
  const context = resolveAimosInstallationContext([]);
  const receiptPath = cutoverReceiptPath(context);
  const receipt = readOwnerOnlyJson(receiptPath,
    'unfreeze_receipt_custody_invalid');
  const installed = readInstalledUserServiceDefinition('canonical');
  validateRetirementReceipt(receipt, installed);
  await assertPrivateServiceReady(installed);
  const admin = new pg.Client({ host: '127.0.0.1',
    port: LEGACY_POSTGRES_PORT, database: 'postgres',
    user: os.userInfo().username, ssl: false,
    connectionTimeoutMillis: 5000 });
  try {
    await admin.connect();
    const outcome = await reenableFrozenDatabase({ admin, name: DATABASE,
      oid: receipt.source_database.oid,
      owner: receipt.source_database.owner });
    if (receipt.status === 'retirement_pending') {
      const { frozen_verified_at: _discard, ...rest } = receipt;
      replaceOwnerOnlyJson(receiptPath, { ...rest, status: 'switched' });
    }
    return Object.freeze({ result: 'canonical_old_database_reenabled',
      changed: outcome.changed, database: DATABASE,
      shared_postgres_port: LEGACY_POSTGRES_PORT,
      rollback_to_shared_database_available: true });
  } finally { await admin.end().catch(() => {}); }
}

async function resetStaging({ generation, pgBin } = {}) {
  if (!/^[0-9a-f]{32}$/.test(String(generation || ''))
      || !path.isAbsolute(String(pgBin || ''))) fail('reset_inputs_invalid');
  const context = resolveAimosInstallationContext([
    '--aimos-postgres-port', String(TARGET_POSTGRES_PORT),
  ]);
  const previous = readInstalledUserServiceDefinition('canonical');
  if (previous.postgres_port !== LEGACY_POSTGRES_PORT
      || previous.port !== SERVICE_PORT || previous.database !== DATABASE) {
    fail('reset_source_service_not_installed');
  }
  await assertSourceServiceReady(previous);
  if (fs.existsSync(cutoverReceiptPath(context))) {
    fail('reset_after_switch_receipt_forbidden');
  }
  const markerPath = stagingMarkerPath(context);
  const marker = readOwnerOnlyJson(markerPath,
    'staging_marker_custody_invalid');
  validateStagingMarker(marker, { context, previous, generation });
  const pgConfig = path.join(pgBin, 'pg_config');
  const pgCtl = path.join(pgBin, 'pg_ctl');
  const version = execFileSync(pgConfig, ['--version'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000,
  });
  if (!/^PostgreSQL 18\./.test(version)) fail('reset_pg_binary_invalid');
  const paths = secureClusterPaths(context.state_root);
  if (fs.existsSync(paths.root)) {
    privateDirectory(paths.root);
    const entries = fs.readdirSync(paths.root).sort();
    if (entries.some((entry) => !['data', 'postgres.log'].includes(entry))) {
      fail('reset_target_contains_unrecognized_files');
    }
    privateDirectory(paths.data);
    if (fs.readFileSync(path.join(paths.data, 'PG_VERSION'), 'utf8').trim() !== '18'
        || fs.readFileSync(path.join(paths.data, 'pg_hba.conf'), 'utf8')
          !== secureHbaText()) fail('reset_target_cluster_invalid');
    let running = false;
    try {
      execFileSync(pgCtl, ['-D', paths.data, 'status'], {
        stdio: ['ignore', 'ignore', 'ignore'], timeout: 10_000,
      });
      running = true;
    } catch (error) {
      if (error.status !== 3) fail('reset_pg_status_unavailable');
    }
    if (running) {
      const secret = readCredentialSync(clusterAdminCredentialService('canonical'));
      if (!secret?.value) fail('reset_admin_credential_missing');
      await verifyExistingSecureCluster({
        stateRoot: context.state_root, port: context.postgres_port,
        adminPassword: secret.value,
      });
      const admin = new pg.Client({ host: '127.0.0.1',
        port: context.postgres_port, database: 'postgres',
        user: CLUSTER_ADMIN_ROLE, password: secret.value,
        ssl: false, connectionTimeoutMillis: 5000 });
      try {
        await admin.connect();
        const sessions = await admin.query(`SELECT count(*)::integer AS count
          FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`,
        [DATABASE]);
        if (sessions.rows[0].count !== 0) fail('reset_target_sessions_active');
      } finally { await admin.end().catch(() => {}); }
      execFileSync(pgCtl, ['-D', paths.data, '-m', 'fast', '-w', 'stop'], {
        stdio: ['ignore', 'ignore', 'ignore'], timeout: 60_000,
      });
    }
    fs.rmSync(paths.root, { recursive: true, force: true });
  }
  for (const service of marker.created_credential_services) {
    const entry = readCredentialSync(service);
    if (!entry) continue;
    keychainDeleteSync(entry.slot, CREDENTIAL_KEYCHAIN_ACCOUNT);
    keychainDeleteSync(entry.versionSlot, CREDENTIAL_KEYCHAIN_ACCOUNT);
    if (readCredentialSync(service)) fail('reset_credential_cleanup_failed');
  }
  fs.unlinkSync(markerPath);
  return Object.freeze({ result: 'canonical_cutover_abandoned_target_reset',
    target_postgres_port: TARGET_POSTGRES_PORT,
    source_database_retained: true, source_service_ready: true });
}

function optionsFromArgv(argv) {
  const pgBin = cliValue(argv, '--pg-bindir');
  const archive = cliValue(argv, '--archive');
  const aclArchive = cliValue(argv, '--acl-archive');
  const actor = cliValue(argv, '--probe-agent');
  const postgresPort = Number(cliValue(argv, '--postgres-port') || TARGET_POSTGRES_PORT);
  const probePort = Number(cliValue(argv, '--probe-port') || PROBE_PORT);
  const sourceOwnerRole = cliValue(argv, '--source-owner-role') || os.userInfo().username;
  if (!path.isAbsolute(String(pgBin || ''))
      || !path.isAbsolute(String(archive || ''))
      || (aclArchive && !path.isAbsolute(aclArchive))
      || !/^[a-z][a-z0-9_-]{0,63}$/.test(String(actor || ''))
      || !/^[a-z][a-z0-9_]{0,62}$/.test(String(sourceOwnerRole))
      || sourceOwnerRole === CLUSTER_ADMIN_ROLE
      || postgresPort !== TARGET_POSTGRES_PORT
      || !Number.isInteger(probePort) || probePort < 1024
      || probePort > 65535 || probePort === SERVICE_PORT
      || probePort === postgresPort || probePort === LEGACY_POSTGRES_PORT
      || RESERVED_LEGACY_PORTS.includes(probePort)) fail('cli_inputs_invalid');
  return { pgBin, archive, aclArchive, actor, postgresPort, probePort,
    rehearsalReceipt: cliValue(argv, '--rehearsal-receipt'),
    sourceOwnerRole,
    database: DATABASE };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const mode = argv[0];
  Promise.resolve().then(() => {
    if (mode === 'rollback') return rollback();
    if (mode === 'retire-source') return retireSource();
    if (mode === 'unfreeze-source') return unfreezeSource();
    if (mode === 'reset-staging') return resetStaging({
      generation: cliValue(argv, '--generation'),
      pgBin: cliValue(argv, '--pg-bindir'),
    });
    const options = optionsFromArgv(argv);
    if (mode === 'plan') return plan(options);
    if (mode === 'apply') return apply(options);
    fail('mode_invalid');
  }).then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
