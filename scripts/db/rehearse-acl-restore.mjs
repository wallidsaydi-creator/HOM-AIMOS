#!/usr/bin/env node

// Rehearse an identity-preserving restore wholly inside a disposable private
// PostgreSQL 18 cluster. This command never connects to the source database,
// canonical Keychain, or AIMOS service. It requires an ACL-bearing archive:
// an archive made with --no-privileges cannot establish historical runtime
// grants when schema_migrations already records their migrations.

import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { runMigrations } from '../../migrations/run.js';
import { RESERVED_LEGACY_PORTS } from '../../services/core/runtime-config.js';
import { preflightRestoreArchive } from './preflight-restore-archive.mjs';
import { CLUSTER_ADMIN_ROLE, initializeSecureCluster,
  secureClusterPaths } from './secure-cluster.mjs';
import { makePostgresScramVerifier } from './scram-verifier.mjs';

const ROLE_NAMES = Object.freeze([
  'agent_runtime', 'aimos_app', 'aimos_app_ro', 'aimos_flag_signer',
  'aimos_service_reader', 'aimos_identity_writer',
]);
const IDENTITY_SQL = `SELECT
  (SELECT count(*)::integer FROM public.aimos_master_identity) AS master_count,
  (SELECT md5(coalesce(string_agg(md5(to_jsonb(x)::text), '' ORDER BY x.id::text), ''))
     FROM public.aimos_master_identity x) AS master_hash,
  (SELECT count(*)::integer FROM public.agent_identity) AS agent_count,
  (SELECT md5(coalesce(string_agg(md5(to_jsonb(x)::text), ''
     ORDER BY x.agent_id::text, x.valid_from::text), ''))
     FROM public.agent_identity x) AS agent_hash,
  (SELECT count(*)::integer FROM public.aimos_memories) AS memory_count,
  (SELECT count(*)::integer FROM public.aimos_events) AS event_count,
  (SELECT count(*)::integer FROM public.aimos_request_receipts) AS request_receipt_count,
  (SELECT count(*)::integer FROM public.schema_migrations) AS migration_count`;

function fail(reason) { throw new Error(`acl_restore_rehearsal_${reason}`); }
function sha256(file) {
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

function cliValue(argv, name) {
  const index = argv.indexOf(name);
  return index < 0 ? null : argv[index + 1];
}

function assertName(name) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(String(name || ''))) fail('role_name_invalid');
  return name;
}

function assertScratchPort(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535
      || port === 5432 || port === 9100
      || RESERVED_LEGACY_PORTS.includes(port)) fail('scratch_port_invalid');
  return port;
}

function archiveToc(pgBin, archive) {
  const stat = fs.lstatSync(archive);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) fail('archive_custody_invalid');
  return execFileSync(path.join(pgBin, 'pg_restore'), ['--list', archive], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 60_000, maxBuffer: 16 * 1024 * 1024,
  });
}

export function fingerprintSchemaSql(sql) {
  if (typeof sql !== 'string' || !sql.startsWith('--\n-- PostgreSQL database dump\n')) {
    fail('schema_sql_invalid');
  }
  // pg_restore uses a fresh psql command-restriction nonce for each dump.
  // The nonce carries no schema meaning; every remaining byte must match.
  return createHash('sha256').update(
    sql.replace(/^\\(?:un)?restrict [^\n]+$/gm, '\\restrict TOKEN'), 'utf8',
  ).digest('hex');
}

function schemaSqlHash(pgBin, archive) {
  const sql = execFileSync(path.join(pgBin, 'pg_restore'), [
    '--schema-only', '--no-owner', '--no-privileges', '--file=-', archive,
  ], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 60_000, maxBuffer: 32 * 1024 * 1024,
  });
  return fingerprintSchemaSql(sql);
}

function companionAclList({ pgBin, dataArchive, aclArchive, database }) {
  const toc = archiveToc(pgBin, aclArchive);
  if (!new RegExp(`^;\\s*dbname:\\s*${database}\\s*$`, 'm').test(toc)
      || !/^;\s*Dumped from database version:\s*18\./m.test(toc)
      || !/^;\s*Dumped by pg_dump version:\s*18\./m.test(toc)) {
    fail('acl_companion_origin_invalid');
  }
  const entries = toc.split('\n').filter((line) => /^\d+;\s/.test(line));
  const acl = entries.filter((line) => /\bACL\b/.test(line));
  if (acl.length < 1 || entries.some((line) =>
    /\b(?:TABLE DATA|MATERIALIZED VIEW DATA|SEQUENCE SET|BLOBS?|LARGE OBJECT)\b/.test(line))) {
    fail('acl_companion_not_schema_only');
  }
  const dataSchemaHash = schemaSqlHash(pgBin, dataArchive);
  const aclSchemaHash = schemaSqlHash(pgBin, aclArchive);
  if (dataSchemaHash !== aclSchemaHash) fail('acl_companion_schema_mismatch');
  return Object.freeze({ list: `${acl.join('\n')}\n`, count: acl.length,
    schemaHash: dataSchemaHash });
}

// libpq requires a regular password file. Supply an already-unlinked,
// mode-0600 temporary inode through fd 3. There is no pathname to reopen,
// and the password is absent from argv and environment values.
export async function runPgRestore({ pgBin, archive, port, password, database,
  scratch, listFile = null }) {
  const args = [
    '--no-owner', '--exit-on-error', '--single-transaction',
    ...(listFile ? [`--use-list=${listFile}`] : []),
    '--host=127.0.0.1', `--port=${port}`, `--username=${CLUSTER_ADMIN_ROLE}`,
    `--dbname=${database}`, archive,
  ];
  const credentialPath = path.join(scratch, `pgpass-${randomBytes(8).toString('hex')}`);
  fs.writeFileSync(credentialPath,
    `127.0.0.1:${port}:*:${CLUSTER_ADMIN_ROLE}:${password}\n`,
    { mode: 0o600, flag: 'wx' });
  const credentialFd = fs.openSync(credentialPath, 'r');
  fs.unlinkSync(credentialPath);
  const child = spawn(path.join(pgBin, 'pg_restore'), args, {
    env: {
      ...process.env,
      PGPASSFILE: '/dev/fd/3',
      PGOPTIONS: '-c pgsodium.enable_event_trigger=off',
    },
    stdio: ['ignore', 'ignore', 'pipe', credentialFd],
  });
  fs.closeSync(credentialFd);
  let stderr = '';
  child.stderr.on('data', (data) => {
    // Never print pg_restore SQL or COPY data. Keep only a bounded diagnostic
    // for classifying local failures; it may contain retained row values.
    stderr = (stderr + data.toString()).slice(-4096);
  });
  const timer = setTimeout(() => child.kill('SIGTERM'), 10 * 60 * 1000);
  const code = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  }).finally(() => clearTimeout(timer));
  if (code !== 0) {
    if (/password file .* must be a plain file|no password supplied|password authentication failed/i.test(stderr)) {
      fail('password_pipe_unavailable');
    }
    fail(`pg_restore_failed:${code}`);
  }
}

export async function sampleIdentity(client) {
  const row = (await client.query(IDENTITY_SQL)).rows[0];
  if (row.master_count !== 1 || row.agent_count < 1 || row.migration_count < 1) {
    fail('identity_cardinality_invalid');
  }
  return row;
}

export async function stageArchiveRoles(client, sourceOwnerRole) {
  for (const role of [...ROLE_NAMES, sourceOwnerRole]) {
    if (role === CLUSTER_ADMIN_ROLE || role === 'pg_database_owner') continue;
    const exists = (await client.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [role])).rowCount;
    if (!exists) await client.query(`CREATE ROLE ${role}
      NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
      NOREPLICATION NOINHERIT`);
  }
}

export async function provePrivileges(client) {
  const row = (await client.query(`SELECT
    has_schema_privilege('agent_runtime', 'public', 'USAGE') AS agent_schema,
    has_any_column_privilege('agent_runtime', 'public.aimos_memories', 'SELECT') AS agent_memory_read,
    has_any_column_privilege('agent_runtime', 'public.aimos_events', 'INSERT') AS agent_event_write,
    has_table_privilege('aimos_service_reader', 'public.aimos_memories', 'SELECT') AS reader_memory_read,
    has_any_column_privilege('aimos_service_reader', 'public.aimos_memories', 'INSERT') AS reader_memory_write,
    has_any_column_privilege('aimos_identity_writer', 'public.agent_identity', 'INSERT') AS identity_append,
    (SELECT count(*)::integer FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relacl IS NOT NULL) AS relation_acl_count,
    (SELECT count(*)::integer FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proacl IS NOT NULL) AS function_acl_count,
    (SELECT count(*)::integer FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND a.attacl IS NOT NULL) AS column_acl_count,
    (SELECT count(*)::integer FROM pg_default_acl) AS default_acl_count`)).rows[0];
  if (!row.agent_schema || !row.agent_memory_read || !row.agent_event_write
      || !row.reader_memory_read || row.reader_memory_write || !row.identity_append
      || row.relation_acl_count < 1 || row.function_acl_count < 1
      || row.column_acl_count < 1 || row.default_acl_count < 1) {
    fail('acl_postcondition_invalid');
  }
  return row;
}

export async function proveBoundaryPolicies(client) {
  const row = (await client.query(`SELECT
    (SELECT count(*)::integer FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relrowsecurity AND c.relforcerowsecurity) AS force_rls_count,
    (SELECT count(*)::integer FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND p.polname='aimos_service_reader_hom_only'
        AND NOT p.polpermissive) AS reader_policy_count,
    (SELECT count(*)::integer FROM pg_policy p
      WHERE p.polrelid='public.aimos_events'::regclass
        AND p.polname='aimos_identity_writer_hom_only'
        AND NOT p.polpermissive) AS identity_policy_count,
    (SELECT NOT rolcanlogin AND rolpassword IS NULL FROM pg_authid
      WHERE rolname='aimos_app') AS legacy_login_retired`)).rows[0];
  if (row.force_rls_count < 17 || row.reader_policy_count !== 17
      || row.identity_policy_count !== 1 || row.legacy_login_retired !== true) {
    fail('boundary_policy_postcondition_invalid');
  }
  return row;
}

async function proveServingLogin(config, role) {
  const password = randomBytes(48).toString('base64url');
  const verifier = makePostgresScramVerifier(password);
  const admin = new pg.Client(config);
  try {
    await admin.connect();
    await admin.query(`ALTER ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS
      NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD '${verifier}'`);
  } finally { await admin.end().catch(() => {}); }
  for (const host of ['127.0.0.1', '::1']) {
    const good = new pg.Client({ ...config, host, user: role, password });
    try {
      await good.connect();
      const result = await good.query(`SELECT current_user,
        current_setting('app.current_client_id', true) AS company,
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
        (SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user) AS bypass_rls`);
      const row = result.rows[0];
      if (row.current_user !== role
          || (role !== 'agent_runtime' && row.company !== 'hom')
          || row.superuser || row.bypass_rls) fail(`serving_login_invalid:${role}`);
    } finally { await good.end().catch(() => {}); }
    for (const invalid of [`${password}wrong`, '']) {
      const bad = new pg.Client({ ...config, host, user: role, password: invalid });
      try {
        await bad.connect();
        fail(`invalid_password_accepted:${role}`);
      } catch (error) {
        if (String(error.message).startsWith('acl_restore_rehearsal_')) throw error;
      } finally { await bad.end().catch(() => {}); }
    }
  }
}

export function prepareArchivePair({ archive, aclArchive = null, pgBin, database = 'aimos' } = {}) {
  if (!path.isAbsolute(String(archive || '')) || !path.isAbsolute(String(pgBin || ''))
      || (aclArchive && !path.isAbsolute(String(aclArchive)))
      || !/^[a-z][a-z0-9_]{0,62}$/.test(database)) fail('inputs_invalid');
  const preflight = preflightRestoreArchive({ archive, pgBin, database,
    requireAcl: !aclArchive });
  if (aclArchive && preflight.aclEntries !== 0) fail('companion_unnecessary');
  const companion = aclArchive ? companionAclList({
    pgBin, dataArchive: archive, aclArchive, database,
  }) : null;
  return Object.freeze({ preflight, companion,
    archiveSha256: sha256(archive),
    aclArchiveSha256: aclArchive ? sha256(aclArchive) : sha256(archive),
    schemaSha256: companion?.schemaHash || schemaSqlHash(pgBin, archive) });
}

export function inspectArchivePair(options = {}) {
  const prepared = prepareArchivePair(options);
  return Object.freeze({ result: 'archive_pair_metadata_pass',
    archive_sha256: prepared.archiveSha256,
    acl_archive_sha256: prepared.aclArchiveSha256,
    archive_acl_entries: prepared.companion?.count || prepared.preflight.aclEntries,
    schema_sha256: prepared.schemaSha256,
    qualification: 'metadata_only_no_database_restore' });
}

export async function rehearseAclRestore({ archive, aclArchive = null, pgBin, port,
  sourceOwnerRole = os.userInfo().username, database = 'aimos' } = {}) {
  assertName(sourceOwnerRole);
  assertScratchPort(port);
  const { preflight, companion, archiveSha256,
    aclArchiveSha256, schemaSha256 } = prepareArchivePair({
    archive, aclArchive, pgBin, database,
  });
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-acl-restore-'));
  fs.chmodSync(scratch, 0o700);
  const aclListFile = companion ? path.join(scratch, 'acl-only.list') : null;
  if (aclListFile) fs.writeFileSync(aclListFile, companion.list, { mode: 0o600, flag: 'wx' });
  const password = randomBytes(48).toString('base64url');
  let admin;
  try {
    await initializeSecureCluster({
      stateRoot: scratch, port, pgBin, adminPassword: password,
    });
    const config = {
      host: '127.0.0.1', port, user: CLUSTER_ADMIN_ROLE,
      password, database: 'postgres', ssl: false, connectionTimeoutMillis: 5000,
    };
    admin = new pg.Client(config);
    await admin.connect();
    await stageArchiveRoles(admin, sourceOwnerRole);
    await admin.query(`CREATE DATABASE ${database}`);
    await admin.end();
    admin = new pg.Client({ ...config, database });
    await admin.connect();
    await runPgRestore({ pgBin, archive, port, password, database, scratch });
    if (companion) {
      await runPgRestore({
        pgBin, archive: aclArchive, port, password, database, scratch,
        listFile: aclListFile,
      });
    }
    const before = await sampleIdentity(admin);
    const migrationPool = new pg.Pool({
      ...config, database, options: '-c pgsodium.enable_event_trigger=off',
    });
    let migration;
    try {
      migration = await runMigrations(migrationPool, { verbose: false });
    } finally { await migrationPool.end(); }
    const after = await sampleIdentity(admin);
    if (before.master_hash !== after.master_hash || before.agent_hash !== after.agent_hash
        || before.master_count !== after.master_count || before.agent_count !== after.agent_count) {
      fail('identity_changed_by_migrations');
    }
    const privileges = await provePrivileges(admin);
    const policies = await proveBoundaryPolicies(admin);
    for (const role of ['agent_runtime', 'aimos_service_reader', 'aimos_identity_writer']) {
      await proveServingLogin({ ...config, database }, role);
    }
    return Object.freeze({
      result: 'isolated_restore_pass', archive_sha256: archiveSha256,
      acl_archive_sha256: aclArchiveSha256,
      archive_acl_entries: companion ? companion.count : preflight.aclEntries,
      schema_sha256: schemaSha256,
      source_migration_count: before.migration_count,
      target_migration_count: after.migration_count,
      applied_migrations: migration.applied.length,
      identity: { master_count: after.master_count, master_hash: after.master_hash,
        agent_count: after.agent_count, agent_hash: after.agent_hash },
      retained_rows: { memories: after.memory_count, events: after.event_count,
        request_receipts: after.request_receipt_count },
      acl: { relation_count: privileges.relation_acl_count,
        function_count: privileges.function_acl_count,
        column_count: privileges.column_acl_count,
        default_count: privileges.default_acl_count },
      boundary: { force_rls_tables: policies.force_rls_count,
        reader_restrictive_policies: policies.reader_policy_count,
        identity_event_policy: policies.identity_policy_count,
        legacy_login_retired: policies.legacy_login_retired },
      serving_roles: ['agent_runtime', 'aimos_service_reader', 'aimos_identity_writer'],
      scratch_cleaned: true,
    });
  } finally {
    await admin?.end().catch(() => {});
    const clusterData = secureClusterPaths(scratch).data;
    let stopped = true;
    if (fs.existsSync(path.join(clusterData, 'PG_VERSION'))) {
      const status = await new Promise((resolve) => {
        const child = spawn(path.join(pgBin, 'pg_ctl'), [
          '-D', clusterData, 'status',
        ], { stdio: 'ignore' });
        child.on('error', () => resolve(false));
        child.on('close', (code) => resolve(code === 0));
      });
      if (status) {
        await new Promise((resolve) => {
          const child = spawn(path.join(pgBin, 'pg_ctl'), [
            '-D', clusterData, '-m', 'fast', '-w', 'stop',
          ], { stdio: 'ignore' });
          child.on('error', () => resolve(false));
          child.on('close', (code) => resolve(code === 0));
        }).then((value) => { stopped = value; });
      }
    }
    if (stopped) {
      fs.rmSync(scratch, { recursive: true, force: true });
    } else {
      process.stderr.write(`acl_restore_rehearsal_scratch_preserved:${scratch}\n`);
      fail('scratch_stop_failed');
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const options = {
    archive: cliValue(argv, '--archive'),
    aclArchive: cliValue(argv, '--acl-archive'),
    pgBin: cliValue(argv, '--pg-bindir'),
    port: Number(cliValue(argv, '--scratch-port')),
    sourceOwnerRole: cliValue(argv, '--source-owner-role') || os.userInfo().username,
    database: cliValue(argv, '--database') || 'aimos',
  };
  Promise.resolve().then(() => argv.includes('--preflight-only')
    ? inspectArchivePair(options) : rehearseAclRestore(options)).then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
