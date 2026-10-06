#!/usr/bin/env node

// Provision a private PostgreSQL 18 cluster for one AIMOS installation. This
// is a database transport boundary, not a source of AIMOS policy authority.
// No password is placed in argv, an environment variable, or a disk file.

import { randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosInstallationContext } from '../../services/installation-context.js';

export const CLUSTER_ADMIN_ROLE = 'aimos_cluster_admin';
export function clusterAdminCredentialService(instance = 'canonical') {
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(String(instance))) {
    fail('instance_invalid');
  }
  return instance === 'canonical'
    ? 'aimos_cluster_admin_password'
    : `aimos_cluster_admin_password-${instance}`;
}
const HBA = [
  '# AIMOS private PostgreSQL cluster. The first matching rule is authoritative.',
  'host all all 127.0.0.1/32 scram-sha-256',
  'host all all ::1/128 scram-sha-256',
  '',
].join('\n');

function fail(reason) { throw new Error(`aimos_secure_cluster_${reason}`); }

function assertPrivateDirectory(directory, { create = false } = {}) {
  if (create) fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    fail('directory_custody_invalid');
  }
}

function binaryAt(pgBin, name) {
  const file = path.join(path.resolve(pgBin), name);
  if (!fs.statSync(file).isFile()) fail(`binary_missing_${name}`);
  return file;
}

function pathExistsNoFollow(file) {
  try { return fs.lstatSync(file); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function assertPostgres18(pgBin) {
  const version = execFileSync(binaryAt(pgBin, 'pg_config'), ['--version'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  if (!/^PostgreSQL 18\./.test(version)) fail('postgresql_18_required');
}

export function secureClusterPaths(stateRoot) {
  const root = path.join(path.resolve(stateRoot), 'postgresql-18');
  return Object.freeze({
    root,
    data: path.join(root, 'data'),
    log: path.join(root, 'postgres.log'),
  });
}

export function secureHbaText() { return HBA; }

async function verifyLiveCluster({ port, password, adminRole, paths }) {
  const hbaFile = path.join(paths.data, 'pg_hba.conf');
  const hbaStat = fs.lstatSync(hbaFile);
  if (!hbaStat.isFile() || hbaStat.isSymbolicLink()
      || hbaStat.uid !== process.getuid() || (hbaStat.mode & 0o077) !== 0
      || fs.readFileSync(hbaFile, 'utf8') !== HBA) fail('hba_file_invalid');
  const client = new pg.Client({
    host: '127.0.0.1', port, database: 'postgres', user: adminRole,
    password, ssl: false, connectionTimeoutMillis: 5000,
  });
  try {
    await client.connect();
    const facts = await client.query(`
      SELECT current_user, current_setting('data_directory') AS data_directory,
             current_setting('hba_file') AS hba_file,
             current_setting('listen_addresses') AS listen_addresses,
             current_setting('unix_socket_directories') AS socket_directories,
             current_setting('password_encryption') AS password_encryption,
             (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser`);
    const row = facts.rows[0];
    if (row.current_user !== adminRole || row.data_directory !== paths.data
        || row.hba_file !== path.join(paths.data, 'pg_hba.conf')
        || row.listen_addresses !== '127.0.0.1,::1'
        || row.socket_directories !== ''
        || row.password_encryption !== 'scram-sha-256' || row.superuser !== true) {
      fail('connected_server_identity_mismatch');
    }
    const rules = await client.query(`
      SELECT type, database, user_name, address, netmask, auth_method, error
        FROM pg_hba_file_rules ORDER BY rule_number`);
    if (rules.rows.length !== 2 || rules.rows.some((rule) => (
      rule.error || rule.auth_method !== 'scram-sha-256'
      || JSON.stringify(rule.database) !== '["all"]'
      || JSON.stringify(rule.user_name) !== '["all"]'
    ))) fail('loaded_hba_rules_invalid');
    const [ipv4, ipv6] = rules.rows;
    if (ipv4.type !== 'host' || ipv4.address !== '127.0.0.1'
        || ipv4.netmask !== '255.255.255.255'
        || ipv6.type !== 'host' || ipv6.address !== '::1'
        || ipv6.netmask !== 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') {
      fail('loaded_hba_scope_invalid');
    }
  } finally {
    await client.end().catch(() => {});
  }
}

export async function verifyExistingSecureCluster({ stateRoot, port, adminPassword,
  adminRole = CLUSTER_ADMIN_ROLE } = {}) {
  if (!path.isAbsolute(String(stateRoot || '')) || !Number.isInteger(port)
      || typeof adminPassword !== 'string') fail('verification_inputs_invalid');
  const paths = secureClusterPaths(stateRoot);
  assertPrivateDirectory(stateRoot);
  assertPrivateDirectory(paths.root);
  assertPrivateDirectory(paths.data);
  if (fs.readFileSync(path.join(paths.data, 'PG_VERSION'), 'utf8').trim() !== '18') {
    fail('existing_version_invalid');
  }
  await verifyLiveCluster({ port, password: adminPassword, adminRole, paths });
  return Object.freeze({ data: paths.data, port, adminRole, authMethod: 'scram-sha-256' });
}

export async function initializeSecureCluster({
  stateRoot, port, pgBin, adminPassword, adminRole = CLUSTER_ADMIN_ROLE,
} = {}) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535
      || [9000, 9001, 9100].includes(port)) fail('port_invalid');
  if (port === 5432) fail('shared_default_port_forbidden');
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(adminRole)) fail('admin_role_invalid');
  if (typeof adminPassword !== 'string' || adminPassword.length < 32) fail('admin_password_invalid');
  if (!path.isAbsolute(String(stateRoot || '')) || !path.isAbsolute(String(pgBin || ''))) {
    fail('absolute_paths_required');
  }

  assertPostgres18(pgBin);
  assertPrivateDirectory(stateRoot, { create: true });
  const paths = secureClusterPaths(stateRoot);
  assertPrivateDirectory(paths.root, { create: true });
  const existing = pathExistsNoFollow(paths.data);
  if (existing) {
    assertPrivateDirectory(paths.data);
    if (fs.readFileSync(path.join(paths.data, 'PG_VERSION'), 'utf8').trim() !== '18') {
      fail('existing_version_invalid');
    }
    const hba = pathExistsNoFollow(path.join(paths.data, 'pg_hba.conf'));
    if (!hba?.isFile() || hba.isSymbolicLink()
        || fs.readFileSync(path.join(paths.data, 'pg_hba.conf'), 'utf8') !== HBA) {
      fail('existing_hba_invalid');
    }
    let running = false;
    try {
      execFileSync(binaryAt(pgBin, 'pg_ctl'), ['-D', paths.data, 'status'], {
        stdio: ['ignore', 'ignore', 'ignore'], timeout: 10_000,
      });
      running = true;
    } catch { /* A stopped verified cluster may be started below. */ }
    if (!running) {
      execFileSync(binaryAt(pgBin, 'pg_ctl'), [
        '-D', paths.data, '-l', paths.log, '-w', '-t', '30', 'start',
      ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 40_000 });
    }
    await verifyLiveCluster({ port, password: adminPassword, adminRole, paths });
    return Object.freeze({
      data: paths.data, port, adminRole, authMethod: 'scram-sha-256', created: false,
    });
  }

  // initdb reads --pwfile=/dev/stdin from an anonymous pipe. Its stdout and
  // stderr are captured and never contain the generated password.
  const init = spawnSync(binaryAt(pgBin, 'initdb'), [
    '-D', paths.data, '-U', adminRole, '--encoding=UTF8',
    '--auth-local=scram-sha-256', '--auth-host=scram-sha-256',
    '--pwfile=/dev/stdin', '--data-checksums', '--no-instructions',
  ], {
    input: `${adminPassword}\n`, encoding: 'utf8', timeout: 120_000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (init.status !== 0) fail(`initdb_failed:${init.error?.code || init.status}`);
  assertPrivateDirectory(paths.data);

  fs.writeFileSync(path.join(paths.data, 'pg_hba.conf'), HBA, { mode: 0o600 });
  fs.chmodSync(path.join(paths.data, 'pg_hba.conf'), 0o600);
  fs.appendFileSync(path.join(paths.data, 'postgresql.conf'), [
    '', '# AIMOS private cluster transport settings',
    `port = ${port}`,
    "listen_addresses = '127.0.0.1,::1'",
    "unix_socket_directories = ''",
    "password_encryption = 'scram-sha-256'",
    '',
  ].join('\n'));
  fs.writeFileSync(paths.log, '', { mode: 0o600, flag: 'wx' });

  try {
    execFileSync(binaryAt(pgBin, 'pg_ctl'), [
      '-D', paths.data, '-l', paths.log, '-w', '-t', '30', 'start',
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 40_000 });
    await verifyLiveCluster({ port, password: adminPassword, adminRole, paths });
  } catch (error) {
    // Preserve the failed cluster for inspection; never silently erase PGDATA.
    throw new Error(`aimos_secure_cluster_start_or_verify_failed:${error.message}`);
  }
  return Object.freeze({
    data: paths.data, port, adminRole,
    authMethod: 'scram-sha-256', created: true,
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const context = resolveAimosInstallationContext(argv);
  const binIndex = argv.indexOf('--pg-bindir');
  const pgBin = binIndex < 0 ? null : argv[binIndex + 1];
  if (!pgBin) fail('pg_bindir_required');
  const service = clusterAdminCredentialService(context.instance);
  const { readCredentialSync, storeCredentialSync } = await import('../../services/security/credential-store.js');
  let credential = readCredentialSync(service);
  if (!credential) {
    storeCredentialSync(service, randomBytes(48).toString('base64url'));
    credential = readCredentialSync(service);
  }
  if (!credential?.value) fail('admin_credential_readback_failed');
  const result = await initializeSecureCluster({
    stateRoot: context.state_root,
    port: context.postgres_port,
    pgBin,
    adminPassword: credential.value,
  });
  process.stdout.write(`${JSON.stringify({ ...result, credentialSlot: credential.slot })}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
