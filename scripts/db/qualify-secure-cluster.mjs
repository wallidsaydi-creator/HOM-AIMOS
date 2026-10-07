#!/usr/bin/env node

// Disposable PostgreSQL 18 qualification. It changes only a new temporary
// cluster, then stops and removes that cluster after the assertions finish.

import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';

import { initializeSecureCluster, secureClusterPaths } from './secure-cluster.mjs';
import { makePostgresScramVerifier } from './scram-verifier.mjs';

function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

async function connectionDenied(config) {
  const client = new pg.Client(config);
  try {
    await client.connect();
    return false;
  } catch (error) {
    if (error.code === '28P01' || /password must be a string/i.test(error.message)) return true;
    throw error;
  } finally {
    await client.end().catch(() => {});
  }
}

async function main() {
  const pgBin = cliValue('--pg-bindir');
  const port = Number(cliValue('--port'));
  if (!pgBin || !Number.isInteger(port)) {
    throw new Error('usage: qualify-secure-cluster.mjs --pg-bindir ABSOLUTE --port UNUSED_PORT');
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-secure-pg-'));
  fs.chmodSync(root, 0o700);
  const paths = secureClusterPaths(root);
  const adminPassword = randomBytes(48).toString('base64url');
  const appPassword = randomBytes(48).toString('base64url');
  const role = 'aimos_scram_qualification';
  let admin;
  let started = false;
  let qualified = false;
  try {
    const cluster = await initializeSecureCluster({
      stateRoot: root, port, pgBin, adminPassword,
    });
    started = true;
    if (!cluster.created || cluster.authMethod !== 'scram-sha-256') {
      throw new Error('secure_cluster_initialization_invalid');
    }
    const repeated = await initializeSecureCluster({
      stateRoot: root, port, pgBin, adminPassword,
    });
    if (repeated.created) throw new Error('secure_cluster_reopen_invalid');

    admin = new pg.Client({
      host: '127.0.0.1', port, database: 'postgres',
      user: cluster.adminRole, password: adminPassword, ssl: false,
    });
    await admin.connect();
    const verifier = makePostgresScramVerifier(appPassword);
    await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${verifier}'`);
    const roleResult = await admin.query(
      'SELECT rolsuper, rolbypassrls, rolpassword FROM pg_authid WHERE rolname = $1', [role]);
    if (roleResult.rows.length !== 1 || roleResult.rows[0].rolsuper
        || roleResult.rows[0].rolbypassrls
        || !roleResult.rows[0].rolpassword.startsWith('SCRAM-SHA-256$')) {
      throw new Error('scram_role_catalog_invalid');
    }
    const base = { host: '127.0.0.1', port, database: 'postgres',
      user: role, ssl: false, connectionTimeoutMillis: 5000 };
    const good = new pg.Client({ ...base, password: appPassword });
    try {
      await good.connect();
      const result = await good.query('SELECT current_user');
      if (result.rows[0]?.current_user !== role) throw new Error('scram_role_identity_invalid');
    } finally {
      await good.end().catch(() => {});
    }
    if (!await connectionDenied({ ...base, password: 'wrong-qualification-password' })) {
      throw new Error('scram_wrong_password_accepted');
    }
    if (!await connectionDenied({ ...base, password: '' })) {
      throw new Error('scram_passwordless_connection_accepted');
    }
    await admin.query(`DROP ROLE ${role}`);
    qualified = true;
  } finally {
    await admin?.end().catch(() => {});
    if (started) {
      try {
        execFileSync(path.join(pgBin, 'pg_ctl'), [
          '-D', paths.data, '-m', 'fast', '-w', 'stop',
        ], { stdio: ['ignore', 'ignore', 'ignore'], timeout: 30_000 });
      } catch {
        throw new Error(`secure_cluster_scratch_stop_failed_retained:${root}`);
      }
    }
    // The only directory ever removed is this invocation's random scratch.
    fs.rmSync(root, { recursive: true, force: true });
  }
  if (qualified) process.stdout.write(`${JSON.stringify({
    postgres: 18, auth: 'scram-sha-256', loopbackOnly: true,
    unixSocketsDisabled: true, correctPasswordAccepted: true,
    wrongPasswordDenied: true, passwordlessDenied: true,
    roleSuperuser: false, roleBypassRls: false, scratchRemoved: true,
  })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
