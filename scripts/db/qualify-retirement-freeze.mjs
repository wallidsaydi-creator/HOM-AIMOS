#!/usr/bin/env node

// Disposable PostgreSQL 18 proof for the old-database retirement barrier.
// Exercises ALLOW_CONNECTIONS=false, existing sessions, exclusive session
// census, DROP behavior, re-enable on failure, and unrelated DB continuity.

import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';

import { CLUSTER_ADMIN_ROLE, initializeSecureCluster,
  secureClusterPaths } from './secure-cluster.mjs';
import { freezeVerifyAndDropDatabase,
  reenableFrozenDatabase } from './retirement-freeze.mjs';

function fail(reason) { throw new Error(`retirement_freeze_fixture_${reason}`); }
function cliValue(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}
async function connected(config) {
  const client = new pg.Client(config);
  await client.connect();
  return client;
}
async function rejectedConnect(config) {
  const client = new pg.Client(config);
  try {
    await client.connect();
    fail('new_connection_accepted_while_frozen');
  } catch (error) {
    if (String(error.message).startsWith('retirement_freeze_fixture_')) throw error;
  } finally { await client.end().catch(() => {}); }
}

async function main() {
  if (!process.argv.includes('--disposable')) fail('disposable_flag_required');
  const pgBin = cliValue('--pg-bindir');
  const port = Number(cliValue('--scratch-port'));
  if (!path.isAbsolute(String(pgBin || '')) || !Number.isInteger(port)
      || port < 1024 || port > 65535 || [5432, 9100].includes(port)) {
    fail('inputs_invalid');
  }
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'aimos-retire-freeze-'));
  fs.chmodSync(scratch, 0o700);
  const password = randomBytes(48).toString('base64url');
  const config = { host: '127.0.0.1', port, user: CLUSTER_ADMIN_ROLE,
    password, ssl: false, connectionTimeoutMillis: 5000 };
  let admin;
  let keeper;
  let intruder;
  try {
    await initializeSecureCluster({ stateRoot: scratch, port, pgBin,
      adminPassword: password });
    admin = await connected({ ...config, database: 'postgres' });
    await admin.query('CREATE DATABASE aimos_retire_fixture');
    await admin.query('CREATE DATABASE aimos_retire_failure_fixture');
    await admin.query('CREATE DATABASE aimos_helper_fixture');
    await admin.query('CREATE DATABASE aimos_helper_failure_fixture');
    await admin.query('CREATE DATABASE aimos_unfreeze_fixture');
    await admin.query('CREATE DATABASE unrelated_fixture');
    keeper = await connected({ ...config, database: 'aimos_retire_fixture' });
    intruder = await connected({ ...config, database: 'aimos_retire_fixture' });
    const keeperPid = (await keeper.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await admin.query('ALTER DATABASE aimos_retire_fixture WITH ALLOW_CONNECTIONS false');
    const frozen = (await admin.query(`SELECT datallowconn FROM pg_database
      WHERE datname='aimos_retire_fixture'`)).rows[0];
    if (frozen?.datallowconn !== false) fail('freeze_postcondition_invalid');
    await rejectedConnect({ ...config, database: 'aimos_retire_fixture' });
    // PostgreSQL retains sessions that were admitted before the freeze.
    await keeper.query('SELECT 1');
    await intruder.query('SELECT 1');
    let sessions = (await admin.query(`SELECT pid FROM pg_stat_activity
      WHERE datname='aimos_retire_fixture' ORDER BY pid`)).rows;
    if (sessions.length !== 2) fail('existing_sessions_not_visible');
    await intruder.end(); intruder = null;
    sessions = (await admin.query(`SELECT pid FROM pg_stat_activity
      WHERE datname='aimos_retire_fixture'`)).rows;
    if (sessions.length !== 1 || sessions[0].pid !== keeperPid) {
      fail('keeper_only_census_invalid');
    }
    await keeper.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const fingerprint = (await keeper.query(`SELECT count(*)::integer AS count
      FROM pg_catalog.pg_class`)).rows[0];
    if (fingerprint.count < 1) fail('keeper_read_failed');
    await keeper.query('COMMIT');
    await keeper.end(); keeper = null;
    sessions = (await admin.query(`SELECT pid FROM pg_stat_activity
      WHERE datname='aimos_retire_fixture'`)).rows;
    if (sessions.length !== 0) fail('final_zero_sessions_invalid');
    await admin.query('DROP DATABASE aimos_retire_fixture');
    const dropped = (await admin.query(`SELECT 1 FROM pg_database
      WHERE datname='aimos_retire_fixture'`)).rowCount === 0;
    if (!dropped) fail('drop_postcondition_invalid');

    intruder = await connected({ ...config,
      database: 'aimos_retire_failure_fixture' });
    await admin.query('ALTER DATABASE aimos_retire_failure_fixture WITH ALLOW_CONNECTIONS false');
    let dropRejected = false;
    try { await admin.query('DROP DATABASE aimos_retire_failure_fixture'); }
    catch (error) { dropRejected = error.code === '55006'; }
    if (!dropRejected) fail('active_session_drop_was_not_rejected');
    await admin.query('ALTER DATABASE aimos_retire_failure_fixture WITH ALLOW_CONNECTIONS true');
    const restored = (await admin.query(`SELECT datallowconn FROM pg_database
      WHERE datname='aimos_retire_failure_fixture'`)).rows[0];
    if (restored?.datallowconn !== true) fail('re_enable_postcondition_invalid');
    const recovered = await connected({ ...config,
      database: 'aimos_retire_failure_fixture' });
    await recovered.end();
    const unrelated = await connected({ ...config, database: 'unrelated_fixture' });
    await unrelated.query('SELECT 1');
    await unrelated.end();

    const helperDb = (await admin.query(`SELECT oid::text AS oid,
      pg_get_userbyid(datdba) AS owner FROM pg_database
      WHERE datname='aimos_helper_fixture'`)).rows[0];
    let frozenCallback = false;
    await freezeVerifyAndDropDatabase({
      admin, name: 'aimos_helper_fixture',
      oid: helperDb.oid, owner: helperDb.owner,
      openKeeper: () => connected({ ...config, database: 'aimos_helper_fixture' }),
      readFingerprint: async (client) => (await client.query(
        'SELECT count(*)::integer AS count FROM pg_catalog.pg_class')).rows[0],
      compareFingerprint: (row) => {
        if (row.count < 1) fail('helper_fingerprint_invalid');
      },
      onFrozenVerified: async () => {
        frozenCallback = true;
        await rejectedConnect({ ...config, database: 'aimos_helper_fixture' });
      },
    });
    if (!frozenCallback) fail('helper_freeze_callback_missing');

    const failureDb = (await admin.query(`SELECT oid::text AS oid,
      pg_get_userbyid(datdba) AS owner FROM pg_database
      WHERE datname='aimos_helper_failure_fixture'`)).rows[0];
    let helperReenabled = false;
    const injectedAdmin = {
      query: (sql, params) => {
        if (String(sql).startsWith('DROP DATABASE aimos_helper_failure_fixture')) {
          throw new Error('fixture_injected_drop_failure');
        }
        return admin.query(sql, params);
      },
    };
    let injectedFailed = false;
    try {
      await freezeVerifyAndDropDatabase({
        admin: injectedAdmin, name: 'aimos_helper_failure_fixture',
        oid: failureDb.oid, owner: failureDb.owner,
        openKeeper: () => connected({ ...config,
          database: 'aimos_helper_failure_fixture' }),
        readFingerprint: async () => ({ count: 1 }),
        compareFingerprint: () => {},
        onReenabled: async () => { helperReenabled = true; },
      });
    } catch (error) { injectedFailed = error.message === 'fixture_injected_drop_failure'; }
    if (!injectedFailed || !helperReenabled) fail('helper_drop_failure_not_reenabled');
    const afterHelperFailure = await connected({ ...config,
      database: 'aimos_helper_failure_fixture' });
    await afterHelperFailure.end();
    const unfreezeDb = (await admin.query(`SELECT oid::text AS oid,
      pg_get_userbyid(datdba) AS owner FROM pg_database
      WHERE datname='aimos_unfreeze_fixture'`)).rows[0];
    await admin.query('ALTER DATABASE aimos_unfreeze_fixture WITH ALLOW_CONNECTIONS false');
    const unfreeze = await reenableFrozenDatabase({ admin,
      name: 'aimos_unfreeze_fixture', oid: unfreezeDb.oid,
      owner: unfreezeDb.owner });
    if (!unfreeze.changed) fail('explicit_unfreeze_did_not_change_state');
    const unfreezeAgain = await reenableFrozenDatabase({ admin,
      name: 'aimos_unfreeze_fixture', oid: unfreezeDb.oid,
      owner: unfreezeDb.owner });
    if (unfreezeAgain.changed) fail('explicit_unfreeze_not_idempotent');
    const afterUnfreeze = await connected({ ...config,
      database: 'aimos_unfreeze_fixture' });
    await afterUnfreeze.end();
    return { result: 'retirement_freeze_fixture_pass', port,
      frozen_new_login_denied: true, admitted_session_retained: true,
      keeper_only_census: true, frozen_drop_passed: true,
      failed_drop_reenabled: true, unrelated_database_untouched: true,
      production_helper_success: true,
      production_helper_drop_failure_reenabled: true,
      explicit_unfreeze_recovered_login: true };
  } finally {
    await Promise.allSettled([keeper?.end(), intruder?.end(), admin?.end()]);
    const data = secureClusterPaths(scratch).data;
    if (fs.existsSync(path.join(data, 'PG_VERSION'))) {
      try {
        execFileSync(path.join(pgBin, 'pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'],
          { stdio: ['ignore', 'ignore', 'ignore'], timeout: 60_000 });
      } catch (error) {
        process.stderr.write(`retirement_freeze_fixture_scratch_preserved:${scratch}\n`);
        throw error;
      }
    }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

main().then((result) => {
  process.stdout.write(`${JSON.stringify(result)}\n`);
}).catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
