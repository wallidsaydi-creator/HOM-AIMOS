#!/usr/bin/env node
// scripts/bootstrap-db.mjs
// DB + Role bootstrap for a *fresh* HOM-AIMOS install.

import { randomBytes } from 'node:crypto';
// IMPORTANT: This is HOM-AIMOS (not Oracle). On a completely fresh deployment
// there is NO database yet. This script is what creates it.
//
// What it does:
//   1. Resolves the local AIMOS target from --aimos-db (default: aimos).
//   2. Connects to the maintenance DB on the *same host*:
//        - Try /postgres first
//        - Fall back to /template1
//      (We deliberately do NOT connect to /aimos because it does not exist.)
//   3. CREATE DATABASE <aimos-db> (idempotent).
//   4. CREATE/rotate agent_runtime with a keychain-held random password.
//      This role is what the application uses at runtime (see db/connection.js).
//   5. The installer (genesis-install.mjs) calls this for Phase A2.
//
// Hosted role creation is deliberately out of this local bootstrap boundary;
// no SQL containing the generated secret is ever printed.
//
// Usage (standalone): node scripts/bootstrap-db.mjs [--aimos-db aimos]

import pg from 'pg';
import {
  AIMOS_RUNTIME_CREDENTIAL_SERVICE,
  AIMOS_RUNTIME_ROLE,
  resolveAimosDatabaseName,
  resolveAimosDatabaseUrl
} from '../services/core/runtime-config.js';
import {
  readCredentialSync,
  storeCredentialSync
} from '../services/security/credential-store.js';

const { Pool } = pg;
const ROLE_NAME = AIMOS_RUNTIME_ROLE;

function parseUrl(url) {
  try { return new URL(url); } catch { return null; }
}

function scrubPassword(urlStr) {
  const u = parseUrl(urlStr);
  if (!u) return String(urlStr).replace(/:\/\/([^:]+):[^@]+@/, '://$1:***@');
  if (u.password) u.password = '***';
  return u.toString();
}

function withMaintenanceDb(origUrl, newDb) {
  const u = parseUrl(origUrl);
  if (!u) return null;
  u.pathname = `/${newDb}`;
  return u.toString();
}

function poolConfig(url) {
  const u = parseUrl(url);
  const sslmode = u?.searchParams?.get('sslmode') || '';
  const useSsl = ['require', 'verify-ca', 'verify-full', 'prefer'].includes(sslmode);
  return {
    connectionString: url,
    ssl: useSsl ? { rejectUnauthorized: ['verify-ca', 'verify-full'].includes(sslmode) } : false,
    connectionTimeoutMillis: 5000
  };
}

async function withPool(url, fn) {
  const pool = new Pool(poolConfig(url));
  try {
    return await fn(pool);
  } finally {
    await pool.end().catch(() => {});
  }
}

async function ensureDatabase(pool, dbName) {
  try {
    await pool.query(`CREATE DATABASE "${dbName}"`);
    return { created: true };
  } catch (err) {
    if (err.code === '42P04') return { existed: true };
    throw err;
  }
}

function sqlLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

async function ensureRole(pool, password) {
  const found = await pool.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [ROLE_NAME]);
  const sql = found.rowCount > 0
    ? `ALTER ROLE ${ROLE_NAME} WITH LOGIN PASSWORD ${sqlLiteral(password)}`
    : `CREATE ROLE ${ROLE_NAME} WITH LOGIN PASSWORD ${sqlLiteral(password)}`;
  try {
    await pool.query(sql);
    return found.rowCount > 0 ? { existed: true, rotated: true } : { created: true };
  } catch (err) {
    throw err;
  }
}

function validateBootstrapDatabaseName(value) {
  const name = String(value || '');
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(name) || ['oracle', 'aimos_dev', 'postgres', 'template1'].includes(name)) {
    throw new Error(`Invalid or protected bootstrap database name: ${name}`);
  }
  return name;
}

async function assertBootstrapAuthority(pool, dbName) {
  const result = await pool.query(
    `SELECT current_user,
            role.rolsuper,
            role.rolcreatedb,
            role.rolcreaterole,
            EXISTS (SELECT 1 FROM pg_database WHERE datname = $1) AS database_exists,
            EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2) AS runtime_role_exists
       FROM pg_roles role
      WHERE role.rolname = current_user`,
    [dbName, ROLE_NAME],
  );
  const authority = result.rows[0];
  if (!authority) throw new Error('bootstrap_current_role_unavailable');
  if (!authority.database_exists && !authority.rolsuper && !authority.rolcreatedb) {
    throw new Error('bootstrap_createdb_authority_required');
  }
  if (!authority.rolsuper && (!authority.rolcreaterole || authority.runtime_role_exists)) {
    throw new Error('bootstrap_runtime_role_authority_required');
  }
  return authority;
}

/**
 * Core DB + role bootstrap logic. Can be called from CLI or from genesis-install.mjs
 * Returns summary object.
 */
export async function bootstrapDatabase({ databaseUrl, databaseName } = {}) {
  const dbName = validateBootstrapDatabaseName(databaseName || resolveAimosDatabaseName());
  const url = databaseUrl || resolveAimosDatabaseUrl();
  const targetName = parseUrl(url)?.pathname?.slice(1);
  if (targetName !== dbName) {
    throw new Error(`Bootstrap target mismatch: URL names ${targetName}, expected ${dbName}`);
  }

  const postgresUrl = withMaintenanceDb(url, 'postgres');
  const templateUrl = withMaintenanceDb(url, 'template1');

  if (!postgresUrl && !templateUrl) {
    throw new Error('Invalid AIMOS database target');
  }

  // Only print the banner when not invoked from the orchestrator (which prints its own)
  console.log('\n=== Phase A2 — DB + role bootstrap ===');
  console.log('Aimos DB bootstrap');
  console.log('==================');
  console.log(`Target DB:     ${dbName}`);
  console.log(`Runtime role:  ${ROLE_NAME} (credential: versioned Keychain)`);
  console.log(`Maintenance:   ${scrubPassword(postgresUrl || templateUrl)}`);
  console.log('');

  let result;
  const runAgainst = (maintenanceUrl) => withPool(maintenanceUrl, async (maintenancePool) => {
    await assertBootstrapAuthority(maintenancePool, dbName);
    let runtimeCredential = readCredentialSync(AIMOS_RUNTIME_CREDENTIAL_SERVICE);
    if (!runtimeCredential) {
      runtimeCredential = storeCredentialSync(
        AIMOS_RUNTIME_CREDENTIAL_SERVICE,
        randomBytes(32).toString('base64url'),
      );
    }
    // Establish the restricted role before creating the database. Authority
    // and connectivity were proven before the Keychain pointer moved.
    const role = await ensureRole(maintenancePool, runtimeCredential.value);
    const db = await ensureDatabase(maintenancePool, dbName);
    return { db, role, runtimeCredential };
  });
  try {
    result = await runAgainst(postgresUrl);
  } catch (err) {
    if (err.code === '3D000' || /database "postgres" does not exist/i.test(err.message)) {
      console.warn('[WARN] maintenance DB "postgres" not found; retrying against "template1"...');
      try {
        result = await runAgainst(templateUrl);
      } catch (err2) {
        console.error(`[ERR] could not connect to a maintenance DB: ${err2.message}`);
        console.error('      Check the local PostgreSQL service and bootstrap authority.');
        throw err2;
      }
    } else if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
      console.error(`[ERR] could not reach Postgres: ${err.message}`);
      console.error('      Is the local PostgreSQL service running?');
      throw err;
    } else if (err.code === '28P01' || /authentication failed|password authentication/i.test(err.message)) {
      console.error(`[ERR] authentication failed: ${err.message}`);
      console.error('      The local OS user could not authenticate to PostgreSQL.');
      throw err;
    } else {
      console.error(`[ERR] ${err.code || ''} ${err.message}`);
      throw err;
    }
  }

  const { db, role, runtimeCredential } = result;

  if (db.created) console.log(`[OK]  database "${dbName}" created`);
  else if (db.existed) console.log(`[OK]  database "${dbName}" already exists (skip)`);

  if (role.created) console.log(`[OK]  role "${ROLE_NAME}" created`);
  else if (role.existed) console.log(`[OK]  role "${ROLE_NAME}" already exists (credential synchronized)`);

  console.log('');
  console.log('[Phase A2 complete] DB and role are ready for migrations.');

  return {
    db,
    role,
    databaseUrl: url,
    databaseName: dbName,
    runtimeCredential: {
      slot: runtimeCredential.slot,
      hash: runtimeCredential.hash,
    },
  };
}

/**
 * Re-assert the Keychain-generated runtime credential after historical schema
 * migrations. Migration 029 is immutable and, on a fresh install, temporarily
 * applies its original public bootstrap password. No runtime process may start
 * in that interval; Genesis immediately restores the cryptographic Keychain
 * value here before loading db/connection.js.
 */
export async function synchronizeRuntimeRoleCredential({ databaseUrl, databaseName } = {}) {
  const dbName = validateBootstrapDatabaseName(databaseName || resolveAimosDatabaseName());
  const url = databaseUrl || resolveAimosDatabaseUrl();
  const runtimeCredential = readCredentialSync(AIMOS_RUNTIME_CREDENTIAL_SERVICE);
  if (!runtimeCredential) throw new Error('runtime role credential missing from Keychain');

  const postgresUrl = withMaintenanceDb(url, 'postgres');
  const templateUrl = withMaintenanceDb(url, 'template1');
  let role;
  try {
    role = await withPool(postgresUrl, (maintenancePool) => ensureRole(maintenancePool, runtimeCredential.value));
  } catch (error) {
    if (error.code !== '3D000' && !/database "postgres" does not exist/i.test(error.message)) throw error;
    role = await withPool(templateUrl, (maintenancePool) => ensureRole(maintenancePool, runtimeCredential.value));
  }
  return {
    databaseName: dbName,
    roleName: ROLE_NAME,
    credentialSlot: runtimeCredential.slot,
    synchronized: role.created === true || role.rotated === true,
  };
}

// CLI entrypoint (for direct `node scripts/bootstrap-db.mjs`)
async function main() {
  try {
    await bootstrapDatabase();
    console.log('');
    console.log('Next: create the schema');
    console.log('  npm run migrate');
    console.log('Then: enroll the master identity');
    console.log('  npm run identity:enroll-master');
  } catch (e) {
    console.error('[FATAL]', e?.message || e);
    process.exit(1);
  }
}

// Auto-run only when executed directly as the entry script
const isDirect = import.meta.url === `file://${process.argv[1]}` ||
                 (process.argv[1] && process.argv[1].endsWith('bootstrap-db.mjs'));

if (isDirect) {
  main();
}
