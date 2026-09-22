#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRATCH_PORT = 9202;
const HOUSEKEEPER_CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const ARCHITECTURE_AUTHORITY = path.join(ROOT, 'architecture-authority.json');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function databaseUrl(name) {
  const url = new URL(resolveAimosDatabaseUrl([]));
  url.pathname = `/${name}`;
  return url.toString();
}

async function withPool(name, fn) {
  const pool = new Pool({
    connectionString: databaseUrl(name),
    ssl: false,
    connectionTimeoutMillis: 5_000
  });
  try {
    return await fn(pool);
  } finally {
    await pool.end().catch(() => {});
  }
}

async function canonicalFingerprint() {
  try {
    return await withPool('aimos', async (pool) => {
      const result = await pool.query(
        `SELECT m.id::text, encode(m.content_hash, 'hex') AS content_hash,
                COALESCE(encode(p.mutation_hash, 'hex'), '') AS mutation_hash
           FROM aimos_memories m
           LEFT JOIN LATERAL (
             SELECT mutation_hash
               FROM aimos_memory_provenance
              WHERE memory_id = m.id
              ORDER BY created_at DESC, provenance_id DESC
              LIMIT 1
           ) p ON true
          WHERE m.source = 'test:auth-tier-system-self'
          ORDER BY m.id`
      );
      return {
        database_exists: true,
        memories: result.rowCount,
        digest: sha256(JSON.stringify(result.rows))
      };
    });
  } catch (error) {
    if (error?.code !== '3D000') throw error;
    return {
      database_exists: false,
      memories: 0,
      digest: sha256(JSON.stringify([]))
    };
  }
}

async function scratchProof(databaseName) {
  return withPool(databaseName, async (pool) => {
    const result = await pool.query(
      `SELECT
         count(DISTINCT m.id) FILTER (WHERE m.source = 'test:auth-tier-system-self')::int AS test_memories,
         count(p.provenance_id) FILTER (WHERE m.source = 'test:auth-tier-system-self')::int AS test_provenance,
         count(DISTINCT m.id) FILTER (WHERE m.source = 'heartbeat')::int AS heartbeat_memories,
         count(p.provenance_id) FILTER (WHERE m.source = 'heartbeat')::int AS heartbeat_provenance,
         count(*) FILTER (WHERE p.provenance_id IS NULL)::int AS orphaned_memories,
         max(encode(m.content_hash, 'hex')) FILTER (WHERE m.source = 'test:auth-tier-system-self') AS content_hash,
         max(encode(p.mutation_hash, 'hex')) FILTER (WHERE m.source = 'test:auth-tier-system-self') AS mutation_hash,
         max(octet_length(p.sig)) FILTER (WHERE m.source = 'test:auth-tier-system-self') AS sig_bytes
       FROM aimos_memories m
       LEFT JOIN aimos_memory_provenance p ON p.memory_id = m.id`
    );
    return result.rows[0];
  });
}

async function originGenesisContextProof(databaseName) {
  return withPool(databaseName, async (pool) => {
    const before = (await pool.query(`SELECT
      (SELECT count(*)::int FROM aimos_master_identity) AS masters,
      (SELECT count(*)::int FROM aimos_origin_ledger_entries) AS ledger_entries,
      encode(database_context_sha256,'hex') AS database_context_sha256
      FROM ob2_read_origin_ledger_state('hom')`)).rows[0];
    if (before?.masters !== 0 || before.ledger_entries < 1
        || !/^[0-9a-f]{64}$/.test(before.database_context_sha256 || '')) {
      throw new Error(`origin_genesis_context_precondition_invalid:${JSON.stringify(before)}`);
    }

    await pool.query('BEGIN');
    try {
      await pool.query(`INSERT INTO aimos_master_identity
        (id,master_pubkey,fingerprint,keychain_service,keychain_account)
        VALUES (1,$1,$2,$3,$4)`, [
        Buffer.alloc(44, 7).toString('base64url'),
        'ab'.repeat(32),
        'test-only-origin-context',
        'test-only-origin-context',
      ]);
      const after = (await pool.query(`SELECT
        (SELECT count(*)::int FROM aimos_master_identity) AS masters,
        encode(database_context_sha256,'hex') AS database_context_sha256
        FROM ob2_read_origin_ledger_state('hom')`)).rows[0];
      if (after?.masters !== 1
          || after.database_context_sha256 !== before.database_context_sha256) {
        throw new Error(`origin_genesis_context_changed_after_master:${JSON.stringify({ before, after })}`);
      }
    } finally {
      await pool.query('ROLLBACK');
    }
    const mastersAfterRollback = Number((await pool.query(
      'SELECT count(*)::int AS count FROM aimos_master_identity',
    )).rows[0].count);
    if (mastersAfterRollback !== 0) throw new Error('origin_genesis_context_test_residue');
    return {
      no_master_genesis_verified: true,
      context_stable_after_master_arrival: true,
      database_context_sha256: before.database_context_sha256,
      ledger_entries: before.ledger_entries,
      transaction_rolled_back: true,
    };
  });
}

async function cr5SessionFingerprint(databaseName) {
  return withPool(databaseName, async (pool) => {
    const result = await pool.query(
      `SELECT m.id::text, m.key, encode(m.content_hash, 'hex') AS content_hash,
              count(e.id)::int AS terminal_count
         FROM aimos_memories m
         LEFT JOIN aimos_events e
           ON e.company_id = m.company_id
          AND e.operation = 'canonical_save_terminal'
          AND e.metadata->'stages' @> jsonb_build_array(jsonb_build_object(
            'stage','TERMINAL','status','SUCCESS','evidence',
            jsonb_build_object('memory_id',m.id)))
        WHERE m.company_id = 'hom'
          AND m.source = 'test:cr5-session-convergence'
        GROUP BY m.id, m.key, m.content_hash
        ORDER BY m.key, m.id`
    );
    return {
      rows: result.rowCount,
      digest: sha256(JSON.stringify(result.rows)),
      terminal_count: result.rows.reduce((sum, row) => sum + Number(row.terminal_count || 0), 0),
    };
  });
}

async function waitForHealth(child, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`scratch_server_exited_before_ready:${child.exitCode}`);
    try {
      const response = await fetch(`http://127.0.0.1:${SCRATCH_PORT}/health`);
      const body = await response.json();
      if (response.ok && body?.ready === true) return body;
    } catch { /* bounded readiness poll */ }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error('scratch_server_readiness_timeout');
}

async function stopExactServer(child) {
  if (child.exitCode != null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  const timeout = new Promise((resolve) => setTimeout(resolve, 5_000, 'timeout'));
  if (await Promise.race([exited, timeout]) === 'timeout' && child.exitCode == null) {
    child.kill('SIGKILL');
    await exited;
  }
}

async function bootScratchServer(databaseName) {
  const child = spawn(process.execPath, [
    'server.js',
    '--aimos-db', databaseName,
    '--aimos-port', String(SCRATCH_PORT),
  ], { cwd: ROOT, stdio: 'inherit' });
  try {
    const health = await waitForHealth(child);
    return { child, health };
  } catch (error) {
    await stopExactServer(child);
    throw error;
  }
}

async function proveCr5Restart(databaseName) {
  const before = await cr5SessionFingerprint(databaseName);
  if (before.rows !== 4 || before.terminal_count !== 4) {
    throw new Error(`cr5_restart_precondition_invalid:${JSON.stringify(before)}`);
  }
  const first = await bootScratchServer(databaseName);
  const firstPid = first.child.pid;
  await stopExactServer(first.child);
  const second = await bootScratchServer(databaseName);
  const secondPid = second.child.pid;
  const after = await cr5SessionFingerprint(databaseName);
  await stopExactServer(second.child);
  if (firstPid === secondPid || JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error(`cr5_restart_continuity_failed:${JSON.stringify({ firstPid, secondPid, before, after })}`);
  }
  return {
    first_pid: firstPid,
    second_pid: secondPid,
    pid_changed: true,
    first_health_ready: first.health.ready === true,
    second_health_ready: second.health.ready === true,
    before,
    after,
    continuity_verified: true,
  };
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: ROOT, stdio: 'inherit', ...options });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} exited ${code ?? signal}`));
    });
  });
}

function capture(command, args, marker) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'inherit'] });
    let stdout = '';
    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(text);
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code !== 0) return reject(new Error(`${command} exited ${code ?? signal}`));
      const line = stdout.split(/\r?\n/).findLast((entry) => entry.startsWith(marker));
      if (!line) return reject(new Error(`captured_result_marker_missing:${marker}`));
      try {
        resolve(JSON.parse(line.slice(marker.length)));
      } catch (error) {
        reject(new Error(`captured_result_invalid:${marker}:${error.message}`));
      }
    });
  });
}

async function probeCr6Recall(databaseName) {
  return capture(process.execPath, [
    'scripts/test/probe-cr6-canonical-recall.mjs',
    '--live-fire',
    '--aimos-db', databaseName,
    '--aimos-port', String(SCRATCH_PORT),
  ], 'CR6_PROBE_RESULT:');
}

async function proveCr6Restart(databaseName) {
  let first = null;
  let second = null;
  try {
    first = await bootScratchServer(databaseName);
    const firstPid = first.child.pid;
    const firstProbe = await probeCr6Recall(databaseName);
    await stopExactServer(first.child);
    second = await bootScratchServer(databaseName);
    const secondPid = second.child.pid;
    const secondProbe = await probeCr6Recall(databaseName);
    await stopExactServer(second.child);
    if (firstPid === secondPid
      || firstProbe.candidate_projection_sha256 !== secondProbe.candidate_projection_sha256
      || JSON.stringify(firstProbe.candidate_projection) !== JSON.stringify(secondProbe.candidate_projection)) {
      throw new Error(`cr6_restart_continuity_failed:${JSON.stringify({
        firstPid, secondPid, firstProbe, secondProbe,
      })}`);
    }
    return {
      first_pid: firstPid,
      second_pid: secondPid,
      pid_changed: true,
      first_health_ready: first.health.ready === true,
      second_health_ready: second.health.ready === true,
      candidate_projection_sha256: firstProbe.candidate_projection_sha256,
      returned_count: firstProbe.returned_count,
      security_boundaries_verified_twice: [firstProbe, secondProbe].every((probe) =>
        probe.wrong_company_status === 403
        && probe.wrong_agent_status === 403
        && probe.scope_confined_query_status === 200
        && probe.scope_confined_result_count <= 1
        && probe.scope_confined_merkle_receipt === true
        && [401, 403].includes(probe.replay_status)),
      continuity_verified: true,
    };
  } finally {
    if (second) await stopExactServer(second.child);
    if (first) await stopExactServer(first.child);
  }
}

function captureFile(file) {
  if (!fs.existsSync(file)) return { exists: false, data: null, mode: null };
  const stat = fs.statSync(file);
  return { exists: true, data: fs.readFileSync(file), mode: stat.mode & 0o777 };
}

function restoreFile(file, snapshot) {
  if (!snapshot.exists) {
    if (fs.existsSync(file)) fs.unlinkSync(file);
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, snapshot.data, { mode: snapshot.mode });
  fs.chmodSync(file, snapshot.mode);
}

async function dropScratchDatabase(databaseName) {
  if (!/^aimos_test_security_[a-z0-9_]+$/.test(databaseName)) {
    throw new Error(`refusing to drop non-test database: ${databaseName}`);
  }
  await withPool('postgres', (pool) =>
    pool.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`)
  );
}

async function main() {
  const schemaAudit = process.argv.includes('--audit-002-only') ? '002'
    : process.argv.includes('--audit-r5-only') ? 'r5'
    : process.argv.includes('--audit-r4-only') ? 'r4'
    : process.argv.includes('--audit-003-only') ? '003'
    : process.argv.includes('--audit-023-only') ? '023'
    : process.argv.includes('--audit-r3-only') || process.argv.includes('--audit-r3-projection-only') ? 'r3' : null;
  if (schemaAudit) {
    const databaseName = `aimos_test_security_aud${schemaAudit}_${Date.now()}_${randomBytes(3).toString('hex')}`;
    const pgBin = process.argv.find(arg => arg.startsWith('--pg-bin='))?.slice('--pg-bin='.length);
    if (!pgBin || !path.isAbsolute(pgBin)) throw new Error('explicit_postgres_binary_directory_required');
    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), `aimos-aud${schemaAudit}-schema-`));
    const schemaFile = path.join(temporaryDirectory, 'schema.sql');
    const pgEnvironment = name => {
      const url = new URL(databaseUrl(name));
      return { ...process.env, PGDATABASE:name, PGHOST:url.hostname, PGPORT:url.port || '5432',
        PGUSER:decodeURIComponent(url.username), PGPASSWORD:decodeURIComponent(url.password),
        PGOPTIONS:'-c pgsodium.enable_event_trigger=on' };
    };
    let created = false;
    try {
      // Schema only: no memories, identity rows, credentials or runtime state.
      await run(path.join(pgBin, 'pg_dump'), ['--schema-only', '--file', schemaFile],
        { env: pgEnvironment('aimos') });
      fs.chmodSync(schemaFile, 0o600);
      await withPool('postgres', pool => pool.query(`CREATE DATABASE "${databaseName}" TEMPLATE template0`));
      created = true;
      await run(path.join(pgBin, 'psql'), ['-X', '-v', 'ON_ERROR_STOP=1', '-f', schemaFile],
        { env: pgEnvironment(databaseName), stdio: ['ignore','ignore','inherit'] });
      const selectedTests = schemaAudit === 'r5'
        ? ['tests/security/audit-018-remediation-db.test.mjs','tests/security/audit-018-event-bytes-db.test.mjs','tests/security/audit-018-request-bytes-db.test.mjs']
        : schemaAudit === 'r4'
        ? ['tests/security/audit-009-remediation-db.test.mjs', 'tests/security/audit-004-remediation-db.test.mjs']
        : schemaAudit === 'r3'
        ? process.argv.includes('--audit-r3-projection-only')
          ? ['tests/security/audit-006-remediation-db.test.mjs','tests/security/audit-005-projection-db.test.mjs']
          : ['tests/security/audit-006-remediation-db.test.mjs',
          'tests/security/audit-014-remediation-db.test.mjs',
          'tests/security/audit-005-remediation-db.test.mjs',
          'tests/security/audit-005-projection-db.test.mjs']
        : [schemaAudit === '002' ? 'tests/security/audit-002-remediation-db.test.mjs'
          : schemaAudit === '003' ? 'tests/security/audit-003-remediation-db.test.mjs'
          : 'tests/security/audit-023-remediation-db.test.mjs'];
      for (const selectedTest of selectedTests) {
        await run(process.execPath, [
          ...(selectedTest.endsWith('audit-005-remediation-db.test.mjs') ? ['--expose-gc'] : []),
          selectedTest, '--live-fire', '--aimos-db', databaseName,
        ]);
      }
    } finally {
      try { if (created) await dropScratchDatabase(databaseName); }
      finally { fs.rmSync(temporaryDirectory, { recursive: true }); }
    }
    return;
  }
  // Database-mechanism qualification uses no Genesis, service listener,
  // identity, credential, certificate cache, or architecture-authority writes.
  if (process.argv.includes('--audit-015-only')) {
    const databaseName = `aimos_test_security_aud015_${Date.now()}_${randomBytes(3).toString('hex')}`;
    const baselineDatabaseName = `${databaseName}_baseline`;
    let created = false;
    let baselineCreated = false;
    try {
      await withPool('postgres', async (pool) => {
        await pool.query(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
      });
      created = true;
      await withPool('postgres', pool => pool.query(`CREATE DATABASE "${baselineDatabaseName}" TEMPLATE template0`));
      baselineCreated = true;
      await run(process.execPath, [
        'tests/security/audit-015-remediation-db.test.mjs', '--live-fire', '--aimos-db', databaseName,
        '--baseline-db', baselineDatabaseName,
      ]);
    } finally {
      try { if (baselineCreated) await dropScratchDatabase(baselineDatabaseName); }
      finally { if (created) await dropScratchDatabase(databaseName); }
    }
    return;
  }
  const runId = `${Date.now()}_${randomBytes(3).toString('hex')}`;
  const databaseName = `aimos_test_security_${runId}`;
  const keepScratch = process.argv.includes('--keep-scratch-db');
  const canonicalBefore = await canonicalFingerprint();
  const certCacheBefore = captureFile(HOUSEKEEPER_CERT_CACHE);
  const authorityBefore = captureFile(ARCHITECTURE_AUTHORITY);
  let scratchCreated = false;

  try {
    scratchCreated = true;
    await run(process.execPath, [
      'scripts/genesis-install.mjs',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    const originGenesisContext = await originGenesisContextProof(databaseName);
    await run(process.execPath, [
      'tests/security/auth-tier-system-self.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/native-persistence-atomicity.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/canonical-save-owner-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/cr5-session-convergence-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/cr7-r2-database-local-closure-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/event-ledger-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/native-tool-action-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/cognitive-weight-baseline-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/cognitive-weight-chain-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/cognitive-weight-chain-bidirectional-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'tests/security/hebbian-consensus-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);
    await run(process.execPath, [
      'scripts/test/run-heartbeat-once.mjs',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT)
    ]);

    const cr5RestartProof = await proveCr5Restart(databaseName);
    const cr6RestartProof = await proveCr6Restart(databaseName);

    const proof = await scratchProof(databaseName);
    if (Number(proof.test_memories) !== 1 || Number(proof.test_provenance) !== 2) {
      throw new Error(`unexpected live-fire proof counts: ${JSON.stringify(proof)}`);
    }
    if (Number(proof.orphaned_memories) !== 0) {
      throw new Error(`scratch database contains ${proof.orphaned_memories} orphaned memories`);
    }
    if (Number(proof.heartbeat_memories) !== 1 || Number(proof.heartbeat_provenance) !== 2) {
      throw new Error(`heartbeat provenance contract failed: ${JSON.stringify(proof)}`);
    }
    if (!proof.content_hash || !proof.mutation_hash || Number(proof.sig_bytes) !== 64) {
      throw new Error(`scratch proof fields incomplete: ${JSON.stringify(proof)}`);
    }

    const canonicalAfter = await canonicalFingerprint();
    if (JSON.stringify(canonicalBefore) !== JSON.stringify(canonicalAfter)) {
      throw new Error('canonical AIMOS fingerprint changed during isolated security test');
    }

    console.log(JSON.stringify({
      database_name: databaseName,
      port: SCRATCH_PORT,
      canonical_before: canonicalBefore,
      canonical_after: canonicalAfter,
      canonical_untouched: true,
      scratch_proof: proof,
      cr5_restart_proof: cr5RestartProof,
      cr6_restart_proof: cr6RestartProof,
      origin_genesis_context: originGenesisContext,
      scratch_retained: keepScratch
    }, null, 2));
  } finally {
    // Genesis legitimately materializes machine-local authority and a
    // housekeeper certificate cache. A disposable test must restore both byte
    // for byte so its identity epoch cannot leak into canonical operation.
    restoreFile(HOUSEKEEPER_CERT_CACHE, certCacheBefore);
    restoreFile(ARCHITECTURE_AUTHORITY, authorityBefore);
    if (scratchCreated && !keepScratch) {
      await dropScratchDatabase(databaseName);
    }
  }
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
