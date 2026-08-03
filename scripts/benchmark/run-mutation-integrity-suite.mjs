#!/usr/bin/env node

// Publication execution for MutMem's central authorization construction.
// It provisions one disposable AIMOS brain, runs only the native cognitive
// writer/verifier path, retains the brain for the later signed whole-brain
// purge ceremony, and proves the canonical brain was unchanged.

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
const CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const AUTHORITY = path.join(ROOT, 'architecture-authority.json');

function utcRunId() {
  const stamp = new Date().toISOString().replaceAll(/[-:TZ.]/g, '').slice(0, 14);
  return `${stamp}_${randomBytes(3).toString('hex')}`;
}

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
    connectionTimeoutMillis: 5_000,
  });
  try {
    return await fn(pool);
  } finally {
    await pool.end().catch(() => {});
  }
}

function snapshotFile(file) {
  if (!fs.existsSync(file)) return { exists: false, bytes: null, mode: null };
  const stat = fs.statSync(file);
  return { exists: true, bytes: fs.readFileSync(file), mode: stat.mode & 0o777 };
}

function restoreFile(file, snapshot) {
  if (!snapshot.exists) {
    if (fs.existsSync(file)) fs.unlinkSync(file);
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, snapshot.bytes, { mode: snapshot.mode });
  fs.chmodSync(file, snapshot.mode);
}

async function canonicalFingerprint() {
  return withPool('aimos', async (pool) => {
    const result = await pool.query(
      `SELECT m.id::text,encode(m.content_hash,'hex') AS content_hash,
              encode(p.mutation_hash,'hex') AS terminal_mutation_hash
         FROM aimos_memories m
         LEFT JOIN LATERAL (
           SELECT mutation_hash
             FROM aimos_memory_provenance
            WHERE memory_id=m.id
            ORDER BY created_at DESC,provenance_id DESC LIMIT 1
         ) p ON true
        ORDER BY m.id`
    );
    return {
      memory_count: result.rowCount,
      digest_sha256: sha256(JSON.stringify(result.rows)),
    };
  });
}

function runToLog(command, args, logFile) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const stream = fs.createWriteStream(logFile, { flags: 'a', mode: 0o600 });
    const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    for (const [source, destination] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
      source.on('data', (chunk) => {
        stream.write(chunk);
        destination.write(chunk);
      });
    }
    child.once('error', (error) => {
      stream.end();
      reject(error);
    });
    child.once('exit', (code, signal) => {
      stream.end();
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args[0] || ''} exited ${code ?? signal}`));
    });
  });
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function artifactManifest(runDir) {
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && entry.name !== 'artifact-hashes.json') {
        const relative = path.relative(runDir, absolute);
        const bytes = fs.readFileSync(absolute);
        files.push({
          path: relative,
          bytes: bytes.length,
          sha256: sha256(bytes),
        });
      }
    }
  };
  walk(runDir);
  files.sort((a, b) => a.path.localeCompare(b.path));
  const body = {
    schema: 'hom.aimos.mutation-integrity-artifact-manifest/v1',
    files,
  };
  return { ...body, manifest_sha256: sha256(JSON.stringify(body)) };
}

async function main() {
  const runId = utcRunId();
  const databaseName = `aimos_test_security_mutation_${runId}`;
  const runDir = path.join(ROOT, 'eval', 'public-results', runId, 'mutation-integrity');
  const logDir = path.join(runDir, 'logs');
  const evidenceFile = path.join(runDir, 'mutation-integrity-evidence.json');
  const statusFile = path.join(runDir, 'run-status.json');
  const canonicalBefore = await canonicalFingerprint();
  const certBefore = snapshotFile(CERT_CACHE);
  const authorityBefore = snapshotFile(AUTHORITY);
  writeJson(statusFile, {
    schema: 'hom.aimos.mutation-integrity-run-status/v1',
    run_id: runId,
    database_name: databaseName,
    state: 'running',
    phase: 'genesis',
    scratch_retained_for_signed_purge: true,
  });
  try {
    await runToLog(process.execPath, [
      'scripts/genesis-install.mjs',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT),
    ], path.join(logDir, 'genesis.log'));
    writeJson(statusFile, {
      schema: 'hom.aimos.mutation-integrity-run-status/v1',
      run_id: runId,
      database_name: databaseName,
      state: 'running',
      phase: 'native-live-suite',
      scratch_retained_for_signed_purge: true,
    });
    for (const test of [
      'tests/security/cognitive-weight-baseline-db.test.mjs',
      'tests/security/cognitive-weight-chain-db.test.mjs',
    ]) {
      await runToLog(process.execPath, [
        test,
        '--live-fire',
        '--aimos-db', databaseName,
        '--aimos-port', String(SCRATCH_PORT),
      ], path.join(logDir, `${path.basename(test, '.test.mjs')}.log`));
    }
    await runToLog(process.execPath, [
      'tests/security/cognitive-weight-chain-bidirectional-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT),
      '--evidence-file', evidenceFile,
    ], path.join(logDir, 'cognitive-weight-chain-bidirectional-db.log'));

    const scratch = await withPool(databaseName, async (pool) => {
      await pool.query('BEGIN');
      await pool.query("SELECT set_config('app.current_client_id','hom',true)");
      await pool.query("SELECT set_config('app.current_agent_id','housekeeper',true)");
      const result = await pool.query(
        `SELECT
           (SELECT count(*)::int FROM aimos_memories WHERE company_id='hom') AS memories,
           (SELECT count(*)::int FROM aimos_memory_provenance WHERE event_type='REWEIGHT') AS reweight_provenance,
           (SELECT count(*)::int FROM aimos_cognitive_weight_projections) AS projections,
           (SELECT count(*)::int FROM memory_valence_ledger) AS valence_events,
           (SELECT count(*)::int FROM public.verify_all_cognitive_weight_chains() WHERE NOT ok) AS invalid_chains`
      );
      await pool.query('COMMIT');
      return result.rows[0];
    });
    if (Number(scratch.invalid_chains) !== 0) {
      throw new Error(`mutation_integrity_invalid_terminal_chains:${scratch.invalid_chains}`);
    }
    const canonicalAfter = await canonicalFingerprint();
    if (JSON.stringify(canonicalBefore) !== JSON.stringify(canonicalAfter)) {
      throw new Error('mutation_integrity_canonical_brain_changed');
    }
    writeJson(path.join(runDir, 'isolation-proof.json'), {
      schema: 'hom.aimos.mutation-integrity-isolation-proof/v1',
      run_id: runId,
      scratch_database: databaseName,
      canonical_before: canonicalBefore,
      canonical_after: canonicalAfter,
      canonical_untouched: true,
      scratch_inventory: scratch,
    });
    writeJson(statusFile, {
      schema: 'hom.aimos.mutation-integrity-run-status/v1',
      run_id: runId,
      database_name: databaseName,
      state: 'complete',
      phase: 'complete',
      error: null,
      scratch_retained_for_signed_purge: true,
    });
    writeJson(path.join(runDir, 'artifact-hashes.json'), artifactManifest(runDir));
    process.stdout.write(`${JSON.stringify({
      success: true,
      run_id: runId,
      database_name: databaseName,
      run_directory: runDir,
      evidence_file: evidenceFile,
      scratch_retained_for_signed_purge: true,
      canonical_untouched: true,
    }, null, 2)}\n`);
  } catch (error) {
    writeJson(statusFile, {
      schema: 'hom.aimos.mutation-integrity-run-status/v1',
      run_id: runId,
      database_name: databaseName,
      state: 'failed',
      phase: 'failed',
      error: String(error?.message || error),
      scratch_retained_for_signed_purge: true,
    });
    throw error;
  } finally {
    restoreFile(CERT_CACHE, certBefore);
    restoreFile(AUTHORITY, authorityBefore);
  }
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
