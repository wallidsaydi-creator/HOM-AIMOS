#!/usr/bin/env node

// Disposable-Genesis production custody runner for MutMem V2-S5.
//
// It never operates on the canonical database. It installs one isolated
// aimos_test_security_mutmem_v2_s5_* brain, verifies the immutable public
// corpus, appends one signed source-custody receipt inside the scratch brain,
// proves the canonical brain unchanged, restores mutable identity caches, and
// retains the scratch brain for the explicit master-signed purge ceremony.

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRATCH_PORT = 9202;
const CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const AUTHORITY = path.join(ROOT, 'architecture-authority.json');
const DEFAULT_CORPUS = path.join(ROOT, 'verifiers/mutmem-conformance/v1');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function runId() {
  const stamp = new Date().toISOString().replaceAll(/[-:TZ.]/g, '').slice(0, 14);
  return `${stamp}_${randomBytes(3).toString('hex')}`;
}

function databaseUrl(name) {
  const url = new URL(resolveAimosDatabaseUrl([]));
  url.pathname = `/${name}`;
  return url.toString();
}

async function withPool(name, fn) {
  const local = new Pool({ connectionString: databaseUrl(name), ssl: false, connectionTimeoutMillis: 5_000 });
  try {
    return await fn(local);
  } finally {
    await local.end().catch(() => {});
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

function runToLog(command, args, logFile) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const stream = fs.createWriteStream(logFile, { flags: 'a', mode: 0o600 });
    const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    for (const [source, destination] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
      source.on('data', (chunk) => { stream.write(chunk); destination.write(chunk); });
    }
    child.once('error', (error) => { stream.end(); reject(error); });
    child.once('exit', (code, signal) => {
      stream.end();
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args[0] || ''} exited ${code ?? signal}`));
    });
  });
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function canonicalFingerprint() {
  return withPool('aimos', async (client) => {
    const result = await client.query(
      `SELECT m.id::text, encode(m.content_hash,'hex') AS content_hash,
              COALESCE(encode(p.mutation_hash,'hex'),'') AS terminal_mutation_hash
         FROM aimos_memories m
         LEFT JOIN LATERAL (
           SELECT mutation_hash FROM aimos_memory_provenance
            WHERE memory_id=m.id ORDER BY created_at DESC,provenance_id DESC LIMIT 1
         ) p ON true
        ORDER BY m.id`,
    );
    return { memory_count: result.rowCount, digest_sha256: sha256(JSON.stringify(result.rows)) };
  });
}

function argument(name, fallback = null) {
  const prefix = `--${name}=`;
  const value = process.argv.find((entry) => entry.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

async function main() {
  const corpusDir = path.resolve(argument('corpus', DEFAULT_CORPUS));
  const manifest = path.join(corpusDir, 'manifest.json');
  const parityReport = path.join(corpusDir, 'verification-report.json');
  if (!fs.existsSync(manifest) || !fs.existsSync(parityReport)) {
    throw new Error('mutmem_v2_s5_verified_corpus_required');
  }
  const resumeRunId = argument('resume-run');
  const id = resumeRunId || runId();
  const databaseName = `aimos_test_security_mutmem_v2_s5_${id}`;
  const runDir = path.join(ROOT, 'eval/public-results', id, 'mutmem-v2-s5');
  const evidenceFile = path.join(runDir, 'source-custody.json');
  const statusFile = path.join(runDir, 'run-status.json');
  let interruptedAttempt = null;
  if (resumeRunId) {
    if (!fs.existsSync(statusFile) || fs.existsSync(evidenceFile)) {
      throw new Error('mutmem_v2_s5_resume_boundary_invalid');
    }
    const prior = JSON.parse(fs.readFileSync(statusFile, 'utf8'));
    if (prior.run_id !== id || prior.database_name !== databaseName
        || prior.state !== 'failed' || prior.scratch_retained_for_signed_purge !== true) {
      throw new Error('mutmem_v2_s5_resume_status_invalid');
    }
    await withPool(databaseName, (client) => client.query('SELECT 1'));
    interruptedAttempt = {
      state: prior.state,
      phase: prior.phase,
      error: prior.error,
      evidence_appended: false,
      disposition: 'schema_and_pre_enrollment_master_assumptions_repaired_before_source_custody_append',
      retained_log_sha256: fs.existsSync(path.join(runDir, 'logs/source-custody.log'))
        ? sha256(fs.readFileSync(path.join(runDir, 'logs/source-custody.log')))
        : null,
    };
  }
  const canonicalBefore = await canonicalFingerprint();
  const certBefore = snapshotFile(CERT_CACHE);
  const authorityBefore = snapshotFile(AUTHORITY);
  writeJson(statusFile, {
    schema: 'hom.aimos.mutmem-v2-s5-run-status/v1',
    run_id: id,
    database_name: databaseName,
    state: 'running',
    phase: 'genesis',
    scratch_retained_for_signed_purge: true,
  });
  try {
    if (!resumeRunId) {
      await runToLog(process.execPath, [
        'scripts/genesis-install.mjs',
        '--aimos-db', databaseName,
        '--aimos-port', String(SCRATCH_PORT),
      ], path.join(runDir, 'logs/genesis.log'));
    }
    writeJson(statusFile, {
      schema: 'hom.aimos.mutmem-v2-s5-run-status/v1', run_id: id,
      database_name: databaseName, state: 'running', phase: 'source-custody',
      scratch_retained_for_signed_purge: true,
    });
    await runToLog(process.execPath, [
      'tests/security/mutmem-v2-s5-production-corpus-db.test.mjs',
      '--live-fire',
      '--aimos-db', databaseName,
      '--aimos-port', String(SCRATCH_PORT),
      '--manifest', manifest,
      '--evidence-file', evidenceFile,
    ], path.join(runDir, 'logs/source-custody.log'));

    const canonicalAfter = await canonicalFingerprint();
    if (JSON.stringify(canonicalBefore) !== JSON.stringify(canonicalAfter)) {
      throw new Error('mutmem_v2_s5_canonical_brain_changed');
    }
    const sourceCustody = JSON.parse(fs.readFileSync(evidenceFile, 'utf8'));
    const result = {
      schema: 'hom.aimos.mutmem-v2-s5-production-result/v1',
      run_id: id,
      database_name: databaseName,
      corpus_directory: path.relative(ROOT, corpusDir),
      corpus_manifest_sha256: sha256(fs.readFileSync(manifest)),
      parity_report_sha256: sha256(fs.readFileSync(parityReport)),
      corpus_root: sourceCustody.corpus_root,
      intended_n: sourceCustody.intended_n,
      observed_n: sourceCustody.observed_n,
      required_class_count: sourceCustody.required_class_count,
      interrupted_attempt: interruptedAttempt,
      source_custody_evidence_root_sha256: sourceCustody.evidence_root_sha256,
      canonical_before: canonicalBefore,
      canonical_after: canonicalAfter,
      canonical_untouched: true,
      scratch_retained_for_signed_purge: true,
      purge_receipt: null,
      terminal_state: 'AWAITING_MASTER_SIGNED_PURGE',
    };
    writeJson(path.join(runDir, 'production-result.json'), result);
    writeJson(statusFile, {
      schema: 'hom.aimos.mutmem-v2-s5-run-status/v1', run_id: id,
      database_name: databaseName, state: 'awaiting_purge', phase: 'awaiting-master-signed-purge',
      error: null, scratch_retained_for_signed_purge: true,
    });
    process.stdout.write(`${JSON.stringify({
      success: true,
      run_id: id,
      database_name: databaseName,
      run_directory: runDir,
      corpus_root: result.corpus_root,
      intended_n: result.intended_n,
      observed_n: result.observed_n,
      canonical_untouched: true,
      scratch_retained_for_signed_purge: true,
      next: `node scripts/ceremony/purge-brain.mjs --aimos-db ${databaseName} --receipt-dir ${path.join(runDir, 'purge')} --keychain-account=homaimoswcodex --live`,
    }, null, 2)}\n`);
  } catch (error) {
    writeJson(statusFile, {
      schema: 'hom.aimos.mutmem-v2-s5-run-status/v1', run_id: id,
      database_name: databaseName, state: 'failed', phase: 'failed',
      error: String(error?.message || error), scratch_retained_for_signed_purge: true,
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
