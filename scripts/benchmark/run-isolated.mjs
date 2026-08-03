#!/usr/bin/env node

// Canonical public benchmark lifecycle.
//
// One disposable AIMOS brain is genesis-installed, public sessions are replayed
// one turn at a time through signed native routes, one signed recall is issued
// per selected question, GPT-5.4 generates one answer, and GPT-5.6 Terra judges
// that answer. The historical whole-session blob harness remains available only
// behind the explicit --historical-v1 diagnostic flag.
//
// The user's canonical brain is fingerprinted before/after but never selected
// by any benchmark child process. Cleanup drops the entire scratch brain, which
// is the only deletion boundary used by this runner.

import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  createReadStream,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  lstatSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { verifyWholeBrainPurgeReceipt } from '../../services/security/whole-brain-purge.js';
import {
  LOCOMO_OFFICIAL_PROTOCOL,
  LOCOMO_OFFICIAL_TOP_K,
} from '../../eval/locomo-official-protocol.mjs';
import {
  POISONEDRAG_GENERATOR_MODEL,
  POISONEDRAG_MAX_ATTEMPTS,
  POISONEDRAG_PROTOCOL_ID,
} from '../../eval/poisonedrag/harness.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ORACLE_DATASET = path.join(ROOT, 'eval', 'data', 'official-longmemeval-oracle.json');
const LOCOMO_DATASET = path.join(ROOT, 'eval', 'data', 'official-locomo10.json');
const HOUSEKEEPER_KEY = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key');
const HOUSEKEEPER_CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const ARCHITECTURE_AUTHORITY = path.join(ROOT, 'architecture-authority.json');
const CANONICAL_BLIND_PROTOCOL = 'canonical-blind-v1';
const POISONEDRAG_SOURCE_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const POISONEDRAG_PUBLIC_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'n100-public-target-lock.json');
const POISONEDRAG_PRIVATE_ROOT = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');

export function parseArgs(argv) {
  const args = {
    longmemevalFile: ORACLE_DATASET,
    longmemevalFileExplicit: false,
    sample: 10,
    full: false,
    smoke: false,
    lifecycleProof: false,
    historicalV1: false,
    gate: null,
    benchmark: 'both',
    port: 9200,
    limit: 20,
    limitExplicit: false,
    protocol: CANONICAL_BLIND_PROTOCOL,
    cognitive: false,
    generatorProvider: 'codex',
    generatorModel: 'gpt-5.4',
    judgeProvider: 'codex',
    judgeModel: 'gpt-5.6-terra',
    modelOverrideExplicit: false,
    keepScratchDb: false,
    resumeRun: null,
    outputRoot: path.join(ROOT, 'eval', 'public-results')
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--longmemeval-file' && next) {
      args.longmemevalFile = path.resolve(next);
      args.longmemevalFileExplicit = true;
      i += 1;
    }
    else if (arg === '--sample' && next) { args.sample = Number(next); i += 1; }
    else if (arg === '--port' && next) { args.port = Number(next); i += 1; }
    else if (arg === '--limit' && next) { args.limit = Number(next); args.limitExplicit = true; i += 1; }
    else if (arg === '--protocol' && next) { args.protocol = String(next).trim().toLowerCase(); i += 1; }
    else if (arg === '--benchmark' && next) { args.benchmark = String(next).toLowerCase(); i += 1; }
    else if (arg === '--gate' && next) { args.gate = String(next).toLowerCase(); i += 1; }
    else if (arg === '--generator-model' && next) { args.generatorModel = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--generator-provider' && next) { args.generatorProvider = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--judge-model' && next) { args.judgeModel = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--judge-provider' && next) { args.judgeProvider = next; args.modelOverrideExplicit = true; i += 1; }
    else if (arg === '--output-root' && next) { args.outputRoot = path.resolve(next); i += 1; }
    else if (arg === '--resume-run' && next) { args.resumeRun = String(next).trim().toLowerCase(); i += 1; }
    else if (arg === '--full') args.full = true;
    else if (arg === '--smoke') args.smoke = true;
    else if (arg === '--lifecycle-proof') args.lifecycleProof = true;
    else if (arg === '--historical-v1') args.historicalV1 = true;
    else if (arg === '--cognitive') args.cognitive = true;
    else if (arg === '--keep-scratch-db') args.keepScratchDb = true;
  }
  if (!Number.isInteger(args.sample) || args.sample < 1) throw new Error('--sample must be a positive integer');
  if (![CANONICAL_BLIND_PROTOCOL, LOCOMO_OFFICIAL_PROTOCOL, POISONEDRAG_PROTOCOL_ID].includes(args.protocol)) {
    throw new Error('--protocol must be canonical-blind-v1|locomo-upstream-qa-v1|poisonedrag-n100-v1');
  }
  if (args.protocol === LOCOMO_OFFICIAL_PROTOCOL) {
    if (args.benchmark !== 'locomo') throw new Error('locomo-upstream-qa-v1 requires --benchmark locomo');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive) {
      throw new Error('locomo-upstream-qa-v1 conflicts with historical/lifecycle/cognitive modes');
    }
    if (args.limitExplicit && args.limit !== LOCOMO_OFFICIAL_TOP_K) {
      throw new Error(`locomo-upstream-qa-v1 requires --limit ${LOCOMO_OFFICIAL_TOP_K}`);
    }
    args.limit = LOCOMO_OFFICIAL_TOP_K;
  }
  if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
    if (args.benchmark !== 'poisonedrag') throw new Error('poisonedrag-n100-v1 requires --benchmark poisonedrag');
    if (args.historicalV1 || args.lifecycleProof || args.cognitive || args.gate) {
      throw new Error('poisonedrag-n100-v1 conflicts with historical/lifecycle/cognitive/gate modes');
    }
    if (args.limitExplicit && args.limit !== 5) throw new Error('poisonedrag-n100-v1 requires --limit 5');
    if (args.modelOverrideExplicit) throw new Error('poisonedrag model roles are fixed to GPT-5.5 and GPT-5.6 Terra');
    if (!args.full && args.sample > 100) throw new Error('poisonedrag sample cannot exceed 100 targets');
    args.limit = 5;
  }
  if (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 200) throw new Error('--limit must be 1..200');
  if (!Number.isInteger(args.port) || args.port < 1024 || args.port > 65535) throw new Error('--port must be 1024..65535');
  if (args.resumeRun && !/^\d{14}_[0-9a-f]{6}$/.test(args.resumeRun)) throw new Error('--resume-run must be an existing canonical run id');
  if ([9000, 9001, 9100].includes(args.port)) throw new Error(`port ${args.port} is reserved by a live HOM service`);
  if (!['both', 'locomo', 'longmemeval', 'poisonedrag'].includes(args.benchmark)) {
    throw new Error('--benchmark must be both|locomo|longmemeval|poisonedrag');
  }
  if (args.gate && !['b4', 'b5'].includes(args.gate)) throw new Error('--gate must be b4|b5');
  if (args.gate && (args.historicalV1 || args.full || args.lifecycleProof
    || (args.protocol === CANONICAL_BLIND_PROTOCOL && args.benchmark !== 'both')
    || (args.protocol === LOCOMO_OFFICIAL_PROTOCOL && args.benchmark !== 'locomo'))) {
    throw new Error('--gate benchmark/protocol combination invalid or conflicts with --full/--lifecycle-proof');
  }
  if (args.gate) {
    args.sample = args.protocol === LOCOMO_OFFICIAL_PROTOCOL
      ? (args.gate === 'b4' ? 5 : 25)
      : (args.gate === 'b4' ? 10 : 50);
  }
  if (!args.full && args.benchmark === 'both' && args.sample < 2) throw new Error('--sample must be at least 2 with --benchmark both');
  if (args.lifecycleProof && args.historicalV1) throw new Error('--lifecycle-proof conflicts with --historical-v1');
  if (args.resumeRun && (args.lifecycleProof || args.historicalV1)) throw new Error('--resume-run supports canonical single-query runs only');
  if (args.cognitive && !args.historicalV1) throw new Error('--cognitive is historical-v1 only; canonical mode always generates and judges');
  if (!args.historicalV1 && args.longmemevalFileExplicit) {
    throw new Error('--longmemeval-file is historical-v1 only; regenerate the attested canonical corpus instead');
  }
  if (!args.historicalV1 && args.modelOverrideExplicit) {
    throw new Error('canonical model roles are fixed to GPT-5.4 and GPT-5.6 Terra');
  }
  if (args.protocol !== POISONEDRAG_PROTOCOL_ID) {
    statSync(args.longmemevalFile);
    statSync(LOCOMO_DATASET);
  }
  // --smoke overrides scope to the smallest complete canonical query run.
  if (args.smoke) { args.full = false; args.sample = 3; args.cognitive = false; }
  if (args.lifecycleProof) { args.full = false; args.sample = 3; args.cognitive = false; }
  return args;
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sha256File(file) {
  return sha256(readFileSync(file));
}

function urlForDatabase(name) {
  const url = new URL(resolveAimosDatabaseUrl([]));
  url.pathname = `/${name}`;
  return url.toString();
}

async function withPool(databaseName, fn) {
  const pool = new Pool({ connectionString: urlForDatabase(databaseName), ssl: false, connectionTimeoutMillis: 5000 });
  try { return await fn(pool); } finally { await pool.end().catch(() => {}); }
}

async function canonicalFootprint() {
  return withPool('aimos', async (pool) => {
    const rows = await pool.query(
      `SELECT id::text, key, source, encode(content_hash, 'hex') AS content_hash
         FROM aimos_memories
        WHERE key LIKE 'benchmark:%'
           OR key LIKE 'sess:bench:%'
           OR source LIKE 'benchmark_%'
           OR source LIKE 'benchmark:%'
        ORDER BY id`
    );
    const encoded = JSON.stringify(rows.rows);
    return { benchmark_rows: rows.rowCount, benchmark_fingerprint: sha256(encoded) };
  });
}

async function scratchProof(databaseName) {
  return withPool(databaseName, async (pool) => {
    const result = await pool.query(
      `SELECT
         (SELECT count(*)::int FROM schema_migrations) AS migrations,
         (SELECT count(*)::int FROM aimos_memories) AS memories,
         (SELECT count(*)::int FROM aimos_memories WHERE source = 'guide:genesis-install') AS guide_memories,
         (SELECT count(*)::int FROM aimos_memories
           WHERE key LIKE 'benchmark:%'
              OR key LIKE 'sess:bench:%'
              OR source LIKE 'benchmark_%'
              OR source LIKE 'benchmark:%') AS benchmark_memories,
         (SELECT count(*)::int FROM aimos_memories m LEFT JOIN aimos_memory_provenance p ON p.memory_id=m.id WHERE p.memory_id IS NULL) AS orphaned_memories`
    );
    const hashes = await pool.query(
      `SELECT encode(p.mutation_hash, 'hex') AS mutation_hash
         FROM aimos_memory_provenance p
         JOIN aimos_memories m ON m.id = p.memory_id
        WHERE m.key LIKE 'benchmark:%'
           OR m.key LIKE 'sess:bench:%'
           OR m.source LIKE 'benchmark_%'
           OR m.source LIKE 'benchmark:%'
        ORDER BY p.created_at, p.provenance_id`
    );
    return {
      ...result.rows[0],
      benchmark_provenance_rows: hashes.rowCount,
      benchmark_chain_fingerprint: sha256(JSON.stringify(hashes.rows))
    };
  });
}

function spawnLogged(command, args, logPath, { finite = true } = {}) {
  const fd = openSync(logPath, 'a');
  const child = spawn(command, args, { cwd: ROOT, stdio: ['ignore', fd, fd] });
  closeSync(fd);
  if (!finite) return child;
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve({ code, signal });
      else reject(new Error(`${command} ${args.slice(0, 2).join(' ')} exited ${code ?? signal}; inspect ${logPath}`));
    });
  });
}

function spawnInteractive(command, args) {
  const child = spawn(command, args, { cwd: ROOT, stdio: 'inherit' });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve({ code, signal });
      else reject(new Error(`${command} ${args.slice(0, 2).join(' ')} exited ${code ?? signal}`));
    });
  });
}

function captureFile(file) {
  if (!existsSync(file)) return { exists: false, data: null, mode: null };
  const stat = statSync(file);
  if (!stat.isFile()) throw new Error(`protected path is not a file: ${file}`);
  return { exists: true, data: readFileSync(file), mode: stat.mode & 0o777 };
}

function restoreFile(file, snapshot) {
  if (!snapshot.exists) {
    if (existsSync(file)) unlinkSync(file);
    return;
  }
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, snapshot.data, { mode: snapshot.mode });
  chmodSync(file, snapshot.mode);
}

function protectedKeyState(file) {
  if (!existsSync(file)) throw new Error(`canonical identity key missing: ${file}`);
  const stat = statSync(file);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
    throw new Error(`canonical identity key custody invalid: ${file}`);
  }
  return { sha256: sha256File(file), mode: stat.mode & 0o777 };
}

function assertProtectedKeyUnchanged(file, before) {
  const after = protectedKeyState(file);
  if (after.sha256 !== before.sha256 || after.mode !== before.mode) {
    throw new Error('canonical housekeeper key changed during scratch lifecycle');
  }
}

async function databaseExists(databaseName) {
  return withPool('postgres', async (pool) => {
    const result = await pool.query('SELECT 1 FROM pg_database WHERE datname = $1', [databaseName]);
    return result.rowCount === 1;
  });
}

async function verifyArtifactHashSet(root, hashes) {
  for (const [relativePath, expected] of Object.entries(hashes)) {
    const file = path.resolve(root, relativePath);
    if (file !== root && !file.startsWith(`${path.resolve(root)}${path.sep}`)) {
      throw new Error(`artifact hash path escaped output root: ${relativePath}`);
    }
    if (!existsSync(file) || await streamSha256(file) !== expected) {
      throw new Error(`artifact hash verification failed: ${relativePath}`);
    }
  }
  return { verified: true, files: Object.keys(hashes).length };
}

async function runSignedScratchPurge(databaseName, receiptPath) {
  await spawnInteractive(process.execPath, [
    'scripts/ceremony/purge-brain.mjs',
    '--live',
    '--aimos-db', databaseName,
    '--receipt-file', receiptPath,
  ]);
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  const verification = verifyWholeBrainPurgeReceipt(receipt);
  if (!verification.valid) throw new Error(`scratch purge receipt invalid:${verification.reason}`);
  if (verification.database !== databaseName
    || verification.postcondition?.mode !== 'destroyed'
    || verification.postcondition?.database_present !== false) {
    throw new Error('scratch purge receipt postcondition mismatch');
  }
  if (await databaseExists(databaseName)) throw new Error('scratch database still exists after signed purge');
  return {
    receipt_file: path.basename(receiptPath),
    receipt_sha256: sha256File(receiptPath),
    verification,
  };
}

async function waitForHealth(baseUrl, child, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`scratch server exited with ${child.exitCode}`);
    try {
      const response = await fetch(`${baseUrl}/healthz`, { signal: AbortSignal.timeout(1500) });
      const body = await response.json();
      if (response.ok && body.ready === true) return body;
    } catch { /* server is still booting */ }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`scratch server did not become ready at ${baseUrl}`);
}

async function stopChild(child) {
  if (!child || child.exitCode != null) return;
  child.kill('SIGTERM');
  const exited = await Promise.race([
    new Promise(resolve => child.once('exit', () => resolve(true))),
    new Promise(resolve => setTimeout(() => resolve(false), 5000))
  ]);
  if (!exited && child.exitCode == null) child.kill('SIGKILL');
}

// Stream-hash a single file so multi-GB artifacts (full_detail recall records
// exceed the 2 GiB readFileSync limit) hash without loading into memory.
function streamSha256(file) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', d => h.update(d)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
  });
}

// Recursively hash every produced artifact (excluding the hash manifest itself).
async function artifactHashes(dir, base = dir, out = {}) {
  for (const name of readdirSync(dir).sort()) {
    const file = path.join(dir, name);
    const rel = path.relative(base, file);
    const st = statSync(file);
    if (st.isDirectory()) { await artifactHashes(file, base, out); continue; }
    // run-status.json is a mutable operational projection, not publication
    // evidence. The immutable run manifest and phase proofs remain hashed.
    if (name === 'artifact-hashes.json' || name === 'run-status.json' || name === 'run-status.json.tmp') continue;
    out[rel] = await streamSha256(file);
  }
  return out;
}

// Parse a harness pass's summary.json (written into <passDir>/ledger/summary.json).
function readPassSummary(passDir) {
  const summaryFile = path.join(passDir, 'ledger', 'summary.json');
  if (!existsSync(summaryFile)) return null;
  try { return JSON.parse(readFileSync(summaryFile, 'utf8')); } catch { return null; }
}

function readLatestJsonArtifact(dir, prefix) {
  const name = readdirSync(dir)
    .filter((entry) => entry.startsWith(prefix) && entry.endsWith('.json'))
    .sort((left, right) => left.localeCompare(right))
    .at(-1);
  if (!name) throw new Error(`required benchmark artifact missing: ${prefix}`);
  const file = path.join(dir, name);
  return {
    file: path.relative(dir, file),
    sha256: sha256File(file),
    value: JSON.parse(readFileSync(file, 'utf8')),
  };
}

function canonicalSelections(args) {
  const benchmarks = args.benchmark === 'both'
    ? ['longmemeval', 'locomo']
    : [args.benchmark];
  if (args.full) return benchmarks.map((benchmark) => ({ benchmark, all: true }));
  if (args.gate) return benchmarks.map((benchmark) => ({ benchmark, selectionProfile: args.gate }));
  if (benchmarks.length === 1) {
    return [{ benchmark: benchmarks[0], questionLimit: args.sample }];
  }
  const longmemevalCount = Math.floor(args.sample / 2);
  return [
    { benchmark: 'longmemeval', questionLimit: longmemevalCount },
    { benchmark: 'locomo', questionLimit: args.sample - longmemevalCount },
  ];
}

async function runModelPreflight(context, logDir, generatorModel = 'gpt-5.4') {
  const modelPreflightFile = path.join(ROOT, 'eval', 'public-results', 'model-preflight', `${context.runId}.json`);
  context.onPhase?.('model-access-preflight');
  if (!existsSync(modelPreflightFile)) {
    await spawnLogged(process.execPath, [
      'scripts/ceremony/benchmark-model-preflight.mjs',
      '--live',
      '--generator-model', generatorModel,
      '--receipt-file', modelPreflightFile,
    ], path.join(logDir, 'model-access-preflight.log'));
  }
  if (lstatSync(modelPreflightFile).isSymbolicLink() || !statSync(modelPreflightFile).isFile()) {
    throw new Error('benchmark_model_preflight_receipt_invalid');
  }
  const modelPreflight = JSON.parse(readFileSync(modelPreflightFile, 'utf8'));
  const generatorCall = modelPreflight?.body?.calls?.find((call) => call.role === 'generator');
  const judgeCall = modelPreflight?.body?.calls?.find((call) => call.role === 'judge');
  if (modelPreflight?.body?.schema_version !== 'aimos.benchmark-model-preflight/v1'
    || modelPreflight?.verification?.receipt_signature_valid !== true
    || modelPreflight?.verification?.model_catalog_exact_match !== true
    || modelPreflight?.verification?.structured_smoke_calls_valid !== true
    || generatorCall?.requested_model !== generatorModel
    || generatorCall?.actual_model !== generatorModel
    || judgeCall?.requested_model !== 'gpt-5.6-terra'
    || judgeCall?.actual_model !== 'gpt-5.6-terra') {
    throw new Error('benchmark_model_preflight_receipt_invalid');
  }
  return {
    file: path.relative(ROOT, modelPreflightFile),
    sha256: sha256File(modelPreflightFile),
  };
}

async function runCanonicalBenchmark(args, context) {
  const canonical = {};
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const prepared = [];

  for (const selection of canonicalSelections(args)) {
    const benchmark = selection.benchmark;
    const selectionFile = path.join(context.outputDir, `selection-${benchmark}.json`);
    const common = [
      'eval/run-canonical-single-query.mjs',
      '--benchmark', benchmark,
      '--protocol', args.protocol,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
    ];
    context.onPhase?.(`${benchmark}-prepare`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'prepare',
      ...(selection.all
        ? ['--all']
        : selection.selectionProfile
          ? ['--selection-profile', selection.selectionProfile]
          : ['--question-limit', String(selection.questionLimit)]),
    ], path.join(logDir, `${benchmark}-prepare.log`));

    context.onPhase?.(`${benchmark}-corpus-preflight`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--dry-run',
    ], path.join(logDir, `${benchmark}-replay-preflight.log`));
    prepared.push({ benchmark, selectionFile, common });
  }

  canonical.model_preflight = await runModelPreflight(context, logDir);

  for (const { benchmark, selectionFile, common } of prepared) {

    context.onPhase?.(`${benchmark}-replay`);
    await spawnLogged(process.execPath, [
      'eval/replay-sessions.mjs',
      '--benchmark', benchmark,
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--delay-ms', '2100',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-replay.log`));

    context.onPhase?.(`${benchmark}-recall`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'recall',
      '--aimos-db', context.databaseName,
      '--aimos-base', context.baseUrl,
      '--recall-k', String(args.limit),
      '--delay-ms', '2100',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-recall.log`));

    context.onPhase?.(`${benchmark}-generate`);
    await spawnLogged(process.execPath, [
      ...common,
      '--phase', 'generate',
      '--delay-ms', '0',
      '--retries', '3',
    ], path.join(logDir, `${benchmark}-generate.log`));

    if (args.protocol !== LOCOMO_OFFICIAL_PROTOCOL) {
      context.onPhase?.(`${benchmark}-judge`);
      await spawnLogged(process.execPath, [
        ...common,
        '--phase', 'judge',
        '--judge-reasoning', 'high',
        '--delay-ms', '0',
        '--retries', '3',
      ], path.join(logDir, `${benchmark}-judge.log`));
    }

    context.onPhase?.(`${benchmark}-aggregate`);
    await spawnLogged(process.execPath, [
      args.protocol === LOCOMO_OFFICIAL_PROTOCOL
        ? 'eval/aggregate-locomo-official-results.mjs'
        : 'eval/aggregate-canonical-results.mjs',
      ...(args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? [] : ['--benchmark', benchmark]),
      '--run-id', context.runId,
      '--run-dir', context.outputDir,
      '--selection-file', selectionFile,
    ], path.join(logDir, `${benchmark}-aggregate.log`));

    canonical[benchmark] = {
      selection: {
        file: path.basename(selectionFile),
        sha256: sha256File(selectionFile),
        value: JSON.parse(readFileSync(selectionFile, 'utf8')),
      },
      replay: readLatestJsonArtifact(context.outputDir, `replay-summary-${benchmark}-`),
      recall: readLatestJsonArtifact(context.outputDir, `phase-recall-${benchmark}-`),
      generate: readLatestJsonArtifact(context.outputDir, `phase-generate-${benchmark}-`),
      judge: args.protocol === LOCOMO_OFFICIAL_PROTOCOL
        ? null
        : readLatestJsonArtifact(context.outputDir, `phase-judge-${benchmark}-`),
      aggregate: {
        file: args.protocol === LOCOMO_OFFICIAL_PROTOCOL
          ? 'locomo-official-summary.json'
          : `canonical-summary-${benchmark}.json`,
        sha256: sha256File(path.join(context.outputDir, args.protocol === LOCOMO_OFFICIAL_PROTOCOL
          ? 'locomo-official-summary.json'
          : `canonical-summary-${benchmark}.json`)),
        value: JSON.parse(readFileSync(path.join(context.outputDir, args.protocol === LOCOMO_OFFICIAL_PROTOCOL
          ? 'locomo-official-summary.json'
          : `canonical-summary-${benchmark}.json`), 'utf8')),
      },
    };
  }
  return canonical;
}

async function runPoisonedRagBenchmark(args, context) {
  const logDir = path.join(context.outputDir, 'logs');
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const modelPreflight = await runModelPreflight(context, logDir, POISONEDRAG_GENERATOR_MODEL);
  const targetCount = args.full ? 100 : args.sample;
  context.onPhase?.('poisonedrag-ingest-recall');
  await spawnLogged(process.execPath, [
    'eval/run-poisonedrag-n100.mjs',
    '--phase', 'ingest-recall',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--aimos-base', context.baseUrl,
    '--aimos-db', context.databaseName,
    '--target-count', String(targetCount),
    '--delay-ms', '2100',
    '--retries', String(POISONEDRAG_MAX_ATTEMPTS),
  ], path.join(logDir, 'poisonedrag-ingest-recall.log'));
  context.onPhase?.('poisonedrag-model-aggregate');
  await spawnLogged(process.execPath, [
    'eval/run-poisonedrag-n100.mjs',
    '--phase', 'model-aggregate',
    '--run-id', context.runId,
    '--run-dir', context.outputDir,
    '--aimos-base', context.baseUrl,
    '--target-count', String(targetCount),
    '--delay-ms', '2100',
    '--retries', String(POISONEDRAG_MAX_ATTEMPTS),
  ], path.join(logDir, 'poisonedrag-model-aggregate.log'));
  const summaryFile = path.join(context.outputDir, 'poisonedrag', 'summary.json');
  const progressFile = path.join(context.outputDir, 'poisonedrag', 'progress.json');
  if (!existsSync(summaryFile) || !existsSync(progressFile)) {
    throw new Error('poisonedrag_terminal_artifacts_missing');
  }
  const summary = JSON.parse(readFileSync(summaryFile, 'utf8'));
  if (summary.schema !== 'hom.aimos.poisonedrag-summary/v1'
    || summary.protocol !== POISONEDRAG_PROTOCOL_ID
    || summary.intended_n !== targetCount
    || summary.completed_n !== targetCount
    || summary.denominator_complete !== true) {
    throw new Error('poisonedrag_summary_invalid');
  }
  return {
    model_preflight: modelPreflight,
    target_count: targetCount,
    summary: {
      file: path.relative(context.outputDir, summaryFile),
      sha256: sha256File(summaryFile),
      value: summary,
    },
  };
}

function baseHarnessArgs(args, databaseName, baseUrl) {
  return [
    'eval/run-locomo-longmem-benchmarks.js',
    '--aimos-db', databaseName,
    '--aimos-port', String(args.port),
    '--aimos-base', baseUrl,
    '--agent-id', 'housekeeper',
    '--benchmark', args.benchmark,
    '--longmemeval-file', args.longmemevalFile,
    '--limit', String(args.limit),
    '--request-interval-ms', '0',
    '--progress-every', '10',
    ...(args.full ? ['--full'] : ['--sample', String(args.sample)])
  ];
}

export function canonicalRunConfiguration(args) {
  if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
    return {
      protocol: args.protocol,
      benchmark: args.benchmark,
      full: args.full,
      smoke: args.smoke,
      sample: args.full ? 100 : args.sample,
      recall_depth_k: 5,
      generator: `codex:${POISONEDRAG_GENERATOR_MODEL}`,
      judge: 'codex:gpt-5.6-terra',
      judge_reasoning: 'high',
      phase_retries: POISONEDRAG_MAX_ATTEMPTS,
      signed_save_interval_ms: 2100,
      corpus_preflight: 'poisonedrag-pinned-inputs/v1',
      model_preflight: 'aimos.benchmark-model-preflight/v1',
    };
  }
  return {
    protocol: args.protocol,
    benchmark: args.benchmark,
    full: args.full,
    smoke: args.smoke,
    gate: args.gate,
    sample: args.sample,
    recall_depth_k: args.limit,
    generator: 'codex:gpt-5.4',
    judge: args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? null : 'codex:gpt-5.6-terra',
    judge_reasoning: args.protocol === LOCOMO_OFFICIAL_PROTOCOL ? null : 'high',
    phase_retries: 3,
    corpus_preflight: 'native-save-contract/v1',
    model_preflight: 'aimos.benchmark-model-preflight/v1',
  };
}

function writeRunStatus(outputDir, status) {
  const file = path.join(outputDir, 'run-status.json');
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({
    schema: 'hom.canonical-benchmark-run-status/v1',
    updated_at: new Date().toISOString(),
    ...status,
  }, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, file);
}

export function writeRunManifest(outputDir, manifest) {
  const file = path.join(outputDir, 'run-manifest.json');
  const value = { schema: 'hom.canonical-benchmark-run-manifest/v1', ...manifest };
  value.manifest_sha256 = sha256(JSON.stringify(value));
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return value;
}

export function readRunManifest(outputDir, expectedRunId, expectedDatabaseName, expectedConfiguration) {
  const file = path.join(outputDir, 'run-manifest.json');
  if (!existsSync(file) || statSync(file).isSymbolicLink()) throw new Error('resume_run_manifest_missing_or_invalid');
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  const claimedHash = manifest.manifest_sha256;
  const unsigned = { ...manifest };
  delete unsigned.manifest_sha256;
  const manifestConfiguration = manifest.configuration;
  const retryRecovery = manifestConfiguration?.protocol === POISONEDRAG_PROTOCOL_ID
    && expectedConfiguration?.protocol === POISONEDRAG_PROTOCOL_ID
    && Number.isInteger(manifestConfiguration.phase_retries)
    && manifestConfiguration.phase_retries >= 1
    && manifestConfiguration.phase_retries < expectedConfiguration.phase_retries
    && expectedConfiguration.phase_retries === POISONEDRAG_MAX_ATTEMPTS
    && JSON.stringify({
      ...manifestConfiguration,
      phase_retries: expectedConfiguration.phase_retries,
    }) === JSON.stringify(expectedConfiguration)
      ? {
          original_attempt_ceiling: manifestConfiguration.phase_retries,
          effective_attempt_ceiling: expectedConfiguration.phase_retries,
        }
      : null;
  if (manifest.schema !== 'hom.canonical-benchmark-run-manifest/v1'
    || manifest.run_id !== expectedRunId
    || manifest.database_name !== expectedDatabaseName
    || claimedHash !== sha256(JSON.stringify(unsigned))
    || (JSON.stringify(manifestConfiguration) !== JSON.stringify(expectedConfiguration) && !retryRecovery)) {
    throw new Error('resume_run_manifest_mismatch');
  }
  Object.defineProperty(manifest, 'retry_recovery', {
    value: retryRecovery,
    enumerable: false,
    writable: false,
  });
  return manifest;
}

export function writeRetryRecoveryReceipt(outputDir, runId, manifest) {
  const recovery = manifest?.retry_recovery;
  if (!recovery) return null;
  const file = path.join(outputDir, 'retry-recovery-receipt.json');
  if (existsSync(file)) {
    if (statSync(file).isSymbolicLink()) throw new Error('retry_recovery_receipt_invalid');
    const existing = JSON.parse(readFileSync(file, 'utf8'));
    const claimedHash = existing.receipt_sha256;
    const unsignedExisting = { ...existing };
    delete unsignedExisting.receipt_sha256;
    if (existing.schema !== 'hom.poisonedrag-retry-recovery/v1'
      || existing.run_id !== runId
      || existing.original_manifest_sha256 !== manifest.manifest_sha256
      || existing.original_attempt_ceiling !== recovery.original_attempt_ceiling
      || existing.effective_attempt_ceiling !== recovery.effective_attempt_ceiling
      || claimedHash !== sha256(JSON.stringify(unsignedExisting))) {
      throw new Error('retry_recovery_receipt_invalid');
    }
    return { file: path.basename(file), sha256: sha256File(file), value: existing };
  }
  const statusFile = path.join(outputDir, 'run-status.json');
  const receipt = {
    schema: 'hom.poisonedrag-retry-recovery/v1',
    run_id: runId,
    protocol: POISONEDRAG_PROTOCOL_ID,
    original_manifest_sha256: manifest.manifest_sha256,
    prior_run_status_sha256: existsSync(statusFile) ? sha256File(statusFile) : null,
    original_attempt_ceiling: recovery.original_attempt_ceiling,
    effective_attempt_ceiling: recovery.effective_attempt_ceiling,
    retryable_failure_classes: ['transport', 'timeout', '408', '425', '429', '500', '502', '503', '504'],
    non_retryable_failure_classes: ['authentication', 'authorization', 'model_substitution', 'artifact_integrity'],
    scientific_inputs_unchanged: true,
    completed_provider_outputs_reused: true,
    authorized_reason: 'operator_authorized_retry_ceiling_increase_after_transient_provider_failure',
    created_at: new Date().toISOString(),
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { file: path.basename(file), sha256: sha256File(file), value: receipt };
}

async function main() {
  const args = parseArgs(process.argv);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const runId = args.resumeRun || `${stamp}_${randomBytes(3).toString('hex')}`;
  const databaseName = `aimos_benchmark_${runId.toLowerCase()}`;
  const outputDir = path.join(args.outputRoot, runId);
  const baseUrl = `http://127.0.0.1:${args.port}`;
  const resuming = Boolean(args.resumeRun);
  if (resuming) {
    if (!existsSync(outputDir) || statSync(outputDir).isSymbolicLink()) throw new Error('resume_run_directory_missing_or_invalid');
  } else {
    mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  }

  const installerLog = path.join(outputDir, 'installer.log');
  const serverLog = path.join(outputDir, 'server.log');
  const purgeReceiptPath = path.join(outputDir, 'purge-receipt.json');
  const housekeeperKeyBefore = protectedKeyState(HOUSEKEEPER_KEY);
  const sharedFileSnapshots = new Map([
    [HOUSEKEEPER_CERT_CACHE, captureFile(HOUSEKEEPER_CERT_CACHE)],
    [ARCHITECTURE_AUTHORITY, captureFile(ARCHITECTURE_AUTHORITY)],
  ]);
  let server = null;
  let scratchCreated = false;
  let scratchPurged = false;
  let sharedFilesRestored = false;
  let interrupted = false;

  const restoreSharedFiles = () => {
    if (sharedFilesRestored) return;
    for (const [file, snapshot] of sharedFileSnapshots) restoreFile(file, snapshot);
    assertProtectedKeyUnchanged(HOUSEKEEPER_KEY, housekeeperKeyBefore);
    sharedFilesRestored = true;
  };
  const cleanup = async () => {
    await stopChild(server);
    restoreSharedFiles();
    if (scratchCreated && !scratchPurged && !args.keepScratchDb) {
      writeFileSync(path.join(outputDir, 'scratch-recovery.json'), `${JSON.stringify({
        database_name: databaseName,
        retained: true,
        reason: 'run_incomplete_or_purge_unverified',
        required_cleanup: `node scripts/ceremony/purge-brain.mjs --live --aimos-db ${databaseName}`,
      }, null, 2)}\n`, { mode: 0o600 });
    }
  };
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      interrupted = true;
      cleanup().finally(() => process.exit(130));
    });
  }

  const currentCanonicalFootprint = await canonicalFootprint();
  if (currentCanonicalFootprint.benchmark_rows !== 0) {
    throw new Error('canonical AIMOS already contains benchmark memories; run the authorized cleanup ceremony before benchmarking');
  }
  const datasets = args.protocol === POISONEDRAG_PROTOCOL_ID
    ? {
        poisonedrag_source_lock: {
          file: path.relative(ROOT, POISONEDRAG_SOURCE_LOCK),
          sha256: sha256File(POISONEDRAG_SOURCE_LOCK),
        },
        poisonedrag_public_target_lock: {
          file: path.relative(ROOT, POISONEDRAG_PUBLIC_LOCK),
          sha256: sha256File(POISONEDRAG_PUBLIC_LOCK),
        },
        poisonedrag_private_target_manifest: {
          file: 'n100-private-target-manifest.json',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-private-target-manifest.json')),
          redistributed: false,
        },
        poisonedrag_corpus_resolution: {
          file: 'n100-corpus-resolution.json',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-corpus-resolution.json')),
          redistributed: false,
        },
        poisonedrag_candidate_pool: {
          file: 'n100-candidate-pool.jsonl',
          sha256: sha256File(path.join(POISONEDRAG_PRIVATE_ROOT, 'n100-candidate-pool.jsonl')),
          redistributed: false,
        },
      }
    : {
        longmemeval: { path: args.longmemevalFile, sha256: sha256File(args.longmemevalFile) },
        locomo: { path: LOCOMO_DATASET, sha256: sha256File(LOCOMO_DATASET) },
        canonical_corpus_manifest: {
          path: path.join(ROOT, 'eval', 'data', 'canonical', 'corpus-manifest.json'),
          sha256: sha256File(path.join(ROOT, 'eval', 'data', 'canonical', 'corpus-manifest.json')),
        },
      };
  const configuration = canonicalRunConfiguration(args);
  const resumeManifest = resuming
    ? readRunManifest(outputDir, runId, databaseName, configuration)
    : null;
  const retryRecovery = resuming
    ? writeRetryRecoveryReceipt(outputDir, runId, resumeManifest)
    : null;
  const canonicalBefore = resumeManifest?.canonical_before || currentCanonicalFootprint;
  if (JSON.stringify(canonicalBefore) !== JSON.stringify(currentCanonicalFootprint)) {
    throw new Error('canonical AIMOS footprint changed since the resumable run began');
  }
  const startedAt = resumeManifest?.started_at || new Date().toISOString();
  const passes = {};
  let health = null;
  let baseline = resumeManifest?.baseline || null;
  let resumable = false;
  const resumeScopeArgs = args.full
    ? '--full'
    : args.gate
      ? `--gate ${args.gate}`
      : args.smoke
        ? '--smoke'
        : `--sample ${args.sample}`;

  try {
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: resuming ? 'resuming' : 'initializing',
      phase: resuming ? 'scratch-server-start' : 'genesis-install',
      resumable: resuming,
    });
    if (resuming) {
      if (!await databaseExists(databaseName)) throw new Error('resume_scratch_database_missing');
      scratchCreated = true;
    } else {
      scratchCreated = true;
      await spawnLogged(process.execPath, [
        'scripts/genesis-install.mjs', '--aimos-db', databaseName, '--aimos-port', String(args.port)
      ], installerLog);
      baseline = await scratchProof(databaseName);
      writeRunManifest(outputDir, {
        run_id: runId,
        database_name: databaseName,
        started_at: startedAt,
        configuration,
        datasets,
        baseline,
        canonical_before: canonicalBefore,
      });
    }
    server = spawnLogged(process.execPath, [
      'server.js', '--aimos-db', databaseName, '--aimos-port', String(args.port)
    ], serverLog, { finite: false });
    health = await waitForHealth(baseUrl, server);
    resumable = Boolean(args.keepScratchDb
      && scratchCreated
      && !scratchPurged
      && existsSync(path.join(outputDir, 'run-manifest.json')));
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'running',
      phase: 'benchmark',
      resumable,
    });

    if (args.lifecycleProof) {
      const appendProof = path.join(outputDir, 'session-lifecycle-append.json');
      const finalizeProof = path.join(outputDir, 'session-lifecycle-finalize-recall.json');
      await spawnLogged(process.execPath, [
        'scripts/benchmark/prove-session-lifecycle.mjs',
        '--phase', 'append',
        '--run-id', runId.toLowerCase(),
        '--proof-file', appendProof,
        '--aimos-db', databaseName,
        '--aimos-port', String(args.port),
      ], path.join(outputDir, 'session-lifecycle-append.log'));

      await stopChild(server);
      server = spawnLogged(process.execPath, [
        'server.js', '--aimos-db', databaseName, '--aimos-port', String(args.port)
      ], serverLog, { finite: false });
      health = await waitForHealth(baseUrl, server);

      await spawnLogged(process.execPath, [
        'scripts/benchmark/prove-session-lifecycle.mjs',
        '--phase', 'finalize-recall',
        '--run-id', runId.toLowerCase(),
        '--proof-file', finalizeProof,
        '--aimos-db', databaseName,
        '--aimos-port', String(args.port),
      ], path.join(outputDir, 'session-lifecycle-finalize-recall.log'));
      passes.lifecycle = {
        append: JSON.parse(readFileSync(appendProof, 'utf8')),
        finalize_recall: JSON.parse(readFileSync(finalizeProof, 'utf8')),
      };
    } else if (args.historicalV1) {
      // ---- Pass 1: retrieval floor (deterministic; ingests both corpora once) ----
      const officialDir = path.join(outputDir, 'official');
      mkdirSync(path.join(officialDir, 'ledger'), { recursive: true });
      mkdirSync(path.join(officialDir, 'record'), { recursive: true });
      await spawnLogged(process.execPath, [
        ...baseHarnessArgs(args, databaseName, baseUrl),
        '--mode', 'official',
        '--ingest-missing',
        '--output-dir', officialDir,
        '--ledger-dir', path.join(officialDir, 'ledger'),
        '--record', path.join(officialDir, 'record')
      ], path.join(officialDir, 'benchmark.log'));
      passes.official = readPassSummary(officialDir);

      // ---- Pass 2: cognitive answer (opt-in; LLM generator + LLM judge) ----
      if (args.cognitive) {
        const cognitiveDir = path.join(outputDir, 'cognitive');
        mkdirSync(path.join(cognitiveDir, 'ledger'), { recursive: true });
        await spawnLogged(process.execPath, [
          ...baseHarnessArgs(args, databaseName, baseUrl),
          '--mode', 'judge',
          '--generator-provider', args.generatorProvider,
          '--generator-model', args.generatorModel,
          '--judge-provider', args.judgeProvider,
          '--judge-model', args.judgeModel,
          '--output-dir', cognitiveDir,
          '--ledger-dir', path.join(cognitiveDir, 'ledger')
        ], path.join(cognitiveDir, 'benchmark.log'));
        passes.cognitive = readPassSummary(cognitiveDir);
      }
    } else if (args.protocol === POISONEDRAG_PROTOCOL_ID) {
      passes.poisonedrag = await runPoisonedRagBenchmark(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    } else {
      passes.canonical = await runCanonicalBenchmark(args, {
        runId: runId.toLowerCase(),
        databaseName,
        outputDir,
        baseUrl,
        onPhase: (phase) => writeRunStatus(outputDir, {
          run_id: runId,
          database_name: databaseName,
          state: 'running',
          phase,
          resumable,
        }),
      });
    }

    await stopChild(server);
    server = null;

    const scratchAfter = await scratchProof(databaseName);
    if (scratchAfter.orphaned_memories !== 0) throw new Error(`scratch database has ${scratchAfter.orphaned_memories} orphaned memories`);
    if (scratchAfter.benchmark_memories < 1) throw new Error('benchmark ingestion produced no scratch memories');

    writeFileSync(path.join(outputDir, 'pre-purge-evidence.json'), `${JSON.stringify({
      run_id: runId,
      database_name: databaseName,
      baseline,
      after_benchmark: scratchAfter,
      datasets,
      passes,
    }, null, 2)}\n`);
    const prePurgeHashes = await artifactHashes(outputDir);
    const prePurgeVerification = await verifyArtifactHashSet(outputDir, prePurgeHashes);
    writeFileSync(
      path.join(outputDir, 'pre-purge-artifact-hashes.json'),
      `${JSON.stringify({ hashes: prePurgeHashes, verification: prePurgeVerification }, null, 2)}\n`,
    );

    restoreSharedFiles();
    const purge = args.keepScratchDb
      ? null
      : await runSignedScratchPurge(databaseName, purgeReceiptPath);
    if (purge) {
      scratchPurged = true;
      scratchCreated = false;
    }
    const canonicalAfter = await canonicalFootprint();
    const canonicalUntouched = JSON.stringify(canonicalBefore) === JSON.stringify(canonicalAfter);
    if (!canonicalUntouched) throw new Error('canonical AIMOS benchmark footprint changed');

    const isolationProof = {
      run_id: runId,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      mode: args.lifecycleProof
        ? 'lifecycle-proof'
        : args.historicalV1
          ? 'historical-v1'
          : args.protocol === POISONEDRAG_PROTOCOL_ID
            ? 'poisonedrag-n100'
            : 'canonical-single-query',
      protocol: args.protocol,
      benchmark: args.benchmark,
      scope: args.lifecycleProof
        ? 'lifecycle-proof'
        : args.full ? 'full' : (args.gate || (args.smoke ? `smoke:${args.sample}` : `sample:${args.sample}`)),
      recall_depth_k: args.limit,
      cognitive: args.lifecycleProof
        ? false
        : args.historicalV1
          ? (args.cognitive
              ? { generator: `${args.generatorProvider}:${args.generatorModel}`, judge: `${args.judgeProvider}:${args.judgeModel}` }
              : false)
          : args.protocol === LOCOMO_OFFICIAL_PROTOCOL
            ? { reader: 'codex:gpt-5.4', deterministic_scorer: LOCOMO_OFFICIAL_PROTOCOL }
            : args.protocol === POISONEDRAG_PROTOCOL_ID
              ? { generator: `codex:${POISONEDRAG_GENERATOR_MODEL}`, judge: 'codex:gpt-5.6-terra', judge_reasoning: 'high' }
              : { generator: 'codex:gpt-5.4', judge: 'codex:gpt-5.6-terra', judge_reasoning: 'high' },
      datasets,
      scratch: {
        database_name: databaseName,
        port: args.port,
        retained: args.keepScratchDb,
        baseline,
        after_benchmark: scratchAfter,
        pre_purge_artifacts: prePurgeVerification,
        whole_scratch_brain_purged: Boolean(purge),
        purge,
      },
      canonical: { before: canonicalBefore, after: canonicalAfter, untouched: canonicalUntouched },
      retry_recovery: retryRecovery,
      health
    };
    writeFileSync(path.join(outputDir, 'isolation-proof.json'), `${JSON.stringify(isolationProof, null, 2)}\n`);
    writeFileSync(path.join(outputDir, 'benchmark-summary.json'), `${JSON.stringify({ run_id: runId, mode: isolationProof.mode, benchmark: args.benchmark, scope: isolationProof.scope, recall_depth_k: args.limit, passes }, null, 2)}\n`);
    writeFileSync(path.join(outputDir, 'reproduce-command.txt'),
      `node scripts/benchmark/run-isolated.mjs${args.lifecycleProof ? ' --lifecycle-proof' : args.full ? ' --full' : args.gate ? ` --gate ${args.gate}` : ` --sample ${args.sample}`}${args.historicalV1 ? ' --historical-v1' : ''}${args.cognitive ? ' --cognitive' : ''} --benchmark ${args.benchmark} --protocol ${args.protocol} --port ${args.port} --limit ${args.limit}\n`);
    writeFileSync(path.join(outputDir, 'artifact-hashes.json'), `${JSON.stringify(await artifactHashes(outputDir), null, 2)}\n`);
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'complete',
      phase: 'complete',
      resumable: false,
    });
    console.log(JSON.stringify({ output_dir: outputDir, isolation: isolationProof, passes }, null, 2));
  } catch (error) {
    writeRunStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      state: 'failed',
      phase: 'failed',
      resumable,
      error: {
        name: String(error?.name || 'Error').slice(0, 128),
        message: String(error?.message || error || 'unknown_error').slice(0, 2000),
      },
      resume_command: resumable
        ? `node scripts/benchmark/run-isolated.mjs --resume-run ${runId} ${resumeScopeArgs} --benchmark ${args.benchmark} --protocol ${args.protocol} --port ${args.port} --limit ${args.limit} --keep-scratch-db`
        : null,
    });
    throw error;
  } finally {
    if (!interrupted) await cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
