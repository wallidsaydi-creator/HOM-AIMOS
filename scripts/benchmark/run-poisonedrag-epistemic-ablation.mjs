#!/usr/bin/env node

/**
 * Isolated lifecycle owner for the preregistered PoisonedRAG N=100 epistemic
 * ablation. It clones the completed retained scratch brain, never re-ingests,
 * runs the fixed signed diagnostic policies, and retains the clone for the
 * later signed whole-brain purge ceremony.
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { selfHash } from '../../eval/poisonedrag/harness.mjs';
import { writeImmutableJson } from '../../eval/poisonedrag/protocol.mjs';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SOURCE_RUN_ID = '20260722172124_db0d79';
const SOURCE_DATABASE = `aimos_benchmark_${SOURCE_RUN_ID}`;
const PROTOCOL = 'poisonedrag-n100-epistemic-ablation-v1';
const OUTPUT_ROOT = path.join(ROOT, 'eval', 'public-results');
const HOUSEKEEPER_CERT_CACHE = path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.cert-cache.json');
const ARCHITECTURE_AUTHORITY = path.join(ROOT, 'architecture-authority.json');
const SOURCE_FILES = Object.freeze([
  'services/retrieval/epistemic-trust-retrieval.js',
  'services/observe/recall-doctor-trace.js',
  'services/retrieval/native-recall-pipeline.js',
  'eval/poisonedrag/harness.mjs',
  'eval/run-poisonedrag-epistemic-ablation.mjs',
  'scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs',
  'docs/benchmarks/POISONEDRAG-N100-EPISTEMIC-ABLATION-PREREGISTRATION.md',
]);
const RESUME_LIFECYCLE_FILES = Object.freeze(new Set([
  'eval/run-poisonedrag-epistemic-ablation.mjs',
  'scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs',
]));

function cliValue(argv, name) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function parseOrchestratorArgs(argv) {
  const resumeRun = String(cliValue(argv, '--resume-run') || '').trim().toLowerCase() || null;
  if (resumeRun && !/^\d{14}_[0-9a-f]{6}$/.test(resumeRun)) {
    throw new Error('ablation_resume_run_invalid');
  }
  const port = Number(cliValue(argv, '--port') || 9200);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || [9000, 9001, 9100].includes(port)) {
    throw new Error('ablation_port_invalid_or_reserved');
  }
  const retries = Number(cliValue(argv, '--retries') || 6);
  if (!Number.isInteger(retries) || retries < 1 || retries > 10) {
    throw new Error('ablation_retries_invalid');
  }
  return { resumeRun, port, retries, targetCount: 100 };
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256File(file) {
  return sha256(readFileSync(file));
}

function runIdNow() {
  const timestamp = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
  return `${timestamp}_${randomBytes(3).toString('hex')}`;
}

function databaseUrl(name) {
  const url = new URL(resolveAimosDatabaseUrl([]));
  url.pathname = `/${name}`;
  return url.toString();
}

async function withPool(databaseName, fn) {
  const databasePool = new Pool({
    connectionString: databaseUrl(databaseName),
    ssl: false,
    connectionTimeoutMillis: 10_000,
  });
  try {
    return await fn(databasePool);
  } finally {
    await databasePool.end().catch(() => {});
  }
}

function quoteDatabase(name) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(name)) throw new Error('ablation_database_name_invalid');
  return `"${name}"`;
}

async function databaseExists(databaseName) {
  return withPool('postgres', async (admin) => {
    const result = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [databaseName]);
    return result.rowCount === 1;
  });
}

async function cloneSourceDatabase(targetDatabase) {
  return withPool('postgres', async (admin) => {
    const active = await admin.query(
      `SELECT count(*)::int AS count
         FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [SOURCE_DATABASE],
    );
    if (active.rows[0].count !== 0) {
      throw new Error(`ablation_source_database_has_active_connections:${active.rows[0].count}`);
    }
    await admin.query(
      `CREATE DATABASE ${quoteDatabase(targetDatabase)} WITH TEMPLATE ${quoteDatabase(SOURCE_DATABASE)}`,
    );
  });
}

async function databaseEvidence(databaseName) {
  return withPool(databaseName, async (databasePool) => {
    const [memories, classifications, events, ablationEvents, databaseSize] = await Promise.all([
      databasePool.query(
        `SELECT id::text, key, source, encode(content_hash, 'hex') AS content_hash,
                retrieval_weight::text, current_epistemic_label,
                current_epistemic_confidence_milli,
                current_epistemic_event_id::text
           FROM public.aimos_memories
          ORDER BY id`,
      ),
      databasePool.query(
        `SELECT classification_id::text, memory_id::text, label,
                confidence_milli, authority_event_id::text,
                encode(event_mutation_hash, 'hex') AS event_mutation_hash,
                encode(live_content_hash, 'hex') AS live_content_hash,
                encode(prev_classification_hash, 'hex') AS prev_classification_hash,
                encode(classification_hash, 'hex') AS classification_hash,
                classified_at::text
           FROM public.aimos_memory_epistemic_classifications
          ORDER BY classification_id`,
      ),
      databasePool.query('SELECT count(*)::int AS count FROM public.aimos_events'),
      databasePool.query(
        `SELECT count(*)::int AS count
           FROM public.aimos_events
          WHERE operation = 'poisonedrag_epistemic_ablation_decision'`,
      ),
      databasePool.query('SELECT pg_database_size(current_database())::bigint::text AS bytes'),
    ]);
    return {
      database_name: databaseName,
      database_bytes: Number(databaseSize.rows[0].bytes),
      memory_rows: memories.rowCount,
      memory_root_sha256: sha256(Buffer.from(JSON.stringify(memories.rows), 'utf8')),
      classification_rows: classifications.rowCount,
      classification_root_sha256: sha256(Buffer.from(JSON.stringify(classifications.rows), 'utf8')),
      event_rows: events.rows[0].count,
      ablation_decision_event_rows: ablationEvents.rows[0].count,
    };
  });
}

async function canonicalBenchmarkFootprint() {
  return withPool('aimos', async (databasePool) => {
    const rows = await databasePool.query(
      `SELECT id::text, key, source, encode(content_hash, 'hex') AS content_hash
         FROM public.aimos_memories
        WHERE source = 'benchmark:poisonedrag'
        ORDER BY id`,
    );
    return {
      rows: rows.rowCount,
      root_sha256: sha256(Buffer.from(JSON.stringify(rows.rows), 'utf8')),
    };
  });
}

function writeStatus(outputDir, value) {
  const file = path.join(outputDir, 'run-status.json');
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({
    protocol: PROTOCOL,
    ...value,
    updated_at: new Date().toISOString(),
  }, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, file);
}

function snapshotFile(file) {
  if (!existsSync(file)) return { file, exists: false };
  const stat = lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`ablation_shared_file_invalid:${file}`);
  return {
    file,
    exists: true,
    bytes: readFileSync(file),
    mode: stat.mode & 0o777,
  };
}

function restoreFile(snapshot) {
  if (!snapshot.exists) {
    if (existsSync(snapshot.file) && !lstatSync(snapshot.file).isSymbolicLink()) {
      unlinkSync(snapshot.file);
    }
    return;
  }
  const temporary = `${snapshot.file}.ablation-restore-${process.pid}`;
  writeFileSync(temporary, snapshot.bytes, { mode: snapshot.mode });
  chmodSync(temporary, snapshot.mode);
  renameSync(temporary, snapshot.file);
}

function spawnLogged(command, args, logFile, { finite = true } = {}) {
  mkdirSync(path.dirname(logFile), { recursive: true, mode: 0o700 });
  const descriptor = openSync(logFile, 'a', 0o600);
  const child = spawn(command, args, {
    cwd: ROOT,
    stdio: ['ignore', descriptor, descriptor],
  });
  closeSync(descriptor);
  if (!finite) return child;
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve({ code, signal });
      else reject(new Error(
        `${command} ${args.slice(0, 2).join(' ')} exited ${code ?? signal}; inspect ${logFile}`,
      ));
    });
  });
}

async function stopChild(child) {
  if (!child || child.exitCode != null || child.signalCode != null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 10_000)),
  ]);
  if (child.exitCode == null && child.signalCode == null) child.kill('SIGKILL');
}

async function waitForServer(origin, expectedDatabase, child) {
  const deadline = Date.now() + 120_000;
  let lastError = null;
  while (Date.now() < deadline) {
    if (child.exitCode != null || child.signalCode != null) {
      throw new Error(`ablation_server_exited_early:${child.exitCode ?? child.signalCode}`);
    }
    try {
      const response = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(5000) });
      const body = await response.json();
      if (response.ok && body.ready === true
        && body.runtime?.database_name === expectedDatabase
        && body.runtime?.benchmark_scratch === true) {
        return body;
      }
      lastError = new Error('ablation_server_health_identity_mismatch');
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw lastError || new Error('ablation_server_health_timeout');
}

function sourceFileManifest() {
  return {
    git_head: String(
      execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: ROOT,
        encoding: 'utf8',
      }),
    ).trim(),
    files: SOURCE_FILES.map((relativePath) => {
      const file = path.join(ROOT, relativePath);
      return {
        path: relativePath,
        bytes: statSync(file).size,
        sha256: sha256File(file),
      };
    }),
  };
}

export function sourceManifestDifferences(previous, current) {
  if (!previous || !current || !Array.isArray(previous.files) || !Array.isArray(current.files)) {
    throw new Error('ablation_source_manifest_invalid');
  }
  if (previous.git_head !== current.git_head) {
    throw new Error('ablation_resume_git_head_changed');
  }
  const prior = new Map(previous.files.map((entry) => [entry.path, entry]));
  const next = new Map(current.files.map((entry) => [entry.path, entry]));
  if (prior.size !== previous.files.length || next.size !== current.files.length) {
    throw new Error('ablation_source_manifest_duplicate_path');
  }
  const paths = [...new Set([...prior.keys(), ...next.keys()])].sort();
  return paths.flatMap((relativePath) => {
    const before = prior.get(relativePath) || null;
    const after = next.get(relativePath) || null;
    if (before?.bytes === after?.bytes && before?.sha256 === after?.sha256) return [];
    return [{ path: relativePath, before, after }];
  });
}

export function assertResumeSourceChanges(changes) {
  for (const change of changes) {
    if (!RESUME_LIFECYCLE_FILES.has(change.path) || !change.before || !change.after) {
      throw new Error(`ablation_resume_scientific_source_changed:${change.path}`);
    }
  }
  return changes;
}

function resumeSourceBinding(outputDir, runId, binding, currentManifest) {
  const bindingFile = path.join(outputDir, 'clone-binding.json');
  if (!existsSync(bindingFile)) {
    writeImmutableJson(bindingFile, binding);
    return {
      initial_manifest: currentManifest,
      current_manifest: currentManifest,
      amendment: null,
    };
  }
  const retainedBytes = readFileSync(bindingFile);
  const retained = JSON.parse(retainedBytes.toString('utf8'));
  if (retained.protocol !== PROTOCOL || retained.run_id !== runId) {
    throw new Error('ablation_resume_clone_binding_identity_mismatch');
  }
  if (retained.source?.memory_root_sha256 !== binding.source.memory_root_sha256
    || retained.source?.classification_root_sha256 !== binding.source.classification_root_sha256
    || retained.clone_before?.memory_root_sha256 !== binding.clone_before.memory_root_sha256
    || retained.clone_before?.classification_root_sha256 !== binding.clone_before.classification_root_sha256
    || JSON.stringify(retained.canonical_before) !== JSON.stringify(binding.canonical_before)) {
    throw new Error('ablation_resume_clone_binding_root_mismatch');
  }
  const changes = assertResumeSourceChanges(
    sourceManifestDifferences(retained.source_manifest, currentManifest),
  );
  if (changes.length === 0) {
    return {
      initial_manifest: retained.source_manifest,
      current_manifest: currentManifest,
      amendment: null,
    };
  }
  const unsigned = {
    schema: 'hom.aimos.poisonedrag-epistemic-ablation-resume-amendment/v1',
    protocol: PROTOCOL,
    run_id: runId,
    clone_binding_sha256: sha256(retainedBytes),
    reason: 'immutable_provider_attempt_cursor_and_resume_binding_repair',
    scientific_contract_unchanged: true,
    completed_artifacts_reused: true,
    target_count: 100,
    arms: ['A0', 'A1', 'A2', 'A3'],
    generator_model: 'gpt-5.5',
    judge_model: 'gpt-5.6-terra',
    unchanged_by_manifest_equality: SOURCE_FILES.filter((file) => !RESUME_LIFECYCLE_FILES.has(file)),
    lifecycle_source_changes: changes,
  };
  const amendment = {
    ...unsigned,
    amendment_sha256: sha256(Buffer.from(JSON.stringify(unsigned), 'utf8')),
  };
  writeImmutableJson(path.join(outputDir, 'resume-amendment.json'), amendment);
  return {
    initial_manifest: retained.source_manifest,
    current_manifest: currentManifest,
    amendment,
  };
}

function artifactHashes(root) {
  const output = {};
  function walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute);
      if (entry.isSymbolicLink()) throw new Error(`ablation_artifact_symlink_forbidden:${relative}`);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && !['artifact-hashes.json', 'run-status.json'].includes(entry.name)) {
        output[relative] = sha256File(absolute);
      }
    }
  }
  walk(root);
  return Object.fromEntries(Object.entries(output).sort(([left], [right]) => left.localeCompare(right)));
}

function readJsonFile(file, errorCode) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new Error(errorCode);
  }
}

function assertExactProgress(progress, runId, targetCount) {
  const expected = {
    native_recalls_completed: targetCount * 2,
    native_recalls_total: targetCount * 2,
    retrieval_decisions_completed: targetCount * 2 * 4,
    retrieval_decisions_total: targetCount * 2 * 4,
    generations_completed: targetCount * 2 * 4,
    generations_total: targetCount * 2 * 4,
    judgments_completed: targetCount * 2 * 4 * 2,
    judgments_total: targetCount * 2 * 4 * 2,
  };
  if (progress?.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-progress/v1'
    || progress.run_id !== runId
    || progress.target_count !== targetCount
    || progress.phase !== 'complete') {
    throw new Error('ablation_terminal_progress_identity_invalid');
  }
  for (const [field, value] of Object.entries(expected)) {
    if (progress[field] !== value) {
      throw new Error(`ablation_terminal_progress_count_invalid:${field}:${progress[field]}:${value}`);
    }
  }
}

function verifyArtifactManifest(outputDir, manifest) {
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    throw new Error('ablation_terminal_artifact_manifest_invalid');
  }
  const root = path.resolve(outputDir);
  let verified = 0;
  for (const [relativePath, expectedHash] of Object.entries(manifest)) {
    if (!relativePath || !/^[0-9a-f]{64}$/.test(String(expectedHash || ''))) {
      throw new Error(`ablation_terminal_artifact_manifest_entry_invalid:${relativePath}`);
    }
    const absolute = path.resolve(root, relativePath);
    if (!absolute.startsWith(`${root}${path.sep}`)) {
      throw new Error(`ablation_terminal_artifact_path_escape:${relativePath}`);
    }
    if (!existsSync(absolute)) throw new Error(`ablation_terminal_artifact_missing:${relativePath}`);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`ablation_terminal_artifact_invalid:${relativePath}`);
    }
    if (sha256File(absolute) !== expectedHash) {
      throw new Error(`ablation_terminal_artifact_hash_mismatch:${relativePath}`);
    }
    verified += 1;
  }
  return verified;
}

export function validateCompletedRunArtifacts(outputDir, runId, targetCount = 100) {
  const progressFile = path.join(outputDir, 'poisonedrag-ablation', 'progress.json');
  if (!existsSync(progressFile)) return null;
  const progress = readJsonFile(progressFile, 'ablation_terminal_progress_invalid_json');
  if (progress.phase !== 'complete') return null;

  const summaryFile = path.join(outputDir, 'poisonedrag-ablation', 'summary.json');
  const planFile = path.join(outputDir, 'poisonedrag-ablation', 'execution-plan.json');
  const isolationFile = path.join(outputDir, 'isolation-proof.json');
  const manifestFile = path.join(outputDir, 'artifact-hashes.json');
  for (const file of [summaryFile, planFile, isolationFile, manifestFile]) {
    if (!existsSync(file)) throw new Error(`ablation_terminal_artifact_set_incomplete:${path.basename(file)}`);
  }

  assertExactProgress(progress, runId, targetCount);
  const summary = readJsonFile(summaryFile, 'ablation_terminal_summary_invalid_json');
  if (summary.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-summary/v1'
    || summary.protocol !== PROTOCOL
    || summary.run_id !== runId
    || summary.intended_n !== targetCount
    || summary.completed_n !== targetCount
    || summary.denominator_complete !== true
    || summary.artifact_sha256 !== selfHash(summary, 'artifact_sha256')
    || progress.summary_sha256 !== summary.artifact_sha256) {
    throw new Error('ablation_terminal_summary_invalid');
  }

  const plan = readJsonFile(planFile, 'ablation_terminal_plan_invalid_json');
  if (plan.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-plan/v1'
    || plan.protocol !== PROTOCOL
    || plan.run_id !== runId
    || plan.target_count !== targetCount
    || plan.confirmatory !== true
    || JSON.stringify(plan.retrieval_arms) !== JSON.stringify(['A0', 'A1', 'A2', 'A3'])
    || JSON.stringify(plan.model_arms) !== JSON.stringify(['A0', 'A1', 'A2', 'A3'])
    || plan.generator !== 'codex:gpt-5.5'
    || plan.generator_reasoning !== 'medium'
    || plan.judge !== 'codex:gpt-5.6-terra'
    || plan.judge_reasoning !== 'high'
    || plan.retrieval_decisions !== targetCount * 2 * 4
    || plan.generations !== targetCount * 2 * 4
    || plan.judgments !== targetCount * 2 * 4 * 2
    || plan.plan_sha256 !== selfHash(plan, 'plan_sha256')
    || summary.execution_plan_sha256 !== plan.plan_sha256) {
    throw new Error('ablation_terminal_plan_invalid');
  }

  const isolation = readJsonFile(isolationFile, 'ablation_terminal_isolation_invalid_json');
  const unsignedIsolation = { ...isolation };
  delete unsignedIsolation.isolation_sha256;
  if (isolation.protocol !== PROTOCOL
    || isolation.run_id !== runId
    || isolation.source_run_id !== SOURCE_RUN_ID
    || isolation.clone_retained_for_signed_purge !== true
    || isolation.memory_root_unchanged !== true
    || isolation.classification_root_unchanged !== true
    || isolation.signed_classification_rows_unchanged !== 504
    || isolation.ablation_decision_event_rows !== targetCount * 2 * 4
    || isolation.canonical_benchmark_footprint_unchanged !== true
    || isolation.clone_before?.memory_root_sha256 !== isolation.clone_after?.memory_root_sha256
    || isolation.clone_before?.classification_root_sha256
      !== isolation.clone_after?.classification_root_sha256
    || JSON.stringify(isolation.canonical_before) !== JSON.stringify(isolation.canonical_after)
    || isolation.isolation_sha256 !== sha256(Buffer.from(JSON.stringify(unsignedIsolation), 'utf8'))) {
    throw new Error('ablation_terminal_isolation_invalid');
  }

  const manifest = readJsonFile(manifestFile, 'ablation_terminal_artifact_manifest_invalid_json');
  const verifiedArtifacts = verifyArtifactManifest(outputDir, manifest);
  for (const relativePath of [
    'poisonedrag-ablation/progress.json',
    'poisonedrag-ablation/execution-plan.json',
    'poisonedrag-ablation/summary.json',
    'isolation-proof.json',
  ]) {
    if (!manifest[relativePath]) {
      throw new Error(`ablation_terminal_required_manifest_entry_missing:${relativePath}`);
    }
  }

  return {
    run_id: runId,
    target_count: targetCount,
    verified_artifacts: verifiedArtifacts,
    summary_artifact_sha256: summary.artifact_sha256,
    summary_file_sha256: sha256File(summaryFile),
    execution_plan_sha256: plan.plan_sha256,
    isolation_sha256: isolation.isolation_sha256,
    isolation_file_sha256: sha256File(isolationFile),
    artifact_manifest_sha256: sha256File(manifestFile),
    completed_at: progress.updated_at,
  };
}

function reconcileCompletedStatus(outputDir, runId, databaseName, evidence) {
  const statusFile = path.join(outputDir, 'run-status.json');
  const previousStatusBytes = existsSync(statusFile) ? readFileSync(statusFile) : null;
  const previousStatus = previousStatusBytes
    ? readJsonFile(statusFile, 'ablation_terminal_previous_status_invalid_json')
    : null;
  const reconciliationFile = path.join(outputDir, 'completion-reconciliation.json');
  let reconciliation = existsSync(reconciliationFile)
    ? readJsonFile(reconciliationFile, 'ablation_terminal_reconciliation_invalid_json')
    : null;
  if (reconciliation) {
    if (reconciliation.schema !== 'hom.aimos.poisonedrag-epistemic-ablation-completion-reconciliation/v1'
      || reconciliation.protocol !== PROTOCOL
      || reconciliation.run_id !== runId
      || reconciliation.reconciliation_sha256 !== selfHash(reconciliation, 'reconciliation_sha256')) {
      throw new Error('ablation_terminal_reconciliation_invalid');
    }
  } else if (previousStatus?.state !== 'complete' || previousStatus?.phase !== 'complete') {
    const unsigned = {
      schema: 'hom.aimos.poisonedrag-epistemic-ablation-completion-reconciliation/v1',
      protocol: PROTOCOL,
      run_id: runId,
      reason: 'terminal_artifacts_verified_before_resume_source_binding',
      previous_status: previousStatus,
      previous_status_file_sha256: previousStatusBytes ? sha256(previousStatusBytes) : null,
      terminal_evidence: evidence,
      reconciled_at: new Date().toISOString(),
    };
    reconciliation = {
      ...unsigned,
      reconciliation_sha256: selfHash(unsigned, 'reconciliation_sha256'),
    };
    writeImmutableJson(reconciliationFile, reconciliation);
  }
  if (previousStatus?.state !== 'complete' || previousStatus?.phase !== 'complete') {
    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'complete',
      phase: 'complete',
      resumable: false,
      clone_retained_for_signed_purge: true,
      terminal_evidence_verified: true,
      terminal_summary_sha256: evidence.summary_artifact_sha256,
      terminal_isolation_sha256: evidence.isolation_sha256,
      completion_reconciliation_sha256: reconciliation?.reconciliation_sha256 || null,
    });
  }
  return reconciliation;
}

async function main() {
  const args = parseOrchestratorArgs(process.argv);
  const runId = args.resumeRun || runIdNow();
  const databaseName = `aimos_benchmark_${runId}`;
  const outputDir = path.join(OUTPUT_ROOT, runId);
  const logsDir = path.join(outputDir, 'logs');
  const origin = `http://127.0.0.1:${args.port}`;
  mkdirSync(logsDir, { recursive: true, mode: 0o700 });
  if (args.resumeRun) {
    const terminalEvidence = validateCompletedRunArtifacts(outputDir, runId, args.targetCount);
    if (terminalEvidence) {
      const reconciliation = reconcileCompletedStatus(
        outputDir,
        runId,
        databaseName,
        terminalEvidence,
      );
      console.log(JSON.stringify({
        success: true,
        already_complete: true,
        output_dir: outputDir,
        terminal_evidence: terminalEvidence,
        completion_reconciliation_sha256: reconciliation?.reconciliation_sha256 || null,
      }, null, 2));
      return;
    }
  }
  const sharedSnapshots = [
    snapshotFile(HOUSEKEEPER_CERT_CACHE),
    snapshotFile(ARCHITECTURE_AUTHORITY),
  ];
  let server = null;
  const restoreShared = () => {
    for (const snapshot of sharedSnapshots) restoreFile(snapshot);
  };
  const cleanup = async () => {
    await stopChild(server);
    server = null;
    restoreShared();
  };
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, async () => {
      await cleanup();
      process.exitCode = 130;
    });
  }

  writeStatus(outputDir, {
    run_id: runId,
    database_name: databaseName,
    source_run_id: SOURCE_RUN_ID,
    state: 'running',
    phase: 'prepare',
    resumable: true,
  });

  try {
    if (!await databaseExists(SOURCE_DATABASE)) throw new Error('ablation_source_database_missing');
    const sourceEvidence = await databaseEvidence(SOURCE_DATABASE);
    if (sourceEvidence.classification_rows !== 504) {
      throw new Error(`ablation_source_classification_count_mismatch:${sourceEvidence.classification_rows}`);
    }
    if (!await databaseExists(databaseName)) {
      writeStatus(outputDir, {
        run_id: runId,
        database_name: databaseName,
        source_run_id: SOURCE_RUN_ID,
        state: 'running',
        phase: 'clone-source-brain',
        resumable: true,
      });
      await cloneSourceDatabase(databaseName);
    }
    const cloneBefore = await databaseEvidence(databaseName);
    if (cloneBefore.memory_root_sha256 !== sourceEvidence.memory_root_sha256
      || cloneBefore.classification_root_sha256 !== sourceEvidence.classification_root_sha256
      || cloneBefore.memory_rows !== sourceEvidence.memory_rows
      || cloneBefore.classification_rows !== sourceEvidence.classification_rows) {
      throw new Error('ablation_clone_source_binding_failed');
    }
    const canonicalBefore = await canonicalBenchmarkFootprint();
    const sourceManifest = sourceFileManifest();
    const sourceBinding = resumeSourceBinding(outputDir, runId, {
      protocol: PROTOCOL,
      run_id: runId,
      source: sourceEvidence,
      clone_before: cloneBefore,
      canonical_before: canonicalBefore,
      source_manifest: sourceManifest,
    }, sourceManifest);

    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'running',
      phase: 'retrieval',
      resumable: true,
    });
    server = spawnLogged(process.execPath, [
      'server.js',
      '--aimos-db',
      databaseName,
      '--aimos-port',
      String(args.port),
    ], path.join(logsDir, 'server.log'), { finite: false });
    const health = await waitForServer(origin, databaseName, server);
    await spawnLogged(process.execPath, [
      'eval/run-poisonedrag-epistemic-ablation.mjs',
      '--run-id',
      runId,
      '--run-dir',
      outputDir,
      '--phase',
      'retrieve',
      '--target-count',
      String(args.targetCount),
      '--retries',
      String(args.retries),
      '--aimos-base',
      origin,
      '--aimos-db',
      databaseName,
      '--aimos-port',
      String(args.port),
    ], path.join(logsDir, 'ablation-retrieval.log'));
    await stopChild(server);
    server = null;
    restoreShared();

    const cloneAfterRetrieval = await databaseEvidence(databaseName);
    if (cloneAfterRetrieval.memory_root_sha256 !== cloneBefore.memory_root_sha256
      || cloneAfterRetrieval.classification_root_sha256 !== cloneBefore.classification_root_sha256
      || cloneAfterRetrieval.classification_rows !== 504) {
      throw new Error('ablation_retrieval_mutated_canonical_memory_or_classification');
    }
    const expectedDecisionEvents = args.targetCount * 2 * 4;
    if (cloneAfterRetrieval.ablation_decision_event_rows !== expectedDecisionEvents) {
      throw new Error(
        `ablation_retrieval_ledger_count_invalid:${cloneAfterRetrieval.ablation_decision_event_rows}:${expectedDecisionEvents}`,
      );
    }

    const preflightReceipt = path.join(outputDir, 'model-access-preflight.json');
    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'running',
      phase: 'model-access-preflight',
      resumable: true,
    });
    if (!existsSync(preflightReceipt)) {
      await spawnLogged(process.execPath, [
        'scripts/ceremony/benchmark-model-preflight.mjs',
        '--live',
        '--generator-model',
        'gpt-5.5',
        '--receipt-file',
        preflightReceipt,
      ], path.join(logsDir, 'model-access-preflight.log'));
    }

    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'running',
      phase: 'model-aggregate',
      resumable: true,
    });
    await spawnLogged(process.execPath, [
      'eval/run-poisonedrag-epistemic-ablation.mjs',
      '--run-id',
      runId,
      '--run-dir',
      outputDir,
      '--phase',
      'model-aggregate',
      '--target-count',
      String(args.targetCount),
      '--retries',
      String(args.retries),
    ], path.join(logsDir, 'ablation-model-aggregate.log'));

    const cloneAfter = await databaseEvidence(databaseName);
    const canonicalAfter = await canonicalBenchmarkFootprint();
    if (cloneAfter.memory_root_sha256 !== cloneBefore.memory_root_sha256
      || cloneAfter.classification_root_sha256 !== cloneBefore.classification_root_sha256
      || cloneAfter.classification_rows !== 504) {
      throw new Error('ablation_close_memory_or_classification_root_changed');
    }
    if (JSON.stringify(canonicalBefore) !== JSON.stringify(canonicalAfter)) {
      throw new Error('ablation_canonical_benchmark_footprint_changed');
    }
    const isolation = {
      protocol: PROTOCOL,
      run_id: runId,
      source_run_id: SOURCE_RUN_ID,
      source_database: SOURCE_DATABASE,
      clone_database: databaseName,
      clone_retained_for_signed_purge: true,
      source: sourceEvidence,
      clone_before: cloneBefore,
      clone_after_retrieval: cloneAfterRetrieval,
      clone_after: cloneAfter,
      memory_root_unchanged: true,
      classification_root_unchanged: true,
      signed_classification_rows_unchanged: 504,
      event_rows_appended_since_source_clone: cloneAfter.event_rows - sourceEvidence.event_rows,
      ablation_decision_event_rows: cloneAfter.ablation_decision_event_rows,
      canonical_before: canonicalBefore,
      canonical_after: canonicalAfter,
      canonical_benchmark_footprint_unchanged: true,
      health,
      initial_source_manifest: sourceBinding.initial_manifest,
      source_manifest: sourceBinding.current_manifest,
      resume_amendment: sourceBinding.amendment,
    };
    isolation.isolation_sha256 = sha256(Buffer.from(JSON.stringify(isolation), 'utf8'));
    writeFileSync(
      path.join(outputDir, 'isolation-proof.json'),
      `${JSON.stringify(isolation, null, 2)}\n`,
      { mode: 0o600 },
    );
    writeFileSync(
      path.join(outputDir, 'reproduce-command.txt'),
      `node scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs --resume-run ${runId} --port ${args.port} --retries ${args.retries}\n`,
      { mode: 0o600 },
    );
    writeFileSync(
      path.join(outputDir, 'artifact-hashes.json'),
      `${JSON.stringify(artifactHashes(outputDir), null, 2)}\n`,
      { mode: 0o600 },
    );
    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'complete',
      phase: 'complete',
      resumable: false,
      clone_retained_for_signed_purge: true,
    });
    console.log(JSON.stringify({ success: true, output_dir: outputDir, isolation }, null, 2));
  } catch (error) {
    writeStatus(outputDir, {
      run_id: runId,
      database_name: databaseName,
      source_run_id: SOURCE_RUN_ID,
      state: 'failed',
      phase: 'failed',
      resumable: true,
      error: {
        name: String(error?.name || 'Error').slice(0, 128),
        message: String(error?.message || error).slice(0, 2000),
      },
      resume_command: `node scripts/benchmark/run-poisonedrag-epistemic-ablation.mjs --resume-run ${runId} --port ${args.port} --retries ${args.retries}`,
    });
    throw error;
  } finally {
    await cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
