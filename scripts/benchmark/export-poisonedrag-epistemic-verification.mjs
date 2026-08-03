#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { wilsonInterval } from '../../eval/poisonedrag/harness.mjs';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';

const { Pool } = pg;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RESULTS_ROOT = path.join(ROOT, 'eval', 'public-results');
const OUTPUT_ROOT = path.join(ROOT, 'eval', 'publication');
const RUN_ID_PATTERN = /^20[0-9]{12}_[0-9a-f]{6}$/;
const DATABASE_PATTERN = /^aimos_benchmark_20[0-9]{12}_[0-9a-f]{6}$/;
const ADVERSE_LABELS = new Set(['poison_suspect', 'poison_likely', 'poison_confirmed']);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function readRegularFile(file) {
  if (!existsSync(file) || lstatSync(file).isSymbolicLink() || !statSync(file).isFile()) {
    throw new Error(`epistemic_verification_source_invalid:${path.relative(ROOT, file)}`);
  }
  return readFileSync(file);
}

function readJson(file) {
  return JSON.parse(readRegularFile(file).toString('utf8'));
}

function parseRunId(argv = process.argv.slice(2)) {
  const index = argv.indexOf('--run-id');
  const runId = index >= 0 ? argv[index + 1] : null;
  if (!RUN_ID_PATTERN.test(String(runId || ''))) {
    throw new Error('epistemic_verification_run_id_required');
  }
  return runId;
}

function databaseUrl(databaseName) {
  const url = new URL(resolveAimosDatabaseUrl([]));
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function increment(target, key) {
  target[key] = (target[key] || 0) + 1;
}

function selfHash(value) {
  const unsigned = { ...value };
  delete unsigned.epistemic_verification_sha256;
  return sha256(JSON.stringify(unsigned));
}

async function main() {
  const runId = parseRunId();
  const runDir = path.join(RESULTS_ROOT, runId);
  const status = readJson(path.join(runDir, 'run-status.json'));
  if (status.schema !== 'hom.canonical-benchmark-run-status/v1'
    || status.run_id !== runId
    || status.state !== 'complete'
    || status.phase !== 'complete'
    || status.resumable !== false
    || !DATABASE_PATTERN.test(String(status.database_name || ''))) {
    throw new Error('epistemic_verification_run_incomplete_or_invalid');
  }

  const summaryFile = path.join(runDir, 'poisonedrag', 'summary.json');
  const summaryBytes = readRegularFile(summaryFile);
  const summary = JSON.parse(summaryBytes.toString('utf8'));
  if (summary.schema !== 'hom.aimos.poisonedrag-summary/v1'
    || summary.run_id !== runId
    || summary.completed_n !== 100
    || summary.denominator_complete !== true) {
    throw new Error('epistemic_verification_summary_invalid');
  }

  const pool = new Pool({
    connectionString: databaseUrl(status.database_name),
    ssl: false,
    connectionTimeoutMillis: 5_000,
  });

  let rows;
  let classificationRows;
  const client = await pool.connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(
      'SELECT set_config($1, $2, true)',
      ['app.current_client_id', 'hom'],
    );
    const result = await client.query(
      `SELECT
         m.id::text AS memory_id,
         encode(m.content_hash, 'hex') AS content_hash,
         (m.key LIKE '%:reference:poison:%') AS is_poison,
         m.current_epistemic_label,
         m.current_epistemic_confidence_milli,
         verification.ok,
         verification.chain_length,
         verification.current_label AS verified_current_label,
         verification.current_confidence_milli AS verified_current_confidence_milli,
         encode(verification.head_hash, 'hex') AS head_hash,
         verification.reason
       FROM public.aimos_memories m
       CROSS JOIN LATERAL public.verify_memory_epistemic_classification_chain(m.id) verification
       WHERE m.company_id = 'hom'
         AND m.source = 'benchmark:poisonedrag'
       ORDER BY m.id`,
    );
    rows = result.rows;
    const count = await client.query(
      `SELECT count(*)::integer AS count
         FROM public.aimos_memory_epistemic_classifications classification
         JOIN public.aimos_memories memory ON memory.id = classification.memory_id
        WHERE classification.company_id = 'hom'
          AND memory.company_id = 'hom'
          AND memory.source = 'benchmark:poisonedrag'`,
    );
    classificationRows = count.rows[0].count;
    await client.query('ROLLBACK');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
    await pool.end().catch(() => {});
  }

  const labelCounts = { poison: {}, clean: {} };
  const chainLengths = {};
  const reasons = {};
  let poisonRows = 0;
  let cleanRows = 0;
  let verified = 0;
  let poisonVerified = 0;
  let cleanVerified = 0;
  let poisonAdverse = 0;
  let cleanAdverse = 0;
  const rootRecords = [];

  for (const row of rows) {
    const kind = row.is_poison ? 'poison' : 'clean';
    if (row.is_poison) poisonRows += 1;
    else cleanRows += 1;
    increment(labelCounts[kind], row.current_epistemic_label);
    increment(chainLengths, String(row.chain_length));
    increment(reasons, row.reason || 'ok');
    if (row.ok) {
      verified += 1;
      if (row.is_poison) poisonVerified += 1;
      else cleanVerified += 1;
    }
    if (ADVERSE_LABELS.has(row.current_epistemic_label)) {
      if (row.is_poison) poisonAdverse += 1;
      else cleanAdverse += 1;
    }
    rootRecords.push({
      memory_ref_sha256: sha256(
        `hom.poisonedrag.epistemic-memory/v1\0${runId}\0${row.memory_id}`,
      ),
      content_hash: row.content_hash,
      memory_class: kind,
      current_label: row.current_epistemic_label,
      current_confidence_milli: row.current_epistemic_confidence_milli,
      chain_ok: row.ok,
      chain_length: row.chain_length,
      verified_current_label: row.verified_current_label,
      verified_current_confidence_milli: row.verified_current_confidence_milli,
      head_hash: row.head_hash || null,
      reason: row.reason || null,
    });
  }

  const result = {
    schema: 'hom.aimos.poisonedrag-epistemic-verification/v1',
    run_id: runId,
    source_summary_sha256: summary.summary_sha256,
    source_summary_file_sha256: sha256(summaryBytes),
    database_name_sha256: sha256(status.database_name),
    population: {
      unique_benchmark_memories: rows.length,
      poison_memories: poisonRows,
      clean_memories: cleanRows,
      classification_rows: classificationRows,
    },
    current_labels: labelCounts,
    poison_classification: {
      adverse_label_count: poisonAdverse,
      total: poisonRows,
      rate: poisonRows ? poisonAdverse / poisonRows : null,
      wilson_95: wilsonInterval(poisonAdverse, poisonRows),
      retained_not_deleted: true,
      canonical_content_unchanged_by_classification: true,
    },
    clean_false_positive: {
      definition: 'clean memory whose current signed epistemic label is poison_suspect, poison_likely, or poison_confirmed',
      count: cleanAdverse,
      total: cleanRows,
      rate: cleanRows ? cleanAdverse / cleanRows : null,
      wilson_95: wilsonInterval(cleanAdverse, cleanRows),
    },
    chain_verification: {
      checked: rows.length,
      verified,
      failed: rows.length - verified,
      poison_checked: poisonRows,
      poison_verified: poisonVerified,
      clean_checked: cleanRows,
      clean_verified: cleanVerified,
      chain_length_distribution: chainLengths,
      reason_counts: reasons,
      verifier: 'public.verify_memory_epistemic_classification_chain(uuid)',
    },
    verification_records_root_sha256: sha256(JSON.stringify(rootRecords)),
    disclosure_policy: 'Aggregate counts and a deterministic record root only; no memory IDs, dataset text, certificates, signatures, answers, or absolute paths.',
  };
  result.epistemic_verification_sha256 = selfHash(result);

  mkdirSync(OUTPUT_ROOT, { recursive: true });
  const outputFile = path.join(OUTPUT_ROOT, 'poisonedrag-epistemic-verification.json');
  writeFileSync(outputFile, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
  console.log(JSON.stringify({
    output_file: path.relative(ROOT, outputFile),
    run_id: runId,
    unique_benchmark_memories: rows.length,
    chains_verified: verified,
    poison_adverse_labels: `${poisonAdverse}/${poisonRows}`,
    clean_false_positives: `${cleanAdverse}/${cleanRows}`,
    epistemic_verification_sha256: result.epistemic_verification_sha256,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
