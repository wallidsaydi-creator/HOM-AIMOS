#!/usr/bin/env node

/**
 * Build the append-only, source-bound QuIM and Concept/PPR projections.
 *
 * This ceremony never activates a build. It produces housekeeper-attested
 * derived rows and returns the exact policy values that a separate T0-signed
 * system-configuration ceremony may select. Re-execution reuses an existing
 * complete build instead of duplicating it.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';
import {
  buildConceptPprGraph,
  CONCEPT_PPR_ITERATIONS,
  CONCEPT_SYNONYM_THRESHOLD,
  CONCEPT_MAX_SYNONYMS_PER_NODE,
} from '../../services/retrieval/concept-ppr-native.js';
import {
  buildQuimIndex,
  QUIM_TOP_QUESTIONS,
} from '../../services/retrieval/quim-index.js';
import {
  CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
  QUIM_RETRIEVAL_POLICY_VERSION,
} from '../../services/security/system-config-ledger.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUTPUT_ROOT = path.join(ROOT, 'artifacts', 'retrieval', 'native-derived-builds');
const COMPANY = 'hom';
const REQUIRED_MIGRATIONS = Object.freeze([
  '094-native-retrieval-temporal-neighborhood-index.sql',
  '095-native-quim-and-concept-ppr-projections.sql',
]);
const SOURCE_FILES = Object.freeze([
  'scripts/ceremony/build-native-derived-retrieval.mjs',
  'services/retrieval/quim-index.js',
  'services/retrieval/concept-ppr-native.js',
  'services/security/system-config-ledger.js',
  'migrations/094-native-retrieval-temporal-neighborhood-index.sql',
  'migrations/095-native-quim-and-concept-ppr-projections.sql',
]);

function fail(code) {
  throw new Error(`native_derived_retrieval_build:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileSha256(file) {
  return sha256(fs.readFileSync(file));
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([, field]) => field !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, field]) => [key, canonical(field)]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

async function preflight(database) {
  const migrations = await pool.query(
    `SELECT filename, checksum FROM schema_migrations
      WHERE filename = ANY($1::text[]) ORDER BY filename`,
    [REQUIRED_MIGRATIONS],
  );
  const tableNames = [
    'quim_index_builds',
    'quim_prototypes',
    'quim_index',
    'concept_graph_builds',
    'concept_graph_nodes',
    'concept_passage_edges',
    'concept_relation_edges',
  ];
  const tables = await pool.query(
    `SELECT name, to_regclass('public.' || name) IS NOT NULL AS present
       FROM unnest($1::text[]) AS name ORDER BY name`,
    [tableNames],
  );
  const population = await pool.query(
    `SELECT COUNT(*)::int AS memories,
            COUNT(*) FILTER (WHERE embedding IS NOT NULL)::int AS embedded_memories,
            (SELECT COUNT(*)::int FROM entity_memory_edges WHERE company_id=$1) AS entity_edges
       FROM aimos_memories WHERE company_id=$1`,
    [COMPANY],
  );
  const migrationReady = migrations.rowCount === REQUIRED_MIGRATIONS.length
    && migrations.rows.every((row) => /^[0-9a-f]{64}$/.test(String(row.checksum || '')));
  const tableReady = tables.rows.every((row) => row.present === true);
  return Object.freeze({
    database,
    migration_ready: migrationReady,
    applied_migrations: migrations.rows,
    tables: tables.rows,
    table_ready: tableReady,
    population: population.rows[0],
    activation_performed: false,
  });
}

async function latestQuimBuild() {
  const result = await pool.query(
    `SELECT build_id::text, encode(corpus_root_sha256,'hex') AS corpus_root_sha256,
            encode(index_root_sha256,'hex') AS index_root_sha256, memory_count,
            chunk_count, question_count, prototype_count, max_bucket_size,
            authority_event_id::text
       FROM quim_index_builds WHERE company_id=$1
      ORDER BY created_at DESC, build_id DESC LIMIT 1`,
    [COMPANY],
  );
  if (result.rowCount !== 1) return null;
  const row = result.rows[0];
  return Object.freeze({
    success: true,
    reused_existing_complete_build: true,
    ...row,
    policy: {
      version: QUIM_RETRIEVAL_POLICY_VERSION,
      build_id: row.build_id,
      corpus_root_sha256: row.corpus_root_sha256,
      index_root_sha256: row.index_root_sha256,
      prototype_count: Number(row.prototype_count),
      top_questions: QUIM_TOP_QUESTIONS,
      max_bucket_scan: Number(row.max_bucket_size),
    },
  });
}

async function latestConceptBuild() {
  const result = await pool.query(
    `SELECT build_id::text, encode(corpus_root_sha256,'hex') AS corpus_root_sha256,
            encode(graph_root_sha256,'hex') AS graph_root_sha256, memory_count,
            concept_count, passage_edge_count, relation_edge_count,
            authority_event_id::text
       FROM concept_graph_builds WHERE company_id=$1
      ORDER BY created_at DESC, build_id DESC LIMIT 1`,
    [COMPANY],
  );
  if (result.rowCount !== 1) return null;
  const row = result.rows[0];
  return Object.freeze({
    success: true,
    reused_existing_complete_build: true,
    ...row,
    policy: {
      version: CONCEPT_PPR_RETRIEVAL_POLICY_VERSION,
      build_id: row.build_id,
      corpus_root_sha256: row.corpus_root_sha256,
      graph_root_sha256: row.graph_root_sha256,
      damping: '1/2',
      iterations: CONCEPT_PPR_ITERATIONS,
      entity_seed_limit: 5,
      passage_limit: 20,
      synonym_threshold_q6: Math.round(CONCEPT_SYNONYM_THRESHOLD * 1_000_000),
      max_synonyms_per_node: CONCEPT_MAX_SYNONYMS_PER_NODE,
      max_ppr_nodes: Number(row.concept_count),
      max_ppr_edges: Number(row.relation_edge_count),
    },
  });
}

function writeReceipt(database, body) {
  const bodySha256 = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const receipt = { ...body, receipt_body_sha256: bodySha256 };
  const directory = path.join(OUTPUT_ROOT, database);
  const file = path.join(directory, `native-derived-build-${bodySha256}.json`);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${canonicalJson(receipt)}\n`, { flag: 'wx', mode: 0o600 });
  return Object.freeze({ path: file, sha256: fileSha256(file) });
}

async function main() {
  const explicitDatabase = process.argv.includes('--aimos-db')
    || process.argv.some((argument) => argument.startsWith('--aimos-db='));
  if (!explicitDatabase) fail('explicit_aimos_database_required');
  const database = resolveAimosDatabaseName();
  const before = await preflight(database);
  console.log(JSON.stringify({ mode: process.argv.includes('--live') ? 'LIVE' : 'PREFLIGHT', ...before }, null, 2));
  if (!before.migration_ready || !before.table_ready) fail('migrations_094_095_required');
  if (!process.argv.includes('--live')) return;

  const quim = await latestQuimBuild() || await buildQuimIndex(COMPANY);
  const conceptPpr = await latestConceptBuild() || await buildConceptPprGraph(COMPANY);
  const after = await preflight(database);
  const sourceManifest = SOURCE_FILES.map((relativePath) => ({
    path: relativePath,
    sha256: fileSha256(path.join(ROOT, relativePath)),
  }));
  const body = {
    schema: 'hom.aimos.native-derived-retrieval-build-receipt/v1',
    completed_at: new Date().toISOString(),
    database,
    company_id: COMPANY,
    source_manifest: sourceManifest,
    source_closure_sha256: sha256(Buffer.from(canonicalJson(sourceManifest), 'utf8')),
    before,
    quim,
    concept_ppr: conceptPpr,
    after,
    canonical_memory_changed: false,
    retention_changed: false,
    policy_activation_performed: false,
    next: 'Commit both returned policy objects through a T0-signed system-config ceremony, then restart only the target runtime before proof.',
  };
  const receipt = writeReceipt(database, body);
  console.log(JSON.stringify({ success: true, receipt, quim_policy: quim.policy, concept_ppr_policy: conceptPpr.policy, policy_activation_performed: false }, null, 2));
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error?.stack || error}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end().catch(() => {});
  });
