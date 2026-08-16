#!/usr/bin/env node

/**
 * Read-only live measurement for the existing Concept/PPR baseline.
 *
 * This script reads the canonical HOM-AIMOS database and executes the existing
 * hybridRetrieve export with fixed diagnostic queries. It does not call a save
 * path, mutate graph state, change ranking constants, or activate GAAMA.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { getEmbedding } from '../../services/core/embeddings.js';
import { hybridRetrieve } from '../../services/core/concept-graph.js';
import { AIMOS_COMPANY_ID } from '../../services/core/runtime-config.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const LIVE = process.argv.includes('--live');
const OUTPUT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'concept-gaama');
const REGISTRATION_FILE = path.join(
  ROOT,
  'plans',
  'Codex',
  'active',
  'graphs',
  'CONCEPT-GAAMA-LIVE-BASELINE-PREREGISTRATION-20260810.md',
);

const FIXED_QUERIES = Object.freeze([
  'HOM AIMOS persistent memory retrieval provenance',
  'cryptographically authorized memory mutation history',
  'agent memory poison classification and signed evidence',
  'session continuity recall across conversations',
  'graph retrieval bridge between related memories',
]);
const RANK_EPSILON = 1e-12;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function round(value) {
  return Number(Number(value).toFixed(9));
}

function mean(values) {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function memoryIdCommitment(id) {
  return sha256(`hom-aimos/concept-ppr-baseline-node/v1\0${id}`);
}

async function inventory() {
  const result = await pool.query(
    `SELECT
       current_database() AS database,
       (SELECT count(*)::int FROM aimos_memories WHERE company_id = $1) AS memories,
       (SELECT count(embedding)::int FROM aimos_memories WHERE company_id = $1) AS embedded_memories,
       (SELECT count(*)::int FROM aimos_memories WHERE company_id = $1 AND node_type = 'concept') AS concept_nodes,
       (SELECT count(*)::int FROM concept_edges WHERE company_id = $1) AS concept_edges`,
    [AIMOS_COMPANY_ID],
  );
  return result.rows[0];
}

async function edgeTypes() {
  const result = await pool.query(
    `SELECT edge_type,
            count(*)::int AS count,
            min(weight)::float8 AS min_weight,
            max(weight)::float8 AS max_weight
       FROM concept_edges
      WHERE company_id = $1
      GROUP BY edge_type
      ORDER BY edge_type`,
    [AIMOS_COMPANY_ID],
  );
  return result.rows;
}

async function measureQuery(queryText) {
  const embedding = await getEmbedding(queryText);
  if (!Array.isArray(embedding) || embedding._degraded) {
    throw new Error('concept_ppr_baseline_embedding_unavailable');
  }

  const started = process.hrtime.bigint();
  const results = await hybridRetrieve(
    queryText,
    AIMOS_COMPANY_ID,
    10,
    embedding,
  );
  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
  const cosineOrder = [...results].sort((left, right) =>
    Number(right.cosine) - Number(left.cosine)
    || String(left.id).localeCompare(String(right.id))
  );
  const cosineRank = new Map(cosineOrder.map((row, index) => [row.id, index + 1]));
  const deltas = results.map((row) => Number(row.score) - Number(row.cosine));
  const tieOrderDifferences = results.filter(
    (row, index) => cosineRank.get(row.id) !== index + 1,
  ).length;
  let strictPairwiseInversions = 0;
  for (let left = 0; left < results.length; left += 1) {
    for (let right = left + 1; right < results.length; right += 1) {
      if (Number(results[right].cosine) - Number(results[left].cosine) > RANK_EPSILON) {
        strictPairwiseInversions += 1;
      }
    }
  }
  const maximumCosine = Math.max(...results.map((row) => Number(row.cosine)));

  return {
    query_sha256: sha256(`hom-aimos/concept-ppr-baseline-query/v1\0${queryText}`),
    latency_ms: round(latencyMs),
    returned_candidates: results.length,
    nonzero_ppr_candidates: results.filter((row) => Number(row.ppr) > 0).length,
    graph_only_candidates: results.filter((row) => Number(row.cosine) === 0).length,
    strict_pairwise_rank_inversions_vs_cosine: strictPairwiseInversions,
    strict_top1_changed_vs_cosine:
      results.length > 0
      && maximumCosine - Number(results[0].cosine) > RANK_EPSILON,
    tie_order_differences_vs_id_tiebreak: tieOrderDifferences,
    score_delta_over_cosine: {
      min: round(deltas.length ? Math.min(...deltas) : 0),
      max: round(deltas.length ? Math.max(...deltas) : 0),
      mean: round(mean(deltas)),
    },
    returned_id_commitments: results.map((row) => memoryIdCommitment(row.id)),
  };
}

function writeExclusive(artifact) {
  fs.mkdirSync(OUTPUT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT_DIRECTORY, 0o700);
  const stamp = artifact.measured_at.replaceAll(/[-:.]/g, '').replace('Z', 'Z');
  const target = path.join(OUTPUT_DIRECTORY, `concept-ppr-live-baseline-${stamp}.json`);
  const body = `${JSON.stringify(artifact, null, 2)}\n`;
  const descriptor = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, body, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return { path: target, sha256: sha256(body), bytes: Buffer.byteLength(body) };
}

async function main() {
  const sources = {
    registration_sha256: sha256(fs.readFileSync(REGISTRATION_FILE)),
    script_sha256: sha256(fs.readFileSync(SCRIPT_FILE)),
    concept_graph_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/core/concept-graph.js'))),
    native_recall_pipeline_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/retrieval/native-recall-pipeline.js'))),
    gaama_candidate_sha256: sha256(fs.readFileSync(path.join(ROOT, 'services/core/gaama-candidate/gaama-dormant-candidate.js'))),
  };

  console.log(JSON.stringify({
    mode: LIVE ? 'LIVE_READ_ONLY' : 'DRY_RUN',
    company_id: AIMOS_COMPANY_ID,
    fixed_query_count: FIXED_QUERIES.length,
    sources,
  }, null, 2));
  if (!LIVE) return;

  const before = await inventory();
  const types = await edgeTypes();
  const queries = [];
  for (const queryText of FIXED_QUERIES) {
    queries.push(await measureQuery(queryText));
  }
  const after = await inventory();
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error('concept_ppr_baseline_read_only_inventory_changed');
  }

  const artifact = {
    schema: 'hom-aimos/concept-ppr-live-baseline/v2',
    measured_at: new Date().toISOString(),
    mode: 'LIVE_READ_ONLY',
    company_id: AIMOS_COMPANY_ID,
    sources,
    inventory_before: before,
    inventory_after: after,
    edge_types: types,
    fixed_query_count: FIXED_QUERIES.length,
    query_measurements: queries,
    aggregate: {
      total_returned_candidates: queries.reduce((sum, row) => sum + row.returned_candidates, 0),
      total_nonzero_ppr_candidates: queries.reduce((sum, row) => sum + row.nonzero_ppr_candidates, 0),
      total_graph_only_candidates: queries.reduce((sum, row) => sum + row.graph_only_candidates, 0),
      total_strict_pairwise_rank_inversions_vs_cosine: queries.reduce(
        (sum, row) => sum + row.strict_pairwise_rank_inversions_vs_cosine,
        0,
      ),
      strict_top1_changes_vs_cosine: queries.filter(
        (row) => row.strict_top1_changed_vs_cosine,
      ).length,
      tie_order_differences_vs_id_tiebreak: queries.reduce(
        (sum, row) => sum + row.tie_order_differences_vs_id_tiebreak,
        0,
      ),
      mean_query_latency_ms: round(mean(queries.map((row) => row.latency_ms))),
    },
    interpretation_boundary: {
      zero_edges_means_no_graph_traversal: Number(before.concept_edges) === 0,
      ppr_teleport_residual_is_not_graph_discovery: true,
      final_ranking_utility_claimed: false,
      gaama_candidate_activated: false,
      database_mutation_performed: false,
    },
  };
  const output = writeExclusive(artifact);
  console.log(JSON.stringify({ success: true, artifact: output, aggregate: artifact.aggregate }, null, 2));
}

try {
  await main();
} finally {
  await pool.end();
}
