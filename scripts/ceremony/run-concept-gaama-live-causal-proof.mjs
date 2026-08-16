#!/usr/bin/env node

/**
 * Read-only paired causal proof for the current Concept/PPR baseline and the
 * dormant GAAMA candidate. The script is bound to one retained benchmark
 * scratch brain and cannot target canonical AIMOS.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { getEmbedding } from '../../services/core/embeddings.js';
import {
  compareHybridConceptResults,
  extractConcepts,
  localPPR,
} from '../../services/core/concept-graph.js';
import { runGaamaDormantCandidate } from '../../services/core/gaama-candidate/gaama-dormant-candidate.js';
import { scoreRetrievalEvidence } from '../../eval/aggregate-canonical-results.mjs';
import { exactMcNemarPValue, pairedBootstrap } from '../../eval/poisonedrag/harness.mjs';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const FIXED_DATABASE = 'aimos_benchmark_20260809163640_04a22c';
const FIXED_RUN = '20260809163640_04a22c';
const COMPANY = 'hom';
const LIMIT = 20;
const OPENING = 40;
const EXPECTED_QUESTION_COUNT = 840;
const EXPECTED_QUESTION_ID_SHA256 = '9ad0831310e6d4b5f5e865263f2c57dc6baf9bcee51e684021f7dfa2cb070f0a';
const BOOTSTRAP_REPLICATES = 10_000;
const OUTPUT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'concept-gaama');
const PREREGISTRATION = path.join(
  ROOT,
  'plans',
  'Codex',
  'active',
  'graphs',
  'CONCEPT-GAAMA-LIVE-CAUSAL-PREREGISTRATION-20260810.md',
);
const SELECTION_FILE = path.join(
  ROOT,
  'eval',
  'public-results',
  FIXED_RUN,
  'twin-prime-g5',
  'gate10',
  'selection.json',
);
const CORPUS_ROOT = path.join(ROOT, 'eval', 'data', 'twin-prime-g1p-canonical-v2');
const RANK_EPSILON = 1e-12;

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function round(value, digits = 9) {
  return Number(Number(value).toFixed(digits));
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + Number(value), 0) / values.length : null;
}

function percentile(values, probability) {
  const rows = values.map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (!rows.length) return null;
  const index = Math.min(rows.length - 1, Math.max(0, Math.ceil(probability * rows.length) - 1));
  return rows[index];
}

function normalCdf(value) {
  const sign = value < 0 ? -1 : 1;
  const x = Math.abs(value) / Math.sqrt(2);
  const t = 1 / (1 + (0.3275911 * x));
  const erf = sign * (1 - (((((1.061405429 * t - 1.453152027) * t + 1.421413741)
    * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x)));
  return 0.5 * (1 + erf);
}

function wilcoxonSignedRank(deltas) {
  const nonzero = deltas
    .map(Number)
    .filter(Number.isFinite)
    .filter((value) => Math.abs(value) > RANK_EPSILON)
    .map((value) => ({ value, absolute: Math.abs(value) }))
    .sort((left, right) => left.absolute - right.absolute);
  if (!nonzero.length) {
    return { n: 0, w_plus: 0, w_minus: 0, z: 0, two_sided_p: 1, rank_biserial: 0 };
  }
  let cursor = 0;
  while (cursor < nonzero.length) {
    let end = cursor + 1;
    while (end < nonzero.length && Math.abs(nonzero[end].absolute - nonzero[cursor].absolute) <= RANK_EPSILON) end += 1;
    const averageRank = ((cursor + 1) + end) / 2;
    for (let index = cursor; index < end; index += 1) nonzero[index].rank = averageRank;
    cursor = end;
  }
  const wPlus = nonzero.filter((row) => row.value > 0).reduce((sum, row) => sum + row.rank, 0);
  const wMinus = nonzero.filter((row) => row.value < 0).reduce((sum, row) => sum + row.rank, 0);
  const rankTotal = wPlus + wMinus;
  const expected = rankTotal / 2;
  const variance = nonzero.reduce((sum, row) => sum + (row.rank ** 2), 0) / 4;
  const continuity = wPlus === expected ? 0 : 0.5;
  const z = variance > 0
    ? (Math.abs(wPlus - expected) - continuity) / Math.sqrt(variance)
    : 0;
  return {
    n: nonzero.length,
    w_plus: round(wPlus),
    w_minus: round(wMinus),
    z: round(z),
    two_sided_p: round(Math.max(0, Math.min(1, 2 * (1 - normalCdf(Math.abs(z))))), 12),
    rank_biserial: rankTotal > 0 ? round((wPlus - wMinus) / rankTotal) : 0,
  };
}

function parseVector(value) {
  if (Array.isArray(value)) return value.map(Number);
  const raw = String(value || '').trim();
  if (!raw.startsWith('[') || !raw.endsWith(']')) return null;
  const parsed = raw.slice(1, -1).split(',').map(Number);
  return parsed.length && parsed.every(Number.isFinite) ? parsed : null;
}

function parseRecord(value) {
  try {
    const parsed = JSON.parse(String(value || ''));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function hydrate(rows, memoryById) {
  return rows.map((row) => {
    const memory = memoryById.get(row.id);
    const record = parseRecord(memory?.value);
    return {
      ...row,
      key: memory?.key,
      value: memory?.value,
      source: memory?.source,
      session_id: record.session_id || null,
    };
  });
}

function questionCommitment(rows) {
  return sha256(JSON.stringify(rows.map((row) => row.question_id)));
}

function rankCommitment(rows, domain) {
  return sha256(`${domain}\0${rows.map((row) => row.id).join('\0')}`);
}

function fileSha256(file) {
  return sha256(fs.readFileSync(file));
}

function sourceSessionMap(sessions, scopeId) {
  const scope = sessions.scopes.find((entry) => entry.scope_id === scopeId);
  assert(scope, `concept_gaama_scope_missing:${scopeId}`);
  return new Map(scope.sessions.map((session) => [session.source_session_id, session.session_id]));
}

function loadFixedQuestions() {
  const selection = JSON.parse(fs.readFileSync(SELECTION_FILE, 'utf8'));
  const sourceFilters = new Set(selection.entries.map((entry) => entry.source_filter));
  const questions = [];
  for (const benchmark of ['locomo', 'longmemeval']) {
    const corpus = JSON.parse(fs.readFileSync(path.join(CORPUS_ROOT, `${benchmark}-questions.json`), 'utf8'));
    questions.push(...corpus.questions.filter((question) => sourceFilters.has(question.source_filter)));
  }
  assert(sourceFilters.size === 9, 'concept_gaama_source_filter_count_mismatch');
  assert(questions.length === EXPECTED_QUESTION_COUNT, 'concept_gaama_question_count_mismatch');
  assert(questionCommitment(questions) === EXPECTED_QUESTION_ID_SHA256, 'concept_gaama_question_commitment_mismatch');
  return { questions, sourceFilters };
}

async function inventory(sourceFilters) {
  const sources = [...sourceFilters].sort();
  const memory = await pool.query(
    `SELECT count(*)::int AS memories,
            count(embedding)::int AS embedded_memories,
            count(*) FILTER (WHERE node_type = 'concept')::int AS concept_nodes
       FROM aimos_memories
      WHERE company_id = $1 AND source = ANY($2::text[])`,
    [COMPANY, sources],
  );
  const edges = await pool.query(
    `SELECT count(*)::int AS concept_edges FROM concept_edges WHERE company_id = $1`,
    [COMPANY],
  );
  const fingerprints = await pool.query(
    `SELECT id::text, source, encode(content_hash, 'hex') AS content_hash
       FROM aimos_memories
      WHERE company_id = $1 AND source = ANY($2::text[])
      ORDER BY id`,
    [COMPANY, sources],
  );
  const fingerprint = createHash('sha256');
  fingerprint.update('hom-aimos/concept-gaama-live-proof-scope/v1\0', 'utf8');
  for (const row of fingerprints.rows) {
    fingerprint.update(`${row.id}\0${row.source}\0${row.content_hash || ''}\0`, 'utf8');
  }
  return {
    database: resolveAimosDatabaseName(),
    ...memory.rows[0],
    ...edges.rows[0],
    source_scope_sha256: fingerprint.digest('hex'),
  };
}

async function loadScope(sourceFilter) {
  const result = await pool.query(
    `SELECT id::text, key, value, embedding::text, source, node_type, created_at
       FROM aimos_memories
      WHERE company_id = $1 AND source = $2 AND embedding IS NOT NULL
      ORDER BY id`,
    [COMPANY, sourceFilter],
  );
  const rows = result.rows.map((row) => ({ ...row, embedding: parseVector(row.embedding) }));
  assert(rows.every((row) => Array.isArray(row.embedding)), `concept_gaama_scope_embedding_invalid:${sourceFilter}`);
  const memoryById = new Map(rows.map((row) => [row.id, row]));
  const concepts = new Map();
  const edges = [];
  for (const row of rows) {
    for (const label of extractConcepts(row.value)) {
      const conceptId = `concept:${label}`;
      if (!concepts.has(conceptId)) {
        concepts.set(conceptId, { id: conceptId, node_type: 'concept', content: '', embedding: null });
      }
      edges.push({
        id: sha256(`hom-aimos/concept-gaama-transient-edge/v1\0${row.id}\0${conceptId}`),
        source_id: row.id,
        target_id: conceptId,
        edge_type: 'HAS_CONCEPT',
      });
    }
  }
  return { sourceFilter, rows, memoryById, concepts, edges };
}

async function openCandidates(question, queryEmbedding, scope) {
  const started = process.hrtime.bigint();
  const result = await pool.query(
    `SELECT id::text, 1 - (embedding <=> $1::vector) AS similarity
       FROM aimos_memories
      WHERE company_id = $2 AND source = $3 AND embedding IS NOT NULL
      ORDER BY embedding <=> $1::vector ASC, id ASC
      LIMIT $4`,
    [JSON.stringify(queryEmbedding), COMPANY, question.source_filter, OPENING],
  );
  const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
  const candidates = result.rows.map((row) => {
    const memory = scope.memoryById.get(row.id);
    assert(memory, `concept_gaama_candidate_memory_missing:${row.id}`);
    return {
      id: row.id,
      similarity: Number(row.similarity),
      embedding: memory.embedding,
      node_type: memory.node_type,
      content: '',
      timestamp: memory.created_at instanceof Date ? memory.created_at.toISOString() : String(memory.created_at || ''),
    };
  });
  assert(candidates.length > 0, `concept_gaama_candidate_opening_empty:${question.question_id}`);
  return { candidates, latencyMs };
}

async function runBaseline(candidates, scope) {
  const started = process.hrtime.bigint();
  const seedIds = candidates.map((row) => row.id);
  const seedWeights = candidates.map((row) => Math.max(0, Number(row.similarity)) ** 2);
  const ppr = await localPPR(seedIds, seedWeights, COMPANY, 2);
  const rows = candidates.map((row) => {
    const cosine = Number(row.similarity);
    const pprScore = Number(ppr.get(row.id) || 0);
    return { id: row.id, cosine, ppr: pprScore, score: cosine + (0.1 * pprScore) };
  }).sort(compareHybridConceptResults).slice(0, LIMIT);
  return {
    rows: hydrate(rows, scope.memoryById),
    latencyMs: Number(process.hrtime.bigint() - started) / 1e6,
  };
}

function candidateNodes(candidates, scope) {
  const candidateIds = new Set(candidates.map((row) => row.id));
  const seedNodes = candidates.map((candidate) => {
    const memory = scope.memoryById.get(candidate.id);
    return {
      id: memory.id,
      node_type: memory.node_type,
      content: '',
      embedding: memory.embedding,
      timestamp: memory.created_at instanceof Date ? memory.created_at.toISOString() : String(memory.created_at || ''),
    };
  });
  const remaining = scope.rows
    .filter((row) => !candidateIds.has(row.id))
    .map((row) => ({
      id: row.id,
      node_type: row.node_type,
      content: '',
      embedding: row.embedding,
      timestamp: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at || ''),
    }));
  return [...seedNodes, ...scope.concepts.values(), ...remaining];
}

function runCandidate(candidates, queryEmbedding, scope) {
  const started = process.hrtime.bigint();
  const result = runGaamaDormantCandidate({
    candidates,
    nodes: candidateNodes(candidates, scope),
    edges: scope.edges,
    queryEmbedding,
    retrievalBudget: LIMIT,
    seedCount: OPENING,
    expansionDepth: 2,
  });
  const rows = result.ranking
    .filter((row) => scope.memoryById.has(row.id))
    .slice(0, LIMIT);
  return {
    rows: hydrate(rows, scope.memoryById),
    latencyMs: Number(process.hrtime.bigint() - started) / 1e6,
    diagnostics: {
      graph_nodes: result.graph.nodes.length,
      graph_edges: result.graph.edges.length,
      rejected_edges: result.graph.rejected_edges.length,
      subgraph_nodes: result.subgraph.node_ids.length,
      subgraph_edges: result.subgraph.edges.length,
      graph_discovered_returned: rows.filter((row) => row.graph_discovered).length,
      ppr_converged: result.ppr.converged,
      ppr_iterations: result.ppr.iterations,
      ppr_final_l1_delta: round(result.ppr.final_l1_delta),
      transition_rows_stochastic: result.transition.row_stochastic,
    },
  };
}

function metricSummary(rows, accessor, seed) {
  const deltas = rows.map((row) => Number(accessor(row, 'candidate')) - Number(accessor(row, 'baseline')));
  return {
    baseline_mean: round(mean(rows.map((row) => accessor(row, 'baseline')))),
    candidate_mean: round(mean(rows.map((row) => accessor(row, 'candidate')))),
    mean_delta: round(mean(deltas)),
    paired_bootstrap_95: pairedBootstrap(deltas, { seed, replicates: BOOTSTRAP_REPLICATES }),
    wilcoxon_signed_rank: wilcoxonSignedRank(deltas),
  };
}

function summarize(rows, label) {
  const eligible = rows.filter((row) => row.baseline_retrieval.eligible && row.candidate_retrieval.eligible);
  const b = eligible.filter((row) => row.baseline_retrieval.hit_at_1 && !row.candidate_retrieval.hit_at_1).length;
  const c = eligible.filter((row) => !row.baseline_retrieval.hit_at_1 && row.candidate_retrieval.hit_at_1).length;
  return {
    label,
    questions: rows.length,
    eligible: eligible.length,
    ndcg_at_20: metricSummary(eligible, (row, arm) => row[`${arm}_retrieval`].ndcg_at_k, 2026081001),
    hit_at_1: {
      ...metricSummary(eligible, (row, arm) => Number(row[`${arm}_retrieval`].hit_at_1), 2026081002),
      exact_mcnemar: { b, c, two_sided_p: exactMcNemarPValue(b, c) },
    },
    evidence_recall_at_20: metricSummary(
      eligible,
      (row, arm) => row[`${arm}_retrieval`].evidence_recall_at_k,
      2026081003,
    ),
    reciprocal_rank: metricSummary(
      eligible,
      (row, arm) => row[`${arm}_retrieval`].reciprocal_rank,
      2026081004,
    ),
    latency_ms: {
      baseline: {
        mean: round(mean(rows.map((row) => row.latency_ms.baseline))),
        p50: round(percentile(rows.map((row) => row.latency_ms.baseline), 0.50)),
        p95: round(percentile(rows.map((row) => row.latency_ms.baseline), 0.95)),
        p99: round(percentile(rows.map((row) => row.latency_ms.baseline), 0.99)),
      },
      candidate: {
        mean: round(mean(rows.map((row) => row.latency_ms.candidate))),
        p50: round(percentile(rows.map((row) => row.latency_ms.candidate), 0.50)),
        p95: round(percentile(rows.map((row) => row.latency_ms.candidate), 0.95)),
        p99: round(percentile(rows.map((row) => row.latency_ms.candidate), 0.99)),
      },
      paired: metricSummary(rows, (row, arm) => row.latency_ms[arm], 2026081005),
    },
  };
}

function immutableArtifact(value) {
  fs.mkdirSync(OUTPUT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT_DIRECTORY, 0o700);
  const stamp = value.completed_at.replaceAll(/[-:.]/g, '');
  const file = path.join(OUTPUT_DIRECTORY, `concept-gaama-live-causal-proof-${stamp}.json`);
  const body = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.writeFileSync(file, body, { flag: 'wx', mode: 0o600 });
  return { path: file, sha256: sha256(body), bytes: body.length };
}

async function main() {
  assert(process.argv.includes('--live'), 'concept_gaama_live_flag_required');
  assert(resolveAimosDatabaseName() === FIXED_DATABASE, 'concept_gaama_fixed_scratch_database_required');
  const { questions, sourceFilters } = loadFixedQuestions();
  const sourceFiles = {
    preregistration_sha256: fileSha256(PREREGISTRATION),
    runner_sha256: fileSha256(SCRIPT_FILE),
    isolation_proof_sha256: fileSha256(path.join(ROOT, 'eval', 'public-results', FIXED_RUN, 'isolation-proof.json')),
    gate10_selection_sha256: fileSha256(SELECTION_FILE),
    locomo_questions_sha256: fileSha256(path.join(CORPUS_ROOT, 'locomo-questions.json')),
    longmemeval_questions_sha256: fileSha256(path.join(CORPUS_ROOT, 'longmemeval-questions.json')),
    concept_graph_sha256: fileSha256(path.join(ROOT, 'services', 'core', 'concept-graph.js')),
    gaama_candidate_sha256: fileSha256(path.join(ROOT, 'services', 'core', 'gaama-candidate', 'gaama-dormant-candidate.js')),
    scorer_sha256: fileSha256(path.join(ROOT, 'eval', 'aggregate-canonical-results.mjs')),
  };
  const expectedFiles = {
    isolation_proof_sha256: '7ed4640d56d926bbe644738ddba4bbc797224bdff0f73e762bf2dedc2783f036',
    gate10_selection_sha256: 'c0899e7080bc9a7816c5bb27c84c7a0339552d12909da7262a4c22a9a57922c4',
    locomo_questions_sha256: 'c7205385b5171885cef7dc9c93928554cee6819f2f4f27f00a54e0353cd51998',
    longmemeval_questions_sha256: '6eab23ede8b52cbba4308ac4744dd6e01a1f3baedb20a1f7acb5c2051b68e8be',
    concept_graph_sha256: '425b9619b6d4c7cf0f3b286298503340882b979aad41e4ab523ab35dbab8e77d',
    gaama_candidate_sha256: '79385315b3424e72b9421d888664043338418ce57e0df7b1795317d26afad507',
    scorer_sha256: '0f0614280bbb177d4de17798bb4affe46cb001e2be5beda7a9744bb9e55e09ef',
  };
  for (const [key, expected] of Object.entries(expectedFiles)) {
    assert(sourceFiles[key] === expected, `concept_gaama_source_hash_mismatch:${key}`);
  }

  const sessionsByBenchmark = Object.fromEntries(['locomo', 'longmemeval'].map((benchmark) => [
    benchmark,
    JSON.parse(fs.readFileSync(path.join(CORPUS_ROOT, `${benchmark}-sessions.json`), 'utf8')),
  ]));
  const before = await inventory(sourceFilters);
  assert(before.concept_edges === 0, 'concept_gaama_scratch_edges_not_zero');

  const scopes = new Map();
  for (const sourceFilter of [...sourceFilters].sort()) scopes.set(sourceFilter, await loadScope(sourceFilter));

  const rows = [];
  let completed = 0;
  for (const question of questions) {
    const scope = scopes.get(question.source_filter);
    assert(scope, `concept_gaama_scope_cache_missing:${question.source_filter}`);
    const queryEmbedding = await getEmbedding(question.question);
    assert(Array.isArray(queryEmbedding) && !queryEmbedding._degraded, `concept_gaama_query_embedding_unavailable:${question.question_id}`);
    const opening = await openCandidates(question, queryEmbedding, scope);
    const baseline = await runBaseline(opening.candidates, scope);
    const candidate = runCandidate(opening.candidates, queryEmbedding, scope);
    const candidateReplay = runCandidate(opening.candidates, queryEmbedding, scope);
    const candidateCommitment = rankCommitment(candidate.rows, 'hom-aimos/concept-gaama-candidate-ranking/v1');
    const replayCommitment = rankCommitment(candidateReplay.rows, 'hom-aimos/concept-gaama-candidate-ranking/v1');
    assert(candidateCommitment === replayCommitment, `concept_gaama_determinism_failure:${question.question_id}`);
    const expected = question.benchmark === 'locomo'
      ? (question.expected_evidence || [])
      : (question.answer_session_ids || []);
    const sessionMap = sourceSessionMap(sessionsByBenchmark[question.benchmark], question.scope_id);
    const baselineRetrieval = scoreRetrievalEvidence({
      benchmark: question.benchmark,
      memories: baseline.rows,
      expectedEvidence: expected,
      sourceToCanonical: sessionMap,
    });
    const candidateRetrieval = scoreRetrievalEvidence({
      benchmark: question.benchmark,
      memories: candidate.rows,
      expectedEvidence: expected,
      sourceToCanonical: sessionMap,
    });
    rows.push({
      question_id_sha256: sha256(`hom-aimos/concept-gaama-question/v1\0${question.question_id}`),
      benchmark: question.benchmark,
      category: question.category,
      source_filter_sha256: sha256(`hom-aimos/concept-gaama-source/v1\0${question.source_filter}`),
      baseline_retrieval: baselineRetrieval,
      candidate_retrieval: candidateRetrieval,
      latency_ms: {
        shared_opening: round(opening.latencyMs),
        baseline: round(baseline.latencyMs),
        candidate: round(candidate.latencyMs),
        candidate_replay: round(candidateReplay.latencyMs),
      },
      baseline_rank_commitment: rankCommitment(baseline.rows, 'hom-aimos/concept-gaama-baseline-ranking/v1'),
      candidate_rank_commitment: candidateCommitment,
      deterministic_replay_equal: true,
      candidate_diagnostics: candidate.diagnostics,
    });
    completed += 1;
    if (completed % 25 === 0 || completed === questions.length) {
      console.log(JSON.stringify({ event: 'concept_gaama_question_complete', completed, total: questions.length }));
    }
  }

  const after = await inventory(sourceFilters);
  assert(JSON.stringify(before) === JSON.stringify(after), 'concept_gaama_read_only_inventory_changed');
  const multiHop = rows.filter((row) => row.benchmark === 'locomo' && row.category === 'multi-hop');
  assert(multiHop.length === 361, 'concept_gaama_primary_denominator_mismatch');
  const primary = summarize(multiHop, 'locomo_multi_hop');
  const overall = summarize(rows, 'all_fixed_questions');
  const primaryDecision = {
    ndcg_positive: primary.ndcg_at_20.paired_bootstrap_95.lower > 0,
    hit_at_1_noninferior: primary.hit_at_1.paired_bootstrap_95.lower > -0.02,
    evidence_recall_noninferior: primary.evidence_recall_at_20.paired_bootstrap_95.lower > -0.01,
    candidate_p95_latency_within_bound: primary.latency_ms.candidate.p95 <= 250,
    completed_without_failure: rows.length === EXPECTED_QUESTION_COUNT,
    deterministic_replay_equal: rows.every((row) => row.deterministic_replay_equal),
    database_unchanged: JSON.stringify(before) === JSON.stringify(after),
  };
  primaryDecision.advance_to_native_implementation = Object.values(primaryDecision).every(Boolean);

  const artifact = {
    schema: 'hom-aimos/concept-gaama-live-causal-proof/v1',
    completed_at: new Date().toISOString(),
    mode: 'LIVE_READ_ONLY_ISOLATED_SCRATCH',
    database: FIXED_DATABASE,
    source_files: sourceFiles,
    selection: {
      questions: questions.length,
      unique_source_filters: sourceFilters.size,
      ordered_question_id_sha256: questionCommitment(questions),
      primary_multi_hop_questions: multiHop.length,
    },
    inventory_before: before,
    inventory_after: after,
    primary,
    overall,
    decision: primaryDecision,
    scope_diagnostics: [...scopes.values()].map((scope) => ({
      source_filter_sha256: sha256(`hom-aimos/concept-gaama-source/v1\0${scope.sourceFilter}`),
      memories: scope.rows.length,
      concepts: scope.concepts.size,
      transient_edges: scope.edges.length,
    })),
    rows,
    interpretation_boundary: {
      generator_or_judge_called: false,
      canonical_database_touched: false,
      database_write_performed: false,
      persistent_edge_created: false,
      candidate_wired_or_activated: false,
      save_side_claim: 'no_save_side_claim',
      full_saber_campaign_run: false,
    },
  };
  artifact.summary_sha256 = sha256(JSON.stringify(artifact));
  const output = immutableArtifact(artifact);
  console.log(JSON.stringify({ success: true, artifact: output, primary, decision: primaryDecision }, null, 2));
}

try {
  await main();
} finally {
  await pool.end();
}
