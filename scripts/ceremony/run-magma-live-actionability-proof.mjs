#!/usr/bin/env node

/**
 * Read-only paired actionability proof for the dormant MAGMA pure kernel.
 * Bound to one retained benchmark scratch brain and nine fixed source scopes.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { pool } from '../../db/connection.js';
import { getEmbedding } from '../../services/core/embeddings.js';
import {
  cosineSimilarityMagma,
  identifyMagmaAnchors,
  runMagmaDormantKernel,
} from '../../services/retrieval/magma-lineage-retriever.js';
import { partitionGraphCanaryDisclosure } from '../../services/retrieval/native-recall-pipeline.js';
import { scoreRetrievalEvidence } from '../../eval/aggregate-canonical-results.mjs';
import { exactMcNemarPValue, pairedBootstrap } from '../../eval/poisonedrag/harness.mjs';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const SCRIPT_FILE = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(SCRIPT_FILE), '..', '..');
const FIXED_DATABASE = 'aimos_benchmark_20260809163640_04a22c';
const FIXED_RUN = '20260809163640_04a22c';
const COMPANY = 'hom';
const OPENING = 40;
const LIMIT = 20;
const ANCHOR_COUNT = 5;
const GRAPH_NODE_CAP = 200;
const GRAPH_EXPANSION_DEPTH = 3;
const SEMANTIC_NEIGHBORS_PER_NODE = 8;
const ENTITY_NEIGHBORS_PER_ENTITY = 4;
const ENTITY_NEIGHBORS_PER_NODE = 16;
const EXPECTED_QUESTION_COUNT = 840;
const EXPECTED_MULTI_HOP_COUNT = 361;
const EXPECTED_QUESTION_ID_SHA256 = '9ad0831310e6d4b5f5e865263f2c57dc6baf9bcee51e684021f7dfa2cb070f0a';
const BOOTSTRAP_REPLICATES = 10_000;
const OUTPUT_DIRECTORY = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma');
const PREREGISTRATION = path.join(ROOT, 'plans', 'Codex', 'active', 'graphs', 'MAGMA-LATENCY-REMEDIATION-PREREGISTRATION-20260810.md');
const CERTIFICATE = path.join(ROOT, 'plans', 'Codex', 'active', 'graphs', 'MAGMA-DORMANT-READINESS-CERTIFICATE-20260810.md');
const V1_ARTIFACT = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma', 'magma-live-actionability-proof-20260810T121009498Z.json');
const V1_RUNNER_SNAPSHOT = path.join(ROOT, 'artifacts', 'graph-readiness', 'magma', 'run-magma-live-actionability-proof-v1-21c2bf1da776930c.mjs');
const SELECTION_FILE = path.join(ROOT, 'eval', 'public-results', FIXED_RUN, 'twin-prime-g5', 'gate10', 'selection.json');
const CORPUS_ROOT = path.join(ROOT, 'eval', 'data', 'twin-prime-g1p-canonical-v2');
const RANK_EPSILON = 1e-12;
const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'by', 'did', 'do', 'does',
  'for', 'from', 'had', 'has', 'have', 'he', 'her', 'hers', 'him', 'his', 'how',
  'i', 'in', 'is', 'it', 'its', 'me', 'my', 'of', 'on', 'or', 'our', 'she',
  'that', 'the', 'their', 'them', 'they', 'this', 'to', 'was', 'we', 'were',
  'what', 'when', 'where', 'which', 'who', 'why', 'with', 'would', 'you', 'your',
]);

function assert(condition, reason) {
  if (!condition) throw new Error(reason);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fileSha256(file) {
  return sha256(fs.readFileSync(file));
}

function round(value, digits = 9) {
  return Number(Number(value).toFixed(digits));
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + Number(value), 0) / values.length : null;
}

function percentile(values, probability) {
  const rows = values.map(Number).filter(Number.isFinite).sort((left, right) => left - right);
  if (!rows.length) return null;
  return rows[Math.min(rows.length - 1, Math.max(0, Math.ceil(probability * rows.length) - 1))];
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
  const nonzero = deltas.map(Number).filter(Number.isFinite)
    .filter((value) => Math.abs(value) > RANK_EPSILON)
    .map((value) => ({ value, absolute: Math.abs(value) }))
    .sort((left, right) => left.absolute - right.absolute);
  if (!nonzero.length) return { n: 0, w_plus: 0, w_minus: 0, z: 0, two_sided_p: 1, rank_biserial: 0 };
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
  const z = variance > 0 ? (Math.abs(wPlus - expected) - (wPlus === expected ? 0 : 0.5)) / Math.sqrt(variance) : 0;
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

function tokenize(value) {
  return new Set(String(value || '').toLowerCase().match(/[\p{L}\p{N}]+/gu)?.filter((token) => token.length > 1 && !STOP_WORDS.has(token)) || []);
}

function questionCommitment(rows) {
  return sha256(JSON.stringify(rows.map((row) => row.question_id)));
}

function rankCommitment(rows, domain) {
  return sha256(`${domain}\0${rows.map((row) => row.id).join('\0')}`);
}

function sourceSessionMap(sessions, scopeId) {
  const scope = sessions.scopes.find((entry) => entry.scope_id === scopeId);
  assert(scope, `magma_scope_missing:${scopeId}`);
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
  assert(sourceFilters.size === 9, 'magma_source_filter_count_mismatch');
  assert(questions.length === EXPECTED_QUESTION_COUNT, 'magma_question_count_mismatch');
  assert(questionCommitment(questions) === EXPECTED_QUESTION_ID_SHA256, 'magma_question_commitment_mismatch');
  return { questions, sourceFilters };
}

async function inventory(sourceFilters) {
  const sources = [...sourceFilters].sort();
  const counts = await pool.query(
    `SELECT
       (SELECT count(*)::int FROM aimos_memories WHERE company_id = $1 AND source = ANY($2::text[])) AS memories,
       (SELECT count(*)::int FROM memory_cross_refs cr
          JOIN aimos_memories sm ON sm.id = cr.source_memory_id AND sm.company_id = cr.company_id
          JOIN aimos_memories tm ON tm.id = cr.target_memory_id AND tm.company_id = cr.company_id
         WHERE cr.company_id = $1 AND sm.source = ANY($2::text[]) AND tm.source = ANY($2::text[])) AS semantic_edges,
       (SELECT count(*)::int FROM entity_memory_edges em
          JOIN aimos_memories m ON m.id = em.memory_id AND m.company_id = em.company_id
         WHERE em.company_id = $1 AND m.source = ANY($2::text[])) AS entity_memberships,
       (SELECT count(*)::int FROM concept_edges WHERE company_id = $1) AS concept_edges`,
    [COMPANY, sources],
  );
  const fingerprints = await pool.query(
    `SELECT id::text, source, encode(content_hash, 'hex') AS content_hash
       FROM aimos_memories
      WHERE company_id = $1 AND source = ANY($2::text[])
      ORDER BY id`,
    [COMPANY, sources],
  );
  const fingerprint = createHash('sha256');
  fingerprint.update('hom-aimos/magma-live-proof-scope/v1\0');
  for (const row of fingerprints.rows) fingerprint.update(`${row.id}\0${row.source}\0${row.content_hash || ''}\0`);
  return {
    database: resolveAimosDatabaseName(),
    ...counts.rows[0],
    source_scope_sha256: fingerprint.digest('hex'),
  };
}

function addAdjacency(map, sourceId, row) {
  const rows = map.get(sourceId) || [];
  rows.push(row);
  map.set(sourceId, rows);
}

async function loadScope(sourceFilter) {
  const memoryResult = await pool.query(
    `SELECT id::text, key, value, embedding::text, source, created_at
       FROM aimos_memories
      WHERE company_id = $1 AND source = $2 AND embedding IS NOT NULL
      ORDER BY id`,
    [COMPANY, sourceFilter],
  );
  const rows = memoryResult.rows.map((row) => {
    const embedding = parseVector(row.embedding);
    assert(Array.isArray(embedding), `magma_scope_embedding_invalid:${sourceFilter}:${row.id}`);
    return {
      ...row,
      embedding,
      created_at: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at || ''),
      tokens: tokenize(`${row.key || ''} ${row.value || ''}`),
    };
  });
  const memoryById = new Map(rows.map((row) => [row.id, row]));

  const crossResult = await pool.query(
    `SELECT cr.source_memory_id::text AS source_id,
            cr.target_memory_id::text AS target_id,
            cr.similarity::float8 AS similarity
       FROM memory_cross_refs cr
       JOIN aimos_memories sm ON sm.id = cr.source_memory_id AND sm.company_id = cr.company_id
       JOIN aimos_memories tm ON tm.id = cr.target_memory_id AND tm.company_id = cr.company_id
      WHERE cr.company_id = $1 AND sm.source = $2 AND tm.source = $2
      ORDER BY cr.source_memory_id, cr.similarity DESC, cr.target_memory_id`,
    [COMPANY, sourceFilter],
  );
  const semanticAdjacency = new Map();
  for (const row of crossResult.rows) {
    addAdjacency(semanticAdjacency, row.source_id, { id: row.target_id, similarity: Number(row.similarity) });
    addAdjacency(semanticAdjacency, row.target_id, { id: row.source_id, similarity: Number(row.similarity) });
  }

  const entityResult = await pool.query(
    `SELECT em.memory_id::text AS memory_id, lower(em.entity) AS entity
       FROM entity_memory_edges em
       JOIN aimos_memories m ON m.id = em.memory_id AND m.company_id = em.company_id
      WHERE em.company_id = $1 AND m.source = $2
      ORDER BY lower(em.entity), em.memory_id`,
    [COMPANY, sourceFilter],
  );
  const entityMembers = new Map();
  const entitiesByMemory = new Map();
  for (const row of entityResult.rows) {
    addAdjacency(entityMembers, row.entity, row.memory_id);
    addAdjacency(entitiesByMemory, row.memory_id, row.entity);
  }

  const temporalIds = [...rows]
    .filter((row) => Number.isFinite(Date.parse(row.created_at)))
    .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at) || left.id.localeCompare(right.id))
    .map((row) => row.id);
  const temporalIndex = new Map(temporalIds.map((id, index) => [id, index]));
  return { sourceFilter, rows, memoryById, semanticAdjacency, entityMembers, entitiesByMemory, temporalIds, temporalIndex };
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
  const rows = result.rows.map((row) => ({ id: row.id, similarity: Number(row.similarity) }));
  assert(rows.length > 0, `magma_opening_empty:${question.question_id}`);
  return { rows, latencyMs: Number(process.hrtime.bigint() - started) / 1e6 };
}

function lexicalRanks(question, scope) {
  const queryTokens = tokenize(question.question);
  return scope.rows.map((memory) => {
    let overlap = 0;
    for (const token of queryTokens) if (memory.tokens.has(token)) overlap += 1;
    return { id: memory.id, overlap };
  }).filter((row) => row.overlap > 0)
    .sort((left, right) => right.overlap - left.overlap || left.id.localeCompare(right.id))
    .slice(0, OPENING);
}

function inferIntent(question) {
  if (question.category === 'temporal') return 'WHEN';
  const text = String(question.question || '').trim().toLowerCase();
  if (/^(why\b|how\b|what caused\b)/.test(text)) return 'WHY';
  if (/^(who\b|where\b)/.test(text)) return 'ENTITY';
  return 'SEMANTIC';
}

function edgeId(relation, sourceId, targetId, qualifier = '') {
  return sha256(`hom-aimos/magma-transient-edge/v1\0${relation}\0${sourceId}\0${targetId}\0${qualifier}`);
}

function compareEntityCandidate(left, right) {
  return right.similarity - left.similarity || left.id.localeCompare(right.id);
}

function insertExactTopK(rows, candidate, limit) {
  let index = 0;
  while (index < rows.length && compareEntityCandidate(rows[index], candidate) <= 0) index += 1;
  rows.splice(index, 0, candidate);
  if (rows.length > limit) rows.pop();
}

function buildQuestionGraph({ scope, queryEmbedding, vectorRanks, lexical }) {
  const anchors = identifyMagmaAnchors({
    vectorRanks,
    lexicalRanks: lexical,
    temporalRanks: [],
    topK: ANCHOR_COUNT,
  });
  const selectedIds = [];
  const selectedSet = new Set();
  const edgeMap = new Map();
  const querySimilarityCache = new Map();
  const entityTopMembersCache = new Map();
  let entityCapActivations = 0;

  function querySimilarity(id) {
    if (!querySimilarityCache.has(id)) {
      querySimilarityCache.set(id, cosineSimilarityMagma(scope.memoryById.get(id)?.embedding, queryEmbedding));
    }
    return querySimilarityCache.get(id);
  }

  function topEntityMembers(entity) {
    if (entityTopMembersCache.has(entity)) return entityTopMembersCache.get(entity);
    const memberIds = scope.entityMembers.get(entity) || [];
    const countById = new Map();
    let maximumMultiplicity = 0;
    for (const id of memberIds) {
      const count = (countById.get(id) || 0) + 1;
      countById.set(id, count);
      maximumMultiplicity = Math.max(maximumMultiplicity, count);
    }
    const top = [];
    for (const id of memberIds) {
      insertExactTopK(
        top,
        { id, similarity: querySimilarity(id) },
        ENTITY_NEIGHBORS_PER_ENTITY + maximumMultiplicity,
      );
    }
    const ranked = { top, countById, total: memberIds.length, maximumMultiplicity };
    entityTopMembersCache.set(entity, ranked);
    return ranked;
  }

  function addNode(id) {
    if (!scope.memoryById.has(id) || selectedSet.has(id) || selectedIds.length >= GRAPH_NODE_CAP) return false;
    selectedSet.add(id);
    selectedIds.push(id);
    return true;
  }

  function addEdge(relation, sourceId, targetId, qualifier = '') {
    if (sourceId === targetId || !scope.memoryById.has(sourceId) || !scope.memoryById.has(targetId)) return;
    let from = sourceId;
    let to = targetId;
    if (relation === 'temporal') {
      const fromTime = Date.parse(scope.memoryById.get(from).created_at);
      const toTime = Date.parse(scope.memoryById.get(to).created_at);
      if (!(fromTime < toTime)) [from, to] = [to, from];
      if (!(Date.parse(scope.memoryById.get(from).created_at) < Date.parse(scope.memoryById.get(to).created_at))) return;
    } else if (from > to) {
      [from, to] = [to, from];
    }
    const id = edgeId(relation, from, to, qualifier);
    edgeMap.set(id, { id, source_id: from, target_id: to, relation });
  }

  for (const anchor of anchors) addNode(anchor.id);
  let frontier = anchors.map((anchor) => anchor.id).filter((id) => selectedSet.has(id));
  for (let depth = 0; depth < GRAPH_EXPANSION_DEPTH && frontier.length && selectedIds.length < GRAPH_NODE_CAP; depth += 1) {
    const next = [];
    for (const sourceId of frontier) {
      const semantic = [...(scope.semanticAdjacency.get(sourceId) || [])]
        .sort((left, right) => right.similarity - left.similarity || left.id.localeCompare(right.id))
        .slice(0, SEMANTIC_NEIGHBORS_PER_NODE);
      for (const target of semantic) {
        if (addNode(target.id)) next.push(target.id);
        addEdge('semantic', sourceId, target.id);
      }

      const entityTargets = [];
      for (const entity of scope.entitiesByMemory.get(sourceId) || []) {
        const ranked = topEntityMembers(entity);
        const memberCount = ranked.total - (ranked.countById.get(sourceId) || 0);
        const members = ranked.top.filter((row) => row.id !== sourceId);
        if (memberCount > ENTITY_NEIGHBORS_PER_ENTITY) entityCapActivations += 1;
        for (const member of members.slice(0, ENTITY_NEIGHBORS_PER_ENTITY)) entityTargets.push({ ...member, entity });
      }
      entityTargets.sort((left, right) => right.similarity - left.similarity || left.id.localeCompare(right.id) || left.entity.localeCompare(right.entity));
      if (entityTargets.length > ENTITY_NEIGHBORS_PER_NODE) entityCapActivations += 1;
      for (const target of entityTargets.slice(0, ENTITY_NEIGHBORS_PER_NODE)) {
        if (addNode(target.id)) next.push(target.id);
        addEdge('entity', sourceId, target.id, target.entity);
      }

      const index = scope.temporalIndex.get(sourceId);
      if (Number.isInteger(index)) {
        for (const neighborIndex of [index - 1, index + 1]) {
          const targetId = scope.temporalIds[neighborIndex];
          if (!targetId) continue;
          if (addNode(targetId)) next.push(targetId);
          addEdge('temporal', sourceId, targetId);
        }
      }
      if (selectedIds.length >= GRAPH_NODE_CAP) break;
    }
    frontier = [...new Set(next)].sort();
  }

  const nodes = selectedIds.map((id) => {
    const memory = scope.memoryById.get(id);
    return {
      id,
      content: String(memory.value || memory.key || id),
      timestamp: memory.created_at,
      embedding: memory.embedding,
      reference_id: id,
      attributes: { source: scope.sourceFilter },
    };
  });
  const edges = [...edgeMap.values()].filter((edge) => selectedSet.has(edge.source_id) && selectedSet.has(edge.target_id));
  return { nodes, edges, anchors, entityCapActivations };
}

function hydrateIds(ids, scope, similarityById = new Map()) {
  return ids.map((id) => {
    const memory = scope.memoryById.get(id);
    const record = parseRecord(memory?.value);
    return {
      id,
      key: memory?.key || null,
      value: memory?.value || '',
      source: memory?.source || scope.sourceFilter,
      session_id: record.session_id || null,
      similarity: Number(similarityById.get(id) || 0),
    };
  }).filter((row) => row.id && scope.memoryById.has(row.id));
}

function applyCanary(rows) {
  const partition = partitionGraphCanaryDisclosure(rows);
  return { rows: partition.admitted, withheld: partition.withheld.length, tokens: partition.canary_tokens.length };
}

function runCandidate({ question, queryEmbedding, opening, lexical, scope }) {
  const started = process.hrtime.bigint();
  const vectorRanks = opening.map((row) => ({ id: row.id }));
  const graphInput = buildQuestionGraph({ scope, queryEmbedding, vectorRanks, lexical });
  const result = runMagmaDormantKernel({
    nodes: graphInput.nodes,
    edges: graphInput.edges,
    vectorRanks,
    lexicalRanks: lexical,
    temporalRanks: [],
    queryEmbedding,
    intent: inferIntent(question),
    topK: ANCHOR_COUNT,
    maxDepth: GRAPH_EXPANSION_DEPTH,
    beamWidth: ANCHOR_COUNT,
    budget: LIMIT,
  });
  const ids = result.traversal.selected.map((entry) => entry.id)
    .filter((id) => scope.memoryById.has(id))
    .slice(0, LIMIT);
  const similarityById = new Map(opening.map((row) => [row.id, row.similarity]));
  const disclosure = applyCanary(hydrateIds(ids, scope, similarityById));
  return {
    rows: disclosure.rows,
    withheld: disclosure.withheld,
    canaryTokens: disclosure.tokens,
    latencyMs: Number(process.hrtime.bigint() - started) / 1e6,
    diagnostics: {
      intent: inferIntent(question),
      graph_nodes: result.graph_stats.nodes,
      graph_edges: result.graph_stats.edges,
      rejected_edges: result.graph_stats.rejected_edges,
      anchors: result.anchors.length,
      visited: result.traversal.visited_ids.length,
      traversal_depths: result.traversal.trace.length,
      termination_reason: result.traversal.termination_reason,
      entity_cap_activations: graphInput.entityCapActivations,
      semantic_edges: graphInput.edges.filter((edge) => edge.relation === 'semantic').length,
      entity_edges: graphInput.edges.filter((edge) => edge.relation === 'entity').length,
      temporal_edges: graphInput.edges.filter((edge) => edge.relation === 'temporal').length,
      causal_edges: 0,
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
    ndcg_at_20: metricSummary(eligible, (row, arm) => row[`${arm}_retrieval`].ndcg_at_k, 2026081011),
    hit_at_1: {
      ...metricSummary(eligible, (row, arm) => Number(row[`${arm}_retrieval`].hit_at_1), 2026081012),
      exact_mcnemar: { b, c, two_sided_p: exactMcNemarPValue(b, c) },
    },
    evidence_recall_at_20: metricSummary(eligible, (row, arm) => row[`${arm}_retrieval`].evidence_recall_at_k, 2026081013),
    reciprocal_rank: metricSummary(eligible, (row, arm) => row[`${arm}_retrieval`].reciprocal_rank, 2026081014),
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
      paired: metricSummary(rows, (row, arm) => row.latency_ms[arm], 2026081015),
    },
  };
}

function immutableArtifact(value) {
  fs.mkdirSync(OUTPUT_DIRECTORY, { recursive: true, mode: 0o700 });
  fs.chmodSync(OUTPUT_DIRECTORY, 0o700);
  const stamp = value.completed_at.replaceAll(/[-:.]/g, '');
  const file = path.join(OUTPUT_DIRECTORY, `magma-live-latency-reproof-${stamp}.json`);
  const body = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  fs.writeFileSync(file, body, { flag: 'wx', mode: 0o600 });
  return { path: file, sha256: sha256(body), bytes: body.length };
}

async function main() {
  assert(process.argv.includes('--live'), 'magma_live_flag_required');
  assert(resolveAimosDatabaseName() === FIXED_DATABASE, 'magma_fixed_scratch_database_required');
  const { questions, sourceFilters } = loadFixedQuestions();
  const sourceFiles = {
    preregistration_sha256: fileSha256(PREREGISTRATION),
    certificate_sha256: fileSha256(CERTIFICATE),
    runner_sha256: fileSha256(SCRIPT_FILE),
    isolation_proof_sha256: fileSha256(path.join(ROOT, 'eval', 'public-results', FIXED_RUN, 'isolation-proof.json')),
    gate10_selection_sha256: fileSha256(SELECTION_FILE),
    locomo_questions_sha256: fileSha256(path.join(CORPUS_ROOT, 'locomo-questions.json')),
    longmemeval_questions_sha256: fileSha256(path.join(CORPUS_ROOT, 'longmemeval-questions.json')),
    magma_kernel_sha256: fileSha256(path.join(ROOT, 'services', 'retrieval', 'magma-lineage-retriever.js')),
    scorer_sha256: fileSha256(path.join(ROOT, 'eval', 'aggregate-canonical-results.mjs')),
    canary_closure_owner_sha256: fileSha256(path.join(ROOT, 'services', 'retrieval', 'native-recall-pipeline.js')),
    v1_artifact_sha256: fileSha256(V1_ARTIFACT),
    v1_runner_snapshot_sha256: fileSha256(V1_RUNNER_SNAPSHOT),
  };
  const expectedFiles = {
    isolation_proof_sha256: '7ed4640d56d926bbe644738ddba4bbc797224bdff0f73e762bf2dedc2783f036',
    gate10_selection_sha256: 'c0899e7080bc9a7816c5bb27c84c7a0339552d12909da7262a4c22a9a57922c4',
    locomo_questions_sha256: 'c7205385b5171885cef7dc9c93928554cee6819f2f4f27f00a54e0353cd51998',
    longmemeval_questions_sha256: '6eab23ede8b52cbba4308ac4744dd6e01a1f3baedb20a1f7acb5c2051b68e8be',
    magma_kernel_sha256: 'ae59a189ce101a833be94ad3d337a3559ead466477e13ac34a0c7b266502c363',
    scorer_sha256: '0f0614280bbb177d4de17798bb4affe46cb001e2be5beda7a9744bb9e55e09ef',
    v1_artifact_sha256: '90144c039688d53ee42a54e4a9e84edf5f41a701aef4e9d6f5b048808a6758de',
    v1_runner_snapshot_sha256: '21c2bf1da776930c28d7a3d1f3bdbe4ad29640b5876e34fc6e99da20b9d957fe',
  };
  for (const [key, expected] of Object.entries(expectedFiles)) assert(sourceFiles[key] === expected, `magma_source_hash_mismatch:${key}`);

  const sessionsByBenchmark = Object.fromEntries(['locomo', 'longmemeval'].map((benchmark) => [
    benchmark,
    JSON.parse(fs.readFileSync(path.join(CORPUS_ROOT, `${benchmark}-sessions.json`), 'utf8')),
  ]));
  const before = await inventory(sourceFilters);
  const v1 = JSON.parse(fs.readFileSync(V1_ARTIFACT, 'utf8'));
  const v1RankByQuestion = new Map(v1.rows.map((row) => [row.question_id_sha256, row.candidate_rank_commitment]));
  assert(v1RankByQuestion.size === EXPECTED_QUESTION_COUNT, 'magma_v1_rank_commitment_count_mismatch');
  const scopes = new Map();
  for (const sourceFilter of [...sourceFilters].sort()) scopes.set(sourceFilter, await loadScope(sourceFilter));

  const rows = [];
  let completed = 0;
  for (const question of questions) {
    const scope = scopes.get(question.source_filter);
    assert(scope, `magma_scope_cache_missing:${question.source_filter}`);
    const queryEmbedding = await getEmbedding(question.question);
    assert(Array.isArray(queryEmbedding) && !queryEmbedding._degraded, `magma_query_embedding_unavailable:${question.question_id}`);
    const opening = await openCandidates(question, queryEmbedding, scope);
    const similarityById = new Map(opening.rows.map((row) => [row.id, row.similarity]));
    const baselineStart = process.hrtime.bigint();
    const baselineDisclosure = applyCanary(hydrateIds(opening.rows.slice(0, LIMIT).map((row) => row.id), scope, similarityById));
    const baselineLatency = Number(process.hrtime.bigint() - baselineStart) / 1e6;
    const lexical = lexicalRanks(question, scope);
    const candidate = runCandidate({ question, queryEmbedding, opening: opening.rows, lexical, scope });
    const replay = runCandidate({ question, queryEmbedding, opening: opening.rows, lexical, scope });
    const candidateCommitment = rankCommitment(candidate.rows, 'hom-aimos/magma-candidate-ranking/v1');
    assert(candidateCommitment === rankCommitment(replay.rows, 'hom-aimos/magma-candidate-ranking/v1'), `magma_determinism_failure:${question.question_id}`);
    const questionIdSha256 = sha256(`hom-aimos/magma-question/v1\0${question.question_id}`);
    assert(candidateCommitment === v1RankByQuestion.get(questionIdSha256), `magma_v1_rank_equivalence_failure:${question.question_id}`);

    const expected = question.benchmark === 'locomo' ? (question.expected_evidence || []) : (question.answer_session_ids || []);
    const sessionMap = sourceSessionMap(sessionsByBenchmark[question.benchmark], question.scope_id);
    const baselineRetrieval = scoreRetrievalEvidence({ benchmark: question.benchmark, memories: baselineDisclosure.rows, expectedEvidence: expected, sourceToCanonical: sessionMap });
    const candidateRetrieval = scoreRetrievalEvidence({ benchmark: question.benchmark, memories: candidate.rows, expectedEvidence: expected, sourceToCanonical: sessionMap });
    const baselineIds = new Set(baselineDisclosure.rows.map((row) => row.id));
    const graphDiscovered = candidate.rows.filter((row) => !baselineIds.has(row.id));
    rows.push({
      question_id_sha256: questionIdSha256,
      benchmark: question.benchmark,
      category: question.category,
      source_filter_sha256: sha256(`hom-aimos/magma-source/v1\0${question.source_filter}`),
      baseline_retrieval: baselineRetrieval,
      candidate_retrieval: candidateRetrieval,
      latency_ms: { shared_opening: round(opening.latencyMs), baseline: round(baselineLatency), candidate: round(candidate.latencyMs), candidate_replay: round(replay.latencyMs) },
      baseline_rank_commitment: rankCommitment(baselineDisclosure.rows, 'hom-aimos/magma-baseline-ranking/v1'),
      candidate_rank_commitment: candidateCommitment,
      deterministic_replay_equal: true,
      v1_rank_equivalent: true,
      graph_discovered_returned: graphDiscovered.length,
      canary: { baseline_withheld: baselineDisclosure.withheld, candidate_withheld: candidate.withheld, candidate_token_count: candidate.canaryTokens },
      candidate_diagnostics: candidate.diagnostics,
    });
    completed += 1;
    if (completed % 25 === 0 || completed === questions.length) console.log(JSON.stringify({ event: 'magma_question_complete', completed, total: questions.length }));
  }

  const after = await inventory(sourceFilters);
  assert(JSON.stringify(before) === JSON.stringify(after), 'magma_read_only_inventory_changed');
  const multiHop = rows.filter((row) => row.benchmark === 'locomo' && row.category === 'multi-hop');
  assert(multiHop.length === EXPECTED_MULTI_HOP_COUNT, 'magma_primary_denominator_mismatch');
  const primary = summarize(multiHop, 'locomo_multi_hop');
  const overall = summarize(rows, 'all_fixed_questions');
  const totalGraphDiscovered = rows.reduce((sum, row) => sum + row.graph_discovered_returned, 0);
  const decision = {
    ndcg_positive: primary.ndcg_at_20.paired_bootstrap_95.lower > 0,
    hit_at_1_noninferior: primary.hit_at_1.paired_bootstrap_95.lower > -0.02,
    evidence_recall_noninferior: primary.evidence_recall_at_20.paired_bootstrap_95.lower > -0.01,
    candidate_p95_latency_within_bound: primary.latency_ms.candidate.p95 <= 250,
    completed_without_failure: rows.length === EXPECTED_QUESTION_COUNT,
    deterministic_replay_equal: rows.every((row) => row.deterministic_replay_equal),
    v1_rank_equivalence: rows.every((row) => row.v1_rank_equivalent),
    graph_actionable: totalGraphDiscovered > 0,
    database_unchanged: JSON.stringify(before) === JSON.stringify(after),
  };
  decision.advance_to_native_reader_design = Object.values(decision).every(Boolean);

  const artifact = {
    schema: 'hom-aimos/magma-live-latency-reproof/v2',
    completed_at: new Date().toISOString(),
    mode: 'LIVE_READ_ONLY_ISOLATED_SCRATCH',
    database: FIXED_DATABASE,
    source_files: sourceFiles,
    selection: { questions: questions.length, unique_source_filters: sourceFilters.size, ordered_question_id_sha256: questionCommitment(questions), primary_multi_hop_questions: multiHop.length },
    parameters: {
      opening: OPENING,
      limit: LIMIT,
      anchors: ANCHOR_COUNT,
      graph_node_cap: GRAPH_NODE_CAP,
      expansion_depth: GRAPH_EXPANSION_DEPTH,
      semantic_neighbors_per_node: SEMANTIC_NEIGHBORS_PER_NODE,
      entity_neighbors_per_entity: ENTITY_NEIGHBORS_PER_ENTITY,
      entity_neighbors_per_node: ENTITY_NEIGHBORS_PER_NODE,
      temporal_anchor_ranks: 'omitted_no_admitted_native_interval_parser',
      causal_view: 'absent_not_synthesized',
      optimization: 'query_similarity_memoization_plus_exact_bounded_entity_top_k',
    },
    inventory_before: before,
    inventory_after: after,
    primary,
    overall,
    aggregate_diagnostics: {
      graph_discovered_returned: totalGraphDiscovered,
      candidate_canary_withheld: rows.reduce((sum, row) => sum + row.canary.candidate_withheld, 0),
      entity_cap_activations: rows.reduce((sum, row) => sum + row.candidate_diagnostics.entity_cap_activations, 0),
      mean_graph_nodes: round(mean(rows.map((row) => row.candidate_diagnostics.graph_nodes))),
      mean_graph_edges: round(mean(rows.map((row) => row.candidate_diagnostics.graph_edges))),
      mean_semantic_edges: round(mean(rows.map((row) => row.candidate_diagnostics.semantic_edges))),
      mean_entity_edges: round(mean(rows.map((row) => row.candidate_diagnostics.entity_edges))),
      mean_temporal_edges: round(mean(rows.map((row) => row.candidate_diagnostics.temporal_edges))),
      causal_edges: 0,
    },
    decision,
    rows,
    interpretation_boundary: {
      generator_or_judge_called: false,
      canonical_database_touched: false,
      database_write_performed: false,
      candidate_wired_or_activated: false,
      retrieval_policy_changed_from_v1: false,
      v1_rank_equivalence_required: true,
      legacy_database_adapter_used: false,
      causal_view_claimed: false,
      save_side_claim: 'no_save_side_claim',
      aladdin: 'no_delete_no_decay_no_suppression_no_canonical_mutation',
      full_saber_campaign_run: false,
    },
  };
  artifact.summary_sha256 = sha256(JSON.stringify(artifact));
  const output = immutableArtifact(artifact);
  console.log(JSON.stringify({ success: true, artifact: output, primary, overall, aggregate_diagnostics: artifact.aggregate_diagnostics, decision }, null, 2));
}

try {
  await main();
} finally {
  await pool.end();
}
