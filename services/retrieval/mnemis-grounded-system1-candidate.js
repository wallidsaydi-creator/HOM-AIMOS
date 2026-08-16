/**
 * Dormant, read-only AIMOS Mnemis System-1 candidate.
 *
 * The candidate builds the paper's four base-graph object classes only from
 * provenance-verified, Canary-admitted retained memories. It ranks Episodes,
 * Entities, and Edges independently with cosine/BM25/RRF, maps graph evidence
 * back to canonical Episodes, and applies a deterministic equal-weight RRF
 * with the accepted MAGMA result. The heuristic System-2 hierarchy is emitted
 * only as an unordered diagnostic and has no ranking or disclosure authority.
 *
 * This is not full Mnemis parity: it uses deterministic source-grounded object
 * construction instead of model extraction and does not implement the paper's
 * model selector, early-stop policy, category generator, or learned reranker.
 */

import { createHash } from 'node:crypto';

import {
  buildMnemisBaseGraph,
  buildMnemisHierarchy,
  mnemisGlobalSelection,
  mnemisSystem1,
  reciprocalRankFusionMnemis,
} from './mnemis-dual-route-graph.js';

export const MNEMIS_GROUNDED_SYSTEM1_CONTRACT = Object.freeze({
  schema: 'hom-aimos/mnemis-grounded-system1-candidate/v1',
  dormant: true,
  maximum_scope_memories: 2048,
  disclosure_limit: 20,
  system1_ranked: true,
  system2_diagnostic_only: true,
  model_authority: false,
  database_access: false,
  graph_persistence: false,
  signing_authority: false,
  environment_authority: false,
  canary_authority: false,
  epistemic_authority: false,
  mutates_canonical_memory: false,
  deletes_memory: false,
  applies_decay: false,
  suppresses_memory: false,
  expires_memory: false,
  deactivates_memory: false,
});

const SHA256_RE = /^[a-f0-9]{64}$/;

function fail(code) {
  throw new Error(`mnemis_grounded_system1:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.trunc(parsed)));
}

function parseEmbedding(value) {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    const vector = Array.from(value, Number);
    return vector.length && vector.every(Number.isFinite) ? vector : null;
  }
  const text = String(value || '').trim();
  if (!text.startsWith('[') || !text.endsWith(']')) return null;
  const vector = text.slice(1, -1).split(',').map(Number);
  return vector.length && vector.every(Number.isFinite) ? vector : null;
}

function normalizeAdmittedScope(memories) {
  if (!Array.isArray(memories) || !memories.length) fail('scope_required');
  if (memories.length > MNEMIS_GROUNDED_SYSTEM1_CONTRACT.maximum_scope_memories) {
    fail('scope_limit_exceeded');
  }
  const seen = new Set();
  return memories.map((memory) => {
    const id = String(memory?.id || '').trim().toLowerCase();
    const text = String(memory?.value || '').trim();
    const proof = memory?.provenance_proof;
    const contentHash = String(proof?.live_content_hash || memory?.content_hash || '').trim().toLowerCase();
    if (!id || seen.has(id)) fail('scope_identity_invalid');
    if (!text) fail('scope_content_missing');
    if (!proof || !SHA256_RE.test(contentHash)) fail('canonical_provenance_required');
    if (memory.canary_admitted !== true) fail('canary_admission_required');
    const embedding = parseEmbedding(memory.embedding);
    if (!embedding) fail('scope_embedding_invalid');
    seen.add(id);
    return Object.freeze({
      memory,
      state: {
        id,
        text,
        embedding,
        memory: {
          value: text,
          embedding,
          created_at: memory.created_at || null,
        },
      },
      content_hash: contentHash,
    });
  });
}

function episodeLists(system1, graph) {
  const entityById = new Map(graph.entities.map((entity) => [entity.id, entity]));
  const edgeById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const expand = (ranks, objectClass) => {
    const seen = new Set();
    const rows = [];
    for (const rank of ranks) {
      const ids = objectClass === 'episode'
        ? [rank.id]
        : objectClass === 'entity'
          ? (entityById.get(rank.id)?.episode_idx || [])
          : (edgeById.get(rank.id)?.episode_idx || []);
      for (const id of ids) {
        if (seen.has(id)) continue;
        seen.add(id);
        rows.push({ id });
      }
    }
    return rows;
  };
  return [
    expand(system1.episode_ranks, 'episode'),
    expand(system1.entity_ranks, 'entity'),
    expand(system1.edge_ranks, 'edge'),
  ];
}

function graphSupport(graph, contentHashByState) {
  let unsupportedEntities = 0;
  let unsupportedEdges = 0;
  for (const entity of graph.entities) {
    if (!entity.episode_idx?.length || entity.episode_idx.some((id) => !contentHashByState.has(id.slice(8)))) {
      unsupportedEntities += 1;
    }
  }
  for (const edge of graph.edges) {
    if (!edge.episode_idx?.length || edge.episode_idx.some((id) => !contentHashByState.has(id.slice(8)))) {
      unsupportedEdges += 1;
    }
  }
  return { unsupportedEntities, unsupportedEdges };
}

export function buildMnemisGroundedScope(admittedScopeMemories = []) {
  const normalized = normalizeAdmittedScope(admittedScopeMemories);
  const graph = buildMnemisBaseGraph(
    normalized.map((row) => row.state),
    MNEMIS_GROUNDED_SYSTEM1_CONTRACT.maximum_scope_memories,
  );
  const memoryById = new Map(normalized.map((row) => [row.state.id, row.memory]));
  const contentHashByState = new Map(normalized.map((row) => [row.state.id, row.content_hash]));
  const support = graphSupport(graph, contentHashByState);
  const hierarchy = buildMnemisHierarchy(graph);
  if (graph.episodes.length !== normalized.length) fail('scope_graph_incomplete');
  if (support.unsupportedEntities || support.unsupportedEdges) fail('derived_object_unsupported');
  const graphCommitment = sha256(JSON.stringify({
    schema: 'hom-aimos/mnemis-grounded-graph/v1',
    episodes: graph.episodes.map((episode) => [episode.state_id, contentHashByState.get(episode.state_id)]),
    entities: graph.entities.map((entity) => [entity.id, entity.episode_idx]),
    edges: graph.edges.map((edge) => [edge.id, edge.episode_idx]),
    episodic_edges: graph.episodic_edges.map((edge) => [edge.entity_id, edge.episode_id]),
    categories: hierarchy.categories.map((category) => [category.id, category.child_ids]),
    category_edges: hierarchy.category_edges.map((edge) => [edge.parent_id, edge.child_id]),
  }));
  return Object.freeze({
    graph,
    hierarchy,
    memoryById,
    graph_sha256: graphCommitment,
    diagnostics: Object.freeze({
      sources: normalized.length,
      episodes: graph.episodes.length,
      entities: graph.entities.length,
      edges: graph.edges.length,
      episodic_edges: graph.episodic_edges.length,
      unsupported_entities: support.unsupportedEntities,
      unsupported_edges: support.unsupportedEdges,
    }),
  });
}

export function rankMnemisGroundedSystem1({
  scope,
  queryText = '',
  queryEmbedding,
  baselineMemories,
  limit = MNEMIS_GROUNDED_SYSTEM1_CONTRACT.disclosure_limit,
} = {}) {
  if (!scope?.graph || !(scope.memoryById instanceof Map)) fail('grounded_scope_required');
  const embedding = parseEmbedding(queryEmbedding);
  if (!embedding) fail('query_embedding_invalid');
  if (!Array.isArray(baselineMemories) || !baselineMemories.length) fail('baseline_required');
  const resultLimit = boundedInteger(limit, 20, 1, 50);
  const baselineIds = [];
  const seenBaseline = new Set();
  for (const memory of baselineMemories) {
    const id = String(memory?.id || '').trim().toLowerCase();
    if (!scope.memoryById.has(id) || seenBaseline.has(id)) fail('baseline_outside_admitted_scope');
    seenBaseline.add(id);
    baselineIds.push(id);
  }

  const system1 = mnemisSystem1(scope.graph, queryText, embedding);
  const system1EpisodeRanks = reciprocalRankFusionMnemis(episodeLists(system1, scope.graph));
  const system1Ids = system1EpisodeRanks.map((row) => row.id.slice(8));
  const system2 = mnemisGlobalSelection(scope.graph, queryText, scope.hierarchy);
  const finalRanks = reciprocalRankFusionMnemis([
    baselineIds.map((id) => ({ id })),
    system1Ids.map((id) => ({ id })),
  ]).slice(0, resultLimit);
  const baselineSet = new Set(baselineIds);
  const rows = finalRanks.map((rank) => {
    const memory = scope.memoryById.get(rank.id);
    if (!memory) fail('ranked_identity_not_admitted');
    return Object.freeze({
      ...memory,
      mnemis_graph_only: !baselineSet.has(rank.id),
      mnemis_equal_weight_rrf: rank.score,
      retrieval_source: baselineSet.has(rank.id)
        ? (memory.retrieval_source || 'magma')
        : 'mnemis_system1_graph_discovery',
    });
  });
  const decisionBody = {
    schema: MNEMIS_GROUNDED_SYSTEM1_CONTRACT.schema,
    graph_sha256: scope.graph_sha256,
    baseline_count: baselineIds.length,
    system1_episode_count: system1Ids.length,
    returned_count: rows.length,
    graph_only_returned: rows.filter((row) => row.mnemis_graph_only).length,
    selected_memory_ids: rows.map((row) => String(row.id).toLowerCase()),
    system2_ordering: system2.ordering,
    system2_diagnostic_episode_count: system2.selected_episode_ids.length,
    system2_rank_influence: 0,
    final_reranker: 'deterministic_equal_weight_rrf_aimos_adaptation',
    model_or_generator_used: false,
    canonical_memory_mutated: false,
    retention_changed: false,
  };
  return Object.freeze({
    memories: Object.freeze(rows),
    decision: Object.freeze({
      ...decisionBody,
      decision_sha256: sha256(JSON.stringify(decisionBody)),
    }),
    diagnostics: Object.freeze({
      rank_sources: system1.rank_sources,
      selected_categories: system2.selected_categories.map((row) => row.label),
      system2_selected_episode_ids: Object.freeze([...system2.selected_episode_ids]),
      system2_is_unordered: system2.ordering === 'unordered_set',
      unsupported_entity_ratio: 0,
      unsupported_edge_ratio: 0,
    }),
  });
}
