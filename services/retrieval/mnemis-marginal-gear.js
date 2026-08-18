/**
 * mnemis-marginal-gear.js
 *
 * Dormant Mnemis M2 rank-only graph-family sub-gear. The gear constructs the
 * paper's Episode, Entity, Edge, and Episodic-Edge objects only over an exact,
 * provenance- and Canary-admitted native workspace. It contributes the
 * class-separated System-1 cosine/BM25/RRF signal inside the single bounded
 * graph-family channel. It cannot discover, delete, persist, mutate, or
 * disclose a memory, and the model-guided System-2 route has zero influence.
 *
 * Paper authority: Shi et al., "Mnemis: Dual-Route Retrieval on Hierarchical
 * Graphs for Long-Term LLM Memory" (arXiv:2602.15313v2, 2026).
 */

import { createHash } from 'node:crypto';

import {
  buildMnemisBaseGraph,
  mnemisSystem1EpisodeEvidence,
} from './mnemis-dual-route-graph.js';

const MAX_WORKSPACE_STATES = 40;
const MAX_ADMITTED_POPULATION = 120;
const MAX_EMITTED_RANKS = 40;
const MAX_ENTITIES_PER_EPISODE = 12;
const MAX_EDGES_PER_EPISODE = (
  MAX_ENTITIES_PER_EPISODE * (MAX_ENTITIES_PER_EPISODE - 1)
) / 2;

export const MNEMIS_MARGINAL_GEAR_CONTRACT = Object.freeze({
  schema: 'hom-aimos/mnemis-marginal-gear/v1',
  architecture_role: 'dormant_graph_family_subgear_candidate',
  paper_authority: 'Shi_et_al_2026_Mnemis_System1',
  adaptation: 'deterministic_same_admitted_set_system1_rank_signal',
  maximum_workspace_states: MAX_WORKSPACE_STATES,
  maximum_admitted_population: MAX_ADMITTED_POPULATION,
  maximum_entities_per_episode: MAX_ENTITIES_PER_EPISODE,
  maximum_edges_per_episode: MAX_EDGES_PER_EPISODE,
  maximum_pre_dedup_edges: MAX_WORKSPACE_STATES * MAX_EDGES_PER_EPISODE,
  maximum_emitted_ranks: MAX_EMITTED_RANKS,
  graph_family_outer_channels: 1,
  graph_family_equation: 'max_reciprocal_rank_pooling',
  system1_object_classes: Object.freeze(['episode', 'entity', 'edge']),
  system2_rank_influence: 0,
  candidate_set_monotone: true,
  graph_only_discoveries: false,
  candidate_set_authority: false,
  disclosure_authority: false,
  persistence_authority: false,
  signing_authority: false,
  mutation_authority: false,
  deletion_authority: false,
  environment_authority: false,
  model_authority: false,
  runtime_wired: false,
  time_complexity: 'O(n_e_squared_plus_n_e_d_plus_objects_log_objects)',
  space_complexity: 'O(n_e_squared_plus_n_e_d)',
});

function fail(code) {
  throw new Error(`mnemis_marginal_gear:${code}`);
}

function memoryId(memory) {
  return String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
}

function finiteEmbedding(value) {
  let source = value;
  if (typeof source === 'string') {
    const text = source.trim();
    if (!text.startsWith('[') || !text.endsWith(']')) return null;
    source = text.slice(1, -1).split(',').map((entry) => entry.trim());
  }
  if (!Array.isArray(source) && !ArrayBuffer.isView(source)) return null;
  const embedding = Array.from(source, Number);
  return embedding.length > 0 && embedding.every(Number.isFinite) ? embedding : null;
}

function normalizedSha256(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return bytes.length === 32 ? bytes.toString('hex') : null;
  }
  const text = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(text) ? text : null;
}

/**
 * Exact evidence-eligibility predicate for the paper's System-1 route.
 * Ineligible canonical memories remain retained and available to every other
 * native gear; they simply contribute zero Mnemis evidence.
 */
export function isMnemisMarginalInputEligible(memory) {
  const contentHash = [
    memory?.content_hash,
    memory?.provenance_proof?.live_content_hash,
    memory?.provenance_proof?.content_hash,
  ].map(normalizedSha256).find(Boolean);
  const provenanceSha256 = [
    memory?.provenance_sha256,
    memory?.provenance_proof?.binding_event_mutation_hash,
    memory?.provenance_proof?.binding_event_content_hash,
    memory?.provenance_proof?.save_mutation_hash,
  ].map(normalizedSha256).find(Boolean);
  return Boolean(
    memoryId(memory)
    && String(memory?.value ?? memory?.text ?? '').trim()
    && finiteEmbedding(memory?.embedding)
    && contentHash
    && provenanceSha256
    && memory?.provenance_proof
    && memory?.canary_admitted === true
  );
}

function canonicalRecord(value) {
  if (Array.isArray(value)) return value.map(canonicalRecord);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([, field]) => field !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, field]) => [key, canonicalRecord(field)]));
  }
  return value;
}

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function normalizeAdmittedMemories(memories) {
  if (!Array.isArray(memories) || !memories.length) fail('admitted_memories_required');
  if (memories.length > MAX_ADMITTED_POPULATION) fail('admitted_population_limit_exceeded');
  const seen = new Set();
  const validated = memories.map((memory) => {
    const id = memoryId(memory);
    const text = String(memory?.value ?? memory?.text ?? '').trim();
    const embedding = finiteEmbedding(memory?.embedding);
    const contentHash = [
      memory?.content_hash,
      memory?.provenance_proof?.live_content_hash,
      memory?.provenance_proof?.content_hash,
    ].map(normalizedSha256).find(Boolean);
    const provenanceSha256 = [
      memory?.provenance_sha256,
      memory?.provenance_proof?.binding_event_mutation_hash,
      memory?.provenance_proof?.binding_event_content_hash,
      memory?.provenance_proof?.save_mutation_hash,
    ].map(normalizedSha256).find(Boolean);
    if (!id || seen.has(id)) fail('identity_invalid');
    if (!text) fail('content_missing');
    if (!embedding) fail('embedding_invalid');
    if (!contentHash || !provenanceSha256 || !memory?.provenance_proof) {
      fail('provenance_admission_required');
    }
    if (memory?.canary_admitted !== true) fail('canary_admission_required');
    seen.add(id);
    return Object.freeze({
      id,
      text,
      embedding,
      memory: Object.freeze({
        value: text,
        embedding,
        created_at: memory?.created_at || null,
      }),
      content_hash: contentHash,
      provenance_sha256: provenanceSha256,
    });
  });
  return Object.freeze({
    admittedPopulation: validated.length,
    workspaceCapped: validated.length > MAX_WORKSPACE_STATES,
    states: Object.freeze(validated.slice(0, MAX_WORKSPACE_STATES)),
  });
}

/** Build one exact, query-independent, bounded transient Mnemis workspace. */
export function buildMnemisMarginalWorkspace({ admittedMemories = [] } = {}) {
  const normalized = normalizeAdmittedMemories(admittedMemories);
  const states = normalized.states;
  const graph = buildMnemisBaseGraph(states, MAX_WORKSPACE_STATES);
  if (graph.episodes.length !== states.length) fail('episode_population_incomplete');
  if (graph.entities.length > states.length * MAX_ENTITIES_PER_EPISODE) {
    fail('entity_bound_exceeded');
  }
  if (graph.edges.length > states.length * MAX_EDGES_PER_EPISODE) {
    fail('edge_bound_exceeded');
  }
  const admittedIds = new Set(states.map((state) => state.id));
  if (graph.entities.some((entity) => entity.episode_idx.some(
    (episodeId) => !admittedIds.has(String(episodeId).slice(8)),
  ))) fail('unsupported_entity');
  if (graph.edges.some((edge) => edge.episode_idx.some(
    (episodeId) => !admittedIds.has(String(episodeId).slice(8)),
  ))) fail('unsupported_edge');

  const commitmentBody = {
    schema: 'hom-aimos/mnemis-marginal-workspace/v1',
    episodes: graph.episodes.map((episode) => [
      episode.state_id,
      states.find((state) => state.id === episode.state_id)?.content_hash,
    ]),
    entities: graph.entities.map((entity) => [entity.id, entity.episode_idx]),
    edges: graph.edges.map((edge) => [edge.id, edge.episode_idx]),
    episodic_edges: graph.episodic_edges.map((edge) => [edge.entity_id, edge.episode_id]),
  };
  return Object.freeze({
    states: Object.freeze(states),
    graph,
    decision: Object.freeze({
      ...commitmentBody,
      workspace_sha256: sha256(JSON.stringify(canonicalRecord(commitmentBody))),
      admitted_population: normalized.admittedPopulation,
      workspace_population: states.length,
      workspace_capped: normalized.workspaceCapped,
      canonical_memory_mutated: false,
      retention_changed: false,
    }),
  });
}

/** Rank only identities already present in the exact transient workspace. */
export function rankMnemisMarginalWorkspace({
  workspace,
  queryText = '',
  queryEmbedding,
  rankLimit = MAX_EMITTED_RANKS,
} = {}) {
  const query = String(queryText || '').trim();
  const embedding = finiteEmbedding(queryEmbedding);
  if (!workspace?.graph || !Array.isArray(workspace?.states) || !workspace.states.length) {
    fail('workspace_required');
  }
  if (!query) fail('query_required');
  if (!embedding) fail('query_embedding_invalid');
  const limit = Math.max(1, Math.min(
    MAX_EMITTED_RANKS,
    Math.floor(Number(rankLimit) || MAX_EMITTED_RANKS),
  ));
  const admittedIds = new Set(workspace.states.map((state) => state.id));
  const evidence = mnemisSystem1EpisodeEvidence(
    workspace.graph,
    query,
    embedding,
  );
  const ranks = evidence.ranks
    .map((row) => ({
      id: String(row.id || '').startsWith('episode:')
        ? String(row.id).slice(8).toLowerCase()
        : '',
      score: Number(row.normalized_score),
      raw_rrf_score: Number(row.score),
      source_count: Number(row.sources),
    }))
    .filter((row) => admittedIds.has(row.id) && row.score > 0)
    .sort((left, right) => right.score - left.score
      || right.raw_rrf_score - left.raw_rrf_score
      || left.id.localeCompare(right.id))
    .slice(0, limit)
    .map((row, index) => Object.freeze({ ...row, rank: index + 1 }));
  if (ranks.some((row) => !admittedIds.has(row.id))) fail('outside_identity_emitted');

  const decisionBody = {
    schema: MNEMIS_MARGINAL_GEAR_CONTRACT.schema,
    query_sha256: sha256(query),
    workspace_sha256: workspace.decision.workspace_sha256,
    admitted_population: admittedIds.size,
    emitted_rank_count: ranks.length,
    graph_only_discovery_count: 0,
    system2_rank_influence: 0,
    system1_object_rank_count: evidence.object_rank_count,
    rank_sources: evidence.rank_sources,
    candidate_set_authority: false,
    disclosure_authority: false,
    canonical_memory_mutated: false,
    retention_changed: false,
    rank_commitment_sha256: sha256(JSON.stringify(canonicalRecord(ranks))),
  };
  return Object.freeze({
    ranks: Object.freeze(ranks),
    discovered_memories: Object.freeze([]),
    decision: Object.freeze({
      ...decisionBody,
      decision_sha256: sha256(JSON.stringify(canonicalRecord(decisionBody))),
    }),
    diagnostics: Object.freeze({
      admitted_population: workspace.decision.admitted_population,
      workspace_population: workspace.decision.workspace_population,
      workspace_capped: workspace.decision.workspace_capped,
      episodes: workspace.graph.episodes.length,
      entities: workspace.graph.entities.length,
      edges: workspace.graph.edges.length,
      episodic_edges: workspace.graph.episodic_edges.length,
      unsupported_entities: 0,
      unsupported_edges: 0,
      graph_only_disclosures: 0,
      system2_rank_influence: 0,
    }),
    contract: MNEMIS_MARGINAL_GEAR_CONTRACT,
  });
}

export function composeMnemisMarginalGear({
  admittedMemories = [],
  queryText = '',
  queryEmbedding,
  rankLimit = MAX_EMITTED_RANKS,
} = {}) {
  const workspace = buildMnemisMarginalWorkspace({ admittedMemories });
  return rankMnemisMarginalWorkspace({ workspace, queryText, queryEmbedding, rankLimit });
}
