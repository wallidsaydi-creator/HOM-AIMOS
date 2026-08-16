/**
 * reconstructed-graph-additive/reconstructed-graph-marginal-gear.js
 *
 * Dormant bounded marginal-gear adaptation of Ji, Li, and Hooi,
 * "Memory is Reconstructed, Not Retrieved: Graph Memory for LLM Agents"
 * (ICML 2026, arXiv:2606.06036v1).
 *
 * The paper's Cue-Tag-Content relation and active reconstruction operators are
 * retained through reconstructed-graph-grounded-candidate.js. This successor
 * changes authority, not paper identity: it emits a rank signal over the
 * already admitted native candidate set. It does not own final ranking and it
 * cannot introduce graph-only memories. That boundary directly addresses the
 * retained G1 relevance-contamination result without rewriting it.
 */

import { createHash } from 'node:crypto';

import {
  buildGroundedCueTagContentGraph,
  reconstructGroundedEvidence,
} from '../reconstructed-graph-grounded-candidate.js';

// The native candidate population is retained in full by the outer fusion.
// This cap bounds only the transient Cue-Tag-Content workspace: at most
// 120 * 8 * 8 = 7,680 committed relations before deduplication.
const MAX_WORKSPACE_STATES = 120;
const MAX_RANKS = 40;

export const RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT = Object.freeze({
  schema: 'hom-aimos/reconstructed-graph-marginal-gear/v1',
  paper_authority: 'Ji_Li_Hooi_2026_MRAgent_Cue_Tag_Content',
  adaptation: 'deterministic_extractive_same_admitted_set_rank_signal',
  maximum_workspace_states: MAX_WORKSPACE_STATES,
  maximum_emitted_ranks: MAX_RANKS,
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
  time_complexity: 'O(n_log_n_plus_n_cue_tag_bound)',
  space_complexity: 'O(n_cue_tag_bound)',
});

function fail(code) {
  throw new Error(`reconstructed_graph_marginal_gear:${code}`);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
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

function memoryId(memory) {
  return String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
}

function normalizeAdmittedMemories(memories, workspaceLimit) {
  if (!Array.isArray(memories) || !memories.length) fail('admitted_memories_required');
  const seen = new Set();
  const rows = [];
  for (const memory of memories) {
    const id = memoryId(memory);
    const text = String(memory?.value ?? memory?.text ?? memory?.memory?.value ?? '').trim();
    const contentHash = String(memory?.content_hash ?? memory?.memory?.content_hash ?? '').toLowerCase();
    const provenanceAdmitted = memory?.provenance_admitted === true || Boolean(memory?.provenance_proof);
    const canaryAdmitted = memory?.canary_admitted === true;
    if (!id || seen.has(id)) continue;
    if (!text || !/^[a-f0-9]{64}$/.test(contentHash)) fail('content_binding_invalid');
    if (!provenanceAdmitted) fail('provenance_admission_required');
    if (!canaryAdmitted) fail('canary_admission_required');
    seen.add(id);
    rows.push({
      id,
      text,
      content_hash: contentHash,
      provenance_sha256: String(memory?.provenance_sha256
        ?? memory?.provenance_proof?.binding_event_mutation_hash
        ?? memory?.provenance_proof?.binding_event_content_hash
        ?? '').toLowerCase(),
      provenance_admitted: true,
      canary_admitted: true,
      scope_id: String(memory?.scope_id ?? memory?.source ?? ''),
      session_id: String(memory?.session_id ?? ''),
    });
    if (rows.length >= workspaceLimit) break;
  }
  if (!rows.length) fail('admitted_workspace_empty');
  return rows;
}

/**
 * Build the bounded transient Cue-Tag-Content workspace independently from a
 * query. Keeping construction separate lets the paired proof report its cost
 * without charging it to the per-query rank signal or hiding it in a combined
 * timer. The returned workspace owns no persistence or disclosure authority.
 */
export function buildReconstructedGraphMarginalWorkspace({
  admittedMemories = [],
  workspaceLimit = MAX_WORKSPACE_STATES,
} = {}) {
  const boundedWorkspace = boundedInteger(
    workspaceLimit,
    MAX_WORKSPACE_STATES,
    1,
    MAX_WORKSPACE_STATES,
  );
  const states = normalizeAdmittedMemories(admittedMemories, boundedWorkspace);
  const graph = buildGroundedCueTagContentGraph(states);
  return Object.freeze({
    states: Object.freeze(states),
    graph,
    decision: Object.freeze({
      schema: 'hom-aimos/reconstructed-graph-marginal-workspace/v1',
      graph_sha256: graph.graph_sha256,
      admitted_population: new Set(admittedMemories.map(memoryId).filter(Boolean)).size,
      workspace_population: states.length,
      workspace_capped: states.length < admittedMemories.length,
      canonical_memory_mutated: false,
      persistence_authority: false,
    }),
  });
}

/** Rank one already-built, bounded workspace for one query. */
export function rankReconstructedGraphMarginalWorkspace({
  queryText = '',
  workspace,
  rankLimit = MAX_RANKS,
} = {}) {
  const query = String(queryText || '').trim();
  if (!query) fail('query_required');
  if (!workspace?.graph || !Array.isArray(workspace?.states) || !workspace.states.length) {
    fail('workspace_required');
  }
  const boundedRanks = boundedInteger(rankLimit, MAX_RANKS, 1, MAX_RANKS);
  const admittedIds = new Set(workspace.states.map((state) => state.id));
  const reconstruction = reconstructGroundedEvidence({ graph: workspace.graph, queryText: query });
  if (reconstruction.unsupported_edge_ratio !== 0) fail('unsupported_edge_observed');
  if (reconstruction.ungrounded_disclosure_ratio_at_20 !== 0) fail('ungrounded_path_observed');

  const ranks = reconstruction.discoveries
    .filter((row) => admittedIds.has(String(row?.state_id || '').toLowerCase()))
    .map((row) => ({
      id: String(row.state_id).toLowerCase(),
      score: Number(row.score),
      path_sha256: String(row?.path?.path_sha256 || ''),
      content_hash: String(row.content_hash || ''),
    }))
    .filter((row) => Number.isFinite(row.score)
      && /^[a-f0-9]{64}$/.test(row.path_sha256)
      && /^[a-f0-9]{64}$/.test(row.content_hash))
    .sort((left, right) => right.score - left.score || left.id.localeCompare(right.id))
    .slice(0, boundedRanks)
    .map((row, index) => Object.freeze({ ...row, rank: index + 1 }));

  const decisionBody = {
    schema: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.schema,
    query_sha256: sha256(query),
    graph_sha256: workspace.graph.graph_sha256,
    admitted_population: admittedIds.size,
    workspace_population: workspace.states.length,
    emitted_rank_count: ranks.length,
    graph_only_discovery_count: 0,
    unsupported_edge_ratio: reconstruction.unsupported_edge_ratio,
    ungrounded_disclosure_ratio_at_20: reconstruction.ungrounded_disclosure_ratio_at_20,
    candidate_set_authority: false,
    disclosure_authority: false,
    canonical_memory_mutated: false,
    rank_commitment_sha256: sha256(JSON.stringify(canonicalRecord(ranks))),
  };
  const decisionSha256 = sha256(JSON.stringify(canonicalRecord(decisionBody)));

  return Object.freeze({
    ranks: Object.freeze(ranks),
    discovered_memories: Object.freeze([]),
    decision: Object.freeze({ ...decisionBody, decision_sha256: decisionSha256 }),
    diagnostics: Object.freeze({
      trace_steps: reconstruction.trace.length,
      traversed_edges: reconstruction.traversed_edges,
      unsupported_edges: reconstruction.unsupported_edges,
      ungrounded_disclosures: reconstruction.ungrounded_disclosures,
      graph_disclosure_denominator: reconstruction.graph_discovery_denominator,
      workspace_capped: workspace.decision.workspace_capped,
    }),
    contract: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT,
  });
}

/**
 * Emit one dormant structural rank signal over an already admitted set.
 * Returned ranks are a subset of the input identities; discovered_memories is
 * intentionally empty. Native fusion remains the only rank/disclosure owner.
 */
export function composeReconstructedGraphMarginalGear({
  queryText = '',
  admittedMemories = [],
  workspaceLimit = MAX_WORKSPACE_STATES,
  rankLimit = MAX_RANKS,
} = {}) {
  const workspace = buildReconstructedGraphMarginalWorkspace({ admittedMemories, workspaceLimit });
  return rankReconstructedGraphMarginalWorkspace({
    queryText,
    workspace,
    rankLimit,
  });
}
