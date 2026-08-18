/**
 * reconstructed-graph-native-candidate.js
 *
 * Permanent native adapter for the source-bound Reconstructed Graph G2
 * marginal gear. The proven mathematical kernel remains unchanged in
 * reconstructed-graph-additive/. This adapter accepts only provenance- and
 * Canary-admitted memories, measures bounded construction/ranking cost, and
 * emits one same-set rank signal for the existing graph-family channel.
 *
 * Paper authority: Ji, Li, and Hooi, "Memory is Reconstructed, Not Retrieved:
 * Graph Memory for LLM Agents" (ICML 2026, arXiv:2606.06036v1).
 */

import {
  RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT,
  buildReconstructedGraphMarginalWorkspace,
  rankReconstructedGraphMarginalWorkspace,
} from './reconstructed-graph-additive/reconstructed-graph-marginal-gear.js';
import { fuseBoundedGraphFamily } from './reconstructed-graph-additive/graph-family-bounded-fusion.js';

const NATIVE_WORKSPACE_STATES = 40;
const NATIVE_EMITTED_RANKS = 40;

export const RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT = Object.freeze({
  schema: 'hom-aimos/reconstructed-graph-native-candidate/v1',
  architecture_role: 'permanent_native_graph_family_subgear',
  paper_authority: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.paper_authority,
  adaptation: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.adaptation,
  fixed_corpus_proof_file_sha256: 'a62e0f31fdf9b565209c70d8a5d764ab78bc5bb7a684dc0595b651046899dc50',
  fixed_corpus_summary_sha256: 'b6688996d37aec1ad1c6abf45e3ef8a98674f1291439195d8d4f47e73e293bd9',
  fixed_corpus_predecessor_proof_file_sha256: '3bb1a6ebcda381151682a8cca5e073e1282d78fbdc4ee10626b384549f0b5d1e',
  fixed_corpus_exact_equivalence_questions: 840,
  graph_family_outer_channels: 1,
  graph_family_equation: 'max_reciprocal_rank_pooling',
  graph_family_duplicate_signal_idempotent: true,
  content_state_workspace_required_in_production: true,
  one_workspace_node_per_verified_content_state: true,
  maximum_workspace_states: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.maximum_workspace_states,
  maximum_emitted_ranks: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.maximum_emitted_ranks,
  native_workspace_states: NATIVE_WORKSPACE_STATES,
  native_emitted_ranks: NATIVE_EMITTED_RANKS,
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
  runtime_wired: true,
  time_complexity: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.time_complexity,
  space_complexity: RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.space_complexity,
});

export function composeNativeGraphFamilyChannel({
  magmaGear,
  reconstructedGraphGear = null,
  rrfK = 60,
  limit = 50,
  contentStateProjection = null,
} = {}) {
  return fuseBoundedGraphFamily({
    magmaGear,
    candidateGears: reconstructedGraphGear
      ? [{ name: 'reconstructed_graph', gear: reconstructedGraphGear }]
      : [],
    rrfK,
    limit,
    contentStateProjection,
  });
}

function fail(code) {
  throw new Error(`reconstructed_graph_native_candidate:${code}`);
}

function memoryId(memory) {
  return String(memory?.id || memory?.memory_id || '').trim().toLowerCase();
}

function normalizedSha256(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return bytes.length === 32 ? bytes.toString('hex') : null;
  }
  const text = String(value || '').trim();
  if (/^[a-f0-9]{64}$/i.test(text)) return text.toLowerCase();
  try {
    const bytes = Buffer.from(text, text.includes('-') || text.includes('_') ? 'base64url' : 'base64');
    if (bytes.length === 32) return bytes.toString('hex');
  } catch { /* fail closed below */ }
  return null;
}

function normalizeNativeBindings(memory) {
  const contentHash = [
    memory?.content_hash,
    memory?.provenance_proof?.live_content_hash,
    memory?.provenance_proof?.content_hash,
  ].map(normalizedSha256).find(Boolean);
  if (!contentHash) fail('content_binding_invalid');
  const provenanceSha256 = [
    memory?.provenance_sha256,
    memory?.provenance_proof?.binding_event_mutation_hash,
    memory?.provenance_proof?.binding_event_content_hash,
    memory?.provenance_proof?.binding_mutation_hash,
    memory?.provenance_proof?.save_mutation_hash,
  ].map(normalizedSha256).find(Boolean);
  if (!provenanceSha256) fail('provenance_binding_invalid');
  return Object.freeze({
    ...memory,
    content_hash: contentHash,
    provenance_sha256: provenanceSha256,
  });
}

export function composeReconstructedGraphNativeCandidate({
  admittedMemories = [],
  queryText = '',
  contentStateSelectionDecision = null,
  requireContentStateSelection = false,
} = {}) {
  if (!Array.isArray(admittedMemories) || admittedMemories.length === 0) {
    fail('admitted_memories_required');
  }
  if (admittedMemories.some((memory) => memory?.canary_admitted !== true)) {
    fail('canary_admission_required');
  }
  if (requireContentStateSelection
    && !/^[0-9a-f]{64}$/.test(String(contentStateSelectionDecision?.decision_sha256 || ''))) {
    fail('content_state_selection_required');
  }

  const boundMemories = admittedMemories.map(normalizeNativeBindings);
  const constructionStartedAt = performance.now();
  const workspace = buildReconstructedGraphMarginalWorkspace({
    admittedMemories: boundMemories,
    workspaceLimit: NATIVE_WORKSPACE_STATES,
  });
  const constructionRuntimeMs = Number((performance.now() - constructionStartedAt).toFixed(3));

  const rankingStartedAt = performance.now();
  const gear = rankReconstructedGraphMarginalWorkspace({
    queryText,
    workspace,
    rankLimit: NATIVE_EMITTED_RANKS,
  });
  const rankingRuntimeMs = Number((performance.now() - rankingStartedAt).toFixed(3));
  const selectedMemoryIds = Object.freeze(gear.ranks.map((rank) => memoryId(rank)).filter(Boolean));

  return Object.freeze({
    ...gear,
    decision: Object.freeze({
      ...gear.decision,
      edge_commitment_sha256: gear.decision.graph_sha256,
      selected_memory_ids: selectedMemoryIds,
      content_state_selection_decision_sha256:
        contentStateSelectionDecision?.decision_sha256 || null,
      content_state_input_occurrence_count:
        contentStateSelectionDecision?.unique_candidate_count || admittedMemories.length,
      content_state_selected_state_count: admittedMemories.length,
      content_state_workspace_count: gear.decision.workspace_population,
      content_state_collapsed_occurrence_count:
        contentStateSelectionDecision?.collapsed_occurrence_count || 0,
      one_workspace_node_per_verified_content_state: requireContentStateSelection,
      runtime_adapter_schema: RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.schema,
    }),
    runtime_breakdown_ms: Object.freeze({
      construction: constructionRuntimeMs,
      ranking: rankingRuntimeMs,
      total: Number((constructionRuntimeMs + rankingRuntimeMs).toFixed(3)),
    }),
    contract: RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT,
  });
}
