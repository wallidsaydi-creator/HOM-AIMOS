/**
 * magma-native-candidate.js — native MAGMA retrieval-gear evidence composer
 *
 * The composer expands only from already provenance-admitted recall evidence,
 * opens graph topology through magma-native-reader, and re-admits every newly
 * discovered endpoint before passing it to the pure MAGMA kernel. It emits one
 * ranked gear channel plus admitted graph discoveries to the central native
 * fusion layer. It does not own the candidate set, disclosure, Canary,
 * epistemic selection, SABER, persistence, or activation policy.
 */

import { createHash } from 'node:crypto';

import {
  MAGMA_CONSTANTS,
  identifyMagmaAnchors,
  relationIntentVectorMagma,
  runMagmaRetrievalKernel,
  transitionScoreMagma,
} from './magma-lineage-retriever.js';
import {
  openMagmaNativeReadSession,
  readMagmaNativeEvidence,
  readMagmaNativeTopology,
} from './magma-native-reader.js';

const MAX_DEPTH = 3;
const MAX_NODES = MAGMA_CONSTANTS.max_nodes;
const MAX_RESULTS = 50;
const MAX_FRONTIER_WIDTH = 5;
const GEAR_OUTPUT_POLICY = 'rank_evidence_for_central_native_rrf';
const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'by', 'did', 'do', 'does',
  'for', 'from', 'had', 'has', 'have', 'he', 'her', 'hers', 'him', 'his', 'how',
  'i', 'in', 'is', 'it', 'its', 'me', 'my', 'of', 'on', 'or', 'our', 'she',
  'that', 'the', 'their', 'them', 'they', 'this', 'to', 'was', 'we', 'were',
  'what', 'when', 'where', 'which', 'who', 'why', 'with', 'would', 'you', 'your',
]);

export const MAGMA_NATIVE_CANDIDATE_CONTRACT = Object.freeze({
  schema: 'hom-aimos/magma-native-gear/v2',
  native_retrieval_gear: true,
  runtime_mode: false,
  canonical_caller: 'native-recall-pipeline',
  architecture_authority: 'code_and_manifest_bound_native_retrieval',
  calibration_authority: 'master_signed_system_config_optional_override',
  execution_authority: 'verified_agent_or_role_identity_envelope',
  governance_owner: 'housekeeper',
  maximum_depth: MAX_DEPTH,
  maximum_nodes: MAX_NODES,
  maximum_frontier_width: MAX_FRONTIER_WIDTH,
  maximum_graph_result_budget: MAX_RESULTS,
  graph_baseline_capacity_rule: 'max_nodes_minus_result_budget',
  maximum_incremental_output_candidates: MAX_RESULTS,
  output_policy: GEAR_OUTPUT_POLICY,
  candidate_set_authority: false,
  environment_authority: false,
  database_writes: false,
  disclosure_authority: false,
  grant_authority: false,
  canary_authority: false,
  epistemic_authority: false,
  saber_runtime_authority: false,
});

export const MAGMA_NATIVE_CALIBRATION_DEFAULTS = Object.freeze({
  version: 'hom-aimos/magma-retrieval-calibration/v2',
  max_depth: MAX_DEPTH,
  max_nodes: MAX_NODES,
  result_limit: 20,
  beam_width: MAX_FRONTIER_WIDTH,
  rrf_k: MAGMA_CONSTANTS.rrf_k,
  candidate_p95_ceiling_ms: 250,
  source: 'immutable_code_default',
});

function fail(code) {
  throw new Error(`magma_native_candidate:${code}`);
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
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

function tokenize(value) {
  return new Set(
    String(value || '').toLowerCase().match(/[\p{L}\p{N}]+/gu)
      ?.filter((token) => token.length > 1 && !STOP_WORDS.has(token)) || [],
  );
}

function inferIntent(queryText) {
  const text = String(queryText || '').trim().toLowerCase();
  if (/^(when\b|before\b|after\b|during\b)/.test(text)) return 'WHEN';
  if (/^(why\b|how\b|what caused\b)/.test(text)) return 'WHY';
  if (/^(who\b|where\b)/.test(text)) return 'ENTITY';
  return 'SEMANTIC';
}

function edgeId(edge) {
  return createHash('sha256').update(
    `hom-aimos/magma-native-edge/v1\0${edge.relation}\0${edge.source_id}\0${edge.target_id}\0${edge.qualifier || ''}`,
  ).digest('hex');
}

function asNode(memory) {
  const id = String(memory?.id || '').trim().toLowerCase();
  const content = String(memory?.value || memory?.key || '').trim();
  if (!id || !content) return null;
  return {
    id,
    content,
    timestamp: memory.created_at || null,
    embedding: parseEmbedding(memory.embedding),
    reference_id: id,
    attributes: {
      key: memory.key || null,
      source: memory.source || null,
      memory_type: memory.memory_type || null,
      data_class: memory.data_class || null,
      provenance_event_id: memory.provenance_proof?.binding_event_id || null,
    },
  };
}

function lexicalRanks(memories, queryText) {
  const queryTokens = tokenize(queryText);
  return memories.map((memory) => {
    const memoryTokens = tokenize(`${memory?.key || ''} ${memory?.value || ''}`);
    let overlap = 0;
    for (const token of queryTokens) if (memoryTokens.has(token)) overlap += 1;
    return { id: String(memory.id), overlap };
  }).filter((row) => row.overlap > 0)
    .sort((left, right) => right.overlap - left.overlap || left.id.localeCompare(right.id));
}

export async function composeMagmaNativeCandidate({
  recallAuthority,
  admittedMemories,
  queryEmbedding,
  queryText,
  limit = 20,
  maxDepth = MAX_DEPTH,
  maxNodes = MAX_NODES,
  beamWidth = MAX_FRONTIER_WIDTH,
  readTopologyFn = readMagmaNativeTopology,
  readEvidenceFn = readMagmaNativeEvidence,
} = {}) {
  if (!recallAuthority) fail('authority_required');
  if (!Array.isArray(admittedMemories) || !admittedMemories.length) fail('admitted_memories_required');
  const embedding = parseEmbedding(queryEmbedding);
  if (!embedding) fail('query_embedding_invalid');
  const resultLimit = boundedInteger(limit, 20, 1, MAX_RESULTS);
  const depthLimit = boundedInteger(maxDepth, MAX_DEPTH, 1, MAX_DEPTH);
  const nodeLimit = boundedInteger(maxNodes, MAX_NODES, resultLimit + 1, MAX_NODES);
  const beamLimit = boundedInteger(beamWidth, MAX_FRONTIER_WIDTH, 1, MAX_FRONTIER_WIDTH);
  const ownsNativeReadSession = readTopologyFn === readMagmaNativeTopology
    && readEvidenceFn === readMagmaNativeEvidence;
  let nativeReadSession = null;
  let nativeReadSucceeded = false;
  const runtimeBreakdown = {
    session_open_ms: 0,
    topology_ms: 0,
    evidence_ms: 0,
    kernel_ms: 0,
  };

  try {

  const baselineById = new Map();
  for (const memory of admittedMemories) {
    const id = String(memory?.id || '').trim().toLowerCase();
    if (!id || !memory?.provenance_proof) fail('unadmitted_anchor');
    if (!baselineById.has(id)) baselineById.set(id, memory);
  }
  const initialOrder = [...baselineById.keys()];
  const initialIdSet = new Set(initialOrder);
  // MAX_NODES bounds MAGMA's incremental graph workspace, not the native
  // baseline that has already passed recall admission. Reserve resultLimit
  // slots for graph expansion and retain every baseline candidate in the
  // monotone coverage-fusion channel.
  const graphBaselineCapacity = nodeLimit - resultLimit;
  const graphBaselineOrder = initialOrder.slice(0, graphBaselineCapacity);
  const graphMemoryById = new Map(graphBaselineOrder.map((id) => [id, baselineById.get(id)]));
  const vectorRanks = graphBaselineOrder.map((id) => ({ id }));
  const intent = inferIntent(queryText);
  const intentWeights = relationIntentVectorMagma(intent);
  const anchors = identifyMagmaAnchors({
    vectorRanks,
    lexicalRanks: lexicalRanks([...graphMemoryById.values()], queryText),
    temporalRanks: [],
    topK: beamLimit,
  });
  if (!anchors.length) fail('anchors_empty');
  const sessionOpenStartedAt = performance.now();
  if (ownsNativeReadSession) {
    nativeReadSession = await openMagmaNativeReadSession({ recallAuthority });
  }
  runtimeBreakdown.session_open_ms = performance.now() - sessionOpenStartedAt;

  const topologyDecisions = [];
  const frontierWidths = [];
  const edgesById = new Map();
  let frontier = anchors.map((anchor) => anchor.id);
  for (let depth = 0; depth < depthLimit && frontier.length && graphMemoryById.size < nodeLimit; depth += 1) {
    frontierWidths.push(frontier.length);
    const topologyStartedAt = performance.now();
    const topology = await readTopologyFn({
      recallAuthority,
      frontierIds: frontier,
      queryEmbedding: embedding,
      queryFn: nativeReadSession?.query,
    });
    runtimeBreakdown.topology_ms += performance.now() - topologyStartedAt;
    topologyDecisions.push(topology.decision || null);
    const targetIds = [];
    for (const edge of Array.isArray(topology?.edges) ? topology.edges : []) {
      if (!graphMemoryById.has(edge.source_id)) fail('topology_source_not_admitted');
      if (!graphMemoryById.has(edge.target_id)) targetIds.push(edge.target_id);
    }
    const remaining = nodeLimit - graphMemoryById.size;
    const uniqueTargetIds = [...new Set(targetIds)].slice(0, remaining);
    const evidenceStartedAt = performance.now();
    const evidence = uniqueTargetIds.length
      ? await readEvidenceFn({
          recallAuthority,
          candidateIds: uniqueTargetIds,
          queryFn: nativeReadSession?.query,
          admitFn: nativeReadSession?.admit,
        })
      : { memories: [], decision: null };
    runtimeBreakdown.evidence_ms += performance.now() - evidenceStartedAt;
    const newlyAdmitted = [];
    for (const memory of Array.isArray(evidence?.memories) ? evidence.memories : []) {
      const id = String(memory?.id || '').trim().toLowerCase();
      if (!id || !memory?.provenance_proof || graphMemoryById.has(id)) continue;
      graphMemoryById.set(id, memory);
      newlyAdmitted.push(id);
      if (graphMemoryById.size >= nodeLimit) break;
    }
    for (const edge of Array.isArray(topology?.edges) ? topology.edges : []) {
      if (!graphMemoryById.has(edge.source_id) || !graphMemoryById.has(edge.target_id)) continue;
      let sourceId = edge.source_id;
      let targetId = edge.target_id;
      if (edge.relation === 'temporal') {
        const sourceTime = Date.parse(graphMemoryById.get(sourceId)?.created_at || '');
        const targetTime = Date.parse(graphMemoryById.get(targetId)?.created_at || '');
        if (!Number.isFinite(sourceTime) || !Number.isFinite(targetTime) || sourceTime === targetTime) continue;
        if (sourceTime > targetTime) [sourceId, targetId] = [targetId, sourceId];
      } else if (sourceId > targetId) {
        [sourceId, targetId] = [targetId, sourceId];
      }
      const normalized = {
        relation: edge.relation,
        source_id: sourceId,
        target_id: targetId,
        qualifier: edge.qualifier || '',
      };
      edgesById.set(edgeId(normalized), { id: edgeId(normalized), ...normalized });
    }
    const newlyAdmittedSet = new Set(newlyAdmitted);
    const transitionScores = new Map();
    for (const edge of Array.isArray(topology?.edges) ? topology.edges : []) {
      const targetId = String(edge?.target_id || '').trim().toLowerCase();
      if (!newlyAdmittedSet.has(targetId)) continue;
      const score = transitionScoreMagma({
        relation: edge.relation,
        intentWeights,
        neighborEmbedding: parseEmbedding(graphMemoryById.get(targetId)?.embedding),
        queryEmbedding: embedding,
      });
      const previous = transitionScores.get(targetId);
      if (previous == null || score > previous) transitionScores.set(targetId, score);
    }
    frontier = newlyAdmitted
      .sort((left, right) => (transitionScores.get(right) || 0) - (transitionScores.get(left) || 0)
        || left.localeCompare(right))
      .slice(0, beamLimit);
  }

  const nodes = [...graphMemoryById.values()].map(asNode).filter(Boolean);
  const kernelStartedAt = performance.now();
  const graph = runMagmaRetrievalKernel({
    nodes,
    edges: [...edgesById.values()].sort((left, right) => left.id.localeCompare(right.id)),
    vectorRanks,
    lexicalRanks: lexicalRanks([...graphMemoryById.values()], queryText),
    temporalRanks: [],
    queryEmbedding: embedding,
    intent,
    topK: beamLimit,
    maxDepth: depthLimit,
    beamWidth: beamLimit,
    budget: resultLimit,
  });
  runtimeBreakdown.kernel_ms = performance.now() - kernelStartedAt;
  const selected = graph.traversal.selected.slice(0, resultLimit);
  const ranks = Object.freeze(selected.map((entry, index) => {
    const score = Number(entry.cumulative_score);
    if (!Number.isFinite(score)) fail('rank_score_invalid');
    return Object.freeze({
      id: String(entry.id).toLowerCase(),
      rank: index + 1,
      score,
    });
  }));
  const discoveredMemories = Object.freeze(ranks
    .filter((entry) => !initialIdSet.has(entry.id))
    .map((entry) => {
      const memory = graphMemoryById.get(entry.id);
      return memory ? Object.freeze({
        ...memory,
        retrieval_source: 'magma_graph_discovery',
        magma_score: entry.score,
      }) : null;
    })
    .filter(Boolean));
  const initial = new Set(initialOrder);
  const usedEdges = [...edgesById.values()].sort((left, right) => left.id.localeCompare(right.id));
  const edgeCommitment = createHash('sha256').update(JSON.stringify(usedEdges)).digest('hex');
  const decisionBody = {
    schema: MAGMA_NATIVE_CANDIDATE_CONTRACT.schema,
    intent: graph.traversal.intent,
    initial_admitted_count: initialOrder.length,
    graph_workspace_baseline_count: graphBaselineOrder.length,
    graph_workspace_reserved_capacity: nodeLimit - graphBaselineOrder.length,
    graph_admitted_count: graphMemoryById.size,
    ranked_count: ranks.length,
    discovered_count: discoveredMemories.length,
    graph_result_budget: resultLimit,
    maximum_graph_workspace_nodes: nodeLimit,
    maximum_incremental_output_candidates: resultLimit,
    maximum_output_candidates: initialOrder.length + resultLimit,
    candidate_set_authority: false,
    baseline_candidate_set_changed: false,
    traversal_selected_count: selected.length,
    graph_discovered_ranked: ranks.filter((entry) => !initial.has(entry.id)).length,
    output_policy: GEAR_OUTPUT_POLICY,
    graph_nodes: graph.graph_stats.nodes,
    graph_edges: graph.graph_stats.edges,
    rejected_edges: graph.graph_stats.rejected_edges,
    traversal_depths: graph.traversal.trace.length,
    topology_reads: topologyDecisions.length,
    maximum_frontier_width: beamLimit,
    observed_frontier_widths: Object.freeze(frontierWidths),
    traversal_selected_memory_ids: Object.freeze(
      selected.map((entry) => String(entry.id).toLowerCase()),
    ),
    graph_discovered_memory_ids: Object.freeze(discoveredMemories.map((memory) => String(memory.id).toLowerCase())),
    edge_commitment_sha256: edgeCommitment,
    topology_decisions: Object.freeze(topologyDecisions),
    canonical_memory_mutated: false,
    retention_changed: false,
    canary_or_epistemic_disclosure_authority: false,
    saber_runtime_authority: false,
  };
  const decisionSha256 = createHash('sha256').update(JSON.stringify(decisionBody)).digest('hex');

  const output = Object.freeze({
    ranks,
    discovered_memories: discoveredMemories,
    runtime_breakdown_ms: Object.freeze(Object.fromEntries(
      Object.entries(runtimeBreakdown).map(([key, value]) => [key, Number(value.toFixed(3))]),
    )),
    decision: Object.freeze({
      ...decisionBody,
      decision_sha256: decisionSha256,
    }),
  });
  nativeReadSucceeded = true;
  return output;
  } finally {
    if (nativeReadSession) {
      await nativeReadSession.close({ commit: nativeReadSucceeded });
    }
  }
}
