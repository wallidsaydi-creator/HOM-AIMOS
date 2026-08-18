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
import {
  buildCanaryMagmaGraphAdmission,
  createCanaryContentClassificationMap,
} from '../security/canary-tracker.js';

const MAX_DEPTH = 3;
const MAX_NODES = MAGMA_CONSTANTS.max_nodes;
const MAX_RESULTS = 50;
const MAX_FRONTIER_WIDTH = 5;
// MAGMA Table 5 fixes Phase-1 retrieval at top-k=20.  The complete native
// admitted population remains owned by central fusion; only this bounded
// prefix becomes the initial graph workspace.  This prevents another gear's
// candidate volume from silently scaling MAGMA's per-depth topology work.
const MAX_INITIAL_ANCHOR_POOL = 20;
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
  native_retrieval_gear: false,
  dormant_research: true,
  runtime_wired: false,
  runtime_mode: false,
  canonical_caller: null,
  architecture_authority: 'retained_source_only_no_runtime_pipeline_edge',
  calibration_authority: 'master_signed_system_config_optional_override',
  execution_authority: 'verified_agent_or_role_identity_envelope',
  governance_owner: 'housekeeper',
  maximum_depth: MAX_DEPTH,
  maximum_nodes: MAX_NODES,
  maximum_frontier_width: MAX_FRONTIER_WIDTH,
  beam_admission_order:
    'equation_5_priority_then_provenance_canary_state_admission_with_clean_backfill',
  beam_admission_authority: false,
  rejected_or_duplicate_beam_backfill: true,
  maximum_initial_anchor_pool: MAX_INITIAL_ANCHOR_POOL,
  maximum_graph_result_budget: MAX_RESULTS,
  graph_baseline_capacity_rule:
    'min(admitted_count,anchor_pool_limit,max_nodes_minus_result_budget)',
  maximum_incremental_output_candidates: MAX_RESULTS,
  output_policy: GEAR_OUTPUT_POLICY,
  content_state_workspace_required_in_production: true,
  one_graph_node_per_verified_content_state: true,
  duplicate_endpoint_path_amplification: false,
  restricted_connection_owner: 'shared_request_scoped_r4_session',
  maximum_additional_restricted_connections_per_request: 0,
  canary_magma_composition: 'required_before_anchor_and_endpoint_admission',
  canary_guarded_transition_equation:
    'T_C(i,j|q)=a_i*a_j*exp(lambda_structure*phi(r_ij,T_q)+lambda_semantic*cos(e_j,e_q))',
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
  version: 'hom-aimos/magma-retrieval-calibration/v3',
  max_depth: MAX_DEPTH,
  max_nodes: MAX_NODES,
  result_limit: 20,
  beam_width: MAX_FRONTIER_WIDTH,
  anchor_pool_limit: MAX_INITIAL_ANCHOR_POOL,
  rrf_k: MAGMA_CONSTANTS.rrf_k,
  candidate_p95_ceiling_ms: 250,
  candidate_p95_minimum_samples: 20,
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

function contentStateKey(memory, required = false) {
  const liveContentHash = String(memory?.provenance_proof?.live_content_hash || '').trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(liveContentHash)) return `state:${liveContentHash}`;
  if (required) fail('content_state_binding_required');
  const id = String(memory?.id || '').trim().toLowerCase();
  return id ? `legacy-id:${id}` : null;
}

function selectGraphStateRepresentatives(memories, selector, required = false) {
  const candidates = Array.isArray(memories) ? memories : [];
  if (required && typeof selector !== 'function') fail('content_state_selector_required');
  if (typeof selector !== 'function') {
    return Object.freeze({ memories: Object.freeze([...candidates]), decision: null });
  }
  const selected = selector(candidates);
  if (!selected || !Array.isArray(selected.memories)
    || !/^[0-9a-f]{64}$/.test(String(selected?.decision?.decision_sha256 || ''))) {
    fail('content_state_selection_invalid');
  }
  for (const memory of candidates) contentStateKey(memory, true);
  return selected;
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
  anchorPoolLimit = MAX_INITIAL_ANCHOR_POOL,
  retainedBaselineCount = null,
  governedCanaryDecision = null,
  canaryClassificationMap = null,
  admitEvidenceFn = null,
  selectStateRepresentativesFn = null,
  requireContentStateProjection = false,
  nativeReadQueryFn = null,
  readTopologyFn = readMagmaNativeTopology,
  readEvidenceFn = readMagmaNativeEvidence,
} = {}) {
  if (!recallAuthority) fail('authority_required');
  if (!Array.isArray(admittedMemories) || !admittedMemories.length) fail('admitted_memories_required');
  const classificationMap = canaryClassificationMap || createCanaryContentClassificationMap();
  const initialCanaryComposition = buildCanaryMagmaGraphAdmission(
    admittedMemories,
    { classificationMap },
  );
  const canaryGraphAdmittedMemories = initialCanaryComposition.graph_admitted_memories;
  if (!canaryGraphAdmittedMemories.length) fail('canary_graph_admitted_memories_empty');
  const initialStateSelection = selectGraphStateRepresentatives(
    canaryGraphAdmittedMemories,
    selectStateRepresentativesFn,
    requireContentStateProjection,
  );
  const graphAdmittedMemories = initialStateSelection.memories;
  if (!graphAdmittedMemories.length) fail('content_state_graph_admitted_memories_empty');
  const governedCanaryDecisionSha256 = String(
    governedCanaryDecision?.decision_sha256 || '',
  ).trim().toLowerCase();
  if (governedCanaryDecision != null && !/^[0-9a-f]{64}$/.test(governedCanaryDecisionSha256)) {
    fail('governed_canary_decision_invalid');
  }
  if (governedCanaryDecision
    && governedCanaryDecision.classification_map_root_sha256
      !== initialCanaryComposition.decision.classification_map_root_sha256) {
    fail('governed_canary_classification_map_mismatch');
  }
  const hasExplicitRetainedBaselineCount = retainedBaselineCount !== null
    && retainedBaselineCount !== undefined
    && String(retainedBaselineCount).trim() !== '';
  const centralRetainedBaselineCount = hasExplicitRetainedBaselineCount
    && Number.isInteger(Number(retainedBaselineCount))
    ? Number(retainedBaselineCount)
    : admittedMemories.length;
  if (centralRetainedBaselineCount < admittedMemories.length) fail('retained_baseline_count_invalid');
  const embedding = parseEmbedding(queryEmbedding);
  if (!embedding) fail('query_embedding_invalid');
  const resultLimit = boundedInteger(limit, 20, 1, MAX_RESULTS);
  const depthLimit = boundedInteger(maxDepth, MAX_DEPTH, 1, MAX_DEPTH);
  const nodeLimit = boundedInteger(maxNodes, MAX_NODES, resultLimit + 1, MAX_NODES);
  const beamLimit = boundedInteger(beamWidth, MAX_FRONTIER_WIDTH, 1, MAX_FRONTIER_WIDTH);
  const graphExpansionCapacity = nodeLimit - resultLimit;
  const configuredAnchorPoolLimit = boundedInteger(
    anchorPoolLimit,
    MAX_INITIAL_ANCHOR_POOL,
    1,
    MAX_INITIAL_ANCHOR_POOL,
  );
  const initialAnchorPoolLimit = Math.min(configuredAnchorPoolLimit, graphExpansionCapacity);
  const ownsNativeReadSession = readTopologyFn === readMagmaNativeTopology
    && readEvidenceFn === readMagmaNativeEvidence
    && typeof nativeReadQueryFn !== 'function';
  let nativeReadSession = null;
  let nativeReadSucceeded = false;
  const runtimeBreakdown = {
    session_open_ms: 0,
    topology_ms: 0,
    evidence_ms: 0,
    kernel_ms: 0,
  };
  const topologyReadRuntimeMs = [];
  const discoveryCanaryDecisions = [];
  const discoveryVerificationBatches = [];
  let discoveryCollapsedOccurrenceCount = 0;
  let discoveryPrunedCandidateCount = 0;
  let discoveryPreVerificationCollapsedOccurrenceCount = 0;
  let discoveryExistingStateProposalCount = 0;

  try {

  const baselineById = new Map();
  for (const memory of graphAdmittedMemories) {
    const id = String(memory?.id || '').trim().toLowerCase();
    if (!id || !memory?.provenance_proof) fail('unadmitted_anchor');
    if (!baselineById.has(id)) baselineById.set(id, memory);
  }
  const initialOrder = [...baselineById.keys()];
  const initialStateSet = new Set(
    graphAdmittedMemories.map((memory) => contentStateKey(memory, requireContentStateProjection)),
  );
  // MAX_NODES bounds MAGMA's incremental graph workspace, not the native
  // baseline that has already passed recall admission. Reserve resultLimit
  // slots for graph expansion and retain every baseline candidate in the
  // monotone coverage-fusion channel.
  const graphBaselineCapacity = initialAnchorPoolLimit;
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
      entityCandidateIds: [...graphMemoryById.keys()],
      queryFn: nativeReadQueryFn || nativeReadSession?.query,
    });
    const topologyReadMs = performance.now() - topologyStartedAt;
    runtimeBreakdown.topology_ms += topologyReadMs;
    topologyReadRuntimeMs.push(topologyReadMs);
    topologyDecisions.push(topology.decision || null);
    const targetIds = [];
    const preliminaryScoreByTarget = new Map();
    const proposalStateByTarget = new Map();
    for (const edge of Array.isArray(topology?.edges) ? topology.edges : []) {
      if (!graphMemoryById.has(edge.source_id)) fail('topology_source_not_admitted');
      if (!graphMemoryById.has(edge.target_id)) {
        targetIds.push(edge.target_id);
        proposalStateByTarget.set(
          edge.target_id,
          /^[0-9a-f]{64}$/.test(String(edge.target_content_hash || '').toLowerCase())
            ? `state:${String(edge.target_content_hash).toLowerCase()}`
            : `occurrence:${edge.target_id}`,
        );
        const score = transitionScoreMagma({
          relation: edge.relation,
          intentWeights,
          semanticSimilarity: Number.isFinite(Number(edge.query_similarity))
            ? Number(edge.query_similarity)
            : Number(edge.edge_weight || 0),
          queryEmbedding: embedding,
        });
        const previous = preliminaryScoreByTarget.get(edge.target_id);
        if (previous == null || score > previous) {
          preliminaryScoreByTarget.set(edge.target_id, score);
        }
      }
    }
    const remaining = Math.min(nodeLimit - graphMemoryById.size, beamLimit);
    const orderedTargetIds = [...new Set(targetIds)]
      .sort((left, right) => (preliminaryScoreByTarget.get(right) || 0)
        - (preliminaryScoreByTarget.get(left) || 0)
        || left.localeCompare(right));
    const existingRepresentativeByState = new Map(
      [...graphMemoryById.values()].map((memory) => [
        contentStateKey(memory, requireContentStateProjection),
        String(memory.id).toLowerCase(),
      ]),
    );
    const newStateTargetIds = orderedTargetIds.filter((targetId) => {
      const stateKey = proposalStateByTarget.get(targetId) || `occurrence:${targetId}`;
      return !initialStateSet.has(stateKey) && !existingRepresentativeByState.has(stateKey);
    });
    const existingStateProposalCount = orderedTargetIds.length - newStateTargetIds.length;
    discoveryExistingStateProposalCount += existingStateProposalCount;
    const primaryTargetIds = [];
    const fallbackTargetIds = [];
    const seenProposalStates = new Set();
    for (const targetId of newStateTargetIds) {
      const stateKey = proposalStateByTarget.get(targetId) || `occurrence:${targetId}`;
      if (seenProposalStates.has(stateKey)) fallbackTargetIds.push(targetId);
      else {
        seenProposalStates.add(stateKey);
        primaryTargetIds.push(targetId);
      }
    }
    const uniqueTargetIds = [...primaryTargetIds, ...fallbackTargetIds];
    const preVerificationCollapsedCount = orderedTargetIds.length - primaryTargetIds.length;
    discoveryPreVerificationCollapsedOccurrenceCount += preVerificationCollapsedCount;
    const discoveryGraphAdmittedMemories = [];
    const selectedDiscoveryByState = new Map();
    const newlyAdmitted = [];
    let verifiedCandidateCount = 0;
    let verificationBatchCount = 0;
    for (let offset = 0;
      offset < uniqueTargetIds.length && newlyAdmitted.length < remaining;
      offset += beamLimit) {
      const candidateIds = uniqueTargetIds.slice(offset, offset + beamLimit);
      verificationBatchCount += 1;
      verifiedCandidateCount += candidateIds.length;
      const evidenceStartedAt = performance.now();
      const evidence = await readEvidenceFn({
        recallAuthority,
        candidateIds,
        queryFn: nativeReadQueryFn || nativeReadSession?.query,
        admitFn: admitEvidenceFn || nativeReadSession?.admit,
      });
      runtimeBreakdown.evidence_ms += performance.now() - evidenceStartedAt;
      const discoveryCanaryComposition = buildCanaryMagmaGraphAdmission(
        Array.isArray(evidence?.memories) ? evidence.memories : [],
        { classificationMap },
      );
      discoveryCanaryDecisions.push(discoveryCanaryComposition.decision);
      discoveryGraphAdmittedMemories.push(
        ...discoveryCanaryComposition.graph_admitted_memories,
      );
      const discoveryStateSelection = selectGraphStateRepresentatives(
        discoveryCanaryComposition.graph_admitted_memories,
        selectStateRepresentativesFn,
        requireContentStateProjection,
      );
      discoveryCollapsedOccurrenceCount += Math.max(
        0,
        discoveryCanaryComposition.graph_admitted_memories.length
          - discoveryStateSelection.memories.length,
      );
      for (const memory of discoveryStateSelection.memories) {
        const stateKey = contentStateKey(memory, requireContentStateProjection);
        if (existingRepresentativeByState.has(stateKey)
            || selectedDiscoveryByState.has(stateKey)) {
          discoveryCollapsedOccurrenceCount += 1;
          continue;
        }
        selectedDiscoveryByState.set(stateKey, memory);
        newlyAdmitted.push(String(memory.id).toLowerCase());
        if (newlyAdmitted.length >= remaining) break;
      }
    }
    discoveryVerificationBatches.push(Object.freeze({
      depth: depth + 1,
      proposed_candidate_count: uniqueTargetIds.length,
      proposed_state_count: primaryTargetIds.length,
      pre_verification_collapsed_occurrence_count: preVerificationCollapsedCount,
      existing_state_proposal_count: existingStateProposalCount,
      verified_candidate_count: verifiedCandidateCount,
      verification_batch_count: verificationBatchCount,
      admitted_beam_count: newlyAdmitted.length,
      beam_width: beamLimit,
    }));
    discoveryPrunedCandidateCount += Math.max(0, uniqueTargetIds.length - verifiedCandidateCount);
    const representativeByOccurrenceId = new Map(
      [...graphMemoryById.keys()].map((id) => [id, id]),
    );
    for (const memory of discoveryGraphAdmittedMemories) {
      const id = String(memory?.id || '').trim().toLowerCase();
      const stateKey = contentStateKey(memory, requireContentStateProjection);
      const representative = existingRepresentativeByState.get(stateKey)
        || selectedDiscoveryByState.get(stateKey);
      if (!id || !representative) continue;
      representativeByOccurrenceId.set(
        id,
        typeof representative === 'string'
          ? representative
          : String(representative.id).toLowerCase(),
      );
    }
    const acceptedNewlyAdmitted = [];
    for (const memory of selectedDiscoveryByState.values()) {
      const stateKey = contentStateKey(memory, requireContentStateProjection);
      if (existingRepresentativeByState.has(stateKey)) continue;
      const id = String(memory?.id || '').trim().toLowerCase();
      if (!id || !memory?.provenance_proof || graphMemoryById.has(id)) continue;
      graphMemoryById.set(id, memory);
      existingRepresentativeByState.set(stateKey, id);
      acceptedNewlyAdmitted.push(id);
      if (graphMemoryById.size >= nodeLimit) break;
    }
    const normalizedTopologyEdges = [];
    for (const edge of Array.isArray(topology?.edges) ? topology.edges : []) {
      let sourceId = representativeByOccurrenceId.get(String(edge.source_id).toLowerCase())
        || String(edge.source_id).toLowerCase();
      let targetId = representativeByOccurrenceId.get(String(edge.target_id).toLowerCase())
        || String(edge.target_id).toLowerCase();
      if (!graphMemoryById.has(sourceId) || !graphMemoryById.has(targetId) || sourceId === targetId) continue;
      const traversalTargetId = targetId;
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
      normalizedTopologyEdges.push({ relation: normalized.relation, target_id: traversalTargetId });
    }
    const newlyAdmittedSet = new Set(acceptedNewlyAdmitted);
    const transitionScores = new Map();
    for (const edge of normalizedTopologyEdges) {
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
    frontier = acceptedNewlyAdmitted
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
    .filter((entry) => !initialStateSet.has(contentStateKey(
      graphMemoryById.get(entry.id),
      requireContentStateProjection,
    )))
    .map((entry) => {
      const memory = graphMemoryById.get(entry.id);
      return memory ? Object.freeze({
        ...memory,
        retrieval_source: 'magma_graph_discovery',
        magma_score: entry.score,
      }) : null;
    })
    .filter(Boolean));
  const usedEdges = [...edgesById.values()].sort((left, right) => left.id.localeCompare(right.id));
  const edgeCommitment = createHash('sha256').update(JSON.stringify(usedEdges)).digest('hex');
  const finalClassificationSnapshot = classificationMap.snapshot();
  const decisionBody = {
    schema: MAGMA_NATIVE_CANDIDATE_CONTRACT.schema,
    intent: graph.traversal.intent,
    retained_baseline_count: centralRetainedBaselineCount,
    initial_admitted_count: canaryGraphAdmittedMemories.length,
    initial_admitted_state_count: initialOrder.length,
    initial_collapsed_occurrence_count:
      canaryGraphAdmittedMemories.length - initialOrder.length,
    initial_content_state_selection_sha256:
      initialStateSelection.decision?.decision_sha256 || null,
    initial_canary_graph_admission_sha256:
      initialCanaryComposition.decision.decision_sha256,
    governed_canary_graph_admission_sha256:
      governedCanaryDecisionSha256 || null,
    classification_map_root_sha256:
      finalClassificationSnapshot.classification_map_root_sha256,
    classification_content_scans_executed:
      finalClassificationSnapshot.content_scans_executed,
    classification_content_rescans_executed: 0,
    initial_canary_withheld_count:
      initialCanaryComposition.decision.retained_evidence_count,
    discovery_canary_graph_admissions: Object.freeze(discoveryCanaryDecisions.map((decision) => Object.freeze({
      decision_sha256: decision.decision_sha256,
      input_count: decision.input_count,
      graph_admitted_count: decision.graph_admitted_count,
      retained_evidence_count: decision.retained_evidence_count,
    }))),
    discovery_canary_withheld_count: discoveryCanaryDecisions.reduce(
      (sum, decision) => sum + decision.retained_evidence_count,
      0,
    ),
    discovery_collapsed_occurrence_count: discoveryCollapsedOccurrenceCount,
    discovery_pruned_candidate_count: discoveryPrunedCandidateCount,
    discovery_pre_verification_collapsed_occurrence_count:
      discoveryPreVerificationCollapsedOccurrenceCount,
    discovery_existing_state_proposal_count: discoveryExistingStateProposalCount,
    discovery_verification_batches: Object.freeze(discoveryVerificationBatches),
    paper_beam_applied_before_graph_influence: true,
    pre_admission_priority_disclosure_authority: false,
    one_graph_node_per_verified_content_state: requireContentStateProjection,
    configured_anchor_pool_limit: configuredAnchorPoolLimit,
    initial_anchor_pool_limit: initialAnchorPoolLimit,
    graph_workspace_baseline_count: graphBaselineOrder.length,
    graph_workspace_reserved_capacity: nodeLimit - graphBaselineOrder.length,
    graph_admitted_count: graphMemoryById.size,
    ranked_count: ranks.length,
    discovered_count: discoveredMemories.length,
    graph_result_budget: resultLimit,
    maximum_graph_workspace_nodes: nodeLimit,
    maximum_incremental_output_candidates: resultLimit,
    maximum_output_candidates: centralRetainedBaselineCount + resultLimit,
    candidate_set_authority: false,
    baseline_candidate_set_changed: false,
    traversal_selected_count: selected.length,
    graph_discovered_ranked: ranks.filter((entry) => !initialStateSet.has(contentStateKey(
      graphMemoryById.get(entry.id),
      requireContentStateProjection,
    ))).length,
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
    marked_or_quarantined_graph_vote_count: 0,
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
    topology_read_runtime_ms: Object.freeze(
      topologyReadRuntimeMs.map((value) => Number(value.toFixed(3))),
    ),
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
