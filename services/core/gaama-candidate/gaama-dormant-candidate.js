/**
 * gaama-dormant-candidate.js — isolated GAAMA Equations (1)–(5) candidate
 *
 * Paper authority:
 *   Paul and Sharma, "GAAMA — Graph Augmented Associative Memory" (2026),
 *   Section 3.3, Equations (1)–(5), Table 2.
 *
 * Status and boundary:
 *   - Native, pure, deterministic, database-independent candidate kernel.
 *   - No canonical caller, persistence, migration, server, or recall wiring.
 *   - Inputs must already be admitted evidence; this module grants no access.
 *   - It never deletes, suppresses, expires, decays, or mutates memory.
 *   - Persistent concept edges remain ineligible until a signed append-only
 *     housekeeper-authorized edge protocol exists.
 *
 * Mathematical note:
 *   Equation (3) multiplies every outgoing edge of a hub by the same scalar.
 *   Equation (2) then normalizes those edges per source. The scalar therefore
 *   cancels exactly. This module applies both published equations and reports
 *   the cancellation; it does not claim that the published operation reduces
 *   hub flow, and it does not substitute an unpublished correction.
 */

export const GAAMA_EDGE_TYPE_WEIGHTS = Object.freeze({
  NEXT: 0.8,
  DERIVED_FROM: 0.8,
  HAS_CONCEPT: 0.8,
  ABOUT_CONCEPT: 0.8,
  DERIVED_FROM_FACT: 0.5,
});

export const GAAMA_CONSTANTS = Object.freeze({
  seed_count: 40,
  expansion_depth: 2,
  alpha: 0.6,
  tolerance: 1e-6,
  max_iterations: 200,
  hub_degree_threshold: 50,
  ppr_weight: 0.1,
  similarity_weight: 1.0,
  max_nodes: 1024,
  max_edges: 16384,
});

export const GAAMA_GUARDRAILS = Object.freeze({
  dormant: true,
  canonical_caller: false,
  database_access: false,
  persistent_writes: false,
  environment_authority: false,
  input_authority: 'pre_admitted_evidence_only',
  retention_policy: 'full_retention_no_decay_no_suppression',
  persistent_edge_status: 'blocked_pending_signed_housekeeper_protocol',
});

const EPSILON = 1e-12;

function finiteNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(parsed)));
}

function stableId(value) {
  if (typeof value !== 'string') return null;
  const id = value.trim();
  return id.length > 0 ? id : null;
}

function stableCompare(a, b) {
  return String(a).localeCompare(String(b));
}

function clampUnit(value) {
  return Math.max(0, Math.min(1, finiteNumber(value, 0)));
}

function cloneVector(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const vector = value.map((entry) => Number(entry));
  return vector.every(Number.isFinite) ? vector : null;
}

function normalizeNode(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = stableId(raw.id ?? raw.node_id ?? raw.memory_id);
  if (!id) return null;
  return Object.freeze({
    id,
    node_type: typeof raw.node_type === 'string' ? raw.node_type : null,
    content: typeof raw.content === 'string'
      ? raw.content
      : (typeof raw.value === 'string' ? raw.value : ''),
    embedding: cloneVector(raw.embedding),
    reference_id: stableId(raw.reference_id ?? raw.provenance_id),
    timestamp: typeof raw.timestamp === 'string'
      ? raw.timestamp
      : (typeof raw.created_at === 'string' ? raw.created_at : null),
  });
}

function normalizeCandidate(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = stableId(raw.id ?? raw.node_id ?? raw.memory_id);
  if (!id) return null;
  return Object.freeze({
    id,
    similarity: clampUnit(raw.similarity ?? raw.cosine ?? raw.score),
    embedding: cloneVector(raw.embedding),
    node_type: typeof raw.node_type === 'string' ? raw.node_type : null,
    content: typeof raw.content === 'string'
      ? raw.content
      : (typeof raw.value === 'string' ? raw.value : ''),
    reference_id: stableId(raw.reference_id ?? raw.provenance_id),
    timestamp: typeof raw.timestamp === 'string'
      ? raw.timestamp
      : (typeof raw.created_at === 'string' ? raw.created_at : null),
  });
}

function normalizeEdge(raw, nodeIds) {
  if (!raw || typeof raw !== 'object') {
    return { edge: null, reason: 'malformed_edge' };
  }
  const sourceId = stableId(raw.source_id ?? raw.sourceId ?? raw.source);
  const targetId = stableId(raw.target_id ?? raw.targetId ?? raw.target);
  const edgeType = typeof (raw.edge_type ?? raw.edgeType ?? raw.type) === 'string'
    ? String(raw.edge_type ?? raw.edgeType ?? raw.type).trim().toUpperCase()
    : null;
  if (!sourceId || !targetId) return { edge: null, reason: 'missing_endpoint' };
  if (sourceId === targetId) return { edge: null, reason: 'self_edge' };
  if (!nodeIds.has(sourceId) || !nodeIds.has(targetId)) {
    return { edge: null, reason: 'unknown_endpoint' };
  }
  if (!Object.hasOwn(GAAMA_EDGE_TYPE_WEIGHTS, edgeType)) {
    return { edge: null, reason: 'unsupported_edge_type' };
  }
  const id = stableId(raw.id ?? raw.edge_id) ?? `${sourceId}:${edgeType}:${targetId}`;
  return {
    edge: Object.freeze({ id, source_id: sourceId, target_id: targetId, edge_type: edgeType }),
    reason: null,
  };
}

/** Exact cosine similarity, with malformed or zero vectors returning zero. */
export function cosineSimilarityGaama(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length === 0 || left.length !== right.length) {
    return 0;
  }
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (let index = 0; index < left.length; index += 1) {
    const a = Number(left[index]);
    const b = Number(right[index]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return 0;
    dot += a * b;
    leftNorm += a * a;
    rightNorm += b * b;
  }
  if (leftNorm <= 0 || rightNorm <= 0) return 0;
  return Math.max(-1, Math.min(1, dot / Math.sqrt(leftNorm * rightNorm)));
}

/**
 * Build the broad 2B pool and Equation (1) seed distribution.
 * Similarities are clamped at zero before squaring, matching the paper's KNN
 * interpretation and preventing an anti-similar vector from gaining mass.
 */
export function buildGaamaCandidatePool({ candidates = [], retrievalBudget = 160, seedCount = GAAMA_CONSTANTS.seed_count } = {}) {
  const budget = boundedInteger(retrievalBudget, 160, 1, Math.floor(GAAMA_CONSTANTS.max_nodes / 2));
  const expectedPoolSize = Math.min(GAAMA_CONSTANTS.max_nodes, 2 * budget);
  const deduplicated = new Map();
  for (const raw of Array.isArray(candidates) ? candidates : []) {
    const candidate = normalizeCandidate(raw);
    if (!candidate) continue;
    const current = deduplicated.get(candidate.id);
    if (!current || candidate.similarity > current.similarity) deduplicated.set(candidate.id, candidate);
  }
  const pool = [...deduplicated.values()]
    .sort((a, b) => (b.similarity - a.similarity) || stableCompare(a.id, b.id))
    .slice(0, expectedPoolSize);
  const requestedSeeds = boundedInteger(seedCount, GAAMA_CONSTANTS.seed_count, 1, GAAMA_CONSTANTS.seed_count);
  const seeds = pool.slice(0, Math.min(requestedSeeds, pool.length)).map((candidate) => Object.freeze({
    id: candidate.id,
    similarity: candidate.similarity,
    seed_weight: candidate.similarity ** 2,
  }));
  const seedWeightTotal = seeds.reduce((sum, seed) => sum + seed.seed_weight, 0);
  const teleport = new Map();
  for (const seed of seeds) {
    teleport.set(seed.id, seedWeightTotal > 0 ? seed.seed_weight / seedWeightTotal : 0);
  }
  return Object.freeze({
    retrieval_budget: budget,
    expected_pool_size: expectedPoolSize,
    observed_unique_candidates: deduplicated.size,
    pool_complete: pool.length === expectedPoolSize,
    pool: Object.freeze(pool),
    seeds: Object.freeze(seeds),
    teleport,
    positive_seed_mass: seedWeightTotal,
  });
}

/** Normalize nodes and typed edges without granting persistence or access. */
export function buildGaamaGraph({ nodes = [], edges = [], candidates = [] } = {}) {
  const nodeMap = new Map();
  const rejectedNodes = [];
  for (const raw of Array.isArray(nodes) ? nodes : []) {
    const node = normalizeNode(raw);
    if (!node) {
      rejectedNodes.push({ reason: 'malformed_node' });
      continue;
    }
    if (!nodeMap.has(node.id) && nodeMap.size < GAAMA_CONSTANTS.max_nodes) nodeMap.set(node.id, node);
  }
  for (const raw of Array.isArray(candidates) ? candidates : []) {
    const candidate = normalizeCandidate(raw);
    if (!candidate || nodeMap.has(candidate.id) || nodeMap.size >= GAAMA_CONSTANTS.max_nodes) continue;
    nodeMap.set(candidate.id, Object.freeze({
      id: candidate.id,
      node_type: candidate.node_type,
      content: candidate.content,
      embedding: candidate.embedding,
      reference_id: candidate.reference_id,
      timestamp: candidate.timestamp,
    }));
  }

  const nodeIds = new Set(nodeMap.keys());
  const normalizedEdges = [];
  const rejectedEdges = [];
  const seenEdges = new Set();
  for (const raw of Array.isArray(edges) ? edges : []) {
    if (normalizedEdges.length >= GAAMA_CONSTANTS.max_edges) {
      rejectedEdges.push({ reason: 'edge_cap_reached' });
      continue;
    }
    const normalized = normalizeEdge(raw, nodeIds);
    if (!normalized.edge) {
      rejectedEdges.push({ reason: normalized.reason });
      continue;
    }
    const key = `${normalized.edge.source_id}\u0000${normalized.edge.edge_type}\u0000${normalized.edge.target_id}`;
    if (seenEdges.has(key)) {
      rejectedEdges.push({ reason: 'duplicate_edge' });
      continue;
    }
    seenEdges.add(key);
    normalizedEdges.push(normalized.edge);
  }
  normalizedEdges.sort((a, b) => stableCompare(a.id, b.id));

  const adjacency = new Map([...nodeMap.keys()].map((id) => [id, []]));
  for (const edge of normalizedEdges) {
    adjacency.get(edge.source_id).push(Object.freeze({
      edge_id: edge.id,
      neighbor_id: edge.target_id,
      edge_type: edge.edge_type,
    }));
    adjacency.get(edge.target_id).push(Object.freeze({
      edge_id: edge.id,
      neighbor_id: edge.source_id,
      edge_type: edge.edge_type,
    }));
  }
  for (const entries of adjacency.values()) {
    entries.sort((a, b) => stableCompare(a.neighbor_id, b.neighbor_id) || stableCompare(a.edge_id, b.edge_id));
  }
  return Object.freeze({
    nodes: Object.freeze([...nodeMap.values()].sort((a, b) => stableCompare(a.id, b.id))),
    node_map: nodeMap,
    edges: Object.freeze(normalizedEdges),
    adjacency,
    rejected_nodes: Object.freeze(rejectedNodes),
    rejected_edges: Object.freeze(rejectedEdges),
  });
}

/** Breadth-first local-subgraph expansion from seeds to the paper default d=2. */
export function expandGaamaSubgraph({ graph, seedIds = [], depth = GAAMA_CONSTANTS.expansion_depth } = {}) {
  const expansionDepth = boundedInteger(depth, GAAMA_CONSTANTS.expansion_depth, 0, GAAMA_CONSTANTS.expansion_depth);
  const admittedSeeds = [...new Set((Array.isArray(seedIds) ? seedIds : []).map(stableId).filter(Boolean))]
    .filter((id) => graph?.node_map?.has(id))
    .sort(stableCompare);
  const selected = new Set(admittedSeeds);
  let frontier = admittedSeeds;
  const layers = [Object.freeze([...frontier])];
  for (let hop = 0; hop < expansionDepth && frontier.length > 0; hop += 1) {
    const next = new Set();
    for (const id of frontier) {
      for (const entry of graph.adjacency.get(id) ?? []) {
        if (selected.size >= GAAMA_CONSTANTS.max_nodes) break;
        if (!selected.has(entry.neighbor_id)) {
          selected.add(entry.neighbor_id);
          next.add(entry.neighbor_id);
        }
      }
    }
    frontier = [...next].sort(stableCompare);
    layers.push(Object.freeze(frontier));
  }
  const nodeIds = [...selected].sort(stableCompare);
  const selectedSet = new Set(nodeIds);
  const localEdges = graph.edges.filter((edge) => selectedSet.has(edge.source_id) && selectedSet.has(edge.target_id));
  return Object.freeze({
    seed_ids: Object.freeze(admittedSeeds),
    node_ids: Object.freeze(nodeIds),
    edges: Object.freeze(localEdges),
    layers: Object.freeze(layers),
    expansion_depth: expansionDepth,
  });
}

/**
 * Apply Equations (2) and (3) to the local graph.
 * Every paper edge is traversable in both directions, as in the reference
 * implementation. Parallel typed relations are summed by destination.
 */
export function buildGaamaTransitions({ nodeIds = [], edges = [], hubThreshold = GAAMA_CONSTANTS.hub_degree_threshold } = {}) {
  const ids = [...new Set((Array.isArray(nodeIds) ? nodeIds : []).map(stableId).filter(Boolean))].sort(stableCompare);
  const idSet = new Set(ids);
  const outgoing = new Map(ids.map((id) => [id, []]));
  for (const edge of Array.isArray(edges) ? edges : []) {
    if (!edge || !idSet.has(edge.source_id) || !idSet.has(edge.target_id)) continue;
    const base = GAAMA_EDGE_TYPE_WEIGHTS[edge.edge_type];
    if (!Number.isFinite(base) || base <= 0) continue;
    outgoing.get(edge.source_id).push({ target_id: edge.target_id, edge_type: edge.edge_type, base_weight: base });
    outgoing.get(edge.target_id).push({ target_id: edge.source_id, edge_type: edge.edge_type, base_weight: base });
  }

  const threshold = boundedInteger(hubThreshold, GAAMA_CONSTANTS.hub_degree_threshold, 1, GAAMA_CONSTANTS.max_edges);
  const transitions = new Map();
  const diagnostics = [];
  for (const id of ids) {
    const entries = outgoing.get(id) ?? [];
    const degree = entries.length;
    const hubScale = Math.min(1, threshold / Math.max(1, degree));
    const scaled = entries.map((entry) => ({ ...entry, damped_weight: entry.base_weight * hubScale }));
    const total = scaled.reduce((sum, entry) => sum + entry.damped_weight, 0);
    const byTarget = new Map();
    if (total > 0) {
      for (const entry of scaled) {
        byTarget.set(entry.target_id, (byTarget.get(entry.target_id) ?? 0) + (entry.damped_weight / total));
      }
    }
    const row = [...byTarget.entries()]
      .map(([target_id, probability]) => Object.freeze({ target_id, probability }))
      .sort((a, b) => stableCompare(a.target_id, b.target_id));
    transitions.set(id, Object.freeze(row));
    const probabilitySum = row.reduce((sum, entry) => sum + entry.probability, 0);
    diagnostics.push(Object.freeze({
      source_id: id,
      degree,
      hub_scale: hubScale,
      is_hub: degree > threshold,
      probability_sum: probabilitySum,
      hub_scale_cancels_under_row_normalization: degree > threshold && total > 0,
    }));
  }
  return Object.freeze({
    transitions,
    diagnostics: Object.freeze(diagnostics),
    hub_threshold: threshold,
    row_stochastic: diagnostics.every((row) => row.degree === 0 || Math.abs(row.probability_sum - 1) <= EPSILON),
    published_hub_dampening_effective: false,
    published_hub_dampening_reason: 'uniform_source_scalar_cancels_in_equation_2_row_normalization',
  });
}

/** Equation (4), including teleport redistribution of all sink mass. */
export function personalizedPageRankGaama({
  nodeIds = [],
  transitions,
  teleport,
  alpha = GAAMA_CONSTANTS.alpha,
  tolerance = GAAMA_CONSTANTS.tolerance,
  maxIterations = GAAMA_CONSTANTS.max_iterations,
} = {}) {
  const ids = [...new Set((Array.isArray(nodeIds) ? nodeIds : []).map(stableId).filter(Boolean))].sort(stableCompare);
  const damping = Math.max(0, Math.min(1, finiteNumber(alpha, GAAMA_CONSTANTS.alpha)));
  const epsilon = Math.max(Number.EPSILON, finiteNumber(tolerance, GAAMA_CONSTANTS.tolerance));
  const iterationsCap = boundedInteger(maxIterations, GAAMA_CONSTANTS.max_iterations, 1, GAAMA_CONSTANTS.max_iterations);
  const teleportWeights = new Map();
  let teleportTotal = 0;
  for (const id of ids) {
    const value = Math.max(0, finiteNumber(teleport?.get?.(id), 0));
    teleportWeights.set(id, value);
    teleportTotal += value;
  }
  if (ids.length === 0 || teleportTotal <= 0) {
    return Object.freeze({
      scores: new Map(ids.map((id) => [id, 0])),
      normalized_scores: new Map(ids.map((id) => [id, 0])),
      converged: false,
      iterations: 0,
      final_l1_delta: 0,
      probability_mass: 0,
      termination_reason: ids.length === 0 ? 'empty_graph' : 'no_positive_seed_mass',
    });
  }
  const v = new Map(ids.map((id) => [id, teleportWeights.get(id) / teleportTotal]));
  let scores = new Map(v);
  let converged = false;
  let finalDelta = Number.POSITIVE_INFINITY;
  let completedIterations = 0;

  for (let iteration = 1; iteration <= iterationsCap; iteration += 1) {
    let sinkMass = 0;
    for (const id of ids) {
      if ((transitions?.get?.(id) ?? []).length === 0) sinkMass += scores.get(id) ?? 0;
    }
    const next = new Map(ids.map((id) => [id, ((1 - damping) + (damping * sinkMass)) * (v.get(id) ?? 0)]));
    for (const sourceId of ids) {
      const sourceScore = scores.get(sourceId) ?? 0;
      for (const entry of transitions?.get?.(sourceId) ?? []) {
        if (!next.has(entry.target_id)) continue;
        next.set(entry.target_id, next.get(entry.target_id) + (damping * sourceScore * entry.probability));
      }
    }
    finalDelta = ids.reduce((sum, id) => sum + Math.abs((next.get(id) ?? 0) - (scores.get(id) ?? 0)), 0);
    scores = next;
    completedIterations = iteration;
    if (finalDelta < epsilon) {
      converged = true;
      break;
    }
  }

  const maxScore = Math.max(0, ...scores.values());
  const normalized = new Map(ids.map((id) => [id, maxScore > 0 ? scores.get(id) / maxScore : 0]));
  const probabilityMass = [...scores.values()].reduce((sum, value) => sum + value, 0);
  return Object.freeze({
    scores,
    normalized_scores: normalized,
    converged,
    iterations: completedIterations,
    final_l1_delta: finalDelta,
    probability_mass: probabilityMass,
    termination_reason: converged ? 'l1_converged' : 'iteration_cap_reached',
  });
}

/** Equation (5), including on-demand similarity for graph-discovered nodes. */
export function scoreGaamaCandidates({
  candidateIds = [],
  candidateSimilarity = new Map(),
  graph,
  queryEmbedding = null,
  pprScores = new Map(),
} = {}) {
  const ids = [...new Set((Array.isArray(candidateIds) ? candidateIds : []).map(stableId).filter(Boolean))].sort(stableCompare);
  const rawSimilarity = new Map();
  for (const id of ids) {
    if (candidateSimilarity?.has?.(id)) {
      rawSimilarity.set(id, clampUnit(candidateSimilarity.get(id)));
      continue;
    }
    const nodeEmbedding = graph?.node_map?.get(id)?.embedding;
    rawSimilarity.set(id, clampUnit(cosineSimilarityGaama(nodeEmbedding, queryEmbedding)));
  }
  const maxSimilarity = Math.max(0, ...rawSimilarity.values());
  const rows = ids.map((id) => {
    const similarity = maxSimilarity > 0 ? rawSimilarity.get(id) / maxSimilarity : 0;
    const ppr = clampUnit(pprScores?.get?.(id));
    return Object.freeze({
      id,
      ppr,
      similarity,
      score: (GAAMA_CONSTANTS.ppr_weight * ppr) + (GAAMA_CONSTANTS.similarity_weight * similarity),
      graph_discovered: !candidateSimilarity?.has?.(id),
    });
  });
  rows.sort((a, b) => (b.score - a.score) || stableCompare(a.id, b.id));
  return Object.freeze(rows);
}

/** Complete injected-evidence-only GAAMA candidate pipeline. */
export function runGaamaDormantCandidate({
  candidates = [],
  nodes = [],
  edges = [],
  queryEmbedding = null,
  retrievalBudget = 160,
  seedCount = GAAMA_CONSTANTS.seed_count,
  expansionDepth = GAAMA_CONSTANTS.expansion_depth,
} = {}) {
  const pool = buildGaamaCandidatePool({ candidates, retrievalBudget, seedCount });
  const graph = buildGaamaGraph({ nodes, edges, candidates: pool.pool });
  const subgraph = expandGaamaSubgraph({
    graph,
    seedIds: pool.seeds.map((seed) => seed.id),
    depth: expansionDepth,
  });
  const transition = buildGaamaTransitions({ nodeIds: subgraph.node_ids, edges: subgraph.edges });
  const ppr = personalizedPageRankGaama({
    nodeIds: subgraph.node_ids,
    transitions: transition.transitions,
    teleport: pool.teleport,
  });
  const candidateSimilarity = new Map(pool.pool.map((candidate) => [candidate.id, candidate.similarity]));
  const allCandidateIds = [...new Set([...pool.pool.map((candidate) => candidate.id), ...subgraph.node_ids])];
  const ranking = scoreGaamaCandidates({
    candidateIds: allCandidateIds,
    candidateSimilarity,
    graph,
    queryEmbedding,
    pprScores: ppr.normalized_scores,
  });
  return Object.freeze({
    status: 'dormant_candidate_complete',
    guardrails: GAAMA_GUARDRAILS,
    candidate_pool: pool,
    graph,
    subgraph,
    transition,
    ppr,
    ranking,
  });
}
