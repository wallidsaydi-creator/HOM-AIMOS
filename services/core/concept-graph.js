/**
 * concept-graph.js — Four-Node-Type Knowledge Graph (P0-B3-4)
 * Source: GAAMA — Graph Augmented Associative Memory (Nagarro, 2026)
 * Additive Priority TEM authority: MAGMA (Jiang et al., arXiv:2601.03236, 2026)
 * and Graph-based Agent Memory survey (Yang et al., arXiv:2602.05665, 2026)
 * for multi-view graph lineage surfaces. PPR/math below remains governed by
 * this file's original formulas.
 * Additive Wave 2 authority: Pooling Engram Conditional Memory in Large
 * Language Models using CXL (Ma et al., 2026). Aimos maps the paper's sparse,
 * read-only, latency-tolerant Engram pool to existing co-activation links in
 * memory_cross_refs. This adds bounded associative expansion, not new deletion,
 * PPR, or calibrated recall math.
 * Additive Batch9/9.5 Wave5 authority: Ontology-Aware Design Patterns,
 * SigGate-GT, and 3D Gaussian Splatting. Aimos exposes typed ontology
 * diagnostics and graph over-smoothing proxy checks only; PPR, hub dampening,
 * and hybrid score formulas remain unchanged.
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildNeuromorphicSDMDiagnostic: SDM-style address-space diagnostic
 *     alongside PPR graph traversal. PPR traversal unchanged.
 * Batch 10 Lane 3: VSA binding + HRR self-attention recasting
 *   - computeVSABinding: XOR binding for bipolar graph edge vectors
 *   - computeHRRAttention: circular convolution self-attention recasting
 *   These are alongside-path diagnostics. PPR traversal unchanged.
 *   Aladdin: VSA/HRR are retrieval augmentations. Graph content and PPR
 *   traversal are never modified.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (RECALL pipeline, step 12)
 * 2. → Pulls from: aimos_memories (SQL query for graph traversal)
 * 3. → Pushes to: aimos_memories (PPR augmented results)
 * 4. ↔ Interacts with: services/core/embeddings.js (PPR + cosine hybrid scoring)
 *
 * LOGIC GUIDE: Adds concept-mediated graph structure on top of embeddings. 
 * Resolves episodic, fact, reflection, and concept nodes. 
 * Hybrid scoring: score = 0.1 * PPR + 1.0 * cosine_sim.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (RECALL pipeline, step 12)
// → Calls: services/core/embeddings.js (PPR + cosine hybrid scoring)
// Pipeline: RECALL_PIPELINE
// Position: hybrid retrieval with PPR
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from './runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from './embeddings.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;
const HUB_DEGREE_THRESHOLD = 50;
const PPR_WEIGHT = 0.1;
const COSINE_WEIGHT = 1.0;
const PPR_DAMPING = 0.85;
const PPR_ITERATIONS = 10;
const ENGRAM_POOL_MAX_ASSOCIATIONS = 8;
const WAVE5_GRAPH_DIAGNOSTIC_AUTHORITIES = [
  'SigGate-GT: Taming Over-Smoothing in Graph Transformers via Sigmoid-Gated Attention',
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'Generative 3D Gaussian Splatting for Arbitrary-Resolution Atmospheric Downscaling and Forecasting',
];

// ─── SCHEMA ───────────────────────────────────────────────────────────────
/**
 * Extract concept labels from a memory value.
 * Returns 2-5 word snake_case concept labels.
 * Avoids person-entity nodes (mega-hub problem).
 *
 * @param {string} text
 * @returns {string[]} concept labels
 */
export function extractConcepts(text) {
  const s = String(text || '').toLowerCase();
  const concepts = new Set();

  // Pattern-based concept extraction (no LLM needed for common patterns)
  const patterns = {
    'agent_orchestration': /\b(agent|orchestrat|delegat|coordinator)\b/,
    'memory_system': /\b(memory|aimos|recall|retriev|embed)\b/,
    'security': /\b(security|firewall|injection|attack|defense)\b/,
    'dream_consolidation': /\b(dream|consolidat|nightly|reflection)\b/,
    'skill_learning': /\b(skill|learn|procedural|mastery)\b/,
    'architecture': /\b(architecture|design|system|component)\b/,
    'trust_scoring': /\b(trust|score|confidence|reliability)\b/,
    'governance': /\b(governance|judge|jury|attorney|audit)\b/,
    'user_interaction': /\b(user|client|customer|session|chat)\b/,
    'data_pipeline': /\b(pipeline|ingest|process|transform)\b/,
    'error_handling': /\b(error|fail|exception|retry|fallback)\b/,
    'performance': /\b(latency|throughput|speed|optim|benchmark)\b/,
    'deployment': /\b(deploy|production|release|ship)\b/,
    'revenue': /\b(revenue|pricing|payment|stripe|subscription)\b/,
  };

  for (const [concept, pattern] of Object.entries(patterns)) {
    if (pattern.test(s)) concepts.add(concept);
  }

  return Array.from(concepts).slice(0, 5);
}

/**
 * Create a concept node if it doesn't exist.
 *
 * @param {string} conceptLabel - snake_case label
 * @param {string} companyId
 * @returns {Promise<string>} concept memory ID
 */
export async function ensureConceptNode(conceptLabel, companyId = COMPANY) {
  const key = `concept:${conceptLabel}`;

  const existing = await query(
    `SELECT id FROM aimos_memories WHERE company_id = $1 AND key = $2 AND node_type = 'concept' LIMIT 1`,
    [companyId, key]
  );
  if (existing.rows.length > 0) return existing.rows[0].id;

  const result = await persistMemory({
    company_id: companyId,
    agent_id: 'concept-graph',
    mutation_authority: 'housekeeper',
    key,
    value: conceptLabel,
    scope: 'system',
    memory_type: 'concept',
    memory_tier: 'long-term',
    clearance_level: 5,
  });
  return result.id;
}

/**
 * Link a memory to its concept nodes.
 *
 * @param {string} memoryId
 * @param {string[]} conceptLabels
 * @param {string} companyId
 */
export async function linkToConcepts(memoryId, conceptLabels, companyId = COMPANY) {
  for (const label of conceptLabels) {
    const conceptId = await ensureConceptNode(label, companyId);
    await query(
      `INSERT INTO concept_edges (company_id, source_id, target_id, edge_type)
       VALUES ($1, $2::uuid, $3::uuid, 'HAS_CONCEPT')
       ON CONFLICT DO NOTHING`,
      [companyId, memoryId, conceptId]
    );
  }
}

/**
 * Create a derived-from edge (fact from episode, reflection from facts).
 */
export async function linkDerived(sourceId, targetId, edgeType, companyId = COMPANY) {
  await query(
    `INSERT INTO concept_edges (company_id, source_id, target_id, edge_type)
     VALUES ($1, $2::uuid, $3::uuid, $4)
     ON CONFLICT DO NOTHING`,
    [companyId, sourceId, targetId, edgeType]
  );
}

/**
 * Hub dampening: for nodes with degree > threshold, scale edge weights.
 * When degreeMap is provided, uses pre-fetched data (zero DB queries).
 *
 * @param {string} nodeId
 * @param {string} companyId
 * @param {Map<string, number>} [degreeMap] - optional pre-fetched node degrees
 * @returns {number|Promise<number>} dampening factor (0-1)
 */
function getHubDampening(nodeId, companyId, degreeMap) {
  if (degreeMap) {
    const degree = degreeMap.get(nodeId) || 0;
    return Math.min(1, HUB_DEGREE_THRESHOLD / Math.max(degree, 1));
  }
  // Fallback: individual DB query (used by callers outside localPPR)
  return query(
    `SELECT COUNT(*) as degree FROM concept_edges
     WHERE company_id = $1 AND (source_id = $2::uuid OR target_id = $2::uuid)`,
    [companyId, nodeId]
  ).then(degreeResult => {
    const degree = parseInt(degreeResult.rows[0]?.degree || '0', 10);
    return Math.min(1, HUB_DEGREE_THRESHOLD / Math.max(degree, 1));
  });
}

/**
 * Personalized PageRank on local subgraph from seed memories.
 * Seeds are top-K cosine-similar memories to the query.
 *
 * @param {string[]} seedIds - memory IDs to start from (top KNN results)
 * @param {number[]} seedWeights - w_seed = cosine_sim^2
 * @param {string} companyId
 * @param {number} hops - subgraph expansion hops (default 2)
 * @returns {Promise<Map<string, number>>} nodeId → PPR score
 */
export async function localPPR(seedIds, seedWeights, companyId = COMPANY, hops = 2) {
  if (seedIds.length === 0) return new Map();

  // Expand local subgraph
  const subgraphNodes = new Set(seedIds);
  let frontier = [...seedIds];

  for (let h = 0; h < hops; h++) {
    if (frontier.length === 0) break;
    const neighbors = await query(
      `SELECT DISTINCT target_id as id FROM concept_edges WHERE company_id = $1 AND source_id = ANY($2::uuid[])
       UNION
       SELECT DISTINCT source_id as id FROM concept_edges WHERE company_id = $1 AND target_id = ANY($2::uuid[])`,
      [companyId, frontier]
    );
    frontier = [];
    for (const r of neighbors.rows) {
      if (!subgraphNodes.has(r.id)) {
        subgraphNodes.add(r.id);
        frontier.push(r.id);
      }
    }
  }

  // ─── BATCH PRE-FETCH: all edges and degrees for the subgraph (2 queries total) ───
  const nodeArray = Array.from(subgraphNodes);

  const [edgesResult, degreeResult] = await Promise.all([
    // 1. Fetch ALL edges touching any subgraph node in one query
    query(
      `SELECT source_id, target_id, weight FROM concept_edges
       WHERE company_id = $1 AND (source_id = ANY($2::uuid[]) OR target_id = ANY($2::uuid[]))`,
      [companyId, nodeArray]
    ),
    // 2. Pre-compute degree for all subgraph nodes in one query
    query(
      `SELECT id, SUM(degree)::int as degree FROM (
         SELECT source_id as id, COUNT(*) as degree FROM concept_edges
         WHERE company_id = $1 AND source_id = ANY($2::uuid[])
         GROUP BY source_id
         UNION ALL
         SELECT target_id as id, COUNT(*) as degree FROM concept_edges
         WHERE company_id = $1 AND target_id = ANY($2::uuid[])
         GROUP BY target_id
       ) sub GROUP BY id`,
      [companyId, nodeArray]
    ),
  ]);

  // Build in-memory adjacency list: nodeId → [{ neighbor, weight }]
  const adjacency = new Map();
  for (const id of subgraphNodes) adjacency.set(id, []);
  for (const row of edgesResult.rows) {
    const src = row.source_id;
    const tgt = row.target_id;
    const w = parseFloat(row.weight) || 1.0;
    if (subgraphNodes.has(src) && subgraphNodes.has(tgt)) {
      adjacency.get(src).push({ neighbor: tgt, weight: w });
      adjacency.get(tgt).push({ neighbor: src, weight: w });
    } else if (subgraphNodes.has(src)) {
      adjacency.get(src).push({ neighbor: tgt, weight: w });
    } else if (subgraphNodes.has(tgt)) {
      adjacency.get(tgt).push({ neighbor: src, weight: w });
    }
  }

  // Build degree map for hub dampening
  const degreeMap = new Map();
  for (const row of degreeResult.rows) {
    degreeMap.set(row.id, parseInt(row.degree, 10));
  }

  // Initialize PPR scores
  const scores = new Map();
  const totalSeedWeight = seedWeights.reduce((a, b) => a + b, 0) || 1;
  for (const id of subgraphNodes) scores.set(id, 0);
  for (let i = 0; i < seedIds.length; i++) {
    scores.set(seedIds[i], (seedWeights[i] || 0) / totalSeedWeight);
  }

  // Power iteration (pure in-memory — zero DB queries)
  for (let iter = 0; iter < PPR_ITERATIONS; iter++) {
    const newScores = new Map();
    for (const id of subgraphNodes) newScores.set(id, 0);

    // Teleport component
    for (let i = 0; i < seedIds.length; i++) {
      const current = newScores.get(seedIds[i]) || 0;
      newScores.set(seedIds[i], current + (1 - PPR_DAMPING) * ((seedWeights[i] || 0) / totalSeedWeight));
    }

    // Random walk component (in-memory adjacency traversal)
    for (const [id, score] of scores) {
      if (score <= 0) continue;
      const dampening = getHubDampening(id, companyId, degreeMap);
      const contribution = PPR_DAMPING * score * dampening;

      const neighbors = adjacency.get(id) || [];
      const neighborCount = neighbors.length || 1;
      for (const { neighbor } of neighbors) {
        if (subgraphNodes.has(neighbor)) {
          const current = newScores.get(neighbor) || 0;
          newScores.set(neighbor, current + contribution / neighborCount);
        }
      }
    }

    // Update
    for (const [id, score] of newScores) scores.set(id, score);
  }

  return scores;
}

/**
 * Hybrid retrieval: PPR + cosine similarity.
 * score(n) = PPR_WEIGHT * ppr(n) + COSINE_WEIGHT * cosine_sim(n, query)
 *
 * @param {string} queryText
 * @param {string} companyId
 * @param {number} limit
 * @param {number[]|null} [precomputedEmbedding] - optional pre-computed embedding to skip redundant getEmbedding call
 * @returns {Promise<Array<{ id: string, score: number, ppr: number, cosine: number }>>}
 */
export async function hybridRetrieve(queryText, companyId = COMPANY, limit = 10, precomputedEmbedding = null) {
  const embedding = precomputedEmbedding || await getEmbedding(queryText);
  if (!embedding || embedding._degraded) return [];

  // Get top-40 KNN seeds
  const knn = await query(
    `SELECT id, 1 - (embedding <=> $1::vector) as similarity
     FROM aimos_memories
     WHERE company_id = $2 AND embedding IS NOT NULL
     ORDER BY embedding <=> $1::vector ASC
     LIMIT 40`,
    [JSON.stringify(embedding), companyId]
  );

  if (knn.rows.length === 0) return [];

  const seedIds = knn.rows.map(r => r.id);
  const seedWeights = knn.rows.map(r => Math.pow(parseFloat(r.similarity), 2));

  // Run PPR
  const pprScores = await localPPR(seedIds, seedWeights, companyId);

  // Combine: PPR + cosine
  const results = knn.rows.map(r => {
    const cosine = parseFloat(r.similarity);
    const ppr = pprScores.get(r.id) || 0;
    const score = PPR_WEIGHT * ppr + COSINE_WEIGHT * cosine;
    return { id: r.id, score, ppr, cosine };
  });

  // Add PPR-discovered nodes not in KNN
  for (const [id, ppr] of pprScores) {
    if (!seedIds.includes(id) && ppr > 0.01) {
      results.push({ id, score: PPR_WEIGHT * ppr, ppr, cosine: 0 });
    }
  }

  return results
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

// ─── PHASE 4: CENTRALITY & CONNECTED RETRIEVAL ──────────────────────────

/**
 * Degree centrality for a node in the concept graph.
 *
 * @param {string} nodeId
 * @param {string} companyId
 * @returns {Promise<{ inDegree: number, outDegree: number, totalDegree: number, normalized: number }>}
 */
export async function degreeCentrality(nodeId, companyId = COMPANY) {
  const [inResult, outResult, totalEdgesResult] = await Promise.all([
    query(
      `SELECT COUNT(*) as cnt FROM concept_edges WHERE company_id = $1 AND target_id = $2::uuid`,
      [companyId, nodeId]
    ),
    query(
      `SELECT COUNT(*) as cnt FROM concept_edges WHERE company_id = $1 AND source_id = $2::uuid`,
      [companyId, nodeId]
    ),
    query(
      `SELECT COUNT(*) as cnt FROM concept_edges WHERE company_id = $1`,
      [companyId]
    ),
  ]);

  const inDegree = parseInt(inResult.rows[0]?.cnt || '0', 10);
  const outDegree = parseInt(outResult.rows[0]?.cnt || '0', 10);
  const totalDegree = inDegree + outDegree;
  const totalEdgesInGraph = parseInt(totalEdgesResult.rows[0]?.cnt || '0', 10);
  const normalized = totalEdgesInGraph > 0 ? totalDegree / totalEdgesInGraph : 0;

  return { inDegree, outDegree, totalDegree, normalized };
}

/**
 * Approximate betweenness centrality via random sampling.
 * Samples `sampleSize` random node pairs and runs BFS shortest paths,
 * counting how many pass through `nodeId`.
 *
 * Exact betweenness is O(V*E) — this approximation trades accuracy for speed.
 *
 * @param {string} nodeId
 * @param {string} companyId
 * @param {number} sampleSize
 * @returns {Promise<{ betweenness: number, sampleSize: number, pathsThrough: number, totalPaths: number }>}
 */
export async function betweennessCentrality(nodeId, companyId = COMPANY, sampleSize = 50) {
  // Get all nodes in the graph
  const nodesResult = await query(
    `SELECT DISTINCT id FROM (
       SELECT source_id AS id FROM concept_edges WHERE company_id = $1
       UNION
       SELECT target_id AS id FROM concept_edges WHERE company_id = $1
     ) AS nodes`,
    [companyId]
  );

  const allNodes = nodesResult.rows.map(r => r.id);
  if (allNodes.length < 3) {
    return { betweenness: 0, sampleSize: 0, pathsThrough: 0, totalPaths: 0 };
  }

  // Build adjacency list in memory for BFS efficiency
  const edgesResult = await query(
    `SELECT source_id, target_id FROM concept_edges WHERE company_id = $1`,
    [companyId]
  );

  const adjacency = new Map();
  for (const row of edgesResult.rows) {
    if (!adjacency.has(row.source_id)) adjacency.set(row.source_id, []);
    if (!adjacency.has(row.target_id)) adjacency.set(row.target_id, []);
    adjacency.get(row.source_id).push(row.target_id);
    adjacency.get(row.target_id).push(row.source_id);
  }

  // BFS shortest path returning all nodes on the path (or null if unreachable)
  function bfsPath(start, end) {
    if (start === end) return [start];
    const visited = new Set([start]);
    const queue = [[start]];
    while (queue.length > 0) {
      const path = queue.shift();
      const current = path[path.length - 1];
      const neighbors = adjacency.get(current) || [];
      for (const neighbor of neighbors) {
        if (neighbor === end) return [...path, neighbor];
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      }
    }
    return null;
  }

  // Sample random pairs
  let pathsThrough = 0;
  let totalPaths = 0;
  const effectiveSamples = Math.min(sampleSize, allNodes.length * (allNodes.length - 1) / 2);

  const sampledPairs = new Set();
  let attempts = 0;
  while (sampledPairs.size < effectiveSamples && attempts < effectiveSamples * 3) {
    attempts++;
    const i = Math.floor(Math.random() * allNodes.length);
    const j = Math.floor(Math.random() * allNodes.length);
    if (i === j) continue;
    const pairKey = i < j ? `${i}:${j}` : `${j}:${i}`;
    if (sampledPairs.has(pairKey)) continue;
    sampledPairs.add(pairKey);

    const start = allNodes[i];
    const end = allNodes[j];

    // Skip pairs that include the target node itself
    if (start === nodeId || end === nodeId) continue;

    const path = bfsPath(start, end);
    if (path) {
      totalPaths++;
      if (path.includes(nodeId)) {
        pathsThrough++;
      }
    }
  }

  const betweenness = totalPaths > 0 ? pathsThrough / totalPaths : 0;

  return { betweenness, sampleSize: effectiveSamples, pathsThrough, totalPaths };
}

/**
 * Connected top-K retrieval: hybrid retrieve + 1-hop neighbor expansion.
 * For each result from hybridRetrieve, fetches 1-hop neighbors via concept_edges
 * and interleaves high-weight neighbors into the result set.
 *
 * @param {string} queryText
 * @param {string} companyId
 * @param {number} limit
 * @returns {Promise<Array<{ id: string, score: number, ppr: number, cosine: number, source?: string }>>}
 */
export async function connectedTopK(queryText, companyId = COMPANY, limit = 10) {
  // Step 1: Get base hybrid results
  const baseResults = await hybridRetrieve(queryText, companyId, limit);
  if (baseResults.length === 0) return [];

  const resultIds = new Set(baseResults.map(r => r.id));
  const neighbors = [];

  // Step 2: For each result, get 1-hop neighbors ranked by edge weight
  for (const result of baseResults) {
    const edgesResult = await query(
      `SELECT target_id AS neighbor_id, weight FROM concept_edges
       WHERE company_id = $1 AND source_id = $2::uuid
       UNION ALL
       SELECT source_id AS neighbor_id, weight FROM concept_edges
       WHERE company_id = $1 AND target_id = $2::uuid
       ORDER BY weight DESC`,
      [companyId, result.id]
    );

    for (const edge of edgesResult.rows) {
      if (!resultIds.has(edge.neighbor_id)) {
        resultIds.add(edge.neighbor_id);
        neighbors.push({
          id: edge.neighbor_id,
          score: result.score * parseFloat(edge.weight || '1'),
          ppr: 0,
          cosine: 0,
          source: `neighbor_of:${result.id}`,
        });
      }
    }
  }

  // Step 2b: Engram-pool associative expansion from co-activation links.
  // This follows the paper's sparse lookup idea: activate a tiny, read-only
  // associated pool and prefetch nearby memories without changing base PPR math.
  const engramRows = [];
  for (const result of baseResults) {
    const crossRefResult = await query(
      `SELECT source_memory_id, target_memory_id, similarity
       FROM memory_cross_refs
       WHERE company_id = $1
         AND (source_memory_id = $2::uuid OR target_memory_id = $2::uuid)
       ORDER BY similarity DESC
       LIMIT $3`,
      [companyId, result.id, ENGRAM_POOL_MAX_ASSOCIATIONS]
    ).catch(() => ({ rows: [] }));
    engramRows.push(...crossRefResult.rows);
  }

  const engramBoosts = buildEngramAssociativeBoosts(baseResults, engramRows, limit);
  for (const boost of engramBoosts) {
    if (!resultIds.has(boost.id)) {
      resultIds.add(boost.id);
      neighbors.push(boost);
    }
  }

  // Step 3: Interleave — base results first, then neighbors sorted by score
  neighbors.sort((a, b) => b.score - a.score);

  const merged = [];
  let baseIdx = 0;
  let neighborIdx = 0;

  // Interleave: for every 2 base results, insert 1 neighbor
  while (merged.length < limit && (baseIdx < baseResults.length || neighborIdx < neighbors.length)) {
    if (baseIdx < baseResults.length) {
      merged.push(baseResults[baseIdx++]);
    }
    if (merged.length >= limit) break;

    if (baseIdx < baseResults.length) {
      merged.push(baseResults[baseIdx++]);
    }
    if (merged.length >= limit) break;

    if (neighborIdx < neighbors.length) {
      merged.push(neighbors[neighborIdx++]);
    }
  }

  // Fill remaining slots
  while (merged.length < limit && baseIdx < baseResults.length) {
    merged.push(baseResults[baseIdx++]);
  }
  while (merged.length < limit && neighborIdx < neighbors.length) {
    merged.push(neighbors[neighborIdx++]);
  }

  return merged.slice(0, limit);
}

export function buildEngramAssociativeBoosts(baseResults = [], crossRefRows = [], limit = 10) {
  const baseById = new Map();
  for (const result of baseResults || []) {
    if (result?.id) baseById.set(String(result.id), result);
  }

  const candidates = new Map();
  for (const row of crossRefRows || []) {
    const sourceId = String(row.source_memory_id || row.source_id || '');
    const targetId = String(row.target_memory_id || row.target_id || '');
    if (!sourceId || !targetId) continue;

    const sourceBase = baseById.get(sourceId);
    const targetBase = baseById.get(targetId);
    const seed = sourceBase || targetBase;
    const candidateId = sourceBase ? targetId : targetBase ? sourceId : null;
    if (!seed || !candidateId || baseById.has(candidateId)) continue;

    const similarity = Math.max(0, Math.min(1, Number.parseFloat(row.similarity || '0') || 0));
    const score = Number(seed.score || 0) * similarity;
    const existing = candidates.get(candidateId);
    if (!existing || score > existing.score) {
      candidates.set(candidateId, {
        id: candidateId,
        score,
        ppr: 0,
        cosine: 0,
        source: `engram_pool:${seed.id}`,
        engram_pool_boost: true,
        engram_similarity: similarity,
        source_memory_id: seed.id,
      });
    }
  }

  return Array.from(candidates.values())
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.max(0, Number(limit || 10)));
}

export async function buildEngramPoolDiagnostics({
  companyId = COMPANY,
  limit = 12,
  queryFn = query,
} = {}) {
  const maxRows = Math.max(1, Math.min(Number(limit || 12), 50));
  const result = await queryFn(
    `SELECT cr.source_memory_id,
            sm.key AS source_key,
            COUNT(*)::int AS member_count,
            AVG(cr.similarity)::float AS average_similarity,
            MAX(cr.created_at) AS last_linked_at
     FROM memory_cross_refs cr
     LEFT JOIN aimos_memories sm ON sm.id = cr.source_memory_id AND sm.company_id = cr.company_id
     WHERE cr.company_id = $1
     GROUP BY cr.source_memory_id, sm.key
     ORDER BY member_count DESC, average_similarity DESC NULLS LAST
     LIMIT $2`,
    [companyId, maxRows]
  ).catch(() => ({ rows: [] }));

  const pools = (result.rows || []).map(row => ({
    pool_id: row.source_memory_id,
    source_key: row.source_key || null,
    member_count: Number(row.member_count || 0),
    average_similarity: Number.parseFloat(row.average_similarity || '0') || 0,
    last_linked_at: row.last_linked_at || null,
  }));

  return {
    source_paper: 'Pooling Engram Conditional Memory in Large Language Models using CXL',
    status: pools.length > 0 ? 'active' : 'no_pools_detected',
    pool_count: pools.length,
    pools,
    implementation_mapping: {
      sparse_lookup: 'memory_cross_refs bounded co-activation lookup',
      read_only_pool: true,
      prefetch_boundary: 'connectedTopK associative expansion',
      cxl_hardware_pool: false,
    },
    associative_boost: {
      enabled_in_connected_top_k: true,
      max_associations_per_seed: ENGRAM_POOL_MAX_ASSOCIATIONS,
      base_ppr_formula_changed: false,
      calibrated_recall_math_changed: false,
    },
    aladdin_boundary: {
      physical_delete_allowed: false,
      pools_are_association_edges: true,
      canonical_memory_preserved: true,
    },
  };
}

function edgeEndpoint(edge = {}, side = 'source') {
  if (side === 'source') {
    return String(edge.source_id || edge.source || edge.from || edge.subject || '').trim();
  }
  return String(edge.target_id || edge.target || edge.to || edge.object || '').trim();
}

function edgeType(edge = {}) {
  return String(edge.edge_type || edge.predicate || edge.relationship_type || 'RELATED_TO')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'RELATED_TO';
}

function normalizedEntropy(values = []) {
  if (!values.length) return 0;
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
  if (counts.size <= 1) return 0;
  const total = values.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy / Math.log2(counts.size);
}

function vectorCosine(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length || a.length === 0) return null;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    const av = Number(a[i]);
    const bv = Number(b[i]);
    if (!Number.isFinite(av) || !Number.isFinite(bv)) return null;
    dot += av * bv;
    normA += av * av;
    normB += bv * bv;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? null : dot / denom;
}

function meanPairwiseCosine(embeddings = [], maxPairs = 200) {
  const vectors = embeddings.filter((embedding) => Array.isArray(embedding) && embedding.length > 0);
  let pairs = 0;
  let total = 0;
  for (let i = 0; i < vectors.length; i++) {
    for (let j = i + 1; j < vectors.length; j++) {
      const sim = vectorCosine(vectors[i], vectors[j]);
      if (sim === null) continue;
      total += sim;
      pairs += 1;
      if (pairs >= maxPairs) break;
    }
    if (pairs >= maxPairs) break;
  }
  return pairs > 0 ? total / pairs : null;
}

export function buildGraphOversmoothingDiagnostics({
  nodes = [],
  edges = [],
  embeddings = [],
  depth = 1,
} = {}) {
  const nodeIds = new Set();
  for (const node of Array.isArray(nodes) ? nodes : []) {
    const id = String(node?.id || node?.key || node?.label || '').trim();
    if (id) nodeIds.add(id);
  }

  const edgeList = Array.isArray(edges) ? edges : [];
  const degree = new Map();
  const edgeFingerprints = new Set();
  let repeatedEdges = 0;
  const relationTypes = [];

  for (const edge of edgeList) {
    const source = edgeEndpoint(edge, 'source');
    const target = edgeEndpoint(edge, 'target');
    const type = edgeType(edge);
    if (source) nodeIds.add(source);
    if (target) nodeIds.add(target);
    if (source) degree.set(source, (degree.get(source) || 0) + 1);
    if (target) degree.set(target, (degree.get(target) || 0) + 1);
    relationTypes.push(type);
    const fingerprint = `${source}->${type}->${target}`;
    if (edgeFingerprints.has(fingerprint)) repeatedEdges += 1;
    edgeFingerprints.add(fingerprint);
  }

  const nodeCount = nodeIds.size;
  const edgeCount = edgeList.length;
  const maxDegree = Math.max(0, ...degree.values());
  const averageDegree = nodeCount > 0 ? (edgeCount * 2) / nodeCount : 0;
  const hubDominance = edgeCount > 0 ? maxDegree / Math.max(1, edgeCount * 2) : 0;
  const relationEntropy = normalizedEntropy(relationTypes);
  const repeatedEdgeRatio = edgeCount > 0 ? repeatedEdges / edgeCount : 0;
  const meanCosine = meanPairwiseCosine(embeddings);
  const embeddingCollapse = meanCosine !== null ? Math.max(0, Math.min(1, (meanCosine + 1) / 2)) : 0;
  const structuralCollapse = (
    (1 - relationEntropy) * 0.35 +
    hubDominance * 0.3 +
    repeatedEdgeRatio * 0.2 +
    Math.min(1, Math.max(0, Number(depth || 1) - 1) / 8) * 0.15
  );
  const riskScore = Number(Math.max(0, Math.min(1, structuralCollapse * 0.65 + embeddingCollapse * 0.35)).toFixed(3));
  const riskBand = riskScore >= 0.7 ? 'elevated' : riskScore >= 0.45 ? 'watch' : 'low';

  return {
    diagnostic_type: 'graph_over_smoothing_proxy',
    status: riskBand,
    source_papers: WAVE5_GRAPH_DIAGNOSTIC_AUTHORITIES,
    diagnostic_only: true,
    proxy_formula: '0.65*structural_collapse + 0.35*embedding_collapse; proxy only, not SigGate-GT training math',
    graph_shape: {
      node_count: nodeCount,
      edge_count: edgeCount,
      average_degree: Number(averageDegree.toFixed(3)),
      max_degree: maxDegree,
      hub_dominance: Number(hubDominance.toFixed(3)),
      relationship_type_entropy: Number(relationEntropy.toFixed(3)),
      repeated_edge_ratio: Number(repeatedEdgeRatio.toFixed(3)),
      mean_pairwise_embedding_cosine: meanCosine === null ? null : Number(meanCosine.toFixed(4)),
    },
    risk: {
      score: riskScore,
      band: riskBand,
      likely_causes: [
        ...(relationEntropy < 0.35 && edgeCount > 0 ? ['low_relationship_type_diversity'] : []),
        ...(hubDominance > 0.45 ? ['hub_dominance'] : []),
        ...(repeatedEdgeRatio > 0.2 ? ['repeated_edges'] : []),
        ...(meanCosine !== null && meanCosine > 0.92 ? ['embedding_similarity_collapse'] : []),
      ],
    },
    guardrails: {
      ppr_math_changed: false,
      hybrid_scoring_changed: false,
      sigmoid_gating_enabled: false,
      graph_transformer_enabled: false,
      canonical_memory_changed: false,
      deletion_enabled: false,
    },
    guarded_math: {
      neuromorphic_sdm: true,
    },
    guarded_math_implemented: {
      neuromorphic_sdm: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

/**
 * Neuromorphic SDM Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Beyond LLMs, Sparse Distributed Memory, and Neuromorphics
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes SDM-style address-space metrics
 * as a diagnostic overlay alongside existing PPR graph traversal. It does NOT
 * replace PPR or modify the hybrid scoring formula. The production PPR path
 * remains authoritative. Guarded by guarded_math flag neuromorphic_sdm which
 * is guarded in production (knowledge-gated: paper understanding required to consume).
 */
export function buildNeuromorphicSDMDiagnostic({
  nodeCount = 0,
  edgeCount = 0,
  hubCount = 0,
} = {}) {
  const nodes = Math.max(0, Number(nodeCount) || 0);
  const edges = Math.max(0, Number(edgeCount) || 0);
  const hubs = Math.max(0, Number(hubCount) || 0);

  // SDM address-space metrics: address collision rate and recall interference
  const addressCollisionRate = nodes > 0 ? Math.min(1, hubs / nodes) : 0;
  const recallInterference = edges > 0 && nodes > 0
    ? Math.min(1, (edges / nodes) / 10) // Normalized edge density as interference proxy
    : 0;

  return {
    diagnostic: true,
    source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
    coexistence_class: 'side_by_side_overlay',
    node_count: nodes,
    edge_count: edges,
    hub_count: hubs,
    address_collision_rate: addressCollisionRate,
    recall_interference: recallInterference,
    ppr_unchanged: true,
    note: 'Alongside-path diagnostic. PPR traversal unchanged.',
  };
}

// ─── BATCH 10 LANE 3: VSA BINDING + HRR SELF-ATTENTION ──────────────────────
// Papers: VSA Survey (Kanervela et al.), Generalized HRR (Plate 1995/2023),
//   Recasting Self-Attention with HRR (Sutherland et al., 2024)
// VSA binding: edge_vector = subject ⊗ relation ⊗ object (XOR for bipolar)
// VSA bundling: graph_memory = Σ edges (superposition)
// VSA unbinding: query_result = graph_memory ⊗ inverse(relation) ≈ candidate_subjects
// HRR attention: HRR_attention(Q,K,V) = circular_convolution(Q,K) · V
// Aladdin: VSA/HRR are retrieval augmentations. PPR traversal is never modified.
// ─────────────────────────────────────────────────────────────────────────────

const VSA_DIM = 10000; // VSA vector dimensionality (10K bipolar)
const HRR_DIM = 768;   // HRR matches dense embedding dimension

/**
 * Convert a dense embedding to a bipolar VSA vector.
 * Maps each dimension to {-1, +1} using random projection.
 *
 * @param {number[]} embedding - 768d dense embedding
 * @param {number[][]} projectionMatrix - Random projection matrix (VSA_DIM × 768)
 * @returns {number[]} - VSA_DIM bipolar vector with elements in {-1, +1}
 */
function denseToBipolarVSA(embedding, projectionMatrix) {
  if (!Array.isArray(embedding) || embedding.length === 0) {
    return new Array(VSA_DIM).fill(0);
  }

  const matrix = projectionMatrix || _vsaProjectionMatrix;
  if (!matrix || matrix.length === 0) {
    return new Array(VSA_DIM).fill(0);
  }

  const projected = new Array(VSA_DIM);
  for (let i = 0; i < VSA_DIM; i++) {
    let dot = 0;
    const row = matrix[i] || [];
    const dim = Math.min(embedding.length, row.length);
    for (let j = 0; j < dim; j++) {
      dot += (embedding[j] || 0) * (row[j] || 0);
    }
    // Sign function: positive → +1, negative → -1
    projected[i] = dot >= 0 ? 1 : -1;
  }
  return projected;
}

// Lazy-initialized VSA projection matrix
let _vsaProjectionMatrix = null;

function ensureVSAProjection() {
  if (_vsaProjectionMatrix) return;
  // Seeded PRNG for deterministic random projection
  let seed = 2026;
  function nextRandom() {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return (seed / 0x7fffffff) * 2 - 1; // [-1, 1]
  }

  _vsaProjectionMatrix = [];
  for (let i = 0; i < VSA_DIM; i++) {
    const row = [];
    for (let j = 0; j < 768; j++) {
      row.push(nextRandom());
    }
    _vsaProjectionMatrix.push(row);
  }
}

/**
 * VSA binding: subject ⊗ relation ⊗ object using XOR for bipolar vectors.
 * Formula: edge_vector = subject XOR relation XOR object
 * All vectors are bipolar {-1, +1}, XOR is element-wise multiplication.
 *
 * @param {number[]} subjectVec - Bipolar VSA vector for subject
 * @param {number[]} relationVec - Bipolar VSA vector for relation
 * @param {number[]} objectVec - Bipolar VSA vector for object
 * @returns {{ edge_vector: number[], source_papers: string[], diagnostic_only: boolean }}
 */
export function computeVSABinding(subjectVec, relationVec, objectVec) {
  const s = Array.isArray(subjectVec) ? subjectVec : [];
  const r = Array.isArray(relationVec) ? relationVec : [];
  const o = Array.isArray(objectVec) ? objectVec : [];

  // If any vector is empty, return empty binding
  if (s.length === 0 || r.length === 0 || o.length === 0) {
    return {
      edge_vector: [],
      source_papers: ['VSA Survey', 'Generalized HRR'],
      diagnostic_only: true,
      note: 'Empty input vector — binding undefined',
    };
  }

  const dim = Math.min(s.length, r.length, o.length);
  const edgeVector = new Array(dim);
  for (let i = 0; i < dim; i++) {
    // XOR for bipolar: multiplication preserves {-1, +1} space
    edgeVector[i] = s[i] * r[i] * o[i];
  }

  return {
    edge_vector: edgeVector,
    binding_formula: 'subject ⊗ relation ⊗ object (XOR for bipolar)',
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    ppr_unchanged: true,
  };
}

/**
 * VSA unbinding: query the graph memory for candidates matching a relation.
 * Formula: query_result = graph_memory ⊗ inverse(relation)
 * For bipolar vectors, inverse(x) = x (self-inverse property of XOR).
 *
 * @param {number[]} graphMemory - Bundled graph memory vector (Σ of all edge vectors)
 * @param {number[]} relationVec - Bipolar VSA vector for the relation to unbind
 * @returns {{ candidates: number[], source_papers: string[], diagnostic_only: boolean }}
 */
export function computeVSAUnbinding(graphMemory, relationVec) {
  const gm = Array.isArray(graphMemory) ? graphMemory : [];
  const r = Array.isArray(relationVec) ? relationVec : [];

  if (gm.length === 0 || r.length === 0) {
    return {
      candidates: [],
      source_papers: ['VSA Survey', 'Generalized HRR'],
      diagnostic_only: true,
      note: 'Empty input vector — unbinding undefined',
    };
  }

  // For bipolar vectors, inverse is self: XOR unbinding = multiplication
  const dim = Math.min(gm.length, r.length);
  const candidates = new Array(dim);
  for (let i = 0; i < dim; i++) {
    candidates[i] = gm[i] * r[i];
  }

  return {
    candidates,
    unbinding_formula: 'graph_memory ⊗ inverse(relation) (self-inverse for bipolar)',
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    ppr_unchanged: true,
  };
}

/**
 * VSA bundling: superpose multiple edge vectors into a single graph memory.
 * Formula: graph_memory = Σ edges (element-wise sum, then normalize to bipolar)
 *
 * @param {number[][]} edgeVectors - Array of bipolar VSA edge vectors
 * @returns {{ graph_memory: number[], source_papers: string[], diagnostic_only: boolean }}
 */
export function computeVSABundling(edgeVectors) {
  const edges = Array.isArray(edgeVectors) ? edgeVectors.filter(Array.isArray) : [];

  if (edges.length === 0) {
    return {
      graph_memory: [],
      source_papers: ['VSA Survey', 'Generalized HRR'],
      diagnostic_only: true,
      note: 'No edge vectors provided — bundling undefined',
    };
  }

  const dim = edges[0].length;
  const sum = new Array(dim).fill(0);

  for (const edge of edges) {
    for (let i = 0; i < dim; i++) {
      sum[i] += (edge[i] || 0);
    }
  }

  // Normalize to bipolar via sign function
  const graphMemory = sum.map(v => v >= 0 ? 1 : -1);

  return {
    graph_memory: graphMemory,
    bundling_formula: 'Σ edges → sign() normalization (bipolar)',
    edge_count: edges.length,
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    ppr_unchanged: true,
  };
}

/**
 * Circular convolution (HRR core operation).
 * (f ⊛ g)[k] = Σ_j f[j] * g[(k-j) mod n]
 *
 * @param {number[]} f - First vector
 * @param {number[]} g - Second vector
 * @returns {number[]} - Circular convolution result
 */
function circularConvolution(f, g) {
  const n = Math.max(f.length, g.length);
  if (n === 0) return [];

  const result = new Array(n).fill(0);
  for (let k = 0; k < n; k++) {
    let sum = 0;
    for (let j = 0; j < n; j++) {
      sum += (f[j] || 0) * (g[((k - j) % n + n) % n] || 0);
    }
    result[k] = Number(sum.toFixed(6));
  }
  return result;
}

/**
 * HRR self-attention recasting: HRR_attention(Q,K,V) = circular_convolution(Q,K) · V
 * Formula: attention_weights = softmax(circular_convolution(Q, K))
 *          output = attention_weights · V (element-wise then sum)
 *
 * @param {number[]} queryVec - Query vector (768d embedding)
 * @param {number[]} keyVec - Key vector (768d embedding)
 * @param {number[]} valueVec - Value vector (768d embedding)
 * @returns {{ attention_weights: number[], output: number[], source_papers: string[], diagnostic_only: boolean }}
 */
export function computeHRRAttention(queryVec, keyVec, valueVec) {
  const q = Array.isArray(queryVec) ? queryVec : [];
  const k = Array.isArray(keyVec) ? keyVec : [];
  const v = Array.isArray(valueVec) ? valueVec : [];

  if (q.length === 0 || k.length === 0 || v.length === 0) {
    return {
      attention_weights: [],
      output: [],
      source_papers: ['Recasting Self-Attention with HRR'],
      diagnostic_only: true,
      note: 'Empty input vector — HRR attention undefined',
    };
  }

  // Step 1: circular convolution Q ⊛ K
  const qkConv = circularConvolution(q, k);

  // Step 2: softmax over convolution result
  const maxVal = Math.max(...qkConv);
  const expVals = qkConv.map(v => Math.exp(v - maxVal));
  const sumExp = expVals.reduce((a, b) => a + b, 0) || 1;
  const attentionWeights = expVals.map(v => Number((v / sumExp).toFixed(6)));

  // Step 3: weighted sum of value vectors
  // For single Q/K/V: output = Σ_i attention_weights[i] * value[i]
  // Since we have a single value vector, the output is element-wise multiply + normalize
  const dim = Math.min(attentionWeights.length, v.length);
  const output = new Array(v.length).fill(0);
  for (let i = 0; i < dim; i++) {
    output[i] = Number((attentionWeights[i] * v[i]).toFixed(6));
  }

  // Normalize output to unit length
  let norm = 0;
  for (let i = 0; i < output.length; i++) norm += output[i] * output[i];
  norm = Math.sqrt(norm);
  const normalizedOutput = norm > 0 ? output.map(v => Number((v / norm).toFixed(6))) : output;

  return {
    attention_weights: attentionWeights.slice(0, 10), // Trim for diagnostic readability
    output: normalizedOutput,
    hrr_formula: 'HRR_attention(Q,K,V) = circular_convolution(Q,K) · V',
    source_papers: ['Recasting Self-Attention with HRR', 'Generalized HRR'],
    diagnostic_only: true,
    ppr_unchanged: true,
  };
}

/**
 * Build VSA binding diagnostic for a concept graph edge.
 *
 * @param {Object} params
 * @param {number[]} params.subjectEmbedding - 768d subject embedding
 * @param {number[]} params.relationEmbedding - 768d relation embedding
 * @param {number[]} params.objectEmbedding - 768d object embedding
 * @returns {object} VSA binding diagnostic
 */
export function buildVSABindingDiagnostic({ subjectEmbedding, relationEmbedding, objectEmbedding } = {}) {
  ensureVSAProjection();

  const sVec = Array.isArray(subjectEmbedding) ? denseToBipolarVSA(subjectEmbedding, _vsaProjectionMatrix) : [];
  const rVec = Array.isArray(relationEmbedding) ? denseToBipolarVSA(relationEmbedding, _vsaProjectionMatrix) : [];
  const oVec = Array.isArray(objectEmbedding) ? denseToBipolarVSA(objectEmbedding, _vsaProjectionMatrix) : [];

  const binding = computeVSABinding(sVec, rVec, oVec);
  const bundling = computeVSABundling([binding.edge_vector]);
  const unbinding = binding.edge_vector.length > 0 && rVec.length > 0
    ? computeVSAUnbinding(bundling.graph_memory, rVec)
    : { candidates: [], diagnostic_only: true };

  return {
    diagnostic_type: 'vsa_binding',
    source_papers: ['VSA Survey', 'Generalized HRR'],
    diagnostic_only: true,
    vsa_dim: VSA_DIM,
    input_dimensions: {
      subject: subjectEmbedding?.length || 0,
      relation: relationEmbedding?.length || 0,
      object: objectEmbedding?.length || 0,
    },
    binding: {
      edge_vector_sample: binding.edge_vector.slice(0, 20),
      edge_vector_dim: binding.edge_vector.length,
    },
    bundling: {
      graph_memory_sample: bundling.graph_memory.slice(0, 20),
      edge_count: bundling.edge_count,
    },
    unbinding: {
      candidates_sample: unbinding.candidates?.slice(0, 20) || [],
    },
    guardrails: {
      ppr_math_changed: false,
      hybrid_scoring_changed: false,
      canonical_memory_changed: false,
      deletion_enabled: false,
    },
    aladdin_boundary: {
      vsa_is_alongside_diagnostic: true,
      graph_traversal_unchanged: true,
    },
  };
}

/**
 * Build HRR attention diagnostic for graph query.
 *
 * @param {Object} params
 * @param {number[]} params.queryEmbedding - 768d query embedding
 * @param {number[]} params.keyEmbedding - 768d key embedding
 * @param {number[]} params.valueEmbedding - 768d value embedding
 * @returns {object} HRR attention diagnostic
 */
export function buildHRRAttentionDiagnostic({ queryEmbedding, keyEmbedding, valueEmbedding } = {}) {
  const hrrResult = computeHRRAttention(queryEmbedding, keyEmbedding, valueEmbedding);

  return {
    diagnostic_type: 'hrr_attention',
    source_papers: ['Recasting Self-Attention with HRR', 'Generalized HRR'],
    diagnostic_only: true,
    hrr_dim: HRR_DIM,
    input_dimensions: {
      query: queryEmbedding?.length || 0,
      key: keyEmbedding?.length || 0,
      value: valueEmbedding?.length || 0,
    },
    attention_weights_sample: hrrResult.attention_weights,
    output_norm: hrrResult.output.length > 0
      ? Number(Math.sqrt(hrrResult.output.reduce((s, v) => s + v * v, 0)).toFixed(6))
      : 0,
    hrr_formula: hrrResult.hrr_formula,
    guardrails: {
      ppr_math_changed: false,
      hybrid_scoring_changed: false,
      canonical_memory_changed: false,
      deletion_enabled: false,
    },
    aladdin_boundary: {
      hrr_is_alongside_diagnostic: true,
      ppr_traversal_unchanged: true,
    },
  };
}

// ─── BATCH 10.7 LANE 7, PHASE 3.5: DIFFERENTIABLE SYMBOLIC PLANNING ──────
// Paper: Differentiable Symbolic Planning — A Neural Architecture for
//        Constraint Reasoning with Learned Feasibility
// Alongside-path diagnostic: planning-aware retrieval gating.
// Concept-graph uses PPR with authority-weighted edges (hard constraint).
// Context-builder uses neural retrieval (learned feasibility).
// Planning horizon adds a boost for memories needed by future planned actions,
// even if their immediate RPE is low.
// Phase 0: diagnostic only. RRF weights and PPR traversal unchanged.
// Aladdin: Planning boost only affects retrieval ranking.
//   No memory is deleted or modified.
// Guarded math flag: planning_horizon
// ─────────────────────────────────────────────────────────────────────────────

const PLANNING_BOOST_WEIGHT = 0.15;

/**
 * Compute planning horizon boost for a memory.
 *
 * Boosts memories that are likely needed for planned future actions,
 * even if their immediate RPE is low. This implements the
 * Differentiable Symbolic Planning idea that retrieval should consider
 * not just current query relevance but also future action relevance.
 *
 * @param {object} memory - Memory with embedding and key
 * @param {Array<{embedding: number[], action: string}>} plannedActions - Planned future actions with embeddings
 * @returns {{ boost: number, maxRelevance: number, relevantActions: string[], source_paper: string }}
 */
export function computePlanningHorizonBoost(memory, plannedActions = []) {
  const memEmbedding = Array.isArray(memory?.embedding) ? memory.embedding : [];
  const actions = Array.isArray(plannedActions) ? plannedActions : [];

  if (memEmbedding.length === 0 || actions.length === 0) {
    return {
      boost: 0,
      maxRelevance: 0,
      relevantActions: [],
      source_paper: 'Differentiable Symbolic Planning',
    };
  }

  let maxRelevance = 0;
  const relevantActions = [];

  for (const action of actions) {
    const actionEmbedding = Array.isArray(action?.embedding) ? action.embedding : [];
    if (actionEmbedding.length === 0) continue;

    // Cosine similarity between memory embedding and action embedding
    const dim = Math.min(memEmbedding.length, actionEmbedding.length);
    let dotProduct = 0, normA = 0, normB = 0;
    for (let i = 0; i < dim; i++) {
      dotProduct += (memEmbedding[i] || 0) * (actionEmbedding[i] || 0);
      normA += (memEmbedding[i] || 0) ** 2;
      normB += (actionEmbedding[i] || 0) ** 2;
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    const similarity = denom > 0 ? dotProduct / denom : 0;

    if (similarity > maxRelevance) {
      maxRelevance = similarity;
    }
    if (similarity > 0.5) {
      relevantActions.push(action.action || 'unknown');
    }
  }

  return {
    boost: Number((maxRelevance * PLANNING_BOOST_WEIGHT).toFixed(6)),
    maxRelevance: Number(maxRelevance.toFixed(6)),
    relevantActions,
    planning_boost_weight: PLANNING_BOOST_WEIGHT,
    source_paper: 'Differentiable Symbolic Planning',
  };
}

/**
 * Build planning horizon diagnostic for a memory and set of planned actions.
 *
 * @param {object} memory - Memory to evaluate
 * @param {Array<{embedding: number[], action: string}>} plannedActions - Planned future actions
 * @returns {object} Diagnostic with planning boost info and guardrails
 */
export function buildPlanningHorizonDiagnostic(memory, plannedActions = []) {
  const boostResult = computePlanningHorizonBoost(memory, plannedActions);

  return {
    diagnostic_type: 'planning_horizon',
    source_paper: 'Differentiable Symbolic Planning',
    diagnostic_only: true,
    memory_key: memory?.key || null,
    planning_boost: boostResult.boost,
    max_relevance: boostResult.maxRelevance,
    relevant_actions: boostResult.relevantActions,
    planning_boost_weight: PLANNING_BOOST_WEIGHT,
    guardrails: {
      rrf_weights_changed: false,
      ppr_traversal_changed: false,
      canonical_memory_modified: false,
    },
    guarded_math: {
      planning_horizon: true,
    },
  };
}
