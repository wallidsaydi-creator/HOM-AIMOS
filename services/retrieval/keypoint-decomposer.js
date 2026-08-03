// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — explicit `mode=group_rag` recall path
// Purpose: GroupRAG decomposition — breaks complex queries into 3-7 atomic
//          keypoints, groups by Jaccard overlap > 0.3, parallel group retrieval
// Wire into: retrieval-orchestrator.js (RECALL pipeline, complex query pre-step)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// KEYPOINT DECOMPOSER (keypoint-decomposer.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-11: GroupRAG Keypoint Decomposition
//
// Decomposes complex queries into 3-7 atomic keypoints, groups them by shared
// knowledge context (Jaccard overlap > 0.3), and performs parallel group-wise
// retrieval before synthesising a convergent answer.
//
// Pipeline:
//   1. extractKeypoints(query)        → 3-7 atomic keypoints via native provider
//   2. groupKeypoints(keypoints)      → knowledge-driven grouping (top-5 per KP, Jaccard)
//   3. parallelGroupRetrieval(groups) → concurrent retrieval per group
//   4. computeWIF(results)            → Weighted Inference F-score
//   5. synthesizeGroupResults(...)    → convergent synthesis via native provider
//
// WIF = Core_Recall^2.5 * (1-Noise_Recall)^2 * (1+0.5*Support_Recall)
//
// Theoretical basis: GroupRAG (Xiong et al.), Jaccard-based semantic clustering,
// parallel evidence assembly.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { logEvent } from '../observe/event-ledger.js';
import { callNativeLlm } from '../shared/native-llm.js';

const COMPANY = AIMOS_COMPANY_ID;

// Jaccard overlap threshold for grouping keypoints
const JACCARD_THRESHOLD = 0.3;

// Number of top memories to retrieve per keypoint during grouping
const TOP_K_PER_KEYPOINT = 5;

// Maximum number of keypoints to extract
const MAX_KEYPOINTS = 7;
const MIN_KEYPOINTS = 3;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Compute Jaccard similarity between two sets.
 *
 * @param {Set<string>} setA
 * @param {Set<string>} setB
 * @returns {number} Jaccard index in [0, 1]
 */
function jaccard(setA, setB) {
  if (setA.size === 0 && setB.size === 0) return 0;
  const intersection = new Set([...setA].filter((x) => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return intersection.size / union.size;
}

/**
 * Parse a newline-delimited or JSON-array LLM response into an array of strings.
 *
 * @param {string} text
 * @returns {string[]}
 */
function parseListResponse(text) {
  const trimmed = (text || '').trim();

  // Try JSON array first
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return parsed.map((s) => String(s).trim()).filter(Boolean);
      }
    } catch {
      // fall through to line parsing
    }
  }

  // Newline-delimited, strip numbering
  return trimmed
    .split('\n')
    .map((line) => line.replace(/^\d+[\.\)]\s*/, '').trim())
    .filter(Boolean);
}

function lexicalFallbackKeypoints(queryText) {
  const text = String(queryText || '').trim();
  const parts = text
    .split(/\b(?:and|also|while|plus|versus|vs\.?|then|after|before|because)\b|[;,.?]/i)
    .map((part) => part.trim())
    .filter((part) => part.length >= 8);
  const bounded = parts.length ? parts.slice(0, MAX_KEYPOINTS) : [text];
  while (bounded.length < MIN_KEYPOINTS) {
    bounded.push(text);
  }
  return bounded.slice(0, MAX_KEYPOINTS);
}

function normalizeKeypoints(keypoints, queryText) {
  const bounded = (Array.isArray(keypoints) ? keypoints : [])
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .slice(0, MAX_KEYPOINTS);
  if (bounded.length < MIN_KEYPOINTS) {
    return lexicalFallbackKeypoints(queryText);
  }
  return bounded;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Decompose a complex query into 3-7 atomic keypoints using the native provider path.
 *
 * @param {string} queryText - The complex query to decompose
 * @returns {Promise<string[]>} Array of atomic keypoint strings
 */
export async function extractKeypoints(queryText) {
  if (!queryText || typeof queryText !== 'string') {
    throw new Error('[keypoint-decomposer] extractKeypoints: queryText must be a non-empty string');
  }

  const prompt =
    `You are a query decomposition expert. Break the following query into between ${MIN_KEYPOINTS} and ${MAX_KEYPOINTS} atomic, self-contained keypoints that individually can be answered from a knowledge base. Each keypoint should be a concise statement or question.\n\nQuery: ${queryText.trim()}\n\nRespond with a JSON array of keypoint strings only. Example: ["keypoint 1", "keypoint 2"]`;

  let responseText = '';
  try {
    responseText = await callNativeLlm({
      prompt,
      providerConfigKeys: ['AIMOS_RETRIEVAL_PROVIDER', 'LLM_PROVIDER'],
      modelConfigKeys: ['AIMOS_RETRIEVAL_MODEL', 'LLM_MODEL']
    });
  } catch (err) {
    console.error('[keypoint-decomposer] extractKeypoints LLM error:', err.message);
    return lexicalFallbackKeypoints(queryText);
  }

  return normalizeKeypoints(parseListResponse(responseText), queryText);
}

/**
 * Group keypoints by shared knowledge context.
 * Retrieves top-5 memory IDs per keypoint, computes Jaccard overlap between
 * keypoint retrieval sets; keypoints with overlap > 0.3 are grouped together.
 *
 * @param {string[]} keypoints
 * @param {string} [companyId]
 * @returns {Promise<Array<{groupId: number, keypoints: string[], memoryIds: Set<string>}>>}
 */
export async function groupKeypoints(keypoints, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(keypoints) || keypoints.length === 0) {
    return [];
  }

  // For each keypoint, retrieve top-K memory IDs
  const keypointMemorySets = await Promise.all(
    keypoints.map(async (kp, idx) => {
      let embedding = null;
      try {
        embedding = await getEmbedding(kp);
      } catch (err) {
        console.warn(`[keypoint-decomposer] groupKeypoints embedding error for KP ${idx}:`, err.message);
        return { kp, ids: new Set() };
      }

      let ids = new Set();
      try {
        const result = await query(
          `SELECT id
           FROM aimos_memories
           WHERE company_id = $1
             AND embedding IS NOT NULL
           ORDER BY embedding <=> $2::vector
           LIMIT $3`,
          [cid, JSON.stringify(embedding), TOP_K_PER_KEYPOINT]
        );
        ids = new Set(result.rows.map((r) => String(r.id)));
      } catch (err) {
        console.warn(`[keypoint-decomposer] groupKeypoints DB error for KP ${idx}:`, err.message);
      }

      return { kp, ids };
    })
  );

  // Union-find grouping by Jaccard overlap
  const parent = keypoints.map((_, i) => i);

  function find(i) {
    if (parent[i] !== i) parent[i] = find(parent[i]);
    return parent[i];
  }

  function unite(i, j) {
    parent[find(i)] = find(j);
  }

  for (let i = 0; i < keypointMemorySets.length; i++) {
    for (let j = i + 1; j < keypointMemorySets.length; j++) {
      const sim = jaccard(keypointMemorySets[i].ids, keypointMemorySets[j].ids);
      if (sim >= JACCARD_THRESHOLD) {
        unite(i, j);
      }
    }
  }

  // Collect groups
  const groupMap = new Map();
  for (let i = 0; i < keypoints.length; i++) {
    const root = find(i);
    if (!groupMap.has(root)) {
      groupMap.set(root, { groupId: root, keypoints: [], memoryIds: new Set() });
    }
    const group = groupMap.get(root);
    group.keypoints.push(keypointMemorySets[i].kp);
    for (const id of keypointMemorySets[i].ids) {
      group.memoryIds.add(id);
    }
  }

  // Convert Sets to Arrays for serialisability and re-number groupIds
  let groupIdCounter = 0;
  return Array.from(groupMap.values()).map((g) => ({
    groupId: groupIdCounter++,
    keypoints: g.keypoints,
    memoryIds: Array.from(g.memoryIds),
  }));
}

/**
 * Retrieve memories for each group in parallel.
 *
 * @param {Array<{groupId: number, keypoints: string[], memoryIds: string[]}>} groups
 * @param {string} [companyId]
 * @returns {Promise<Array<{groupId: number, keypoints: string[], memories: Array<{id: string, key: string, value: string}>}>>}
 */
export async function parallelGroupRetrieval(groups, companyId) {
  const cid = companyId || COMPANY;

  if (!Array.isArray(groups) || groups.length === 0) {
    return [];
  }

  const results = await Promise.all(
    groups.map(async (group) => {
      if (!Array.isArray(group.memoryIds) || group.memoryIds.length === 0) {
        return { groupId: group.groupId, keypoints: group.keypoints, memories: [] };
      }

      let memories = [];
      try {
        const result = await query(
          `SELECT id, key, value
           FROM aimos_memories
           WHERE company_id = $1
             AND id = ANY($2::uuid[])`,
          [cid, group.memoryIds]
        );
        memories = result.rows.map((r) => ({
          id: String(r.id),
          key: String(r.key),
          value: String(r.value),
        }));
      } catch (err) {
        console.error(`[keypoint-decomposer] parallelGroupRetrieval DB error for group ${group.groupId}:`, err.message);
      }

      return { groupId: group.groupId, keypoints: group.keypoints, memories };
    })
  );

  return results;
}

/**
 * Compute the Weighted Inference F-score (WIF) for a set of retrieval results.
 *
 * WIF = Core_Recall^2.5 * (1-Noise_Recall)^2 * (1+0.5*Support_Recall)
 *
 * @param {Array<{groupId: number, memories: Array<{id: string, key: string, value: string}>, coreHits?: number, noiseHits?: number, supportHits?: number, total?: number}>} retrievalResults
 * @returns {number} WIF score in [0, +∞), practically in [0, ~2]
 */
export function computeWIF(retrievalResults) {
  if (!Array.isArray(retrievalResults) || retrievalResults.length === 0) return 0;

  // Aggregate across all groups
  let totalMemories = 0;
  let coreHits = 0;
  let noiseHits = 0;
  let supportHits = 0;

  for (const group of retrievalResults) {
    const groupTotal = (group.memories || []).length;
    totalMemories += groupTotal;

    // Use provided hit counts if available; otherwise estimate from total
    coreHits += Number(group.coreHits ?? Math.round(groupTotal * 0.6));
    noiseHits += Number(group.noiseHits ?? Math.round(groupTotal * 0.1));
    supportHits += Number(group.supportHits ?? Math.round(groupTotal * 0.3));
  }

  if (totalMemories === 0) return 0;

  const coreRecall = Math.min(1, coreHits / Math.max(totalMemories, 1));
  const noiseRecall = Math.min(1, noiseHits / Math.max(totalMemories, 1));
  const supportRecall = Math.min(1, supportHits / Math.max(totalMemories, 1));

  const wif =
    Math.pow(coreRecall, 2.5) *
    Math.pow(1 - noiseRecall, 2) *
    (1 + 0.5 * supportRecall);

  return Math.round(wif * 100000) / 100000;
}

/**
 * Synthesize local conclusions from each group into a convergent final answer.
 * Uses the native provider path to combine evidence from all groups coherently.
 *
 * @param {Array<{groupId: number, keypoints: string[], memories: Array<{key: string, value: string}>}>} localConclusions
 * @param {string} originalQuery
 * @returns {Promise<string>} Synthesized answer
 */
export async function synthesizeGroupResults(localConclusions, originalQuery) {
  if (!Array.isArray(localConclusions) || localConclusions.length === 0) {
    return 'No evidence groups available to synthesize.';
  }

  const evidenceBlocks = localConclusions.map((group, i) => {
    const keypointList = (group.keypoints || []).join('; ');
    const memoryList = (group.memories || [])
      .slice(0, 5)
      .map((m) => `  - [${m.key}]: ${String(m.value).slice(0, 200)}`)
      .join('\n');
    return `Group ${i + 1} (keypoints: ${keypointList}):\n${memoryList || '  (no memories)'}`;
  }).join('\n\n');

  const prompt =
    `You are a synthesis expert. Multiple evidence groups have been retrieved for the query below. Converge them into a single coherent, comprehensive answer.\n\nOriginal Query: ${originalQuery.trim()}\n\nEvidence Groups:\n${evidenceBlocks}\n\nProvide a concise, accurate synthesis:`;

  try {
    const result = await callNativeLlm({
      prompt,
      providerConfigKeys: ['AIMOS_RETRIEVAL_PROVIDER', 'LLM_PROVIDER'],
      modelConfigKeys: ['AIMOS_RETRIEVAL_MODEL', 'LLM_MODEL']
    });
    return result || 'Synthesis unavailable.';
  } catch (err) {
    console.error('[keypoint-decomposer] synthesizeGroupResults LLM error:', err.message);
    return `Synthesis error: ${err.message}`;
  }
}

/**
 * Full GroupRAG pipeline: extract → group → retrieve → score → synthesize.
 *
 * @param {string} queryText
 * @param {string} [companyId]
 * @returns {Promise<{keypoints: string[], groups: object[], wif: number, synthesis: string}>}
 */
export async function runGroupRAG(queryText, companyId, options = {}) {
  const cid = companyId || COMPANY;
  const agentId = String(options.agentId || 'group-rag').trim() || 'group-rag';

  const keypoints = await extractKeypoints(queryText);
  const groups = await groupKeypoints(keypoints, cid);
  const retrievalResults = await parallelGroupRetrieval(groups, cid);
  const wif = computeWIF(retrievalResults);
  const synthesis = await synthesizeGroupResults(retrievalResults, queryText);
  const memoryCount = retrievalResults.reduce((sum, group) => sum + (group.memories || []).length, 0);

  const eventId = await logEvent(cid, agentId, 'group_rag_pipeline', `group-rag:${queryText.slice(0, 80)}`, {
    keypoint_count: keypoints.length,
    group_count: groups.length,
    memory_count: memoryCount,
    wif,
    ranking_math_changed: false,
    retrieval_weight_changed: false,
    canonical_memory_changed: false,
    reasoning: 'Explicit GroupRAG recall mode decomposed a complex query into keypoints, grouped evidence by Jaccard overlap, and synthesized bounded evidence without changing default recall ranking.',
    source_knowledge: 'keypoint-decomposer.js P1-B3-11 GroupRAG keypoint decomposition with Jaccard grouping and WIF diagnostic.',
  }).catch(() => {});

  return { keypoints, groups: retrievalResults, wif, synthesis, event_id: eventId };
}
