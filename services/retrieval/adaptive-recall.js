/**
 * adaptive-recall.js — Linear Cosine-Similarity Memory Recall
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (RECALL pipeline, step 1)
 * 2. → Pulls from: services/core/embeddings.js (getEmbedding)
 * 3. → Pulls from: aimos_memories (SQL pgvector search)
 * 4. ↔ Interacts with: services/db/connection.js (Read pool)
 *
 * LOGIC GUIDE: Primary vector similarity entry point. Queries memory by 
 * pgvector distance (<=>) and returns results with amplitude_score (retrieval_weight).
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (RECALL pipeline, step 1 — optional fast path)
// → Calls: services/core/embeddings.js (getEmbedding)
// Pipeline: RECALL_PIPELINE
// Position: adaptive recall entry
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';

const COMPANY_ID = AIMOS_COMPANY_ID;

/**
 * Normalize a raw recall result into the standard adaptive shape.
 * Kept for backward compatibility with callers that invoke it directly.
 */
export function normalizeAdaptiveRecallResult(result = {}) {
  const normalizedResults = Array.isArray(result?.results)
    ? result.results.map((entry) => {
      const normalized = { ...entry };
      if ('quantum_kernel' in normalized) {
        normalized.adaptive_score = normalized.quantum_kernel;
        delete normalized.quantum_kernel;
      }
      if ('quantum_amplitude' in normalized) {
        normalized.amplitude_score = normalized.quantum_amplitude;
        delete normalized.quantum_amplitude;
      }
      return normalized;
    })
    : [];

  return {
    ...result,
    results: normalizedResults,
    metadata: {
      ...(result?.metadata || {}),
      mode: 'adaptive',
    },
  };
}

/**
 * Adaptive recall — main entry point.
 *
 * Accepts the same params the quantum path accepted so callers don't break.
 *
 * @param {object} params
 * @param {string} params.queryText        - the search query
 * @param {string} params.companyId
 * @param {string} params.agentId          - for tesseract scoping
 * @param {number} params.limit            - max results (default 20)
 * @param {number} params.clearanceLevel   - max clearance (default 10)
 * @param {string} params.memoryTypeFilter
 * @param {string} params.selectivity      - unused in linear mode, kept for compat
 * @param {boolean} params.lazy            - unused in linear mode, kept for compat
 * @returns {object} { results, metadata }
 */
export async function adaptiveRecall({
  queryText,
  companyId,
  agentId,
  limit = 20,
  clearanceLevel = 10,
  memoryTypeFilter,
  selectivity = 'standard',
  lazy = true,
} = {}) {
  const company = companyId || COMPANY_ID;
  const t0 = Date.now();

  try {
    // ─── Step 1: Embed query ────────────────────────────────────────
    const queryEmbedding = await getEmbedding(queryText);
    if (!queryEmbedding || queryEmbedding._degraded) {
      return {
        results: [],
        metadata: { error: 'Query embedding failed or degraded', mode: 'adaptive' },
      };
    }

    // ─── Step 2: Build SQL — cosine distance via pgvector <=> ───────
    const conditions = [
      'm.company_id = $1',
      'm.clearance_level <= $2',
      'm.embedding IS NOT NULL',
    ];
    const params = [company, clearanceLevel];

    // Embedding parameter for the ORDER BY distance
    params.push(JSON.stringify(queryEmbedding));
    const embeddingParamIdx = params.length; // $3

    if (memoryTypeFilter) {
      params.push(memoryTypeFilter);
      conditions.push(`m.memory_type = $${params.length}`);
    }

    if (agentId) {
      params.push(agentId);
      conditions.push(
        `(m.cube_scope = 'shared' OR m.cube_scope = 'propagated' OR (m.cube_scope = 'private' AND m.agent_id = $${params.length}))`,
      );
    } else {
      conditions.push(`m.cube_scope IN ('shared', 'propagated')`);
    }

    const sql = `
      SELECT m.id, m.key, m.value, m.scope, m.memory_type, m.clearance_level,
             m.created_at, m.credit_score, m.memory_tier, m.data_class, m.cube_scope,
             m.agent_id, m.retrieval_weight,
             (m.embedding <=> $${embeddingParamIdx}::vector) AS distance
        FROM aimos_memories m
       WHERE ${conditions.join(' AND ')}
       ORDER BY m.embedding <=> $${embeddingParamIdx}::vector ASC
       LIMIT $${params.push(limit)}
    `;

    const result = await query(sql, params);
    const rows = result.rows;

    // ─── Step 3: Map to the expected return shape ───────────────────
    const results = rows.map((r) => ({
      id: r.id,
      key: r.key,
      value: r.value,
      scope: r.scope,
      memory_type: r.memory_type,
      clearance_level: r.clearance_level,
      created_at: r.created_at,
      credit_score: parseFloat(r.credit_score),
      memory_tier: r.memory_tier,
      data_class: r.data_class,
      cube_scope: r.cube_scope,
      // Adaptive fields — distance as score, retrieval_weight as amplitude
      adaptive_score: 1 - parseFloat(r.distance),  // convert distance → similarity
      amplitude_score: parseFloat(r.retrieval_weight) || 1.0,
    }));

    const elapsed = Date.now() - t0;

    return {
      results,
      metadata: {
        mode: 'adaptive',
        memories_scanned: rows.length,
        results_returned: results.length,
        selectivity,
        elapsed_ms: elapsed,
      },
    };
  } catch (err) {
    console.error('[adaptive-recall] error:', err.message);
    return {
      results: [],
      metadata: { error: err.message, mode: 'adaptive' },
    };
  }
}

export default { adaptiveRecall, normalizeAdaptiveRecallResult };

/**
 * Sentinel severity-proportional recall depth (from Sentinel Clinical Triage MCP paper).
 * Critical queries get deeper search (more results, higher k) than low-severity queries.
 */
export function getSentinelRecallDepth(severity) {
  // severity: 1-5 (5 = critical)
  const depthMap = { 1: 3, 2: 5, 3: 8, 4: 12, 5: 20 };
  return depthMap[Math.max(1, Math.min(5, severity || 1))] || 8;
}

export function classifyQuerySeverity(query) {
  const text = (query || '').toLowerCase();
  if (/urgent|critical|emergency|immediate|fatal|block|broke|down/.test(text)) return 5;
  if (/error|fail|broken|wrong|bug|issue/.test(text)) return 4;
  if (/slow|warning|degraded|unexpected/.test(text)) return 3;
  if (/how|what|why|explain|describe/.test(text)) return 2;
  return 1;
}
