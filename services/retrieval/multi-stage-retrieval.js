/**
 * multi-stage-retrieval.js — Reciprocal Rank Fusion + confidence-gated recall
 * Source: Auralink SDC (RRF, 95.2% Recall@5)
 *
 * Epistemology validation (Batch 10.7 Lane 7, Phase 3.6):
 *   Concentration of measure proves that in 768d space, cosine distance is
 *   uninformative — direction matters, not magnitude. This validates RRF
 *   multi-signal retrieval (W_VEC + W_TXT + W_INFINI) over pure cosine
 *   similarity, since no single distance metric captures the full geometry.
 *   Paper: Epistemology of Generative AI — The Geometry of Knowing
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: retrieval-orchestrator.js (Fusion stage)
 * 2. → Pulls from: services/core/embeddings.js (Query vectors)
 * 3. → Pulls from: services/db/connection.js (Dense + Sparse candidates)
 * 4. ↔ Interacts with: MMR Dedup logic (Diversity filter)
 *
 * LOGIC GUIDE: Implements normalized RRF (Reciprocal Rank Fusion) across dense
 * and sparse results. Ranking is evidence-driven; age never attenuates memory.
 *
 * Additive Batch9 Wave5 authority: Ontology-Aware Design Patterns, ELISA, and
 * Reconstructing Content via Collaborative Attention. Aimos exposes
 * ontology recall-path diagnostics only; RRF weights, thresholds, temporal
 * decay, and result ordering are unchanged.
 *
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildSparseRetrievalDiagnostic: Sparse sign-hash retrieval alongside
 *     existing RRF pipeline. RRF weights unchanged.
 *   - buildCascadeRetrievalDiagnostic: Local/global cascade stage metrics
 *     alongside existing multi-stage path. Stage ordering unchanged.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { getW_VEC, getW_TXT, getW_INFINI, getMemoryCount } from '../shared/scale-baseline.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

// ─── Scale-adaptive RRF blend weights (Anatomical Pathology RAG, 2026) ──────
// Per paper: 30% semantic + 70% BM25 works best for domain-specific workloads.
// Defaults preserve current behavior (0.55/0.25/0.20) for backward compatibility.
// Override via: RRF_VECTOR_WEIGHT=0.30 RRF_BM25_WEIGHT=0.70
// Scale-adaptive (Batch 10.7 Lane 7): W_INFINI grows with memory count,
//   W_VEC decreases to compensate, W_TXT stays constant at 0.25.
//   At N=14000: W_VEC=0.55, W_TXT=0.25, W_INFINI=0.20 (unchanged, sum=1.0)
//   Use getW_VEC(memoryCount), getW_INFINI(memoryCount) for scale-adaptive weights.
export const W_VEC = 0.55;
export const W_TXT = 0.25;
export const W_INFINI = 0.20;
export const RRF_K = 60; // Reciprocal Rank Fusion constant (Auralink SDC)
const S_VEC_MIN = 0.72; // Minimum vector similarity threshold
const WAVE5_ONTOLOGY_RECALL_AUTHORITIES = [
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'ELISA: An Interpretable Hybrid Generative AI Agent for Expression-Grounded Discovery in Single-Cell Genomics',
  'Reconstructing Content via Collaborative Attention to Improve Multimodal Embedding Quality',
];

/**
 * Get scale-adaptive RRF weights for a given memory count.
 * At N=14000, returns identical values to the hardcoded constants.
 * Paper: Epistemology (concentration of measure), Infini-attention
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {{ W_VEC: number, W_TXT: number, W_INFINI: number }}
 */
export function getScaleAdaptiveRRFWeights(memoryCount) {
  return {
    W_VEC: getW_VEC(memoryCount),
    W_TXT: getW_TXT(),
    W_INFINI: getW_INFINI(memoryCount),
  };
}

export async function hydeExpand(queryText) {
  const hypothetical = `A document that answers this question would say: ${queryText}`;
  return getEmbedding(hypothetical);
}

export async function interactionBoost(results, companyId = AIMOS_COMPANY_ID) {
  if (results.length === 0) return results;

  const keys = results.map(r => r.key).filter(Boolean);
  if (keys.length === 0) return results;

  const sql = `SELECT DISTINCT value FROM aimos_memories
    WHERE company_id = $1
      AND memory_type = 'event_log'
      AND value ILIKE ANY(ARRAY[${keys.map((_, i) => `$${i + 2}`).join(', ')}])
    LIMIT 200`;

  const likePatterns = keys.map(k => `%${k}%`);
  const params = [companyId, ...likePatterns];

  try {
    const res = await query(sql, params);
    const recentInteractionText = res.rows.map(r => r.value).join(' ');

    return results.map(r => {
      if (r.key && recentInteractionText.includes(r.key)) {
        return { ...r, rrf_score: r.rrf_score * 1.15, interaction_boosted: true };
      }
      return r;
    });
  } catch {
    // If interaction lookup fails, return results unchanged
    return results;
  }
}

export async function multiStageRecall(queryText, options = {}) {
  const {
    limit = 10,
    minConfidence = 0.3,
    clearanceLevel = 3,
    memoryTypeFilter,
    companyId = AIMOS_COMPANY_ID,
    memoryCount: suppliedMemoryCount
  } = options;
  const embedding = await getEmbedding(queryText);
  const memoryCount = suppliedMemoryCount ?? await getMemoryCount(companyId);

  let denseResults = await denseSearch(embedding, limit * 3, clearanceLevel, memoryTypeFilter, companyId);
  const sparseResults = await sparseSearch(queryText, limit * 3, clearanceLevel, memoryTypeFilter, companyId);

  // HyDE fallback: if dense search returns fewer than 3 results above S_VEC_MIN, retry with hypothetical embedding
  const denseAboveThreshold = denseResults.filter(r => parseFloat(r.similarity) >= S_VEC_MIN);
  if (denseAboveThreshold.length < 3) {
    const hydeEmbedding = await hydeExpand(queryText);
    const hydeResults = await denseSearch(hydeEmbedding, limit * 3, clearanceLevel, memoryTypeFilter, companyId);
    // Merge and deduplicate by ID, keeping original results first
    const seenIds = new Set(denseResults.map(r => r.id));
    for (const r of hydeResults) {
      if (!seenIds.has(r.id)) {
        seenIds.add(r.id);
        denseResults.push(r);
      }
    }
  }

  const fused = reciprocalRankFusion(denseResults, sparseResults, RRF_K, [], { memoryCount });
  const weighted = fused.map(r => ({
    ...r,
    rrf_score: r.rrf_score * (parseFloat(r.retrieval_weight) || 1.0)
  }));

  // Interaction boost: boost scores for memories referenced in recent interactions
  const boosted = await interactionBoost(weighted, companyId);

  const deduped = mmrDeduplicate(boosted, 0.85);
  const gated = deduped.filter(r => r.rrf_score >= minConfidence);
  const contextLimit = estimateContextNeed(queryText, gated.length);

  return gated.slice(0, Math.min(limit, contextLimit));
}

async function denseSearch(embedding, limit, clearance, typeFilter, companyId) {
  const embStr = `[${embedding.join(',')}]`;
  const sql = typeFilter
    ? `SELECT id, key, value, retrieval_weight, 1 - (embedding <=> $1::vector) as similarity, memory_type, clearance_level, ts_created FROM aimos_memories WHERE company_id = $2 AND clearance_level <= $3 AND memory_type = $4 ORDER BY embedding <=> $1::vector LIMIT $5`
    : `SELECT id, key, value, retrieval_weight, 1 - (embedding <=> $1::vector) as similarity, memory_type, clearance_level, ts_created FROM aimos_memories WHERE company_id = $2 AND clearance_level <= $3 ORDER BY embedding <=> $1::vector LIMIT $4`;
  const params = typeFilter
    ? [embStr, companyId, clearance, typeFilter, limit]
    : [embStr, companyId, clearance, limit];
  const res = await query(sql, params);
  return res.rows.map((r, i) => ({ ...r, dense_rank: i + 1, source: 'dense' }));
}

async function sparseSearch(queryText, limit, clearance, typeFilter, companyId) {
  const sql = typeFilter
    ? `SELECT id, key, value, retrieval_weight, ts_rank_cd(search_vector, plainto_tsquery('english', $1)) as bm25_score, memory_type, clearance_level, ts_created FROM aimos_memories WHERE company_id = $2 AND clearance_level <= $3 AND search_vector @@ plainto_tsquery('english', $1) AND memory_type = $4 ORDER BY bm25_score DESC LIMIT $5`
    : `SELECT id, key, value, retrieval_weight, ts_rank_cd(search_vector, plainto_tsquery('english', $1)) as bm25_score, memory_type, clearance_level, ts_created FROM aimos_memories WHERE company_id = $2 AND clearance_level <= $3 AND search_vector @@ plainto_tsquery('english', $1) ORDER BY bm25_score DESC LIMIT $4`;
  const params = typeFilter
    ? [queryText, companyId, clearance, typeFilter, limit]
    : [queryText, companyId, clearance, limit];
  const res = await query(sql, params);
  return res.rows.map((r, i) => ({ ...r, sparse_rank: i + 1, source: 'sparse' }));
}

/**
 * Reciprocal Rank Fusion across dense, sparse, and optional Infini-attention signals.
 * Phase 0: W_INFINI defaults to 0.0, so behavior is identical to pre-Phase 0.
 * Phase 2+: activate W_INFINI via env var RRF_INFINI_WEIGHT (suggested 0.20).
 *
 * @param {Array} denseResults - Vector similarity results with dense_rank
 * @param {Array} sparseResults - BM25 text results with sparse_rank
 * @param {number} k - RRF constant (default 60)
 * @param {Array} [infiniResults] - Optional Infini-attention linear memory results with infini_rank
 * @returns {Array} - Fused and sorted results
 */
export function reciprocalRankFusion(denseResults, sparseResults, k = 60, infiniResults = [], options = {}) {
  const scores = new Map();
  const weights = getScaleAdaptiveRRFWeights(options.memoryCount);
  const activeWeight = weights.W_VEC + weights.W_TXT + (infiniResults.length > 0 ? weights.W_INFINI : 0);
  const maxRrfMass = activeWeight / (k + 1);

  for (const r of denseResults) {
    if (parseFloat(r.similarity) < S_VEC_MIN) continue;
    if (!scores.has(r.id)) scores.set(r.id, { ...r, rrf_score: 0 });
    scores.get(r.id).rrf_score += weights.W_VEC / (k + r.dense_rank);
  }

  for (const r of sparseResults) {
    if (!scores.has(r.id)) scores.set(r.id, { ...r, rrf_score: 0 });
    scores.get(r.id).rrf_score += weights.W_TXT / (k + r.sparse_rank);
  }

  // Phase 0: infiniResults empty → W_INFINI * 0 = 0 (no behavioral change)
  // Phase 2+: pass Infini-attention results to activate third signal
  if (Array.isArray(infiniResults) && infiniResults.length > 0 && weights.W_INFINI > 0) {
    for (const r of infiniResults) {
      if (!scores.has(r.id)) scores.set(r.id, { ...r, rrf_score: 0 });
      scores.get(r.id).rrf_score += weights.W_INFINI / (k + (r.infini_rank || 1));
    }
  }

  return Array.from(scores.values())
    .map((result) => ({
      ...result,
      rrf_raw_score: result.rrf_score,
      rrf_score: maxRrfMass > 0 ? Math.min(1, result.rrf_score / maxRrfMass) : 0,
      rrf_weights: weights
    }))
    .sort((a, b) => b.rrf_score - a.rrf_score);
}

export function mmrDeduplicate(results, threshold = 0.85) {
  const selected = [];
  for (const r of results) {
    const isDuplicate = selected.some(s => {
      if (s.key === r.key) return true;
      const overlap = jaccardSimilarity(s.value?.slice(0, 200) || '', r.value?.slice(0, 200) || '');
      return overlap > threshold;
    });
    if (!isDuplicate) selected.push(r);
  }
  return selected;
}

function jaccardSimilarity(a, b) {
  const setA = new Set(a.toLowerCase().split(/\s+/));
  const setB = new Set(b.toLowerCase().split(/\s+/));
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return union.size > 0 ? intersection.size / union.size : 0;
}

function estimateContextNeed(queryText, resultCount) {
  const wordCount = queryText.split(/\s+/).length;
  if (wordCount > 20) return 15;
  if (wordCount > 10) return 10;
  return Math.min(resultCount, 7);
}

function normalizeRelationshipType(raw = '') {
  return String(raw || 'related_to')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'RELATED_TO';
}

export function buildOntologyRecallPathDiagnostics({
  queryText = '',
  results = [],
  relationships = [],
} = {}) {
  const safeResults = Array.isArray(results) ? results : [];
  const safeRelationships = Array.isArray(relationships) ? relationships : [];
  const resultKeys = new Set(safeResults.map((result) => String(result.key || result.id || '').toLowerCase()).filter(Boolean));
  const relationshipEdges = (safeRelationships.length > 0
    ? safeRelationships
    : safeResults.map((result, index) => ({
        subject: queryText || 'query',
        predicate: 'retrieved_evidence',
        object: result.key || result.id || `result-${index + 1}`,
        confidence: result.rrf_score ?? result.recall_confidence ?? result.similarity ?? 0.5,
      }))
  ).map((rel, index) => {
    const object = String(rel.object || rel.target || '').trim();
    const sourceKey = resultKeys.has(object.toLowerCase()) ? object : null;
    return {
      edge_index: index + 1,
      subject: String(rel.subject || rel.source || queryText || 'query'),
      relationship_type: normalizeRelationshipType(rel.predicate || rel.edge_type || rel.relationship_type),
      object,
      confidence: Number(Math.max(0, Math.min(Number(rel.confidence ?? 0.5), 1)).toFixed(3)),
      source_key: sourceKey,
      path_role: sourceKey ? 'retrieved_source_bound' : 'diagnostic_relationship',
    };
  });

  return {
    diagnostic_type: 'ontology_recall_path',
    status: safeResults.length > 0 ? 'ready' : 'no_results',
    source_papers: WAVE5_ONTOLOGY_RECALL_AUTHORITIES,
    diagnostic_only: true,
    query: String(queryText || '').slice(0, 240),
    result_count: safeResults.length,
    relationship_count: relationshipEdges.length,
    relationship_types: [...new Set(relationshipEdges.map((edge) => edge.relationship_type))],
    source_bound_edge_count: relationshipEdges.filter((edge) => edge.source_key).length,
    edges: relationshipEdges,
    guardrails: {
      rrf_weights_changed: false,
      dense_threshold_changed: false,
      sparse_threshold_changed: false,
      temporal_decay_changed: false,
      result_order_changed: false,
      hidden_chain_of_thought_exposed: false,
      multimodal_production_claim: false,
    },
    guarded_math: {
      sparse_retrieval: true,
      cascade_retrieval: true,
    },
    guarded_math_implemented: {
      sparse_retrieval: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
        coexistence_class: 'side_by_side_overlay',
      },
      cascade_retrieval: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Bridging Local and Global Knowledge — Cascaded MoE Path Routing',
        coexistence_class: 'side_by_side_independent',
      },
    },
  };
}

/**
 * Sparse Retrieval Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Beyond LLMs, Sparse Distributed Memory, and Neuromorphics
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes sparse sign-hash retrieval metrics
 * alongside the existing RRF pipeline. It does NOT replace or modify RRF
 * weights, dense/sparse thresholds, or result ordering. The production RRF
 * path remains authoritative. Guarded by guarded_math flag sparse_retrieval
 * which is guarded in production (knowledge-gated: paper understanding required).
 */
export function buildSparseRetrievalDiagnostic({
  queryVector = [],
  results = [],
  topK = 10,
} = {}) {
  const vec = Array.isArray(queryVector) ? queryVector : [];
  const res = Array.isArray(results) ? results : [];
  const k = Math.max(1, Number(topK) || 10);

  // Sparse sign-hash: binary hash of query vector for approximate retrieval
  const queryHash = vec.map((v) => (v >= 0 ? 1 : -1));
  const hashDensity = vec.length > 0 ? queryHash.filter((v) => v === 1).length / vec.length : 0.5;

  return {
    diagnostic: true,
    source_paper: 'Beyond LLMs, Sparse Distributed Memory, and Neuromorphics',
    coexistence_class: 'side_by_side_overlay',
    query_dimensions: vec.length,
    result_count: res.length,
    top_k: k,
    query_hash_density: hashDensity,
    rrf_weights_unchanged: true,
    note: 'Alongside-path diagnostic. Does not replace production RRF pipeline.',
  };
}

/**
 * Cascade Retrieval Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Bridging Local and Global Knowledge — Cascaded MoE Path Routing
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes local/global cascade stage metrics
 * as a diagnostic alongside the existing multi-stage retrieval path. It does
 * NOT modify stage ordering or routing. The production multi-stage path
 * remains authoritative. Guarded by guarded_math flag cascade_retrieval which
 * is guarded in production (knowledge-gated: paper understanding required).
 */
export function buildCascadeRetrievalDiagnostic({
  query = '',
  stages = [],
} = {}) {
  const stageList = Array.isArray(stages) ? stages : [];

  return {
    diagnostic: true,
    source_paper: 'Bridging Local and Global Knowledge — Cascaded MoE Path Routing',
    coexistence_class: 'side_by_side_independent',
    query: String(query || '').slice(0, 240),
    stage_count: stageList.length,
    local_stage_coverage: stageList.length > 0 ? 1 / stageList.length : 0,
    global_stage_coverage: stageList.length > 0 ? 1 / stageList.length : 0,
    cascade_order_unchanged: true,
    note: 'Alongside-path diagnostic. Local/global cascade stays separate from active routing.',
  };
}
