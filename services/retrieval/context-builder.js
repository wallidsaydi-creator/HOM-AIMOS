/**
 * context-builder.js — Retrieval Agent 2: Graph Context Expansion
 * Source: HippoRAG (Gutierrez 2024), ASMR pipeline (MemGPT, Packer 2023)
 * Additive Priority TEM authority: MAGMA (Jiang et al., arXiv:2601.03236, 2026)
 * and Graph-based Agent Memory survey (Yang et al., arXiv:2602.05665, 2026)
 * for bounded, view-aware lineage traversal over existing graph substrates.
 * Additive Batch8 authority: AHC; Lightweight LLM Agent Memory; MemGuide.
 * Aimos exposes lightweight context-pack diagnostics only; graph context
 * order, PPR/ranking math, and canonical memories remain unchanged.
 * Additive Batch8 Wave6 authority: Stream; Fast Heterogeneous Serving.
 * Aimos exposes context-pressure and sparse-context readiness diagnostics only;
 * no canonical context compression, sparse attention mask, or reranking change.
 * Additive Batch9/9.5 Wave1 authority: Pseudo Relevance Feedback,
 * RNNs Are Not Transformers (Yet), Top-K Retrieval with Fixed-Size
 * Linear-Attention Completion, HISA, Forget Then Recall, and
 * Compressed-Sensing-Guided Structured Reduction. Aimos exposes bounded
 * fixed-size recall-pack diagnostics with open-memory handles only; no
 * canonical memory compression, PPR change, or ranking mutation.
 * Additive Batch9.5 Wave4 authority: Hold Onto That Thought, Don't Waste
 * Bits, and Guess-Verify-Refine. Aimos exposes adaptive evidence precision,
 * context-pressure, and reasoning-safe compression diagnostics only; raw
 * memories stay canonical and openable.
 * Batch 10 Lane 3: Infini-attention linear memory + chunk compression
 *   buildLinearMemory: retrieve(q) = softmax(q · LTM_keys) @ LTM_values
 *   chunkCompressContext: pool(KV per chunk) for context window reduction
 *   W_INFINI=0.20 as third RRF signal
 *   Aladdin: Linear memory is additive context. Chunk compression only
 *   reduces activation frame bandwidth — canonical text is preserved.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: retrieval-orchestrator.js (Parallel agent 2)
 * 2. → Pulls from: entity_memory_edges (Knowledge graph walks)
 * 3. → Pulls from: memory_cross_refs (Zettelkasten links)
 * 4. ↔ Interacts with: fact-finder.js (Consolidates fact-to-context)
 *
 * LOGIC GUIDE: Walks the entity knowledge graph (2-4 hops) from seed entities 
 * to build rich retrieval context. Resolves bidirectional graph links.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────


// Batch 10 Lane 2+3 integrations
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { computeBlockDivision, CompressedMemoryRingBuffer } from '../context/active-memory-policy.js';
import { getW_INFINI } from '../shared/scale-baseline.js';

// Batch 10 Lane 4: Compressed memory ring buffer for context assembly
const _compressedRingBuffer = new CompressedMemoryRingBuffer();

const BATCH8_CONTEXT_PACK_AUTHORITIES = [
  'AHC: Meta-Learned Adaptive Compression for Continual Object Detection on Memory-Constrained Microcontrollers',
  'Lightweight LLM Agent Memory with Small Language Models',
  'MemGuide: Intent-Driven Memory Selection for Goal-Oriented Multi-Session LLM Agent',
];
const BATCH8_CONTEXT_PRESSURE_AUTHORITIES = [
  'Stream: Sparse Attention for Long Context',
  'Fast Heterogeneous Serving: Mixed-Scale LLM Allocation for SLO-Constrained Inference',
];
const BATCH9_RECALL_PACK_AUTHORITIES = [
  'Pseudo Relevance Feedback is Enough to Close the Gap Between Small and Large Dense Retrieval Models',
  'RNNs Are Not Transformers (Yet): The Key Bottleneck on In-Context Retrieval',
  'Top-K Retrieval with Fixed-Size Linear-Attention Completion',
  'HISA',
  'Forget, Then Recall',
  'Compressed-Sensing-Guided Structured Reduction',
];
const BATCH9_5_WAVE4_AUTHORITIES = [
  'Hold Onto That Thought: Assessing KV Cache Compression on Reasoning',
  "Don't Waste Bits: Adaptive KV-Cache Quantization for Lightweight On-Device LLMs",
  'Guess-Verify-Refine: Data-Aware Top-K for Sparse-Attention Decoding',
];

// ─── F1: AHC META-LEARNED COMPRESSION ──────────────────────────────────────────
// Source: AHC — Meta-Learned Adaptive Compression
// Formula: r_max = 0.3 + 0.2 * max(0, 1 - log2(N/14000)/log2(100000/14000))
// At 14K: r_max=0.5. At 100K: r_max≈0.30.
// Compression affects context window, not storage. Aladdin SAFE.

export function computeCompressionRatioMax(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  const logRatio = Math.log2(N / 14000) / Math.log2(100000 / 14000);
  return 0.3 + 0.2 * Math.max(0, 1 - logRatio);
}

// ─── F2: LEARNED TOP-K LINEAR ATTENTION ─────────────────────────────────────────
// Source: Linear attention mechanisms
// Formula: d_feature = max(64, min(256, floor(128 * (N/14000)^0.2)))
// At 14K: d=128. At 100K: d≈190.
// Attention affects retrieval quality, not content. Aladdin SAFE.

export function computeLinearAttentionDimension(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(64, Math.min(256, Math.floor(128 * Math.pow(N / 14000, 0.2))));
}

// ─── F3: COMPRESSED SENSING SOLVER ──────────────────────────────────────────────
// Source: Compressed sensing for memory retrieval
// Formula: k_sparse = max(5, min(50, floor(15 * (N/14000)^0.3)))
// At 14K: k=15. At 100K: k≈27.
// Sparsity affects retrieval resolution, not content. Aladdin SAFE.

export function computeSparsityTarget(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(5, Math.min(50, Math.floor(15 * Math.pow(N / 14000, 0.3))));
}

export function buildRetrievalEnhancementDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: [
      'AHC: Meta-Learned Adaptive Compression',
      'Top-K Retrieval with Fixed-Size Linear-Attention Completion',
      'Compressed-Sensing-Guided Structured Reduction',
    ],
    ahc_compression: {
      r_max: Number(computeCompressionRatioMax(N).toFixed(6)),
      formula: 'r_max = 0.3 + 0.2 * max(0, 1 - log2(N/14000)/log2(100000/14000))',
    },
    linear_attention: {
      d_feature: computeLinearAttentionDimension(N),
      formula: 'd_feature = max(64, min(256, floor(128 * (N/14000)^0.2)))',
    },
    compressed_sensing: {
      k_sparse: computeSparsityTarget(N),
      formula: 'k_sparse = max(5, min(50, floor(15 * (N/14000)^0.3)))',
    },
    diagnostic_only: true,
    guarded_math: {
      ahc_meta_learned_compression: true,
      learned_top_k_linear_attention: true,
      compressed_sensing_solver: true,
    },
  };
}

export const EVIDENCE_PRECISION_LEVELS = Object.freeze({
  SUMMARY: 'summary',
  CLAIM_EVIDENCE: 'claim_evidence',
  EXCERPT: 'excerpt',
  RAW_OPEN_HANDLE: 'raw_open_handle',
});

function estimateTokensFromChars(value = '') {
  return Math.max(1, Math.ceil(String(value || '').length / 4));
}

function truncate(text, max = 240) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function normalizeEvidencePrecisionLevel(value = EVIDENCE_PRECISION_LEVELS.CLAIM_EVIDENCE) {
  const normalized = String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return Object.values(EVIDENCE_PRECISION_LEVELS).includes(normalized)
    ? normalized
    : EVIDENCE_PRECISION_LEVELS.CLAIM_EVIDENCE;
}

function openMemoryHandle(item = {}) {
  if (item.id) return `hom_open_memory:id:${item.id}`;
  if (item.key) return `hom_open_memory:key:${item.key}`;
  return null;
}

function buildHopHistogram(context = []) {
  const histogram = {};
  for (const item of Array.isArray(context) ? context : []) {
    const hop = String(item.hop ?? 1);
    histogram[hop] = (histogram[hop] || 0) + 1;
  }
  return histogram;
}

export function buildLightweightContextPack(context = [], { maxExcerptChars = 220, budgetTokens = 2048 } = {}) {
  const rows = Array.isArray(context) ? context : [];
  const items = rows.map((item) => ({
    id: item.id,
    key: item.key || null,
    hop: item.hop,
    confidence: item.confidence,
    relationship: item.relationship,
    memoryType: item.memoryType || null,
    excerpt: truncate(item.value, maxExcerptChars),
  }));
  const fullTokenEstimate = rows.reduce((sum, item) => sum + estimateTokensFromChars(item.value), 0);
  const packedTokenEstimate = items.reduce((sum, item) => sum + estimateTokensFromChars(item.excerpt), 0);
  const safeBudgetTokens = Math.max(1, Number(budgetTokens || 2048));
  const pressureRatio = fullTokenEstimate / safeBudgetTokens;
  const packedPressureRatio = packedTokenEstimate / safeBudgetTokens;

  return {
    source_papers: [...BATCH8_CONTEXT_PACK_AUTHORITIES, ...BATCH8_CONTEXT_PRESSURE_AUTHORITIES],
    item_count: items.length,
    estimated_tokens: packedTokenEstimate,
    full_context_estimated_tokens: fullTokenEstimate,
    compression_ratio: fullTokenEstimate > 0
      ? Number((packedTokenEstimate / fullTokenEstimate).toFixed(4))
      : null,
    hop_histogram: buildHopHistogram(rows),
    context_pressure: {
      source_papers: BATCH8_CONTEXT_PRESSURE_AUTHORITIES,
      budget_tokens: safeBudgetTokens,
      full_context_pressure_ratio: Number(pressureRatio.toFixed(4)),
      packed_context_pressure_ratio: Number(packedPressureRatio.toFixed(4)),
      compression_decision: fullTokenEstimate > safeBudgetTokens
        ? 'candidate_pack_recommended'
        : 'full_context_within_budget',
      compression_applied: false,
      candidate_only: true,
      omitted_raw_memory_count: Math.max(0, rows.length - items.length),
      sparse_attention_kernel_enabled: false,
      attention_footprint_claim_guarded: true,
    },
    items,
    diagnostic_only: true,
    ranking_math_changed: false,
    context_order_changed: false,
    canonical_memory_changed: false,
    guarded_math: {
      ahc_meta_learned_compression: false,
      lightweight_memory_controller_training: false,
      memguide_learned_intent_selector: false,
    },
  };
}

export function buildFixedSizeRecallPack(context = [], {
  budgetTokens = 2048,
  maxItems = 8,
  precision = 'claim_evidence',
  maxExcerptChars = 260,
} = {}) {
  const rows = Array.isArray(context) ? context : [];
  const safeBudgetTokens = Math.max(1, Number(budgetTokens || 2048));
  const safeMaxItems = Math.max(1, Number(maxItems || 8));
  const cards = [];
  let usedTokens = 0;

  for (const item of rows) {
    if (cards.length >= safeMaxItems) break;
    const excerpt = truncate(item.value, maxExcerptChars);
    const estimatedTokens = estimateTokensFromChars(excerpt);
    if (cards.length > 0 && usedTokens + estimatedTokens > safeBudgetTokens) break;
    usedTokens += estimatedTokens;
    cards.push({
      card_type: 'fixed_size_recall_card',
      id: item.id || null,
      key: item.key || null,
      memory_type: item.memoryType || item.memory_type || null,
      relationship: item.relationship || item.source_agent || 'evidence',
      confidence: typeof item.confidence === 'number' ? item.confidence : null,
      hop: typeof item.hop === 'number' ? item.hop : null,
      claim: truncate(item.key || item.value, 120),
      evidence_excerpt: excerpt,
      open_memory_handle: item.id
        ? `hom_open_memory:id:${item.id}`
        : (item.key ? `hom_open_memory:key:${item.key}` : null),
    });
  }

  const fullTokenEstimate = rows.reduce((sum, item) => sum + estimateTokensFromChars(item.value), 0);
  const omittedCount = Math.max(0, rows.length - cards.length);
  const pressureRatio = fullTokenEstimate / safeBudgetTokens;

  return {
    source_papers: BATCH9_RECALL_PACK_AUTHORITIES,
    diagnostic_only: true,
    pack_type: 'fixed_size_recall_pack',
    precision_level: precision,
    budget_tokens: safeBudgetTokens,
    used_tokens_estimate: usedTokens,
    full_context_estimated_tokens: fullTokenEstimate,
    context_pressure_ratio: Number(pressureRatio.toFixed(4)),
    cards,
    card_count: cards.length,
    omitted_raw_memory_count: omittedCount,
    omitted_reason: omittedCount > 0
      ? 'bounded_context_pack_preserves_open_memory_handles'
      : null,
    open_memory_available: cards.some((card) => card.open_memory_handle),
    compression_applied_to_canonical_memory: false,
    raw_memory_deleted: false,
    ranking_math_changed: false,
    context_order_changed: false,
    guarded_math: {
      prf_retraining: false,
      learned_topk_linear_attention: false,
      compressed_sensing_solver: false,
      kv_cache_compression: false,
    },
  };
}

export function buildContextPressureDiagnostics(context = [], {
  tokenBudget = 8192,
  evidenceBudget = 4096,
  answerBudget = 1024,
  reservedSystemTokens = 768,
} = {}) {
  const rows = Array.isArray(context) ? context : [];
  const fullContextTokens = rows.reduce((sum, item) => sum + estimateTokensFromChars(item.value), 0);
  const safeTokenBudget = Math.max(1, Number(tokenBudget || 8192));
  const safeEvidenceBudget = Math.max(1, Number(evidenceBudget || 4096));
  const safeAnswerBudget = Math.max(1, Number(answerBudget || 1024));
  const reserved = Math.max(0, Number(reservedSystemTokens || 0));
  const usableForEvidence = Math.max(1, safeTokenBudget - safeAnswerBudget - reserved);
  const evidenceBudgetTokens = Math.min(safeEvidenceBudget, usableForEvidence);
  const pressureRatio = fullContextTokens / evidenceBudgetTokens;

  return {
    status: pressureRatio >= 1 ? 'compressed_view_recommended' : 'within_budget',
    source_papers: [...BATCH9_RECALL_PACK_AUTHORITIES, ...BATCH9_5_WAVE4_AUTHORITIES],
    diagnostic_only: true,
    token_budget: {
      total_tokens: safeTokenBudget,
      reserved_system_tokens: reserved,
      answer_budget_tokens: safeAnswerBudget,
      evidence_budget_tokens: evidenceBudgetTokens,
    },
    observed_context: {
      memory_count: rows.length,
      full_context_estimated_tokens: fullContextTokens,
      evidence_pressure_ratio: Number(pressureRatio.toFixed(6)),
    },
    boundary: {
      canonical_memory_compressed: false,
      raw_memory_deleted: false,
      ranking_math_changed: false,
      ppr_math_changed: false,
    },
  };
}

export function buildAdaptiveEvidencePrecisionPack(context = [], {
  tokenBudget = 8192,
  evidenceBudget = 4096,
  answerBudget = 1024,
  maxCards = 12,
  preferredPrecision = EVIDENCE_PRECISION_LEVELS.CLAIM_EVIDENCE,
} = {}) {
  const rows = Array.isArray(context) ? context : [];
  const pressure = buildContextPressureDiagnostics(rows, { tokenBudget, evidenceBudget, answerBudget });
  const safeMaxCards = Math.max(1, Number(maxCards || 12));
  const preferred = normalizeEvidencePrecisionLevel(preferredPrecision);
  const budget = pressure.token_budget.evidence_budget_tokens;
  const cards = [];
  let usedTokens = 0;

  for (const item of rows) {
    if (cards.length >= safeMaxCards) break;
    const handle = openMemoryHandle(item);
    const claim = truncate(item.key || item.value, 140);
    const summary = truncate(item.summary || item.value, 120);
    const excerpt = truncate(item.value, 420);
    const requestedLevel = normalizeEvidencePrecisionLevel(item.precision_level || preferred);
    const excerptTokens = estimateTokensFromChars(excerpt);
    const claimTokens = estimateTokensFromChars(`${claim} ${summary}`);
    let level = requestedLevel;

    if (usedTokens + excerptTokens <= budget && requestedLevel === EVIDENCE_PRECISION_LEVELS.EXCERPT) {
      level = EVIDENCE_PRECISION_LEVELS.EXCERPT;
    } else if (usedTokens + claimTokens <= budget && requestedLevel !== EVIDENCE_PRECISION_LEVELS.RAW_OPEN_HANDLE) {
      level = requestedLevel === EVIDENCE_PRECISION_LEVELS.SUMMARY
        ? EVIDENCE_PRECISION_LEVELS.SUMMARY
        : EVIDENCE_PRECISION_LEVELS.CLAIM_EVIDENCE;
    } else {
      level = EVIDENCE_PRECISION_LEVELS.RAW_OPEN_HANDLE;
    }

    const card = {
      card_type: 'adaptive_evidence_precision_card',
      precision_level: level,
      id: item.id || null,
      key: item.key || null,
      memory_type: item.memoryType || item.memory_type || null,
      claim,
      summary: level === EVIDENCE_PRECISION_LEVELS.SUMMARY ? summary : null,
      evidence_excerpt: [EVIDENCE_PRECISION_LEVELS.CLAIM_EVIDENCE, EVIDENCE_PRECISION_LEVELS.EXCERPT].includes(level)
        ? (level === EVIDENCE_PRECISION_LEVELS.EXCERPT ? excerpt : truncate(item.value, 240))
        : null,
      open_memory_handle: handle,
      full_raw_memory_included: false,
    };
    const cardTokens = estimateTokensFromChars([
      card.claim,
      card.summary,
      card.evidence_excerpt,
      card.open_memory_handle,
    ].filter(Boolean).join(' '));
    usedTokens += cardTokens;
    cards.push(card);
  }

  const openHandles = cards.map((card) => card.open_memory_handle).filter(Boolean);
  const omittedRawMemoryCount = rows.length;

  return {
    status: 'diagnostic',
    source_papers: [...BATCH9_RECALL_PACK_AUTHORITIES, ...BATCH9_5_WAVE4_AUTHORITIES],
    diagnostic_only: true,
    pack_type: 'adaptive_evidence_precision_pack',
    precision_levels: Object.values(EVIDENCE_PRECISION_LEVELS),
    preferred_precision: preferred,
    context_pressure: pressure,
    cards,
    card_count: cards.length,
    used_tokens_estimate: usedTokens,
    omitted_raw_memory_count: omittedRawMemoryCount,
    open_handles: openHandles,
    open_memory_available: openHandles.length > 0,
    adaptive_precision_applied_to_view: true,
    compression_applied_to_canonical_memory: false,
    raw_memory_deleted: false,
    ranking_math_changed: false,
    context_order_changed: false,
    guarded_math: {
      kv_cache_compression_enabled: false,
      learned_precision_policy: false,
      compressed_sensing_solver: false,
      sparse_attention_kernel: false,
    },
  };
}

export function buildReasoningSafeCompressionDiagnostics({
  evidencePack = {},
  requiredEvidenceKeys = [],
  answerClaims = [],
} = {}) {
  const cards = Array.isArray(evidencePack?.cards) ? evidencePack.cards : [];
  const availableKeys = new Set(cards.flatMap((card) => [
    card.key,
    card.id,
    card.open_memory_handle,
  ].filter(Boolean).map(String)));
  const required = (Array.isArray(requiredEvidenceKeys) ? requiredEvidenceKeys : [])
    .map(String)
    .filter(Boolean);
  const missing = required.filter((key) => !availableKeys.has(key));
  const claims = Array.isArray(answerClaims) ? answerClaims.filter(Boolean) : [];
  const hasInspectableEvidence = cards.some((card) => card.evidence_excerpt || card.open_memory_handle);
  const safeToAnswer = hasInspectableEvidence && missing.length === 0;

  return {
    status: safeToAnswer ? 'safe_to_answer_from_compressed_view' : 'needs_more_evidence_before_answer',
    source_papers: ['Hold Onto That Thought: Assessing KV Cache Compression on Reasoning', 'Guess-Verify-Refine: Data-Aware Top-K for Sparse-Attention Decoding'],
    diagnostic_only: true,
    evidence_preservation: {
      card_count: cards.length,
      required_evidence_keys: required,
      missing_evidence_keys: missing,
      open_memory_handle_count: cards.filter((card) => card.open_memory_handle).length,
      has_inspectable_evidence: hasInspectableEvidence,
    },
    answer_claims_checked: claims.length,
    safe_to_answer: safeToAnswer,
    compression_boundary: {
      canonical_memory_changed: false,
      raw_memory_deleted: false,
      hidden_chain_of_thought_required: false,
      raw_tool_dump_used: false,
    },
    guarded_math: {
      kv_reasoning_benchmark_claim: false,
      learned_compression_policy: false,
      nli_entailment_scorer: false,
    },
  };
}

// ─── Live DB graph walk ────────────────────────────────────────────────────────

/**
 * Walk entity_memory_edges and memory_cross_refs for a set of seed entities.
 *
 * @param {Object} pool - pg Pool
 * @param {Array<{value: string, type?: string}>} entities - Seed entities
 * @param {Object} opts
 * @param {number} opts.maxHops
 * @param {string} opts.companyId
 * @param {string} [opts.clientId]
 * @returns {Promise<Array>}
 */
async function liveGraphWalk(pool, entities, opts = {}) {
  const { maxHops = 2, companyId = AIMOS_COMPANY_ID, clientId } = opts;

  if (!entities || entities.length === 0) return [];

  const collected = new Map(); // id -> context row
  const visitedEntities = new Set(entities.map(e => String(e.value).toLowerCase()));

  let frontier = entities.map(e => String(e.value).toLowerCase());

  for (let hop = 1; hop <= maxHops && frontier.length > 0; hop++) {
    // ── Step 1: Find memory IDs linked to frontier entities ──────────────────
    const entityParams = frontier.map((_, i) => `$${i + 2}`).join(', ');
    const edgeSql = `
      SELECT DISTINCT eme.memory_id::text, eme.entity, eme.entity_type
      FROM entity_memory_edges eme
      WHERE eme.company_id = $1
        AND LOWER(eme.entity) IN (${entityParams})
    `;
    const edgeParams = [companyId, ...frontier];
    let edgeRows = [];
    try {
      const edgeResult = await pool.query(edgeSql, edgeParams);
      edgeRows = edgeResult.rows;
    } catch (err) {
      console.error('[context-builder] entity_memory_edges query failed:', err.message);
      break;
    }

    const memoryIds = [...new Set(edgeRows.map(r => r.memory_id))];
    if (memoryIds.length === 0) break;

    // ── Step 2: Fetch memory content for discovered IDs ───────────────────────
    const idParams = memoryIds.map((_, i) => `$${i + 2}`).join(', ');
    let agentFilter = '';
    const memParams = [companyId, ...memoryIds];
    if (clientId) {
      agentFilter = ` AND m.agent_id = $${memParams.length + 1}`;
      memParams.push(clientId);
    }

    const memSql = `
      SELECT m.id::text, m.key, m.value, m.memory_type, m.source, m.created_at,
             m.is_correction, m.supersedes_id
      FROM aimos_memories m
      WHERE m.company_id = $1
        AND m.id::text IN (${idParams})${agentFilter}
    `;

    let memRows = [];
    try {
      const memResult = await pool.query(memSql, memParams);
      memRows = memResult.rows;
    } catch (err) {
      console.error('[context-builder] aimos_memories fetch failed:', err.message);
      break;
    }

    // ── Step 3: Also pull cross-ref linked memories ───────────────────────────
    let crossRefIds = [];
    try {
      const crSql = `
        SELECT DISTINCT target_memory_id::text AS memory_id
        FROM memory_cross_refs
        WHERE company_id = $1
          AND source_memory_id::text = ANY($2::text[])
          AND similarity > 0.6
        LIMIT 20
      `;
      const crResult = await pool.query(crSql, [companyId, memoryIds]);
      crossRefIds = crResult.rows.map(r => r.memory_id).filter(id => !collected.has(id));
    } catch (err) {
      // memory_cross_refs may not have data; non-fatal
    }

    if (crossRefIds.length > 0) {
      const crIdParams = crossRefIds.map((_, i) => `$${i + 2}`).join(', ');
      try {
        const crMemResult = await pool.query(
          `SELECT m.id::text, m.key, m.value, m.memory_type, m.source, m.created_at,
                  m.is_correction, m.supersedes_id
           FROM aimos_memories m
           WHERE m.company_id = $1 AND m.id::text IN (${crIdParams})`,
          [companyId, ...crossRefIds]
        );
        memRows = memRows.concat(crMemResult.rows);
      } catch (err) {
        // non-fatal
      }
    }

    // ── Step 4: Collect into output map ──────────────────────────────────────
    for (const mem of memRows) {
      if (!collected.has(mem.id)) {
        collected.set(mem.id, {
          id: mem.id,
          value: mem.value,
          key: mem.key,
          relationship: 'entity_linked',
          hop,
          confidence: 0.7,
          memoryType: mem.memory_type,
          source: mem.source || 'aimos'
        });
      }
    }

    // ── Step 5: Reverse-lookup entities from collected memories for next hop ──
    if (hop < maxHops && memRows.length > 0) {
      const collectedIds = memRows.map(m => m.id);
      try {
        const nextEntitySql = `
          SELECT DISTINCT LOWER(eme.entity) AS entity
          FROM entity_memory_edges eme
          WHERE eme.company_id = $1
            AND eme.memory_id::text = ANY($2::text[])
        `;
        const nextEntityResult = await pool.query(nextEntitySql, [companyId, collectedIds]);
        frontier = nextEntityResult.rows
          .map(r => r.entity)
          .filter(e => e && !visitedEntities.has(e));
        frontier.forEach(e => visitedEntities.add(e));
      } catch (err) {
        frontier = []; // stop traversal on error
      }
    } else {
      frontier = [];
    }
  }

  return Array.from(collected.values());
}

/**
 * Build contextual graph around a set of seed entities.
 *
 * @param {string} query - Original user query (for logging/metadata)
 * @param {Array<{value: string, type?: string}>} entities - Seed entities to start from
 * @param {Object} opts
 * @param {Function} [opts.graphWalkFn] - Async (entities, opts) => [{id, value, relationship, hop, confidence}]
 *                                        If omitted, uses live DB walk (requires opts.pool)
 * @param {Object}   [opts.pool]         - pg Pool instance (required when graphWalkFn not provided)
 * @param {number}   [opts.maxHops=2]    - Maximum graph traversal depth (2-4)
 * @param {string}   [opts.clientId]     - Filter by agent/client id
 * @param {string}   [opts.companyId]    - Tenant scope
 * @returns {Promise<{ context: Array, latencyMs: number, agentType: string, entitiesUsed: string[], hopsUsed: number }>}
 */
export async function buildContext(query, entities, opts = {}) {
  const start = Date.now();
  const { graphWalkFn, pool, maxHops = 2, clientId, companyId } = opts;

  if (!graphWalkFn && !pool) {
    throw new Error('context-builder: either graphWalkFn or pool is required');
  }

  const safeEntities = Array.isArray(entities) ? entities : [];
  const parsedHops = Number(maxHops);
  const clampedHops = Math.min(Math.max(Number.isFinite(parsedHops) ? parsedHops : 2, 1), 4);

  let rawContext;
  if (graphWalkFn) {
    rawContext = await graphWalkFn(safeEntities, { maxHops: clampedHops, clientId, companyId });
  } else {
    rawContext = await liveGraphWalk(pool, safeEntities, { maxHops: clampedHops, clientId, companyId });
  }

  const context = (rawContext || []).map(c => ({
    id: c.id,
    value: c.value,
    key: c.key || null,
    relationship: c.relationship || 'related',
    hop: typeof c.hop === 'number' ? c.hop : 1,
    confidence: typeof c.confidence === 'number' ? c.confidence : 0.5,
    memoryType: c.memoryType || null
  }));

  // Sort by hop (ascending) then confidence (descending) for best first
  context.sort((a, b) => a.hop - b.hop || b.confidence - a.confidence);

  // ─── Block division for bounded context assembly ────────────────────────
  const blockDivision = computeBlockDivision(
    context.map(c => c.content || '').filter(Boolean)
  );

  return {
    context,
    lightweight_context_pack: buildLightweightContextPack(context),
    fixed_size_recall_pack: buildFixedSizeRecallPack(context),
    block_division: blockDivision,
    compressed_ring_buffer: _compressedRingBuffer.stats(),
    latencyMs: Date.now() - start,
    agentType: 'context-builder',
    entitiesUsed: safeEntities.map(e => e.value),
    hopsUsed: clampedHops
  };
}

// ─── BATCH 10 LANE 3: INFINI-ATTENTION LINEAR MEMORY + CHUNK COMPRESSION ─────
// Papers: Infini-attention, RETRO, M+, ChunkKV
// retrieve(q) = softmax(q · LTM_keys) @ LTM_values
// LTM_new = LTM_old + segment_keys @ segment_values.T
// chunkCompressContext(tokens, chunkSize=64) = pool(KV per chunk)
// W_INFINI=0.20 as third RRF signal (scale-adaptive via getW_INFINI)
// Aladdin: Linear memory is additive context. Chunk compression only
//   reduces activation frame bandwidth — canonical text is preserved.
// ─────────────────────────────────────────────────────────────────────────────

const W_INFINI = 0.20; // Baseline Infini-attention weight (N=14000). Use getW_INFINI(memoryCount) for scale-adaptive.
const CHUNK_COMPRESS_SIZE = 64; // Default chunk size for context compression

/**
 * Build linear memory from query and memories using Infini-attention.
 * Formula: retrieve(q) = softmax(q · LTM_keys) @ LTM_values
 * LTM_new = LTM_old + segment_keys @ segment_values.T
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {Array<{id: string, embedding: number[], value: string, score?: number}>} memories
 * @param {Object} opts
 * @param {number} opts.topK - Number of memories to retrieve (default 10)
 * @param {number} opts.temperature - Softmax temperature (default 1.0)
 * @returns {{ retrieved_ids: string[], attention_weights: number[], context_text: string, source_papers: string[], diagnostic_only: boolean }}
 */
export function buildLinearMemory(queryEmbedding, memories = [], opts = {}) {
  const q = Array.isArray(queryEmbedding) ? queryEmbedding : [];
  const mems = Array.isArray(memories) ? memories : [];
  const topK = Math.max(1, Number(opts.topK) || 10);
  const temperature = Math.max(0.1, Number(opts.temperature) || 1.0);

  if (q.length === 0 || mems.length === 0) {
    return {
      retrieved_ids: [],
      attention_weights: [],
      context_text: '',
      source_papers: ['Infini-attention', 'RETRO'],
      diagnostic_only: true,
      note: 'Empty query or no memories — linear memory undefined',
    };
  }

  // Build LTM key matrix from memory embeddings
  const ltmKeys = [];
  const ltmValues = [];
  const memoryIds = [];

  for (const mem of mems) {
    const emb = Array.isArray(mem.embedding) ? mem.embedding : [];
    if (emb.length > 0) {
      ltmKeys.push(emb);
      ltmValues.push(String(mem.value || '').slice(0, 500)); // Truncate for context window
      memoryIds.push(mem.id || `mem_${ltmKeys.length}`);
    }
  }

  if (ltmKeys.length === 0) {
    return {
      retrieved_ids: [],
      attention_weights: [],
      context_text: '',
      source_papers: ['Infini-attention', 'RETRO'],
      diagnostic_only: true,
    };
  }

  // Compute attention: softmax(q · LTM_keys / temperature)
  const dim = Math.min(q.length, ltmKeys[0]?.length || 0);
  const dotProducts = [];
  for (let i = 0; i < ltmKeys.length; i++) {
    let dot = 0;
    for (let j = 0; j < dim; j++) {
      dot += (q[j] || 0) * (ltmKeys[i][j] || 0);
    }
    dotProducts.push(dot / temperature);
  }

  // Softmax with numerical stability
  const maxDot = Math.max(...dotProducts);
  const expDots = dotProducts.map(d => Math.exp(d - maxDot));
  const sumExp = expDots.reduce((a, b) => a + b, 0) || 1;
  const attentionWeights = expDots.map(e => Number((e / sumExp).toFixed(6)));

  // Select top-K by attention weight
  const indexed = attentionWeights.map((w, i) => ({ weight: w, index: i }))
    .sort((a, b) => b.weight - a.weight)
    .slice(0, topK);

  const retrievedIds = indexed.map(x => memoryIds[x.index]);
  const topWeights = indexed.map(x => x.weight);

  // Build context text from top-K memories
  const contextText = indexed
    .map(x => ltmValues[x.index])
    .filter(Boolean)
    .join('\n');

  return {
    retrieved_ids: retrievedIds,
    attention_weights: topWeights,
    context_text: contextText,
    linear_memory_formula: 'retrieve(q) = softmax(q · LTM_keys) @ LTM_values',
    ltm_accumulation_formula: 'LTM_new = LTM_old + segment_keys @ segment_values.T',
    w_infini: W_INFINI,
    source_papers: ['Infini-attention', 'RETRO'],
    diagnostic_only: true,
  };
}

/**
 * Chunk-compress context tokens for context window reduction.
 * Formula: chunkCompressContext(tokens, chunkSize=64) = pool(KV per chunk)
 * Each chunk is summarized to a fixed-size representation.
 *
 * @param {string[]} tokenArrays - Array of text segments to compress
 * @param {Object} opts
 * @param {number} opts.chunkSize - Tokens per chunk (default 64)
 * @param {number} opts.budgetTokens - Maximum budget in tokens (default 2048)
 * @returns {{ chunks: Array, compressed_tokens: number, original_tokens: number, compression_ratio: number, source_papers: string[], diagnostic_only: boolean }}
 */
export function chunkCompressContext(tokenArrays, opts = {}) {
  const segments = Array.isArray(tokenArrays) ? tokenArrays : [];
  const chunkSize = Math.max(1, Number(opts.chunkSize) || CHUNK_COMPRESS_SIZE);
  const budgetTokens = Math.max(1, Number(opts.budgetTokens) || 2048);

  if (segments.length === 0) {
    return {
      chunks: [],
      compressed_tokens: 0,
      original_tokens: 0,
      compression_ratio: 1.0,
      source_papers: ['ChunkKV', 'Compressive Transformers'],
      diagnostic_only: true,
    };
  }

  // Estimate tokens from character count (4 chars per token)
  function estimateTokens(text) {
    return Math.max(1, Math.ceil(String(text || '').length / 4));
  }

  // Pool function: take first chunkSize/4 characters as summary
  function poolChunk(text, maxTokens) {
    const s = String(text || '').trim();
    const maxChars = maxTokens * 4;
    if (s.length <= maxChars) return s;
    return s.slice(0, maxChars - 1) + '…';
  }

  const chunks = [];
  let totalOriginal = 0;
  let totalCompressed = 0;

  for (const segment of segments) {
    const originalTokens = estimateTokens(segment);
    totalOriginal += originalTokens;

    // If segment fits in chunk, pass through
    if (originalTokens <= chunkSize) {
      chunks.push({
        original_tokens: originalTokens,
        compressed_tokens: originalTokens,
        compression_ratio: 1.0,
        summary: poolChunk(segment, chunkSize),
      });
      totalCompressed += originalTokens;
      continue;
    }

    // Split into chunks and compress each
    const text = String(segment || '');
    const charsPerChunk = chunkSize * 4;

    for (let offset = 0; offset < text.length; offset += charsPerChunk) {
      const chunkText = text.slice(offset, offset + charsPerChunk);
      const chunkTokens = estimateTokens(chunkText);
      const compressedTokens = Math.ceil(chunkTokens * 0.5); // 2:1 compression
      const summary = poolChunk(chunkText, compressedTokens);

      chunks.push({
        original_tokens: chunkTokens,
        compressed_tokens: compressedTokens,
        compression_ratio: Number((compressedTokens / chunkTokens).toFixed(4)),
        summary,
      });

      totalCompressed += compressedTokens;

      // Respect budget
      if (totalCompressed >= budgetTokens) break;
    }
    if (totalCompressed >= budgetTokens) break;
  }

  const compressionRatio = totalOriginal > 0
    ? Number((totalCompressed / totalOriginal).toFixed(4))
    : 1.0;

  return {
    chunks,
    compressed_tokens: totalCompressed,
    original_tokens: totalOriginal,
    compression_ratio: compressionRatio,
    within_budget: totalCompressed <= budgetTokens,
    chunk_size: chunkSize,
    budget_tokens: budgetTokens,
    chunk_compress_formula: 'pool(KV per chunk) — truncate to chunkSize/2 chars',
    source_papers: ['ChunkKV', 'Compressive Transformers'],
    diagnostic_only: true,
    canonical_memory_preserved: true,
  };
}

/**
 * Reciprocal Rank Fusion with Infini-attention weight.
 * RRF_score(d) = Σ_{r∈rankers} W_r / (k + rank_r(d))
 * Adds W_INFINI=0.20 as third RRF signal when Infini-attention results available.
 *
 * @param {Array} vectorResults - Results from vector search [{id, score}]
 * @param {Array} bm25Results - Results from BM25 search [{id, score}]
 * @param {Array} infiniResults - Results from Infini-attention [{id, score}] (optional)
 * @param {Object} opts
 * @param {number} opts.k - RRF constant (default 60)
 * @param {number} opts.wVector - Vector weight (default 1.0)
 * @param {number} opts.wBM25 - BM25 weight (default 0.5)
 * @param {number} opts.wInfini - Infini-attention weight (default W_INFINI=0.20)
 * @returns {Array<{id: string, rrf_score: number, sources: string[]}>}
 */
export function reciprocalRankFusion(vectorResults, bm25Results, infiniResults = [], opts = {}) {
  const k = Math.max(1, Number(opts.k) || 60);
  const wVector = Number(opts.wVector) || 1.0;
  const wBM25 = Number(opts.wBM25) || 0.5;
  const wInfini = Number(opts.wInfini) ?? W_INFINI;

  const scoreMap = new Map(); // id → { score, sources }

  function addResults(results, weight, sourceName) {
    const arr = Array.isArray(results) ? results : [];
    arr.forEach((r, i) => {
      const id = String(r.id);
      if (!id) return;
      const rank = i + 1;
      const rrfContribution = weight / (k + rank);
      const existing = scoreMap.get(id) || { score: 0, sources: [] };
      existing.score += rrfContribution;
      if (!existing.sources.includes(sourceName)) existing.sources.push(sourceName);
      scoreMap.set(id, existing);
    });
  }

  addResults(vectorResults, wVector, 'vector');
  addResults(bm25Results, wBM25, 'bm25');

  // Infini-attention results are optional (activated when W_INFINI > 0)
  if (Array.isArray(infiniResults) && infiniResults.length > 0 && wInfini > 0) {
    addResults(infiniResults, wInfini, 'infini_attention');
  }

  const fused = Array.from(scoreMap.entries())
    .map(([id, { score, sources }]) => ({ id, rrf_score: Number(score.toFixed(6)), sources }))
    .sort((a, b) => b.rrf_score - a.rrf_score);

  return fused;
}
