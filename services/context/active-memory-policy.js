/**
 * active-memory-policy.js — AgeMem-style memory operation policy
 * Source: Agentic Memory: Learning Unified Long-Term and Short-Term Memory
 * Management for Large Language Model Agents (AgeMem; Yu et al.,
 * arXiv:2601.01885, 2026)
 * Additive Batch8 authority: MemGuide; Lightweight LLM Agent Memory;
 * Joint Optimization of Reasoning and Dual-Memory; Catastrophic Forgetting
 * Mitigation; Learning from Many and Adapting to the Unknown. Aimos exposes
 * intent/lane selection diagnostics only; no physical delete, unlearning, or
 * learned selector is enabled here.
 *
 * Batch 10 Lane 2: Block-size context division + ring buffer
 *   BLOCK_SIZE = 512 tokens
 *   blockRead(q, block_summaries) = softmax(q · summaries) · blocks
 *   CompressedMemoryRingBuffer with MAX=8 slots
 *   MOBILE_MEMORY_BUDGET = 1024 tokens
 * Aladdin: Block division only affects context window assembly. Canonical memory
 *   is never split or deleted.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: routes/aimos.js save and policy surfaces
 * 2. ↔ Guides: persist-memory.js and scoped-state.js boundaries
 * 3. → Exposes: LTM/STM tool-operation recommendations without deleting Aimos
 *
 * LOGIC GUIDE:
 * AgeMem exposes memory operations as tools: ADD/UPDATE/DELETE for long-term
 * memory and RETRIEVE/SUMMARY/FILTER for short-term memory. Aimos maps those
 * operations into Aladdin-safe policy diagnostics. Physical deletion of Aimos
 * memories is never recommended here.
 */

export const AGEMEM_TOOLS = {
  LTM_ADD: 'ADD_LTM',
  LTM_UPDATE: 'UPDATE_LTM',
  LTM_DELETE: 'DELETE_LTM_GUARDED',
  STM_RETRIEVE: 'RETRIEVE_STM',
  STM_SUMMARY: 'SUMMARY_STM',
  STM_FILTER: 'FILTER_STM',
};

const BATCH8_MEMORY_SELECTION_AUTHORITIES = [
  'MemGuide: Intent-Driven Memory Selection for Goal-Oriented Multi-Session LLM Agent',
  'Lightweight LLM Agent Memory with Small Language Models',
  'Joint Optimization of Reasoning and Dual-Memory for Self-Learning Diagnostic Agent',
  'A Comparative Empirical Study of Catastrophic Forgetting Mitigation in Sequential Task Adaptation',
  'Learning from Many and Adapting to the Unknown in Open-set Test Streams',
];

const CANONICAL_LTM_TYPES = new Set([
  'identity',
  'core_belief',
  'crew_identity',
  'operational_rule',
  'strategic_directive',
  'session_debrief',
  'session_exchange',
  'session_manifest',
  'session_reasoning',
  'procedural',
  'tacit_knowledge',
  'dream_summary',
  'dream_artifact',
  'framework',
  'bibliographic_reference',
]);

const STM_TYPES = new Set([
  'event_log',
  'agent_session',
  'conversation_feed',
  'heartbeat',
  'reasoning_state',
]);

function valueLength(value) {
  if (value == null) return 0;
  return typeof value === 'string' ? value.length : JSON.stringify(value).length;
}

function normalizeType(value) {
  return String(value || '').trim().toLowerCase();
}

function classifySelectionIntent({ requested, type, normalizedScope, updateIntent, pressure, length }) {
  if (requested.includes('delete')) return 'guarded_destructive_intent';
  if (updateIntent) return 'verification_or_correction';
  if (STM_TYPES.has(type) || normalizedScope === 'run') {
    if (pressure >= 0.75 || length > 4000) return 'short_term_context_compression';
    if (length < 80) return 'low_substance_short_term_filter';
    return 'active_short_term_retrieval';
  }
  if (CANONICAL_LTM_TYPES.has(type)) return 'canonical_long_term_retention';
  if (length > 1200) return 'substantial_long_term_retention';
  return 'general_memory_candidate';
}

function buildSelectionDiagnostics({
  requested,
  type,
  normalizedScope,
  updateIntent,
  pressure,
  length,
  recommendedTool,
  lane,
  reason,
}) {
  const intentClass = classifySelectionIntent({
    requested,
    type,
    normalizedScope,
    updateIntent,
    pressure,
    length,
  });
  const laneCandidates = [
    {
      lane: 'long_term_memory',
      applicable: CANONICAL_LTM_TYPES.has(type) || length > 1200 || updateIntent || requested.includes('delete'),
      rationale: 'persistent evidence, correction, verification, or audit-preserved guarded request',
    },
    {
      lane: 'short_term_memory',
      applicable: STM_TYPES.has(type) || normalizedScope === 'run',
      rationale: 'active event/session material suitable for bounded context or summary',
    },
    {
      lane: 'procedural_memory',
      applicable: ['procedural', 'tacit_knowledge', 'session_reasoning'].includes(type),
      rationale: 'reusable method or reasoning continuity',
    },
  ];

  return {
    source_papers: BATCH8_MEMORY_SELECTION_AUTHORITIES,
    intent_class: intentClass,
    lane_candidates: laneCandidates,
    selected_lane: lane,
    selected_tool: recommendedTool,
    selection_reason: reason,
    context_pressure: pressure,
    value_chars: length,
    diagnostic_only: true,
    ranking_math_changed: false,
    recall_weight_changed: false,
    deletion_enabled: false,
    guarded_math: {
      memguide_learned_selector: false,
      lightweight_compressor_training: false,
      dual_memory_joint_optimization: false,
      anti_forgetting_regularizer: false,
      open_set_stream_adaptation: false,
    },
  };
}

export function decideActiveMemoryPolicy({
  operation = 'save',
  key = '',
  value = '',
  memoryType = '',
  scope = '',
  isCorrection = false,
  supersedesId = null,
  verifyTargetId = null,
  verifyTargetKey = null,
  contextPressure = 0,
} = {}) {
  const type = normalizeType(memoryType);
  const normalizedScope = normalizeType(scope);
  const requested = normalizeType(operation) || 'save';
  const length = valueLength(value);
  const pressure = Math.max(0, Math.min(1, Number(contextPressure || 0)));
  const updateIntent = Boolean(isCorrection || supersedesId || verifyTargetId || verifyTargetKey);

  let recommendedTool = AGEMEM_TOOLS.LTM_ADD;
  let lane = 'long_term_memory';
  let reason = 'canonical_aimos_save';

  if (requested.includes('delete')) {
    recommendedTool = AGEMEM_TOOLS.LTM_DELETE;
    lane = type && STM_TYPES.has(type) ? 'short_term_memory' : 'long_term_memory';
    reason = 'delete_request_guarded_by_aladdin';
  } else if (updateIntent) {
    recommendedTool = AGEMEM_TOOLS.LTM_UPDATE;
    lane = 'long_term_memory';
    reason = 'correction_or_verification_updates_existing_truth';
  } else if (STM_TYPES.has(type) || normalizedScope === 'run') {
    lane = 'short_term_memory';
    if (pressure >= 0.75 || length > 4000) {
      recommendedTool = AGEMEM_TOOLS.STM_SUMMARY;
      reason = 'stm_context_pressure_prefers_summary';
    } else if (length < 80) {
      recommendedTool = AGEMEM_TOOLS.STM_FILTER;
      reason = 'low_substance_stm_candidate';
    } else {
      recommendedTool = AGEMEM_TOOLS.STM_RETRIEVE;
      reason = 'stm_candidate_available_for_active_context';
    }
  } else if (CANONICAL_LTM_TYPES.has(type) || String(key || '').startsWith('paper:')) {
    recommendedTool = AGEMEM_TOOLS.LTM_ADD;
    lane = 'long_term_memory';
    reason = 'high_value_ltm_candidate';
  } else if (length > 1200) {
    recommendedTool = AGEMEM_TOOLS.LTM_ADD;
    lane = 'long_term_memory';
    reason = 'substantial_content_candidate';
  }

  return {
    source_paper: 'AgeMem',
    source_papers: ['AgeMem', ...BATCH8_MEMORY_SELECTION_AUTHORITIES],
    requested_operation: requested,
    recommended_tool: recommendedTool,
    memory_lane: lane,
    reason,
    selection_diagnostics: buildSelectionDiagnostics({
      requested,
      type,
      normalizedScope,
      updateIntent,
      pressure,
      length,
      recommendedTool,
      lane,
      reason,
    }),
    signals: {
      memory_type: type || null,
      scope: normalizedScope || null,
      value_chars: length,
      context_pressure: pressure,
      update_intent: updateIntent,
    },
    aladdin_boundary: {
      physical_delete_allowed: false,
      destructive_forgetting_allowed: false,
      delete_semantics: 'Never delete, deactivate, expire, or age-suppress an Aimos memory; use append-only supersession or correction.',
    },
    guarded_math: {
      grpo_training: false,
      reward_function_formula_1_7: false,
      policy_update: false,
    },
  };
}

// ─── BATCH 10 LANE 2: BLOCK DIVISION + RING BUFFER ──────────────────────────
// Papers: M+, ChunkKV
// BLOCK_SIZE = 512 tokens
// blockRead(q, block_summaries) = softmax(q · summaries) · blocks
// CompressedMemoryRingBuffer(MAX=8)
// MOBILE_MEMORY_BUDGET = 1024 tokens
// Aladdin: Block division only affects context window assembly.
//   Canonical memory is never split or deleted.
// ─────────────────────────────────────────────────────────────────────────────

const BLOCK_SIZE = 512;           // tokens per context block
const MOBILE_MEMORY_BUDGET = 1024; // max tokens in mobile context window
const MAX_COMPRESSED_SEGMENTS = 8; // ring buffer size

/**
 * Divide context tokens into blocks of BLOCK_SIZE (512 tokens).
 *
 * @param {string[]} contextTokens - Array of tokens
 * @param {number} blockSize - Block size (default 512)
 * @returns {{ blocks: Array, block_count: number, block_size: number, total_tokens: number }}
 */
export function computeBlockDivision(contextTokens, blockSize = BLOCK_SIZE) {
  const tokens = Array.isArray(contextTokens) ? contextTokens : [];
  const bs = Math.max(1, Number(blockSize) || BLOCK_SIZE);

  const blocks = [];
  for (let i = 0; i < tokens.length; i += bs) {
    blocks.push({
      index: blocks.length,
      tokens: tokens.slice(i, i + bs),
      token_count: Math.min(bs, tokens.length - i),
    });
  }

  return {
    blocks,
    block_count: blocks.length,
    block_size: bs,
    total_tokens: tokens.length,
    within_budget: tokens.length <= MOBILE_MEMORY_BUDGET,
  };
}

/**
 * Block read: softmax(query · block_summaries) · blocks
 * Selects and blends blocks based on query relevance.
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {Array<{summary: number[], tokens: string[]}>} blockSummaries - Block summary embeddings + content
 * @returns {{ blended_context: string, attention_weights: Array, source_papers: string[] }}
 */
export function computeBlockRead(queryEmbedding, blockSummaries = []) {
  if (!Array.isArray(queryEmbedding) || queryEmbedding.length === 0 || !Array.isArray(blockSummaries) || blockSummaries.length === 0) {
    return { blended_context: '', attention_weights: [], source_papers: ['M+'] };
  }

  // Compute dot products
  const dotProducts = blockSummaries.map((block, i) => {
    const summary = Array.isArray(block.summary) ? block.summary : [];
    const dim = Math.min(queryEmbedding.length, summary.length);
    let dot = 0;
    for (let j = 0; j < dim; j++) dot += (queryEmbedding[j] || 0) * (summary[j] || 0);
    return { index: i, dot };
  });

  // Softmax with numerical stability
  const maxDot = Math.max(...dotProducts.map(d => d.dot));
  const expDots = dotProducts.map(d => ({ index: d.index, weight: Math.exp(d.dot - maxDot) }));
  const sumExp = expDots.reduce((s, e) => s + e.weight, 0) || 1;
  const attentionWeights = expDots.map(e => ({
    index: e.index,
    attention: Number((e.weight / sumExp).toFixed(6)),
  }));

  // Blend blocks by attention
  const blendedContext = blockSummaries
    .map((block, i) => {
      const weight = attentionWeights.find(w => w.index === i)?.attention || 0;
      return weight > 0.01 ? (Array.isArray(block.tokens) ? block.tokens.join(' ') : '') : '';
    })
    .filter(Boolean)
    .join(' ');

  return {
    blended_context: blendedContext,
    attention_weights: attentionWeights,
    source_papers: ['M+'],
  };
}

/**
 * Compressed Memory Ring Buffer for context window compression.
 * MAX_COMPRESSED_SEGMENTS = 8 slots.
 * Oldest compressed segment is evicted when full.
 * Aladdin: compression only reduces context window footprint,
 *   canonical memory text is never modified or deleted.
 */
export class CompressedMemoryRingBuffer {
  constructor(maxSegments = MAX_COMPRESSED_SEGMENTS) {
    this._maxSegments = Math.max(1, Number(maxSegments) || MAX_COMPRESSED_SEGMENTS);
    this._buffer = [];
    this._writeIndex = 0;
  }

  /**
   * Push a compressed segment into the ring buffer.
   * @param {{ segment_kv: object, compression_ratio: number, freshness_state: string, memory_id: string }} segment
   */
  push(segment) {
    const entry = {
      ...segment,
      timestamp: Date.now(),
      index: this._writeIndex,
    };

    if (this._buffer.length < this._maxSegments) {
      this._buffer.push(entry);
    } else {
      this._buffer[this._writeIndex % this._maxSegments] = entry;
    }
    this._writeIndex++;

    return { pushed: true, buffer_size: this._buffer.length, index: entry.index };
  }

  /**
   * Get all compressed segments in order.
   */
  getAll() {
    return [...this._buffer];
  }

  /**
   * Get the current buffer size.
   */
  get size() {
    return this._buffer.length;
  }

  /**
   * Get the max segments.
   */
  get maxSegments() {
    return this._maxSegments;
  }
}
