// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT RENEWAL (context-renewal.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: CoALA (Sumers 2023), MemGPT (Packer 2023) — virtual context management
// Additive TEM authority: TiMem: Temporal-Hierarchical Memory Consolidation
// for Long-Horizon Conversational Agents
// Additive Batch 6/7 authority: Human-Like Lifelong Memory: A
// Neuroscience-Grounded Architecture for Infinite Interaction. This service
// exposes a lifelong-memory contract for episodic/semantic/procedural lanes
// and System 1/System 2 recall posture. It does not alter consolidation,
// retrieval_weight, STDP, or dream math.
//
// P1-6: Context Renewal (exec-style)
//
// When a long-running agent approaches its context window limit, it checkpoints
// its accumulated wisdom to Aimos and restarts with a compact summary.
// This prevents catastrophic context loss while preserving continuity.
//
// Inspired by human executive function: periodic summarisation ("what have
// I learned so far?") enables indefinitely long reasoning chains without
// degradation from context window overflow.
//
// Wisdom object structure:
//   { accumulated_findings, decisions_made, remaining_tasks, confidence }
//
// Safety: renewal count is capped at MAX_RENEWALS to prevent infinite loops.
//
// TiMem note: boot/renewal summaries can be organized by temporal hierarchy
// metadata, but renewal thresholds and checkpoint logic remain unchanged here.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 10)
// → Calls: routes/aimos.js (checkpoint save on renewal)
// Pipeline: AGENT_RUN_PIPELINE
// Position: renewal checkpoint
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import { logEvent } from '../observe/event-ledger.js';
import { encodeSemanticBins } from './mnemonic-encoder.js';

const COMPANY = AIMOS_COMPANY_ID;

// Default renewal threshold: renew when 85% of context window is consumed
const DEFAULT_RENEWAL_THRESHOLD = 0.85;

// Maximum renewals per run to prevent infinite loop scenarios
const MAX_RENEWALS = 5;

// Aimos key prefix for checkpoint storage
const CHECKPOINT_KEY_PREFIX = 'context_renewal';

const EPISODIC_TYPES = new Set([
  'event_log',
  'agent_session',
  'after_action_review',
  'session_debrief',
  'session_reasoning',
  'dream_artifact',
  'dream_summary',
]);

const SEMANTIC_TYPES = new Set([
  'declarative',
  'book_extract',
  'bibliographic_reference',
  'framework',
  'directive',
  'core_belief',
  'identity',
]);

const PROCEDURAL_TYPES = new Set([
  'procedural',
  'procedural_seed',
  'tacit_knowledge',
  'reasoning_state',
]);

/**
 * Classify a memory into the lifelong-memory lane used by boot/continuity
 * diagnostics. This is metadata only; it does not move or mutate the memory.
 *
 * @param {{ memory_type?: string, key?: string, scope?: string }} memory
 * @returns {object}
 */
export function classifyLifelongMemoryLane(memory = {}) {
  const memoryType = String(memory.memory_type || '').trim();
  const key = String(memory.key || '');
  let lane = 'semantic';

  if (EPISODIC_TYPES.has(memoryType) || /^session_|^event:|^run:/.test(key)) {
    lane = 'episodic';
  } else if (PROCEDURAL_TYPES.has(memoryType) || key.startsWith('ai_adr:')) {
    lane = 'procedural';
  } else if (SEMANTIC_TYPES.has(memoryType)) {
    lane = 'semantic';
  }

  const system = lane === 'episodic' || memoryType === 'session_reasoning'
    ? 'system_2_deliberate'
    : 'system_1_associative';

  return {
    lane,
    recall_posture: system,
    memory_type: memoryType || 'unknown',
    key: key || null,
    aladdin_boundary: {
      canonical_memory_persistent: true,
      physical_delete_allowed: false,
      salience_mutable: true,
    },
    maturation_policy: {
      canonical_content_changes: false,
      retrieval_salience_may_change: true,
      dream_consolidation_math_changed: false,
      stdp_math_changed: false,
    },
  };
}

/**
 * Build a live lifelong-memory contract/checklist for a memory sample.
 *
 * @param {Array<object>} memories
 * @returns {object}
 */
export function buildLifelongMemoryContract(memories = []) {
  const rows = Array.isArray(memories) ? memories : [];
  const classifications = rows.map(classifyLifelongMemoryLane);
  const laneCounts = classifications.reduce((acc, item) => {
    acc[item.lane] = (acc[item.lane] || 0) + 1;
    return acc;
  }, { episodic: 0, semantic: 0, procedural: 0 });

  return {
    source_paper: 'Human-Like Lifelong Memory: A Neuroscience-Grounded Architecture for Infinite Interaction',
    status: 'live_contract',
    sample_count: rows.length,
    lane_counts: laneCounts,
    classifications,
    functional_properties: {
      valence_visible: 'metadata_contract_only',
      system_1_default: true,
      system_2_escalation: true,
      active_encoding_gateway: 'quality_gate_and_context_renewal',
      episodic_semantic_separation: true,
      consolidation_supported: 'dream_stack_guarded_math',
      reconsolidation_supported: 'salience_only_no_delete',
    },
    aladdin_boundary: {
      no_physical_delete: true,
      salience_mutable: true,
      canonical_memory_permanent: true,
    },
    guarded_math: {
      valence_vector_scoring: false,
      dream_consolidation_weight_update: false,
      stdp_update_rule_change: false,
    },
    ranking_math_changed: false,
  };
}

/**
 * Determine whether context renewal is needed.
 *
 * @param {number} tokenCount - Current token count in the context window
 * @param {number} maxTokens - Maximum token capacity of the context window
 * @param {number} [renewalThreshold=0.85] - Fraction at which renewal triggers
 * @returns {boolean}
 */
export function shouldRenew(tokenCount, maxTokens, renewalThreshold = DEFAULT_RENEWAL_THRESHOLD) {
  if (!Number.isFinite(tokenCount) || !Number.isFinite(maxTokens) || maxTokens <= 0) {
    return false;
  }
  const threshold = Number.isFinite(renewalThreshold) ? renewalThreshold : DEFAULT_RENEWAL_THRESHOLD;
  return (tokenCount / maxTokens) >= threshold;
}

/**
 * Increment the renewal counter for a run.
 * Returns the updated count; caps at MAX_RENEWALS.
 * Prevents infinite renewal loops.
 *
 * @param {string} runId - Unique run identifier
 * @param {string} [companyId]
 * @returns {Promise<number>} Updated renewal count (1-indexed)
 */
export async function incrementRenewalCount(runId, companyId) {
  const cid = companyId || COMPANY;
  const counterKey = `${CHECKPOINT_KEY_PREFIX}:${runId}:renewal_count`;

  let current = 0;
  try {
    const result = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2
       ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
       LIMIT 1`,
      [cid, counterKey]
    );
    if (result.rows.length) {
      const parsed = parseInt(result.rows[0].value, 10);
      current = Number.isFinite(parsed) ? parsed : 0;
    }
  } catch (err) {
    console.error('[context-renewal] incrementRenewalCount read error:', err.message);
  }

  if (current >= MAX_RENEWALS) {
    console.warn(`[context-renewal] MAX_RENEWALS (${MAX_RENEWALS}) reached for run ${runId}`);
    return current;
  }

  const updated = current + 1;

  try {
    await persistMemory({
      company_id: cid,
      agent_id: 'context-renewal',
      mutation_authority: 'housekeeper',
      key: counterKey,
      value: String(updated),
      scope: 'run',
      memory_type: 'episodic',
    });
  } catch (err) {
    console.error('[context-renewal] incrementRenewalCount write error:', err.message);
  }

  return updated;
}

/**
 * Checkpoint the current run's accumulated wisdom to Aimos.
 * Stored as a structured JSON memory under key:
 *   context_renewal:{runId}:checkpoint
 *
 * @param {string} runId - Unique run identifier
 * @param {string} progressSummary - Free-text summary of progress so far
 * @param {Object} wisdom - Structured wisdom object
 * @param {string|string[]} wisdom.accumulated_findings - Key findings so far
 * @param {string|string[]} wisdom.decisions_made - Decisions already committed
 * @param {string|string[]} wisdom.remaining_tasks - Tasks still to complete
 * @param {Array<object>} [wisdom.memories] - Raw working memories for quantization
 * @param {number} [wisdom.confidence] - Overall confidence score (0-1)
 * @param {string} [companyId]
 * @returns {Promise<void>}
 */
export async function checkpointProgress(runId, progressSummary, wisdom, companyId) {
  const cid = companyId || COMPANY;
  const checkpointKey = `${CHECKPOINT_KEY_PREFIX}:${runId}:checkpoint`;

  const reasoningQuanta = wisdom?.memories ? encodeSemanticBins(wisdom.memories) : '';

  const wisdomObj = {
    accumulated_findings: wisdom?.accumulated_findings || [],
    decisions_made: wisdom?.decisions_made || [],
    remaining_tasks: wisdom?.remaining_tasks || [],
    reasoning_quanta: reasoningQuanta,
    confidence: typeof wisdom?.confidence === 'number' ? wisdom.confidence : null,
    progress_summary: String(progressSummary || ''),
    checkpointed_at: new Date().toISOString(),
    run_id: runId,
  };

  try {
    await persistMemory({
      company_id: cid,
      agent_id: 'context-renewal',
      mutation_authority: 'housekeeper',
      key: checkpointKey,
      value: JSON.stringify(wisdomObj),
      scope: 'run',
      memory_type: 'episodic',
    });

    await logEvent(cid, 'context-renewal', 'checkpoint_saved', checkpointKey, {
      reasoning: `Context renewal checkpoint for run '${runId}'. Progress: ${String(progressSummary || '').slice(0, 200)}`,
      runId,
      confidence: wisdomObj.confidence,
    });
  } catch (err) {
    console.error('[context-renewal] checkpointProgress write error:', err.message);
    throw err;
  }
}

/**
 * Load the most recent checkpoint for a run.
 *
 * @param {string} runId - Unique run identifier
 * @param {string} [companyId]
 * @returns {Promise<Object|null>} Wisdom object from last checkpoint, or null if none
 */
export async function loadCheckpoint(runId, companyId) {
  const cid = companyId || COMPANY;
  const checkpointKey = `${CHECKPOINT_KEY_PREFIX}:${runId}:checkpoint`;

  try {
    const result = await query(
      `SELECT value, updated_at FROM aimos_memories
       WHERE company_id = $1 AND key = $2
       ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
       LIMIT 1`,
      [cid, checkpointKey]
    );

    if (!result.rows.length) {
      return null;
    }

    const raw = result.rows[0].value;
    try {
      return typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return { raw_value: raw, loaded_at: result.rows[0].updated_at };
    }
  } catch (err) {
    console.error('[context-renewal] loadCheckpoint DB error:', err.message);
    return null;
  }
}
