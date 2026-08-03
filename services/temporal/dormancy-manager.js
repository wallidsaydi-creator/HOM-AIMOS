// ═══════════════════════════════════════════════════════════════════════════════
// SALIENCE FREQUENCY MANAGER (dormancy-manager.js compatibility file)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Medallion Architecture (bronze→silver→gold), Aladdin Retention Model
//
// P1-3: Strategic Salience Frequency
//
// Low-frequency salience is a retrieval frequency signal, not deletion, decay,
// suppression, pruning, expiry, hidden state, or canonical memory mutation.
// Low-frequency memories persist in DB forever and must remain reachable by
// specific cues.
//
// Trust Score formula:
//   T = 0.4 * access_freq + 0.2 * cross_refs + 0.2 * recency + 0.2 * credit_score
//
// Low-frequency salience is triggered when trust score drops below threshold,
// OR when a memory has been explicitly superseded.
//
// Reactivation readiness: if a low-frequency memory receives 3+ partial
// activations, the ledger records that it should surface normally. This does
// not rewrite canonical memory rows.
//
// Batch 10 Lane 5: Bourbon learned index + trust-adjusted salience frequency (From WiscKey to Bourbon)
//   BourbonLearnedIndex: piecewise linear CDF model for cold-memory position lookup
//   trustAdjustedSalienceFrequency(trustScore, baseThreshold=0.25): higher trust → higher threshold
//   Aladdin: trust adjustment only changes retrieval activation threshold.
//     Low-frequency memories remain fully present and addressable. No memory is
//     ever deleted, suppressed, pruned, expired, or decay-mutated.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (RECALL pipeline, step 13)
// → Calls: services/learning/trust-score.js (salience frequency threshold check)
// Pipeline: RECALL_PIPELINE
// Position: salience frequency evaluation
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import { getDormancyThreshold, getReactivationCount, getMaxAccessNormalization, getMaxCrossRefNormalization } from '../shared/scale-baseline.js';

const COMPANY = AIMOS_COMPANY_ID;

// Trust score threshold below which low-frequency salience is triggered
// Scale-adaptive: use getDormancyThreshold(memoryCount) for dynamic scaling.
// At N=14000: 0.25 (unchanged).
export const SALIENCE_FREQUENCY_THRESHOLD = 0.25;

// Number of partial activations required for auto-reactivation
// Scale-adaptive: use getReactivationCount(memoryCount) for dynamic scaling.
// At N=14000: 3 (unchanged).
export const LOW_FREQUENCY_REACTIVATION_COUNT = 3;

export const SALIENCE_FREQUENCY_ALADDIN_CONTRACT = Object.freeze({
  canonical_delete_allowed: false,
  soft_delete_allowed: false,
  expiry_allowed: false,
  decay_mutation_allowed: false,
  suppression_allowed: false,
  pruning_allowed: false,
  hard_filter_allowed: false,
  canonical_value_mutation_allowed: false,
  canonical_metric_mutation_allowed: false,
  permanent_value_lowering_allowed: false,
  low_frequency_only: true,
  always_reachable_by_specific_cue: true,
  telemetry_surface: 'aimos_events',
  metric_sources: Object.freeze({
    access_frequency: 'aimos_events(operation=recall)',
    access_recency: 'aimos_events(operation=recall).max(ts)',
    cross_refs: 'memory_cross_refs grouped count',
    permanent_value_prior: 'aimos_memories.credit_score read_only',
    cold_start_recency_fallback: 'aimos_memories.created_at read_only',
  }),
  canonical_memory_policy: 'read_only_for_identity_and_prior_no_body_history_or_value_rewrite',
});

// Compatibility exports. Keep old names importable, but do not use them on the
// native recall hot path.
export const DORMANCY_THRESHOLD = SALIENCE_FREQUENCY_THRESHOLD;
export const REACTIVATION_ACTIVATION_COUNT = LOW_FREQUENCY_REACTIVATION_COUNT;
export const DORMANCY_ALADDIN_CONTRACT = SALIENCE_FREQUENCY_ALADDIN_CONTRACT;

export function buildLowFrequencyProfile(reason, reactivationTriggers = []) {
  return {
    state: 'low_frequency',
    marked_at: new Date().toISOString(),
    reason: String(reason || 'unspecified'),
    reactivation_triggers: Array.isArray(reactivationTriggers) ? reactivationTriggers : [],
    partial_activation_count: 0,
    aladdin_contract: SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
  };
}

/**
 * Compute the Trust Score for a memory.
 *
 * T = 0.4 * access_freq + 0.2 * cross_refs + 0.2 * recency + 0.2 * credit_score
 *
 * All inputs are expected to be normalised to [0, 1].
 *
 * @param {Object} params
 * @param {number} params.access_freq     - Normalised access frequency (0-1)
 * @param {number} params.cross_refs      - Normalised cross-reference count (0-1)
 * @param {number} params.recency         - Normalised recency score (0-1; 1 = very recent)
 * @param {number} params.credit_score    - Memory credit score (0-1)
 * @returns {number} Trust score in [0, 1]
 */
export function computeTrustScore({ access_freq = 0, cross_refs = 0, recency = 0, credit_score = 0 } = {}) {
  const f = Math.max(0, Math.min(1, Number(access_freq) || 0));
  const c = Math.max(0, Math.min(1, Number(cross_refs) || 0));
  const r = Math.max(0, Math.min(1, Number(recency) || 0));
  const s = Math.max(0, Math.min(1, Number(credit_score) || 0));
  return (0.4 * f) + (0.2 * c) + (0.2 * r) + (0.2 * s);
}

/**
 * Evaluate whether a memory has low-frequency salience.
 *
 * Fetches derived telemetry and computes trust score.
 * Returns salience-frequency recommendation with detailed reason.
 * Scale-adaptive: salience frequency threshold and normalization ceilings grow with memory count.
 *
 * @param {string} memoryId - UUID of the memory to evaluate
 * @param {string} [companyId]
 * @param {Object} [options] - { memoryCount } for scale-adaptive thresholds
 * @returns {Promise<{isLowFrequency: boolean, reason: string, trustScore: number}>}
 */
export async function evaluateSalienceFrequency(memoryId, companyId, options = {}) {
  const batch = await evaluateSalienceFrequencyBatch([memoryId], companyId, options);
  return batch.get(memoryId) || { isLowFrequency: false, reason: 'memory_not_found', trustScore: 0 };
}

/**
 * Batch-evaluate salience frequency for multiple memories in a single DB round-trip.
 *
 * Returns a Map<string, {isLowFrequency, reason, trustScore}> keyed by memory ID.
 * Scale-adaptive: salience frequency threshold and ceilings grow with memory count.
 *
 * @param {string[]} memoryIds - Array of memory UUIDs
 * @param {string} [companyId]
 * @param {Object} [options] - { memoryCount } for scale-adaptive thresholds
 * @returns {Promise<Map<string, {isLowFrequency: boolean, reason: string, trustScore: number}>>}
 */
export async function evaluateSalienceFrequencyBatch(memoryIds, companyId, options = {}) {
  const cid = companyId || COMPANY;
  const mc = options.memoryCount || undefined;
  const threshold = mc ? getDormancyThreshold(mc) : SALIENCE_FREQUENCY_THRESHOLD;
  const maxAccess = mc ? getMaxAccessNormalization(mc) : 100;
  const maxCrossRefs = mc ? getMaxCrossRefNormalization(mc) : 10;
  const results = new Map();

  if (!memoryIds || memoryIds.length === 0) return results;
  const uniqueMemoryIds = [...new Set(memoryIds.filter(Boolean))];
  if (uniqueMemoryIds.length === 0) return results;

  try {
    const dbResult = await query(
      `WITH candidate_ids AS (
         SELECT DISTINCT unnest($1::uuid[]) AS id
       ),
       candidate_memories AS (
         SELECT m.id, m.key, m.credit_score, m.supersedes_id, m.created_at
         FROM aimos_memories m
         JOIN candidate_ids ci ON ci.id = m.id
         WHERE m.company_id = $2
       ),
       recall_counts AS (
         SELECT cm.id AS memory_id, COUNT(e.key)::int AS cnt, MAX(e.ts) AS last_recall_at
         FROM candidate_memories cm
         LEFT JOIN aimos_events e
           ON e.company_id = $2
          AND e.key = cm.key
          AND e.operation = 'recall'
         GROUP BY cm.id
       ),
       cross_ref_edges AS (
         SELECT cr.source_memory_id AS memory_id
         FROM memory_cross_refs cr
         JOIN candidate_ids ci ON ci.id = cr.source_memory_id
         WHERE cr.company_id = $2
         UNION ALL
         SELECT cr.target_memory_id AS memory_id
         FROM memory_cross_refs cr
         JOIN candidate_ids ci ON ci.id = cr.target_memory_id
         WHERE cr.company_id = $2
       ),
       cross_ref_counts AS (
         SELECT memory_id, COUNT(*)::int AS cnt
         FROM cross_ref_edges
         GROUP BY memory_id
       )
       SELECT cm.id, cm.key, cm.credit_score, cm.supersedes_id, cm.created_at,
              COALESCE(rc.cnt, 0) AS recall_count,
              rc.last_recall_at,
              COALESCE(xr.cnt, 0) AS cross_ref_count
       FROM candidate_memories cm
       LEFT JOIN recall_counts rc ON rc.memory_id = cm.id
       LEFT JOIN cross_ref_counts xr ON xr.memory_id = cm.id`,
      [uniqueMemoryIds, cid]
    );

    for (const row of dbResult.rows) {
      // Scale-adaptive normalization ceilings
      const recallCount = parseInt(row.recall_count, 10) || 0;
      const access_freq = Math.min(1.0, recallCount / maxAccess);

      const crossRefCount = parseInt(row.cross_ref_count, 10) || 0;
      const cross_refs = Math.min(1.0, crossRefCount / maxCrossRefs);

      // Recency comes from access telemetry. Creation time is a cold-start fallback.
      const recencyAnchor = row.last_recall_at ? new Date(row.last_recall_at) : new Date(row.created_at);
      const ageDays = (Date.now() - recencyAnchor.getTime()) / 86400000;
      const recency = Math.max(0, 1.0 - ageDays / 180);
      const recency_source = row.last_recall_at
        ? 'aimos_events(operation=recall).max(ts)'
        : 'aimos_memories.created_at read_only_cold_start_fallback';

      // Credit score is a read-only permanent-value prior. Salience frequency never writes it.
      const rawCredit = parseFloat(row.credit_score) || 0;
      const credit_score = rawCredit > 1 ? rawCredit / 100 : rawCredit;

      const trustScore = computeTrustScore({ access_freq, cross_refs, recency, credit_score });

      // Determine low-frequency salience (scale-adaptive threshold)
      let isLowFrequency = false;
      let reason = 'trust_score_sufficient';

      if (trustScore < threshold) {
        isLowFrequency = true;
        reason = `trust_score_below_threshold (${trustScore.toFixed(3)} < ${threshold.toFixed(4)})`;
      } else if (row.supersedes_id) {
        isLowFrequency = true;
        reason = `superseded_by_${row.supersedes_id}`;
      }

      results.set(row.id, {
        isLowFrequency,
        reason,
        trustScore,
        components: {
          access_freq,
          cross_refs,
          recency,
          credit_score,
        },
        metricSources: {
          ...SALIENCE_FREQUENCY_ALADDIN_CONTRACT.metric_sources,
          active_recency_source: recency_source,
        },
        canonical_memory_mutated: false,
        permanent_value_lowered: false,
      });
    }

    // Any requested IDs not found in DB get a safe default
    for (const id of uniqueMemoryIds) {
      if (!results.has(id)) {
        results.set(id, { isLowFrequency: false, reason: 'memory_not_found', trustScore: 0 });
      }
    }
  } catch (err) {
    console.error('[salience-frequency] evaluateSalienceFrequencyBatch DB error:', err.message);
    // On error, return safe defaults for all requested IDs
    for (const id of uniqueMemoryIds) {
      if (!results.has(id)) {
        results.set(id, { isLowFrequency: false, reason: `db_error: ${err.message}`, trustScore: 0 });
      }
    }
  }

  return results;
}

export function applySalienceFrequencyAnnotations(memories = [], salienceFrequencyResults = new Map()) {
  let lowFrequencyCount = 0;
  if (!Array.isArray(memories)) {
    return {
      memories,
      annotated_count: 0,
      low_frequency_count: 0,
      hard_filter_applied: false,
      canonical_memory_mutated: false,
      permanent_value_lowered: false,
    };
  }

  for (const mem of memories) {
    if (mem?.id) {
      const salienceFrequency = salienceFrequencyResults.get(mem.id);
      const salienceScore = Number(salienceFrequency?.trustScore || 0);
      const lowFrequency = Boolean(salienceFrequency?.isLowFrequency);
      mem.low_frequency_salience = lowFrequency;
      mem.salience_reason = salienceFrequency?.reason || 'trust_score_sufficient';
      mem.salience_score = Number(salienceScore.toFixed(6));
      mem._trust_score_salience_frequency = mem.salience_score;
      if (lowFrequency) lowFrequencyCount += 1;
    } else if (mem) {
      mem.low_frequency_salience = false;
      mem.salience_reason = 'no_memory_id';
      mem.salience_score = 0;
    }
  }

  return {
    memories,
    annotated_count: memories.filter(m => m?.id).length,
    low_frequency_count: lowFrequencyCount,
    hard_filter_applied: false,
    canonical_memory_mutated: false,
    permanent_value_lowered: false,
  };
}

export async function evaluateDormancy(memoryId, companyId, options = {}) {
  const result = await evaluateSalienceFrequency(memoryId, companyId, options);
  return { ...result, shouldDormant: result.isLowFrequency === true };
}

export async function evaluateDormancyBatch(memoryIds, companyId, options = {}) {
  const result = await evaluateSalienceFrequencyBatch(memoryIds, companyId, options);
  for (const [id, value] of result.entries()) {
    result.set(id, { ...value, shouldDormant: value.isLowFrequency === true });
  }
  return result;
}

/**
 * Mark a memory as low-frequency through additive telemetry only.
 *
 * Aladdin boundary: this does not update aimos_memories, decay_weight,
 * is_active, expires_at, or canonical memory value. The mark is a ledger
 * signal that later ranking can consume without making the memory disappear.
 *
 * @param {string} memoryId
 * @param {string} reason - Human-readable low-frequency reason
 * @param {string[]} [reactivationTriggers=[]] - Keywords/concepts that should restore normal salience
 * @param {string} [companyId]
 * @returns {Promise<object>}
 */
export async function markLowFrequency(memoryId, reason, reactivationTriggers = [], companyId) {
  const cid = companyId || COMPANY;
  const lowFrequencyProfile = buildLowFrequencyProfile(reason, reactivationTriggers);

  try {
    const eventId = await logEvent(cid, 'salience-frequency', 'memory_low_frequency_marked', memoryId, {
      reasoning: `Memory marked low-frequency without canonical mutation: ${reason || 'unspecified'}`,
      memoryId,
      reason,
      reactivationTriggers,
      low_frequency_profile: lowFrequencyProfile,
      aladdin_contract: SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
    });
    return {
      marked: true,
      eventId,
      memoryId,
      profile: lowFrequencyProfile,
      canonical_memory_mutated: false,
      decay_mutated: false,
    };
  } catch (err) {
    console.error('[salience-frequency] markLowFrequency DB error:', err.message);
    throw err;
  }
}

export async function setDormant(memoryId, reason, reactivationTriggers = [], companyId) {
  return markLowFrequency(memoryId, reason, reactivationTriggers, companyId);
}

/**
 * Record a partial activation and report whether normal salience is ready.
 *
 * @param {string} memoryId
 * @param {string} [companyId]
 * @returns {Promise<{reactivated: boolean, partialCount: number}>}
 */
export async function checkLowFrequencyReactivation(memoryId, companyId) {
  const cid = companyId || COMPANY;

  try {
    const activationEventId = await logEvent(
      cid,
      'salience-frequency',
      'memory_low_frequency_partial_activation',
      memoryId,
      {
        reasoning: 'Low-frequency memory received a partial activation; canonical memory row remains unchanged.',
        memoryId,
        aladdin_contract: SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
      }
    );

    const result = await query(
      `SELECT COUNT(*)::int AS partial_count
       FROM aimos_events
       WHERE company_id = $1
         AND key = $2
         AND operation = 'memory_low_frequency_partial_activation'`,
      [cid, memoryId]
    );
    const currentCount = Number(result.rows?.[0]?.partial_count || 0);
    const reactivated = currentCount >= LOW_FREQUENCY_REACTIVATION_COUNT;

    let reactivationEventId = null;
    if (reactivated) {
      reactivationEventId = await logEvent(cid, 'salience-frequency', 'memory_low_frequency_reactivation_ready', memoryId, {
        reasoning: `Low-frequency memory reached ${currentCount} partial activations; ranking may treat it as normal salience without row mutation.`,
        memoryId,
        partialCount: currentCount,
        threshold: LOW_FREQUENCY_REACTIVATION_COUNT,
        aladdin_contract: SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
      });
    }

    return {
      reactivated,
      partialCount: currentCount,
      activationEventId,
      reactivationEventId,
      canonical_memory_mutated: false,
      decay_mutated: false,
    };
  } catch (err) {
    console.error('[salience-frequency] checkLowFrequencyReactivation ledger error:', err.message);
    return {
      reactivated: false,
      partialCount: 0,
      reason: `ledger_error: ${err.message}`,
      canonical_memory_mutated: false,
      decay_mutated: false,
    };
  }
}

export async function checkReactivation(memoryId, companyId) {
  return checkLowFrequencyReactivation(memoryId, companyId);
}

// ─── BATCH 10 LANE 5: BOURBON LEARNED INDEX + TRUST-ADJUSTED SALIENCE FREQUENCY
// Papers: From WiscKey to Bourbon, Temporal Memory
// BourbonLearnedIndex: piecewise linear CDF model for cold-memory position lookup
//   learned_index(key) → position_in_sorted_array
//   CDF model: piecewise linear approximation of key distribution
//   cold_retrieval = learned_index_lookup + sequential_scan(δ)
// trustAdjustedSalienceFrequency(trustScore, baseThreshold=0.25): higher trust → higher threshold
//   salience_frequency_threshold(trust_score) = base_threshold * (1 + trust_score)
// Aladdin: trust adjustment only changes salience metadata.
//   Low-frequency memories remain fully present and addressable. No memory is
//   ever deleted, suppressed, pruned, expired, or decay-mutated.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Bourbon Learned Index: piecewise linear CDF model for cold-memory position lookup.
 * learned_index(key) → position_in_sorted_array
 * Cold retrieval falls back to sequential scan with δ window.
 */
export class BourbonLearnedIndex {
  constructor() {
    this._segments = [];  // { start, end, slope, intercept }
    this._sorted = false;
    this._size = 0;
  }

  /**
   * Build the learned index from sorted keys.
   * Creates piecewise linear segments approximating the CDF.
   *
   * @param {Array<{key: string|number, position: number}>} entries - Sorted key-position pairs
   */
  build(entries = []) {
    const data = Array.isArray(entries) ? entries : [];
    this._segments = [];
    this._size = data.length;
    this._sorted = true;

    if (data.length === 0) return;

    // Piecewise linear approximation: create segments
    // Each segment covers a range and has slope/intercept for position lookup
    const MAX_SEGMENTS = Math.max(1, Math.min(64, Math.ceil(data.length / 16)));

    for (let i = 0; i < data.length - 1; i += Math.max(1, Math.floor(data.length / MAX_SEGMENTS))) {
      const endIdx = Math.min(i + Math.max(1, Math.floor(data.length / MAX_SEGMENTS)), data.length - 1);
      const start = data[i];
      const end = data[endIdx];

      const startKey = typeof start.key === 'string' ? start.key.length : Number(start.key);
      const endKey = typeof end.key === 'string' ? end.key.length : Number(end.key);
      const keyRange = endKey - startKey;

      this._segments.push({
        start_key: startKey,
        end_key: endKey,
        start_position: start.position,
        end_position: end.position,
        slope: keyRange !== 0 ? (end.position - start.position) / keyRange : 0,
        intercept: keyRange !== 0 ? start.position - (start.position / keyRange) * startKey : start.position,
      });
    }

    // Ensure at least one segment
    if (this._segments.length === 0 && data.length > 0) {
      const first = data[0];
      const last = data[data.length - 1];
      const firstKey = typeof first.key === 'string' ? first.key.length : Number(first.key);
      const lastKey = typeof last.key === 'string' ? last.key.length : Number(last.key);
      const keyRange = lastKey - firstKey;

      this._segments.push({
        start_key: firstKey,
        end_key: lastKey,
        start_position: first.position,
        end_position: last.position,
        slope: keyRange !== 0 ? (last.position - first.position) / keyRange : 0,
        intercept: keyRange !== 0 ? first.position - (first.position / keyRange) * firstKey : first.position,
      });
    }
  }

  /**
   * Look up position for a key using the learned index.
   * learned_index(key) → position_in_sorted_array
   * Falls back to sequential scan with δ window for misses.
   *
   * @param {string|number} key - Key to look up
   * @param {number} delta - Search window size for local scan (default 16)
   * @returns {{ position: number, delta_scan_required: boolean, source_paper: string }}
   */
  lookup(key, delta = 16) {
    if (!this._sorted || this._segments.length === 0) {
      return {
        position: 0,
        delta_scan_required: true,
        source_paper: 'From WiscKey to Bourbon',
      };
    }

    const keyHash = typeof key === 'string' ? key.length : Number(key);

    // Find the segment that covers this key
    let segment = this._segments[0];
    for (let i = 0; i < this._segments.length; i++) {
      if (keyHash >= this._segments[i].start_key && keyHash <= this._segments[i].end_key) {
        segment = this._segments[i];
        break;
      }
      if (keyHash < this._segments[i].start_key) {
        segment = this._segments[Math.max(0, i - 1)];
        break;
      }
      if (i === this._segments.length - 1) {
        segment = this._segments[i];
      }
    }

    const predictedPosition = Math.max(0, Math.min(this._size - 1,
      Math.round(segment.slope * keyHash + segment.intercept)
    ));

    return {
      position: predictedPosition,
      delta: Number(delta),
      delta_scan_required: true, // Always requires local scan for accuracy
      source_paper: 'From WiscKey to Bourbon',
    };
  }

  /**
   * Get index statistics for diagnostics.
   */
  getStats() {
    return {
      size: this._size,
      segments: this._segments.length,
      sorted: this._sorted,
      source_paper: 'From WiscKey to Bourbon',
      diagnostic_only: true,
    };
  }
}

/**
 * Trust-score-adjusted salience frequency threshold.
 * salience_frequency_threshold(trust_score) = base_threshold * (1 + trust_score)
 * Higher trust → higher threshold → harder to mark low-frequency.
 * Scale-adaptive: base threshold adjusts with memory count.
 *
 * @param {number} trustScore - Trust score [0, 1]
 * @param {number} [baseThreshold] - Base salience frequency threshold (default: scale-adaptive)
 * @param {Object} [options] - { memoryCount } for scale-adaptive threshold
 * @returns {{ threshold: number, base_threshold: number, trust_score: number, source_paper: string, aladdin: string }}
 */
export function trustAdjustedSalienceFrequency(trustScore, baseThreshold, options = {}) {
  const ts = Math.max(0, Math.min(1, Number(trustScore) || 0));
  const bt = baseThreshold !== undefined
    ? Math.max(0.01, Number(baseThreshold))
    : (options.memoryCount ? getDormancyThreshold(options.memoryCount) : SALIENCE_FREQUENCY_THRESHOLD);

  // Higher trust -> higher threshold -> harder to mark low-frequency.
  // T = 0.0 -> threshold = base.
  // T = 1.0 -> threshold = 2 * base.
  const threshold = bt * (1 + ts);

  return {
    threshold: Number(threshold.toFixed(6)),
    base_threshold: bt,
    trust_score: ts,
    formula: 'salience_frequency_threshold(trust_score) = base_threshold * (1 + trust_score)',
    source_paper: 'Temporal Memory',
    aladdin: 'trust_adjustment_only_changes_salience_metadata_no_decay_suppression_pruning_deletion',
  };
}

export function trustAdjustedDormancy(trustScore, baseThreshold, options = {}) {
  return trustAdjustedSalienceFrequency(trustScore, baseThreshold, options);
}

// ─── BATCH 10.7 LANE 7, PHASE 3.3: COARSENING DYNAMICS ─────────────────────
// Paper: Coarsening Dynamics of Fingerprint Labyrinthine Patterns —
//        ML Assisted Characterization
// Alongside-path diagnostic: multi-resolution salience (FINE/COARSE/LOW_FREQUENCY)
// and junction resolution. Production low-frequency path unchanged.
// Phase 0: diagnostic only. Low-frequency salience remains binary in production.
// Proposed spectrum: FINE -> COARSE -> LOW_FREQUENCY.
//   FINE: full activation, full context window bandwidth
//   COARSE: reduced activation, compressed representation in context
//   LOW_FREQUENCY: lower broad-query salience, fully addressable by specific cue
// Aladdin: no decay, suppression, pruning, expiry, or deletion.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Salience resolution levels for multi-resolution salience diagnostics.
 * FINE = fully active, COARSE = compressed display, LOW_FREQUENCY = low frequency.
 */
export const SALIENCE_FREQUENCY_RESOLUTIONS = {
  FINE: 'fine',
  COARSE: 'coarse',
  LOW_FREQUENCY: 'low_frequency',
};
export const DORMANCY_RESOLUTIONS = Object.freeze({
  ...SALIENCE_FREQUENCY_RESOLUTIONS,
  DORMANT: SALIENCE_FREQUENCY_RESOLUTIONS.LOW_FREQUENCY,
});

/**
 * Compute junction resolution for coarsening dynamics.
 *
 * Memories coarsen through cross-reference junctions, not through global
 * diffusion. Isolated memories (terminal defects) persist until a
 * cross-reference junction reconnects them.
 *
 * Paper: Coarsening Dynamics of Fingerprint Labyrinthine Patterns
 * Guarded math flag: coarsening_dynamics (Phase 0: diagnostic only)
 *
 * @param {object} memory - Memory to evaluate
 * @param {Array<object>} neighbors - Neighboring memories with crossRefCount
 * @returns {{ junctionDensity: number, terminalRatio: number, coarseningMode: string, source_paper: string }}
 */
export function computeJunctionResolution(memory, neighbors = []) {
  const nbrs = Array.isArray(neighbors) ? neighbors : [];

  // Junction = neighbor with 2+ cross-references (well-connected hub)
  const junctions = nbrs.filter(n => (n.crossRefCount || 0) >= 2);
  // Terminal = neighbor with 0 cross-references (isolated endpoint)
  const terminals = nbrs.filter(n => (n.crossRefCount || 0) === 0);

  const junctionDensity = nbrs.length > 0 ? junctions.length / nbrs.length : 0;
  const terminalRatio = nbrs.length > 0 ? terminals.length / nbrs.length : 0;

  let coarseningMode;
  if (junctions.length > terminals.length) {
    coarseningMode = 'junction_dominated';
  } else if (terminals.length > junctions.length) {
    coarseningMode = 'terminal_dominant';
  } else {
    coarseningMode = 'balanced';
  }

  return {
    junctionDensity: Number(junctionDensity.toFixed(6)),
    terminalRatio: Number(terminalRatio.toFixed(6)),
    junctionCount: junctions.length,
    terminalCount: terminals.length,
    neighborCount: nbrs.length,
    coarseningMode,
    source_paper: 'Coarsening Dynamics of Fingerprint Labyrinthine Patterns',
  };
}

/**
 * Classify salience frequency resolution for a memory.
 *
 * Instead of binary active/hidden language, classify into FINE/COARSE/LOW_FREQUENCY:
 * - FINE: trust >= threshold, high recency, high cross-refs → full activation
 * - COARSE: trust >= threshold, but moderate recency/cross-refs → compressed
 * - LOW_FREQUENCY: trust < threshold → lower broad-query salience only
 *
 * @param {object} memory - Memory to classify
 * @param {object} [options] - { memoryCount } for scale-adaptive threshold
 * @returns {{ resolution: string, trustScore: number, threshold: number, junctionInfo: object|null, source_paper: string, aladdin: string }}
 */
export function classifySalienceFrequencyResolution(memory, options = {}) {
  if (!memory) {
    return { resolution: SALIENCE_FREQUENCY_RESOLUTIONS.FINE, trustScore: 0, threshold: SALIENCE_FREQUENCY_THRESHOLD };
  }

  const mc = options.memoryCount || undefined;
  const threshold = mc ? getDormancyThreshold(mc) : SALIENCE_FREQUENCY_THRESHOLD;
  const maxAccess = mc ? getMaxAccessNormalization(mc) : 100;
  const maxCrossRefs = mc ? getMaxCrossRefNormalization(mc) : 10;

  // Compute trust components
  const accessFreq = Math.min(1.0, (memory.access_freq || memory.access_count || 0) / maxAccess);
  const crossRefs = Math.min(1.0, ((memory.graph_links || []).length || memory.cross_ref_count || 0) / maxCrossRefs);
  const recency = memory.recency || 0.5;
  const credit = (memory.credit_score || 0) > 1 ? (memory.credit_score || 0) / 100 : (memory.credit_score || 0);

  const trustScore = computeTrustScore({
    access_freq: accessFreq,
    cross_refs: crossRefs,
    recency,
    credit_score: credit,
  });

  let resolution;
  if (trustScore < threshold) {
    resolution = SALIENCE_FREQUENCY_RESOLUTIONS.LOW_FREQUENCY;
  } else if (trustScore >= threshold && recency < 0.3 && crossRefs < 0.3) {
    // Trust passes threshold but low recency and few cross-refs → coarse resolution
    resolution = SALIENCE_FREQUENCY_RESOLUTIONS.COARSE;
  } else {
    resolution = SALIENCE_FREQUENCY_RESOLUTIONS.FINE;
  }

  return {
    resolution,
    trustScore: Number(trustScore.toFixed(6)),
    threshold: Number(threshold.toFixed(6)),
    components: { access_freq: accessFreq, cross_refs: crossRefs, recency, credit_score: credit },
    junctionInfo: null, // Populated by computeJunctionResolution if neighbors provided
    source_paper: 'Coarsening Dynamics of Fingerprint Labyrinthine Patterns',
    aladdin: 'low_frequency_salience_only_no_decay_suppression_pruning_deletion',
    diagnostic_only: true,
  };
}

export function classifyDormancyResolution(memory, options = {}) {
  return classifySalienceFrequencyResolution(memory, options);
}

/**
 * Build coarsening dynamics diagnostic for a memory and its neighborhood.
 *
 * @param {object} memory - Memory to evaluate
 * @param {Array<object>} neighbors - Neighboring memories
 * @param {object} [options] - { memoryCount } for scale-adaptive threshold
 * @returns {object} Diagnostic with junction resolution and salience frequency classification
 */
export function buildCoarseningDynamicsDiagnostic(memory, neighbors = [], options = {}) {
  const junctionInfo = computeJunctionResolution(memory, neighbors);
  const resolutionInfo = classifySalienceFrequencyResolution(memory, options);

  return {
    diagnostic_type: 'coarsening_dynamics',
    source_paper: 'Coarsening Dynamics of Fingerprint Labyrinthine Patterns',
    diagnostic_only: true,
    memory_key: memory?.key || null,
    resolution: resolutionInfo.resolution,
    trust_score: resolutionInfo.trustScore,
    threshold: resolutionInfo.threshold,
    junction_resolution: junctionInfo,
    proposed_spectrum: {
      FINE: 'full_activation_full_context_bandwidth',
      COARSE: 'reduced_activation_compressed_representation',
      LOW_FREQUENCY: 'lower_broad_query_salience_fully_addressable_by_specific_cue',
    },
    current_production_path: 'binary_normal_or_low_frequency',
    guardrails: {
      production_salience_frequency_changed: false,
      binary_low_frequency_preserved: true,
      canonical_memory_modified: false,
    },
    guarded_math: {
      coarsening_dynamics: true,
    },
  };
}
