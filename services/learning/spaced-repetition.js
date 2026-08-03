// ═══════════════════════════════════════════════════════════════════════════════
// SPACED REPETITION (spaced-repetition.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: SM-2 Algorithm (SuperMemo), Ebbinghaus forgetting curve
//
// P2-B3-5: SM-2 algorithm variant for spaced repetition scheduling.
// Computes optimal review intervals based on quality of recall and repetition count.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 13)
// → Calls: services/observe/event-ledger.js (review schedule events)
// Pipeline: DREAM_PIPELINE
// Position: review scheduling
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// SM-2 constants
const MIN_EASE_FACTOR = 1.3;
const MAX_EASE_FACTOR = 2.5;

/**
 * Compute next interval using SM-2 algorithm variant.
 *
 * Algorithm:
 *   if quality >= 3:
 *     if rep_count == 1: interval = 1 day
 *     elif rep_count == 2: interval = 3 days
 *     else: interval = last_interval * ease_factor
 *   else:
 *     rep_count = 1, ease_factor = 1.3, interval = 1 day
 *
 * @param {number} repetitionCount - How many times reviewed
 * @param {number} easeFactor - Multiplier for intervals
 * @param {number} lastInterval - Previous interval in days
 * @returns {number} - Next interval in days
 */
export function computeInterval(repetitionCount, easeFactor, lastInterval) {
  if (repetitionCount === 1) {
    return 1; // First review after 1 day
  } else if (repetitionCount === 2) {
    return 3; // Second review after 3 days
  } else {
    return Math.max(1, Math.round((lastInterval || 1) * easeFactor));
  }
}

/**
 * Schedule the next review time for a memory.
 *
 * @param {string} memoryId - Memory UUID
 * @param {string} companyId - Company ID
 * @returns {Promise<{nextReviewAt: Date, interval: number, repetitionCount: number}>}
 */
export async function scheduleRepetition(memoryId, companyId) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT m.repetition_count, m.ease_factor, m.next_review_at,
              latest.metadata AS latest_schedule,
              EXTRACT(EPOCH FROM (NOW() - m.last_review_at)) / 86400 as last_interval_days
         FROM aimos_memories m
         LEFT JOIN LATERAL (
           SELECT metadata
             FROM aimos_events
            WHERE company_id = m.company_id
              AND key = m.id::text
              AND operation IN ('memory_review_scheduled', 'memory_review_recorded')
            ORDER BY ts DESC
            LIMIT 1
         ) latest ON true
        WHERE m.id = $1 AND m.company_id = $2`,
      [memoryId, cid]
    );

    if (result.rows.length === 0) {
      return { scheduled: false, reason: 'memory_not_found' };
    }

    const row = result.rows[0];
    const latestSchedule = row.latest_schedule || {};
    const repCount = parseInt(latestSchedule.repetition_count ?? row.repetition_count, 10) || 0;
    const easeFactor = parseFloat(latestSchedule.ease_factor ?? row.ease_factor) || 1.3;
    const lastIntervalDays = parseFloat(row.last_interval_days) || 1;

    const nextInterval = computeInterval(repCount + 1, easeFactor, lastIntervalDays);
    const nextReviewAt = new Date(Date.now() + nextInterval * 86400000);

    const eventId = await logEvent(cid, 'housekeeper', 'memory_review_scheduled', memoryId, {
      next_review_at: nextReviewAt.toISOString(),
      interval_days: nextInterval,
      repetition_count: repCount + 1,
      ease_factor: easeFactor,
      canonical_memory_changed: false,
      reasoning: 'Housekeeper appended an SM-2 review schedule without suppressing or expiring the retained memory.',
      source_knowledge: 'SM-2 spaced repetition schedule',
    });
    return {
      scheduled: true,
      nextReviewAt,
      interval: nextInterval,
      repetitionCount: repCount + 1,
      eventId,
    };
  } catch (err) {
    console.error('[spaced-repetition] scheduleRepetition error:', err.message);
    return { scheduled: false, reason: err.message };
  }
}

/**
 * Get memories due for review.
 *
 * @param {string} companyId - Company ID
 * @param {number} limit - Max results (default: 50)
 * @returns {Promise<Array>} - Memories due for review
 */
export async function getNextReviewBatch(companyId, limit = 50) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT m.id, m.key,
              COALESCE((latest.metadata->>'repetition_count')::int, m.repetition_count) AS repetition_count,
              COALESCE((latest.metadata->>'ease_factor')::double precision, m.ease_factor) AS ease_factor,
              COALESCE((latest.metadata->>'next_review_at')::timestamptz, m.next_review_at, m.created_at + INTERVAL '1 day') AS next_review_at
         FROM aimos_memories m
         LEFT JOIN LATERAL (
           SELECT metadata
             FROM aimos_events
            WHERE company_id = m.company_id
              AND key = m.id::text
              AND operation IN ('memory_review_scheduled', 'memory_review_recorded')
            ORDER BY ts DESC
            LIMIT 1
         ) latest ON true
        WHERE m.company_id = $1
          AND COALESCE((latest.metadata->>'next_review_at')::timestamptz, m.next_review_at, m.created_at + INTERVAL '1 day') <= NOW()
       ORDER BY next_review_at ASC
       LIMIT $2`,
      [cid, limit]
    );

    return result.rows || [];
  } catch (err) {
    console.error('[spaced-repetition] getNextReviewBatch error:', err.message);
    return [];
  }
}

/**
 * Record a review and update repetition metrics.
 * Quality scale: 0-5 (5 = perfect, 0 = complete blackout)
 *
 * SM-2 ease factor update:
 *   EF' = EF + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
 *
 * @param {string} memoryId - Memory UUID
 * @param {number} quality - Quality score (0-5)
 * @param {string} companyId - Company ID
 * @returns {Promise<boolean>} - true on success
 */
export async function recordReview(memoryId, quality, companyId) {
  const cid = companyId || COMPANY;

  try {
    const q = Math.max(0, Math.min(5, Math.floor(quality)));

    // Calculate new ease factor
    const result = await query(
      `SELECT m.ease_factor, m.repetition_count, latest.metadata AS latest_schedule
         FROM aimos_memories m
         LEFT JOIN LATERAL (
           SELECT metadata
             FROM aimos_events
            WHERE company_id = m.company_id
              AND key = m.id::text
              AND operation IN ('memory_review_scheduled', 'memory_review_recorded')
            ORDER BY ts DESC
            LIMIT 1
         ) latest ON true
        WHERE m.id = $1 AND m.company_id = $2`,
      [memoryId, cid]
    );

    if (result.rows.length === 0) {
      return false;
    }

    const latestSchedule = result.rows[0].latest_schedule || {};
    const oldEaseFactor = parseFloat(latestSchedule.ease_factor ?? result.rows[0].ease_factor) || 1.3;
    const newEaseFactor = Math.max(
      MIN_EASE_FACTOR,
      oldEaseFactor + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
    );

    // Schedule next review
    const nextInterval = computeInterval(
      (parseInt(latestSchedule.repetition_count ?? result.rows[0].repetition_count, 10) || 0) + 1,
      newEaseFactor,
      1
    );
    const nextReviewAt = new Date(Date.now() + nextInterval * 86400000);

    await logEvent(cid, 'housekeeper', 'memory_review_recorded', memoryId, {
      quality: q,
      prior_ease_factor: oldEaseFactor,
      ease_factor: newEaseFactor,
      repetition_count: (parseInt(latestSchedule.repetition_count ?? result.rows[0].repetition_count, 10) || 0) + 1,
      next_review_at: nextReviewAt.toISOString(),
      interval_days: nextInterval,
      canonical_memory_changed: false,
      reasoning: 'Housekeeper recorded an SM-2 review as append-only signed evidence; the retained memory was not mutated.',
      source_knowledge: 'SM-2 ease-factor update',
    });

    return true;
  } catch (err) {
    console.error('[spaced-repetition] recordReview error:', err.message);
    return false;
  }
}
