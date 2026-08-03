// ═══════════════════════════════════════════════════════════════════════════════
// MASTERY PARADOX DETECTOR (mastery-paradox-detector.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Senge Fifth Discipline (learning organization), Dunning-Kruger effect
//
// P2-B3-3: Detects mastery paradox (success rate rising while error diversity
// remains constant), indicating potential surface memorization rather than
// deep learning.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 14)
// → Calls: services/observe/event-ledger.js (paradox detection events)
// Pipeline: DREAM_PIPELINE
// Position: paradox detection
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Compute success rate trend (linear slope) over a time window.
 *
 * @param {string} domain - Domain/task identifier
 * @param {string} companyId - Company ID
 * @param {number} windowDays - Time window in days (e.g., 30)
 * @returns {Promise<number>} - Slope of success rate over time (positive = improving)
 */
export async function computeSuccessTrend(domain, companyId, windowDays = 30) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT DATE(ts) as day,
              SUM(CASE WHEN operation = 'success' THEN 1 ELSE 0 END)::float /
              NULLIF(COUNT(*), 0) as success_rate
       FROM aimos_events
       WHERE company_id = $1 AND key LIKE $2
         AND ts > NOW() - INTERVAL '1 day' * $3
         AND operation IN ('success', 'failure')
       GROUP BY DATE(ts)
       ORDER BY DATE(ts) ASC`,
      [cid, `%${domain}%`, windowDays]
    );

    if (result.rows.length < 2) {
      return 0; // Not enough data
    }

    // Compute linear regression slope
    const rows = result.rows;
    const n = rows.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;

    for (let i = 0; i < n; i++) {
      const x = i;
      const y = parseFloat(rows[i].success_rate) || 0;
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumX2 += x * x;
    }

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return isFinite(slope) ? slope : 0;
  } catch (err) {
    console.error('[mastery-paradox-detector] computeSuccessTrend error:', err.message);
    return 0;
  }
}

/**
 * Compute failure diversity: count of unique error classes over a time window.
 * Stable or declining diversity despite rising success suggests memorization.
 *
 * @param {string} domain - Domain/task identifier
 * @param {string} companyId - Company ID
 * @param {number} windowDays - Time window in days
 * @returns {Promise<number>} - Count of unique error classes
 */
export async function computeFailureDiversity(domain, companyId, windowDays = 30) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT COUNT(DISTINCT metadata->>'error_class') as unique_errors
       FROM aimos_events
       WHERE company_id = $1 AND key LIKE $2
         AND ts > NOW() - INTERVAL '1 day' * $3
         AND operation = 'failure'
         AND metadata->>'error_class' IS NOT NULL`,
      [cid, `%${domain}%`, windowDays]
    );

    return parseInt(result.rows[0]?.unique_errors || 0, 10);
  } catch (err) {
    console.error('[mastery-paradox-detector] computeFailureDiversity error:', err.message);
    return 0;
  }
}

/**
 * Determine if a mastery paradox is present.
 * True when success trend is rising but failure diversity is constant/declining.
 *
 * @param {number} successTrend - Slope of success rate (positive = improving)
 * @param {number} failureDiversity - Unique error class count
 * @returns {boolean} - true if paradox detected
 */
export function isParadoxPresent(successTrend, failureDiversity) {
  // Paradox: success improving (slope > 0.01) but error diversity very low (< 3 unique errors)
  return successTrend > 0.01 && failureDiversity < 3;
}

/**
 * Detect mastery paradox in a domain.
 *
 * @param {string} domain - Domain/task identifier
 * @param {string} companyId - Company ID
 * @param {number} windowDays - Time window in days (default: 30)
 * @returns {Promise<{detected: boolean, successTrend: number, failureDiversity: number, reason: string}>}
 */
export async function detectMasteryParadox(domain, companyId, windowDays = 30) {
  try {
    const successTrend = await computeSuccessTrend(domain, companyId, windowDays);
    const failureDiversity = await computeFailureDiversity(domain, companyId, windowDays);

    const detected = isParadoxPresent(successTrend, failureDiversity);
    let reason = '';

    if (detected) {
      reason = `Success improving (slope=${successTrend.toFixed(3)}) but low error diversity (${failureDiversity} unique errors) suggests surface memorization`;
    } else if (successTrend > 0.01 && failureDiversity >= 3) {
      reason = 'Success improving with healthy error diversity — genuine learning detected';
    } else if (successTrend <= 0.01) {
      reason = 'Success rate not improving significantly';
    }

    return {
      detected,
      successTrend,
      failureDiversity,
      reason
    };
  } catch (err) {
    console.error('[mastery-paradox-detector] detectMasteryParadox error:', err.message);
    return {
      detected: false,
      successTrend: 0,
      failureDiversity: 0,
      reason: `error: ${err.message}`
    };
  }
}
