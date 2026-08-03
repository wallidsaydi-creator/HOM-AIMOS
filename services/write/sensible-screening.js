// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: Validates RPE gate screening — ensures optimal items are included and
//          high-utility memories are never filtered out (P2-B3-2)
// Wire into: quality-gate.js or rpe-gate.js (SAVE pipeline, screener validation)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// SENSIBLE SCREENING (sensible-screening.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-2: Validates screening logic to ensure optimal items are included and
// RPE gate quality is maintained (never filters out high-utility memories).
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Validate that a screener includes the optimal items from a test set.
 *
 * @param {Object} screener - Screening function or configuration
 * @param {Array} testSet - Test items with utility scores
 * @param {Array} testSet[].id - Item ID
 * @param {number} testSet[].utility - Utility score (higher is better)
 * @returns {Promise<{valid: boolean, missingOptimal: Array, reason: string}>}
 */
export async function validateSensibleScreening(screener, testSet) {
  try {
    if (!Array.isArray(testSet) || testSet.length === 0) {
      return { valid: false, missingOptimal: [], reason: 'empty_test_set' };
    }

    // Identify optimal items (top 20% by utility)
    const sorted = [...testSet].sort((a, b) => (b.utility || 0) - (a.utility || 0));
    const optimalCount = Math.max(1, Math.ceil(testSet.length * 0.2));
    const optimalIds = new Set(sorted.slice(0, optimalCount).map(item => item.id));

    // Apply screener (assuming async function or sync filter)
    let included;
    if (typeof screener === 'function') {
      included = testSet.filter(item => screener(item)).map(item => item.id);
    } else if (Array.isArray(screener)) {
      included = screener;
    } else {
      return { valid: false, missingOptimal: Array.from(optimalIds), reason: 'invalid_screener_type' };
    }

    const includedSet = new Set(included);
    const missingOptimal = Array.from(optimalIds).filter(id => !includedSet.has(id));

    return {
      valid: missingOptimal.length === 0,
      missingOptimal,
      reason: missingOptimal.length === 0 ? 'all_optimal_included' : 'optimal_excluded'
    };
  } catch (err) {
    console.error('[sensible-screening] validateSensibleScreening error:', err.message);
    return { valid: false, missingOptimal: [], reason: `error: ${err.message}` };
  }
}

/**
 * Compute screening quality metrics.
 *
 * @param {Array<string>} included - IDs of included items
 * @param {Array<string>} excluded - IDs of excluded items
 * @param {Array<string>} optimal - IDs of optimal items
 * @returns {{includes_optimal: boolean, optimal_count: number, suboptimal_count: number}}
 */
export function computeScreeningQuality(included, excluded, optimal) {
  const includedSet = new Set(included || []);
  const optimalSet = new Set(optimal || []);

  const includedOptimal = included.filter(id => optimalSet.has(id));
  const includedSuboptimal = included.filter(id => !optimalSet.has(id));

  return {
    includes_optimal: includedOptimal.length > 0,
    optimal_count: includedOptimal.length,
    suboptimal_count: includedSuboptimal.length
  };
}

/**
 * Monitor RPE gate quality to ensure it never filters high-utility memories.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<{healthy: boolean, issues: Array, highUtilityFiltered: number}>}
 */
export async function monitorRPEGateQuality(companyId) {
  const cid = companyId || COMPANY;
  const issues = [];

  try {
    // Find memories with high utility that were recently filtered by RPE gate
    const result = await query(
      `SELECT id, key, utility_score,
              (SELECT COUNT(*) FROM aimos_events
               WHERE key = m.key AND company_id = $1
                 AND operation = 'rpe_gate_filter'
                 AND ts > NOW() - INTERVAL '24 hours') as recent_filters
       FROM aimos_memories m
       WHERE company_id = $1
         AND utility_score > 0.7
       ORDER BY utility_score DESC
       LIMIT 50`,
      [cid]
    );

    let highUtilityFiltered = 0;
    for (const row of result.rows) {
      const recentFilters = parseInt(row.recent_filters, 10) || 0;
      if (recentFilters > 0) {
        highUtilityFiltered++;
        issues.push({
          memory_id: row.id,
          key: row.key,
          utility_score: row.utility_score,
          filter_count: recentFilters
        });
      }
    }

    return {
      healthy: highUtilityFiltered === 0,
      issues,
      highUtilityFiltered
    };
  } catch (err) {
    console.error('[sensible-screening] monitorRPEGateQuality error:', err.message);
    return {
      healthy: false,
      issues: [],
      highUtilityFiltered: 0
    };
  }
}
