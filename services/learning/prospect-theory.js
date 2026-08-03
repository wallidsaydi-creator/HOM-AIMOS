// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: Corrects for loss aversion bias and probability weighting in human
//          feedback using Prospect Theory / CPT (P2-B3-8)
// Wire into: governance-resolver.js or agent-runner.js (feedback calibration)
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// PROSPECT THEORY (prospect-theory.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-8: Models decision-making using Prospect Theory and Cumulative Prospect
// Theory. Corrects for loss aversion bias and probability weighting in human feedback.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// PT constants (Tversky & Kahneman, 1992)
const DEFAULT_ALPHA = 0.88;      // Risk aversion for gains
const DEFAULT_BETA = 0.88;       // Risk aversion for losses
const DEFAULT_LAMBDA = 2.25;     // Loss aversion coefficient
const DEFAULT_DELTA = 0.69;      // CPT probability weighting exponent

/**
 * Compute Prospect Theory value function.
 *
 * Value(x) = x^α                          if x ≥ 0 (gains)
 * Value(x) = -λ * (-x)^β                  if x < 0 (losses)
 *
 * @param {number} outcome - Outcome value (can be negative)
 * @param {number} reference - Reference point
 * @param {number} alpha - Risk aversion for gains (default: 0.88)
 * @param {number} beta - Risk aversion for losses (default: 0.88)
 * @param {number} lambda - Loss aversion coefficient (default: 2.25)
 * @returns {number} - Prospect Theory value
 */
export function ptValue(outcome, reference, alpha = DEFAULT_ALPHA, beta = DEFAULT_BETA, lambda = DEFAULT_LAMBDA) {
  const diff = outcome - reference;

  if (diff >= 0) {
    return Math.pow(diff, alpha);
  } else {
    return -lambda * Math.pow(-diff, beta);
  }
}

/**
 * Recover true signal from human feedback biased by prospect theory.
 * Corrects for loss aversion and reference-dependence.
 *
 * @param {number} humanFeedback - Observed feedback (0-1 scale)
 * @param {number} referencePoint - Current reference point
 * @param {number} lambda - Loss aversion coefficient
 * @returns {number} - Estimated true utility
 */
export function inversePTCorrection(humanFeedback, referencePoint, lambda = DEFAULT_LAMBDA) {
  // Feedback as deviation from reference
  const fbAsDeviation = humanFeedback - 0.5; // Center around 0.5

  // Correct for loss aversion: feedback below reference is amplified
  const sign = fbAsDeviation < 0 ? -1 : 1;
  const magnitude = Math.abs(fbAsDeviation);
  const corrected = sign * (magnitude / lambda);

  // Map back to [0, 1]
  return Math.max(0, Math.min(1, 0.5 + corrected));
}

/**
 * Update reference point using exponential moving average.
 * ref_new = (1 - α) * ref_old + α * outcome
 *
 * @param {string} userId - User ID
 * @param {string} domain - Domain identifier
 * @param {number} outcome - New outcome
 * @param {number} alpha - Update weight (default: 0.1)
 * @returns {Promise<number>} - Updated reference point
 */
export async function updateReferencePoint(userId, domain, outcome, alpha = 0.1) {
  try {
    const result = await query(
      `SELECT reference_point FROM user_reference_points
       WHERE user_id = $1 AND domain = $2`,
      [userId, domain]
    );

    let oldRef = 0.5; // Default reference
    if (result.rows.length > 0) {
      oldRef = parseFloat(result.rows[0].reference_point) || 0.5;
    }

    const newRef = (1 - alpha) * oldRef + alpha * outcome;

    await query(
      `INSERT INTO user_reference_points (user_id, domain, reference_point, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, domain) DO UPDATE
       SET reference_point = $3, updated_at = NOW()`,
      [userId, domain, newRef]
    );

    return newRef;
  } catch (err) {
    console.error('[prospect-theory] updateReferencePoint error:', err.message);
    return 0.5;
  }
}

/**
 * Get current reference point for a user in a domain.
 *
 * @param {string} userId - User ID
 * @param {string} domain - Domain identifier
 * @returns {Promise<number>} - Reference point (0-1 scale)
 */
export async function getReferencePoint(userId, domain) {
  try {
    const result = await query(
      `SELECT reference_point FROM user_reference_points
       WHERE user_id = $1 AND domain = $2`,
      [userId, domain]
    );

    if (result.rows.length > 0) {
      return parseFloat(result.rows[0].reference_point) || 0.5;
    }
    return 0.5; // Default reference
  } catch (err) {
    console.error('[prospect-theory] getReferencePoint error:', err.message);
    return 0.5;
  }
}

/**
 * Apply Cumulative Prospect Theory probability weighting.
 *
 * w(p) = p^δ / (p^δ + (1-p)^δ)^(1/δ)
 *
 * where δ = 0.69 (Kahneman & Tversky, 1992) for standard risk aversion.
 *
 * @param {number} probability - Probability (0-1)
 * @param {number} delta - Weighting exponent (default: 0.69)
 * @returns {number} - Decision weight w(p) (0-1)
 */
export function applyProbabilityWeighting(probability, delta = DEFAULT_DELTA) {
  const p = Math.max(0, Math.min(1, probability));

  // Avoid division by zero
  if (p === 0) return 0;
  if (p === 1) return 1;

  const pDelta = Math.pow(p, delta);
  const oneMinusPDelta = Math.pow(1 - p, delta);

  return pDelta / Math.pow(pDelta + oneMinusPDelta, 1 / delta);
}
