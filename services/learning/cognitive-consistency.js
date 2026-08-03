// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: Evaluates cognitive consistency across foundational premise, strategic
//          preference, logic mapping, and taboo avoidance dimensions (P2-B3-9)
// Wire into: governance-resolver.js or the native offline reflection pipeline
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// COGNITIVE CONSISTENCY (cognitive-consistency.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-9: Evaluates cognitive consistency across dimensions (foundational premise,
// strategic preference, logic mapping, taboo avoidance). Detects surface memorization
// via cross-domain performance drop.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Compute consistency score for a set of responses.
 * Measures uniformity of answers across multiple prompts.
 *
 * @param {Array<string>} responses - Text responses
 * @returns {number} - Consistency score (0-1)
 */
function computeResponseConsistency(responses) {
  if (!Array.isArray(responses) || responses.length < 2) {
    return 1; // Trivially consistent if <2 responses
  }

  // Simple heuristic: measure lexical overlap between consecutive responses
  let totalOverlap = 0;
  for (let i = 0; i < responses.length - 1; i++) {
    const wordsA = new Set(responses[i].toLowerCase().split(/\s+/));
    const wordsB = new Set(responses[i + 1].toLowerCase().split(/\s+/));

    const intersection = [...wordsA].filter(w => wordsB.has(w)).length;
    const union = new Set([...wordsA, ...wordsB]).size;

    totalOverlap += union > 0 ? intersection / union : 0;
  }

  return totalOverlap / (responses.length - 1);
}

/**
 * Evaluate consistency of foundational premise across responses.
 * High consistency suggests coherent problem framing.
 *
 * @param {Array<string>} responses - Problem descriptions
 * @returns {number} - Consistency score (0-1)
 */
export function evaluateFoundationalPremise(responses) {
  return computeResponseConsistency(responses);
}

/**
 * Evaluate consistency of strategic preference across responses.
 * High consistency suggests stable solution approach.
 *
 * @param {Array<string>} responses - Solution type descriptions
 * @returns {number} - Consistency score (0-1)
 */
export function evaluateStrategicPreference(responses) {
  return computeResponseConsistency(responses);
}

/**
 * Evaluate consistency of logical patterns across domains.
 * High consistency suggests deep understanding vs surface patterns.
 *
 * @param {Array<string>} responses - Logical reasoning statements
 * @returns {number} - Consistency score (0-1)
 */
export function evaluateLogicMapping(responses) {
  return computeResponseConsistency(responses);
}

/**
 * Evaluate taboo avoidance consistency.
 * Does the system consistently avoid distrusted solutions?
 *
 * @param {Array<string>} responses - Solution proposals
 * @param {Set<string>} knownTaboos - Set of distrusted/forbidden approaches
 * @returns {number} - Consistency score (0-1)
 */
export function evaluateTabooAvoidance(responses, knownTaboos = new Set()) {
  if (!Array.isArray(responses) || responses.length === 0) {
    return 1;
  }

  const tabooViolations = responses.filter(resp => {
    const text = resp.toLowerCase();
    return [...knownTaboos].some(taboo => text.includes(taboo.toLowerCase()));
  }).length;

  // 0 violations = perfect consistency (1.0)
  // Some violations = proportionally reduced
  return 1 - (tabooViolations / responses.length);
}

/**
 * Compute overall consistency across all dimensions.
 *
 * @param {Object} dimensions - Consistency scores by dimension
 * @param {number} dimensions.foundational - Premise consistency (0-1)
 * @param {number} dimensions.strategic - Strategy consistency (0-1)
 * @param {number} dimensions.logic - Logic consistency (0-1)
 * @param {number} dimensions.taboo - Taboo avoidance (0-1)
 * @returns {number} - Weighted average (0-1)
 */
export function computeOverallConsistency(dimensions) {
  const weights = {
    foundational: 0.25,
    strategic: 0.25,
    logic: 0.35,
    taboo: 0.15
  };

  let score = 0;
  let totalWeight = 0;

  for (const [key, weight] of Object.entries(weights)) {
    if (key in dimensions) {
      score += (dimensions[key] || 0) * weight;
      totalWeight += weight;
    }
  }

  return totalWeight > 0 ? score / totalWeight : 0;
}

/**
 * Detect surface memorization by comparing in-domain vs cross-domain performance.
 * True if cross-domain performance drops significantly (>0.3 points) vs in-domain.
 *
 * @param {number} crossDomainScore - Performance on cross-domain problems (0-1)
 * @param {number} inDomainScore - Performance on in-domain problems (0-1)
 * @returns {boolean} - true if surface memorization suspected
 */
export function isSurfaceMemorized(crossDomainScore, inDomainScore) {
  const drop = inDomainScore - crossDomainScore;
  return drop > 0.3; // Significant performance drop indicates surface memorization
}
