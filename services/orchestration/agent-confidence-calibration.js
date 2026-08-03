/**
 * agent-confidence-calibration.js — Confidence Scoring & Calibration (Gap 4 extraction)
 *
 * Extracts confidence derivation, complexity classification, F7 protocol evaluation,
 * route confidence, and autonomy enforcement from agent-runner.js.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (post-run confidence, pre-run calibration)
 * 2. → Calls: db/connection.js (query), agent-learning.js (getCalibrationFactor)
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: confidence scoring
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getPermissions } from '../core/permissions.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── CONFIDENCE SCORING (DARPA ASIMOV + Ameisen calibration) ──────────────────

/**
 * extractConfidence — derives a calibrated 0.0–1.0 confidence score for a run.
 *
 * Priority 1: explicit declaration in the response text
 *   Matches patterns like "confidence: 0.85" or "confidence score: 0.9" (case-insensitive).
 *   Parsed value is clamped to [0.0, 1.0].
 *
 * Priority 2: heuristic from observable run signals
 *   Base:                   0.35
 *   Length > 2000:          +0.12
 *   Length > 800:           +0.08
 *   Length > 300:           +0.04
 *   Tool calls:             +0.04 each (cap 0.12)
 *   Memory hits:            +0.03 each (cap 0.12)
 *   Causal reasoning:       +0.05
 *   Logical conclusion:     +0.04
 *   Nuanced thinking:      +0.05
 *   Risk awareness:         +0.04
 *   Actionability:          +0.03
 *   Hedge words:            -0.08 / -0.10
 *
 * @param {string} responseText  - Full text of the model response.
 * @param {number} toolCallCount - Number of tool calls executed during the run (0 if unknown).
 * @param {number} memoryHits    - Number of aimos memory items retrieved (keptItems).
 * @returns {number} Confidence score in [0.1, 0.98].
 */
export function extractConfidence(responseText, toolCallCount = 0, memoryHits = 0) {
  const text = String(responseText || '');

  // Priority 1: explicit confidence declaration in the response
  const explicit = text.match(/\bconfidence(?:\s+score)?\s*[:=]\s*([0-9]*\.?[0-9]+)/i);
  if (explicit) {
    const parsed = parseFloat(explicit[1]);
    if (Number.isFinite(parsed)) {
      return Math.max(0.0, Math.min(1.0, parsed));
    }
  }

  // Priority 2: multi-signal heuristic with finer gradations
  let score = 0.35;

  // Length signals (response depth)
  if (text.length > 2000) score += 0.12;
  else if (text.length > 800) score += 0.08;
  else if (text.length > 300) score += 0.04;

  // Tool usage signals
  if (Number.isFinite(toolCallCount) && toolCallCount > 0) score += Math.min(0.12, toolCallCount * 0.04);

  // Memory grounding signals
  if (Number.isFinite(memoryHits) && memoryHits > 0) score += Math.min(0.12, memoryHits * 0.03);

  // Reasoning quality signals from text
  const lower = text.toLowerCase();
  if (/\bbecause\b|\bsince\b|\bdue to\b/.test(lower)) score += 0.05;
  if (/\btherefore\b|\bthus\b|\bconsequently\b/.test(lower)) score += 0.04;
  if (/\bhowever\b|\balternatively\b|\btrade-?off\b/.test(lower)) score += 0.05;
  if (/\brisk\b|\bcaveat\b|\blimitation\b|\bdownside\b/.test(lower)) score += 0.04;
  if (/\brecommend\b|\bshould\b|\bnext step\b/.test(lower)) score += 0.03;

  // Negative signals — hedge words reduce confidence
  if (/\bi'?m not sure\b|\buncertain\b|\bhard to say\b|\bmight be wrong\b/.test(lower)) score -= 0.08;
  if (/\bi don'?t know\b|\bno information\b|\bcannot determine\b/.test(lower)) score -= 0.1;

  return Math.max(0.1, Math.min(0.98, score));
}

// ─── COMPLEXITY CLASSIFIER ────────────────────────────────────────────────────

/**
 * classifyComplexity — categorises a prompt into simple / moderate / complex.
 *
 * @param {string} prompt    - User prompt text.
 * @param {string} taskType  - Task type (default 'chat').
 * @returns {'simple'|'moderate'|'complex'}
 */
export function classifyComplexity(prompt, taskType = 'chat') {
  const text = String(prompt || '').toLowerCase();
  const len = text.length;

  if (len < 60) return 'simple';
  if (/^(hi|hello|hey|thanks|ok|yes|no|good|fine)\b/i.test(text)) return 'simple';
  if (taskType === 'chat' && len < 150 && !/\b(analyze|research|compare|explain|investigate|evaluate|plan)\b/.test(text)) return 'simple';

  if (/\b(analyze|research|compare|investigate|evaluate|synthesize|audit|review all|deep dive)\b/.test(text)) return 'complex';
  if (taskType === 'research' || taskType === 'analysis') return 'complex';
  if (len > 500) return 'complex';
  if ((text.match(/\?/g) || []).length >= 2) return 'complex';
  if (/\b(and also|additionally|furthermore|then|after that|step \d)\b/.test(text)) return 'complex';

  return 'moderate';
}

// ─── F7 PROTOCOL EVALUATION ────────────────────────────────────────────────────

/**
 * evaluateWithF7Protocol — blends F7 criteria-based score with heuristic confidence.
 *
 * Loads the F7 evaluation protocol from aimos_memories and blends it with the
 * heuristic confidence using 60/40 weighting (F7 / heuristic).
 *
 * @param {string} agentId             - Agent identifier.
 * @param {string} taskType            - Task type for criteria lookup.
 * @param {number} heuristicConfidence - Heuristic confidence from extractConfidence().
 * @param {string} responseText        - Full response text for keyword matching.
 * @returns {Promise<number>} Blended confidence score [0, 1].
 */
export async function evaluateWithF7Protocol(agentId, taskType, heuristicConfidence, responseText) {
  try {
    const result = await query(
      `SELECT value FROM aimos_memories
     WHERE company_id = $1 AND key = 'procedure_f7_evaluation_protocol'
     ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
     LIMIT 1`,
      [COMPANY]
    );
    if (!result.rows.length) return heuristicConfidence;
    const protocol = JSON.parse(result.rows[0].value || '{}');
    const criteria = protocol.task_criteria?.[taskType] || protocol.task_criteria?.['default'];
    if (!criteria) return heuristicConfidence;

    let totalWeight = 0;
    let earnedWeight = 0;
    const text = String(responseText || '').toLowerCase();
    for (const [criterion, weight] of Object.entries(criteria)) {
      totalWeight += parseFloat(weight) || 0;
      const keywords = criterion.toLowerCase().split(/[\s_]+/);
      const matches = keywords.filter(k => k.length > 3 && text.includes(k));
      if (matches.length >= Math.ceil(keywords.length * 0.4)) {
        earnedWeight += parseFloat(weight) || 0;
      }
    }
    if (totalWeight === 0) return heuristicConfidence;
    const f7Score = earnedWeight / totalWeight;
    return Math.max(0, Math.min(1, f7Score * 0.6 + heuristicConfidence * 0.4));
  } catch {
    return heuristicConfidence;
  }
}

// ─── ROUTE CONFIDENCE ─────────────────────────────────────────────────────────

/**
 * evaluateRouteConfidence — determines whether a DAG route should be re-routed
 * based on confidence threshold.
 *
 * @param {Object|null} taskRoute  - Route config with confidence_threshold / reroute_below.
 * @param {number}      confidence - Final confidence score.
 * @returns {{ reroute: boolean, reason?: string, fallbackRoute?: * }}
 */
export function evaluateRouteConfidence(taskRoute, confidence) {
  if (!taskRoute) return { reroute: false };
  const threshold = parseFloat(taskRoute.confidence_threshold || taskRoute.reroute_below || 0);
  if (threshold <= 0 || confidence >= threshold) return { reroute: false };
  const fallback = taskRoute.fallback_route || taskRoute.fallback_frameworks || null;
  if (!fallback) return { reroute: false };
  return {
    reroute: true,
    reason: `confidence ${confidence.toFixed(2)} < threshold ${threshold}`,
    fallbackRoute: fallback
  };
}

// ─── AUTONOMY ENFORCEMENT ─────────────────────────────────────────────────────

/**
 * checkAutonomyLevel — maps confidence to autonomy level (L1/L2/L3).
 *
 * L3 (auto): confidence >= auto_threshold
 * L2 (notify): confidence >= notify_threshold
 * L1 (escalate): below notify_threshold
 *
 * @param {string} agentId    - Agent identifier.
 * @param {number} confidence - Final confidence score.
 * @param {string} taskType   - Task type (unused, reserved).
 * @returns {Promise<{level: string, action: string}>}
 */
export async function checkAutonomyLevel(agentId, confidence, taskType) {
  try {
    const permissions = await getPermissions(agentId, COMPANY);
    if (confidence >= 0.8 && (permissions.delegate === true || permissions.admin_override === true)) {
      return { level: 'L3', action: 'proceed', authority: 'signed_capability_ledger' };
    }
    if (confidence >= 0.6 && (permissions.memory_read === true || permissions.memory_write === true)) {
      return { level: 'L2', action: 'notify', authority: 'signed_capability_ledger' };
    }
    return { level: 'L1', action: 'escalate' };
  } catch {
    return { level: 'L1', action: 'escalate', reason: 'authorization_unavailable' };
  }
}
