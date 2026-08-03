// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into AGENT_RUN pre-LLM security gates
// Purpose: Classifies requests by Bloom's taxonomy (1-6); maps to security/review
//          tiers and detects alignment gaps between required vs enacted levels
// ← Called by: orchestration/agent-security-gates.js
// Pipeline: AGENT_RUN | Position: cognitive demand classification gate
// ─────────────────────────────────────────────────────────────────────────────

/**
 * cognitive-demand.js — Cognitive Demand Classifier (P1-B3-19)
 *
 * Classifies requests by Bloom's taxonomy level (Remember 1 → Create 6).
 * Maps Bloom levels to appropriate security/review tiers.
 * Detects alignment gaps between required vs enacted cognitive levels.
 * Builds cognitive profiles across request history.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Classify prompt by Bloom's taxonomy level (1-6).
 *
 * 1: Remember — recall facts/definitions
 * 2: Understand — explain concepts
 * 3: Apply — use knowledge in new situations
 * 4: Analyze — distinguish components, relationships
 * 5: Evaluate — make judgments, defend positions
 * 6: Create — produce new work, synthesize
 *
 * @param {string} prompt - User prompt or request text
 * @returns {number} - Bloom level (1-6)
 */
export function classifyBloomLevel(prompt) {
  const text = String(prompt || '').toLowerCase().trim();

  // Keywords for each Bloom level
  const bloomKeywords = {
    1: ['what is', 'define', 'list', 'recall', 'repeat', 'identify', 'name', 'label', 'quote', 'recognize'],
    2: ['explain', 'describe', 'summarize', 'paraphrase', 'interpret', 'translate', 'rephrase', 'discuss'],
    3: ['apply', 'use', 'solve', 'demonstrate', 'illustrate', 'modify', 'show', 'implement', 'execute'],
    4: ['analyze', 'compare', 'contrast', 'distinguish', 'examine', 'break down', 'categorize', 'outline', 'structure'],
    5: ['evaluate', 'assess', 'judge', 'justify', 'critique', 'defend', 'rate', 'weigh', 'decide'],
    6: ['create', 'design', 'generate', 'plan', 'synthesize', 'invent', 'compose', 'construct', 'develop']
  };

  // Count keyword matches per level
  const matches = {};
  for (const [level, keywords] of Object.entries(bloomKeywords)) {
    const levelNum = Number(level);
    matches[levelNum] = keywords.filter(kw => text.includes(kw)).length;
  }

  // Find highest level with matches (break ties towards higher levels)
  let maxLevel = 1;
  let maxMatches = 0;
  for (let level = 6; level >= 1; level--) {
    if ((matches[level] || 0) > maxMatches) {
      maxMatches = matches[level] || 0;
      maxLevel = level;
    }
  }

  // If no clear keywords, use heuristic: prompt length and question complexity
  if (maxMatches === 0) {
    const wordCount = text.split(/\s+/).length;
    const questionCount = (text.match(/\?/g) || []).length;
    const conjunctionCount = (text.match(/\b(and|or|but|however|therefore|because)\b/gi) || []).length;

    // Longer, more complex prompts → higher levels
    if (wordCount < 10) {
      maxLevel = 1; // Simple recall
    } else if (wordCount < 20 && questionCount <= 1) {
      maxLevel = 2; // Explain/describe
    } else if (conjunctionCount > 1) {
      maxLevel = Math.min(4, Math.ceil(wordCount / 15)); // Analysis or higher
    } else {
      maxLevel = 3; // Apply
    }
  }

  return Math.max(1, Math.min(6, maxLevel));
}

/**
 * Map Bloom level to security review tier.
 * Higher Bloom levels → more stringent security review.
 *
 * @param {number} bloomLevel - Bloom level (1-6)
 * @returns {'se_gate_only' | 'security_classifier' | 'full_review'}
 */
export function mapBloomToSecurityTier(bloomLevel) {
  const level = Math.max(1, Math.min(6, Number(bloomLevel) || 1));

  // Level 1-2: Simple recall/understand → SE gate only
  // Level 3-4: Apply/analyze → security classifier
  // Level 5-6: Evaluate/create → full review
  if (level <= 2) {
    return 'se_gate_only';
  } else if (level <= 4) {
    return 'security_classifier';
  } else {
    return 'full_review';
  }
}

/**
 * Compute alignment gap between required Bloom level and enacted level.
 * Flag if gap > 1 (significant underperformance relative to request).
 *
 * @param {number} requiredLevel - Required Bloom level (1-6)
 * @param {number} enactedLevel - Actual Bloom level enacted (1-6)
 * @returns {{gap: number, aligned: boolean, severity: string}}
 */
export function computeAlignmentGap(requiredLevel, enactedLevel) {
  const required = Math.max(1, Math.min(6, Number(requiredLevel) || 1));
  const enacted = Math.max(1, Math.min(6, Number(enactedLevel) || 1));

  const gap = Math.abs(required - enacted);
  const aligned = gap <= 1;

  let severity = 'aligned';
  if (enacted < required) {
    // Underperformance (gap exists and enacted < required)
    if (gap > 2) severity = 'critical_underperformance';
    else if (gap > 1) severity = 'significant_underperformance';
    else severity = 'minor_underperformance';
  } else if (enacted > required) {
    // Overperformance (exceeding request)
    severity = 'overperformance';
  }

  return {
    gap,
    aligned,
    severity,
    requiredLevel: required,
    enactedLevel: enacted
  };
}

/**
 * Detect enacted Bloom level from response trace.
 * Infers what level of cognitive work was actually performed by examining:
 * - Tool calls and their complexity
 * - Reasoning depth (number of inference steps)
 * - Solution novelty
 *
 * @param {object} responseTrace - Trace containing {toolCalls, reasoning, output}
 * @returns {number} - Inferred Bloom level (1-6)
 */
export function detectEnactedLevel(responseTrace = {}) {
  let level = 1;

  // Check for tool calls
  const toolCalls = Array.isArray(responseTrace.toolCalls) ? responseTrace.toolCalls : [];
  const reasoning = String(responseTrace.reasoning || '').toLowerCase();
  const outputLength = String(responseTrace.output || '').length;

  // Level 1: No tools, simple output
  if (toolCalls.length === 0 && outputLength < 100) {
    level = 1;
  }

  // Level 2: Simple lookup or description (1-2 tools, straightforward reasoning)
  else if (toolCalls.length <= 2 && reasoning.split(/\b(because|since|therefore|however)\b/i).length < 3) {
    level = 2;
  }

  // Level 3: Apply (3-4 tools, some decision logic)
  else if (toolCalls.length <= 4 || reasoning.includes('apply') || reasoning.includes('use')) {
    level = 3;
  }

  // Level 4: Analyze (5+ tools, comparison/decomposition, multiple reasoning steps)
  else if (toolCalls.length > 4 || reasoning.includes('analyze') || reasoning.includes('compare')) {
    level = 4;
  }

  // Level 5: Evaluate (complex chains, explicit criteria, trade-offs)
  else if (reasoning.includes('evaluate') || reasoning.includes('trade-off') || reasoning.includes('weigh')) {
    level = 5;
  }

  // Level 6: Create (novel synthesis, design decisions, architecture)
  else if (reasoning.includes('design') || reasoning.includes('create') || reasoning.includes('synthesize')) {
    level = 6;
  }

  // Boost if complex interdependencies detected
  if (toolCalls.length > 0 && (reasoning.includes('based on') || reasoning.includes('given')) && level < 4) {
    level = Math.min(4, level + 1);
  }

  return Math.max(1, Math.min(6, level));
}

/**
 * Build cognitive profile from request history.
 * Computes distribution of Bloom levels across requests to understand
 * typical cognitive demand patterns.
 *
 * @param {string} userId - User ID or agent ID
 * @param {string} companyId - Company ID for scoping
 * @param {number} days - Historical window in days (default 30)
 * @returns {Promise<{levels: Map<number, number>, distribution: {mean: number, median: number, std: number}, samples: number}>}
 */
export async function buildCognitiveProfile(userId, companyId = COMPANY, days = 30) {
  try {
    // Query historical requests for this user
    const result = await query(`
      SELECT
        request_text,
        response_trace
      FROM agent_requests
      WHERE user_id = $1
        AND company_id = $2
        AND timestamp > NOW() - INTERVAL '${Math.max(1, Math.min(365, Math.floor(days)))} days'
      ORDER BY timestamp DESC
      LIMIT 500
    `, [userId, companyId]);

    const levels = new Map();
    const allLevels = [];

    if (result && result.rows) {
      for (const row of result.rows) {
        const text = String(row.request_text || '');
        const trace = typeof row.response_trace === 'string' ? JSON.parse(row.response_trace) : row.response_trace || {};

        // Classify request bloom level
        const requiredLevel = classifyBloomLevel(text);
        // Detect enacted level if trace available
        const enactedLevel = Object.keys(trace).length > 0 ? detectEnactedLevel(trace) : requiredLevel;

        // Use enacted level for profile
        const level = enactedLevel;
        levels.set(level, (levels.get(level) || 0) + 1);
        allLevels.push(level);
      }
    }

    // Compute distribution statistics
    let mean = 0;
    let median = 0;
    let std = 0;

    if (allLevels.length > 0) {
      mean = allLevels.reduce((a, b) => a + b, 0) / allLevels.length;

      // Median
      const sorted = [...allLevels].sort((a, b) => a - b);
      median = sorted.length % 2 === 0
        ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
        : sorted[Math.floor(sorted.length / 2)];

      // Standard deviation
      const variance = allLevels.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / allLevels.length;
      std = Math.sqrt(variance);
    }

    return {
      levels,
      distribution: {
        mean: parseFloat(mean.toFixed(2)),
        median: parseFloat(median.toFixed(2)),
        std: parseFloat(std.toFixed(2))
      },
      samples: allLevels.length
    };
  } catch (err) {
    console.warn('[cognitive-demand] Failed to build cognitive profile:', err.message);
    return {
      levels: new Map(),
      distribution: { mean: 0, median: 0, std: 0 },
      samples: 0,
      error: err.message
    };
  }
}

/**
 * Get human-readable description of Bloom level.
 *
 * @param {number} level - Bloom level (1-6)
 * @returns {string}
 */
export function getBloomLevelDescription(level) {
  const descriptions = {
    1: 'Remember - recall facts and definitions',
    2: 'Understand - explain and interpret concepts',
    3: 'Apply - use knowledge in new situations',
    4: 'Analyze - examine components and relationships',
    5: 'Evaluate - make judgments and defend positions',
    6: 'Create - generate new work and synthesize ideas'
  };

  const lvl = Math.max(1, Math.min(6, Number(level) || 1));
  return descriptions[lvl];
}

/**
 * Assess security implications of cognitive demand.
 * Higher Bloom levels → higher stakes for security misalignment.
 *
 * @param {number} bloomLevel - Required Bloom level
 * @param {object} gap - Alignment gap result
 * @returns {{riskLevel: string, requiresReview: boolean, reason: string}}
 */
function computeSecurityImplications(bloomLevel, gap = {}) {
  const level = Math.max(1, Math.min(6, Number(bloomLevel) || 1));
  const gapSize = Math.abs(Number(gap.gap) || 0);
  const enactedLevel = Number(gap.enactedLevel ?? gap.enacted);
  const requiredLevel = Number(gap.requiredLevel ?? gap.required);

  let riskLevel = 'low';
  let requiresReview = false;
  let reason = '';

  // High Bloom levels are higher risk
  if (level >= 5) {
    riskLevel = 'high';
    reason = 'Evaluate/Create level requires full security review';
    requiresReview = true;
  } else if (level >= 3) {
    riskLevel = 'medium';
    reason = 'Apply/Analyze level requires security classification';
    requiresReview = gapSize > 1;
  } else {
    riskLevel = 'low';
    reason = 'Remember/Understand level: SE gate sufficient';
    requiresReview = false;
  }

  // Underperformance increases risk
  if (gapSize > 1 && Number.isFinite(enactedLevel) && Number.isFinite(requiredLevel) && enactedLevel < requiredLevel) {
    riskLevel = riskLevel === 'low' ? 'medium' : 'high';
    requiresReview = true;
    reason += ` (underperformance detected: gap=${gapSize})`;
  }

  return { riskLevel, requiresReview, reason };
}

export function assessSecurityImplications(bloomLevel, gap = {}) {
  const level = Math.max(1, Math.min(6, Number(bloomLevel) || 1));
  const implication = computeSecurityImplications(level, gap);

  if (implication.requiresReview) {
    logEvent(COMPANY, 'cognitive-demand', 'security_detection', `cognitive-demand:${implication.riskLevel}`, {
      reasoning: `Security event: Cognitive demand classification requires review — bloom level ${level}, risk ${implication.riskLevel}: ${implication.reason}`,
      severity: implication.riskLevel === 'high' ? 'high' : 'medium',
      details: {
        bloomLevel: level,
        riskLevel: implication.riskLevel,
        gapSize: Math.abs(Number(gap.gap) || 0),
        reason: implication.reason
      }
    }).catch(() => {});
  }

  return implication;
}

/**
 * Return the complete cognitive security contract for downstream gates.
 * Review tier selects which analysis pipeline runs; task risk selects the
 * required trust-verification strength. They are deliberately separate enums.
 */
export function classifyCognitiveSecurity(bloomLevel, gap = {}) {
  const level = Math.max(1, Math.min(6, Number(bloomLevel) || 1));
  const implication = computeSecurityImplications(level, gap);
  return Object.freeze({
    bloomLevel: level,
    reviewTier: mapBloomToSecurityTier(level),
    taskRiskLevel: implication.riskLevel,
    requiresReview: implication.requiresReview,
    reason: implication.reason
  });
}

export default {
  classifyBloomLevel,
  mapBloomToSecurityTier,
  classifyCognitiveSecurity,
  computeAlignmentGap,
  detectEnactedLevel,
  buildCognitiveProfile,
  getBloomLevelDescription,
  assessSecurityImplications
};
