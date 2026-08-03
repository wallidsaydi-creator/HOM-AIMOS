// ═══════════════════════════════════════════════════════════════════════════════
// FAILURE REPLAY (failure-replay.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Sources: Sutton & Barto (Temporal Difference learning), Counterfactual regret minimization
//
// P1-7: Active Failure Replay
//
// Extracts structured failure profiles, clusters failures across tasks by
// error signature, and synthesises "anti-skills" — procedural memories that
// encode what NOT to do and why.
//
// Anti-skills are stored to Aimos as memory_type='procedural' with key prefix
// 'anti_skill:' so they can be retrieved before any new plan is executed.
//
// Theoretical basis: Temporal Difference learning (Sutton & Barto),
// Counterfactual regret minimisation, and Sleep-replay consolidation
// (replay most surprising failures first — highest temporal difference error).
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 9)
// → Calls: services/shared/native-llm.js (anti-skill synthesis)
// → Calls: services/observe/event-ledger.js (replay events)
// Pipeline: DREAM_PIPELINE
// Position: failure batch replay
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Similarity threshold for grouping failures into clusters (hash-based grouping)
// Two failures share an error signature if their normalised error type matches
const ANTI_SKILL_KEY_PREFIX = 'anti_skill';

/**
 * Normalise an error string into a stable signature key.
 * Used to group related failures into clusters.
 *
 * @param {string} error - Raw error message
 * @returns {string} Normalised signature (lowercase, whitespace collapsed, truncated)
 */
function normaliseErrorSignature(error) {
  return String(error || '')
    .toLowerCase()
    .replace(/[^a-z0-9_:\- ]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
}

/**
 * Compute a temporal difference (surprise) score for a failure.
 * Failures that deviate most from expected outcomes score highest.
 *
 * Expected outcomes are approximated via confidence: a high-confidence
 * prediction that failed is maximally surprising.
 *
 * @param {Object} failure - Failure record with optional confidence field
 * @param {number} [failure.confidence] - Predicted confidence (0-1) before failure
 * @param {string} [failure.error_type] - Error category
 * @returns {number} Surprise score in [0, 1]
 */
export function getTemporalDifferenceError(failure) {
  if (!failure || typeof failure !== 'object') return 0.5;

  // TD error = |actual_outcome - predicted_outcome|
  // actual_outcome = 0 (failure), predicted_outcome = confidence
  const predicted = typeof failure.confidence === 'number'
    ? Math.max(0, Math.min(1, failure.confidence))
    : 0.5; // assume moderate confidence if unknown

  // High confidence + failure = high surprise
  return predicted;
}

/**
 * Extract a structured failure profile from an error and its context.
 *
 * @param {Error|Object|string} error - The error that occurred
 * @param {Object} context - Execution context at the time of failure
 * @param {string} [context.tool] - Tool that failed
 * @param {string} [context.strategy] - Strategy being attempted
 * @param {string} [context.input] - Input that triggered the failure
 * @returns {Promise<{root_cause_category: string, triggering_conditions: string, attempted_strategy: string, divergence_point: string}>}
 */
export async function extractFailureProfile(error, context) {
  const errorMsg = error instanceof Error
    ? error.message
    : (typeof error === 'string' ? error : JSON.stringify(error || {}));

  const ctx = context && typeof context === 'object' ? context : {};

  const prompt = `You are a failure analysis engine. Extract a structured failure profile.

ERROR:
${String(errorMsg).slice(0, 800)}

CONTEXT:
Tool: ${String(ctx.tool || 'unknown')}
Strategy: ${String(ctx.strategy || 'unknown')}
Input: ${String(ctx.input || '').slice(0, 400)}

Return ONLY a JSON object — no markdown, no explanation.
Output format:
{
  "root_cause_category": "<taxonomy: logic_error|data_error|tool_failure|permission_error|timeout|unknown>",
  "triggering_conditions": "<what specific conditions caused this>",
  "attempted_strategy": "<what approach was being tried>",
  "divergence_point": "<where execution deviated from the expected path>"
}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[failure-replay] extractFailureProfile LLM call failed:', err.message);
  }

  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(stripped);
    return {
      root_cause_category: String(parsed?.root_cause_category || 'unknown'),
      triggering_conditions: String(parsed?.triggering_conditions || ''),
      attempted_strategy: String(parsed?.attempted_strategy || ctx.strategy || ''),
      divergence_point: String(parsed?.divergence_point || ''),
    };
  } catch {
    return {
      root_cause_category: 'unknown',
      triggering_conditions: errorMsg.slice(0, 200),
      attempted_strategy: String(ctx.strategy || ''),
      divergence_point: '',
    };
  }
}

/**
 * Replay all failures for a company since a given timestamp, grouped by
 * error signature, extracting cross-task patterns.
 *
 * @param {string} [companyId]
 * @param {string|Date} [since] - ISO timestamp or Date; defaults to 7 days ago
 * @returns {Promise<Array<{signature: string, count: number, failures: Object[], pattern: string}>>}
 */
export async function replayFailuresBatch(companyId, since) {
  const cid = companyId || COMPANY;
  const sinceDate = since
    ? (since instanceof Date ? since : new Date(since))
    : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  let rows;
  try {
    const result = await query(
      `SELECT id, operation, key, metadata, ts
       FROM aimos_events
       WHERE company_id = $1
         AND operation IN ('error', 'failure', 'tool_failure', 'task_failure')
         AND ts >= $2
       ORDER BY ts DESC
       LIMIT 500`,
      [cid, sinceDate.toISOString()]
    );
    rows = result.rows;
  } catch (err) {
    console.error('[failure-replay] replayFailuresBatch DB error:', err.message);
    return [];
  }

  if (!rows.length) return [];

  // Group by normalised error signature
  const clusters = new Map();
  for (const row of rows) {
    let metadata = {};
    try {
      metadata = typeof row.metadata === 'string'
        ? JSON.parse(row.metadata)
        : (row.metadata || {});
    } catch { metadata = {}; }

    const errorText = metadata.error || metadata.message || row.key || row.operation;
    const signature = normaliseErrorSignature(errorText);

    if (!clusters.has(signature)) {
      clusters.set(signature, { signature, count: 0, failures: [] });
    }
    const cluster = clusters.get(signature);
    cluster.count++;
    cluster.failures.push({ id: row.id, operation: row.operation, key: row.key, metadata, ts: row.ts });
  }

  // Sort clusters by frequency descending, extract cross-task patterns
  const sortedClusters = Array.from(clusters.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 20); // top 20 clusters

  // Extract pattern for each cluster via LLM
  const enriched = await Promise.all(
    sortedClusters.map(async (cluster) => {
      const sampleErrors = cluster.failures.slice(0, 5)
        .map((f) => JSON.stringify(f.metadata).slice(0, 150))
        .join('\n');

      const patternPrompt = `Identify the cross-task failure pattern from these error samples.
Samples:
${sampleErrors}

Return ONE concise sentence describing the common pattern. No JSON needed.`;

      let pattern = '';
      try {
        pattern = await runProvider({ prompt: patternPrompt });
        pattern = (pattern || '').trim().slice(0, 300);
      } catch {
        pattern = `Repeated failure: ${cluster.signature}`;
      }

      return { ...cluster, pattern };
    })
  );

  return enriched;
}

/**
 * Generate an anti-skill memory from a failure cluster and save it to Aimos.
 * Anti-skills are procedural memories encoding what NOT to do.
 *
 * @param {Object} failureCluster - Output from replayFailuresBatch
 * @param {string} failureCluster.signature - Error signature
 * @param {number} failureCluster.count - Number of occurrences
 * @param {string} failureCluster.pattern - Cross-task pattern description
 * @param {Array} failureCluster.failures - Raw failure records
 * @param {string} [companyId]
 * @returns {Promise<{key: string, saved: boolean}>}
 */
export async function generateAntiSkill(failureCluster, companyId) {
  const cid = companyId || COMPANY;

  if (!failureCluster?.signature) {
    return { key: null, saved: false };
  }

  const prompt = `You are a skill consolidation engine. Create an anti-skill from a failure pattern.

FAILURE PATTERN: ${String(failureCluster.pattern || '').slice(0, 400)}
ERROR SIGNATURE: ${String(failureCluster.signature).slice(0, 200)}
OCCURRENCE COUNT: ${failureCluster.count}

Return ONLY a JSON object — no markdown, no explanation.
Output format:
{
  "anti_skill_name": "<short descriptive name>",
  "what_not_to_do": "<specific behaviour to avoid>",
  "why_it_fails": "<mechanism of failure>",
  "safe_alternative": "<what to do instead>",
  "applicability": "<when this anti-skill applies>"
}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[failure-replay] generateAntiSkill LLM call failed:', err.message);
  }

  let antiSkillContent;
  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    antiSkillContent = JSON.parse(stripped);
  } catch {
    antiSkillContent = {
      anti_skill_name: failureCluster.signature.slice(0, 60),
      what_not_to_do: failureCluster.pattern || '',
      why_it_fails: 'Repeated failure pattern',
      safe_alternative: '',
      applicability: 'general',
    };
  }

  // Compute surprise score for prioritisation
  const surpriseScore = failureCluster.failures.length > 0
    ? getTemporalDifferenceError(failureCluster.failures[0].metadata || {})
    : 0.5;

  const key = `${ANTI_SKILL_KEY_PREFIX}:${failureCluster.signature.slice(0, 60).replace(/\s+/g, '_')}`;
  const value = JSON.stringify({
    ...antiSkillContent,
    error_signature: failureCluster.signature,
    occurrence_count: failureCluster.count,
    td_surprise_score: surpriseScore,
    generated_at: new Date().toISOString(),
  });

  try {
    await persistMemory({
      company_id: cid,
      agent_id: 'failure-replay',
      mutation_authority: 'housekeeper',
      key,
      value,
      scope: 'global',
      memory_type: 'procedural',
      clearance_level: 3
    });

    await logEvent(cid, 'failure-replay', 'anti_skill_generated', key, {
      reasoning: `Anti-skill generated from ${failureCluster.count} failure(s). Pattern: ${failureCluster.pattern?.slice(0, 100) || failureCluster.signature}`,
      signature: failureCluster.signature,
      occurrenceCount: failureCluster.count,
      tdSurpriseScore: surpriseScore,
    });

    return { key, saved: true };
  } catch (err) {
    console.error('[failure-replay] generateAntiSkill save error:', err.message);
    return { key, saved: false };
  }
}
