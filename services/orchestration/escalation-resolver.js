// ═══════════════════════════════════════════════════════════════════════════════
// ESCALATION RESOLVER (escalation-resolver.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Source: Progressive difficulty (curriculum learning), Cascaded retrieval
// P1-2: Failure-Triggered Escalation
//
// Replaces QMD auto-switch heuristic with failure-triggered, diagnostic-driven
// escalation. The escalation engine operates on the ERROR DIAGNOSTIC, not the
// original query, so each tier can address the actual failure mode.
//
// Three tiers:
//   fast    — rule-based BM25/lightweight (free, default)
//   deep    — semantic repair via embedding + larger model (cheap)
//   causal  — causal reflection via expensive LLM (costly, rate-limited)
//
// Infinite loop prevention: caps escalation count per query at MAX_ESCALATIONS.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (post-run step 39)
// → Calls: services/shared/native-llm.js (deep/causal escalation LLM call)
// Pipeline: AGENT_RUN_PIPELINE
// Position: escalation resolution
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';
import { buildCooperativeActionArbitrationDiagnostics } from './cooperative-action-arbitration.js';

const COMPANY = AIMOS_COMPANY_ID;

// Escalation tiers in order
const TIERS = ['fast', 'deep', 'causal'];

// Maximum escalations per unique query before forcing a final answer
const MAX_ESCALATIONS = 3;

// In-memory escalation counter: queryHash → count
// Intentionally process-scoped (not persisted) to prevent cascading retries
const _escalationCounts = new Map();

/**
 * Generate a stable hash key for a query string (simple, non-crypto).
 *
 * @param {string} query
 * @returns {string}
 */
function hashQuery(query) {
  let h = 0;
  const s = String(query || '');
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return String(h >>> 0);
}

/**
 * Determine whether escalation is warranted based on failure information.
 * Returns false if the query has already been escalated MAX_ESCALATIONS times.
 *
 * @param {Object} failureInfo - Failure metadata from the previous tier
 * @param {string} failureInfo.type - e.g. 'no_results', 'low_confidence', 'parse_error'
 * @param {number} [failureInfo.confidence] - 0-1 confidence of previous result
 * @param {string} [failureInfo.error] - Error message if applicable
 * @param {string} queryHash - Hash of the original query
 * @returns {boolean}
 */
export function shouldEscalate(failureInfo, queryHash) {
  if (!failureInfo || typeof failureInfo !== 'object') return false;

  const count = _escalationCounts.get(queryHash) || 0;
  if (count >= MAX_ESCALATIONS) {
    console.warn(`[escalation-resolver] MAX_ESCALATIONS (${MAX_ESCALATIONS}) reached for query ${queryHash}`);
    return false;
  }

  // Definite escalation triggers
  if (failureInfo.type === 'no_results') return true;
  if (failureInfo.type === 'parse_error') return true;
  if (failureInfo.type === 'timeout') return true;
  if (typeof failureInfo.confidence === 'number' && failureInfo.confidence < 0.4) return true;
  if (failureInfo.error && String(failureInfo.error).length > 0) return true;

  return false;
}

export { buildCooperativeActionArbitrationDiagnostics };

/**
 * Perform semantic repair — use a mid-tier LLM to reframe the diagnostic into
 * a better query for the deep retrieval pass.
 *
 * @param {string} originalQuery
 * @param {Object} failureInfo
 * @returns {Promise<{repairedQuery: string, reasoning: string}>}
 */
async function semanticRepair(originalQuery, failureInfo) {
  const diagnostic = JSON.stringify(failureInfo, null, 2);
  const prompt = `You are a query repair agent. A retrieval query failed. Repair it.

ORIGINAL QUERY:
${String(originalQuery).slice(0, 1000)}

FAILURE DIAGNOSTIC:
${diagnostic.slice(0, 500)}

Return ONLY a JSON object — no markdown, no explanation.
Output: {"repairedQuery": "<improved query>", "reasoning": "<why this repair helps>"}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[escalation-resolver] semanticRepair LLM call failed:', err.message);
    return { repairedQuery: originalQuery, reasoning: 'LLM call failed — using original' };
  }

  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(stripped);
    return {
      repairedQuery: String(parsed?.repairedQuery || originalQuery),
      reasoning: String(parsed?.reasoning || ''),
    };
  } catch {
    return { repairedQuery: originalQuery, reasoning: 'Parse failed — using original' };
  }
}

/**
 * Perform causal reflection — expensive LLM call to diagnose root cause and
 * produce a causal explanation for why previous tiers failed.
 *
 * @param {string} originalQuery
 * @param {*} previousResult
 * @param {Object} failureInfo
 * @returns {Promise<{causalAnalysis: string, suggestedFix: string}>}
 */
async function causalReflection(originalQuery, previousResult, failureInfo) {
  const prompt = `You are a causal failure analyst. Multiple retrieval attempts failed. Identify the root cause.

ORIGINAL QUERY: ${String(originalQuery).slice(0, 800)}
PREVIOUS RESULT: ${JSON.stringify(previousResult || null).slice(0, 400)}
FAILURE INFO: ${JSON.stringify(failureInfo || {}).slice(0, 400)}

Return ONLY a JSON object — no markdown, no explanation.
Output: {"causalAnalysis": "<root cause>", "suggestedFix": "<how to resolve>"}`;

  let raw = '';
  try {
    raw = await runProvider({ prompt });
  } catch (err) {
    console.error('[escalation-resolver] causalReflection LLM call failed:', err.message);
    return { causalAnalysis: 'LLM call failed', suggestedFix: 'Manual inspection required' };
  }

  try {
    const stripped = raw.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(stripped);
    return {
      causalAnalysis: String(parsed?.causalAnalysis || ''),
      suggestedFix: String(parsed?.suggestedFix || ''),
    };
  } catch {
    return { causalAnalysis: raw.slice(0, 400), suggestedFix: '' };
  }
}

/**
 * Resolve the appropriate escalation tier for a failed query.
 * Feeds the ERROR DIAGNOSTIC (not the original query) into the escalated tier.
 *
 * @param {string} query - Original query string
 * @param {*} previousResult - Result from the previous tier (may be null/empty)
 * @param {Object} failureInfo - Failure metadata: { type, confidence, error }
 * @param {string} [companyId]
 * @returns {Promise<{escalated: boolean, tier: 'fast'|'deep'|'causal', diagnostics: Object}>}
 */
export async function resolveEscalation(query, previousResult, failureInfo, companyId) {
  const cid = companyId || COMPANY;
  const queryHash = hashQuery(query);

  const escalate = shouldEscalate(failureInfo, queryHash);
  if (!escalate) {
    return {
      escalated: false,
      tier: 'fast',
      diagnostics: {
        reason: 'no_escalation_needed',
        escalationCount: _escalationCounts.get(queryHash) || 0,
      },
    };
  }

  // Increment escalation counter
  const currentCount = (_escalationCounts.get(queryHash) || 0) + 1;
  _escalationCounts.set(queryHash, currentCount);

  // Determine target tier based on escalation count
  // 1st escalation → deep, 2nd → causal, 3rd → causal (final attempt)
  const tierIndex = Math.min(currentCount, TIERS.length - 1);
  const targetTier = TIERS[tierIndex];

  let diagnostics = {
    escalationCount: currentCount,
    failureType: failureInfo?.type || 'unknown',
    previousConfidence: failureInfo?.confidence ?? null,
  };

  if (targetTier === 'deep') {
    const repair = await semanticRepair(query, failureInfo);
    diagnostics = { ...diagnostics, ...repair };
  } else if (targetTier === 'causal') {
    const reflection = await causalReflection(query, previousResult, failureInfo);
    diagnostics = { ...diagnostics, ...reflection };
  }

  await logEvent(cid, 'escalation-resolver', 'escalation_triggered', query.slice(0, 80), {
    reasoning: `Query escalated to '${targetTier}' tier after ${currentCount} failure(s). Failure type: ${failureInfo?.type || 'unknown'}`,
    tier: targetTier,
    escalationCount: currentCount,
    failureInfo,
  });

  return { escalated: true, tier: targetTier, diagnostics };
}
