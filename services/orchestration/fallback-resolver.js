/**
 * fallback-resolver.js — Partial Answer Extraction
 * Source: Graceful Degradation patterns, Circuit Breaker fallback chain
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: governance-resolver.js
 * 2. → Pulls from: Intermediate deliberation results (Shared context)
 * 3. → Benefits: All agents (Prevents zero-response failures)
 * 4. ↔ Interacts with: agent-runner.js (Final answer assembly)
 *
 * LOGIC GUIDE: Extracts the best partial answer when orchestration hits 
 * budget or timeout. Ranks by completeness and confidence to maximize utility.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
/**
 * FALLBACK RESOLVER — EXTRACT BEST PARTIAL ANSWER UNDER BUDGET/TIMEOUT
 *
 * When orchestration hits budget or timeout constraints, extracts the best
 * partial answer from intermediate results rather than returning nothing.
 * Ranks by completeness and confidence to maximize utility.
 *
 * Created: 2026-03-31
 */

/**
 * Resolve fallback when orchestration is exhausted
 * Returns the best partial answer available.
 *
 * @param {object} intermediateResults - Map of stage outputs
 * @param {object} budget - Budget constraints {elapsed, remaining, maxTime}
 * @returns {{partial_answer: any, confidence: number, source_stage: string, completeness_ratio: number}}
 */
export function resolveFallback(intermediateResults, budget) {
  if (!intermediateResults || typeof intermediateResults !== 'object') {
    return {
      partial_answer: null,
      confidence: 0,
      source_stage: 'none',
      completeness_ratio: 0
    };
  }

  // Score each result by completeness and confidence
  const candidates = [];

  for (const [stage, result] of Object.entries(intermediateResults)) {
    if (!result) continue;

    const score = scoreResult(result);
    if (score.completeness > 0 || score.confidence > 0) {
      candidates.push({
        stage,
        result,
        completeness: score.completeness,
        confidence: score.confidence,
        combined: score.completeness * 0.6 + score.confidence * 0.4
      });
    }
  }

  if (candidates.length === 0) {
    return {
      partial_answer: null,
      confidence: 0,
      source_stage: 'none',
      completeness_ratio: 0
    };
  }

  // Sort by combined score (completeness weighted 60%, confidence 40%)
  candidates.sort((a, b) => b.combined - a.combined);
  const best = candidates[0];

  return {
    partial_answer: extractAnswer(best.result),
    confidence: best.confidence,
    source_stage: best.stage,
    completeness_ratio: best.completeness
  };
}

/**
 * Score a result for completeness and confidence
 *
 * @param {any} result - Result object to score
 * @returns {{completeness: number, confidence: number}}
 */
function scoreResult(result) {
  let completeness = 0;
  let confidence = 0;

  if (typeof result === 'object' && result !== null) {
    // Check for completeness indicators
    if (result.answer || result.output || result.response) {
      completeness += 0.7;
    }
    if (result.reasoning || result.steps || result.trace) {
      completeness += 0.2;
    }

    // Check for confidence indicators
    if (result.confidence !== undefined) {
      confidence = Math.max(0, Math.min(1, Number(result.confidence)));
    } else if (result.score !== undefined) {
      confidence = Math.max(0, Math.min(1, Number(result.score)));
    } else if (result.success) {
      confidence = 0.8;
    } else {
      confidence = 0.5;
    }
  } else if (typeof result === 'string' && result.length > 0) {
    completeness = 0.6;
    confidence = 0.6;
  }

  // Cap at 1.0
  completeness = Math.min(1.0, completeness);
  confidence = Math.min(1.0, confidence);

  return { completeness, confidence };
}

/**
 * Extract answer from result object
 *
 * @param {any} result - Result object
 * @returns {any}
 */
function extractAnswer(result) {
  if (!result) return null;

  // Try common answer field names
  if (result.answer) return result.answer;
  if (result.output) return result.output;
  if (result.response) return result.response;
  if (result.result) return result.result;

  // If result is string, return it
  if (typeof result === 'string') return result;

  // Return whole object as last resort
  return result;
}

/**
 * Check if orchestration is exhausted
 * Returns true if budget/timeout is exceeded or routing limit hit.
 *
 * @param {number} elapsed - Elapsed time in ms
 * @param {number} budget - Budget in ms
 * @param {number} routingCount - Number of routing steps taken
 * @returns {boolean}
 */
export function isOrchestrationExhausted(elapsed, budget, routingCount) {
  const maxRouting = 15;
  const timeThreshold = 0.9; // Exhaust at 90% of budget

  if (elapsed >= budget * timeThreshold) {
    return true;
  }

  if (routingCount >= maxRouting) {
    return true;
  }

  return false;
}

/**
 * Get exhaustion reason for logging
 *
 * @param {number} elapsed - Elapsed time in ms
 * @param {number} budget - Budget in ms
 * @param {number} routingCount - Number of routing steps
 * @returns {string}
 */
export function getExhaustionReason(elapsed, budget, routingCount) {
  const maxRouting = 15;
  const timeThreshold = 0.9;

  if (elapsed >= budget * timeThreshold) {
    return `Time budget exhausted: ${elapsed}ms / ${budget}ms`;
  }

  if (routingCount >= maxRouting) {
    return `Routing limit exceeded: ${routingCount} / ${maxRouting} steps`;
  }

  return 'Unknown exhaustion reason';
}

/**
 * Prepare fallback result with metadata
 *
 * @param {any} fallbackAnswer - Fallback answer
 * @param {string} reason - Reason for fallback
 * @param {object} originalBudget - Original budget info
 * @returns {object}
 */
export function prepareFallbackResult(fallbackAnswer, reason, originalBudget) {
  return {
    answer: fallbackAnswer,
    is_fallback: true,
    fallback_reason: reason,
    fallback_at: new Date().toISOString(),
    budget_info: originalBudget,
    completeness: fallbackAnswer ? 0.6 : 0,
    confidence: fallbackAnswer ? 0.5 : 0
  };
}

/**
 * Merge multiple intermediate results into single fallback
 *
 * @param {Array} results - Array of result objects from different stages
 * @returns {object}
 */
export function mergePartialResults(results) {
  if (!Array.isArray(results) || results.length === 0) {
    return { merged: null, count: 0 };
  }

  const merged = {
    answers: [],
    reasoning: [],
    metadata: {
      sources: [],
      mergedAt: new Date().toISOString()
    }
  };

  for (const result of results) {
    if (!result) continue;

    if (result.answer) merged.answers.push(result.answer);
    if (result.reasoning) merged.reasoning.push(result.reasoning);
    if (result.stage) merged.metadata.sources.push(result.stage);
  }

  return {
    merged,
    count: results.length,
    completeness: merged.answers.length > 0 ? 0.7 : 0
  };
}
