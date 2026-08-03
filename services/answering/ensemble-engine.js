/**
 * M3 Ensemble Answer Engine
 * Source: ES-LLMs — Ensemble of Specialized LLMs (SUTD, 2026)
 *
 * Runs 3+ prompt variants in parallel via Promise.all, then aggregates
 * their answers into a single high-confidence response.
 *
 * Aggregation modes:
 *   'any-correct'   — return the highest-weighted valid (non-NOT_FOUND) answer.
 *                     Best for factual queries where one variant will nail it.
 *   'majority-vote' — normalise all answers, group by content, weight-sum each
 *                     group, pick the group with the highest total weight.
 *                     Best for ambiguous or multi-inference queries.
 *
 * Returns:
 *   {
 *     answer: string,
 *     confidence: number,          // 0–1 fraction of valid / total variants
 *     mode: string,
 *     variantResults: [{ id, answer, error }],
 *     validCount: number,
 *     totalVariants: number,
 *     latencyMs: number
 *   }
 *
 * @module services/answering/ensemble-engine
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: asmr-pipeline.js, v1-api.js
// → Calls: prompt-variants.js, shared/native-llm.js
// Pipeline: ASMR | Position: Final stage (answer synthesis)
// ─────────────────────────────────────────────────────────────────────────────
import { VARIANTS, STANDARD_VARIANTS, buildVariantPrompt } from './prompt-variants.js';
import { callNativeLlm } from '../shared/native-llm.js';
import { getCalibrationFactor } from '../learning/agent-learning.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const NOT_FOUND_SENTINEL = 'NOT_FOUND';
const FALLBACK_ANSWER = 'Unable to determine from available evidence.';

// ─── Core runner ─────────────────────────────────────────────────────────────

/**
 * Call the configured native provider for a single variant.
 * Returns the raw answer string, or throws on provider error.
 *
 * @param {Object} variant
 * @param {string} query
 * @param {Array}  evidence
 * @param {Object} opts
 * @returns {Promise<string>}
 */
async function runVariant(variant, query, evidence, opts = {}) {
  const { system, user } = buildVariantPrompt(variant, query, evidence);
  const answer = await callNativeLlm({
    systemPrompt: system,
    userPrompt: user,
    provider: opts.provider,
    model: opts.model
  });

  return typeof answer === 'string' ? answer.trim() : String(answer || '').trim();
}

// ─── Aggregation helpers ──────────────────────────────────────────────────────

/**
 * Normalise an answer for grouping in majority-vote mode.
 * Lowercase, collapse whitespace, strip trailing punctuation.
 *
 * @param {string} text
 * @returns {string}
 */
function normalise(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[.,;:!?]+$/, '')
    .trim();
}

/**
 * Check whether an answer is a valid (non-sentinel) response.
 *
 * @param {string|null} answer
 * @returns {boolean}
 */
function isValid(answer) {
  if (!answer) return false;
  const n = normalise(answer);
  return n.length > 0 && n !== normalise(NOT_FOUND_SENTINEL);
}

/**
 * Aggregate via 'any-correct': return the highest-weighted valid answer.
 *
 * @param {Array<{variantId, answer, weight}>} responses
 * @param {Array<{weight: number}>}            variants
 * @returns {{ finalAnswer: string, confidence: number }}
 */
function aggregateAnyCorrect(responses, variants) {
  const valid = responses
    .filter(r => isValid(r.answer))
    .sort((a, b) => b.weight - a.weight);

  const finalAnswer = valid[0]?.answer || FALLBACK_ANSWER;
  const confidence  = variants.length > 0 ? valid.length / variants.length : 0;

  return { finalAnswer, confidence };
}

/**
 * Aggregate via 'majority-vote': group normalised answers, weight-sum each,
 * pick the winner, return the original-cased answer from the winning group.
 *
 * @param {Array<{variantId, answer, weight}>} responses
 * @param {Array<{weight: number}>}            variants
 * @returns {{ finalAnswer: string, confidence: number }}
 */
function aggregateMajorityVote(responses, variants) {
  const valid = responses.filter(r => isValid(r.answer));

  if (valid.length === 0) {
    return { finalAnswer: FALLBACK_ANSWER, confidence: 0 };
  }

  // Build weight-sum map: normalised text → { totalWeight, firstOriginal }
  const groups = new Map();
  for (const r of valid) {
    const key = normalise(r.answer);
    if (!groups.has(key)) {
      groups.set(key, { totalWeight: 0, firstOriginal: r.answer });
    }
    groups.get(key).totalWeight += r.weight;
  }

  // Pick winning group
  const totalVariantWeight = variants.reduce((s, v) => s + (v.weight || 1), 0);
  const winner = [...groups.entries()].sort((a, b) => b[1].totalWeight - a[1].totalWeight)[0];

  const finalAnswer = winner[1].firstOriginal;
  const confidence  = totalVariantWeight > 0 ? winner[1].totalWeight / totalVariantWeight : 0;

  return { finalAnswer, confidence };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Run the ensemble engine against a query and evidence bundle.
 *
 * @param {string} query    - User question
 * @param {Array}  evidence - Evidence array from retrieval-orchestrator
 * @param {Object} [opts]
 * @param {Array}  [opts.variants]  - Override variant list (takes precedence over quality)
 * @param {string} [opts.quality]   - Quality tier: 'fast' | 'standard' | 'thorough'
 *                                    'fast'     → 1 variant (precise only)
 *                                    'standard' → 2 variants (precise + temporal)
 *                                    'thorough' → 3 variants (all) — default when unset
 * @param {string} [opts.mode]      - 'any-correct' | 'majority-vote' (default: 'any-correct')
 * @param {string} [opts.model]     - Override LLM model
 * @param {string} [opts.provider]  - Override LLM provider
 * @param {Function} [opts.llmFn]   - Inject mock LLM fn for testing: (variant, query, evidence, opts) => string
 *
 * @returns {Promise<{
 *   answer: string,
 *   confidence: number,
 *   mode: string,
 *   variantResults: Array<{id: string, answer: string|null, error: string|null}>,
 *   validCount: number,
 *   totalVariants: number,
 *   latencyMs: number
 * }>}
 */
export async function runEnsemble(query, evidence, opts = {}) {
  const start = Date.now();
  const mode  = opts.mode || 'any-correct';
  const llmFn = typeof opts.llmFn === 'function' ? opts.llmFn : runVariant;

  // Resolve variant list — explicit override always wins.
  // Without an override, pick based on quality tier:
  //   'fast'     → precise only (1 variant)
  //   'standard' → precise + temporal (2 variants, drops contextual)
  //   'thorough' or unset → all 3
  let variants;
  if (Array.isArray(opts.variants)) {
    variants = opts.variants;
  } else if (opts.quality === 'fast') {
    variants = [VARIANTS.precise];
  } else if (opts.quality === 'standard') {
    variants = Array.from(STANDARD_VARIANTS);
  } else {
    // 'thorough' or no quality specified — use full set
    variants = Object.values(VARIANTS);
  }

  // Run all variants in parallel — individual errors are isolated
  const responses = await Promise.all(
    variants.map(async (variant) => {
      try {
        const answer = await llmFn(variant, query, evidence, opts);
        return {
          variantId: variant.id,
          answer:    answer || null,
          weight:    variant.weight ?? 1.0,
          error:     null
        };
      } catch (err) {
        return {
          variantId: variant.id,
          answer:    null,
          weight:    variant.weight ?? 1.0,
          error:     err.message
        };
      }
    })
  );

  // Aggregate
  let finalAnswer, confidence;
  if (mode === 'majority-vote') {
    ({ finalAnswer, confidence } = aggregateMajorityVote(responses, variants));
  } else {
    // Default: 'any-correct'
    ({ finalAnswer, confidence } = aggregateAnyCorrect(responses, variants));
  }

  const validCount = responses.filter(r => isValid(r.answer)).length;

  // ─── Confidence Calibration via recommendation_log outcome data ──────────
  const rawConfidence = confidence;
  let calibrationFactor = 1.0;
  try {
    calibrationFactor = await getCalibrationFactor('asmr-ensemble', 'recall');
  } catch { /* calibration data may not exist yet */ }
  const calibratedConfidence = Math.max(0.05, Math.min(0.99, rawConfidence * calibrationFactor));

  return {
    answer:    finalAnswer,
    confidence: calibratedConfidence,
    mode,
    variantResults: responses.map(r => ({
      id:     r.variantId,
      answer: r.answer ? r.answer.slice(0, 400) : null,
      error:  r.error
    })),
    validCount,
    totalVariants: variants.length,
    latencyMs: Date.now() - start
  };
}
