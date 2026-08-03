/**
 * M3 Ensemble Answer Engine — Prompt Variants
 * Source: ES-LLMs — Ensemble of Specialized LLMs (SUTD, 2026)
 *
 * Defines 3 specialist prompt variants for the ensemble answer engine.
 * Each variant approaches the same evidence bundle with a different
 * interpretive lens, allowing the ensemble to cross-validate answers.
 *
 * Variants:
 *   precise    — fact-only extraction, refuses to infer, weight 1.0
 *   temporal   — recency-focused, supersession-aware,   weight 0.9
 *   contextual — inference-permitted, completeness-first, weight 0.8
 *
 * @module services/answering/prompt-variants
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: ensemble-engine.js
// Pipeline: ASMR | Position: Ensemble dependency (variant definitions)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} Variant
 * @property {string} id     - Unique variant identifier
 * @property {string} system - System prompt text
 * @property {number} weight - Aggregation weight (0–1)
 */

/**
 * Registry of all available prompt variants.
 * Import and iterate over Object.values(VARIANTS) to run all three (thorough mode).
 *
 * @type {Record<string, Variant>}
 */
export const VARIANTS = Object.freeze({
  precise: {
    id: 'precise',
    system: `You are a precise fact retriever. Answer ONLY from the evidence provided. \
If the evidence does not contain a clear answer, respond with exactly: NOT_FOUND. \
Do not infer, speculate, or reason beyond what is explicitly stated. \
Be exact and brief — one sentence when possible.`,
    weight: 1.0
  },

  temporal: {
    id: 'temporal',
    system: `You are a temporal specialist. Focus on the most recent information in the evidence. \
If facts have changed over time, report the CURRENT state only. \
Evidence items marked [SUPERSEDED] represent outdated information — treat them as background \
context only and do NOT use them as the answer. \
If no current (non-superseded) evidence answers the question, respond with exactly: NOT_FOUND.`,
    weight: 0.9
  },

  contextual: {
    id: 'contextual',
    system: `You are a contextual reasoner. Use the evidence provided and make reasonable inferences \
where the evidence strongly implies an answer. Connect related information across evidence items. \
Provide a complete answer with enough context for the reader to understand. \
If the evidence is entirely absent or contradictory with no clear signal, respond with: NOT_FOUND.`,
    weight: 0.8
  }
});

/**
 * Standard-mode variant subset: precise + temporal only (2 variants).
 * Drops the contextual variant to save one CLI call on everyday queries.
 * Use this when opts.quality === 'standard' in the ensemble engine.
 *
 * @type {Variant[]}
 */
export const STANDARD_VARIANTS = Object.freeze([
  VARIANTS.precise,
  VARIANTS.temporal
]);

/**
 * Format a single evidence item for inclusion in a prompt.
 * Attaches a sequence number, optional date, and [SUPERSEDED] marker when applicable.
 *
 * Evidence item shape (from retrieval-orchestrator / fact-finder):
 *   { id, value, key, confidence, source, created_at, isLatest }
 *
 * @param {Object} item
 * @param {number} index - 1-based sequence number
 * @returns {string}
 */
function formatEvidenceItem(item, index) {
  const parts = [`[${index}] ${item.value || item.key || '(empty)'}`];

  // Attach date if present — prefer explicit `date` field, fall back to created_at
  const rawDate = item.date || item.created_at;
  if (rawDate) {
    // Trim to YYYY-MM-DD for readability
    const dateStr = String(rawDate).slice(0, 10);
    parts.push(`(${dateStr})`);
  }

  // Mark superseded items so the temporal variant can ignore them
  // isLatest === false means a newer correction exists
  if (item.isLatest === false || item.superseded === true) {
    parts.push('[SUPERSEDED]');
  }

  return parts.join(' ');
}

/**
 * Build the full system + user prompt for a given variant.
 *
 * @param {Variant}  variant  - One of the VARIANTS entries
 * @param {string}   query    - The user's question
 * @param {Array}    evidence - Evidence bundle from retrieval-orchestrator
 * @returns {{ system: string, user: string }}
 */
export function buildVariantPrompt(variant, query, evidence) {
  const items = Array.isArray(evidence) ? evidence : [];

  const evidenceText = items.length > 0
    ? items.map((e, i) => formatEvidenceItem(e, i + 1)).join('\n')
    : '(no evidence available)';

  const user = `Evidence:\n${evidenceText}\n\nQuestion: ${query}\n\nAnswer:`;

  return {
    system: variant.system,
    user
  };
}
