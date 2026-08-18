// ─── SAVE RESPONSE ENVELOPE (uniform contract) ──────────────────────────────
// Status: Pure formatter — no I/O, no mutations.
// Purpose: One save-response shape for every endpoint that persists to
//          aimos_memories. Eliminates the /save (full envelope) vs
//          /reasoning-state (3-key minimal) drift documented in
//          aimos-llm-guide.md §24 "Save Response Inconsistency".
// Contract: A SUPERSET of every prior shape — no legacy key removed.
//          Old clients reading `saved`, `key`, `memory_id` keep working.
//          New clients can rely on `success`, `memory_tier`, `quarantined`,
//          `correction_applied`, `rpe`, `encoding_style`.
// Source:  Internal API hygiene (one contract, telemetry-keyed by mode).
// Compliance: Knowledge Gate [—] (formatter only) | Aladdin Law [X]
// ─────────────────────────────────────────────────────────────────────────────

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (/reasoning-state POST; future /save migration)
// → Calls: nothing (pure function)
// Pipeline: SAVE_PIPELINE
// Position: response shaping (post-persist)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a uniform save-response envelope from a persistMemory() result.
 *
 * Both `success` and `saved` are emitted (they always agree) so existing
 * clients of either contract keep working without changes.
 *
 * @param {object|null} persistResult - The dict returned by persistMemory().
 *   Expected fields (all optional): { id, key, rejected, reason, memory_tier,
 *   quarantined, correction_applied, rpe, encoding_style }.
 * @param {object} [opts]
 * @param {'full'|'lightweight'} [opts.mode='full'] - Telemetry tag for the
 *   calling endpoint. 'lightweight' marks endpoints (e.g. /reasoning-state)
 *   whose historical contract was the 3-key minimal shape; the envelope is
 *   still complete, the tag just lets dashboards distinguish call sites.
 * @param {object} [opts.extras] - Endpoint-specific fields to merge in
 *   (e.g. /save adds gate results that aren't part of the universal shape).
 * @returns {object} Uniform save envelope.
 */
export function buildSaveEnvelope(persistResult, opts = {}) {
  const { mode = 'full', extras = {} } = opts;
  const result = persistResult || {};
  const ok = !result.rejected;
  const env = {
    success: ok,
    saved: ok,
    key: result.key ?? null,
    memory_id: result.id ?? null,
    memory_tier: result.memory_tier ?? null,
    quarantined: Boolean(result.quarantined),
    correction_applied: Boolean(result.correction_applied),
    rpe: result.rpe ?? null,
    encoding_style: result.encoding_style ?? null,
    occurrence_reasserted: result.occurrence_reasserted === true,
    occurrence_event_id: result.save_feedback?.occurrence_event_id ?? null,
    occurrence_commitment: result.save_feedback?.occurrence_commitment ?? null,
    retrieval_vote_added: result.occurrence_reasserted === true ? false : null,
  };
  if (!ok) {
    env.reason = result.reason ?? null;
  }
  if (mode === 'lightweight' || mode === 'full') {
    env.response_mode = mode;
  }
  return { ...env, ...extras };
}
