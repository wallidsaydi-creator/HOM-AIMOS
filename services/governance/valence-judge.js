// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (diagnostic-only when governors OFF) — computeValence is
// callable from the governors (cohen-grossberg-energy-governor.js,
// signed valence reference-point updater). When governor flags are OFF, the judge
// is still called for telemetry but drives no weight updates. The judge
// reads from memory_valence_ledger (migration 023) via valence-ledger.js.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * valence-judge.js — evidence-weighted tanh valence judge (Aimos-2 / Paper 2)
 *
 * Definition (see DERIVATION-dynamic-mutation-governors.md §4):
 *
 *   j_i = tanh( Σ_ℓ r_{i,ℓ} )
 *
 * where:
 *   . r_{i,ℓ} ∈ {-1, +1}    is the reward sign for the ℓ-th event on memory i
 * Every recorded outcome remains evidence. Time is not a coefficient.
 *
 * Properties (proved in the derivation):
 *   P1: j_i : R → [-1, 1] — bounded (tanh). Licenses CG Hypothesis (d)
 *       Lipschitz bound |b_i(x) - b_i(y)| ≤ |x - y| since |j_i| ≤ 1.
 *   P2: j_i ∈ C^∞ — smooth, no discontinuous valence flips.
 *   P3: evidence monotonicity — each retained positive or negative outcome
 *       contributes one unit. Time is not a coefficient.
 *   P4: j_i = 0 when no reward events in lookback — static fallback
 *       (governors fall back to existing R_TARGET behavior, bit-exact).
 *   P5: changes only when a new signed outcome is appended. There is no
 *       time-driven drift or evidence expiry.
 *
 * Source paper: signed-evidence tanh (HOM native) — derivation in
 *   `Book batches /Cogpaper/DERIVATION-dynamic-mutation-governors.md`
 *
 * Pure function over the ledger query result — no side effects, no weight
 * writes. The governors are responsible for any mutation; the judge only
 * computes the valence scalar in [-1, 1].
 */

import { valenceLedger } from './valence-ledger.js';

export const VALENCE_JUDGE_CONSTANTS = Object.freeze({
  SOURCE_PAPER: 'signed-evidence tanh (HOM native, age-neutral)'
});

/**
 * Compute the valence judge scalar for a memory.
 *
 * @param {string} memoryId — UUID string
 * @param {object} [opts]
 * @param {object} [opts.ledger] — dependency-injected ledger (for tests)
 * @returns {Promise<number>} — valence in [-1, 1]; 0 if no events
 */
export async function computeValence(memoryId, opts = {}) {
  if (typeof memoryId !== 'string' || memoryId.length === 0) return 0;

  const ledger = opts.ledger || valenceLedger;

  const events = await ledger.readValenceEvents(memoryId, { client: opts.client || null });
  if (!events.length) return 0;  // P4: static fallback

  let sum = 0;
  for (const ev of events) {
    const r = Number(ev.reward_sign);
    if (r !== 1 && r !== -1) continue;
    sum += r * Number(ev.evidence_count || 1);
  }

  return Math.tanh(sum);  // bounded in [-1, 1] (P1)
}

export default { computeValence, VALENCE_JUDGE_CONSTANTS };
