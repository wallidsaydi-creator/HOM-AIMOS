// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Shadow-first (flag-gated OFF via governor-config-ledger) —
// enforceEnergyBound is callable from spiced-consolidator.js
// runDreamConsolidation (line ~680) but is a no-op when the latest signed
// row in aimos_governor_config for COHEN_GROSSBERG_GOVERNOR has
// enabled=false (or no row exists). When enabled=true, computes the
// Cohen-Grossberg Lyapunov V over the top-K consolidation window and
// dampens only the next cycle's amplification surplus if V would increase
// (ΔV > 0); it never applies a factor below the identity transform. The
// decision is signed by the dedicated `housekeeper` system identity before
// its gamma can influence SPICED. Any later weight change is committed by
// SPICED in its own atomic provenance transaction. The flag toggle itself is
// a signed row in aimos_governor_config (migration 025).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * cohen-grossberg-energy-governor.js — bounded energy governor (Aimos-2)
 *
 * Math foundation (see DERIVATION-dynamic-mutation-governors.md §2):
 *
 * The Cohen-Grossberg system (Cohen83 eq 1):
 *   ẋ_i = a_i(x_i) [ b_i(x_i) - Σ_k c_ik d_k(x_k) ]
 *
 * HOM specialization under assumptions (A1)–(A5):
 *   . C symmetric non-negative (verified at concept-graph.js:276-281)
 *   . a_i = ALPHA_AMP = 1.0
 *   . d_i(x) = x (identity, strictly monotone)
 *   . b_i(x_i, t) = j_i(t) · (R_TARGET - x_i)
 *
 * Lyapunov function (Cohen83 eq 21, specialized):
 *   V(x, t) = -Σ_i j_i(t) · (R_TARGET·x_i - x_i²/2) + ½ Σ_{j,k} c_jk x_j x_k
 *
 * Within a fixed-judge epoch (licensed by η y² ≫ 1/τ, verified by ~3 orders
 * of magnitude at the Oja layer and ~11 at the CG layer):
 *   dV/dt = -Σ_j [ j_j(R_TARGET - x_j) - Σ_k c_jk x_k ]² ≤ 0  (Cohen83 eq 22)
 *
 * BOUNDEDNESS: V is unbounded below on R when any j_i < 0, so "bounded
 * attractor via V" is FALSE on the open domain. Boundedness is provided
 * by the Aladdin clamp onto compact [W_MIN, W_MAX]
 * via LEAST/GREATEST). CG governs the INTERIOR flow within an epoch; the
 * clamp guarantees the state stays in a compact set.
 *
 * Tier-A amplification-surplus dampening rule (Governor #1 action):
 *   When a candidate micro-cycle would increase V (ΔV = V_after - V_before > 0),
 *   apply γ_dampen = exp(-κ · max(0, ΔV)), floored at MAX_DAMPENING_GAMMA = 0.1.
 *   γ_dampen scales the next cycle's amplification surplus:
 *     γ_effective = 1 + γ_dampen(LTP_AMPLIFY_FACTOR - 1).
 *   Therefore γ_effective ∈ [1.03, 1.3], preserving the Aladdin invariant
 *   that energy governance cannot lower canonical retrieval weight.
 *
 * Flag: COHEN_GROSSBERG_GOVERNOR — live state in aimos_governor_config
 *       (migration 025, signed by housekeeper). Shadow-first default
 *       (no row → OFF). Toggle via scripts/identity/toggle-governor-flag.js.
 *
 * Source paper: Cohen-Grossberg 1983 (two-timescale, Aladdin-clamp bounded).
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import { computeValence } from './valence-judge.js';
import { governorConfigLedger } from './governor-config-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

export const CG_GOVERNOR_CONSTANTS = Object.freeze({
  ALPHA_AMP: 1.0,
  KAPPA: 10.0,
  ENERGY_GUARD_EPSILON: 1e-6,
  MAX_DAMPENING_GAMMA: 0.1,
  R_TARGET: 1.0,
  W_MIN: 0.1,
  W_MAX: 3.0,
  SOURCE_PAPER: 'Cohen-Grossberg 1983 (two-timescale, Aladdin-clamp bounded)'
});

async function isFlagOn() {
  return governorConfigLedger.readFlag('COHEN_GROSSBERG_GOVERNOR');
}

/**
 * Compute the Cohen-Grossberg Lyapunov function V over the candidate window.
 *
 * V(x, t) = -Σ_i j_i(t) · (R_TARGET·x_i - x_i²/2) + ½ Σ_{j,k} c_jk x_j x_k
 *
 * Within a fixed-judge epoch, this is a valid Lyapunov function and dV/dt ≤ 0.
 * Across epochs (valence updates), the equilibrium moves and the system
 * re-converges (two-timescale, licensed by η y² ≫ 1/τ).
 *
 * @param {Array<{ id: string, weight: number, valence: number }>} memories
 * @param {number[][]} C — concept-graph adjacency over the same indexing
 * @returns {number} V
 */
export function computeLyapunovV(memories, C) {
  if (!Array.isArray(memories) || memories.length === 0) return 0;
  const R = CG_GOVERNOR_CONSTANTS.R_TARGET;

  // First sum: -Σ_i j_i · (R·x_i - x_i²/2)
  let sum1 = 0;
  for (let i = 0; i < memories.length; i++) {
    const x_i = Number(memories[i]?.weight);
    if (!Number.isFinite(x_i)) continue;
    const j_i = Number(memories[i]?.valence);
    if (!Number.isFinite(j_i)) continue;
    sum1 += -j_i * (R * x_i - x_i * x_i / 2);
  }

  // Second sum: ½ Σ_{j,k} c_jk x_j x_k
  // C is symmetric non-negative (A1). Only lower-triangle needed for the
  // double sum, but we iterate the full matrix for clarity. C[j][k] = c_jk.
  let sum2 = 0;
  const n = memories.length;
  for (let j = 0; j < n; j++) {
    const x_j = Number(memories[j]?.weight);
    if (!Number.isFinite(x_j)) continue;
    if (!Array.isArray(C?.[j])) continue;
    for (let k = 0; k < n; k++) {
      const x_k = Number(memories[k]?.weight);
      if (!Number.isFinite(x_k)) continue;
      const c_jk = Number(C[j][k]);
      if (!Number.isFinite(c_jk) || c_jk <= 0) continue;
      sum2 += c_jk * x_j * x_k;
    }
  }
  sum2 *= 0.5;

  return sum1 + sum2;
}

/**
 * Compute ΔV = V_after - V_before.
 *
 * @param {number} V_before
 * @param {number} V_after
 * @returns {number} — positive means the candidate cycle would increase V
 *                    (departure from the epoch's equilibrium).
 */
export function computeDeltaV(V_before, V_after) {
  const a = Number(V_before);
  const b = Number(V_after);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return 0;
  return b - a;
}

/**
 * Tier-A dampening multiplier.
 *
 * γ_dampen = exp(-κ · max(0, ΔV)), floored at MAX_DAMPENING_GAMMA = 0.1.
 * Returns 1.0 (no dampening) when ΔV ≤ 0 (cycle moves toward equilibrium).
 *
 * @param {number} deltaV
 * @returns {number} γ_dampen ∈ [0.1, 1.0]
 */
export function computeDampenGamma(deltaV) {
  const dv = Number(deltaV);
  if (!Number.isFinite(dv) || dv <= 0) return 1.0;
  const gamma = Math.exp(-CG_GOVERNOR_CONSTANTS.KAPPA * dv);
  return Math.max(CG_GOVERNOR_CONSTANTS.MAX_DAMPENING_GAMMA, Math.min(1.0, gamma));
}

/**
 * Build the concept-graph adjacency matrix C for the candidate window.
 *
 * C is symmetric non-negative (A1) — built in-memory from the concept-graph
 * adjacency list, scoped to the top-K window (K ≤ 15). For a 15×15 matrix
 * this is 225 entries — trivial.
 *
 * @param {string[]} memoryIds
 * @returns {Promise<number[][]>} C[i][j] = c_ij ≥ 0
 */
async function buildConceptGraphMatrix(memoryIds) {
  if (!Array.isArray(memoryIds) || memoryIds.length === 0) return [];
  const n = memoryIds.length;

  // Initialize zero matrix
  const C = Array.from({ length: n }, () => new Array(n).fill(0));

  // Query concept-graph edges between candidates. The concept-graph schema
  // (migration 007-concept-edges.sql) stores edges as (source_id, target_id,
  // weight). We read edges where both endpoints are in the candidate window.
  const r = await query(
    `SELECT source_id, target_id, weight
       FROM concept_edges
      WHERE source_id = ANY($1::uuid[]) AND target_id = ANY($1::uuid[])`,
    [memoryIds]
  );

  const idToIdx = new Map();
  for (let i = 0; i < n; i++) idToIdx.set(memoryIds[i], i);

  for (const row of r?.rows || []) {
    const i = idToIdx.get(row.source_id);
    const k = idToIdx.get(row.target_id);
    if (i === undefined || k === undefined) continue;
    const w = Number(row.weight);
    if (!Number.isFinite(w) || w <= 0) continue;
    // Symmetric by construction (concept-graph.js:276-281 inserts both
    // directions). We set both entries to be robust to any asymmetry from
    // legacy rows.
    C[i][k] = w;
    C[k][i] = w;
  }

  return C;
}

/**
 * Load the current weights and compute valences for the candidate window.
 *
 * @param {string[]} memoryIds
 * @returns {Promise<Array<{ id: string, weight: number, valence: number }>>}
 */
async function loadWindowState(memoryIds) {
  if (!memoryIds.length) return [];
  const r = await query(
    `SELECT id, retrieval_weight
       FROM aimos_memories
      WHERE id = ANY($1::uuid[])`,
    [memoryIds]
  );
  const memories = [];
  for (const row of r?.rows || []) {
    const weight = Number(row.retrieval_weight);
    if (!Number.isFinite(weight)) continue;
    const valence = await computeValence(row.id);
    memories.push({ id: row.id, weight, valence });
  }
  return memories;
}

/**
 * Enforce the Cohen-Grossberg energy bound on the current consolidation cycle.
 *
 * This is the Governor #1 entry point. Called from spiced-consolidator.js
 * runDreamConsolidation after amplifyConsolidated and before edge formation.
 *
 * Algorithm:
 *   1. Load window state (weights + valences)
 *   2. Build C matrix
 *   3. Compute V_after (current state, post-amplification)
 *   4. Compute V_before (state with each weight rolled back to its
 *      pre-amplification value — caller passes via opts.previousWeights)
 *   5. ΔV = V_after - V_before; if ΔV > 0, γ_dampen = exp(-κ·ΔV), floored 0.1
 *   6. Return { γ_dampen, gate_logic_unchanged, source_paper }
 *
 * The caller (spiced-consolidator.js) applies γ_dampen to the NEXT cycle's
 * amplification surplus above 1.0. The resulting factor is never below 1.0.
 *
 * When the flag is OFF, returns γ_dampen = 1.0 (no dampening) — bit-exact
 * existing behavior.
 *
 * @param {string[]} candidateIds — top-K window (K ≤ 15)
 * @param {object} [opts]
 * @param {Map<string, number>} [opts.previousWeights] — memory_id → pre-amp weight
 * @returns {Promise<{ gamma_dampen: number, delta_v: number, gate_logic_unchanged: boolean, source_paper: string }>}
 */
export async function enforceEnergyBound(candidateIds, opts = {}) {
  if (!(await isFlagOn()) || !Array.isArray(candidateIds) || candidateIds.length === 0) {
    return {
      gamma_dampen: 1.0,
      delta_v: 0,
      gate_logic_unchanged: true,
      source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER
    };
  }

  try {
    const after = await loadWindowState(candidateIds);
    if (!after.length) {
      return {
        gamma_dampen: 1.0,
        delta_v: 0,
        gate_logic_unchanged: true,
        source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER
      };
    }
    const C = await buildConceptGraphMatrix(candidateIds);
    const V_after = computeLyapunovV(after, C);

    // V_before: state with each weight rolled back to its pre-amplification
    // value (passed by the caller). If the caller didn't pass previousWeights,
    // approximate V_before by scaling back by LTP_AMPLIFY (1.3×). The caller
    // SHOULD pass previousWeights for an exact ΔV.
    const previousWeights = opts.previousWeights instanceof Map ? opts.previousWeights : null;
    let V_before;
    if (previousWeights) {
      const beforeMemories = after.map(m => ({
        id: m.id,
        weight: previousWeights.get(m.id) ?? m.weight,
        valence: m.valence
      }));
      V_before = computeLyapunovV(beforeMemories, C);
    } else {
      // Approximate: roll back by /LTP_AMPLIFY (1.3×) — the spiced-consolidator
      // amplification factor at spiced-consolidator.js:64. Used only when the
      // caller didn't pass previousWeights.
      const LTP_AMPLIFY = 1.3;
      const beforeMemories = after.map(m => ({
        id: m.id,
        weight: m.weight / LTP_AMPLIFY,
        valence: m.valence
      }));
      V_before = computeLyapunovV(beforeMemories, C);
    }

    const deltaV = computeDeltaV(V_before, V_after);
    const gamma = computeDampenGamma(deltaV);

    // The signed decision receipt must commit before its gamma can influence
    // the next SPICED cycle. If the receipt fails, the catch path returns the
    // identity factor and no cognitive action occurs.
    const decisionEventId = await logEvent(COMPANY, 'cg_governor', 'energy_bound_check', null, {
      candidate_count: after.length,
      v_before: V_before,
      v_after: V_after,
      delta_v: deltaV,
      gamma_dampen: gamma,
      flag_on: true,
      source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER
    });

    return {
      gamma_dampen: gamma,
      delta_v: deltaV,
      v_before: V_before,
      v_after: V_after,
      decision_event_id: decisionEventId,
      gate_logic_unchanged: false,
      source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER
    };
  } catch (err) {
    // Any computation or receipt failure returns the identity factor. The
    // unsigned decision therefore has no cognitive effect. The error receipt
    // below is diagnostic only and is allowed to fail independently.
    await logEvent(COMPANY, 'cg_governor', 'error', null, {
      error: String(err?.message || err),
      stack: err?.stack
    }).catch(() => {});
    return {
      gamma_dampen: 1.0,
      delta_v: 0,
      gate_logic_unchanged: true,
      error: String(err?.message || err),
      source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER
    };
  }
}

export default {
  computeLyapunovV,
  computeDeltaV,
  computeDampenGamma,
  enforceEnergyBound,
  CG_GOVERNOR_CONSTANTS
};
