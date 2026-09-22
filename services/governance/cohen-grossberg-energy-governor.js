// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Dormant unless enabled by governor-config-ledger —
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
 *   . C symmetric non-negative (constructed from retained graph rows below)
 *   . a_i = ALPHA_AMP = 1.0
 *   . d_i(x) = x (identity, strictly monotone)
 *   . b_i(x_i, t) = j_i(t) · (R_TARGET - x_i)
 *
 * Lyapunov function (Cohen83 eq 21, specialized):
 *   V(x, t) = -Σ_i j_i(t) · (R_TARGET·x_i - x_i²/2) + ½ Σ_{j,k} c_jk x_j x_k
 *
 * For the continuous system with fixed C and fixed judge values only:
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
 * This discrete, next-cycle damping policy is not that continuous flow and
 * does not prove convergence or non-increasing energy for future cycles.
 * Before/after comparison uses one immutable graph/judge basis and exact
 * weights read under the native mutation transaction's writer locks.
 *
 * Flag: COHEN_GROSSBERG_GOVERNOR — live state in aimos_governor_config
 *       (migration 025, signed by housekeeper). Dormant default
 *       (no row → OFF). Toggle via scripts/identity/toggle-governor-flag.js.
 *
 * Source paper: Cohen-Grossberg 1983 (two-timescale, Aladdin-clamp bounded).
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../security/protocol/canonical-json.js';
import { logEvent, readVerifiedEventsByIds } from '../observe/event-ledger.js';
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
  SOURCE_PAPER: 'Cohen-Grossberg 1983 Eq.21 potential; HOM discrete next-cycle policy'
});

async function isFlagOn() {
  return governorConfigLedger.readFlag('COHEN_GROSSBERG_GOVERNOR');
}

/**
 * Compute the Cohen-Grossberg Lyapunov function V over the candidate window.
 *
 * V(x, t) = -Σ_i j_i(t) · (R_TARGET·x_i - x_i²/2) + ½ Σ_{j,k} c_jk x_j x_k
 *
 * This potential has the continuous derivative stated above only for the
 * specified flow with fixed C/j. No discrete or cross-epoch convergence claim.
 *
 * @param {Array<{ id: string, weight: number, valence: number }>} memories
 * @param {number[][]} C — concept-graph adjacency over the same indexing
 * @returns {number} V
 */
export function computeLyapunovV(memories, C) {
  if (!Array.isArray(memories) || !Array.isArray(C) || C.length !== memories.length
      || new Set(memories.map(m => m.id)).size !== memories.length
      || memories.some(m => typeof m.id !== 'string' || !m.id
        || !Number.isFinite(m.weight) || m.weight < 0.1 || m.weight > 3
        || !Number.isFinite(m.valence) || Math.abs(m.valence) > 1)
      || C.some(row => !Array.isArray(row) || row.length !== memories.length
        || row.some(value => !Number.isFinite(value) || value < 0))) {
    throw new Error('cg_window_state_invalid');
  }
  for (let i = 0; i < C.length; i++) for (let j = 0; j < C.length; j++) {
    if (C[i][j] !== C[j][i]) throw new Error('cg_matrix_not_symmetric');
  }
  const R = CG_GOVERNOR_CONSTANTS.R_TARGET;
  // Stable physical-ID summation makes joint row/matrix permutations bit-exact,
  // not merely approximately equal after floating-point re-association.
  const order = memories.map((_, i) => i).sort((a, b) => memories[a].id < memories[b].id ? -1 : 1);

  // First sum: -Σ_i j_i · (R·x_i - x_i²/2)
  let sum1 = 0;
  for (const i of order) {
    const x_i = Number(memories[i]?.weight);
    const j_i = Number(memories[i]?.valence);
    sum1 += -j_i * (R * x_i - x_i * x_i / 2);
  }

  // Second sum: ½ Σ_{j,k} c_jk x_j x_k
  // C is symmetric non-negative (A1). Only lower-triangle needed for the
  // double sum, but we iterate the full matrix for clarity. C[j][k] = c_jk.
  let sum2 = 0;
  for (const j of order) {
    const x_j = Number(memories[j]?.weight);
    for (const k of order) {
      const x_k = Number(memories[k]?.weight);
      const c_jk = Number(C[j][k]);
      sum2 += c_jk * x_j * x_k;
    }
  }
  sum2 *= 0.5;

  const value = sum1 + sum2;
  if (!Number.isFinite(value)) throw new Error('cg_energy_nonfinite');
  return value;
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
  if (typeof V_before !== 'number' || typeof V_after !== 'number') throw new Error('cg_energy_nonfinite');
  const a = Number(V_before);
  const b = Number(V_after);
  if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error('cg_energy_nonfinite');
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
  if (typeof deltaV !== 'number') throw new Error('cg_energy_nonfinite');
  const dv = Number(deltaV);
  if (!Number.isFinite(dv)) throw new Error('cg_energy_nonfinite');
  if (dv <= 0) return 1.0;
  const gamma = Math.exp(-CG_GOVERNOR_CONSTANTS.KAPPA * dv);
  return Math.max(CG_GOVERNOR_CONSTANTS.MAX_DAMPENING_GAMMA, Math.min(1.0, gamma));
}

/**
 * Build the exact induced signed associative graph, not a capped recall walk.
 *
 * S contains native SAVE/SPICED similarity values. C=(S+S^T)/2 preserves
 * x^T S x and is the unique Frobenius-nearest symmetric matrix. This local
 * coupling interpretation is not usefulness, truth, or a data mapping derived
 * from Cohen83. Unsigned legacy rows remain retained, with no authority here.
 *
 * @param {string[]} memoryIds
 * @returns {Promise<number[][]>} C[i][j] = c_ij ≥ 0
 */
async function buildConceptGraphMatrix(memoryIds, client) {
  const n = memoryIds.length;

  const S = Array.from({ length: n }, () => new Array(n).fill(0));
  const r = await client.query(
    `SELECT source_memory_id,target_memory_id,similarity,edge_type,authority_event_id
       FROM memory_cross_refs
      WHERE company_id=$2 AND source_memory_id = ANY($1::uuid[]) AND target_memory_id = ANY($1::uuid[])
      ORDER BY source_memory_id,target_memory_id`,
    [memoryIds, COMPANY]
  );

  const idToIdx = new Map();
  for (let i = 0; i < n; i++) idToIdx.set(memoryIds[i], i);
  if (r.rows.length > n * n) throw new Error('cg_graph_cardinality_invalid');
  const signedRows = r.rows.filter(row => row.authority_event_id !== null);
  const events = await readVerifiedEventsByIds(signedRows.map(row => row.authority_event_id), COMPANY, { client });
  const edges = [];
  const pairs = new Set();
  for (const row of signedRows) {
    const i = idToIdx.get(row.source_memory_id);
    const k = idToIdx.get(row.target_memory_id);
    if (i === undefined || k === undefined) throw new Error('cg_edge_outside_window');
    const pair = `${i}:${k}`;
    if (pairs.has(pair)) throw new Error('cg_duplicate_edge');
    pairs.add(pair);
    const w = Number(row.similarity);
    if (!Number.isFinite(w) || w < 0) throw new Error('cg_edge_weight_invalid');
    const event = events.get(String(row.authority_event_id));
    const metadata = typeof event?.metadata === 'string' ? JSON.parse(event.metadata) : event?.metadata;
    const pairMatches = value => value?.source_memory_id === row.source_memory_id
      && value?.target_memory_id === row.target_memory_id;
    const bound = event?.operation === 'memory_cross_refs_seeded'
      ? metadata?.edges?.some(edge => pairMatches(edge) && Number(edge.similarity) === w)
      : event?.operation === 'spiced_graph_projection'
        && metadata?.transitions?.some(edge => pairMatches(edge)
          && Number(edge.next?.similarity) === w && edge.next?.edge_type === row.edge_type);
    if (!bound) throw new Error('cg_edge_authority_relational_mismatch');
    S[i][k] = w;
    edges.push({ source_memory_id: row.source_memory_id, target_memory_id: row.target_memory_id,
      similarity: w, authority_event_id: String(row.authority_event_id),
      producer_operation: event.operation,
      authority_mutation_hash: Buffer.from(event.mutation_hash).toString('hex') });
  }
  return { matrix: S.map((row, i) => row.map((w, j) => (w + S[j][i]) / 2)),
    graph_basis: { schema: 'hom.aimos.signed-associative-energy-graph/v1',
      symmetrization: '(S+transpose(S))/2', edges,
      unsigned_historical_edges_retained: r.rows.length - signedRows.length } };
}

/**
 * Load the current weights and compute valences for the candidate window.
 *
 * @param {string[]} memoryIds
 * @returns {Promise<Array<{ id: string, weight: number, valence: number }>>}
 */
async function loadWindowState(memoryIds, client, fixedValences = null) {
  if (!memoryIds.length) return [];
  const r = await client.query(
    `SELECT id, retrieval_weight
       FROM aimos_memories
      WHERE company_id=$2 AND id = ANY($1::uuid[])`,
    [memoryIds, COMPANY]
  );
  const byId = new Map(r.rows.map(row => [String(row.id), row]));
  if (r.rows.length !== memoryIds.length || byId.size !== memoryIds.length
      || memoryIds.some(id => !byId.has(id))) throw new Error('cg_window_membership_invalid');
  const memories = [];
  for (const id of memoryIds) {
    const row = byId.get(id);
    const weight = Number(row.retrieval_weight);
    if (!Number.isFinite(weight)) throw new Error('cg_window_weight_invalid');
    const valence = fixedValences ? fixedValences.get(id) : await computeValence(id, { client });
    memories.push(Object.freeze({ id, weight, valence }));
  }
  return memories;
}

function exactWindowIds(ids) {
  if (!Array.isArray(ids) || !ids.length || ids.length > 15
      || ids.some(id => typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id))
      || new Set(ids).size !== ids.length) throw new Error('cg_window_ids_invalid');
  return [...ids].sort();
}

// Read-only native primitive; caller owns the transaction and writer locks.
export async function readEnergyWindowSnapshot(candidateIds, { client } = {}) {
  if (!client?.query) throw new Error('cg_transaction_client_required');
  const ids = exactWindowIds(candidateIds);
  const memories = await loadWindowState(ids, client);
  const { matrix, graph_basis } = await buildConceptGraphMatrix(ids, client);
  computeLyapunovV(memories, matrix);
  const judgeCounts = await client.query(`SELECT count(*)::int AS retained_rows,
    count(*) FILTER(WHERE proof_required IS NOT TRUE)::int AS unsigned_legacy_rows
    FROM memory_valence_ledger WHERE company_id=$1 AND memory_id=ANY($2::uuid[])
    AND (evidence_schema_version=1 OR target_scope='principal_state')`, [COMPANY, ids]);
  const body = { schema: 'hom.aimos.cg-energy-window/v1', company_id: COMPANY, ids, memories, matrix,
    graph_basis, judge_basis: { method: 'existing_native_signed_evidence_tanh_with_retained_legacy',
      ...judgeCounts.rows[0], all_rows_cryptographically_verified: false } };
  const snapshot_sha256 = createHash('sha256').update(canonicalJson(body)).digest('hex');
  return Object.freeze({ ...body, ids: Object.freeze(ids), memories: Object.freeze(memories),
    matrix: Object.freeze(matrix.map(row => Object.freeze(row))), snapshot_sha256 });
}

/**
 * Compare the exact mutation transaction's pre/post weights on ONE fixed
 * graph and judge basis. This controls only the next cycle's surplus.
 * A missing/inconsistent snapshot is an error, never an invented /1.3 past.
 * The decision and the mutations share the caller's transaction.
 */
export async function enforceEnergyBound(candidateIds, opts = {}) {
  if (!(await isFlagOn()) || candidateIds.length === 0) {
    return { gamma_dampen: 1, delta_v: 0, gate_logic_unchanged: true,
      source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER };
  }
  const client = opts.client;
  if (!client?.query) throw new Error('cg_transaction_client_required');
  const ids = exactWindowIds(candidateIds);
  const before = opts.before;
  if (!before || before.schema !== 'hom.aimos.cg-energy-window/v1' || before.company_id !== COMPANY
      || !Array.isArray(before.memories)
      || canonicalJson(before.ids) !== canonicalJson(ids)
      || canonicalJson(before.memories.map(m => m.id)) !== canonicalJson(ids)) {
    throw new Error('cg_comparison_window_invalid');
  }
  const { snapshot_sha256, ...snapshotBody } = before;
  if (createHash('sha256').update(canonicalJson(snapshotBody)).digest('hex') !== snapshot_sha256) {
    throw new Error('cg_comparison_snapshot_invalid');
  }
  const fixedValences = new Map(before.memories.map(m => [m.id, m.valence]));
  const after = await loadWindowState(ids, client, fixedValences);
  const V_before = computeLyapunovV(before.memories, before.matrix);
  const V_after = computeLyapunovV(after, before.matrix);
  const deltaV = computeDeltaV(V_before, V_after);
  const gamma = computeDampenGamma(deltaV);
  const decision = await logEvent(COMPANY, 'housekeeper', 'energy_bound_check', null, {
    schema: 'hom.aimos.cg-energy-comparison/v2',
    window_snapshot_sha256: snapshot_sha256,
    window: snapshotBody,
    after,
    candidate_count: ids.length,
    v_before: V_before,
    v_after: V_after,
    delta_v: deltaV,
    gamma_dampen: gamma,
    flag_on: true,
    controls_next_cycle_only: true,
    global_convergence_claimed: false,
    reasoning: 'Exact pre/post mutation weights compared under one fixed graph and judge basis in the signed mutation transaction.',
    source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER,
  }, null, { client, returnReceipt: true });
  return { gamma_dampen: gamma, delta_v: deltaV, v_before: V_before, v_after: V_after,
    decision_event_id: decision.event_id, window_snapshot_sha256: snapshot_sha256,
    gate_logic_unchanged: false, source_paper: CG_GOVERNOR_CONSTANTS.SOURCE_PAPER };
}
export default {
  computeLyapunovV,
  computeDeltaV,
  computeDampenGamma,
  enforceEnergyBound,
  CG_GOVERNOR_CONSTANTS
};
