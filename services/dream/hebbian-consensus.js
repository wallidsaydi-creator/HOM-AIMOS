// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: jobs/nightly-dream.js (one rotating corpus batch per night)
// → Calls: commitGovernorMutation + public.apply_signed_cognitive_reweight (the
//          signed, tamper-evident cognitive-weight chain — SPEC docs/security/
//          cognitive-weight-chain-SPEC.md)
// Shadow-first: gated by governor flag HEBBIAN_CONSENSUS (OFF by default).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * hebbian-consensus.js — relational ("Hebbian") sleep consolidation.
 *
 * Grounding papers:
 *   HeLa-Mem: Hebbian Learning and Associative Memory for LLM Agents
 *   (arXiv 2604.16839) — `Book batches /Batch8/`.
 *   . Eq. 2 hub / associative strength:  D(v_i) = Σ_{j∈N(i)} w_ij  > δ_hub
 *   . "neurons that fire together, wire together" — co-related memories reinforce.
 *   Complementary Learning Systems (O'Reilly 2014) — slow consolidation pass.
 *   Bi-CRCL — bidirectional (symmetric up/down) conservative/radical balance.
 *
 * Model: a memory corroborated by its related
 * neighbors (a hub — high weighted associative strength) is ELEVATED; a memory
 * that diverges from its neighborhood consensus (a weak/fringe member) is
 * ATTENUATED. Support is primary; contradiction is *absence of support*. The
 * signal is SUBJECT-BOUND (only a memory's semantic neighbors vote), so an
 * off-subject memory is never wrongly demoted.
 *
 * Aladdin: weight is retrieval FREQUENCY, never existence. Floored at 0.1; no
 * delete, no is_active change. Movement is bounded + symmetric + gradual — one
 * night cannot crater a memory; repeated divergence fades it slowly.
 *
 * Every Δ is applied ONLY through the signed cognitive-weight chain (governor
 * flag HEBBIAN_CONSENSUS), so each decision is housekeeper-signed, chained, and
 * tamper-evident. The REWEIGHT body records the (subject, alignment, cluster)
 * context so the signed decision remains independently auditable.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query, withTransaction } from '../../db/connection.js';
import { commitGovernorMutation } from '../governance/governor-provenance.js';
import { logEvent } from '../observe/event-ledger.js';

// Thresholds — first-pass defaults. CALIBRATE against the live corpus before
// enforcing (spec §9.5); tune with HeLa-Mem δ_hub methodology, not by memory.
export const HEBBIAN_CONSTANTS = Object.freeze({
  ASSOC_MIN: 0.70,        // cosine ≥ this ⇒ a real associative edge (matches dream L2)
  TOP_K: 24,              // HNSW neighbours examined per memory (bounded, sublinear)
  MIN_NEIGHBORS: 3,       // need a real consensus, not a pair (spec §2.3)
  ALIGN_HIGH: 0.85,       // weighted assoc. alignment ≥ ⇒ supported hub → elevate
  ALIGN_LOW: 0.76,        // ≤ ⇒ divergent/fringe member → attenuate
  ETA: 0.08,              // step scale in log-weight space
  MAX_LOG_STEP: 0.262,    // |Δ ln w| ≤ ln(1.3) — at most ×1.3 up or ÷1.3 down / night
  W_MIN: 0.1,
  W_MAX: 3.0,
  DEFAULT_BATCHES: 28,    // whole corpus swept over this many nights (rotating)
  FLAG_KEY: 'HEBBIAN_CONSENSUS',
});

const COMPANY = AIMOS_COMPANY_ID;

/**
 * HOM adaptation of HeLa-Mem Eq. 2 to a semantic kNN neighborhood. The paper
 * sums learned graph-edge weights; this service derives an evidence score from
 * cosine edges weighted by each neighbor's live retrieval frequency. It does
 * not claim byte-for-byte implementation of the paper's state variable.
 *
 * Weighted associative strength of a memory within its semantic neighbourhood.
 * SQL-native via the HNSW index (no vector marshalling): the top-K nearest
 * neighbours, filtered to real edges (sim ≥ ASSOC_MIN), weighted by the
 * neighbour's retrieval weight (established memories vote more — inspired by HeLa-Mem Eq. 2,
 * and the operator's guard against a lone newcomer flipping consensus).
 *
 *   support   S(m) = Σ_{n∈N(m)} w(n)·sim(m,n)
 *   alignment a(m) = S(m) / Σ_{n∈N(m)} w(n)      ∈ [ASSOC_MIN, 1]
 *
 * @returns {Promise<null | {alignment:number, support:number, neighborCount:number}>}
 *          null when there is no real neighbourhood (fewer than MIN_NEIGHBORS).
 */
export async function computeConsensus(memoryId, { companyId = COMPANY } = {}) {
  const { ASSOC_MIN, TOP_K, MIN_NEIGHBORS } = HEBBIAN_CONSTANTS;
  const res = await query(
    `WITH target AS (
        SELECT embedding FROM aimos_memories
         WHERE company_id = $1 AND id = $2 AND embedding IS NOT NULL AND is_active = true
     ),
     neigh AS (
        SELECT n.retrieval_weight::double precision AS w,
               1 - (n.embedding <=> t.embedding)     AS sim
          FROM aimos_memories n, target t
         WHERE n.company_id = $1 AND n.id <> $2
           AND n.is_active = true AND n.embedding IS NOT NULL
         ORDER BY n.embedding <=> t.embedding
         LIMIT $3
     )
     SELECT count(*)                        FILTER (WHERE sim >= $4)  AS ncount,
            coalesce(sum(w)                 FILTER (WHERE sim >= $4), 0) AS wsum,
            coalesce(sum(w * sim)           FILTER (WHERE sim >= $4), 0) AS support
       FROM neigh`,
    [companyId, memoryId, TOP_K, ASSOC_MIN]
  );
  const row = res.rows[0];
  const ncount = Number(row?.ncount || 0);
  const wsum = Number(row?.wsum || 0);
  const support = Number(row?.support || 0);
  if (ncount < MIN_NEIGHBORS || wsum <= 0) return null;
  return { alignment: support / wsum, support, neighborCount: ncount };
}

/**
 * Apply one bounded, symmetric, SIGNED consensus reweight to a memory. Re-reads
 * the live weight under the per-memory advisory lock (same key STDP uses), so it
 * is safe against a concurrent outcome reweight. No-op transitions are skipped.
 */
export async function applyConsensusReweight(memoryId, consensus, direction, deps = {}) {
  const { ETA, MAX_LOG_STEP, W_MIN, W_MAX, ALIGN_HIGH, ALIGN_LOW } = HEBBIAN_CONSTANTS;
  const commit = deps.commitGovernorMutation || commitGovernorMutation;
  const companyId = deps.companyId || COMPANY;
  const tau = direction > 0 ? ALIGN_HIGH : ALIGN_LOW;
  const strength = Math.abs(consensus.alignment - tau);          // distance past the threshold
  const deltaLog = direction * Math.min(MAX_LOG_STEP, ETA * strength * 10);

  return withTransaction(async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`cognitive-reweight:${companyId}:${memoryId}`]);
    const cur = await client.query(
      'SELECT retrieval_weight FROM aimos_memories WHERE company_id = $1 AND id = $2 AND is_active = true',
      [companyId, memoryId]);
    if (cur.rows.length === 0) return { applied: false, reason: 'gone' };
    const oldWeight = Number(cur.rows[0].retrieval_weight);
    const newWeight = Math.max(W_MIN, Math.min(W_MAX, oldWeight * Math.exp(deltaLog)));
    if (Math.round(newWeight * 1000) === Math.round(oldWeight * 1000)) {
      return { applied: false, reason: 'noop' };
    }
    const mutation = await commit({
      memoryId,
      oldWeight,
      newWeight,
      judgeValence: Math.max(-1, Math.min(1, consensus.alignment)),
      governorFlag: 'HEBBIAN_CONSENSUS',
      reason: direction > 0 ? 'consensus_support' : 'consensus_divergence',
      extra: {
        consensus_alignment: Number(consensus.alignment.toFixed(6)),
        associative_support: Number(consensus.support.toFixed(6)),
        neighbor_count: consensus.neighborCount,
        direction: direction > 0 ? 'elevate' : 'attenuate',
        // Subject-axis context accompanies the certified time ordinal (this
        // transition's chain index). Canonical content remains unchanged.
        canonical_content_changed: false,
        source_knowledge: 'HOM adaptation of HeLa-Mem Eq.2: semantic-kNN support weighted by retained retrieval frequency; bounded symmetric consolidation',
      },
      client,
    });
    if (!mutation.ok) throw new Error(`hebbian_commit_failed:${mutation.reason}`);
    await client.query(
      'SELECT public.apply_signed_cognitive_reweight($1::uuid, $2, $3, $4, $5)',
      [memoryId, oldWeight, newWeight, mutation.mutationHash, mutation.transitionSig]);
    return { applied: true, oldWeight, newWeight };
  }, { restricted: true, client_id: companyId, agent_id: 'housekeeper' });
}

/**
 * Deterministic corpus partition: memory falls in batch
 * (abs(hashtextextended(id)) mod batchCount). Whole corpus is covered over
 * `batchCount` nights. Only active, embedded memories are eligible.
 */
async function selectBatch(batchIndex, batchCount, { companyId = COMPANY, limit = 500 } = {}) {
  const res = await query(
    `SELECT id::text
       FROM aimos_memories
      WHERE company_id = $1 AND is_active = true AND embedding IS NOT NULL
        AND (abs(hashtextextended(id::text, 0)) % $2) = $3
      ORDER BY id
      LIMIT $4`,
    [companyId, batchCount, batchIndex, limit]);
  return res.rows.map((r) => r.id);
}

/**
 * Run ONE rotating consensus batch. Shadow-first: no-op unless the
 * HEBBIAN_CONSENSUS governor flag is enabled. Each memory is reviewed against
 * its own semantic neighbourhood and, if it is a supported hub or a divergent
 * outlier, reweighted through the signed chain.
 *
 * @returns {Promise<{enabled:boolean, reviewed:number, elevated:number, attenuated:number, skipped:number}>}
 */
export async function runHebbianConsensusBatch(batchIndex, batchCount = HEBBIAN_CONSTANTS.DEFAULT_BATCHES, deps = {}) {
  const companyId = deps.companyId || COMPANY;
  const readFlag = deps.readFlag;
  const stats = { enabled: true, reviewed: 0, elevated: 0, attenuated: 0, skipped: 0 };

  // Shadow gate — additive, OFF by default. Missing flag path ⇒ disabled.
  if (typeof readFlag === 'function') {
    let on = false;
    try { on = await readFlag(HEBBIAN_CONSTANTS.FLAG_KEY); } catch { on = false; }
    if (!on) { stats.enabled = false; return stats; }
  } else {
    stats.enabled = false;
    return stats;
  }

  const ids = await selectBatch(batchIndex, batchCount, { companyId });
  for (const memoryId of ids) {
    stats.reviewed += 1;
    let consensus;
    try {
      consensus = await computeConsensus(memoryId, { companyId });
    } catch { consensus = null; }
    if (!consensus) { stats.skipped += 1; continue; }

    const direction = classifyConsensus(consensus.alignment);
    if (direction === 0) { stats.skipped += 1; continue; }

    try {
      const r = await applyConsensusReweight(memoryId, consensus, direction, { companyId, ...deps });
      if (r.applied) { direction > 0 ? (stats.elevated += 1) : (stats.attenuated += 1); }
      else { stats.skipped += 1; }
    } catch (err) {
      stats.skipped += 1;
      await logEvent(companyId, 'hebbian_consensus', 'reweight_skipped', memoryId, {
        reason: String(err?.message || err).slice(0, 160),
        alignment: consensus.alignment,
        reasoning: 'Consensus reweight failed for one memory; batch continues. Canonical memory untouched.',
      }).catch(() => {});
    }
  }

  await logEvent(companyId, 'hebbian_consensus', 'batch_complete', `dream:hebbian:${batchIndex}`, {
    ...stats, batch_index: batchIndex, batch_count: batchCount,
    reasoning: 'Relational consolidation swept one rotating corpus batch; supported hubs elevated, divergent members attenuated, all signed + chained, existence preserved.',
    source_knowledge: 'HeLa-Mem association→consolidation; Complementary Learning Systems slow pass',
  }).catch(() => {});
  return stats;
}

// Direction from a consensus alignment: +1 supported hub, −1 divergent outlier,
// 0 neutral (no change). Exported so callers/tests share one classification.
export function classifyConsensus(alignment) {
  if (alignment >= HEBBIAN_CONSTANTS.ALIGN_HIGH) return 1;
  if (alignment <= HEBBIAN_CONSTANTS.ALIGN_LOW) return -1;
  return 0;
}

export default {
  runHebbianConsensusBatch,
  computeConsensus,
  applyConsensusReweight,
  classifyConsensus,
  HEBBIAN_CONSTANTS,
};
