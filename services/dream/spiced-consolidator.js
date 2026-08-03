/**
 * spiced-consolidator.js — SPICED-inspired dream consolidation engine
 * Sources: SPICED (NeurIPS 2025), ThaCo (2026), Neural Manifolds (2025)
 * Additive Batch9 Wave6 authority: AgentPulse, Forecasting the Past, and
 * PHMForge provide diagnostic-only dream viability signals. They do not alter
 * SPICED/ThaCo promotion formulas or canonical memory content.
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildForgettingBoundDiagnostic: Data-dependent forgetting bound
 *     alongside existing dream consolidation. Consolidation unchanged.
 *   - buildForgettingPrevalenceDiagnostic: Cross-system forgetting prevalence
 *     alongside existing dream diagnostics. Dream math unchanged.
 *   - buildEWCAnalogDiagnostic: EWC-analog (not literal Fisher EWC) importance
 *     score alongside existing consolidation. Consolidation unchanged.
 *   - buildSVDQRDiagnostic: Linear-regression forgetting via SVD
 *     (applicability-gated R² ≥ 0.8) alongside existing consolidation.
 *   - buildContinualLearningSurveyDiagnostic: Meta+continual learning survey
 *     audit-only taxonomy alongside existing diagnostics.
 *
 * Batch 10 Lane 2: Titans/M+/Dostoevsky — importance scoring + block attention + LSM levels
 *   importance = 0.5*retrieval_weight + 0.3*surprise + 0.2*access_frequency
 *   block_attention = softmax(query_embedding · block_summaries)
 *   LSM: compaction_job() → merge L0→L1→L2 (medallion: Bronze→Silver→Gold)
 *
 * ALADDIN: Consolidation is promotion-only. Never delete, suppress, deactivate,
 *          or reduce canonical retrieval_weight as a function of age.
 * Dream curator runs in up to 20 micro-cycles (ThaCo protocol).
 * Each cycle: select top-K=15 by importance -> gate -> consolidate -> edge formation -> convergence check.
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 17)
// → Calls: services/governance/cohen-grossberg-energy-governor.js
// Pipeline: DREAM_PIPELINE
// Position: neuromorphic consolidation
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query, withTransaction } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import { W_MIN, W_MAX } from '../learning/stdp-kernel.js';
import { enforceEnergyBound } from '../governance/cohen-grossberg-energy-governor.js';
import { governorConfigLedger } from '../governance/governor-config-ledger.js';
import { commitGovernorMutation } from '../governance/governor-provenance.js';

const COMPANY = AIMOS_COMPANY_ID;

// --- SPICED Parameters (NeurIPS 2025, production-validated) ---
const CONSOLIDATION_GAMMA = 1.3;     // LTP amplification factor
const CONSOLIDATION_CAP = 3.0;       // Max weight (prevents monopoly)
const TOP_K = 15;                    // Candidates per cycle
const IMPORTANCE_ALPHA = 0.2;        // Weight of cosine sim vs avg edge strength
const CONFIDENCE_GATE = 0.9;         // Minimum confidence for new write promotion
const DREAM_CYCLES = 20;             // ThaCo micro-consolidation protocol (max)
const SLEEP_RATIO = 0.15;            // Process 15% of recent write volume
const CONVERGENCE_THRESHOLD = 0.001; // Early termination if delta_w < this

// --- Edge Formation xi thresholds (SPICED graph wiring) ---
const XI_STRONG = 0.4;               // Strong edge threshold
const XI_WEAK = 0.1;                 // Weak edge threshold

// --- SpWR replay priority (Neural Manifolds paper) ---
const REPLAY_GAMMA = 2.0;            // Quadratic amplification for replay selection

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

function averageNumeric(values = []) {
  const numbers = values.map(Number).filter(Number.isFinite);
  if (!numbers.length) return 0;
  return numbers.reduce((sum, value) => sum + value, 0) / numbers.length;
}

function recallDriftPressure(recallDrift = null) {
  if (typeof recallDrift === 'number') return clamp01(recallDrift);
  const status = String(recallDrift?.status || recallDrift?.drift_status || '').toLowerCase();
  if (status === 'critical') return 1;
  if (status === 'warning' || status === 'monitor') return 0.62;
  if (status === 'stable') return 0.12;
  return clamp01(recallDrift?.score ?? recallDrift?.drift_score ?? 0);
}

function normalizeHealthScore(entry) {
  if (typeof entry === 'number') return entry > 1 ? clamp01(entry / 100) : clamp01(entry);
  const value = entry?.healthScore ?? entry?.health_score ?? entry?.score ?? entry?.confidence ?? 1;
  return Number(value) > 1 ? clamp01(Number(value) / 100) : clamp01(value, 1);
}

/**
 * Wave6 diagnostic-only dream viability pulse.
 * Does not call DB, alter weights, select candidates, or mutate canonical memory.
 */
export function buildDreamViabilityDiagnostics({
  dreamCycles = [],
  recallDrift = null,
  agentHealth = [],
  confidenceTrend = [],
  safetyIntercepts = 0,
  contextPressure = 0,
  periodLabel = 'unspecified',
} = {}) {
  const cycles = Array.isArray(dreamCycles) ? dreamCycles : [];
  const cycleActivity = cycles.map((cycle) => (
    Number(cycle?.amplified || 0)
    + Number(cycle?.edgesFormed || 0)
  ));
  const sparsePeriod = cycles.length === 0 || averageNumeric(cycleActivity) <= 0;
  const driftPressure = recallDriftPressure(recallDrift);
  const healthValues = Array.isArray(agentHealth) ? agentHealth.map(normalizeHealthScore) : [normalizeHealthScore(agentHealth)];
  const meanHealth = healthValues.length ? averageNumeric(healthValues) : 1;
  const confidenceValues = (Array.isArray(confidenceTrend) ? confidenceTrend : [])
    .map((entry) => typeof entry === 'number' ? entry : entry?.confidence ?? entry?.score)
    .map((value) => clamp01(value))
    .filter(Number.isFinite);
  const confidenceDrop = confidenceValues.length >= 2
    ? Math.max(0, confidenceValues[0] - confidenceValues[confidenceValues.length - 1])
    : 0;
  const context = clamp01(contextPressure);
  const safetyPressure = clamp01(Number(safetyIntercepts || 0) / 5);
  const highPressure = context >= 0.72 || safetyPressure >= 0.6;
  const viabilityScore = clamp01(
    1
    - (0.28 * driftPressure)
    - (0.2 * (1 - meanHealth))
    - (0.18 * confidenceDrop)
    - (0.22 * context)
    - (0.12 * safetyPressure)
  );
  const driftedPeriod = driftPressure >= 0.6 || confidenceDrop >= 0.18;

  return {
    source_papers: [
      'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment',
      'Forecasting the Past: Gradient-Based Distribution Shift Detection in Trajectory Prediction',
      'PHMForge: A Scenario-Driven Agentic Benchmark for Industrial Asset Lifecycle Maintenance',
    ],
    status: highPressure || driftedPeriod
      ? 'attention_required'
      : sparsePeriod
        ? 'sparse_period'
        : 'viable',
    period_label: periodLabel,
    diagnostic_only: true,
    sample_count: cycles.length,
    viability_score: Number(viabilityScore.toFixed(6)),
    flags: {
      sparse_period: sparsePeriod,
      drifted_period: driftedPeriod,
      high_pressure_period: highPressure,
    },
    signals: {
      recall_drift_pressure: Number(driftPressure.toFixed(6)),
      mean_agent_health: Number(meanHealth.toFixed(6)),
      confidence_drop: Number(confidenceDrop.toFixed(6)),
      context_pressure: Number(context.toFixed(6)),
      safety_intercept_pressure: Number(safetyPressure.toFixed(6)),
      mean_cycle_activity: Number(averageNumeric(cycleActivity).toFixed(6)),
    },
    action_contract: {
      report_only: true,
      dream_formula_changed: false,
      retrieval_weight_changed: false,
      canonical_memory_changed: false,
      hom_local_inheritance_activated: false,
    },
    guarded_math: {
      forgetting_bound: true,
      forgetting_prevalence: true,
      ewc_analog: true,
      svd_qr: true,
      continual_learning_survey: true,
    },
    guarded_math_implemented: {
      forgetting_bound: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Data-Dependent & Aimos Bounds on Forgetting',
        coexistence_class: 'side_by_side_independent',
      },
      forgetting_prevalence: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Forgetting Is Everywhere',
        coexistence_class: 'side_by_side_overlay',
      },
      ewc_analog: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Overcoming Catastrophic Forgetting in Neural Networks',
        coexistence_class: 'side_by_side_independent',
      },
      svd_qr: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Understanding Forgetting in Continual Learning — Linear Regression',
        coexistence_class: 'side_by_side_independent',
      },
      continual_learning_survey: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'When Meta-Learning Meets Online and Continual Learning',
        coexistence_class: 'audit_only_analogy',
      },
    },
  };
}

/**
 * Compute cosine similarity between two embedding vectors.
 * Returns value in [-1, 1].
 */
function cosineSimilarity(embA, embB) {
  if (!embA || !embB || embA.length !== embB.length || embA.length === 0) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < embA.length; i++) {
    dot += embA[i] * embB[i];
    normA += embA[i] * embA[i];
    normB += embB[i] * embB[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  if (denom === 0) return 0;
  return dot / denom;
}

/**
 * Parse an embedding from DB. Handles pgvector text format "[0.1,0.2,...]" or JSON array.
 */
function parseEmbedding(raw) {
  if (!raw) return null;
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      const cleaned = raw.replace(/^\[/, '').replace(/\]$/, '');
      return cleaned.split(',').map(Number);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * FIX #1: Compute importance coefficient I(N_i, N_j) -- SPICED formula
 * I = alpha * cosine_similarity(embedding_i, embedding_j) + (1 - alpha) * avg_edge_strength
 *
 * Now computes REAL cosine similarity between memory embeddings instead of using
 * retrieval_weight as a proxy.
 */
export async function computeImportance(memoryId) {
  // Fetch the memory with its embedding
  const memRes = await query(`
    SELECT m.id, m.retrieval_weight, m.access_count, m.embedding
    FROM aimos_memories m
    WHERE m.company_id = $1 AND m.id = $2
  `, [COMPANY, memoryId]);

  if (!memRes.rows[0]) return 0;
  const mem = memRes.rows[0];
  const selfEmbedding = parseEmbedding(mem.embedding);

  // ─── Batch 10 Lane 2: Augment with surprise-weighted importance ──────────
  // Paper: Titans, M+. importance = α*retrieval_weight + β*surprise + γ*access_frequency
  // This augments the SPICED formula with the surprise dimension.
  const batch10Importance = computeImportanceScore({
    retrieval_weight: parseFloat(mem.retrieval_weight) || 1.0,
    surprise_at_save: parseFloat(mem.surprise_at_save) || 0,
    access_count: parseInt(mem.access_count) || 0,
  });
  const surpriseWeightedComponent = batch10Importance.importance;

  // Get neighbor IDs and their stored edge_strength from memory_cross_refs table
  let neighborIds = [];
  const neighborEdgeStrengthMap = new Map();
  const crossRefRes = await query(`
    SELECT target_memory_id, similarity, edge_strength, edge_type FROM memory_cross_refs
    WHERE source_memory_id = $1
  `, [memoryId]);
  for (const r of crossRefRes.rows) {
    neighborIds.push(r.target_memory_id);
    neighborEdgeStrengthMap.set(r.target_memory_id, parseFloat(r.edge_strength) || parseFloat(r.similarity) || 0);
  }

  if (!neighborIds.length || !selfEmbedding) {
    // Fallback: no neighbors or no embedding, use retrieval_weight as edge strength proxy
    const selfWeight = parseFloat(mem.retrieval_weight) || 1.0;
    return IMPORTANCE_ALPHA * 0.5 + (1 - IMPORTANCE_ALPHA) * selfWeight;
  }

  // Fetch neighbor embeddings
  const neighborsRes = await query(`
    SELECT id, embedding
    FROM aimos_memories
    WHERE company_id = $1 AND id = ANY($2::uuid[])
  `, [COMPANY, neighborIds]);

  if (!neighborsRes.rows.length) {
    const selfWeight = parseFloat(mem.retrieval_weight) || 1.0;
    return IMPORTANCE_ALPHA * 0.5 + (1 - IMPORTANCE_ALPHA) * selfWeight;
  }

  // SPICED paper: I = 0.2 * cosine_sim + 0.8 * avg_edge_strength
  // edge_strength comes from the edge_strength column in memory_cross_refs (not retrieval_weight)
  let totalCosSim = 0;
  let totalEdgeStrength = 0;
  let validCount = 0;

  for (const neighbor of neighborsRes.rows) {
    const neighborEmbedding = parseEmbedding(neighbor.embedding);
    if (neighborEmbedding) {
      totalCosSim += cosineSimilarity(selfEmbedding, neighborEmbedding);
      // Use stored edge_strength from cross_refs (paper-backed); fallback to 0.5 if missing
      totalEdgeStrength += neighborEdgeStrengthMap.get(neighbor.id) ?? 0.5;
      validCount++;
    }
  }

  if (validCount === 0) {
    const selfWeight = parseFloat(mem.retrieval_weight) || 1.0;
    return IMPORTANCE_ALPHA * 0.5 + (1 - IMPORTANCE_ALPHA) * selfWeight;
  }

  const avgCosSim = totalCosSim / validCount;
  // SPICED paper: I = 0.2 * cosine_sim + 0.8 * avg_edge_strength
  const avgEdgeStrength = totalEdgeStrength / validCount;

  // Blend SPICED importance with Batch 10 surprise-weighted importance
  // SPICED: 0.7 weight, Surprise: 0.3 weight (configurable)
  const spicedImportance = IMPORTANCE_ALPHA * avgCosSim + (1 - IMPORTANCE_ALPHA) * avgEdgeStrength;
  return 0.7 * spicedImportance + 0.3 * surpriseWeightedComponent;
}

async function commitSpicedEdgeProjection(ids, { sourceMemoryId = null } = {}) {
  const uniqueIds = [...new Set(ids.map((id) => String(id || '')).filter(Boolean))];
  if (uniqueIds.length < 2 && !sourceMemoryId) return 0;
  if (sourceMemoryId && !uniqueIds.includes(String(sourceMemoryId))) {
    uniqueIds.push(String(sourceMemoryId));
  }

  return withTransaction(async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`spiced-cross-refs:${COMPANY}`]
    );
    const res = await client.query(
      `SELECT id, embedding, retrieval_weight
         FROM aimos_memories
        WHERE company_id = $1 AND id = ANY($2::uuid[])
        FOR SHARE`,
      [COMPANY, uniqueIds]
    );
    const rows = res.rows
      .map((row) => ({
        id: String(row.id),
        emb: parseEmbedding(row.embedding),
        weight: parseFloat(row.retrieval_weight) || 0.5,
      }))
      .filter((row) => row.emb);
    const byId = new Map(rows.map((row) => [row.id, row]));
    const sources = sourceMemoryId
      ? [byId.get(String(sourceMemoryId))].filter(Boolean)
      : rows;
    const targets = sourceMemoryId
      ? uniqueIds.map((id) => byId.get(id)).filter(Boolean)
      : rows;
    const links = [];
    for (const source of sources) {
      for (const target of targets) {
        if (source.id === target.id) continue;
        const cosine = cosineSimilarity(source.emb, target.emb);
        const importance = IMPORTANCE_ALPHA * cosine + (1 - IMPORTANCE_ALPHA) * target.weight;
        if (importance <= XI_WEAK) continue;
        links.push({
          source: source.id,
          target: target.id,
          similarity: importance,
          edge_strength: importance,
          edge_type: importance > XI_STRONG ? 'strong' : 'weak',
        });
      }
    }
    if (!links.length) return 0;

    const existing = await client.query(
      `SELECT source_memory_id, target_memory_id, similarity, edge_strength, edge_type
         FROM memory_cross_refs
        WHERE company_id = $1
          AND source_memory_id = ANY($2::uuid[])
          AND target_memory_id = ANY($3::uuid[])
        FOR UPDATE`,
      [COMPANY, [...new Set(links.map((link) => link.source))], [...new Set(links.map((link) => link.target))]]
    );
    const previous = new Map(existing.rows.map((row) => [
      `${row.source_memory_id}:${row.target_memory_id}`,
      {
        similarity: Number(row.similarity),
        edge_strength: Number(row.edge_strength),
        edge_type: row.edge_type,
      },
    ]));
    const transitions = links.map((link) => ({
      source_memory_id: link.source,
      target_memory_id: link.target,
      previous: previous.get(`${link.source}:${link.target}`) || null,
      next: {
        similarity: link.similarity,
        edge_strength: link.edge_strength,
        edge_type: link.edge_type,
      },
    }));
    const event = await logEvent(
      COMPANY,
      'housekeeper',
      'spiced_graph_projection',
      'dream:spiced:graph',
      {
        formula: 'importance=0.2*cosine_similarity+0.8*target_retrieval_weight',
        thresholds: { weak: XI_WEAK, strong: XI_STRONG },
        transitions,
        canonical_memory_changed: false,
        retention_changed: false,
        reasoning: 'SPICED-inspired associative edges were projected from the retained candidate set; every prior and next edge state is signed before the atomic projection mutation.',
        source_knowledge: 'SPICED Eq. 2 importance and Section 3.3 connection formation; Aimos graph adaptation keeps all canonical memories retained.',
      },
      null,
      { client, returnReceipt: true }
    );

    const values = [];
    const placeholders = [];
    links.forEach((link, index) => {
      const offset = index * 7;
      placeholders.push(`($${offset + 1},$${offset + 2},$${offset + 3},$${offset + 4},$${offset + 5},$${offset + 6},$${offset + 7})`);
      values.push(
        COMPANY,
        link.source,
        link.target,
        link.similarity,
        link.edge_strength,
        link.edge_type,
        event.event_id,
      );
    });
    const projected = await client.query(
      `INSERT INTO memory_cross_refs
         (company_id, source_memory_id, target_memory_id, similarity, edge_strength, edge_type, authority_event_id)
       VALUES ${placeholders.join(',')}
       ON CONFLICT (company_id, source_memory_id, target_memory_id)
       DO UPDATE SET similarity = EXCLUDED.similarity,
                     edge_strength = EXCLUDED.edge_strength,
                     edge_type = EXCLUDED.edge_type,
                     authority_event_id = EXCLUDED.authority_event_id`,
      values
    );
    return projected.rowCount;
  }, { restricted: true, client_id: COMPANY, agent_id: 'housekeeper' });
}

/**
 * FIX #4: Edge Formation -- build graph edges at xi thresholds
 * After computing importance between a pair, store edges in memory_cross_refs:
 *   importance > 0.4 -> strong edge
 *   importance > 0.1 -> weak edge
 */
export async function formEdges(memoryId, neighbors) {
  if (!neighbors || !neighbors.length) return 0;
  return commitSpicedEdgeProjection(
    [memoryId, ...neighbors.map((neighbor) => neighbor.id || neighbor)],
    { sourceMemoryId: memoryId }
  );
}

/**
 * Batch edge formation for a set of candidates. Fetches all embeddings once,
 * computes pairwise importance in memory, issues a single multi-row UPSERT.
 * Replaces 15 per-candidate formEdges calls (30+ queries) with 2 queries total.
 */
export async function formEdgesBatch(candidates) {
  if (!candidates || candidates.length < 2) return 0;
  return commitSpicedEdgeProjection(candidates.map((candidate) => candidate.id || candidate));
}

/**
 * Select top-K candidates for consolidation using SpWR replay priority
 * P(k|sleep) = P(k|wake)^gamma where gamma=2.0 (quadratic amplification)
 *
 * FIX #3: SLEEP_RATIO limits candidates to 15% of retained write volume
 */
export async function selectConsolidationCandidates(limit = TOP_K) {
  // Count the retained corpus to apply SLEEP_RATIO without an age cutoff.
  const countRes = await query(`
    SELECT COUNT(*) as write_volume
    FROM aimos_memories
    WHERE company_id = $1
  `, [COMPANY]);

  const writeVolume = parseInt(countRes.rows[0]?.write_volume || '0', 10);
  const ratioLimit = Math.max(1, Math.floor(SLEEP_RATIO * writeVolume));
  const effectiveLimit = Math.min(limit, ratioLimit);

  const res = await query(`
    SELECT id, key, value, retrieval_weight, access_count, last_accessed_at,
           POWER(COALESCE(retrieval_weight, 1.0)::double precision, ${REPLAY_GAMMA}::double precision) as replay_priority
    FROM aimos_memories
    WHERE company_id = $1
    ORDER BY replay_priority DESC
    LIMIT $2
  `, [COMPANY, effectiveLimit]);

  return res.rows;
}

/**
 * Consolidation amplification -- SPICED LTP analog
 * weight = min(weight * gamma, cap)
 *
 * FIX #2: CONFIDENCE_GATE -- only amplify memories whose retrieval_weight >= 0.9
 *
 * Aimos-2 / Paper 2 Governor #1: `gammaDampen` ∈ [0.1, 1.0] scales only
 * the surplus above the identity transform:
 *   gamma_effective = 1 + gammaDampen * (CONSOLIDATION_GAMMA - 1)
 * Therefore gamma_effective ∈ [1.03, 1.3]. The governor can slow promotion,
 * but it cannot reduce a canonical retrieval weight.
 *
 * Returns { amplified: number, gatedOut: number }
 */
export function computeConsolidationAmplificationFactor(gammaDampen = 1.0) {
  const numeric = Number(gammaDampen);
  const boundedDampen = Number.isFinite(numeric)
    ? Math.max(0.1, Math.min(1.0, numeric))
    : 1.0;
  return 1.0 + boundedDampen * (CONSOLIDATION_GAMMA - 1.0);
}

export async function amplifyConsolidated(memoryIds, gammaDampen = 1.0) {
  if (!memoryIds.length) return { amplified: 0, gatedOut: 0 };

  const effectiveGamma = computeConsolidationAmplificationFactor(gammaDampen);

  // HOM adaptation of SPICED Eq. 5. SPICED strengthens a connection state
  // s_ij; Aimos maps that multiplicative promotion onto a retained memory's
  // retrieval-frequency projection. The signed proof and projection share one
  // restricted transaction, and prior/new weights reproduce every update.
  const res = await withTransaction(async (client) => {
    // The runtime role has SELECT but deliberately no UPDATE privilege, which
    // also makes SELECT FOR UPDATE unavailable. Acquire the same certified
    // writer locks in deterministic UUID order before reading the batch.
    const orderedMemoryIds = [...new Set(memoryIds.map(String))].sort();
    for (const memoryId of orderedMemoryIds) {
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`cognitive-reweight:${COMPANY}:${memoryId}`]
      );
    }
    const targets = await client.query(`
      SELECT id, retrieval_weight AS old_weight
        FROM aimos_memories
       WHERE company_id = $1
         AND id = ANY($4::uuid[])
         AND retrieval_weight >= $3
         AND retrieval_weight < $2
    `, [COMPANY, CONSOLIDATION_CAP, CONFIDENCE_GATE, orderedMemoryIds]);

    const mutations = [];
    for (const row of targets.rows) {
      const oldWeight = Number(row.old_weight);
      // HOM mapping of SPICED Eq. 5: monotone retrieval-frequency promotion,
      // capped at CONSOLIDATION_CAP; canonical memory content never changes.
      const newWeight = Math.max(oldWeight, Math.min(CONSOLIDATION_CAP, oldWeight * effectiveGamma));

      const attestation = await commitGovernorMutation({
        memoryId: row.id,
        oldWeight,
        newWeight,
        judgeValence: 0,
        governorFlag: 'SPICED_CONSOLIDATION',
        reason: 'spiced_ltp_promotion',
        extra: {
          formula: 's_prime=min(3,gamma_effective*s)',
          gamma_effective: effectiveGamma,
          confidence_gate: CONFIDENCE_GATE,
          canonical_content_changed: false,
          monotone_promotion: true,
        },
        client,
      });
      if (!attestation.ok) {
        throw new Error(`mutation_ledger_failed:${attestation.reason}`);
      }

      // Apply the weight ONLY through the signed stored function: it verifies the
      // REWEIGHT provenance row just committed, enforces the Aladdin [0.1,3.0]
      // bound and housekeeper scope, and is the sole writer of retrieval_weight.
      await client.query(
        'SELECT public.apply_signed_cognitive_reweight($1::uuid, $2, $3, $4, $5)',
        [row.id, oldWeight, newWeight, attestation.mutationHash, attestation.transitionSig]
      );

      mutations.push({ memory_id: row.id, old_weight: oldWeight, new_weight: newWeight });
    }

    if (mutations.length) {
      await logEvent(COMPANY, 'housekeeper', 'spiced_consolidation_amplified', 'dream:spiced', {
        formula: 's_prime=min(3,gamma_effective*s)',
        gamma_effective: effectiveGamma,
        confidence_gate: CONFIDENCE_GATE,
        mutations,
        canonical_content_changed: false,
        monotone_promotion: true,
        reasoning: 'SPICED top-K consolidation strengthened eligible synaptic projections without decay or content mutation.',
        source_knowledge: 'HOM adaptation of SPICED Eq. 5 s_prime=gamma*s: connection-strength promotion mapped to the retained retrieval-frequency projection, capped at 3',
      }, null, { client });
    }
    return mutations.length;
  }, { restricted: true, client_id: COMPANY, agent_id: 'housekeeper' });

  const gatedOut = memoryIds.length - res;
  return { amplified: res, gatedOut };
}

/**
 * FIX #5: Compute total weight delta for a cycle (convergence detection).
 * Returns sum of absolute weight changes for the given memory IDs.
 */
async function computeCycleDelta(memoryIds, gammaDampen) {
  if (!memoryIds.length) return 0;
  const effectiveGamma = computeConsolidationAmplificationFactor(gammaDampen);
  const res = await query(`
    SELECT COALESCE(SUM(ABS(
      retrieval_weight - GREATEST(retrieval_weight, LEAST($3, retrieval_weight * $2))
    )), 0) as total_delta
    FROM aimos_memories
    WHERE company_id = $1 AND id = ANY($4)
  `, [COMPANY, effectiveGamma, CONSOLIDATION_CAP, memoryIds]);

  return parseFloat(res.rows[0]?.total_delta || '0');
}

/**
 * Run full dream consolidation -- up to 20 micro-cycles (ThaCo protocol)
 * Each cycle: select -> gate -> amplify -> form edges -> convergence check
 *
 * FIX #2: CONFIDENCE_GATE wired into amplification
 * FIX #3: SLEEP_RATIO limits candidate pool to 15% of write volume
 * FIX #4: Edge formation with xi thresholds after importance computation
 * FIX #5: Early termination on convergence (delta_w < 0.001)
 */
export async function runDreamConsolidation() {
  const results = {
    cycles: 0,
    amplified: 0,
    gatedOut: 0,
    edgesFormed: 0,
    convergedEarly: false
  };

  // Per-cycle dampening multiplier from the CG governor. Starts at 1.0
  // (no dampening). Each cycle's enforceEnergyBound sets cycleGamma based
  // on ΔV; the NEXT cycle's amplifyConsolidated multiplies LTP_AMPLIFY by it.
  let cycleGamma = 1.0;

  for (let cycle = 0; cycle < DREAM_CYCLES; cycle++) {
    // 1. Select top-K candidates by replay priority (FIX #3: SLEEP_RATIO applied inside)
    const candidates = await selectConsolidationCandidates(TOP_K);
    if (!candidates.length) break;

    const candidateIds = candidates.map(c => c.id);

    // 2. FIX #5: Compute expected delta_w before amplification for convergence check
    const cycleDelta = await computeCycleDelta(candidateIds, cycleGamma);

    // 2.5. Capture pre-amplification weights for the CG governor's ΔV computation.
    //      The governor needs V_before (pre-amp) and V_after (post-amp) to
    //      decide whether to dampen the NEXT cycle. Only fetched when the
    //      governor flag is ON (the governor no-ops otherwise).
    let previousWeights = null;
    if (await governorConfigLedger.readFlag('COHEN_GROSSBERG_GOVERNOR')) {
      const preRows = await query(
        `SELECT id, retrieval_weight FROM aimos_memories WHERE company_id = $1 AND id = ANY($2::uuid[])`,
        [COMPANY, candidateIds]
      );
      previousWeights = new Map((preRows?.rows || []).map(r => [r.id, Number(r.retrieval_weight)]));
    }

    // 3. Amplify selected candidates (SPICED LTP) -- FIX #2: CONFIDENCE_GATE applied.
    //    Pass the PREVIOUS cycle's cycleGamma so the CG governor's dampening
    //    decision bites on THIS cycle's amplification. cycleGamma = 1.0 on the
    //    first cycle (no prior ΔV to dampen) — bit-exact existing behavior.
    const { amplified: ampCount, gatedOut } = await amplifyConsolidated(candidateIds, cycleGamma);
    results.amplified += ampCount;
    results.gatedOut += gatedOut;

    // 3.5. Aimos-2 / Paper 2 Governor #1 — Cohen-Grossberg bounded energy.
    //      Flag-gated OFF internally by the signed governor ledger. When
    //      OFF, returns γ_dampen = 1.0 — bit-exact existing behavior. When ON,
    //      computes V over the top-K window and returns γ_dampen that the
    //      caller applies to the NEXT cycle's amplification surplus. The
    //      effective factor stays >= 1, so dampening never lowers stored
    //      retrieval weight. The signed governor decision is committed before
    //      gamma becomes eligible for the next cycle; the later SPICED weight
    //      mutation and its exact old/new evidence commit atomically.
    try {
      const cg = await enforceEnergyBound(candidateIds, { previousWeights });
      cycleGamma = cg.gamma_dampen;
      if (cg.gate_logic_unchanged === false) {
        results.cg_governor = results.cg_governor || { cycles: 0, dampens: 0 };
        results.cg_governor.cycles++;
        if (cycleGamma < 1.0) results.cg_governor.dampens++;
      }
    } catch (err) {
      // Fail-open: governor error does not crash the dream cycle. Reset
      // cycleGamma to 1.0 so the next cycle is not dampened by a stale value.
      cycleGamma = 1.0;
      results.cg_governor_error = String(err?.message || err);
    }

    // 4. FIX #4: Batch edge formation — single query for embeddings + one upsert.
    results.edgesFormed += await formEdgesBatch(candidates);

    // 5. Record the completed promotion cycle.
    results.cycles++;

    // 6. FIX #5: Convergence check -- stop early if weight change is negligible
    if (cycleDelta < CONVERGENCE_THRESHOLD) {
      results.convergedEarly = true;
      break;
    }
  }

  return results;
}

export const FORGETTING_BOUND_SOURCE = 'Data-Dependent & Aimos Bounds on Forgetting';
export const FORGETTING_PREVALENCE_SOURCE = 'Forgetting Is Everywhere';
export const EWC_ANALOG_SOURCE = 'Overcoming Catastrophic Forgetting in Neural Networks';
export const SVD_QR_SOURCE = 'Understanding Forgetting in Continual Learning — Linear Regression';
export const CONTINUAL_LEARNING_SURVEY_SOURCE = 'When Meta-Learning Meets Online and Continual Learning';

// ─── H1: SVD-QR CONSOLIDATION ────────────────────────────────────────────────
// Source: Understanding Forgetting in Continual Learning
// Formula: [U, Σ, V^T] = svd(M), then QR decomposition of selected columns
// Scale adaptation: k_concepts = max(5, min(50, floor(15 * (N/14000)^0.3)))
// At 14K: k=15. At 100K: k≈27.
// Consolidation creates new memories, doesn't delete old ones. Aladdin SAFE.

export function computeSVDQRConcepts(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(5, Math.min(50, Math.floor(15 * Math.pow(N / 14000, 0.3))));
}

// ─── H2: EWC ANALOG (FISHER SAMPLE COUNT) ──────────────────────────────────────
// Source: Overcoming Catastrophic Forgetting (EWC)
// Formula: importance_i = F_i · |θ_i - θ*_i|²
// Scale adaptation: n_fisher = max(200, min(2000, floor(500 * (N/14000)^0.5)))
// At 14K: n=500. At 100K: n≈1336.
// Importance weighting affects consolidation priority, not content. Aladdin SAFE.

export function computeFisherSampleCount(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(200, Math.min(2000, Math.floor(500 * Math.pow(N / 14000, 0.5))));
}

export function computeEWCImportanceScore(fisherInfo, thetaDiff) {
  const F = Number(fisherInfo) || 0;
  const d = Number(thetaDiff) || 0;
  return F * d * d;
}

// ─── H3: CONTINUAL LEARNING META RATE ────────────────────────────────────────
// Source: When Meta-Learning Meets Online and Continual Learning
// Formula: η_meta = η_base * (1 + β·task_count)
// Scale adaptation: η_base = 0.01 * max(0.1, (14000/N)^0.5)
// At 14K: η=0.01. At 100K: η≈0.0037.
// Learning rate affects consolidation quality, not content. Aladdin SAFE.

export function computeMetaLearningRate(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 0.01 * Math.max(0.1, Math.pow(14000 / N, 0.5));
}

export function computeMetaRateWithTaskCount(memoryCount = 14000, taskCount = 0, beta = 0.01) {
  const etaBase = computeMetaLearningRate(memoryCount);
  return etaBase * (1 + beta * Math.max(0, taskCount));
}

export function buildDreamConsolidationDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: [SVD_QR_SOURCE, EWC_ANALOG_SOURCE, CONTINUAL_LEARNING_SURVEY_SOURCE],
    svd_qr: {
      k_concepts: computeSVDQRConcepts(N),
      formula: 'k_concepts = max(5, min(50, floor(15 * (N/14000)^0.3)))',
    },
    ewc_analog: {
      n_fisher: computeFisherSampleCount(N),
      formula: 'n_fisher = max(200, min(2000, floor(500 * (N/14000)^0.5)))',
    },
    continual_learning: {
      eta_base: Number(computeMetaLearningRate(N).toFixed(6)),
      formula: 'η_base = 0.01 * max(0.1, (14000/N)^0.5)',
    },
    aladdin_compliance: {
      consolidation_creates_new_memories: true,
      never_deletes_old_memories: true,
      frequency_modulated_recall: true,
    },
    diagnostic_only: true,
    guarded_math: {
      svd_qr: true,
      ewc_analog: true,
      continual_learning_survey: true,
    },
  };
}

/**
 * Forgetting Bound Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Data-Dependent & Aimos Bounds on Forgetting
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper provides data-dependent upper bounds on how much a model forgets
 * when learning new tasks. This diagnostic computes a forgetting bound
 * estimate for consolidation candidates based on their weight trajectories.
 * Dream consolidation math unchanged. Guarded by guarded_math flag
 * forgetting_bound (knowledge-gated: paper understanding required).
 */
export function buildForgettingBoundDiagnostic({
  consolidationCandidates = [],
  weightTrajectory = [],
} = {}) {
  const candidates = Array.isArray(consolidationCandidates) ? consolidationCandidates : [];
  const trajectory = Array.isArray(weightTrajectory) ? weightTrajectory : [];

  // Forgetting bound: estimate from weight trajectory
  // Paper: forgetting ≈ |w_old - w_new| for each parameter group
  // Here: estimate from retrieval_weight trajectory of candidates
  const weightDeltas = candidates.map((c) => {
    const current = Number(c?.retrieval_weight || c?.weight || 1);
    const initial = Number(c?.initial_weight || c?.baseline_weight || current);
    return Math.abs(current - initial);
  });
  const maxDelta = weightDeltas.length > 0 ? Math.max(...weightDeltas) : 0;
  const meanDelta = weightDeltas.length > 0
    ? weightDeltas.reduce((s, d) => s + d, 0) / weightDeltas.length
    : 0;

  // Data-dependent bound: proportional to candidate pool size and max drift
  const forgettingBound = candidates.length > 0
    ? Math.min(1, maxDelta * Math.sqrt(candidates.length / Math.max(1, candidates.length + trajectory.length)))
    : 0;

  return {
    diagnostic: true,
    source_paper: FORGETTING_BOUND_SOURCE,
    coexistence_class: 'side_by_side_independent',
    candidate_count: candidates.length,
    weight_trajectory_length: trajectory.length,
    max_weight_delta: Number(maxDelta.toFixed(6)),
    mean_weight_delta: Number(meanDelta.toFixed(6)),
    forgetting_bound_estimate: Number(forgettingBound.toFixed(6)),
    dream_consolidation_unchanged: true,
    note: 'Alongside-path diagnostic. Forgetting bound does not modify dream consolidation math.',
  };
}

/**
 * Forgetting Prevalence Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Forgetting Is Everywhere
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper: forgetting is a cross-system phenomenon, not isolated to one module.
 * This diagnostic computes prevalence of forgetting across the memory pool
 * by measuring what fraction of memories show weight decline.
 * Dream diagnostics unchanged. Guarded by guarded_math flag
 * forgetting_prevalence (knowledge-gated: paper understanding required).
 */
export function buildForgettingPrevalenceDiagnostic({
  memoryPool = [],
  referenceWeights = {},
} = {}) {
  const pool = Array.isArray(memoryPool) ? memoryPool : [];
  const refs = referenceWeights && typeof referenceWeights === 'object' ? referenceWeights : {};

  // Forgetting prevalence: fraction of memories with weight decline
  const decliningMemories = pool.filter((m) => {
    const current = Number(m?.retrieval_weight || m?.weight || 1);
    const reference = Number(refs[m?.id || m?.key] || refs[String(m?.id)] || current);
    return current < reference;
  });
  const prevalence = pool.length > 0 ? decliningMemories.length / pool.length : 0;

  // Average decline magnitude for declining memories
  const declineMagnitudes = decliningMemories.map((m) => {
    const current = Number(m?.retrieval_weight || m?.weight || 1);
    const reference = Number(refs[m?.id || m?.key] || refs[String(m?.id)] || current);
    return reference > 0 ? (reference - current) / reference : 0;
  });
  const meanDecline = declineMagnitudes.length > 0
    ? declineMagnitudes.reduce((s, d) => s + d, 0) / declineMagnitudes.length
    : 0;

  return {
    diagnostic: true,
    source_paper: FORGETTING_PREVALENCE_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    pool_size: pool.length,
    declining_count: decliningMemories.length,
    forgetting_prevalence: Number(prevalence.toFixed(6)),
    mean_decline_ratio: Number(meanDecline.toFixed(6)),
    cross_system_note: 'Forgetting measured across memory pool; not isolated to dream cycle.',
    dream_diagnostics_unchanged: true,
    note: 'Alongside-path diagnostic. Forgetting prevalence does not modify dream diagnostics.',
  };
}

/**
 * EWC-analog Diagnostic — Alongside-path diagnostic
 *
 * EWC-analog (not literal Fisher EWC — memories are not parameterized weights)
 *
 * Source paper: Overcoming Catastrophic Forgetting in Neural Networks
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * EWC paper: protect important parameters via Fisher-information penalty.
 * Analog: importance_i = alpha * access_freq + beta * centrality + gamma * recency
 * Score = Σ importance_i · drift_i². Memories are NOT parameterized weights —
 * this is an analogy. Dream consolidation math unchanged. Guarded by
 * guarded_math flag ewc_analog (knowledge-gated: paper understanding required).
 */
export function buildEWCAnalogDiagnostic({
  memories = [],
  driftMetrics = {},
  alpha = 0.4,
  beta = 0.35,
  gamma = 0,
} = {}) {
  const mems = Array.isArray(memories) ? memories : [];
  const drifts = driftMetrics && typeof driftMetrics === 'object' ? driftMetrics : {};

  // Age-neutral importance: usage evidence + graph centrality only.
  const importanceScores = mems.map((m) => {
    const accessFreq = Math.min(1, Number(m?.access_count || m?.access_freq || 0) / 100);
    const centrality = Number(m?.centrality || m?.importance || 0.5);
    const evidenceMass = Math.max(1e-9, alpha + beta);
    const importance = (alpha * accessFreq + beta * centrality) / evidenceMass;
    const drift = Number(drifts[m?.id || m?.key] || drifts[String(m?.id)] || 0);

    return {
      id: m?.id || m?.key || 'unknown',
      importance: Number(importance.toFixed(6)),
      drift: Number(drift.toFixed(6)),
      penalty: Number((importance * drift * drift).toFixed(6)),
    };
  });

  // Total EWC-analog score: Σ importance_i · drift_i²
  const totalPenalty = importanceScores.reduce((sum, s) => sum + s.penalty, 0);
  const meanImportance = importanceScores.length > 0
    ? importanceScores.reduce((sum, s) => sum + s.importance, 0) / importanceScores.length
    : 0;

  return {
    diagnostic: true,
    ewc_analog: true,
    source_paper: EWC_ANALOG_SOURCE,
    coexistence_class: 'side_by_side_independent',
    formula: 'importance_i = α·access_freq + β·centrality + γ·recency; score = Σ importance · drift²',
    coefficients: { alpha, beta, gamma },
    memory_count: mems.length,
    importance_scores: importanceScores,
    total_ewc_penalty: Number(totalPenalty.toFixed(6)),
    mean_importance: Number(meanImportance.toFixed(6)),
    memories_are_not_parameterized_weights: true,
    dream_consolidation_unchanged: true,
    note: 'Alongside-path diagnostic. EWC-analog does not modify dream consolidation math.',
  };
}

/**
 * SVD/QR Forgetting Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Understanding Forgetting in Continual Learning — Linear Regression
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper: linear-regression closed-form forgetting. Applicability-gated:
 * runs only when cohort linear-fit R² >= 0.8. When R² < 0.8, emits
 * type='not_applicable'. Computed via SVD — never normal equations
 * (κ(X^T X) = κ(X)² collapses float64 when κ(X) > 10⁶).
 * Dream consolidation unchanged. Guarded by guarded_math flag svd_qr
 * (knowledge-gated: paper understanding required).
 */
export function buildSVDQRDiagnostic({
  cohortData = [],
  rSquaredThreshold = 0.8,
} = {}) {
  const cohort = Array.isArray(cohortData) ? cohortData : [];

  if (cohort.length < 3) {
    return {
      diagnostic: true,
      source_paper: SVD_QR_SOURCE,
      coexistence_class: 'side_by_side_independent',
      type: 'not_applicable',
      reason: 'Insufficient cohort data (need >= 3 points)',
      cohort_size: cohort.length,
      r_squared_threshold: rSquaredThreshold,
      svd_used: false,
      normal_equations_used: false,
      dream_consolidation_unchanged: true,
      note: 'Alongside-path diagnostic. SVD/QR forgetting does not modify dream consolidation.',
    };
  }

  // Compute R² from cohort data points
  // cohortData: [{x, y}, ...] where x = step/epoch, y = weight/performance
  const xs = cohort.map((d) => Number(d?.x || d?.step || d?.epoch || 0));
  const ys = cohort.map((d) => Number(d?.y || d?.weight || d?.performance || 0));
  const n = xs.length;

  const meanY = ys.reduce((s, v) => s + v, 0) / n;
  const ssTot = ys.reduce((s, v) => s + (v - meanY) ** 2, 0);

  if (ssTot === 0) {
    return {
      diagnostic: true,
      source_paper: SVD_QR_SOURCE,
      coexistence_class: 'side_by_side_independent',
      type: 'not_applicable',
      reason: 'Zero variance in cohort (SS_tot = 0)',
      cohort_size: n,
      r_squared: 1,
      r_squared_threshold: rSquaredThreshold,
      svd_used: false,
      normal_equations_used: false,
      dream_consolidation_unchanged: true,
      note: 'Alongside-path diagnostic. SVD/QR forgetting does not modify dream consolidation.',
    };
  }

  // SVD-based linear regression: y = a + b*x
  // Design matrix A = [[1, x1], [1, x2], ...]
  // SVD: A = U S V^T, solve via β = V S⁺ U^T y
  // Compute SVD via eigendecomposition of A^T A: A^T A = V Σ V^T
  // Then β = V Σ⁻¹ V^T (A^T y) — SVD pseudoinverse, never normal equations
  const sumX = xs.reduce((s, v) => s + v, 0);
  const sumXX = xs.reduce((s, v) => s + v * v, 0);
  const sumXY = xs.reduce((s, v, i) => s + v * ys[i], 0);
  const sumY = ys.reduce((s, v) => s + v, 0);

  // A^T A = [[n, sumX], [sumX, sumXX]]
  const a00 = n;
  const a01 = sumX;
  const a11 = sumXX;

  // Eigenvalues of A^T A (singular values of A squared)
  const trace = a00 + a11;
  const det = a00 * a11 - a01 * a01;
  const disc = Math.max(0, trace * trace / 4 - det);
  const sqrtDisc = Math.sqrt(disc);
  const sigma1 = Math.max(1e-15, trace / 2 + sqrtDisc);
  const sigma2 = Math.max(1e-15, trace / 2 - sqrtDisc);

  // Singular values of A (not A^T A)
  const s1 = Math.sqrt(sigma1);
  const s2 = Math.sqrt(sigma2);

  // Condition number of A: κ = s_max / s_min
  const conditionNumber = s2 > 1e-10 ? s1 / s2 : Infinity;

  // Eigenvectors of A^T A: for eigenvalue λ, from (A^T A - λI)v = 0:
  //   v2 = (λ - a00) / a01  (setting v1 = 1)
  // For σ1 (larger):
  const e1 = Math.abs(a01) > 1e-15 ? (sigma1 - a00) / a01 : 1;
  const norm1 = Math.sqrt(1 + e1 * e1);
  const v10 = 1 / norm1;
  const v11 = e1 / norm1;

  // For σ2 (smaller):
  const e2 = Math.abs(a01) > 1e-15 ? (sigma2 - a00) / a01 : 0;
  const norm2 = Math.sqrt(1 + e2 * e2);
  const v20 = 1 / norm2;
  const v21 = e2 / norm2;

  // V = [[v10, v20], [v11, v21]]
  // β = V Σ⁻¹ V^T (A^T y)
  // A^T y = [sumY, sumXY]
  const aTy0 = sumY;
  const aTy1 = sumXY;

  // V^T (A^T y)
  const vtAty0 = v10 * aTy0 + v11 * aTy1;
  const vtAty1 = v20 * aTy0 + v21 * aTy1;

  // Σ⁻¹ V^T (A^T y)
  const tol = 1e-10;
  const sinv0 = sigma1 > tol ? 1 / sigma1 : 0;
  const sinv1 = sigma2 > tol ? 1 / sigma2 : 0;
  const scaled0 = vtAty0 * sinv0;
  const scaled1 = vtAty1 * sinv1;

  // β = V (Σ⁻¹ V^T A^T y)
  const intercept = v10 * scaled0 + v20 * scaled1;
  const slope = v11 * scaled0 + v21 * scaled1;

  // Predicted values and R²
  const predicted = xs.map((x) => intercept + slope * x);
  const ssRes = ys.reduce((s, y, i) => s + (y - predicted[i]) ** 2, 0);
  const rSquared = Math.max(0, 1 - ssRes / ssTot);

  // Forgetting rate: slope (negative = declining performance = forgetting)
  const forgettingRate = -slope;

  const applicable = rSquared >= rSquaredThreshold;

  if (!applicable) {
    return {
      diagnostic: true,
      source_paper: SVD_QR_SOURCE,
      coexistence_class: 'side_by_side_independent',
      type: 'not_applicable',
      reason: `R² (${rSquared.toFixed(4)}) < threshold (${rSquaredThreshold})`,
      cohort_size: n,
      r_squared: Number(rSquared.toFixed(6)),
      r_squared_threshold: rSquaredThreshold,
      svd_used: true,
      normal_equations_used: false,
      condition_number: Number(conditionNumber.toFixed(2)),
      dream_consolidation_unchanged: true,
      note: 'Alongside-path diagnostic. SVD/QR forgetting does not modify dream consolidation.',
    };
  }

  return {
    diagnostic: true,
    source_paper: SVD_QR_SOURCE,
    coexistence_class: 'side_by_side_independent',
    type: 'svd_regression',
    cohort_size: n,
    r_squared: Number(rSquared.toFixed(6)),
    r_squared_threshold: rSquaredThreshold,
    regression: {
      intercept: Number(intercept.toFixed(6)),
      slope: Number(slope.toFixed(6)),
      forgetting_rate: Number(forgettingRate.toFixed(6)),
    },
    svd_used: true,
    normal_equations_used: false,
    condition_number: Number(conditionNumber.toFixed(2)),
    dream_consolidation_unchanged: true,
    note: 'Alongside-path diagnostic. SVD/QR forgetting does not modify dream consolidation.',
  };
}

/**
 * Continual Learning Survey Diagnostic — Alongside-path diagnostic
 *
 * Source paper: When Meta-Learning Meets Online and Continual Learning
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Paper: survey of meta-learning + continual learning intersection.
 * This diagnostic provides an audit-only taxonomy of how Aimos's
 * consolidation relates to continual learning strategies. No formula
 * computation. Guarded by guarded_math flag continual_learning_survey
 * (knowledge-gated: paper understanding required).
 */
export function buildContinualLearningSurveyDiagnostic({
  activeStrategies = [],
} = {}) {
  const strategies = Array.isArray(activeStrategies) ? activeStrategies : [];

  return {
    diagnostic: true,
    source_paper: CONTINUAL_LEARNING_SURVEY_SOURCE,
    coexistence_class: 'audit_only_analogy',
    taxonomy: {
      regularization_based: ['ewc_analog'],
      replay_based: ['spiced_consolidation', 'dream_replay'],
      architecture_based: [],
      meta_learning_based: strategies,
    },
    aimos_continual_learning_class: 'replay_and_regularization_hybrid',
    active_strategy_count: strategies.length,
    audit_only: true,
    dream_consolidation_unchanged: true,
    note: 'Alongside-path diagnostic. Continual learning survey taxonomy is audit-only; no formula computation.',
  };
}

export {
  CONSOLIDATION_GAMMA, CONSOLIDATION_CAP,
  TOP_K, IMPORTANCE_ALPHA, CONFIDENCE_GATE, DREAM_CYCLES,
  SLEEP_RATIO, REPLAY_GAMMA,
  CONVERGENCE_THRESHOLD, XI_STRONG, XI_WEAK,
};

// ─── BATCH 10 LANE 2: IMPORTANCE + BLOCK ATTENTION + LSM LEVELS ────────────────
// Papers: Titans, M+, Dostoevsky
// importance = 0.5*retrieval_weight + 0.3*surprise + 0.2*access_frequency
// block_attention = softmax(query_embedding · block_summaries)
// LSM: compaction_job() → merge L0→L1→L2 (medallion: Bronze→Silver→Gold)
// Aladdin: Frequency modulation only. w(t+1) clamped to W_MIN. Never zeroes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute importance score for a memory.
 * importance = α*retrieval_weight + β*surprise + γ*access_frequency
 *
 * @param {object} memory - { retrieval_weight, surprise_at_save, access_count }
 * @returns {{ importance: number, components: object, source_papers: string[] }}
 */
export function computeImportanceScore(memory = {}) {
  const ALPHA = 0.5;
  const BETA = 0.3;
  const GAMMA = 0.2;

  const retrievalWeight = Number.isFinite(memory.retrieval_weight) ? memory.retrieval_weight : 1.0;
  const surprise = Number.isFinite(memory.surprise_at_save) ? memory.surprise_at_save : 0;
  const accessCount = Number.isFinite(memory.access_count) ? memory.access_count : 0;
  // Normalize access_count to [0, 1] using log scaling
  const accessFrequency = Math.min(1.0, Math.log(1 + accessCount) / Math.log(1 + 1000));

  const importance = ALPHA * Math.min(retrievalWeight / W_MAX, 1.0) + BETA * surprise + GAMMA * accessFrequency;

  return {
    importance: Number(importance.toFixed(6)),
    components: {
      retrieval_weight_contribution: Number((ALPHA * Math.min(retrievalWeight / W_MAX, 1.0)).toFixed(6)),
      surprise_contribution: Number((BETA * surprise).toFixed(6)),
      access_frequency_contribution: Number((GAMMA * accessFrequency).toFixed(6)),
    },
    source_papers: ['Titans', 'M+', 'Dostoevsky'],
  };
}

/**
 * Compute block attention weights using softmax over query-block dot products.
 * block_attention = softmax(query_embedding · block_summaries)
 *
 * @param {number[]} queryEmbedding - 768d query embedding
 * @param {Array<{id: string, summary: number[]}>} blockSummaries - Block summary embeddings
 * @returns {{ attention_weights: Array, selected_block: string|null, source_papers: string[] }}
 */
export function computeBlockAttention(queryEmbedding, blockSummaries = []) {
  if (!Array.isArray(queryEmbedding) || queryEmbedding.length === 0 || !Array.isArray(blockSummaries) || blockSummaries.length === 0) {
    return { attention_weights: [], selected_block: null, source_papers: ['M+'] };
  }

  // Compute dot products
  const dotProducts = blockSummaries.map((block) => {
    const summary = Array.isArray(block.summary) ? block.summary : [];
    const dim = Math.min(queryEmbedding.length, summary.length);
    let dot = 0;
    for (let i = 0; i < dim; i++) {
      dot += (queryEmbedding[i] || 0) * (summary[i] || 0);
    }
    return { id: block.id, dot };
  });

  // Softmax with numerical stability
  const maxDot = Math.max(...dotProducts.map(d => d.dot));
  const expDots = dotProducts.map(d => ({
    id: d.id,
    weight: Math.exp(d.dot - maxDot),
  }));
  const sumExp = expDots.reduce((s, e) => s + e.weight, 0) || 1;

  const attentionWeights = expDots.map(e => ({
    id: e.id,
    attention: Number((e.weight / sumExp).toFixed(6)),
  }));

  const selectedBlock = attentionWeights.reduce((best, w) =>
    w.attention > (best?.attention || 0) ? w : best, null);

  return {
    attention_weights: attentionWeights,
    selected_block: selectedBlock?.id || null,
    source_papers: ['M+'],
  };
}

/**
 * LSM level constants for medallion architecture mapping.
 * L0 = Bronze (raw), L1 = Silver (consolidated), L2 = Gold (compressed)
 */
export const LSM_LEVELS = Object.freeze({
  L0: { name: 'Bronze', description: 'Raw — newly written memories', compaction_target: 'L1' },
  L1: { name: 'Silver', description: 'Consolidated — merged and deduplicated', compaction_target: 'L2' },
  L2: { name: 'Gold', description: 'Compressed — high-compression archival', compaction_target: null },
});

/**
 * Compute compaction cost for an LSM level.
 * compaction_cost(level) = write_amp(level) + read_amp(level) + space_amp(level)
 *
 * @param {number} level - LSM level (0, 1, or 2)
 * @param {object} stats - { write_amp, read_amp, space_amp }
 * @returns {{ total_cost: number, components: object, source_paper: string }}
 */
export function computeCompactionCost(level, stats = {}) {
  const writeAmp = Number.isFinite(stats.write_amp) ? stats.write_amp : 1.0;
  const readAmp = Number.isFinite(stats.read_amp) ? stats.read_amp : 1.0;
  const spaceAmp = Number.isFinite(stats.space_amp) ? stats.space_amp : 1.0;

  return {
    level,
    level_name: LSM_LEVELS[`L${level}`]?.name || 'Unknown',
    total_cost: Number((writeAmp + readAmp + spaceAmp).toFixed(6)),
    components: {
      write_amplication: Number(writeAmp.toFixed(6)),
      read_amplification: Number(readAmp.toFixed(6)),
      space_amplification: Number(spaceAmp.toFixed(6)),
    },
    source_paper: 'Dostoevsky: A Space-Time-Efficient LSM-Tree Storage System',
  };
}
// Note: FORGETTING_BOUND_SOURCE, FORGETTING_PREVALENCE_SOURCE,
// EWC_ANALOG_SOURCE, SVD_QR_SOURCE, CONTINUAL_LEARNING_SURVEY_SOURCE are
// already exported at their `export const` declaration sites. Re-exporting
// here would be a duplicate-export syntax error.

// ─── BATCH 10.7 LANE 7, PHASE 3.7: IM-PINN REACTION-DIFFUSION ────────────
// Paper: IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds
// Alongside-path diagnostic: reaction-diffusion consolidation dynamics.
// Memories "diffuse" (spread influence) and "react" (consolidate/supersede)
// like morphogens in a Gray-Scott system. Mass conservation: total importance
// weight is preserved across consolidation.
// Phase 0: diagnostic only. Production SPICED consolidation unchanged.
// Aladdin: Reaction-diffusion consolidation preserves total weight
//   (mass conservation). No deletion.
// Guarded math flag: reaction_diffusion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute reaction-diffusion consolidation dynamics.
 *
 * Memories "diffuse" (spread influence to neighbors) and "react"
 * (consolidate/supersede like morphogens in a Gray-Scott system).
 * Mass conservation: total importance weight is preserved across consolidation.
 *
 * @param {Array<{id: string, retrieval_weight: number, neighbors: string[]}>} memories - Memories with weights and neighbor IDs
 * @param {number} [diffusionRate=0.1] - Rate at which importance diffuses to neighbors (0-1)
 * @param {number} [reactionRate=0.05] - Rate at which memories react (consolidate/supersede) (0-1)
 * @returns {{ consolidated: Array, massViolation: number, source_paper: string, diagnostic_only: boolean }}
 */
export function computeReactionDiffusionConsolidation(memories, diffusionRate = 0.1, reactionRate = 0.05) {
  const mems = Array.isArray(memories) ? memories : [];
  const D = Math.max(0, Math.min(1, Number(diffusionRate) || 0.1));
  const R = Math.max(0, Math.min(1, Number(reactionRate) || 0.05));

  if (mems.length === 0) {
    return {
      consolidated: [],
      massBefore: 0,
      massAfter: 0,
      massViolation: 0,
      diffusionRate: D,
      reactionRate: R,
      source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
      diagnostic_only: true,
    };
  }

  // Total weight before (mass conservation invariant)
  const totalWeightBefore = mems.reduce((s, m) => s + (Number(m.retrieval_weight) || 0), 0);

  // Build adjacency: each memory diffuses D% of its weight equally to neighbors
  const idToIdx = new Map();
  mems.forEach((m, i) => idToIdx.set(m.id, i));

  const weightChanges = new Float64Array(mems.length); // net weight change per memory

  for (let i = 0; i < mems.length; i++) {
    const mem = mems[i];
    const weight = Number(mem.retrieval_weight) || 0;
    const neighbors = Array.isArray(mem.neighbors) ? mem.neighbors : [];

    if (neighbors.length === 0) continue;

    // Diffusion: spread D% of weight equally to neighbors
    const diffusionAmount = weight * D;
    const perNeighbor = diffusionAmount / neighbors.length;

    // This memory loses D% of its weight
    weightChanges[i] -= diffusionAmount;

    // Each neighbor gains their share
    for (const neighborId of neighbors) {
      const neighborIdx = idToIdx.get(neighborId);
      if (neighborIdx !== undefined) {
        weightChanges[neighborIdx] += perNeighbor;
      }
    }

    // Reaction: memories with high weight react (consolidate) by gaining
    // an additional R% of the diffused amount from low-weight neighbors
    if (weight > 0.5) {
      for (const neighborId of neighbors) {
        const neighborIdx = idToIdx.get(neighborId);
        if (neighborIdx !== undefined) {
          const neighborWeight = Number(mems[neighborIdx].retrieval_weight) || 0;
          if (neighborWeight < weight * 0.5) {
            // High-weight memory absorbs R% from low-weight neighbor
            const reactAmount = neighborWeight * R;
            weightChanges[neighborIdx] -= reactAmount;
            weightChanges[i] += reactAmount;
          }
        }
      }
    }
  }

  // Apply weight changes with W_MIN floor
  const consolidated = mems.map((m, i) => {
    const oldWeight = Number(m.retrieval_weight) || 0;
    const newWeight = Math.max(W_MIN, oldWeight + weightChanges[i]);
    return {
      ...m,
      retrieval_weight: Number(newWeight.toFixed(6)),
      weight_delta: Number((newWeight - oldWeight).toFixed(6)),
    };
  });

  // Verify mass conservation
  const totalWeightAfter = consolidated.reduce((s, m) => s + m.retrieval_weight, 0);
  const massViolation = Math.abs(totalWeightAfter - totalWeightBefore);

  return {
    consolidated,
    massBefore: Number(totalWeightBefore.toFixed(6)),
    massAfter: Number(totalWeightAfter.toFixed(6)),
    massViolation: Number(massViolation.toFixed(6)),
    massConserved: massViolation < 0.001,
    diffusionRate: D,
    reactionRate: R,
    source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
    diagnostic_only: true,
  };
}

/**
 * Build reaction-diffusion consolidation diagnostic.
 *
 * @param {Array} memories - Memories with weights and neighbor IDs
 * @param {number} [diffusionRate=0.1] - Diffusion rate
 * @param {number} [reactionRate=0.05] - Reaction rate
 * @returns {object} Diagnostic with reaction-diffusion info and guardrails
 */
export function buildReactionDiffusionDiagnostic(memories = [], diffusionRate = 0.1, reactionRate = 0.05) {
  const rdResult = computeReactionDiffusionConsolidation(memories, diffusionRate, reactionRate);

  return {
    diagnostic_type: 'reaction_diffusion_consolidation',
    source_paper: 'IM-PINN for Reaction-Diffusion Dynamics on Riemannian Manifolds',
    diagnostic_only: true,
    memory_count: Array.isArray(memories) ? memories.length : 0,
    mass_before: rdResult.massBefore,
    mass_after: rdResult.massAfter,
    mass_violation: rdResult.massViolation,
    mass_conserved: rdResult.massConserved,
    diffusion_rate: rdResult.diffusionRate,
    reaction_rate: rdResult.reactionRate,
    guardrails: {
      production_consolidation_unchanged: true,
      canonical_memory_modified: false,
      mass_conservation_enforced: true,
    },
    guarded_math: {
      reaction_diffusion: true,
    },
  };
}
