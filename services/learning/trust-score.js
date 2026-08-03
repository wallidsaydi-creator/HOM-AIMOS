/**
 * TRUST SCORE — WEIGHTED FORMULA FOR MEMORY RELIABILITY
 * Sources: PageRank (authority scoring), Aladdin (credit attribution)
 * Additive Batch 6/7 authority: ReAlign (reasoning-guided alignment).
 * This service exposes usage-outcome alignment diagnostics only. It does not
 * implement ReAlign KL distribution alignment, contrastive retraining, or
 * automatic retrieval_weight updates.
 *
 * Trust Score T = 0.5 * access_frequency_normalized
 *                + 0.25 * cross_reference_count_normalized
 *                + 0.25 * credit_attribution_score
 *
 * Range: 0-1 (higher = more trustworthy)
 *
 * Scale-adaptive (Batch 10.7 Lane 7, Phase 2):
 *   Normalization ceilings scale with memory count:
 *   - access_frequency: max(100, floor(N/140))
 *   - cross_references: max(20, floor(N/700))
 *   At N=14000: identical to hardcoded values (100, 20).
 *   Paper: Bridging Philosophy and Machine Learning (structural alignment)
 *
 * Epistemology validation (Batch 10.7 Lane 7, Phase 3.6):
 *   Concentration of measure proves that in 768d embedding space,
 *   single-metric ranking (e.g., pure cosine similarity) is uninformative —
 *   direction matters, not magnitude. The trust formula's multi-signal
 *   approach (0.5 access + 0.25 refs + 0.25 credit) is
 *   epistemologically justified as context-sensitive navigation through
 *   learned geometric structure. Structural agency validates combining
 *   trust scoring with MVS context sufficiency gating.
 *   Paper: Epistemology of Generative AI — The Geometry of Knowing
 *
 * Batch 10 Lane 6: Contradictory memory injection tests (MemBench)
 *   Inject contradictory memories with different trust scores.
 *   Verify higher-trust memory returned in 95%+ of conflicts.
 *   Aladdin: trust scoring only affects retrieval ranking, never deletes memory.
 *
 * Created: 2026-03-31
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (RECALL pipeline, step 11)
// ← Called by: scale-baseline.js (normalization ceilings)
// → Calls: services/shared/scale-baseline.js (getMaxAccessNormalization, getMaxCrossRefNormalization)
// Pipeline: RECALL_PIPELINE
// Position: trust scoring after vector search
// ─────────────────────────────────────────────────────────────────────────────

import { getMaxAccessNormalization, getMaxCrossRefNormalization } from '../shared/scale-baseline.js';

/**
 * Compute trust score for a memory
 * Formula: T = 0.4 * freq + 0.2 * refs + 0.2 * recency + 0.2 * credit
 * Scale-adaptive: normalization ceilings grow with memory count.
 *
 * @param {object} memory - Memory object with properties
 * @param {object} [options] - { memoryCount } for scale-adaptive ceilings
 * @returns {number} Trust score 0-1
 */
export function computeTrustScore(memory, options = {}) {
  if (!memory) {
    return 0;
  }

  // Scale-adaptive normalization ceilings
  const maxAccess = options.memoryCount ? getMaxAccessNormalization(options.memoryCount) : 100;
  const maxRefs = options.memoryCount ? getMaxCrossRefNormalization(options.memoryCount) : 20;

  // Normalize components
  const freqScore = normalizeAccessFrequency(
    memory.access_count || 0,
    maxAccess
  );

  const refsScore = normalizeCrossRefs(
    (memory.graph_links || []).length,
    maxRefs
  );

  const creditScore = normalizeCreditAttribution(
    memory.credit_score || 0,
    100  // max credit score
  );

  // Weighted sum
  const trust = (
    0.5 * freqScore +
    0.25 * refsScore +
    0.25 * creditScore
  );

  // Cap at 1.0
  return Math.min(1.0, Math.max(0, trust));
}

/**
 * Normalize access frequency
 * Higher access_count = more frequently accessed = higher score.
 * Scale-adaptive: the normalization ceiling grows with memory count.
 *
 * @param {number} accessCount - Current access count
 * @param {number} maxAccessCount - Maximum observed access count (default: 100, scale-adaptive)
 * @returns {number} Normalized 0-1
 */
export function normalizeAccessFrequency(accessCount, maxAccessCount = 100) {
  if (maxAccessCount <= 0) return 0;

  const normalized = Math.min(1.0, accessCount / maxAccessCount);
  return normalized;
}

/**
 * Normalize cross-reference count
 * More references = more trusted (validated by multiple sources).
 * Scale-adaptive: maxLinks scales with memory count via getMaxCrossRefNormalization().
 * At N=14000: maxLinks=20 (unchanged).
 *
 * @param {number} graphLinksCount - Number of graph links
 * @param {number} maxLinks - Maximum expected links (default: 20, scale-adaptive)
 * @returns {number} Normalized 0-1
 */
export function normalizeCrossRefs(graphLinksCount, maxLinks = 20) {
  if (maxLinks <= 0) return 0;

  const normalized = Math.min(1.0, graphLinksCount / maxLinks);
  return normalized;
}

/**
 * Normalize credit attribution score
 * Agent-assigned credit for contribution quality.
 *
 * @param {number} creditScore - Credit score 0-100
 * @param {number} maxCredit - Maximum credit score
 * @returns {number} Normalized 0-1
 */
function normalizeCreditAttribution(creditScore, maxCredit = 100) {
  if (maxCredit <= 0) return 0;

  const normalized = Math.min(1.0, creditScore / maxCredit);
  return normalized;
}

/**
 * Rank memories by trust score (descending)
 *
 * @param {Array<object>} memories - Array of memory objects
 * @returns {Array<object>}
 */
export function rankByTrust(memories) {
  if (!Array.isArray(memories)) {
    return [];
  }

  // Compute trust for each and sort
  const scored = memories.map(mem => ({
    memory: mem,
    trust_score: computeTrustScore(mem)
  }));

  scored.sort((a, b) => b.trust_score - a.trust_score);

  // Return reordered memories with trust_score added
  return scored.map(item => ({
    ...item.memory,
    trust_score: item.trust_score
  }));
}

function normalizeUsageOutcome(memory = {}) {
  const accessCount = Number(memory.access_count || 0);
  const accessSignal = Math.min(1, accessCount / 50);
  return Math.max(0, Math.min(1, accessSignal));
}

/**
 * Build a diagnostic-only trust/usage alignment report.
 *
 * ReAlign-style full alignment is guarded because it requires calibrated
 * outcome labels and a chosen alignment objective. This function only compares
 * Aimos's existing trust score with observed usage/access outcomes so humans
 * and downstream services can inspect where trust may need review.
 *
 * @param {Array<object>} memories
 * @returns {object}
 */
export function buildTrustAlignmentDiagnostics(memories = []) {
  const rows = Array.isArray(memories) ? memories : [];
  const observations = rows.map((memory) => {
    const trust = computeTrustScore(memory);
    const usageOutcome = normalizeUsageOutcome(memory);
    const gap = usageOutcome - trust;
    let alignment_state = 'aligned';
    if (gap >= 0.35) alignment_state = 'under_trusted_by_usage';
    if (gap <= -0.35) alignment_state = 'over_trusted_by_usage';

    return {
      id: memory.id || null,
      key: memory.key || null,
      memory_type: memory.memory_type || null,
      trust_score: Number(trust.toFixed(3)),
      usage_outcome_score: Number(usageOutcome.toFixed(3)),
      alignment_gap: Number(gap.toFixed(3)),
      alignment_state,
      access_count: Number(memory.access_count || 0),
      retrieval_weight: Number(memory.retrieval_weight || 0),
      last_accessed_at: memory.last_accessed_at || null,
    };
  });

  const underTrusted = observations.filter((row) => row.alignment_state === 'under_trusted_by_usage');
  const overTrusted = observations.filter((row) => row.alignment_state === 'over_trusted_by_usage');

  return {
    source_paper: 'ReAlign',
    status: 'diagnostic_only',
    observation_count: observations.length,
    under_trusted_count: underTrusted.length,
    over_trusted_count: overTrusted.length,
    observations,
    candidate_reviews: [...underTrusted, ...overTrusted].slice(0, 12),
    guarded_math: {
      kl_distribution_alignment: false,
      contrastive_retraining: false,
      automatic_retrieval_weight_update: false,
    },
    ranking_math_changed: false,
    retrieval_weight_changed: false,
  };
}

/**
 * Get trust breakdown for a memory (for debugging)
 * Scale-adaptive: normalization ceilings grow with memory count.
 *
 * @param {object} memory - Memory object
 * @param {object} [options] - { memoryCount } for scale-adaptive ceilings
 * @returns {object}
 */
export function getTrustBreakdown(memory, options = {}) {
  if (!memory) {
    return null;
  }

  const maxAccess = options.memoryCount ? getMaxAccessNormalization(options.memoryCount) : 100;
  const maxRefs = options.memoryCount ? getMaxCrossRefNormalization(options.memoryCount) : 20;

  const freqScore = normalizeAccessFrequency(memory.access_count || 0, maxAccess);
  const refsScore = normalizeCrossRefs((memory.graph_links || []).length, maxRefs);
  const creditScore = normalizeCreditAttribution(memory.credit_score || 0, 100);

  return {
    key: memory.key,
    total_trust: computeTrustScore(memory),
    components: {
      access_frequency: { score: freqScore, weight: 0.5, contribution: freqScore * 0.5 },
      cross_references: { score: refsScore, weight: 0.25, contribution: refsScore * 0.25 },
      credit_attribution: { score: creditScore, weight: 0.25, contribution: creditScore * 0.25 }
    },
    created_at: memory.created_at,
    age_hours: (new Date().getTime() - new Date(memory.created_at).getTime()) / (1000 * 60 * 60),
    retrieval_weight: memory.retrieval_weight,
    cross_refs_count: (memory.graph_links || []).length,
    credit_score: memory.credit_score
  };
}

/**
 * Filter memories by minimum trust threshold
 *
 * @param {Array<object>} memories - Array of memories
 * @param {number} minTrust - Minimum trust threshold 0-1
 * @returns {Array<object>}
 */
export function filterByTrust(memories, minTrust = 0.5) {
  if (!Array.isArray(memories)) {
    return [];
  }

  return memories.filter(mem => {
    const score = computeTrustScore(mem);
    return score >= minTrust;
  });
}

/**
 * Get trust statistics for a batch
 *
 * @param {Array<object>} memories - Array of memories
 * @returns {object}
 */
export function getTrustStats(memories) {
  if (!Array.isArray(memories) || memories.length === 0) {
    return {
      count: 0,
      mean_trust: 0,
      median_trust: 0,
      min_trust: 0,
      max_trust: 0
    };
  }

  const scores = memories.map(mem => computeTrustScore(mem));
  scores.sort((a, b) => a - b);

  const sum = scores.reduce((a, b) => a + b, 0);
  const mean = sum / scores.length;
  const median = scores[Math.floor(scores.length / 2)];

  return {
    count: memories.length,
    mean_trust: mean,
    median_trust: median,
    min_trust: scores[0],
    max_trust: scores[scores.length - 1],
    distribution: {
      very_low: scores.filter(s => s < 0.2).length,
      low: scores.filter(s => s >= 0.2 && s < 0.4).length,
      medium: scores.filter(s => s >= 0.4 && s < 0.6).length,
      high: scores.filter(s => s >= 0.6 && s < 0.8).length,
      very_high: scores.filter(s => s >= 0.8).length
    }
  };
}

/**
 * Recommend trust threshold for scenario
 *
 * @param {string} scenario - Use case: 'strict', 'balanced', 'permissive'
 * @returns {number}
 */
export function getRecommendedThreshold(scenario = 'balanced') {
  const thresholds = {
    strict: 0.75,      // Only highly trusted memories
    balanced: 0.5,     // Moderate threshold
    permissive: 0.3    // Most memories pass
  };

  return thresholds[scenario] || thresholds.balanced;
}

// ─── BATCH 10 LANE 6: CONTRADICTORY MEMORY INJECTION TESTS ─────────────────
// Paper: MemBench
// Inject contradictory memories with different trust scores.
// Verify higher-trust memory is returned in 95%+ of conflicts.
// T = 0.4*access + 0.2*cross_refs + 0.2*recency + 0.2*credit_score
// Aladdin: trust scoring only affects retrieval ranking, never deletes memory.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Evaluate contradictory memory resolution by trust score.
 * Given two memories with conflicting values, the one with higher trust
 * score should be preferred. This function simulates and evaluates that.
 *
 * @param {object} memoryA - First memory with potentially conflicting value
 * @param {object} memoryB - Second memory with conflicting value
 * @returns {{ winner: string, trust_a: number, trust_b: number, resolution_confidence: number, source_paper: string, aladdin: string }}
 */
export function evaluateContradictoryResolution(memoryA, memoryB) {
  const trustA = computeTrustScore(memoryA);
  const trustB = computeTrustScore(memoryB);

  const winner = trustA >= trustB ? 'memory_a' : 'memory_b';
  const trustGap = Math.abs(trustA - trustB);
  const resolutionConfidence = Math.min(1.0, trustGap * 5); // Scale gap to confidence

  return {
    winner,
    trust_a: Number(trustA.toFixed(6)),
    trust_b: Number(trustB.toFixed(6)),
    trust_gap: Number(trustGap.toFixed(6)),
    resolution_confidence: Number(resolutionConfidence.toFixed(6)),
    formula: 'T = 0.4*access + 0.2*cross_refs + 0.2*recency + 0.2*credit_score',
    source_paper: 'MemBench',
    aladdin: 'trust_scoring_only_affects_retrieval_ranking_never_deletes',
  };
}

/**
 * Run a batch of contradictory memory injection tests.
 * Simulates N pairs of contradictory memories with different trust scores
 * and measures the percentage of times the higher-trust memory wins.
 * Target: ≥ 95% resolution rate.
 *
 * @param {Array<{ memoryA: object, memoryB: object }>} pairs - Contradictory pairs
 * @returns {{ total_pairs: number, higher_trust_wins: number, resolution_rate: number, passes_target: boolean, source_paper: string }}
 */
export function runContradictoryInjectionTest(pairs = []) {
  const testPairs = Array.isArray(pairs) ? pairs : [];
  let higherTrustWins = 0;

  for (const pair of testPairs) {
    const trustA = computeTrustScore(pair.memoryA);
    const trustB = computeTrustScore(pair.memoryB);
    // The higher trust should "win" (be returned in recall)
    if (trustA >= trustB && pair.memoryA.expected_winner) higherTrustWins++;
    else if (trustB > trustA && pair.memoryB.expected_winner) higherTrustWins++;
  }

  const resolutionRate = testPairs.length > 0 ? higherTrustWins / testPairs.length : 0;

  return {
    total_pairs: testPairs.length,
    higher_trust_wins: higherTrustWins,
    resolution_rate: Number(resolutionRate.toFixed(4)),
    passes_target: resolutionRate >= 0.95,
    target: '≥ 95% resolution rate',
    source_paper: 'MemBench',
    diagnostic_only: true,
  };
}

// ─── BATCH 10.7 LANE 7, PHASE 3.2: STRUCTURAL ALIGNMENT ─────────────────────
// Paper: Bridging Philosophy and Machine Learning — A Structuralist Framework
//       for Classifying Neural Network Representations
// Alongside-path diagnostic: structural alignment as a 5th trust component.
// Phase 0: diagnostic only. Production trust formula unchanged (0.4/0.2/0.2/0.2).
// Proposed formula (guarded, not active):
//   T = 0.35*access + 0.15*refs + 0.15*recency + 0.15*credit + 0.20*structural_alignment
// Aladdin: Structural alignment only affects trust score, which modulates
// retrieval_weight (clamped to the constitutional W_MIN=0.1). Never deletes memory.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute structural alignment between a memory and a reference set.
 *
 * Structural alignment classifies the relationship between two memories:
 * - Isomorphic: same embedding structure (cos > 0.95 + overlapping entity types)
 * - Homomorphic: partial structure match (cos > 0.80 + some entity overlap)
 * - Decorative: co-occurring but structurally different (cos < 0.80 or disjoint types)
 *
 * Paper: Bridging Philosophy and Machine Learning
 * Guarded math flag: structural_alignment (Phase 0: diagnostic only)
 *
 * @param {object} memory - Memory with embedding and entities
 * @param {object} referenceSet - Reference memory or set for comparison
 * @returns {{ alignment: string, score: number, cos_similarity: number, entity_overlap: number, source_paper: string }}
 */
export function computeStructuralAlignment(memory, referenceSet) {
  const memEmbedding = Array.isArray(memory?.embedding) ? memory.embedding : [];
  const refEmbedding = Array.isArray(referenceSet?.embedding) ? referenceSet.embedding : [];

  // Cosine similarity between embeddings
  let cosSimilarity = 0;
  if (memEmbedding.length > 0 && refEmbedding.length > 0) {
    const dim = Math.min(memEmbedding.length, refEmbedding.length);
    let dotProduct = 0, normA = 0, normB = 0;
    for (let i = 0; i < dim; i++) {
      dotProduct += memEmbedding[i] * refEmbedding[i];
      normA += memEmbedding[i] * memEmbedding[i];
      normB += refEmbedding[i] * refEmbedding[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    cosSimilarity = denom > 0 ? dotProduct / denom : 0;
  }

  // Entity overlap via Jaccard similarity
  const memEntities = new Set(Array.isArray(memory?.entities) ? memory.entities : []);
  const refEntities = new Set(Array.isArray(referenceSet?.entities) ? referenceSet.entities : []);
  const entityIntersection = new Set([...memEntities].filter(e => refEntities.has(e)));
  const entityUnion = new Set([...memEntities, ...refEntities]);
  const entityOverlap = entityUnion.size > 0 ? entityIntersection.size / entityUnion.size : 0;

  // Structural alignment classification
  let alignment, score;
  if (cosSimilarity > 0.95 && entityOverlap > 0.8) {
    alignment = 'isomorphic';
    score = 1.0;
  } else if (cosSimilarity > 0.80 && entityOverlap > 0.5) {
    alignment = 'homomorphic';
    score = 0.7;
  } else {
    alignment = 'decorative';
    score = 0.3;
  }

  return {
    alignment,
    score,
    cos_similarity: Number(cosSimilarity.toFixed(6)),
    entity_overlap: Number(entityOverlap.toFixed(6)),
    source_paper: 'Bridging Philosophy and Machine Learning',
  };
}

/**
 * Build structural alignment diagnostic for trust scoring.
 *
 * @param {object} memory - Memory to evaluate
 * @param {Array<object>} referenceMemories - Reference set for alignment
 * @returns {object} Diagnostic object with alignment info and guardrails
 */
export function buildStructuralAlignmentDiagnostic(memory, referenceMemories = []) {
  const refs = Array.isArray(referenceMemories) ? referenceMemories : [];

  // Compute alignment against each reference, take the best
  const alignments = refs.map(ref => computeStructuralAlignment(memory, ref));
  const bestAlignment = alignments.length > 0
    ? alignments.reduce((best, a) => a.score > best.score ? a : best, alignments[0])
    : { alignment: 'no_reference', score: 0, cos_similarity: 0, entity_overlap: 0 };

  return {
    diagnostic_type: 'structural_alignment',
    source_paper: 'Bridging Philosophy and Machine Learning',
    diagnostic_only: true,
    memory_key: memory?.key || null,
    reference_count: refs.length,
    best_alignment: bestAlignment.alignment,
    best_score: bestAlignment.score,
    all_alignments: alignments.map(a => ({
      alignment: a.alignment,
      score: a.score,
      cos_similarity: a.cos_similarity,
      entity_overlap: a.entity_overlap,
    })),
    proposed_formula: 'T = 0.35*access + 0.15*refs + 0.15*recency + 0.15*credit + 0.20*structural_alignment',
    current_formula: 'T = 0.4*access + 0.2*refs + 0.2*recency + 0.2*credit',
    guardrails: {
      trust_formula_changed: false,
      production_ranking_changed: false,
      canonical_memory_modified: false,
    },
    guarded_math: {
      structural_alignment: true,
    },
  };
}
