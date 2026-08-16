/**
 * NATIVE EPISTEMIC TRUST RETRIEVAL
 *
 * Paper / corpus authority:
 * - PoisonedRAG: retrieval and generation conditions must both be controlled;
 *   exact duplicate and perplexity-only filters are insufficient.
 * - MMR: select by relevance while penalizing similarity to already selected
 *   evidence before the final disclosure boundary.
 * - Reasoning Graphs: reliability is evidence-specific and must have a
 *   graceful cold start.
 * - RAGCHECKER / VerifAI / Reason-and-Verify: provenance integrity, evidence
 *   support, and answer verification are distinct decisions.
 *
 * Aladdin contract:
 * - This service never deletes, suppresses, expires, or rewrites memory.
 * - A quarantine decision is a retained, reversible 0.1-frequency working-set
 *   state. Persistent retrieval-weight changes remain housekeeper-owned and
 *   must use the signed cognitive-weight chain.
 *
 * Pipeline position:
 * - after provenance admission and native relevance/confidence scoring;
 * - before final top-k disclosure and response calibration.
 */

import { createHash } from 'node:crypto';
import { canonicalJson } from '../security/agent-identity.js';
import {
  buildTwinPrimeTemporalCoordinates,
  computeB2Distance,
  computeTwinPrimeDistance,
  cosineDistance,
  gaussianTwinIndicator,
  parseNumericVector,
  quantizeTime,
  relativeGaussianCoordinate,
  simHash31,
  twinPrimeTemporalDistance,
} from './twin-prime-arithmetic.js';

export const EPISTEMIC_DECISION_VERSION = 'aimos-epistemic-retrieval-v2';
export const EPISTEMIC_ABLATION_VERSION = 'aimos-epistemic-ablation-v1';
export const TWIN_PRIME_SELECTION_VERSION = 'hom-aimos/twin-prime-selection/v1';

const PRODUCTION_POLICY = Object.freeze({
  policyId: 'production',
  applyRetainedQuarantine: true,
  applyStoredClassification: true,
  applyExplicitVerification: true,
  applyQueryLocalSignals: true,
  defaultMultiplier: 0.72,
  withholdUntrustedFromActiveContext: true,
});

const EPISTEMIC_ABLATION_POLICIES = Object.freeze([
  Object.freeze({
    policyId: 'A0',
    applyRetainedQuarantine: false,
    applyStoredClassification: false,
    applyExplicitVerification: false,
    applyQueryLocalSignals: false,
    defaultMultiplier: 1,
    withholdUntrustedFromActiveContext: false,
  }),
  Object.freeze({
    policyId: 'A1',
    applyRetainedQuarantine: true,
    applyStoredClassification: true,
    applyExplicitVerification: true,
    applyQueryLocalSignals: false,
    defaultMultiplier: 0.72,
    withholdUntrustedFromActiveContext: false,
  }),
  Object.freeze({
    policyId: 'A2',
    applyRetainedQuarantine: true,
    applyStoredClassification: true,
    applyExplicitVerification: true,
    applyQueryLocalSignals: true,
    defaultMultiplier: 0.72,
    withholdUntrustedFromActiveContext: false,
  }),
  Object.freeze({
    policyId: 'A3',
    applyRetainedQuarantine: true,
    applyStoredClassification: true,
    applyExplicitVerification: true,
    applyQueryLocalSignals: true,
    defaultMultiplier: 0.72,
    withholdUntrustedFromActiveContext: true,
  }),
]);

export const EPISTEMIC_ABLATION_POLICY_IDS = Object.freeze(
  EPISTEMIC_ABLATION_POLICIES.map((policy) => policy.policyId),
);

const STORED_EPISTEMIC_STATES = Object.freeze({
  poison_confirmed: { state: 'poison_confirmed', handling: 'untrusted_reference_only', multiplier: 0.1, persistent: true },
  poison_likely: { state: 'poison_likely', handling: 'untrusted_reference_only', multiplier: 0.1, persistent: true },
  poison_suspect: { state: 'poison_suspect', handling: 'untrusted_reference_only', multiplier: 0.25, persistent: false },
  disputed: { state: 'disputed', handling: 'contradictory_reference', multiplier: 0.4, persistent: false },
  supported: { state: 'supported', handling: 'supported_reference', multiplier: 1, persistent: false },
  poison_refuted: { state: 'poison_refuted', handling: 'supported_reference', multiplier: 1, persistent: true },
});

const QUERY_STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'but', 'by', 'can',
  'did', 'do', 'does', 'for', 'from', 'had', 'has', 'have', 'how', 'in',
  'is', 'it', 'of', 'on', 'or', 'that', 'the', 'their', 'then', 'there',
  'they', 'this', 'to', 'was', 'were', 'what', 'when', 'where', 'which',
  'who', 'why', 'will', 'with', 'would', 'you', 'your',
]);

const EXPLICIT_VERIFICATION_BASES = new Set([
  'independent_evidence',
  'independent_verification',
  'publisher_verified_genesis',
  'supervisor_verified',
  'tool_attested',
  'tool_verified',
]);

function clamp01(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(1, number));
}

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenSet(value, { removeStopwords = false } = {}) {
  const tokens = normalizeText(value).split(' ').filter(Boolean);
  return new Set(removeStopwords ? tokens.filter((token) => !QUERY_STOPWORDS.has(token)) : tokens);
}

function jaccard(left, right) {
  if (!left.size || !right.size) return 0;
  let intersection = 0;
  for (const token of left) {
    if (right.has(token)) intersection += 1;
  }
  const union = left.size + right.size - intersection;
  return union > 0 ? intersection / union : 0;
}

function queryCoverage(queryTokens, memoryTokens) {
  if (!queryTokens.size) return 0;
  let covered = 0;
  for (const token of queryTokens) {
    if (memoryTokens.has(token)) covered += 1;
  }
  return covered / queryTokens.size;
}

function relevanceFor(memory, index, total) {
  const candidates = [
    memory?.calibrated_recall_score,
    memory?._raw_rerank,
    memory?.rerank_score,
    memory?.recall_confidence,
    memory?.score,
  ];
  for (const value of candidates) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return clamp01(parsed);
  }
  return total > 0 ? 1 - (index / Math.max(1, total)) : 0;
}

function provenanceValid(memory) {
  const proof = memory?.provenance_proof;
  return Boolean(
    proof
    && /^[0-9a-f]{64}$/i.test(String(proof.live_content_hash || ''))
    && /^[0-9a-f]{64}$/i.test(String(proof.save_mutation_hash || ''))
    && /^[0-9a-f]{64}$/i.test(String(proof.binding_mutation_hash || ''))
  );
}

function explicitVerification(memory) {
  const basis = String(memory?.verification_basis || '').trim().toLowerCase();
  return EXPLICIT_VERIFICATION_BASES.has(basis) && Boolean(String(memory?.verified_by || '').trim());
}

function isRetainedQuarantine(memory) {
  return memory?.scope === 'quarantine'
    || memory?.memory_type === 'quarantine'
    || Number(memory?.retrieval_weight) === 0.1
    || memory?.evidence_handling === 'untrusted_reference_only';
}

function candidateContentHash(memory) {
  const liveHash = String(memory?.provenance_proof?.live_content_hash || '').toLowerCase();
  if (/^[0-9a-f]{64}$/.test(liveHash)) return liveHash;
  return createHash('sha256').update(String(memory?.value || ''), 'utf8').digest('hex');
}

function annotateCandidates(query, memories, policy = PRODUCTION_POLICY) {
  const normalizedQuery = normalizeText(query);
  const queryTokens = tokenSet(query, { removeStopwords: true });
  const candidates = memories.map((memory, index) => {
    const normalizedValue = normalizeText(memory?.value || '');
    const contentTokens = tokenSet(memory?.value || '', { removeStopwords: true });
    const prefixEcho = normalizedQuery.length >= 12
      && (normalizedValue === normalizedQuery || normalizedValue.startsWith(`${normalizedQuery} `));
    return {
      memory,
      index,
      contentTokens,
      source: String(memory?.source || 'unknown'),
      queryCoverage: queryCoverage(queryTokens, contentTokens),
      prefixEcho,
      relevance: relevanceFor(memory, index, memories.length),
      contentHash: candidateContentHash(memory),
    };
  });

  const echoedBySource = new Map();
  for (const candidate of candidates) {
    if (!candidate.prefixEcho || candidate.queryCoverage < 0.8) continue;
    echoedBySource.set(candidate.source, (echoedBySource.get(candidate.source) || 0) + 1);
  }

  const distinctSources = new Set(candidates.map((candidate) => candidate.source)).size;
  for (const candidate of candidates) {
    let maxSimilarity = 0;
    let redundantCount = 0;
    for (const other of candidates) {
      if (other === candidate) continue;
      const similarity = jaccard(candidate.contentTokens, other.contentTokens);
      maxSimilarity = Math.max(maxSimilarity, similarity);
      if (similarity >= 0.55) redundantCount += 1;
    }

    const queryLureCluster = candidate.prefixEcho
      && candidate.queryCoverage >= 0.8
      && (echoedBySource.get(candidate.source) || 0) >= 3;
    const retainedQuarantine = isRetainedQuarantine(candidate.memory);
    const supported = explicitVerification(candidate.memory);
    const storedLabel = String(candidate.memory?.current_epistemic_label || 'unverified').trim().toLowerCase();
    const storedClassification = STORED_EPISTEMIC_STATES[storedLabel] || null;
    let epistemicState = 'unverified';
    let evidenceHandling = 'unverified_reference';
    let multiplier = policy.defaultMultiplier;
    let persistentReweightEligible = false;

    if (policy.applyRetainedQuarantine && retainedQuarantine) {
      epistemicState = 'retained_quarantine';
      evidenceHandling = 'untrusted_reference_only';
      multiplier = 0.1;
    } else if (policy.applyStoredClassification && storedClassification) {
      epistemicState = storedClassification.state;
      evidenceHandling = storedClassification.handling;
      multiplier = storedClassification.multiplier;
      persistentReweightEligible = storedClassification.persistent;
    } else if (policy.applyExplicitVerification && supported) {
      epistemicState = 'supported';
      evidenceHandling = 'supported_reference';
      multiplier = 1;
    } else if (policy.applyQueryLocalSignals && queryLureCluster) {
      epistemicState = 'query_lure_cluster';
      evidenceHandling = 'untrusted_reference_only';
      multiplier = 0.1;
      persistentReweightEligible = true;
    } else if (
      policy.applyQueryLocalSignals
      && candidate.prefixEcho
      && candidate.queryCoverage >= 0.8
    ) {
      // One exact echo is enough to keep the passage out of factual support,
      // but not enough to justify a persistent cognitive mutation. A benign
      // quoted question therefore remains fully retained and reversible.
      epistemicState = 'query_lure_suspect';
      evidenceHandling = 'untrusted_reference_only';
      multiplier = 0.25;
    }

    candidate.maxSimilarity = maxSimilarity;
    candidate.redundantCount = redundantCount;
    candidate.epistemicState = epistemicState;
    candidate.evidenceHandling = evidenceHandling;
    candidate.epistemicScore = multiplier;
    candidate.persistentReweightEligible = persistentReweightEligible;
    candidate.distinctSources = distinctSources;
    candidate.echoClusterSize = echoedBySource.get(candidate.source) || 0;
    candidate.storedEpistemicLabel = storedLabel;
    candidate.storedEpistemicConfidenceMilli = Math.max(
      0,
      Math.min(1000, Math.trunc(Number(candidate.memory?.current_epistemic_confidence_milli) || 0)),
    );
    candidate.storedEpistemicEventId = candidate.memory?.current_epistemic_event_id || null;
    candidate.effectiveRelevance = candidate.relevance * multiplier;
  }
  return candidates;
}

function selectMmr(candidates, limit) {
  const selected = [];
  const remaining = [...candidates];
  const lambda = 0.72;
  while (remaining.length && selected.length < limit) {
    let bestIndex = 0;
    let bestScore = -Infinity;
    for (let index = 0; index < remaining.length; index += 1) {
      const candidate = remaining[index];
      const similarityToSelected = selected.reduce(
        (maximum, selectedCandidate) => Math.max(
          maximum,
          jaccard(candidate.contentTokens, selectedCandidate.contentTokens),
        ),
        0,
      );
      const score = (lambda * candidate.effectiveRelevance) - ((1 - lambda) * similarityToSelected);
      if (score > bestScore || (score === bestScore && candidate.index < remaining[bestIndex].index)) {
        bestScore = score;
        bestIndex = index;
      }
    }
    const [picked] = remaining.splice(bestIndex, 1);
    picked.mmrScore = bestScore;
    selected.push(picked);
  }
  return selected;
}

function policyRational(value, name) {
  const text = String(value);
  if (/^\d+$/.test(text)) return Number(text);
  const match = text.match(/^(\d+)\/(\d+)$/);
  if (!match || Number(match[2]) === 0) throw new TypeError(`${name}_invalid`);
  return Number(match[1]) / Number(match[2]);
}

function validOriginEvidence(memory) {
  const proof = memory?.provenance_proof;
  const milliseconds = new Date(proof?.memory_originated_at).getTime();
  return Number(proof?.binding_schema_version) === 4
    && proof?.historical_signature_status === 'original_save_verified'
    && Number.isSafeInteger(milliseconds)
    && milliseconds > 0
    ? milliseconds
    : null;
}

function isInsideTemporalConstraint(memoryTime, temporal) {
  if (!temporal?.constrained) return true;
  if (temporal.start != null && memoryTime < temporal.start) return false;
  if (temporal.end != null && memoryTime >= temporal.end) return false;
  return true;
}

function twinPrimeSelection(candidates, limit, context) {
  const policy = context?.policy;
  const policyMutationHash = String(context?.policyMutationHash || '').toLowerCase();
  if (!policy || !/^[0-9a-f]{64}$/.test(policyMutationHash)) {
    throw new TypeError('verified_twin_prime_policy_required');
  }

  const baseline = selectMmr(candidates.map((candidate) => ({ ...candidate })), limit);
  const baselineIds = baseline.map((candidate) => String(candidate.memory?.id || candidate.memory?.memory_id || ''));
  const preArmIds = candidates.map((candidate) => String(candidate.memory?.id || candidate.memory?.memory_id || ''));
  const baseEvidence = {
    version: TWIN_PRIME_SELECTION_VERSION,
    policy: { ...policy },
    policy_mutation_hash: policyMutationHash,
    pre_arm_candidate_ids: preArmIds,
    pre_arm_candidate_count: preArmIds.length,
    baseline_selected_memory_ids: baselineIds,
  };

  if (context.eligible === false || policy.arm === 'B0') {
    return {
      returned: baseline,
      evidenceById: new Map(),
      decision: {
        ...baseEvidence,
        eligible: context.eligible !== false,
        ineligible_reason: context.eligible === false ? String(context.ineligibleReason || 'native_lane_ineligible') : null,
        computed_selected_memory_ids: baselineIds,
        returned_selected_memory_ids: baselineIds,
        feature_counts: { active_context_eligible: 0, temporal_eligible: 0, tau: 0 },
        shadow_returned_baseline: false,
      },
    };
  }

  const featureById = context.featuresByMemoryId instanceof Map
    ? context.featuresByMemoryId
    : new Map(Object.entries(context.featuresByMemoryId || {}));
  const rows = candidates.map((candidate) => {
    const memoryId = String(candidate.memory?.id || candidate.memory?.memory_id || '');
    const feature = featureById.get(memoryId) || {};
    const originTime = validOriginEvidence(candidate.memory);
    const activeContextEligible = candidate.evidenceHandling !== 'untrusted_reference_only';
    return {
      candidate,
      memoryId,
      embedding: feature.embedding,
      originTime,
      activeContextEligible,
    };
  });
  const verifiedTimes = rows.filter((row) => row.activeContextEligible && row.originTime != null)
    .map((row) => row.originTime);
  if (!verifiedTimes.length) {
    return {
      returned: baseline,
      evidenceById: new Map(rows.map((row) => [row.memoryId, {
        active_context_eligible: row.activeContextEligible,
        temporal_eligible: false,
        ineligible_reason: row.activeContextEligible ? 'tp_g0_origin_evidence_missing' : 'untrusted_active_context',
      }])),
      decision: {
        ...baseEvidence,
        eligible: false,
        ineligible_reason: 'verified_candidate_time_scope_empty',
        computed_selected_memory_ids: baselineIds,
        returned_selected_memory_ids: baselineIds,
        feature_counts: { active_context_eligible: 0, temporal_eligible: 0, tau: 0 },
        shadow_returned_baseline: false,
      },
    };
  }

  const requestTimeMs = Number(context.requestTimeMs);
  if (!Number.isSafeInteger(requestTimeMs) || requestTimeMs <= 0) {
    throw new TypeError('signed_request_time_required');
  }
  const scopeMin = Math.min(...verifiedTimes);
  const scopeMax = Math.max(...verifiedTimes);
  const scopeSpan = Math.max(1, scopeMax - scopeMin);
  const temporal = buildTwinPrimeTemporalCoordinates({
    temporalScope: context.temporalScope || {},
    requestTimeMs,
    scopeMin,
    scopeMax,
  });
  const lambdaT = policyRational(policy.lambda_t, 'lambda_t');
  const gamma = policyRational(policy.gamma, 'gamma');
  const requiresEmbedding = policy.arm === 'B2' || policy.arm === 'T';
  const queryEmbedding = requiresEmbedding ? parseNumericVector(context.queryEmbedding) : null;
  const querySubject = policy.arm === 'T' ? simHash31(queryEmbedding).coordinate : null;
  let tauCount = 0;
  let activeContextCount = 0;
  let temporalEligibleCount = 0;
  const evidenceById = new Map();
  const armCandidates = [];

  for (const row of rows) {
    let ineligibleReason = null;
    if (!row.activeContextEligible) ineligibleReason = 'untrusted_active_context';
    else if (row.originTime == null) ineligibleReason = 'tp_g0_origin_evidence_missing';
    const temporalEligible = ineligibleReason == null && isInsideTemporalConstraint(row.originTime, temporal);
    if (ineligibleReason == null && !temporalEligible) ineligibleReason = 'outside_signed_temporal_scope';
    if (row.activeContextEligible) activeContextCount += 1;
    if (temporalEligible) temporalEligibleCount += 1;

    const evidence = {
      active_context_eligible: row.activeContextEligible,
      temporal_eligible: temporalEligible,
      ineligible_reason: ineligibleReason,
      memory_originated_at: row.originTime == null ? null : new Date(row.originTime).toISOString(),
      semantic_distance: null,
      temporal_distance: null,
      b2_distance: null,
      tau: 0,
      arm_distance: null,
      arm_relevance: null,
      embedding_sha256: null,
    };

    if (ineligibleReason == null && requiresEmbedding) {
      try {
        const embedding = parseNumericVector(row.embedding);
        evidence.embedding_sha256 = createHash('sha256')
          .update(JSON.stringify(embedding), 'utf8')
          .digest('hex');
        evidence.semantic_distance = cosineDistance(queryEmbedding, embedding);
        evidence.temporal_distance = twinPrimeTemporalDistance(row.originTime, temporal, scopeSpan);
        evidence.b2_distance = computeB2Distance(evidence.semantic_distance, evidence.temporal_distance, lambdaT);
        if (policy.arm === 'T') {
          const memorySubject = simHash31(embedding).coordinate;
          const memoryTime = quantizeTime(row.originTime, scopeMin, scopeMax);
          const delta = relativeGaussianCoordinate(
            querySubject,
            memorySubject,
            temporal.queryQuantized,
            memoryTime,
          );
          evidence.tau = gaussianTwinIndicator(delta.real, delta.imaginary);
          evidence.delta_real = delta.real;
          evidence.delta_imaginary = delta.imaginary;
          tauCount += evidence.tau;
        }
        evidence.arm_distance = policy.arm === 'T'
          ? computeTwinPrimeDistance(evidence.b2_distance, gamma, evidence.tau)
          : evidence.b2_distance;
        // Positive monotone conversion keeps lower declared distance better,
        // while preserving the already-computed epistemic trust multiplier.
        evidence.arm_relevance = row.candidate.epistemicScore / (1 + evidence.arm_distance);
      } catch {
        ineligibleReason = 'candidate_embedding_invalid';
        evidence.ineligible_reason = ineligibleReason;
      }
    }

    if (ineligibleReason == null) {
      const armCandidate = { ...row.candidate };
      if (requiresEmbedding) armCandidate.effectiveRelevance = evidence.arm_relevance;
      armCandidates.push(armCandidate);
    }
    evidenceById.set(row.memoryId, evidence);
  }

  const computed = selectMmr(armCandidates, Math.min(limit, armCandidates.length));
  const computedIds = computed.map((candidate) => String(candidate.memory?.id || candidate.memory?.memory_id || ''));
  const returned = policy.execution === 'shadow' ? baseline : computed;
  const returnedIds = returned.map((candidate) => String(candidate.memory?.id || candidate.memory?.memory_id || ''));
  return {
    returned,
    evidenceById,
    decision: {
      ...baseEvidence,
      eligible: true,
      ineligible_reason: null,
      scope_time_min: new Date(scopeMin).toISOString(),
      scope_time_max: new Date(scopeMax).toISOString(),
      signed_request_time: new Date(requestTimeMs).toISOString(),
      temporal_scope: {
        kind: String(context.temporalScope?.kind || 'open'),
        start_day: context.temporalScope?.start_day || null,
        end_day_exclusive: context.temporalScope?.end_day_exclusive || null,
      },
      query_time_anchor: new Date(temporal.anchor).toISOString(),
      query_time_coordinate: temporal.queryQuantized,
      arm_relevance_formula: requiresEmbedding ? 'epistemic_score/(1+arm_distance)' : 'native_epistemic_relevance',
      computed_selected_memory_ids: computedIds,
      returned_selected_memory_ids: returnedIds,
      feature_counts: {
        active_context_eligible: activeContextCount,
        temporal_eligible: temporalEligibleCount,
        tau: tauCount,
      },
      shadow_returned_baseline: policy.execution === 'shadow',
    },
  };
}

function memoryWithDecision(candidate, selectedRank = null) {
  return {
    ...candidate.memory,
    epistemic_state: candidate.epistemicState,
    epistemic_score: Number(candidate.epistemicScore.toFixed(3)),
    evidence_handling: candidate.evidenceHandling,
    epistemic_decision_version: EPISTEMIC_DECISION_VERSION,
    epistemic_signals: {
      provenance_valid: provenanceValid(candidate.memory),
      explicit_verification: explicitVerification(candidate.memory),
      query_coverage: Number(candidate.queryCoverage.toFixed(6)),
      query_prefix_echo: candidate.prefixEcho,
      query_echo_cluster_size: candidate.echoClusterSize,
      max_candidate_similarity: Number(candidate.maxSimilarity.toFixed(6)),
      redundant_candidate_count: candidate.redundantCount,
      independent_source_count: candidate.distinctSources,
      persistent_reweight_eligible: candidate.persistentReweightEligible,
      stored_epistemic_label: candidate.storedEpistemicLabel,
      stored_epistemic_confidence_milli: candidate.storedEpistemicConfidenceMilli,
      stored_epistemic_event_id: candidate.storedEpistemicEventId,
    },
    ...(selectedRank == null ? {} : {
      epistemic_selected_rank: selectedRank,
      epistemic_mmr_score: Number(candidate.mmrScore.toFixed(6)),
    }),
  };
}

/**
 * Pure, deterministic selection. The caller owns the signed event receipt and
 * any housekeeper-governed persistent reweight transition.
 */
function calibrateWithPolicy({
  query = '',
  memories = [],
  limit = 10,
  policy = PRODUCTION_POLICY,
  decisionVersion = EPISTEMIC_DECISION_VERSION,
  decisionExtras = null,
  twinPrimeContext = null,
} = {}) {
  const source = Array.isArray(memories) ? memories : [];
  const boundedLimit = Math.max(1, Math.min(200, Math.trunc(Number(limit) || 10)));
  const candidates = annotateCandidates(query, source, policy);
  const twinPrime = twinPrimeContext
    ? twinPrimeSelection(candidates, Math.min(boundedLimit, candidates.length), twinPrimeContext)
    : null;
  const selected = twinPrime?.returned
    || selectMmr(candidates, Math.min(boundedLimit, candidates.length));
  const selectedIds = new Set(selected.map((candidate) => String(candidate.memory?.id || candidate.memory?.memory_id || '')));
  const selectedMemories = selected.map((candidate, index) => memoryWithDecision(candidate, index + 1));
  const decisions = candidates.map((candidate) => {
    const memoryId = String(candidate.memory?.id || candidate.memory?.memory_id || '');
    return {
    memory_id: memoryId,
    content_hash: candidate.contentHash,
    selected: selectedIds.has(String(candidate.memory?.id || candidate.memory?.memory_id || '')),
    epistemic_state: candidate.epistemicState,
    evidence_handling: candidate.evidenceHandling,
    epistemic_score: Number(candidate.epistemicScore.toFixed(3)),
    query_coverage: Number(candidate.queryCoverage.toFixed(6)),
    query_prefix_echo: candidate.prefixEcho,
    query_echo_cluster_size: candidate.echoClusterSize,
    max_candidate_similarity: Number(candidate.maxSimilarity.toFixed(6)),
    redundant_candidate_count: candidate.redundantCount,
    persistent_reweight_eligible: candidate.persistentReweightEligible,
    stored_epistemic_label: candidate.storedEpistemicLabel,
    stored_epistemic_confidence_milli: candidate.storedEpistemicConfidenceMilli,
    stored_epistemic_event_id: candidate.storedEpistemicEventId,
    ...(twinPrime ? { twin_prime_features: twinPrime.evidenceById.get(memoryId) || null } : {}),
  };
  });
  const querySha256 = createHash('sha256').update(String(query), 'utf8').digest('hex');
  const decisionBody = {
    version: decisionVersion,
    ...(decisionExtras || {}),
    query_sha256: querySha256,
    candidate_count: candidates.length,
    selected_memory_ids: selectedMemories.map((memory) => String(memory.id || memory.memory_id || '')),
    states: decisions.reduce((counts, decision) => {
      counts[decision.epistemic_state] = (counts[decision.epistemic_state] || 0) + 1;
      return counts;
    }, {}),
    ...(twinPrime ? { twin_prime: twinPrime.decision } : {}),
    decisions,
  };
  const decisionSha256 = createHash('sha256')
    .update(canonicalJson(decisionBody), 'utf8')
    .digest('hex');
  const abstentionRequired = selectedMemories.length === 0
    || selectedMemories.every((memory) => memory.evidence_handling === 'untrusted_reference_only');

  return {
    memories: selectedMemories,
    decision: {
      ...decisionBody,
      decision_sha256: decisionSha256,
      abstention_required: abstentionRequired,
      canonical_memory_mutated: false,
      persistent_reweight_applied: false,
      aladdin_contract: 'retained_active_no_delete_no_suppress_no_decay',
    },
  };
}

export function calibrateEpistemicRecall({ query = '', memories = [], limit = 10, twinPrimeContext = null } = {}) {
  return calibrateWithPolicy({
    query,
    memories,
    limit,
    policy: PRODUCTION_POLICY,
    twinPrimeContext,
  });
}

/**
 * Fixed-policy diagnostic for the preregistered PoisonedRAG causal ablation.
 *
 * No caller-controlled policy is accepted. The four arms are sealed in source,
 * are not exposed through the recall route, and never mutate native ranking or
 * canonical memory. The caller owns copied-candidate evidence, active-context
 * construction, and signed ledger receipts for each arm.
 */
export function evaluateEpistemicRecallAblation({
  query = '',
  memories = [],
  limit = 5,
} = {}) {
  return Object.fromEntries(EPISTEMIC_ABLATION_POLICIES.map((policy) => {
    const result = calibrateWithPolicy({
      query,
      memories,
      limit,
      policy,
      decisionVersion: EPISTEMIC_ABLATION_VERSION,
      decisionExtras: {
        protocol: 'poisonedrag-n100-epistemic-ablation-v1',
        policy_id: policy.policyId,
        policy: {
          stored_signed_labels: policy.applyStoredClassification,
          query_local_lure_detection: policy.applyQueryLocalSignals,
          active_context_withholding: policy.withholdUntrustedFromActiveContext,
          retained_quarantine: policy.applyRetainedQuarantine,
          explicit_verification: policy.applyExplicitVerification,
          default_multiplier: policy.defaultMultiplier,
        },
      },
    });
    const activeContextMemories = policy.withholdUntrustedFromActiveContext
      ? result.memories.filter((memory) => memory.evidence_handling !== 'untrusted_reference_only')
      : result.memories;
    return [policy.policyId, {
      ...result,
      active_context_memories: activeContextMemories,
      active_context_withholding: policy.withholdUntrustedFromActiveContext,
    }];
  }));
}

export default {
  EPISTEMIC_DECISION_VERSION,
  EPISTEMIC_ABLATION_VERSION,
  EPISTEMIC_ABLATION_POLICY_IDS,
  TWIN_PRIME_SELECTION_VERSION,
  calibrateEpistemicRecall,
  evaluateEpistemicRecallAblation,
};
