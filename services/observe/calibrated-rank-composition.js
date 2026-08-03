/**
 * calibrated-rank-composition.js — diagnostic rank-composition candidate
 *
 * Status: diagnostic-only. This module runs over copied recall candidate rows
 * from the doctor sidecar. It is not imported by /aimos/recall and must not
 * mutate rank, confidence, memory content, answer text, or Aimos DB.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Consumes observable native recall features: similarity, score components,
 *      final score, memory type, body length, rank, and deep-recall metadata.
 * 2. → Emits a logistic/LTR-style candidate ranking plus score spread/margins.
 * 3. ✕ Does not use expected answers as scoring features. Positive labels are
 *      accepted only for offline MRR/top-1 diagnostics.
 *
 * FORMULA GUIDE:
 * p(relevant | x) = sigma(b + sum_i w_i x_i)
 * sigma(z) = 1 / (1 + exp(-z))
 *
 * Unlike the retired monotone paper stack, weights may be positive or negative.
 * The goal is ranking discrimination and observability, not guaranteed boosts.
 */

import { createHash } from 'node:crypto';
import { buildAladdinSalienceSidecar } from './aladdin-salience-sidecar.js';
import { buildRecallRelevanceLabels } from './recall-relevance-labels.js';

const DEFAULT_MODEL = Object.freeze({
  version: 'calibrated-rank-composition-v1-diagnostic-default',
  training_status: 'default_untrained_requires_held_out_labels_before_native_promotion',
  intercept: -1.15,
  weights: Object.freeze({
    native_final_score: 1.25,
    similarity_observed: 0.95,
    semantic_component: 0.72,
    lexical_component: 0.38,
    temporal_component: 0.34,
    authority_component: 0.28,
    type_authority_component: 0.22,
    freshness_delta_positive: 0.16,
    salience_activation: 0.18,
    deep_recall_override: 1.15,
    original_rank_depth: -0.42,
    missing_similarity: -0.82,
    missing_component_fraction: -0.36,
    noisy_memory_type: -0.68,
    long_body_noise: -0.18,
    low_frequency_without_override: 0,
  }),
  collapse_thresholds: Object.freeze({
    score_spread: 0.05,
    top1_margin: 0.015,
  }),
});

const NOISY_MEMORY_TYPES = new Set([
  'conversation_feed',
  'event_log',
  'heartbeat',
  'tool_event',
  'dream_artifact',
  'dream_summary',
  'debug_trace',
]);

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value, min = 0, max = 1) {
  const n = finiteNumber(value, min);
  return Math.max(min, Math.min(max, n));
}

function round(value, fallback = null) {
  const n = finiteNumber(value, null);
  return n == null ? fallback : Number(n.toFixed(6));
}

function sigmoid(value) {
  const z = clamp(value, -40, 40);
  return 1 / (1 + Math.exp(-z));
}

function hashWeights(model) {
  return createHash('sha256')
    .update(JSON.stringify({ intercept: model.intercept, weights: model.weights }))
    .digest('hex');
}

function scoreComponent(memory = {}, name, fallback = null) {
  const components = memory.score_components || memory.confidence?.components || {};
  return finiteNumber(
    components[name],
    name === 'lexical'
      ? finiteNumber(components.keyword, fallback)
      : name === 'temporal'
        ? finiteNumber(components.recency, fallback)
        : fallback
  );
}

export function extractCalibratedRankFeatures(candidate = {}, index = 0, total = 1, options = {}) {
  const diagnostics = candidate.rank_diagnostics || {};
  const similarity = finiteNumber(candidate.similarity, null);
  const rerank = finiteNumber(candidate.rerank_score, null);
  const confidence = finiteNumber(candidate.recall_confidence, null);
  const finalScore = finiteNumber(
    diagnostics.final_score,
    finiteNumber(confidence, finiteNumber(rerank, similarity))
  );
  const semantic = scoreComponent(candidate, 'semantic', similarity);
  const lexical = scoreComponent(candidate, 'lexical', rerank);
  const temporal = scoreComponent(candidate, 'temporal', null);
  const authority = scoreComponent(candidate, 'authority', null);
  const typeAuthority = scoreComponent(candidate, 'type_authority', null);
  const freshnessDelta = finiteNumber(scoreComponent(candidate, 'freshness_delta', 0), 0);
  const componentValues = [semantic, lexical, temporal, authority, typeAuthority].filter((value) => value != null);
  const missingComponentFraction = 1 - (componentValues.length / 5);
  const originalRank = finiteNumber(candidate.rank, finiteNumber(diagnostics.rank, index + 1));
  const rankDepthDenominator = Math.log1p(Math.max(2, total));
  const rankDepth = Math.log1p(Math.max(0, (originalRank || index + 1) - 1)) / rankDepthDenominator;
  const valueLength = finiteNumber(candidate.value_length, String(candidate.value || '').length);
  const deepOverride = candidate.deep_recall_override?.applied === true
    || candidate.deep_recall_rank_eligible === true;
  const lowFrequency = candidate.low_frequency_salience === true
    || candidate.retrieval_frequency_band === 'quiet'
    || candidate.salience_frequency_band === 'quiet';
  const salienceSidecar = buildAladdinSalienceSidecar(candidate, {
    nowMs: options.nowMs,
    signer: options.sidecarSigner,
  });

  return {
    native_final_score: clamp(finalScore, 0, 1),
    similarity_observed: similarity == null ? 0 : clamp(similarity, 0, 1),
    semantic_component: clamp(semantic, 0, 1),
    lexical_component: clamp(lexical, 0, 1),
    temporal_component: clamp(temporal, 0, 1),
    authority_component: clamp(authority, 0, 1),
    type_authority_component: clamp((finiteNumber(typeAuthority, 0) + 0.2) / 0.4, 0, 1),
    freshness_delta_positive: clamp((freshnessDelta + 0.05) / 0.1, 0, 1),
    salience_activation: clamp(salienceSidecar.ranker_salience_feature, 0, 1),
    deep_recall_override: deepOverride ? 1 : 0,
    original_rank_depth: clamp(rankDepth, 0, 1),
    missing_similarity: similarity == null ? 1 : 0,
    missing_component_fraction: clamp(missingComponentFraction, 0, 1),
    noisy_memory_type: NOISY_MEMORY_TYPES.has(String(candidate.memory_type || '')) ? 1 : 0,
    long_body_noise: clamp(valueLength / 24000, 0, 1),
    low_frequency_without_override: lowFrequency && !deepOverride ? 1 : 0,
    salience_sidecar: salienceSidecar,
  };
}

export function scoreCalibratedRankFeatures(features = {}, model = DEFAULT_MODEL) {
  let logit = finiteNumber(model.intercept, DEFAULT_MODEL.intercept);
  const contributions = {};
  for (const [name, weight] of Object.entries(model.weights || DEFAULT_MODEL.weights)) {
    const featureValue = finiteNumber(features[name], 0);
    const contribution = Number(weight) * featureValue;
    contributions[name] = round(contribution, 0);
    logit += contribution;
  }
  return {
    logit: round(logit, 0),
    score: round(sigmoid(logit), 0),
    contributions,
  };
}

function spreadMetrics(scored = [], thresholds = DEFAULT_MODEL.collapse_thresholds) {
  const scores = scored.map((row) => finiteNumber(row.composition_score, null)).filter((value) => value != null);
  if (!scores.length) {
    return {
      score_spread: null,
      top1_margin: null,
      score_collapse: false,
      margin_collapse: false,
      collapse_detected: false,
    };
  }
  const max = Math.max(...scores);
  const min = Math.min(...scores);
  const top = scored[0]?.composition_score ?? null;
  const second = scored[1]?.composition_score ?? null;
  const spread = scores.length > 1 ? max - min : 0;
  const margin = top != null && second != null ? top - second : null;
  const scoreCollapse = scores.length > 1 && spread < thresholds.score_spread;
  const marginCollapse = margin != null && margin < thresholds.top1_margin;
  return {
    score_spread: round(spread, 0),
    top1_margin: round(margin, null),
    score_collapse: scoreCollapse,
    margin_collapse: marginCollapse,
    collapse_detected: scoreCollapse || marginCollapse,
  };
}

function rankOfPositive(rows = []) {
  const index = rows.findIndex((row) => row.label?.positive === true);
  if (index < 0) return { rank: null, key: null, reciprocal_rank: 0 };
  return {
    rank: index + 1,
    key: rows[index].key || null,
    reciprocal_rank: round(1 / (index + 1), 0),
  };
}

export function composeCalibratedRankCandidates({
  queryText = '',
  candidates = [],
  sourceKey = null,
  positiveKeyPatterns = [],
  positiveTerms = [],
  aliases = [],
  model = DEFAULT_MODEL,
  maxRows = 50,
  nowMs = Date.now(),
  sidecarSigner = null,
} = {}) {
  const rows = asArray(candidates);
  const limit = Math.max(1, Math.min(200, Number(maxRows) || 50));
  const weights = model.weights || DEFAULT_MODEL.weights;
  const negativeWeightCount = Object.values(weights).filter((value) => Number(value) < 0).length;
  const relevanceLabels = buildRecallRelevanceLabels(rows, {
    sourceKey,
    positiveKeyPatterns,
    positiveTerms,
    aliases,
  });
  const labelsByIndex = new Map(relevanceLabels.labels.map((row) => [row.index, row.label]));
  const scored = rows.map((candidate, index) => {
    const features = extractCalibratedRankFeatures(candidate, index, rows.length, { nowMs, sidecarSigner });
    const salienceSidecar = features.salience_sidecar;
    const scoreFeatures = { ...features };
    delete scoreFeatures.salience_sidecar;
    const score = scoreCalibratedRankFeatures(features, model);
    const nativeScore = finiteNumber(
      candidate?.rank_diagnostics?.final_score,
      finiteNumber(candidate?.recall_confidence, finiteNumber(candidate?.rerank_score, candidate?.similarity))
    );
    return {
      original_rank: index + 1,
      id: candidate?.id || null,
      key: candidate?.key || null,
      memory_type: candidate?.memory_type || null,
      retrieval_source: candidate?.retrieval_source || candidate?.rank_diagnostics?.retrieval_source || null,
      label: labelsByIndex.get(index) || { relevance: 'unlabeled', positive: false },
      native_final_score: round(nativeScore, null),
      composition_logit: score.logit,
      composition_score: score.score,
      composition_delta: nativeScore == null ? null : round(score.score - nativeScore),
      features: scoreFeatures,
      salience_sidecar: salienceSidecar,
      contributions: score.contributions,
    };
  });

  const ranked = scored
    .map((row) => ({ ...row }))
    .sort((a, b) =>
      (b.composition_score - a.composition_score)
      || (a.original_rank - b.original_rank)
      || String(a.key || a.id || '').localeCompare(String(b.key || b.id || ''))
    )
    .map((row, index) => ({
      ...row,
      composition_rank: index + 1,
      rank_shift: row.original_rank - (index + 1),
    }));

  const originalPositive = rankOfPositive(scored);
  const composedPositive = rankOfPositive(ranked);
  const metrics = spreadMetrics(ranked, model.collapse_thresholds || DEFAULT_MODEL.collapse_thresholds);
  const changedRows = ranked.filter((row) => row.rank_shift !== 0).length;
  const demotedRows = ranked.filter((row) => row.composition_delta != null && row.composition_delta < 0).length;

  return {
    diagnostic_only: true,
    scorer: {
      type: 'logistic_rank_composition',
      version: model.version || DEFAULT_MODEL.version,
      training_status: model.training_status || DEFAULT_MODEL.training_status,
      formula: 'p(relevant|x)=sigma(b + sum_i w_i*x_i)',
      weight_sha256: hashWeights(model),
      negative_weight_count: negativeWeightCount,
      observable_features_only: true,
      expected_answer_used_for_scoring: false,
      salience_feature: 'B_i=ln(min(C, sum_j(t_j^-d)+prior_i)) as one observable feature',
    },
    query: String(queryText || '').slice(0, 500),
    candidate_count: rows.length,
    emitted_count: Math.min(limit, ranked.length),
    rank_discrimination: metrics,
    ranking_delta: {
      changed_rows: changedRows,
      demoted_rows: demotedRows,
      promoted_rows: changedRows - demotedRows,
    },
    labeling: {
      ...relevanceLabels,
      labels: relevanceLabels.labels.slice(0, limit),
    },
    positive_evidence: {
      label_source: relevanceLabels.label_source,
      original_rank: originalPositive.rank,
      original_key: originalPositive.key,
      original_reciprocal_rank: originalPositive.reciprocal_rank,
      composed_rank: composedPositive.rank,
      composed_key: composedPositive.key,
      composed_reciprocal_rank: composedPositive.reciprocal_rank,
      reciprocal_rank_delta: round(composedPositive.reciprocal_rank - originalPositive.reciprocal_rank, 0),
    },
    ranked_candidates: ranked.slice(0, limit),
  };
}

export default {
  DEFAULT_MODEL,
  extractCalibratedRankFeatures,
  scoreCalibratedRankFeatures,
  composeCalibratedRankCandidates,
};
