/**
 * recall-doctor-sidecar.js — read-only Aimos Recall diagnostic doctor
 *
 * Status: diagnostic-only. The report builder runs outside /aimos/recall over
 * copied native responses or explicit body-free candidate traces.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Consumes copied native /aimos/recall responses or explicit candidate sets.
 * 2. → Emits diagnostic reports for offline ledgers and A/B analysis.
 * 3. ✕ Does not mutate rank, confidence, memory content, answer text, or Aimos DB.
 *
 * LOGIC GUIDE:
 * The doctor observes native recall from outside the hot path. It detects
 * operator leakage, exposes score deltas/rank margins, classifies failures, and
 * suggests the next calibration surface. It is not a recall stage and not a
 * fallback.
 */

import { composeCalibratedRankCandidates } from './calibrated-rank-composition.js';
import { buildRecallRelevanceLabels } from './recall-relevance-labels.js';

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function round(value, fallback = null) {
  const n = finiteNumber(value, null);
  return n == null ? fallback : Number(n.toFixed(6));
}

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9:_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function wildcardToRegex(pattern) {
  const escaped = String(pattern || '')
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function keyMatchesPattern(key, pattern) {
  const raw = String(pattern || '').trim();
  const candidate = String(key || '').trim();
  if (!raw || !candidate) return false;
  return raw.includes('*')
    ? wildcardToRegex(raw).test(candidate)
    : raw.toLowerCase() === candidate.toLowerCase();
}

function findPositiveRank(memories, positiveKeyPatterns = [], positiveTerms = []) {
  const patterns = asArray(positiveKeyPatterns).filter(Boolean);
  const terms = asArray(positiveTerms).map(normalizeText).filter(Boolean);
  for (let index = 0; index < memories.length; index += 1) {
    const memory = memories[index] || {};
    const key = memory.key || '';
    const pattern = patterns.find((candidate) => keyMatchesPattern(key, candidate));
    if (pattern) {
      return { rank: index + 1, key, match_type: 'key_pattern', match: pattern };
    }
    const text = normalizeText(`${memory.key || ''}\n${memory.value || ''}`);
    const term = terms.find((candidate) => text.includes(candidate));
    if (term) {
      return { rank: index + 1, key, match_type: 'term', match: term };
    }
  }
  return { rank: null, key: null, match_type: null, match: null };
}

function extractScore(memory = {}, index = 0, next = null) {
  const diagnostics = memory.rank_diagnostics || {};
  const components = memory.score_components || memory.confidence?.components || {};
  const similarity = finiteNumber(memory.similarity, null);
  const rerank = finiteNumber(memory.rerank_score, null);
  const confidence = finiteNumber(memory.recall_confidence, null);
  const finalScore = finiteNumber(diagnostics.final_score, finiteNumber(confidence, finiteNumber(rerank, similarity)));
  const nextScore = next
    ? finiteNumber(next.rank_diagnostics?.final_score, finiteNumber(next.recall_confidence, finiteNumber(next.rerank_score, next.similarity)))
    : null;
  return {
    rank: index + 1,
    id: memory.id || null,
    key: memory.key || null,
    memory_type: memory.memory_type || null,
    retrieval_source: memory.retrieval_source || diagnostics.retrieval_source || null,
    similarity: round(similarity),
    similarity_basis: memory.similarity_basis || null,
    rerank_score: round(rerank),
    recall_confidence: round(confidence),
    final_score: round(finalScore),
    next_margin: nextScore == null || finalScore == null ? null : round(finalScore - nextScore),
    score_components: {
      semantic: round(components.semantic),
      lexical: round(components.lexical ?? components.keyword),
      bm25: round(components.bm25),
      temporal: round(components.temporal ?? components.recency),
      authority: round(components.authority),
      freshness_delta: round(components.freshness_delta, 0),
    },
    score_deltas: {
      rerank_minus_similarity: rerank == null || similarity == null ? null : round(rerank - similarity),
      confidence_minus_similarity: confidence == null || similarity == null ? null : round(confidence - similarity),
      final_minus_similarity: finalScore == null || similarity == null ? null : round(finalScore - similarity),
    },
  };
}

function detectOperatorLeak(nativeResponse = {}, memories = []) {
  const meta = nativeResponse?.recall_meta || {};
  const explainStages = meta.explain?.stages || {};
  return {
    detected: Boolean(
      meta.native_paper_recall
      || explainStages.native_paper_recall_operators
      || asArray(memories).some((memory) => memory?.native_paper_recall)
    ),
    meta_field_present: Object.prototype.hasOwnProperty.call(meta, 'native_paper_recall'),
    explain_stage_present: Object.prototype.hasOwnProperty.call(explainStages, 'native_paper_recall_operators'),
    memory_field_count: asArray(memories).filter((memory) => memory?.native_paper_recall).length,
  };
}

function classifyFailure({ responseOk, memories, operatorLeak, positiveRank, latencyMs, timeoutMs }) {
  if (!responseOk) return 'native_recall_request_error';
  if (operatorLeak.detected) return 'native_operator_leak';
  if (Number.isFinite(timeoutMs) && Number.isFinite(latencyMs) && latencyMs >= timeoutMs) return 'timeout_boundary';
  if (!memories.length) return 'no_evidence_returned';
  if (positiveRank.rank == null && (positiveRank.expected || false)) return 'positive_not_in_returned_pack';
  if (positiveRank.rank != null && positiveRank.rank > 1) return 'ranking_not_top1';
  const nullSimilarityCount = memories.filter((memory) => memory?.similarity == null).length;
  if (nullSimilarityCount > 0) return 'observability_gap';
  return 'no_failure_detected';
}

function buildSuggestions({
  failureClass,
  rankObservability,
  positiveRank,
  candidateScope,
  calibratedRankComposition = null,
}) {
  const suggestions = [];
  if (!['pre_response_candidate_set', 'pre_truncation_candidate_set', 'explicit_candidate_set'].includes(candidateScope)) {
    suggestions.push('Add an explicit pre-truncation candidate tap before rank truncation so doctor can separate retrieval breadth from ranking.');
  }
  if (failureClass === 'native_operator_leak') {
    suggestions.push('Keep paper/operator scoring outside /aimos/recall; run only in offline doctor diagnostics over copied candidates.');
  }
  if (failureClass === 'positive_not_in_returned_pack') {
    suggestions.push('Measure gold-in-candidate-pool before ranker work; if absent, fix retrieval breadth rather than ranking.');
  }
  if (failureClass === 'ranking_not_top1') {
    suggestions.push('Inspect score components and hard negatives; this is a rank-composition issue only if the positive is already in the candidate pack.');
  }
  if (failureClass === 'observability_gap') {
    suggestions.push('Expose similarity and score components for every returned memory before ranking calibration work.');
  }
  if (rankObservability?.score_spread != null && rankObservability.score_spread < 0.05) {
    suggestions.push('Score spread is compressed; inspect rank margin before adding any boost-like calibration.');
  }
  if (calibratedRankComposition?.rank_discrimination?.collapse_detected) {
    suggestions.push('Calibrated rank composition also detects score collapse; collect held-out labels before any native ranker promotion.');
  }
  if ((calibratedRankComposition?.scorer?.negative_weight_count || 0) === 0) {
    suggestions.push('Rank composition has no negative weights; reject it as another monotone boost stack.');
  }
  if (positiveRank.rank === 1) {
    suggestions.push('Positive evidence is top-1; preserve this behavior as a regression guard.');
  }
  return suggestions;
}

export function buildRecallDoctorReport({
  queryText = '',
  nativeResponse = {},
  latencyMs = null,
  timeoutMs = null,
  candidateSet = null,
  candidateScope = null,
  sourceKey = null,
  positiveKeyPatterns = [],
  positiveTerms = [],
  aliases = [],
  sidecarSigner = null,
} = {}) {
  const responseMemories = asArray(nativeResponse?.memories);
  const memories = asArray(candidateSet).length ? asArray(candidateSet) : responseMemories;
  const resolvedScope = candidateScope || (asArray(candidateSet).length ? 'explicit_candidate_set' : 'returned_pack_only');
  const meta = nativeResponse?.recall_meta || {};
  const operatorLeak = detectOperatorLeak(nativeResponse, memories);
  const expected = asArray(positiveKeyPatterns).length > 0 || asArray(positiveTerms).length > 0;
  const relevanceLabels = buildRecallRelevanceLabels(memories, {
    sourceKey,
    positiveKeyPatterns,
    positiveTerms,
    aliases,
  });
  const positiveRank = {
    expected: expected || Boolean(sourceKey),
    ...findPositiveRank(memories, sourceKey ? [sourceKey, ...asArray(positiveKeyPatterns)] : positiveKeyPatterns, positiveTerms),
  };
  const rankObservability = meta.rank_observability || meta.explain?.stages?.rank_observability || null;
  const failureClass = classifyFailure({
    responseOk: nativeResponse?.ok !== false,
    memories,
    operatorLeak,
    positiveRank,
    latencyMs,
    timeoutMs,
  });
  const scoreDeltas = memories.slice(0, 20).map((memory, index) => extractScore(memory, index, memories[index + 1] || null));
  const calibratedRankComposition = composeCalibratedRankCandidates({
    queryText,
    candidates: memories,
    sourceKey,
    positiveKeyPatterns,
    positiveTerms,
    aliases,
    sidecarSigner,
    maxRows: 20,
  });
  const goldInCandidatePool = positiveRank.expected ? positiveRank.rank != null : null;

  return {
    diagnostic_only: true,
    sidecar: 'recall_doctor',
    query: String(queryText || '').slice(0, 500),
    guardrails: {
      native_hot_path: false,
      mutates_rank: false,
      mutates_confidence: false,
      mutates_memory: false,
      mutates_answer_text: false,
      writes_aimos_db: false,
      calls_native_paper_operator: false,
    },
    candidate_scope: resolvedScope,
    candidate_count: memories.length,
    returned_count: responseMemories.length,
    latency_ms: latencyMs,
    timeout_ms: timeoutMs,
    operator_boundary: {
      expected_native_operator_count: 0,
      operator_firings: [],
      leak: operatorLeak,
    },
    rank_observability: rankObservability,
    labeling: {
      label_source: relevanceLabels.label_source,
      positive_count: relevanceLabels.positive_count,
      hard_negative_count: relevanceLabels.hard_negative_count,
      unlabeled_count: relevanceLabels.unlabeled_count,
      split_discipline: relevanceLabels.split_discipline,
      hard_negative_policy: relevanceLabels.hard_negative_policy,
    },
    pre_rank_recall: {
      gold_expected: positiveRank.expected,
      gold_in_candidate_pool: goldInCandidatePool,
      recall_at_n_pre_rank: positiveRank.expected ? (goldInCandidatePool ? 1 : 0) : null,
      candidate_scope: resolvedScope,
      bottleneck_if_failed: positiveRank.expected && !goldInCandidatePool ? 'retrieval_breadth' : null,
    },
    calibrated_rank_composition: calibratedRankComposition,
    positive_evidence: positiveRank,
    failure_class: failureClass,
    score_deltas: scoreDeltas,
    stage_timings: asArray(meta.stage_timings).map((stage) => ({
      id: stage.id,
      duration_ms: stage.duration_ms,
      skipped: stage.skipped === true,
      skip_reason: stage.skip_reason || null,
    })),
    suggestions: buildSuggestions({
      failureClass,
      rankObservability,
      positiveRank,
      candidateScope: resolvedScope,
      calibratedRankComposition,
    }),
  };
}

export default {
  buildRecallDoctorReport,
};
