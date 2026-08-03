/**
 * recall-relevance-labels.js — offline relevance labels for recall diagnostics
 *
 * Status: diagnostic-only. Labels are used for metrics, held-out gates, and
 * hard-negative analysis. They must not be used as ranker scoring features.
 *
 * Contract:
 * - source_key / positive_key_patterns identify positives.
 * - positive_terms and aliases are metrics-only fallback labels.
 * - hard negatives are high-scoring non-positive candidates.
 * - Split discipline is external: train/calibrate and gate sets must differ.
 */

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
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

export function keyMatchesPattern(key, pattern) {
  const raw = String(pattern || '').trim();
  const candidate = String(key || '').trim();
  if (!raw || !candidate) return false;
  return raw.includes('*')
    ? wildcardToRegex(raw).test(candidate)
    : raw.toLowerCase() === candidate.toLowerCase();
}

function candidateScore(candidate = {}) {
  return finiteNumber(
    candidate?.rank_diagnostics?.final_score,
    finiteNumber(candidate?.recall_confidence, finiteNumber(candidate?.rerank_score, candidate?.similarity, 0))
  ) || 0;
}

export function labelCandidate(candidate = {}, {
  positiveKeyPatterns = [],
  sourceKey = null,
  positiveTerms = [],
  aliases = [],
} = {}) {
  const patterns = [
    ...asArray(positiveKeyPatterns),
    ...(sourceKey ? [sourceKey] : []),
  ].filter(Boolean);
  const key = String(candidate.key || '');
  const pattern = patterns.find((item) => keyMatchesPattern(key, item));
  if (pattern) {
    return { relevance: 'positive', positive: true, match_type: 'key_pattern', match: pattern };
  }

  const text = normalizeText(`${candidate.key || ''}\n${candidate.value || ''}`);
  const normalizedTerms = [
    ...asArray(positiveTerms),
    ...asArray(aliases),
  ].map(normalizeText).filter(Boolean);
  const term = normalizedTerms.find((item) => text.includes(item));
  if (term) {
    return { relevance: 'positive', positive: true, match_type: 'term_or_alias', match: term };
  }

  return { relevance: 'unlabeled', positive: false, match_type: null, match: null };
}

export function buildRecallRelevanceLabels(candidates = [], {
  positiveKeyPatterns = [],
  sourceKey = null,
  positiveTerms = [],
  aliases = [],
  hardNegativeTopK = 12,
  hardNegativeScoreFloor = 0.62,
} = {}) {
  const rows = asArray(candidates).map((candidate, index) => ({
    index,
    key: candidate?.key || null,
    score: candidateScore(candidate),
    label: labelCandidate(candidate, { positiveKeyPatterns, sourceKey, positiveTerms, aliases }),
  }));

  const positiveKeys = new Set(rows.filter((row) => row.label.positive).map((row) => row.key).filter(Boolean));
  const hardNegatives = rows
    .filter((row) => !row.label.positive)
    .filter((row, index) => index < hardNegativeTopK || row.score >= hardNegativeScoreFloor)
    .map((row) => ({
      ...row,
      label: {
        relevance: 'hard_negative',
        positive: false,
        match_type: 'high_scoring_non_positive',
        match: null,
      },
    }));

  const byIndex = new Map(rows.map((row) => [row.index, row.label]));
  for (const row of hardNegatives) byIndex.set(row.index, row.label);

  const labeled = rows.map((row) => ({
    index: row.index,
    key: row.key,
    score: row.score,
    label: byIndex.get(row.index) || row.label,
  }));

  return {
    label_source: positiveKeys.size
      ? 'source_key_or_positive_pattern'
      : (asArray(positiveTerms).length || asArray(aliases).length)
        ? 'term_or_alias_metric_fallback'
        : 'none',
    split_discipline: 'labels_for_metrics_only_train_and_gate_splits_must_differ',
    positive_count: labeled.filter((row) => row.label.positive).length,
    hard_negative_count: labeled.filter((row) => row.label.relevance === 'hard_negative').length,
    unlabeled_count: labeled.filter((row) => row.label.relevance === 'unlabeled').length,
    hard_negative_policy: {
      top_k: hardNegativeTopK,
      score_floor: hardNegativeScoreFloor,
      definition: 'high-scoring candidate that is not the source positive',
    },
    labels: labeled,
  };
}

export default {
  keyMatchesPattern,
  labelCandidate,
  buildRecallRelevanceLabels,
};
