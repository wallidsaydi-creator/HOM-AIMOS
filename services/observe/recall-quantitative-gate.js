/**
 * recall-quantitative-gate.js — pre-benchmark quantitative gate
 *
 * Status: diagnostic-only. This evaluates doctor-sidecar reports before any
 * benchmark/publication claim. It does not call /aimos/recall and does not
 * mutate native ranking.
 *
 * Priority:
 * 1. Retrieval accuracy floors.
 * 2. Rank discrimination floors.
 * 3. p95 latency ceiling.
 *
 * QA answer accuracy is deliberately separate and must be supplied by a frozen
 * generator/judge protocol.
 */

const DEFAULT_THRESHOLDS = Object.freeze({
  top1_target: 0.95,
  mrr_target: 0.95,
  any_of_k_baseline: 0.99,
  p95_latency_ms: 30000,
  score_spread_floor: 0.05,
  top1_margin_floor: 0.015,
});

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function round(value, fallback = null) {
  const n = finiteNumber(value, null);
  return n == null ? fallback : Number(n.toFixed(6));
}

function percentile(values = [], p = 95) {
  const rows = values.map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (!rows.length) return null;
  const index = Math.min(rows.length - 1, Math.max(0, Math.ceil((p / 100) * rows.length) - 1));
  return rows[index];
}

function mean(values = []) {
  const rows = values.map(Number).filter(Number.isFinite);
  return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : null;
}

function variance(values = []) {
  const rows = values.map(Number).filter(Number.isFinite);
  if (rows.length < 2) return 0;
  const m = mean(rows);
  return rows.reduce((sum, value) => sum + ((value - m) ** 2), 0) / rows.length;
}

export function computeRecallGateMetrics(reports = []) {
  const expected = asArray(reports).filter((report) => report?.positive_evidence?.expected);
  const ranks = expected.map((report) => finiteNumber(report.positive_evidence.rank, null));
  const found = ranks.filter((rank) => rank != null);
  const top1 = ranks.filter((rank) => rank === 1).length;
  const reciprocal = ranks.map((rank) => (rank == null ? 0 : 1 / rank));
  const latencies = asArray(reports).map((report) => finiteNumber(report.latency_ms, null)).filter((value) => value != null);
  const spreads = asArray(reports)
    .map((report) => finiteNumber(report.calibrated_rank_composition?.rank_discrimination?.score_spread, null))
    .filter((value) => value != null);
  const margins = asArray(reports)
    .map((report) => finiteNumber(report.calibrated_rank_composition?.rank_discrimination?.top1_margin, null))
    .filter((value) => value != null);
  const candidateScopeCounts = asArray(reports).reduce((acc, report) => {
    const key = report.candidate_scope || 'unknown';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const denominator = expected.length || 0;
  return {
    report_count: asArray(reports).length,
    labeled_query_count: denominator,
    unlabeled_query_count: asArray(reports).length - denominator,
    retrieval_metrics: {
      top1: denominator ? round(top1 / denominator, 0) : null,
      mrr: denominator ? round(reciprocal.reduce((sum, value) => sum + value, 0) / denominator, 0) : null,
      any_of_k: denominator ? round(found.length / denominator, 0) : null,
      recall_at_n_pre_rank: denominator ? round(found.length / denominator, 0) : null,
      missing_from_candidate_pool: denominator - found.length,
      ranking_not_top1: found.filter((rank) => rank > 1).length,
      bottleneck: denominator === 0
        ? 'unlabeled_no_gate'
        : found.length < denominator
          ? 'retrieval_breadth'
          : top1 < denominator
            ? 'ranking'
            : 'no_retrieval_or_ranking_bottleneck_detected',
    },
    latency_metrics: {
      p95_latency_ms: percentile(latencies, 95),
      mean_latency_ms: round(mean(latencies), null),
      doctor_scan_excluded_from_hot_path_latency: true,
    },
    rank_discrimination: {
      min_score_spread: spreads.length ? round(Math.min(...spreads), 0) : null,
      mean_score_spread: round(mean(spreads), null),
      min_top1_margin: margins.length ? round(Math.min(...margins), 0) : null,
      mean_top1_margin: round(mean(margins), null),
      score_spread_variance: round(variance(spreads), null),
      top1_margin_variance: round(variance(margins), null),
    },
    candidate_scope_counts: candidateScopeCounts,
  };
}

export function evaluateRecallQuantitativeGate({
  reports = [],
  thresholds = {},
  protocol = {},
} = {}) {
  const t = { ...DEFAULT_THRESHOLDS, ...(thresholds || {}) };
  const metrics = computeRecallGateMetrics(reports);
  const retrieval = metrics.retrieval_metrics;
  const latency = metrics.latency_metrics;
  const rank = metrics.rank_discrimination;

  const checks = {
    labeled_queries_present: metrics.labeled_query_count > 0,
    top1: retrieval.top1 != null && retrieval.top1 >= t.top1_target,
    mrr: retrieval.mrr != null && retrieval.mrr >= t.mrr_target,
    any_of_k: retrieval.any_of_k != null && retrieval.any_of_k >= t.any_of_k_baseline,
    p95_latency: latency.p95_latency_ms != null && latency.p95_latency_ms <= t.p95_latency_ms,
    score_spread: rank.min_score_spread != null && rank.min_score_spread >= t.score_spread_floor,
    top1_margin: rank.min_top1_margin != null && rank.min_top1_margin >= t.top1_margin_floor,
    operator_state_declared: Boolean(protocol.operator_state),
    early_exit_state_declared: Boolean(protocol.early_exit_state),
    scorer_declared: Boolean(protocol.scorer),
    corpus_declared: Boolean(protocol.corpus),
    judge_config_declared: Boolean(protocol.judge_config),
  };

  const accuracyPass = checks.labeled_queries_present && checks.top1 && checks.mrr && checks.any_of_k;
  const discriminationPass = checks.score_spread && checks.top1_margin;
  const latencyPass = checks.p95_latency;
  const protocolPass = checks.operator_state_declared
    && checks.early_exit_state_declared
    && checks.scorer_declared
    && checks.corpus_declared
    && checks.judge_config_declared;

  return {
    diagnostic_only: true,
    gate: 'pre_benchmark_recall_quantitative_gate',
    decision: accuracyPass && discriminationPass && latencyPass && protocolPass ? 'pass' : 'fail',
    priority: 'accuracy_floor_first_then_rank_discrimination_then_p95_latency',
    thresholds: t,
    checks,
    metrics,
    protocol: {
      corpus: protocol.corpus || null,
      scorer: protocol.scorer || null,
      filters: protocol.filters || null,
      early_exit_state: protocol.early_exit_state || null,
      operator_state: protocol.operator_state || null,
      judge_config: protocol.judge_config || null,
      split_policy: protocol.split_policy || 'train_calibration_split_must_differ_from_gate_split',
      metric_separation: 'retrieval_metrics_are_separate_from_QA_answer_accuracy',
    },
  };
}

export default {
  DEFAULT_THRESHOLDS,
  computeRecallGateMetrics,
  evaluateRecallQuantitativeGate,
};
