// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: nightly-dream.js (step 3)
// → Calls: services/db/connection.js (drift metrics snapshot)
// Pipeline: DREAM_PIPELINE
// Position: drift snapshot
// Sources: Designing ML Systems (Huyen), continual learning drift detection
// Additive Batch 6/7 authority: Multi-Scale Temporal Homeostasis Enables
// Efficient and Robust Neural Networks. Aimos exposes cross-scale
// homeostasis diagnostics only; no STDP, dream, or retrieval_weight formulas
// are changed here.
// Additive Batch8 authority: Catastrophic Forgetting Mitigation and
// Deconfounded Lifelong Learning. Aimos exposes anti-forgetting diagnostics
// only; no replay training, deletion, or canonical memory rewriting happens here.
// Additive Batch9 Wave6 authority: AgentPulse and Forecasting the Past add
// viability-pulse and backward-looking shift diagnostics only; no retrieval
// ranking, benchmark scoring, or retrieval_weight formulas are changed here.
// Batch9.75 Wave 1 authority: Data-Dependent & Aimos Bounds on Forgetting,
// Forgetting Is Everywhere, Overcoming Catastrophic Forgetting (EWC). Forgetting
// bound, prevalence, and EWC-analog drift diagnostics are additive alongside-path
// diagnostics; no retrieval ranking, benchmark scoring, or retrieval_weight
// formulas are changed.
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { query } from '../../db/connection.js';

export const FORGETTING_BOUND_MONITOR_SOURCE = 'Data-Dependent & Aimos Bounds on Forgetting';
export const FORGETTING_PREVALENCE_MONITOR_SOURCE = 'Forgetting Is Everywhere';
export const EWC_DRIFT_SOURCE = 'Overcoming Catastrophic Forgetting (EWC)';

// ─── E1: FORGETTING BOUND MONITOR ─────────────────────────────────────────────
// Source: Data-Dependent & Aimos Bounds on Forgetting
// Formula: P(|f_new(x) - f_old(x)| > ε) ≤ δ = 2·exp(-2nε²/K)
// Scale adaptation: n = max(100, min(2000, floor(500 * sqrt(N/14000))))
// At 14K: n=500. At 100K: n≈1336.

export function computeForgettingBoundSampleSize(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(100, Math.min(2000, Math.floor(500 * Math.sqrt(N / 14000))));
}

export function computeHoeffdingBound(n, epsilon, K = 1) {
  return 2 * Math.exp(-2 * n * epsilon * epsilon / Math.max(1, K));
}

// ─── E2: FORGETTING PREVALENCE MONITOR ─────────────────────────────────────────
// Source: Forgetting Is Everywhere
// Formula: prevalence = (count of regressed queries) / (total queries in window)
// Scale adaptation: window = max(100, min(5000, floor(1000 * (N/14000)^0.5)))
// At 14K: window=1000. At 100K: window≈2673.

export function computePrevalenceWindow(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(100, Math.min(5000, Math.floor(1000 * Math.pow(N / 14000, 0.5))));
}

export function computePrevalence(regressedCount, totalQueries) {
  const total = Math.max(1, totalQueries);
  return Math.min(1, Math.max(0, regressedCount / total));
}

// ─── E3: EWC DRIFT ────────────────────────────────────────────────────────────
// Source: Overcoming Catastrophic Forgetting (EWC), Kirkpatrick et al., 2017
// Formula: L_ewc = L_task + (λ/2) Σ F_i·(θ_i - θ*_i)²
// Scale adaptation: λ = 1000 * max(0.5, (14000/N)^0.5)
// At 14K: λ=1000. At 100K: λ≈500 (clamped by 0.5 floor).

export function computeEWCLambda(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 1000 * Math.max(0.5, Math.pow(14000 / N, 0.5));
}

export function computeEWCImportance({ accessFreq = 0, maxAccess = 1, centrality = 0, recency = 1, alpha = 0.4, beta = 0.35, gamma = 0.25 } = {}) {
  const normalizedFreq = maxAccess > 0 ? Math.min(1, accessFreq / maxAccess) : 0;
  return alpha * normalizedFreq + beta * Math.min(1, centrality) + gamma * Math.min(1, recency);
}

export function computeEWCDriftScore(memories = [], driftMetrics = [], alpha = 0.4, beta = 0.35, gamma = 0.25) {
  const mems = Array.isArray(memories) ? memories : [];
  const drifts = Array.isArray(driftMetrics) ? driftMetrics : [];
  let totalScore = 0;
  const maxAccess = Math.max(1, ...mems.map(m => Number(m?.access_count ?? m?.access_freq ?? 0)));
  for (let i = 0; i < mems.length; i++) {
    const m = mems[i];
    const importance = computeEWCImportance({
      accessFreq: Number(m?.access_count ?? m?.access_freq ?? 0),
      maxAccess,
      centrality: Number(m?.centrality ?? m?.cross_ref_count ?? 0) / Math.max(1, Math.max(...mems.map(x => Number(x?.centrality ?? x?.cross_ref_count ?? 1)))),
      recency: Number(m?.recency ?? 1),
      alpha, beta, gamma,
    });
    const drift = Number(drifts[i]?.drift ?? drifts[i] ?? 0);
    totalScore += importance * drift * drift;
  }
  return totalScore;
}

export function buildObservationDriftDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: [FORGETTING_BOUND_MONITOR_SOURCE, FORGETTING_PREVALENCE_MONITOR_SOURCE, EWC_DRIFT_SOURCE],
    forgetting_bound: {
      sample_size: computeForgettingBoundSampleSize(N),
      hoeffding_formula: 'P(|f_new - f_old| > ε) ≤ 2·exp(-2nε²/K)',
    },
    prevalence: {
      window_size: computePrevalenceWindow(N),
    },
    ewc: {
      lambda: computeEWCLambda(N),
      importance_formula: 'importance_i = α·access_freq + β·centrality + γ·recency',
    },
    diagnostic_only: true,
    guarded_math: {
      forgetting_bound_monitor: true,
      forgetting_prevalence_monitor: true,
      ewc_drift: true,
    },
  };
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_ROOT = path.resolve(__dirname, '..', '..');

export const AIMOS_NATIVE_RETRIEVAL_SOURCE = 'aimos-native://retrieval-telemetry';
export const DEFAULT_BENCHMARK_PATH = null;
export const LEGACY_ASMR_BENCHMARK_PATH = path.join(
  BACKEND_ROOT,
  'eval',
  'results',
  'asmr-full-brain-benchmark.json'
);

function round(value, digits = 4) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function toFiniteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function toOptionalNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function average(values) {
  if (!values.length) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function safeRatio(numerator, denominator) {
  if (!denominator) return 0;
  return numerator / denominator;
}

function formatPercentMetric(value) {
  const numeric = toOptionalNumber(value);
  return numeric === null ? 'n/a' : `${(numeric * 100).toFixed(1)}%`;
}

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

function statusPressure(status) {
  const normalized = String(status || '').toLowerCase();
  if (normalized === 'critical') return 1;
  if (normalized === 'warning' || normalized === 'monitor') return 0.62;
  if (normalized === 'stable') return 0.12;
  return 0;
}

function normalizeHealthScore(entry) {
  if (typeof entry === 'number') return entry > 1 ? clamp01(entry / 100) : clamp01(entry);
  const value = entry?.healthScore ?? entry?.health_score ?? entry?.score ?? entry?.confidence ?? 1;
  return Number(value) > 1 ? clamp01(Number(value) / 100) : clamp01(value, 1);
}

function tokenizeShiftEvidence(row = {}) {
  return new Set(String([
    row.summary,
    row.value,
    row.topic,
    row.project_direction,
    row.projectDirection,
    row.behavior,
    row.decision,
    row.fix,
  ].filter(Boolean).join(' '))
    .toLowerCase()
    .split(/[^a-z0-9_:-]+/)
    .filter((token) => token.length > 2));
}

function jaccardDistance(a, b) {
  const left = a instanceof Set ? a : new Set();
  const right = b instanceof Set ? b : new Set();
  const union = new Set([...left, ...right]);
  if (!union.size) return 0;
  let intersection = 0;
  for (const token of left) {
    if (right.has(token)) intersection++;
  }
  return 1 - (intersection / union.size);
}

export function computeBenchmarkMetrics(meta = {}, results = []) {
  const total = toFiniteNumber(meta.total_questions ?? meta.totalQuestions, results.length || 0) || results.length;
  const correct = toFiniteNumber(
    meta.correct ?? meta.correct_count ?? meta.correctCount,
    results.filter((row) => toFiniteNumber(row.score, 0) === 1).length
  );
  const accuracyValue = meta.accuracy ?? meta.accuracy_score ?? meta.accuracyScore;
  const accuracy = Number.isFinite(Number(accuracyValue))
    ? Number(accuracyValue)
    : safeRatio(correct, total || results.length);

  const evidenceCounts = results.map((row) => toFiniteNumber(row.evidence_count ?? row.evidenceCount, 0));
  const latencyValues = results.map((row) => toFiniteNumber(row.latency_ms ?? row.latencyMs, 0)).filter((value) => value > 0);
  const zeroEvidenceCount = evidenceCounts.filter((value) => value === 0).length;
  const notFoundCount = results.filter((row) => {
    const answer = String(row.predicted ?? row.prediction ?? '').trim().toUpperCase();
    return answer === '' || answer === 'NOT_FOUND';
  }).length;

  return {
    totalQuestions: total,
    correct,
    accuracy: round(accuracy),
    avgEvidenceCount: round(average(evidenceCounts)),
    zeroEvidenceRate: round(safeRatio(zeroEvidenceCount, total || results.length)),
    notFoundRate: round(safeRatio(notFoundCount, total || results.length)),
    avgLatencyMs: Math.round(average(latencyValues)),
  };
}

function emptyBenchmarkMetrics() {
  return {
    totalQuestions: null,
    correct: null,
    accuracy: null,
    avgEvidenceCount: null,
    zeroEvidenceRate: null,
    notFoundRate: null,
    avgLatencyMs: null,
  };
}

function buildAimosNativeBenchmarkResult(telemetry = {}) {
  const sampleCount = Number(telemetry.sampleCount || 0);
  const hasTelemetry = sampleCount > 0;

  return {
    exists: hasTelemetry,
    configured: false,
    required: false,
    path: AIMOS_NATIVE_RETRIEVAL_SOURCE,
    meta: {
      run_id: hasTelemetry ? `aimos-native-${telemetry.windowHours}h` : null,
      telemetry_sample_count: sampleCount,
      telemetry_window_hours: telemetry.windowHours ?? null,
      latest_recall_event_at: telemetry.latestRecallEventAt ?? null,
      source_table: 'aimos_events',
      source_operation: 'pipeline_recall_summary',
    },
    results: [],
    metrics: hasTelemetry
      ? {
          totalQuestions: sampleCount,
          correct: null,
          accuracy: null,
          avgEvidenceCount: telemetry.avgResultCount,
          zeroEvidenceRate: telemetry.zeroResultRate,
          notFoundRate: telemetry.zeroResultRate,
          avgLatencyMs: telemetry.avgLatencyMs,
        }
      : emptyBenchmarkMetrics(),
    mtimeIso: null,
    ageHours: null,
  };
}

function parseEventMetadata(value) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
}

async function getAimosNativeRetrievalTelemetry(companyId, windowHours = 168, limit = 1000) {
  const safeWindowHours = Math.max(1, Math.min(720, Number(windowHours || 168)));
  const safeLimit = Math.max(10, Math.min(5000, Number(limit || 1000)));
  const result = await query(
    `SELECT ts, metadata
       FROM aimos_events
      WHERE company_id = $1
        AND operation = 'pipeline_recall_summary'
        AND ts >= NOW() - ($2::int * INTERVAL '1 hour')
      ORDER BY ts DESC
      LIMIT $3`,
    [companyId, safeWindowHours, safeLimit]
  );

  const rows = result.rows || [];
  const resultCounts = rows
    .map((row) => {
      const metadata = parseEventMetadata(row.metadata);
      return toOptionalNumber(metadata.result_count ?? metadata.resultCount);
    })
    .filter((value) => value !== null);
  const latencyValues = rows
    .map((row) => {
      const metadata = parseEventMetadata(row.metadata);
      return toOptionalNumber(metadata.total_duration_ms ?? metadata.totalDurationMs);
    })
    .filter((value) => value !== null && value > 0);
  const zeroResultCount = resultCounts.filter((value) => value === 0).length;

  return {
    windowHours: safeWindowHours,
    sampleCount: resultCounts.length,
    avgResultCount: resultCounts.length ? round(average(resultCounts)) : null,
    zeroResultRate: resultCounts.length ? round(safeRatio(zeroResultCount, resultCounts.length)) : null,
    avgLatencyMs: latencyValues.length ? Math.round(average(latencyValues)) : null,
    latestRecallEventAt: rows[0]?.ts ? new Date(rows[0].ts).toISOString() : null,
  };
}

function loadBenchmarkResult(benchmarkPath, options = {}) {
  if (!benchmarkPath) {
    return buildAimosNativeBenchmarkResult();
  }

  const absolutePath = path.resolve(benchmarkPath);
  const required = options.required === true;
  if (!fs.existsSync(absolutePath)) {
    return {
      exists: false,
      configured: true,
      required,
      path: absolutePath,
      meta: {},
      results: [],
      metrics: emptyBenchmarkMetrics(),
      mtimeIso: null,
      ageHours: null,
    };
  }

  const raw = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
  const stat = fs.statSync(absolutePath);
  const mtimeIso = stat.mtime.toISOString();
  const ageHours = round((Date.now() - stat.mtime.getTime()) / 3_600_000, 2);

  return {
    exists: true,
    configured: true,
    required,
    path: absolutePath,
    meta: raw.meta || {},
    results: raw.results || [],
    metrics: computeBenchmarkMetrics(raw.meta || {}, raw.results || []),
    mtimeIso,
    ageHours,
  };
}

async function ensureRetrievalDriftSchema() {
  await query(
    `SELECT id, company_id, benchmark_name, benchmark_path, benchmark_exists,
            benchmark_mtime, benchmark_age_hours, benchmark_run_id,
            benchmark_accuracy, benchmark_correct, benchmark_total_questions,
            avg_evidence_count, zero_evidence_rate, not_found_rate,
            avg_latency_ms, hom_active_memory_count, total_active_memory_count,
            benchmark_memory_count_hom_active, benchmark_memory_count_total_active,
            memory_growth_since_benchmark, memory_growth_since_benchmark_ratio,
            accuracy_delta_from_previous, zero_evidence_delta_from_previous,
            status, reasons, created_at
     FROM aimos_retrieval_drift_snapshots
     WHERE false`
  );
}

async function getMemoryCounts(companyId) {
  const result = await query(
    `SELECT
       COUNT(*) FILTER (WHERE company_id = $1 AND memory_type != 'test')::int AS hom_active,
       COUNT(*) FILTER (WHERE memory_type != 'test')::int AS total_active
     FROM aimos_memories`,
    [companyId]
  );

  return {
    homActive: result.rows[0]?.hom_active || 0,
    totalActive: result.rows[0]?.total_active || 0,
  };
}

async function getPreviousSnapshot(companyId) {
  const result = await query(
    `SELECT *
       FROM aimos_retrieval_drift_snapshots
      WHERE company_id = $1
      ORDER BY created_at DESC
      LIMIT 1`,
    [companyId]
  );
  return result.rows[0] || null;
}

export function classifyRetrievalDrift({ benchmark, memoryCounts, previousSnapshot = null }) {
  const reasons = [];
  let severity = 0;
  const metrics = benchmark.metrics || emptyBenchmarkMetrics();
  const meta = benchmark.meta || {};

  if (!benchmark.exists) {
    if (benchmark.configured === false) {
      reasons.push(`aimos_native_telemetry_unavailable:${benchmark.path}`);
    } else if (benchmark.required) {
      reasons.push(`benchmark_missing:${benchmark.path}`);
      severity = Math.max(severity, 3);
    } else {
      reasons.push(`benchmark_unavailable:${benchmark.path}`);
      severity = Math.max(severity, 2);
    }
  } else {
    const accuracy = toOptionalNumber(metrics.accuracy);
    if (accuracy !== null) {
      if (accuracy <= 0.05) {
        reasons.push(`accuracy_critical:${(accuracy * 100).toFixed(1)}%`);
        severity = Math.max(severity, 3);
      } else if (accuracy <= 0.15) {
        reasons.push(`accuracy_low:${(accuracy * 100).toFixed(1)}%`);
        severity = Math.max(severity, 2);
      }
    }

    const zeroEvidenceRate = toOptionalNumber(metrics.zeroEvidenceRate);
    if (zeroEvidenceRate !== null) {
      if (zeroEvidenceRate >= 0.6) {
        reasons.push(`zero_evidence_critical:${(zeroEvidenceRate * 100).toFixed(1)}%`);
        severity = Math.max(severity, 3);
      } else if (zeroEvidenceRate >= 0.35) {
        reasons.push(`zero_evidence_high:${(zeroEvidenceRate * 100).toFixed(1)}%`);
        severity = Math.max(severity, 2);
      }
    }
  }

  const benchmarkHomCount = toOptionalNumber(
    meta.benchmark_memory_count_hom_active ?? meta.benchmarkMemoryCountHomActive
  );
  const benchmarkTotalCount = toOptionalNumber(
    meta.benchmark_memory_count_total_active ?? meta.benchmarkMemoryCountTotalActive
  );

  const homGrowthSinceBenchmark = benchmarkHomCount === null
    ? null
    : memoryCounts.homActive - benchmarkHomCount;
  const growthRatioSinceBenchmark = benchmarkHomCount && homGrowthSinceBenchmark !== null
    ? homGrowthSinceBenchmark / Math.max(benchmarkHomCount, 1)
    : null;

  if (benchmark.configured !== false && benchmark.exists && benchmark.ageHours !== null) {
    if ((growthRatioSinceBenchmark ?? 0) >= 0.2 || benchmark.ageHours >= 120) {
      reasons.push(
        `benchmark_stale_critical:age=${benchmark.ageHours}h growth=${((growthRatioSinceBenchmark ?? 0) * 100).toFixed(1)}%`
      );
      severity = Math.max(severity, 3);
    } else if ((growthRatioSinceBenchmark ?? 0) >= 0.05 || benchmark.ageHours >= 48) {
      reasons.push(
        `benchmark_stale_warning:age=${benchmark.ageHours}h growth=${((growthRatioSinceBenchmark ?? 0) * 100).toFixed(1)}%`
      );
      severity = Math.max(severity, 2);
    }
  }

  let accuracyDelta = null;
  let zeroEvidenceDelta = null;
  if (previousSnapshot) {
    const currentAccuracy = toOptionalNumber(metrics.accuracy);
    const previousAccuracy = toOptionalNumber(previousSnapshot.benchmark_accuracy);
    if (currentAccuracy !== null && previousAccuracy !== null) {
      accuracyDelta = round(currentAccuracy - previousAccuracy);
    }

    const currentZeroEvidence = toOptionalNumber(metrics.zeroEvidenceRate);
    const previousZeroEvidence = toOptionalNumber(previousSnapshot.zero_evidence_rate);
    if (currentZeroEvidence !== null && previousZeroEvidence !== null) {
      zeroEvidenceDelta = round(currentZeroEvidence - previousZeroEvidence);
    }

    const memoryGrowthSincePrevious =
      memoryCounts.homActive - toFiniteNumber(previousSnapshot.hom_active_memory_count, memoryCounts.homActive);

    if (memoryGrowthSincePrevious > 0) {
      if (accuracyDelta !== null && accuracyDelta <= -0.05) {
        reasons.push(`accuracy_regressed_critical:${(accuracyDelta * 100).toFixed(1)}pts`);
        severity = Math.max(severity, 3);
      } else if (accuracyDelta !== null && accuracyDelta <= -0.02) {
        reasons.push(`accuracy_regressed_warning:${(accuracyDelta * 100).toFixed(1)}pts`);
        severity = Math.max(severity, 2);
      }

      if (zeroEvidenceDelta !== null && zeroEvidenceDelta >= 0.15) {
        reasons.push(`zero_evidence_regressed_critical:${(zeroEvidenceDelta * 100).toFixed(1)}pts`);
        severity = Math.max(severity, 3);
      } else if (zeroEvidenceDelta !== null && zeroEvidenceDelta >= 0.05) {
        reasons.push(`zero_evidence_regressed_warning:${(zeroEvidenceDelta * 100).toFixed(1)}pts`);
        severity = Math.max(severity, 2);
      }
    }
  }

  const status = severity >= 3 ? 'critical' : severity >= 2 ? 'warning' : 'stable';

  return {
    status,
    reasons,
    accuracyDelta,
    zeroEvidenceDelta,
    benchmarkMemoryCountHomActive: benchmarkHomCount,
    benchmarkMemoryCountTotalActive: benchmarkTotalCount,
    memoryGrowthSinceBenchmark: homGrowthSinceBenchmark,
    memoryGrowthSinceBenchmarkRatio: growthRatioSinceBenchmark === null ? null : round(growthRatioSinceBenchmark),
  };
}

export function buildAntiForgettingDiagnostics({
  drift = null,
  benchmark = null,
  memoryCounts = null,
  previousSnapshot = null,
} = {}) {
  const base = drift || classifyRetrievalDrift({
    benchmark: benchmark || {
      exists: true,
      path: 'diagnostic',
      meta: {},
      metrics: { accuracy: 1, zeroEvidenceRate: 0 },
      ageHours: 0,
    },
    memoryCounts: memoryCounts || { homActive: 0, totalActive: 0 },
    previousSnapshot,
  });
  const accuracyDelta = Number(base.accuracyDelta ?? 0);
  const zeroEvidenceDelta = Number(base.zeroEvidenceDelta ?? 0);
  const growthRatio = Number(base.memoryGrowthSinceBenchmarkRatio ?? 0);
  const highRisk = accuracyDelta <= -0.05 || zeroEvidenceDelta >= 0.15;
  const moderateRisk = accuracyDelta <= -0.02 || zeroEvidenceDelta >= 0.05 || growthRatio >= 0.05;

  return {
    source_papers: [
      'A Comparative Empirical Study of Catastrophic Forgetting Mitigation in Sequential Task Adaptation for Continual NLP',
      'Deconfounded Lifelong Learning for Autonomous Driving via Dynamic Knowledge Spaces',
    ],
    status: highRisk ? 'replay_recommended' : moderateRisk ? 'monitor' : 'stable',
    drift_status: base.status,
    reasons: base.reasons || [],
    signals: {
      accuracy_delta: Number.isFinite(accuracyDelta) ? accuracyDelta : null,
      zero_evidence_delta: Number.isFinite(zeroEvidenceDelta) ? zeroEvidenceDelta : null,
      memory_growth_since_benchmark: base.memoryGrowthSinceBenchmark ?? null,
      memory_growth_since_benchmark_ratio: Number.isFinite(growthRatio) ? growthRatio : null,
    },
    replay_policy: {
      recommended: highRisk || moderateRisk,
      action: highRisk ? 'run_recall_regression_and_replay_high_value_evidence' : moderateRisk ? 'schedule_benchmark_refresh' : 'none',
      canonical_memory_changed: false,
      physical_delete_allowed: false,
    },
    diagnostic_only: true,
    ranking_math_changed: false,
    retrieval_weight_changed: false,
    guarded_math: {
      forgetting_regularizer: false,
      dynamic_knowledge_space_update: false,
      causal_deconfounding_optimizer: false,
      forgetting_bound_monitor: true,
      forgetting_prevalence_monitor: true,
      ewc_drift: true,
    },
    guarded_math_implemented: {
      forgetting_bound_monitor: { enabled: true, diagnostic_only: true, source_paper: FORGETTING_BOUND_MONITOR_SOURCE },
      forgetting_prevalence_monitor: { enabled: true, diagnostic_only: true, source_paper: FORGETTING_PREVALENCE_MONITOR_SOURCE },
      ewc_drift: { enabled: true, diagnostic_only: true, source_paper: EWC_DRIFT_SOURCE },
    },
  };
}

/**
 * Build a diagnostic-only temporal homeostasis report over a memory sample.
 * MSTH's paper scales (5 ms, 2 s, 5 min, 1 h) are represented as Aimos
 * monitoring windows rather than applied as weight-update formulas.
 *
 * @param {Array<object>} memories
 * @returns {object}
 */
export function buildTemporalHomeostasisDiagnostics(memories = []) {
  const rows = Array.isArray(memories) ? memories : [];
  const weights = rows
    .map((memory) => Number(memory.retrieval_weight ?? memory.decay_weight ?? 1))
    .filter(Number.isFinite);
  const accessCounts = rows
    .map((memory) => Number(memory.access_count || 0))
    .filter(Number.isFinite);

  const highWeightCount = weights.filter((weight) => weight >= 2.5).length;
  const lowWeightCount = weights.filter((weight) => weight > 0 && weight <= 0.05).length;
  const aladdinBreachCount = weights.filter((weight) => weight < 0.01 || weight > 3).length;
  const meanWeight = weights.length ? average(weights) : 0;
  const maxWeight = weights.length ? Math.max(...weights) : 0;
  const meanAccess = accessCounts.length ? average(accessCounts) : 0;
  const highWeightRatio = safeRatio(highWeightCount, weights.length);
  const lowWeightRatio = safeRatio(lowWeightCount, weights.length);

  let status = 'stable';
  const reasons = [];
  if (aladdinBreachCount > 0) {
    status = 'critical';
    reasons.push(`aladdin_weight_bounds_breach:${aladdinBreachCount}`);
  }
  if (highWeightRatio >= 0.25) {
    status = status === 'critical' ? status : 'warning';
    reasons.push(`high_weight_concentration:${round(highWeightRatio, 3)}`);
  }
  if (lowWeightRatio >= 0.25) {
    status = status === 'critical' ? status : 'warning';
    reasons.push(`low_weight_floor_pressure:${round(lowWeightRatio, 3)}`);
  }

  return {
    source_paper: 'Multi-Scale Temporal Homeostasis Enables Efficient and Robust Neural Networks',
    status,
    sample_count: rows.length,
    timescales: {
      ultra_fast_5ms: 'runtime event telemetry only',
      fast_2s: 'run/stream cadence diagnostics',
      medium_5min: 'session and recall pressure diagnostics',
      slow_1h: 'dream/heartbeat/retrieval drift diagnostics',
    },
    metrics: {
      mean_retrieval_weight: round(meanWeight, 4),
      max_retrieval_weight: round(maxWeight, 4),
      mean_access_count: round(meanAccess, 4),
      high_weight_count: highWeightCount,
      low_weight_count: lowWeightCount,
      aladdin_bounds_breach_count: aladdinBreachCount,
      high_weight_ratio: round(highWeightRatio, 4),
      low_weight_ratio: round(lowWeightRatio, 4),
    },
    reasons,
    guarded_math: {
      homeostatic_weight_update: false,
      cross_scale_coupling_formula: false,
      dream_consolidation_formula_change: false,
      stdp_update_rule_change: false,
    },
    retrieval_weight_changed: false,
    ranking_math_changed: false,
  };
}

export function buildAimosViabilityPulseDiagnostics({
  recallDrift = null,
  agentHealth = [],
  confidenceTrend = [],
  safetyIntercepts = [],
  contextPressure = 0,
} = {}) {
  const driftPressure = typeof recallDrift === 'number'
    ? clamp01(recallDrift)
    : Math.max(statusPressure(recallDrift?.status), clamp01(recallDrift?.score ?? recallDrift?.drift_score ?? 0));
  const healthValues = (Array.isArray(agentHealth) ? agentHealth : [agentHealth]).map(normalizeHealthScore);
  const meanHealth = healthValues.length ? average(healthValues) : 1;
  const confidenceValues = (Array.isArray(confidenceTrend) ? confidenceTrend : [])
    .map((entry) => typeof entry === 'number' ? entry : entry?.confidence ?? entry?.score)
    .map((value) => clamp01(value));
  const confidenceDelta = confidenceValues.length >= 2
    ? confidenceValues[confidenceValues.length - 1] - confidenceValues[0]
    : 0;
  const safetyEvents = Array.isArray(safetyIntercepts) ? safetyIntercepts : [];
  const safetyPressure = safetyEvents.length
    ? clamp01(safetyEvents.filter((event) => event?.blocked !== false).length / Math.max(1, safetyEvents.length))
    : clamp01(Number(safetyIntercepts || 0) / 5);
  const context = clamp01(contextPressure);
  const pressureScore = clamp01(
    (0.3 * driftPressure)
    + (0.2 * (1 - meanHealth))
    + (0.16 * Math.max(0, -confidenceDelta))
    + (0.18 * safetyPressure)
    + (0.16 * context)
  );

  return {
    source_paper: 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment',
    status: pressureScore >= 0.7 ? 'critical' : pressureScore >= 0.4 ? 'watch' : 'stable',
    diagnostic_only: true,
    pulse_interval: 'runtime_or_dream_snapshot',
    signals: {
      recall_drift_pressure: round(driftPressure, 6),
      mean_agent_health: round(meanHealth, 6),
      confidence_delta: round(confidenceDelta, 6),
      safety_intercept_pressure: round(safetyPressure, 6),
      context_pressure: round(context, 6),
      viability_pressure: round(pressureScore, 6),
    },
    action_contract: {
      recall_ranking_changed: false,
      retrieval_weight_changed: false,
      safety_policy_changed: false,
      canonical_memory_changed: false,
    },
  };
}

export function buildBackwardLookingShiftDiagnostics({
  queryText = 'what changed last week?',
  timeline = [],
  minDistance = 0.55,
} = {}) {
  const rows = Array.isArray(timeline) ? [...timeline] : [];
  const ordered = rows.sort((a, b) => String(a.date || a.created_at || '').localeCompare(String(b.date || b.created_at || '')));
  const changes = [];

  for (let index = 1; index < ordered.length; index++) {
    const previous = ordered[index - 1];
    const current = ordered[index];
    const distance = jaccardDistance(tokenizeShiftEvidence(previous), tokenizeShiftEvidence(current));
    const explicitShift = Boolean(current.shift_marker || current.changed || current.change_point);
    if (distance >= minDistance || explicitShift) {
      changes.push({
        from_key: previous.key || previous.id || `timeline:${index - 1}`,
        to_key: current.key || current.id || `timeline:${index}`,
        at: current.date || current.created_at || null,
        distance: round(distance, 6),
        reason: explicitShift ? 'explicit_shift_marker' : 'timeline_evidence_shift',
        evidence_keys: [previous.key, current.key].filter(Boolean),
      });
    }
  }

  return {
    source_paper: 'Forecasting the Past: Gradient-Based Distribution Shift Detection in Trajectory Prediction',
    query_text: queryText,
    status: changes.length ? 'shift_detected' : 'no_shift_detected',
    diagnostic_only: true,
    timeline_evidence_count: ordered.length,
    changes,
    answer_contract: {
      must_answer_from_timeline_evidence: true,
      recent_session_bias_allowed: false,
      raw_database_shortcut_allowed: false,
      canonical_memory_changed: false,
    },
    guardrails: {
      ranking_math_changed: false,
      retrieval_weight_changed: false,
      dream_weight_changed: false,
    },
  };
}

export function formatRetrievalDriftSummary(snapshot) {
  const reasons = Array.isArray(snapshot.reasons) ? snapshot.reasons : [];
  const parts = [
    `status=${snapshot.status}`,
    `accuracy=${formatPercentMetric(snapshot.benchmarkAccuracy)}`,
    `zero_evidence=${formatPercentMetric(snapshot.zeroEvidenceRate)}`,
    `hom_memories=${snapshot.homActiveMemoryCount}`,
  ];

  if (snapshot.benchmarkAgeHours !== null) {
    parts.push(`benchmark_age_h=${snapshot.benchmarkAgeHours}`);
  }

  if (snapshot.memoryGrowthSinceBenchmark !== null) {
    parts.push(`growth_since_benchmark=${snapshot.memoryGrowthSinceBenchmark}`);
  }

  if (reasons.length) {
    parts.push(`reasons=${reasons.join('|')}`);
  }

  return parts.join(' | ');
}

export async function recordRetrievalDriftSnapshot(companyId = 'hom', options = {}) {
  await ensureRetrievalDriftSchema();

  const benchmark = options.benchmarkPath
    ? loadBenchmarkResult(options.benchmarkPath, { required: options.requireBenchmark !== false })
    : buildAimosNativeBenchmarkResult(
        await getAimosNativeRetrievalTelemetry(companyId, options.nativeWindowHours || 168)
      );
  const memoryCounts = await getMemoryCounts(companyId);
  const previousSnapshot = await getPreviousSnapshot(companyId);
  const drift = classifyRetrievalDrift({ benchmark, memoryCounts, previousSnapshot });

  const snapshot = {
    benchmarkName: benchmark.path === AIMOS_NATIVE_RETRIEVAL_SOURCE
      ? 'aimos-native-retrieval-telemetry'
      : path.basename(benchmark.path),
    benchmarkPath: benchmark.path,
    benchmarkExists: benchmark.exists,
    benchmarkMtime: benchmark.mtimeIso,
    benchmarkAgeHours: benchmark.ageHours,
    benchmarkRunId: benchmark.meta.run_id || null,
    benchmarkAccuracy: benchmark.metrics.accuracy,
    benchmarkCorrect: benchmark.metrics.correct,
    benchmarkTotalQuestions: benchmark.metrics.totalQuestions,
    avgEvidenceCount: benchmark.metrics.avgEvidenceCount,
    zeroEvidenceRate: benchmark.metrics.zeroEvidenceRate,
    notFoundRate: benchmark.metrics.notFoundRate,
    avgLatencyMs: benchmark.metrics.avgLatencyMs,
    homActiveMemoryCount: memoryCounts.homActive,
    totalActiveMemoryCount: memoryCounts.totalActive,
    benchmarkMemoryCountHomActive: drift.benchmarkMemoryCountHomActive,
    benchmarkMemoryCountTotalActive: drift.benchmarkMemoryCountTotalActive,
    memoryGrowthSinceBenchmark: drift.memoryGrowthSinceBenchmark,
    memoryGrowthSinceBenchmarkRatio: drift.memoryGrowthSinceBenchmarkRatio,
    accuracyDeltaFromPrevious: drift.accuracyDelta,
    zeroEvidenceDeltaFromPrevious: drift.zeroEvidenceDelta,
    status: drift.status,
    reasons: drift.reasons,
  };

  await query(
    `INSERT INTO aimos_retrieval_drift_snapshots (
       company_id,
       benchmark_name,
       benchmark_path,
       benchmark_exists,
       benchmark_mtime,
       benchmark_age_hours,
       benchmark_run_id,
       benchmark_accuracy,
       benchmark_correct,
       benchmark_total_questions,
       avg_evidence_count,
       zero_evidence_rate,
       not_found_rate,
       avg_latency_ms,
       hom_active_memory_count,
       total_active_memory_count,
       benchmark_memory_count_hom_active,
       benchmark_memory_count_total_active,
       memory_growth_since_benchmark,
       memory_growth_since_benchmark_ratio,
       accuracy_delta_from_previous,
       zero_evidence_delta_from_previous,
       status,
       reasons
     ) VALUES (
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb
     )`,
    [
      companyId,
      snapshot.benchmarkName,
      snapshot.benchmarkPath,
      snapshot.benchmarkExists,
      snapshot.benchmarkMtime,
      snapshot.benchmarkAgeHours,
      snapshot.benchmarkRunId,
      snapshot.benchmarkAccuracy,
      snapshot.benchmarkCorrect,
      snapshot.benchmarkTotalQuestions,
      snapshot.avgEvidenceCount,
      snapshot.zeroEvidenceRate,
      snapshot.notFoundRate,
      snapshot.avgLatencyMs,
      snapshot.homActiveMemoryCount,
      snapshot.totalActiveMemoryCount,
      snapshot.benchmarkMemoryCountHomActive,
      snapshot.benchmarkMemoryCountTotalActive,
      snapshot.memoryGrowthSinceBenchmark,
      snapshot.memoryGrowthSinceBenchmarkRatio,
      snapshot.accuracyDeltaFromPrevious,
      snapshot.zeroEvidenceDeltaFromPrevious,
      snapshot.status,
      JSON.stringify(snapshot.reasons),
    ]
  );

  return snapshot;
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Alongside-path diagnostics
// Forgetting bound, prevalence, and EWC-analog drift diagnostics.
// These do NOT replace production drift classification or retrieval ranking.
// ---------------------------------------------------------------------------

/**
 * Forgetting Bound Monitor Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Data-Dependent & Aimos Bounds on Forgetting
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Computes a forgetting upper-bound estimate from drift accuracy deltas.
 * The production drift classification and benchmark scoring remain
 * authoritative. Guarded by guarded_math flag forgetting_bound_monitor
 * (knowledge-gated).
 */
export function buildForgettingBoundMonitorDiagnostic({
  accuracyDelta = 0,
  zeroEvidenceDelta = 0,
  memoryGrowthRatio = 0,
} = {}) {
  const ad = Number(accuracyDelta ?? 0);
  const zed = Number(zeroEvidenceDelta ?? 0);
  const gr = Number(memoryGrowthRatio ?? 0);
  const forgettingEstimate = Math.max(0, Math.min(1, -ad + zed * 0.5 + gr * 0.3));

  return {
    diagnostic: true,
    source_paper: FORGETTING_BOUND_MONITOR_SOURCE,
    coexistence_class: 'side_by_side_independent',
    accuracy_delta: ad,
    zero_evidence_delta: zed,
    memory_growth_ratio: gr,
    forgetting_bound_estimate: Number(forgettingEstimate.toFixed(6)),
    drift_classification_unchanged: true,
    note: 'Alongside-path diagnostic. Forgetting bound does not replace production drift classification.',
  };
}

/**
 * Forgetting Prevalence Monitor Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Forgetting Is Everywhere
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Computes the fraction of monitored dimensions showing forgetting
 * (accuracy decline, zero-evidence increase, weight decline). The production
 * drift classification remains authoritative. Guarded by guarded_math flag
 * forgetting_prevalence_monitor (knowledge-gated).
 */
export function buildForgettingPrevalenceMonitorDiagnostic({
  dimensions = [],
} = {}) {
  const dims = Array.isArray(dimensions) ? dimensions : [];
  const total = dims.length || 1;
  const forgettingDims = dims.filter(d => {
    const val = Number(d?.delta ?? d?.change ?? 0);
    return val < 0 || (d?.declining === true);
  }).length;
  const prevalenceRatio = forgettingDims / total;

  return {
    diagnostic: true,
    source_paper: FORGETTING_PREVALENCE_MONITOR_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    total_dimensions: dims.length,
    forgetting_dimensions: forgettingDims,
    prevalence_ratio: Number(prevalenceRatio.toFixed(6)),
    drift_classification_unchanged: true,
    note: 'Alongside-path diagnostic. Prevalence assessment does not replace production drift classification.',
  };
}

/**
 * EWC Drift Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Overcoming Catastrophic Forgetting (EWC)
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * EWC-analog importance-weighted drift diagnostic. This is an ANALOG —
 * memories are NOT parameterized weights. importance_i = α·access_freq +
 * β·centrality + γ·recency; score = Σ importance · drift². The production
 * drift classification remains authoritative. Guarded by guarded_math flag
 * ewc_drift (knowledge-gated).
 */
export function buildEWCDriftDiagnostic({
  memories = [],
  driftMetrics = [],
  alpha = 0.4,
  beta = 0.35,
  gamma = 0.25,
} = {}) {
  const mems = Array.isArray(memories) ? memories : [];
  const drifts = Array.isArray(driftMetrics) ? driftMetrics : [];
  const a = Number(alpha) || 0.4;
  const b = Number(beta) || 0.35;
  const g = Number(gamma) || 0.25;

  let totalScore = 0;
  const details = [];
  for (let i = 0; i < mems.length; i++) {
    const m = mems[i];
    const accessFreq = Number(m?.access_count ?? m?.access_freq ?? 0);
    const maxAccess = Math.max(1, ...mems.map(x => Number(x?.access_count ?? x?.access_freq ?? 0)));
    const centrality = Number(m?.centrality ?? m?.cross_ref_count ?? 0) / Math.max(1, Math.max(...mems.map(x => Number(x?.centrality ?? x?.cross_ref_count ?? 1))));
    const recency = Number(m?.recency ?? 1);
    const importance = a * (accessFreq / maxAccess) + b * centrality + g * Math.min(1, recency);
    const drift = Number(drifts[i]?.drift ?? drifts[i] ?? 0);
    const contribution = importance * drift * drift;
    totalScore += contribution;
    if (i < 10) {
      details.push({ importance: Number(importance.toFixed(6)), drift: Number(drift.toFixed(6)), contribution: Number(contribution.toFixed(6)) });
    }
  }

  return {
    diagnostic: true,
    source_paper: EWC_DRIFT_SOURCE,
    coexistence_class: 'side_by_side_independent',
    ewc_analog: true,
    memories_are_not_parameterized_weights: true,
    formula: 'importance_i = α·access_freq + β·centrality + γ·recency; score = Σ importance · drift²',
    alpha: a,
    beta: b,
    gamma: g,
    memory_count: mems.length,
    total_ewc_score: Number(totalScore.toFixed(6)),
    top_contributions: details,
    drift_classification_unchanged: true,
    note: 'Alongside-path diagnostic. EWC-analog drift assessment does not replace production drift classification.',
  };
}
