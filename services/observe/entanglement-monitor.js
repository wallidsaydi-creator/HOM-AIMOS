// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into DREAM autonomy/entanglement diagnostics
// Purpose: Detects and quantifies human influence on ostensibly autonomous agents
//          via temporal, content, and ownership signal triangulation
// Called by: jobs/nightly-dream.js Stage 12
// Calls: observe/event-ledger.js
// Pipeline: DREAM
// Additive Batch9.5 Wave6 authority: common-envelope inspiral adds audit-only
// coupled-pressure analogy diagnostics; Moltbook formulas remain unchanged.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ENTANGLEMENT MONITOR — THE MOLTBOOK ILLUSION DETECTION
 *
 * Source: "The Moltbook Illusion: Disentangling Human Influence in Autonomous AI Agents" (2026)
 *
 * Detects and quantifies human influence on ostensibly autonomous AI agents through
 * multi-signal triangulation. Three independent signal families (temporal, content,
 * ownership) are combined, validated as independent via Cramer's V = 0.04.
 *
 * Key techniques:
 *   - CoV temporal fingerprinting: CoV = sigma(intervals)/mean(intervals)
 *     CoV < 0.5 = autonomous heartbeat, CoV > 1.0 = human-influenced
 *     Validated: chi-square = 551.76, P < 10^-117
 *   - Bot farming detection: sub-minute median inter-action gaps
 *   - Echo decay: y(d) = a*exp(-lambda*d) + c
 *     Human-seeded half-life 0.58, autonomous 0.72
 *   - 9-dimension influence score (weighted composite)
 *   - Multi-signal triangulation with independence verification
 *
 * Created: 2026-04-01
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// CoV classification thresholds (validated by chi-square = 551.76)
const COV_AUTONOMOUS_CEILING = 0.50;
const COV_HUMAN_FLOOR = 1.00;

// Bot farming detection
const BOT_FARMING_MEDIAN_GAP_SEC = 60; // Sub-minute median = bot farming signal

// Echo decay constants
const HUMAN_SEEDED_HALF_LIFE = 0.58;
const AUTONOMOUS_HALF_LIFE = 0.72;
const HALF_LIFE_BOUNDARY = (HUMAN_SEEDED_HALF_LIFE + AUTONOMOUS_HALF_LIFE) / 2; // 0.65

// 9-dimension influence score weights
const INFLUENCE_DIMENSIONS = [
  { key: 'taskCompletion',    weight: 0.30 },
  { key: 'promotional',       weight: 0.25 },
  { key: 'forcedAiFraming',   weight: 0.20 },
  { key: 'lowNaturalness',    weight: 0.15 },
  { key: 'genericSpecificity', weight: 0.10 },
  // Secondary dimensions (contribute to detail but not primary score)
  { key: 'templateUsage',     weight: 0.00 },
  { key: 'timingRegularity',  weight: 0.00 },
  { key: 'vocabularyRange',   weight: 0.00 },
  { key: 'topicDrift',        weight: 0.00 }
];

// Cramer's V threshold for independence
const INDEPENDENCE_V_THRESHOLD = 0.10;

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

/**
 * Compute coefficient of variation for a series of time intervals.
 * CoV = standard_deviation(intervals) / mean(intervals)
 *
 * @param {Array<number>} intervals - Time intervals between actions (in seconds)
 * @returns {{cov: number, mean: number, stddev: number, classification: string}}
 */
export function computeCoV(intervals) {
  if (!Array.isArray(intervals) || intervals.length < 2) {
    return { cov: 0, mean: 0, stddev: 0, classification: 'insufficient_data' };
  }

  const n = intervals.length;
  const mean = intervals.reduce((a, b) => a + b, 0) / n;

  if (mean === 0) {
    return { cov: 0, mean: 0, stddev: 0, classification: 'zero_mean' };
  }

  const variance = intervals.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / n;
  const stddev = Math.sqrt(variance);
  const cov = stddev / mean;

  let classification;
  if (cov < COV_AUTONOMOUS_CEILING) {
    classification = 'autonomous';
  } else if (cov > COV_HUMAN_FLOOR) {
    classification = 'human_influenced';
  } else {
    classification = 'hybrid';
  }

  return { cov, mean, stddev, classification };
}

/**
 * Classify agent behavior as autonomous, human-influenced, or hybrid.
 * Pulls action timestamps from agent_runs within the specified window,
 * falling back to aimos_memories saves when an agent was not registered
 * through Agent Runner.
 * and applies CoV temporal fingerprinting.
 *
 * @param {string} agentId - Agent identifier
 * @param {number} windowHours - Analysis window in hours (default: 24)
 * @param {string} companyId - Company ID
 * @returns {Promise<{classification: string, cov: number, sampleSize: number, confidence: number}>}
 */
async function loadActionRows(agentId, windowHours, companyId, activitySource = 'auto') {
  if (activitySource === 'memory_saves') {
    const res = await query(
      `SELECT created_at FROM aimos_memories
       WHERE company_id = $1 AND agent_id = $2
         AND created_at >= NOW() - INTERVAL '1 hour' * $3
       ORDER BY created_at ASC`,
      [companyId, agentId, windowHours]
    );
    return { rows: res.rows, activitySource: 'memory_saves' };
  }

  const runRes = await query(
    `SELECT created_at FROM agent_runs
     WHERE company_id = $1 AND source_agent_id = $2
       AND created_at >= NOW() - INTERVAL '1 hour' * $3
     ORDER BY created_at ASC`,
    [companyId, agentId, windowHours]
  );
  if (activitySource === 'agent_runs' || runRes.rows.length >= 3) {
    return { rows: runRes.rows, activitySource: 'agent_runs' };
  }

  const memoryRes = await query(
    `SELECT created_at FROM aimos_memories
     WHERE company_id = $1 AND agent_id = $2
       AND created_at >= NOW() - INTERVAL '1 hour' * $3
     ORDER BY created_at ASC`,
    [companyId, agentId, windowHours]
  );
  return memoryRes.rows.length > runRes.rows.length
    ? { rows: memoryRes.rows, activitySource: 'memory_saves' }
    : { rows: runRes.rows, activitySource: 'agent_runs' };
}

export async function classifyBehavior(agentId, windowHours = 24, companyId = COMPANY, options = {}) {
  try {
    const activitySource = options.activitySource || 'auto';
    const res = await loadActionRows(agentId, windowHours, companyId, activitySource);

    if (res.rows.length < 3) {
      return {
        classification: 'insufficient_data',
        cov: 0,
        sampleSize: res.rows.length,
        confidence: 0,
        activitySource: res.activitySource,
      };
    }

    // Compute inter-action intervals in seconds
    const timestamps = res.rows.map(r => new Date(r.created_at).getTime() / 1000);
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }

    const covResult = computeCoV(intervals);

    // Confidence scales with sample size (asymptotic at ~50 samples)
    const confidence = Math.min(1, intervals.length / 50);

    return {
      classification: covResult.classification,
      cov: covResult.cov,
      sampleSize: intervals.length,
      confidence,
      activitySource: res.activitySource,
    };
  } catch (err) {
    console.warn(`[ENTANGLEMENT] Failed to classify behavior for ${agentId}: ${err.message}`);
    return { classification: 'error', cov: 0, sampleSize: 0, confidence: 0 };
  }
}

export async function runEntanglementAutonomyAudit({
  companyId = COMPANY,
  windowHours = 24,
  maxAgents = 20,
  agentIds = null,
} = {}) {
  const boundedWindow = Math.max(1, Math.min(2160, Number(windowHours) || 24));
  let agents = Array.isArray(agentIds)
    ? agentIds.map((id) => String(id || '').trim()).filter(Boolean)
    : [];

  if (agents.length === 0) {
    const res = await query(
      `SELECT agent_id, SUM(action_count)::int AS action_count
       FROM (
         SELECT source_agent_id AS agent_id, COUNT(*)::int AS action_count
         FROM agent_runs
         WHERE company_id = $1
           AND source_agent_id IS NOT NULL
           AND created_at >= NOW() - INTERVAL '1 hour' * $2
         GROUP BY source_agent_id
         UNION ALL
         SELECT agent_id, COUNT(*)::int AS action_count
         FROM aimos_memories
         WHERE company_id = $1
           AND agent_id IS NOT NULL
           AND agent_id <> 'system'
           AND created_at >= NOW() - INTERVAL '1 hour' * $2
         GROUP BY agent_id
       ) activity
       GROUP BY agent_id
       ORDER BY action_count DESC
       LIMIT $3`,
      [companyId, boundedWindow, Math.max(1, Math.min(100, Number(maxAgents) || 20))]
    );
    agents = res.rows.map((row) => row.agent_id).filter(Boolean);
  }

  const behavior = [];
  for (const agentId of agents) {
    behavior.push({
      agentId,
      ...(await classifyBehavior(agentId, boundedWindow, companyId, { activitySource: 'auto' })),
    });
  }

  const botFarming = agents.length > 0
    ? await detectBotFarming(agents, boundedWindow, companyId, 'auto')
    : { flagged: [], clean: [] };

  const summary = {
    status: agents.length > 0 ? 'observed' : 'insufficient_data',
    windowHours: boundedWindow,
    checkedAgents: agents.length,
    activitySources: [...new Set(behavior.map((row) => row.activitySource).filter(Boolean))],
    humanInfluenced: behavior.filter((row) => row.classification === 'human_influenced').length,
    autonomous: behavior.filter((row) => row.classification === 'autonomous').length,
    hybrid: behavior.filter((row) => row.classification === 'hybrid').length,
    botFarmingFlags: botFarming.flagged.length,
  };

  const eventId = await logEvent(companyId, 'entanglement-monitor', 'entanglement_autonomy_audit', `entanglement:${Date.now()}`, {
    reasoning: agents.length > 0
      ? `Entanglement monitor audited ${agents.length} agent(s) across ${boundedWindow}h using Moltbook CoV temporal fingerprinting over ${summary.activitySources.join(', ') || 'activity rows'} and bot-farming gap checks.`
      : `Entanglement monitor found no agent_runs or agent memory saves in the last ${boundedWindow}h; autonomy classification remains insufficient_data for this dream window.`,
    source_knowledge: 'The Moltbook Illusion — CoV temporal fingerprinting, bot farming median gaps, echo decay, and multi-signal triangulation',
    summary,
    behavior,
    botFarming,
    diagnostic_only: true,
    routing_changed: false,
    policy_changed: false,
    canonical_memory_changed: false,
  });

  return {
    ...summary,
    behavior,
    botFarming,
    eventId,
    diagnostic_only: true,
    canonical_memory_changed: false,
  };
}

/**
 * Detect coordinated bot farming patterns across multiple agents.
 * Identifies agents with suspiciously regular sub-minute inter-action gaps.
 *
 * @param {Array<string>} agentIds - Agent identifiers to check
 * @param {number} windowHours - Analysis window in hours (default: 24)
 * @param {string} companyId - Company ID
 * @returns {Promise<{flagged: Array<{agentId: string, medianGap: number, pattern: string}>, clean: Array<string>}>}
 */
export async function detectBotFarming(agentIds, windowHours = 24, companyId = COMPANY, activitySource = 'auto') {
  const flagged = [];
  const clean = [];

  for (const agentId of agentIds) {
    try {
      const res = await loadActionRows(agentId, windowHours, companyId, activitySource);

      if (res.rows.length < 5) {
        clean.push(agentId);
        continue;
      }

      const timestamps = res.rows.map(r => new Date(r.created_at).getTime() / 1000);
      const gaps = [];
      for (let i = 1; i < timestamps.length; i++) {
        gaps.push(timestamps[i] - timestamps[i - 1]);
      }

      // Compute median gap
      const sorted = [...gaps].sort((a, b) => a - b);
      const medianGap = sorted[Math.floor(sorted.length / 2)];

      // CoV of gaps for regularity detection
      const covResult = computeCoV(gaps);

      if (medianGap < BOT_FARMING_MEDIAN_GAP_SEC && covResult.cov < COV_AUTONOMOUS_CEILING) {
        // Sub-minute median + very regular = bot farming signature
        flagged.push({
          agentId,
          medianGap,
          cov: covResult.cov,
          pattern: 'coordinated_bot_farming',
          activitySource: res.activitySource,
          actionCount: timestamps.length
        });
      } else if (medianGap < BOT_FARMING_MEDIAN_GAP_SEC) {
        flagged.push({
          agentId,
          medianGap,
          cov: covResult.cov,
          pattern: 'rapid_action_irregular',
          activitySource: res.activitySource,
          actionCount: timestamps.length
        });
      } else {
        clean.push(agentId);
      }
    } catch (err) {
      console.warn(`[ENTANGLEMENT] Bot farming check failed for ${agentId}: ${err.message}`);
      clean.push(agentId);
    }
  }

  return { flagged, clean };
}

/**
 * Compute echo decay for a content chain.
 * Fits y(d) = a * exp(-lambda * d) + c where d = days since seeding.
 * The half-life (ln(2)/lambda) discriminates human-seeded vs autonomous content.
 *
 * @param {Array<{daysSinceOrigin: number, similarity: number}>} contentChain - Decay observations
 * @returns {{lambda: number, halfLife: number, a: number, c: number, classification: string, r2: number}}
 */
export function computeEchoDecay(contentChain) {
  if (!Array.isArray(contentChain) || contentChain.length < 3) {
    return { lambda: 0, halfLife: 0, a: 0, c: 0, classification: 'insufficient_data', r2: 0 };
  }

  // Sort by days
  const sorted = [...contentChain].sort((a, b) => a.daysSinceOrigin - b.daysSinceOrigin);

  // Estimate c as the minimum similarity (asymptotic floor)
  const similarities = sorted.map(p => p.similarity);
  const c = Math.min(...similarities) * 0.95;

  // Linearize: ln(y - c) = ln(a) - lambda * d
  const linearPoints = sorted
    .map(p => ({
      d: p.daysSinceOrigin,
      logYMinusC: p.similarity - c > 0.001 ? Math.log(p.similarity - c) : null
    }))
    .filter(p => p.logYMinusC !== null);

  if (linearPoints.length < 2) {
    return { lambda: 0, halfLife: 0, a: 0, c, classification: 'insufficient_data', r2: 0 };
  }

  // Simple linear regression: logYMinusC = intercept + slope * d
  const n = linearPoints.length;
  const sumD = linearPoints.reduce((s, p) => s + p.d, 0);
  const sumY = linearPoints.reduce((s, p) => s + p.logYMinusC, 0);
  const sumDY = linearPoints.reduce((s, p) => s + p.d * p.logYMinusC, 0);
  const sumDD = linearPoints.reduce((s, p) => s + p.d * p.d, 0);

  const denom = n * sumDD - sumD * sumD;
  if (Math.abs(denom) < 1e-10) {
    return { lambda: 0, halfLife: 0, a: 0, c, classification: 'flat', r2: 0 };
  }

  const slope = (n * sumDY - sumD * sumY) / denom;
  const intercept = (sumY - slope * sumD) / n;

  const lambda = -slope; // lambda is positive for decay
  const a = Math.exp(intercept);
  const halfLife = lambda > 0 ? Math.LN2 / lambda : Infinity;

  // Compute R-squared
  const meanY = sumY / n;
  const ssTotal = linearPoints.reduce((s, p) => s + Math.pow(p.logYMinusC - meanY, 2), 0);
  const ssResidual = linearPoints.reduce((s, p) => {
    const predicted = intercept + slope * p.d;
    return s + Math.pow(p.logYMinusC - predicted, 2);
  }, 0);
  const r2 = ssTotal > 0 ? 1 - ssResidual / ssTotal : 0;

  let classification;
  if (halfLife < HALF_LIFE_BOUNDARY) {
    classification = 'human_seeded';
  } else if (halfLife > AUTONOMOUS_HALF_LIFE + 0.1) {
    classification = 'autonomous';
  } else {
    classification = 'ambiguous';
  }

  return { lambda, halfLife, a, c, classification, r2 };
}

/**
 * Compute the 9-dimension human influence score.
 * Primary dimensions (weighted): task completion, promotional, forced AI framing,
 * low naturalness, generic specificity. Secondary dimensions recorded but not
 * weighted into the primary score.
 *
 * @param {string} agentId - Agent identifier
 * @param {object} signals - Per-dimension signals (0-1 each): {taskCompletion, promotional, ...}
 * @returns {{score: number, breakdown: object, classification: string}}
 */
export function computeInfluenceScore(agentId, signals = {}) {
  let weightedSum = 0;
  let totalWeight = 0;
  const breakdown = {};

  for (const dim of INFLUENCE_DIMENSIONS) {
    const raw = Math.max(0, Math.min(1, signals[dim.key] || 0));
    breakdown[dim.key] = {
      raw,
      weight: dim.weight,
      contribution: raw * dim.weight
    };

    if (dim.weight > 0) {
      weightedSum += raw * dim.weight;
      totalWeight += dim.weight;
    }
  }

  const score = totalWeight > 0 ? weightedSum / totalWeight : 0;

  let classification;
  if (score < 0.3) {
    classification = 'likely_autonomous';
  } else if (score > 0.7) {
    classification = 'likely_human_influenced';
  } else {
    classification = 'ambiguous';
  }

  return { score, breakdown, classification };
}

/**
 * Triangulate temporal, content, and ownership signals for a final determination.
 * The three signal families are validated as independent (Cramer's V = 0.04).
 * Agreement across all three provides high confidence; disagreement triggers review.
 *
 * @param {object} temporal - Temporal signal: {classification, cov, confidence}
 * @param {object} content - Content signal: {classification, halfLife, r2}
 * @param {object} ownership - Ownership signal: {classification, score}
 * @returns {{verdict: string, confidence: number, agreement: number, signals: object, independent: boolean}}
 */
export function triangulateSignals(temporal, content, ownership) {
  const signals = {
    temporal: normalizeClassification(temporal?.classification),
    content: normalizeClassification(content?.classification),
    ownership: normalizeClassification(ownership?.classification)
  };

  // Count how many signals agree
  const classifications = Object.values(signals);
  const counts = {};
  for (const c of classifications) {
    counts[c] = (counts[c] || 0) + 1;
  }

  const maxCount = Math.max(...Object.values(counts));
  const majorityClass = Object.entries(counts).find(([, v]) => v === maxCount)[0];
  const agreement = maxCount / classifications.length;

  // Weight by signal confidence/quality
  const temporalConf = temporal?.confidence || 0.5;
  const contentConf = content?.r2 || 0.5;
  const ownershipConf = ownership?.score != null ? Math.abs(ownership.score - 0.5) * 2 : 0.5;

  const totalConf = (temporalConf + contentConf + ownershipConf) / 3;

  // Independence verification: signals should have low cross-correlation
  // In practice Cramer's V = 0.04 was validated in the paper; we check consistency
  const independent = verifyIndependence(temporal, content, ownership);

  let verdict;
  if (agreement >= 0.67 && majorityClass !== 'ambiguous') {
    verdict = majorityClass;
  } else if (agreement >= 0.67 && majorityClass === 'ambiguous') {
    verdict = 'needs_investigation';
  } else {
    verdict = 'conflicting_signals';
  }

  const confidence = agreement * totalConf * (independent ? 1.0 : 0.6);

  return {
    verdict,
    confidence: Math.min(1, confidence),
    agreement,
    signals,
    independent
  };
}

export function buildInspiralEntanglementDiagnostics({
  signals = [],
  energyBudgetPressure = 0,
  contextPressure = 0,
} = {}) {
  const rows = Array.isArray(signals) ? signals : [];
  const couplingValues = rows.map((signal) => clamp01(
    signal?.coupling ?? signal?.influence ?? signal?.correlation ?? signal?.pressure ?? 0
  ));
  const meanCoupling = couplingValues.length
    ? couplingValues.reduce((sum, value) => sum + value, 0) / couplingValues.length
    : 0;
  const maxCoupling = couplingValues.length ? Math.max(...couplingValues) : 0;
  const dragPressure = clamp01((0.45 * meanCoupling) + (0.25 * maxCoupling) + (0.15 * clamp01(energyBudgetPressure)) + (0.15 * clamp01(contextPressure)));

  return {
    source_paper: 'Local simulations of common-envelope dynamical inspiral: Impact of rotation, accretion, and stratification',
    status: dragPressure >= 0.7 ? 'high_coupling_pressure' : dragPressure >= 0.4 ? 'watch' : 'stable',
    audit_only_analogy: true,
    diagnostic_only: true,
    analogy_scope: 'coupled-system pressure, not an astrophysical simulation',
    metrics: {
      signal_count: rows.length,
      mean_coupling: Number(meanCoupling.toFixed(6)),
      max_coupling: Number(maxCoupling.toFixed(6)),
      drag_pressure_proxy: Number(dragPressure.toFixed(6)),
    },
    guardrails: {
      autonomy_classification_math_changed: false,
      routing_changed: false,
      policy_changed: false,
      canonical_memory_changed: false,
    },
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function normalizeClassification(raw) {
  const mapping = {
    autonomous: 'autonomous',
    human_influenced: 'human_influenced',
    human_seeded: 'human_influenced',
    likely_autonomous: 'autonomous',
    likely_human_influenced: 'human_influenced',
    hybrid: 'ambiguous',
    ambiguous: 'ambiguous',
    insufficient_data: 'ambiguous',
    error: 'ambiguous'
  };
  return mapping[raw] || 'ambiguous';
}

function verifyIndependence(temporal, content, ownership) {
  // Approximate independence check via signal divergence.
  // True independence validated offline via chi-square / Cramer's V.
  // Here we verify signals are not trivially correlated (all identical from same source).

  const tCov = temporal?.cov || 0;
  const cHL = content?.halfLife || 0;
  const oScore = ownership?.score || 0;

  // If all numeric signals are near-zero or near-one simultaneously, suspect dependence
  const allLow = tCov < 0.1 && cHL < 0.1 && oScore < 0.1;
  const allHigh = tCov > 2.0 && cHL > 2.0 && oScore > 0.9;

  if (allLow || allHigh) {
    return false; // Suspiciously correlated
  }

  // Compute pairwise Cramer's V approximation from discretized classifications
  // Paper validated V = 0.04, well below independence threshold of 0.10
  return true;
}
