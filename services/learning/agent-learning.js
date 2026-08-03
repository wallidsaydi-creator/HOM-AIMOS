/**
 * agent-learning.js — Learning Metrics and Behavioral Baseline
 * Source: Senge Five Disciplines, L2M Transfer Metrics
 * Wave 3 source: Agent Psychometrics — Task-Level Performance Prediction
 * in Agentic Coding Benchmarks (ICLR Agents in the Wild, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (pre-run and post-run hooks)
 * 2. ← Called by: nightly-dream.js (Step 16: Consolidation metrics)
 * 3. ↔ Interacts with: epistemic-vigilance.js (Source trust modulation)
 * 4. ↔ Interacts with: plasticity-controller.js (Domain-based learning strength)
 * 5. → Pushes to: aimos_events (agent_run_metric logs)
 *
 * LOGIC GUIDE: Tracks Forward/Backward transfer and Performance Maintenance. 
 * Detects behavioral anomalies and updates agent trust scores over time.
 * Agent Psychometrics adaptation: exposes the paper's IRT success model
 * P(y=1 | theta_m, theta_s, beta_j) = sigma(theta_m + theta_s - beta_j)
 * as a runtime diagnostic contract. Learned SVI/ridge calibration remains
 * guarded until Aimos has an explicit calibration set.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run steps 5,7; post-run steps 31,34,35,38)
// ← Called by: nightly-dream.js (steps 1, 2, 16)
// → Calls: services/learning/epistemic-vigilance.js (source trust)
// → Calls: services/learning/plasticity-controller.js (domain plasticity)
// Pipeline: AGENT_RUN_PIPELINE, DREAM_PIPELINE
// Position: behavioral baseline, risk, learning metrics
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getSourceTrust, getDepositMode, recordDeposit } from './epistemic-vigilance.js';
import { getDomainPlasticity, modulateLearningStrength } from './plasticity-controller.js';
import { persistMemory } from '../write/persist-memory.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

const AGENT_PSYCHOMETRICS_SOURCE = 'Agent Psychometrics: Task-Level Performance Prediction in Agentic Coding Benchmarks';

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

function stableSigmoid(x) {
  const value = Number(x);
  if (!Number.isFinite(value)) return 0.5;
  if (value >= 0) return 1 / (1 + Math.exp(-value));
  const exp = Math.exp(value);
  return exp / (1 + exp);
}

function logit(rate) {
  const p = Math.min(0.999, Math.max(0.001, Number(rate)));
  return Math.log(p / (1 - p));
}

export function computeIrtSuccessProbability({
  llmAbility = 0,
  scaffoldAbility = 0,
  taskDifficulty = 0,
} = {}) {
  const thetaM = Number(llmAbility) || 0;
  const thetaS = Number(scaffoldAbility) || 0;
  const betaJ = Number(taskDifficulty) || 0;
  const logitValue = thetaM + thetaS - betaJ;

  return {
    source_paper: AGENT_PSYCHOMETRICS_SOURCE,
    formula: 'P(y=1 | theta_m, theta_s, beta_j) = sigma(theta_m + theta_s - beta_j)',
    llm_ability: Number(thetaM.toFixed(6)),
    scaffold_ability: Number(thetaS.toFixed(6)),
    task_difficulty: Number(betaJ.toFixed(6)),
    logit: Number(logitValue.toFixed(6)),
    probability: Number(stableSigmoid(logitValue).toFixed(6)),
  };
}

export function estimatePsychometricTaskDifficulty({ prompt = '', taskType = 'chat', toolsUsed = 0 } = {}) {
  const text = String(prompt || '');
  const lengthPressure = Math.min(1, text.length / 4000);
  const questionPressure = Math.min(1, (text.match(/\?/g) || []).length / 6);
  const toolPressure = Math.min(1, Number(toolsUsed || 0) / 8);
  const typePressure = ['research', 'investigation', 'analysis', 'code', 'coding', 'architecture'].includes(String(taskType || '').toLowerCase())
    ? 0.35
    : 0.1;
  const difficulty01 = clamp01((lengthPressure * 0.35) + (questionPressure * 0.2) + (toolPressure * 0.2) + typePressure);

  return {
    source_paper: AGENT_PSYCHOMETRICS_SOURCE,
    difficulty_proxy_0_1: Number(difficulty01.toFixed(3)),
    beta_proxy: Number((((difficulty01 - 0.5) * 4)).toFixed(6)),
    features: {
      length_pressure: Number(lengthPressure.toFixed(3)),
      question_pressure: Number(questionPressure.toFixed(3)),
      tool_pressure: Number(toolPressure.toFixed(3)),
      task_type_pressure: Number(typePressure.toFixed(3)),
    },
    guarded_math: {
      ridge_task_feature_predictor_trained: false,
      llm_as_judge_feature_extraction: false,
    }
  };
}

export function buildPsychometricContract({
  agentId = 'unknown',
  model = 'unknown',
  scaffold = 'unknown',
  taskType = 'chat',
  prompt = '',
  toolsUsed = 0,
  behavioralCheck = {},
  healthScore = null,
} = {}) {
  const baselineRuns = Number(behavioralCheck.baselineRuns || 0);
  const anomalyScore = clamp01(behavioralCheck.anomalyScore, 0);
  const observedSuccessRate = healthScore?.runsLast24h > 0
    ? clamp01(healthScore.successRate, 0.5)
    : 0.5;
  const observedConfidence = healthScore?.runsLast24h > 0
    ? clamp01(healthScore.avgConfidence, 0.5)
    : 0.5;
  const llmAbilityProxy = logit((observedSuccessRate * 0.65) + (observedConfidence * 0.35));
  const scaffoldAbilityProxy = logit(Math.min(0.95, Math.max(0.05, 0.5 + Math.min(0.2, Number(toolsUsed || 0) * 0.025))));
  const taskDifficulty = estimatePsychometricTaskDifficulty({ prompt, taskType, toolsUsed });
  const prediction = computeIrtSuccessProbability({
    llmAbility: llmAbilityProxy,
    scaffoldAbility: scaffoldAbilityProxy,
    taskDifficulty: taskDifficulty.beta_proxy,
  });

  return {
    source_paper: AGENT_PSYCHOMETRICS_SOURCE,
    status: 'wired',
    agent_id: agentId,
    model,
    scaffold,
    task_type: taskType,
    psychometric_model: {
      ability_decomposition: 'theta_agent = theta_llm + theta_scaffold',
      success_formula: prediction.formula,
      prediction,
      proxy_notice: 'Runtime values are observed proxies until Aimos has a trained IRT calibration set.',
    },
    task_difficulty: taskDifficulty,
    behavioral_profile: {
      baseline_runs: baselineRuns,
      anomaly_score: anomalyScore,
      drift_triggered: baselineRuns >= 5 && anomalyScore > 0.6,
      traits: {
        consistency: Number((1 - anomalyScore).toFixed(3)),
        tool_reliance: Number(Math.min(1, Number(toolsUsed || 0) / 8).toFixed(3)),
        security_sensitivity: behavioralCheck.features?.mentions_credentials || behavioralCheck.features?.mentions_clearance ? 'elevated' : 'normal',
        override_pressure: behavioralCheck.features?.mentions_override ? 'present' : 'absent',
      }
    },
    guarded_math: {
      svi_hierarchical_irt_training: false,
      ridge_difficulty_regression: false,
      auc_roc_evaluation: false,
      calibrated_benchmark_response_matrix: false,
    }
  };
}

export async function getAgentPsychometricStatus(agentId, options = {}) {
  const baselineKey = `behavioral_baseline:${agentId}`;
  let baseline = null;
  try {
    const existing = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2 AND memory_type = 'infrastructure'
       ORDER BY created_at DESC
       LIMIT 1`,
      [COMPANY, baselineKey]
    );
    if (existing.rows.length > 0) {
      baseline = typeof existing.rows[0].value === 'string'
        ? JSON.parse(existing.rows[0].value)
        : existing.rows[0].value;
    }
  } catch {
    baseline = null;
  }

  const health = await getAgentHealthScore(agentId).catch(() => null);
  return buildPsychometricContract({
    agentId,
    model: options.model || 'unknown',
    scaffold: options.scaffold || 'unknown',
    taskType: options.taskType || 'status',
    prompt: options.prompt || '',
    toolsUsed: options.toolsUsed || 0,
    healthScore: health,
    behavioralCheck: {
      anomalyScore: 0,
      baselineRuns: baseline?.total_runs || 0,
      features: {}
    }
  });
}

export async function recordAgentRun(agentId, runData) {
  try {
    await logEvent(
      'hom',
      agentId,
      'agent_run_metric',
      `run_metric:${agentId}:${Date.now()}`,
      runData
    );
  } catch {
    // fire-and-forget
  }
}

// ─── BEHAVIORAL BASELINE: Track normal patterns per agent for anomaly detection ──
// This is Layer 2 of SE defense. Instead of regex, we know what "normal" looks like
// for each agent and flag deviations. Mitnick principle: catch anomalies, not keywords.
export async function updateBehavioralBaseline(agentId, promptData) {
  try {
    const prompt = String(promptData.prompt || '');
    const taskType = promptData.taskType || 'chat';
    const toolsUsed = promptData.toolsUsed || 0;

    // Extract behavioral features from the prompt
    const features = {
      prompt_length: prompt.length,
      task_type: taskType,
      tools_requested: toolsUsed,
      question_count: (prompt.match(/\?/g) || []).length,
      mentions_credentials: /\b(api.?key|secret|token|password|credential|private.?key)\b/i.test(prompt),
      mentions_clearance: /\bclearance|permission|access.?level\b/i.test(prompt),
      mentions_override: /\boverride|bypass|disable|skip|ignore\b/i.test(prompt),
      timestamp: new Date().toISOString()
    };

    // Load existing baseline
    const baselineKey = `behavioral_baseline:${agentId}`;
    const existing = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2 AND memory_type = 'infrastructure'
       ORDER BY created_at DESC
       LIMIT 1`,
      [COMPANY, baselineKey]
    );

    let baseline = {
      total_runs: 0,
      avg_prompt_length: 0,
      task_type_distribution: {},
      credential_mention_rate: 0,
      clearance_mention_rate: 0,
      override_mention_rate: 0,
      avg_question_count: 0,
      last_updated: null
    };

    if (existing.rows.length > 0) {
      try { baseline = JSON.parse(existing.rows[0].value); } catch { /* fresh baseline */ }
    }

    // Update running averages
    const n = baseline.total_runs;
    const newN = n + 1;
    baseline.avg_prompt_length = (baseline.avg_prompt_length * n + features.prompt_length) / newN;
    baseline.avg_question_count = (baseline.avg_question_count * n + features.question_count) / newN;
    baseline.credential_mention_rate = (baseline.credential_mention_rate * n + (features.mentions_credentials ? 1 : 0)) / newN;
    baseline.clearance_mention_rate = (baseline.clearance_mention_rate * n + (features.mentions_clearance ? 1 : 0)) / newN;
    baseline.override_mention_rate = (baseline.override_mention_rate * n + (features.mentions_override ? 1 : 0)) / newN;
    baseline.task_type_distribution[taskType] = (baseline.task_type_distribution[taskType] || 0) + 1;
    baseline.total_runs = newN;
    baseline.last_updated = features.timestamp;

    // Compute anomaly score for THIS prompt against baseline
    let anomalyScore = 0;
    if (n >= 5) { // need at least 5 runs to establish baseline
      // Credential mention anomaly: agent that never mentions creds suddenly does
      if (features.mentions_credentials && baseline.credential_mention_rate < 0.1) anomalyScore += 0.4;
      // Override mention anomaly
      if (features.mentions_override && baseline.override_mention_rate < 0.05) anomalyScore += 0.3;
      // Clearance mention anomaly
      if (features.mentions_clearance && baseline.clearance_mention_rate < 0.05) anomalyScore += 0.2;
      // Unusual task type for this agent
      const taskPct = (baseline.task_type_distribution[taskType] || 0) / n;
      if (taskPct < 0.05 && n > 10) anomalyScore += 0.1;
    }

    // Save updated baseline
    const baselineValue = JSON.stringify(baseline);
    await persistMemory({
      company_id: COMPANY,
      agent_id: agentId,
      mutation_authority: 'housekeeper',
      key: baselineKey,
      value: baselineValue,
      scope: 'system',
      memory_type: 'infrastructure',
      clearance_level: 8,
      source: 'agent-learning',
    });

    return { anomalyScore, features, baselineRuns: newN };
  } catch {
    return { anomalyScore: 0, features: {}, baselineRuns: 0 };
  }
}

export async function getAgentHealthScore(agentId) {
  const res = await query(
    `SELECT metadata FROM aimos_events
     WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
       AND ts >= NOW() - INTERVAL '24 hours'`,
    [COMPANY, agentId]
  );

  const rows = res.rows;
  const total = rows.length;

  if (total === 0) {
    return {
      agentId,
      healthScore: 50,
      successRate: 0,
      avgConfidence: 0,
      errorRate: 0,
      avgLatencyMs: 0,
      runsLast24h: 0
    };
  }

  let successCount = 0;
  let errorCount = 0;
  let confidenceSum = 0;
  let latencySum = 0;

  for (const row of rows) {
    const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
    if (m.success === true) successCount++;
    if ((m.errorCount || 0) > 0) errorCount++;
    confidenceSum += m.confidence || 0;
    latencySum += m.latencyMs || 0;
  }

  const successRate = successCount / total;
  const errorRate = errorCount / total;
  const avgConfidence = confidenceSum / total;
  const avgLatencyMs = latencySum / total;
  const healthScore = Math.round(
    (successRate * 40) +
    (avgConfidence * 30) +
    ((1 - errorRate) * 20) +
    (Math.max(0, 1 - avgLatencyMs / 30000) * 10)
  );

  return { agentId, healthScore, successRate, avgConfidence, errorRate, avgLatencyMs, runsLast24h: total };
}

export async function getAgentRiskBudget(agentId) {
  const defaults = {
    maxErrorsPerRun: 5,
    maxTokensPerRun: 50000,
    maxLatencyMs: 60000
  };

  try {
    const res = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2 AND memory_type = 'config'
       LIMIT 1`,
      [COMPANY, `risk_budget:${agentId}`]
    );
    if (res.rows.length > 0) {
      const custom = JSON.parse(res.rows[0].value);
      return { ...defaults, ...custom };
    }
  } catch {
    // fall through to defaults
  }

  return defaults;
}

export async function checkRiskBudget(agentId, currentRun) {
  const budget = await getAgentRiskBudget(agentId);
  const { errorCount = 0, tokenEstimate = 0, latencyMs = 0 } = currentRun;

  if (errorCount > budget.maxErrorsPerRun) {
    return { exceeded: true, reason: `errorCount ${errorCount} exceeds maxErrorsPerRun ${budget.maxErrorsPerRun}`, budget };
  }
  if (tokenEstimate > budget.maxTokensPerRun) {
    return { exceeded: true, reason: `tokenEstimate ${tokenEstimate} exceeds maxTokensPerRun ${budget.maxTokensPerRun}`, budget };
  }
  if (latencyMs > budget.maxLatencyMs) {
    return { exceeded: true, reason: `latencyMs ${latencyMs} exceeds maxLatencyMs ${budget.maxLatencyMs}`, budget };
  }

  return { exceeded: false, reason: null, budget };
}

export async function getAgentLearningMetrics(agentId) {
  const skillsRes = await query(
    `SELECT COUNT(*) AS total_skills,
            SUM(success_count) AS total_successes,
            SUM(fail_count) AS total_fails
     FROM procedural_skills
     WHERE company_id = $1 AND agent_id = $2`,
    [COMPANY, agentId]
  );

  const row = skillsRes.rows[0];
  const totalSkills = parseInt(row.total_skills, 10) || 0;
  const totalSuccesses = parseInt(row.total_successes, 10) || 0;
  const totalFails = parseInt(row.total_fails, 10) || 0;

  const transferRes = await query(
    `SELECT COUNT(*) AS transfer_count FROM aimos_events
     WHERE company_id = $1 AND operation = 'agent_run_metric'
       AND agent_id != $2
       AND metadata::text LIKE '%toolsUsed%'`,
    [COMPANY, agentId]
  );

  const skillTransferCount = parseInt(transferRes.rows[0].transfer_count, 10) || 0;
  const learningRate = (totalSuccesses + totalFails) > 0
    ? totalSuccesses / (totalSuccesses + totalFails)
    : 0;

  return { totalSkills, totalSuccesses, totalFails, skillTransferCount, learningRate };
}

export async function getAllAgentHealthScores() {
  const res = await query(
    `SELECT DISTINCT agent_id FROM aimos_events
     WHERE company_id = $1 AND operation = 'agent_run_metric'
       AND ts >= NOW() - INTERVAL '24 hours'`,
    [COMPANY]
  );

  const scores = await Promise.all(
    res.rows.map(r => getAgentHealthScore(r.agent_id))
  );

  return scores.sort((a, b) => b.healthScore - a.healthScore);
}

// ─── Fifth Discipline: Personal Mastery — Capability Gap Tracker ──────────
// Each agent maintains a running profile of task types it performs poorly on.
// This gap drives self-directed learning, not just error correction.
// "Creative tension" = gap between current performance and optimal performance.
export async function getAgentCapabilityGap(agentId) {
  const res = await query(
    `SELECT metadata FROM aimos_events
     WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
       AND ts >= NOW() - INTERVAL '7 days'`,
    [COMPANY, agentId]
  );

  const taskPerformance = {};
  for (const row of res.rows) {
    const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
    const taskType = m.taskType || 'unknown';
    if (!taskPerformance[taskType]) {
      taskPerformance[taskType] = { total: 0, success: 0, totalLatency: 0, totalConfidence: 0 };
    }
    taskPerformance[taskType].total++;
    if (m.success) taskPerformance[taskType].success++;
    taskPerformance[taskType].totalLatency += m.latencyMs || 0;
    taskPerformance[taskType].totalConfidence += m.confidence || 0;
  }

  const gaps = Object.entries(taskPerformance).map(([taskType, stats]) => {
    const successRate = stats.total > 0 ? stats.success / stats.total : 0;
    const avgLatency = stats.total > 0 ? stats.totalLatency / stats.total : 0;
    const avgConfidence = stats.total > 0 ? stats.totalConfidence / stats.total : 0;
    return {
      taskType,
      runs: stats.total,
      successRate,
      avgLatency,
      avgConfidence,
      gapScore: Math.round((1 - successRate) * 50 + (1 - avgConfidence) * 30 + Math.min(avgLatency / 60000, 1) * 20)
    };
  });

  // Sort by gapScore descending — highest gap = most needs improvement
  gaps.sort((a, b) => b.gapScore - a.gapScore);

  return {
    agentId,
    weakest: gaps[0] || null,
    strongest: gaps[gaps.length - 1] || null,
    gaps,
    creativeTension: gaps[0] ? `Agent '${agentId}' weakest on '${gaps[0].taskType}' (gap=${gaps[0].gapScore}). Focus learning here.` : 'No data yet.'
  };
}

// ─── SENGE #1: Personal Mastery — Self-Reflection Loop ─────────────────────
// After each run, the executive agent reads its own capability gaps and creates a learning entry
// if performance is degraded. This is "creative tension" in action:
// the gap between current performance and desired performance drives learning.
export async function selfReflect(agentId) {
  try {
    const gap = await getAgentCapabilityGap(agentId);
    if (!gap.weakest || gap.weakest.gapScore < 15) return null; // reflect on any meaningful gap

    const reflection = {
      agent: agentId,
      weakest_task: gap.weakest.taskType,
      gap_score: gap.weakest.gapScore,
      success_rate: gap.weakest.successRate,
      avg_confidence: gap.weakest.avgConfidence,
      creative_tension: gap.creativeTension,
      reflected_at: new Date().toISOString()
    };

    // Save reflection as a learning memory — agents can query this to self-correct
    await persistMemory({
      company_id: COMPANY,
      agent_id: agentId,
      mutation_authority: 'housekeeper',
      key: `reflection:${agentId}:${Date.now()}`,
      value: JSON.stringify(reflection),
      scope: 'agent',
      memory_type: 'self_reflection',
      clearance_level: 3,
      source: 'agent-learning',
    });

    return reflection;
  } catch {
    return null;
  }
}

// ─── SENGE #3: Team Learning — Cross-Agent Shared Failures ─────────────────
// When an agent fails at a taskType, other agents can learn from that failure.
// Returns recent failures from OTHER agents on the same taskType.
export async function getSharedFailures(taskType, excludeAgentId, limit = 5) {
  try {
    const res = await query(
      `SELECT agent_id, metadata FROM aimos_events
       WHERE company_id = $1 AND operation = 'agent_run_metric'
         AND agent_id != $2
         AND ts >= NOW() - INTERVAL '7 days'
       ORDER BY ts DESC LIMIT 100`,
      [COMPANY, excludeAgentId]
    );

    const failures = [];
    for (const row of res.rows) {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      if (m.success === false && m.taskType === taskType && m.error) {
        failures.push({
          agent_id: row.agent_id,
          error: String(m.error).slice(0, 200),
          taskType: m.taskType,
          confidence: m.confidence || 0
        });
        if (failures.length >= limit) break;
      }
    }
    return failures;
  } catch {
    return [];
  }
}

// ─── OUTCOME TRACKING: Wire recommendation_log into pipeline ───────────────
// Every significant agent response is logged as a recommendation.
// A nightly or periodic scorer can later fill in actual_outcome and outcome_score.
export async function recordRecommendation(agentId, recommendation, confidence, taskType, context = {}) {
  try {
    const windowHours = taskType === 'trading' ? 4 : (taskType === 'analysis' ? 48 : 24);
    await query(
      `INSERT INTO recommendation_log (company_id, agent_id, recommendation, confidence_at_time, outcome_window_hours, outcome_due_at, context, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(hours => $6), $7, NOW())`,
      [COMPANY, agentId, String(recommendation).slice(0, 2000), confidence, windowHours, windowHours, JSON.stringify({
        task_type: taskType,
        ...context
      })]
    );
  } catch {
    // best-effort
  }
}

// ─── CALIBRATION FACTOR: compute confidence calibration for an agent+taskType ──
// Exported so ensemble-engine and other callers can apply calibration.
// Mirrors the logic in agent-runner.js but is importable from this module.
export async function getCalibrationFactor(agentId, taskType) {
  try {
    const res = await query(
      `SELECT confidence_at_time, outcome_score FROM recommendation_log
       WHERE company_id = $1 AND agent_id = $2 AND actual_outcome IS NOT NULL
         AND outcome_score IS NOT NULL
         AND context->>'task_type' = $3
       ORDER BY scored_at DESC LIMIT 20`,
      [COMPANY, agentId, taskType]
    );

    if (res.rows.length < 3) return 1.0;

    let totalBias = 0;
    for (const row of res.rows) {
      const predicted = parseFloat(row.confidence_at_time) || 0.5;
      const actual = parseFloat(row.outcome_score) || 0.5;
      totalBias += (predicted - actual);
    }

    const avgBias = totalBias / res.rows.length;

    if (avgBias > 0) {
      return Math.max(0.7, 1.0 - avgBias);
    } else {
      return Math.min(1.1, 1.0 - avgBias * 0.5);
    }
  } catch {
    return 1.0;
  }
}

// ─── OUTCOME SCORER: grade past recommendations based on subsequent performance ──
// Finds recommendations past their outcome window that haven't been scored yet.
// Scores them by checking if the agent's subsequent runs on the same taskType improved.
export async function scoreDueRecommendations() {
  try {
    const due = await query(
      `SELECT id, agent_id, confidence_at_time, context, created_at
       FROM recommendation_log
       WHERE company_id = $1 AND outcome_due_at <= NOW() AND actual_outcome IS NULL
       ORDER BY created_at ASC LIMIT 20`,
      [COMPANY]
    );

    const scored = [];
    for (const rec of due.rows) {
      const ctx = typeof rec.context === 'string' ? JSON.parse(rec.context) : (rec.context || {});
      const taskType = ctx.task_type || 'unknown';

      // Check agent's performance on this taskType AFTER the recommendation was made
      const perf = await query(
        `SELECT metadata FROM aimos_events
         WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
           AND ts > $3
         ORDER BY ts ASC LIMIT 10`,
        [COMPANY, rec.agent_id, rec.created_at]
      );

      let successCount = 0;
      let totalCount = 0;
      let avgConf = 0;
      for (const row of perf.rows) {
        const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
        if (m.taskType === taskType || taskType === 'unknown') {
          totalCount++;
          if (m.success) successCount++;
          avgConf += m.confidence || 0;
        }
      }

      let outcomeScore;
      let actualOutcome;
      if (totalCount === 0) {
        outcomeScore = 0.5; // no follow-up data = neutral
        actualOutcome = 'no_followup_data';
      } else {
        avgConf = avgConf / totalCount;
        const successRate = successCount / totalCount;
        outcomeScore = Math.round((successRate * 0.6 + avgConf * 0.4) * 100) / 100;
        actualOutcome = successRate >= 0.7 ? 'positive' : successRate >= 0.4 ? 'neutral' : 'negative';
      }

      await query(
        `UPDATE recommendation_log SET actual_outcome = $1, outcome_score = $2, scored_at = NOW()
         WHERE id = $3`,
        [actualOutcome, outcomeScore, rec.id]
      );

      scored.push({ id: rec.id, agent: rec.agent_id, taskType, outcomeScore, actualOutcome });
    }

    return { scored: scored.length, results: scored };
  } catch (err) {
    return { scored: 0, error: err.message };
  }
}

// ─── AFTER-ACTION REVIEW: evaluate the specific run that just completed ─────
// Unlike selfReflect (aggregate gaps), this evaluates the actual output quality.
// Checks: response relevance to prompt, confidence calibration, length adequacy,
// and whether the task type matches the output characteristics.
export async function afterActionReview(agentId, { prompt, response, taskType, confidence, model, latencyMs }) {
  try {
    if (!response || response.length < 50) return null; // trivial responses skip review

    const issues = [];
    const strengths = [];

    // 1. Response length vs task type expectations
    const respLen = response.length;
    if (taskType === 'research' && respLen < 500) issues.push('Short response for research task — expected detailed analysis');
    if (taskType === 'chat' && respLen > 5000) issues.push('Overly verbose for chat — brevity expected');
    if (taskType === 'analysis' && respLen < 300) issues.push('Thin analysis — expected structured breakdown');

    // 2. Confidence calibration check
    if (confidence > 0.9 && respLen < 200) issues.push('High confidence but short output — overconfident?');
    if (confidence < 0.3 && !response.includes('uncertain') && !response.includes('unclear'))
      issues.push('Low confidence but no hedging language — miscalibrated');
    if (confidence >= 0.7) strengths.push(`High confidence (${confidence.toFixed(2)})`);

    // 3. Prompt relevance — check if key prompt terms appear in response
    const promptTerms = String(prompt).toLowerCase().split(/\s+/).filter(t => t.length > 4);
    const respLower = response.toLowerCase();
    const termOverlap = promptTerms.length > 0
      ? promptTerms.filter(t => respLower.includes(t)).length / promptTerms.length
      : 1;
    if (termOverlap < 0.2 && promptTerms.length >= 3) issues.push(`Low prompt-response relevance (${(termOverlap * 100).toFixed(0)}% term overlap)`);
    if (termOverlap > 0.6) strengths.push('Good prompt-response alignment');

    // 4. Latency check
    if (latencyMs > 30000) issues.push(`Slow execution (${(latencyMs / 1000).toFixed(1)}s)`);
    if (latencyMs < 5000 && respLen > 1000) strengths.push('Fast + detailed response');

    const verdict = issues.length === 0 ? 'pass' : issues.length <= 2 ? 'acceptable' : 'needs_improvement';

    const review = {
      agent: agentId,
      task_type: taskType,
      verdict,
      confidence,
      response_length: respLen,
      prompt_relevance: +(termOverlap * 100).toFixed(0),
      issues,
      strengths,
      model,
      latency_ms: latencyMs,
      reviewed_at: new Date().toISOString()
    };

    // Save review — agents can read their past reviews to self-improve
    await persistMemory({
      company_id: COMPANY,
      agent_id: agentId,
      mutation_authority: 'housekeeper',
      key: `aar:${agentId}:${Date.now()}`,
      value: JSON.stringify(review),
      scope: 'agent',
      memory_type: 'after_action_review',
      clearance_level: 3,
      source: 'agent-learning',
    });

    // If needs_improvement, also save as a learning signal
    if (verdict === 'needs_improvement') {
      await logEvent(
        'hom',
        agentId,
        'after_action_review',
        `aar_flag:${agentId}:${Date.now()}`,
        { verdict, issues, task_type: taskType, confidence }
      );
    }

    return review;
  } catch {
    return null;
  }
}

// ─── SENGE #4: Systems Thinking — Cross-Agent Pattern Detection ────────────
// Identifies reinforcing/balancing loops, recurring failures, and bottlenecks.
// Called periodically (nightly dream or on-demand).
export async function identifySystemPatterns() {
  try {
    const res = await query(
      `SELECT agent_id, metadata FROM aimos_events
       WHERE company_id = $1 AND operation = 'agent_run_metric'
         AND ts >= NOW() - INTERVAL '24 hours'
       ORDER BY ts DESC`,
      [COMPANY]
    );

    const agentStats = {};
    const taskStats = {};
    for (const row of res.rows) {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      const aid = row.agent_id;
      const tt = m.taskType || 'unknown';

      if (!agentStats[aid]) agentStats[aid] = { total: 0, fails: 0, totalLatency: 0 };
      agentStats[aid].total++;
      if (!m.success) agentStats[aid].fails++;
      agentStats[aid].totalLatency += m.latencyMs || 0;

      if (!taskStats[tt]) taskStats[tt] = { total: 0, fails: 0, agents: new Set() };
      taskStats[tt].total++;
      if (!m.success) taskStats[tt].fails++;
      taskStats[tt].agents.add(aid);
    }

    const patterns = [];

    // Detect bottleneck agents (>40% failure rate)
    for (const [aid, s] of Object.entries(agentStats)) {
      if (s.total >= 3 && s.fails / s.total > 0.4) {
        patterns.push({ type: 'bottleneck_agent', agent: aid, failRate: (s.fails / s.total).toFixed(2), runs: s.total });
      }
    }

    // Detect systemic task failures (same taskType failing across multiple agents)
    for (const [tt, s] of Object.entries(taskStats)) {
      if (s.total >= 3 && s.fails / s.total > 0.3 && s.agents.size > 1) {
        patterns.push({ type: 'systemic_task_failure', taskType: tt, failRate: (s.fails / s.total).toFixed(2), affectedAgents: [...s.agents] });
      }
    }

    return { patterns, agentCount: Object.keys(agentStats).length, totalRuns: res.rows.length };
  } catch {
    return { patterns: [], agentCount: 0, totalRuns: 0 };
  }
}

// ─── Voyager: Skill Library — count reusable procedural skills per agent ───
export async function getAgentSkillLibrary(agentId) {
  const res = await query(
    `SELECT skill_name, success_count, fail_count, created_at
     FROM procedural_skills
     WHERE company_id = $1 AND agent_id = $2
     ORDER BY success_count DESC
     LIMIT 20`,
    [COMPANY, agentId]
  );

  return {
    agentId,
    skillCount: res.rows.length,
    skills: res.rows.map(r => ({
      name: r.skill_name,
      successCount: parseInt(r.success_count, 10) || 0,
      failCount: parseInt(r.fail_count, 10) || 0,
      reliability: (parseInt(r.success_count, 10) || 0) / Math.max(1, (parseInt(r.success_count, 10) || 0) + (parseInt(r.fail_count, 10) || 0))
    }))
  };
}

// ─── Feature 4: Agent Modeling Layer (BDI State Reader) ──────────────────────
// Reads the agent's current BDI state from agent_state table.
// Used before delegation to check if target agent is available.
export async function getAgentModel(agentId) {
  try {
    const res = await query(
      `SELECT phase, current_task, beliefs, desires, intentions, waiting_for, blockers, confidence, updated_at
       FROM agent_state
       WHERE company_id = $1 AND agent_id = $2`,
      [COMPANY, agentId]
    );
    if (!res.rows.length) {
      return { agentId, phase: 'unknown', available: true, blockers: [], confidence: 0.5 };
    }
    const row = res.rows[0];
    const phase = row.phase || 'idle';
    const blockers = Array.isArray(row.blockers) ? row.blockers : [];
    const available = phase === 'idle' && blockers.length === 0;
    return {
      agentId,
      phase,
      currentTask: row.current_task,
      beliefs: typeof row.beliefs === 'string' ? JSON.parse(row.beliefs) : (row.beliefs || {}),
      desires: typeof row.desires === 'string' ? JSON.parse(row.desires) : (row.desires || {}),
      intentions: typeof row.intentions === 'string' ? JSON.parse(row.intentions) : (row.intentions || {}),
      waitingFor: row.waiting_for,
      blockers,
      confidence: parseFloat(row.confidence) || 0.5,
      available,
      lastUpdated: row.updated_at
    };
  } catch {
    return { agentId, phase: 'unknown', available: true, blockers: [], confidence: 0.5 };
  }
}

// ─── Feature 7: Autonomous Skill Curation (Ameisen Loop) ─────────────────────
// Scans last 24h for successful runs with confidence >= 0.8.
// Groups by agent+taskType, requires 2+ occurrences (pattern, not one-off).
// Creates procedural_skills entry with tag 'curated'.
// Called from nightly dream after scoreDueRecommendations().
export async function curateSkillsFromSuccesses(companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT agent_id, metadata FROM aimos_events
       WHERE company_id = $1 AND operation = 'agent_run_metric'
         AND ts >= NOW() - INTERVAL '24 hours'
       ORDER BY ts DESC`,
      [companyId]
    );

    // Group by agent+taskType, filter success=true AND confidence >= 0.8
    const groups = {};
    for (const row of res.rows) {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      if (!m.success || (m.confidence || 0) < 0.8) continue;
      const taskType = m.taskType || 'unknown';
      const key = `${row.agent_id}:${taskType}`;
      if (!groups[key]) groups[key] = { agentId: row.agent_id, taskType, runs: [], avgConfidence: 0 };
      groups[key].runs.push(m);
    }

    let curated = 0;
    for (const [, group] of Object.entries(groups)) {
      if (group.runs.length < 2) continue; // require pattern, not one-off

      // ─── Wire #26: Epistemic Vigilance — source trust gating on skill deposit ──
      try {
        const sourceTrust = await getSourceTrust(group.agentId, companyId);
        const depositMode = getDepositMode(sourceTrust.trust);
        if (depositMode === 'provisional') {
          console.warn(`[agent-learning] Skipping skill deposit for low-trust source ${group.agentId} (trust=${sourceTrust.trust.toFixed(2)})`);
          continue; // skip deposit from untrusted sources
        }
        await recordDeposit(group.agentId, `curated_${group.agentId}_${group.taskType}`, companyId);
      } catch (err) {
        console.warn('[agent-learning] Epistemic vigilance check failed:', err.message);
      }

      // ─── Wire #27: Plasticity Controller — domain plasticity modulation ────────
      let learningMultiplier = 1.0;
      try {
        const plasticity = await getDomainPlasticity(group.taskType, companyId);
        learningMultiplier = modulateLearningStrength(1.0, plasticity.plasticity);
      } catch (err) {
        console.warn('[agent-learning] Plasticity modulation failed:', err.message);
      }

      const avgConf = group.runs.reduce((s, r) => s + (r.confidence || 0), 0) / group.runs.length;
      const adjustedConfidence = avgConf * learningMultiplier;
      const toolsUsed = [...new Set(group.runs.flatMap(r => {
        if (Array.isArray(r.toolsUsed)) return r.toolsUsed;
        if (typeof r.toolsUsed === 'number') return [];
        return [];
      }))];
      const skillName = `curated_${group.agentId}_${group.taskType}`;
      const skillDesc = `${skillName}: Curated pattern from ${group.runs.length} successful ${group.taskType} runs (avg confidence ${adjustedConfidence.toFixed(2)})`;

      // Embed for vector retrieval
      let skillEmbedding = null;
      try {
        const { getEmbedding } = await import('./embeddings.js');
        skillEmbedding = await getEmbedding(skillDesc);
      } catch { /* embedding optional */ }

      await query(
        `INSERT INTO procedural_skills (company_id, agent_id, skill_name, trigger_pattern, steps, expected_outcome, success_count, fail_count, last_used, tags, skill_embedding)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0, NOW(), $8, $9::vector)
         ON CONFLICT (company_id, skill_name)
         DO UPDATE SET success_count = procedural_skills.success_count + EXCLUDED.success_count,
                       last_used = NOW(), updated_at = NOW(),
                       tags = EXCLUDED.tags,
                       skill_embedding = COALESCE(EXCLUDED.skill_embedding, procedural_skills.skill_embedding)`,
        [
          companyId, group.agentId, skillName,
          group.taskType,
          JSON.stringify(toolsUsed.map(t => `use ${t}`)),
          `Curated from ${group.runs.length} high-confidence ${group.taskType} runs`,
          group.runs.length,
          JSON.stringify(['curated', group.taskType]),
          skillEmbedding ? JSON.stringify(skillEmbedding) : null
        ]
      );
      curated++;
    }

    return { curated, groupsScanned: Object.keys(groups).length };
  } catch (err) {
    return { curated: 0, error: err.message };
  }
}

// ─── L2M Phase 4: Forward Transfer (FT) ────────────────────────────────────
// Measures how learning on previous tasks helps performance on NEW tasks.
// Positive FT = previous experience accelerates learning on unseen task types.
// Negative FT = previous experience actively hinders new tasks (interference).
export async function computeForwardTransfer(agentId, companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT metadata, ts FROM aimos_events
       WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
       ORDER BY ts ASC`,
      [companyId, agentId]
    );

    if (res.rows.length < 2) {
      return { forwardTransfer: 0, taskCount: 0, details: [] };
    }

    // Parse all runs in chronological order
    const runs = res.rows.map(row => {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      return { success: m.success === true, taskType: m.taskType || 'unknown', ts: row.ts };
    });

    // Track which task types have been seen and baseline before each new type
    const seenTaskTypes = new Set();
    let cumulativeSuccess = 0;
    let cumulativeTotal = 0;
    const details = [];

    // Group runs into sequential blocks by task_type appearance order
    for (const run of runs) {
      if (!seenTaskTypes.has(run.taskType)) {
        // New task type encountered — compute baseline from all prior runs
        const baselineBefore = cumulativeTotal > 0 ? cumulativeSuccess / cumulativeTotal : 0;

        // Collect first-attempt runs on this new task type (up to first 5 runs)
        const firstAttempts = runs.filter(r => r.taskType === run.taskType).slice(0, 5);
        const firstAttemptSuccesses = firstAttempts.filter(r => r.success).length;
        const firstAttemptRate = firstAttempts.length > 0 ? firstAttemptSuccesses / firstAttempts.length : 0;

        // Only count if we had prior data to compare against
        if (cumulativeTotal > 0) {
          details.push({
            taskType: run.taskType,
            firstAttemptSuccessRate: +firstAttemptRate.toFixed(4),
            baselineBefore: +baselineBefore.toFixed(4),
            transfer: +(firstAttemptRate - baselineBefore).toFixed(4),
            firstAttemptRuns: firstAttempts.length
          });
        }

        seenTaskTypes.add(run.taskType);
      }

      // Update cumulative stats
      cumulativeTotal++;
      if (run.success) cumulativeSuccess++;
    }

    const forwardTransfer = details.length > 0
      ? details.reduce((sum, d) => sum + d.transfer, 0) / details.length
      : 0;

    return {
      forwardTransfer: +forwardTransfer.toFixed(4),
      taskCount: details.length,
      details
    };
  } catch {
    return { forwardTransfer: 0, taskCount: 0, details: [] };
  }
}

// ─── L2M Phase 4: Backward Transfer (BT) ───────────────────────────────────
// Measures whether learning new tasks degrades performance on OLD tasks.
// Negative BT = catastrophic forgetting — new learning overwrites old competence.
// Positive BT = new learning synergistically improves old task performance.
export async function computeBackwardTransfer(agentId, companyId = COMPANY) {
  try {
    // Fetch last 37 days of runs (30-day historical window + 7-day recent window)
    const res = await query(
      `SELECT metadata, ts FROM aimos_events
       WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
         AND ts >= NOW() - INTERVAL '37 days'
       ORDER BY ts ASC`,
      [companyId, agentId]
    );

    if (res.rows.length === 0) {
      return { backwardTransfer: 0, taskCount: 0, details: [] };
    }

    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const thirtySevenDaysAgo = new Date(now.getTime() - 37 * 24 * 60 * 60 * 1000);

    // Bucket runs by task type into historical (8-37 days ago) and recent (last 7 days)
    const taskBuckets = {};
    for (const row of res.rows) {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      const taskType = m.taskType || 'unknown';
      const ts = new Date(row.ts);

      if (!taskBuckets[taskType]) {
        taskBuckets[taskType] = { historical: { success: 0, total: 0 }, recent: { success: 0, total: 0 } };
      }

      if (ts >= thirtySevenDaysAgo && ts < sevenDaysAgo) {
        // Historical period: 8-37 days ago
        taskBuckets[taskType].historical.total++;
        if (m.success === true) taskBuckets[taskType].historical.success++;
      } else if (ts >= sevenDaysAgo) {
        // Recent period: last 7 days
        taskBuckets[taskType].recent.total++;
        if (m.success === true) taskBuckets[taskType].recent.success++;
      }
    }

    const details = [];
    for (const [taskType, buckets] of Object.entries(taskBuckets)) {
      // Require >= 3 runs in each period for statistical relevance
      if (buckets.historical.total < 3 || buckets.recent.total < 3) continue;

      const historicalRate = buckets.historical.success / buckets.historical.total;
      const recentRate = buckets.recent.success / buckets.recent.total;
      const transfer = recentRate - historicalRate;

      details.push({
        taskType,
        historicalSuccessRate: +historicalRate.toFixed(4),
        recentSuccessRate: +recentRate.toFixed(4),
        transfer: +transfer.toFixed(4),
        historicalRuns: buckets.historical.total,
        recentRuns: buckets.recent.total
      });
    }

    const backwardTransfer = details.length > 0
      ? details.reduce((sum, d) => sum + d.transfer, 0) / details.length
      : 0;

    return {
      backwardTransfer: +backwardTransfer.toFixed(4),
      taskCount: details.length,
      details
    };
  } catch {
    return { backwardTransfer: 0, taskCount: 0, details: [] };
  }
}

// ─── L2M Phase 4: Performance Maintenance (PM) ─────────────────────────────
// Measures long-term stability across three 30-day windows over 90 days.
// PM ~ 1.0 = stable, PM < 0.8 = degrading, PM > 1.2 = improving.
// Capped at [0, 2] to prevent unbounded ratios from sparse data.
export async function computePerformanceMaintenance(agentId, companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT metadata, ts FROM aimos_events
       WHERE company_id = $1 AND agent_id = $2 AND operation = 'agent_run_metric'
         AND ts >= NOW() - INTERVAL '90 days'
       ORDER BY ts ASC`,
      [companyId, agentId]
    );

    if (res.rows.length === 0) {
      return { performanceMaintenance: 1.0, windows: [] };
    }

    const now = new Date();
    const windowBoundaries = [
      { label: 'window1 (60-90 days ago)', start: new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000), end: new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000) },
      { label: 'window2 (30-60 days ago)', start: new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000), end: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000) },
      { label: 'window3 (last 30 days)',   start: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000), end: now }
    ];

    const windows = windowBoundaries.map(wb => ({
      period: wb.label,
      successCount: 0,
      totalCount: 0,
      confidenceSum: 0,
      successRate: 0,
      avgConfidence: 0,
      runCount: 0,
      _start: wb.start,
      _end: wb.end
    }));

    for (const row of res.rows) {
      const m = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      const ts = new Date(row.ts);

      for (const win of windows) {
        if (ts >= win._start && ts < win._end) {
          win.totalCount++;
          if (m.success === true) win.successCount++;
          win.confidenceSum += (typeof m.confidence === 'number' ? m.confidence : 0);
          break;
        }
      }
    }

    // Compute rates and clean up internal fields
    const cleanWindows = windows.map(w => {
      const successRate = w.totalCount > 0 ? w.successCount / w.totalCount : 0;
      const avgConfidence = w.totalCount > 0 ? w.confidenceSum / w.totalCount : 0;
      return {
        period: w.period,
        successRate: +successRate.toFixed(4),
        avgConfidence: +avgConfidence.toFixed(4),
        runCount: w.totalCount
      };
    });

    // PM = window3 success rate / window1 success rate, capped at [0, 2]
    const w1Rate = cleanWindows[0].successRate;
    const w3Rate = cleanWindows[2].successRate;

    let performanceMaintenance;
    if (w1Rate === 0 && w3Rate === 0) {
      performanceMaintenance = 1.0; // no data in either window — assume stable
    } else if (w1Rate === 0) {
      performanceMaintenance = 2.0; // went from no data to some success — cap at max
    } else {
      performanceMaintenance = Math.min(2.0, Math.max(0, w3Rate / w1Rate));
    }

    return {
      performanceMaintenance: +performanceMaintenance.toFixed(4),
      windows: cleanWindows
    };
  } catch {
    return { performanceMaintenance: 1.0, windows: [] };
  }
}
