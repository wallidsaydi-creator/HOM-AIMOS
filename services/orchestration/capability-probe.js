// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into GOVERNANCE capability-gate diagnostics
// Purpose: WMF-AM pre-task probe — measures agent working-memory fidelity (EMS,
//          MCC, EMC, CLA) at K=3/5/7 horizons before complex task assignment
// ← Called by: governance-resolver.js
// → Calls: shared/native-llm.js, observe/event-ledger.js, write/persist-memory.js
// Pipeline: GOVERNANCE | Position: pre-task capability diagnostic gate
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// CAPABILITY PROBE (capability-probe.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-12: WMF-AM Pre-Task Probe
//
// Probes agent working-memory fidelity before assigning complex tasks.
// Uses K-step state-tracking tasks (WMF = Working Memory Fidelity) to measure:
//   - Exact Match Score (EMS) per K-horizon
//   - Multi-Step Consistency (MCC)
//   - Error Magnification Coefficient (EMC)
//   - Cognitive Load Adherence (CLA)
//
// Probe design: "X starts at 10, gains 5, loses 3, gains 7. What is X?"
// Scaled to K=3, K=5, K=7 state transitions to stress-test working memory.
//
// If an agent scores below threshold for a given task horizon, it is excluded
// from assignments at or above that horizon.
//
// Theoretical basis: Baddeley's working memory model, WMF-AM (Cognitive Load
// Theory), K-step Markov chain fidelity.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { callNativeLlm } from '../shared/native-llm.js';
import { logEvent } from '../observe/event-ledger.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// K-values for probing (step counts)
const K_VALUES = [3, 5, 7];

// Default exclusion threshold (EMS score below this triggers exclusion)
const DEFAULT_EXCLUSION_THRESHOLD = 0.6;

// ─── Probe generation ────────────────────────────────────────────────────────

/**
 * Generate a K-step numeric state-tracking probe.
 * Starting value is 10; each step applies a random ±1..±9 delta.
 * Returns the prompt and the correct final value.
 *
 * @param {number} K - Number of state transitions
 * @returns {{prompt: string, correctAnswer: number, steps: Array<{op: string, delta: number}>}}
 */
function generateProbe(K) {
  const steps = [];
  let value = 10;

  for (let i = 0; i < K; i++) {
    const delta = Math.floor(Math.random() * 9) + 1; // 1-9
    const op = Math.random() < 0.5 ? 'gains' : 'loses';
    steps.push({ op, delta });
    value = op === 'gains' ? value + delta : value - delta;
  }

  const stepDescriptions = steps.map((s) => `${s.op} ${s.delta}`).join(', ');
  const prompt = `X starts at 10, ${stepDescriptions}. What is X? Respond with only the number.`;

  return { prompt, correctAnswer: value, steps };
}

/**
 * Parse numeric answer from LLM response text.
 *
 * @param {string} text
 * @returns {number|null}
 */
function parseNumericAnswer(text) {
  const match = String(text || '').trim().match(/-?\d+(\.\d+)?/);
  return match ? parseFloat(match[0]) : null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Run a K-step state-tracking probe against an agent (LLM endpoint).
 * Executes 3 trials per K-value to estimate accuracy.
 *
 * @param {string} agentId - Agent identifier (used for logging)
 * @param {number} K - Number of state transitions in the probe
 * @param {object} [options]
 * @param {number} [options.trials=3]
 * @param {Function} [options.answerFn] - Optional test hook; production uses native LLM
 * @returns {Promise<{K: number, exactMatchScore: number, trials: number, correct: number}>}
 */
export async function runWMFProbe(agentId, K, options = {}) {
  const kVal = Math.max(1, Math.min(20, parseInt(K, 10) || 3));
  const TRIALS = Math.max(1, Math.min(10, parseInt(options.trials, 10) || 3));
  const answerFn = typeof options.answerFn === 'function'
    ? options.answerFn
    : async (prompt) => callNativeLlm({ prompt, provider: options.provider, model: options.model });

  let correct = 0;
  const trialResults = [];

  for (let t = 0; t < TRIALS; t++) {
    const { prompt, correctAnswer } = generateProbe(kVal);
    let agentAnswer = null;

    try {
      const response = await answerFn(prompt, { agentId, K: kVal, trial: t });
      agentAnswer = parseNumericAnswer(response);
    } catch (err) {
      console.warn(`[capability-probe] runWMFProbe trial ${t} error:`, err.message);
    }

    const isCorrect = agentAnswer !== null && agentAnswer === correctAnswer;
    if (isCorrect) correct++;

    trialResults.push({ trial: t, correctAnswer, agentAnswer, isCorrect });
  }

  const exactMatchScore = correct / TRIALS;

  await logEvent(COMPANY, agentId, 'wmf_probe_run', `wmf_probe:${agentId}:K${kVal}:${Date.now()}`, {
    reasoning: `WMF-AM probe completed for K=${kVal}; exact match score=${exactMatchScore.toFixed(3)} across ${TRIALS} trial(s).`,
    source_knowledge: 'capability-probe.js WMF-AM — K-step state tracking, EMS, MCC, EMC, CLA',
    agentId,
    K: kVal,
    exactMatchScore,
    correct,
    trials: TRIALS,
    trialResults,
  }).catch(() => {});

  return { K: kVal, exactMatchScore, trials: TRIALS, correct };
}

/**
 * Get the capability profile for an agent, including WMF scores at K=3,5,7
 * and derived metrics: MCC, EMC, CLA.
 *
 * Runs probes for K=3, K=5, K=7 in parallel.
 *
 * @param {string} agentId
 * @param {object} [options] - Forwarded to runWMFProbe
 * @returns {Promise<{agentId: string, wmf_scores: {K3: number, K5: number, K7: number}, mcc: number, emc: number, cla: number}>}
 */
export async function getAgentCapabilityProfile(agentId, options = {}) {
  const probeResults = await Promise.all(
    K_VALUES.map((k) => runWMFProbe(agentId, k, options))
  );

  const wmf_scores = {
    K3: probeResults.find((r) => r.K === 3)?.exactMatchScore ?? 0,
    K5: probeResults.find((r) => r.K === 5)?.exactMatchScore ?? 0,
    K7: probeResults.find((r) => r.K === 7)?.exactMatchScore ?? 0,
  };

  // Multi-Step Consistency: how much score degrades across K
  // MCC = 1 - (std_dev of WMF scores across K values)
  const scores = [wmf_scores.K3, wmf_scores.K5, wmf_scores.K7];
  const mean = scores.reduce((s, v) => s + v, 0) / scores.length;
  const variance = scores.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / scores.length;
  const mcc = Math.max(0, 1 - Math.sqrt(variance));

  // Error Magnification Coefficient: rate of score drop per K step
  // EMC = (K3 - K7) / (7 - 3) ; positive = errors grow with K
  const emc = Math.max(0, (wmf_scores.K3 - wmf_scores.K7) / 4);

  // Cognitive Load Adherence: average WMF across all K
  const cla = mean;

  // Persist profile in aimos_memories
  try {
    await persistMemory({
      company_id: COMPANY,
      agent_id: 'capability-probe',
      key: `capability_profile:${agentId}`,
      value: JSON.stringify({ agentId, wmf_scores, mcc, emc, cla, probedAt: new Date().toISOString() }),
      scope: 'system',
      memory_type: 'agent_capability',
      memory_tier: 'long-term',
      clearance_level: 5,
      mutation_authority: 'housekeeper',
    });
  } catch (err) {
    console.warn('[capability-probe] getAgentCapabilityProfile persist error:', err.message);
  }

  return { agentId, wmf_scores, mcc, emc, cla };
}

/**
 * Estimate the equivalent K-step horizon for a given task prompt.
 * Uses heuristic: count distinct entities + state-modifying verbs.
 *
 * @param {string} taskPrompt
 * @returns {number} Estimated K value (1-7)
 */
export function estimateStateUpdateDepth(taskPrompt) {
  if (!taskPrompt || typeof taskPrompt !== 'string') return 3;

  const text = taskPrompt.toLowerCase();

  // Count state-modifying verbs as a proxy for state transitions
  const stateVerbs = [
    'update', 'change', 'set', 'increment', 'decrement', 'add', 'remove',
    'modify', 'replace', 'delete', 'create', 'adjust', 'assign', 'move',
    'transfer', 'convert', 'merge', 'split', 'increase', 'decrease',
  ];
  const verbCount = stateVerbs.reduce(
    (count, verb) => count + (text.split(verb).length - 1),
    0
  );

  // Count distinct entities (capitalised words heuristic)
  const entityCount = (taskPrompt.match(/\b[A-Z][a-z]+\b/g) || []).length;

  // Combine: weighted sum, clamped to [1, 7]
  const raw = Math.round(verbCount * 0.6 + entityCount * 0.2 + 1);
  return Math.max(1, Math.min(7, raw));
}

function scoreForHorizon(profile, taskHorizon) {
  if (!profile?.wmf_scores) return null;
  const k = Math.max(1, Math.min(7, parseInt(taskHorizon, 10) || 3));
  if (k <= 3) return Number(profile.wmf_scores.K3);
  if (k <= 5) return Number(profile.wmf_scores.K5);
  return Number(profile.wmf_scores.K7);
}

export function buildCapabilityGateDecision({
  agentId = 'unknown',
  taskPrompt = '',
  taskHorizon = null,
  profile = null,
  threshold = DEFAULT_EXCLUSION_THRESHOLD,
} = {}) {
  const horizon = taskHorizon == null ? estimateStateUpdateDepth(taskPrompt) : Math.max(1, Math.min(7, parseInt(taskHorizon, 10) || 3));
  const th = Number(threshold) || DEFAULT_EXCLUSION_THRESHOLD;
  const relevantScore = scoreForHorizon(profile, horizon);
  const profileAvailable = Number.isFinite(relevantScore);
  const excluded = profileAvailable ? relevantScore < th : false;

  return {
    agentId,
    task_horizon: horizon,
    threshold: th,
    relevant_score: profileAvailable ? relevantScore : null,
    profile_available: profileAvailable,
    excluded,
    decision: profileAvailable ? (excluded ? 'exclude' : 'allow') : 'profile_unavailable',
  };
}

export async function observeCapabilityGate({
  companyId = COMPANY,
  agentId = 'unknown',
  taskPrompt = '',
  taskHorizon = null,
  profile = null,
  threshold = DEFAULT_EXCLUSION_THRESHOLD,
  runId = null,
  source = 'governance-resolver',
} = {}) {
  const decision = buildCapabilityGateDecision({ agentId, taskPrompt, taskHorizon, profile, threshold });
  const eventId = await logEvent(companyId, agentId, 'capability_gate_observed', `capability_gate:${agentId}:${Date.now()}`, {
    reasoning: `Capability gate observed task horizon K=${decision.task_horizon}; decision=${decision.decision}; profile_available=${decision.profile_available}.`,
    source_knowledge: 'capability-probe.js WMF-AM — pre-task working-memory fidelity gate',
    decision,
    run_id: runId,
    source,
    diagnostic_only: true,
  });

  return { decision, eventId };
}

/**
 * Decide whether an agent should be excluded from a task given its capability profile.
 *
 * @param {string} agentId
 * @param {number} taskHorizon - Required K-horizon for the task
 * @param {number} [threshold=0.6] - Minimum WMF score required
 * @param {object} [options] - Forwarded to getAgentCapabilityProfile
 * @returns {Promise<boolean>} True if agent should be excluded
 */
export async function shouldExcludeAgent(agentId, taskHorizon, threshold = DEFAULT_EXCLUSION_THRESHOLD, options = {}) {
  const profile = await getAgentCapabilityProfile(agentId, options);
  const th = Number(threshold) || DEFAULT_EXCLUSION_THRESHOLD;
  const relevantScore = scoreForHorizon(profile, taskHorizon);

  return Number.isFinite(relevantScore) && relevantScore < th;
}
