// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: HLER two-loop quality architecture (question quality + answer quality)
//          for multi-agent pipeline coordination via shared RunState
// Wire into: jobs/dream or agent-runner.js (agent-run pipeline, reflection step)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * BATCH REFLECTOR — HLER MULTI-AGENT PIPELINE QUALITY LOOPS
 *
 * Source: "HLER: Hypothesis-Led Exploration and Research Multi-Agent Pipelines" (2026)
 *
 * Implements shared RunState coordination for multi-stage pipelines with
 * two-loop quality architecture:
 *   1. Question Quality Loop: generate -> screen -> human gate
 *   2. Research Revision Loop: generate -> review -> revise (2-3 iterations)
 *
 * Multi-dimensional reviewer scoring evaluates 5 dimensions on a 1-10 scale:
 * novelty, identification, data quality, clarity, and policy relevance.
 * Human decision gates appear at exactly 2 points in the pipeline.
 * Hypothesis generation is constrained by the actual dataset schema/variables.
 *
 * Created: 2026-04-01
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;

// Quality loop defaults
const DEFAULT_QUALITY_MAX_ITERATIONS = 3;
const DEFAULT_REVISION_MAX_ITERATIONS = 3;
const QUALITY_PASS_THRESHOLD = 6.5;  // Mean score >= 6.5/10 passes screening

// Scoring dimensions with weights
const SCORING_DIMENSIONS = [
  { key: 'novelty',          label: 'Novelty',          weight: 0.20 },
  { key: 'identification',   label: 'Identification',   weight: 0.20 },
  { key: 'dataQuality',      label: 'Data Quality',     weight: 0.25 },
  { key: 'clarity',          label: 'Clarity',           weight: 0.20 },
  { key: 'policyRelevance',  label: 'Policy Relevance', weight: 0.15 }
];

/**
 * Initialize a shared RunState for a pipeline execution.
 * The RunState is the central coordination object that all stages read/write.
 *
 * @param {string} pipelineId - Unique pipeline identifier
 * @param {string} companyId - Company ID
 * @returns {Promise<{runStateId: string, created: boolean}>}
 */
export async function createRunState(pipelineId, companyId = COMPANY) {
  const runStateId = `rs_${pipelineId}_${Date.now()}`;

  try {
    const state = {
      runStateId,
      pipelineId,
      stages: [],
      humanGates: { gate1: null, gate2: null },
      qualityScores: [],
      currentStage: 'initialized',
      iterationCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await persistMemory({
      company_id: companyId,
      agent_id: 'batch-reflector',
      mutation_authority: 'housekeeper',
      key: runStateId,
      value: JSON.stringify(state),
      scope: 'system',
      memory_type: 'pipeline_run_state',
      memory_tier: 'short-term',
      clearance_level: 5
    });

    return { runStateId, created: true };
  } catch (err) {
    console.error(`[BATCH-REFLECTOR] Failed to create run state: ${err.message}`);
    return { runStateId, created: false };
  }
}

/**
 * Append a stage result to an existing RunState.
 * Each stage records its output, timing, and metadata.
 *
 * @param {string} runStateId - RunState identifier
 * @param {string} stage - Stage name (e.g. 'generate', 'screen', 'review', 'revise')
 * @param {object} result - Stage output: {output, metadata, scores?}
 * @param {string} companyId - Company ID
 * @returns {Promise<{appended: boolean, stageIndex: number}>}
 */
export async function addStageResult(runStateId, stage, result, companyId = COMPANY) {
  try {
    const state = await loadRunState(runStateId, companyId);
    if (!state) {
      return { appended: false, stageIndex: -1 };
    }

    const stageEntry = {
      stage,
      result,
      timestamp: new Date().toISOString(),
      iterationAtTime: state.iterationCount
    };

    state.stages.push(stageEntry);
    state.currentStage = stage;
    state.updatedAt = new Date().toISOString();

    await persistRunState(runStateId, state, companyId);

    return { appended: true, stageIndex: state.stages.length - 1 };
  } catch (err) {
    console.error(`[BATCH-REFLECTOR] Failed to add stage result: ${err.message}`);
    return { appended: false, stageIndex: -1 };
  }
}

/**
 * Multi-dimensional scoring of a pipeline output.
 * Scores across 5 dimensions (1-10 scale each) and computes a weighted aggregate.
 *
 * @param {object} output - The content to score
 * @param {Array<{key: string, score: number}>} dimensions - Per-dimension scores (1-10)
 * @returns {{scores: object, weightedMean: number, pass: boolean, feedback: Array<string>}}
 */
export function scoreOutput(output, dimensions = []) {
  const scores = {};
  const feedback = [];
  let weightedSum = 0;
  let totalWeight = 0;

  for (const dim of SCORING_DIMENSIONS) {
    const provided = dimensions.find(d => d.key === dim.key);
    const score = provided ? Math.max(1, Math.min(10, provided.score)) : 5;

    scores[dim.key] = {
      score,
      label: dim.label,
      weight: dim.weight
    };

    weightedSum += score * dim.weight;
    totalWeight += dim.weight;

    // Generate dimension-specific feedback
    if (score <= 3) {
      feedback.push(`${dim.label}: critically low (${score}/10). Major revision needed.`);
    } else if (score <= 5) {
      feedback.push(`${dim.label}: below expectations (${score}/10). Consider strengthening.`);
    } else if (score >= 9) {
      feedback.push(`${dim.label}: excellent (${score}/10).`);
    }
  }

  const weightedMean = totalWeight > 0 ? weightedSum / totalWeight : 0;
  const pass = weightedMean >= QUALITY_PASS_THRESHOLD;

  return { scores, weightedMean, pass, feedback };
}

/**
 * Run the Question Quality Loop: generate -> screen -> human gate.
 * Iterates until the hypothesis passes screening or maxIterations is reached.
 * The human gate (gate 1) is recorded but execution continues — the gate
 * result is consumed asynchronously by the pipeline orchestrator.
 *
 * @param {object} hypothesis - Initial hypothesis: {text, datasetSchema, variables}
 * @param {number} maxIterations - Max loop iterations (default: 3)
 * @param {string} companyId - Company ID
 * @returns {Promise<{hypothesis: object, iterations: number, passed: boolean, gateStatus: string}>}
 */
export async function runQualityLoop(hypothesis, maxIterations = DEFAULT_QUALITY_MAX_ITERATIONS, companyId = COMPANY) {
  let current = { ...hypothesis };
  let iterations = 0;
  let passed = false;

  for (let i = 0; i < maxIterations; i++) {
    iterations++;

    // Generate: constrain hypothesis by dataset schema
    const constrained = constrainBySchema(current);

    // Screen: multi-dimensional scoring
    const screening = scoreOutput(constrained, [
      { key: 'novelty', score: assessNovelty(constrained) },
      { key: 'identification', score: assessIdentification(constrained) },
      { key: 'dataQuality', score: assessDataFeasibility(constrained) },
      { key: 'clarity', score: assessClarity(constrained) },
      { key: 'policyRelevance', score: assessPolicyRelevance(constrained) }
    ]);

    current.lastScreening = screening;
    current.text = constrained.text || current.text;

    if (screening.pass) {
      passed = true;
      break;
    }

    // Refine based on lowest-scoring dimensions
    current = refineHypothesis(current, screening);
  }

  // Record human gate 1 (pending human decision)
  const gateStatus = passed ? 'pending_human_approval' : 'failed_screening';

  try {
    await persistMemory({
      company_id: companyId,
      agent_id: 'batch-reflector',
      mutation_authority: 'housekeeper',
      key: `gate1_${Date.now()}`,
      value: JSON.stringify({
        gateNumber: 1,
        hypothesis: current,
        passed,
        iterations,
        status: gateStatus,
        createdAt: new Date().toISOString()
      }),
      scope: 'system',
      memory_type: 'human_gate',
      memory_tier: 'short-term',
      clearance_level: 6
    });
  } catch (err) {
    console.warn(`[BATCH-REFLECTOR] Failed to record gate 1: ${err.message}`);
  }

  return { hypothesis: current, iterations, passed, gateStatus };
}

/**
 * Run the Research Revision Loop: generate -> review -> revise.
 * Iterates 2-3 times to improve draft quality through review feedback.
 *
 * @param {object} draft - Initial research draft: {text, citations, methodology}
 * @param {object} reviewer - Reviewer configuration: {strictness, focusDimensions}
 * @param {number} maxIterations - Max revision iterations (default: 3)
 * @returns {Promise<{draft: object, iterations: number, finalScore: number, revisionHistory: Array}>}
 */
export async function runRevisionLoop(draft, reviewer = {}, maxIterations = DEFAULT_REVISION_MAX_ITERATIONS) {
  let current = { ...draft };
  const revisionHistory = [];
  let iterations = 0;
  let finalScore = 0;

  const strictness = reviewer.strictness || 1.0;
  const focusDimensions = reviewer.focusDimensions || SCORING_DIMENSIONS.map(d => d.key);

  for (let i = 0; i < maxIterations; i++) {
    iterations++;

    // Review: score the current draft
    const dimensionScores = focusDimensions.map(key => ({
      key,
      score: assessDimension(current, key, strictness)
    }));

    const review = scoreOutput(current, dimensionScores);
    finalScore = review.weightedMean;

    revisionHistory.push({
      iteration: iterations,
      scores: review.scores,
      weightedMean: review.weightedMean,
      feedback: review.feedback
    });

    // If quality is sufficient after at least 2 iterations, stop
    if (review.pass && iterations >= 2) {
      break;
    }

    // Revise: apply feedback to improve weakest dimensions
    current = applyRevisionFeedback(current, review);
  }

  return { draft: current, iterations, finalScore, revisionHistory };
}

/**
 * Retrieve full RunState by pipeline ID.
 *
 * @param {string} pipelineId - Pipeline identifier
 * @param {string} companyId - Company ID
 * @returns {Promise<object|null>}
 */
export async function getRunState(pipelineId, companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT key, value FROM aimos_memories
       WHERE company_id = $1
         AND memory_type = 'pipeline_run_state'
         AND key LIKE $2
       ORDER BY updated_at DESC
       LIMIT 1`,
      [companyId, `rs_${pipelineId}_%`]
    );

    if (res.rows.length > 0) {
      try {
        return JSON.parse(res.rows[0].value);
      } catch {
        return null;
      }
    }
    return null;
  } catch (err) {
    console.warn(`[BATCH-REFLECTOR] Failed to get run state for ${pipelineId}: ${err.message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function loadRunState(runStateId, companyId) {
  try {
    const res = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2
         AND memory_type = 'pipeline_run_state'
       ORDER BY created_at DESC
       LIMIT 1`,
      [companyId, runStateId]
    );

    if (res.rows.length > 0) {
      return JSON.parse(res.rows[0].value);
    }
    return null;
  } catch (err) {
    console.warn(`[BATCH-REFLECTOR] Failed to load run state: ${err.message}`);
    return null;
  }
}

async function persistRunState(runStateId, state, companyId) {
  await persistMemory({
    company_id: companyId,
    agent_id: 'batch-reflector',
    mutation_authority: 'housekeeper',
    key: runStateId,
    value: JSON.stringify(state),
    scope: 'system',
    memory_type: 'pipeline_run_state',
    memory_tier: 'short-term',
    clearance_level: 5,
    source: 'batch-reflector',
  });
}

function constrainBySchema(hypothesis) {
  // Constrain hypothesis by dataset variables/schema if provided
  const constrained = { ...hypothesis };

  if (hypothesis.datasetSchema && hypothesis.variables) {
    const schemaVars = new Set(hypothesis.datasetSchema.map(v => v.name || v));
    const referenced = hypothesis.variables.filter(v => schemaVars.has(v));
    const missing = hypothesis.variables.filter(v => !schemaVars.has(v));

    constrained.constrainedVariables = referenced;
    constrained.droppedVariables = missing;

    if (missing.length > 0) {
      constrained.text = (constrained.text || '') +
        ` [Note: variables ${missing.join(', ')} not found in dataset schema; removed from analysis.]`;
    }
  }

  return constrained;
}

function assessNovelty(hypothesis) {
  const text = String(hypothesis.text || '').toLowerCase();
  // Penalize overly generic hypotheses
  const genericTerms = ['relationship', 'impact', 'effect', 'correlation'];
  const genericCount = genericTerms.filter(t => text.includes(t)).length;
  return Math.max(1, Math.min(10, 8 - genericCount * 1.5));
}

function assessIdentification(hypothesis) {
  // Check if hypothesis clearly identifies variables and direction
  const hasVariables = (hypothesis.variables || []).length >= 2;
  const hasDirection = /increas|decreas|positiv|negativ|higher|lower/.test(hypothesis.text || '');
  return (hasVariables ? 5 : 2) + (hasDirection ? 3 : 0) + (hypothesis.methodology ? 2 : 0);
}

function assessDataFeasibility(hypothesis) {
  // Score based on schema constraint satisfaction
  const dropped = (hypothesis.droppedVariables || []).length;
  const constrained = (hypothesis.constrainedVariables || hypothesis.variables || []).length;
  if (constrained === 0) return 3;
  return Math.max(1, Math.min(10, 10 - dropped * 2));
}

function assessClarity(hypothesis) {
  const text = String(hypothesis.text || '');
  const wordCount = text.split(/\s+/).length;
  // Penalize too short or too long
  if (wordCount < 10) return 3;
  if (wordCount > 200) return 5;
  return Math.min(10, 6 + Math.floor(wordCount / 30));
}

function assessPolicyRelevance(hypothesis) {
  const text = String(hypothesis.text || '').toLowerCase();
  const policyTerms = ['policy', 'intervention', 'regulation', 'reform', 'outcome', 'welfare'];
  const matches = policyTerms.filter(t => text.includes(t)).length;
  return Math.max(1, Math.min(10, 4 + matches * 2));
}

function assessDimension(draft, key, strictness) {
  const assessors = {
    novelty: assessNovelty,
    identification: assessIdentification,
    dataQuality: assessDataFeasibility,
    clarity: assessClarity,
    policyRelevance: assessPolicyRelevance
  };

  const fn = assessors[key];
  if (!fn) return 5;

  const raw = fn(draft);
  // Apply strictness multiplier (< 1 = lenient, > 1 = strict)
  return Math.max(1, Math.min(10, Math.round(raw / strictness)));
}

function refineHypothesis(hypothesis, screening) {
  const refined = { ...hypothesis };

  // Identify weakest dimension and suggest improvement
  const weakest = Object.entries(screening.scores)
    .sort((a, b) => a[1].score - b[1].score)[0];

  if (weakest) {
    refined.refinementTarget = weakest[0];
    refined.refinementReason = `Lowest score: ${weakest[1].label} (${weakest[1].score}/10)`;
  }

  return refined;
}

function applyRevisionFeedback(draft, review) {
  const revised = { ...draft };

  // Mark which dimensions improved and which need more work
  revised.appliedFeedback = review.feedback;
  revised.revisionTarget = review.feedback
    .filter(f => f.includes('critically low') || f.includes('below expectations'))
    .map(f => f.split(':')[0]);

  return revised;
}
