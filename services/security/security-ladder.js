/**
 * security-ladder.js — Multi-tier Threat Response Ladder (P1-B3-17)
 * Source: EWMA Anomaly Scoring, Positive Security Model
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js or governance-resolver.js
 * 2. → Pulls from: services/db/connection.js (Historical usage patterns)
 * 3. → Returns to: agent-security-gates.js (the native enforcement/event owner)
 * 4. No direct tool or transport side effects; the orchestration owner enforces.
 *
 * LOGIC GUIDE: Graduated response based on anomaly Z-score: observe (passive), 
 * shape (nudge), challenge (query), or block (deny). Learns positive usage models.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { toolActionArgumentsHash } from '../orchestration/tool-action-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

/**
 * Compute Exponentially Weighted Moving Average (EWMA) based anomaly Z-score.
 * Tracks mean and std dev of request rates to detect sudden spikes.
 *
 * @param {number} currentRate - Current request rate or metric value
 * @param {number} previousMean - Previous EWMA mean
 * @param {number} previousStd - Previous EWMA standard deviation
 * @param {number} alpha - EWMA smoothing factor (0.1-0.3 typical), default 0.2
 * @returns {{z_score: number, alert: boolean, newMean: number, newStd: number}}
 */
export function computeEWMAAnomaly(currentRate, previousMean, previousStd, alpha = 0.2) {
  if (alpha < 0 || alpha > 1) {
    throw new Error('alpha must be between 0 and 1');
  }

  // Update mean using EWMA
  const newMean = alpha * currentRate + (1 - alpha) * previousMean;

  // Update std dev (simplified: based on deviation from old mean)
  const deviation = Math.abs(currentRate - previousMean);
  const newStd = alpha * deviation + (1 - alpha) * previousStd;

  // Compute Z-score (std dev must not be 0)
  const zScore = newStd > 0 ? (currentRate - newMean) / newStd : 0;

  // Alert if Z-score exceeds 2 (2-sigma threshold)
  const alert = Math.abs(zScore) > 2;

  return {
    z_score: zScore,
    alert,
    newMean,
    newStd
  };
}

/**
 * Get decision ladder configuration with thresholds for each tier.
 * Maps anomaly score to security response level.
 *
 * @returns {{observe: {min: number, max: number}, shape: {min: number, max: number}, challenge: {min: number, max: number}, block: {min: number, max: number}}}
 */
export function getDecisionLadderConfig() {
  return {
    observe: {
      min: 0,
      max: 0.3,
      description: 'Passive observation: log and monitor without intervention'
    },
    shape: {
      min: 0.3,
      max: 0.6,
      description: 'Nudge: subtle guidance or prompt modification'
    },
    challenge: {
      min: 0.6,
      max: 0.8,
      description: 'Query: explicit question to user about intent'
    },
    block: {
      min: 0.8,
      max: 1.0,
      description: 'Deny: refuse operation entirely'
    }
  };
}

/**
 * Classify threat response tier based on anomaly score.
 * Uses decision ladder tiers: observe < 0.3, shape 0.3-0.6, challenge 0.6-0.8, block > 0.8.
 *
 * @param {number} anomalyScore - Anomaly score (0-1)
 * @returns {'observe' | 'shape' | 'challenge' | 'block'}
 */
export function classifyThreatResponse(anomalyScore) {
  const score = Math.max(0, Math.min(1, Number(anomalyScore) || 0));
  const config = getDecisionLadderConfig();

  let tier = 'observe';
  if (score >= config.block.min) {
    tier = 'block';
  } else if (score >= config.challenge.min) {
    tier = 'challenge';
  } else if (score >= config.shape.min) {
    tier = 'shape';
  }

  return tier;
}

/**
 * Build a positive security model from historical clean runs.
 * Learns the expected distribution of (tool, params, frequency) from trusted executions.
 *
 * @param {string} companyId - Company ID for scoping the model
 * @returns {Promise<{tools: Map<string, {params: Set<string>, frequency: Map<string, number>}>, trainingSize: number, timestamp: string}>}
 */
export async function buildPositiveSecurityModel(companyId = COMPANY) {
  try {
    // Learn only from signed successful tool-action receipts. The retired
    // The retired phantom run-log table never existed in the canonical schema and could not
    // provide cryptographic execution truth.
    const result = await query(`
      SELECT
        key AS tool_name,
        metadata->>'args_sha256' AS params,
        COUNT(*) as frequency
      FROM aimos_events
      WHERE company_id = $1
        AND operation = 'tool_execution_succeeded'
        AND proof_required = TRUE
        AND ledger_version = 1
        AND metadata->>'outcome' = 'succeeded'
        AND ts > NOW() - INTERVAL '30 days'
      GROUP BY key, metadata->>'args_sha256'
      ORDER BY frequency DESC
      LIMIT 1000
    `, [companyId]);

    // Build model structure
    const tools = new Map();

    if (result && result.rows) {
      for (const row of result.rows) {
        const toolName = String(row.tool_name || '');
        const params = String(row.params || '');
        const frequency = Number(row.frequency) || 0;

        if (!tools.has(toolName)) {
          tools.set(toolName, { params: new Set(), frequency: new Map() });
        }

        const toolData = tools.get(toolName);
        toolData.params.add(params);
        toolData.frequency.set(params, frequency);
      }
    }

    return {
      tools,
      trainingSize: result?.rowCount || 0,
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    console.warn('[security-ladder] Failed to build positive model:', err.message);
    return {
      tools: new Map(),
      trainingSize: 0,
      timestamp: new Date().toISOString(),
      error: err.message
    };
  }
}

/**
 * Check a tool invocation against the positive security model.
 * Detects deviations from expected (tool, params, frequency) patterns.
 *
 * @param {string} toolName - Tool being invoked
 * @param {string|object} params - Parameters (will be stringified if object)
 * @param {string} companyId - Company ID for model lookup
 * @param {object} model - Optional pre-built model (to avoid repeated DB queries)
 * @returns {Promise<{expected: boolean, deviation_score: number, confidence: number, reason: string}>}
 */
export async function checkPositiveModel(toolName, params, companyId = COMPANY, model = null) {
  try {
    const tool = String(toolName || '').trim();
    const paramsHash = toolActionArgumentsHash(params || {});

    // Use provided model or build fresh
    const positiveModel = model || await buildPositiveSecurityModel(companyId);

    if (!positiveModel.tools || positiveModel.tools.size === 0) {
      return {
        expected: true,
        deviation_score: 0,
        confidence: 0.2,
        reason: 'No positive model available (insufficient training data)'
      };
    }

    // Check if tool exists in model
    if (!positiveModel.tools.has(tool)) {
      return {
        expected: false,
        deviation_score: 0.8,
        confidence: 0.7,
        reason: `Tool '${tool}' not in positive model (never observed in clean runs)`
      };
    }

    const toolData = positiveModel.tools.get(tool);

    // Check if params combination exists
    if (!toolData.params.has(paramsHash)) {
      // Partial match: tool exists but params are novel
      return {
        expected: false,
        deviation_score: 0.5,
        confidence: 0.6,
        reason: `Tool '${tool}' exists but params combination is novel (not seen in clean runs)`
      };
    }

    // Full match: tool and params both in model
    return {
      expected: true,
      deviation_score: 0,
      confidence: 0.95,
      reason: `Tool '${tool}' with these params matches positive model`
    };
  } catch (err) {
    console.warn('[security-ladder] Failed to check positive model:', err.message);
    return {
      expected: true,
      deviation_score: 0.3,
      confidence: 0.3,
      reason: `Model check error: ${err.message}`
    };
  }
}

/**
 * Compute a graduated response from three normalized, independently observed
 * runtime signals. The caller must provide evidence in [0, 1]; unrelated
 * request fields (for example prompt length) are deliberately ignored.
 *
 * This is the local decision ladder, not a claim to implement the full
 * RiskGate viability model. Statistical estimators remain responsible for
 * producing the normalized evidence supplied here.
 *
 * @param {object} signals
 * @param {number} [signals.behavioralDrift] - Historical behavior deviation.
 * @param {number} [signals.manipulationRisk] - Manipulation score / block boundary.
 * @param {number} [signals.contextualRisk] - Independent contextual detector risk.
 * @returns {{tier: string, action: string, anomalyScore: number, reason: string, explanation: string, components: object}}
 */
export function computeSecurityResponse(signals = {}) {
  const weights = {
    behavioralDrift: 0.4,
    manipulationRisk: 0.35,
    contextualRisk: 0.25,
  };

  const components = Object.freeze({
    behavioralDrift: Math.max(0, Math.min(1, Number(signals.behavioralDrift) || 0)),
    manipulationRisk: Math.max(0, Math.min(1, Number(signals.manipulationRisk) || 0)),
    contextualRisk: Math.max(0, Math.min(1, Number(signals.contextualRisk) || 0)),
  });

  const compositeScore = (
    components.behavioralDrift * weights.behavioralDrift
    + components.manipulationRisk * weights.manipulationRisk
    + components.contextualRisk * weights.contextualRisk
  );
  const tier = classifyThreatResponse(compositeScore);
  const reason = `behavioral_drift=${components.behavioralDrift.toFixed(2)}, manipulation_risk=${components.manipulationRisk.toFixed(2)}, contextual_risk=${components.contextualRisk.toFixed(2)}`;

  return Object.freeze({
    tier,
    action: tier,
    anomalyScore: compositeScore,
    reason,
    explanation: `Composite: Behavioral=${components.behavioralDrift.toFixed(2)}, Manipulation=${components.manipulationRisk.toFixed(2)}, Contextual=${components.contextualRisk.toFixed(2)}`,
    components,
  });
}

export default {
  classifyThreatResponse,
  computeEWMAAnomaly,
  buildPositiveSecurityModel,
  checkPositiveModel,
  getDecisionLadderConfig,
  computeSecurityResponse
};
