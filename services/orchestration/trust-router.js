/**
 * trust-router.js — Trust-Aware Agent Routing (G-TRAC) (P0-B3-8)
 * Source: G-TRAC — Trust-Aware Routing (Umeå University, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: governance-resolver.js
 * 2. → Pulls from: agent_runs (Latency and success history)
 * 3. → Pushes to: services/observe/event-ledger.js (Routing decisions)
 * 4. ↔ Interacts with: services/db/connection.js (Trust score persistence)
 *
 * LOGIC GUIDE: Uses EWMA latency and asymmetric penalties (+0.03 success / -0.20 failure). 
 * Implements trust-floor pruning to prevent unreliable nodes from receiving tasks.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: governance-resolver.js
// → Calls: db (connection.js), event-ledger.js
// Pipeline: GOVERNANCE | Position: Trust routing (agent selection by trust score)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const TRUST_INCREMENT = 0.03;   // reward on success
const TRUST_DECREMENT = 0.20;   // penalty on failure (6.7x asymmetric)
const EWMA_BETA = 0.30;         // latency smoothing factor
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_TRUST_FLOOR = 0.3;

// ─── SCHEMA CONTRACT ──────────────────────────────────────────────────────
let _schemaVerified = false;
async function ensureSchema() {
  if (_schemaVerified) return;
  await query(`SELECT agent_id, company_id, trust_score, estimated_latency_ms,
                      liveness, success_count, failure_count, last_success_at,
                      last_failure_at, updated_at
               FROM agent_trust
               WHERE false`);
  _schemaVerified = true;
}

/**
 * Get trust state for an agent.
 *
 * @param {string} agentId
 * @param {string} companyId
 * @returns {Promise<{ trustScore: number, estimatedLatency: number, liveness: boolean, successCount: number, failureCount: number }>}
 */
export async function getAgentTrust(agentId, companyId = COMPANY) {
  await ensureSchema();
  const result = await query(
    `SELECT trust_score, estimated_latency_ms, liveness, success_count, failure_count
     FROM agent_trust WHERE agent_id = $1 AND company_id = $2`,
    [agentId, companyId]
  );

  if (result.rows.length === 0) {
    return { trustScore: 0.5, estimatedLatency: 5000, liveness: true, successCount: 0, failureCount: 0 };
  }

  const r = result.rows[0];
  return {
    trustScore: parseFloat(r.trust_score),
    estimatedLatency: parseFloat(r.estimated_latency_ms),
    liveness: r.liveness,
    successCount: parseInt(r.success_count, 10),
    failureCount: parseInt(r.failure_count, 10)
  };
}

/**
 * Record a successful agent execution. Trust increases by TRUST_INCREMENT.
 * Latency updated via EWMA.
 *
 * @param {string} agentId
 * @param {number} latencyMs - actual execution time
 * @param {string} companyId
 */
export async function recordSuccess(agentId, latencyMs, companyId = COMPANY) {
  await ensureSchema();
  const current = await getAgentTrust(agentId, companyId);

  const newTrust = Math.min(1.0, current.trustScore + TRUST_INCREMENT);
  const newLatency = (1 - EWMA_BETA) * current.estimatedLatency + EWMA_BETA * latencyMs;

  await query(
    `INSERT INTO agent_trust (agent_id, company_id, trust_score, estimated_latency_ms, liveness, success_count, last_success_at, updated_at)
     VALUES ($1, $2, $3, $4, true, 1, NOW(), NOW())
     ON CONFLICT (agent_id, company_id) DO UPDATE SET
       trust_score = $3, estimated_latency_ms = $4, liveness = true,
       success_count = agent_trust.success_count + 1, last_success_at = NOW(), updated_at = NOW()`,
    [agentId, companyId, newTrust, newLatency]
  );
}

/**
 * Record a failed agent execution. Trust decreases by TRUST_DECREMENT.
 *
 * @param {string} agentId
 * @param {number} latencyMs
 * @param {string} companyId
 */
export async function recordFailure(agentId, latencyMs, companyId = COMPANY) {
  await ensureSchema();
  const current = await getAgentTrust(agentId, companyId);

  const newTrust = Math.max(0.0, current.trustScore - TRUST_DECREMENT);
  const newLatency = (1 - EWMA_BETA) * current.estimatedLatency + EWMA_BETA * latencyMs;

  await query(
    `INSERT INTO agent_trust (agent_id, company_id, trust_score, estimated_latency_ms, failure_count, last_failure_at, updated_at)
     VALUES ($1, $2, $3, $4, 1, NOW(), NOW())
     ON CONFLICT (agent_id, company_id) DO UPDATE SET
       trust_score = $3, estimated_latency_ms = $4,
       failure_count = agent_trust.failure_count + 1, last_failure_at = NOW(), updated_at = NOW()`,
    [agentId, companyId, newTrust, newLatency]
  );

  // Log trust degradation event
  if (newTrust < DEFAULT_TRUST_FLOOR) {
    logEvent(companyId, agentId, 'trust_below_floor', `trust_low:${agentId}`, {
      reasoning: `Agent ${agentId} trust dropped to ${newTrust.toFixed(3)}, below floor ${DEFAULT_TRUST_FLOOR}. Agent will be excluded from routing until trust recovers.`,
      trust_score: newTrust,
      failure_count: current.failureCount + 1
    }).catch(() => {});
  }
}

/**
 * Compute effective cost for routing.
 * C(agent) = estimated_latency + (1 - trust) * timeout
 *
 * Lower cost = better routing candidate.
 *
 * @param {string} agentId
 * @param {number} timeoutMs
 * @param {string} companyId
 * @returns {Promise<number>} effective cost in ms
 */
export async function computeEffectiveCost(agentId, timeoutMs = DEFAULT_TIMEOUT_MS, companyId = COMPANY) {
  const state = await getAgentTrust(agentId, companyId);
  if (!state.liveness) return Infinity;
  return state.estimatedLatency + (1 - state.trustScore) * timeoutMs;
}

/**
 * Trust-floor pruning: filter agents below the trust floor.
 *
 * τ = (1 - ε)^(1/K_max)
 * where ε = acceptable failure probability, K_max = max pipeline length
 *
 * @param {string[]} agentIds - candidate agents
 * @param {{ epsilon?: number, kMax?: number }} options
 * @param {string} companyId
 * @returns {Promise<string[]>} agents meeting trust floor
 */
export async function trustFloorPrune(agentIds, options = {}, companyId = COMPANY) {
  const { epsilon = 0.1, kMax = 3 } = options;
  const trustFloor = Math.pow(1 - epsilon, 1 / kMax);

  const eligible = [];
  for (const agentId of agentIds) {
    const state = await getAgentTrust(agentId, companyId);
    if (state.liveness && state.trustScore >= trustFloor) {
      eligible.push(agentId);
    }
  }

  return eligible;
}

/**
 * Route task to best agent: trust-floor prune → sort by effective cost → pick best.
 *
 * @param {string[]} candidateAgents
 * @param {{ epsilon?: number, kMax?: number, timeoutMs?: number }} options
 * @param {string} companyId
 * @returns {Promise<{ agentId: string|null, cost: number, alternatives: number }>}
 */
export async function routeTask(candidateAgents, options = {}, companyId = COMPANY) {
  const eligible = await trustFloorPrune(candidateAgents, options, companyId);

  if (eligible.length === 0) {
    return { agentId: null, cost: Infinity, alternatives: 0 };
  }

  const costs = [];
  for (const agentId of eligible) {
    const cost = await computeEffectiveCost(agentId, options.timeoutMs, companyId);
    costs.push({ agentId, cost });
  }

  costs.sort((a, b) => a.cost - b.cost);

  return {
    agentId: costs[0].agentId,
    cost: costs[0].cost,
    alternatives: costs.length - 1
  };
}

/**
 * Bounded one-shot repair: if an agent fails mid-pipeline, find one replacement.
 * Do NOT retry unboundedly.
 *
 * @param {string} failedAgentId
 * @param {string[]} allCandidates
 * @param {string} companyId
 * @returns {Promise<string|null>} replacement agent ID, or null if none available
 */
export async function findRepairAgent(failedAgentId, allCandidates, companyId = COMPANY) {
  const eligible = await trustFloorPrune(
    allCandidates.filter(id => id !== failedAgentId),
    {},
    companyId
  );

  if (eligible.length === 0) return null;

  // Pick highest trust agent as replacement
  let best = null;
  let bestTrust = -1;
  for (const agentId of eligible) {
    const state = await getAgentTrust(agentId, companyId);
    if (state.trustScore > bestTrust) {
      bestTrust = state.trustScore;
      best = agentId;
    }
  }

  return best;
}

/**
 * Compute sequential chain reliability.
 * Rel(chain) = product of individual agent trust scores.
 *
 * @param {string[]} agentChain - ordered list of agents in pipeline
 * @param {string} companyId
 * @returns {Promise<number>} chain reliability (0-1)
 */
export async function computeChainReliability(agentChain, companyId = COMPANY) {
  let reliability = 1.0;
  for (const agentId of agentChain) {
    const state = await getAgentTrust(agentId, companyId);
    reliability *= state.trustScore;
  }
  return reliability;
}

/**
 * Get trust leaderboard for all agents.
 */
export async function getTrustLeaderboard(companyId = COMPANY) {
  await ensureSchema();
  const result = await query(
    `SELECT agent_id, trust_score, estimated_latency_ms, liveness, success_count, failure_count
     FROM agent_trust WHERE company_id = $1 ORDER BY trust_score DESC`,
    [companyId]
  );
  return result.rows;
}
