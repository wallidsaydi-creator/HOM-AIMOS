/**
 * provider-health.js — Per-Provider Health Scoring with EWMA
 * Source: Google SRE (latency percentiles), Hystrix (health indicators)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: providers.js (health score informs provider selection)
 * 2. ← Called by: routes/aimos.js (diagnostics endpoint)
 * 3. → Reads from: provider-circuit-breaker.js (circuit state feeds health)
 * 4. → Reads from: scale-baseline.js (latency neutral point at scale)
 * Pipeline: AGENT_RUN | Position: Provider health scoring (pre-call ranking)
 *
 * Design:
 *   - EWMA (Exponential Weighted Moving Average) for success rate and latency
 *   - Health score = success_rate * latency_penalty, clamped [0, 1]
 *   - Scale-adaptive latency neutral point (2s at 14K, 3s at 100K)
 *   - Health scores feed into pickActiveProvider ranking
 *   - In-memory, process-scoped — resets on restart (acceptable for transient data)
 *
 * Phase 10/11 compliance: no envelope interception. Only scores provider SELECTION.
 * Phase 5B readiness: keyed by provider_id; agent_id dimension added later.
 *
 * Aladdin: health scores are advisory rankings, never delete provider data.
 */

import { getCircuitState, CIRCUIT_STATE } from './provider-circuit-breaker.js';

// ─── EWMA PARAMETERS ──────────────────────────────────────────────────────────
const ALPHA_SUCCESS = 0.3;  // Fast adaptation for success rate
const ALPHA_LATENCY = 0.2;  // Slower adaptation for latency (smoother)

// ─── PER-PROVIDER HEALTH STATE ────────────────────────────────────────────────
const healthScores = new Map(); // provider_id → { successRate, avgLatencyMs, healthScore, lastUpdate, callCount }

function getOrCreateHealth(providerId) {
  if (!healthScores.has(providerId)) {
    healthScores.set(providerId, {
      successRate: 1.0,      // Optimistic start
      avgLatencyMs: 1000,   // Assume 1s baseline
      healthScore: 1.0,      // Start healthy
      lastUpdate: Date.now(),
      callCount: 0
    });
  }
  return healthScores.get(providerId);
}

// ─── SCALE-ADAPTIVE LATENCY NEUTRAL POINT ───────────────────────────────────────

/**
 * Latency neutral point in milliseconds.
 * Below this latency, there's no penalty. Above it, penalty increases.
 * At 14K: 2000ms. At 100K: 3000ms (more tolerant at scale).
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {number} Latency neutral point in ms
 */
export function getLatencyNeutralMs(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  // log2(1/14000) is negative, so min(1, ...) handles that
  // Also ensure the result is at least 2000ms baseline
  return Math.max(2000, 2000 + 1000 * Math.min(1, Math.log2(Math.max(1, N / 14000))));
}

/**
 * Compute health score from success rate and latency.
 * health = success_rate * latency_penalty
 * latency_penalty = max(0, 1 - (latency / neutral)^2)
 *
 * @param {number} successRate - EWMA success rate [0, 1]
 * @param {number} avgLatencyMs - EWMA average latency in ms
 * @param {number} [memoryCount] - Override memory count for neutral point
 * @returns {number} Health score [0, 1]
 */
export function computeHealthScore(successRate, avgLatencyMs, memoryCount) {
  const neutralMs = getLatencyNeutralMs(memoryCount);
  const latencyPenalty = Math.max(0, 1 - Math.pow(avgLatencyMs / neutralMs, 2));
  return Math.max(0, Math.min(1, successRate * latencyPenalty));
}

// ─── HEALTH SCORING OPERATIONS ─────────────────────────────────────────────────

/**
 * Record the outcome of a provider call.
 * Updates EWMA success rate and latency, then recomputes health score.
 *
 * @param {string} providerId - Provider identifier
 * @param {boolean} success - Whether the call succeeded
 * @param {number} latencyMs - Call latency in milliseconds
 * @param {number} [memoryCount] - Override memory count for health score
 */
export function recordCallOutcome(providerId, success, latencyMs, memoryCount) {
  const health = getOrCreateHealth(providerId);
  health.callCount += 1;
  health.lastUpdate = Date.now();

  // EWMA update for success rate
  if (health.callCount === 1) {
    health.successRate = success ? 1.0 : 0.0;
  } else {
    health.successRate = ALPHA_SUCCESS * (success ? 1.0 : 0.0) + (1 - ALPHA_SUCCESS) * health.successRate;
  }

  // EWMA update for latency
  health.avgLatencyMs = ALPHA_LATENCY * latencyMs + (1 - ALPHA_LATENCY) * health.avgLatencyMs;

  // Recompute health score
  health.healthScore = computeHealthScore(health.successRate, health.avgLatencyMs, memoryCount);
}

/**
 * Get the health score for a provider.
 * Accounts for circuit breaker state: OPEN circuits get health = 0.
 *
 * @param {string} providerId - Provider identifier
 * @returns {number} Health score [0, 1]
 */
export function getHealthScore(providerId) {
  const circuitState = getCircuitState(providerId);
  if (circuitState === CIRCUIT_STATE.OPEN) {
    return 0; // OPEN circuits are unhealthy regardless of past performance
  }

  const health = healthScores.get(providerId);
  if (!health) return 1.0; // Unknown providers are assumed healthy

  return health.healthScore;
}

/**
 * Get all healthy providers sorted by health score (descending).
 * Excludes OPEN circuits and providers with health < 0.1.
 *
 * @param {string[]} [providerIds] - Optional filter list
 * @returns {Array<{providerId: string, healthScore: number, circuit: string}>} Sorted providers
 */
export function getHealthyProviders(providerIds) {
  const allProviders = providerIds || Array.from(healthScores.keys());
  const result = [];

  for (const providerId of allProviders) {
    const circuitState = getCircuitState(providerId);
    if (circuitState === CIRCUIT_STATE.OPEN) continue;

    const health = healthScores.get(providerId);
    const score = health ? health.healthScore : 1.0;
    if (score < 0.1) continue; // Effectively dead providers

    result.push({
      providerId,
      healthScore: score,
      circuit: circuitState
    });
  }

  result.sort((a, b) => b.healthScore - a.healthScore);
  return result;
}

/**
 * Get provider health diagnostics for all known providers.
 *
 * @param {number} [memoryCount] - Override memory count
 * @returns {Object} Diagnostics object
 */
export function getProviderHealthDiagnostics(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  const providers = {};

  for (const [providerId, health] of healthScores.entries()) {
    const circuitState = getCircuitState(providerId);
    providers[providerId] = {
      circuit: circuitState,
      healthScore: Math.round(health.healthScore * 100) / 100,
      successRate: Math.round(health.successRate * 100) / 100,
      avgLatencyMs: Math.round(health.avgLatencyMs),
      callCount: health.callCount,
      lastUpdate: health.lastUpdate ? new Date(health.lastUpdate).toISOString() : null
    };
  }

  return {
    providers,
    scale: {
      latencyNeutralMs: getLatencyNeutralMs(N),
      alphaSuccess: ALPHA_SUCCESS,
      alphaLatency: ALPHA_LATENCY,
      memoryCount: N
    }
  };
}

/**
 * Reset health data for a provider (for testing or admin override).
 *
 * @param {string} providerId - Provider to reset
 */
export function resetHealth(providerId) {
  healthScores.delete(providerId);
}

/**
 * Reset all health data (for testing).
 */
export function resetAllHealth() {
  healthScores.clear();
}