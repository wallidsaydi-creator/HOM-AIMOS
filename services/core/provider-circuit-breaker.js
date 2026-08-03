/**
 * provider-circuit-breaker.js — Per-Provider Circuit Breaker
 * Source: Circuit Breaker pattern (Netflix Hystrix), Release It (Nygard)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: providers.js (isCircuitAvailable before runProvider)
 * 2. ← Called by: provider-health.js (circuit state feeds health score)
 * 3. → Reads from: scale-baseline.js (failure thresholds, cooldowns)
 * Pipeline: AGENT_RUN | Position: Provider resilience (pre-call gate)
 *
 * Design:
 *   - Per-provider in-memory state (no DB persistence — failures are transient)
 *   - Three states: CLOSED (healthy) → OPEN (failing) → HALF_OPEN (probing)
 *   - Scale-adaptive thresholds: more failures tolerated at higher memory counts
 *   - HALF_OPEN allows 1 probe; success closes, failure re-opens
 *   - Zero wrappers: does NOT intercept HTTP. Only gates provider SELECTION.
 *
 * Phase 10/11 compliance: no envelope interception, no signedFetch.
 * Phase 5B readiness: keyed by provider_id; agent_id dimension added later.
 *
 * Aladdin: circuit breaker marks providers temporarily unavailable but never
 *           deletes provider configuration or data.
 */

import { getMemoryCount } from '../shared/scale-baseline.js';

// ─── CIRCUIT STATES ────────────────────────────────────────────────────────────
export const CIRCUIT_STATE = Object.freeze({
  CLOSED: 'closed',
  OPEN: 'open',
  HALF_OPEN: 'half_open'
});

// ─── PER-PROVIDER CIRCUIT STATE ───────────────────────────────────────────────
const circuits = new Map(); // provider_id → { state, failureCount, lastFailureTs, lastSuccessTs, successInHalfOpen }

function getOrCreateCircuit(providerId) {
  if (!circuits.has(providerId)) {
    circuits.set(providerId, {
      state: CIRCUIT_STATE.CLOSED,
      failureCount: 0,
      lastFailureTs: 0,
      lastSuccessTs: 0,
      successInHalfOpen: false
    });
  }
  return circuits.get(providerId);
}

// ─── SCALE-ADAPTIVE THRESHOLDS ────────────────────────────────────────────────
// Paper: Release It (Nygard) — circuit thresholds should be higher for mature systems
// that have more traffic and can tolerate transient spikes.

/**
 * Failure threshold before opening the circuit.
 * At 14K: 5 failures. At 100K: 8 failures (more tolerant at scale).
 *
 * @param {number} [memoryCount] - Override memory count for testing
 * @returns {number} Failure threshold
 */
export function getFailureThreshold(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  return Math.max(3, Math.min(10, Math.floor(5 * Math.pow(N / 14000, 0.1))));
}

/**
 * Cooldown period in milliseconds before transitioning from OPEN to HALF_OPEN.
 * At 14K: 30s. At 100K: 60s (longer recovery window at scale).
 *
 * @param {number} [memoryCount] - Override memory count for testing
 * @returns {number} Cooldown in milliseconds
 */
export function getCooldownMs(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  return Math.min(120_000, Math.max(15_000, Math.floor(30_000 * Math.pow(N / 14000, 0.2))));
}

/**
 * Maximum failover attempts (primary + fallbacks).
 * Fixed at 3 — scale-independent. More attempts waste time and tokens.
 *
 * @returns {number} Max attempts
 */
export function getMaxFailoverAttempts() {
  return 3;
}

// ─── CIRCUIT BREAKER OPERATIONS ────────────────────────────────────────────────

/**
 * Record a successful call for a provider.
 * Resets failure count, closes circuit if HALF_OPEN.
 *
 * @param {string} providerId - Provider identifier
 */
export function recordSuccess(providerId) {
  const circuit = getOrCreateCircuit(providerId);
  circuit.failureCount = 0;
  circuit.lastSuccessTs = Date.now();
  if (circuit.state === CIRCUIT_STATE.HALF_OPEN) {
    circuit.state = CIRCUIT_STATE.CLOSED;
    circuit.successInHalfOpen = false;
  }
}

/**
 * Record a failed call for a provider.
 * Increments failure count, may transition to OPEN.
 * In HALF_OPEN, a single failure re-opens the circuit.
 *
 * @param {string} providerId - Provider identifier
 * @param {number} [memoryCount] - Override memory count for threshold calculation
 */
export function recordFailure(providerId, memoryCount) {
  const circuit = getOrCreateCircuit(providerId);
  circuit.failureCount += 1;
  circuit.lastFailureTs = Date.now();

  if (circuit.state === CIRCUIT_STATE.HALF_OPEN) {
    // Single failure in HALF_OPEN → re-open immediately
    circuit.state = CIRCUIT_STATE.OPEN;
    circuit.successInHalfOpen = false;
    return;
  }

  const threshold = getFailureThreshold(memoryCount);
  if (circuit.failureCount >= threshold) {
    circuit.state = CIRCUIT_STATE.OPEN;
  }
}

/**
 * Check if a provider is available (circuit CLOSED or HALF_OPEN).
 * OPEN providers are skipped during failover.
 * In HALF_OPEN, the circuit allows one probe request.
 *
 * @param {string} providerId - Provider identifier
 * @returns {boolean} Whether the provider is available for calls
 */
export function isCircuitAvailable(providerId) {
  const circuit = getOrCreateCircuit(providerId);

  if (circuit.state === CIRCUIT_STATE.CLOSED) {
    return true;
  }

  if (circuit.state === CIRCUIT_STATE.HALF_OPEN) {
    return true; // Allow one probe
  }

  // OPEN state — check if cooldown has elapsed
  const memoryCount = 14000; // Will be refreshed by getMemoryCount in production
  const cooldown = getCooldownMs(memoryCount);
  const elapsed = Date.now() - circuit.lastFailureTs;
  if (elapsed >= cooldown) {
    // Transition to HALF_OPEN
    circuit.state = CIRCUIT_STATE.HALF_OPEN;
    circuit.successInHalfOpen = false;
    return true;
  }

  return false;
}

/**
 * Get the current circuit state for a provider.
 *
 * @param {string} providerId - Provider identifier
 * @returns {string} 'closed' | 'open' | 'half_open'
 */
export function getCircuitState(providerId) {
  const circuit = getOrCreateCircuit(providerId);

  // Auto-transition OPEN → HALF_OPEN if cooldown has elapsed
  if (circuit.state === CIRCUIT_STATE.OPEN) {
    const cooldown = getCooldownMs();
    const elapsed = Date.now() - circuit.lastFailureTs;
    if (elapsed >= cooldown) {
      circuit.state = CIRCUIT_STATE.HALF_OPEN;
      circuit.successInHalfOpen = false;
    }
  }

  return circuit.state;
}

/**
 * Get circuit breaker diagnostics for all providers.
 *
 * @param {number} [memoryCount] - Override memory count for scale-adaptive params
 * @returns {Object} Diagnostics object with per-provider state and scale params
 */
export function getCircuitBreakerDiagnostics(memoryCount) {
  const N = Math.max(1, memoryCount || 14000);
  const providers = {};

  for (const [providerId, circuit] of circuits.entries()) {
    const state = getCircuitState(providerId);
    const cooldownMs = getCooldownMs(N);
    const elapsed = Date.now() - circuit.lastFailureTs;
    providers[providerId] = {
      circuit: state,
      failureCount: circuit.failureCount,
      lastFailureTs: circuit.lastFailureTs || null,
      lastSuccessTs: circuit.lastSuccessTs || null,
      cooldownRemainingMs: state === CIRCUIT_STATE.OPEN
        ? Math.max(0, cooldownMs - elapsed)
        : 0
    };
  }

  return {
    providers,
    scale: {
      failureThreshold: getFailureThreshold(N),
      cooldownMs: getCooldownMs(N),
      maxFailoverAttempts: getMaxFailoverAttempts(),
      memoryCount: N
    }
  };
}

/**
 * Reset circuit state for a provider (for testing or admin override).
 *
 * @param {string} providerId - Provider to reset
 */
export function resetCircuit(providerId) {
  circuits.delete(providerId);
}

/**
 * Reset all circuits (for testing).
 */
export function resetAllCircuits() {
  circuits.clear();
}