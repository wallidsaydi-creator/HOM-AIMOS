// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: WIRED (agent-runner.js, memory pipeline)
// ← Called by: agent-runner.js (after inference), stdp-kernel.js (weight update)
// → Calls: services/db/connection.js (memory queries)
// Pipeline: MEMORY_PIPELINE | Position: plasticity modulation
// Batch 10 Lane 2: Wire into live pipeline + block capacity (G-MemLLM, M+)
//   write_strength = plasticity_level * gate_confidence
//   block_capacity(level) = {L1:100, L2:50, L3:30, L4:10, L5:5}
//   evict_candidate = lowest_trust_block when capacity exceeded
// Aladdin: Block eviction suppresses from context window, never deletes from Aimos.
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// PLASTICITY CONTROLLER (plasticity-controller.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-13: Variable Plasticity
//
// Modulates learning rate by domain maturity to balance:
//   - Fast acquisition in novel domains (high plasticity)
//   - Stability preservation in established domains (low plasticity)
//
// Plasticity levels:
//   high   — new domain (<10 memories, high prediction error)
//             → accept new information readily, decay existing beliefs quickly
//   medium — developing domain (10-50 memories, moderate error)
//             → balanced update rate
//   low    — established domain (>50 memories, low prediction error)
//             → resist overwriting stable knowledge
//
// Domain shift detection: if prediction error spikes above SHIFT_THRESHOLD
// after a low-plasticity period, plasticity is temporarily re-opened.
//
// Theoretical basis: Hopfield networks, Bienenstock-Cooper-Munro (BCM) rule,
// catastrophic forgetting literature (Kirkpatrick et al., EWC-analog reference
// only; EWC-analog is not literal Fisher EWC over Aimos memories).
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import { getBlockCapacityAll, getBlockCapacity as scaleBlockCapacity } from '../shared/scale-baseline.js';

const COMPANY = AIMOS_COMPANY_ID;

// Memory count thresholds for plasticity levels
const LOW_PLASTICITY_THRESHOLD = 50;    // >50 memories in domain → low plasticity
const MEDIUM_PLASTICITY_THRESHOLD = 10; // 10-50 → medium

// Prediction error rate thresholds
const HIGH_ERROR_THRESHOLD = 0.6;       // >60% error rate → re-open plasticity
const SHIFT_THRESHOLD = 0.45;           // Error spike above this triggers domain shift

// Learning strength multipliers per plasticity level
const LEARNING_MULTIPLIERS = Object.freeze({
  high: 1.0,
  medium: 0.5,
  low: 0.15,
});

// Per-domain prediction error history (process-scoped cache)
// domain:companyId → { errors: number[], lastUpdated: number }
const _predictionErrorHistory = new Map();

/**
 * Build a cache key for the domain + company combination.
 *
 * @param {string} domain
 * @param {string} companyId
 * @returns {string}
 */
function domainKey(domain, companyId) {
  return `${String(companyId || COMPANY)}:${String(domain || 'default')}`;
}

/**
 * Record a new prediction error observation for a domain.
 * Used by track-error callers to maintain the per-domain history.
 *
 * @param {string} domain
 * @param {number} error - 0 (correct) to 1 (completely wrong)
 * @param {string} [companyId]
 */
export function recordPredictionError(domain, error, companyId) {
  const key = domainKey(domain, companyId);
  const clamped = Math.max(0, Math.min(1, Number(error) || 0));

  if (!_predictionErrorHistory.has(key)) {
    _predictionErrorHistory.set(key, { errors: [], lastUpdated: Date.now() });
  }

  const entry = _predictionErrorHistory.get(key);
  entry.errors.push(clamped);
  entry.lastUpdated = Date.now();

  // Keep last 50 observations to avoid unbounded memory growth
  if (entry.errors.length > 50) {
    entry.errors.splice(0, entry.errors.length - 50);
  }
}

/**
 * Get the current prediction error rate for a domain from in-memory history.
 * Falls back to 0.5 if no history is available.
 *
 * @param {string} domain
 * @param {string} [companyId]
 * @returns {number} Average prediction error rate (0-1)
 */
function getPredictionErrorRate(domain, companyId) {
  const key = domainKey(domain, companyId);
  const entry = _predictionErrorHistory.get(key);
  if (!entry || entry.errors.length === 0) return 0.5; // unknown domain → moderate assumption
  const sum = entry.errors.reduce((acc, v) => acc + v, 0);
  return sum / entry.errors.length;
}

/**
 * Determine the plasticity level for a domain based on memory count and
 * prediction error history.
 *
 * @param {string} domain - Domain identifier (e.g. 'finance', 'legal', 'code')
 * @param {string} [companyId]
 * @returns {Promise<{plasticity: 'high'|'medium'|'low', reason: string, predictionErrorRate: number}>}
 */
export async function getDomainPlasticity(domain, companyId) {
  const cid = companyId || COMPANY;
  const domainPattern = `%${String(domain || '').trim()}%`;

  let memoryCount = 0;
  try {
    const result = await query(
      `SELECT COUNT(*) AS cnt
       FROM aimos_memories
       WHERE company_id = $1
         AND (key ILIKE $2 OR value::text ILIKE $2)`,
      [cid, domainPattern]
    );
    memoryCount = parseInt(result.rows[0]?.cnt || 0, 10);
  } catch (err) {
    console.error('[plasticity-controller] getDomainPlasticity DB error:', err.message);
    memoryCount = 0;
  }

  const predictionErrorRate = getPredictionErrorRate(domain, cid);

  let plasticity;
  let reason;

  if (memoryCount > LOW_PLASTICITY_THRESHOLD && predictionErrorRate < HIGH_ERROR_THRESHOLD) {
    plasticity = 'low';
    reason = `Established domain (${memoryCount} memories, error_rate=${predictionErrorRate.toFixed(2)}) — resist overwriting`;
  } else if (memoryCount >= MEDIUM_PLASTICITY_THRESHOLD) {
    plasticity = 'medium';
    reason = `Developing domain (${memoryCount} memories, error_rate=${predictionErrorRate.toFixed(2)}) — balanced learning`;
  } else {
    plasticity = 'high';
    reason = `New domain (${memoryCount} memories, error_rate=${predictionErrorRate.toFixed(2)}) — fast acquisition`;
  }

  // Override: high prediction error always opens plasticity
  if (predictionErrorRate >= HIGH_ERROR_THRESHOLD && plasticity === 'low') {
    plasticity = 'medium';
    reason += ` [OVERRIDE: high error rate ${predictionErrorRate.toFixed(2)} re-opened plasticity]`;
  }

  return { plasticity, reason, predictionErrorRate };
}

/**
 * Detect whether a domain shift has occurred by checking if recent prediction
 * errors spike significantly above the historical baseline.
 *
 * A domain shift re-opens plasticity even in well-established domains.
 *
 * @param {string} domain
 * @param {number[]} recentPredictionErrors - Array of recent error values (0-1)
 * @param {string} [companyId]
 * @returns {boolean} True if a domain shift is detected
 */
export function detectDomainShift(domain, recentPredictionErrors, companyId) {
  if (!Array.isArray(recentPredictionErrors) || recentPredictionErrors.length === 0) {
    return false;
  }

  const cid = companyId || COMPANY;
  const key = domainKey(domain, cid);
  const history = _predictionErrorHistory.get(key);

  // No historical baseline — cannot detect shift
  if (!history || history.errors.length < 5) return false;

  // Compute historical baseline (exclude last N observations)
  const baselineErrors = history.errors.slice(0, Math.max(1, history.errors.length - recentPredictionErrors.length));
  const baselineRate = baselineErrors.reduce((acc, v) => acc + v, 0) / baselineErrors.length;

  // Recent error rate
  const recentRate = recentPredictionErrors.reduce((acc, v) => acc + v, 0) / recentPredictionErrors.length;

  // Domain shift: recent error rate significantly exceeds baseline
  const shift = (recentRate - baselineRate) > SHIFT_THRESHOLD;

  if (shift) {
    console.warn(
      `[plasticity-controller] Domain shift detected for '${domain}': ` +
      `baseline=${baselineRate.toFixed(2)}, recent=${recentRate.toFixed(2)}`
    );
  }

  return shift;
}

/**
 * Modulate the base learning strength by the current plasticity level.
 *
 * @param {number} baseLearning - Base learning strength (0-1)
 * @param {'high'|'medium'|'low'} plasticity - From getDomainPlasticity()
 * @returns {number} Adjusted learning strength (0-1)
 */
export function modulateLearningStrength(baseLearning, plasticity) {
  const base = Math.max(0, Math.min(1, Number(baseLearning) || 0.5));
  const multiplier = LEARNING_MULTIPLIERS[plasticity] ?? LEARNING_MULTIPLIERS.medium;
  return Math.min(1.0, base * multiplier);
}

// ─── BATCH 10 LANE 2: BLOCK CAPACITY + WRITE STRENGTH (G-MemLLM, M+) ──────
// Papers: G-MemLLM, M+
// write_strength = plasticity_level * gate_confidence
// block_capacity(level) = {L1:100, L2:50, L3:30, L4:10, L5:5}
// evict_candidate = lowest_trust_block when capacity exceeded
// Aladdin: Block eviction suppresses from context window, never deletes from Aimos.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Block capacity constraints per level.
 * L1 (short-term): 100 blocks, L2 (working): 50, L3 (episodic): 30,
 * L4 (semantic): 10, L5 (long-term): 5
 *
 * Scale-adaptive: Use getBlockCapacityAll(memoryCount) for dynamic scaling.
 * At N=14000, returns identical values.
 */
export const BLOCK_CAPACITY = Object.freeze({
  L1: 100,  // Short-term memory
  L2: 50,   // Working memory
  L3: 30,   // Episodic memory
  L4: 10,   // Semantic memory
  L5: 5,    // Long-term memory
});

/**
 * Get scale-adaptive block capacity for a given memory count.
 * Paper: G-MemLLM, M+
 * BLOCK_CAPACITY(L, N) = floor(BASE_CAPACITY[L] * max(1, sqrt(N/14000)))
 * At 14K: unchanged. At 50K: ~1.89x. At 100K: ~2.67x.
 *
 * @param {number} [memoryCount] - Override memory count (defaults to cached/baseline)
 * @returns {Object} { L1, L2, L3, L4, L5 }
 */
export function getScaleAdaptiveBlockCapacity(memoryCount) {
  return getBlockCapacityAll(memoryCount);
}

/**
 * Compute write strength as product of plasticity level and gate confidence.
 * write_strength = plasticity_level * gate_confidence
 *
 * @param {'high'|'medium'|'low'} plasticity - From getDomainPlasticity()
 * @param {number} gateConfidence - Confidence score from RPE/MVS gate (0-1)
 * @returns {{ write_strength: number, plasticity_level: number, gate_confidence: number }}
 */
export function computeWriteStrength(plasticity, gateConfidence) {
  const plasticityLevel = LEARNING_MULTIPLIERS[plasticity] ?? 0.5;
  const confidence = Math.max(0, Math.min(1, Number(gateConfidence) || 0.5));
  const writeStrength = plasticityLevel * confidence;

  return {
    write_strength: Number(writeStrength.toFixed(6)),
    plasticity_level: plasticityLevel,
    gate_confidence: confidence,
  };
}

/**
 * Select eviction candidate from blocks when capacity is exceeded.
 * Eviction only suppresses from context window — never deletes from Aimos.
 * Scale-adaptive: capacity grows with memory count via getBlockCapacityAll().
 *
 * @param {Array<{id: string, level: string, trust_score: number}>} blocks - Current blocks
 * @param {Object} trustScores - Map of block ID to trust score
 * @param {Object} [options] - { memoryCount } for scale-adaptive capacity
 * @returns {{ evict_candidate: string|null, reason: string, aladdin_compliant: boolean }}
 */
export function selectEvictionCandidate(blocks, trustScores = {}, options = {}) {
  if (!Array.isArray(blocks) || blocks.length === 0) {
    return { evict_candidate: null, reason: 'no_blocks', aladdin_compliant: true };
  }

  // Use scale-adaptive capacity if memoryCount provided, else hardcoded baseline
  const capacities = options.memoryCount
    ? getBlockCapacityAll(options.memoryCount)
    : BLOCK_CAPACITY;

  // Group blocks by level and check capacity
  const levelCounts = {};
  for (const block of blocks) {
    const level = block.level || 'L3';
    levelCounts[level] = (levelCounts[level] || 0) + 1;
  }

  // Find over-capacity levels
  for (const [level, count] of Object.entries(levelCounts)) {
    const capacity = capacities[level] || BLOCK_CAPACITY.L3;
    if (count > capacity) {
      // Eviction: select lowest-trust block at this level
      const candidatesAtLevel = blocks.filter(b => (b.level || 'L3') === level);
      const sortedByTrust = candidatesAtLevel.sort((a, b) => {
        const trustA = Number(a.trust_score) || Number(trustScores[a.id]) || 0.5;
        const trustB = Number(b.trust_score) || Number(trustScores[b.id]) || 0.5;
        return trustA - trustB;
      });

      const candidate = sortedByTrust[0];
      return {
        evict_candidate: candidate?.id || null,
        reason: `capacity_exceeded_at_${level}`,
        level,
        count,
        capacity,
        block_trust: Number(candidate?.trust_score) || 0.5,
        aladdin_compliant: true, // Eviction only suppresses from context, never deletes
      };
    }
  }

  return { evict_candidate: null, reason: 'within_capacity', aladdin_compliant: true };
}

/**
 * Compute plasticity for a given memory type (used in pipeline integration).
 *
 * @param {string} memoryType - Aimos memory type
 * @param {number} [predictionError=0.5] - Recent prediction error rate
 * @returns {Promise<{plasticity: string, write_strength: number, block_level: string}>}
 */
export async function computePlasticity(memoryType, predictionError = 0.5) {
  const { plasticity, reason } = await getDomainPlasticity(memoryType);
  const gateConfidence = 1 - (predictionError || 0.5); // Higher error → lower confidence
  const { write_strength } = computeWriteStrength(plasticity, gateConfidence);

  // Map plasticity to block level
  const blockLevel = plasticity === 'high' ? 'L1' : plasticity === 'medium' ? 'L3' : 'L5';

  return {
    plasticity,
    write_strength,
    block_level: blockLevel,
    reason,
  };
}
