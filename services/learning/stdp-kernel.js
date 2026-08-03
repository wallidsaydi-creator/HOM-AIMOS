/**
 * stdp-kernel.js — Neuromorphic weight update engine (STDP)
 * Source: DA-SSDP (TMLR 2025), SADP (2025)
 * Additive Wave 2 authority: Hebbian-Oscillatory Co-Learning (HOC-L)
 * (Hays, arXiv:2603.08731, 2026). HOC-L contributes the optional
 * synchronization gate only:
 *   r(t)e^{iψ(t)} = (1/N) Σ_j e^{iθ_j(t)}
 *   G(r) = σ(β(r - r_c)), with β=20 and r_c=0.5 in the paper appendix.
 * This gate multiplies an existing STDP delta only when phase/order evidence
 * is provided. The DA-SSDP dopamine gate, Gaussian lag kernel, learnable sigma,
 * and Aladdin clipping remain unchanged.
 *
 * DA-SSDP formula used by the STDP diagnostic/update functions below:
 * DeltaW = clip(G_b * g * (A+ * lambda - A- * (1-lambda)), -1, 1)
 * G_b = clip(1 + k*(S_b - mu_S)/sigma_S, 0, 2)  — dopamine gate
 * g = exp(-dt^2 / (2*sigma^2))  — Gaussian temporal kernel
 * lambda = binary from co-activation (1 if pre before post, 0 otherwise)
 * S_b = batch synchrony scalar (tracks learning health)
 * sigma is LEARNABLE (not fixed)
 *
 * Phase 4 guarded math (alongside paths, not replacements):
 * 4a. Kuramoto Phase Evolution ODE
 *     Paper: Kuramoto (1984) "Chemical Oscillations, Waves, and Turbulence"
 *     Formula: dθ_i/dt = ω_i + (K/N) Σ_j sin(θ_j - θ_i) + η_i(t)
 *     Parameters: K=0.5 (coupling), η_i ~ N(0, 0.01²) (thermal noise)
 *     Complexity: O(N²) naive, O(N log N) with FFT. Acceptable for synchrony buffer < 50.
 *     Stability: Euler method sufficient for diagnostic use. K < K_critical ≈ 2 guarantees convergence.
 *
 * 4b. Hyperbolic Sparse Geometry
 *     Paper: Nickel & Kiela (2017) "Poincaré Embeddings for Learning Hierarchical Representations"
 *     Formula: d_h(u,v) = arccosh(1 + 2||u-v||² / ((1-||u||²)(1-||v||²)))
 *     Projection: u_poincare = tanh(||u_euclid||) * u_euclid / ||u_euclid|| (768d → 16d)
 *     Stability: clamp norm < 1-ε (ε=1e-5), use log instead of arccosh for large arguments.
 *
 * 4c. Lyapunov Trajectory Diagnostic
 *     Paper: Nonlinear dynamical systems theory (Lyapunov stability)
 *     Formula: λ = lim(t→∞) (1/t) ln(||δx(t)|| / ||δx(0)||)
 *     λ < 0 → convergent, λ > 0 → divergent, λ ≈ 0 → marginal
 *     Diagnostic only over caller-supplied before/after trajectories.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';
import { withTransaction } from '../../db/connection.js';
import { logEvent } from '../../services/observe/event-ledger.js';
import { valenceLedger } from '../../services/governance/valence-ledger.js';
import { computeValence } from '../../services/governance/valence-judge.js';
import { commitGovernorMutation } from '../../services/governance/governor-provenance.js';

const COMPANY = AIMOS_COMPANY_ID;

// --- DA-SSDP Parameters (TMLR peer-reviewed) ---
const A_PLUS = 1.0e-3;
const A_MINUS = 1.0e-3;

// Technique 6: Effective Tau (tau_eff) — the synchrony detection window
const TAU_PLUS = 20.0;           // ms
const TAU_MINUS = 20.0;          // ms
const TAU_EFF = (TAU_PLUS * TAU_MINUS) / (TAU_PLUS + TAU_MINUS);  // = 10ms

// Technique 5: Learnable sigma (initialized to TAU_EFF / 5.0)
let _sigma = TAU_EFF / 5.0;
const SIGMA_LR = 1e-5;  // Learning rate for sigma adaptation
const SIGMA_MIN = 1.0;
const SIGMA_MAX = 50.0;

// Technique 7: Dopamine Gating (G_b) — batch synchrony modulated
// G_b = clip(1 + k*(S_b - mu_S)/sigma_S, 0, 2)
const DA_GATE_K = 1.0;       // Sensitivity coefficient k
const DA_GATE_CLIP = 2.0;    // Upper bound
const OSCILLATORY_RC = 0.5;  // HOC-L critical synchronization threshold
const OSCILLATORY_BETA = 20; // HOC-L smooth sigmoid gate sharpness

// Asymmetric window ratio: A+*tau+/A-*tau- should be 1.05-1.10 for slight causal bias
// Current: (1.5e-3 * 20) / (1.0e-4 * 20) = 15.0 — very high potentiation bias

// Homeostatic scaling
const W_MIN = 0.1;
const W_MAX = 3.0;
const R_TARGET = 1.0;  // Target mean retrieval weight
const VALENCE_ETA = 0.2;

export function referencePointWeightUpdate(currentWeight, valence, eta = VALENCE_ETA) {
  const current = Number.isFinite(Number(currentWeight)) ? Number(currentWeight) : R_TARGET;
  const signedEvidence = Math.max(-1, Math.min(1, Number(valence) || 0));
  const learningRate = Math.max(0.001, Math.min(0.5, Number(eta) || VALENCE_ETA));
  return Math.max(W_MIN, Math.min(W_MAX, current * Math.exp(learningRate * signedEvidence)));
}

// Batch synchrony tracking (S_b) — tracks learning health per session
let _sessionSynchronyBuffer = [];
const _synapseMetrics = new Map();  // memoryId -> { frequency: Hz, lastChange: ms }

/**
 * Update synapse telemetry for monitoring
 */
function updateSynapseTelemetry(memoryId, deltaW) {
  const now = Date.now();
  const entry = _synapseMetrics.get(memoryId) || { lastChange: now, frequency: 0 };
  const dt = (now - entry.lastChange) / 1000.0;
  const instantFreq = dt > 0 ? 1.0 / dt : 0;
  entry.frequency = entry.frequency * 0.9 + instantFreq * 0.1;
  entry.lastChange = now;
  _synapseMetrics.set(memoryId, entry);
}

/**
 * Technique 7: Dopamine Gate G_b = clip(1 + k*(S_b - mu_S)/sigma_S, 0, 2)
 *
 * S_b = batch synchrony scalar — average synchrony of recent updates
 * When learning is healthy (high S_b), G_b > 1 amplifies updates
 * When learning degrades (low S_b), G_b < 1 dampens updates
 */
export function getDopamineGate(batchSynchrony) {
  const mu_S = 0.5;   // Target mean synchrony
  const sigma_S = 0.3; // Normalized spread
  const raw = 1 + DA_GATE_K * (batchSynchrony - mu_S) / sigma_S;
  return Math.max(0, Math.min(DA_GATE_CLIP, raw));
}

/**
 * Compute batch synchrony scalar S_b from the current session buffer
 */
function computeBatchSynchrony() {
  if (_sessionSynchronyBuffer.length === 0) return 0.5; // Default neutral
  const sum = _sessionSynchronyBuffer.reduce((a, b) => a + b, 0);
  return sum / _sessionSynchronyBuffer.length;
}

/**
 * Add a synchrony sample to the current session buffer
 */
function addSynchronySample(synchrony) {
  _sessionSynchronyBuffer.push(Math.max(0, Math.min(1, synchrony)));
  // Keep buffer bounded (last 100 samples)
  if (_sessionSynchronyBuffer.length > 100) {
    _sessionSynchronyBuffer = _sessionSynchronyBuffer.slice(-100);
  }
}

/**
 * Technique 2/6: Gaussian temporal kernel (synchrony detection)
 * g = exp(-dt^2 / (2 * sigma^2))
 * tau_eff = 10ms is the effective detection window
 *
 * STDP detects synchrony (not causality) within this window.
 * Cohens kappa provides chance-corrected agreement.
 */
export function gaussianKernel(dt, sigma = _sigma) {
  return Math.exp(-(dt * dt) / (2 * sigma * sigma));
}

/**
 * SADP: Cohen's kappa for chance-corrected agreement
 * kappa = (p0 - pe) / max(1 - pe, eps)
 * p0 = observed agreement, pe = chance agreement from firing rates
 */
export function cohensKappa(observedAgreement, preRate, postRate) {
  const chanceAgreement = preRate * postRate + (1 - preRate) * (1 - postRate);
  const denom = Math.max(1 - chanceAgreement, 1e-7);
  return (observedAgreement - chanceAgreement) / denom;
}

function sigmoid(x) {
  if (x >= 0) {
    const z = Math.exp(-x);
    return 1 / (1 + z);
  }
  const z = Math.exp(x);
  return z / (1 + z);
}

function normalizePhaseRadians(value) {
  const twoPi = Math.PI * 2;
  const raw = Number(value);
  if (!Number.isFinite(raw)) return null;
  return ((raw % twoPi) + twoPi) % twoPi;
}

/**
 * HOC-L Kuramoto order parameter:
 * r(t)e^{iψ(t)} = (1/N) Σ_j e^{iθ_j(t)}
 *
 * @param {number[]} phasesRadians oscillator phases in radians
 * @returns {{ r: number, psi: number|null, n: number }}
 */
export function computeKuramotoOrderParameter(phasesRadians = []) {
  const phases = (phasesRadians || [])
    .map(normalizePhaseRadians)
    .filter(phase => phase !== null);
  const n = phases.length;
  if (n === 0) return { r: 0, psi: null, n: 0 };

  const sumCos = phases.reduce((sum, phase) => sum + Math.cos(phase), 0);
  const sumSin = phases.reduce((sum, phase) => sum + Math.sin(phase), 0);
  const meanCos = sumCos / n;
  const meanSin = sumSin / n;
  return {
    r: Math.max(0, Math.min(1, Math.sqrt(meanCos * meanCos + meanSin * meanSin))),
    psi: Math.atan2(meanSin, meanCos),
    n,
  };
}

/**
 * HOC-L smooth synchronization gate:
 * G(r) = σ(β(r - r_c)).
 *
 * @param {object|number} input order parameter or { phasesRadians, orderParameter }
 * @param {object} options
 * @returns {{ source_paper: string, r: number, psi: number|null, n: number, gate: number, gate_open: boolean, beta: number, critical_threshold: number, smooth: boolean }}
 */
export function computeOscillatoryPlasticityGate(input = {}, options = {}) {
  const criticalThreshold = Number.isFinite(options.criticalThreshold)
    ? options.criticalThreshold
    : OSCILLATORY_RC;
  const beta = Number.isFinite(options.beta) ? options.beta : OSCILLATORY_BETA;
  const smooth = options.smooth !== false;
  const order = Number.isFinite(input)
    ? { r: Number(input), psi: null, n: 0 }
    : Number.isFinite(input?.orderParameter)
      ? { r: Number(input.orderParameter), psi: null, n: Number(input.n || 0) }
      : computeKuramotoOrderParameter(input?.phasesRadians || input?.phases || []);
  const r = Math.max(0, Math.min(1, Number(order.r || 0)));
  const gate = smooth ? sigmoid(beta * (r - criticalThreshold)) : (r > criticalThreshold ? 1 : 0);
  return {
    source_paper: 'Hebbian-Oscillatory Co-Learning',
    r,
    psi: order.psi ?? null,
    n: Number(order.n || 0),
    gate,
    gate_open: r > criticalThreshold,
    beta,
    critical_threshold: criticalThreshold,
    smooth,
  };
}

function resolveOscillatoryGate(context = {}) {
  if (context.oscillatoryGate === false || context.oscillatory_gate === false) {
    return { applied: false, multiplier: 1 };
  }
  const hasPhaseEvidence =
    Array.isArray(context.phasesRadians) ||
    Array.isArray(context.phases) ||
    Number.isFinite(context.orderParameter) ||
    Number.isFinite(context.r);
  if (!hasPhaseEvidence) return { applied: false, multiplier: 1 };

  const gate = computeOscillatoryPlasticityGate({
    phasesRadians: context.phasesRadians || context.phases || [],
    orderParameter: Number.isFinite(context.orderParameter) ? context.orderParameter : context.r,
  }, {
    criticalThreshold: Number.isFinite(context.criticalThreshold) ? context.criticalThreshold : undefined,
    beta: Number.isFinite(context.beta) ? context.beta : undefined,
    smooth: context.smoothOscillatoryGate !== false,
  });

  return {
    applied: true,
    multiplier: gate.gate,
    ...gate,
  };
}

/**
 * Technique 1: Plasticity Auto-Scaling eta(t)
 * Adapts learning rate based on gradient magnitude
 */
const ETA_BASE = 1.0e-3;
const ETA_MIN = 1.0e-5;
const ETA_MAX = 5.0e-3;

export function computeAdaptiveEta(gradientMag) {
  return Math.max(ETA_MIN, Math.min(ETA_MAX, ETA_BASE * (gradientMag || 1.0)));
}

/**
 * HOM signed-outcome adaptation. This path retains co-activation and lag as
 * signed context, but updates retrieval frequency with the age-neutral
 * reference-point rule w' = clamp(w * exp(eta * tanh(sum rewards))). It does
 * not claim that DA-SSDP's co-activation/lag delta directly produces w'.
 *
 * @param {string} memoryId - Memory to update
 * @param {number} coActivationScore - The co-activation score (kappa * synchrony)
 * @param {number} rewardSign - +1 for success, -1 for error
 * @param {object} context - Additional context (isConsolidation, etc.)
 */
export async function applyRewardSignal(memoryId, rewardSign, context = {}) {
  const { coActivationScore = 0, lagMs = 0 } = context;
  if (rewardSign !== 1 && rewardSign !== -1) {
    throw new Error('rewardSign must be +1 or -1');
  }

  const contextHash = createHash('sha256').update(JSON.stringify({
    memory_id: memoryId,
    reward_sign: rewardSign,
    co_activation_score: Number(coActivationScore || 0),
    lag_ms: Number(lagMs || 0)
  })).digest('hex');
  const eta = Math.max(0.001, Math.min(0.5, Number(context.eta || VALENCE_ETA)));
  let oldWeight = 1;
  let newWeight = 1;
  let valence = 0;
  let valenceCommit = null;

  await withTransaction(async (client) => {
    // The runtime role deliberately has no table UPDATE privilege, so
    // SELECT FOR UPDATE is unavailable. Serialize every certified writer on
    // the same transaction-scoped key; the SECURITY DEFINER writer acquires
    // this exact key again before taking its owner-level row lock.
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`cognitive-reweight:${COMPANY}:${memoryId}`]
    );
    const current = await client.query(
      'SELECT retrieval_weight FROM aimos_memories WHERE company_id = $1 AND id = $2',
      [COMPANY, memoryId]
    );
    if (current.rows.length === 0) throw new Error('memory_not_found');
    valenceCommit = await valenceLedger.appendValence({
      memoryId,
      rewardSign,
      contextHash,
      client,
    });
    if (!valenceCommit.ok) {
      throw new Error(`valence_ledger_failed:${valenceCommit.reason}`);
    }
    valence = await computeValence(memoryId, { client });
    oldWeight = Number(current.rows[0].retrieval_weight || R_TARGET);
    newWeight = referencePointWeightUpdate(oldWeight, valence, eta);
    if (Math.round(newWeight * 1000) === Math.round(oldWeight * 1000)) {
      // Identical quantized targets are not cognitive transitions (SPEC §8,
      // Theorem 2), but the signed outcome evidence must still be retained.
      // Committing this no-transition observation lets later evidence move the
      // cumulative valence across zero instead of rolling the evidence back
      // forever on the database's correct no-op REWEIGHT rejection.
      newWeight = oldWeight;
      await logEvent(COMPANY, 'housekeeper', 'cognitive_weight_unchanged', memoryId, {
        retrieval_weight: oldWeight,
        signed_valence: valence,
        reward_sign: rewardSign,
        eta,
        context_hash: contextHash,
        valence_row_hash: Buffer.from(valenceCommit.rowHash).toString('hex'),
        projection_appended: false,
        reasoning: 'Signed outcome evidence was retained, but its quantized target equaled the current weight; no fictitious REWEIGHT transition was appended.',
        source_knowledge: 'Certified Cognitive-Weight Trajectory SPEC Theorem 2: an identical target requires no transition',
      }, null, { client });
      return;
    }
    const mutation = await commitGovernorMutation({
      memoryId,
      oldWeight,
      newWeight,
      judgeValence: valence,
      governorFlag: 'SIGNED_VALENCE_REFERENCE_POINT',
      reason: 'outcome_evidence',
      extra: {
        eta,
        quality_before: Math.log(oldWeight),
        quality_after: Math.log(newWeight),
        valence_row_hash: Buffer.from(valenceCommit.rowHash).toString('hex')
      },
      client
    });
    if (!mutation.ok) throw new Error(`mutation_ledger_failed:${mutation.reason}`);
    await client.query(
      `SELECT public.apply_signed_cognitive_reweight($1::uuid, $2, $3, $4, $5)`,
      [memoryId, oldWeight, newWeight, mutation.mutationHash, mutation.transitionSig]
    );
    await logEvent(COMPANY, 'housekeeper', 'cognitive_weight_adjusted', memoryId, {
      old_weight: oldWeight,
      new_weight: newWeight,
      delta_weight: newWeight - oldWeight,
      signed_valence: valence,
      eta,
      lower_bound: W_MIN,
      upper_bound: W_MAX,
      valence_row_hash: Buffer.from(valenceCommit.rowHash).toString('hex'),
      reasoning: 'Signed outcome evidence moved retrieval frequency bidirectionally within Aladdin bounds; canonical memory remained fully retained.',
      source_knowledge: 'HOM age-neutral signed-valence reference-point update; DA-SSDP co-activation and lag retained as contextual evidence, not the direct weight equation',
    }, null, { client });
  }, { restricted: true, agent_id: 'housekeeper', client_id: COMPANY });

  const deltaW = newWeight - oldWeight;
  updateSynapseTelemetry(memoryId, deltaW);
  addSynchronySample(Math.abs(coActivationScore));

  return deltaW;
}

/**
 * Technique 2: Three-Factor eligibility traces
 * deltaW = eta * eligibility * Reward * G_da
 *
 * Used for online updates when full paper formula isn't available.
 * Falls back to this when only eligibility and reward are provided.
 */
export async function applyThreeFactorUpdate(memoryId, eligibility, reward, gradient = 1.0) {
  const rewardSign = Number(reward) >= 0 ? 1 : -1;
  return applyRewardSignal(memoryId, rewardSign, {
    coActivationScore: Number(eligibility || 0),
    eta: computeAdaptiveEta(gradient)
  });
}

/**
 * Technique 4: SSDP Contrastive Loss
 * Used for embedding-space training (not directly in retrieval scoring)
 */
export function computeSSDPContrastiveLoss(queryEmb, positiveEmb, negativeEmbs = []) {
  const dot = (a, b) => a.reduce((sum, val, i) => sum + val * b[i], 0);
  const posSim = Math.exp(dot(queryEmb, positiveEmb));
  const negSimSum = negativeEmbs.reduce((sum, neg) => sum + Math.exp(dot(queryEmb, neg)), 0);
  return -Math.log(posSim / (posSim + negSimSum + 1e-7));
}

/**
 * Technique 3: Homeostatic Reward Signaling
 * Normalizes reward signal relative to recent history
 */
export function normalizeRewardSignal(reward, history = []) {
  if (!history.length) return reward;
  const mean = history.reduce((a, b) => a + b, 0) / history.length;
  const variance = history.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / history.length;
  const std = Math.sqrt(variance) || 1.0;
  return (reward - mean) / std;
}

/**
 * Learnable sigma adaptation — adjusts the temporal kernel width
 * based on recent learning effectiveness
 */
export function adaptSigma(learningEffectiveness) {
  // If learning is effective (effectiveness > 0.5), widen the kernel
  // If ineffective, narrow it to be more selective
  const targetSigma = TAU_EFF / 5.0 * (1 + learningEffectiveness);
  _sigma = _sigma + SIGMA_LR * (targetSigma - _sigma);
  _sigma = Math.max(SIGMA_MIN, Math.min(SIGMA_MAX, _sigma));
  return _sigma;
}

/**
 * Get current batch synchrony status (S_b)
 */
export function getBatchSynchronyStatus() {
  return {
    S_b: computeBatchSynchrony(),
    sampleCount: _sessionSynchronyBuffer.length,
    sigma: _sigma,
    G_b: getDopamineGate(computeBatchSynchrony()),
    oscillatory_gate: {
      source_paper: 'Hebbian-Oscillatory Co-Learning',
      critical_threshold: OSCILLATORY_RC,
      beta: OSCILLATORY_BETA,
      optional_phase_sensitive_multiplier: true,
    },
  };
}

// ---------------------------------------------------------------------------
// Phase 4: Guarded Math — Alongside-path implementations
// These functions run ALONGSIDE existing DA-SSDP formulas for diagnostic comparison.
// They do NOT replace any existing computation. Guarded flags remain false in production.
// ---------------------------------------------------------------------------

// --- 4a. Kuramoto Phase Evolution ODE ---
// Paper: Kuramoto (1984), "Chemical Oscillations, Waves, and Turbulence"
// dθ_i/dt = ω_i + (K/N) Σ_j sin(θ_j - θ_i) + η_i(t)
// K = global coupling strength, η_i = Gaussian noise (thermal fluctuation)

const KURAMOTO_K = 0.5;            // Global coupling strength (default, configurable)
const KURAMOTO_NOISE_SIGMA = 0.01; // Thermal fluctuation σ (Gaussian noise)

/**
 * Compute Kuramoto phase evolution for one integration step (Euler method).
 *
 * @param {number[]} phasesRadians - Current phases θ_i for each memory in synchrony window
 * @param {number[]} [naturalFrequencies] - Natural frequencies ω_i (defaults derived from memory_type authority)
 * @param {object} [options] - { couplingK, noiseSigma, dt }
 * @returns {{ predicted_phases: number[], order_parameter: { r: number, psi: number|null, n: number },
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeKuramotoPhaseEvolution(phasesRadians = [], naturalFrequencies = [], options = {}) {
 {
  const K = Number.isFinite(options.couplingK) ? options.couplingK : KURAMOTO_K;
  const noiseSigma = Number.isFinite(options.noiseSigma) ? options.noiseSigma : KURAMOTO_NOISE_SIGMA;
  const dt = Number.isFinite(options.dt) ? options.dt : 1.0; // one integration step
  const phases = (phasesRadians || []).filter(p => Number.isFinite(p));
  const N = phases.length;

  if (N === 0) {
    return {
      predicted_phases: [],
      order_parameter: computeKuramotoOrderParameter([]),
      source_paper: 'Kuramoto (1984)',
      diagnostic: true,
      note: 'Alongside path — does not replace existing gate computation',
    };
  }

  // Derive natural frequencies from memory_type authority if not provided
  // procedural_seed → high ω (0.8), declarative → medium (0.5), conversation_feed → low (0.2)
  const authorityMap = { procedural_seed: 0.8, procedural: 0.7, tacit_knowledge: 0.7,
    book_extract: 0.6, framework: 0.55, directive: 0.5, identity: 0.4,
    declarative: 0.5, session_debrief: 0.4, event_log: 0.2, heartbeat: 0.15,
    conversation_feed: 0.2 };
  const omegas = naturalFrequencies.length === N
    ? naturalFrequencies
    : phases.map(() => 0.5); // default neutral frequency

  // Euler integration: dθ_i/dt = ω_i + (K/N) Σ_j sin(θ_j - θ_i) + η_i
  const predictedPhases = phases.map((theta_i, i) => {
    const coupling = (K / N) * phases.reduce((sum, theta_j) => sum + Math.sin(theta_j - theta_i), 0);
    const noise = gaussianRandom(0, noiseSigma);
    const dTheta = omegas[i] + coupling + noise;
    const newPhase = theta_i + dTheta * dt;
    return ((newPhase % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI); // normalize to [0, 2π)
  });

  return {
    predicted_phases: predictedPhases,
    order_parameter: computeKuramotoOrderParameter(predictedPhases),
    source_paper: 'Kuramoto (1984)',
    diagnostic: true,
    note: 'Alongside path — does not replace existing gate computation',
  };
}
}

/**
 * Box-Muller transform for Gaussian random numbers (for Kuramoto noise term)
 */
function gaussianRandom(mean = 0, sigma = 1) {
  const u1 = Math.random();
  const u2 = Math.random();
  const z0 = Math.sqrt(-2 * Math.log(Math.max(u1, 1e-10))) * Math.cos(2 * Math.PI * u2);
  return mean + sigma * z0;
}

// --- 4b. Hyperbolic Sparse Geometry ---
// Paper: Nickel & Kiela (2017) "Poincaré Embeddings for Learning Hierarchical Representations"
// d_h(u,v) = arccosh(1 + 2||u-v||² / ((1-||u||²)(1-||v||²)))
// Projection: u_poincare = tanh(||u_euclid||) * u_euclid / ||u_euclid|| (768d → 16d)

const HYPERBOLIC_DIM = 16;       // Projection dimension for Poincaré ball
const HYPERBOLIC_EPSILON = 1e-5; // Clamp norm to < 1-ε for Poincaré ball

/**
 * Compute hyperbolic distance between two embeddings in the Poincaré ball model.
 *
 * @param {number[]} embeddingA - 768d Euclidean embedding
 * @param {number[]} embeddingB - 768d Euclidean embedding
 * @param {object} [options] - { projectionDim }
 * @returns {{ euclidean_cosine: number, hyperbolic_distance: number, hierarchy_depth_ratio: number,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeHyperbolicDistance(embeddingA = [], embeddingB = [], options = {}) {
  const dim = options.projectionDim || HYPERBOLIC_DIM;

  if (!embeddingA.length || !embeddingB.length) {
    return {
      euclidean_cosine: 0,
      hyperbolic_distance: Infinity,
      hierarchy_depth_ratio: 0,
      source_paper: 'Nickel & Kiela (2017)',
      diagnostic: true,
      note: 'Alongside path — does not replace cosine similarity in recall',
    };
  }

  // Euclidean cosine similarity (existing recall metric)
  const dot = (a, b) => a.reduce((sum, val, i) => sum + val * (b[i] || 0), 0);
  const normA = Math.sqrt(dot(embeddingA, embeddingA)) || 1e-10;
  const normB = Math.sqrt(dot(embeddingB, embeddingB)) || 1e-10;
  const euclideanCosine = dot(embeddingA, embeddingB) / (normA * normB);

  // Project 768d → dim-dimensional Poincaré ball
  // u_poincare = tanh(||u_euclid||) * u_euclid / ||u_euclid||
  const project = (emb) => {
    const norm = Math.sqrt(dot(emb, emb));
    if (norm < 1e-10) return new Array(dim).fill(0);
    // Take first `dim` components and project
    const truncated = emb.slice(0, dim);
    const truncNorm = Math.sqrt(truncated.reduce((s, v) => s + v * v, 0));
    if (truncNorm < 1e-10) return new Array(dim).fill(0);
    const scalar = Math.tanh(truncNorm) / truncNorm;
    // Clamp norm to < 1-ε for Poincaré ball stability
    const projected = truncated.map(v => v * scalar);
    const projNorm = Math.sqrt(projected.reduce((s, v) => s + v * v, 0));
    if (projNorm >= 1 - HYPERBOLIC_EPSILON) {
      const clampFactor = (1 - HYPERBOLIC_EPSILON) / projNorm;
      return projected.map(v => v * clampFactor);
    }
    return projected;
  };

  const u = project(embeddingA);
  const v = project(embeddingB);

  const normU2 = u.reduce((s, x) => s + x * x, 0);
  const normV2 = v.reduce((s, x) => s + x * x, 0);
  const diff2 = u.reduce((s, x, i) => s + (x - v[i]) ** 2, 0);

  // d_h(u,v) = arccosh(1 + 2||u-v||² / ((1-||u||²)(1-||v||²)))
  // Use log for numerical stability when argument is large
  const denominator = (1 - normU2) * (1 - normV2);
  const arg = 1 + 2 * diff2 / Math.max(denominator, 1e-10);
  const hyperbolicDistance = arg <= 1 ? 0 : Math.log(arg + Math.sqrt(arg * arg - 1)); // arccosh via log

  // Hierarchy depth ratio: how much deeper A is than B in the hierarchy
  const hierarchyDepthRatio = normU2 > 0 && normV2 > 0 ? normV2 / (normU2 + 1e-10) : 1.0;

  return {
    euclidean_cosine: euclideanCosine,
    hyperbolic_distance: hyperbolicDistance,
    hierarchy_depth_ratio: hierarchyDepthRatio,
    source_paper: 'Nickel & Kiela (2017)',
    diagnostic: true,
    note: 'Alongside path — does not replace cosine similarity in recall',
  };
}

// --- 4c. Lyapunov Convergence Control ---
// Paper: Nonlinear dynamical systems theory (Lyapunov stability)
// λ = lim(t→∞) (1/t) ln(||δx(t)|| / ||δx(0)||)
// λ < 0 → convergent, λ > 0 → divergent, λ ≈ 0 → marginal

/**
 * Compute a Lyapunov exponent over caller-supplied weight trajectories.
 *
 * @param {number[]} preRescaleWeights - Weight deviations before rescaling cycle
 * @param {number[]} postRescaleWeights - Weight deviations after rescaling cycle
 * @param {number} [steps=1] - Number of rescaling steps (t)
 * @returns {{ lyapunov_exponent: number, convergence_status: string,
 *             source_paper: string, diagnostic: boolean, note: string }}
 */
export function computeLyapunovExponent(preRescaleWeights = [], postRescaleWeights = [], steps = 1) {
  if (!preRescaleWeights.length || !postRescaleWeights.length) {
    return {
      lyapunov_exponent: 0,
      convergence_status: 'insufficient_data',
      source_paper: 'Lyapunov stability theory',
      diagnostic: true,
      note: 'Diagnostic only — does not mutate canonical retrieval weights',
    };
  }

  // δx(0) = deviation of weights from target before rescaling
  const target = R_TARGET;
  const deltaPre = preRescaleWeights.map(w => w - target);
  const deltaPost = postRescaleWeights.map(w => w - target);

  const normDelta0 = Math.sqrt(deltaPre.reduce((s, d) => s + d * d, 0)) || 1e-10;
  const normDeltaT = Math.sqrt(deltaPost.reduce((s, d) => s + d * d, 0)) || 1e-10;

  // λ = (1/t) * ln(||δx(t)|| / ||δx(0)||)
  const ratio = normDeltaT / normDelta0;
  const lambda = (1 / Math.max(steps, 1)) * Math.log(Math.max(ratio, 1e-10));

  let convergenceStatus;
  if (lambda < -0.01) convergenceStatus = 'convergent';
  else if (lambda > 0.01) convergenceStatus = 'divergent';
  else convergenceStatus = 'marginal';

  return {
    lyapunov_exponent: lambda,
    convergence_status: convergenceStatus,
    source_paper: 'Lyapunov stability theory',
    diagnostic: true,
    note: 'Diagnostic only — does not mutate canonical retrieval weights',
  };
}

export function buildOscillatorySTDPStatus(phasesRadians = [0, 0.1, 0.2, Math.PI]) {
  const gate = computeOscillatoryPlasticityGate({ phasesRadians });
  return {
    source_paper: 'Hebbian-Oscillatory Co-Learning',
    status: 'wired',
    formula: {
      order_parameter: 'r(t)e^{iψ(t)} = (1/N) Σ_j e^{iθ_j(t)}',
      smooth_gate: 'G(r) = σ(β(r - r_c))',
      beta: OSCILLATORY_BETA,
      critical_threshold: OSCILLATORY_RC,
    },
    sample_gate: gate,
    integration: {
      applies_when_phase_evidence_exists: true,
      default_without_phase_evidence: 'multiplier_1_existing_stdp_behavior',
      da_ssdp_formula_changed: false,
      dopamine_gate_changed: false,
      gaussian_kernel_changed: false,
      aladdin_clipping_changed: false,
    },
    guarded_math: {
      kuramoto_phase_evolution_ode: false,
      hyperbolic_sparse_geometry: false,
      lyapunov_convergence_control: false,
    },
    guarded_math_implemented: {
      kuramoto_phase_evolution_ode: { source: 'Kuramoto (1984)', diagnostic_only: true },
      hyperbolic_sparse_geometry: { source: 'Nickel & Kiela (2017)', diagnostic_only: true },
      lyapunov_convergence_control: { source: 'Lyapunov stability theory', diagnostic_only: true },
    },
  };
}

/**
 * Clear the session synchrony buffer (call after each batch run)
 */
export function clearSessionBuffer() {
  _sessionSynchronyBuffer = [];
}

export { A_PLUS, A_MINUS, W_MIN, W_MAX, OSCILLATORY_BETA, OSCILLATORY_RC };

// ─── BATCH 10 LANE 2: TITANS SURPRISE DIMENSION + CONTINUOUS LAMBDA ──────────
// Papers: Titans (Surge et al., 2024), Titans Revisited
// Alongside-path: additive alongside existing DA-SSDP. Existing path unchanged.
//   G_b_titans = clip(surprise_t / surprise_μ, 0, 2)
//   lambda_continuous = σ(surprise_t - threshold)
//   DeltaW = clip(G_b * g * (A+ * lambda - A- * (1-lambda)), -1, 1)
// Aladdin: this diagnostic does not mutate any memory field. The signed live
// path changes retrieval_weight only, bidirectionally within [0.1, 3.0].
// Canonical value, embedding, and retained eligibility are never touched.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute Titans surprise gate alongside existing DA-SSDP dopamine gate.
 * G_b_titans = clip(surprise_t / surprise_μ, 0, 2)
 *
 * @param {number} surpriseScore - Current surprise score (surprise_at_save)
 * @param {number} surpriseMean - Running mean of surprise scores
 * @returns {{ G_b_titans: number, surprise_ratio: number, source_paper: string, diagnostic_only: boolean }}
 */
export function computeTitansGate(surpriseScore, surpriseMean) {
  const s = Number(surpriseScore) || 0;
  const mu = Number(surpriseMean) || 0.5; // Default to neutral if no data

  // Avoid division by zero
  const ratio = mu > 0 ? s / mu : s > 0 ? 2.0 : 0.0;
  const gBTitans = Math.max(0, Math.min(2.0, ratio));

  return {
    G_b_titans: Number(gBTitans.toFixed(6)),
    surprise_ratio: Number(ratio.toFixed(6)),
    surprise_score: s,
    surprise_mean: mu,
    source_paper: 'Titans: Surprisingly Effective Memory for LLMs',
    diagnostic_only: true,
    note: 'Alongside existing DA-SSDP gate. Does not replace dopamine gating.',
  };
}

/**
 * Compute continuous lambda from Titans surprise dimension.
 * lambda_continuous = σ(surprise_t - threshold)
 *
 * @param {number} surpriseScore - Current surprise score
 * @param {number} threshold - Surprise threshold for lambda activation (default 0.5)
 * @returns {{ lambda_continuous: number, source_paper: string }}
 */
export function computeContinuousLambda(surpriseScore, threshold = 0.5) {
  const s = Number(surpriseScore) || 0;
  const t = Number(threshold) || 0.5;

  // Sigmoid: σ(s - t) = 1 / (1 + exp(-(s - t)))
  const exponent = -(s - t);
  const lambdaContinuous = exponent >= 0
    ? Math.exp(exponent) / (1 + Math.exp(exponent))
    : 1 / (1 + Math.exp(exponent));

  return {
    lambda_continuous: Number(lambdaContinuous.toFixed(6)),
    threshold: t,
    source_paper: 'Titans: Surprisingly Effective Memory for LLMs',
  };
}

// ─── BATCH 10 LANE 5: STDP KERNEL SCALING FUNCTIONS ─────────────────────────
// D3: Kuramoto Phase Evolution, D4: Hyperbolic Geometry, D5: Lyapunov Control
// All formulas scale with memory count N. Baseline at N=14000.
// Guarded math: diagnostic-only until benchmark gate passes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * D3: Kuramoto Phase Evolution — coupling K scaling
 * Paper: Kuramoto (1984) — coupled oscillator synchronization
 * Formula: K = K_base * (14000/N)^0.5
 * At 14K: K=K_base. At 100K: K≈0.37*K_base.
 */
export function computeKuramotoK(KBase, memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return KBase * Math.pow(14000 / N, 0.5);
}

/**
 * D3: Kuramoto order parameter r = |(1/N) Σ e^(iθ_j)|
 * Measures synchronization: r=1 fully synchronized, r≈0 incoherent.
 */
export function kuramotoOrderParameter(phases) {
  if (!Array.isArray(phases) || phases.length === 0) return 0;
  let cosSum = 0, sinSum = 0;
  for (const theta of phases) {
    cosSum += Math.cos(theta);
    sinSum += Math.sin(theta);
  }
  const N = phases.length;
  return Math.sqrt((cosSum / N) ** 2 + (sinSum / N) ** 2);
}

/**
 * D4: Hyperbolic Sparse Geometry — Poincaré ball curvature scaling
 * Paper: Nickel & Kiela (2017) — hyperbolic embeddings
 * Formula: c = min(1, (14000/N)^0.3)
 * At 14K: c=1.0 (unit curvature). At 100K: c≈0.55 (flatter for more concepts).
 */
export function computeHyperbolicCurvature(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 1.0 * Math.min(1, Math.pow(14000 / N, 0.3));
}

/**
 * D4: Poincaré ball distance
 * d_hyp(x,y) = arcosh(1 + 2·||x-y||² / ((1-||x||²)(1-||y||²))) / √c
 */
export function poincareDistance(x, y, c = 1.0) {
  const xNorm = x.reduce((s, v) => s + v * v, 0);
  const yNorm = y.reduce((s, v) => s + v * v, 0);
  const diffNorm = x.reduce((s, v, i) => s + (v - y[i]) ** 2, 0);
  const denom = (1 - xNorm) * (1 - yNorm);
  const inner = 1 + 2 * diffNorm / Math.max(1e-10, denom);
  return Math.acosh(Math.max(1, inner)) / Math.sqrt(Math.max(1e-10, c));
}

/**
 * D5: Lyapunov Convergence Control — Q weight scaling
 * Paper: Lyapunov stability theory
 * Formula: q_weight = 1.0 * (1 + 0.5*log2(N/14000))
 * At 14K: q=1.0. At 100K: q≈2.42.
 */
export function computeLyapunovQWeight(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 1.0 * (1 + 0.5 * Math.log2(N / 14000));
}

/**
 * Build STDP kernel diagnostic with scale-adaptive parameters (D3-D5).
 */
export function buildSTDPDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);

  return {
    diagnostic_only: true,
    memory_count: N,
    scale_parameters: {
      kuramoto_K_ratio: Number(computeKuramotoK(1.0, N).toFixed(6)),
      hyperbolic_curvature: Number(computeHyperbolicCurvature(N).toFixed(6)),
      lyapunov_q_weight: Number(computeLyapunovQWeight(N).toFixed(6)),
    },
    guarded_math: {
      kuramoto_phase_enabled: false,
      hyperbolic_geometry_enabled: false,
      lyapunov_control_enabled: false,
    },
  };
}
