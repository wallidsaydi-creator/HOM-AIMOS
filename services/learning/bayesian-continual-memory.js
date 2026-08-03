/**
 * Native MESU/Bayesian continual-memory operator from:
 * - Bayesian continual learning and forgetting in neural networks.pdf
 *
 * Implemented formulas / techniques:
 * - mean-field Gaussian posterior `q(theta)=N(mu, diag(sigma^2))`
 * - Bayes precision combination
 *   `1/sigma_post^2 = 1/sigma_L^2 + 1/sigma_prior^2`
 * - Gaussian KL `log(sigma_post/sigma) + (sigma^2+(mu-mu_post)^2)/(2sigma_post^2)-1/2`
 * - sequential free-energy terms over posterior drift and current evidence
 * - MESU mean/std updates with uncertainty-scaled plasticity
 * - reparameterization `omega = mu + epsilon*sigma`
 * - Hessian/variance protection diagnostics
 * - epistemic uncertainty `EU = TU - AU`
 * - memory rigidity `R_t = |A_0 - A_t|`
 *
 * Aimos adaptation:
 * - treats "forgetting" as non-destructive uncertainty/plasticity diagnostics
 * - no canonical memory decay, deletion, pruning, or overwrite
 */

import { createHash } from 'node:crypto';

export const MESU_CONSTANTS = Object.freeze({
  prior_mu: 0,
  prior_sigma: 1,
  finite_n: 32,
  learning_rate_gamma: 1 / 32,
  epsilon_samples: [-1.224744871, 0, 1.224744871],
});

export const MESU_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  forgets_by_removal: false,
});

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(value = '') {
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

export function hashUnitInterval(value = '') {
  const digest = createHash('sha256').update(String(value || '')).digest();
  return digest.readUInt32BE(0) / 0xffffffff;
}

export function meanFieldGaussian({ mu = 0, sigma = 1 } = {}) {
  return { mu: Number(mu) || 0, sigma: Math.max(1e-9, Number(sigma) || 1) };
}

export function gaussianKl(q = {}, posterior = {}) {
  const left = meanFieldGaussian(q);
  const right = meanFieldGaussian(posterior);
  return Math.log(right.sigma / left.sigma)
    + ((left.sigma ** 2) + ((left.mu - right.mu) ** 2)) / (2 * (right.sigma ** 2))
    - 0.5;
}

export function combineGaussianPosterior({
  likelihoodMu = 0,
  likelihoodSigma = 1,
  priorMu = MESU_CONSTANTS.prior_mu,
  priorSigma = MESU_CONSTANTS.prior_sigma,
} = {}) {
  const lVar = Math.max(1e-9, Number(likelihoodSigma) ** 2 || 1);
  const pVar = Math.max(1e-9, Number(priorSigma) ** 2 || 1);
  const sigma2 = 1 / ((1 / lVar) + (1 / pVar));
  const mu = sigma2 * ((Number(likelihoodMu) || 0) / lVar + (Number(priorMu) || 0) / pVar);
  return { mu, sigma: Math.sqrt(sigma2), precision: 1 / sigma2 };
}

export function sequentialFreeEnergy({
  q = {},
  previous = {},
  currentCost = 0,
  forgottenCost = 0,
} = {}) {
  return gaussianKl(q, previous) + (Number(currentCost) || 0) - (Number(forgottenCost) || 0);
}

export function mesuMeanUpdate({
  mu = 0,
  sigma = 1,
  gradMu = 0,
  priorMu = MESU_CONSTANTS.prior_mu,
  n = MESU_CONSTANTS.finite_n,
  priorSigma = MESU_CONSTANTS.prior_sigma,
} = {}) {
  const s = Math.max(1e-9, Number(sigma) || 1);
  const N = Math.max(1, Number(n) || 1);
  return -(s * (Number(gradMu) || 0)) + ((2 * ((Number(priorMu) || 0) - (Number(mu) || 0))) / (N * Math.max(1e-9, Number(priorSigma) || 1)));
}

export function mesuStdUpdate({
  sigma = 1,
  gradSigma = 0,
  priorSigma = MESU_CONSTANTS.prior_sigma,
  n = MESU_CONSTANTS.finite_n,
} = {}) {
  const s = Math.max(1e-9, Number(sigma) || 1);
  const N = Math.max(1, Number(n) || 1);
  const p = Math.max(1e-9, Number(priorSigma) || 1);
  return -((s * (Number(gradSigma) || 0)) / 2) + ((2 * (p - s)) / (2 * N * p));
}

export function reparameterize({ mu = 0, sigma = 1, epsilon = 0 } = {}) {
  return (Number(mu) || 0) + ((Number(epsilon) || 0) * Math.max(1e-9, Number(sigma) || 1));
}

export function expectedCost(samples = [], lossFn = (value) => value * value) {
  if (!samples.length) return 0;
  return samples.reduce((sum, value) => sum + (Number(lossFn(value)) || 0), 0) / samples.length;
}

export function varianceFloor({ hessian = 1, n = MESU_CONSTANTS.finite_n, priorSigma = MESU_CONSTANTS.prior_sigma } = {}) {
  const H = Math.max(1e-9, Number(hessian) || 1);
  const N = Math.max(1, Number(n) || 1);
  const priorPrecision = 1 / (Math.max(1e-9, Number(priorSigma) || 1) ** 2);
  return 1 / ((N * H) + priorPrecision);
}

export function mutualInformationUncertainty({ totalUncertainty = 0, aleatoricUncertainty = 0 } = {}) {
  return Math.max(0, (Number(totalUncertainty) || 0) - (Number(aleatoricUncertainty) || 0));
}

export function memoryRigidity({ initialAccuracy = 0, currentAccuracy = 0 } = {}) {
  return Math.abs((Number(initialAccuracy) || 0) - (Number(currentAccuracy) || 0));
}

export function posteriorImportance(sigma = 1) {
  const s = Math.max(1e-9, Number(sigma) || 1);
  return 1 / (s * s);
}

export function rocAuc(points = []) {
  const positives = points.filter((p) => p.label === 1);
  const negatives = points.filter((p) => p.label === 0);
  if (!positives.length || !negatives.length) return 0.5;
  let wins = 0;
  for (const p of positives) {
    for (const n of negatives) {
      if (p.score > n.score) wins += 1;
      else if (p.score === n.score) wins += 0.5;
    }
  }
  return wins / (positives.length * negatives.length);
}

function lexicalOverlapScore(query = '', text = '') {
  const q = new Set(tokens(query));
  const t = new Set(tokens(text));
  if (!q.size || !t.size) return 0;
  let hits = 0;
  for (const token of q) if (t.has(token)) hits += 1;
  return hits / q.size;
}

export function bayesianContinualScores({
  queryText = '',
  states = [],
} = {}) {
  const querySize = Math.max(1, tokens(queryText).length);
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of (states || []).slice(0, 180)) {
    const text = state.text || state.memory?.value || '';
    const overlap = lexicalOverlapScore(queryText, text);
    const ageDays = Math.max(0, (Date.now() - Date.parse(state.memory?.created_at || Date.now())) / 86_400_000);
    const observation = hashUnitInterval(`${state.id}:${queryText}`);
    const posterior = combineGaussianPosterior({
      likelihoodMu: overlap,
      likelihoodSigma: 1 / (1 + querySize + (tokens(text).length / 64)),
      priorMu: MESU_CONSTANTS.prior_mu,
      priorSigma: MESU_CONSTANTS.prior_sigma,
    });
    const gradMu = posterior.mu - overlap;
    const gradSigma = posterior.sigma - MESU_CONSTANTS.prior_sigma;
    const deltaMu = mesuMeanUpdate({ mu: posterior.mu, sigma: posterior.sigma, gradMu });
    const deltaSigma = mesuStdUpdate({ sigma: posterior.sigma, gradSigma });
    const epistemic = mutualInformationUncertainty({
      totalUncertainty: posterior.sigma + (observation * 0.1),
      aleatoricUncertainty: Math.min(posterior.sigma, 0.35),
    });
    const recencyPlasticity = 1 / (1 + Math.log1p(ageDays));
    const score = clamp01((0.48 * overlap) + (0.22 * clamp01(posterior.precision / 40)) + (0.18 * recencyPlasticity) + (0.12 * clamp01(1 - epistemic)));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      posterior_mu: Number(posterior.mu.toFixed(6)),
      posterior_sigma: Number(posterior.sigma.toFixed(6)),
      posterior_precision: Number(posterior.precision.toFixed(6)),
      delta_mu: Number(deltaMu.toFixed(6)),
      delta_sigma: Number(deltaSigma.toFixed(6)),
      epistemic_uncertainty: Number(epistemic.toFixed(6)),
      recency_plasticity: Number(recencyPlasticity.toFixed(6)),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: MESU_CONSTANTS,
    guardrails: MESU_GUARDRAILS,
    formula: 'q(theta)=N(mu,diag(sigma^2)); KL=q||posterior; delta_mu=-sigma*dC/dmu+2(mu_prior-mu)/(N*sigma_prior); EU=TU-AU',
  };
}
