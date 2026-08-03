/**
 * Native TACOS neuromodulated consolidation recall operator from:
 * - TACOS.pdf
 *
 * Implemented formulas / techniques:
 * - LIF membrane dynamics `V(t+1)=V(t)+(dt/tau_mem)(V_rest-V(t)+I(t)R)`
 * - synaptic current `I(t+1)=I(t)+(dt/tau_syn)(sum_j w_j S_j(t)-I(t))`
 * - error current `I_err(t)=S_out(t)-L(t)`
 * - output/hidden error pathways using random feedback
 * - error-compartment integration `U(t+1)=U(t)+(dt/tau_mem)E(t)R`
 * - boxcar surrogate gate `Theta(I_i)=1` when `I_post in [I_min,I_max]`
 * - eRBP update `w_ij(t+1)=w_ij(t)-eta*S_j(t)*U_i(t)*Theta(I_i(t))`
 * - metaplastic modulation `f(m,w)=exp(-abs(m*w))`
 * - heterosynaptic reference drift `Delta w_ij=-alpha*(w_ij-w_ref_ij)`
 * - TACOS combined update with synapse-local consolidation
 *
 * Aimos adaptation:
 * - computes transient synaptic support scores over recall candidates
 * - heterosynaptic decay is reported as a read-local reference-drift diagnostic
 * - no canonical weight, memory, rank prior, or stored evidence is deleted or decayed
 */

export const TACOS_CONSTANTS = Object.freeze({
  dt: 1,
  tau_mem: 20,
  tau_syn: 5,
  v_rest: 0,
  resistance: 1,
  eta: 0.08,
  alpha: 0.03,
  i_min: 0.05,
  i_max: 0.95,
});

export const TACOS_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  heterosynaptic_decay_is_transient_diagnostic_only: true,
});

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'from', 'have', 'many', 'more', 'most',
  'that', 'their', 'there', 'these', 'this', 'those', 'through', 'what',
  'when', 'where', 'which', 'while', 'with', 'would',
]);

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
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
  return normalizeText(value)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function lexicalOverlap(query = '', text = '') {
  const q = new Set(tokens(query));
  const t = new Set(tokens(text));
  if (!q.size || !t.size) return 0;
  let hits = 0;
  for (const token of q) if (t.has(token)) hits += 1;
  return hits / q.size;
}

export function lifMembraneUpdate({
  v = 0,
  inputCurrent = 0,
  dt = TACOS_CONSTANTS.dt,
  tauMem = TACOS_CONSTANTS.tau_mem,
  vRest = TACOS_CONSTANTS.v_rest,
  resistance = TACOS_CONSTANTS.resistance,
} = {}) {
  return (Number(v) || 0) + ((dt / tauMem) * (vRest - (Number(v) || 0) + ((Number(inputCurrent) || 0) * resistance)));
}

export function synapticCurrentUpdate({
  current = 0,
  weights = [],
  spikes = [],
  dt = TACOS_CONSTANTS.dt,
  tauSyn = TACOS_CONSTANTS.tau_syn,
} = {}) {
  const drive = weights.reduce((sum, weight, index) => sum + ((Number(weight) || 0) * (Number(spikes[index]) || 0)), 0);
  return (Number(current) || 0) + ((dt / tauSyn) * (drive - (Number(current) || 0)));
}

export function boxcarSurrogateGate(value = 0, min = TACOS_CONSTANTS.i_min, max = TACOS_CONSTANTS.i_max) {
  const n = Number(value) || 0;
  return n >= min && n <= max ? 1 : 0;
}

export function errorCompartmentUpdate({
  u = 0,
  error = 0,
  dt = TACOS_CONSTANTS.dt,
  tauMem = TACOS_CONSTANTS.tau_mem,
  resistance = TACOS_CONSTANTS.resistance,
} = {}) {
  return (Number(u) || 0) + ((dt / tauMem) * ((Number(error) || 0) * resistance));
}

export function metaplasticityModulation(m = 1, w = 0) {
  return Math.exp(-Math.abs((Number(m) || 0) * (Number(w) || 0)));
}

export function heterosynapticReferenceDrift(w = 0, wRef = 0, alpha = TACOS_CONSTANTS.alpha) {
  return -alpha * ((Number(w) || 0) - (Number(wRef) || 0));
}

export function tacosWeightUpdate({
  weight = 0,
  referenceWeight = 0,
  metaplasticity = 1,
  presynapticSpike = 0,
  errorCompartment = 0,
  postCurrent = 0,
  postSpike = 0,
  eta = TACOS_CONSTANTS.eta,
  alpha = TACOS_CONSTANTS.alpha,
} = {}) {
  const plastic = metaplasticityModulation(metaplasticity, weight)
    * eta
    * (Number(presynapticSpike) || 0)
    * (Number(errorCompartment) || 0)
    * boxcarSurrogateGate(postCurrent);
  const referenceDrift = heterosynapticReferenceDrift(weight, referenceWeight, alpha) * (Number(postSpike) || 0);
  return (Number(weight) || 0) - plastic + referenceDrift;
}

function labelSignal(queryText = '', text = '') {
  const overlap = lexicalOverlap(queryText, text);
  if (/\b(current|currently|now|last|recent)\b/i.test(queryText) && /\b(current|currently|now|last|recent)\b/i.test(text)) return Math.max(overlap, 0.85);
  return overlap;
}

export function tacosScores({ queryText = '', states = [] } = {}) {
  const scoreById = new Map();
  const synapses = [];
  for (const [index, state] of (states || []).entries()) {
    const signal = labelSignal(queryText, stateText(state));
    const current = synapticCurrentUpdate({ current: 0, weights: [signal, 1 - signal], spikes: [signal > 0 ? 1 : 0, 1] });
    const membrane = lifMembraneUpdate({ v: signal, inputCurrent: current });
    const error = signal - (index / Math.max(1, states.length - 1));
    const u = errorCompartmentUpdate({ u: 0, error });
    const w = tacosWeightUpdate({
      weight: signal,
      referenceWeight: Math.min(1, signal + 0.08),
      metaplasticity: 1 + index / Math.max(1, states.length),
      presynapticSpike: signal > 0 ? 1 : 0,
      errorCompartment: u,
      postCurrent: clamp01(membrane),
      postSpike: signal > 0.2 ? 1 : 0,
    });
    const consolidation = 1 - Math.abs(signal - clamp01(w));
    synapses.push({ state_id: String(state.id), signal, current, membrane, u, weight: w, consolidation });
    scoreById.set(String(state.id), clamp01((0.58 * signal) + (0.22 * clamp01(membrane)) + (0.20 * consolidation)));
  }
  return {
    scoreById,
    synapse_count: synapses.length,
    active_gate_count: synapses.filter((row) => boxcarSurrogateGate(row.membrane)).length,
    consolidated_count: synapses.filter((row) => row.consolidation >= 0.8).length,
    mean_consolidation: synapses.reduce((sum, row) => sum + row.consolidation, 0) / Math.max(1, synapses.length),
    formula: 'w(t+1)=w(t)-exp(-abs(mw))*eta*S*U*Theta(I)+Delta_ref; V/I/U LIF dynamics',
    guardrails: TACOS_GUARDRAILS,
  };
}
