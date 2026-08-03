/**
 * Native recurrent-neurogenesis recall operator from:
 * - On the role of neurogenesis in overcoming catastrophic forgetting.pdf
 *
 * Implemented formulas / techniques:
 * - dynamic neuron set `A`; neuron state `(w_j, c_j,k)` with context descriptors
 * - BMU `b=argmin_j d_j`
 * - temporal-context distance
 *   `d_j = alpha_0||x(t)-w_j||^2 + sum_k alpha_k||C_k(t)-c_j,k||^2`
 * - global context `C_k(t)=beta*w_b(t-1)+(1-beta)*c_b,k(t-1)`
 * - activity `a(t)=exp(-d_b)`
 * - growth gate when activity falls below threshold
 * - temporal synaptic increment `Delta P(i,j)=1`
 * - RNAT transition `s(i)=argmax P(n,s(i-1))`
 * - label association `xi_j=argmax_l H(j,l)`
 *
 * Aimos adaptation:
 * - grows transient read prototypes only; canonical memory is untouched
 * - no shrink/delete path is applied because Aladdin law forbids deletion
 * - replay is represented by returned evidence order, not hidden corpus replay
 */

export const NEUROGENESIS_CONSTANTS = Object.freeze({
  activity_threshold: 0.3,
  habituation_threshold: 0.1,
  beta: 0.7,
  alpha: [0.67, 0.24, 0.09],
  k_context: 2,
  rnat_k: 2,
  tau_b: 0.3,
  tau_n: 0.1,
  kappa: 1.05,
  epsilon_b: 0.5,
  epsilon_n: 0.005,
});

export const NEUROGENESIS_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  grows_transient_read_neurons_only: true,
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

function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function vectorize(text = '', vocabulary = []) {
  const counts = new Map();
  for (const token of tokens(text)) counts.set(token, (counts.get(token) || 0) + 1);
  const vector = vocabulary.map((token) => counts.get(token) || 0);
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0)) || 1;
  return vector.map((value) => value / norm);
}

function squaredDistance(left = [], right = []) {
  const width = Math.max(left.length, right.length);
  let sum = 0;
  for (let i = 0; i < width; i += 1) {
    const d = (Number(left[i]) || 0) - (Number(right[i]) || 0);
    sum += d * d;
  }
  return sum;
}

export function bmuDistance(inputVector = [], neuron = {}, contexts = [], alpha = NEUROGENESIS_CONSTANTS.alpha) {
  const base = (alpha[0] || 0.67) * squaredDistance(inputVector, neuron.w || []);
  const contextCost = contexts.reduce((sum, context, index) => {
    const descriptor = (neuron.c || [])[index] || [];
    return sum + ((alpha[index + 1] || 0) * squaredDistance(context, descriptor));
  }, 0);
  return base + contextCost;
}

export function habituationUpdate(h = 1, tau = NEUROGENESIS_CONSTANTS.tau_b, kappa = NEUROGENESIS_CONSTANTS.kappa) {
  return clamp01((Number(h) || 0) + (tau * kappa * (1 - (Number(h) || 0))) - tau);
}

export function adaptWeight(w = [], x = [], h = 1, epsilon = NEUROGENESIS_CONSTANTS.epsilon_b) {
  return w.map((value, index) => (Number(value) || 0) + (epsilon * h * ((Number(x[index]) || 0) - (Number(value) || 0))));
}

function labelFor(text = '') {
  const labels = [
    ['temporal', /\b(after|before|between|last|first|currently|now|days?|months?)\b/i],
    ['person', /\b(member|community|person|who|called|named|melanie)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['possession', /\b(own|have|bought|purchased|currently have|how many)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip)\b/i],
  ];
  return labels.find(([, pattern]) => pattern.test(text))?.[0] || 'memory';
}

function globalContexts(previousBmu = null, k = NEUROGENESIS_CONSTANTS.k_context) {
  if (!previousBmu) return Array.from({ length: k }, () => []);
  return Array.from({ length: k }, (_, index) => {
    const descriptor = previousBmu.c?.[index] || previousBmu.w || [];
    return descriptor.map((value, i) => (NEUROGENESIS_CONSTANTS.beta * (previousBmu.w?.[i] || 0)) + ((1 - NEUROGENESIS_CONSTANTS.beta) * value));
  });
}

export function buildNeurogenesisState({ states = [], maxVocabulary = 64 } = {}) {
  const vocabulary = unique((states || []).flatMap((state) => tokens(stateText(state)))).slice(0, maxVocabulary);
  const neurons = [];
  const synapses = new Map();
  const labels = new Map();
  let previousBmu = null;
  let grownCount = 0;

  for (const state of states || []) {
    const x = vectorize(stateText(state), vocabulary);
    const contexts = globalContexts(previousBmu);
    let bmu = null;
    let distance = Infinity;
    for (const neuron of neurons) {
      const d = bmuDistance(x, neuron, contexts);
      if (d < distance) {
        distance = d;
        bmu = neuron;
      }
    }
    const activity = Math.exp(-Math.max(0, distance));
    if (!bmu || activity < NEUROGENESIS_CONSTANTS.activity_threshold || bmu.h < NEUROGENESIS_CONSTANTS.habituation_threshold) {
      const midpoint = bmu ? x.map((value, index) => (value + (bmu.w[index] || 0)) / 2) : x;
      bmu = {
        id: `neuron:${neurons.length + 1}`,
        state_ids: [String(state.id)],
        w: midpoint,
        c: contexts.map((context) => context.length ? context : midpoint),
        h: 1,
        label: labelFor(stateText(state)),
      };
      neurons.push(bmu);
      grownCount += 1;
    } else {
      bmu.w = adaptWeight(bmu.w, x, bmu.h, NEUROGENESIS_CONSTANTS.epsilon_b);
      bmu.c = bmu.c.map((descriptor, index) => adaptWeight(descriptor, contexts[index] || descriptor, bmu.h, NEUROGENESIS_CONSTANTS.epsilon_n));
      bmu.h = habituationUpdate(bmu.h);
      bmu.state_ids.push(String(state.id));
    }
    const label = labelFor(stateText(state));
    const assoc = labels.get(bmu.id) || {};
    assoc[label] = (assoc[label] || 0) + 1;
    labels.set(bmu.id, assoc);
    if (previousBmu) {
      const key = `${previousBmu.id}->${bmu.id}`;
      synapses.set(key, (synapses.get(key) || 0) + 1);
    }
    previousBmu = bmu;
  }

  return { vocabulary, neurons, synapses, labels, grown_count: grownCount };
}

export function rnatSequence(state = {}, startNeuronId = '', length = NEUROGENESIS_CONSTANTS.rnat_k + 1) {
  const sequence = [startNeuronId].filter(Boolean);
  let current = startNeuronId;
  while (current && sequence.length < length) {
    const outgoing = [...(state.synapses || new Map()).entries()]
      .filter(([key]) => key.startsWith(`${current}->`))
      .map(([key, weight]) => ({ to: key.split('->')[1], weight }));
    outgoing.sort((a, b) => b.weight - a.weight || a.to.localeCompare(b.to));
    if (!outgoing.length) break;
    current = outgoing[0].to;
    sequence.push(current);
  }
  return sequence;
}

export function neurogenesisScores({ queryText = '', states = [] } = {}) {
  const model = buildNeurogenesisState({ states });
  const queryVector = vectorize(queryText, model.vocabulary);
  const scoreById = new Map();
  const rnat = [];
  for (const neuron of model.neurons) {
    const distance = bmuDistance(queryVector, neuron, globalContexts(neuron));
    const activity = clamp01(Math.exp(-Math.max(0, distance)));
    const sequence = rnatSequence(model, neuron.id);
    rnat.push(sequence);
    for (const stateId of neuron.state_ids || []) {
      const labelAssoc = model.labels.get(neuron.id) || {};
      const labelStrength = Math.max(0, ...Object.values(labelAssoc)) / Math.max(1, (neuron.state_ids || []).length);
      const prev = scoreById.get(stateId) || 0;
      scoreById.set(stateId, Math.max(prev, clamp01((0.74 * activity) + (0.16 * labelStrength) + (0.10 * Math.min(1, sequence.length / 3)))));
    }
  }
  for (const state of states || []) if (!scoreById.has(String(state.id))) scoreById.set(String(state.id), 0);
  return {
    scoreById,
    neuron_count: model.neurons.length,
    grown_count: model.grown_count,
    synapse_count: model.synapses.size,
    rnat_count: rnat.length,
    formula: 'b=argmin d_j; a(t)=exp(-d_b); DeltaP(i,j)=1; s(i)=argmax P(n,s(i-1))',
    guardrails: NEUROGENESIS_GUARDRAILS,
  };
}
