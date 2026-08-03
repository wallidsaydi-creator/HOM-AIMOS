/**
 * recurrent-event-network.js - RE-NET recurrent temporal event operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: deterministic math/state transformations only. This file does
 * not call providers, mutate memory, prune evidence, apply canonical decay, or
 * delete records. In recall it contributes recurrent event diagnostics and
 * bounded native scoring signals.
 *
 * Paper authority:
 * - Recurrent Event Network.pdf
 */

export const ALADDIN_RECURRENT_EVENT_NETWORK_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'RE-NET operators create derived temporal graph states, probabilities, and metrics only.',
});

export const RENET_DEFAULTS = Object.freeze({
  history_length_m: 10,
  embedding_size: 128,
  negative_sampling_ratio: 5,
  margin: 1,
  rgcn_layers: 2,
  block_dimension: 2,
  lambda_relation: 0.1,
  lambda_subject: 0.1,
  learning_rate: 0.001,
  optimizer_weight_decay: 0.00001,
  adam_beta1: 0.9,
  adam_beta2: 0.999,
});

function text(value) {
  return String(value ?? '').trim();
}

function key(value) {
  return text(value).toLowerCase();
}

function add(a = [], b = []) {
  const n = Math.max(a.length, b.length);
  return Array.from({ length: n }, (_, i) => (Number(a[i]) || 0) + (Number(b[i]) || 0));
}

function sub(a = [], b = []) {
  const n = Math.max(a.length, b.length);
  return Array.from({ length: n }, (_, i) => (Number(a[i]) || 0) - (Number(b[i]) || 0));
}

function scale(a = [], factor = 1) {
  return a.map(value => (Number(value) || 0) * factor);
}

function dot(a = [], b = []) {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i += 1) sum += (Number(a[i]) || 0) * (Number(b[i]) || 0);
  return sum;
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-(Number(value) || 0)));
}

function tanhVector(vector = []) {
  return vector.map(value => Math.tanh(Number(value) || 0));
}

function sigmoidVector(vector = []) {
  return vector.map(sigmoid);
}

function multiplyMatrixVector(matrix = [], vector = []) {
  return matrix.map(row => dot(row, vector));
}

function hadamard(a = [], b = []) {
  const n = Math.max(a.length, b.length);
  return Array.from({ length: n }, (_, i) => (Number(a[i]) || 0) * (Number(b[i]) || 0));
}

function softmaxScores(rows = []) {
  if (!rows.length) return [];
  const max = Math.max(...rows.map(row => row.score));
  const exp = rows.map(row => Math.exp(row.score - max));
  const total = exp.reduce((sum, value) => sum + value, 0) || 1;
  return rows.map((row, index) => ({ ...row, probability: exp[index] / total }));
}

function vectorFor(id, embeddings = {}, width = RENET_DEFAULTS.embedding_size) {
  const direct = embeddings[id] || embeddings[key(id)];
  if (Array.isArray(direct)) return direct.map(value => Number(value) || 0);
  const seed = [...key(id)].reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return Array.from({ length: Math.max(1, Math.min(width, 16)) }, (_, index) => (((seed + index * 17) % 101) - 50) / 50);
}

export function makeTemporalEvent({ subject, relation, object, time, start = null, end = null, weight = 1, metadata = {} } = {}) {
  return {
    subject: text(subject),
    relation: text(relation),
    object: text(object),
    time: Number(time ?? start ?? 0),
    start: start ?? time ?? null,
    end: end ?? time ?? start ?? null,
    weight: Number(weight) || 1,
    metadata: { ...metadata },
  };
}

export function temporalEventKey(event = {}, includeTime = true) {
  const row = makeTemporalEvent(event);
  return includeTime
    ? `${row.subject}|${row.relation}|${row.object}|${row.time}`
    : `${row.subject}|${row.relation}|${row.object}`;
}

export function groupEventsByTime(events = []) {
  const grouped = new Map();
  for (const event of events.map(makeTemporalEvent)) {
    const rows = grouped.get(event.time) || [];
    rows.push(event);
    grouped.set(event.time, rows);
  }
  return Object.fromEntries([...grouped.entries()].sort((a, b) => Number(a[0]) - Number(b[0])));
}

export function expandIntervalFacts(facts = []) {
  const rows = [];
  for (const fact of facts) {
    const start = Number(fact.start ?? fact.time ?? fact.ts);
    const end = Number(fact.end ?? fact.time ?? fact.te ?? start);
    if (!Number.isFinite(start) || !Number.isFinite(end)) continue;
    for (let time = Math.min(start, end); time <= Math.max(start, end); time += 1) {
      rows.push(makeTemporalEvent({ ...fact, time }));
    }
  }
  return rows;
}

export function empiricalMarginals(events = []) {
  const rows = events.map(makeTemporalEvent);
  const total = rows.length || 1;
  const subjects = new Map();
  const relations = new Map();
  for (const event of rows) {
    subjects.set(event.subject, (subjects.get(event.subject) || 0) + 1);
    relations.set(event.relation, (relations.get(event.relation) || 0) + 1);
  }
  return {
    p_subject: Object.fromEntries([...subjects.entries()].map(([subject, count]) => [subject, count / total])),
    p_relation: Object.fromEntries([...relations.entries()].map(([relation, count]) => [relation, count / total])),
    p_subject_relation: Object.fromEntries([...subjects.keys()].flatMap(subject =>
      [...relations.keys()].map(relation => [`${subject}|${relation}`, (subjects.get(subject) / total) * (relations.get(relation) / total)])
    )),
  };
}

export function conditionalGraphProbability(events = []) {
  const grouped = groupEventsByTime(events);
  return {
    factorization: 'product_of_conditionals',
    time_slices: Object.keys(grouped).length,
    event_count: events.length,
    conditional_independence_given_history: true,
  };
}

export function concatState(parts = []) {
  return parts.flat().map(value => Number(value) || 0);
}

export function linearClassScores(input = [], classWeights = {}) {
  return Object.entries(classWeights).map(([label, weight]) => ({ label, score: dot(input, weight) }));
}

export function objectDistribution({ subject, relation, state = [], objectWeights = {}, embeddings = {} } = {}) {
  const input = concatState([vectorFor(subject, embeddings), vectorFor(relation, embeddings), state]);
  return softmaxScores(linearClassScores(input, objectWeights));
}

export function relationDistribution({ subject, state = [], relationWeights = {}, embeddings = {} } = {}) {
  const input = concatState([vectorFor(subject, embeddings), state]);
  return softmaxScores(linearClassScores(input, relationWeights));
}

export function subjectDistribution({ globalState = [], subjectWeights = {} } = {}) {
  return softmaxScores(linearClassScores(globalState, subjectWeights));
}

export function meanAggregator(neighborVectors = []) {
  if (!neighborVectors.length) return [];
  const sum = neighborVectors.reduce((acc, vector) => add(acc, vector), []);
  return scale(sum, 1 / neighborVectors.length);
}

export function attentionAggregator({ subjectVector = [], relationVector = [], neighbors = [], attentionVector = [], attentionMatrix = null } = {}) {
  if (!neighbors.length) return [];
  const rows = neighbors.map(neighbor => {
    const input = concatState([subjectVector, relationVector, neighbor]);
    const hidden = tanhVector(attentionMatrix ? multiplyMatrixVector(attentionMatrix, input) : input);
    return { vector: neighbor, score: dot(attentionVector.length ? attentionVector : hidden, hidden) };
  });
  const weighted = softmaxScores(rows);
  return weighted.reduce((acc, row) => add(acc, scale(row.vector, row.probability)), []);
}

export function rgcnAggregate({
  self = [],
  neighborsByRelation = {},
  relationWeights = {},
  selfWeight = null,
  normalizers = {},
  activation = sigmoid,
} = {}) {
  let aggregate = selfWeight ? multiplyMatrixVector(selfWeight, self) : [...self];
  for (const [relation, neighbors] of Object.entries(neighborsByRelation)) {
    const matrix = relationWeights[relation] || null;
    const normalizer = Number(normalizers[relation]) || neighbors.length || 1;
    for (const neighbor of neighbors) {
      const transformed = matrix ? multiplyMatrixVector(matrix, neighbor) : neighbor;
      aggregate = add(aggregate, scale(transformed, 1 / normalizer));
    }
  }
  return aggregate.map(activation);
}

export function maxPool(vectors = []) {
  if (!vectors.length) return [];
  const width = Math.max(...vectors.map(vector => vector.length));
  return Array.from({ length: width }, (_, index) => Math.max(...vectors.map(vector => Number(vector[index]) || 0)));
}

export function buildNeighborhood(events = [], subject = '', relation = null, embeddings = {}) {
  return events
    .map(makeTemporalEvent)
    .filter(event => event.subject === subject && (relation == null || event.relation === relation))
    .map(event => vectorFor(event.object, embeddings));
}

export function graphRepresentation(events = [], embeddings = {}, aggregator = meanAggregator) {
  const bySubject = new Map();
  for (const event of events.map(makeTemporalEvent)) {
    const vectors = bySubject.get(event.subject) || [];
    vectors.push(vectorFor(event.object, embeddings));
    bySubject.set(event.subject, vectors);
  }
  const subjectStates = [...bySubject.entries()].map(([subject, vectors]) => aggregator(vectors, subject));
  return maxPool(subjectStates);
}

export function gruUpdate({ input = [], previous = [], weights = {} } = {}) {
  const width = Math.max(previous.length, input.length, 1);
  const prev = Array.from({ length: width }, (_, index) => Number(previous[index]) || 0);
  const inp = Array.from({ length: width }, (_, index) => Number(input[index]) || 0);
  const wz = weights.W_z || identityMatrix(width);
  const uz = weights.U_z || identityMatrix(width);
  const wr = weights.W_r || identityMatrix(width);
  const ur = weights.U_r || identityMatrix(width);
  const wh = weights.W_h || identityMatrix(width);
  const uh = weights.U_h || identityMatrix(width);
  const z = sigmoidVector(add(multiplyMatrixVector(wz, inp), multiplyMatrixVector(uz, prev)));
  const r = sigmoidVector(add(multiplyMatrixVector(wr, inp), multiplyMatrixVector(ur, prev)));
  const candidate = tanhVector(add(multiplyMatrixVector(wh, inp), multiplyMatrixVector(uh, hadamard(r, prev))));
  return add(hadamard(sub(Array(width).fill(1), z), prev), hadamard(z, candidate));
}

function identityMatrix(width) {
  return Array.from({ length: width }, (_, row) => Array.from({ length: width }, (_, col) => row === col ? 1 : 0));
}

export function updateGlobalState({ graphState = [], previousGlobal = [], weights = {} } = {}) {
  return gruUpdate({ input: graphState, previous: previousGlobal, weights });
}

export function updateLocalState({ subjectVector = [], relationVector = [], neighborhood = [], globalState = [], previousLocal = [], weights = {} } = {}) {
  const input = concatState([subjectVector, relationVector, neighborhood, globalState]);
  return gruUpdate({ input, previous: previousLocal, weights });
}

export function sparseHistoryFallback(events = [], { subject = '', relation = null, time = 0, m = RENET_DEFAULTS.history_length_m } = {}) {
  const history = [];
  const sorted = events.map(makeTemporalEvent).filter(event => event.time < time).sort((a, b) => b.time - a.time);
  for (const event of sorted) {
    if (history.length >= m) break;
    if (event.subject === subject || event.object === subject || (relation && event.relation === relation)) history.push(event);
  }
  return history.reverse();
}

export function recurrentEventEncode({
  events = [],
  embeddings = {},
  historyLength = RENET_DEFAULTS.history_length_m,
  weights = {},
} = {}) {
  const grouped = groupEventsByTime(events);
  let globalState = [];
  const localSubject = new Map();
  const localSubjectRelation = new Map();
  const timeline = [];
  for (const [time, rows] of Object.entries(grouped)) {
    const graphState = graphRepresentation(rows, embeddings);
    globalState = updateGlobalState({ graphState, previousGlobal: globalState, weights: weights.global });
    for (const event of rows) {
      const history = sparseHistoryFallback(events, { subject: event.subject, relation: event.relation, time: event.time, m: historyLength });
      const neighborhood = meanAggregator(history.map(row => vectorFor(row.object, embeddings)));
      const subjectKey = event.subject;
      const subjectRelationKey = `${event.subject}|${event.relation}`;
      localSubject.set(subjectKey, updateLocalState({
        subjectVector: vectorFor(event.subject, embeddings),
        neighborhood,
        globalState,
        previousLocal: localSubject.get(subjectKey) || [],
        weights: weights.local_subject,
      }));
      localSubjectRelation.set(subjectRelationKey, updateLocalState({
        subjectVector: vectorFor(event.subject, embeddings),
        relationVector: vectorFor(event.relation, embeddings),
        neighborhood,
        globalState,
        previousLocal: localSubjectRelation.get(subjectRelationKey) || [],
        weights: weights.local_subject_relation,
      }));
    }
    timeline.push({ time: Number(time), graph_state: graphState, global_state: globalState });
  }
  return {
    aladdin: ALADDIN_RECURRENT_EVENT_NETWORK_GUARDRAILS,
    global_state: globalState,
    local_subject: Object.fromEntries(localSubject.entries()),
    local_subject_relation: Object.fromEntries(localSubjectRelation.entries()),
    timeline,
  };
}

export function eventLogLoss(events = [], distributions = {}, { lambdaRelation = RENET_DEFAULTS.lambda_relation, lambdaSubject = RENET_DEFAULTS.lambda_subject } = {}) {
  let loss = 0;
  for (const event of events.map(makeTemporalEvent)) {
    const objectP = Math.max(1e-12, Number(distributions.objects?.[event.object]) || 0);
    const relationP = Math.max(1e-12, Number(distributions.relations?.[event.relation]) || 0);
    const subjectP = Math.max(1e-12, Number(distributions.subjects?.[event.subject]) || 0);
    loss -= Math.log(objectP) + lambdaRelation * Math.log(relationP) + lambdaSubject * Math.log(subjectP);
  }
  return loss;
}

export function chronologicalSplit(events = [], { train = 0.8, valid = 0.1 } = {}) {
  const sorted = [...events.map(makeTemporalEvent)].sort((a, b) => a.time - b.time);
  const nTrain = Math.floor(sorted.length * train);
  const nValid = Math.floor(sorted.length * valid);
  return {
    train: sorted.slice(0, nTrain),
    valid: sorted.slice(nTrain, nTrain + nValid),
    test: sorted.slice(nTrain + nValid),
  };
}

export function filteredCandidates(candidates = [], knownEvents = [], target = {}) {
  const known = new Set(knownEvents.map(event => temporalEventKey(event, false)));
  const targetKey = temporalEventKey(target, false);
  return candidates.filter(candidate => temporalEventKey(candidate, false) === targetKey || !known.has(temporalEventKey(candidate, false)));
}

export function rankCandidatesByScore(candidates = [], scoreFn = () => 0) {
  return candidates.map(candidate => ({ ...candidate, score: Number(scoreFn(candidate)) || 0 }))
    .sort((a, b) => b.score - a.score || temporalEventKey(a).localeCompare(temporalEventKey(b)));
}

export function averageTieRank(ranked = [], targetKey = '') {
  const index = ranked.findIndex(row => temporalEventKey(row) === targetKey || temporalEventKey(row, false) === targetKey);
  if (index < 0) return Infinity;
  const score = ranked[index].score;
  let start = index;
  let end = index;
  while (start > 0 && ranked[start - 1].score === score) start -= 1;
  while (end + 1 < ranked.length && ranked[end + 1].score === score) end += 1;
  return (start + 1 + end + 1) / 2;
}

export function rankingMetrics(ranks = [], hits = [3, 10]) {
  const rows = ranks.map(Number).filter(value => Number.isFinite(value) && value > 0);
  const n = rows.length || 1;
  const metrics = {
    MRR: rows.reduce((sum, rank) => sum + 1 / rank, 0) / n,
  };
  for (const k of hits) metrics[`Hits@${k}`] = rows.filter(rank => rank <= k).length / n;
  return metrics;
}

export function staticCumulativeGraph(events = []) {
  return {
    nodes: [...new Set(events.flatMap(event => [makeTemporalEvent(event).subject, makeTemporalEvent(event).object]))],
    edges: events.map(makeTemporalEvent),
    ignores_timestamps: true,
  };
}

export function topKTriplesForStep({ subjects = [], relations = [], objects = [], scoreFn = () => 0, k = 10, time = 0 } = {}) {
  const rows = [];
  for (const subject of subjects) {
    for (const relation of relations) {
      for (const object of objects) {
        const event = makeTemporalEvent({ subject, relation, object, time });
        rows.push({ ...event, score: Number(scoreFn(event)) || 0 });
      }
    }
  }
  return rows.sort((a, b) => b.score - a.score || temporalEventKey(a).localeCompare(temporalEventKey(b))).slice(0, Math.max(0, Number(k) || 0));
}

export function multiStepRollout({ history = [], horizon = 1, cutoffK = 0, subjects = [], relations = [], objects = [], scoreFn = () => 0 } = {}) {
  const generated = [];
  const baseTime = Math.max(0, ...history.map(event => makeTemporalEvent(event).time));
  let currentHistory = history.map(makeTemporalEvent);
  for (let step = 1; step <= horizon; step += 1) {
    const time = baseTime + step;
    const snapshot = cutoffK > 0
      ? topKTriplesForStep({ subjects, relations, objects, scoreFn: event => scoreFn(event, currentHistory), k: cutoffK, time })
      : [];
    generated.push({ time, events: snapshot });
    currentHistory = currentHistory.concat(snapshot);
  }
  return {
    approximation: cutoffK > 0 ? 'generated_future_history' : 'single_step_no_future_graph_generation',
    generated,
    history: currentHistory,
  };
}

export function intensityScore({ candidate = {}, lastInvolvedTime = 0, currentTime = 0, relationFunction = value => value } = {}) {
  if (Number(currentTime) === Number(lastInvolvedTime)) return 0;
  const gap = Math.max(0, Number(currentTime) - Number(lastInvolvedTime));
  return Math.max(0, Number(relationFunction(candidate, lastInvolvedTime)) || 0) * gap;
}

export function mostRecentInvolvedTime(events = [], entity = '') {
  const matches = events.map(makeTemporalEvent).filter(event => event.subject === entity || event.object === entity);
  return matches.length ? Math.max(...matches.map(event => event.time)) : -Infinity;
}

export function rankObjectsByIntensity({ subject = '', relation = '', objects = [], history = [], currentTime = 0, relationFunction = () => 1 } = {}) {
  const lastInvolvedTime = mostRecentInvolvedTime(history, subject);
  return objects.map(object => {
    const candidate = makeTemporalEvent({ subject, relation, object, time: currentTime });
    return { ...candidate, intensity: intensityScore({ candidate, lastInvolvedTime, currentTime, relationFunction }) };
  }).sort((a, b) => b.intensity - a.intensity || a.object.localeCompare(b.object));
}

export function blockDiagonal(blocks = []) {
  const size = blocks.reduce((sum, block) => sum + block.length, 0);
  const matrix = Array.from({ length: size }, () => Array(size).fill(0));
  let offset = 0;
  for (const block of blocks) {
    for (let i = 0; i < block.length; i += 1) {
      for (let j = 0; j < (block[i] || []).length; j += 1) matrix[offset + i][offset + j] = Number(block[i][j]) || 0;
    }
    offset += block.length;
  }
  return matrix;
}

export function temporalTokenize(timestamp = '') {
  const parts = text(timestamp).match(/\d+/g) || [];
  return {
    year: parts[0] || null,
    month: parts[1] || null,
    day: parts[2] || null,
    hour: parts[3] || null,
    minute: parts[4] || null,
  };
}

export function rawAndFilteredEvaluation({ target = {}, candidates = [], knownEvents = [], scoreFn = () => 0 } = {}) {
  const rawRanked = rankCandidatesByScore(candidates, scoreFn);
  const filteredRanked = rankCandidatesByScore(filteredCandidates(candidates, knownEvents, target), scoreFn);
  const targetFull = temporalEventKey(target);
  const targetFact = temporalEventKey(target, false);
  return {
    raw_rank: averageTieRank(rawRanked, targetFull),
    filtered_rank: averageTieRank(filteredRanked, targetFact),
    raw_ranked: rawRanked,
    filtered_ranked: filteredRanked,
  };
}

export function renetComplexity({ edgeCount = 0, layers = RENET_DEFAULTS.rgcn_layers, historyLength = RENET_DEFAULTS.history_length_m, sampledSubjects = 0, relationCount = 0, objectCount = 0, dimension = RENET_DEFAULTS.embedding_size, cutoffK = 0 } = {}) {
  return {
    subject_probability: `O(${edgeCount}*${layers}*${historyLength})`,
    triple_probability: `O(${dimension}*${layers}*${historyLength})`,
    rollout: `O(${sampledSubjects}*${relationCount}*${objectCount}*(${dimension}*${layers}*${historyLength} + log ${Math.max(1, cutoffK)}))`,
  };
}

export function renetTrainingConfig(overrides = {}) {
  return {
    ...RENET_DEFAULTS,
    ...overrides,
    optimizer: 'Adam',
    recurrent_encoder: 'GRU',
    negative_sampling: 'time_agnostic_negative_sampling',
    teacher_forcing: true,
    canonical_memory_mutation: false,
  };
}
