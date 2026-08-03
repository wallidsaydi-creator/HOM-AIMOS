/**
 * multi-view-timeline.js - MTGER and NARRATIVETIME temporal cognition operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: pure deterministic math/state transformations. It does not
 * mutate memory, prune evidence, apply decay, delete records, or call providers.
 * In recall it contributes timeline consistency signals to bounded native
 * scoring.
 *
 * Paper authority:
 * - MTGER- Multi-view.pdf
 * - NARRATIVETIME- Dense Temporal Annotation on a Timeline.pdf
 */

export const ALADDIN_MULTI_VIEW_TIMELINE_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Operators produce derived temporal graph/timeline states and diagnostics only.',
});

export const MTGER_NODE_TYPES = Object.freeze([
  'event',
  'time',
  'entity',
  'sentence',
  'document',
  'question',
]);

export const NARRATIVETIME_RELATIONS = Object.freeze([
  'BEFORE',
  'DURING',
  'AFTER',
  'OVERLAP',
  'BEGINS-ON',
  'ENDS-ON',
  'CONTAINS',
]);

function text(value) {
  return String(value ?? '').trim();
}

function normText(value) {
  return text(value).toLowerCase();
}

function tokens(value) {
  return normText(value).split(/[^a-z0-9]+/).filter(Boolean);
}

function dot(a = [], b = []) {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i += 1) sum += (Number(a[i]) || 0) * (Number(b[i]) || 0);
  return sum;
}

function add(a = [], b = []) {
  const n = Math.max(a.length, b.length);
  return Array.from({ length: n }, (_, i) => (Number(a[i]) || 0) + (Number(b[i]) || 0));
}

function scale(a = [], factor = 1) {
  return a.map(value => (Number(value) || 0) * factor);
}

function relu(vector = []) {
  return vector.map(value => Math.max(0, Number(value) || 0));
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-(Number(value) || 0)));
}

function softmax(values = []) {
  if (!values.length) return [];
  const max = Math.max(...values);
  const exp = values.map(value => Math.exp(value - max));
  const total = exp.reduce((sum, value) => sum + value, 0) || 1;
  return exp.map(value => value / total);
}

function intervalNumber(value, fallback = NaN) {
  if (value === -Infinity || value === Infinity) return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : fallback;
  const raw = text(value);
  if (!raw) return fallback;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  const parsed = Date.parse(raw.length === 4 ? `${raw}-01-01T00:00:00Z` : raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function mtgerAnswerObjective(answerCandidates = []) {
  return [...answerCandidates].sort((a, b) => (Number(b.probability) || 0) - (Number(a.probability) || 0))[0] || null;
}

export function segmentDocument(document = '', { headingPattern = /^#{1,6}\s+/m } = {}) {
  const raw = text(document);
  if (!raw) return [];
  const lines = raw.split(/\n+/);
  const segments = [];
  let current = [];
  for (const line of lines) {
    if (headingPattern.test(line) && current.length) {
      segments.push(current.join(' ').trim());
      current = [line.replace(headingPattern, '')];
    } else {
      current.push(line);
    }
  }
  if (current.length) segments.push(current.join(' ').trim());
  return segments.filter(Boolean);
}

export function tokenizeParagraphs(document = '') {
  const paragraphs = text(document).split(/\n{2,}/).map(row => row.trim()).filter(Boolean);
  return paragraphs.map((paragraph, index) => ({
    id: `p${index + 1}`,
    text: paragraph,
    tokens: tokens(paragraph),
  }));
}

export function documentEncoder(paragraphs = []) {
  return paragraphs.map(paragraph => {
    const rowTokens = Array.isArray(paragraph.tokens) ? paragraph.tokens : tokens(paragraph.text || paragraph);
    const vector = [rowTokens.length, new Set(rowTokens).size, rowTokens.join('').length];
    return { id: paragraph.id || '', vector, text: paragraph.text || text(paragraph) };
  });
}

export function pooling(tokenEmbeddings = [], mode = 'mean') {
  if (!tokenEmbeddings.length) return [];
  const width = Math.max(...tokenEmbeddings.map(row => row.length));
  if (mode === 'max') {
    return Array.from({ length: width }, (_, i) => Math.max(...tokenEmbeddings.map(row => Number(row[i]) || 0)));
  }
  const sum = tokenEmbeddings.reduce((acc, row) => add(acc, row), Array(width).fill(0));
  return scale(sum, 1 / tokenEmbeddings.length);
}

export function typeProjectNode(vector = [], type = 'event', weightsByType = {}) {
  const matrix = weightsByType[type] || null;
  if (!matrix) return [...vector];
  return matrix.map(row => dot(row, vector));
}

export function createHeterogeneousTemporalGraph({ nodes = [], factualEdges = [], temporalEdges = [], question = '' } = {}) {
  const mappedNodes = nodes.map((node, index) => ({
    id: text(node.id || `${node.type || 'node'}:${index + 1}`),
    type: MTGER_NODE_TYPES.includes(node.type) ? node.type : 'event',
    text: text(node.text || node.label || node.id),
    vector: Array.isArray(node.vector) ? node.vector.map(value => Number(value) || 0) : [tokens(node.text || node.label || node.id).length],
    interval: node.interval || null,
  }));
  if (question) mappedNodes.push({ id: 'question', type: 'question', text: text(question), vector: [tokens(question).length], interval: null });
  return {
    aladdin: ALADDIN_MULTI_VIEW_TIMELINE_GUARDRAILS,
    nodes: mappedNodes,
    fact_view: { nodes: mappedNodes, edges: factualEdges.map((edge, index) => ({ id: edge.id || `f${index + 1}`, ...edge, view: 'fact' })) },
    time_view: { nodes: mappedNodes, edges: temporalEdges.map((edge, index) => ({ id: edge.id || `t${index + 1}`, ...edge, view: 'time' })) },
  };
}

export function relationAttention({ query = [], keys = [], values = [] } = {}) {
  const scores = keys.map(key => dot(query, key));
  const weights = softmax(scores);
  const width = Math.max(0, ...values.map(value => value.length));
  const state = values.reduce((acc, value, index) => add(acc, scale(value, weights[index] || 0)), Array(width).fill(0));
  return { scores, weights, state };
}

export function heterogeneousGnnUpdate({ self = [], neighbors = [], relationWeights = [], selfWeight = null } = {}) {
  const selfState = selfWeight ? selfWeight.map(row => dot(row, self)) : [...self];
  const messages = neighbors.map((neighbor, index) => {
    const weight = relationWeights[index] || null;
    return weight ? weight.map(row => dot(row, neighbor)) : neighbor;
  });
  const aggregate = messages.reduce((acc, row) => add(acc, scale(row, 1 / Math.max(1, messages.length))), selfState);
  return relu(aggregate);
}

export function adaptiveMultiViewGate(factVector = [], timeVector = [], gateWeights = null) {
  const combined = [...factVector, ...timeVector];
  const raw = gateWeights ? dot(gateWeights, combined) : dot(factVector, timeVector) / Math.max(1, factVector.length);
  return sigmoid(raw);
}

export function fuseViews(factVector = [], timeVector = [], lambda = adaptiveMultiViewGate(factVector, timeVector)) {
  const n = Math.max(factVector.length, timeVector.length);
  return Array.from({ length: n }, (_, i) => ((1 - lambda) * (Number(factVector[i]) || 0)) + (lambda * (Number(timeVector[i]) || 0)));
}

export function pairwiseTemporalRelation(left = {}, right = {}) {
  const aStart = intervalNumber(left.start ?? left.interval?.start, NaN);
  const aEnd = intervalNumber(left.end ?? left.interval?.end ?? left.start ?? left.interval?.start, NaN);
  const bStart = intervalNumber(right.start ?? right.interval?.start, NaN);
  const bEnd = intervalNumber(right.end ?? right.interval?.end ?? right.start ?? right.interval?.start, NaN);
  if (![aStart, aEnd, bStart, bEnd].every(Number.isFinite)) return 'overlap';
  if (aEnd < bStart) return 'before';
  if (aStart > bEnd) return 'after';
  return 'overlap';
}

export function pairwiseTimeScoring(events = [], relationWeights = {}) {
  const rows = [];
  for (let i = 0; i < events.length; i += 1) {
    for (let j = 0; j < events.length; j += 1) {
      if (i === j) continue;
      const relation = pairwiseTemporalRelation(events[i], events[j]);
      rows.push({
        left: events[i].id || `e${i + 1}`,
        right: events[j].id || `e${j + 1}`,
        relation,
        score: Number(relationWeights[relation]) || (relation === 'overlap' ? 0.5 : 1),
      });
    }
  }
  return rows;
}

export function temporalConsistencyLoss(predicted = [], gold = []) {
  const goldByPair = new Map(gold.map(row => [`${row.left}|${row.right}`, row.relation]));
  if (!predicted.length) return 0;
  const misses = predicted.filter(row => goldByPair.get(`${row.left}|${row.right}`) && goldByPair.get(`${row.left}|${row.right}`) !== row.relation).length;
  return misses / predicted.length;
}

export function questionGuidedCrossAttention({ questionVector = [], contextVectors = [], heads = 1 } = {}) {
  const chunks = Math.max(1, heads);
  const outputs = [];
  for (let head = 0; head < chunks; head += 1) {
    const projectedQuestion = questionVector.map((value, index) => index % chunks === head ? value : 0);
    outputs.push(relationAttention({ query: projectedQuestion, keys: contextVectors, values: contextVectors }).state);
  }
  return pooling(outputs, 'mean');
}

export function crossEntropyLoss(probabilities = [], targetIndex = 0) {
  const p = Math.max(1e-12, Number(probabilities[targetIndex]) || 0);
  return -Math.log(p);
}

export function totalMtgerLoss({ decoderProbabilities = [], targetIndex = 0, temporalPredictions = [], temporalGold = [], temporalWeight = 1 } = {}) {
  const decoder = crossEntropyLoss(decoderProbabilities, targetIndex);
  const temporal = temporalConsistencyLoss(temporalPredictions, temporalGold);
  return { total: decoder + temporalWeight * temporal, decoder, temporal, temporal_weight: temporalWeight };
}

export function perturbInterval(interval = {}, { shrinkRatio = 0.25 } = {}) {
  const start = intervalNumber(interval.start, NaN);
  const end = intervalNumber(interval.end, NaN);
  if (![start, end].every(Number.isFinite) || start >= end) return { ...interval };
  const delta = (end - start) * shrinkRatio;
  return { start: start + delta, end: end - delta };
}

export function consistencyMetric(originalRelations = [], perturbedRelations = []) {
  const n = Math.min(originalRelations.length, perturbedRelations.length);
  if (!n) return 1;
  let same = 0;
  for (let i = 0; i < n; i += 1) {
    if (originalRelations[i] === perturbedRelations[i]) same += 1;
  }
  return same / n;
}

export function unanswerableOutput({ context = [], threshold = 0.1 } = {}) {
  const maxScore = Math.max(0, ...context.map(row => Number(row.score ?? row.context_score) || 0));
  return maxScore < threshold ? '[unanswerable]' : null;
}

export function createTimelineState({ events = [], timexes = [], branches = [] } = {}) {
  return {
    aladdin: ALADDIN_MULTI_VIEW_TIMELINE_GUARDRAILS,
    events: events.map((event, index) => ({
      id: text(event.id || `e${index + 1}`),
      text: text(event.text || event.label || event.id),
      start: event.start ?? event.interval?.start ?? null,
      end: event.end ?? event.interval?.end ?? event.start ?? event.interval?.start ?? null,
      factuality: event.factuality ?? 'factual',
      branch: event.branch || 'main',
    })),
    timexes: timexes.map((timex, index) => ({ id: text(timex.id || `t${index + 1}`), value: timex.value ?? timex.text ?? timex })),
    branches: branches.length ? branches : ['main'],
  };
}

export function narrativeTimelineRelation(left = {}, right = {}) {
  const relation = pairwiseTemporalRelation(left, right).toUpperCase();
  if (relation === 'BEFORE' || relation === 'AFTER') return relation;
  const aStart = intervalNumber(left.start, NaN);
  const aEnd = intervalNumber(left.end ?? left.start, NaN);
  const bStart = intervalNumber(right.start, NaN);
  const bEnd = intervalNumber(right.end ?? right.start, NaN);
  if (![aStart, aEnd, bStart, bEnd].every(Number.isFinite)) return 'OVERLAP';
  if (aStart >= bStart && aEnd <= bEnd) return 'DURING';
  if (aStart <= bStart && aEnd >= bEnd) return 'CONTAINS';
  if (aStart === bStart) return 'BEGINS-ON';
  if (aEnd === bEnd) return 'ENDS-ON';
  return 'OVERLAP';
}

export function inverseTlink(relation = '') {
  const rel = text(relation).toUpperCase();
  const map = {
    BEFORE: 'AFTER',
    AFTER: 'BEFORE',
    DURING: 'CONTAINS',
    CONTAINS: 'DURING',
    'BEGINS-ON': 'BEGINS-ON',
    'ENDS-ON': 'ENDS-ON',
    OVERLAP: 'OVERLAP',
  };
  return map[rel] || 'OVERLAP';
}

export function transitiveTimelineClosure(relations = []) {
  const edges = relations.map(row => ({ from: row.from || row.left, to: row.to || row.right, relation: text(row.relation).toUpperCase() }));
  const inferred = [...edges];
  let changed = true;
  while (changed) {
    changed = false;
    for (const a of inferred) {
      for (const b of inferred) {
        if (a.to !== b.from) continue;
        if (a.relation === 'BEFORE' && b.relation === 'BEFORE' && !inferred.some(row => row.from === a.from && row.to === b.to && row.relation === 'BEFORE')) {
          inferred.push({ from: a.from, to: b.to, relation: 'BEFORE', inferred: true });
          changed = true;
        }
        if (a.relation === 'AFTER' && b.relation === 'AFTER' && !inferred.some(row => row.from === a.from && row.to === b.to && row.relation === 'AFTER')) {
          inferred.push({ from: a.from, to: b.to, relation: 'AFTER', inferred: true });
          changed = true;
        }
      }
    }
  }
  return inferred;
}

export function tlinkDensity({ eventCount = 0, timexCount = 0, tlinkCount = 0 } = {}) {
  const denom = (Number(eventCount) || 0) + (Number(timexCount) || 0);
  return denom ? (Number(tlinkCount) || 0) / denom : 0;
}

export function cohenKappa(labelsA = [], labelsB = []) {
  const n = Math.min(labelsA.length, labelsB.length);
  if (!n) return 0;
  const labels = [...new Set([...labelsA.slice(0, n), ...labelsB.slice(0, n)].map(text))];
  const observed = labelsA.slice(0, n).filter((label, index) => text(label) === text(labelsB[index])).length / n;
  let expected = 0;
  for (const label of labels) {
    const pa = labelsA.slice(0, n).filter(value => text(value) === label).length / n;
    const pb = labelsB.slice(0, n).filter(value => text(value) === label).length / n;
    expected += pa * pb;
  }
  return expected === 1 ? 1 : (observed - expected) / (1 - expected);
}

export function krippendorffAlphaNominal(assignments = []) {
  const pairs = [];
  for (const row of assignments) {
    for (let i = 0; i < row.length; i += 1) {
      for (let j = i + 1; j < row.length; j += 1) pairs.push([row[i], row[j]]);
    }
  }
  if (!pairs.length) return 1;
  const disagreement = pairs.filter(([a, b]) => text(a) !== text(b)).length / pairs.length;
  const all = assignments.flat().map(text);
  const labels = [...new Set(all)];
  const expected = 1 - labels.reduce((sum, label) => {
    const p = all.filter(value => value === label).length / (all.length || 1);
    return sum + p * p;
  }, 0);
  return expected ? 1 - disagreement / expected : 1;
}

export function bilinearRelationScores(hidden = [], relationTensors = {}) {
  const ids = hidden.map(row => row.id);
  const rows = [];
  for (let i = 0; i < hidden.length; i += 1) {
    for (let j = 0; j < hidden.length; j += 1) {
      if (i === j) continue;
      const scores = {};
      for (const [relation, matrix] of Object.entries(relationTensors)) {
        const projected = matrix.map(row => dot(row, hidden[j].vector || []));
        scores[relation] = dot(hidden[i].vector || [], projected);
      }
      rows.push({ left: ids[i], right: ids[j], scores });
    }
  }
  return rows;
}

export function textOrderHeuristic(events = []) {
  const rows = [];
  for (let i = 0; i < events.length; i += 1) {
    for (let j = i + 1; j < events.length; j += 1) {
      rows.push({ left: events[i].id || `e${i + 1}`, right: events[j].id || `e${j + 1}`, relation: 'BEFORE' });
    }
  }
  return rows;
}

export function wordDistanceGate(left = {}, right = {}, { near = 10, far = 100 } = {}) {
  const distance = Math.abs((Number(left.token_index) || 0) - (Number(right.token_index) || 0));
  return {
    distance,
    bucket: distance < near ? 'near' : distance > far ? 'far' : 'middle',
    should_compare: distance <= far,
  };
}

export function spanClusters(spans = []) {
  const sorted = [...spans].sort((a, b) => (Number(a.start) || 0) - (Number(b.start) || 0));
  const clusters = [];
  for (const span of sorted) {
    const last = clusters.at(-1);
    if (last && (Number(span.start) || 0) <= last.end) {
      last.end = Math.max(last.end, Number(span.end) || 0);
      last.spans.push(span);
    } else {
      clusters.push({ start: Number(span.start) || 0, end: Number(span.end) || 0, spans: [span] });
    }
  }
  return clusters;
}

export function eventStateToken(state = {}) {
  if (state.bounded === false) return '[U]';
  if (state.point != null) return `{${state.point}}`;
  if (state.start != null && state.end != null) return `{${state.start}:${state.end}}`;
  if (state.start == null && state.end == null) return '{U1:U2}';
  return '[B]';
}

export function timelineToTimeML(timeline = {}) {
  const events = (timeline.events || []).map(event => `<EVENT eid="${event.id}">${event.text}</EVENT>`);
  const tlinks = [];
  for (let i = 0; i < (timeline.events || []).length; i += 1) {
    for (let j = i + 1; j < (timeline.events || []).length; j += 1) {
      const left = timeline.events[i];
      const right = timeline.events[j];
      tlinks.push(`<TLINK eventInstanceID="${left.id}" relatedToEventInstance="${right.id}" relType="${narrativeTimelineRelation(left, right)}"/>`);
    }
  }
  return [...events, ...tlinks].join('\n');
}
