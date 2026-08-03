/**
 * event-ordering-graph.js — Native event temporal relation algebra
 *
 * Status: Native capability service, exported by temporal/index.js.
 * Runtime note: this file is pure math/state transformation. It does not mutate
 * memory, prune canonical evidence, apply decay, delete records, call providers,
 * or change recall ranking until a caller wires it.
 *
 * Paper authority:
 * - A Multi-Axis Annotation Scheme for Event Temporal Relations.pdf
 * - An Annotation Framework for Dense Event Ordering.pdf
 * - NARRATIVETIME / TempEval / MATRES temporal relation rows in the 58-paper corpus
 *
 * Core techniques implemented:
 * - Event interval representation [t_start, t_end].
 * - Start-point comparison for event-pair ordering.
 * - 80% confidence gate for optional labels.
 * - Anchorability before relation labeling.
 * - Same-axis relation labeling and cross-axis suppression.
 * - Verb-only preprocessing.
 * - Dense local event/time graph over sentence windows.
 * - Event-DCT and Time-DCT edge schema.
 * - VAGUE label for ambiguous/no-majority relations.
 * - Post-label transitive closure with conflict rejection.
 * - Cohen kappa for annotator agreement.
 */

export const TEMPORAL_AXES = Object.freeze({
  MAIN: 'main',
  INTENTION: 'intention',
  OPINION: 'opinion',
});

export const EVENT_NODE_TYPES = Object.freeze({
  EVENT: 'Event',
  TIME: 'Time',
  DCT: 'DCT',
});

export const EVENT_RELATIONS = Object.freeze({
  BEFORE: 'BEFORE',
  AFTER: 'AFTER',
  EQUAL: 'EQUAL',
  INCLUDES: 'INCLUDES',
  IS_INCLUDED: 'IS_INCLUDED',
  SIMULTANEOUS: 'SIMULTANEOUS',
  VAGUE: 'VAGUE',
  NON_COMPARABLE: 'NON_COMPARABLE',
  CROSS_AXIS_SUPPRESSED: 'CROSS_AXIS_SUPPRESSED',
  LOW_CONFIDENCE: 'LOW_CONFIDENCE',
});

export const SIX_TEMPORAL_RELATIONS = Object.freeze([
  EVENT_RELATIONS.BEFORE,
  EVENT_RELATIONS.AFTER,
  EVENT_RELATIONS.INCLUDES,
  EVENT_RELATIONS.IS_INCLUDED,
  EVENT_RELATIONS.SIMULTANEOUS,
  EVENT_RELATIONS.VAGUE,
]);

export const THIRTEEN_INTERVAL_RELATIONS = Object.freeze([
  'AFTER',
  'IMMEDIATELY_AFTER',
  'AFTER_AND_OVERLAP',
  'ENDS',
  'INCLUDED',
  'STARTED_BY',
  'EQUAL',
  'STARTS',
  'INCLUDES',
  'ENDED_BY',
  'BEFORE_AND_OVERLAP',
  'IMMEDIATELY_BEFORE',
  'BEFORE',
]);

export const TB_DENSE_SPLIT = Object.freeze({
  train_documents: 22,
  dev_documents: 5,
  test_documents: 9,
  total_documents: 36,
});

export const ALADDIN_EVENT_ORDERING_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Verb-only preprocessing, anchorability gates, and cross-axis suppression are annotation-scope decisions only; they do not remove canonical memory or evidence.',
});

const INVERSE = Object.freeze({
  BEFORE: EVENT_RELATIONS.AFTER,
  AFTER: EVENT_RELATIONS.BEFORE,
  EQUAL: EVENT_RELATIONS.EQUAL,
  INCLUDES: EVENT_RELATIONS.IS_INCLUDED,
  IS_INCLUDED: EVENT_RELATIONS.INCLUDES,
  SIMULTANEOUS: EVENT_RELATIONS.SIMULTANEOUS,
  VAGUE: EVENT_RELATIONS.VAGUE,
});

const DEFAULT_CONFIDENCE_GATE = 0.8;
const DEFAULT_QUALITY_GATE = 0.7;
const MODAL_VERBS = new Set(['will', 'would', 'can', 'could', 'may', 'might', 'shall', 'should', 'must']);
const TEMPORAL_CONNECTIVES = new Set(['before', 'after', 'when', 'while', 'until', 'since', 'during', 'then', 'later', 'earlier']);

function finite(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function stableId(value, fallback) {
  return String(value || fallback).trim();
}

function tokenText(token) {
  return String(token?.text || token?.token || token || '').toLowerCase();
}

function tokenPos(token) {
  return String(token?.pos || token?.tag || '').toUpperCase();
}

function numericIndex(value, fallback = 0) {
  return Number.isInteger(value) ? value : fallback;
}

function tokenWindow(tokens, index, radius = 3) {
  const rows = Array.isArray(tokens) ? tokens : [];
  const from = Math.max(0, index - radius);
  const to = Math.min(rows.length, index + radius + 1);
  return rows.slice(from, to);
}

function tokensBetween(tokens, leftIndex, rightIndex) {
  const rows = Array.isArray(tokens) ? tokens : [];
  const from = Math.min(leftIndex, rightIndex) + 1;
  const to = Math.max(leftIndex, rightIndex);
  return rows.slice(Math.max(0, from), Math.max(0, to));
}

function lexicalResourceValues(resource, key) {
  const values = resource?.[String(key || '').toLowerCase()] || [];
  return new Set(Array.isArray(values) ? values.map(value => String(value).toLowerCase()) : []);
}

function shareLexicalResource(resource, leftToken, rightToken) {
  const left = tokenText(leftToken);
  const right = tokenText(rightToken);
  const leftValues = lexicalResourceValues(resource, left);
  const rightValues = lexicalResourceValues(resource, right);
  return leftValues.has(right) || rightValues.has(left) || [...leftValues].some(value => rightValues.has(value));
}

export function createEventInterval({
  id,
  start,
  end = start,
  axis = TEMPORAL_AXES.MAIN,
  anchorable = true,
  partOfSpeech = 'VERB',
  bridgeAxes = [],
} = {}) {
  const from = finite(start);
  const to = finite(end);
  if (from === null || to === null) throw new Error(`event_interval_requires_numeric_bounds:${id || ''}`);
  return {
    id: stableId(id, `event:${from}:${to}`),
    start: from,
    end: Math.max(from, to),
    axis: axis || TEMPORAL_AXES.MAIN,
    anchorable: Boolean(anchorable),
    partOfSpeech: String(partOfSpeech || '').toUpperCase(),
    bridgeAxes: Array.isArray(bridgeAxes) ? bridgeAxes.map(String) : [],
  };
}

export function compareEventStartPoints(left, right, epsilon = 1e-9) {
  const a = createEventInterval(left);
  const b = createEventInterval(right);
  const delta = a.start - b.start;
  if (Math.abs(delta) <= epsilon) return EVENT_RELATIONS.EQUAL;
  return delta < 0 ? EVENT_RELATIONS.BEFORE : EVENT_RELATIONS.AFTER;
}

export function passesTemporalConfidence(confidence, threshold = DEFAULT_CONFIDENCE_GATE) {
  return Number(confidence) >= threshold;
}

export function verbOnlyEvents(events = []) {
  return events.filter(event => String(event?.partOfSpeech || event?.pos || '').toUpperCase() === 'VERB');
}

export function extractEventPairFeatures({
  tokens = [],
  left = {},
  right = {},
  wordNet = {},
} = {}) {
  const leftIndex = numericIndex(left.tokenIndex, numericIndex(left.index, 0));
  const rightIndex = numericIndex(right.tokenIndex, numericIndex(right.index, leftIndex));
  const leftWindow = tokenWindow(tokens, leftIndex, 3);
  const rightWindow = tokenWindow(tokens, rightIndex, 3);
  const between = tokensBetween(tokens, leftIndex, rightIndex);
  const leftToken = tokens[leftIndex] || left;
  const rightToken = tokens[rightIndex] || right;
  return {
    left_pos: left.pos || tokenPos(leftToken),
    right_pos: right.pos || tokenPos(rightToken),
    left_neighbor_pos: leftWindow.map(tokenPos).filter(Boolean),
    right_neighbor_pos: rightWindow.map(tokenPos).filter(Boolean),
    left_neighbor_tokens: leftWindow.map(tokenText).filter(Boolean),
    right_neighbor_tokens: rightWindow.map(tokenText).filter(Boolean),
    sentence_distance: Math.abs(numericIndex(left.sentenceIndex, 0) - numericIndex(right.sentenceIndex, 0)),
    token_distance: Math.abs(rightIndex - leftIndex),
    modal_between: between.some(token => MODAL_VERBS.has(tokenText(token))),
    temporal_connective_between: between.some(token => TEMPORAL_CONNECTIVES.has(tokenText(token))),
    common_wordnet_synonym: shareLexicalResource(wordNet.synonyms, leftToken, rightToken),
    common_wordnet_derivational_form: shareLexicalResource(wordNet.derivations, leftToken, rightToken),
    preposition_heads: [left.prepositionHead, right.prepositionHead].filter(Boolean).map(String),
    left_aspect: left.aspect || '',
    right_aspect: right.aspect || '',
    left_modality: left.modality || '',
    right_modality: right.modality || '',
    left_polarity: left.polarity || '',
    right_polarity: right.polarity || '',
  };
}

export function isAnchorableOnAxis(event, axis = TEMPORAL_AXES.MAIN) {
  const row = createEventInterval(event);
  void axis;
  return Boolean(row.anchorable);
}

export function comparableOnAxis(left, right, axis = TEMPORAL_AXES.MAIN) {
  const a = createEventInterval(left);
  const b = createEventInterval(right);
  if (!isAnchorableOnAxis(a, axis) || !isAnchorableOnAxis(b, axis)) {
    return { comparable: false, reason: EVENT_RELATIONS.NON_COMPARABLE };
  }
  const sameAxis = a.axis === axis && b.axis === axis;
  const bridgeable = a.bridgeAxes.includes(axis) || b.bridgeAxes.includes(axis);
  if (!sameAxis && !bridgeable) {
    return { comparable: false, reason: EVENT_RELATIONS.CROSS_AXIS_SUPPRESSED };
  }
  return { comparable: true, reason: 'same_axis_or_bridgeable' };
}

export function labelSameAxisRelation(left, right, {
  axis = TEMPORAL_AXES.MAIN,
  confidence = 1,
  threshold = DEFAULT_CONFIDENCE_GATE,
} = {}) {
  if (!passesTemporalConfidence(confidence, threshold)) {
    return { relation: EVENT_RELATIONS.LOW_CONFIDENCE, comparable: false, axis, confidence };
  }
  const gate = comparableOnAxis(left, right, axis);
  if (!gate.comparable) return { relation: gate.reason, comparable: false, axis, confidence };
  return {
    relation: compareEventStartPoints(left, right),
    comparable: true,
    axis,
    confidence,
  };
}

export function annotateAxisRelations(events = [], {
  axis = TEMPORAL_AXES.MAIN,
  confidence = 1,
  verbOnly = true,
} = {}) {
  const candidates = verbOnly ? verbOnlyEvents(events) : [...events];
  const anchorable = candidates.filter(event => isAnchorableOnAxis(event, axis));
  const relations = [];
  for (let i = 0; i < anchorable.length; i += 1) {
    for (let j = i + 1; j < anchorable.length; j += 1) {
      relations.push({
        left: anchorable[i].id,
        right: anchorable[j].id,
        ...labelSameAxisRelation(anchorable[i], anchorable[j], { axis, confidence }),
      });
    }
  }
  return {
    aladdin: ALADDIN_EVENT_ORDERING_GUARDRAILS,
    axis,
    anchorable_event_ids: anchorable.map(event => event.id),
    relations,
    suppressed_event_count: candidates.length - anchorable.length,
    workflow: 'anchorability_then_relation_annotation',
  };
}

export function qualificationGate({ correct = 0, total = 0, threshold = DEFAULT_QUALITY_GATE, requiredQuestions = 10 } = {}) {
  const n = Number(total) || 0;
  const accuracy = n ? (Number(correct) || 0) / n : 0;
  return {
    passed: n >= requiredQuestions && accuracy >= threshold,
    accuracy,
    threshold,
    requiredQuestions,
  };
}

export function survivalGate(results = [], { threshold = DEFAULT_QUALITY_GATE } = {}) {
  const n = results.length;
  const correct = results.filter(row => Boolean(row.correct)).length;
  const accuracy = n ? correct / n : 0;
  return {
    survived: n > 0 && accuracy >= threshold,
    accuracy,
    threshold,
    discard_annotations: n > 0 && accuracy < threshold,
  };
}

export function majorityVote(labels = []) {
  const votes = labels.filter(Boolean).map(label => normalizeRelation(label));
  const counts = new Map();
  for (const vote of votes) counts.set(vote, (counts.get(vote) || 0) + 1);
  const required = Math.floor(votes.length / 2) + 1;
  const winner = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
  if (!winner || winner[1] < required) {
    return { relation: EVENT_RELATIONS.VAGUE, required, counts: Object.fromEntries(counts), reason: 'no_majority' };
  }
  return { relation: winner[0], required, counts: Object.fromEntries(counts), reason: 'majority' };
}

function featureEntries(features = {}) {
  const entries = [];
  for (const [key, value] of Object.entries(features || {})) {
    if (Array.isArray(value)) {
      for (const item of value) entries.push([`${key}=${item}`, 1]);
    } else if (typeof value === 'boolean') {
      if (value) entries.push([key, 1]);
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      entries.push([key, value]);
    } else if (value) {
      entries.push([`${key}=${value}`, 1]);
    }
  }
  entries.push(['bias', 1]);
  return entries;
}

function scoreWithWeights(weights = {}, features = {}) {
  return featureEntries(features).reduce((sum, [feature, value]) => sum + (Number(weights[feature]) || 0) * value, 0);
}

export function shouldSuppressEqualPredictions({ equalExamples = 0, minEqualExamples = 1 } = {}) {
  return Number(equalExamples) < Number(minEqualExamples);
}

export function predictAveragedPerceptron(model = {}, features = {}, { suppressEqual = false } = {}) {
  const availableLabels = (model.labels || [EVENT_RELATIONS.BEFORE, EVENT_RELATIONS.AFTER, EVENT_RELATIONS.EQUAL, EVENT_RELATIONS.VAGUE])
    .filter(label => !(suppressEqual && normalizeRelation(label) === EVENT_RELATIONS.EQUAL));
  const weights = model.averagedWeights || model.weights || {};
  const scored = availableLabels.map(label => ({
    label,
    score: scoreWithWeights(weights[label] || {}, features),
  })).sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
  return scored[0]?.label || EVENT_RELATIONS.VAGUE;
}

export function trainAveragedPerceptron(instances = [], {
  labels = [EVENT_RELATIONS.BEFORE, EVENT_RELATIONS.AFTER, EVENT_RELATIONS.EQUAL, EVENT_RELATIONS.VAGUE],
  iterations = 5,
  minEqualExamples = 1,
} = {}) {
  const equalExamples = instances.filter(row => normalizeRelation(row.label) === EVENT_RELATIONS.EQUAL).length;
  const suppressEqual = shouldSuppressEqualPredictions({ equalExamples, minEqualExamples });
  const activeLabels = labels.map(normalizeRelation).filter(label => !(suppressEqual && label === EVENT_RELATIONS.EQUAL));
  const weights = Object.fromEntries(activeLabels.map(label => [label, {}]));
  const totals = {};
  const timestamps = {};
  let step = 0;
  const update = (label, feature, amount) => {
    weights[label][feature] ||= 0;
    const key = `${label}\t${feature}`;
    totals[key] = (totals[key] || 0) + (step - (timestamps[key] || 0)) * weights[label][feature];
    timestamps[key] = step;
    weights[label][feature] += amount;
  };
  for (let epoch = 0; epoch < iterations; epoch += 1) {
    for (const row of instances) {
      const truth = normalizeRelation(row.label);
      if (!activeLabels.includes(truth)) continue;
      step += 1;
      const predicted = predictAveragedPerceptron({ labels: activeLabels, weights }, row.features || row, { suppressEqual });
      if (predicted === truth) continue;
      for (const [feature, value] of featureEntries(row.features || row)) {
        update(truth, feature, value);
        update(predicted, feature, -value);
      }
    }
  }
  const averagedWeights = Object.fromEntries(activeLabels.map(label => [label, {}]));
  for (const label of activeLabels) {
    for (const [feature, weight] of Object.entries(weights[label])) {
      const key = `${label}\t${feature}`;
      const total = (totals[key] || 0) + (step - (timestamps[key] || 0)) * weight;
      averagedWeights[label][feature] = step ? total / step : weight;
    }
  }
  return {
    type: 'averaged_perceptron',
    labels: activeLabels,
    iterations,
    equalExamples,
    suppressEqual,
    weights,
    averagedWeights,
    steps: step,
  };
}

export function f1Score({ tp = 0, fp = 0, fn = 0 } = {}) {
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { precision, recall, f1 };
}

export function selectBestHyperparameters(candidates = [], devResults = {}) {
  return [...candidates].map(candidate => {
    const key = candidate.id || JSON.stringify(candidate);
    const score = f1Score(devResults[key] || candidate.dev || {});
    return { candidate, key, ...score };
  }).sort((a, b) => b.f1 - a.f1 || a.key.localeCompare(b.key))[0] || null;
}

export function combineTrainDevSplit({ train = [], dev = [], test = [] } = {}) {
  return {
    train_dev: [...train, ...dev],
    test: [...test],
    split_authority: TB_DENSE_SPLIT,
  };
}

export function singleAxisTemporalFrame(axis = TEMPORAL_AXES.MAIN) {
  return {
    axis,
    state: 'single_axis_start_point_frame',
    compare: 'event_start_points',
    endpoint_policy: 'ignored_unless_interval_decomposition_requested',
  };
}

export function mapQ1Q2ToRelation({ q1Possible, q2Possible } = {}) {
  const q1 = Boolean(q1Possible);
  const q2 = Boolean(q2Possible);
  if (q1 && q2) return EVENT_RELATIONS.VAGUE;
  if (!q1 && !q2) return EVENT_RELATIONS.EQUAL;
  if (q1 && !q2) return EVENT_RELATIONS.BEFORE;
  return EVENT_RELATIONS.AFTER;
}

export function completeGraphPairCount(nodeCount) {
  const n = Number(nodeCount);
  if (!Number.isInteger(n) || n < 0) throw new Error('complete_graph_pair_count_requires_nonnegative_integer');
  return (n * (n - 1)) / 2;
}

export function wawaMetric(agreeingWorkers, totalWorkers) {
  const n = Number(agreeingWorkers);
  const total = Number(totalWorkers);
  if (!Number.isFinite(n) || !Number.isFinite(total) || total <= 0) return 0;
  return n / total;
}

export function intervalToStartpointRelation({ outerRelation } = {}) {
  const relation = normalizeRelation(outerRelation);
  if (relation === EVENT_RELATIONS.INCLUDES) return EVENT_RELATIONS.BEFORE;
  if (relation === EVENT_RELATIONS.IS_INCLUDED) return EVENT_RELATIONS.AFTER;
  return relation;
}

export function collapseRealisToActuality(label) {
  const raw = String(label || '').trim().toUpperCase();
  if (raw === 'GENERIC' || raw === 'HYPOTHETICAL' || raw === 'HEDGED') return 'NON_ACTUAL';
  if (!raw) return 'UNKNOWN';
  return 'ACTUAL';
}

export function anchorabilityConsensus(labels = []) {
  const votes = labels.map(label => String(label).toLowerCase());
  return votes.length >= 2 && votes.every(label => label === 'anchorable' || label === 'yes' || label === 'true');
}

function erfApprox(x) {
  const sign = x < 0 ? -1 : 1;
  const z = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * z);
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const y = 1 - (((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-z * z));
  return sign * y;
}

export function mcnemarStatistic({ b = 0, c = 0, alpha = 0.001 } = {}) {
  const discordant = Number(b) + Number(c);
  if (discordant <= 0) {
    return { chi_square: 0, p_value: 1, significant: false, alpha };
  }
  const chi = ((Math.abs(Number(b) - Number(c)) - 1) ** 2) / discordant;
  const p = 1 - erfApprox(Math.sqrt(chi / 2));
  return {
    chi_square: chi,
    p_value: Math.max(0, Math.min(1, p)),
    significant: p < alpha,
    alpha,
  };
}

export function buildAnchorabilityInterface({ event = {}, context = '' } = {}) {
  return {
    event: createEventNode({ ...event, type: EVENT_NODE_TYPES.EVENT }),
    context: String(context || ''),
    question: 'Is this event anchorable on the selected axis?',
    response_type: 'binary_yes_no',
    shows_single_event: true,
    shows_full_context: true,
  };
}

export function buildSeparateQTasks({ left = {}, right = {} } = {}) {
  return {
    taskA: {
      id: 'Q1',
      left: left.id,
      right: right.id,
      question: 'Is it possible that t1start is before t2start?',
    },
    taskB: {
      id: 'Q2',
      left: left.id,
      right: right.id,
      question: 'Is it possible that t2start is before t1start?',
    },
    same_annotator_may_see_both: false,
  };
}

export function labelAgreementRatio(numerator, denominator) {
  const n = Number(numerator);
  const d = Number(denominator);
  return d > 0 ? n / d : 0;
}

export function interpretNonAssertedEvent(event = {}) {
  const row = createEventNode({ ...event, type: EVENT_NODE_TYPES.EVENT });
  if (!row.negated && !row.modal && row.asserted) {
    return { ...row, ordering_assumption: 'asserted_event' };
  }
  return { ...row, ordering_assumption: 'core_event_occurs_for_ordering_semantics' };
}

export function aspectualEventRelation() {
  return EVENT_RELATIONS.IS_INCLUDED;
}

export function reduceToSixTemporalRelations(relation) {
  const normalized = normalizeRelation(relation);
  if (normalized === EVENT_RELATIONS.EQUAL) return EVENT_RELATIONS.SIMULTANEOUS;
  return SIX_TEMPORAL_RELATIONS.includes(normalized) ? normalized : EVENT_RELATIONS.VAGUE;
}

export function confidenceGateNonVague(relation, confidence, threshold = DEFAULT_CONFIDENCE_GATE) {
  const normalized = reduceToSixTemporalRelations(relation);
  if (normalized === EVENT_RELATIONS.VAGUE) return { relation: normalized, accepted: true };
  return {
    relation: passesTemporalConfidence(confidence, threshold) ? normalized : EVENT_RELATIONS.VAGUE,
    accepted: passesTemporalConfidence(confidence, threshold),
  };
}

export function vagueEscalationFromDisagreement(labels = []) {
  const normalized = labels.map(label => reduceToSixTemporalRelations(label));
  return normalized.every(label => label === normalized[0])
    ? normalized[0]
    : EVENT_RELATIONS.VAGUE;
}

export function classifyVagueDisagreement(leftRelation, rightRelation) {
  const left = reduceToSixTemporalRelations(leftRelation);
  const right = reduceToSixTemporalRelations(rightRelation);
  if (left === right) return left === EVENT_RELATIONS.VAGUE ? 'mutual_vague' : 'agreement';
  if (left === EVENT_RELATIONS.VAGUE || right === EVENT_RELATIONS.VAGUE) return 'partial_vague';
  return 'no_vague';
}

export function genericOrderingConstraint(left = {}, right = {}, proposedRelation = EVENT_RELATIONS.VAGUE) {
  const leftGeneric = Boolean(left.generic || String(left.realis || '').toUpperCase() === 'GENERIC');
  const rightGeneric = Boolean(right.generic || String(right.realis || '').toUpperCase() === 'GENERIC');
  if (leftGeneric !== rightGeneric) {
    return {
      relation: EVENT_RELATIONS.VAGUE,
      reason: 'generic_non_generic_pair_forced_vague',
    };
  }
  return {
    relation: reduceToSixTemporalRelations(proposedRelation),
    reason: leftGeneric && rightGeneric ? 'generic_pair_orderable' : 'non_generic_pair_orderable',
  };
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function timemlTag({ id, tag = 'EVENT', text = '', attributes = {} } = {}) {
  const attrs = Object.entries({ eid: id, ...attributes })
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}="${escapeXml(value)}"`)
    .join(' ');
  return `<${tag}${attrs ? ` ${attrs}` : ''}>${escapeXml(text)}</${tag}>`;
}

export function denseAnnotationStateInvariants({ nodes = [], edges = [] } = {}) {
  const labels = edges.map(edge => reduceToSixTemporalRelations(edge.relation));
  return {
    node_count: nodes.length,
    edge_count: edges.length,
    all_edges_in_reduced_ontology: labels.every(label => SIX_TEMPORAL_RELATIONS.includes(label)),
    aladdin: ALADDIN_EVENT_ORDERING_GUARDRAILS,
  };
}

export function cohensKappa(leftLabels = [], rightLabels = []) {
  const n = Math.min(leftLabels.length, rightLabels.length);
  if (!n) return { kappa: 0, observed_agreement: 0, expected_agreement: 0, item_count: 0 };
  const labels = new Set();
  const leftCounts = new Map();
  const rightCounts = new Map();
  let observed = 0;
  for (let i = 0; i < n; i += 1) {
    const left = normalizeRelation(leftLabels[i]);
    const right = normalizeRelation(rightLabels[i]);
    labels.add(left);
    labels.add(right);
    leftCounts.set(left, (leftCounts.get(left) || 0) + 1);
    rightCounts.set(right, (rightCounts.get(right) || 0) + 1);
    if (left === right) observed += 1;
  }
  const po = observed / n;
  let pe = 0;
  for (const label of labels) {
    pe += ((leftCounts.get(label) || 0) / n) * ((rightCounts.get(label) || 0) / n);
  }
  const kappa = Math.abs(1 - pe) < 1e-12 ? 1 : (po - pe) / (1 - pe);
  return { kappa, observed_agreement: po, expected_agreement: pe, item_count: n };
}

export function createEventNode({ id, type = EVENT_NODE_TYPES.EVENT, sentenceIndex = 0, token = '', asserted = true, modal = false, negated = false } = {}) {
  if (!Object.values(EVENT_NODE_TYPES).includes(type)) throw new Error(`invalid_event_node_type:${type}`);
  return {
    id: stableId(id, `${type}:${sentenceIndex}:${token}`),
    type,
    sentenceIndex: Number.isInteger(sentenceIndex) ? sentenceIndex : 0,
    token: String(token || ''),
    asserted: Boolean(asserted),
    modal: Boolean(modal),
    negated: Boolean(negated),
  };
}

export function coreEdgeSchema(nodes = [], { dct = createEventNode({ id: 'DCT', type: EVENT_NODE_TYPES.DCT, sentenceIndex: -1 }) } = {}) {
  const rows = nodes.map(node => createEventNode(node));
  const pairs = [];
  for (let i = 0; i < rows.length; i += 1) {
    for (let j = i + 1; j < rows.length; j += 1) {
      const distance = Math.abs(rows[i].sentenceIndex - rows[j].sentenceIndex);
      if (distance <= 1) {
        pairs.push({
          left: rows[i].id,
          right: rows[j].id,
          schema: distance === 0 ? 'same_sentence_tri_type_pair' : 'next_sentence_tri_type_pair',
        });
      }
    }
  }
  for (const row of rows) {
    if (row.type === EVENT_NODE_TYPES.EVENT) pairs.push({ left: row.id, right: dct.id, schema: 'event_dct' });
    if (row.type === EVENT_NODE_TYPES.TIME) pairs.push({ left: row.id, right: dct.id, schema: 'time_dct' });
  }
  return pairs;
}

export function locallyCompleteEventGraph(nodes = [], { windowSize = 1 } = {}) {
  const rows = nodes.map(node => createEventNode(node));
  const edgeMap = new Map();
  for (let i = 0; i < rows.length; i += 1) {
    for (let j = i + 1; j < rows.length; j += 1) {
      const distance = Math.abs(rows[i].sentenceIndex - rows[j].sentenceIndex);
      if (distance <= windowSize) {
        edgeMap.set(`${rows[i].id}:${rows[j].id}`, {
          left: rows[i].id,
          right: rows[j].id,
          schema: 'local_window_pair',
          distance,
        });
      }
    }
  }
  for (const edge of coreEdgeSchema(rows)) {
    edgeMap.set(`${edge.left}:${edge.right}`, { ...edgeMap.get(`${edge.left}:${edge.right}`), ...edge });
  }
  return {
    aladdin: ALADDIN_EVENT_ORDERING_GUARDRAILS,
    nodes: rows,
    edges: [...edgeMap.values()],
    completeness: 'locally_complete_neighboring_sentence_graph',
    target: 'strongly_connected_non_complete_event_time_graph',
  };
}

export function normalizeRelation(relation) {
  const raw = String(relation || '').trim().toUpperCase().replace(/[- ]+/g, '_');
  if (raw === 'BEFORE') return EVENT_RELATIONS.BEFORE;
  if (raw === 'AFTER') return EVENT_RELATIONS.AFTER;
  if (raw === 'EQUAL' || raw === 'IDENTITY') return EVENT_RELATIONS.EQUAL;
  if (raw === 'INCLUDES') return EVENT_RELATIONS.INCLUDES;
  if (raw === 'IS_INCLUDED' || raw === 'INCLUDED') return EVENT_RELATIONS.IS_INCLUDED;
  if (raw === 'SIMULTANEOUS') return EVENT_RELATIONS.SIMULTANEOUS;
  return EVENT_RELATIONS.VAGUE;
}

function inverseRelation(relation) {
  return INVERSE[normalizeRelation(relation)] || EVENT_RELATIONS.VAGUE;
}

function composeRelations(first, second) {
  const a = normalizeRelation(first);
  const b = normalizeRelation(second);
  if (a === EVENT_RELATIONS.VAGUE || b === EVENT_RELATIONS.VAGUE) return EVENT_RELATIONS.VAGUE;
  if (a === EVENT_RELATIONS.SIMULTANEOUS || a === EVENT_RELATIONS.EQUAL) return b;
  if (b === EVENT_RELATIONS.SIMULTANEOUS || b === EVENT_RELATIONS.EQUAL) return a;
  if (a === b && (a === EVENT_RELATIONS.BEFORE || a === EVENT_RELATIONS.AFTER)) return a;
  if (a === b && (a === EVENT_RELATIONS.INCLUDES || a === EVENT_RELATIONS.IS_INCLUDED)) return a;
  if (a === EVENT_RELATIONS.IS_INCLUDED && b === EVENT_RELATIONS.BEFORE) return EVENT_RELATIONS.BEFORE;
  if (a === EVENT_RELATIONS.AFTER && b === EVENT_RELATIONS.INCLUDES) return EVENT_RELATIONS.AFTER;
  if (a === EVENT_RELATIONS.INCLUDES && b === EVENT_RELATIONS.AFTER) return EVENT_RELATIONS.AFTER;
  if (a === EVENT_RELATIONS.BEFORE && b === EVENT_RELATIONS.IS_INCLUDED) return EVENT_RELATIONS.BEFORE;
  return EVENT_RELATIONS.VAGUE;
}

export function transitiveClosure(edges = []) {
  const relationMap = new Map();
  const nodes = new Set();
  for (const edge of edges) {
    const left = String(edge.left);
    const right = String(edge.right);
    const relation = normalizeRelation(edge.relation);
    nodes.add(left);
    nodes.add(right);
    relationMap.set(`${left}->${right}`, relation);
    relationMap.set(`${right}->${left}`, inverseRelation(relation));
  }
  let changed = true;
  while (changed) {
    changed = false;
    const ids = [...nodes];
    for (const a of ids) {
      for (const b of ids) {
        if (a === b) continue;
        const ab = relationMap.get(`${a}->${b}`);
        if (!ab) continue;
        for (const c of ids) {
          if (c === a || c === b) continue;
          const bc = relationMap.get(`${b}->${c}`);
          if (!bc) continue;
          const ac = composeRelations(ab, bc);
          if (ac === EVENT_RELATIONS.VAGUE) continue;
          const key = `${a}->${c}`;
          if (!relationMap.has(key)) {
            relationMap.set(key, ac);
            relationMap.set(`${c}->${a}`, inverseRelation(ac));
            changed = true;
          }
        }
      }
    }
  }
  return [...relationMap.entries()].map(([key, relation]) => {
    const [left, right] = key.split('->');
    return { left, right, relation, inferred: true };
  });
}

export function addTemporalRelation(edges = [], edge) {
  const attempted = {
    left: String(edge.left),
    right: String(edge.right),
    relation: normalizeRelation(edge.relation),
    inferred: false,
  };
  const inferred = transitiveClosure(edges).find(row => row.left === attempted.left && row.right === attempted.right);
  if (inferred && inferred.relation !== EVENT_RELATIONS.VAGUE && attempted.relation !== EVENT_RELATIONS.VAGUE && inferred.relation !== attempted.relation) {
    return { accepted: false, edges: [...edges], conflict: { attempted, inferred } };
  }
  const next = [...edges, attempted];
  return { accepted: true, edges: next, closure: transitiveClosure(next) };
}

export function anchorNowTodayToDct(surface, { documentCreationTime = '', replaceableWithNowadays = false } = {}) {
  const text = String(surface || '').toLowerCase();
  const dct = String(documentCreationTime || '').match(/\b\d{4}-\d{2}-\d{2}\b/)?.[0] || 'DCT';
  if (!/\b(now|today|tonight)\b/.test(text)) {
    return { relation_to_dct: EVENT_RELATIONS.VAGUE, value: '', reason: 'not_now_today' };
  }
  if (replaceableWithNowadays) {
    return { relation_to_dct: EVENT_RELATIONS.INCLUDES, value: `PAST/${dct}`, reason: 'long_now_includes_dct' };
  }
  return { relation_to_dct: EVENT_RELATIONS.IS_INCLUDED, value: dct, reason: 'included_in_dct' };
}
