/**
 * temporal-kg-reasoning.js - temporal KG QA, HyTE, and temporal KGQA operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: pure deterministic math/state transformation. It does not
 * mutate memory, prune evidence, apply decay, delete records, or call providers.
 * In recall it contributes temporal KG diagnostics and bounded native scoring
 * signals.
 *
 * Paper authority:
 * - Complex Temporal Question Answering on Knowledge Graphs.pdf
 * - HyTE.pdf
 * - Question Answering Over Temporal Knowledge Graphs.pdf
 */

export const ALADDIN_TEMPORAL_KG_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Temporal KG functions create derived graph states, diagnostics, and scores only.',
});

export const TEMPORAL_QA_CATEGORIES = Object.freeze({
  EXPLICIT_EXPRESSION: 'explicit_expression',
  IMPLICIT_EXPRESSION: 'implicit_expression',
  TEMPORAL_ORDINAL: 'temporal_ordinal',
  TEMPORAL_ANSWER: 'temporal_answer',
});

export const EXAQT_BUDGETS = Object.freeze({
  questionRelevantFacts: 25,
  groupSteinerTrees: 25,
  temporalFacts: 25,
  temporalNeighborhoodHops: 2,
  negativeRatio: 5,
});

export const EXAQT_TRAINING_CONFIG = Object.freeze({
  bertClassifier: {
    model: 'bert-base-cased',
    optimizer: 'AdamW',
    learning_rate: 3e-5,
    accumulation: 512,
    epochs: 2,
    dropout: 0.3,
    mini_batch_size: 50,
    weight_decay: 0.001,
  },
  rgcn: {
    embedding_dim: 100,
    tce_dim: 100,
    tse_dim: 100,
    te_dim: 100,
    tee_dim: 100,
    layers: 3,
    epochs: 100,
    mini_batch_size: 25,
    gradient_clip: 1,
    learning_rate: 0.001,
    lstm_dropout: 0.3,
    linear_dropout: 0.2,
    fact_dropout: 0.1,
  },
  nerd: {
    best: 'TagMe_without_pruning_threshold_plus_ELQ_defaults',
    candidates: ['TagMe', 'AIDA', 'ELQ', 'TagMe+ELQ', 'AIDA+ELQ', 'TagMe+AIDA'],
  },
});

export const HYTE_DEFAULTS = Object.freeze({
  embedding_dim: 128,
  batch_size: 50000,
  margins: [1, 2, 5, 10],
  learning_rates: [0.1, 0.01, 0.001],
  optimizer: 'SGD',
});

function text(value) {
  return String(value ?? '').trim();
}

function normText(value) {
  return text(value).toLowerCase();
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

function sub(a = [], b = []) {
  const n = Math.max(a.length, b.length);
  return Array.from({ length: n }, (_, i) => (Number(a[i]) || 0) - (Number(b[i]) || 0));
}

function scale(a = [], factor = 1) {
  return a.map(value => (Number(value) || 0) * factor);
}

function norm(a = [], order = 2) {
  if (order === 1 || String(order).toLowerCase() === 'l1') return a.reduce((sum, value) => sum + Math.abs(Number(value) || 0), 0);
  return Math.sqrt(a.reduce((sum, value) => sum + (Number(value) || 0) ** 2, 0));
}

function normalizeVector(vector = []) {
  const length = norm(vector, 2);
  return length ? vector.map(value => (Number(value) || 0) / length) : vector.map(() => 0);
}

function softmax(values = []) {
  if (!values.length) return [];
  const max = Math.max(...values);
  const exp = values.map(value => Math.exp(value - max));
  const total = exp.reduce((sum, value) => sum + value, 0) || 1;
  return exp.map(value => value / total);
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-(Number(value) || 0)));
}

export function makeKgTriple({ subject, predicate, object, qualifiers = {} } = {}) {
  return {
    subject: text(subject),
    predicate: text(predicate),
    object: text(object),
    qualifiers: { ...qualifiers },
  };
}

export function directedKgEdge(triple = {}) {
  const row = makeKgTriple(triple);
  return {
    from: row.subject,
    to: row.object,
    predicate: row.predicate,
    direction: 'subject_to_object',
  };
}

export function makeNaryTemporalFact({ subject, predicate, object, startDate = '', endDate = '', qualifiers = {} } = {}) {
  return makeKgTriple({
    subject,
    predicate,
    object,
    qualifiers: {
      ...qualifiers,
      ...(startDate ? { start_date: text(startDate) } : {}),
      ...(endDate ? { end_date: text(endDate) } : {}),
    },
  });
}

export function isTemporalPredicate(triple = {}) {
  const row = makeKgTriple(triple);
  const values = [row.object, ...Object.values(row.qualifiers)].map(text);
  return values.some(value => /\b(?:\d{4}|\d{4}-\d{2}-\d{2})\b/.test(value));
}

export function encodeQuestionKeywords(question = '') {
  return text(question).split(/\W+/).filter(Boolean);
}

export function classifyTemporalQuestion(question = '') {
  const q = normText(question);
  if (/\b(first|last|earliest|latest|oldest|newest)\b/.test(q)) return TEMPORAL_QA_CATEGORIES.TEMPORAL_ORDINAL;
  if (/^(when|what year|which year|what date)\b/.test(q)) return TEMPORAL_QA_CATEGORIES.TEMPORAL_ANSWER;
  if (/\b(before|after|during|while|between|since|until|overlap)\b/.test(q)) return TEMPORAL_QA_CATEGORIES.IMPLICIT_EXPRESSION;
  if (/\b(?:19|20)\d{2}\b|\b(today|yesterday|tomorrow|last|next)\b/.test(q)) return TEMPORAL_QA_CATEGORIES.EXPLICIT_EXPRESSION;
  return TEMPORAL_QA_CATEGORIES.IMPLICIT_EXPRESSION;
}

export function mapTemporalSignal(signal = '') {
  const raw = normText(signal).replace(/[- ]+/g, '_');
  if (['before', 'meets'].includes(raw)) return 'BEFORE';
  if (['before_inverse', 'meet_inverse', 'after'].includes(raw)) return 'AFTER';
  if (raw === 'starts') return 'START';
  if (raw === 'finishes') return 'FINISH';
  if (raw === 'last' || raw === 'ordinal') return 'ORDINAL';
  if (raw === 'equals' || raw === 'equal') return 'EQUAL';
  return 'OVERLAP';
}

export function verbalizeFact(fact = {}) {
  const row = makeKgTriple(fact);
  const qualifierText = Object.entries(row.qualifiers || {})
    .map(([key, value]) => `${key} ${value}`)
    .join(' and ');
  return [row.subject, row.predicate, row.object, qualifierText].filter(Boolean).join(' ');
}

export function bertPairInput(question = '', fact = {}) {
  return `[CLS] ${text(question)} [SEP] ${verbalizeFact(fact)} [SEP]`;
}

export function logSoftmaxScore(logits = [], targetIndex = 0) {
  const probabilities = softmax(logits);
  const p = probabilities[targetIndex] || 1e-12;
  return Math.log(p);
}

export function edgeCostFromRelevance(score = 0) {
  return Math.max(0, Math.min(1, 1 - (Number(score) || 0)));
}

export function cosineSimilarity(a = [], b = []) {
  const denom = norm(a, 2) * norm(b, 2);
  return denom ? dot(a, b) / denom : 0;
}

export function pathRelevance(questionVector = [], pathVector = []) {
  return cosineSimilarity(questionVector, pathVector);
}

export function buildTerminalGroups(questionKeywords = [], candidateNodes = []) {
  const nodes = candidateNodes.map(node => ({ id: text(node.id || node), aliases: (node.aliases || []).map(normText) }));
  return questionKeywords.map(keyword => {
    const needle = normText(keyword);
    return {
      keyword,
      terminals: nodes.filter(node => normText(node.id).includes(needle) || node.aliases.includes(needle)).map(node => node.id),
    };
  });
}

export function groupSteinerObjective(groups = [], treeNodes = []) {
  const set = new Set(treeNodes.map(text));
  return groups.every(group => (group.terminals || []).some(node => set.has(text(node))));
}

export function selectTopK(items = [], k = 25, scoreField = 'score') {
  return [...items].sort((a, b) => (Number(b[scoreField]) || 0) - (Number(a[scoreField]) || 0)).slice(0, k);
}

export function buildAnswerGraph({ questionRelevantFacts = [], gstSubgraphs = [], temporalFacts = [] } = {}) {
  return {
    aladdin: ALADDIN_TEMPORAL_KG_GUARDRAILS,
    stage: 'answer_graph_construction',
    question_relevant_facts: selectTopK(questionRelevantFacts, EXAQT_BUDGETS.questionRelevantFacts),
    gst_subgraphs: selectTopK(gstSubgraphs, EXAQT_BUDGETS.groupSteinerTrees),
    temporal_facts: selectTopK(temporalFacts, EXAQT_BUDGETS.temporalFacts),
  };
}

export function sinusoidalTimeEncoding(k, dimension = 100) {
  return Array.from({ length: dimension }, (_, j) => {
    const denom = 10000 ** ((2 * Math.floor(j / 2)) / dimension);
    return j % 2 === 0 ? Math.sin(Number(k) / denom) : Math.cos(Number(k) / denom);
  });
}

export function timestampEncoding(timestamp = '', dimension = 100) {
  const parts = text(timestamp).match(/\d+/g) || [];
  return parts.reduce((acc, part) => add(acc, sinusoidalTimeEncoding(Number(part), dimension)), Array(dimension).fill(0));
}

export function attentionOverTemporalRelations({ edges = [], questionState = [] } = {}) {
  const scores = edges.map(edge => dot([...(edge.relationEmbedding || []), ...(edge.timeEncoding || [])], questionState));
  const weights = softmax(scores);
  return edges.map((edge, index) => ({ ...edge, attention: weights[index] || 0 }));
}

export function relu(vector = []) {
  return vector.map(value => Math.max(0, Number(value) || 0));
}

export function ffnConcat(parts = [], weights = null, bias = 0) {
  const vector = parts.flat().map(value => Number(value) || 0);
  if (!weights) return vector;
  return weights.map(row => dot(row, vector) + bias);
}

export function rgcnEntityUpdate({ previousEntity = [], question = [], timeAwareEntity = [], neighborMessages = [] } = {}) {
  const aggregated = neighborMessages.reduce((acc, message) => add(acc, scale(message.vector || [], Number(message.weight) || 0)), []);
  return relu(ffnConcat([previousEntity, question, timeAwareEntity, aggregated]));
}

export function personalizedPageRankMessage({ ppr = 1, relationEmbedding = [], neighborEmbedding = [] } = {}) {
  return scale(ffnConcat([relationEmbedding, neighborEmbedding]), Number(ppr) || 0);
}

export function answerProbability(entityRepresentation = [], weights = [], bias = 0) {
  return sigmoid(dot(weights, entityRepresentation) + (Number(bias) || 0));
}

export function pAt1(predictions = [], gold = []) {
  const answers = new Set(gold.map(text));
  return answers.has(text(predictions[0])) ? 1 : 0;
}

export function meanReciprocalRank(predictions = [], gold = []) {
  const answers = new Set(gold.map(text));
  const index = predictions.findIndex(item => answers.has(text(item)));
  return index >= 0 ? 1 / (index + 1) : 0;
}

export function hitAtK(predictions = [], gold = [], k = 5) {
  const answers = new Set(gold.map(text));
  return predictions.slice(0, k).some(item => answers.has(text(item))) ? 1 : 0;
}

export function answerRecallInGraph(graphNodes = [], gold = []) {
  const nodes = new Set(graphNodes.map(text));
  return gold.some(answer => nodes.has(text(answer))) ? 1 : 0;
}

export function pairedTStatistic(before = [], after = []) {
  const n = Math.min(before.length, after.length);
  if (!n) return { t: 0, n: 0, significant_p_lt_0_05: false };
  const diffs = Array.from({ length: n }, (_, i) => (Number(after[i]) || 0) - (Number(before[i]) || 0));
  const mean = diffs.reduce((sum, value) => sum + value, 0) / n;
  const variance = n > 1 ? diffs.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (n - 1) : 0;
  const se = Math.sqrt(variance / n);
  const t = se ? mean / se : 0;
  return { t, n, significant_p_lt_0_05: Math.abs(t) > 1.96 };
}

export function temporalProjection(vector = [], normal = []) {
  const w = normalizeVector(normal);
  return sub(vector, scale(w, dot(w, vector)));
}

export function transEScore(head = [], relation = [], tail = [], order = 2) {
  return norm(sub(add(head, relation), tail), order);
}

export function hyteScore({ head = [], relation = [], tail = [], timeNormal = [], order = 2 } = {}) {
  return transEScore(
    temporalProjection(head, timeNormal),
    temporalProjection(relation, timeNormal),
    temporalProjection(tail, timeNormal),
    order
  );
}

export function marginRankingLoss(positiveScore, negativeScore, margin = 1) {
  return Math.max(0, (Number(positiveScore) || 0) - (Number(negativeScore) || 0) + (Number(margin) || 0));
}

export function decomposeTemporalKgByTimestamp(facts = []) {
  const byTime = new Map();
  for (const fact of facts) {
    const start = Number.parseInt(fact.start_time ?? fact.startTime ?? fact.ST ?? fact.time ?? fact.timestamp, 10);
    const end = Number.parseInt(fact.end_time ?? fact.endTime ?? fact.ET ?? fact.time ?? fact.timestamp, 10);
    if (!Number.isInteger(start) || !Number.isInteger(end)) continue;
    for (let t = Math.min(start, end); t <= Math.max(start, end); t += 1) {
      const rows = byTime.get(t) || [];
      rows.push({ ...fact, timestamp: t });
      byTime.set(t, rows);
    }
  }
  return Object.fromEntries([...byTime.entries()].map(([timestamp, rows]) => [timestamp, rows]));
}

export function constructTemporalPositiveTriples(intervalFacts = []) {
  return Object.entries(decomposeTemporalKgByTimestamp(intervalFacts)).flatMap(([timestamp, rows]) =>
    rows.map(row => ({ head: row.subject, relation: row.predicate, tail: row.object, timestamp: Number(timestamp) }))
  );
}

export function corruptTriple(triple = {}, entities = [], { corruptHead = true } = {}) {
  const replacement = entities.find(entity => text(entity) !== text(corruptHead ? triple.head : triple.tail)) || entities[0] || '';
  return corruptHead
    ? { ...triple, head: replacement }
    : { ...triple, tail: replacement };
}

export function timeAgnosticNegativeSamples(positiveTriples = [], entities = [], existing = new Set()) {
  return positiveTriples.flatMap(triple => [
    corruptTriple(triple, entities, { corruptHead: true }),
    corruptTriple(triple, entities, { corruptHead: false }),
  ]).filter(triple => !existing.has(`${triple.head}|${triple.relation}|${triple.tail}`));
}

export function timeDependentNegativeSamples(positiveTriples = [], entities = [], globalTriples = []) {
  const positiveAtTime = new Set(positiveTriples.map(row => `${row.head}|${row.relation}|${row.tail}|${row.timestamp}`));
  const globalSet = new Set(globalTriples.map(row => `${row.head}|${row.relation}|${row.tail}`));
  return timeAgnosticNegativeSamples(positiveTriples, entities)
    .filter(row => !positiveAtTime.has(`${row.head}|${row.relation}|${row.tail}|${row.timestamp}`))
    .concat(globalTriples.filter(row => !positiveAtTime.has(`${row.head}|${row.relation}|${row.tail}|${row.timestamp}`) && globalSet.has(`${row.head}|${row.relation}|${row.tail}`)));
}

export function filteredCandidateSet({ head, relation, trueTail, entities = [], knownTriples = new Set() } = {}) {
  return entities
    .map(entity => ({ head, relation, tail: entity }))
    .filter(row => row.tail === trueTail || !knownTriples.has(`${row.head}|${row.relation}|${row.tail}`));
}

export function rankByScore(candidates = [], scoreFn = () => 0) {
  return candidates.map(candidate => ({ ...candidate, score: scoreFn(candidate) }))
    .sort((a, b) => a.score - b.score);
}

export function rankMetrics(ranks = []) {
  const rows = ranks.map(Number).filter(value => Number.isFinite(value) && value > 0);
  const n = rows.length || 1;
  return {
    MR: rows.reduce((sum, value) => sum + value, 0) / n,
    HitsAt10: rows.filter(value => value <= 10).length / n,
    HitsAt1: rows.filter(value => value <= 1).length / n,
  };
}

export function temporalScopingRank({ timestamps = [], targetInterval = [], scoreFn = value => value } = {}) {
  const [start, end] = targetInterval.map(Number);
  const ranked = timestamps.map(time => ({ time, score: scoreFn(time) })).sort((a, b) => a.score - b.score);
  const index = ranked.findIndex(row => row.time >= start && row.time <= end);
  return index >= 0 ? index + 1 : Infinity;
}

export function pca2d(vectors = []) {
  if (!vectors.length) return [];
  return vectors.map(vector => ({ x: Number(vector[0]) || 0, y: Number(vector[1]) || 0 }));
}

export function hyteTrainingPlan() {
  return {
    steps: ['learn_time_hyperplanes', 'project_triples', 'score_projected_translation', 'optimize_margin_ranking_loss_with_negative_sampling'],
    defaults: HYTE_DEFAULTS,
    no_explicit_ordering_regularization: true,
    type_constraints: false,
  };
}

export const TEMPORAL_KGQA_TEMPLATE_TYPES = Object.freeze([
  'before',
  'after',
  'first',
  'last',
  'time_join',
  'duration',
  'entity_at_time',
]);

export const TEMPORAL_KGQA_MODELS = Object.freeze({
  ComplEx: 'complex-valued static KG embedding',
  TComplEx: 'complex-valued temporal KG embedding',
  TNTComplEx: 'temporal plus non-temporal complex factorization',
  TimePlex: 'temporal pair interaction and interval-aware scoring',
  CRON: 'question-conditioned temporal KGQA model',
  TEQUILA: 'temporal QA decomposition workflow',
});

export function makeTemporalKgFact({ head, relation, tail, start = null, end = null, qualifiers = {} } = {}) {
  return {
    head: text(head),
    relation: text(relation),
    tail: text(tail),
    start: start ?? qualifiers.start ?? qualifiers.start_time ?? null,
    end: end ?? qualifiers.end ?? qualifiers.end_time ?? start ?? qualifiers.start ?? null,
    qualifiers: { ...qualifiers },
  };
}

export function temporalKgFactToTuple(fact = {}) {
  const row = makeTemporalKgFact(fact);
  return [row.head, row.relation, row.tail, row.start, row.end];
}

export function classifyTemporalKgqaTemplate(question = '') {
  const q = normText(question);
  if (/\b(before|prior to|earlier than)\b/.test(q)) return 'before';
  if (/\b(after|later than|following)\b/.test(q)) return 'after';
  if (/\b(first|earliest|initial)\b/.test(q)) return 'first';
  if (/\b(last|latest|most recent|final)\b/.test(q)) return 'last';
  if (/\b(how long|duration|between)\b/.test(q)) return 'duration';
  if (/\b(when|what time|what year|which year)\b/.test(q)) return 'time_join';
  return 'entity_at_time';
}

export function complexVector(real = [], imaginary = []) {
  return { real: real.map(value => Number(value) || 0), imaginary: imaginary.map(value => Number(value) || 0) };
}

export function complexMultiply(left = complexVector(), right = complexVector()) {
  const n = Math.max(left.real.length, left.imaginary.length, right.real.length, right.imaginary.length);
  const real = [];
  const imaginary = [];
  for (let i = 0; i < n; i += 1) {
    const ar = Number(left.real[i]) || 0;
    const ai = Number(left.imaginary[i]) || 0;
    const br = Number(right.real[i]) || 0;
    const bi = Number(right.imaginary[i]) || 0;
    real.push(ar * br - ai * bi);
    imaginary.push(ar * bi + ai * br);
  }
  return complexVector(real, imaginary);
}

export function complexConjugate(vector = complexVector()) {
  return complexVector(vector.real, vector.imaginary.map(value => -(Number(value) || 0)));
}

export function complexTriLinear(head = complexVector(), relation = complexVector(), tail = complexVector()) {
  const product = complexMultiply(complexMultiply(head, relation), complexConjugate(tail));
  return product.real.reduce((sum, value) => sum + value, 0);
}

export function complexScore({ head = complexVector(), relation = complexVector(), tail = complexVector() } = {}) {
  return complexTriLinear(head, relation, tail);
}

export function tcomplexScore({ head = complexVector(), relation = complexVector(), tail = complexVector(), time = complexVector() } = {}) {
  return complexTriLinear(complexMultiply(head, time), relation, tail);
}

export function tntcomplexScore({
  head = complexVector(),
  relation = complexVector(),
  tail = complexVector(),
  time = complexVector(),
  nonTemporalWeight = 1,
  temporalWeight = 1,
} = {}) {
  return (Number(temporalWeight) || 0) * tcomplexScore({ head, relation, tail, time })
    + (Number(nonTemporalWeight) || 0) * complexScore({ head, relation, tail });
}

export function timePlexScore({
  head = complexVector(),
  relation = complexVector(),
  tail = complexVector(),
  start = complexVector(),
  end = complexVector(),
  intervalWeight = 0.5,
} = {}) {
  const startScore = tcomplexScore({ head, relation, tail, time: start });
  const endScore = tcomplexScore({ head, relation, tail, time: end });
  const intervalInteraction = complexTriLinear(start, relation, complexConjugate(end));
  return startScore + endScore + (Number(intervalWeight) || 0) * intervalInteraction;
}

export function cronQuestionState({ questionVector = [], entityState = [], relationState = [], timeState = [] } = {}) {
  return ffnConcat([questionVector, entityState, relationState, timeState]);
}

export function typedGrounding(value = {}, embeddings = {}) {
  const type = value.type || value.kind || 'zero';
  if (type === 'entity') return embeddings.entities?.[value.id] || embeddings.entity?.[value.id] || [];
  if (type === 'time') return embeddings.times?.[value.id] || embeddings.time?.[value.id] || [];
  if (type === 'relation') return embeddings.relations?.[value.id] || embeddings.relation?.[value.id] || [];
  return [];
}

export function temporalKgqaForwardEq6({ questionState = [], candidateStates = [], weights = null, bias = 0 } = {}) {
  const q = weights ? weights.map(row => dot(row, questionState)) : questionState;
  return candidateStates.map((candidate, index) => ({
    index,
    score: dot(q, candidate) + (Number(bias) || 0),
  }));
}

export function temporalKgqaForwardEq7({ logits = [], candidates = [] } = {}) {
  const probabilities = softmax(logits);
  return candidates.map((candidate, index) => ({
    candidate,
    probability: probabilities[index] || 0,
  })).sort((a, b) => b.probability - a.probability);
}

export function crossEntropyLoss(probabilities = [], targetIndex = 0) {
  const p = Math.max(1e-12, Number(probabilities[targetIndex]) || 0);
  return -Math.log(p);
}

export function answerSpaceForTemporalKgqa(templateType = 'entity_at_time') {
  const type = TEMPORAL_KGQA_TEMPLATE_TYPES.includes(templateType) ? templateType : 'entity_at_time';
  if (['time_join', 'duration'].includes(type)) return 'time_or_duration';
  return 'entity';
}

export function applyTemporalTemplate(facts = [], { templateType = 'entity_at_time', anchorTime = null } = {}) {
  const type = TEMPORAL_KGQA_TEMPLATE_TYPES.includes(templateType) ? templateType : classifyTemporalKgqaTemplate(templateType);
  const rows = facts.map(makeTemporalKgFact);
  if (type === 'first') return [...rows].sort((a, b) => Number(a.start ?? Infinity) - Number(b.start ?? Infinity)).slice(0, 1);
  if (type === 'last') return [...rows].sort((a, b) => Number(b.end ?? b.start ?? -Infinity) - Number(a.end ?? a.start ?? -Infinity)).slice(0, 1);
  if (type === 'before') return rows.filter(row => anchorTime == null || Number(row.end ?? row.start ?? Infinity) < Number(anchorTime));
  if (type === 'after') return rows.filter(row => anchorTime == null || Number(row.start ?? -Infinity) > Number(anchorTime));
  if (type === 'duration') {
    return rows.map(row => ({ ...row, duration: Number(row.end ?? row.start ?? 0) - Number(row.start ?? row.end ?? 0) }));
  }
  return rows;
}

export function tequilaDecomposeQuestion(question = '') {
  const templateType = classifyTemporalKgqaTemplate(question);
  const placeholders = {
    entity: (text(question).match(/\b[A-Z][A-Za-z0-9_-]+\b/g) || [])[0] || '[ENTITY]',
    relation: templateType,
    time: (text(question).match(/\b(?:19|20)\d{2}\b/) || [])[0] || '[TIME]',
  };
  return {
    question: text(question),
    template_type: templateType,
    answer_space: answerSpaceForTemporalKgqa(templateType),
    placeholders,
    operators: ['detect_template', 'ground_entities_relations_times', 'retrieve_temporal_facts', 'score_answers'],
  };
}

export function tequilaPipeline({ question = '', facts = [], embeddings = {}, candidates = [] } = {}) {
  const decomposition = tequilaDecomposeQuestion(question);
  const filteredFacts = applyTemporalTemplate(facts, {
    templateType: decomposition.template_type,
    anchorTime: Number(decomposition.placeholders.time) || null,
  });
  const candidateRows = candidates.length
    ? candidates
    : [...new Set(filteredFacts.map(row => decomposition.answer_space === 'time_or_duration' ? (row.start ?? row.end) : row.tail).filter(value => value != null))];
  const questionState = cronQuestionState({
    questionVector: encodeQuestionKeywords(question).map(token => token.length),
    entityState: typedGrounding({ type: 'entity', id: decomposition.placeholders.entity }, embeddings),
    timeState: typedGrounding({ type: 'time', id: decomposition.placeholders.time }, embeddings),
  });
  const candidateStates = candidateRows.map(candidate => {
    const vector = typedGrounding({ type: decomposition.answer_space === 'entity' ? 'entity' : 'time', id: candidate }, embeddings);
    return vector.length ? vector : [String(candidate).length];
  });
  const logits = temporalKgqaForwardEq6({ questionState, candidateStates }).map(row => row.score);
  const ranked = temporalKgqaForwardEq7({ logits, candidates: candidateRows });
  return {
    aladdin: ALADDIN_TEMPORAL_KG_GUARDRAILS,
    model: 'TEQUILA+CRON deterministic operator plan',
    decomposition,
    filtered_facts: filteredFacts,
    ranked_answers: ranked,
  };
}

export function teaeAdd(fact = {}, event = {}) {
  const row = makeTemporalKgFact(fact);
  return {
    ...row,
    qualifiers: {
      ...row.qualifiers,
      added_event: text(event.id || event.label || event),
    },
  };
}

export function teaeReplace(fact = {}, event = {}) {
  const row = makeTemporalKgFact(fact);
  return {
    ...row,
    tail: text(event.tail || event.object || event.label || event),
    qualifiers: {
      ...row.qualifiers,
      replaced_by_event: text(event.id || event.label || event),
    },
  };
}

export function earlyStopOnValidation(history = [], { patience = 3, metric = 'hits_at_10' } = {}) {
  if (history.length <= patience) return { stop: false, best_index: history.length - 1 };
  let bestIndex = 0;
  for (let i = 1; i < history.length; i += 1) {
    if ((Number(history[i][metric]) || 0) > (Number(history[bestIndex][metric]) || 0)) bestIndex = i;
  }
  return {
    stop: history.length - 1 - bestIndex >= patience,
    best_index: bestIndex,
    best_value: Number(history[bestIndex]?.[metric]) || 0,
  };
}

export function temporalKgSplitLeakageCheck({ train = [], valid = [], test = [] } = {}) {
  const key = row => temporalKgFactToTuple(row).join('|');
  const trainSet = new Set(train.map(key));
  const validSet = new Set(valid.map(key));
  const testSet = new Set(test.map(key));
  const validLeakage = [...validSet].filter(row => trainSet.has(row));
  const testLeakage = [...testSet].filter(row => trainSet.has(row) || validSet.has(row));
  return {
    leakage_free: validLeakage.length === 0 && testLeakage.length === 0,
    valid_leakage: validLeakage,
    test_leakage: testLeakage,
  };
}

export function temporalKgqaModelCard() {
  return {
    models: TEMPORAL_KGQA_MODELS,
    task_assumptions: ['answer_is_entity_or_time_duration', 'facts_are_temporal_tuples', 'templates_include_before_after_first_last_time_join'],
    validation: ['hits_at_10_early_stop', 'split_leakage_check', 'typed_entity_time_grounding'],
    guardrails: ALADDIN_TEMPORAL_KG_GUARDRAILS,
  };
}
