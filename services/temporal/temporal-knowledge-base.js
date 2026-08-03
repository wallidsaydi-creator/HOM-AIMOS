/**
 * temporal-knowledge-base.js - temporal KB fact/probe operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: this file is pure deterministic math/state transformation. It
 * does not mutate memory, prune evidence, apply decay, delete records, or call
 * providers. In recall it contributes derived temporal fact diagnostics and
 * bounded native scoring signals.
 *
 * Paper authority:
 * - Can Language Models Serve as Temporal Knowledge Bases?.pdf
 *
 * Core techniques implemented:
 * - Temporally scoped fact state: <S, P, O, ST, ET>.
 * - Conflicting arity categories: 1-N, N-1, N-M.
 * - Prompt textualization: "from ST to ET" and "in T".
 * - Entity-level MLM masking with full answer-list retention.
 * - Four-way masking over subject, object, start time, end time; predicate is
 *   not masked.
 * - Dynamic time masking with k percent alternate-time masking and 10 variants.
 * - Query Acc@K and answer-oriented Hit@K.
 * - Implicit temporal query generation, distractor construction, and zero-shot
 *   template protocol descriptors.
 */

export const ALADDIN_TEMPORAL_KB_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Temporal KB operators construct derived examples, diagnostics, and metrics only; canonical memories and rankings are untouched.',
});

export const TEMPORAL_KB_ARITY = Object.freeze({
  ONE_TO_ONE: '1-1',
  ONE_TO_MANY: '1-N',
  MANY_TO_ONE: 'N-1',
  MANY_TO_MANY: 'N-M',
});

export const TEMPORAL_KB_MASK_FIELDS = Object.freeze({
  SUBJECT: 'subject',
  OBJECT: 'object',
  START_TIME: 'start_time',
  END_TIME: 'end_time',
});

export const LAMA_TK_EXCLUDED_COMPLEX_QUERY_TYPES = Object.freeze([
  'first_last',
  'before_after',
]);

export const TEMPORAL_KB_MODEL_SPECS = Object.freeze({
  'roberta-6l': {
    name: 'RoBERTa(6L)',
    layers: 6,
    hidden_size: 768,
    attention_heads: 12,
    parameters_millions: 89,
    initialization: 'DistilRoBERTa-base',
    training_focus: 'LAMA-TK temporal facts only',
  },
  'roberta-12l': {
    name: 'RoBERTa(12L)',
    layers: 12,
    hidden_size: 768,
    attention_heads: 12,
    parameters_millions: 125,
    initialization: 'HuggingFace RoBERTa-base',
    training_focus: 'LAMA-TK temporal facts only',
  },
  'roberta-randinit-12l': {
    name: 'RoBERTa-randinit(12L)',
    layers: 12,
    hidden_size: 768,
    attention_heads: 12,
    parameters_millions: 125,
    initialization: 'random',
    training_focus: 'LAMA-TK temporal facts only',
  },
  't5-cbqa': {
    name: 'T5-cbqa',
    layers: null,
    hidden_size: null,
    attention_heads: null,
    parameters_millions: 737,
    initialization: 'published CBQA baseline',
    training_focus: 'comparison baseline',
  },
});

function asText(value) {
  return String(value ?? '').trim();
}

function normalizeDateToken(value) {
  const text = asText(value);
  const year = text.match(/\b(?:19|20)\d{2}\b/)?.[0] || text;
  return year;
}

function keyOf(parts = []) {
  return parts.map(part => asText(part).toLowerCase()).join('\u0001');
}

function unique(values = []) {
  return [...new Set(values.map(asText).filter(Boolean))];
}

function mulberry32(seed) {
  let state = Number(seed) >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function normalizeTemporalKbFact(fact = {}) {
  return {
    subject: asText(fact.subject ?? fact.s ?? fact.S),
    predicate: asText(fact.predicate ?? fact.relation ?? fact.p ?? fact.P),
    object: asText(fact.object ?? fact.o ?? fact.O),
    start_time: normalizeDateToken(fact.start_time ?? fact.startTime ?? fact.ST ?? fact.st),
    end_time: normalizeDateToken(fact.end_time ?? fact.endTime ?? fact.ET ?? fact.et),
    relation_type: asText(fact.relation_type ?? fact.relationType ?? ''),
    source: asText(fact.source ?? ''),
    metadata: fact.metadata && typeof fact.metadata === 'object' ? { ...fact.metadata } : {},
  };
}

export function temporalFactHasBoundaries(fact = {}) {
  const row = normalizeTemporalKbFact(fact);
  return Boolean(row.start_time && row.end_time);
}

export function temporalFactState(fact = {}) {
  const row = normalizeTemporalKbFact(fact);
  return {
    aladdin: ALADDIN_TEMPORAL_KB_GUARDRAILS,
    tuple: [row.subject, row.predicate, row.object, row.start_time, row.end_time],
    labels: ['S', 'P', 'O', 'ST', 'ET'],
    fact: row,
  };
}

export function classifyTemporalRelationArity(facts = []) {
  const rows = facts.map(normalizeTemporalKbFact).filter(row => row.subject && row.predicate && row.object);
  const byPredicate = new Map();
  for (const row of rows) {
    const bucket = byPredicate.get(row.predicate) || { subjectsByObject: new Map(), objectsBySubject: new Map(), facts: [] };
    const subjectKey = row.subject;
    const objectKey = row.object;
    bucket.objectsBySubject.set(subjectKey, unique([...(bucket.objectsBySubject.get(subjectKey) || []), objectKey]));
    bucket.subjectsByObject.set(objectKey, unique([...(bucket.subjectsByObject.get(objectKey) || []), subjectKey]));
    bucket.facts.push(row);
    byPredicate.set(row.predicate, bucket);
  }
  return Object.fromEntries([...byPredicate.entries()].map(([predicate, bucket]) => {
    const hasOneToMany = [...bucket.objectsBySubject.values()].some(objects => objects.length > 1);
    const hasManyToOne = [...bucket.subjectsByObject.values()].some(subjects => subjects.length > 1);
    const arity = hasOneToMany && hasManyToOne
      ? TEMPORAL_KB_ARITY.MANY_TO_MANY
      : hasOneToMany
        ? TEMPORAL_KB_ARITY.ONE_TO_MANY
        : hasManyToOne
          ? TEMPORAL_KB_ARITY.MANY_TO_ONE
          : TEMPORAL_KB_ARITY.ONE_TO_ONE;
    return [predicate, {
      arity,
      subject_count: bucket.objectsBySubject.size,
      object_count: bucket.subjectsByObject.size,
      fact_count: bucket.facts.length,
    }];
  }));
}

export function temporalScopeText(fact = {}, { durative = true } = {}) {
  const row = normalizeTemporalKbFact(fact);
  if (!durative && row.start_time) return `in ${row.start_time}`;
  if (row.start_time && row.end_time) return `from ${row.start_time} to ${row.end_time}`;
  if (row.start_time) return `in ${row.start_time}`;
  return '';
}

export function temporalScopeTokenSequence(tokens = [], fact = {}) {
  const row = normalizeTemporalKbFact(fact);
  return [
    ...tokens.map(asText).filter(Boolean),
    'from',
    row.start_time,
    'to',
    row.end_time,
  ].filter(Boolean);
}

export function applyTemporalRelationTemplate(fact = {}, templates = {}) {
  const row = normalizeTemporalKbFact(fact);
  const template = templates[row.predicate] || templates.default || '[X] [P] [Y] [T]';
  return template
    .replace(/\[X\]/g, row.subject)
    .replace(/\[S\]/g, row.subject)
    .replace(/\[P\]/g, row.predicate)
    .replace(/\[Y\]/g, row.object)
    .replace(/\[O\]/g, row.object)
    .replace(/\[ST\]/g, row.start_time)
    .replace(/\[ET\]/g, row.end_time)
    .replace(/\[T\]/g, temporalScopeText(row));
}

export function temporalPromptStatement(fact = {}, { template = '', durative = true } = {}) {
  const row = normalizeTemporalKbFact(fact);
  const templateIncludesScope = /\[(?:T|ST|ET)\]/.test(template);
  const base = template
    ? applyTemporalRelationTemplate(row, { default: template })
    : `${row.subject} ${row.predicate} ${row.object}`;
  const scope = temporalScopeText(row, { durative });
  return [base, templateIncludesScope ? '' : scope].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}

export function entityLevelMask(tokens = [], { entityStart = 0, entityLength = 1, maskToken = '[MASK]' } = {}) {
  const start = Math.max(0, Number(entityStart) || 0);
  const length = Math.max(1, Number(entityLength) || 1);
  return [
    ...tokens.slice(0, start),
    maskToken,
    ...tokens.slice(start + length),
  ];
}

export function maskTemporalFact(fact = {}, {
  maskField = TEMPORAL_KB_MASK_FIELDS.OBJECT,
  maskToken = '[MASK]',
  template = '',
} = {}) {
  const row = normalizeTemporalKbFact(fact);
  const masked = { ...row };
  const field = String(maskField);
  if (!Object.values(TEMPORAL_KB_MASK_FIELDS).includes(field)) throw new Error(`invalid_temporal_kb_mask_field:${field}`);
  const answer = row[field];
  masked[field] = maskToken;
  const statement = template
    ? applyTemporalRelationTemplate(masked, { default: template })
    : temporalPromptStatement(masked);
  return {
    fact: row,
    mask_field: field,
    answer,
    answer_list: answer ? [answer] : [],
    predicate_masked: false,
    statement,
  };
}

export function buildFourWayMaskedStatements(fact = {}, options = {}) {
  return [
    TEMPORAL_KB_MASK_FIELDS.SUBJECT,
    TEMPORAL_KB_MASK_FIELDS.OBJECT,
    TEMPORAL_KB_MASK_FIELDS.START_TIME,
    TEMPORAL_KB_MASK_FIELDS.END_TIME,
  ].map(maskField => maskTemporalFact(fact, { ...options, maskField }));
}

function queryIdentity(example = {}) {
  const fact = example.fact || normalizeTemporalKbFact(example);
  return keyOf([
    example.mask_field,
    example.statement,
    fact.predicate,
  ]);
}

export function retainFullAnswerLists(maskedExamples = []) {
  const grouped = new Map();
  for (const example of maskedExamples) {
    const key = queryIdentity(example);
    const current = grouped.get(key) || { ...example, answer_list: [] };
    current.answer_list = unique([...current.answer_list, example.answer, ...(example.answer_list || [])]);
    grouped.set(key, current);
  }
  return [...grouped.values()];
}

export function buildMaskedTemporalExamples(facts = [], options = {}) {
  return retainFullAnswerLists(facts.flatMap(fact => buildFourWayMaskedStatements(fact, options)));
}

export function splitSingleAndMultiAnswerExamples(examples = []) {
  const rows = examples.map(example => ({ ...example, answer_list: unique(example.answer_list || [example.answer]) }));
  return {
    single_answer: rows.filter(row => row.answer_list.length <= 1),
    multiple_answer: rows.filter(row => row.answer_list.length > 1),
  };
}

export function conflictAblationExamples(examples = [], { removeConflicts = false } = {}) {
  const rows = examples.map(example => ({ ...example, answer_list: unique(example.answer_list || [example.answer]) }));
  return removeConflicts ? rows.filter(row => row.answer_list.length <= 1) : rows;
}

export function selectFrequentTemporalRelations(facts = [], { topN = 5 } = {}) {
  const counts = new Map();
  for (const fact of facts.map(normalizeTemporalKbFact).filter(temporalFactHasBoundaries)) {
    counts.set(fact.predicate, (counts.get(fact.predicate) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, topN)
    .map(([predicate, count]) => ({ predicate, count }));
}

export function constructLamaTkDataset(facts = [], { topN = 5, templates = {} } = {}) {
  const relations = selectFrequentTemporalRelations(facts, { topN });
  const allowed = new Set(relations.map(row => row.predicate));
  const scopedFacts = facts.map(normalizeTemporalKbFact)
    .filter(fact => temporalFactHasBoundaries(fact) && allowed.has(fact.predicate));
  return {
    aladdin: ALADDIN_TEMPORAL_KB_GUARDRAILS,
    relation_count: relations.length,
    relations,
    facts: scopedFacts,
    statements: scopedFacts.map(fact => temporalPromptStatement(fact, { template: templates[fact.predicate] || '' })),
    masked_examples: buildMaskedTemporalExamples(scopedFacts, { template: templates.default || '' }),
  };
}

export function dynamicTimeMaskVariants(fact = {}, { kPercent = 10, duplicates = 10, maskToken = '[MASK]' } = {}) {
  const row = normalizeTemporalKbFact(fact);
  const alternateCount = Math.round((Math.max(0, Math.min(100, Number(kPercent))) / 100) * duplicates);
  const variants = [];
  for (let index = 0; index < duplicates; index += 1) {
    const targetField = index % 2 === 0 ? TEMPORAL_KB_MASK_FIELDS.START_TIME : TEMPORAL_KB_MASK_FIELDS.END_TIME;
    const otherField = targetField === TEMPORAL_KB_MASK_FIELDS.START_TIME
      ? TEMPORAL_KB_MASK_FIELDS.END_TIME
      : TEMPORAL_KB_MASK_FIELDS.START_TIME;
    const maskOtherTemporalInfo = index < alternateCount;
    const masked = { ...row };
    masked[targetField] = maskToken;
    if (maskOtherTemporalInfo) masked[otherField] = maskToken;
    variants.push({
      index,
      k_percent: kPercent,
      mask_mode: maskOtherTemporalInfo ? 'mask_other_temporal_information' : 'mask_target_timestamp',
      mask_field: targetField,
      other_temporal_field: otherField,
      statement: temporalPromptStatement(masked),
      answer: row[targetField],
      fact: row,
    });
  }
  return variants;
}

export function dynamicMaskScoreDelta(score, baseline) {
  const value = Number(score) || 0;
  const base = Number(baseline) || 0;
  const delta = value - base;
  return {
    score: value,
    baseline: base,
    delta,
    notation: `${value.toFixed(4)}(${delta >= 0 ? '+' : ''}${delta.toFixed(4)})`,
  };
}

export function temporalBoundaryTemplates(fact = {}) {
  const row = normalizeTemporalKbFact(fact);
  return [
    `${row.subject} was elected ${row.object} in [MASK]`,
    `${row.subject} resigned from ${row.object} in [MASK]`,
    `${row.subject} held the position of ${row.object} from [MASK] to ${row.end_time}`,
    `${row.subject} held the position of ${row.object} from ${row.start_time} to [MASK]`,
  ];
}

export function zeroShotBoundaryProtocol({ trainingTemplates = [], evaluationTemplates = [] } = {}) {
  const train = new Set(trainingTemplates.map(asText));
  const evalRows = evaluationTemplates.map(asText).filter(Boolean);
  return {
    zero_shot: evalRows.every(template => !train.has(template)),
    training_templates: [...train],
    evaluation_templates: evalRows,
  };
}

export function sampleImplicitTemporalYear(fact = {}, { seed = 1 } = {}) {
  const row = normalizeTemporalKbFact(fact);
  const start = Number.parseInt(row.start_time, 10);
  const end = Number.parseInt(row.end_time, 10);
  if (!Number.isInteger(start) || !Number.isInteger(end)) return '';
  const lo = Math.min(start, end);
  const hi = Math.max(start, end);
  const rng = mulberry32(seed);
  return String(lo + Math.floor(rng() * (hi - lo + 1)));
}

export function implicitTemporalQueries(fact = {}, { seed = 1 } = {}) {
  const row = normalizeTemporalKbFact(fact);
  const year = sampleImplicitTemporalYear(row, { seed });
  return {
    original: `${row.subject} held the position of ${row.object} in ${year}`,
    new_template: `${row.subject} served as ${row.object} in ${year}`,
    timestamp: year,
    fact: row,
  };
}

export function buildTemporalDistractors(fact = {}, factPool = []) {
  const row = normalizeTemporalKbFact(fact);
  const pool = factPool.map(normalizeTemporalKbFact);
  return {
    same_subject_predicate_different_object: pool.find(candidate =>
      candidate.subject === row.subject
      && candidate.predicate === row.predicate
      && candidate.object !== row.object
    ) || null,
    same_subject_different_predicate_object: pool.find(candidate =>
      candidate.subject === row.subject
      && candidate.predicate !== row.predicate
      && candidate.object !== row.object
    ) || null,
    source_tuple: [row.subject, row.predicate, row.object, row.start_time, row.end_time],
  };
}

export function accAtK(predictions = [], answerList = [], k = 1) {
  const top = new Set(predictions.slice(0, k).map(asText));
  return answerList.map(asText).some(answer => top.has(answer)) ? 1 : 0;
}

export function hitAtK(predictions = [], targetAnswer = '', k = 1) {
  const top = new Set(predictions.slice(0, k).map(asText));
  return top.has(asText(targetAnswer)) ? 1 : 0;
}

export function answerOrientedHitAtK(predictions = [], answerList = [], k = 5) {
  const answers = unique(answerList);
  if (!answers.length) return 0;
  return answers.reduce((sum, answer) => sum + hitAtK(predictions, answer, k), 0) / answers.length;
}

export function evaluateTemporalKbTopK(rows = [], { k = 5 } = {}) {
  const scored = rows.map(row => ({
    acc: accAtK(row.predictions || [], row.answer_list || [], k),
    hit: answerOrientedHitAtK(row.predictions || [], row.answer_list || [], k),
  }));
  const n = scored.length || 1;
  return {
    k,
    acc_at_k: scored.reduce((sum, row) => sum + row.acc, 0) / n,
    hit_at_k: scored.reduce((sum, row) => sum + row.hit, 0) / n,
    row_count: rows.length,
  };
}

export function buildTemporalKbMetricSuite(rows = []) {
  return {
    AccAt1: evaluateTemporalKbTopK(rows, { k: 1 }).acc_at_k,
    AccAt5: evaluateTemporalKbTopK(rows, { k: 5 }).acc_at_k,
    HitAt5: evaluateTemporalKbTopK(rows, { k: 5 }).hit_at_k,
    HitAt10: evaluateTemporalKbTopK(rows, { k: 10 }).hit_at_k,
  };
}

export function isExcludedComplexTemporalQuery(type) {
  return LAMA_TK_EXCLUDED_COMPLEX_QUERY_TYPES.includes(asText(type).toLowerCase().replace(/[- ]+/g, '_'));
}

export function modelSpec(name) {
  const key = asText(name).toLowerCase();
  return TEMPORAL_KB_MODEL_SPECS[key] || null;
}

export function maskedLmTemporalKbPlan({ model = 'roberta-12l', dataset = 'LAMA-TK' } = {}) {
  return {
    aladdin: ALADDIN_TEMPORAL_KB_GUARDRAILS,
    model: modelSpec(model),
    dataset,
    method: 'masked_language_model_as_temporal_kb',
    predicate_masking: 'skipped',
    temporal_scope_modeling: ['from ST to ET', 'in T'],
    training_focus: 'temporal knowledge contained in training data',
  };
}

export function augmentEntityVocabulary(baseVocabulary = [], entities = []) {
  const vocabulary = unique([...baseVocabulary, ...entities]);
  const entitySet = new Set(entities.map(asText));
  return vocabulary.map((token, index) => ({
    token,
    index,
    is_temporal_entity: entitySet.has(token),
  }));
}

export function stableSoftmax(scores = []) {
  if (!scores.length) return [];
  const max = Math.max(...scores);
  const exp = scores.map(score => Math.exp(score - max));
  const total = exp.reduce((sum, value) => sum + value, 0) || 1;
  return exp.map(value => value / total);
}

export function projectMaskHiddenState(maskHiddenState = [], entityEmbeddings = [], entityVocabulary = []) {
  const logits = entityEmbeddings.map(vector => vector.reduce((sum, value, index) => sum + value * (Number(maskHiddenState[index]) || 0), 0));
  const probabilities = stableSoftmax(logits);
  return entityVocabulary.map((entity, index) => ({
    entity: asText(entity.token || entity),
    logit: logits[index] ?? 0,
    probability: probabilities[index] ?? 0,
  })).sort((a, b) => b.probability - a.probability || a.entity.localeCompare(b.entity));
}

export function temporalKgSubsetConstruction(facts = [], { topN = 7, templates = {} } = {}) {
  return constructLamaTkDataset(facts, { topN, templates });
}

export function recitingEvaluationProtocol({ facts = [], predictions = [], topK = [1, 5, 10] } = {}) {
  const examples = buildMaskedTemporalExamples(facts);
  const rows = examples.map((example, index) => ({
    ...example,
    predictions: predictions[index] || [],
  }));
  return {
    examples,
    metrics: Object.fromEntries(topK.map(k => [`k${k}`, evaluateTemporalKbTopK(rows, { k })])),
  };
}
