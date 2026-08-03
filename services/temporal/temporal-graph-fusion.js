/**
 * temporal-graph-fusion.js - temporal graph fusion operators
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: pure deterministic transformations. No provider calls, no
 * canonical memory mutation, no pruning, no decay, no deletion, and no provider
 * calls. In recall it contributes derived temporal graph signals to bounded
 * native scoring.
 *
 * Paper authority:
 * - Fusing Temporal Graphs .pdf
 */

export const ALADDIN_TEMPORAL_GRAPH_FUSION_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Graph fusion functions produce derived input sequences, graph states, and diagnostics only.',
});

export const TEMPORAL_GRAPH_RELATIONS = Object.freeze([
  'before',
  'after',
  'includes',
  'included_by',
  'overlap',
  'simultaneous',
]);

export const LONGT5_BASE_CONFIG = Object.freeze({
  model: 'LongT5-Base',
  parameters_millions: 250,
  checkpoint: 'long-t5-tglobal-base',
  attention: 'transient-global',
  context_token_limit: 10000,
});

export const FUSING_TEMPORAL_GRAPHS_CONFIG = Object.freeze({
  gpt4_sample_size: { easy: 100, hard: 100, total: 200 },
  error_analysis: { err_correct_fid_wrong: 10, fid_correct_err_wrong: 10, splits: ['TimeQA Easy', 'TimeQA Hard'], total: 40 },
  hyperparameter_grid: {
    learning_rate: [1e-5, 2e-5, 3e-5, 4e-5, 5e-5],
    batch_size: [4, 8, 16, 32],
    rel_graph_conv_layers: [1, 3, 6],
  },
  compute_environment: { gpu: 'Nvidia A6000', gpu_count: 4 },
});

function text(value) {
  return String(value ?? '').trim();
}

function normRelation(value) {
  const raw = text(value).toLowerCase().replace(/[- ]+/g, '_');
  if (raw === 'included_in' || raw === 'is_included' || raw === 'is_included_by') return 'included_by';
  if (TEMPORAL_GRAPH_RELATIONS.includes(raw)) return raw;
  return 'overlap';
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

function mean(values = []) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

export function createTemporalGraph({ events = [], timexes = [], edges = [], questionTime = null } = {}) {
  const nodes = [
    ...events.map((event, index) => ({ id: text(event.id || `e${index + 1}`), type: 'event', text: text(event.text || event.label || event.id) })),
    ...timexes.map((timex, index) => ({ id: text(timex.id || timex.tid || `t${index + 1}`), type: 'time', text: text(timex.text || timex.value || timex.id), interval: timex.interval || null })),
  ];
  if (questionTime) nodes.push({ id: 'question_time', type: 'question_time', text: text(questionTime.text || questionTime.value || questionTime) });
  return {
    aladdin: ALADDIN_TEMPORAL_GRAPH_FUSION_GUARDRAILS,
    nodes,
    edges: edges.map((edge, index) => ({
      id: text(edge.id || `r${index + 1}`),
      from: text(edge.from || edge.left),
      to: text(edge.to || edge.right),
      relation: normRelation(edge.relation || edge.type),
    })),
  };
}

export function intervalRelation(left = {}, right = {}) {
  const a0 = Date.parse(left.start ?? left.from ?? left.begin ?? left);
  const a1 = Date.parse(left.end ?? left.to ?? left.begin ?? left);
  const b0 = Date.parse(right.start ?? right.from ?? right.begin ?? right);
  const b1 = Date.parse(right.end ?? right.to ?? right.begin ?? right);
  if (![a0, a1, b0, b1].every(Number.isFinite)) return 'overlap';
  if (a1 < b0) return 'before';
  if (a0 > b1) return 'after';
  if (a0 <= b0 && a1 >= b1) return 'includes';
  if (a0 >= b0 && a1 <= b1) return 'included_by';
  if (a0 === b0 && a1 === b1) return 'simultaneous';
  return 'overlap';
}

export function composeTemporalGraphRelations(first, second) {
  const a = normRelation(first);
  const b = normRelation(second);
  if (a === 'before' && ['before', 'includes', 'overlap', 'included_by'].includes(b)) return 'before';
  if (a === 'after' && ['after', 'included_by', 'overlap', 'includes'].includes(b)) return 'after';
  if (a === 'included_by' && b === 'before') return 'before';
  if (a === 'includes' && b === 'after') return 'after';
  if (a === 'simultaneous') return b;
  if (b === 'simultaneous') return a;
  return 'overlap';
}

export function inferRelationFromPath(relations = []) {
  return relations.map(normRelation).reduce((current, next) => current ? composeTemporalGraphRelations(current, next) : next, '');
}

export function shortestPath(graph = {}, from = '', to = '') {
  const start = text(from);
  const target = text(to);
  const adjacency = new Map();
  for (const edge of graph.edges || []) {
    const rows = adjacency.get(edge.from) || [];
    rows.push(edge);
    adjacency.set(edge.from, rows);
  }
  const queue = [{ node: start, path: [] }];
  const seen = new Set([start]);
  while (queue.length) {
    const current = queue.shift();
    if (current.node === target) return current.path;
    for (const edge of adjacency.get(current.node) || []) {
      if (seen.has(edge.to)) continue;
      seen.add(edge.to);
      queue.push({ node: edge.to, path: [...current.path, edge] });
    }
  }
  return [];
}

export function questionTimeRelation(graph = {}, eventId = '') {
  const path = shortestPath(graph, eventId, 'question_time');
  return {
    event: eventId,
    question_time: 'question_time',
    path,
    relation: inferRelationFromPath(path.map(edge => edge.relation)) || 'overlap',
  };
}

export function temporalRelationTag(relation, content = '') {
  const rel = normRelation(relation).replace(/_/g, ' ');
  return `<${rel}>${text(content)}</${rel}>`;
}

export function errFuseInput({ question = '', context = '', graph = {}, mode = 'DT2QT' } = {}) {
  const edgeText = (graph.edges || []).map(edge => temporalRelationTag(edge.relation, `${edge.from} ${edge.to}`)).join(' ');
  return {
    aladdin: ALADDIN_TEMPORAL_GRAPH_FUSION_GUARDRAILS,
    mode,
    sequence: `${text(question)} ${text(context)} ${edgeText}`.replace(/\s+/g, ' ').trim(),
    graph_token_count: edgeText.split(/\s+/).filter(Boolean).length,
  };
}

export function extendTemporalGraphVocabulary(baseVocabulary = []) {
  const additions = ['<e>', '</e>', '<question time>', '</question time>', ...TEMPORAL_GRAPH_RELATIONS.flatMap(rel => [`<${rel.replace(/_/g, ' ')}>`, `</${rel.replace(/_/g, ' ')}>`])];
  return [...new Set([...baseVocabulary, ...additions])];
}

export function wrapGraphNode(textValue = '') {
  return `<e>${text(textValue)}</e>`;
}

export function relGraphConvUpdate({ self = [], neighborsByRelation = {}, weightsByRelation = {}, selfWeight = null } = {}) {
  let aggregate = selfWeight ? multiplyMatrixVector(selfWeight, self) : [...self];
  for (const [relation, neighbors] of Object.entries(neighborsByRelation)) {
    const weight = weightsByRelation[relation] || null;
    const c = neighbors.length || 1;
    for (const neighbor of neighbors) {
      const transformed = weight ? multiplyMatrixVector(weight, neighbor) : neighbor;
      aggregate = add(aggregate, scale(transformed, 1 / c));
    }
  }
  return relu(aggregate);
}

function multiplyMatrixVector(matrix = [], vector = []) {
  return matrix.map(row => row.reduce((sum, value, index) => sum + (Number(value) || 0) * (Number(vector[index]) || 0), 0));
}

export function bootstrapConfidenceInterval(values = [], { iterations = 1000, alpha = 0.05 } = {}) {
  const rows = values.map(Number).filter(Number.isFinite);
  if (!rows.length) return { mean: 0, lower: 0, upper: 0, alpha };
  const samples = [];
  for (let i = 0; i < iterations; i += 1) {
    const draw = rows.map((_, index) => rows[(i + index * 17) % rows.length]);
    samples.push(mean(draw));
  }
  samples.sort((a, b) => a - b);
  return {
    mean: mean(rows),
    lower: samples[Math.floor((alpha / 2) * samples.length)] ?? samples[0],
    upper: samples[Math.ceil((1 - alpha / 2) * samples.length) - 1] ?? samples.at(-1),
    alpha,
  };
}

export function hyperparameterGrid() {
  const rows = [];
  for (const learning_rate of FUSING_TEMPORAL_GRAPHS_CONFIG.hyperparameter_grid.learning_rate) {
    for (const batch_size of FUSING_TEMPORAL_GRAPHS_CONFIG.hyperparameter_grid.batch_size) {
      for (const rel_graph_conv_layers of FUSING_TEMPORAL_GRAPHS_CONFIG.hyperparameter_grid.rel_graph_conv_layers) {
        rows.push({ learning_rate, batch_size, rel_graph_conv_layers });
      }
    }
  }
  return rows;
}

export function selectBestByDevExactMatch(candidates = []) {
  return [...candidates].sort((a, b) => (Number(b.dev_exact_match) || 0) - (Number(a.dev_exact_match) || 0))[0] || null;
}

export function noAnswerGate(context = '') {
  return text(context) ? { should_answer: true, output: null } : { should_answer: false, output: 'no answer' };
}

export function crossEncoderRankParagraphs(question = '', paragraphs = []) {
  const qTokens = new Set(text(question).toLowerCase().split(/\W+/).filter(Boolean));
  return paragraphs.map((paragraph, index) => {
    const pTokens = new Set(text(paragraph).toLowerCase().split(/\W+/).filter(Boolean));
    let overlap = 0;
    for (const token of qTokens) if (pTokens.has(token)) overlap += 1;
    return { paragraph, index, score: overlap / Math.max(1, qTokens.size) };
  }).sort((a, b) => b.score - a.score || a.index - b.index);
}

export function truncateToTokenLimit(textValue = '', limit = LONGT5_BASE_CONFIG.context_token_limit) {
  return text(textValue).split(/\s+/).slice(0, limit).join(' ');
}

export function graphFusionModelState(name = 'LongT5ERR') {
  const states = {
    FiD: { name: 'FiD', fusion: 'none' },
    LongT5ERR: { name: 'LongT5ERR', fusion: 'explicit_edge_representation', base: LONGT5_BASE_CONFIG },
    LongT5GNN: { name: 'LongT5GNN', fusion: 'relational_graph_convolution', base: LONGT5_BASE_CONFIG },
    GPT4: { name: 'GPT-4', fusion: 'in_context_err_optional' },
  };
  return states[name] || states.LongT5ERR;
}

export function deltaExactMatch(longT5err, fid) {
  return (Number(longT5err) || 0) - (Number(fid) || 0);
}

export function sampledGpt4Protocol() {
  return FUSING_TEMPORAL_GRAPHS_CONFIG.gpt4_sample_size;
}

export function contextWindowAblation(paragraphs = []) {
  return paragraphs.slice(0, 1);
}

export function temporalGraphFusionPlan() {
  return {
    construction: ['question_time_node', 'CAEVO_event_time_edges', 'SUTime_normalized_intervals', 'direct_interval_relations'],
    final_model_choice: 'DT2QT_ERR',
    rejected_preprocessing: ['coreference_resolution'],
    tested_but_lower: ['full_graph_convolution_over_final_hidden_embeddings'],
  };
}
