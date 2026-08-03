/**
 * memory-agent-benchmark.js - incremental multi-turn memory benchmark operators
 *
 * Status: Native capability service.
 * Runtime note: pure deterministic benchmark/config operators. No provider
 * calls, no canonical memory mutation, no pruning, no decay, no deletion, no
 * recall ranking changes.
 *
 * Paper authority:
 * - Evaluating Memory in LLM Agents via Incremental Multi-Turn Interactions.pdf
 */

export const ALADDIN_MEMORY_AGENT_BENCH_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Benchmark operators model input delivery, scoring, and derived views only.',
});

export const MEMORY_AGENT_COMPETENCIES = Object.freeze({
  AR: 'accurate_retrieval',
  TTL: 'test_time_learning',
  LRU: 'long_range_understanding',
  SF: 'selective_forgetting',
});

export const MEMORY_AGENT_STATE_MODALITIES = Object.freeze([
  'parameters',
  'vectors',
  'textual_histories',
  'external_databases',
]);

export const MEMORY_AGENT_CHUNK_SIZES = Object.freeze([512, 1024, 2048, 4096]);
export const MEMORY_AGENT_RETRIEVAL_K = Object.freeze([2, 5, 10]);
export const MEMORY_AGENT_CONTEXT_SCALES = Object.freeze([6000, 32000, 64000, 262000]);
export const MEMORY_AGENT_TASK_OUTPUT_LIMITS = Object.freeze({
  SH_QA: 50,
  MH_QA: 50,
  LME_S_STAR: 100,
  EventQA: 40,
  MCC: 20,
  MovieRecommendation: 300,
  InfinityBenchSum: 1200,
  DetectiveQA: 500,
  FactConsolidation: 10,
});

function text(value) {
  return String(value ?? '').trim();
}

function tokens(value) {
  return text(value).toLowerCase().split(/\W+/).filter(Boolean);
}

function estimateTokens(value = '') {
  return Math.ceil(text(value).length / 4);
}

function dot(a = [], b = []) {
  const n = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < n; i += 1) sum += (Number(a[i]) || 0) * (Number(b[i]) || 0);
  return sum;
}

function norm(a = []) {
  return Math.sqrt(a.reduce((sum, value) => sum + (Number(value) || 0) ** 2, 0));
}

export function memoryAgentCompetencyEnvelope() {
  return {
    aladdin: ALADDIN_MEMORY_AGENT_BENCH_GUARDRAILS,
    competencies: { ...MEMORY_AGENT_COMPETENCIES },
    state_modalities: [...MEMORY_AGENT_STATE_MODALITIES],
    focus_modalities: ['textual_histories', 'external_databases'],
  };
}

export function chunkLongContext(input = '', { chunkSize = 4096 } = {}) {
  const words = text(input).split(/\s+/).filter(Boolean);
  const chunks = [];
  for (let i = 0; i < words.length; i += chunkSize) {
    chunks.push({ id: `c${chunks.length + 1}`, text: words.slice(i, i + chunkSize).join(' '), index: chunks.length });
  }
  return chunks;
}

export function reconstructIncrementalTurns(input = '', options = {}) {
  return chunkLongContext(input, options).map(chunk => ({
    turn_id: chunk.id,
    order: chunk.index + 1,
    content: chunk.text,
    delivery: 'incremental_multi_turn',
  }));
}

export function contextWindowMemory(chunks = [], { tokenLimit = 100000 } = {}) {
  const retained = [];
  let total = 0;
  for (let i = chunks.length - 1; i >= 0; i -= 1) {
    const cost = estimateTokens(chunks[i].text || chunks[i].content || chunks[i]);
    if (total + cost > tokenLimit) break;
    retained.unshift(chunks[i]);
    total += cost;
  }
  return {
    retained,
    overflowed: retained.length < chunks.length,
    policy: 'fifo_context_window_view_only',
    token_estimate: total,
  };
}

export function topK(items = [], k = 10, scoreField = 'score') {
  return [...items].sort((a, b) => (Number(b[scoreField]) || 0) - (Number(a[scoreField]) || 0)).slice(0, k);
}

export function substringExactMatch(prediction = '', gold = '') {
  const p = text(prediction).toLowerCase();
  const g = text(gold).toLowerCase();
  return g && p.includes(g) ? 1 : 0;
}

export function recallAtK(predictions = [], gold = [], k = 5) {
  const top = new Set(predictions.slice(0, k).map(value => text(value).toLowerCase()));
  const answers = gold.map(value => text(value).toLowerCase()).filter(Boolean);
  if (!answers.length) return 0;
  return answers.filter(answer => top.has(answer)).length / answers.length;
}

export function summarizationDotProductScore({ fluency = 0, f1 = 0 } = {}) {
  return (Number(fluency) || 0) * (Number(f1) || 0);
}

export function serializeTtlClassificationSample({ sentence = '', label = '' } = {}) {
  return `${text(sentence)} \n Label: ${text(label)} \n`;
}

export function buildTtlClassificationContext(samples = []) {
  return [...samples].map(serializeTtlClassificationSample).join('');
}

export function selectMovieRecommendations(candidates = [], { count = 20 } = {}) {
  return topK(candidates, count).map(row => row.movie || row.title || row.id || row);
}

export function factConsolidationOrder(pairs = []) {
  return [...pairs].sort((a, b) => (Number(a.serial ?? a.id) || 0) - (Number(b.serial ?? b.id) || 0));
}

export function resolveFactByRecency(facts = []) {
  const ordered = factConsolidationOrder(facts);
  return ordered.at(-1) || null;
}

export function buildFactConsolidationContext(editPairs = []) {
  return factConsolidationOrder(editPairs).map(row => `${row.serial ?? row.id}. ${text(row.fact || row.text)}`).join('\n');
}

export function bm25Score(query = '', document = '', { k1 = 1.5, b = 0.75, avgdl = null } = {}) {
  const q = tokens(query);
  const d = tokens(document);
  const dl = d.length || 1;
  const average = avgdl || dl;
  let score = 0;
  for (const term of q) {
    const tf = d.filter(token => token === term).length;
    if (!tf) continue;
    score += ((tf * (k1 + 1)) / (tf + k1 * (1 - b + b * (dl / average))));
  }
  return score;
}

export function tfidfRetrieve(query = '', documents = [], { k = 10 } = {}) {
  return topK(documents.map((document, index) => ({
    document,
    index,
    score: bm25Score(query, document),
  })), k);
}

export function cosineSimilarity(a = [], b = []) {
  const denom = norm(a) * norm(b);
  return denom ? dot(a, b) / denom : 0;
}

export function embeddingRetrieve(queryEmbedding = [], documents = [], { k = 10 } = {}) {
  return topK(documents.map((document, index) => ({
    ...document,
    index,
    score: cosineSimilarity(queryEmbedding, document.embedding || []),
  })), k);
}

export function structureAugmentedRetrieve(query = '', graph = {}, { k = 10 } = {}) {
  const q = new Set(tokens(query));
  const nodes = graph.nodes || [];
  return topK(nodes.map((node, index) => {
    const nodeTokens = new Set(tokens([node.label, node.text, ...(node.neighbors || [])].join(' ')));
    let overlap = 0;
    for (const token of q) if (nodeTokens.has(token)) overlap += 1;
    return { ...node, index, score: overlap };
  }), k);
}

export function agenticRetrievalLoop({ query = '', retrieve = () => [], maxIterations = 3 } = {}) {
  const trace = [];
  let currentQuery = query;
  let evidence = [];
  for (let i = 0; i < maxIterations; i += 1) {
    const result = retrieve(currentQuery, evidence);
    evidence = [...evidence, ...(Array.isArray(result) ? result : [])];
    trace.push({ iteration: i + 1, query: currentQuery, evidence_count: evidence.length });
    if (!result || !result.length) break;
    currentQuery = `${query} ${result.map(row => row.text || row.document || '').join(' ')}`.slice(0, 1000);
  }
  return { trace, evidence };
}

export function buildEventQaQuestion({ previousEvents = [], correctEvent = '', distractors = [] } = {}) {
  return {
    previous_events: previousEvents.slice(0, 5),
    options: [correctEvent, ...distractors].slice(0, 6),
    answer: correctEvent,
  };
}

export function meanAccuracy(rows = []) {
  if (!rows.length) return 0;
  return rows.reduce((sum, row) => sum + (row.correct ? 1 : 0), 0) / rows.length;
}

export function latencyDecomposition({ memoryConstructionSeconds = 0, queryExecutionSeconds = 0, estimated = false } = {}) {
  return {
    MC: Number(memoryConstructionSeconds) || 0,
    QE: Number(queryExecutionSeconds) || 0,
    total: (Number(memoryConstructionSeconds) || 0) + (Number(queryExecutionSeconds) || 0),
    estimated_marker: estimated ? '*' : '',
  };
}

export function chunkSizePolicy(taskFamily = '') {
  const family = text(taskFamily).toLowerCase();
  if (['ar', 'sf', 'synthetic'].includes(family)) return 512;
  if (['mem0', 'zep', 'cognee', 'mirix', 'expensive'].includes(family)) return 4096;
  return 4096;
}

export function outputGate(task = '', answer = '') {
  const key = text(task);
  const limits = MEMORY_AGENT_TASK_OUTPUT_LIMITS;
  if (key === 'MCC') return `label: ${text(answer)}`;
  if (key === 'MovieRecommendation') return text(answer).split(/\n|,/).map(text).filter(Boolean).slice(0, 20);
  return text(answer).split(/\s+/).slice(0, limits[key] || 100).join(' ');
}

export function promptProtocol(type = 'memory_construction') {
  const prompts = {
    memory_construction: 'Please memorize it',
    constrained_qa: 'Only give me the answer and do not output any other words.',
    single_phrase: 'using a single phrase if possible',
    mcc_label: 'Only output "label: {{label}}" and nothing else.',
    recommendation_20: '20 recommendations',
    summary_1000_1200: 'about 1000 to 1200 words',
  };
  return prompts[type] || prompts.memory_construction;
}

export function benchmarkProtocol() {
  return {
    aladdin: ALADDIN_MEMORY_AGENT_BENCH_GUARDRAILS,
    datasets: ['EventQA', 'FactConsolidation', 'LongMemEval(S*)', 'NIAH', 'MCC', 'MovieRecommendation'],
    competencies: { ...MEMORY_AGENT_COMPETENCIES },
    chunk_sizes: [...MEMORY_AGENT_CHUNK_SIZES],
    retrieval_k: [...MEMORY_AGENT_RETRIEVAL_K],
    output_limits: { ...MEMORY_AGENT_TASK_OUTPUT_LIMITS },
    context_scales: [...MEMORY_AGENT_CONTEXT_SCALES],
    one_k_is_tokens: 1024,
  };
}
