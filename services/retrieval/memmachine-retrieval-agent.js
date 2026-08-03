/**
 * Native MemMachine retrieval-agent recall operator from:
 * - MemMachine.pdf
 *
 * Implemented formulas / techniques:
 * - memory taxonomy: STM, long-term episodic, semantic, procedural
 * - ground-truth-preserving raw conversational episodes
 * - sentence-level indexing with one key per sentence
 * - contextualized retrieval: nucleus matches expanded with neighboring episodes
 * - staged recall: STM search -> LTM vector/lexical search -> contextualization
 *   -> de-duplicate episodes -> rerank clusters -> chronological sort
 * - structural query router:
 *   - ChainOfQuery for multi-hop dependency chains
 *   - SplitQuery for single-hop multi-entity queries
 *   - direct MemMachine leaf for single-hop lookup
 * - query-complexity-aware retrieval depth, including k=20 -> 30 expansion
 * - user-role query prefix support as a routing feature
 *
 * Aimos adaptation:
 * - uses deterministic routing over returned recall candidates
 * - expands/read-reranks clusters without mutating or pruning canonical memory
 * - never calls an LLM and never injects benchmark answers
 */

export const MEMMACHINE_CONSTANTS = Object.freeze({
  direct_k: 20,
  complex_k: 30,
  max_chain_steps: 3,
  split_min: 2,
  split_max: 6,
  neighbor_radius: 1,
});

export const MEMMACHINE_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  contextualization_is_read_expansion_only: true,
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

function lexicalSimilarity(left = '', right = '') {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function dateMs(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : NaN;
}

function splitSentences(text = '') {
  return String(text || '')
    .split(/(?<=[.!?])\s+|\n+/)
    .map((row) => row.trim())
    .filter(Boolean);
}

function chrono(states = []) {
  return [...(states || [])].sort((a, b) => {
    const da = dateMs(a.memory?.created_at) || a.interval?.start || a.index || 0;
    const db = dateMs(b.memory?.created_at) || b.interval?.start || b.index || 0;
    return da - db || String(a.id).localeCompare(String(b.id));
  });
}

export function routeQueryStructure(queryText = '') {
  const q = String(queryText || '');
  const hasDependency = /\b(after|before|between|then|next|previous|first|last|passed|older|newer)\b/i.test(q);
  const hasMultiEntity = /\b(?:and|or)\b/i.test(q)
    && ([...q.matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].length >= 2 || /\b(list|all|how many|which|prefer|compare|recommend)\b/i.test(q));
  if (hasDependency && /\b(between|after|before|passed|first|last)\b/i.test(q)) return 'chain';
  if (hasMultiEntity) return 'split';
  return 'direct';
}

function querySubparts(queryText = '', route = routeQueryStructure(queryText)) {
  if (route === 'chain') {
    return unique(String(queryText || '').split(/\b(?:then|after|before|between)\b/i).map((part) => part.trim()).filter((part) => part.length >= 3))
      .slice(0, MEMMACHINE_CONSTANTS.max_chain_steps);
  }
  if (route === 'split') {
    return unique(String(queryText || '').split(/\b(?:and|or|,)\b/i).map((part) => part.trim()).filter((part) => part.length >= 3))
      .slice(0, MEMMACHINE_CONSTANTS.split_max);
  }
  return [queryText];
}

export function sentenceIndex(states = []) {
  const rows = [];
  for (const [episodeIndex, state] of chrono(states).entries()) {
    const sentences = splitSentences(state.text || state.memory?.value || '');
    sentences.forEach((sentence, sentenceIndexInEpisode) => {
      rows.push({
        id: `${state.id}:s${sentenceIndexInEpisode + 1}`,
        state_id: String(state.id),
        episode_index: episodeIndex,
        sentence_index: sentenceIndexInEpisode,
        text: sentence,
        created_at: state.memory?.created_at || null,
      });
    });
    if (!sentences.length) {
      rows.push({
        id: `${state.id}:s1`,
        state_id: String(state.id),
        episode_index: episodeIndex,
        sentence_index: 0,
        text: state.text || '',
        created_at: state.memory?.created_at || null,
      });
    }
  }
  return rows;
}

function episodeNeighbors(indexRows = [], nucleus = {}, radius = MEMMACHINE_CONSTANTS.neighbor_radius) {
  const lower = nucleus.episode_index - radius;
  const upper = nucleus.episode_index + radius;
  return indexRows.filter((row) => row.episode_index >= lower && row.episode_index <= upper);
}

export function contextualizedEpisodeClusters(states = [], queryText = '', retrievalDepth = MEMMACHINE_CONSTANTS.direct_k) {
  const indexRows = sentenceIndex(states);
  const nuclei = indexRows
    .map((row) => ({ row, score: lexicalSimilarity(queryText, row.text) }))
    .sort((a, b) => b.score - a.score || a.row.id.localeCompare(b.row.id))
    .slice(0, Math.min(retrievalDepth, indexRows.length));
  const clusterMap = new Map();
  for (const nucleus of nuclei) {
    const neighbors = episodeNeighbors(indexRows, nucleus.row);
    const stateIds = unique(neighbors.map((row) => row.state_id));
    const key = stateIds.join('|') || nucleus.row.state_id;
    const previous = clusterMap.get(key) || { key, nuclei: [], state_ids: stateIds, text: '', score: 0, first_episode_index: nucleus.row.episode_index };
    previous.nuclei.push(nucleus.row.id);
    previous.score = Math.max(previous.score, nucleus.score);
    previous.text = neighbors.map((row) => row.text).join('\n');
    previous.first_episode_index = Math.min(previous.first_episode_index, nucleus.row.episode_index);
    clusterMap.set(key, previous);
  }
  return [...clusterMap.values()]
    .map((cluster) => ({
      ...cluster,
      rerank_score: clamp01((0.62 * cluster.score) + (0.28 * lexicalSimilarity(queryText, cluster.text)) + (0.10 * Math.min(1, cluster.state_ids.length / 3))),
    }))
    .sort((a, b) => b.rerank_score - a.rerank_score || a.first_episode_index - b.first_episode_index);
}

function routeDepth(routeType = 'direct') {
  return routeType === 'direct' ? MEMMACHINE_CONSTANTS.direct_k : MEMMACHINE_CONSTANTS.complex_k;
}

function proceduralScore(text = '') {
  return /\b(step|strategy|procedure|workflow|tool|action|should|must|plan)\b/i.test(text) ? 1 : 0;
}

function semanticMemoryScore(text = '') {
  return /\b(profile|prefer|usually|favorite|fact|summary|overall|likes|dislikes)\b/i.test(text) ? 1 : 0;
}

export function memMachineScores({ queryText = '', states = [] } = {}) {
  const routeType = routeQueryStructure(queryText);
  const subqueries = querySubparts(queryText, routeType);
  const retrievalDepth = routeDepth(routeType);
  const clusters = [];
  for (const subquery of subqueries.length ? subqueries : [queryText]) {
    clusters.push(...contextualizedEpisodeClusters(states, subquery, retrievalDepth));
  }
  const bestClusterByState = new Map();
  for (const cluster of clusters) {
    for (const stateId of cluster.state_ids || []) {
      const prev = bestClusterByState.get(stateId);
      if (!prev || prev.rerank_score < cluster.rerank_score) bestClusterByState.set(stateId, cluster);
    }
  }
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const id = String(state.id);
    const cluster = bestClusterByState.get(id);
    const direct = lexicalSimilarity(queryText, state.text || '');
    const semantic = semanticMemoryScore(state.text || '');
    const procedural = proceduralScore(state.text || '');
    const routeBonus = routeType === 'chain' && /\b(after|before|between|last|first|then|\d{4})\b/i.test(state.text || '')
      ? 0.12
      : routeType === 'split' && direct > 0.15 ? 0.08 : 0;
    const score = clamp01((0.42 * direct) + (0.38 * (cluster?.rerank_score || 0)) + (0.10 * semantic) + (0.06 * procedural) + routeBonus);
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      route_type: routeType,
      direct_similarity: Number(direct.toFixed(6)),
      cluster_score: Number((cluster?.rerank_score || 0).toFixed(6)),
      cluster_key: cluster?.key || null,
      semantic_memory_signal: Boolean(semantic),
      procedural_memory_signal: Boolean(procedural),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    route_type: routeType,
    subqueries,
    clusters: clusters.slice(0, 12).map((cluster) => ({
      key: cluster.key,
      state_ids: cluster.state_ids,
      rerank_score: Number(cluster.rerank_score.toFixed(6)),
    })),
    cluster_count: clusters.length,
    retrieval_depth: retrievalDepth,
    guardrails: MEMMACHINE_GUARDRAILS,
    formula: 'STM/LTM sentence search -> nucleus expansion radius=1 -> dedupe clusters -> route direct|split|chain; score=0.42*direct+0.38*cluster+taxonomy bonuses',
  };
}
