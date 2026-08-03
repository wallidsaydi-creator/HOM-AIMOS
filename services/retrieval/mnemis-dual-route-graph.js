/**
 * Native Mnemis dual-route hierarchical-graph recall operator from:
 * - Mnemis- Dual-Route Retrieval on Hierarchical Graphs for Long-Term LLM Memory.pdf
 *
 * Implemented formulas / techniques:
 * - Dual-route retrieval: System-1 similarity search plus System-2 Global Selection.
 * - Base graph over Episodes, Entities, and Edges with `valid_at`.
 * - Similarity operators: cosine-style token overlap and BM25-style lexical scoring.
 * - Hierarchical graph over semantic categories with minimum concept abstraction.
 * - System-2 top-down traversal from categories to entities and connected episodes.
 * - Reciprocal rank fusion: `RRF(d)=sum_r 1/(k + rank_r(d))`.
 * - Route union and rerank under fixed read caps.
 *
 * Aimos adaptation:
 * - constructs transient read graphs from returned recall candidates only
 * - performs no canonical pruning, deletion, decay, or mutation
 * - never injects benchmark answers or changes the user query during traversal
 */

export const MNEMIS_CONSTANTS = Object.freeze({
  rrf_k: 60,
  system1_top_k: 10,
  system2_top_categories: 5,
  system2_leaf_cap: 20,
  min_category_children: 2,
});

export const MNEMIS_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  query_rewrite: false,
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

function lexicalCosine(left = '', right = '') {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function bm25Like(query = '', text = '') {
  const q = tokens(query);
  const d = tokens(text);
  if (!q.length || !d.length) return 0;
  const freq = new Map();
  for (const token of d) freq.set(token, (freq.get(token) || 0) + 1);
  const k1 = 1.2;
  const b = 0.75;
  const avgdl = Math.max(1, d.length);
  let score = 0;
  for (const token of unique(q)) {
    const tf = freq.get(token) || 0;
    if (!tf) continue;
    const denom = tf + k1 * (1 - b + b * (d.length / avgdl));
    score += ((tf * (k1 + 1)) / denom);
  }
  return clamp01(score / Math.max(1, unique(q).length));
}

function dateIso(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function salientTerms(text = '', max = 8) {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]));
  const salient = tokens(text).filter((token) => token.length >= 5);
  return unique([...named, ...salient]).slice(0, max);
}

function semanticCategory(text = '') {
  const patterns = [
    ['temporal', /\b(after|before|between|last|first|current|currently|now|days?|months?|years?)\b/i],
    ['person_identity', /\b(member|community|person|who|called|named|identity|considered)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['possession', /\b(own|have|bought|purchased|currently have|how many)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel)\b/i],
    ['event', /\b(event|attended|joined|visited|walk|cleanup|concert)\b/i],
    ['procedure', /\b(step|strategy|workflow|tool|procedure|plan)\b/i],
  ];
  return patterns.find(([, pattern]) => pattern.test(text))?.[0] || `term:${tokens(text)[0] || 'memory'}`;
}

export function buildMnemisBaseGraph(states = []) {
  const episodes = [];
  const entityMap = new Map();
  const edges = [];

  for (const state of states || []) {
    const text = stateText(state);
    const episode = {
      id: `episode:${state.id}`,
      state_id: String(state.id),
      text,
      episode_embedding: tokens(text),
      valid_at: dateIso(state.memory?.created_at) || dateIso(state.interval?.start),
      category: semanticCategory(text),
    };
    episodes.push(episode);

    for (const term of salientTerms(text)) {
      const entityId = `entity:${term}`;
      const previous = entityMap.get(entityId) || {
        id: entityId,
        name: term,
        summary: '',
        tag: semanticCategory(term),
        episode_idx: [],
        name_embedding: tokens(term),
        summary_embedding: [],
      };
      previous.episode_idx.push(episode.id);
      previous.summary = unique([previous.summary, text.slice(0, 180)]).filter(Boolean).join(' ');
      previous.summary_embedding = tokens(previous.summary);
      entityMap.set(entityId, previous);
      edges.push({
        id: `edge:${episode.id}:${entityId}`,
        from: episode.id,
        to: entityId,
        fact: `${term} mentioned in ${episode.category}`,
        fact_embedding: tokens(`${term} ${episode.category} ${text}`),
        valid_at: episode.valid_at,
        invalid_at: null,
        state_id: String(state.id),
      });
    }
  }

  return { episodes, entities: [...entityMap.values()], edges };
}

export function buildMnemisHierarchy(graph = {}, minChildren = MNEMIS_CONSTANTS.min_category_children) {
  const categories = new Map();
  for (const episode of graph.episodes || []) {
    const key = episode.category || 'memory';
    const category = categories.get(key) || { id: `category:${key}`, label: key, episodes: [], entities: [], standalone: false };
    category.episodes.push(episode.id);
    categories.set(key, category);
  }
  for (const entity of graph.entities || []) {
    const labels = unique((entity.episode_idx || [])
      .map((episodeId) => (graph.episodes || []).find((episode) => episode.id === episodeId)?.category)
      .filter(Boolean));
    for (const label of labels.length ? labels : [entity.tag || 'memory']) {
      const category = categories.get(label) || { id: `category:${label}`, label, episodes: [], entities: [], standalone: false };
      category.entities.push(entity.id);
      categories.set(label, category);
    }
  }
  const rows = [...categories.values()].map((category) => ({
    ...category,
    episodes: unique(category.episodes),
    entities: unique(category.entities),
  }));
  return rows.map((category) => ({
    ...category,
    standalone: (category.episodes.length + category.entities.length) < minChildren,
  }));
}

function rankRows(rows = [], queryText = '', textOf = (row) => row.text || row.id, cap = rows.length) {
  return rows
    .map((row) => ({
      id: row.id,
      row,
      score: clamp01((0.52 * lexicalCosine(queryText, textOf(row))) + (0.48 * bm25Like(queryText, textOf(row)))),
    }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, cap);
}

export function reciprocalRankFusionMnemis(rankLists = [], k = MNEMIS_CONSTANTS.rrf_k) {
  const fused = new Map();
  for (const list of rankLists || []) {
    (list || []).forEach((item, index) => {
      const id = String(item.id || item);
      const previous = fused.get(id) || { id, score: 0, sources: 0 };
      previous.score += 1 / (k + index + 1);
      previous.sources += 1;
      fused.set(id, previous);
    });
  }
  return [...fused.values()].sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

export function mnemisSystem1(graph = {}, queryText = '') {
  const episodeRanks = rankRows(graph.episodes || [], queryText, (row) => row.text, MNEMIS_CONSTANTS.system1_top_k);
  const entityRanks = rankRows(graph.entities || [], queryText, (row) => `${row.name} ${row.summary}`, MNEMIS_CONSTANTS.system1_top_k * 2);
  const edgeRanks = rankRows(graph.edges || [], queryText, (row) => row.fact, MNEMIS_CONSTANTS.system1_top_k * 2);
  return { episodeRanks, entityRanks, edgeRanks };
}

export function mnemisGlobalSelection(graph = {}, queryText = '') {
  const hierarchy = buildMnemisHierarchy(graph);
  const selectedCategories = hierarchy
    .map((category) => ({
      ...category,
      score: clamp01((0.70 * lexicalCosine(queryText, category.label)) + (0.30 * Math.min(1, (category.episodes.length + category.entities.length) / 6))),
    }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, MNEMIS_CONSTANTS.system2_top_categories);

  const selectedEntityIds = new Set(selectedCategories.flatMap((category) => category.entities));
  const selectedEpisodeIds = new Set(selectedCategories.flatMap((category) => category.episodes));
  for (const edge of graph.edges || []) {
    if (selectedEntityIds.has(edge.to)) selectedEpisodeIds.add(edge.from);
  }

  const episodeRanks = [...selectedEpisodeIds]
    .map((episodeId) => {
      const episode = (graph.episodes || []).find((row) => row.id === episodeId);
      return episode ? { id: episode.id, row: episode, score: lexicalCosine(queryText, episode.text) } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, MNEMIS_CONSTANTS.system2_leaf_cap);

  return { hierarchy, selectedCategories, episodeRanks };
}

export function mnemisScores({ queryText = '', states = [] } = {}) {
  const graph = buildMnemisBaseGraph(states);
  const system1 = mnemisSystem1(graph, queryText);
  const system2 = mnemisGlobalSelection(graph, queryText);
  const fused = reciprocalRankFusionMnemis([
    system1.episodeRanks,
    system1.entityRanks.flatMap((rank) => (rank.row.episode_idx || []).map((episodeId) => ({ id: episodeId }))),
    system1.edgeRanks.map((rank) => ({ id: rank.row.from })),
    system2.episodeRanks,
  ]);
  const maxFused = Math.max(1e-9, ...fused.map((row) => row.score));
  const fusedByEpisode = new Map(fused.map((row) => [row.id, clamp01(row.score / maxFused)]));
  const scoreById = new Map();

  for (const state of states || []) {
    const episodeId = `episode:${state.id}`;
    const direct = lexicalCosine(queryText, stateText(state));
    const fusedScore = fusedByEpisode.get(episodeId) || 0;
    scoreById.set(String(state.id), clamp01((0.44 * direct) + (0.56 * fusedScore)));
  }

  return {
    scoreById,
    graph_stats: {
      episodes: graph.episodes.length,
      entities: graph.entities.length,
      edges: graph.edges.length,
      categories: system2.hierarchy.length,
    },
    system1_count: system1.episodeRanks.length + system1.entityRanks.length + system1.edgeRanks.length,
    system2_count: system2.episodeRanks.length,
    union_count: fused.length,
    selected_categories: system2.selectedCategories.map((category) => category.label),
    formula: 'RRF(d)=sum_r 1/(k+rank_r(d)); score=0.44*cos_q_episode+0.56*rrf_union',
    guardrails: MNEMIS_GUARDRAILS,
  };
}
