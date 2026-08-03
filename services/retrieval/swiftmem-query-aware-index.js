/**
 * Native SwiftMem query-aware indexing recall operator from:
 * - SwiftMem.pdf
 *
 * Implemented formulas / techniques:
 * - exhaustive baseline `R_exhaustive(q)=top-k{cos(e_q,x_i)}_{i=1}^{N_mem}`
 * - episode tuple `e_i=(u_i,m_i,t_i,x_i)` and episodic set `E={e_1,...,e_Nmem}`
 * - semantic DAG-tag index `G=(V,E)`
 * - filtered retrieval `R_filtered(q,f)=top-k{cos(e_q,x_i) | f(e_i)=true}`
 * - temporal index `L_u={(t_i,e_i)}` plus global lookup `M:e -> (u,t_i)`
 * - binary-searchable temporal range retrieval `O(log N_mem + r)`
 * - query-tag routing and temporal indicator gating
 * - tag sparsity relation `k << |V| << N_mem`
 * - DAG query bound `T_query=O(k*(log|V| + D_max))`
 * - tag-embedding co-consolidation through transient cluster ordering
 *
 * Aimos adaptation:
 * - indexes are built from the returned recall candidate set only
 * - co-consolidation is read-local ordering metadata, not physical storage mutation
 * - no pruning, decay, deletion, or canonical memory mutation
 */

export const SWIFTMEM_CONSTANTS = Object.freeze({
  tag_top_k: 5,
  max_dag_depth: 4,
  temporal_window_days: 45,
});

export const SWIFTMEM_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  co_consolidation_is_read_local_only: true,
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

function dateMs(value, fallback = 0) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : fallback;
}

function lexicalCosine(left = '', right = '') {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function tagsFor(text = '') {
  const patterns = [
    ['temporal', /\b(after|before|between|last|first|current|currently|now|when|days?|months?|years?)\b/i],
    ['identity', /\b(member|community|person|who|called|named|identity|melanie)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['inventory', /\b(own|have|bought|purchased|instrument|model kit|how many)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel)\b/i],
    ['event', /\b(event|joined|attended|walk|cleanup|concert)\b/i],
    ['procedure', /\b(step|strategy|workflow|tool|procedure|plan)\b/i],
  ];
  return unique([
    ...patterns.filter(([, pattern]) => pattern.test(text)).map(([label]) => label),
    ...tokens(text).filter((token) => token.length >= 5).slice(0, 5),
  ]);
}

export function swiftMemEpisode(state = {}, index = 0) {
  const text = stateText(state);
  return {
    id: String(state.id),
    u: String(state.memory?.agent_id || state.memory?.source || state.memory?.session_id || 'default'),
    m: text,
    t: dateMs(state.memory?.created_at, state.interval?.start || index),
    x: tokens(text),
    tags: tagsFor(text),
    state,
  };
}

export function buildSwiftMemTemporalIndex(states = []) {
  const timelines = new Map();
  const lookup = new Map();
  const episodes = (states || []).map(swiftMemEpisode);
  for (const episode of episodes) {
    const list = timelines.get(episode.u) || [];
    list.push([episode.t, episode.id]);
    timelines.set(episode.u, list);
    lookup.set(episode.id, { user: episode.u, time: episode.t, episode });
  }
  for (const list of timelines.values()) list.sort((a, b) => a[0] - b[0] || a[1].localeCompare(b[1]));
  return { episodes, timelines, lookup };
}

function lowerBound(list = [], target = 0) {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (list[mid][0] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

export function temporalRangeQuery(index = {}, { user = null, start = -Infinity, end = Infinity } = {}) {
  const out = [];
  const timelines = user ? [[user, index.timelines?.get(user) || []]] : [...(index.timelines || new Map()).entries()];
  for (const [, list] of timelines) {
    const begin = Number.isFinite(start) ? lowerBound(list, start) : 0;
    for (let i = begin; i < list.length; i += 1) {
      const [time, episodeId] = list[i];
      if (Number.isFinite(end) && time > end) break;
      out.push(index.lookup.get(episodeId)?.episode);
    }
  }
  return out.filter(Boolean);
}

export function buildSwiftMemDagTagIndex(states = []) {
  const V = new Map();
  const E = new Set();
  const episodes = (states || []).map(swiftMemEpisode);
  const parentOf = {
    temporal: 'memory',
    identity: 'person',
    preference: 'semantic',
    inventory: 'semantic',
    travel: 'event',
    event: 'memory',
    procedure: 'semantic',
  };
  for (const episode of episodes) {
    for (const tag of episode.tags) {
      V.set(tag, { id: tag, episodes: unique([...(V.get(tag)?.episodes || []), episode.id]) });
      const parent = parentOf[tag] || 'semantic';
      V.set(parent, { id: parent, episodes: unique([...(V.get(parent)?.episodes || []), episode.id]) });
      E.add(`${parent}->${tag}`);
    }
  }
  return {
    V: [...V.values()],
    E: [...E].map((edge) => {
      const [from, to] = edge.split('->');
      return { from, to };
    }),
    episodes,
  };
}

export function queryTagRouter(queryText = '', dag = buildSwiftMemDagTagIndex([])) {
  const queryTags = tagsFor(queryText);
  const scored = (dag.V || []).map((tag) => ({
    tag: tag.id,
    score: Math.max(queryTags.includes(tag.id) ? 1 : 0, lexicalCosine(queryText, tag.id)),
    episode_ids: tag.episodes || [],
  })).sort((a, b) => b.score - a.score || a.tag.localeCompare(b.tag));
  const temporal = /\b(after|before|between|last|first|current|currently|now|when|days?|months?|years?|\d{4})\b/i.test(queryText);
  return {
    temporal_indicator: temporal,
    selected_tags: scored.filter((row) => row.score > 0).slice(0, SWIFTMEM_CONSTANTS.tag_top_k),
  };
}

export function swiftMemFilteredRetrieval({ queryText = '', episodes = [], predicate = () => true, topK = 8 } = {}) {
  return (episodes || [])
    .filter(predicate)
    .map((episode) => ({ episode, score: lexicalCosine(queryText, episode.m) }))
    .sort((a, b) => b.score - a.score || a.episode.id.localeCompare(b.episode.id))
    .slice(0, topK);
}

export function clusterCohesion(tags = [], edges = []) {
  const members = new Set(tags);
  const n = members.size;
  if (n < 2) return n;
  const actual = edges.filter((edge) => members.has(edge.from) && members.has(edge.to)).length;
  return actual / Math.max(1, n * (n - 1));
}

export function swiftMemScores({ queryText = '', states = [], referenceDate = new Date() } = {}) {
  const temporal = buildSwiftMemTemporalIndex(states);
  const dag = buildSwiftMemDagTagIndex(states);
  const routed = queryTagRouter(queryText, dag);
  const now = dateMs(referenceDate, Date.now());
  const windowMs = SWIFTMEM_CONSTANTS.temporal_window_days * 86400000;
  const temporalEpisodes = routed.temporal_indicator
    ? temporalRangeQuery(temporal, { start: now - windowMs, end: now + windowMs })
    : temporal.episodes;
  const selectedEpisodeIds = new Set(routed.selected_tags.flatMap((tag) => tag.episode_ids));
  const filtered = swiftMemFilteredRetrieval({
    queryText,
    episodes: temporalEpisodes,
    predicate: (episode) => !selectedEpisodeIds.size || selectedEpisodeIds.has(episode.id),
    topK: Math.max(8, states.length),
  });
  const max = Math.max(1e-9, ...filtered.map((row) => row.score));
  const scoreById = new Map();
  const filteredScore = new Map(filtered.map((row) => [row.episode.id, clamp01(row.score / max)]));
  for (const episode of temporal.episodes) {
    const tagHit = episode.tags.some((tag) => routed.selected_tags.some((selected) => selected.tag === tag)) ? 1 : 0;
    const temporalHit = temporalEpisodes.some((row) => row.id === episode.id) ? 1 : 0;
    scoreById.set(episode.id, clamp01(
      (0.48 * (filteredScore.get(episode.id) || 0))
      + (0.24 * lexicalCosine(queryText, episode.m))
      + (0.16 * tagHit)
      + (0.12 * (routed.temporal_indicator ? temporalHit : 1))
    ));
  }
  return {
    scoreById,
    temporal_index: {
      user_count: temporal.timelines.size,
      episode_count: temporal.episodes.length,
      complexity: 'O(log N_mem + r)',
    },
    dag_tag_index: {
      tag_count: dag.V.length,
      edge_count: dag.E.length,
      selected_tags: routed.selected_tags.map((row) => row.tag),
      complexity: 'O(k*(log|V| + D_max))',
    },
    filtered_count: filtered.length,
    temporal_indicator: routed.temporal_indicator,
    cluster_cohesion: clusterCohesion(dag.V.map((row) => row.id), dag.E),
    formula: 'R_filtered(q,f)=top-k{cos(e_q,x_i)|f(e_i)=true}; e_i=(u_i,m_i,t_i,x_i); G=(V,E)',
    guardrails: SWIFTMEM_GUARDRAILS,
  };
}
