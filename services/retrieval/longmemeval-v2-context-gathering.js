/**
 * Native LongMemEval-V2 context-gathering recall operator from:
 * - LongMemEval-V2.pdf
 *
 * Implemented formulas / techniques:
 * - ordered trajectory haystack `H_i = {h_i,1, ..., h_i,m_i}`
 * - memory API contract `Insert(h)` and `Query(q)`
 * - sequential insertion `M_i,j = Insert_{M_i,j-1}(h_i,j)`
 * - final context query `c_i = Query_{M_i,m}(q_i)`
 * - reader context truncation `y_hat_i = R(q_i, Trunc(c_i))`
 * - AgentRunbook-R pools: raw state observations, events, strategy/procedure notes
 * - radius-1 state slices around evidence states
 * - multi-query pool retrieval with `m = min(2, 6 // n_queries)`
 *
 * Aimos adaptation:
 * - projects returned memories into transient trajectory pools
 * - context truncation is a diagnostic read budget only; no memory is removed
 * - returns monotone bounded recall scores for `/aimos/recall`
 */

export const LMEV2_CONSTANTS = Object.freeze({
  radius: 1,
  top_context_budget: 6,
  max_raw_states: 500,
  max_state_chars: 1600,
});

export const LMEV2_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  truncation_is_read_diagnostic_only: true,
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

function tokenOverlap(left = '', right = '') {
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

function chronologicalStates(states = []) {
  return [...(states || [])]
    .slice(0, LMEV2_CONSTANTS.max_raw_states)
    .sort((a, b) => {
      const da = dateMs(a.memory?.created_at) || a.interval?.start || a.index || 0;
      const db = dateMs(b.memory?.created_at) || b.interval?.start || b.index || 0;
      return da - db || String(a.id).localeCompare(String(b.id));
    });
}

function eventLabel(text = '') {
  const patterns = [
    ['temporal', /\b(after|before|between|last|currently|now|when|days?|months?)\b/i],
    ['purchase', /\b(bought|ordered|purchased|returned|paid)\b/i],
    ['travel', /\b(airline|airport|flight|flew|trip|hotel)\b/i],
    ['preference', /\b(like|prefer|favorite|enjoy|recommend|dislike)\b/i],
    ['identity', /\b(member|community|person|name|called|who)\b/i],
    ['task', /\b(task|project|workflow|step|procedure|strategy)\b/i],
  ];
  return patterns.find(([, pattern]) => pattern.test(text))?.[0] || tokens(text)[0] || 'state';
}

export function buildKnowledgePools(states = []) {
  const ordered = chronologicalStates(states);
  const raw_state_slices = ordered.map((state, index) => {
    const neighbors = ordered
      .slice(Math.max(0, index - LMEV2_CONSTANTS.radius), Math.min(ordered.length, index + LMEV2_CONSTANTS.radius + 1))
      .map((row) => String(row.text || row.memory?.value || '').slice(0, LMEV2_CONSTANTS.max_state_chars));
    return {
      id: String(state.id),
      state_id: String(state.id),
      index,
      type: 'raw_state_slice',
      text: neighbors.join('\n'),
      center_text: String(state.text || state.memory?.value || '').slice(0, LMEV2_CONSTANTS.max_state_chars),
    };
  });
  const events = ordered.map((state, index) => ({
    id: `event:${state.id}`,
    state_id: String(state.id),
    index,
    type: 'event',
    event_type: eventLabel(state.text || ''),
    text: `[${eventLabel(state.text || '')}] ${String(state.text || '').slice(0, LMEV2_CONSTANTS.max_state_chars)}`,
  }));
  const notes = ordered
    .filter((state) => /\b(note|hint|strategy|procedure|step|should|must|remember|prefer|usually|currently)\b/i.test(state.text || ''))
    .map((state, index) => ({
      id: `note:${state.id}`,
      state_id: String(state.id),
      index,
      type: 'strategy_note',
      text: String(state.text || '').slice(0, 900),
    }));
  return { raw_state_slices, events, notes, ordered_state_count: ordered.length };
}

export function queryBundle(queryText = '') {
  const qTokens = tokens(queryText);
  const named = [...String(queryText || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((match) => match[0]);
  const raw_queries = unique([
    queryText,
    named.join(' '),
    qTokens.slice(0, 6).join(' '),
  ]).filter((value) => value.trim().length >= 3);
  const event_query = unique([eventLabel(queryText), ...qTokens.filter((token) => /^(after|before|current|last|first|buy|bought|flight|member|prefer)/.test(token))]).join(' ');
  const note_query = unique(qTokens.filter((token) => /^(prefer|usually|current|strategy|procedure|remember|recommend|should|must)/.test(token))).join(' ') || queryText;
  return {
    raw_state_queries: raw_queries.length ? raw_queries : [queryText],
    event_query,
    note_query,
  };
}

export function topMPerQuery(nQueries = 1) {
  const n = Math.max(1, Number(nQueries) || 1);
  return Math.max(1, Math.min(2, Math.floor(LMEV2_CONSTANTS.top_context_budget / n)));
}

function retrievePool(pool = [], queries = [], m = 1) {
  const rows = [];
  for (const query of queries) {
    const ranked = pool
      .map((item) => ({ item, score: tokenOverlap(query, item.text) }))
      .sort((a, b) => b.score - a.score || a.item.id.localeCompare(b.item.id))
      .slice(0, m);
    rows.push(...ranked);
  }
  const best = new Map();
  for (const row of rows) {
    const key = row.item.id;
    if (!best.has(key) || best.get(key).score < row.score) best.set(key, row);
  }
  return [...best.values()].sort((a, b) => b.score - a.score || a.item.id.localeCompare(b.item.id));
}

export function contextGatheringQuery({ queryText = '', pools = buildKnowledgePools([]) } = {}) {
  const bundle = queryBundle(queryText);
  const nQueries = bundle.raw_state_queries.length + 2;
  const m = topMPerQuery(nQueries);
  const raw = retrievePool(pools.raw_state_slices, bundle.raw_state_queries, m);
  const events = retrievePool(pools.events, [bundle.event_query], Math.min(3, m + 1));
  const notes = retrievePool(pools.notes, [bundle.note_query], Math.min(3, m + 1));
  return {
    bundle,
    m,
    contexts: [...notes, ...events, ...raw],
  };
}

export function longMemEvalV2Scores({ queryText = '', states = [] } = {}) {
  const pools = buildKnowledgePools(states);
  const gathered = contextGatheringQuery({ queryText, pools });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const id = String(state.id);
    const direct = tokenOverlap(queryText, state.text || '');
    const poolHits = gathered.contexts.filter((row) => row.item.state_id === id);
    const poolScore = poolHits.reduce((max, row) => Math.max(max, row.score), 0);
    const typeDiversity = new Set(poolHits.map((row) => row.item.type)).size;
    const score = clamp01((0.46 * direct) + (0.42 * poolScore) + (0.12 * Math.min(1, typeDiversity / 3)));
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      direct_similarity: Number(direct.toFixed(6)),
      pool_score: Number(poolScore.toFixed(6)),
      pool_hit_types: [...new Set(poolHits.map((row) => row.item.type))],
    });
  }
  return {
    scoreById,
    diagnosticsById,
    pools: {
      raw_state_slices: pools.raw_state_slices.length,
      events: pools.events.length,
      notes: pools.notes.length,
      ordered_state_count: pools.ordered_state_count,
      radius: LMEV2_CONSTANTS.radius,
    },
    query_bundle: gathered.bundle,
    top_m_per_query: gathered.m,
    selected_context_count: gathered.contexts.length,
    guardrails: LMEV2_GUARDRAILS,
    formula: 'M_i,j=Insert(M_i,j-1,h_i,j); c_i=Query(M_i,m,q_i); m=min(2,6//n_queries); score=0.46*direct+0.42*pool+0.12*pool_diversity',
  };
}
