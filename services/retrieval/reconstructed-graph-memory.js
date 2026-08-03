/**
 * Native Graph Memory reconstruction recall operator from:
 * - Memory is Reconstructed, Not Retrieved- Graph Memory for LLM Agents.pdf
 *
 * Implemented formulas / techniques:
 * - active reconstruction policy `v(t)=pi_a(t)(x,S(t-1))`
 * - monotone reconstruction state `S(t)=S(t-1) union {v(t)}`
 * - similarity retrieval `pi_sim(x)=TopK({sim(x,v)}_{v in V}, k)`
 * - graph retrieval `pi_graph(x)=V_sim union Neighbor(V_sim)`
 * - heterogeneous memory graph `M=(C,V,R)`
 * - typed cue-content relation `R subset C x G x V`
 * - induced mappings:
 *   - `phi_{c->g}(c) = {g | (c,g,.) in R}`
 *   - `phi_{(c,g)->v}(c,g) = {v | (c,g,v) in R}`
 * - reverse traversal `phi_{v->(c,g)}(v) = {(c,g) | (c,g,v) in R}`
 * - traversal action set `{Pi_1,...,Pi_m}`
 * - reconstruction state `S(t)=(Z(t),H(t))`
 * - candidate generation `Z_e(t+1)=union_{a in A(t)} Pi_a Z(t)`
 * - routing/state update `Z(t+1)=f_route(x,H(t),Z_e(t+1))`
 *
 * Aimos adaptation:
 * - query cues/tags/content are built transiently from returned recall candidates
 * - routing selects active read evidence but does not prune canonical memory
 * - reconstruction is deterministic and contains no benchmark-answer injection
 */

export const RECONSTRUCTED_GRAPH_CONSTANTS = Object.freeze({
  max_steps: 3,
  top_seed_cues: 8,
  route_cap_per_step: 18,
});

export const RECONSTRUCTED_GRAPH_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  routing_prunes_transient_paths_only: true,
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

function cueTokens(text = '', max = 8) {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]));
  const salient = tokens(text).filter((token) => token.length >= 5);
  return unique([...named, ...salient]).slice(0, max);
}

function tagsForText(text = '') {
  const patterns = [
    ['time', /\b(after|before|between|last|current|currently|now|when|days?|months?|\d{4})\b/i],
    ['person', /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/],
    ['preference', /\b(like|prefer|favorite|enjoy|recommend|dislike)\b/i],
    ['possession', /\b(own|have|bought|purchased|currently have)\b/i],
    ['travel', /\b(airline|airport|flight|flew|trip|travel)\b/i],
    ['event', /\b(event|joined|attended|visited|walk|cleanup)\b/i],
    ['identity', /\b(member|community|identity|considered|who)\b/i],
    ['procedure', /\b(step|strategy|workflow|tool|action|procedure)\b/i],
  ];
  return unique([
    ...patterns.filter(([, pattern]) => pattern.test(text)).map(([tag]) => tag),
    ...tokens(text).slice(0, 4).map((token) => `term:${token}`),
  ]);
}

export function buildCueTagContentGraph(states = []) {
  const C = new Map();
  const G = new Map();
  const V = new Map();
  const R = [];
  for (const state of states || []) {
    const contentId = `v:${state.id}`;
    const text = state.text || state.memory?.value || '';
    V.set(contentId, {
      id: contentId,
      state_id: String(state.id),
      text,
      layer: /\b(prefer|usually|fact|summary|profile)\b/i.test(text) ? 'semantic' : 'episodic',
    });
    const cues = cueTokens(text);
    const tags = tagsForText(text);
    for (const cue of cues) {
      const cueId = `c:${cue}`;
      C.set(cueId, { id: cueId, cue });
      for (const tag of tags) {
        const tagId = `g:${tag}`;
        G.set(tagId, { id: tagId, tag });
        R.push({ c: cueId, g: tagId, v: contentId });
      }
    }
  }
  return { C: [...C.values()], G: [...G.values()], V: [...V.values()], R };
}

export function phiCueToTag(graph = {}, cueIds = []) {
  const wanted = new Set(cueIds);
  return unique((graph.R || []).filter((rel) => wanted.has(rel.c)).map((rel) => rel.g));
}

export function phiCueTagToContent(graph = {}, cueIds = [], tagIds = []) {
  const cues = new Set(cueIds);
  const tags = new Set(tagIds);
  return unique((graph.R || [])
    .filter((rel) => (!cues.size || cues.has(rel.c)) && (!tags.size || tags.has(rel.g)))
    .map((rel) => rel.v));
}

export function phiContentToCueTag(graph = {}, contentIds = []) {
  const wanted = new Set(contentIds);
  return unique((graph.R || [])
    .filter((rel) => wanted.has(rel.v))
    .flatMap((rel) => [rel.c, rel.g]));
}

function seedCues(graph = {}, queryText = '') {
  const qCues = cueTokens(queryText, RECONSTRUCTED_GRAPH_CONSTANTS.top_seed_cues);
  const cueScores = (graph.C || []).map((cue) => ({
    id: cue.id,
    score: Math.max(qCues.includes(cue.cue) ? 1 : 0, lexicalSimilarity(queryText, cue.cue)),
  }));
  return cueScores
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, RECONSTRUCTED_GRAPH_CONSTANTS.top_seed_cues)
    .map((row) => row.id);
}

function routeCandidates(graph = {}, queryText = '', history = [], candidates = []) {
  const contentById = new Map((graph.V || []).map((content) => [content.id, content]));
  const scored = unique(candidates).map((id) => {
    const content = contentById.get(id);
    const label = content?.text || id.replace(/^[cg]:/, '');
    const historyText = history.map((row) => row.text || row).join(' ');
    const novelty = historyText.includes(label.slice(0, 24)) ? 0 : 0.12;
    return {
      id,
      score: clamp01((0.78 * lexicalSimilarity(queryText, label)) + novelty + (content ? 0.10 : 0)),
      text: label,
    };
  });
  return scored
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, RECONSTRUCTED_GRAPH_CONSTANTS.route_cap_per_step);
}

export function reconstructMemoryState({ graph = {}, queryText = '', steps = RECONSTRUCTED_GRAPH_CONSTANTS.max_steps } = {}) {
  let Z = new Set(seedCues(graph, queryText));
  const H = [];
  const trace = [];
  for (let t = 0; t < steps; t += 1) {
    const active = [...Z];
    const activeCues = active.filter((id) => id.startsWith('c:'));
    const activeTags = active.filter((id) => id.startsWith('g:'));
    const activeValues = active.filter((id) => id.startsWith('v:'));
    const tags = phiCueToTag(graph, activeCues);
    const values = phiCueTagToContent(graph, activeCues, unique([...activeTags, ...tags]));
    const reverse = phiContentToCueTag(graph, activeValues);
    const candidates = unique([...tags, ...values, ...reverse]);
    const routed = routeCandidates(graph, queryText, H, candidates);
    for (const row of routed) {
      Z.add(row.id);
      if (row.id.startsWith('v:')) H.push(row);
    }
    trace.push({
      step: t + 1,
      active_before: active.length,
      candidate_count: candidates.length,
      routed_count: routed.length,
      values_added: routed.filter((row) => row.id.startsWith('v:')).length,
    });
    if (!routed.length) break;
  }
  return { Z: [...Z], H, trace };
}

export function reconstructedGraphMemoryScores({ queryText = '', states = [] } = {}) {
  const graph = buildCueTagContentGraph(states);
  const reconstruction = reconstructMemoryState({ graph, queryText });
  const activeValues = new Set(reconstruction.Z.filter((id) => id.startsWith('v:')));
  const valueById = new Map(graph.V.map((content) => [content.id, content]));
  const relationCountByValue = new Map();
  for (const rel of graph.R) relationCountByValue.set(rel.v, (relationCountByValue.get(rel.v) || 0) + 1);
  const maxDegree = Math.max(1, ...relationCountByValue.values());

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const content of graph.V) {
    const active = activeValues.has(content.id);
    const direct = lexicalSimilarity(queryText, content.text);
    const degree = (relationCountByValue.get(content.id) || 0) / maxDegree;
    const reconstructed = reconstruction.H.find((row) => row.id === content.id)?.score || 0;
    const score = clamp01((0.42 * direct) + (0.34 * reconstructed) + (0.14 * degree) + (active ? 0.10 : 0));
    scoreById.set(content.state_id, score);
    diagnosticsById.set(content.state_id, {
      active,
      direct_similarity: Number(direct.toFixed(6)),
      reconstructed_score: Number(reconstructed.toFixed(6)),
      relation_degree: Number(degree.toFixed(6)),
      layer: content.layer,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    graph_stats: {
      cues: graph.C.length,
      tags: graph.G.length,
      contents: graph.V.length,
      relations: graph.R.length,
    },
    reconstruction_steps: reconstruction.trace,
    active_count: reconstruction.Z.length,
    reconstructed_context_count: reconstruction.H.length,
    guardrails: RECONSTRUCTED_GRAPH_GUARDRAILS,
    formula: 'S(t)=S(t-1)∪{v(t)}; pi_graph=V_sim∪Neighbor(V_sim); R⊂C×G×V; phi_cg mappings with deterministic f_route',
  };
}
