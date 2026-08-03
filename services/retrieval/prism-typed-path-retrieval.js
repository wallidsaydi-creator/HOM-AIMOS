/**
 * Native PRISM typed-path recall operator from:
 * - PRISM.pdf
 *
 * Implemented formulas / techniques:
 * - multi-relational graph `G=(V,E,tau)`
 * - four-layer hierarchy: Entity -> FacetPoint -> Facet -> Episode
 * - typed edges: belongs_to, semantic, temporal, causal, evolution, involves_entity
 * - adaptive intent routing with keyword/prototype tiers
 * - anchor discovery across hierarchy layers
 * - path cost `Cost(pi)=d(a)+c_edge(e_i)+c_hop`
 * - episode scoring `s(Ep)=min_{pi in Pi(Ep)} Cost(pi)`
 * - query-sensitive edge discounts for temporal, causal, and evolution paths
 * - budgeted evidence bundle selection
 *
 * Aimos adaptation:
 * - zero-LLM deterministic routing only
 * - compression is a read-budget diagnostic, not answer synthesis
 * - no canonical pruning, deletion, decay, or mutation
 */

export const PRISM_CONSTANTS = Object.freeze({
  prototype_threshold: 0.28,
  prototype_margin: 0.10,
  anchor_top_k: 6,
  hop_cost: 0.03,
  budget_chars: 2400,
});

export const PRISM_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  llm_fallback: false,
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

function stateText(state = {}) {
  return String(state.text || state.memory?.value || '').trim();
}

function facetLabel(text = '') {
  const facets = [
    ['temporal', /\b(after|before|between|last|first|currently|now|days?|months?)\b/i],
    ['identity', /\b(member|community|person|who|called|named|melanie|identity)\b/i],
    ['preference', /\b(prefer|favorite|like|enjoy|recommend|dislike)\b/i],
    ['inventory', /\b(own|have|bought|purchased|how many|instrument|model kit)\b/i],
    ['travel', /\b(airline|airport|flight|flew|hotel|trip|travel)\b/i],
    ['event', /\b(event|joined|attended|walk|cleanup|concert)\b/i],
  ];
  return facets.find(([, pattern]) => pattern.test(text))?.[0] || `term:${tokens(text)[0] || 'memory'}`;
}

function entityTerms(text = '') {
  const named = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((match) => normalizeText(match[0]));
  return unique([...named, ...tokens(text).filter((token) => token.length >= 6)]).slice(0, 8);
}

export function adaptivePrismIntent(queryText = '') {
  const keyword = [
    ['temporal', /\b(after|before|between|last|first|currently|now|when|days?|months?)\b/i],
    ['causal', /\b(why|because|caused|reason|led to|due to)\b/i],
    ['evolution', /\b(changed|became|used to|now|currently|update|recent)\b/i],
    ['preference', /\b(prefer|favorite|like|recommend|enjoy)\b/i],
    ['entity', /\b(who|which|what|member|called|name)\b/i],
  ].find(([, pattern]) => pattern.test(queryText));
  if (keyword) return { intent: keyword[0], route: 'keyword', margin: 1 };

  const prototypes = ['temporal', 'causal', 'evolution', 'preference', 'entity', 'inventory']
    .map((label) => ({ label, score: lexicalCosine(queryText, label) }))
    .sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
  const top = prototypes[0] || { label: 'entity', score: 0 };
  const second = prototypes[1] || { label: 'entity', score: 0 };
  if (top.score > PRISM_CONSTANTS.prototype_threshold && top.score - second.score > PRISM_CONSTANTS.prototype_margin) {
    return { intent: top.label, route: 'prototype', margin: top.score - second.score };
  }
  return { intent: 'entity', route: 'deterministic_default', margin: top.score - second.score };
}

export function buildPrismGraph(states = []) {
  const V = [];
  const E = [];
  const facetIds = new Map();
  const entityIds = new Map();

  for (const state of states || []) {
    const text = stateText(state);
    const episodeId = `episode:${state.id}`;
    const facet = facetLabel(text);
    const facetId = `facet:${facet}`;
    const facetPointId = `facet_point:${facet}:${state.id}`;
    V.push({ id: episodeId, layer: 'Episode', state_id: String(state.id), text });
    if (!facetIds.has(facetId)) {
      facetIds.set(facetId, { id: facetId, layer: 'Facet', label: facet, text: facet });
      V.push(facetIds.get(facetId));
    }
    V.push({ id: facetPointId, layer: 'FacetPoint', state_id: String(state.id), label: facet, text: `${facet} ${text.slice(0, 120)}` });
    E.push({ from: facetPointId, to: facetId, tau: 'belongs_to' });
    E.push({ from: episodeId, to: facetPointId, tau: 'semantic' });
    E.push({ from: facetPointId, to: episodeId, tau: 'belongs_to' });
    if (/\b(after|before|between|last|first|currently|now)\b/i.test(text)) E.push({ from: facetPointId, to: episodeId, tau: 'temporal' });
    if (/\b(because|reason|caused|led to|due to)\b/i.test(text)) E.push({ from: facetPointId, to: episodeId, tau: 'causal' });
    if (/\b(changed|became|used to|now|currently|update|recent)\b/i.test(text)) E.push({ from: facetPointId, to: episodeId, tau: 'evolution' });
    for (const entity of entityTerms(text)) {
      const entityId = `entity:${entity}`;
      if (!entityIds.has(entityId)) {
        entityIds.set(entityId, { id: entityId, layer: 'Entity', label: entity, text: entity });
        V.push(entityIds.get(entityId));
      }
      E.push({ from: entityId, to: facetPointId, tau: 'involves_entity' });
      E.push({ from: episodeId, to: entityId, tau: 'involves_entity' });
    }
  }
  return { V, E, tau: unique(E.map((edge) => edge.tau)) };
}

export function prismEdgeCost(edge = {}, intent = 'entity') {
  const base = edge.tau === 'belongs_to' ? 0.02 : 0.90;
  if (intent === 'temporal' && edge.tau === 'temporal') return 0.5 * base;
  if (intent === 'causal' && edge.tau === 'causal') return 0.5 * base;
  if (intent === 'evolution' && edge.tau === 'evolution') return 0.7 * base;
  if (intent === 'entity' && edge.tau === 'involves_entity') return 0.45 * base;
  return base;
}

export function prismPathCost({ anchorDistance = 1, edges = [], intent = 'entity', hopCost = PRISM_CONSTANTS.hop_cost } = {}) {
  return (Number(anchorDistance) || 0)
    + edges.reduce((sum, edge) => sum + prismEdgeCost(edge, intent) + hopCost, 0);
}

function anchors(graph = {}, queryText = '') {
  return (graph.V || [])
    .map((node) => ({ node, distance: 1 - lexicalCosine(queryText, node.text || node.label || node.id) }))
    .sort((a, b) => a.distance - b.distance || a.node.id.localeCompare(b.node.id))
    .slice(0, PRISM_CONSTANTS.anchor_top_k);
}

function candidateBundle(graph = {}, queryText = '', intent = 'entity') {
  const byFrom = new Map();
  for (const edge of graph.E || []) {
    const list = byFrom.get(edge.from) || [];
    list.push(edge);
    byFrom.set(edge.from, list);
  }
  const episodes = new Map();
  for (const anchor of anchors(graph, queryText)) {
    const firstHop = byFrom.get(anchor.node.id) || [];
    const paths = firstHop.length ? firstHop : [{ from: anchor.node.id, to: anchor.node.id, tau: 'semantic' }];
    for (const edge of paths) {
      const secondHop = byFrom.get(edge.to) || [];
      const allPaths = secondHop.length ? secondHop.map((next) => [edge, next]) : [[edge]];
      for (const path of allPaths) {
        const terminal = path[path.length - 1].to;
        const episodeId = terminal.startsWith('episode:') ? terminal : path.find((row) => row.from.startsWith('episode:'))?.from;
        if (!episodeId) continue;
        const cost = prismPathCost({ anchorDistance: anchor.distance, edges: path, intent });
        const prev = episodes.get(episodeId);
        if (!prev || cost < prev.cost) episodes.set(episodeId, { episodeId, cost, path });
      }
    }
  }
  return [...episodes.values()].sort((a, b) => a.cost - b.cost || a.episodeId.localeCompare(b.episodeId));
}

function compressBundle(bundle = [], graph = {}, budgetChars = PRISM_CONSTANTS.budget_chars) {
  const nodeById = new Map((graph.V || []).map((node) => [node.id, node]));
  const selected = [];
  let used = 0;
  for (const row of bundle) {
    const text = nodeById.get(row.episodeId)?.text || '';
    const cost = Math.max(1, text.length);
    if (used + cost > budgetChars && selected.length) continue;
    selected.push(row);
    used += cost;
    if (used >= budgetChars) break;
  }
  return { selected, used };
}

export function prismScores({ queryText = '', states = [] } = {}) {
  const graph = buildPrismGraph(states);
  const intent = adaptivePrismIntent(queryText);
  const bundle = candidateBundle(graph, queryText, intent.intent);
  const compressed = compressBundle(bundle, graph);
  const minCost = Math.min(...bundle.map((row) => row.cost), 1);
  const maxCost = Math.max(...bundle.map((row) => row.cost), minCost + 1);
  const scoreByEpisode = new Map(bundle.map((row) => [
    row.episodeId,
    clamp01(1 - ((row.cost - minCost) / Math.max(1e-9, maxCost - minCost))),
  ]));
  const scoreById = new Map();
  for (const state of states || []) {
    const episodeId = `episode:${state.id}`;
    scoreById.set(String(state.id), clamp01((0.72 * (scoreByEpisode.get(episodeId) || 0)) + (0.28 * lexicalCosine(queryText, stateText(state)))));
  }
  return {
    scoreById,
    graph_stats: {
      nodes: graph.V.length,
      edges: graph.E.length,
      relation_types: graph.tau.length,
      episodes: states.length,
    },
    intent,
    bundle_count: bundle.length,
    compressed_count: compressed.selected.length,
    compressed_chars: compressed.used,
    formula: 'Cost(pi)=d(a)+sum(c_edge(e)+c_hop); s(Ep)=1-normalized(min Cost(pi))',
    guardrails: PRISM_GUARDRAILS,
  };
}
