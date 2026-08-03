/**
 * Native HAGE graph-reasoning recall operator from:
 * - HAGE.pdf
 *
 * Implemented formulas / techniques:
 * - memory interaction state `rt = Retrieve(qt, Mt)`, `ot = LLM(qt, rt)`, `Mt+1 = Update(Mt, qt, ot)`
 * - weighted multi-relational graph over shared memory nodes
 * - query-conditioned traversal of the graph
 * - relational intent detection and routing modulation
 * - traversal score as semantic similarity plus query-conditioned edge signals
 * - sequential decision process view of graph retrieval
 * - node-level evidence target scoring without path labels
 *
 * Aimos adaptation:
 * - performs deterministic retrieval/traversal over returned memory nodes
 * - does not call an LLM and does not update canonical memory in recall
 * - exposes traversal scores as bounded monotone evidence signals only
 */

export const HAGE_CONSTANTS = Object.freeze({
  max_nodes: 220,
  max_edges_per_node: 10,
  traversal_steps: 4,
  beam_width: 12,
  vector_dim: 64,
});

export const HAGE_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  learned_terms_are_deterministic_operator_adaptations: true,
});

const STOPWORDS = new Set(['about', 'after', 'and', 'are', 'between', 'from', 'have', 'many', 'that', 'the', 'this', 'what', 'when', 'which', 'with']);

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
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function tokenSet(value = '') {
  return new Set(tokens(value));
}

function lexicalOverlap(left = '', right = '') {
  const a = tokenSet(left);
  const b = tokenSet(right);
  if (!a.size || !b.size) return 0;
  let hit = 0;
  for (const token of a) if (b.has(token)) hit += 1;
  return hit / Math.sqrt(a.size * b.size);
}

function ms(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : NaN;
}

function dayGap(left, right) {
  const a = ms(left);
  const b = ms(right);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return Infinity;
  return Math.abs(Math.floor(a / 86400000) - Math.floor(b / 86400000));
}

function entities(text = '') {
  const proper = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((m) => m[0].toLowerCase());
  const nouns = tokens(text).filter((token) => token.length >= 5).slice(0, 8);
  return [...new Set([...proper, ...nouns])];
}

export function relationalIntent(queryText = '') {
  const q = String(queryText || '');
  return {
    semantic: 1,
    temporal: /\b(after|before|between|during|last|next|when|days?|weeks?|months?|years?)\b/i.test(q) ? 1 : 0.25,
    entity: entities(q).length ? 1 : 0.35,
    session: /\b(session|conversation|talk|discussed|said|told)\b/i.test(q) ? 1 : 0.3,
    preference: /\b(like|prefer|favorite|recommend|enjoy)\b/i.test(q) ? 1 : 0.2,
  };
}

export function buildHageGraph(states = []) {
  const nodes = (states || []).slice(0, HAGE_CONSTANTS.max_nodes).map((state) => ({
    id: String(state.id),
    text: state.text || state.memory?.value || '',
    created_at: state.memory?.created_at || '',
    session_id: state.memory?.session_id || state.memory?.source || '',
    entities: entities(state.text || state.memory?.value || ''),
  }));
  const edges = [];
  for (let i = 0; i < nodes.length; i += 1) {
    const candidates = [];
    for (let j = 0; j < nodes.length; j += 1) {
      if (i === j) continue;
      const semantic = lexicalOverlap(nodes[i].text, nodes[j].text);
      const temporal = Math.exp(-Math.min(365, dayGap(nodes[i].created_at, nodes[j].created_at)) / 45);
      const entity = lexicalOverlap(nodes[i].entities.join(' '), nodes[j].entities.join(' '));
      const session = nodes[i].session_id && nodes[i].session_id === nodes[j].session_id ? 1 : 0;
      const feature = { semantic, temporal, entity, session, preference: lexicalOverlap(nodes[i].text, `${nodes[j].text} prefer like favorite`) };
      const base = (0.38 * semantic) + (0.20 * temporal) + (0.27 * entity) + (0.15 * session);
      if (base > 0.08) candidates.push({ from: nodes[i].id, to: nodes[j].id, feature, base_weight: clamp01(base) });
    }
    candidates
      .sort((a, b) => b.base_weight - a.base_weight || a.to.localeCompare(b.to))
      .slice(0, HAGE_CONSTANTS.max_edges_per_node)
      .forEach((edge) => edges.push(edge));
  }
  return { nodes, edges };
}

export function queryConditionedEdgeWeight(edge = {}, intent = {}) {
  const f = edge.feature || {};
  const numerator = Object.entries(intent).reduce((sum, [key, weight]) => sum + ((Number(f[key]) || 0) * (Number(weight) || 0)), 0);
  const denom = Object.values(intent).reduce((sum, value) => sum + (Number(value) || 0), 0) || 1;
  return clamp01((0.45 * (edge.base_weight || 0)) + (0.55 * (numerator / denom)));
}

export function hageTraversalScores({ queryText = '', graph = buildHageGraph([]) } = {}) {
  const intent = relationalIntent(queryText);
  const nodeText = new Map((graph.nodes || []).map((node) => [node.id, node.text]));
  const score = new Map((graph.nodes || []).map((node) => [node.id, lexicalOverlap(queryText, node.text)]));
  let beam = [...score.entries()]
    .map(([id, value]) => ({ id, score: value, path: [id] }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, HAGE_CONSTANTS.beam_width);

  for (let step = 0; step < HAGE_CONSTANTS.traversal_steps; step += 1) {
    const next = [...beam];
    for (const row of beam) {
      for (const edge of (graph.edges || []).filter((item) => item.from === row.id)) {
        const edgeWeight = queryConditionedEdgeWeight(edge, intent);
        const semantic = lexicalOverlap(queryText, nodeText.get(edge.to) || '');
        const candidate = clamp01((0.58 * row.score) + (0.27 * edgeWeight) + (0.15 * semantic));
        if (candidate > (score.get(edge.to) || 0)) score.set(edge.to, candidate);
        next.push({ id: edge.to, score: candidate, path: [...row.path, edge.to] });
      }
    }
    beam = next
      .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
      .slice(0, HAGE_CONSTANTS.beam_width);
  }
  return { score, intent, beam };
}

export function hageScores({ queryText = '', states = [] } = {}) {
  const graph = buildHageGraph(states);
  const traversal = hageTraversalScores({ queryText, graph });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const node of graph.nodes) {
    const direct = lexicalOverlap(queryText, node.text);
    const traversalScore = traversal.score.get(node.id) || 0;
    const score = clamp01((0.42 * direct) + (0.58 * traversalScore));
    scoreById.set(node.id, score);
    diagnosticsById.set(node.id, {
      direct_similarity: Number(direct.toFixed(6)),
      traversal_score: Number(traversalScore.toFixed(6)),
      entity_count: node.entities.length,
    });
  }
  for (const state of states || []) {
    const id = String(state.id);
    if (!scoreById.has(id)) scoreById.set(id, 0);
    if (!diagnosticsById.has(id)) diagnosticsById.set(id, { direct_similarity: 0, traversal_score: 0, entity_count: 0 });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: HAGE_CONSTANTS,
    guardrails: HAGE_GUARDRAILS,
    graph_stats: { nodes: graph.nodes.length, edges: graph.edges.length },
    relational_intent: traversal.intent,
    beam_count: traversal.beam.length,
    formula: 'rt=Retrieve(qt,Mt); traversal=0.58*prev+0.27*query_edge+0.15*sim(q,node)',
  };
}
