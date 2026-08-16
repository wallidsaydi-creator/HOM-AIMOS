/**
 * Deterministic AIMOS relational-graph recall adaptation inspired by:
 * - HAGE.pdf
 *
 * Paper concepts represented structurally:
 * - relation-feature graph over shared memory nodes
 * - query-conditioned deterministic traversal of the graph
 * - relational intent detection and routing modulation
 *
 * Non-equivalence boundary:
 * - does not implement HAGE Equations (7)-(15), a trained QueryRouter,
 *   trainable edge embeddings, neighbor softmax, REINFORCE, or checkpoints
 * - lexical/entity features are deterministic AIMOS proxies, not dense embeddings
 * - performs bounded deterministic traversal over returned memory nodes
 * - does not call an LLM and does not update canonical memory in recall
 * - remains dormant until a separately measured activation decision
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
  implements_trained_hage_policy: false,
  requires_bound_checkpoint_for_hage_claim: true,
});

export const HAGE_TRAINED_ARM_REQUIREMENTS = Object.freeze([
  'licensed_training_corpus_manifest',
  'deterministic_split_and_initialization_manifest',
  'query_router_architecture_and_weights',
  'trainable_edge_feature_checkpoint',
  'reward_and_target_evidence_contract',
  'reinforce_baseline_and_anchor_regularization_proof',
  'checkpoint_signature_and_source_binding',
  'train_inference_separation_test',
]);

const STOPWORDS = new Set(['about', 'after', 'and', 'are', 'between', 'from', 'have', 'many', 'that', 'the', 'this', 'what', 'when', 'which', 'with']);

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function validStates(states) {
  if (!Array.isArray(states)) return [];
  const unique = new Map();
  for (const state of states) {
    if (!state || typeof state !== 'object') continue;
    const id = String(state.id || '').trim();
    if (!id || unique.has(id)) continue;
    unique.set(id, state);
  }
  return [...unique.values()];
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

function overlapSets(left = new Set(), right = new Set()) {
  if (!(left instanceof Set) || !(right instanceof Set) || !left.size || !right.size) return 0;
  let hit = 0;
  for (const token of left) if (right.has(token)) hit += 1;
  return hit / Math.sqrt(left.size * right.size);
}

function lexicalOverlap(left = '', right = '') {
  return overlapSets(tokenSet(left), tokenSet(right));
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
  const normalizedStates = validStates(states).slice(0, HAGE_CONSTANTS.max_nodes);
  const nodes = normalizedStates.map((state) => ({
    id: String(state.id),
    text: state.text || state.memory?.value || '',
    created_at: state.memory?.created_at || '',
    session_id: String(state.memory?.session_id || state.memory?.source || ''),
    entities: entities(state.text || state.memory?.value || ''),
  }));
  const lexicalTokensById = new Map(nodes.map((node) => [node.id, tokenSet(node.text)]));
  const entityTokensById = new Map(nodes.map((node) => [node.id, tokenSet(node.entities.join(' '))]));
  const edges = [];
  for (let i = 0; i < nodes.length; i += 1) {
    const candidates = [];
    for (let j = 0; j < nodes.length; j += 1) {
      if (i === j) continue;
      const leftLexical = lexicalTokensById.get(nodes[i].id);
      const rightLexical = lexicalTokensById.get(nodes[j].id);
      const semantic = overlapSets(leftLexical, rightLexical);
      const gap = dayGap(nodes[i].created_at, nodes[j].created_at);
      const temporal = Number.isFinite(gap) ? Math.exp(-Math.min(365, gap) / 45) : 0;
      const entity = overlapSets(entityTokensById.get(nodes[i].id), entityTokensById.get(nodes[j].id));
      const session = nodes[i].session_id && nodes[i].session_id === nodes[j].session_id ? 1 : 0;
      const preference = overlapSets(
        leftLexical,
        new Set([...rightLexical, 'prefer', 'like', 'favorite']),
      );
      const feature = { semantic, temporal, entity, session, preference };
      const base = (0.38 * semantic) + (0.20 * temporal) + (0.27 * entity) + (0.15 * session);
      if (base > 0.08) candidates.push({ from: nodes[i].id, to: nodes[j].id, feature, base_weight: clamp01(base) });
    }
    candidates
      .sort((a, b) => b.base_weight - a.base_weight || a.to.localeCompare(b.to))
      .slice(0, HAGE_CONSTANTS.max_edges_per_node)
      .forEach((edge) => edges.push(edge));
  }
  const adjacency = Object.fromEntries(nodes.map((node) => [node.id, []]));
  for (const edge of edges) adjacency[edge.from]?.push(edge);
  return { nodes, edges, adjacency };
}

export function queryConditionedEdgeWeight(edge = {}, intent = {}) {
  const safeEdge = edge && typeof edge === 'object' ? edge : {};
  const safeIntent = intent && typeof intent === 'object' && !Array.isArray(intent) ? intent : {};
  const f = safeEdge.feature && typeof safeEdge.feature === 'object' ? safeEdge.feature : {};
  const numerator = Object.entries(safeIntent).reduce((sum, [key, weight]) => sum + ((Number(f[key]) || 0) * (Number(weight) || 0)), 0);
  const denom = Object.values(safeIntent).reduce((sum, value) => sum + (Number(value) || 0), 0) || 1;
  return clamp01((0.45 * (safeEdge.base_weight || 0)) + (0.55 * (numerator / denom)));
}

export function hageTraversalScores({ queryText = '', graph = buildHageGraph([]) } = {}) {
  const intent = relationalIntent(queryText);
  const nodeRows = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const nodes = new Map();
  for (const node of nodeRows) {
    if (!node || typeof node !== 'object') continue;
    const id = String(node.id || '').trim();
    if (!id || nodes.has(id)) continue;
    nodes.set(id, { ...node, id });
  }
  const edgeRows = Array.isArray(graph?.edges) ? graph.edges : [];
  const adjacency = new Map([...nodes.keys()].map((id) => [id, []]));
  for (const edge of edgeRows) {
    if (!edge || typeof edge !== 'object') continue;
    const from = String(edge.from || '').trim();
    const to = String(edge.to || '').trim();
    if (!nodes.has(from) || !nodes.has(to) || from === to) continue;
    const outgoing = adjacency.get(from);
    if (outgoing.length >= HAGE_CONSTANTS.max_edges_per_node) continue;
    outgoing.push({ ...edge, from, to });
  }
  for (const outgoing of adjacency.values()) {
    outgoing.sort((a, b) => String(a.to).localeCompare(String(b.to)));
  }

  const nodeText = new Map([...nodes.values()].map((node) => [node.id, node.text || '']));
  const score = new Map([...nodes.values()].map((node) => [node.id, lexicalOverlap(queryText, node.text || '')]));
  let beam = [...score.entries()]
    .map(([id, value]) => ({ id, score: value, path: [id] }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, HAGE_CONSTANTS.beam_width);
  let frontier = [...beam];
  const bestPathById = new Map(beam.map((row) => [row.id, row]));
  let stepsExecuted = 0;

  for (let step = 0; step < HAGE_CONSTANTS.traversal_steps; step += 1) {
    const nextById = new Map();
    for (const row of frontier) {
      for (const edge of adjacency.get(row.id) || []) {
        if (row.path.includes(edge.to)) continue;
        const edgeWeight = queryConditionedEdgeWeight(edge, intent);
        const semantic = lexicalOverlap(queryText, nodeText.get(edge.to) || '');
        const candidate = clamp01((0.58 * row.score) + (0.27 * edgeWeight) + (0.15 * semantic));
        if (candidate > (score.get(edge.to) || 0)) score.set(edge.to, candidate);
        const candidateRow = { id: edge.to, score: candidate, path: [...row.path, edge.to] };
        const current = nextById.get(edge.to);
        if (!current || candidate > current.score
          || (candidate === current.score && candidateRow.path.join('\u0000') < current.path.join('\u0000'))) {
          nextById.set(edge.to, candidateRow);
        }
      }
    }
    if (!nextById.size) break;
    frontier = [...nextById.values()]
      .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
      .slice(0, HAGE_CONSTANTS.beam_width);
    stepsExecuted += 1;
    for (const row of frontier) {
      const current = bestPathById.get(row.id);
      if (!current || row.score > current.score
        || (row.score === current.score && row.path.join('\u0000') < current.path.join('\u0000'))) {
        bestPathById.set(row.id, row);
      }
    }
  }
  beam = [...bestPathById.values()]
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, HAGE_CONSTANTS.beam_width);
  return { score, intent, beam, steps_executed: stepsExecuted };
}

export function hageScores({ queryText = '', states = [] } = {}) {
  const normalizedStates = validStates(states);
  const graph = buildHageGraph(normalizedStates);
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
  for (const state of normalizedStates) {
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
    traversal_steps_executed: traversal.steps_executed,
    trained_hage_requirements: HAGE_TRAINED_ARM_REQUIREMENTS,
    formula: 'AIMOS deterministic adaptation: traversal=0.58*prev+0.27*query_edge+0.15*lexical_similarity',
  };
}
