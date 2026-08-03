/**
 * Native temporal retrieval operator from:
 * - RIGHT ANSWER AT THE RIGHT TIME.pdf
 *
 * Implemented formulas / techniques:
 * - time-aligned rule graph + graph propagation
 * - seeded personalized PageRank: p_{t+1} = (1 - d) v + d A^T p_t
 * - semantic similarity over graph neighborhoods
 * - edge-to-node dual graph casting
 * - message passing over event-category graph
 *
 * Aimos adaptation:
 * - no training/fine-tuning
 * - no candidate pruning, deletion, decay, or suppression
 * - produces bounded ranking evidence only
 */

const STOPWORDS = new Set([
  'about', 'after', 'again', 'also', 'among', 'before', 'being', 'between',
  'could', 'current', 'during', 'event', 'events', 'from', 'have', 'many',
  'most', 'that', 'their', 'there', 'these', 'this', 'through', 'time', 'what',
  'when', 'where', 'which', 'while', 'with', 'would', 'your',
]);

const CATEGORY_HINTS = [
  ['travel', /\b(flew|flight|airline|airport|train|trip|travel|hotel|boarding)\b/i],
  ['work', /\b(project|meeting|client|work|deadline|office|launch|review)\b/i],
  ['health', /\b(doctor|hospital|medication|therapy|health|pain|symptom)\b/i],
  ['finance', /\b(bank|budget|invoice|payment|tax|loan|fund|price|cost)\b/i],
  ['food', /\b(dinner|lunch|breakfast|restaurant|coffee|meal|recipe)\b/i],
  ['education', /\b(class|course|exam|school|study|lecture|assignment)\b/i],
  ['social', /\b(friend|family|partner|call|party|visit|birthday)\b/i],
  ['purchase', /\b(bought|buy|ordered|purchased|returned|shopping)\b/i],
  ['preference', /\b(like|prefer|favorite|enjoy|hate|dislike|recommend)\b/i],
  ['temporal_delta', /\b(days?|weeks?|months?|years?)\s+(?:passed|between|after|before)|\bhow long\b/i],
];

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function tokenize(text = '') {
  return String(text || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .split(/\s+/)
    .map((token) => token.replace(/^-+|-+$/g, ''))
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function lexicalSimilarity(a = '', b = '') {
  const left = new Set(tokenize(a));
  const right = new Set(tokenize(b));
  if (!left.size || !right.size) return 0;
  let hit = 0;
  for (const token of left) {
    if (right.has(token)) hit += 1;
  }
  return clamp01(hit / Math.sqrt(left.size * right.size));
}

function dayIndex(ms) {
  const n = Number(ms);
  return Number.isFinite(n) ? Math.floor(n / 86400000) : 0;
}

function eventStart(event = {}) {
  const start = Number(event.interval?.start ?? event.start ?? Date.parse(event.created_at || ''));
  return Number.isFinite(start) ? start : 0;
}

export function extractEventCategories(text = '', options = {}) {
  const tokens = tokenize(text);
  const categories = new Set();
  for (const [category, pattern] of CATEGORY_HINTS) {
    if (pattern.test(String(text || ''))) categories.add(category);
  }
  for (const token of tokens.slice(0, options.maxTokens || 12)) {
    categories.add(`term:${token}`);
  }
  return [...categories];
}

export function edgeToNodeDualGraph(graph = {}) {
  const nodes = new Map((graph.nodes || []).map((node) => [node.id, { ...node, kind: node.kind || 'category' }]));
  const edges = [];
  for (const edge of graph.edges || []) {
    const edgeNodeId = `edge:${edge.from}->${edge.to}`;
    nodes.set(edgeNodeId, {
      id: edgeNodeId,
      kind: 'temporal_edge',
      weight: edge.weight,
      source: edge.from,
      target: edge.to,
    });
    edges.push({ from: edge.from, to: edgeNodeId, weight: edge.weight, relation: 'casts_from' });
    edges.push({ from: edgeNodeId, to: edge.to, weight: edge.weight, relation: 'casts_to' });
  }
  return { nodes: [...nodes.values()], edges };
}

export function buildTimeAlignedRuleGraph(events = [], options = {}) {
  const maxEvents = Math.max(1, options.maxEvents || 160);
  const sorted = [...events]
    .filter((event) => event && String(event.id || '').trim())
    .sort((a, b) => eventStart(a) - eventStart(b))
    .slice(0, maxEvents);

  const nodes = new Map();
  const edgeWeights = new Map();
  const eventCategories = new Map();

  for (const event of sorted) {
    const categories = extractEventCategories(event.text || event.value || '', { maxTokens: 8 });
    eventCategories.set(String(event.id), categories);
    for (const category of categories) {
      const node = nodes.get(category) || { id: category, count: 0, event_ids: [] };
      node.count += 1;
      node.event_ids.push(String(event.id));
      nodes.set(category, node);
    }
    for (let i = 0; i < categories.length; i += 1) {
      for (let j = i + 1; j < categories.length; j += 1) {
        const key = `${categories[i]}\u0000${categories[j]}`;
        edgeWeights.set(key, (edgeWeights.get(key) || 0) + 0.25);
        const reverse = `${categories[j]}\u0000${categories[i]}`;
        edgeWeights.set(reverse, (edgeWeights.get(reverse) || 0) + 0.25);
      }
    }
  }

  for (let i = 0; i + 1 < sorted.length; i += 1) {
    const current = sorted[i];
    const next = sorted[i + 1];
    const gapDays = Math.abs(dayIndex(eventStart(next)) - dayIndex(eventStart(current)));
    const temporalWeight = 1 / (1 + Math.max(0, gapDays));
    for (const from of eventCategories.get(String(current.id)) || []) {
      for (const to of eventCategories.get(String(next.id)) || []) {
        const key = `${from}\u0000${to}`;
        edgeWeights.set(key, (edgeWeights.get(key) || 0) + temporalWeight);
      }
    }
  }

  const edges = [...edgeWeights.entries()]
    .map(([key, weight]) => {
      const [from, to] = key.split('\u0000');
      return { from, to, weight: clamp01(weight), relation: 'precedes_or_cooccurs' };
    })
    .filter((edge) => edge.from && edge.to && edge.from !== edge.to);

  return {
    nodes: [...nodes.values()],
    edges,
    event_categories: Object.fromEntries(eventCategories.entries()),
    dual_graph: edgeToNodeDualGraph({ nodes: [...nodes.values()], edges }),
  };
}

export function messagePassRuleGraph(graph = {}, seedScores = {}, options = {}) {
  const iterations = Math.max(1, options.iterations || 2);
  const retain = clamp01(options.retain ?? 0.62);
  const scores = new Map((graph.nodes || []).map((node) => [node.id, clamp01(seedScores[node.id] || 0)]));
  for (let step = 0; step < iterations; step += 1) {
    const next = new Map(scores);
    for (const edge of graph.edges || []) {
      const propagated = (scores.get(edge.from) || 0) * clamp01(edge.weight);
      next.set(edge.to, Math.max(next.get(edge.to) || 0, propagated * (1 - retain)));
    }
    for (const node of graph.nodes || []) {
      next.set(node.id, clamp01((scores.get(node.id) || 0) * retain + (next.get(node.id) || 0)));
    }
    scores.clear();
    for (const [key, value] of next.entries()) scores.set(key, clamp01(value));
  }
  return Object.fromEntries(scores.entries());
}

export function personalizedTemporalPageRank(graph = {}, seedCategories = [], options = {}) {
  const damping = clamp01(options.damping ?? 0.85);
  const iterations = Math.max(1, options.iterations || 24);
  const nodes = (graph.nodes || []).map((node) => node.id);
  if (!nodes.length) return {};

  const seedSet = new Set(seedCategories.filter((id) => nodes.includes(id)));
  const teleport = new Map(nodes.map((id) => [id, seedSet.has(id) ? 1 / Math.max(1, seedSet.size) : 0]));
  if (!seedSet.size) {
    for (const id of nodes) teleport.set(id, 1 / nodes.length);
  }

  const outgoing = new Map(nodes.map((id) => [id, []]));
  for (const edge of graph.edges || []) {
    if (!outgoing.has(edge.from) || !outgoing.has(edge.to)) continue;
    outgoing.get(edge.from).push({ to: edge.to, weight: Math.max(0, Number(edge.weight) || 0) });
  }

  let rank = new Map(teleport);
  for (let step = 0; step < iterations; step += 1) {
    const next = new Map(nodes.map((id) => [id, (1 - damping) * (teleport.get(id) || 0)]));
    for (const id of nodes) {
      const edges = outgoing.get(id) || [];
      const total = edges.reduce((sum, edge) => sum + edge.weight, 0);
      if (!edges.length || total <= 0) {
        const spill = damping * (rank.get(id) || 0) / nodes.length;
        for (const target of nodes) next.set(target, (next.get(target) || 0) + spill);
        continue;
      }
      for (const edge of edges) {
        next.set(edge.to, (next.get(edge.to) || 0) + damping * (rank.get(id) || 0) * (edge.weight / total));
      }
    }
    rank = next;
  }

  const max = Math.max(1e-9, ...rank.values());
  return Object.fromEntries([...rank.entries()].map(([id, score]) => [id, clamp01(score / max)]));
}

export function rightTimeEvidenceScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
  options = {},
} = {}) {
  const graph = buildTimeAlignedRuleGraph(states, options);
  const seedCategories = extractEventCategories(queryText, { maxTokens: 14 })
    .filter((category) => graph.nodes.some((node) => node.id === category));
  const ppr = personalizedTemporalPageRank(graph, seedCategories, options);
  const seedScores = Object.fromEntries(seedCategories.map((category) => [category, 1]));
  const messageScores = messagePassRuleGraph(graph, { ...ppr, ...seedScores }, { iterations: 2 });
  const scoreById = new Map();

  for (const state of states) {
    const categories = graph.event_categories[String(state.id)] || [];
    const graphScore = categories.reduce((max, category) => Math.max(max, ppr[category] || 0, messageScores[category] || 0), 0);
    const semanticScore = lexicalSimilarity(queryText, state.text || state.value || '');
    const recencyDays = Math.max(0, dayIndex(referenceDate) - dayIndex(state.interval?.start ?? state.memory?.created_at));
    const temporalProximity = clamp01(1 / (1 + recencyDays / 365));
    const score = clamp01((graphScore * 0.5) + (semanticScore * 0.35) + (temporalProximity * 0.15));
    scoreById.set(String(state.id), score);
  }

  return {
    scoreById,
    graph,
    seed_categories: seedCategories,
    ppr,
    message_scores: messageScores,
    formula: 'p_{t+1} = (1 - d) v + d A^T p_t',
  };
}
