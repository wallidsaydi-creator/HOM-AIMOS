/**
 * Native event-memory graph operator from:
 * - A Simple Yet Strong Baseline for Long-Term Conversational Memory of LLM Agents.pdf
 *
 * Implemented formulas / techniques:
 * - event-semantic / neo-Davidsonian EDU state
 * - EDU tuple `e=(text(e), src(e), tau(e))`
 * - global EDU union `E = union_s E_s`
 * - query encoding `z_q = h(q)` with shared encoder
 * - filtered candidate sets `C_tilde_edu`, `C_tilde_arg`
 * - heterogeneous graph `G=(V,E)` with session-EDU, EDU-argument, synonym edges
 * - synonym criterion `sim(a,a') >= delta`, delta=0.9
 * - PPR recurrence `pi=(1-alpha)s + alpha T^T pi`
 * - Top-Ke=30, Top-Ka=10, argument cap 30, final EDU Top-K=10
 * - chunk summary `s(c)` used as indexable `text(e)`, full chunk disclosed only when selected
 *
 * Aimos adaptation:
 * - builds a bounded event graph over returned recall candidates
 * - graph propagation contributes a monotone recall signal only
 * - no pruning, deletion, decay, or canonical memory mutation
 */

export const EVENT_MEMORY_CONSTANTS = Object.freeze({
  synonym_delta: 0.9,
  top_edu_candidates: 30,
  top_argument_candidates: 10,
  argument_seed_cap: 30,
  final_top_edu: 10,
  ppr_alpha: 0.85,
  ppr_iterations: 24,
  max_diagnostic_edus: 80,
  max_diagnostic_arguments: 240,
});

export const EVENT_MEMORY_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
});

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
  const stop = new Set(['about', 'after', 'and', 'are', 'for', 'from', 'have', 'into', 'that', 'the', 'this', 'what', 'when', 'with']);
  return normalizeText(value).split(/\s+/).filter((token) => token.length > 2 && !stop.has(token));
}

export function hashEmbedding(text = '', dim = 64) {
  const out = Array.from({ length: dim }, () => 0);
  for (const token of tokens(text)) {
    let h = 2166136261;
    for (let i = 0; i < token.length; i += 1) {
      h ^= token.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    out[h % dim] += 1;
  }
  const n = Math.sqrt(out.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return out.map((value) => value / n);
}

function dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let out = 0;
  for (let i = 0; i < n; i += 1) out += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return out;
}

export function embeddingSimilarity(left = '', right = '') {
  return clamp01((dot(hashEmbedding(left), hashEmbedding(right)) + 1) / 2);
}

export function summarizeChunk(text = '') {
  const sentences = String(text || '').split(/(?<=[.!?])\s+/).filter(Boolean);
  const first = sentences.slice(0, 3).join(' ');
  return first.length > 420 ? `${first.slice(0, 417)}...` : first;
}

export function extractEdusFromSession(state = {}) {
  const text = state.text || state.value || '';
  const sentences = String(text).split(/(?<=[.!?])\s+/).filter(Boolean);
  const rows = sentences.length ? sentences : [text].filter(Boolean);
  return rows.map((sentence, index) => ({
    id: `edu:${state.id}:${index + 1}`,
    session_id: state.memory?.session_id || state.memory?.source || state.id,
    text: summarizeChunk(sentence),
    full_text: sentence,
    src: [state.memory?.key || state.id],
    tau: state.memory?.created_at || state.interval?.start || '',
    state_id: String(state.id),
  }));
}

export function extractArgumentNodes(edu = {}) {
  return [...new Set(tokens(edu.text).filter((token) => token.length >= 4))]
    .slice(0, 12)
    .map((argument) => ({
      id: `arg:${argument}`,
      text: argument,
      edu_id: edu.id,
    }));
}

export function buildEventMemoryGraph(states = []) {
  const edus = states.flatMap(extractEdusFromSession).slice(0, EVENT_MEMORY_CONSTANTS.max_diagnostic_edus);
  const args = edus.flatMap(extractArgumentNodes);
  const nodes = [
    ...new Set(edus.map((edu) => edu.session_id)),
  ].map((id) => ({ id: `session:${id}`, type: 'session', text: String(id) }));
  nodes.push(...edus.map((edu) => ({ id: edu.id, type: 'edu', text: edu.text, state_id: edu.state_id, edu })));
  const uniqueArgs = new Map();
  for (const arg of args) uniqueArgs.set(arg.id, { id: arg.id, type: 'argument', text: arg.text });
  nodes.push(...uniqueArgs.values());

  const edges = [];
  for (const edu of edus) {
    edges.push({ from: `session:${edu.session_id}`, to: edu.id, type: 'session_edu', weight: 1 });
    for (const arg of extractArgumentNodes(edu)) edges.push({ from: edu.id, to: arg.id, type: 'edu_argument', weight: 1 });
  }
  const argRows = [...uniqueArgs.values()].slice(0, EVENT_MEMORY_CONSTANTS.max_diagnostic_arguments);
  const argEmbeddings = new Map(argRows.map((arg) => [arg.id, hashEmbedding(arg.text)]));
  for (let i = 0; i < argRows.length; i += 1) {
    for (let j = i + 1; j < argRows.length; j += 1) {
      if (argRows[i].text[0] !== argRows[j].text[0]) continue;
      const sim = clamp01((dot(argEmbeddings.get(argRows[i].id), argEmbeddings.get(argRows[j].id)) + 1) / 2);
      if (sim >= EVENT_MEMORY_CONSTANTS.synonym_delta) {
        edges.push({ from: argRows[i].id, to: argRows[j].id, type: 'synonym', weight: sim });
        edges.push({ from: argRows[j].id, to: argRows[i].id, type: 'synonym', weight: sim });
      }
    }
  }
  return { nodes, edges, edus, args: [...uniqueArgs.values()] };
}

export function retrieveEduCandidates(query = '', edus = [], topK = EVENT_MEMORY_CONSTANTS.top_edu_candidates) {
  return edus
    .map((edu) => ({ edu, score: embeddingSimilarity(query, edu.text) }))
    .sort((a, b) => b.score - a.score || a.edu.id.localeCompare(b.edu.id))
    .slice(0, topK);
}

export function retrieveArgumentCandidates(query = '', args = [], topK = EVENT_MEMORY_CONSTANTS.top_argument_candidates) {
  return args
    .map((arg) => ({ arg, score: embeddingSimilarity(query, arg.text) }))
    .sort((a, b) => b.score - a.score || a.arg.id.localeCompare(b.arg.id))
    .slice(0, topK);
}

export function eventMemoryFilter(query = '', text = '') {
  return embeddingSimilarity(query, text) >= 0.52 ? 1 : 0;
}

export function personalizedPageRank(graph = {}, seeds = new Map(), {
  alpha = EVENT_MEMORY_CONSTANTS.ppr_alpha,
  iterations = EVENT_MEMORY_CONSTANTS.ppr_iterations,
} = {}) {
  const ids = graph.nodes.map((node) => node.id);
  const score = new Map(ids.map((id) => [id, clamp01(seeds.get(id) || 0)]));
  const seedSum = [...score.values()].reduce((sum, value) => sum + value, 0) || 1;
  for (const id of ids) score.set(id, score.get(id) / seedSum);
  const outgoing = new Map();
  for (const edge of graph.edges || []) {
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from).push(edge);
  }
  for (let iter = 0; iter < iterations; iter += 1) {
    const next = new Map(ids.map((id) => [id, (1 - alpha) * (seeds.get(id) || 0) / seedSum]));
    for (const id of ids) {
      const outs = outgoing.get(id) || [];
      const total = outs.reduce((sum, edge) => sum + (Number(edge.weight) || 1), 0) || 1;
      for (const edge of outs) next.set(edge.to, (next.get(edge.to) || 0) + (alpha * (score.get(id) || 0) * ((Number(edge.weight) || 1) / total)));
    }
    for (const [id, value] of next.entries()) score.set(id, value);
  }
  return score;
}

export function eventMemoryScores({
  queryText = '',
  states = [],
} = {}) {
  const graph = buildEventMemoryGraph(states);
  const eduCandidates = retrieveEduCandidates(queryText, graph.edus)
    .filter((row) => eventMemoryFilter(queryText, row.edu.text));
  const argCandidates = retrieveArgumentCandidates(queryText, graph.args)
    .filter((row) => eventMemoryFilter(queryText, row.arg.text))
    .slice(0, EVENT_MEMORY_CONSTANTS.argument_seed_cap);
  const seeds = new Map();
  for (const row of eduCandidates) seeds.set(row.edu.id, Math.max(seeds.get(row.edu.id) || 0, row.score));
  for (const row of argCandidates) seeds.set(row.arg.id, Math.max(seeds.get(row.arg.id) || 0, row.score));
  const ppr = personalizedPageRank(graph, seeds);
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const stateEdus = graph.edus.filter((edu) => edu.state_id === String(state.id));
    const bestPpr = Math.max(0, ...stateEdus.map((edu) => ppr.get(edu.id) || 0));
    const dense = Math.max(0, ...stateEdus.map((edu) => embeddingSimilarity(queryText, edu.text)));
    const score = clamp01((bestPpr * 8 * 0.55) + (dense * 0.45));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      best_ppr: Number(bestPpr.toFixed(6)),
      dense: Number(dense.toFixed(6)),
      edu_count: stateEdus.length,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    graph_stats: {
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      edus: graph.edus.length,
      argument_nodes: graph.args.length,
    },
    constants: EVENT_MEMORY_CONSTANTS,
    formula: 'pi = (1-alpha)s + alpha T^T pi; R(q)=TopK{(e, pi(v_e)): e in E}',
  };
}
