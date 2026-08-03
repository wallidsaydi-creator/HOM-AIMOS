/**
 * Native HINDSIGHT/TEMPR recall operator from:
 * - HINDSIGHT IS 20:20.pdf
 *
 * Implemented formulas / techniques:
 * - memory partition `M = {W, B, O, S}`
 * - fact unit `f = (u,b,t,v,tau_s,tau_e,tau_m,l,c,x)`
 * - type mapping `l(f) in {world, experience, opinion, observation}`
 * - recall interface `Recall(B, Q, k) -> {f1, ..., fn}`
 * - temporal/entity/semantic/causal graph `G=(V,E)`
 * - entity resolution objective `rho(m)=argmax alpha*sim_str + beta*sim_co + gamma*sim_temp`
 * - entity links `e_ij=(f_i,f_j,w=1.0,l=entity,e)`
 * - temporal edge weight `w_ij = exp(-Delta t_ij / sigma_t)`
 * - semantic edge weight by cosine threshold
 * - causal links with unit weight and typed relation
 * - four-way parallel retrieval: semantic, BM25, graph, temporal
 * - Reciprocal Rank Fusion `RRF(f)=sum_R 1/(k+rank_R(f))`
 * - deterministic cross-encoder-style final score `CE(Q,f)`
 * - opinion confidence update rule over {reinforce,weaken,contradict,neutral}
 *
 * Aimos adaptation:
 * - builds a transient memory graph over returned recall candidates
 * - token budget is a read-window diagnostic, not canonical pruning
 * - opinion updates are exposed as pure functions; recall path does not persist them
 */

export const HINDSIGHT_CONSTANTS = Object.freeze({
  rrf_k: 60,
  semantic_threshold: 0.32,
  temporal_sigma_days: 45,
  token_budget: 4096,
  top_k: 12,
});

export const HINDSIGHT_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  temporal_weight_is_read_edge_weight_only: true,
});

const STOPWORDS = new Set(['about', 'after', 'and', 'are', 'between', 'from', 'have', 'many', 'that', 'the', 'this', 'what', 'when', 'which', 'with', 'would']);

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
}

function normalizeText(value = '') {
  return String(value || '').toLowerCase().normalize('NFKD').replace(/[^\p{L}\p{N}\s-]+/gu, ' ').replace(/\s+/g, ' ').trim();
}

function tokens(value = '') {
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function tokenCount(value = '') {
  return tokens(value).length;
}

function tokenSet(value = '') {
  return new Set(tokens(value));
}

function lexicalSimilarity(left = '', right = '') {
  const a = tokenSet(left);
  const b = tokenSet(right);
  if (!a.size || !b.size) return 0;
  let hits = 0;
  for (const token of a) if (b.has(token)) hits += 1;
  return hits / Math.sqrt(a.size * b.size);
}

function dateMs(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : NaN;
}

function dayDiff(left, right) {
  const a = dateMs(left);
  const b = dateMs(right);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return Infinity;
  return Math.abs(a - b) / 86400000;
}

function extractEntities(text = '') {
  const proper = [...String(text || '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)].map((m) => m[0].toLowerCase());
  const salient = tokens(text).filter((token) => token.length >= 5).slice(0, 10);
  return [...new Set([...proper, ...salient])];
}

export function partitionMemoryUnit(state = {}) {
  const text = state.text || state.memory?.value || '';
  const lower = normalizeText(text);
  let type = 'experience';
  if (/\b(i think|i believe|i prefer|favorite|like|dislike|recommend)\b/i.test(text)) type = 'opinion';
  else if (/\b(currently|profile|summary|overall|usually)\b/i.test(text)) type = 'observation';
  else if (!/\b(i|my|me|we|our)\b/i.test(text)) type = 'world';
  return {
    u: String(state.id),
    b: state.memory?.source || state.memory?.session_id || '',
    t: text.slice(0, 1800),
    v: tokens(lower).slice(0, 16),
    tau_s: state.memory?.created_at || state.interval?.start || null,
    tau_e: state.memory?.created_at || state.interval?.end || null,
    tau_m: state.memory?.updated_at || state.memory?.created_at || null,
    l: type,
    c: type === 'opinion' ? 0.66 : 1,
    x: { key: state.memory?.key || null, memory_type: state.memory?.memory_type || null },
    entities: extractEntities(text),
  };
}

export function memoryPartition(units = []) {
  return {
    W: units.filter((unit) => unit.l === 'world'),
    B: units.filter((unit) => unit.l === 'experience'),
    O: units.filter((unit) => unit.l === 'opinion'),
    S: units.filter((unit) => unit.l === 'observation'),
  };
}

export function entityResolutionScore(mention = '', entity = '', coText = '', timeLeft = '', timeRight = '') {
  const simStr = lexicalSimilarity(mention, entity);
  const simCo = lexicalSimilarity(coText, entity);
  const simTemp = Number.isFinite(dayDiff(timeLeft, timeRight)) ? Math.exp(-dayDiff(timeLeft, timeRight) / HINDSIGHT_CONSTANTS.temporal_sigma_days) : 0;
  return clamp01((0.46 * simStr) + (0.34 * simCo) + (0.20 * simTemp));
}

export function temporalEdgeWeight(left = {}, right = {}, sigmaDays = HINDSIGHT_CONSTANTS.temporal_sigma_days) {
  const delta = dayDiff(left.tau_s, right.tau_s);
  if (!Number.isFinite(delta)) return 0;
  return clamp01(Math.exp(-delta / sigmaDays));
}

export function semanticEdgeWeight(left = {}, right = {}, threshold = HINDSIGHT_CONSTANTS.semantic_threshold) {
  const score = lexicalSimilarity(left.t, right.t);
  return score >= threshold ? score : 0;
}

export function buildHindsightGraph(states = []) {
  const units = (states || []).slice(0, 240).map(partitionMemoryUnit);
  const edges = [];
  for (let i = 0; i < units.length; i += 1) {
    for (let j = i + 1; j < units.length; j += 1) {
      const a = units[i];
      const b = units[j];
      const shared = a.entities.filter((entity) => b.entities.includes(entity));
      if (shared.length) {
        edges.push({ from: a.u, to: b.u, weight: 1, type: 'entity', entity: shared[0] });
        edges.push({ from: b.u, to: a.u, weight: 1, type: 'entity', entity: shared[0] });
      }
      const temporal = temporalEdgeWeight(a, b);
      if (temporal > 0.08) {
        edges.push({ from: a.u, to: b.u, weight: temporal, type: 'temporal' });
        edges.push({ from: b.u, to: a.u, weight: temporal, type: 'temporal' });
      }
      const semantic = semanticEdgeWeight(a, b);
      if (semantic > 0) {
        edges.push({ from: a.u, to: b.u, weight: semantic, type: 'semantic' });
        edges.push({ from: b.u, to: a.u, weight: semantic, type: 'semantic' });
      }
      if (/\b(caused|because|enabled|prevented|led to)\b/i.test(`${a.t} ${b.t}`)) {
        edges.push({ from: a.u, to: b.u, weight: 1, type: 'causal' });
      }
    }
  }
  return { V: units, E: edges, partition: memoryPartition(units) };
}

function rankedBy(rows = [], scoreFn = () => 0) {
  return rows
    .map((row) => ({ id: row.u, score: clamp01(scoreFn(row)), row }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

function bm25Like(query = '', text = '') {
  const q = tokens(query);
  const doc = tokens(text);
  if (!q.length || !doc.length) return 0;
  const counts = new Map();
  for (const token of doc) counts.set(token, (counts.get(token) || 0) + 1);
  let score = 0;
  for (const token of q) {
    const tf = counts.get(token) || 0;
    score += tf ? ((tf * 2.2) / (tf + 1.2)) : 0;
  }
  return clamp01(score / q.length);
}

function graphCentralityScores(graph = {}) {
  const out = new Map((graph.V || []).map((unit) => [unit.u, 0]));
  for (const edge of graph.E || []) out.set(edge.to, (out.get(edge.to) || 0) + clamp01(edge.weight));
  const max = Math.max(1e-9, ...out.values());
  return new Map([...out.entries()].map(([id, score]) => [id, clamp01(score / max)]));
}

function temporalQueryScore(query = '', unit = {}) {
  if (!/\b(after|before|between|during|last|recent|currently|when|days?|weeks?|months?)\b/i.test(query)) return 0;
  return unit.tau_s ? 1 : 0;
}

export function reciprocalRankFusion(rankings = [], k = HINDSIGHT_CONSTANTS.rrf_k) {
  const scores = new Map();
  for (const ranking of rankings) {
    ranking.forEach((row, index) => {
      scores.set(row.id, (scores.get(row.id) || 0) + (1 / (k + index + 1)));
    });
  }
  const max = Math.max(1e-9, ...scores.values());
  return new Map([...scores.entries()].map(([id, value]) => [id, clamp01(value / max)]));
}

export function crossEncoderScore(query = '', unit = {}, graphScore = 0) {
  return clamp01((0.44 * lexicalSimilarity(query, unit.t)) + (0.24 * bm25Like(query, unit.t)) + (0.20 * graphScore) + (0.12 * temporalQueryScore(query, unit)));
}

export function assessOpinionEvidence(opinion = {}, fact = {}) {
  const sim = lexicalSimilarity(opinion.t || opinion.text || '', fact.t || fact.text || '');
  if (/\b(not|never|no longer|stopped|instead)\b/i.test(fact.t || '') && sim > 0.2) return 'contradict';
  if (sim > 0.55) return 'reinforce';
  if (sim > 0.28) return 'weaken';
  return 'neutral';
}

export function updateOpinionConfidence(confidence = 0, assessment = 'neutral', alpha = 0.1) {
  const c = clamp01(confidence);
  if (assessment === 'reinforce') return Math.min(c + alpha, 1);
  if (assessment === 'weaken') return Math.max(c - alpha, 0);
  if (assessment === 'contradict') return Math.max(c - (2 * alpha), 0);
  return c;
}

export function hindsightMemoryGraphScores({ queryText = '', states = [], tokenBudget = HINDSIGHT_CONSTANTS.token_budget } = {}) {
  const graph = buildHindsightGraph(states);
  const centrality = graphCentralityScores(graph);
  const semantic = rankedBy(graph.V, (unit) => lexicalSimilarity(queryText, unit.t));
  const keyword = rankedBy(graph.V, (unit) => bm25Like(queryText, unit.t));
  const graphRank = rankedBy(graph.V, (unit) => centrality.get(unit.u) || 0);
  const temporal = rankedBy(graph.V, (unit) => temporalQueryScore(queryText, unit));
  const rrf = reciprocalRankFusion([semantic, keyword, graphRank, temporal]);

  const final = graph.V
    .map((unit) => ({
      unit,
      rrf: rrf.get(unit.u) || 0,
      ce: crossEncoderScore(queryText, unit, centrality.get(unit.u) || 0),
      tokens: tokenCount(unit.t),
    }))
    .sort((a, b) => ((0.48 * b.rrf) + (0.52 * b.ce)) - ((0.48 * a.rrf) + (0.52 * a.ce)) || a.unit.u.localeCompare(b.unit.u));

  let used = 0;
  const selected = new Set();
  for (const row of final) {
    if (selected.size >= HINDSIGHT_CONSTANTS.top_k) break;
    if (used + row.tokens > tokenBudget && selected.size) continue;
    selected.add(row.unit.u);
    used += row.tokens;
  }

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const row of final) {
    const score = clamp01((0.48 * row.rrf) + (0.42 * row.ce) + (0.10 * (selected.has(row.unit.u) ? 1 : 0)));
    scoreById.set(row.unit.u, score);
    diagnosticsById.set(row.unit.u, {
      partition: row.unit.l,
      rrf: Number(row.rrf.toFixed(6)),
      ce: Number(row.ce.toFixed(6)),
      selected_in_budget_window: selected.has(row.unit.u),
      token_count: row.tokens,
      entity_count: row.unit.entities.length,
    });
  }
  for (const state of states || []) {
    const id = String(state.id);
    if (!scoreById.has(id)) scoreById.set(id, 0);
    if (!diagnosticsById.has(id)) diagnosticsById.set(id, { partition: 'unknown', rrf: 0, ce: 0, selected_in_budget_window: false, token_count: 0, entity_count: 0 });
  }

  return {
    scoreById,
    diagnosticsById,
    constants: HINDSIGHT_CONSTANTS,
    guardrails: HINDSIGHT_GUARDRAILS,
    graph_stats: {
      nodes: graph.V.length,
      edges: graph.E.length,
      world: graph.partition.W.length,
      experience: graph.partition.B.length,
      opinion: graph.partition.O.length,
      observation: graph.partition.S.length,
    },
    used_tokens: used,
    budget_tokens: tokenBudget,
    formula: 'M={W,B,O,S}; RRF(f)=sum_R 1/(k+rank_R(f)); score=0.48*RRF+0.42*CE+0.10*budget_select',
  };
}
