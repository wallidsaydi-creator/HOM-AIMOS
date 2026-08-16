/**
 * Dormant HINDSIGHT/TEMPR recall kernel.
 *
 * Paper authority:
 * - HINDSIGHT IS 20:20.pdf, Sections 3-5, Equations (1)-(17), (25)-(26)
 *
 * Paper-faithful pure kernels implemented here:
 * - four-network partition M = {W, B, O, S}
 * - temporal edges w = exp(-Delta t / sigma_t)
 * - cosine-threshold semantic edges
 * - corpus BM25 lexical ranking
 * - bounded spreading activation adapted from Equation (12)
 * - temporal interval overlap and midpoint proximity
 * - raw Reciprocal Rank Fusion from Equation (15)
 * - token-budget filtering from Equation (17)
 * - pure opinion-confidence arithmetic from Equation (26)
 *
 * Explicit AIMOS adaptations and exclusions:
 * - partition and entity extraction are deterministic diagnostics, not the
 *   paper's LLM extraction/entity-resolution pipeline;
 * - graph propagation is hop-bounded and activation-clamped so cycles cannot
 *   create an unbounded read-time score;
 * - no neural cross-encoder is claimed or simulated; RRF is the terminal
 *   ranking until a native, measured reranker exists;
 * - no retain, observation synthesis, opinion persistence, database access,
 *   canonical mutation, deletion, suppression, or age-based score decay occurs;
 * - any future opinion mutation must use the signed MutMem transition path.
 */

export const HINDSIGHT_CONSTANTS = Object.freeze({
  rrf_k: 60,
  semantic_threshold: 0.32,
  temporal_sigma_days: 45,
  temporal_edge_minimum: 0.08,
  token_budget: 4096,
  top_k: 12,
  max_nodes: 240,
  max_hops: 3,
  path_attenuation: 0.85,
  bm25_k1: 1.2,
  bm25_b: 0.75,
  link_multipliers: Object.freeze({
    entity: 1.08,
    causal: 1.12,
    causes: 1.12,
    caused_by: 1.12,
    enables: 1.12,
    prevents: 1.12,
    semantic: 1,
    temporal: 0.92,
  }),
});

export const HINDSIGHT_GUARDRAILS = Object.freeze({
  dormant: true,
  mutates_canonical_memory: false,
  persists_opinion_updates: false,
  prunes_canonical_memory: false,
  applies_age_decay: false,
  deletes_memory: false,
  suppresses_memory: false,
  injects_answers: false,
  uses_database: false,
  uses_environment_authority: false,
  temporal_weight_is_transient_read_edge_evidence: true,
  path_attenuation_is_bounded_within_query_only: true,
  neural_cross_encoder_implemented: false,
});

const STOPWORDS = new Set([
  'about', 'after', 'and', 'are', 'between', 'from', 'have', 'many', 'that',
  'the', 'this', 'what', 'when', 'which', 'with', 'would',
]);

const VALID_ASSESSMENTS = new Set(['reinforce', 'weaken', 'contradict', 'neutral']);
const VALID_CAUSAL_TYPES = new Set(['causal', 'causes', 'caused_by', 'enables', 'prevents']);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
}

function positiveFinite(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function boundedInteger(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function normalizeText(value = '') {
  return String(value ?? '')
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
  return clamp01(hits / Math.sqrt(a.size * b.size));
}

function dateMs(value) {
  if (Number.isFinite(value)) return Number(value);
  const parsed = Date.parse(value ?? '');
  return Number.isFinite(parsed) ? parsed : NaN;
}

function dayDiff(left, right) {
  const a = dateMs(left);
  const b = dateMs(right);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return Infinity;
  return Math.abs(a - b) / 86400000;
}

function finiteVector(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const vector = value.map(Number);
  return vector.every(Number.isFinite) ? vector : null;
}

function cosineSimilarity(left, right) {
  const a = finiteVector(left);
  const b = finiteVector(right);
  if (!a || !b || a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return clamp(dot / Math.sqrt(normA * normB), -1, 1);
}

function normalizeEntities(value, text = '') {
  const supplied = Array.isArray(value)
    ? value.map((entry) => normalizeText(isRecord(entry) ? entry.name : entry)).filter(Boolean)
    : [];
  if (supplied.length) return [...new Set(supplied)].sort();
  const proper = [...String(text ?? '').matchAll(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g)]
    .map((match) => normalizeText(match[0]));
  return [...new Set(proper)].sort();
}

function normalizeInterval(state) {
  const memory = isRecord(state.memory) ? state.memory : {};
  const interval = isRecord(state.interval) ? state.interval : {};
  const start = dateMs(interval.start ?? memory.occurred_at ?? memory.created_at);
  const endCandidate = dateMs(interval.end ?? memory.ended_at ?? memory.occurred_at ?? memory.created_at);
  const end = Number.isFinite(endCandidate) ? endCandidate : start;
  return {
    start: Number.isFinite(start) ? start : NaN,
    end: Number.isFinite(end) ? Math.max(start, end) : NaN,
    mention: dateMs(memory.updated_at ?? memory.created_at),
  };
}

function normalizeCausalLinks(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .map((link) => ({
      target: String(link.target ?? link.to ?? ''),
      type: String(link.type ?? link.relation ?? 'causal').toLowerCase(),
      weight: clamp01(link.weight ?? 1),
    }))
    .filter((link) => link.target && VALID_CAUSAL_TYPES.has(link.type) && link.weight > 0)
    .sort((a, b) => a.target.localeCompare(b.target) || a.type.localeCompare(b.type));
}

export function partitionMemoryUnit(state = {}) {
  if (!isRecord(state)) return null;
  const memory = isRecord(state.memory) ? state.memory : {};
  const id = String(state.id ?? memory.id ?? '').trim();
  const text = String(state.text ?? memory.value ?? '').trim();
  if (!id || !text) return null;

  const lower = normalizeText(text);
  let type = 'experience';
  if (/\b(i think|i believe|i prefer|favorite|like|dislike|recommend)\b/i.test(text)) type = 'opinion';
  else if (/\b(currently|profile|summary|overall|usually)\b/i.test(text)) type = 'observation';
  else if (!/\b(i|my|me|we|our)\b/i.test(text)) type = 'world';

  const interval = normalizeInterval(state);
  return {
    u: id,
    b: String(memory.source ?? memory.session_id ?? ''),
    t: text.slice(0, 1800),
    v: finiteVector(state.embedding ?? memory.embedding ?? memory.vector),
    tau_s: Number.isFinite(interval.start) ? interval.start : null,
    tau_e: Number.isFinite(interval.end) ? interval.end : null,
    tau_m: Number.isFinite(interval.mention) ? interval.mention : null,
    l: type,
    c: type === 'opinion' ? clamp01(memory.confidence ?? 0.66) : null,
    x: Object.freeze({
      key: memory.key ?? null,
      memory_type: memory.memory_type ?? null,
    }),
    entities: normalizeEntities(state.entities ?? memory.entities, text),
    causal_links: normalizeCausalLinks(state.causal_links ?? memory.causal_links),
  };
}

export function memoryPartition(units = []) {
  const rows = Array.isArray(units) ? units.filter(isRecord) : [];
  return {
    W: rows.filter((unit) => unit.l === 'world'),
    B: rows.filter((unit) => unit.l === 'experience'),
    O: rows.filter((unit) => unit.l === 'opinion'),
    S: rows.filter((unit) => unit.l === 'observation'),
  };
}

export function entityResolutionScore(mention = '', entity = '', coText = '', timeLeft = '', timeRight = '') {
  const simStr = lexicalSimilarity(mention, entity);
  const simCo = lexicalSimilarity(coText, entity);
  const delta = dayDiff(timeLeft, timeRight);
  const simTemp = Number.isFinite(delta)
    ? Math.exp(-delta / HINDSIGHT_CONSTANTS.temporal_sigma_days)
    : 0;
  return clamp01((0.46 * simStr) + (0.34 * simCo) + (0.20 * simTemp));
}

export function temporalEdgeWeight(left = {}, right = {}, sigmaDays = HINDSIGHT_CONSTANTS.temporal_sigma_days) {
  const sigma = positiveFinite(sigmaDays, NaN);
  if (!Number.isFinite(sigma)) return 0;
  const delta = dayDiff(left?.tau_s, right?.tau_s);
  if (!Number.isFinite(delta)) return 0;
  return clamp01(Math.exp(-delta / sigma));
}

export function semanticEdgeWeight(left = {}, right = {}, threshold = HINDSIGHT_CONSTANTS.semantic_threshold) {
  const minimum = clamp01(threshold);
  const score = cosineSimilarity(left?.v, right?.v);
  return score >= minimum ? clamp01(score) : 0;
}

function normalizeUnits(states) {
  if (!Array.isArray(states)) return [];
  const seen = new Set();
  const units = [];
  for (const state of states) {
    if (units.length >= HINDSIGHT_CONSTANTS.max_nodes) break;
    const unit = partitionMemoryUnit(state);
    if (!unit || seen.has(unit.u)) continue;
    seen.add(unit.u);
    units.push(unit);
  }
  return units;
}

function addEdge(edges, seen, edge) {
  if (!edge.from || !edge.to || edge.from === edge.to || edge.weight <= 0) return;
  const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
  if (seen.has(key)) return;
  seen.add(key);
  edges.push(Object.freeze(edge));
}

export function buildHindsightGraph(states = []) {
  const units = normalizeUnits(states);
  const edges = [];
  const edgeKeys = new Set();

  for (let i = 0; i < units.length; i += 1) {
    for (let j = i + 1; j < units.length; j += 1) {
      const left = units[i];
      const right = units[j];
      const shared = left.entities.filter((entity) => right.entities.includes(entity));
      if (shared.length) {
        addEdge(edges, edgeKeys, { from: left.u, to: right.u, weight: 1, type: 'entity', entity: shared[0] });
        addEdge(edges, edgeKeys, { from: right.u, to: left.u, weight: 1, type: 'entity', entity: shared[0] });
      }

      const temporal = temporalEdgeWeight(left, right);
      if (temporal >= HINDSIGHT_CONSTANTS.temporal_edge_minimum) {
        addEdge(edges, edgeKeys, { from: left.u, to: right.u, weight: temporal, type: 'temporal' });
        addEdge(edges, edgeKeys, { from: right.u, to: left.u, weight: temporal, type: 'temporal' });
      }

      const semantic = semanticEdgeWeight(left, right);
      if (semantic > 0) {
        addEdge(edges, edgeKeys, { from: left.u, to: right.u, weight: semantic, type: 'semantic' });
        addEdge(edges, edgeKeys, { from: right.u, to: left.u, weight: semantic, type: 'semantic' });
      }
    }
  }

  const ids = new Set(units.map((unit) => unit.u));
  for (const unit of units) {
    for (const link of unit.causal_links) {
      if (!ids.has(link.target)) continue;
      addEdge(edges, edgeKeys, {
        from: unit.u,
        to: link.target,
        weight: link.weight,
        type: link.type === 'causal' ? 'causal' : link.type,
      });
    }
  }

  return {
    V: units,
    E: edges,
    partition: memoryPartition(units),
  };
}

function rankedBy(rows = [], scoreFn = () => 0, { includeZero = false } = {}) {
  return rows
    .map((row) => ({ id: row.u, score: clamp01(scoreFn(row)), row }))
    .filter((row) => includeZero || row.score > 0)
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

export function bm25Scores(query = '', units = [], {
  k1 = HINDSIGHT_CONSTANTS.bm25_k1,
  b = HINDSIGHT_CONSTANTS.bm25_b,
} = {}) {
  const queryTerms = [...new Set(tokens(query))];
  const rows = Array.isArray(units) ? units.filter(isRecord) : [];
  if (!queryTerms.length || !rows.length) return new Map();

  const safeK1 = positiveFinite(k1, HINDSIGHT_CONSTANTS.bm25_k1);
  const safeB = clamp(b, 0, 1);
  const documents = rows.map((unit) => tokens(unit.t));
  const averageLength = documents.reduce((sum, doc) => sum + doc.length, 0) / documents.length || 1;
  const documentFrequency = new Map();
  for (const term of queryTerms) {
    documentFrequency.set(term, documents.reduce((count, doc) => count + (doc.includes(term) ? 1 : 0), 0));
  }

  const scores = new Map();
  for (let i = 0; i < rows.length; i += 1) {
    const counts = new Map();
    for (const term of documents[i]) counts.set(term, (counts.get(term) || 0) + 1);
    let score = 0;
    for (const term of queryTerms) {
      const tf = counts.get(term) || 0;
      if (!tf) continue;
      const df = documentFrequency.get(term) || 0;
      const idf = Math.log(1 + ((documents.length - df + 0.5) / (df + 0.5)));
      const lengthNorm = 1 - safeB + (safeB * (documents[i].length / averageLength));
      score += idf * ((tf * (safeK1 + 1)) / (tf + (safeK1 * lengthNorm)));
    }
    if (score > 0) scores.set(rows[i].u, score);
  }
  return scores;
}

function normalizeScoreMap(scores) {
  if (!(scores instanceof Map) || scores.size === 0) return new Map();
  const max = Math.max(...[...scores.values()].filter(Number.isFinite), 0);
  if (!(max > 0)) return new Map([...scores.keys()].map((id) => [id, 0]));
  return new Map([...scores.entries()].map(([id, score]) => [id, clamp01(score / max)]));
}

export function temprSpreadingActivation(graph = {}, seedScores = new Map(), {
  maxHops = HINDSIGHT_CONSTANTS.max_hops,
  attenuation = HINDSIGHT_CONSTANTS.path_attenuation,
  linkMultipliers = HINDSIGHT_CONSTANTS.link_multipliers,
} = {}) {
  const vertices = Array.isArray(graph?.V) ? graph.V : [];
  const edges = Array.isArray(graph?.E) ? graph.E : [];
  const ids = new Set(vertices.map((unit) => String(unit.u)));
  const hops = boundedInteger(maxHops, HINDSIGHT_CONSTANTS.max_hops, 0, 8);
  const delta = clamp(attenuation, Number.EPSILON, 1);
  const adjacency = new Map([...ids].map((id) => [id, []]));
  for (const edge of edges) {
    if (!isRecord(edge) || !ids.has(String(edge.from)) || !ids.has(String(edge.to))) continue;
    adjacency.get(String(edge.from)).push(edge);
  }
  for (const list of adjacency.values()) {
    list.sort((a, b) => String(a.to).localeCompare(String(b.to)) || String(a.type).localeCompare(String(b.type)));
  }

  let frontier = new Map();
  const best = new Map([...ids].map((id) => [id, 0]));
  if (seedScores instanceof Map) {
    for (const [idValue, scoreValue] of seedScores) {
      const id = String(idValue);
      if (!ids.has(id)) continue;
      const score = clamp01(scoreValue);
      if (score <= 0) continue;
      frontier.set(id, score);
      best.set(id, score);
    }
  }

  for (let step = 0; step < hops && frontier.size; step += 1) {
    const next = new Map();
    for (const [from, activation] of frontier) {
      for (const edge of adjacency.get(from) || []) {
        const multiplier = positiveFinite(linkMultipliers?.[edge.type], 1);
        const candidate = clamp01(activation * clamp01(edge.weight) * delta * multiplier);
        const to = String(edge.to);
        if (candidate <= (next.get(to) || 0)) continue;
        next.set(to, candidate);
        if (candidate > (best.get(to) || 0)) best.set(to, candidate);
      }
    }
    frontier = next;
  }

  return best;
}

function normalizeQueryInterval(value) {
  if (!isRecord(value)) return null;
  const start = dateMs(value.start ?? value.tau_s);
  const endCandidate = dateMs(value.end ?? value.tau_e);
  if (!Number.isFinite(start) || !Number.isFinite(endCandidate)) return null;
  return { start: Math.min(start, endCandidate), end: Math.max(start, endCandidate) };
}

export function temporalIntervalScores(units = [], queryInterval = null) {
  const query = normalizeQueryInterval(queryInterval);
  if (!query || !Array.isArray(units)) return new Map();
  const queryMidpoint = (query.start + query.end) / 2;
  const halfWidth = Math.max((query.end - query.start) / 2, 1);
  const scores = new Map();
  for (const unit of units) {
    if (!isRecord(unit)) continue;
    const start = dateMs(unit.tau_s);
    const end = dateMs(unit.tau_e ?? unit.tau_s);
    if (!Number.isFinite(start) || !Number.isFinite(end)) continue;
    if (Math.max(start, query.start) > Math.min(end, query.end)) continue;
    const midpoint = (start + end) / 2;
    scores.set(String(unit.u), clamp01(1 - (Math.abs(midpoint - queryMidpoint) / halfWidth)));
  }
  return scores;
}

export function reciprocalRankFusion(rankings = [], k = HINDSIGHT_CONSTANTS.rrf_k) {
  const safeK = positiveFinite(k, HINDSIGHT_CONSTANTS.rrf_k);
  const scores = new Map();
  if (!Array.isArray(rankings)) return scores;
  for (const ranking of rankings) {
    if (!Array.isArray(ranking)) continue;
    const seen = new Set();
    for (let index = 0; index < ranking.length; index += 1) {
      const id = String(ranking[index]?.id ?? '').trim();
      if (!id || seen.has(id)) continue;
      seen.add(id);
      const rank = seen.size;
      scores.set(id, (scores.get(id) || 0) + (1 / (safeK + rank)));
    }
  }
  return scores;
}

export function assessOpinionEvidence(opinion = {}, fact = {}) {
  const opinionText = isRecord(opinion) ? String(opinion.t ?? opinion.text ?? '') : '';
  const factText = isRecord(fact) ? String(fact.t ?? fact.text ?? '') : '';
  const similarity = lexicalSimilarity(opinionText, factText);
  if (/\b(not|never|no longer|stopped|instead)\b/i.test(factText) && similarity > 0.2) return 'contradict';
  if (similarity > 0.55) return 'reinforce';
  if (similarity > 0.28) return 'weaken';
  return 'neutral';
}

export function updateOpinionConfidence(confidence = 0, assessment = 'neutral', alpha = 0.1) {
  const current = clamp01(confidence);
  const step = clamp(alpha, Number.EPSILON, 1);
  const relation = VALID_ASSESSMENTS.has(assessment) ? assessment : 'neutral';
  if (relation === 'reinforce') return Math.min(current + step, 1);
  if (relation === 'weaken') return Math.max(current - step, 0);
  if (relation === 'contradict') return Math.max(current - (2 * step), 0);
  return current;
}

function rankFromScoreMap(scoreMap) {
  if (!(scoreMap instanceof Map)) return [];
  return [...scoreMap.entries()]
    .filter(([, score]) => Number.isFinite(score) && score > 0)
    .map(([id, score]) => ({ id: String(id), score }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

export function hindsightMemoryGraphScores({
  queryText = '',
  queryEmbedding = null,
  queryInterval = null,
  states = [],
  tokenBudget = HINDSIGHT_CONSTANTS.token_budget,
} = {}) {
  const graph = buildHindsightGraph(states);
  const semanticScores = new Map();
  for (const unit of graph.V) {
    const score = cosineSimilarity(queryEmbedding, unit.v);
    if (score > 0) semanticScores.set(unit.u, score);
  }

  const keywordScores = bm25Scores(queryText, graph.V);
  const seedScores = normalizeScoreMap(semanticScores.size ? semanticScores : keywordScores);
  const graphScores = temprSpreadingActivation(graph, seedScores);
  const temporalScores = temporalIntervalScores(graph.V, queryInterval);
  const rankings = [semanticScores, keywordScores, graphScores, temporalScores]
    .map(rankFromScoreMap)
    .filter((ranking) => ranking.length > 0);
  const rawRrf = reciprocalRankFusion(rankings);
  const normalizedRrf = normalizeScoreMap(rawRrf);

  const final = graph.V
    .map((unit) => ({
      unit,
      rawRrf: rawRrf.get(unit.u) || 0,
      score: normalizedRrf.get(unit.u) || 0,
      semantic: semanticScores.get(unit.u) || 0,
      bm25: keywordScores.get(unit.u) || 0,
      graph: graphScores.get(unit.u) || 0,
      temporal: temporalScores.get(unit.u) || 0,
      tokens: tokenCount(unit.t),
    }))
    .sort((a, b) => b.rawRrf - a.rawRrf || b.semantic - a.semantic || b.bm25 - a.bm25 || a.unit.u.localeCompare(b.unit.u));

  const budget = Math.max(0, Math.floor(Number(tokenBudget) || 0));
  let used = 0;
  const selected = new Set();
  for (const row of final) {
    if (selected.size >= HINDSIGHT_CONSTANTS.top_k) break;
    if (used + row.tokens > budget) break;
    selected.add(row.unit.u);
    used += row.tokens;
  }

  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const row of final) {
    scoreById.set(row.unit.u, row.score);
    diagnosticsById.set(row.unit.u, {
      partition: row.unit.l,
      rrf_raw: Number(row.rawRrf.toFixed(9)),
      rrf_normalized: Number(row.score.toFixed(6)),
      semantic_cosine: Number(row.semantic.toFixed(6)),
      bm25: Number(row.bm25.toFixed(6)),
      graph_activation: Number(row.graph.toFixed(6)),
      temporal_interval: Number(row.temporal.toFixed(6)),
      selected_in_budget_window: selected.has(row.unit.u),
      token_count: row.tokens,
      entity_count: row.unit.entities.length,
    });
  }

  if (Array.isArray(states)) {
    for (const state of states) {
      if (!isRecord(state)) continue;
      const id = String(state.id ?? state.memory?.id ?? '').trim();
      if (!id || scoreById.has(id)) continue;
      scoreById.set(id, 0);
      diagnosticsById.set(id, {
        partition: 'invalid_or_out_of_bound',
        rrf_raw: 0,
        rrf_normalized: 0,
        semantic_cosine: 0,
        bm25: 0,
        graph_activation: 0,
        temporal_interval: 0,
        selected_in_budget_window: false,
        token_count: 0,
        entity_count: 0,
      });
    }
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
    channel_stats: {
      semantic: semanticScores.size,
      bm25: keywordScores.size,
      graph: [...graphScores.values()].filter((score) => score > 0).length,
      temporal: temporalScores.size,
      neural_cross_encoder: 0,
    },
    used_tokens: used,
    budget_tokens: budget,
    formula: 'RRF(f)=sum_R 1/(k+rank_R(f)); terminal_rank=RRF; output=sum |f_i| <= token_budget',
  };
}
