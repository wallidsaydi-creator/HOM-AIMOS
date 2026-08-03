/**
 * Native explainable temporal KG reasoning operator from:
 * - xERTE- Explainable Reasoning on Temporal Knowledge Graphs.pdf
 *
 * Implemented formulas / techniques:
 * - temporal quadruple `(s, p, o, t)` and query `(eq, pq, ?, tq)`
 * - reciprocal relation augmentation `(eo, p^-1, es, t)`
 * - prior-neighbor filtering with `t0 < tq`
 * - time-aware exponential and linear sampling weights
 * - sinusoidal time encoding `Phi(t)`
 * - entity-time embedding `[e_i || Phi(t)]`
 * - TRGA-style edge attention, softmax, segment sum, segment softmax
 * - attention propagation, contribution score `c_vu = alpha_vu * a_v`
 * - reverse representation update iteration count `(1+L)L/2`
 * - entity attention aggregation and MRR / Hits@k metrics
 *
 * Aimos adaptation:
 * - builds an explainable bounded inference graph over returned evidence
 * - no graph pruning of canonical memory; retained edges are diagnostic only
 * - no deletion, decay, answer injection, or model training
 */

import { createHash } from 'node:crypto';

export const XERTE_GUARDRAILS = Object.freeze({
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
  return normalizeText(value).split(/\s+/).filter((token) => token.length >= 2);
}

function lexicalSimilarity(left = '', right = '') {
  const l = new Set(tokens(left));
  const r = new Set(tokens(right));
  if (!l.size || !r.size) return 0;
  let hit = 0;
  for (const token of l) if (r.has(token)) hit += 1;
  return clamp01(hit / Math.sqrt(l.size * r.size));
}

function hashUnit(label, index = 0) {
  const digest = createHash('sha256').update(`${label}:${index}`).digest();
  return ((digest.readUInt32BE(0) / 0xffffffff) * 2) - 1;
}

function dot(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let out = 0;
  for (let i = 0; i < n; i += 1) out += (Number(left[i]) || 0) * (Number(right[i]) || 0);
  return out;
}

function norm(vector = []) {
  return Math.sqrt(dot(vector, vector));
}

function cosine(left = [], right = []) {
  const denom = norm(left) * norm(right);
  return denom > 0 ? dot(left, right) / denom : 0;
}

export function leakyRelu(value, alpha = 0.01) {
  const n = Number(value) || 0;
  return n >= 0 ? n : alpha * n;
}

export function softmax(values = []) {
  if (!values.length) return [];
  const max = Math.max(...values.map((value) => Number(value) || 0));
  const exps = values.map((value) => Math.exp((Number(value) || 0) - max));
  const denom = exps.reduce((sum, value) => sum + value, 0) || 1;
  return exps.map((value) => value / denom);
}

export function segmentSum(values = [], segments = []) {
  const out = new Map();
  for (let i = 0; i < values.length; i += 1) {
    const key = String(segments[i] ?? 0);
    out.set(key, (out.get(key) || 0) + (Number(values[i]) || 0));
  }
  return out;
}

export function segmentSoftmax(values = [], segments = []) {
  const grouped = new Map();
  for (let i = 0; i < values.length; i += 1) {
    const key = String(segments[i] ?? 0);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push({ index: i, value: Number(values[i]) || 0 });
  }
  const out = Array(values.length).fill(0);
  for (const rows of grouped.values()) {
    const probs = softmax(rows.map((row) => row.value));
    rows.forEach((row, index) => { out[row.index] = probs[index]; });
  }
  return out;
}

function timeMs(value, fallback = 0) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function makeTemporalQuadruple({ subject = '', predicate = '', object = '', timestamp = '', qualifiers = {} } = {}) {
  return { subject: String(subject), predicate: String(predicate), object: String(object), timestamp: String(timestamp || ''), qualifiers };
}

export function reciprocalQuadruples(quadruples = []) {
  const out = [];
  for (const q of quadruples || []) {
    out.push(q);
    out.push(makeTemporalQuadruple({
      subject: q.object,
      predicate: `${q.predicate}:inverse`,
      object: q.subject,
      timestamp: q.timestamp,
      qualifiers: { ...q.qualifiers, reciprocal_of: q },
    }));
  }
  return out;
}

export function priorNeighbors(quadruples = [], node = {}, queryTime = new Date(), direction = 'forward') {
  const tq = timeMs(queryTime, Date.now());
  const entity = String(node.entity || node.subject || '');
  return (quadruples || []).filter((q) => {
    const t0 = timeMs(q.timestamp, -Infinity);
    if (direction === 'reverse') return q.object === entity && t0 < tq;
    return q.subject === entity && t0 < tq;
  });
}

export function timeAwareSamplingWeights(edges = [], queryTime = new Date(), mode = 'exponential') {
  const tq = timeMs(queryTime, Date.now());
  const raw = edges.map((edge) => {
    const dtDays = Math.max(0, (tq - timeMs(edge.timestamp, tq)) / 86400000);
    if (mode === 'linear') return 1 / (1 + dtDays);
    return Math.exp(-Math.min(60, dtDays / 30));
  });
  const denom = raw.reduce((sum, value) => sum + value, 0) || 1;
  return raw.map((value) => value / denom);
}

export function sinusoidalTimeEncoding(time = '', dim = 8) {
  const t = timeMs(time, 0) / 86400000;
  return Array.from({ length: dim }, (_, index) => {
    const omega = 1 / (10000 ** (index / Math.max(1, dim)));
    const phi = hashUnit('xerte:phi', index) * Math.PI;
    return Math.cos((omega * t) + phi);
  });
}

export function entityTimeEmbedding(entity = '', time = '', { staticDim = 16, timeDim = 8 } = {}) {
  const stat = Array.from({ length: staticDim }, (_, index) => hashUnit(`xerte:entity:${normalizeText(entity)}`, index));
  return [...stat, ...sinusoidalTimeEncoding(time, timeDim)];
}

export function edgeAttentionScore(query = {}, edge = {}) {
  const qText = [query.subject || query.eq, query.predicate || query.pq].filter(Boolean).join(' ');
  const edgeText = [edge.subject, edge.predicate, edge.object].join(' ');
  const lexical = lexicalSimilarity(qText, edgeText);
  const qEmb = entityTimeEmbedding(query.subject || query.eq || qText, query.timestamp || query.tq || '');
  const sEmb = entityTimeEmbedding(edge.subject, edge.timestamp);
  const oEmb = entityTimeEmbedding(edge.object, edge.timestamp);
  return leakyRelu((lexical * 1.5) + (cosine(qEmb, sEmb) * 0.35) + (cosine(qEmb, oEmb) * 0.15));
}

export function buildXerteInferenceGraph({
  query = {},
  quadruples = [],
  steps = 3,
  edgeBudget = 32,
} = {}) {
  const all = reciprocalQuadruples(quadruples);
  const queryTime = query.timestamp || query.tq || new Date();
  const seed = String(query.subject || query.eq || '');
  const nodes = new Map([[`${seed}@${queryTime}`, { entity: seed, timestamp: String(queryTime), attention: 1 }]]);
  const edges = [];
  let frontier = [{ entity: seed, timestamp: String(queryTime), attention: 1 }];

  for (let step = 0; step < Math.max(1, steps); step += 1) {
    const candidates = [];
    for (const node of frontier) {
      for (const edge of priorNeighbors(all, node, queryTime)) {
        const raw = edgeAttentionScore(query, edge);
        candidates.push({ ...edge, from: node.entity, to: edge.object, raw_attention: raw, source_attention: node.attention, step });
      }
    }
    const probs = softmax(candidates.map((edge) => edge.raw_attention));
    const ranked = candidates.map((edge, index) => ({
      ...edge,
      alpha: probs[index] || 0,
      contribution: (probs[index] || 0) * (edge.source_attention || 0),
    })).sort((a, b) => b.contribution - a.contribution);
    const retained = ranked.slice(0, edgeBudget);
    edges.push(...retained);
    frontier = retained.map((edge) => {
      const key = `${edge.object}@${edge.timestamp}`;
      const current = nodes.get(key) || { entity: edge.object, timestamp: edge.timestamp, attention: 0 };
      current.attention += edge.contribution;
      nodes.set(key, current);
      return current;
    });
    if (!frontier.length) break;
  }

  const entityAttention = new Map();
  for (const node of nodes.values()) {
    entityAttention.set(node.entity, (entityAttention.get(node.entity) || 0) + node.attention);
  }
  return {
    nodes: [...nodes.values()],
    edges,
    entity_attention: [...entityAttention.entries()].map(([entity, attention]) => ({ entity, attention })),
    message_passing_iterations: ((1 + steps) * steps) / 2,
  };
}

export function binaryCrossEntropyFromAttention(attentionByEntity = [], goldEntity = '') {
  const total = attentionByEntity.reduce((sum, row) => sum + (Number(row.attention) || 0), 0) || 1;
  let loss = 0;
  for (const row of attentionByEntity) {
    const p = clamp01((Number(row.attention) || 0) / total);
    const y = row.entity === goldEntity ? 1 : 0;
    loss += -(y * Math.log(Math.max(1e-12, p)) + (1 - y) * Math.log(Math.max(1e-12, 1 - p)));
  }
  return attentionByEntity.length ? loss / attentionByEntity.length : 0;
}

export function mrr(ranks = []) {
  const rows = ranks.map(Number).filter((rank) => Number.isFinite(rank) && rank > 0);
  return rows.length ? rows.reduce((sum, rank) => sum + (1 / rank), 0) / rows.length : 0;
}

export function hitsAtK(ranks = [], k = 10) {
  const rows = ranks.map(Number).filter((rank) => Number.isFinite(rank) && rank > 0);
  return rows.length ? rows.filter((rank) => rank <= k).length / rows.length : 0;
}

export function xerteEvidenceScores({
  queryText = '',
  states = [],
  facts = [],
  referenceDate = new Date(),
} = {}) {
  const quadruples = facts.slice(0, 120).map((fact) => makeTemporalQuadruple({
    subject: fact.subject || fact.memory_id || 'memory',
    predicate: fact.predicate || 'mentions',
    object: fact.object || fact.key || fact.id || 'evidence',
    timestamp: fact.startDate || fact.start_time || fact.timestamp || referenceDate,
    qualifiers: fact.qualifiers || {},
  }));
  const query = {
    subject: queryText.split(/\s+/).find((token) => token.length > 3) || 'memory',
    predicate: 'mentions',
    timestamp: referenceDate,
  };
  const graph = buildXerteInferenceGraph({ query, quadruples, steps: 3, edgeBudget: 24 });
  const byMemory = new Map();
  for (const edge of graph.edges) {
    const memoryId = String(edge.qualifiers?.memory_id || edge.object || '');
    byMemory.set(memoryId, Math.max(byMemory.get(memoryId) || 0, clamp01(edge.contribution * 4)));
  }
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const textScore = lexicalSimilarity(queryText, state.text || '');
    const graphScore = byMemory.get(String(state.id)) || byMemory.get(String(state.memory?.key || '')) || 0;
    const score = clamp01((graphScore * 0.56) + (textScore * 0.44));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      graph_contribution: Number(graphScore.toFixed(6)),
      lexical: Number(textScore.toFixed(6)),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    graph,
    formula: 'TRGA attention over prior temporal neighbors with contribution c_vu = alpha_vu * a_v',
  };
}
