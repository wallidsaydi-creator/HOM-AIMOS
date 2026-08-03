/**
 * Native xMemory/Beyond-RAG recall operator from:
 * - Beyond RAG for Agent Memory.pdf
 *
 * Implemented formulas / techniques:
 * - decoupling before aggregation
 * - hierarchy: raw messages -> local segments -> memory components -> groups
 * - grouping objective `f(P)=SparsityScore(P)+SemScore(P)`
 * - sparsity `1/N^2 * sum_k n_k^2`
 * - semantic coherence
 *   `1/K sum_k 1/n_k sum_i cos(x_i,mu_k) * g(s_k)`
 * - inter-group geometry
 *   `g(s_k)=exp(-(s_k-sbar)^2/(2sigma^2))`
 * - nearest group assignment `argmax_k cos(x,mu_k)`
 * - top-down retrieval with coverage delta
 *   `C(R)={u | exists r in R, u in {r} union N(r)}`
 * - coverage-relevance objective
 *   `argmax_i sum_{u in Delta(i;R)} w_iu/Z + s(q,i)`
 * - Fano-style routing bound `H(Z|O)<=h(pe)+pe log2(n_k-1)`
 *
 * Aimos adaptation:
 * - builds transient recall hierarchy over candidate memories only
 * - never rewrites, splits, merges, deletes, prunes, or decays canonical memory
 */

import { createHash } from 'node:crypto';

export const XMEMORY_CONSTANTS = Object.freeze({
  component_cap: 256,
  group_count: 12,
  neighbor_k: 3,
  attach_threshold: 0.42,
});

export const XMEMORY_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  split_merge_is_diagnostic_only: true,
});

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function clamp01(value) {
  return clamp(value, 0, 1);
}

function normalizeText(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s.,;:!?-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(value = '') {
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

export function hashVector(text = '', dim = 48) {
  const vector = Array.from({ length: dim }, () => 0);
  for (const token of tokens(text)) {
    const digest = createHash('sha256').update(token).digest();
    const idx = digest.readUInt32BE(0) % dim;
    vector[idx] += digest[4] % 2 ? 1 : -1;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return vector.map((value) => value / norm);
}

export function cosine(left = [], right = []) {
  const n = Math.min(left.length, right.length);
  let dot = 0;
  let ln = 0;
  let rn = 0;
  for (let i = 0; i < n; i += 1) {
    const l = Number(left[i]) || 0;
    const r = Number(right[i]) || 0;
    dot += l * r;
    ln += l * l;
    rn += r * r;
  }
  return dot / ((Math.sqrt(ln) || 1) * (Math.sqrt(rn) || 1));
}

export function segmentInteractionHistory(states = []) {
  return (states || []).map((state, index) => ({
    id: `segment:${state.id}`,
    memory_id: state.id,
    order: index,
    text: state.text || state.memory?.value || '',
    timestamp: state.memory?.created_at || null,
  }));
}

export function decoupleSegmentComponents(segment = {}) {
  const text = normalizeText(segment.text || '');
  const parts = text
    .split(/(?<=[.!?;])\s+|\n+/)
    .map((part) => part.trim())
    .filter(Boolean);
  const chunks = parts.length ? parts : [text].filter(Boolean);
  return chunks.slice(0, 6).map((part, idx) => ({
    id: `${segment.id}:component:${idx}`,
    segment_id: segment.id,
    memory_id: segment.memory_id,
    text: part,
    embedding: hashVector(part),
  }));
}

export function centroid(vectors = []) {
  if (!vectors.length) return [];
  const dim = vectors[0].length;
  const out = Array.from({ length: dim }, () => 0);
  for (const vector of vectors) for (let i = 0; i < dim; i += 1) out[i] += Number(vector[i]) || 0;
  const avg = out.map((value) => value / vectors.length);
  const norm = Math.sqrt(avg.reduce((sum, value) => sum + (value * value), 0)) || 1;
  return avg.map((value) => value / norm);
}

export function groupComponents(components = [], groupCount = XMEMORY_CONSTANTS.group_count) {
  const groups = new Map();
  for (const component of components.slice(0, XMEMORY_CONSTANTS.component_cap)) {
    const digest = createHash('sha256').update(component.text || component.id).digest();
    const groupId = digest.readUInt32BE(0) % Math.max(1, groupCount);
    if (!groups.has(groupId)) groups.set(groupId, []);
    groups.get(groupId).push(component);
  }
  return [...groups.entries()].map(([id, members]) => ({
    id: `group:${id}`,
    members,
    centroid: centroid(members.map((member) => member.embedding)),
  }));
}

export function sparsityScore(groups = []) {
  const n = groups.reduce((sum, group) => sum + group.members.length, 0);
  if (!n) return 0;
  return groups.reduce((sum, group) => sum + (group.members.length ** 2), 0) / (n * n);
}

function median(values = []) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function interGroupGeometryWeight(sk = 0, allSk = []) {
  const center = median(allSk);
  const sigma = median(allSk.map((value) => Math.abs(value - center))) + 1e-9;
  return Math.exp(-(((sk - center) ** 2) / (2 * sigma * sigma)));
}

export function semanticCoherenceScore(groups = []) {
  if (!groups.length) return 0;
  const sks = groups.map((group) => Math.max(0, ...groups.filter((other) => other.id !== group.id).map((other) => cosine(group.centroid, other.centroid))));
  let total = 0;
  for (let k = 0; k < groups.length; k += 1) {
    const group = groups[k];
    const g = interGroupGeometryWeight(sks[k], sks);
    const memberAvg = group.members.length
      ? group.members.reduce((sum, member) => sum + cosine(member.embedding, group.centroid), 0) / group.members.length
      : 0;
    total += memberAvg * g;
  }
  return total / groups.length;
}

export function groupingObjective(groups = []) {
  return sparsityScore(groups) + semanticCoherenceScore(groups);
}

export function nearestGroup(component = {}, groups = []) {
  let best = null;
  let score = Number.NEGATIVE_INFINITY;
  for (const group of groups) {
    const s = cosine(component.embedding || [], group.centroid || []);
    if (s > score) {
      best = group;
      score = s;
    }
  }
  return { group: best, score };
}

export function buildGroupNeighbors(groups = [], k = XMEMORY_CONSTANTS.neighbor_k) {
  const out = new Map();
  for (const group of groups) {
    const neighbors = groups
      .filter((other) => other.id !== group.id)
      .map((other) => ({ id: other.id, weight: (cosine(group.centroid, other.centroid) + 1) / 2 }))
      .sort((a, b) => b.weight - a.weight)
      .slice(0, k);
    out.set(group.id, neighbors);
  }
  return out;
}

export function coverageSet(selected = [], neighbors = new Map()) {
  const covered = new Set();
  for (const id of selected) {
    covered.add(id);
    for (const edge of neighbors.get(id) || []) covered.add(edge.id);
  }
  return covered;
}

export function coverageDelta(candidateId, selected = [], neighbors = new Map()) {
  const before = coverageSet(selected, neighbors);
  const after = coverageSet([...selected, candidateId], neighbors);
  return [...after].filter((id) => !before.has(id));
}

export function binaryEntropy(p = 0) {
  const x = clamp01(p);
  if (x === 0 || x === 1) return 0;
  return -(x * Math.log2(x)) - ((1 - x) * Math.log2(1 - x));
}

export function fanoBound({ errorProbability = 0, classCount = 2 } = {}) {
  const pe = clamp01(errorProbability);
  const nk = Math.max(2, Number(classCount) || 2);
  return binaryEntropy(pe) + (pe * Math.log2(nk - 1));
}

export function xmemoryScores({
  queryText = '',
  states = [],
} = {}) {
  const segments = segmentInteractionHistory(states);
  const components = segments.flatMap((segment) => decoupleSegmentComponents(segment));
  const groups = groupComponents(components);
  const neighbors = buildGroupNeighbors(groups);
  const query = hashVector(queryText);
  const groupRelevance = groups.map((group) => ({
    group,
    score: (cosine(query, group.centroid) + 1) / 2,
    coverage: coverageDelta(group.id, [], neighbors).length,
  }));
  const z = Math.max(1, Math.max(...groupRelevance.map((row) => row.coverage), 1));
  const groupScore = new Map(groupRelevance.map((row) => [row.group.id, clamp01(row.score + (row.coverage / z) * 0.15)]));
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of states || []) {
    const owned = components.filter((component) => component.memory_id === state.id);
    const componentScore = owned.length
      ? Math.max(...owned.map((component) => (cosine(query, component.embedding) + 1) / 2))
      : 0;
    const nearest = owned.length ? nearestGroup(owned[0], groups) : { group: null, score: 0 };
    const high = nearest.group ? groupScore.get(nearest.group.id) || 0 : 0;
    const score = clamp01((0.58 * componentScore) + (0.30 * high) + (0.12 * clamp01(groupingObjective(groups) / 2)));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      component_count: owned.length,
      component_score: Number(componentScore.toFixed(6)),
      group_id: nearest.group?.id || null,
      group_similarity: Number((nearest.score || 0).toFixed(6)),
      group_score: Number(high.toFixed(6)),
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: XMEMORY_CONSTANTS,
    guardrails: XMEMORY_GUARDRAILS,
    hierarchy: {
      segment_count: segments.length,
      component_count: components.length,
      group_count: groups.length,
      grouping_objective: Number(groupingObjective(groups).toFixed(6)),
      fano_bound_pe_0_1: Number(fanoBound({ errorProbability: 0.1, classCount: Math.max(2, groups.length) }).toFixed(6)),
    },
    formula: 'f(P)=Sparsity(P)+Sem(P); C(R)={u in {r} union N(r)}; argmax_i sum Delta(i;R)/Z+s(q,i)',
  };
}
