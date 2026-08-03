/**
 * Native Temporal Semantic Memory operator from:
 * - Beyond Dialogue Time- Temporal Semantic Memory for Personalized LLM Agents.pdf
 *
 * Implemented formulas / techniques:
 * - semantic timeline construction from event time rather than dialogue time
 * - temporal KG fact `G={(e_s,r,e_o,t)|t in T}`
 * - temporal slice `G^k={(e_s,r,e_o,t)|t in [tau_k,tau_{k+1})}`
 * - entity set per slice `E(k)={e | e appears in G(k)}`
 * - deterministic GMM-like posterior `p(z|e)` and assignment `argmax_z p(z|e)`
 * - cluster member set `E_z`, summary input set `X_z`, topic tuple `{tau_k,s_z,c_z}`
 * - mention mapping `D_z={d | d mentions e, e in E_z}`
 * - semantic score `s_sem(m;q)=sim(Enc(q),Enc(m))`
 * - top-k semantic candidates with temporal intent and duration alignment
 *
 * Aimos adaptation:
 * - uses existing recalled memories as temporal facts and durative semantic topics
 * - produces bounded recall signals and diagnostics only
 * - no canonical memory pruning, decay, deletion, or answer injection
 */

import { createHash } from 'node:crypto';

export const TSM_CONSTANTS = Object.freeze({
  top_k: 25,
  cluster_count: 8,
  day_ms: 86_400_000,
});

export const TSM_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
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
    .replace(/[^\p{L}\p{N}\s-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(value = '') {
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

function dayKey(dateLike) {
  const date = new Date(dateLike || Date.now());
  if (Number.isNaN(date.getTime())) return new Date(0).toISOString().slice(0, 10);
  return date.toISOString().slice(0, 10);
}

function hashBucket(value = '', buckets = TSM_CONSTANTS.cluster_count) {
  const digest = createHash('sha256').update(String(value || '')).digest();
  return digest.readUInt32BE(0) % Math.max(1, buckets);
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

export function temporalKgFactsFromStates(states = []) {
  return (states || []).map((state) => ({
    subject: state.memory?.source || state.memory?.memory_type || 'memory',
    relation: state.memory?.memory_type || 'mentions',
    object: state.memory?.key || state.id,
    time: dayKey(state.memory?.created_at),
    memory_id: state.id,
    text: state.text || state.memory?.value || '',
  }));
}

export function sliceTemporalKg(facts = [], { start = null, end = null } = {}) {
  const s = start ? Date.parse(start) : Number.NEGATIVE_INFINITY;
  const e = end ? Date.parse(end) : Number.POSITIVE_INFINITY;
  return facts.filter((fact) => {
    const t = Date.parse(fact.time);
    return Number.isFinite(t) && t >= s && t < e;
  });
}

export function entitySetForSlice(facts = []) {
  const entities = new Set();
  for (const fact of facts) {
    if (fact.subject) entities.add(String(fact.subject));
    if (fact.object) entities.add(String(fact.object));
  }
  return [...entities];
}

export function clusterPosterior(entity = '', clusters = TSM_CONSTANTS.cluster_count) {
  const base = hashBucket(entity, clusters);
  const scores = Array.from({ length: clusters }, (_, i) => 1 / (1 + Math.abs(i - base)));
  const total = scores.reduce((sum, value) => sum + value, 0) || 1;
  return scores.map((value) => value / total);
}

export function assignCluster(entity = '', clusters = TSM_CONSTANTS.cluster_count) {
  const posterior = clusterPosterior(entity, clusters);
  let best = 0;
  for (let i = 1; i < posterior.length; i += 1) if (posterior[i] > posterior[best]) best = i;
  return { cluster: best, posterior };
}

export function topicTuple({ slice = '', entities = [], facts = [] } = {}) {
  const summary = facts
    .slice(0, 5)
    .map((fact) => `${fact.subject} ${fact.relation} ${fact.object}`)
    .join('; ');
  return {
    tau: slice,
    sz: summary,
    cz: hashVector(summary || entities.join(' ')),
    entities,
    fact_count: facts.length,
  };
}

export function semanticScore(memoryText = '', queryText = '') {
  return (cosine(hashVector(memoryText), hashVector(queryText)) + 1) / 2;
}

export function detectTemporalIntent(queryText = '') {
  const q = normalizeText(queryText);
  return {
    asks_duration: /\b(duration|how long|for how many|between|days?|weeks?|months?|years?)\b/.test(q),
    asks_current: /\b(current|currently|now|latest|recent|last)\b/.test(q),
    asks_order: /\b(before|after|then|previous|next|first|last)\b/.test(q),
  };
}

export function constructDurativeMemories(facts = []) {
  const byCluster = new Map();
  for (const fact of facts) {
    const entity = fact.object || fact.subject || fact.memory_id;
    const { cluster } = assignCluster(entity);
    if (!byCluster.has(cluster)) byCluster.set(cluster, []);
    byCluster.get(cluster).push(fact);
  }
  return [...byCluster.entries()].map(([cluster, rows]) => {
    const times = rows.map((row) => Date.parse(row.time)).filter(Number.isFinite).sort((a, b) => a - b);
    return {
      cluster,
      start: times[0] ? new Date(times[0]).toISOString().slice(0, 10) : null,
      end: times.at(-1) ? new Date(times.at(-1)).toISOString().slice(0, 10) : null,
      topic: topicTuple({ slice: `cluster:${cluster}`, entities: entitySetForSlice(rows), facts: rows }),
      memory_ids: rows.map((row) => row.memory_id),
    };
  });
}

export function temporalSemanticMemoryScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
} = {}) {
  const facts = temporalKgFactsFromStates(states).slice(0, 200);
  const topics = constructDurativeMemories(facts);
  const intent = detectTemporalIntent(queryText);
  const refDay = Date.parse(dayKey(referenceDate));
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const state of (states || []).slice(0, 180)) {
    const text = state.text || state.memory?.value || '';
    const sem = semanticScore(text, queryText);
    const stateDay = Date.parse(dayKey(state.memory?.created_at));
    const ageDays = Number.isFinite(stateDay) ? Math.max(0, (refDay - stateDay) / TSM_CONSTANTS.day_ms) : 365;
    const currentBoost = intent.asks_current ? 1 / (1 + Math.log1p(ageDays)) : 0;
    const topic = topics.find((row) => row.memory_ids.includes(state.id));
    const topicSem = topic ? (cosine(topic.topic.cz, hashVector(queryText)) + 1) / 2 : 0;
    const durativeBoost = intent.asks_duration && topic?.start && topic?.end && topic.start !== topic.end ? 1 : 0;
    const score = clamp01((0.48 * sem) + (0.24 * topicSem) + (0.18 * currentBoost) + (0.10 * durativeBoost));
    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      semantic_score: Number(sem.toFixed(6)),
      topic_semantic_score: Number(topicSem.toFixed(6)),
      current_boost: Number(currentBoost.toFixed(6)),
      durative_boost: Number(durativeBoost.toFixed(6)),
      topic_cluster: topic?.cluster ?? null,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: TSM_CONSTANTS,
    guardrails: TSM_GUARDRAILS,
    topic_count: topics.length,
    temporal_intent: intent,
    formula: 'G={(es,r,eo,t)}; G^k={facts in [tau_k,tau_k+1)}; a(e)=argmax_z p(z|e); s_sem=sim(Enc(q),Enc(m)); TopK=25',
  };
}
