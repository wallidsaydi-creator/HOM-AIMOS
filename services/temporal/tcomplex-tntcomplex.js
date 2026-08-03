/**
 * Native temporal KG tensor operator from:
 * - TComplEx : TNTComplEx.pdf
 *
 * Implemented formulas / techniques:
 * - CP decomposition: X = [[U,V,W]]
 * - ComplEx conjugate object factor
 * - TComplEx: Re([[U, V, conjugate(U), T]])
 * - TNTComplEx: temporal branch + non-temporal branch
 * - multiclass loss: -x_gold + log(sum exp(x_k))
 * - regularized empirical objective
 * - temporal smoothness penalty
 * - reciprocal relation augmentation
 *
 * Aimos adaptation:
 * - deterministic feature-hash embeddings; no training/fine-tuning at recall time
 * - produces bounded temporal-KG rank evidence only
 * - no pruning, deletion, decay, suppression, or canonical memory mutation
 */

import { createHash } from 'node:crypto';

const DEFAULT_DIM = 16;

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function sigmoid(value) {
  const x = Math.max(-40, Math.min(40, Number(value) || 0));
  return 1 / (1 + Math.exp(-x));
}

function tokenize(text = '') {
  return String(text || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}\s-]/gu, ' ')
    .split(/\s+/)
    .filter((token) => token.length >= 3);
}

function overlap(a = '', b = '') {
  const left = new Set(tokenize(a));
  const right = new Set(tokenize(b));
  if (!left.size || !right.size) return 0;
  let hit = 0;
  for (const token of left) {
    if (right.has(token)) hit += 1;
  }
  return clamp01(hit / Math.sqrt(left.size * right.size));
}

function unitFromHash(label, index, part) {
  const digest = createHash('sha256').update(`${part}:${index}:${label}`).digest();
  const raw = digest.readUInt32BE(0) / 0xffffffff;
  return (raw * 2) - 1;
}

export function hashedComplexEmbedding(label = '', dim = DEFAULT_DIM, namespace = 'tcomplex') {
  const key = `${namespace}:${String(label || '').toLowerCase()}`;
  return Array.from({ length: dim }, (_, index) => ({
    re: unitFromHash(key, index, 're'),
    im: unitFromHash(key, index, 'im'),
  }));
}

export function complexConjugate(value = { re: 0, im: 0 }) {
  return { re: Number(value.re) || 0, im: -(Number(value.im) || 0) };
}

export function complexMultiply(left = { re: 0, im: 0 }, right = { re: 0, im: 0 }) {
  const a = Number(left.re) || 0;
  const b = Number(left.im) || 0;
  const c = Number(right.re) || 0;
  const d = Number(right.im) || 0;
  return { re: (a * c) - (b * d), im: (a * d) + (b * c) };
}

function complexProductReal(factors = []) {
  const product = factors.reduce((acc, value) => complexMultiply(acc, value), { re: 1, im: 0 });
  return product.re;
}

export function canonicalPolyadicScore(subject, predicate, object, options = {}) {
  const dim = options.dim || DEFAULT_DIM;
  const s = hashedComplexEmbedding(subject, dim, 'cp:subject');
  const p = hashedComplexEmbedding(predicate, dim, 'cp:predicate');
  const o = hashedComplexEmbedding(object, dim, 'cp:object');
  let score = 0;
  for (let i = 0; i < dim; i += 1) {
    score += complexProductReal([s[i], p[i], o[i]]);
  }
  return score / Math.sqrt(dim);
}

export function tcomplexScore({ subject = '', predicate = '', object = '', timestamp = '', dim = DEFAULT_DIM } = {}) {
  const s = hashedComplexEmbedding(subject, dim, 'entity');
  const p = hashedComplexEmbedding(predicate, dim, 'relation');
  const o = hashedComplexEmbedding(object, dim, 'entity').map(complexConjugate);
  const t = hashedComplexEmbedding(timestamp || 'atemporal', dim, 'time');
  let score = 0;
  for (let i = 0; i < dim; i += 1) {
    score += complexProductReal([s[i], p[i], o[i], t[i]]);
  }
  return score / Math.sqrt(dim);
}

export function tntcomplexScore({
  subject = '',
  predicate = '',
  object = '',
  timestamp = '',
  dim = DEFAULT_DIM,
  temporalWeight = 0.65,
} = {}) {
  const temporal = tcomplexScore({ subject, predicate, object, timestamp, dim });
  const nonTemporal = canonicalPolyadicScore(subject, `${predicate}:non_temporal`, object, { dim });
  const w = clamp01(temporalWeight);
  return {
    raw: (w * temporal) + ((1 - w) * nonTemporal),
    temporal,
    non_temporal: nonTemporal,
    temporal_weight: w,
  };
}

export function reciprocalTemporalFacts(facts = []) {
  const augmented = [];
  for (const fact of facts || []) {
    augmented.push(fact);
    augmented.push({
      ...fact,
      subject: fact.object,
      object: fact.subject,
      predicate: `${fact.predicate || 'related'}:reciprocal`,
      reciprocal_of: fact,
    });
  }
  return augmented;
}

export function multiclassObjectLoss(goldScore = 0, alternativeScores = []) {
  const scores = [Number(goldScore) || 0, ...alternativeScores.map((value) => Number(value) || 0)];
  const max = Math.max(...scores);
  const logSumExp = max + Math.log(scores.reduce((sum, score) => sum + Math.exp(score - max), 0));
  return -(Number(goldScore) || 0) + logSumExp;
}

export function temporalSmoothnessPenalty(embeddings = []) {
  if (!Array.isArray(embeddings) || embeddings.length < 2) return 0;
  let penalty = 0;
  let count = 0;
  for (let i = 0; i + 1 < embeddings.length; i += 1) {
    const left = embeddings[i] || [];
    const right = embeddings[i + 1] || [];
    const len = Math.min(left.length, right.length);
    for (let j = 0; j < len; j += 1) {
      const dre = (Number(right[j]?.re) || 0) - (Number(left[j]?.re) || 0);
      const dim = (Number(right[j]?.im) || 0) - (Number(left[j]?.im) || 0);
      penalty += (dre * dre) + (dim * dim);
      count += 1;
    }
  }
  return count ? penalty / count : 0;
}

export function regularizedObjective(losses = [], regularizer = 0, lambda = 0.01) {
  const empirical = losses.length
    ? losses.reduce((sum, loss) => sum + (Number(loss) || 0), 0) / losses.length
    : 0;
  return empirical + ((Number(lambda) || 0) * (Number(regularizer) || 0));
}

export function parameterCountTComplEx({ rank = DEFAULT_DIM, entities = 0, timestamps = 0, predicates = 0 } = {}) {
  return 2 * rank * (entities + timestamps + (2 * predicates));
}

export function parameterCountTNTComplEx({ rank = DEFAULT_DIM, entities = 0, timestamps = 0, predicates = 0 } = {}) {
  return 2 * rank * (entities + timestamps + (4 * predicates));
}

function factTimestamp(fact = {}, fallback = new Date()) {
  const source = fact.timestamp || fact.time || fact.startDate || fact.start_time || fact.created_at || fallback;
  const parsed = Date.parse(source || '');
  if (!Number.isFinite(parsed)) return 'atemporal';
  return new Date(parsed).toISOString().slice(0, 10);
}

function factText(fact = {}) {
  return [fact.subject, fact.predicate, fact.object, fact.key, fact.text, fact.value]
    .filter(Boolean)
    .join(' ');
}

export function scoreTemporalKgFacts({
  queryText = '',
  facts = [],
  states = [],
  referenceDate = new Date(),
  dim = DEFAULT_DIM,
} = {}) {
  const scoreById = new Map();
  const detailsById = new Map();
  const byId = new Map((states || []).map((state) => [String(state.id), state]));
  const augmented = reciprocalTemporalFacts(facts);

  for (const fact of augmented) {
    const memoryId = String(fact.qualifiers?.memory_id || fact.memory_id || fact.id || '');
    const state = byId.get(memoryId) || byId.get(String(fact.object || '')) || null;
    const targetId = state ? String(state.id) : memoryId;
    if (!targetId) continue;
    const timestamp = factTimestamp(fact, referenceDate);
    const model = tntcomplexScore({
      subject: fact.subject || 'memory',
      predicate: fact.predicate || 'mentions',
      object: fact.object || targetId,
      timestamp,
      dim,
    });
    const body = state?.text || factText(fact);
    const lexical = overlap(queryText, body);
    const tensorScore = sigmoid(model.raw);
    const score = clamp01((tensorScore * 0.54) + (lexical * 0.46));
    const previous = scoreById.get(targetId) || 0;
    if (score >= previous) {
      scoreById.set(targetId, score);
      detailsById.set(targetId, {
        temporal: Number(model.temporal.toFixed(6)),
        non_temporal: Number(model.non_temporal.toFixed(6)),
        raw: Number(model.raw.toFixed(6)),
        tensor_score: Number(tensorScore.toFixed(6)),
        lexical: Number(lexical.toFixed(6)),
        timestamp,
        reciprocal: Boolean(fact.reciprocal_of),
      });
    }
  }

  const timeEmbeddings = [...new Set(augmented.map((fact) => factTimestamp(fact, referenceDate)))]
    .sort()
    .map((timestamp) => hashedComplexEmbedding(timestamp, dim, 'time'));
  return {
    scoreById,
    detailsById,
    fact_count: facts.length,
    augmented_fact_count: augmented.length,
    temporal_smoothness_penalty: temporalSmoothnessPenalty(timeEmbeddings),
    formula: 'TNTComplEx = temporal Re([[U,V,conj(U),T]]) + non-temporal CP branch',
  };
}
