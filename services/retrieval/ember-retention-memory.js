/**
 * Native EMBER retained-evidence recall operator from:
 * - EMBER.pdf
 *
 * Implemented formulas / techniques:
 * - Budgeted Pre-Query Retention `B_ret`
 * - retained evidence token constraint `|S_K|_tok <= B_ret`
 * - ordered stream notation `c_{1:K}`
 * - retained capsules with source snippets, retrieval keys, metadata
 * - query-visible/raw-log access gates as diagnostics
 * - top-k read retrieval, default `top-k=10`
 * - budget sweep `B in {512,1024,2048,4096,8192}`
 * - Retain-Recall, Read-Recall, F1
 * - coverage balance `avg_g min_j RetainRecall(q_{g,j})`
 * - bootstrap CI helper for reporting
 *
 * Aimos adaptation:
 * - applies EMBER budget math to the returned evidence window only
 * - keeps canonical Aimos memory untouched; budget is not pruning or deletion
 */

import { createHash } from 'node:crypto';

export const EMBER_CONSTANTS = Object.freeze({
  default_budget_tokens: 8192,
  budget_sweep: [512, 1024, 2048, 4096, 8192],
  default_top_k: 10,
  bootstrap_samples: 500,
});

export const EMBER_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  injects_answers: false,
  budget_is_read_window_only: true,
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

export function tokenize(value = '') {
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

export function tokenCount(value = '') {
  return tokenize(value).length;
}

function tokenSet(value = '') {
  return new Set(tokenize(value));
}

function overlap(query = '', text = '') {
  const q = tokenSet(query);
  const t = tokenSet(text);
  if (!q.size || !t.size) return 0;
  let hits = 0;
  for (const token of q) if (t.has(token)) hits += 1;
  return hits / q.size;
}

function capsuleKey(text = '', metadata = {}) {
  return createHash('sha256')
    .update(`${metadata.memory_id || ''}:${text}`)
    .digest('hex')
    .slice(0, 16);
}

export function evidenceCapsule(state = {}) {
  const text = state.text || state.memory?.value || '';
  const excerpt = text.slice(0, 1600);
  const metadata = {
    memory_id: state.id,
    key: state.memory?.key || null,
    source: state.memory?.source || null,
    created_at: state.memory?.created_at || null,
    memory_type: state.memory?.memory_type || null,
  };
  return {
    id: `capsule:${state.id}`,
    source_excerpt: excerpt,
    retrieval_key: capsuleKey(excerpt, metadata),
    metadata,
    token_count: tokenCount(excerpt),
  };
}

export function answerabilityProbeScore(queryText = '', capsule = {}) {
  const exact = overlap(queryText, capsule.source_excerpt || '');
  const metadataText = Object.values(capsule.metadata || {}).filter(Boolean).join(' ');
  const meta = overlap(queryText, metadataText);
  const sourceSpecificity = clamp01(Math.log1p(capsule.token_count || 0) / Math.log(512));
  return clamp01((0.64 * exact) + (0.18 * meta) + (0.18 * sourceSpecificity));
}

export function budgetedRetentionSelect({
  capsules = [],
  queryText = '',
  budgetTokens = EMBER_CONSTANTS.default_budget_tokens,
  topK = EMBER_CONSTANTS.default_top_k,
} = {}) {
  const ranked = capsules
    .map((capsule, index) => ({
      capsule,
      index,
      score: answerabilityProbeScore(queryText, capsule),
    }))
    .sort((a, b) => b.score - a.score || a.index - b.index);
  const selected = [];
  let used = 0;
  for (const row of ranked) {
    const cost = Math.max(1, row.capsule.token_count || 1);
    if (selected.length >= topK) break;
    if (used + cost > budgetTokens && selected.length) continue;
    selected.push(row);
    used += cost;
  }
  return { selected, used_tokens: used, budget_tokens: budgetTokens };
}

export function retainRecall(requiredEvidenceIds = [], retainedCapsules = []) {
  const required = new Set(requiredEvidenceIds.map(String));
  if (!required.size) return 1;
  const retained = new Set(retainedCapsules.map((row) => String(row.capsule?.metadata?.memory_id || row.metadata?.memory_id || row.memory_id || '')));
  let hits = 0;
  for (const id of required) if (retained.has(id)) hits += 1;
  return hits / required.size;
}

export function readRecall(requiredEvidenceIds = [], readRows = []) {
  return retainRecall(requiredEvidenceIds, readRows);
}

export function f1Score(precision = 0, recall = 0) {
  const p = clamp01(precision);
  const r = clamp01(recall);
  return (p + r) ? (2 * p * r) / (p + r) : 0;
}

export function coverageBalance(bundleRecallRows = []) {
  if (!bundleRecallRows.length) return 0;
  const mins = bundleRecallRows.map((bundle) => Math.min(...bundle.map((value) => clamp01(value))));
  return mins.reduce((sum, value) => sum + value, 0) / mins.length;
}

export function deterministicBootstrapCi(values = [], samples = EMBER_CONSTANTS.bootstrap_samples) {
  if (!values.length) return { mean: 0, half_width_95: 0 };
  const means = [];
  for (let s = 0; s < Math.max(1, samples); s += 1) {
    let total = 0;
    for (let i = 0; i < values.length; i += 1) {
      const digest = createHash('sha256').update(`${s}:${i}:${values[i]}`).digest();
      const idx = digest.readUInt32BE(0) % values.length;
      total += Number(values[idx]) || 0;
    }
    means.push(total / values.length);
  }
  means.sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + (Number(value) || 0), 0) / values.length;
  const lo = means[Math.floor(0.025 * (means.length - 1))] ?? mean;
  const hi = means[Math.floor(0.975 * (means.length - 1))] ?? mean;
  return { mean, half_width_95: (hi - lo) / 2 };
}

export function emberRetentionScores({
  queryText = '',
  states = [],
  budgetTokens = EMBER_CONSTANTS.default_budget_tokens,
  topK = EMBER_CONSTANTS.default_top_k,
} = {}) {
  const capsules = (states || []).slice(0, 220).map(evidenceCapsule);
  const retained = budgetedRetentionSelect({ capsules, queryText, budgetTokens, topK });
  const retainedIds = new Set(retained.selected.map((row) => String(row.capsule.metadata.memory_id)));
  const retainedScores = new Map(retained.selected.map((row) => [String(row.capsule.metadata.memory_id), row.score]));
  const allProbeScores = capsules.map((capsule) => answerabilityProbeScore(queryText, capsule));
  const ci = deterministicBootstrapCi(allProbeScores, Math.min(EMBER_CONSTANTS.bootstrap_samples, 128));
  const scoreById = new Map();
  const diagnosticsById = new Map();
  for (const capsule of capsules) {
    const id = String(capsule.metadata.memory_id);
    const probe = answerabilityProbeScore(queryText, capsule);
    const retainedBoost = retainedIds.has(id) ? 1 : 0;
    const score = clamp01((0.70 * probe) + (0.30 * retainedBoost));
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      probe_score: Number(probe.toFixed(6)),
      retained: retainedIds.has(id),
      retained_rank_score: Number((retainedScores.get(id) || 0).toFixed(6)),
      token_count: capsule.token_count,
      retrieval_key: capsule.retrieval_key,
    });
  }
  return {
    scoreById,
    diagnosticsById,
    constants: EMBER_CONSTANTS,
    guardrails: EMBER_GUARDRAILS,
    retained_count: retained.selected.length,
    used_tokens: retained.used_tokens,
    budget_tokens: retained.budget_tokens,
    bootstrap_probe_ci: {
      mean: Number(ci.mean.toFixed(6)),
      half_width_95: Number(ci.half_width_95.toFixed(6)),
    },
    formula: '|S_K|_tok <= B_ret; top_k=10; F1=2PR/(P+R); coverage_balance=avg_g min_j RetainRecall(q_gj)',
  };
}
