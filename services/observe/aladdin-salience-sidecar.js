/**
 * aladdin-salience-sidecar.js — retrieval salience feature sidecar
 *
 * Status: diagnostic-only. This computes a retrieval-time feature and a
 * signable sidecar payload. It never edits canonical memory, never applies
 * decay, never prunes, and never suppresses recall eligibility.
 *
 * Formula:
 *   B_i = ln(min(C, sum_j(t_j^-d) + prior_i))
 *
 * Where:
 * - t_j is age in days since an observed access event.
 * - d is a retrieval-time frequency exponent, not storage decay.
 * - prior_i is a cold-start / sparse-history importance prior.
 * - C caps rich-get-richer feedback loops.
 *
 * Deep recall rule:
 * exact/identifier/specific semantic override => salience_penalty = 0.
 */

import { createHash } from 'node:crypto';

const DEFAULTS = Object.freeze({
  exponent_d: 0.5,
  min_age_days: 1 / 24,
  max_activation_sum: 20,
  cold_start_base_prior: 0.18,
  max_prior: 1.25,
});

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function finiteNumber(value, fallback = null) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value, min = 0, max = 1) {
  const n = finiteNumber(value, min);
  return Math.max(min, Math.min(max, n));
}

function round(value, fallback = null) {
  const n = finiteNumber(value, null);
  return n == null ? fallback : Number(n.toFixed(6));
}

function sigmoid(value) {
  const z = Math.max(-40, Math.min(40, finiteNumber(value, 0)));
  return 1 / (1 + Math.exp(-z));
}

function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (t === 'object' && value) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return 'null';
}

function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function parseTime(value) {
  const ms = Date.parse(value || '');
  return Number.isFinite(ms) ? ms : null;
}

function accessAgesDays(memory = {}, nowMs = Date.now(), minAgeDays = DEFAULTS.min_age_days) {
  const explicitEvents = [
    ...asArray(memory.access_events),
    ...asArray(memory.retrieval_access_events),
    ...asArray(memory.access_timestamps),
  ];
  const ages = explicitEvents
    .map((event) => parseTime(event?.ts || event?.timestamp || event?.accessed_at || event))
    .filter((ms) => ms != null)
    .map((ms) => Math.max(minAgeDays, (nowMs - ms) / 864e5))
    .filter(Number.isFinite);

  if (ages.length) {
    return { ages, quality: 'event_timestamps', summarized_access_count: 0 };
  }

  const lastAccess = parseTime(memory.retrieval_last_accessed_at || memory.last_accessed_at);
  const accessCount = Math.max(0, finiteNumber(memory.retrieval_access_count, finiteNumber(memory.access_count, 0)) || 0);
  if (lastAccess != null) {
    return {
      ages: [Math.max(minAgeDays, (nowMs - lastAccess) / 864e5)],
      quality: accessCount > 1 ? 'last_access_plus_count_summary' : 'last_access_only',
      summarized_access_count: Math.max(0, accessCount - 1),
    };
  }

  return { ages: [], quality: 'cold_start', summarized_access_count: accessCount };
}

function importancePrior(memory = {}, summarizedAccessCount = 0, options = DEFAULTS) {
  const creditRaw = finiteNumber(memory.credit_score, null);
  const credit = creditRaw == null ? 0 : clamp(creditRaw > 1 ? creditRaw / 2 : creditRaw, 0, 1);
  const rpe = clamp(memory.rpe_score ?? memory.rpe ?? 0, 0, 1);
  const surprise = clamp(memory.surprise_score ?? memory.surprise ?? 0, 0, 1);
  const confidenceAuthority = clamp(memory.confidence?.components?.authority ?? 0, 0, 1);
  const tierPrior = String(memory.memory_tier || memory.medallion || '').toLowerCase() === 'gold'
    ? 0.28
    : String(memory.memory_tier || memory.medallion || '').toLowerCase() === 'silver'
      ? 0.16
      : 0;
  const summaryPrior = Math.min(0.35, Math.log1p(Math.max(0, summarizedAccessCount)) / 10);
  return Math.min(
    options.max_prior,
    options.cold_start_base_prior
      + (0.32 * credit)
      + (0.18 * rpe)
      + (0.14 * surprise)
      + (0.12 * confidenceAuthority)
      + tierPrior
      + summaryPrior
  );
}

export function buildAladdinSalienceSidecar(memory = {}, {
  nowMs = Date.now(),
  exponentD = DEFAULTS.exponent_d,
  signer = null,
} = {}) {
  const options = DEFAULTS;
  const deepOverride = memory.deep_recall_override?.applied === true
    || memory.deep_recall_rank_eligible === true;
  const { ages, quality, summarized_access_count: summarizedAccessCount } = accessAgesDays(memory, nowMs, options.min_age_days);
  const accessSum = ages.reduce((sum, age) => sum + (age ** (-exponentD)), 0);
  const prior = importancePrior(memory, summarizedAccessCount, options);
  const cappedSum = Math.min(options.max_activation_sum, Math.max(1e-9, accessSum + prior));
  const b = Math.log(cappedSum);
  const payload = {
    sidecar_type: 'aladdin_retrieval_salience',
    version: 'salience-sidecar-v1',
    memory_id: memory.id || memory.memory_id || null,
    key: memory.key || null,
    memory_type: memory.memory_type || null,
    formula: 'B_i=ln(min(C, sum_j(t_j^-d)+prior_i))',
    exponent_d: exponentD,
    access_event_count: ages.length,
    summarized_access_count: summarizedAccessCount,
    history_quality: quality,
    access_activation_sum: round(accessSum, 0),
    cold_start_importance_prior: round(prior, 0),
    saturation_cap: options.max_activation_sum,
    B_i: round(b, 0),
    ranker_salience_feature: round(sigmoid(b), 0),
    salience_penalty: deepOverride ? 0 : null,
    deep_recall_override_applied: deepOverride,
    storage_policy: 'retrieval_time_sidecar_no_canonical_memory_mutation',
    aladdin: {
      permanent_storage_untouched: true,
      no_pruning: true,
      no_decay: true,
      no_deletion: true,
      no_suppression: true,
    },
  };
  const hash = sha256Canonical(payload);
  const signature = typeof signer === 'function' ? signer(payload) : null;
  return {
    ...payload,
    sidecar_hash: hash,
    signature: signature || {
      signed: false,
      scheme: 'sha256_canonical_sidecar_hash_only',
      reason: 'no_signer_available_in_pure_diagnostic_function',
    },
  };
}

export default {
  buildAladdinSalienceSidecar,
};
