/**
 * Native temporal-knowledge language model control operator from:
 * - Time-Aware_Language_Models_as_Temporal_Knowledge_B.pdf
 *
 * Implemented formulas / techniques:
 * - P(y | x, t; theta) temporal conditioning contract
 * - yearly expert routing P(y | x; theta_t)
 * - time-prefix conditioning P(y | concat(t, x); theta)
 * - token-level F1 with max over multiple accepted answers
 * - perplexity from normalized negative log likelihood
 * - macro average across time slices
 * - deterministic bootstrap confidence interval
 * - answer-change frequency buckets
 *
 * Aimos adaptation:
 * - contributes bounded temporal-conditioning recall scores only
 * - no pruning, no decay, no deletion, no answer injection
 */

export const TIME_AWARE_LM_KB_GUARDRAILS = Object.freeze({
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

function tokenCounts(value = '') {
  const counts = new Map();
  for (const token of normalizeText(value).split(/\s+/).filter(Boolean)) {
    counts.set(token, (counts.get(token) || 0) + 1);
  }
  return counts;
}

function yearFrom(value) {
  const raw = String(value || '');
  const direct = raw.match(/\b(19|20)\d{2}\b/)?.[0];
  if (direct) return Number(direct);
  const parsed = Date.parse(raw);
  if (Number.isFinite(parsed)) return new Date(parsed).getUTCFullYear();
  return null;
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = Math.imul(1664525, state) + 1013904223;
    return (state >>> 0) / 4294967296;
  };
}

export function temporalPrefixInput(input = '', time = '') {
  const year = yearFrom(time);
  return year ? `In ${year}, ${String(input || '').trim()}` : String(input || '').trim();
}

export function routeTemporalExpert(time = '', { availableYears = [] } = {}) {
  const years = [...new Set((availableYears || []).map(Number).filter(Number.isFinite))].sort((a, b) => a - b);
  const target = yearFrom(time);
  if (!target || !years.length) return { target_year: target, expert_year: null, strategy: 'no_temporal_expert' };
  if (years.includes(target)) return { target_year: target, expert_year: target, strategy: 'exact_year_expert' };
  if ((target === 2019 || target === 2020) && years.includes(2018)) {
    return { target_year: target, expert_year: 2018, strategy: 'paper_2018_fallback' };
  }
  const earlier = years.filter((year) => year <= target).pop();
  const expert = earlier ?? years[years.length - 1];
  return { target_year: target, expert_year: expert, strategy: earlier ? 'nearest_past_expert' : 'latest_available_expert' };
}

export function temporalConditionalModelSpec(input = '', time = '') {
  return {
    conditional: 'P(y | x, t; theta)',
    yearly_expert: 'P(y | x; theta_t)',
    time_prefix: 'P(y | concat(t, x); theta)',
    prefixed_input: temporalPrefixInput(input, time),
  };
}

export function tokenF1(prediction = '', goldAnswers = []) {
  const answers = Array.isArray(goldAnswers) ? goldAnswers : [goldAnswers];
  const predCounts = tokenCounts(prediction);
  let best = 0;
  for (const answer of answers) {
    const goldCounts = tokenCounts(answer);
    let common = 0;
    for (const [token, count] of predCounts.entries()) common += Math.min(count, goldCounts.get(token) || 0);
    if (!predCounts.size && !goldCounts.size) best = Math.max(best, 1);
    if (!predCounts.size || !goldCounts.size || common === 0) continue;
    const precision = common / predCounts.size;
    const recall = common / goldCounts.size;
    best = Math.max(best, (2 * precision * recall) / (precision + recall));
  }
  return clamp01(best);
}

export function perplexityFromLogLikelihood({ logLikelihood = 0, totalLength = 1 } = {}) {
  const len = Math.max(1, Number(totalLength) || 1);
  return Math.exp(-(Number(logLikelihood) || 0) / len);
}

export function macroAverage(values = []) {
  const rows = (values || []).map(Number).filter(Number.isFinite);
  return rows.length ? rows.reduce((sum, value) => sum + value, 0) / rows.length : 0;
}

export function bootstrapConfidenceInterval(values = [], { samples = 200, alpha = 0.05, seed = 1337 } = {}) {
  const rows = (values || []).map(Number).filter(Number.isFinite);
  if (!rows.length) return { low: 0, high: 0, mean: 0, samples: 0 };
  const random = seededRandom(seed);
  const means = [];
  for (let i = 0; i < Math.max(1, samples); i += 1) {
    let sum = 0;
    for (let j = 0; j < rows.length; j += 1) sum += rows[Math.floor(random() * rows.length)];
    means.push(sum / rows.length);
  }
  means.sort((a, b) => a - b);
  const lowIndex = Math.floor((alpha / 2) * (means.length - 1));
  const highIndex = Math.ceil((1 - (alpha / 2)) * (means.length - 1));
  return {
    low: means[lowIndex],
    high: means[highIndex],
    mean: macroAverage(rows),
    samples: means.length,
  };
}

export function answerChangeFrequencyBucket(yearToAnswers = {}) {
  const entries = Object.entries(yearToAnswers || {}).sort(([a], [b]) => Number(a) - Number(b));
  if (entries.length <= 1) return 'never_changes';
  let changes = 0;
  for (let i = 1; i < entries.length; i += 1) {
    if (normalizeText(entries[i][1]) !== normalizeText(entries[i - 1][1])) changes += 1;
  }
  const rate = changes / (entries.length - 1);
  if (rate >= 0.5) return 'frequently_changes';
  if (rate > 0) return 'rarely_changes';
  return 'never_changes';
}

export function timeAwareLmKbScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
} = {}) {
  const queryYear = yearFrom(queryText) || yearFrom(referenceDate);
  const availableYears = states
    .map((state) => yearFrom(state.memory?.created_at) || yearFrom(state.text))
    .filter(Number.isFinite);
  const expert = routeTemporalExpert(queryYear, { availableYears });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  const query = normalizeText(queryText);
  const currentIntent = /\b(currently|now|today|recent|recently|latest|last)\b/.test(query);

  for (const state of states || []) {
    const id = String(state.id);
    const text = state.text || state.value || '';
    const memoryYear = yearFrom(state.memory?.created_at) || yearFrom(text);
    const yearScore = queryYear && memoryYear ? clamp01(1 / (1 + Math.abs(queryYear - memoryYear))) : 0;
    const expertScore = expert.expert_year && memoryYear ? (expert.expert_year === memoryYear ? 1 : yearScore) : yearScore;
    const currentScore = currentIntent && memoryYear
      ? clamp01(1 / (1 + Math.max(0, (queryYear || memoryYear) - memoryYear)))
      : 0;
    const f1Proxy = tokenF1(text, [queryText]);
    const score = clamp01((expertScore * 0.36) + (yearScore * 0.24) + (currentScore * 0.20) + (f1Proxy * 0.20));
    scoreById.set(id, score);
    diagnosticsById.set(id, {
      memory_year: memoryYear,
      year_score: Number(yearScore.toFixed(6)),
      expert_score: Number(expertScore.toFixed(6)),
      current_score: Number(currentScore.toFixed(6)),
      token_f1_proxy: Number(f1Proxy.toFixed(6)),
      temporal_prefix: temporalPrefixInput(queryText, memoryYear || queryYear || ''),
    });
  }

  return {
    scoreById,
    diagnosticsById,
    expert,
    conditional_model: temporalConditionalModelSpec(queryText, queryYear || ''),
    formula: 'temporal conditioning uses P(y | x, t; theta), yearly expert routing, and time-prefix conditioning',
  };
}
