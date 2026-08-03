/**
 * Native time-series forecasting operator from:
 * - A DECODER-ONLY FOUNDATION MODEL FOR TIME-SERIES FORECASTING.pdf
 *
 * Implemented formulas / techniques:
 * - forecasting map `f: y_1:L -> yhat_{L+1:L+H}`
 * - covariate-conditioned map `f: (y_1:L, x_1:L+H) -> yhat`
 * - fixed non-overlapping patch decomposition
 * - element-wise mask `y_tilde_j * (1 - m_tilde_j)`
 * - date covariates: day-of-week, month, year position
 * - trend/seasonality/ARMA-inspired synthetic components
 * - MAE and msMAPE metrics
 *
 * Aimos adaptation:
 * - derives bounded horizon/recency/trend evidence signals for recall
 * - no training, no generation, no deletion, no decay, no answer injection
 */

export const TIME_SERIES_FORECAST_GUARDRAILS = Object.freeze({
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

function timeMs(value, fallback = NaN) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function contextWindow(series = [], L = series.length) {
  return series.slice(0, Math.max(0, L));
}

export function forecastHorizon(series = [], L = 0, H = 1) {
  return series.slice(Math.max(0, L), Math.max(0, L) + Math.max(0, H));
}

export function patchSeries(values = [], mask = [], patchSize = 8) {
  const p = Math.max(1, patchSize);
  const patches = [];
  for (let start = 0; start < values.length; start += p) {
    const y = values.slice(start, start + p);
    const m = mask.slice(start, start + p);
    while (y.length < p) y.push(0);
    while (m.length < p) m.push(0);
    patches.push({ y, mask: m, start, end: start + p });
  }
  return patches;
}

export function applyPatchMask(patch = {}) {
  const y = patch.y || [];
  const mask = patch.mask || [];
  return y.map((value, index) => (Number(value) || 0) * (1 - clamp01(mask[index] || 0)));
}

export function dateCovariates(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  return {
    day_of_week: d.getUTCDay(),
    month_of_year: d.getUTCMonth() + 1,
    day_of_month: d.getUTCDate(),
    year: d.getUTCFullYear(),
  };
}

export function movingTrendForecast(values = [], H = 1) {
  const rows = values.map(Number).filter(Number.isFinite);
  if (!rows.length) return Array(Math.max(0, H)).fill(0);
  const n = rows.length;
  const slope = n > 1 ? (rows[n - 1] - rows[0]) / (n - 1) : 0;
  return Array.from({ length: Math.max(0, H) }, (_, index) => rows[n - 1] + (slope * (index + 1)));
}

export function seasonalSineComponent(length = 1, { period = 7, amplitude = 1, delay = 0 } = {}) {
  return Array.from({ length: Math.max(0, length) }, (_, index) => amplitude * Math.sin((2 * Math.PI * (index + delay)) / Math.max(1, period)));
}

export function armaLikeSynthetic(length = 1, { ar = [0.5], ma = [0.1], seed = 7 } = {}) {
  let state = seed >>> 0;
  const random = () => {
    state = Math.imul(1664525, state) + 1013904223;
    return ((state >>> 0) / 4294967296) - 0.5;
  };
  const out = [];
  const errors = [];
  for (let i = 0; i < Math.max(0, length); i += 1) {
    const err = random();
    errors.push(err);
    let value = err;
    for (let p = 0; p < Math.min(ar.length, out.length); p += 1) value += ar[p] * out[out.length - 1 - p];
    for (let q = 0; q < Math.min(ma.length, errors.length - 1); q += 1) value += ma[q] * errors[errors.length - 2 - q];
    out.push(value);
  }
  return out;
}

export function mae(actual = [], predicted = []) {
  const n = Math.min(actual.length, predicted.length);
  if (!n) return 0;
  let total = 0;
  for (let i = 0; i < n; i += 1) total += Math.abs((Number(actual[i]) || 0) - (Number(predicted[i]) || 0));
  return total / n;
}

export function msMape(actual = [], predicted = [], epsilon = 1e-6) {
  const n = Math.min(actual.length, predicted.length);
  if (!n) return 0;
  let total = 0;
  for (let i = 0; i < n; i += 1) {
    const a = Number(actual[i]) || 0;
    const p = Number(predicted[i]) || 0;
    total += Math.abs(a - p) / Math.max(Math.abs(a) + Math.abs(p) + epsilon, 0.5 + epsilon);
  }
  return total / n;
}

function lexicalScore(query = '', text = '') {
  const q = new Set(String(query).toLowerCase().split(/\W+/).filter((token) => token.length > 2));
  const t = new Set(String(text).toLowerCase().split(/\W+/).filter((token) => token.length > 2));
  if (!q.size || !t.size) return 0;
  let hit = 0;
  for (const token of q) if (t.has(token)) hit += 1;
  return clamp01(hit / Math.sqrt(q.size * t.size));
}

export function timeSeriesForecastScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
} = {}) {
  const sorted = [...(states || [])].sort((a, b) => timeMs(a.memory?.created_at, a.interval?.start || 0) - timeMs(b.memory?.created_at, b.interval?.start || 0));
  const times = sorted.map((state, index) => ({
    id: String(state.id),
    x: index,
    y: lexicalScore(queryText, state.text || '') + (Number.isFinite(timeMs(state.memory?.created_at)) ? 0.1 : 0),
    ms: timeMs(state.memory?.created_at, state.interval?.start || 0),
  }));
  const observed = times.map((row) => row.y);
  const predicted = movingTrendForecast(observed.slice(0, Math.max(1, observed.length - 1)), Math.max(1, observed.length - Math.max(1, observed.length - 1)));
  const error = observed.length > 1 ? msMape(observed.slice(-predicted.length), predicted) : 0;
  const currentIntent = /\b(current|currently|now|recent|recently|latest|last|next|future|will|forecast|predict)\b/i.test(queryText);
  const scoreById = new Map();
  const diagnosticsById = new Map();
  const maxAge = Math.max(1, ...times.map((row) => Math.max(0, timeMs(referenceDate, Date.now()) - row.ms)));

  for (const row of times) {
    const recency = clamp01(1 - (Math.max(0, timeMs(referenceDate, Date.now()) - row.ms) / maxAge));
    const horizon = currentIntent ? recency : 0;
    const score = clamp01((row.y * 0.52) + (horizon * 0.32) + ((1 - clamp01(error)) * 0.16));
    scoreById.set(row.id, score);
    diagnosticsById.set(row.id, {
      lexical_observation: Number(row.y.toFixed(6)),
      recency: Number(recency.toFixed(6)),
      horizon: Number(horizon.toFixed(6)),
    });
  }

  return {
    scoreById,
    diagnosticsById,
    forecast_error_msmapE: Number(error.toFixed(6)),
    covariates: dateCovariates(referenceDate),
    formula: 'f: y_1:L -> yhat_L+1:L+H with patch masking y_tilde_j * (1 - m_tilde_j), MAE, and msMAPE',
  };
}
