/**
 * Native time-horizon operator from:
 * - StreamingQA.pdf
 *
 * Implemented formulas / techniques:
 * - Q = {(dq_i, q_i, a_i)} and C = {(dc_j, c_j)}
 * - Q_t = {(dq_i, q_i, a_i) in Q : ts <= dq_i <= te}
 * - C_<=t = {(dc_j, c_j) in C : dc_j <= te}
 * - p(a_i | q_i, dq_i, C_<=t)
 * - recent / past split and timestamp lag diagnostics
 * - recall@k diagnostic helper
 *
 * Aimos adaptation:
 * - no future-evidence deletion; future evidence receives a bounded low score
 * - no pruning, decay, or canonical memory mutation
 */

const DAY_MS = 86400000;

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalize(text = '') {
  return String(text || '').toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, ' ').replace(/\s+/g, ' ').trim();
}

function parseDateLike(text = '', referenceDate = new Date()) {
  const raw = String(text || '');
  const direct = raw.match(/\b(19|20)\d{2}-\d{2}-\d{2}\b/);
  if (direct) return new Date(`${direct[0]}T00:00:00.000Z`);
  const year = raw.match(/\b(19|20)\d{2}\b/);
  if (year) return new Date(Date.UTC(Number(year[0]), 6, 1));
  const lower = normalize(raw);
  const ref = new Date(referenceDate);
  if (/\btoday|now|currently|current\b/.test(lower)) return ref;
  if (/\byesterday\b/.test(lower)) return new Date(ref.getTime() - DAY_MS);
  if (/\blast week\b/.test(lower)) return new Date(ref.getTime() - 7 * DAY_MS);
  if (/\blast month\b/.test(lower)) return new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth() - 1, 1));
  if (/\blast year\b/.test(lower)) return new Date(Date.UTC(ref.getUTCFullYear() - 1, 6, 1));
  return null;
}

function docDate(memory = {}, fallback = null) {
  for (const key of ['publication_date', 'document_date', 'valid_from', 'created_at', 'ts_created']) {
    const parsed = Date.parse(memory[key] || '');
    if (Number.isFinite(parsed)) return new Date(parsed);
  }
  return fallback;
}

function periodFor(date = new Date(), granularity = 'quarter') {
  const d = new Date(date);
  if (granularity === 'year') {
    return {
      ts: new Date(Date.UTC(d.getUTCFullYear(), 0, 1)),
      te: new Date(Date.UTC(d.getUTCFullYear(), 11, 31, 23, 59, 59, 999)),
      granularity,
    };
  }
  if (granularity === 'month') {
    return {
      ts: new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)),
      te: new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0, 23, 59, 59, 999)),
      granularity,
    };
  }
  const q = Math.floor(d.getUTCMonth() / 3);
  return {
    ts: new Date(Date.UTC(d.getUTCFullYear(), q * 3, 1)),
    te: new Date(Date.UTC(d.getUTCFullYear(), q * 3 + 3, 0, 23, 59, 59, 999)),
    granularity: 'quarter',
  };
}

function hasStreamingTemporalIntent(queryText = '') {
  return /\b(as of|currently|current|now|today|recent|recently|last|latest|in \d{4}|since|until|before|after|during|when)\b/i.test(String(queryText || ''));
}

export function streamingQuestionPeriod(queryText = '', options = {}) {
  const referenceDate = options.referenceDate || new Date();
  const queryDate = parseDateLike(queryText, referenceDate) || new Date(referenceDate);
  const lower = normalize(queryText);
  const granularity = /\bmonth|january|february|march|april|june|july|august|september|october|november|december\b/.test(lower)
    ? 'month'
    : /\byear|annual|in \d{4}\b/.test(lower)
      ? 'year'
      : 'quarter';
  const period = periodFor(queryDate, granularity);
  return {
    dq: queryDate,
    ...period,
    active_query: hasStreamingTemporalIntent(queryText),
  };
}

export function buildStreamingQaModel({ questions = [], corpus = [], period = {} } = {}) {
  const ts = period.ts ? Date.parse(period.ts) : -Infinity;
  const te = period.te ? Date.parse(period.te) : Infinity;
  const Q_t = questions.filter((row) => {
    const dq = Date.parse(row.dq || row.question_date || '');
    return Number.isFinite(dq) && dq >= ts && dq <= te;
  });
  const C_lte_t = corpus.filter((row) => {
    const dc = Date.parse(row.dc || row.document_date || row.created_at || '');
    return Number.isFinite(dc) && dc <= te;
  });
  return {
    Q_t,
    C_lte_t,
    formula: 'Q_t = {q: ts <= dq <= te}; C_<=t = {c: dc <= te}; p(a | q, dq, C_<=t)',
  };
}

export function timestampLagDays(goldTimestamp, retrievedTimestamp) {
  const left = Date.parse(goldTimestamp || '');
  const right = Date.parse(retrievedTimestamp || '');
  if (!Number.isFinite(left) || !Number.isFinite(right)) return null;
  return Math.round((left - right) / DAY_MS);
}

export function recallAtK(relevantIds = [], rankedIds = [], k = 20) {
  const relevant = new Set(relevantIds.map(String));
  if (!relevant.size) return 0;
  let hit = 0;
  for (const id of rankedIds.slice(0, Math.max(0, k)).map(String)) {
    if (relevant.has(id)) hit += 1;
  }
  return clamp01(hit / relevant.size);
}

export function streamingHorizonScores({
  queryText = '',
  states = [],
  referenceDate = new Date(),
} = {}) {
  const period = streamingQuestionPeriod(queryText, { referenceDate });
  const scoreById = new Map();
  const diagnosticsById = new Map();
  const te = period.te.getTime();

  for (const state of states || []) {
    const date = docDate(state.memory || state, period.dq);
    const dc = date ? date.getTime() : NaN;
    const future = Number.isFinite(dc) && dc > te;
    const lagDays = Number.isFinite(dc) ? Math.round((period.dq.getTime() - dc) / DAY_MS) : null;
    const recent = lagDays !== null && lagDays >= 0 && lagDays <= 30;
    const past = lagDays !== null && lagDays > 30;
    let score = 0;

    if (period.active_query && Number.isFinite(dc)) {
      if (future) score = 0.08;
      else if (recent) score = 1;
      else score = clamp01(0.62 / (1 + Math.max(0, lagDays - 30) / 365));
    }

    scoreById.set(String(state.id), score);
    diagnosticsById.set(String(state.id), {
      dc: date ? date.toISOString() : null,
      lag_days: lagDays,
      subset: future ? 'future' : recent ? 'recent' : past ? 'past' : 'unknown',
      c_lte_t: Boolean(Number.isFinite(dc) && dc <= te),
    });
  }

  return {
    scoreById,
    diagnosticsById,
    period: {
      dq: period.dq.toISOString(),
      ts: period.ts.toISOString(),
      te: period.te.toISOString(),
      granularity: period.granularity,
      active_query: period.active_query,
    },
    formula: 'C_<=t = {c_j : dc_j <= te}; score preserves all candidates and downweights future evidence',
  };
}
