/**
 * Native context-conditioned QA operator from:
 * - SITUATEDQA.pdf
 *
 * Implemented formulas / techniques:
 * - situated tuple: (q, c_v, a)
 * - context decomposition: c = (c_t, c_v)
 * - context dependence: exists c_i, c_j such that a_i != a_j
 * - temporal and geographical context detection
 * - exact-match compatibility diagnostics
 *
 * Aimos adaptation:
 * - scores context compatibility for recall evidence
 * - does not generate answers or inject benchmark labels
 * - does not filter, delete, decay, prune, or suppress memories
 */

const MONTHS = new Map([
  ['january', 1], ['february', 2], ['march', 3], ['april', 4],
  ['may', 5], ['june', 6], ['july', 7], ['august', 8],
  ['september', 9], ['october', 10], ['november', 11], ['december', 12],
]);

const TEMPORAL_WORDS = /\b(as of|currently|current|now|today|yesterday|recently|last|next|previously|then|before|after|during|in \d{4}|since|until)\b/i;
const GEO_WORDS = /\b(in|from|near|around|at|within)\s+([A-Z][A-Za-z]+(?:[\s-][A-Z][A-Za-z]+){0,3})\b/g;

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalize(text = '') {
  return String(text || '').toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, ' ').replace(/\s+/g, ' ').trim();
}

function tokens(text = '') {
  return normalize(text).split(/\s+/).filter((token) => token.length >= 3);
}

function parseYearMonth(text = '') {
  const lower = normalize(text);
  const yearMatch = lower.match(/\b(19|20)\d{2}\b/);
  const month = [...MONTHS.entries()].find(([name]) => new RegExp(`\\b${name}\\b`, 'i').test(lower));
  return {
    year: yearMatch ? Number(yearMatch[0]) : null,
    month: month ? month[1] : null,
  };
}

function dateFromContext(value = '', referenceDate = new Date()) {
  const parsed = Date.parse(value);
  if (Number.isFinite(parsed)) return new Date(parsed);
  const lower = normalize(value);
  const ref = new Date(referenceDate);
  if (/\btoday|now|currently|current\b/.test(lower)) return ref;
  if (/\byesterday\b/.test(lower)) return new Date(ref.getTime() - 86400000);
  if (/\blast week\b/.test(lower)) return new Date(ref.getTime() - 7 * 86400000);
  if (/\blast month\b/.test(lower)) return new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth() - 1, 1));
  const ym = parseYearMonth(value);
  if (ym.year && ym.month) return new Date(Date.UTC(ym.year, ym.month - 1, 15));
  if (ym.year) return new Date(Date.UTC(ym.year, 6, 1));
  return null;
}

export function parseSituatedContext(queryText = '', options = {}) {
  const referenceDate = options.referenceDate || new Date();
  const contexts = [];
  const query = String(queryText || '');
  const temporalRaw = [];

  if (TEMPORAL_WORDS.test(query)) temporalRaw.push(query.match(TEMPORAL_WORDS)?.[0] || 'temporal');
  for (const year of query.match(/\b(19|20)\d{2}\b/g) || []) temporalRaw.push(year);
  for (const [month] of MONTHS) {
    if (new RegExp(`\\b${month}\\b`, 'i').test(query)) temporalRaw.push(month);
  }
  for (const value of [...new Set(temporalRaw)]) {
    const date = dateFromContext(value, referenceDate);
    contexts.push({
      c_t: 'TEMP',
      c_v: value,
      normalized: date ? date.toISOString().slice(0, 10) : normalize(value),
    });
  }

  const geoMatches = [...query.matchAll(GEO_WORDS)];
  for (const match of geoMatches) {
    const place = String(match[2] || '').trim();
    if (!place || /^(I|The|This|That|When|Which|What)$/.test(place)) continue;
    contexts.push({ c_t: 'GEO', c_v: place, normalized: normalize(place) });
  }

  return {
    q: query,
    contexts,
    tuple_template: '(q, c_v, a)',
    context_types: [...new Set(contexts.map((context) => context.c_t))],
    context_dependent: contexts.length > 0,
  };
}

export function isContextDependentQuestion(questionContexts = []) {
  return Array.isArray(questionContexts) && questionContexts.length > 0;
}

export function exactMatchCompatible(expected = '', observed = '') {
  const left = normalize(expected);
  const right = normalize(observed);
  return Boolean(left && right && (left === right || right.includes(left) || left.includes(right)));
}

function temporalCompatibility(context = {}, memoryText = '', memory = {}, referenceDate = new Date()) {
  const memoryDate = Date.parse(memory.created_at || memory.valid_from || memory.ts_created || '');
  const queryDate = dateFromContext(context.c_v, referenceDate);
  const textYm = parseYearMonth(memoryText);
  const contextYm = parseYearMonth(context.c_v);

  if (contextYm.year && textYm.year && contextYm.year !== textYm.year) return 0;
  if (contextYm.month && textYm.month && contextYm.month !== textYm.month) return 0.1;
  if (contextYm.year && textYm.year === contextYm.year && (!contextYm.month || textYm.month === contextYm.month)) return 1;

  if (queryDate && Number.isFinite(memoryDate)) {
    const gapDays = Math.abs((memoryDate - queryDate.getTime()) / 86400000);
    if (/\bcurrent|currently|now|today\b/i.test(context.c_v)) {
      return clamp01(1 / (1 + gapDays / 30));
    }
    return clamp01(1 / (1 + gapDays / 180));
  }
  return TEMPORAL_WORDS.test(memoryText) ? 0.35 : 0;
}

function geoCompatibility(context = {}, memoryText = '') {
  const cvTokens = new Set(tokens(context.c_v));
  if (!cvTokens.size) return 0;
  const body = new Set(tokens(memoryText));
  let hits = 0;
  for (const token of cvTokens) {
    if (body.has(token)) hits += 1;
  }
  return clamp01(hits / cvTokens.size);
}

export function situatedContextScore({
  queryText = '',
  memoryText = '',
  memory = {},
  referenceDate = new Date(),
} = {}) {
  const parsed = parseSituatedContext(queryText, { referenceDate });
  if (!parsed.contexts.length) {
    return { score: 0, parsed, components: [] };
  }
  const components = parsed.contexts.map((context) => {
    const score = context.c_t === 'TEMP'
      ? temporalCompatibility(context, memoryText, memory, referenceDate)
      : geoCompatibility(context, memoryText);
    return { ...context, score };
  });
  const score = clamp01(components.reduce((sum, item) => sum + item.score, 0) / Math.max(1, components.length));
  return {
    score,
    parsed,
    components,
    formula: 'c = (c_t, c_v); situated evidence compatibility = mean(score(c_i, memory))',
  };
}

export function situatedQaEvaluate({
  queryText = '',
  contexts = [],
  referenceDate = new Date(),
} = {}) {
  const parsed = parseSituatedContext(queryText, { referenceDate });
  const scoreById = new Map();
  const componentsById = new Map();
  for (const context of contexts || []) {
    const scored = situatedContextScore({
      queryText,
      memoryText: context.text || context.value || '',
      memory: context.memory || context,
      referenceDate,
    });
    scoreById.set(String(context.id), scored.score);
    componentsById.set(String(context.id), scored.components);
  }
  return {
    scoreById,
    componentsById,
    parsed,
    context_dependent: isContextDependentQuestion(parsed.contexts),
    formula: 'exists c_i, c_j: a_i != a_j indicates context dependence',
  };
}
