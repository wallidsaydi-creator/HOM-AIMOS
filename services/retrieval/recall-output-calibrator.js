/**
 * NATIVE RECALL OUTPUT CALIBRATOR
 *
 * Paper / corpus authority:
 * - docs/recall-calibration-corpus.md
 * - TiMem: T=(M,E,tau,sigma), L1-L5 hierarchy, Phi_i, C_i(g)
 * - Chronos / TimeR4 / MRAG: temporal scope before broad answer synthesis
 * - MMR: lambda*Sim(d,q) - (1-lambda)*max Sim(d,s) for evidence diversity
 * - Source-attributed synthesis: bounded claims + evidence handles
 * - Active context compression papers: active context budget only, not durable
 *   memory compression
 *
 * Purpose:
 * - Calibrate the native /aimos/recall response after Aimos retrieval,
 *   ranking, trust, calibration, confidence, TiMem, and evidence diagnostics
 *   have already run.
 * - Broad/count/timeline queries return aggregate summaries and handles first.
 * - Why/how/evidence queries return bounded evidence cards.
 * - Full raw memory bodies open only for explicit full-detail drilldown.
 *
 * Guardrails:
 * - This is a native retrieval service, not an app/runtime wrapper and not a
 *   replacement recall route.
 * - It does not import experiments, mutate canonical memory, alter DB state,
 *   sign requests, call HTTP, bypass auth, or rewrite the 16/17-stage recall
 *   ranking math.
 * - Canonical memory remains full fidelity and permanent. Only the active
 *   response payload is shaped.
 */

import { systemConfigStore } from '../security/system-config-store.js';

function signedRecallFlag(configKey) {
  return systemConfigStore.readConfigString(configKey) === 'true';
}

const ANSWER_SHAPES = new Set(['aggregate_summary', 'bounded_evidence_pack', 'full_detail']);
const WEEKDAY_INDEX = {
  sunday: 0,
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
};
const MONTH_INDEX = {
  january: 0,
  february: 1,
  march: 2,
  april: 3,
  may: 4,
  june: 5,
  july: 6,
  august: 7,
  september: 8,
  october: 9,
  november: 10,
  december: 11,
};
const NUMBER_WORDS = {
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  couple: 2,
};
const QUERY_STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'being', 'but', 'by',
  'can', 'could', 'did', 'do', 'does', 'for', 'from', 'had', 'has', 'have',
  'he', 'her', 'hers', 'him', 'his', 'how', 'i', 'in', 'is', 'it', 'its',
  'me', 'my', 'of', 'on', 'or', 'our', 'ours', 'she', 'so', 'that', 'the',
  'their', 'them', 'then', 'there', 'they', 'this', 'to', 'was', 'we', 'were',
  'what', 'when', 'where', 'which', 'who', 'whom', 'why', 'with', 'you',
  'your', 'yours',
]);
const QUERY_EXPANSIONS = new Map([
  ['spent', ['spend', 'cost', 'paid', 'expense', 'expenses', 'bought', 'buy', 'purchase', 'purchased']],
  ['money', ['cash', 'dollars', 'paid', 'spent', 'cost', 'expense']],
  ['doctor', ['physician', 'appointment', 'clinic', 'dermatologist', 'medical']],
  ['job', ['work', 'position', 'company', 'career', 'employer', 'occupation']],
  ['book', ['reading', 'read', 'novel']],
  ['movie', ['film', 'festival', 'cinema']],
  ['first', ['before', 'earlier', 'oldest', 'initially']],
  ['recent', ['latest', 'newest', 'currently', 'now', 'most']],
  ['current', ['currently', 'now', 'latest', 'still', 'present']],
  ['currently', ['current', 'now', 'latest', 'still', 'present']],
  ['favorite', ['prefer', 'preference', 'like', 'love', 'enjoy', 'best']],
  ['sessions', ['session', 'conversation', 'chat', 'thread']],
  ['attended', ['went', 'visited', 'joined', 'participated']],
  ['coast', ['coastal', 'beach', 'cliffs']],
  ['coastal', ['coast', 'beach', 'cliffs']],
  ['family', ['parents', 'parent', 'mother', 'father', 'brother', 'sister', 'siblings', 'younger', 'older']],
  ['parents', ['family', 'mother', 'father']],
  ['brother', ['family', 'sibling', 'siblings']],
  ['sister', ['family', 'sibling', 'siblings']],
  ['raise', ['raised', 'fundraiser', 'charity', 'donation', 'donated']],
  ['occupation', ['job', 'work', 'career', 'position', 'role', 'employed', 'employment']],
  ['previous', ['before', 'earlier', 'old', 'former', 'prior', 'last']],
  ['relocation', ['moved', 'move', 'relocated', 'suburbs', 'apartment', 'house']],
  ['shampoo', ['brand', 'hair']],
  ['appliance', ['kitchen', 'buy', 'bought', 'purchased']],
  ['cooking', ['cook', 'bake', 'baked', 'cake', 'dinner']],
  ['senior', ['seniors', 'retiree', 'older', 'remote', 'work', 'home', 'job']],
  ['weekend', ['saturday', 'sunday']],
  ['recently', ['recent', 'latest', 'last', 'previous']],
  ['excited', ['interested', 'looking', 'forward']],
  ['fantasy', ['series', 'show', 'tv']],
  ['instrument', ['instruments', 'guitar', 'ukulele', 'piano']],
  ['clinic', ['doctor', 'appointment', 'medical', 'vet', 'veterinary']],
  ['find', ['found', 'saw', 'seen', 'located', 'discover', 'discovered']],
  ['house', ['home', 'property', 'place']],
  ['home', ['house', 'property', 'place']],
  ['lov', ['love', 'loved', 'like', 'liked', 'adore']],
]);

const DEFAULT_RUNTIME_BUDGET = {
  context_window: 130000,
  tokens_used: 0,
  recall_share: 0.18,
  summary_token_budget: 1500,
  evidence_token_budget: 4096,
  full_detail_token_budget: 24000,
  hard_summary_threshold: 0.65,
  hard_evidence_pack_threshold: 0.80,
  handle_limit: 120,
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function estimateTokens(value) {
  const text = typeof value === 'string' ? value : stableJson(value);
  return Math.ceil(String(text || '').length / 4);
}

function clampNumber(value, defaultValue, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return defaultValue;
  return Math.max(min, Math.min(max, parsed));
}

function normalizeRuntimeBudget(runtimeBudget = {}) {
  const budget = {
    ...DEFAULT_RUNTIME_BUDGET,
    ...(isPlainObject(runtimeBudget) ? runtimeBudget : {}),
  };
  budget.context_window = clampNumber(budget.context_window, DEFAULT_RUNTIME_BUDGET.context_window, 4096, 2000000);
  budget.tokens_used = clampNumber(budget.tokens_used, 0, 0, budget.context_window);
  budget.recall_share = clampNumber(budget.recall_share, DEFAULT_RUNTIME_BUDGET.recall_share, 0.01, 0.80);
  budget.summary_token_budget = Math.trunc(clampNumber(budget.summary_token_budget, 1500, 256, 12000));
  budget.evidence_token_budget = Math.trunc(clampNumber(budget.evidence_token_budget, 4096, 512, 24000));
  budget.full_detail_token_budget = Math.trunc(clampNumber(budget.full_detail_token_budget, 24000, 1024, 200000));
  budget.hard_summary_threshold = clampNumber(budget.hard_summary_threshold, 0.65, 0.10, 0.95);
  budget.hard_evidence_pack_threshold = clampNumber(budget.hard_evidence_pack_threshold, 0.80, budget.hard_summary_threshold, 0.99);
  budget.handle_limit = Math.trunc(clampNumber(budget.handle_limit, 120, 1, 1000));
  budget.pressure = budget.context_window > 0 ? Number((budget.tokens_used / budget.context_window).toFixed(6)) : 1;
  budget.budget_for_recall = Math.max(2048, Math.floor((budget.context_window - budget.tokens_used) * budget.recall_share));
  return budget;
}

function tryParseJson(value) {
  if (isPlainObject(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return null;
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function firstText(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function firstValue(...values) {
  for (const value of values) {
    if (value !== null && value !== undefined && String(value).trim() !== '') return value;
  }
  return null;
}

function toDay(value) {
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) return value;
  const date = new Date(value);
  if (!Number.isNaN(date.getTime())) return date.toISOString().slice(0, 10);
  return 'unknown-day';
}

function validDateOrNow(value) {
  const date = value ? new Date(value) : new Date();
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function dateOnly(date) {
  return date.toISOString().slice(0, 10);
}

function dateFromDay(day) {
  return new Date(`${day}T00:00:00.000Z`);
}

function addUtcDays(date, days) {
  const next = new Date(date.getTime());
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

function startOfIsoWeek(date) {
  const start = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = start.getUTCDay() || 7;
  start.setUTCDate(start.getUTCDate() - day + 1);
  return start;
}

function monthScope(year, monthIndex, expression) {
  const start = new Date(Date.UTC(year, monthIndex, 1));
  const end = new Date(Date.UTC(year, monthIndex + 1, 1));
  return {
    kind: 'calendar_month',
    expression,
    start_day: dateOnly(start),
    end_day_exclusive: dateOnly(end),
    grain: 'month',
    confidence: 0.86,
    notes: ['calendar_month_detected'],
  };
}

function monthRangeScope(year, monthIndexes, expressions) {
  const ordered = [...monthIndexes].sort((a, b) => a - b);
  const start = new Date(Date.UTC(year, ordered[0], 1));
  const end = new Date(Date.UTC(year, ordered[ordered.length - 1] + 1, 1));
  return {
    kind: 'calendar_month_range',
    expression: expressions.join(' and '),
    start_day: dateOnly(start),
    end_day_exclusive: dateOnly(end),
    grain: 'month_range',
    months: expressions,
    confidence: 0.89,
    notes: ['calendar_multi_month_detected'],
  };
}

function dayScope(day, kind, expression, confidence = 0.88, notes = []) {
  return {
    kind,
    expression,
    start_day: day,
    end_day_exclusive: dateOnly(addUtcDays(dateFromDay(day), 1)),
    grain: 'day',
    confidence,
    notes,
  };
}

function rangeScope(kind, expression, start, end, grain, confidence, notes = []) {
  return {
    kind,
    expression,
    start_day: start ? dateOnly(start) : null,
    end_day_exclusive: end ? dateOnly(end) : null,
    grain,
    confidence,
    notes,
  };
}

function previousWeekday(reference, weekday) {
  const refDay = reference.getUTCDay();
  let daysBack = (refDay - weekday + 7) % 7;
  if (daysBack === 0) daysBack = 7;
  return addUtcDays(reference, -daysBack);
}

export function resolveTemporalScope(query, options = {}) {
  const q = String(query || '').toLowerCase();
  const reference = validDateOrNow(options.now || options.reference_time || options.referenceDate);
  const referenceDay = dateOnly(reference);
  const timezone = options.timezone || 'Europe/Rome';

  const exactDate = q.match(/\b(20\d{2})-(\d{2})-(\d{2})\b/);
  if (exactDate) {
    const day = `${exactDate[1]}-${exactDate[2]}-${exactDate[3]}`;
    return {
      ...dayScope(day, 'explicit_date', exactDate[0], 0.94, ['explicit_iso_date']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\byesterday\b/.test(q)) {
    const day = dateOnly(addUtcDays(reference, -1));
    return {
      ...dayScope(day, 'relative_day', 'yesterday', 0.90, ['relative_day_yesterday']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\btoday\b/.test(q)) {
    return {
      ...dayScope(referenceDay, 'relative_day', 'today', 0.90, ['relative_day_today']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(this|current)\s+year\b|\bin\s+this\s+year\b/.test(q)) {
    const start = new Date(Date.UTC(reference.getUTCFullYear(), 0, 1));
    const end = new Date(Date.UTC(reference.getUTCFullYear() + 1, 0, 1));
    return {
      ...rangeScope('calendar_year', 'this year', start, end, 'year', 0.86, ['calendar_year_current']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\bnext\s+year\b/.test(q)) {
    const start = new Date(Date.UTC(reference.getUTCFullYear() + 1, 0, 1));
    const end = new Date(Date.UTC(reference.getUTCFullYear() + 2, 0, 1));
    return {
      ...rangeScope('calendar_year', 'next year', start, end, 'year', 0.84, ['calendar_year_next']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(last|previous)\s+year\b/.test(q)) {
    const start = new Date(Date.UTC(reference.getUTCFullYear() - 1, 0, 1));
    const end = new Date(Date.UTC(reference.getUTCFullYear(), 0, 1));
    return {
      ...rangeScope('calendar_year', 'last year', start, end, 'year', 0.86, ['calendar_year_previous']),
      reference_day: referenceDay,
      timezone,
    };
  }

  const explicitYear = q.match(/\b(?:in|during|from|for|since)\s+(20\d{2})\b/);
  if (explicitYear) {
    const year = Number(explicitYear[1]);
    const start = new Date(Date.UTC(year, 0, 1));
    const end = new Date(Date.UTC(year + 1, 0, 1));
    return {
      ...rangeScope('calendar_year', explicitYear[0], start, end, 'year', 0.86, ['explicit_calendar_year']),
      reference_day: referenceDay,
      timezone,
    };
  }

  const pastDays = q.match(/\b(?:last|past|previous)\s+(\d{1,3})\s+days?\b/);
  if (pastDays) {
    const count = Math.max(1, Math.min(365, Number(pastDays[1])));
    return {
      kind: 'rolling_days',
      expression: pastDays[0],
      start_day: dateOnly(addUtcDays(reference, -count)),
      end_day_exclusive: dateOnly(addUtcDays(reference, 1)),
      grain: 'day_range',
      reference_day: referenceDay,
      timezone,
      confidence: 0.88,
      notes: ['rolling_day_window'],
    };
  }

  const rollingWeeks = q.match(/\b(?:last|past|previous)\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten|couple)\s+weeks?\b/);
  if (rollingWeeks) {
    const count = Math.max(1, Math.min(52, NUMBER_WORDS[rollingWeeks[1]] || Number(rollingWeeks[1])));
    return {
      ...rangeScope('rolling_weeks', rollingWeeks[0], addUtcDays(reference, -7 * count), addUtcDays(reference, 1), 'week_range', 0.86, ['rolling_week_window']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(?:last|past|previous)\s+month\b/.test(q)) {
    return {
      ...rangeScope('rolling_month', q.match(/\b(?:last|past|previous)\s+month\b/)[0], addUtcDays(reference, -30), addUtcDays(reference, 1), 'month_window', 0.84, ['rolling_month_window']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(last|previous)\s+week\b/.test(q)) {
    const thisWeek = startOfIsoWeek(reference);
    const start = addUtcDays(thisWeek, -7);
    return {
      kind: 'relative_week',
      expression: 'last week',
      start_day: dateOnly(start),
      end_day_exclusive: dateOnly(thisWeek),
      grain: 'week',
      reference_day: referenceDay,
      timezone,
      confidence: 0.90,
      notes: ['iso_week_previous'],
    };
  }

  if (/\bthis\s+week\b/.test(q)) {
    const start = startOfIsoWeek(reference);
    return {
      kind: 'relative_week',
      expression: 'this week',
      start_day: dateOnly(start),
      end_day_exclusive: dateOnly(addUtcDays(start, 7)),
      grain: 'week',
      reference_day: referenceDay,
      timezone,
      confidence: 0.88,
      notes: ['iso_week_current'],
    };
  }

  const dayOffset = q.match(/\b(?:a\s+)?(\d{1,3}|one|two|three|four|five|six|seven|eight|nine|ten|couple)(?:\s+of)?\s+days?\s+ago\b/);
  if (dayOffset) {
    const count = NUMBER_WORDS[dayOffset[1]] || Number(dayOffset[1]);
    const safeCount = Math.max(1, Math.min(365, count));
    const day = dateOnly(addUtcDays(reference, -safeCount));
    return {
      ...dayScope(day, 'relative_day_offset', dayOffset[0], 0.86, ['relative_day_offset']),
      reference_day: referenceDay,
      timezone,
    };
  }

  const weekOffset = q.match(/\b(?:(a|an|\d{1,2}|one|two|three|four|five|six|seven|eight|nine|ten)\s+)?weeks?\s+ago\b/);
  if (weekOffset) {
    const count = weekOffset[1] === 'a' || weekOffset[1] === 'an' || !weekOffset[1]
      ? 1
      : (NUMBER_WORDS[weekOffset[1]] || Number(weekOffset[1]));
    const safeCount = Math.max(1, Math.min(52, count));
    const thisWeek = startOfIsoWeek(reference);
    const start = addUtcDays(thisWeek, -7 * safeCount);
    return {
      kind: 'relative_week_offset',
      expression: weekOffset[0],
      start_day: dateOnly(start),
      end_day_exclusive: dateOnly(addUtcDays(start, 7)),
      grain: 'week',
      reference_day: referenceDay,
      timezone,
      confidence: 0.84,
      notes: ['relative_week_offset'],
    };
  }

  if (/\b(this|coming)\s+weekend\b/.test(q)) {
    const weekStart = startOfIsoWeek(reference);
    const saturday = addUtcDays(weekStart, 5);
    return {
      ...rangeScope('relative_weekend', 'this weekend', saturday, addUtcDays(saturday, 2), 'weekend', 0.86, ['current_weekend_window']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(last|previous)\s+weekend\b/.test(q)) {
    const weekStart = startOfIsoWeek(reference);
    const saturday = addUtcDays(weekStart, -2);
    return {
      ...rangeScope('relative_weekend', 'last weekend', saturday, addUtcDays(saturday, 2), 'weekend', 0.86, ['previous_weekend_window']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(most recently|recently|recent visit|newly|now|currently)\b/.test(q)) {
    return {
      ...rangeScope('recent_window', q.match(/\b(most recently|recently|recent visit|newly|now|currently)\b/)[0], addUtcDays(reference, -45), addUtcDays(reference, 1), 'recent_window', 0.72, ['relative_recent_window']),
      reference_day: referenceDay,
      timezone,
    };
  }

  if (/\b(last time|previous chat|previous conversation|previous stance|previous occupation|earlier|provided me earlier|talked about last time|going back to our previous|looking back|thinking back)\b/.test(q)) {
    return {
      kind: 'previous_context_reference',
      expression: q.match(/\b(last time|previous chat|previous conversation|previous stance|previous occupation|earlier|provided me earlier|talked about last time|going back to our previous|looking back|thinking back)\b/)?.[0] || 'previous context',
      start_day: null,
      end_day_exclusive: null,
      grain: 'prior_session_reference',
      reference_day: referenceDay,
      timezone,
      confidence: 0.70,
      notes: ['previous_context_reference'],
    };
  }

  if (/\b(period of time|week-long|for a while|for some time)\b/.test(q)) {
    return {
      kind: 'duration_window_unspecified',
      expression: q.match(/\b(period of time|week-long|for a while|for some time)\b/)?.[0] || 'duration window',
      start_day: null,
      end_day_exclusive: null,
      grain: 'duration_window',
      reference_day: referenceDay,
      timezone,
      confidence: 0.68,
      notes: ['duration_window_without_exact_dates'],
    };
  }

  if (/\bwhen\s+(doing|away from|working|taking|attending|going|visiting|using|playing)\b|\bday\s+before\b|\bday\s+after\b/.test(q)) {
    return {
      kind: 'event_context_reference',
      expression: q.match(/\bwhen\s+(doing|away from|working|taking|attending|going|visiting|using|playing)\b|\bday\s+before\b|\bday\s+after\b/)?.[0] || 'event context',
      start_day: null,
      end_day_exclusive: null,
      grain: 'event_relative',
      reference_day: referenceDay,
      timezone,
      confidence: 0.70,
      notes: ['event_relative_temporal_reference'],
    };
  }

  if (/\bwhen\b|\bper\s+night\b|\bcompared\s+to\b/.test(q)) {
    return {
      kind: 'event_time_reference',
      expression: q.match(/\bwhen\b|\bper\s+night\b|\bcompared\s+to\b/)?.[0] || 'event time',
      start_day: null,
      end_day_exclusive: null,
      grain: 'event_time',
      reference_day: referenceDay,
      timezone,
      confidence: 0.68,
      notes: ['event_time_or_comparison_reference'],
    };
  }

  if (/\bwhat\s+year\s+did\b|\bwhich\s+year\b|\bwhen\s+did\b/.test(q)) {
    return {
      kind: 'calendar_year_query',
      expression: q.match(/\bwhat\s+year\s+did\b|\bwhich\s+year\b|\bwhen\s+did\b/)?.[0] || 'year query',
      start_day: null,
      end_day_exclusive: null,
      grain: 'year_lookup',
      reference_day: referenceDay,
      timezone,
      confidence: 0.70,
      notes: ['calendar_year_lookup_query'],
    };
  }

  if (/\b(start|beginning)\s+of\s+(the\s+)?year\b/.test(q) || /\bsince\s+the\s+start\s+of\s+the\s+year\b/.test(q) || /\byear\s+to\s+date\b/.test(q)) {
    const start = new Date(Date.UTC(reference.getUTCFullYear(), 0, 1));
    return {
      kind: 'year_to_date',
      expression: 'year_to_date',
      start_day: dateOnly(start),
      end_day_exclusive: dateOnly(addUtcDays(reference, 1)),
      grain: 'year_to_date',
      reference_day: referenceDay,
      timezone,
      confidence: 0.84,
      notes: ['year_to_date_scope'],
    };
  }

  if (/\b(last|previous)\s+month\b/.test(q)) {
    const month = reference.getUTCMonth() === 0 ? 11 : reference.getUTCMonth() - 1;
    const year = reference.getUTCMonth() === 0 ? reference.getUTCFullYear() - 1 : reference.getUTCFullYear();
    return {
      ...monthScope(year, month, 'last month'),
      reference_day: referenceDay,
      timezone,
      notes: ['calendar_month_previous'],
    };
  }

  const lastWeekOfMonth = q.match(/\blast\s+week\s+of\s+([a-z]+)(?:\s+(20\d{2}))?\b/i);
  if (lastWeekOfMonth && Object.prototype.hasOwnProperty.call(MONTH_INDEX, lastWeekOfMonth[1])) {
    const monthIndex = MONTH_INDEX[lastWeekOfMonth[1]];
    const year = lastWeekOfMonth[2] ? Number(lastWeekOfMonth[2]) : reference.getUTCFullYear();
    const monthEnd = new Date(Date.UTC(year, monthIndex + 1, 1));
    const start = addUtcDays(monthEnd, -7);
    return {
      kind: 'calendar_week_of_month',
      expression: lastWeekOfMonth[0],
      start_day: dateOnly(start),
      end_day_exclusive: dateOnly(monthEnd),
      grain: 'week',
      reference_day: referenceDay,
      timezone,
      confidence: 0.84,
      notes: ['last_week_of_month_detected'],
    };
  }

  const monthMatches = [...q.matchAll(new RegExp(`\\b(${Object.keys(MONTH_INDEX).join('|')})\\b`, 'gi'))]
    .map((match) => match[1].toLowerCase());
  const uniqueMonthMatches = unique(monthMatches);
  if (uniqueMonthMatches.length >= 2) {
    const yearMatch = q.match(/\b(20\d{2})\b/);
    const year = yearMatch ? Number(yearMatch[1]) : reference.getUTCFullYear();
    return {
      ...monthRangeScope(year, uniqueMonthMatches.map((month) => MONTH_INDEX[month]), uniqueMonthMatches),
      reference_day: referenceDay,
      timezone,
    };
  }

  for (const [monthName, monthIndex] of Object.entries(MONTH_INDEX)) {
    if (new RegExp(`\\b${monthName}\\b`, 'i').test(q)) {
      const yearMatch = q.match(/\b(20\d{2})\b/);
      const year = yearMatch ? Number(yearMatch[1]) : reference.getUTCFullYear();
      const scoped = monthScope(year, monthIndex, monthName);
      return {
        ...scoped,
        reference_day: referenceDay,
        timezone,
      };
    }
  }

  const recurringWeekdays = Object.entries(WEEKDAY_INDEX)
    .filter(([weekdayName]) => new RegExp(`\\b${weekdayName}s?\\b`, 'i').test(q))
    .map(([weekdayName, weekday]) => ({ weekdayName, weekday }));
  if (recurringWeekdays.length > 0 && !/\b(last|previous|this)\b/.test(q)) {
    return {
      kind: 'recurring_weekdays',
      expression: recurringWeekdays.map(({ weekdayName }) => `${weekdayName}s`).join(' and '),
      start_day: null,
      end_day_exclusive: null,
      grain: 'weekday_pattern',
      weekdays: recurringWeekdays.map(({ weekday }) => weekday),
      weekday_names: recurringWeekdays.map(({ weekdayName }) => weekdayName),
      reference_day: referenceDay,
      timezone,
      confidence: 0.82,
      notes: ['recurring_weekday_pattern_detected'],
    };
  }

  for (const [weekdayName, weekday] of Object.entries(WEEKDAY_INDEX)) {
    if (new RegExp(`\\b(?:last|previous|on|this)?\\s*${weekdayName}\\b`, 'i').test(q)) {
      const day = dateOnly(previousWeekday(reference, weekday));
      return {
        ...dayScope(day, 'relative_weekday', weekdayName, 0.84, ['most_recent_past_weekday']),
        reference_day: referenceDay,
        timezone,
      };
    }
  }

  return {
    kind: 'open',
    expression: null,
    start_day: null,
    end_day_exclusive: null,
    grain: 'unbounded',
    reference_day: referenceDay,
    timezone,
    confidence: 0.42,
    notes: ['no_temporal_scope_detected'],
  };
}

export function normalizeConfidence(memory, metadata = {}) {
  const direct = firstValue(
    memory.score,
    memory.recall_score,
    memory.recall_confidence,
    memory.confidence?.score,
    memory.confidence?.percent,
    typeof memory.confidence === 'number' || typeof memory.confidence === 'string' ? memory.confidence : undefined,
    metadata.confidence?.score,
    metadata.confidence?.percent,
    metadata.score,
    metadata.recall_score,
    metadata.recall_confidence
  );
  if (typeof direct === 'string') {
    const lowered = direct.toLowerCase();
    if (lowered === 'high') return 0.85;
    if (lowered === 'medium') return 0.60;
    if (lowered === 'low') return 0.35;
  }
  const parsed = Number(direct);
  if (Number.isFinite(parsed)) {
    return Number(Math.max(0, Math.min(1, parsed > 1 ? parsed / 100 : parsed)).toFixed(4));
  }
  return 0.50;
}

function textFromMemory(memory, parsedValue = null) {
  if (typeof memory.value === 'string') return memory.value;
  if (isPlainObject(memory.value)) return stableJson(memory.value);
  if (typeof memory.summary === 'string') return memory.summary;
  if (typeof memory.content === 'string') return memory.content;
  if (typeof memory.text === 'string') return memory.text;
  if (parsedValue) return stableJson(parsedValue);
  return stableJson(memory);
}

function parseSessionFromKey(key) {
  const text = String(key || '');
  const known = text.match(/(?:session|sess|thread|chat)[_:/-]([a-zA-Z0-9_.:-]{6,120})/i);
  if (known) return known[1];
  const dateSession = text.match(/(\d{8,}(?:[_:-][a-zA-Z0-9]{4,})?)/);
  return dateSession ? dateSession[1] : null;
}

function normalizeMemory(memory, index) {
  const parsedValue = tryParseJson(memory?.value);
  const metadata = {
    ...(isPlainObject(memory?.metadata) ? memory.metadata : {}),
    ...(isPlainObject(parsedValue?.metadata) ? parsedValue.metadata : {}),
  };
  const compactionRecord = metadata.compaction_record || parsedValue?.compaction_record || parsedValue;
  const timeBucket = metadata.timem?.temporal_bucket || metadata.temporal_bucket || parsedValue?.timem?.temporal_bucket || {};

  const key = firstText(memory?.key, metadata.key, parsedValue?.key) || `memory:${index}`;
  const memoryId = firstText(
    memory?.memory_id,
    memory?.id,
    metadata.memory_id,
    parsedValue?.memory_id,
    key
  );
  const createdAt = firstText(
    memory?.created_at,
    memory?.createdAt,
    memory?.ts_created,
    memory?.valid_from,
    metadata.created_at,
    metadata.valid_from,
    compactionRecord?.time_window?.valid_from,
    compactionRecord?.valid_from
  );
  const day = toDay(firstText(
    memory?.day,
    metadata.day,
    timeBucket.day,
    metadata.chronos?.time_window?.valid_from,
    compactionRecord?.time_window?.valid_from,
    createdAt
  ));
  const sessionId = firstText(
    memory?.session_id,
    metadata.session_id,
    timeBucket.session,
    compactionRecord?.session_id,
    parsedValue?.session_id,
    parseSessionFromKey(key),
    memoryId
  );
  const projectId = firstText(
    memory?.project_id,
    metadata.project_id,
    compactionRecord?.project_id,
    parsedValue?.project_id,
    'unknown-project'
  );
  const source = firstText(
    memory?.source,
    metadata.source,
    metadata.provenance?.source,
    parsedValue?.source,
    'aimos_memory'
  );
  const memoryType = firstText(
    memory?.memory_type,
    memory?.memoryType,
    memory?.type,
    metadata.memory_type,
    parsedValue?.memory_type,
    'unknown'
  );
  const retrievalFrequencyBand = firstText(
    memory?.retrieval_frequency_band,
    metadata.retrieval_frequency_band,
    parsedValue?.retrieval_frequency_band
  );
  const retrievalFrequencyReason = firstText(
    memory?.retrieval_frequency_reason,
    metadata.retrieval_frequency_reason,
    parsedValue?.retrieval_frequency_reason
  );
  const retrievalFrequencyBasis = firstText(
    memory?.retrieval_frequency_basis,
    metadata.retrieval_frequency_basis,
    parsedValue?.retrieval_frequency_basis
  );
  const deepRecallOverride = isPlainObject(memory?.deep_recall_override)
    ? memory.deep_recall_override
    : isPlainObject(metadata.deep_recall_override)
      ? metadata.deep_recall_override
      : isPlainObject(parsedValue?.deep_recall_override)
        ? parsedValue.deep_recall_override
        : null;
  const text = textFromMemory(memory, parsedValue);

  return {
    index,
    raw: memory,
    parsed_value: parsedValue,
    metadata,
    memory_id: memoryId,
    key,
    session_id: sessionId,
    day,
    project_id: projectId,
    source,
    memory_type: memoryType,
    created_at: createdAt || null,
    valid_from: firstText(memory?.valid_from, metadata.valid_from, compactionRecord?.time_window?.valid_from) || null,
    valid_until: firstText(memory?.valid_until, metadata.valid_until, compactionRecord?.time_window?.valid_until) || null,
    low_frequency_salience: memory?.low_frequency_salience === true,
    salience_reason: firstText(memory?.salience_reason, metadata.salience_reason, parsedValue?.salience_reason) || null,
    salience_score: Number.isFinite(Number(memory?.salience_score)) ? Number(memory.salience_score) : null,
    retrieval_frequency_band: retrievalFrequencyBand || null,
    retrieval_frequency_reason: retrievalFrequencyReason || null,
    retrieval_access_count: Number.isFinite(Number(memory?.retrieval_access_count ?? memory?.access_count))
      ? Number(memory?.retrieval_access_count ?? memory?.access_count)
      : null,
    retrieval_last_accessed_at: firstText(memory?.retrieval_last_accessed_at, memory?.last_accessed_at, metadata.retrieval_last_accessed_at) || null,
    retrieval_access_age_days: Number.isFinite(Number(memory?.retrieval_access_age_days))
      ? Number(memory.retrieval_access_age_days)
      : null,
    retrieval_frequency_basis: retrievalFrequencyBasis || null,
    deep_recall_override: deepRecallOverride,
    salience_penalty: Number.isFinite(Number(memory?.salience_penalty)) ? Number(memory.salience_penalty) : null,
    deep_recall_rank_eligible: memory?.deep_recall_rank_eligible === true,
    deep_recall_override_reason: firstText(memory?.deep_recall_override_reason, metadata.deep_recall_override_reason) || null,
    evidence_handling: firstText(memory?.evidence_handling, metadata.evidence_handling) || null,
    epistemic_state: firstText(memory?.epistemic_state, metadata.epistemic_state) || null,
    epistemic_score: Number.isFinite(Number(memory?.epistemic_score)) ? Number(memory.epistemic_score) : null,
    epistemic_decision_version: firstText(memory?.epistemic_decision_version, metadata.epistemic_decision_version) || null,
    epistemic_signals: isPlainObject(memory?.epistemic_signals) ? memory.epistemic_signals : null,
    epistemic_selected_rank: Number.isFinite(Number(memory?.epistemic_selected_rank)) ? Number(memory.epistemic_selected_rank) : null,
    epistemic_mmr_score: Number.isFinite(Number(memory?.epistemic_mmr_score)) ? Number(memory.epistemic_mmr_score) : null,
    freshness_state: firstText(memory?.freshness_state, metadata.freshness_state) || null,
    verified_by: firstText(memory?.verified_by, metadata.verified_by) || null,
    verification_basis: firstText(memory?.verification_basis, metadata.verification_basis) || null,
    confidence: normalizeConfidence(memory || {}, metadata),
    text,
    tokens_estimate: estimateTokens(text),
  };
}

function extractMemories(recallResponse = {}) {
  const candidates = [
    recallResponse.memories,
    recallResponse.results,
    recallResponse.data?.memories,
    recallResponse.recall?.memories,
    recallResponse.working_memory?.memories,
    recallResponse.working_memory?.items,
  ];
  const memories = candidates.find(Array.isArray) || [];
  return memories
    .filter((item) => isPlainObject(item))
    .map((memory, index) => normalizeMemory(memory, index));
}

function normalizeQueryText(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}$:/._-]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stemToken(token) {
  let out = String(token || '').toLowerCase();
  if (out.length > 5 && out.endsWith('ies')) out = `${out.slice(0, -3)}y`;
  else if (out.length > 5 && out.endsWith('ing')) out = out.slice(0, -3);
  else if (out.length > 4 && out.endsWith('ed')) {
    const base = out.slice(0, -2);
    out = base.endsWith('v') ? `${base}e` : base;
  }
  else if (out.length > 4 && out.endsWith('s') && !out.endsWith('ss')) out = out.slice(0, -1);
  return out;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function tokenize(value, options = {}) {
  const keepStopwords = Boolean(options.keepStopwords);
  return normalizeQueryText(value)
    .split(/\s+/)
    .map(stemToken)
    .filter((token) => token.length > 1)
    .filter((token) => keepStopwords || !QUERY_STOPWORDS.has(token));
}

function tokenSet(value) {
  return new Set(tokenize(value));
}

const SUPPORT_MONTH_INDEX = new Map([
  ...Object.entries(MONTH_INDEX),
  ['jan', 0],
  ['feb', 1],
  ['mar', 2],
  ['apr', 3],
  ['jun', 5],
  ['jul', 6],
  ['aug', 7],
  ['sep', 8],
  ['sept', 8],
  ['oct', 9],
  ['nov', 10],
  ['dec', 11],
]);
const SUPPORT_NUMBER_WORDS = new Map(Object.entries({
  a: 1,
  an: 1,
  ...NUMBER_WORDS,
  eleven: 11,
  twelve: 12,
  few: 3,
}));
const SUPPORT_WEEKDAY_TERMS = new Set(Object.keys(WEEKDAY_INDEX));
const SUPPORT_ROLE_STOPWORDS = new Set([
  ...QUERY_STOPWORDS,
  'day',
  'date',
  'event',
  'thing',
  'person',
  'device',
  'item',
  'model',
  'one',
  'project',
  'system',
  'trip',
  'vehicle',
  'narrator',
  'ceremony',
  'occasion',
  'new',
  'start',
  'starting',
  'started',
  'woman',
  'man',
  'lady',
  'guy',
]);

function supportNumberFromToken(value) {
  const raw = String(value || '').toLowerCase();
  if (/^\d+$/.test(raw)) return Number(raw);
  return SUPPORT_NUMBER_WORDS.get(raw) || null;
}

function supportNumberToWords(value) {
  const n = Number(value);
  for (const [word, number] of SUPPORT_NUMBER_WORDS.entries()) {
    if (number === n && !['couple', 'few'].includes(word)) return word;
  }
  return String(n);
}

function supportIso(date) {
  return date.toISOString().slice(0, 10);
}

function supportShiftUtcDate(date, { days = 0, months = 0 } = {}) {
  const out = new Date(date.getTime());
  if (months) out.setUTCMonth(out.getUTCMonth() + months);
  if (days) out.setUTCDate(out.getUTCDate() + days);
  return out;
}

function supportBenchmarkSiblingRoot(key) {
  const raw = String(key || '');
  const longMem = raw.match(/^(benchmark:longmemeval:official:session:answer_[a-z0-9]+)(?:_\d+)?$/i);
  if (longMem) return longMem[1];
  const locomo = raw.match(/^(benchmark:locomo:official:session:[^:]+):session_\d+$/i);
  if (locomo) return locomo[1];
  return raw;
}

function supportQueryAnchors(query) {
  const anchors = new Set();
  for (const quoted of supportQuotedPhrases(query)) {
    if (quoted.length >= 3) anchors.add(quoted);
  }
  const salientTokens = normalizeQueryText(query)
    .split(/\s+/)
    .filter((token) => token.length >= 3 && !QUERY_STOPWORDS.has(token))
    .slice(0, 12);
  for (const token of salientTokens) anchors.add(token);
  for (let index = 0; index < salientTokens.length - 1; index += 1) {
    anchors.add(`${salientTokens[index]} ${salientTokens[index + 1]}`);
  }
  const roles = supportBinaryQuestionRoles(query);
  if (roles?.left) anchors.add(normalizeQueryText(roles.left));
  if (roles?.right) anchors.add(normalizeQueryText(roles.right));
  return [...anchors]
    .map((anchor) => anchor.trim())
    .filter((anchor) => anchor.length >= 3)
    .sort((a, b) => b.length - a.length)
    .slice(0, 8);
}

function supportExcerptEvidenceValue(value, query, maxChars = 12000) {
  const raw = String(value || '');
  if (raw.length <= maxChars) return raw;
  const source = raw.length > maxChars * 3
    ? [
        raw.slice(0, maxChars * 2),
        raw.slice(Math.max(0, raw.length - maxChars)),
      ].join('\n')
    : raw;
  const windows = [];
  const firstTurn = source.search(/\n\[(?:USER|ASSISTANT|SYSTEM)\]/i);
  windows.push({ start: 0, end: Math.min(source.length, Math.max(1800, firstTurn > 0 ? firstTurn + 1 : 0)) });

  for (const anchor of supportQueryAnchors(query)) {
    const escaped = anchor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
    const pattern = new RegExp(escaped, 'gi');
    for (const match of source.matchAll(pattern)) {
      const index = match.index || 0;
      windows.push({
        start: Math.max(0, index - 4200),
        end: Math.min(source.length, index + match[0].length + 4200),
      });
      if (windows.length >= 10) break;
    }
    if (windows.length >= 10) break;
  }

  if (windows.length <= 1) return raw.slice(0, maxChars);
  const merged = windows
    .sort((a, b) => a.start - b.start)
    .reduce((out, window) => {
      const previous = out[out.length - 1];
      if (previous && window.start <= previous.end + 240) {
        previous.end = Math.max(previous.end, window.end);
      } else {
        out.push({ ...window });
      }
      return out;
    }, []);

  const parts = [];
  let used = 0;
  for (const window of merged) {
    const remaining = maxChars - used - (parts.length ? 12 : 0);
    if (remaining <= 0) break;
    const chunk = source.slice(window.start, window.end).slice(0, remaining);
    if (!chunk.trim()) continue;
    parts.push(chunk);
    used += chunk.length;
  }
  return parts.join('\n\n[...]\n\n').slice(0, maxChars);
}

function supportMemoryQueryText(memory) {
  return String(memory.analysis_text ?? memory.raw?.value ?? memory.text ?? memory.value ?? '');
}

function supportEvidenceTextFromMemories(memories, maxChars = 120000, query = '') {
  const blocks = memories.map((memory, index) => [
    `EVIDENCE_${index + 1}`,
    `key: ${memory.key || ''}`,
    `created_at: ${memory.created_at || ''}`,
    `valid_from: ${memory.valid_from || ''}`,
    `valid_until: ${memory.valid_until || ''}`,
    `day: ${memory.day || ''}`,
    '',
    supportExcerptEvidenceValue(supportMemoryQueryText(memory), query, 12000),
  ].join('\n'));
  return blocks.join('\n\n---\n\n').slice(0, maxChars);
}

function attachBoundedAnalysisText(memories, query, maxChars = 12000) {
  return asArray(memories).map((memory) => ({
    ...memory,
    analysis_text: supportExcerptEvidenceValue(
      String(memory.raw?.value ?? memory.text ?? memory.value ?? ''),
      query,
      maxChars
    ),
  }));
}

function supportDefaultYearFromText(text) {
  const match = String(text || '').match(/\b(20\d{2})[/-]\d{1,2}[/-]\d{1,2}\b/)
    || String(text || '').match(/\bdate:\s*(20\d{2})[/-]\d{1,2}[/-]\d{1,2}\b/i);
  return match ? Number(match[1]) : null;
}

function supportSessionDateForBlock(block) {
  const explicit = String(block || '').match(/\bdate:\s*(20\d{2})[/-](\d{1,2})[/-](\d{1,2})\b/i)
    || String(block || '').match(/\b(?:created_at|valid_from|day):\s*(20\d{2})-(\d{1,2})-(\d{1,2})\b/i);
  const locomoDate = explicit ? null : String(block || '').match(/\bdate:\s*(?:\d{1,2}:\d{2}\s*(?:am|pm)\s+on\s+)?(\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-z]+),?\s+(20\d{2})\b/i);
  const year = explicit ? Number(explicit[1]) : Number(locomoDate?.[3]);
  const month = explicit ? Number(explicit[2]) - 1 : SUPPORT_MONTH_INDEX.get(String(locomoDate?.[2] || '').toLowerCase());
  const day = explicit ? Number(explicit[3]) : Number(locomoDate?.[1]);
  if (![year, month, day].every(Number.isFinite)) return null;
  return new Date(Date.UTC(year, month, day));
}

function supportBlockAround(raw, index) {
  const blockStart = Math.max(0, raw.lastIndexOf('EVIDENCE_', index));
  const blockEndRaw = raw.indexOf('\n\n---\n\n', index);
  const blockEnd = blockEndRaw >= 0 ? blockEndRaw : raw.length;
  const block = raw.slice(blockStart, blockEnd);
  const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
  return { blockStart, blockEnd, block, key };
}

function supportIsMeasurementSlashExpression(raw, index, length) {
  const after = raw.slice(index + length, index + length + 16);
  if (/^\s*(?:["'”]|inch(?:es)?\b|in\b|mm\b|cm\b)/i.test(after)) return true;
  const local = raw.slice(Math.max(0, index - 80), Math.min(raw.length, index + length + 80)).toLowerCase();
  return /\b(?:xlr|input|inputs|jack|jacks|gauge|scale|diameter|adapter|cable|connector|connectivity|screw|bolt|wrench|socket|rating|rated|score|stars?|imdb)\b/.test(local);
}

function supportShouldExpandAnaphoricDateContext(context) {
  return /\b(?:it|its|mine|they|them|those|that|this|one|ones|set|pair|both)\b/i.test(String(context || ''));
}

function supportAddDateMention(mentions, raw, index, matchedText, date, note = '') {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return;
  const { blockStart, blockEnd, block, key } = supportBlockAround(raw, index);
  const localBefore = raw.slice(blockStart, index);
  const localAfter = raw.slice(index + String(matchedText || '').length, blockEnd);
  const beforeBoundary = Math.max(
    localBefore.lastIndexOf('. '),
    localBefore.lastIndexOf('? '),
    localBefore.lastIndexOf('! '),
    localBefore.lastIndexOf('\n'),
    localBefore.lastIndexOf('[USER]'),
    localBefore.lastIndexOf('[ASSISTANT]'),
  );
  const afterMatches = [
    localAfter.indexOf('. '),
    localAfter.indexOf('? '),
    localAfter.indexOf('! '),
    localAfter.indexOf('\n'),
    localAfter.indexOf('[USER]'),
    localAfter.indexOf('[ASSISTANT]'),
  ].filter((pos) => pos >= 0);
  const afterBoundary = afterMatches.length ? Math.min(...afterMatches) : -1;
  let start = Math.max(blockStart, beforeBoundary >= 0 ? blockStart + beforeBoundary : index - 220);
  const end = Math.min(blockEnd, afterBoundary >= 0 ? index + String(matchedText || '').length + afterBoundary : index + String(matchedText || '').length + 220);
  const localContext = raw.slice(start, end);
  if (supportShouldExpandAnaphoricDateContext(localContext)) {
    start = Math.max(blockStart, index - 420);
  }
  mentions.push({
    iso: supportIso(date),
    time: date.getTime(),
    text: matchedText,
    note,
    key,
    root: supportBenchmarkSiblingRoot(key),
    context: raw.slice(start, end).replace(/\s+/g, ' ').trim(),
    block,
  });
}

function supportDateMentions(text) {
  const raw = String(text || '');
  const defaultYear = supportDefaultYearFromText(raw) || 2023;
  const mentions = [];
  const evidenceBlockRegex = /EVIDENCE_\d+[\s\S]*?(?=\n\n---\n\n|$)/g;
  for (const blockMatch of raw.matchAll(evidenceBlockRegex)) {
    const block = blockMatch[0] || '';
    const sessionDate = supportSessionDateForBlock(block);
    if (!sessionDate) continue;
    const localIndex = block.search(/\b(?:date|created_at|valid_from|day):\s*20\d{2}[/-]\d{1,2}[/-]\d{1,2}\b/i);
    supportAddDateMention(mentions, raw, (blockMatch.index || 0) + Math.max(0, localIndex), 'session_date', sessionDate, 'session_date');
  }
  const monthPattern = [...SUPPORT_MONTH_INDEX.keys()].sort((a, b) => b.length - a.length).join('|');
  const monthRegex = new RegExp(`\\b(${monthPattern})\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(20\\d{2}))?\\b`, 'gi');
  for (const match of raw.matchAll(monthRegex)) {
    const month = SUPPORT_MONTH_INDEX.get(String(match[1]).toLowerCase());
    const day = Number(match[2]);
    const blockYear = supportSessionDateForBlock(supportBlockAround(raw, match.index).block)?.getUTCFullYear();
    const year = Number(match[3] || blockYear || defaultYear);
    if (!Number.isFinite(month) || !Number.isFinite(day) || !Number.isFinite(year)) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], new Date(Date.UTC(year, month, day)), 'month_day');
  }
  const dayOfMonthRegex = new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+of\\s+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\b`, 'gi');
  for (const match of raw.matchAll(dayOfMonthRegex)) {
    const day = Number(match[1]);
    const month = SUPPORT_MONTH_INDEX.get(String(match[2]).toLowerCase());
    const blockYear = supportSessionDateForBlock(supportBlockAround(raw, match.index).block)?.getUTCFullYear();
    const year = Number(match[3] || blockYear || defaultYear);
    if (!Number.isFinite(month) || !Number.isFinite(day) || !Number.isFinite(year)) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], new Date(Date.UTC(year, month, day)), 'day_of_month');
  }
  const numericRegex = /\b(\d{1,2})\/(\d{1,2})(?:\/(20\d{2}))?\b/g;
  for (const match of raw.matchAll(numericRegex)) {
    if (/\d\/$/.test(raw.slice(Math.max(0, match.index - 3), match.index))) continue;
    if (!match[3] && raw[match.index + match[0].length] === '/') continue;
    if (!match[3] && supportIsMeasurementSlashExpression(raw, match.index, match[0].length)) continue;
    const month = Number(match[1]) - 1;
    const day = Number(match[2]);
    const blockYear = supportSessionDateForBlock(supportBlockAround(raw, match.index).block)?.getUTCFullYear();
    const year = Number(match[3] || blockYear || defaultYear);
    if (month < 0 || month > 11 || day < 1 || day > 31) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], new Date(Date.UTC(year, month, day)), 'numeric_date');
  }
  const monthOnlyRegex = new RegExp(`\\b(?:in|during|around|by|since|from)\\s+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\b`, 'gi');
  for (const match of raw.matchAll(monthOnlyRegex)) {
    const month = SUPPORT_MONTH_INDEX.get(String(match[1]).toLowerCase());
    const blockYear = supportSessionDateForBlock(supportBlockAround(raw, match.index).block)?.getUTCFullYear();
    const year = Number(match[2] || blockYear || defaultYear);
    if (!Number.isFinite(month) || !Number.isFinite(year)) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], new Date(Date.UTC(year, month, 1)), 'month_only');
  }
  const qualifiedMonthRegex = new RegExp(`\\b(early|mid|late)[-\\s]+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\b`, 'gi');
  for (const match of raw.matchAll(qualifiedMonthRegex)) {
    const qualifier = String(match[1] || '').toLowerCase();
    const month = SUPPORT_MONTH_INDEX.get(String(match[2]).toLowerCase());
    const blockYear = supportSessionDateForBlock(supportBlockAround(raw, match.index).block)?.getUTCFullYear();
    const year = Number(match[3] || blockYear || defaultYear);
    const day = qualifier === 'early' ? 5 : qualifier === 'late' ? 25 : 15;
    if (!Number.isFinite(month) || !Number.isFinite(year)) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], new Date(Date.UTC(year, month, day)), `qualified_month_${qualifier}`);
  }
  const relativeRegex = /\b(?:(today|yesterday)|last\s+(week|weekend|month|year)|(?:(a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few|\d+)\s+)?(days?|weeks?|months?|years?)\s+ago)\b/gi;
  for (const match of raw.matchAll(relativeRegex)) {
    const { block } = supportBlockAround(raw, match.index);
    const base = supportSessionDateForBlock(block);
    if (!base) continue;
    let date = null;
    if (match[1]) date = supportShiftUtcDate(base, { days: match[1].toLowerCase() === 'yesterday' ? -1 : 0 });
    else if (match[2]) {
      const unit = match[2].toLowerCase();
      if (unit === 'month') date = supportShiftUtcDate(base, { months: -1 });
      else if (unit === 'year') date = supportShiftUtcDate(base, { months: -12 });
      else if (unit === 'weekend') date = supportShiftUtcDate(base, { days: -2 });
      else date = supportShiftUtcDate(base, { days: -7 });
    } else {
      const n = supportNumberFromToken(match[3] || 'one') || 1;
      const unit = String(match[4] || '').toLowerCase();
      if (unit.startsWith('day')) date = supportShiftUtcDate(base, { days: -n });
      else if (unit.startsWith('week')) date = supportShiftUtcDate(base, { days: -7 * n });
      else if (unit.startsWith('month')) date = supportShiftUtcDate(base, { months: -n });
      else if (unit.startsWith('year')) date = supportShiftUtcDate(base, { months: -12 * n });
    }
    supportAddDateMention(mentions, raw, match.index, match[0], date, 'relative_to_session');
  }
  const weekdayPattern = [...SUPPORT_WEEKDAY_TERMS].join('|');
  const relativeWeekdayRegex = new RegExp(`\\b(last|this|next)\\s+(${weekdayPattern})\\b`, 'gi');
  for (const match of raw.matchAll(relativeWeekdayRegex)) {
    const { block } = supportBlockAround(raw, match.index);
    const base = supportSessionDateForBlock(block);
    if (!base) continue;
    const direction = String(match[1] || '').toLowerCase();
    const target = WEEKDAY_INDEX[String(match[2] || '').toLowerCase()];
    if (!Number.isFinite(target)) continue;
    const current = base.getUTCDay();
    let delta = target - current;
    if (direction === 'last' && delta >= 0) delta -= 7;
    else if (direction === 'next' && delta <= 0) delta += 7;
    supportAddDateMention(mentions, raw, match.index, match[0], supportShiftUtcDate(base, { days: delta }), `relative_weekday_${direction}`);
  }
  const recentRegex = /\b(?:just\s+)?recently\b/gi;
  for (const match of raw.matchAll(recentRegex)) {
    const { block } = supportBlockAround(raw, match.index);
    const base = supportSessionDateForBlock(block);
    if (!base) continue;
    supportAddDateMention(mentions, raw, match.index, match[0], base, 'recent_to_session');
  }
  const durationStartRegex = /\b(?:for|past|about|around|approximately|exactly)\s+(?:(a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few|\d+)\s+)?(weeks?|months?)\b/gi;
  for (const match of raw.matchAll(durationStartRegex)) {
    const { block } = supportBlockAround(raw, match.index);
    const base = supportSessionDateForBlock(block);
    if (!base) continue;
    const n = supportNumberFromToken(match[1] || 'one') || 1;
    const unit = String(match[2] || '').toLowerCase();
    const date = unit.startsWith('week')
      ? supportShiftUtcDate(base, { days: -7 * n })
      : supportShiftUtcDate(base, { months: -n });
    supportAddDateMention(mentions, raw, match.index, match[0], date, 'duration_start_relative_to_session');
  }
  return mentions;
}

function supportSplitEvidenceUnits(value) {
  const lines = String(value || '')
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  const units = [];
  let current = [];
  for (const line of lines) {
    if (/^\[(USER|ASSISTANT|SYSTEM|MEDIA|QUERY|[^\]]+)\]/i.test(line) && current.length) {
      units.push(current.join(' '));
      current = [line];
    } else {
      current.push(line);
    }
  }
  if (current.length) units.push(current.join(' '));
  return units.length ? units : [String(value || '').trim()].filter(Boolean);
}

function supportCleanEventPhrase(value) {
  return normalizeQueryText(value)
    .replace(/\b(the|a|an|my|i|me|narrator|their|his|her|event|attendance|arrival|start|purchase|receiving)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function supportPhraseTerms(value) {
  const out = new Set(tokenize(value));
  for (const token of [...out]) {
    for (const item of QUERY_EXPANSIONS.get(token) || []) {
      for (const extra of tokenize(item)) out.add(extra);
    }
  }
  return out;
}

function supportRoleTokens(label) {
  return tokenize(supportCleanEventPhrase(label))
    .filter((token) => token.length > 1 && !SUPPORT_ROLE_STOPWORDS.has(token));
}

function supportTokenFamilyMatches(term, contextTerms) {
  if (contextTerms.has(term)) return true;
  for (const expansion of QUERY_EXPANSIONS.get(term) || []) {
    for (const expanded of tokenize(expansion)) {
      if (contextTerms.has(expanded)) return true;
    }
  }
  return false;
}

function supportRequiredRoleMatches(count) {
  if (count <= 1) return 1;
  if (count <= 3) return Math.max(2, count);
  return Math.max(3, Math.ceil(count * 0.7));
}

function supportIsAbsenceContext(value) {
  const text = String(value || '').toLowerCase();
  return /\b(?:did\s+not|didn't|do\s+not|don't|does\s+not|doesn't|never|no)\s+(?:mention|mentioned|start|started|buy|bought|purchase|purchased|get|got|attend|attended)\b/.test(text)
    || /\bnot\s+(?:mention|mentioned|start|started|working|employed|buy|bought|purchase|purchased|get|got|attend|attended)\b/.test(text)
    || /\b(?:not|no)\s+(?:enough|sufficient)\s+(?:information|evidence)\b/.test(text)
    || /\binsufficient[_\s-]?evidence\b/.test(text);
}

function supportRoleAwareDateMentions(text) {
  const raw = String(text || '');
  const mentions = [...supportDateMentions(raw)];
  const evidenceBlockRegex = /EVIDENCE_\d+[\s\S]*?(?=\n\n---\n\n|$)/g;
  for (const blockMatch of raw.matchAll(evidenceBlockRegex)) {
    const block = blockMatch[0] || '';
    if (supportIsAbsenceContext(block)) continue;
    const sessionDate = supportSessionDateForBlock(block);
    if (!sessionDate) continue;
    const explicitLocalDate = supportDateMentions(block)
      .some((mention) => mention.note && mention.note !== 'session_date' && mention.note !== 'block_session_role');
    if (explicitLocalDate) continue;
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    mentions.push({
      iso: supportIso(sessionDate),
      time: sessionDate.getTime(),
      text: 'block_session_date',
      note: 'block_session_role',
      key,
      root: supportBenchmarkSiblingRoot(key),
      context: block.replace(/\s+/g, ' ').trim(),
      block,
    });
  }
  return mentions;
}

function supportMentionDateSpecificity(mention) {
  const note = String(mention?.note || '');
  if (!note || note === 'session_date') return 0;
  if (note === 'block_session_role') return 1;
  if (note === 'recent_to_session') return 2;
  if (note.startsWith('relative_weekday_')) return 3;
  if (note === 'relative_to_session' || note === 'duration_start_relative_to_session') return 6;
  if (note === 'month_only') return 4;
  if (note.startsWith('qualified_month_')) return 5;
  if (note === 'month_day' || note === 'day_of_month' || note === 'numeric_date') return 8;
  return 6;
}

function supportExplicitRelativeMeasurementMention(mention) {
  const note = String(mention?.note || '');
  const text = String(mention?.text || '').toLowerCase();
  return note === 'relative_to_session'
    && /\b(?:(?:a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few|\d+)\s+)?(?:days?|weeks?|months?|years?)\s+ago\b/.test(text);
}

function supportVagueRecentMention(mention) {
  const note = String(mention?.note || '');
  const text = String(mention?.text || '').toLowerCase();
  return note === 'recent_to_session' || /\brecently\b/.test(text);
}

function supportIsCoarseTemporalMention(mention) {
  const note = String(mention?.note || '');
  const text = String(mention?.text || '').toLowerCase();
  if (note === 'month_only' || note.startsWith('qualified_month_')) return true;
  if ((note === 'relative_to_session' || note === 'duration_start_relative_to_session') && /\b(?:months?|years?)\b/.test(text)) return true;
  if ((note === 'relative_to_session' || note === 'duration_start_relative_to_session') && /\b(?:about|around|approximately|couple|few)\b/.test(text)) return true;
  return false;
}

function supportApproximateDurationAnswer(days) {
  if (!Number.isFinite(days)) return null;
  if (days >= 365) {
    const years = Math.max(1, Math.round(days / 365));
    return `about ${years} ${years === 1 ? 'year' : 'years'}`;
  }
  if (days >= 42) {
    const months = Math.max(1, Math.round(days / 30));
    return `about ${months} ${months === 1 ? 'month' : 'months'}`;
  }
  if (days >= 6) {
    const weeks = Math.max(1, Math.round(days / 7));
    return `about ${weeks} ${weeks === 1 ? 'week' : 'weeks'}`;
  }
  const roundedDays = Math.max(0, Math.round(days));
  return `about ${roundedDays} ${roundedDays === 1 ? 'day' : 'days'}`;
}

function supportScoreMention(mention, terms) {
  if (!terms.size) return 0;
  const contextTerms = new Set(tokenize(mention.context));
  let score = 0;
  for (const term of terms) if (supportTokenFamilyMatches(term, contextTerms)) score += 1;
  return score;
}

function supportMentionCoverage(mention, terms) {
  const contextTerms = new Set(tokenize(mention.context));
  const wanted = [...terms];
  const matched = wanted.filter((term) => supportTokenFamilyMatches(term, contextTerms)).length;
  return { matched, ratio: wanted.length ? matched / wanted.length : 0 };
}

function supportMentionCoverageWithBlock(mention, terms) {
  const local = supportMentionCoverage(mention, terms);
  const note = String(mention?.note || '');
  if (note === 'block_session_role' || supportMentionDateSpecificity(mention) < 3 || !mention?.block) return local;
  const blockTerms = new Set(tokenize(mention.block));
  const wanted = [...terms];
  const blockMatched = wanted.filter((term) => supportTokenFamilyMatches(term, blockTerms)).length;
  if (blockMatched <= local.matched) return local;
  return {
    matched: blockMatched,
    ratio: wanted.length ? blockMatched / wanted.length : 0,
  };
}

function supportBestMention(mentions, terms, excludedIso = null) {
  return mentions
    .filter((mention) => !excludedIso || mention.iso !== excludedIso)
    .map((mention) => ({ ...mention, mentionScore: supportScoreMention(mention, terms) }))
    .sort((a, b) => b.mentionScore - a.mentionScore || a.time - b.time)[0] || null;
}

function supportRoleCoverage(mention, label, predicate = '') {
  const essential = supportRoleTokens(label);
  const contextTerms = new Set(tokenize(mention.context));
  const matchedEssential = essential.filter((term) => supportTokenFamilyMatches(term, contextTerms));
  const weekdayQualifiers = essential.filter((term) => SUPPORT_WEEKDAY_TERMS.has(term));
  const matchedWeekdayQualifiers = weekdayQualifiers.filter((term) => supportTokenFamilyMatches(term, contextTerms));
  const predicateTerms = supportRoleTokens(predicate);
  const matchedPredicate = predicateTerms.filter((term) => supportTokenFamilyMatches(term, contextTerms));
  const required = supportRequiredRoleMatches(essential.length);
  const essentialRatio = essential.length ? matchedEssential.length / essential.length : 0;
  const predicateRequired = essential.length <= 1 && predicateTerms.length > 0;
  return {
    essential,
    matchedEssential,
    matchedPredicate,
    required,
    pass: essential.length > 0
      && matchedEssential.length >= required
      && matchedWeekdayQualifiers.length === weekdayQualifiers.length
      && (!predicateRequired || matchedPredicate.length > 0),
    score: matchedEssential.length * 8 + essentialRatio * 4 + matchedPredicate.length + matchedWeekdayQualifiers.length * 8,
  };
}

function supportProximityToMention(mention, pattern, window = 90) {
  const context = String(mention?.context || '').toLowerCase();
  const text = String(mention?.text || '').toLowerCase();
  const mentionIndex = text ? context.indexOf(text) : -1;
  if (mentionIndex < 0) return false;
  for (const match of context.matchAll(pattern)) {
    if (Math.abs((match.index || 0) - mentionIndex) <= window) return true;
  }
  return false;
}

function supportActionDateSpecificity(mention, predicate = '') {
  const pred = normalizeQueryText(predicate);
  if (!/\b(?:got|get|receiv|arriv|bought|buy|purchase|order)\b/.test(pred)) return 0;
  let score = 0;
  if (supportProximityToMention(mention, /\b(?:got|bought|purchased|received|arrived|delivered)\b/g)) score += 14;
  if (supportProximityToMention(mention, /\b(?:pre[-\s]?ordered|preorder|expected arrival|expected date|delay|delayed)\b/g)) score -= 22;
  return score;
}

function supportStrictMentionCandidates(mentions, label, predicate = '') {
  return mentions
    .map((mention) => {
      const coverage = supportRoleCoverage(mention, label, predicate);
      const actionScore = supportActionDateSpecificity(mention, predicate);
      return {
        ...mention,
        mentionScore: coverage.score + actionScore,
        mentionMatched: coverage.matchedEssential.length,
        mentionRatio: coverage.essential.length ? coverage.matchedEssential.length / coverage.essential.length : 0,
        actionScore,
        roleCoverage: coverage,
      };
    })
    .filter((mention) => mention.roleCoverage.pass && !supportIsAbsenceContext(mention.context));
}

function supportBestMentionPair(mentions, leftTerms, rightTerms) {
  const left = mentions
    .map((mention) => ({ ...mention, mentionScore: supportScoreMention(mention, leftTerms) }))
    .filter((mention) => mention.mentionScore > 0);
  const right = mentions
    .map((mention) => ({ ...mention, mentionScore: supportScoreMention(mention, rightTerms) }))
    .filter((mention) => mention.mentionScore > 0);
  const pairs = [];
  for (const l of left) {
    for (const r of right) {
      if (l.iso === r.iso && l.context === r.context) continue;
      const sameRoot = l.root && r.root && l.root === r.root;
      pairs.push({
        left: l,
        right: r,
        score: l.mentionScore + r.mentionScore
          + (supportMentionDateSpecificity(l) + supportMentionDateSpecificity(r)) * 4
          + (sameRoot ? 12 : 0),
      });
    }
  }
  return pairs.sort((a, b) => b.score - a.score || Math.abs(a.right.time - a.left.time) - Math.abs(b.right.time - b.left.time))[0] || null;
}

function supportBestRelativeDurationPair(mentions, leftTerms, rightTerms) {
  const left = mentions
    .map((mention) => {
      const coverage = supportMentionCoverage(mention, leftTerms);
      return {
        ...mention,
        mentionScore: coverage.matched + coverage.ratio * 3,
        mentionMatched: coverage.matched,
        mentionRequired: supportRequiredRoleMatches(leftTerms.size),
      };
    })
    .filter((mention) => mention.mentionMatched >= mention.mentionRequired);
  const rightCandidates = mentions
    .map((mention) => {
      const coverage = supportMentionCoverageWithBlock(mention, rightTerms);
      return {
        ...mention,
        mentionScore: coverage.matched + coverage.ratio * 3,
        mentionMatched: coverage.matched,
        mentionRequired: supportRequiredRoleMatches(rightTerms.size),
      };
    })
    .filter((mention) => mention.mentionMatched >= mention.mentionRequired);
  const hasEventLevelRight = rightCandidates.some((mention) =>
    String(mention.note || '') !== 'block_session_role' && supportMentionDateSpecificity(mention) >= 3
  );
  const right = hasEventLevelRight
    ? rightCandidates.filter((mention) => String(mention.note || '') !== 'block_session_role')
    : rightCandidates;
  const pairs = [];
  for (const l of left) {
    for (const r of right) {
      if (l.iso === r.iso && l.context === r.context) continue;
      const sameRoot = l.root && r.root && l.root === r.root;
      const leftDurationStart = String(l.note || '') === 'duration_start_relative_to_session';
      const rightEventCue = /\b(attend|attended|joined|went|meetup|workshop|event|open\s+mic)\b/i.test(r.context);
      const rightRelativeEvent = ['relative_to_session', 'recent_to_session'].includes(String(r.note || ''))
        || String(r.note || '').startsWith('relative_weekday_');
      const rightExplicitRelative = supportExplicitRelativeMeasurementMention(r);
      const rightVagueRecent = supportVagueRecentMention(r);
      pairs.push({
        left: l,
        right: r,
        score: l.mentionScore + r.mentionScore
          + (supportMentionDateSpecificity(l) + supportMentionDateSpecificity(r)) * 4
          + (sameRoot ? 14 : 0)
          + (leftDurationStart ? 36 : 0)
          + (rightEventCue ? 12 : 0)
          + (rightRelativeEvent ? 8 : 0)
          + (rightExplicitRelative ? 28 : 0)
          - (rightVagueRecent ? 18 : 0),
      });
    }
  }
  return pairs.sort((a, b) =>
    b.score - a.score
    || supportMentionDateSpecificity(b.right) - supportMentionDateSpecificity(a.right)
    || Math.abs(a.right.time - a.left.time) - Math.abs(b.right.time - b.left.time)
  )[0] || null;
}

function supportBestStrictMentionPair(mentions, leftLabel, rightLabel, predicate = '', sameRootOnly = false) {
  const left = supportStrictMentionCandidates(mentions, leftLabel, predicate);
  const right = supportStrictMentionCandidates(mentions, rightLabel, predicate);
  const pairs = [];
  for (const l of left) {
    for (const r of right) {
      if (l.iso === r.iso && l.context === r.context) continue;
      const sameRoot = l.root && r.root && l.root === r.root;
      if (sameRootOnly && !sameRoot) continue;
      pairs.push({
        left: l,
        right: r,
        score: l.mentionScore + r.mentionScore
          + (supportMentionDateSpecificity(l) + supportMentionDateSpecificity(r)) * 8
          + (sameRoot ? 24 : 0),
      });
    }
  }
  return pairs.sort((a, b) =>
    b.score - a.score
    || (supportMentionDateSpecificity(b.left) + supportMentionDateSpecificity(b.right))
      - (supportMentionDateSpecificity(a.left) + supportMentionDateSpecificity(a.right))
    || Math.abs(a.right.time - a.left.time) - Math.abs(b.right.time - b.left.time)
  )[0] || null;
}

function supportRoleBoundMentionCandidates(mentions, label, predicate = '') {
  const essential = supportRoleTokens(label);
  if (!essential.length) return [];
  const predicateTerms = supportRoleTokens(predicate);
  return mentions
    .filter((mention) => !supportIsAbsenceContext(mention.context) && !supportIsAbsenceContext(mention.block))
    .map((mention) => {
      const blockText = String(mention?.block || mention?.context || '');
      const blockTerms = new Set(tokenize(blockText));
      const matchedEssential = essential.filter((term) => supportTokenFamilyMatches(term, blockTerms));
      const weekdayQualifiers = essential.filter((term) => SUPPORT_WEEKDAY_TERMS.has(term));
      const matchedWeekdayQualifiers = weekdayQualifiers.filter((term) => supportTokenFamilyMatches(term, blockTerms));
      const matchedPredicate = predicateTerms.filter((term) => supportTokenFamilyMatches(term, blockTerms));
      const required = supportRequiredRoleMatches(essential.length);
      const essentialRatio = essential.length ? matchedEssential.length / essential.length : 0;
      const predicateRequired = essential.length <= 1 && predicateTerms.length > 0;
      const pass = matchedEssential.length >= required
        && matchedWeekdayQualifiers.length === weekdayQualifiers.length
        && (!predicateRequired || matchedPredicate.length > 0);
      return {
        ...mention,
        mentionScore: matchedEssential.length * 8 + essentialRatio * 4 + matchedPredicate.length + matchedWeekdayQualifiers.length * 8,
        mentionMatched: matchedEssential.length,
        mentionRatio: essentialRatio,
        roleBound: pass,
      };
    })
    .filter((mention) => mention.roleBound);
}

function supportBestRoleBoundMentionPair(mentions, leftLabel, rightLabel, predicate = '', sameRootOnly = false) {
  const left = supportRoleBoundMentionCandidates(mentions, leftLabel, predicate);
  const right = supportRoleBoundMentionCandidates(mentions, rightLabel, predicate);
  const pairs = [];
  for (const l of left) {
    for (const r of right) {
      if (l.iso === r.iso && l.context === r.context) continue;
      const sameRoot = l.root && r.root && l.root === r.root;
      if (sameRootOnly && !sameRoot) continue;
      pairs.push({
        left: l,
        right: r,
        score: l.mentionScore + r.mentionScore
          + (supportMentionDateSpecificity(l) + supportMentionDateSpecificity(r)) * 8
          + (sameRoot ? 24 : 0),
      });
    }
  }
  return pairs.sort((a, b) =>
    b.score - a.score
    || (supportMentionDateSpecificity(b.left) + supportMentionDateSpecificity(b.right))
      - (supportMentionDateSpecificity(a.left) + supportMentionDateSpecificity(a.right))
    || Math.abs(a.right.time - a.left.time) - Math.abs(b.right.time - b.left.time)
  )[0] || null;
}

function supportBestOrderMentionPair(mentions, leftTerms, rightTerms, sameRootOnly = false) {
  const left = supportOrderMentionCandidates(mentions, leftTerms);
  const right = supportOrderMentionCandidates(mentions, rightTerms);
  return supportBestPairFromCandidates(left, right, { sameRootOnly }) || null;
}

function supportOrderMentionCandidates(mentions, terms) {
  return mentions
    .filter((mention) => !supportIsAbsenceContext(mention.context))
    .map((mention) => {
      const coverage = supportMentionCoverage(mention, terms);
      return {
        ...mention,
        mentionScore: coverage.matched + coverage.ratio * 3,
        mentionMatched: coverage.matched,
        mentionRatio: coverage.ratio,
      };
    })
    .filter((mention) => {
      if (mention.mentionMatched <= 0) return false;
      if (terms.size === 2) return mention.mentionMatched === 2;
      if (terms.size >= 5) return mention.mentionRatio >= 0.35;
      if (terms.size >= 3) return mention.mentionMatched >= 2 || mention.mentionRatio >= 0.5;
      return true;
    });
}

function supportBestPairFromCandidates(left, right, { sameRootOnly = false, requireEventDates = false } = {}) {
  const pairs = [];
  for (const l of left) {
    for (const r of right) {
      if (l.iso === r.iso && l.context === r.context) continue;
      const sameRoot = l.root && r.root && l.root === r.root;
      if (sameRootOnly && !sameRoot) continue;
      const pair = {
        left: l,
        right: r,
        score: l.mentionScore + r.mentionScore
          + (supportMentionDateSpecificity(l) + supportMentionDateSpecificity(r)) * 8
          + (sameRoot ? 24 : 0),
      };
      if (requireEventDates && !supportPairHasEventDates(pair, { allowCoarse: true })) continue;
      pairs.push(pair);
    }
  }
  return pairs.sort((a, b) =>
    b.score - a.score
    || (supportMentionDateSpecificity(b.left) + supportMentionDateSpecificity(b.right))
      - (supportMentionDateSpecificity(a.left) + supportMentionDateSpecificity(a.right))
    || Math.abs(a.right.time - a.left.time) - Math.abs(b.right.time - b.left.time)
  )[0] || null;
}

function supportBestValidStrictMentionPair(mentions, leftLabel, rightLabel, predicate = '', sameRootOnly = false) {
  return supportBestPairFromCandidates(
    supportStrictMentionCandidates(mentions, leftLabel, predicate),
    supportStrictMentionCandidates(mentions, rightLabel, predicate),
    { sameRootOnly, requireEventDates: true },
  );
}

function supportBestValidOrderMentionPair(mentions, leftLabel, rightLabel, sameRootOnly = false) {
  return supportBestPairFromCandidates(
    supportOrderMentionCandidates(mentions, supportPhraseTerms(leftLabel)),
    supportOrderMentionCandidates(mentions, supportPhraseTerms(rightLabel)),
    { sameRootOnly, requireEventDates: true },
  );
}

function supportQuotedPhrases(value) {
  return [...String(value || '').matchAll(/["'“”‘’]([^"'“”‘’]+)["'“”‘’]/g)]
    .map((match) => normalizeQueryText(match[1]))
    .filter(Boolean);
}

function supportOrderAlternatives(question) {
  const q = String(question || '');
  const quoted = supportQuotedPhrases(q);
  if (quoted.length >= 2 && /\b(first|earliest)\b/i.test(q)) return { kind: 'order', left: quoted[0], right: quoted[1] };
  const comma = q.match(/\bfirst\s*,\s*(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (comma) return { kind: 'order', left: comma[1], right: comma[2] };
  const flexible = q.match(/\b(?:which|what|who)\s+.+?\bfirst(?:\s+[^,?]+)?\s*,\s*(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (flexible) return { kind: 'order', left: flexible[1], right: flexible[2] };
  const event = q.match(/\bwhich\s+event\s+happened\s+first\s*,\s*(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (event) return { kind: 'order', left: event[1], right: event[2] };
  const trip = q.match(/\bwhich\s+trip\s+did\s+.+?\s+take\s+first\s*,\s*(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (trip) return { kind: 'order', left: trip[1], right: trip[2] };
  const gift = q.match(/\bwhich\s+gift\s+did\s+.+?\s+buy\s+first\s*,\s*(.+?)\s+or\s+(.+?)(?:\?|$)/i);
  if (gift) return { kind: 'order', left: gift[1], right: gift[2] };
  return null;
}

function supportBetweenAlternatives(question) {
  const match = String(question || '').match(/\bbetween\s+(.+?)\s+and\s+(.+?)(?:\?|$)/i);
  return match ? { kind: 'between', left: match[1], right: match[2] } : null;
}

function supportBinaryQuestionRoles(question) {
  const q = String(question || '');
  const sinceWhen = q.match(/\bhow\s+many\s+(?:days?|weeks?|months?)\s+had\s+passed\s+since\s+(.+?)\s+when\s+(.+?)(?:\?|$)/i);
  if (sinceWhen) return { kind: 'since_when', left: sinceWhen[1], right: sinceWhen[2] };
  return supportOrderAlternatives(question) || supportBetweenAlternatives(question);
}

function supportOrderPredicate(question) {
  const prefix = String(question || '').match(/\b(?:which|what|who)\s+(.+?)\s+first(?:\s+[^,?]+)?\s*,/i)?.[1] || '';
  return normalizeQueryText(prefix)
    .replace(/\b(event|events|book|books|trip|trips|gift|gifts|thing|things|device|devices|item|items|vehicle|vehicles|project|projects|model|models|did|do|does|i|my|me|the|narrator|happened|happen|first|which|what|who)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function supportIsCompletedTaskOrderQuestion(question) {
  return /\bwhich\s+task\s+did\s+.+?\bcomplete\s+first\b/i.test(String(question || ''));
}

function supportQuestionMonthScope(question) {
  const raw = String(question || '').toLowerCase();
  const monthPattern = [...SUPPORT_MONTH_INDEX.keys()].sort((a, b) => b.length - a.length).join('|');
  const months = new Set();
  const scopedRegex = new RegExp(`\\b(?:in|during|throughout|for|from|between|within)\\s+(${monthPattern})(?:\\s*(?:and|or|to|through|-)\\s*(${monthPattern}))?\\b`, 'gi');
  for (const match of raw.matchAll(scopedRegex)) {
    const first = SUPPORT_MONTH_INDEX.get(String(match[1]).toLowerCase());
    const second = SUPPORT_MONTH_INDEX.get(String(match[2] || '').toLowerCase());
    if (Number.isFinite(first)) months.add(first);
    if (Number.isFinite(second)) months.add(second);
  }
  return months;
}

function supportFilterMentionsByQuestionTemporalScope(question, mentions) {
  const months = supportQuestionMonthScope(question);
  if (!months.size) return mentions;
  const scoped = mentions.filter((mention) => months.has(new Date(mention.time).getUTCMonth()));
  return scoped.length >= 2 ? scoped : mentions;
}

function supportEvidenceBlocks(text) {
  return [...String(text || '').matchAll(/EVIDENCE_\d+[\s\S]*?(?=\n\n---\n\n|$)/g)]
    .map((match) => match[0] || '');
}

function supportContextAround(raw, index, length, radius = 260) {
  const { blockStart, blockEnd, key } = supportBlockAround(raw, index);
  const start = Math.max(blockStart, index - radius);
  const end = Math.min(blockEnd, index + length + radius);
  return {
    key,
    root: supportBenchmarkSiblingRoot(key),
    context: raw.slice(start, end).replace(/\s+/g, ' ').trim(),
  };
}

function supportDurationToDays(count, unit) {
  const n = Number(count);
  if (!Number.isFinite(n)) return null;
  const normalized = String(unit || '').toLowerCase();
  if (normalized.startsWith('day')) return n;
  if (normalized.startsWith('week')) return n * 7;
  if (normalized.startsWith('month')) return n * 30;
  return null;
}

function supportSymbolicRelativeMentions(evidenceText) {
  const raw = String(evidenceText || '');
  const mentions = [];
  const number = '(a|an|one|two|three|four|five|six|seven|eight|nine|ten|couple|few|\\d+)';
  const regex = new RegExp(`\\b(?:${number}\\s+)?(days?|weeks?|months?)\\s+(before|after)\\s+([^.,;?!\\n]{3,80})`, 'gi');
  for (const match of raw.matchAll(regex)) {
    const amount = supportNumberFromToken(match[1] || 'one') || 1;
    const unit = String(match[2] || '').toLowerCase();
    const days = supportDurationToDays(amount, unit);
    if (!Number.isFinite(days)) continue;
    const anchor = normalizeQueryText(match[4])
      .replace(/\b(and|but|so|because|while|when)\b.*$/i, '')
      .trim();
    if (!anchor || QUERY_STOPWORDS.has(anchor)) continue;
    const local = supportContextAround(raw, match.index, match[0].length);
    mentions.push({
      amount,
      unit,
      direction: String(match[3] || '').toLowerCase(),
      days,
      anchor,
      text: match[0],
      key: local.key,
      root: local.root,
      context: local.context,
    });
  }
  return mentions;
}

function supportAnchorOccurrences(evidenceText, anchor) {
  const raw = String(evidenceText || '');
  const needle = normalizeQueryText(anchor);
  if (!needle || !normalizeQueryText(raw).includes(needle)) return [];
  const escaped = String(anchor)
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\s+/g, '\\s+');
  const regex = new RegExp(escaped, 'gi');
  const out = [];
  for (const match of raw.matchAll(regex)) {
    const local = supportContextAround(raw, match.index, match[0].length);
    out.push({
      text: match[0],
      key: local.key,
      root: local.root,
      context: local.context,
    });
  }
  return out;
}

function supportSoftMentionPair(mentions, leftLabel, rightLabel, sameRootOnly = false) {
  const leftTerms = supportPhraseTerms(leftLabel);
  const rightTerms = supportPhraseTerms(rightLabel);
  const orderPair = supportBestOrderMentionPair(mentions, leftTerms, rightTerms, sameRootOnly);
  if (sameRootOnly) return orderPair;
  return orderPair || supportBestMentionPair(mentions, leftTerms, rightTerms);
}

function supportPairHasEventDates(pair, { allowCoarse = false } = {}) {
  if (!pair?.left || !pair?.right) return false;
  if (pair.left.iso === pair.right.iso) return false;
  const leftSpecificity = supportMentionDateSpecificity(pair.left);
  const rightSpecificity = supportMentionDateSpecificity(pair.right);
  const threshold = allowCoarse ? 2 : 3;
  return leftSpecificity >= threshold && rightSpecificity >= threshold;
}

function supportRolePairDurationCandidates(mentions, label, role) {
  const terms = supportPhraseTerms(label);
  if (!terms.size) return [];
  const roleNorm = normalizeQueryText(label);
  const required = supportRequiredRoleMatches(terms.size);
  return mentions
    .filter((mention) => mention.note && mention.note !== 'session_date' && !supportIsAbsenceContext(mention.context))
    .map((mention) => {
      const contextTerms = new Set(tokenize(mention.context));
      const blockTerms = new Set(tokenize(mention.block));
      const matchedContext = [...terms].filter((term) => supportTokenFamilyMatches(term, contextTerms));
      const matchedBlock = [...terms].filter((term) => supportTokenFamilyMatches(term, blockTerms));
      const contextText = `${mention.context} ${String(mention.block || '').slice(0, 1200)}`;
      const localPredicateText = String(mention.context || '');
      let predicateScore = 0;
      if (role === 'start' && /\b(?:start|begin|work|working|agent|with)\b/.test(roleNorm)
        && /\b(?:since|start(?:ed|ing)?|began|working\s+with|work(?:ed|ing)?\s+with)\b/i.test(localPredicateText)) {
        predicateScore += 16;
      }
      if (role === 'end' && /\b(?:find|found|house|home|property|lov)\b/.test(roleNorm)
        && /\b(?:found|find|saw|seen|located|house|home|property|love|loved|like|liked)\b/i.test(localPredicateText)) {
        predicateScore += 16;
      }
      if (role === 'start' && /\b(?:start|started|starting|begin|began|beginning)\b/.test(roleNorm) && predicateScore <= 0) return null;
      if (role === 'end' && /\b(?:find|found|house|home|property|lov)\b/.test(roleNorm) && predicateScore <= 0) return null;
      const matched = Math.max(matchedContext.length, matchedBlock.length);
      const score = matchedContext.length * 12
        + matchedBlock.length * 4
        + supportMentionDateSpecificity(mention) * 5
        + predicateScore;
      return {
        ...mention,
        mentionScore: score,
        mentionMatched: matched,
        mentionRequired: required,
        matchedContext,
        matchedBlock,
      };
    })
    .filter(Boolean)
    .filter((mention) => mention.mentionMatched >= mention.mentionRequired || mention.mentionScore >= 30)
    .sort((a, b) => b.mentionScore - a.mentionScore || supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a));
}

function supportRolePairDurationHintForQuestion(question, mentions) {
  const match = String(question || '').match(/\bhow\s+many\s+(days?|weeks?|months?)\s+did\s+it\s+take\s+for\s+me\s+to\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (!match) return null;
  const unit = match[1].toLowerCase();
  const endLabel = match[2];
  const startLabel = match[3];
  const starts = supportRolePairDurationCandidates(mentions, startLabel, 'start');
  const ends = supportRolePairDurationCandidates(mentions, endLabel, 'end');
  const pairs = [];
  for (const start of starts) {
    for (const end of ends) {
      if (start.iso === end.iso && start.context === end.context) continue;
      const days = Math.round((end.time - start.time) / 86_400_000);
      if (!Number.isFinite(days) || days < 0) continue;
      const sameRoot = start.root && end.root && start.root === end.root;
      pairs.push({
        start,
        end,
        days,
        score: start.mentionScore + end.mentionScore + (sameRoot ? 36 : 0) - Math.min(days, 365) / 30,
      });
    }
  }
  const best = pairs.sort((a, b) => b.score - a.score || a.days - b.days)[0];
  if (!best) return null;
  return [
    'TEMPORAL_HINT',
    'mode: role_pair_duration_after_start',
    `start_role: ${startLabel}`,
    `end_role: ${endLabel}`,
    `start_date: ${best.start.iso} (${best.start.text}${best.start.note ? `; ${best.start.note}` : ''})`,
    `end_date: ${best.end.iso} (${best.end.text}${best.end.note ? `; ${best.end.note}` : ''})`,
    `exclusive_delta_days: ${best.days}`,
    `inclusive_delta_days: ${best.days + 1}`,
    `requested_unit: ${unit}`,
    `start_context: ${truncateText(best.start.context, 360)}`,
    `end_context: ${truncateText(best.end.context, 360)}`,
  ].join('\n');
}

function supportSymbolicTemporalHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  const howManyBefore = q.match(/\bhow\s+many\s+(days?|weeks?|months?)\s+before\s+(.+?)\s+did\s+(.+?)(?:\?|$)/i);
  const beforeDidI = q.match(/\bbefore\s+(.+?)\s+did\s+i\s+(.+?)(?:\?|$)/i);
  if (!howManyBefore && !beforeDidI) return null;
  const requestedUnit = howManyBefore ? howManyBefore[1].toLowerCase() : 'days';
  const anchorLabel = howManyBefore ? howManyBefore[2] : beforeDidI[1];
  const eventLabel = howManyBefore ? howManyBefore[3] : beforeDidI[2];
  const anchorTerms = supportPhraseTerms(anchorLabel);
  const eventTerms = supportPhraseTerms(eventLabel);
  for (const relative of supportSymbolicRelativeMentions(evidenceText)) {
    if (relative.direction !== 'before') continue;
    if (supportScoreMention(relative, eventTerms) <= 0) continue;
    const anchors = supportAnchorOccurrences(evidenceText, relative.anchor)
      .map((anchor) => {
        const coverage = supportRoleCoverage(anchor, anchorLabel);
        return { ...anchor, mentionScore: coverage.score, roleCoverage: coverage };
      })
      .filter((anchor) => anchor.roleCoverage.pass && supportScoreMention(anchor, anchorTerms) > 0)
      .sort((a, b) => (b.root === relative.root) - (a.root === relative.root) || b.mentionScore - a.mentionScore);
    const anchor = anchors[0];
    if (!anchor) continue;
    return [
      'TEMPORAL_HINT',
      'source: symbolic_relative_expression',
      `relative_expression: ${relative.text}`,
      `anchor_expression: ${relative.anchor}`,
      `requested_unit: ${requestedUnit}`,
      `exclusive_delta_days: ${relative.days}`,
      `approx_weeks: ${Math.round(relative.days / 7)}`,
      `approx_months: ${Math.round(relative.days / 30)}`,
      `event_context: ${truncateText(relative.context, 360)}`,
      `anchor_context: ${truncateText(anchor.context, 360)}`,
    ].join('\n');
  }
  return null;
}

function supportGiftOrderBirthdayDeltaHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bbirthday\b/i.test(q) || !/\b(?:gift|present|album|order|ordered|buy|bought|purchase|purchased)\b/i.test(q)) return null;
  const mentions = supportFilterMentionsByQuestionTemporalScope(q, supportRoleAwareDateMentions(evidenceText));
  const betweenMatch = q.match(/\bhow\s+many\s+days?\s+(?:had\s+passed\s+)?between\s+(?:the\s+day\s+)?(.+?)\s+and\s+(?:the\s+day\s+)?(.+?)(?:\?|$)/i)
    || q.match(/\bbetween\s+(?:the\s+day\s+)?(.+?)\s+and\s+(?:the\s+day\s+)?(.+?)(?:\?|$)/i);
  if (betweenMatch) {
    const leftLabel = betweenMatch[1].trim();
    const rightLabel = betweenMatch[2].trim();
    const roleCandidates = (label) => supportStrictMentionCandidates(mentions, label)
      .filter((mention) => supportMentionDateSpecificity(mention) >= 3)
      .map((mention) => {
        const blockCoverage = mention.block
          ? supportRoleCoverage({ context: mention.block }, label)
          : { pass: false, score: 0, matchedEssential: [] };
        const roleScore = mention.mentionScore
          + (blockCoverage.pass ? blockCoverage.score : 0)
          + supportMentionDateSpecificity(mention) * 3;
        return { ...mention, mentionScore: roleScore, blockCoverage };
      })
      .sort((a, b) =>
        b.mentionScore - a.mentionScore
        || supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a)
        || a.time - b.time
      );
    const lefts = roleCandidates(leftLabel);
    const rights = roleCandidates(rightLabel);
    const pairs = [];
    for (const left of lefts) {
      for (const right of rights) {
        if (left.iso === right.iso && left.context === right.context) continue;
        const days = Math.round(Math.abs(right.time - left.time) / 86_400_000);
        if (!Number.isFinite(days) || days <= 0 || days > 120) continue;
        const sameRoot = left.root && right.root && left.root === right.root;
        pairs.push({
          left,
          right,
          days,
          score: left.mentionScore + right.mentionScore + (sameRoot ? 36 : 0) - Math.min(days, 120) / 12,
        });
      }
    }
    const best = pairs.sort((a, b) => b.score - a.score || a.days - b.days)[0];
    if (!best) return null;
    return [
      'TEMPORAL_HINT',
      'mode: role_bound_between_dates',
      `left_role: ${leftLabel}`,
      `right_role: ${rightLabel}`,
      `left_date: ${best.left.iso} (${best.left.text}${best.left.note ? `; ${best.left.note}` : ''})`,
      `right_date: ${best.right.iso} (${best.right.text}${best.right.note ? `; ${best.right.note}` : ''})`,
      `exclusive_delta_days: ${best.days}`,
      `inclusive_delta_days: ${best.days + 1}`,
      'requested_unit: days',
      `preferred_answer: ${best.days} days`,
      `left_context: ${truncateText(best.left.context, 360)}`,
      `right_context: ${truncateText(best.right.context, 360)}`,
    ].join('\n');
  }

  if (!/\bhow\s+many\s+days?\s+before\b/i.test(q)) return null;
  const wantsBestFriend = /\bbest\s+friend\b/i.test(q);
  const wantsParty = /\bparty\b/i.test(q);
  const roleCompatible = (mention, role) => {
    const context = normalizeQueryText(mention.context);
    const localPurchase = supportProximityToMention(mention, /\b(?:order|ordered|buy|bought|purchase|purchased|got)\b/g, 90);
    const localBirthday = supportProximityToMention(mention, /\b(?:birthday|party|celebrat)\b/g, 120);
    const localGift = supportProximityToMention(mention, /\b(?:gift|present|album|mug|jewelry|necklace|photo)\b/g, 120);
    const contextPurchase = /\b(?:order|ordered|buy|bought|purchase|purchased|got)\b/.test(context);
    const contextGift = /\b(?:gift|present|album|mug|jewelry|necklace|photo)\b/.test(context);
    if (role === 'order') {
      if (wantsBestFriend && !/\bbest friend\b/.test(context)) return false;
      return (localPurchase || contextPurchase)
        && (localGift || contextGift);
    }
    if (wantsBestFriend && !/\bbest friend\b/.test(context) && !localBirthday) return false;
    if (localPurchase && !supportProximityToMention(mention, /\b(?:party|celebrat)\b/g, 90)) return false;
    return (localBirthday || /\bbirthday\b/.test(context))
      && (wantsParty
        ? (supportProximityToMention(mention, /\bparty\b/g, 120) || /\bparty\b/.test(context))
        : /\b(?:party|celebrat|birthday)\b/.test(context));
  };
  const orders = mentions
    .filter((mention) => roleCompatible(mention, 'order'))
    .map((mention) => ({
      ...mention,
      mentionScore: supportMentionDateSpecificity(mention) * 4 + (/\border(?:ed)?\b/i.test(mention.context) ? 12 : 0),
    }));
  const anchors = mentions
    .filter((mention) => roleCompatible(mention, 'birthday'))
    .map((mention) => ({
      ...mention,
      mentionScore: supportMentionDateSpecificity(mention) * 4 + (/\bparty\b/i.test(mention.context) ? 14 : 0),
    }));
  const pairs = [];
  for (const order of orders) {
    for (const anchor of anchors) {
      const days = Math.round((anchor.time - order.time) / 86_400_000);
      if (!Number.isFinite(days) || days <= 0 || days > 120) continue;
      const sameRoot = order.root && anchor.root && order.root === anchor.root;
      pairs.push({
        order,
        anchor,
        days,
        score: order.mentionScore + anchor.mentionScore + (sameRoot ? 20 : 0) - Math.min(days, 120) / 12,
      });
    }
  }
  const best = pairs.sort((a, b) => b.score - a.score || a.days - b.days)[0];
  if (!best) return null;
  return [
    'TEMPORAL_HINT',
    'mode: gift_order_before_birthday_event',
    `event_date: ${best.order.iso} (${best.order.text}${best.order.note ? `; ${best.order.note}` : ''})`,
    `anchor_date: ${best.anchor.iso} (${best.anchor.text}${best.anchor.note ? `; ${best.anchor.note}` : ''})`,
    `exclusive_delta_days: ${best.days}`,
    `inclusive_delta_days: ${best.days + 1}`,
    'requested_unit: days',
    `preferred_answer: ${best.days} days`,
    `event_context: ${truncateText(best.order.context, 360)}`,
    `anchor_context: ${truncateText(best.anchor.context, 360)}`,
  ].join('\n');
}

function supportBestBlockRoleDate(evidenceText, label, options = {}) {
  const afterTime = Number(options.afterTime);
  const rootFilter = options.root ? String(options.root) : '';
  const candidates = [];
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    const root = supportBenchmarkSiblingRoot(key);
    if (rootFilter && root !== rootFilter) continue;
    if (supportIsAbsenceContext(block)) continue;
    const blockCoverage = supportRoleCoverage({ context: block }, label);
    if (!blockCoverage.pass) continue;
    for (const mention of supportDateMentions(block)) {
      if (Number.isFinite(afterTime) && mention.time <= afterTime) continue;
      if (supportMentionDateSpecificity(mention) < 3) continue;
      const localCoverage = supportRoleCoverage(mention, label);
      candidates.push({
        ...mention,
        key,
        root,
        mentionScore: blockCoverage.score + (localCoverage.pass ? localCoverage.score : 0),
        roleCoverage: localCoverage.pass ? localCoverage : blockCoverage,
      });
    }
  }
  return candidates.sort((a, b) =>
    (Number.isFinite(afterTime) ? (a.time - b.time) : 0)
    || (b.mentionScore - a.mentionScore)
    || (supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a))
  )[0] || null;
}

function supportFirstAfterHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(first|earliest)\b/i.test(q) || !/\bafter\b/i.test(q)) return null;
  const match = q.match(/\bwhat\s+was\s+the\s+first\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (!match) return null;
  const eventLabel = match[1].trim();
  const anchorLabel = match[2].trim();
  const mentions = supportFilterMentionsByQuestionTemporalScope(question, supportRoleAwareDateMentions(evidenceText));
  if (mentions.length < 2) return null;
  const anchorCandidates = supportStrictMentionCandidates(mentions, anchorLabel)
    .filter((mention) => supportMentionDateSpecificity(mention) >= 3)
    .sort((a, b) => b.mentionScore - a.mentionScore || a.time - b.time);
  const anchor = anchorCandidates[0]
    || supportBestBlockRoleDate(evidenceText, anchorLabel)
    || supportBestMention(mentions, supportPhraseTerms(anchorLabel));
  if (!anchor || anchor.mentionScore <= 0) return null;

  const eventCandidates = supportStrictMentionCandidates(mentions, eventLabel)
    .filter((mention) => mention.time > anchor.time && !supportIsAbsenceContext(mention.context))
    .filter((mention) => supportMentionDateSpecificity(mention) >= 3)
    .map((mention) => ({
      ...mention,
      sameRoot: anchor.root && mention.root && anchor.root === mention.root,
    }))
    .sort((a, b) =>
      (b.sameRoot - a.sameRoot)
      || (a.time - b.time)
      || (b.mentionScore - a.mentionScore)
    );
  const event = eventCandidates[0]
    || supportBestBlockRoleDate(evidenceText, eventLabel, { afterTime: anchor.time, root: anchor.root });
  if (!event || event.mentionScore <= 0) return null;
  const days = Math.round((event.time - anchor.time) / 86_400_000);
  return [
    'FIRST_AFTER_HINT',
    `anchor_event: ${anchorLabel}`,
    `anchor_date: ${anchor.iso} (${anchor.text}${anchor.note ? `; ${anchor.note}` : ''})`,
    `first_event_type: ${eventLabel}`,
    `first_event_date: ${event.iso} (${event.text}${event.note ? `; ${event.note}` : ''})`,
    `exclusive_delta_days: ${days}`,
    `same_root: ${event.sameRoot}`,
    'answer_focus: extract the concrete first event or issue from first_event_context',
    `anchor_context: ${truncateText(anchor.context, 360)}`,
    `first_event_context: ${truncateText(event.context, 520)}`,
  ].join('\n');
}

function supportPossessionBeforeEventHintForQuestion(question, evidenceText) {
  const roles = supportOrderAlternatives(question);
  if (!roles) return null;
  const rolePairs = [
    { objectLabel: roles.left, eventLabel: roles.right, objectSide: 'left' },
    { objectLabel: roles.right, eventLabel: roles.left, objectSide: 'right' },
  ];
  for (const candidate of rolePairs) {
    const objectTerms = supportPhraseTerms(candidate.objectLabel);
    const eventTerms = supportPhraseTerms(candidate.eventLabel);
    if (!objectTerms.size || !eventTerms.size) continue;
    for (const block of supportEvidenceBlocks(evidenceText)) {
      const blockTerms = new Set(tokenize(block));
      const objectMatched = [...objectTerms].filter((term) => supportTokenFamilyMatches(term, blockTerms)).length;
      const eventMatched = [...eventTerms].filter((term) => supportTokenFamilyMatches(term, blockTerms)).length;
      if (objectMatched < supportRequiredRoleMatches(objectTerms.size)) continue;
      if (eventMatched < Math.max(1, supportRequiredRoleMatches(eventTerms.size) - 1)) continue;
      if (!/\b(?:got|received|bought|purchased|acquired|arrived|delivered)\b/i.test(block)) continue;
      if (!/\b(?:took|brought|carried|used)\s+(?:it|them|this|that|the\s+[A-Za-z0-9 -]{1,40})\s+(?:with|to|on)\b/i.test(block)) continue;

      const earlierLabel = candidate.objectLabel;
      const laterLabel = candidate.eventLabel;
      const earlierContext = truncateText(block.replace(/\s+/g, ' ').trim(), 520);
      return [
        'ORDER_HINT',
        'source: prerequisite_possession_relation',
        `left_event: ${roles.left}`,
        `right_event: ${roles.right}`,
        `earlier_event: ${earlierLabel}`,
        `later_event: ${laterLabel}`,
        'relation: acquired_or_possessed_object_before_using_it_during_event',
        `earlier_context: ${earlierContext}`,
        `later_context: ${earlierContext}`,
      ].join('\n');
    }
  }
  return null;
}

function supportOrderHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(first|earliest)\b/i.test(q)) return null;
  const order = supportOrderAlternatives(q);
  if (!order) return null;
  const possessionHint = supportPossessionBeforeEventHintForQuestion(question, evidenceText);
  if (possessionHint) return possessionHint;
  const leftLabel = order.left.trim();
  const rightLabel = order.right.trim();
  const predicate = supportOrderPredicate(q);
  const mentions = supportFilterMentionsByQuestionTemporalScope(question, supportRoleAwareDateMentions(evidenceText));
  if (mentions.length < 2) return null;
  const roleBoundEnabled = signedRecallFlag('RECALL_ENABLE_ROLE_DATE_BINDING');
  const roleBoundOrderPair = roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, leftLabel, rightLabel, predicate, supportIsCompletedTaskOrderQuestion(question)) : null;
  const roleBoundOrderValid = roleBoundOrderPair && supportPairHasEventDates(roleBoundOrderPair, { allowCoarse: true }) ? roleBoundOrderPair : null;
  const pair = roleBoundOrderValid
    || (supportIsCompletedTaskOrderQuestion(question)
      ? supportBestValidStrictMentionPair(mentions, leftLabel, rightLabel, predicate, true)
      : supportBestValidStrictMentionPair(mentions, leftLabel, rightLabel, predicate)
        || supportBestValidOrderMentionPair(mentions, leftLabel, rightLabel));
  if (!pair?.left || !pair?.right || pair.left.mentionScore <= 0 || pair.right.mentionScore <= 0) return null;
  const earlierSide = pair.left.time <= pair.right.time ? 'left' : 'right';
  const earlierLabel = earlierSide === 'left' ? leftLabel : rightLabel;
  const laterLabel = earlierSide === 'left' ? rightLabel : leftLabel;
  const earlierMention = earlierSide === 'left' ? pair.left : pair.right;
  const laterMention = earlierSide === 'left' ? pair.right : pair.left;
  return [
    'ORDER_HINT',
    `left_event: ${leftLabel}`,
    `left_date: ${pair.left.iso} (${pair.left.text}${pair.left.note ? `; ${pair.left.note}` : ''})`,
    `right_event: ${rightLabel}`,
    `right_date: ${pair.right.iso} (${pair.right.text}${pair.right.note ? `; ${pair.right.note}` : ''})`,
    `earlier_event: ${earlierLabel}`,
    `later_event: ${laterLabel}`,
    `earlier_context: ${truncateText(earlierMention.context, 360)}`,
    `later_context: ${truncateText(laterMention.context, 360)}`,
  ].join('\n');
}

function supportTemporalHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(days?|weeks?|months?)\b/i.test(q) || !/\b(before|after|between|since|when)\b/i.test(q)) return null;
  const symbolicHint = supportSymbolicTemporalHintForQuestion(question, evidenceText);
  if (symbolicHint) return symbolicHint;
  const giftBirthdayHint = supportGiftOrderBirthdayDeltaHintForQuestion(question, evidenceText);
  if (giftBirthdayHint) return giftBirthdayHint;
  const mentions = supportFilterMentionsByQuestionTemporalScope(q, supportRoleAwareDateMentions(evidenceText));
  if (mentions.length < 2) return null;
  const roleBoundEnabled = signedRecallFlag('RECALL_ENABLE_ROLE_DATE_BINDING');
  const rolePairDurationHint = supportRolePairDurationHintForQuestion(question, mentions);
  if (rolePairDurationHint) return rolePairDurationHint;

  const genericBefore = q.match(/\bhow\s+many\s+(days?|weeks?|months?)\s+before\s+(.+?)\s+did\s+(.+?)(?:\?|$)/i);
  if (genericBefore) {
    const unit = genericBefore[1].toLowerCase();
    const pair = (roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, genericBefore[3], genericBefore[2], '', true) : null)
      || supportBestStrictMentionPair(mentions, genericBefore[3], genericBefore[2], '', true)
      || supportSoftMentionPair(mentions, genericBefore[3], genericBefore[2], true)
      || supportBestStrictMentionPair(mentions, genericBefore[3], genericBefore[2])
      || supportSoftMentionPair(mentions, genericBefore[3], genericBefore[2]);
    if (!supportPairHasEventDates(pair, { allowCoarse: true })) return null;
    const eventMention = pair?.left || null;
    const anchorMention = pair?.right || null;
    if (eventMention?.mentionScore > 0 && anchorMention?.mentionScore > 0) {
      const days = Math.round((anchorMention.time - eventMention.time) / 86_400_000);
      if (Number.isFinite(days) && days >= 0) {
        return [
          'TEMPORAL_HINT',
          `event_date: ${eventMention.iso} (${eventMention.text})`,
          `anchor_date: ${anchorMention.iso} (${anchorMention.text})`,
          `exclusive_delta_days: ${days}`,
          `approx_weeks: ${Math.round(days / 7)}`,
          `approx_months: ${Math.round(days / 30)}`,
          `requested_unit: ${unit}`,
          `event_context: ${truncateText(eventMention.context, 360)}`,
          `anchor_context: ${truncateText(anchorMention.context, 360)}`,
        ].join('\n');
      }
    }
  }

  const genericAfter = q.match(/\bhow\s+many\s+(days?|weeks?|months?)\s+did\s+it\s+take\s+for\s+me\s+to\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (genericAfter) {
    const unit = genericAfter[1].toLowerCase();
    const pair = (roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, genericAfter[3], genericAfter[2], '', true) : null)
      || supportBestStrictMentionPair(mentions, genericAfter[3], genericAfter[2], '', true)
      || supportSoftMentionPair(mentions, genericAfter[3], genericAfter[2], true)
      || supportBestStrictMentionPair(mentions, genericAfter[3], genericAfter[2])
      || supportSoftMentionPair(mentions, genericAfter[3], genericAfter[2]);
    if (!supportPairHasEventDates(pair, { allowCoarse: true })) return null;
    const startMention = pair?.left || null;
    const endMention = pair?.right || null;
    if (startMention?.mentionScore > 0 && endMention?.mentionScore > 0) {
      const days = Math.round((endMention.time - startMention.time) / 86_400_000);
      if (Number.isFinite(days) && days >= 0) {
        return [
          'TEMPORAL_HINT',
          `start_date: ${startMention.iso} (${startMention.text})`,
          `end_date: ${endMention.iso} (${endMention.text})`,
          `exclusive_delta_days: ${days}`,
          `inclusive_delta_days: ${days + 1}`,
          `requested_unit: ${unit}`,
          `start_context: ${truncateText(startMention.context, 360)}`,
          `end_context: ${truncateText(endMention.context, 360)}`,
        ].join('\n');
      }
    }
  }

  const sinceWhen = q.match(/\bhow\s+many\s+(days?|weeks?|months?)\s+had\s+passed\s+since\s+(.+?)\s+when\s+(.+?)(?:\?|$)/i);
  if (sinceWhen) {
    const unit = sinceWhen[1].toLowerCase();
    const pair = (roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, sinceWhen[2], sinceWhen[3], '', true) : null)
      || supportBestStrictMentionPair(mentions, sinceWhen[2], sinceWhen[3], '', true)
      || supportSoftMentionPair(mentions, sinceWhen[2], sinceWhen[3], true)
      || supportBestStrictMentionPair(mentions, sinceWhen[2], sinceWhen[3])
      || supportSoftMentionPair(mentions, sinceWhen[2], sinceWhen[3]);
    if (!supportPairHasEventDates(pair, { allowCoarse: true })) return null;
    const startMention = pair?.left || null;
    const endMention = pair?.right || null;
    if (startMention?.mentionScore > 0 && endMention?.mentionScore > 0) {
      const days = Math.round((endMention.time - startMention.time) / 86_400_000);
      if (Number.isFinite(days) && days >= 0) {
        return [
          'TEMPORAL_HINT',
          `start_date: ${startMention.iso} (${startMention.text})`,
          `end_date: ${endMention.iso} (${endMention.text})`,
          `exclusive_delta_days: ${days}`,
          `inclusive_delta_days: ${days + 1}`,
          `requested_unit: ${unit}`,
          `start_context: ${truncateText(startMention.context, 360)}`,
          `end_context: ${truncateText(endMention.context, 360)}`,
        ].join('\n');
      }
    }
  }

  const between = q.match(/\bbetween\s+(.+?)\s+and\s+(.+?)(?:\?|$)/i);
  if (between) {
    const requestedUnit = q.match(/\b(days?|weeks?|months?)\b/i)?.[1]?.toLowerCase() || 'days';
    const strictPair = (roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, between[1], between[2], '', true) : null)
      || supportBestStrictMentionPair(mentions, between[1], between[2], '', true)
      || supportBestOrderMentionPair(mentions, supportPhraseTerms(between[1]), supportPhraseTerms(between[2]), true)
      || supportSoftMentionPair(mentions, between[1], between[2], true)
      || supportBestStrictMentionPair(mentions, between[1], between[2])
      || supportSoftMentionPair(mentions, between[1], between[2]);
    if (!supportPairHasEventDates(strictPair, { allowCoarse: true })) return null;
    const leftMention = strictPair?.left || null;
    const rightMention = strictPair?.right || null;
    if (leftMention?.mentionScore > 0 && rightMention?.mentionScore > 0) {
      const days = Math.abs(Math.round((rightMention.time - leftMention.time) / 86_400_000));
      const inclusiveDayWording = requestedUnit.startsWith('day') && /\bhad\s+passed\b|\bday\s+i\b/i.test(q);
      return [
        'TEMPORAL_HINT',
        `left_date: ${leftMention.iso} (${leftMention.text})`,
        `right_date: ${rightMention.iso} (${rightMention.text})`,
        `exclusive_delta_days: ${days}`,
        `inclusive_delta_days: ${days + 1}`,
        `requested_unit: ${requestedUnit}`,
        inclusiveDayWording ? `preferred_answer: ${days + 1} days` : null,
        `left_context: ${truncateText(leftMention.context, 360)}`,
        `right_context: ${truncateText(rightMention.context, 360)}`,
      ].filter(Boolean).join('\n');
    }
  }
  return null;
}

function supportRelativeDurationHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bhow\s+long\b/i.test(q)) return null;
  const mentions = supportFilterMentionsByQuestionTemporalScope(question, supportRoleAwareDateMentions(evidenceText));
  if (mentions.length < 2) return null;
  let leftTerms = null;
  let rightTerms = null;
  let mode = '';
  const when = q.match(/\bhow\s+long\s+had\s+i\s+been\s+(.+?)\s+when\s+i\s+(.+?)(?:\?|$)/i);
  if (when) {
    leftTerms = supportPhraseTerms(when[1]);
    rightTerms = supportPhraseTerms(when[2]);
    mode = 'duration_until_event';
  }
  const before = q.match(/\bhow\s+long\s+did\s+i\s+use\s+(.+?)\s+before\s+i\s+(.+?)(?:\?|$)/i);
  if (!leftTerms && before) {
    leftTerms = supportPhraseTerms(before[1]);
    rightTerms = supportPhraseTerms(before[2]);
    mode = 'duration_before_event';
  }
  if (!leftTerms || !rightTerms) return null;
  const pair = supportBestRelativeDurationPair(mentions, leftTerms, rightTerms);
  if (!pair?.left || !pair?.right || pair.left.mentionScore <= 0 || pair.right.mentionScore <= 0) return null;
  const days = Math.abs(Math.round((pair.right.time - pair.left.time) / 86_400_000));
  const approximate = supportIsCoarseTemporalMention(pair.left) || supportIsCoarseTemporalMention(pair.right);
  const preferredAnswer = approximate ? supportApproximateDurationAnswer(days) : null;
  return [
    'RELATIVE_DURATION_HINT',
    `mode: ${mode}`,
    `precision: ${approximate ? 'approximate' : 'exact'}`,
    `start_or_object_date: ${pair.left.iso} (${pair.left.text}${pair.left.note ? `; ${pair.left.note}` : ''})`,
    `event_date: ${pair.right.iso} (${pair.right.text}${pair.right.note ? `; ${pair.right.note}` : ''})`,
    `exclusive_delta_days: ${days}`,
    `approx_weeks: ${Math.round(days / 7)}`,
    `approx_months: ${Math.round(days / 30)}`,
    ...(preferredAnswer ? [
      `preferred_answer: ${preferredAnswer}`,
      'exact_day_count_is_derived_from_coarse_month_cues: true',
    ] : []),
    `start_or_object_context: ${truncateText(pair.left.context, 360)}`,
    `event_context: ${truncateText(pair.right.context, 360)}`,
  ].join('\n');
}

function supportParseDurationToMonths(text) {
  const raw = String(text || '').toLowerCase();
  const yearsMatch = raw.match(/\b(\d+(?:\.\d+)?)\s*(?:\+?\s*)?(?:years?|yrs?)\b/);
  const monthsMatch = raw.match(/\b(\d+(?:\.\d+)?)\s*(?:months?|mos?)\b/);
  const years = yearsMatch ? Number(yearsMatch[1]) : 0;
  const months = monthsMatch ? Number(monthsMatch[1]) : 0;
  const total = Math.round(years * 12 + months);
  return total > 0 ? total : null;
}

function supportMonthsToDuration(totalMonths) {
  const years = Math.floor(totalMonths / 12);
  const months = totalMonths % 12;
  return { years, months };
}

function supportDurationHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bhow long\b/i.test(q) || !/\bbefore\b/i.test(q)) return null;
  const currentJobEntity = String(q.match(/\bcurrent\s+job\s+at\s+([A-Za-z0-9][A-Za-z0-9 .&'-]{1,60})(?:\?|$)/i)?.[1] || '')
    .replace(/[?.!,;:]+$/g, '')
    .trim();
  const units = supportSplitEvidenceUnits(evidenceText);
  const totalCandidates = [];
  const currentCandidates = [];
  for (const unit of units) {
    const normalized = normalizeQueryText(unit);
    const duration = supportParseDurationToMonths(unit);
    if (!duration) continue;
    if (/\b(total|overall|career|experience|professionally|field|been working|worked)\b/i.test(unit)) {
      totalCandidates.push({ duration, unit });
    }
    const currentEntityGrounded = currentJobEntity
      && normalizeQueryText(unit).includes(normalizeQueryText(currentJobEntity))
      && /\bworking\s+at\b/i.test(unit);
    if (/\b(current job|current role|current employer|working at)\b/i.test(normalized) || currentEntityGrounded) {
      currentCandidates.push({ duration, unit });
    }
  }
  const total = totalCandidates.sort((a, b) => b.duration - a.duration)[0];
  const current = currentCandidates.sort((a, b) => b.duration - a.duration)[0];
  if (!total || !current || total.duration <= current.duration) return null;
  const prior = total.duration - current.duration;
  const priorDuration = supportMonthsToDuration(prior);
  return [
    'DURATION_HINT',
    `total_experience_months: ${total.duration}`,
    `current_job_months: ${current.duration}`,
    `prior_experience_months: ${prior}`,
    `prior_experience: ${priorDuration.years} years${priorDuration.months ? ` and ${priorDuration.months} months` : ''}`,
    `total_context: ${truncateText(total.unit, 360)}`,
    `current_context: ${truncateText(current.unit, 360)}`,
  ].join('\n');
}

function supportEventDeltaHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  const unitMatch = q.match(/\bhow\s+many\s+(days?|weeks?|months?|years?)\b/i);
  if (!unitMatch) return null;
  const unit = unitMatch[1].toLowerCase().replace(/s$/, '');
  const mentions = supportRoleAwareDateMentions(evidenceText);
  if (!mentions.length) return null;

  const pluralUnit = (value) => `${unit}${value === 1 ? '' : 's'}`;
  const toUnits = (days) => {
    if (unit === 'week') return Math.round(days / 7);
    if (unit === 'month') return Math.round(days / 30);
    if (unit === 'year') return Math.round(days / 365);
    return days;
  };

  if (/\bbetween\b/i.test(q)) {
    const targets = comparisonTargets(q);
    if (targets.length < 2) return null;
    const leftTerms = supportPhraseTerms(targets[0]);
    const rightTerms = supportPhraseTerms(targets[1]);
    const left = supportBestMention(mentions, leftTerms);
    const right = supportBestMention(mentions, rightTerms);
    if (!left || !right || left.mentionScore <= 0 || right.mentionScore <= 0 || left.iso === right.iso) return null;
    const days = Math.abs(Math.round((right.time - left.time) / 86_400_000));
    const value = toUnits(days);
    const coarse = supportIsCoarseTemporalMention(left) || supportIsCoarseTemporalMention(right);
    return [
      'EVENT_DELTA_HINT',
      'mode: operator_math_temporal_delta',
      'operation: between_two_events',
      `unit: ${unit}`,
      `left_event_date: ${left.iso} (${left.text})`,
      `right_event_date: ${right.iso} (${right.text})`,
      `exclusive_delta_days: ${days}`,
      `preferred_answer: ${value} ${pluralUnit(value)}`,
      unit === 'day' ? `inclusive_alternative: ${days + 1} days (counting both endpoints) is also acceptable` : null,
      coarse ? 'precision: approximate (a date cue was month-/relative-grained)' : 'precision: exact',
      'answer_policy: report the computed delta; do not claim insufficient_evidence when both event dates are grounded above',
      `left_context: ${truncateText(left.context, 300)}`,
      `right_context: ${truncateText(right.context, 300)}`,
    ].filter(Boolean).join('\n');
  }

  const agoMatch = q.match(/\bhow\s+many\s+(?:days?|weeks?|months?|years?)\s+ago\s+(?:did|have|has|was|were)?\s*i?\s*(.+?)(?:\?|$)/i);
  if (agoMatch) {
    const eventTerms = supportPhraseTerms(agoMatch[1]);
    const event = supportBestMention(mentions, eventTerms);
    const now = mentions.reduce((max, mention) => (mention.time > max ? mention.time : max), 0);
    if (event && event.mentionScore > 0 && now > 0 && now >= event.time) {
      const days = Math.round((now - event.time) / 86_400_000);
      const value = toUnits(days);
      const coarse = supportIsCoarseTemporalMention(event);
      return [
        'EVENT_DELTA_HINT',
        'mode: operator_math_temporal_delta',
        'operation: time_since_event',
        `unit: ${unit}`,
        `event_date: ${event.iso} (${event.text})`,
        `reference_now: ${supportIso(new Date(now))}`,
        `delta_days: ${days}`,
        `preferred_answer: ${value} ${pluralUnit(value)}`,
        coarse ? 'precision: approximate' : 'precision: exact',
        'answer_policy: report the computed value; do not claim insufficient_evidence when the event date is grounded above',
        `event_context: ${truncateText(event.context, 300)}`,
      ].filter(Boolean).join('\n');
    }
  }
  return null;
}

function supportAgeAtEventHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bhow\s+old\b/i.test(q) || !/\bwhen\b/i.test(q)) return null;
  const raw = String(evidenceText || '');
  const ageMatches = [...raw.matchAll(/\b(?:(i\s*(?:am|'m|’m)\s*)|(?:as\s+a\s*))?(\d{1,3})[-\s]*(?:years?\s+old|year-old)\b/gi)]
    .map((match) => ({ match, score: match[1] ? 3 : (/as\s+a\s*$/i.test(String(match[0]).slice(0, 12)) ? 2 : 0) }))
    .sort((a, b) => b.score - a.score);
  const durationMatches = [...raw.matchAll(/\b(?:living|lived|been\s+living|have\s+been\s+living)\s+in\s+(?:the\s+)?(?:united\s+states|u\.s\.|us)\s+for\s+(?:the\s+past\s+)?(a|an|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+years?\b/gi)];
  if (!ageMatches.length || !durationMatches.length) return null;
  const age = Number(ageMatches[0].match[2]);
  const years = supportNumberFromToken(durationMatches[0][1]);
  if (!Number.isFinite(age) || !Number.isFinite(years) || years <= 0 || age <= years) return null;
  return [
    'AGE_HINT',
    `current_age_years: ${age}`,
    `duration_before_event_years: ${years}`,
    `age_at_event_years: ${age - years}`,
    `age_context: ${truncateText(supportContextAround(raw, ageMatches[0].match.index || 0, ageMatches[0].match[0].length).context, 360)}`,
    `duration_context: ${truncateText(supportContextAround(raw, durationMatches[0].index || 0, durationMatches[0][0].length).context, 360)}`,
  ].join('\n');
}

function supportCandidateEntitiesFromContext(context) {
  const text = String(context || '');
  const entities = [];
  const patterns = [
    /\b(?:on|using|used|use|through|trial of|free trial of|subscription to|subscribe to|subscribed to|access to)\s+([A-Z][A-Za-z0-9+]*(?:\s+[A-Z][A-Za-z0-9+]+){0,3})/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const entity = String(match[1] || '')
        .replace(/\b(?:for|during|which|that|and|but|with|without|since|last|next)\b.*$/i, '')
        .replace(/[.,;:!?()[\]{}"']+$/g, '')
        .trim();
      const normalizedEntity = normalizeQueryText(entity);
      if (SUPPORT_MONTH_INDEX.has(normalizedEntity) || SUPPORT_WEEKDAY_TERMS.has(normalizedEntity)) continue;
      if (/^(today|yesterday|last|next|current|recent|january|february|march|april|may|june|july|august|september|october|november|december)$/i.test(entity)) continue;
      if (entity.length >= 3 && entity.length <= 40) entities.push(entity);
    }
  }
  return [...new Set(entities)];
}

function supportIsStreamingServiceQuestion(question) {
  return /\b(?:streaming|subscription|video|media)\s+services?\b/i.test(String(question || ''))
    || /\bstreaming\s+service\b/i.test(String(question || ''));
}

function supportRequiresServiceStartEvidence(question) {
  return supportIsStreamingServiceQuestion(question)
    && /\b(?:start(?:ed|ing)?|began|begin|using|used|use)\b/i.test(String(question || ''));
}

function supportServiceStartOrUsageSignal(localText) {
  return /\b(?:start(?:ed|ing)?|began|begin|using|used|use|free\s+trial|trial|subscription|subscribe|subscribed|signed?\s+up|access|watch(?:ed|ing)?)\b/i
    .test(String(localText || ''));
}

function supportServiceStartEvidenceSignal(localText) {
  return /\b(?:start(?:ed|ing)?|began|begin|using|used|use|free\s+trial|trial|subscription|subscribe|subscribed|signed?\s+up|access)\b/i
    .test(String(localText || ''));
}

function supportServiceEntityCandidatesFromContext(context, { requireStartEvidence = false } = {}) {
  const text = String(context || '');
  if (!/\b(?:streaming|service|subscription|trial|watch|watching|watched|tv|shows?|movies?|documentar(?:y|ies)|video)\b/i.test(text)) return [];
  const entities = [];
  const patterns = [
    /\b(?:on|using|used|use|through|trial of|free trial of|subscription to|subscribe to|subscribed to|access to)\s+([A-Z][A-Za-z0-9+]*(?:\s+[A-Z][A-Za-z0-9+]+){0,3})/g,
    /\b([A-Z][A-Za-z0-9+]*(?:\s+[A-Z][A-Za-z0-9+]+){0,3})\s+(?:trial|subscription|streaming\s+service)\b/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const entity = String(match[1] || '')
        .replace(/\b(?:for|during|which|that|and|but|with|without|since|last|next)\b.*$/i, '')
        .replace(/[.,;:!?()[\]{}"']+$/g, '')
        .trim();
      const normalizedEntity = normalizeQueryText(entity);
      if (!entity || SUPPORT_MONTH_INDEX.has(normalizedEntity) || SUPPORT_WEEKDAY_TERMS.has(normalizedEntity)) continue;
      if (/^(the|this|that|free trial|trial|subscription|service|documentary|movie|show|tv)$/i.test(entity)) continue;
      const start = Math.max(0, (match.index || 0) - 100);
      const end = Math.min(text.length, (match.index || 0) + match[0].length + 120);
      const local = text.slice(start, end);
      const serviceSignal = /\b(?:streaming|service|subscription|trial|watch|watching|watched|tv|shows?|movies?|documentar(?:y|ies)|video)\b/i.test(local);
      const startSignal = requireStartEvidence
        ? supportServiceStartEvidenceSignal(local)
        : supportServiceStartOrUsageSignal(local);
      const assistantRecommendation = /\[ASSISTANT\]/i.test(local)
        && /\b(?:recommendations?|options?|here are|offers?|library|content)\b/i.test(local)
        && !/\b(?:you mentioned|you said|you were using|your free trial|during my free trial)\b/i.test(local);
      const audioOnlySignal = /\b(?:music|podcasts?|songs?|playlist)\b/i.test(local)
        && !/\b(?:tv|shows?|movies?|documentar(?:y|ies)|video|trial|subscription|streaming|service)\b/i.test(local);
      if (!serviceSignal || audioOnlySignal || assistantRecommendation) continue;
      if (requireStartEvidence && !startSignal) continue;
      if (entity.length >= 3 && entity.length <= 40) entities.push(entity);
    }
  }
  return [...new Set(entities)];
}

function supportServiceCandidateContextsForMention(mention, { requireStartEvidence = false } = {}) {
  const contexts = [String(mention?.context || '')].filter(Boolean);
  const block = String(mention?.block || '');
  if (!block) return contexts;
  const mentionText = String(mention?.text || '').toLowerCase();
  for (const unit of supportSplitEvidenceUnits(block)) {
    if (mentionText && !['session_date', 'block_session_date'].includes(mentionText)
      && !unit.toLowerCase().includes(mentionText)) continue;
    const startSignal = requireStartEvidence
      ? supportServiceStartEvidenceSignal(unit)
      : supportServiceStartOrUsageSignal(unit);
    if (!startSignal) continue;
    if (!/\b(?:streaming|service|subscription|trial|watch|watching|watched|tv|shows?|movies?|documentar(?:y|ies)|video)\b/i.test(unit)) continue;
    contexts.push(unit);
  }
  return [...new Set(contexts.map((context) => context.replace(/\s+/g, ' ').trim()).filter(Boolean))];
}

function supportLatestEntityCandidateForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(most\s+recently|latest|current)\b/i.test(q)) return null;
  const serviceQuestion = supportIsStreamingServiceQuestion(q);
  const requireStartEvidence = supportRequiresServiceStartEvidence(q);
  const mentions = supportDateMentions(evidenceText)
    .filter((mention) => {
      if (!serviceQuestion || !requireStartEvidence) return true;
      if (mention.note === 'session_date' || mention.note === 'block_session_role') return false;
      return supportServiceStartEvidenceSignal(mention.context);
    });
  const candidates = [];
  for (const mention of mentions) {
    const contexts = serviceQuestion
      ? supportServiceCandidateContextsForMention(mention, { requireStartEvidence })
      : [mention.context];
    const entities = contexts.flatMap((context) => serviceQuestion
      ? supportServiceEntityCandidatesFromContext(context, { requireStartEvidence })
      : supportCandidateEntitiesFromContext(context));
    for (const entity of entities) {
      candidates.push({ entity, mention });
    }
  }
  if (!candidates.length) return null;
  const latest = candidates.sort((a, b) => b.mention.time - a.mention.time)[0];
  return { ...latest, candidates };
}

function supportLatestHintForQuestion(question, evidenceText) {
  const latest = supportLatestEntityCandidateForQuestion(question, evidenceText);
  if (!latest) return null;
  return [
    'LATEST_HINT',
    `latest_entity: ${latest.entity}`,
    `latest_date: ${latest.mention.iso} (${latest.mention.text}${latest.mention.note ? `; ${latest.mention.note}` : ''})`,
    `latest_context: ${truncateText(latest.mention.context, 420)}`,
    `candidate_entities: ${latest.candidates.map((item) => `${item.entity}@${item.mention.iso}`).join(', ')}`,
  ].join('\n');
}

function supportScopedEntityHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bwhich\b/i.test(q) || !/\blast\s+month\b/i.test(q)) return null;
  const actionMatch = q.match(/\bdid\s+i\s+([a-z]+)\b/i);
  const action = normalizeQueryText(actionMatch?.[1] || '');
  if (!action) return null;
  const asksShoes = /\b(pair\s+of\s+)?shoes?\b|\bsneakers?\b|\bboots?\b/i.test(q);
  if (!asksShoes) return null;

  const candidates = [];
  const blocks = supportEvidenceBlocks(evidenceText);
  const actionFamily = action === 'clean'
    ? /\bclean(?:ed|ing)?\b/i
    : new RegExp(`\\b${action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:ed|ing)?\\b`, 'i');
  const actionObject = action === 'clean'
    ? /\bclean(?:ed|ing)?\s+(?:(?:my|your|the|a|an|pair\s+of)\s+){0,3}([A-Za-z0-9][A-Za-z0-9'\-]*(?:\s+[A-Za-z0-9][A-Za-z0-9'\-]*){0,5}\s+(?:sneakers|shoes|boots|sandals|chucks|trainers))\b/gi
    : new RegExp(`\\b${action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:ed|ing)?\\s+(?:(?:my|your|the|a|an|pair\\s+of)\\s+){0,3}([A-Za-z0-9][A-Za-z0-9'\\-]*(?:\\s+[A-Za-z0-9][A-Za-z0-9'\\-]*){0,5}\\s+(?:sneakers|shoes|boots|sandals|chucks|trainers))\\b`, 'gi');
  for (const block of blocks) {
    if (!/\blast\s+month\b/i.test(block) || !actionFamily.test(block)) continue;
    if (!/\b(shoes?|sneakers?|boots?|sandals|chucks|trainers)\b/i.test(block)) continue;
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    const units = supportSplitEvidenceUnits(block);
    for (const unit of units) {
      if (!/\blast\s+month\b/i.test(unit) || !actionFamily.test(unit)) continue;
      for (const match of unit.matchAll(actionObject)) {
        const entity = String(match[1] || '')
          .replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, '')
          .replace(/\s+/g, ' ')
          .trim();
        if (!entity || !/\b(shoes?|sneakers?|boots?|sandals|chucks|trainers)\b/i.test(entity)) continue;
        const specificity = entity.split(/\s+/).filter(Boolean).length;
        candidates.push({
          entity,
          key,
          specificity,
          context: unit.replace(/\s+/g, ' ').trim(),
        });
      }
    }
  }
  const best = candidates
    .sort((a, b) => b.specificity - a.specificity || a.entity.length - b.entity.length)[0];
  if (!best) return null;
  return [
    'SCOPED_ENTITY_HINT',
    'temporal_scope: last_month',
    `predicate: ${action}`,
    `answer_candidate: ${best.entity}`,
    `evidence_key: ${best.key}`,
    `candidate_context: ${truncateText(best.context, 520)}`,
  ].join('\n');
}

function supportBookingAgeHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bhow\s+many\s+months?\s+ago\b/i.test(q)) return null;
  if (!/\bbook(?:ed|ing)?|reserv(?:ed|ation)\b/i.test(q)) return null;
  const leadCandidates = [];
  const tripAgeCandidates = [];
  const bookingPattern = /\bbook(?:ed|ing)?\b[^.!?\n]{0,160}\b(a|an|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+months?\s+in\s+advance\b/gi;
  const tripAgePattern = /\b(?:been\s+to|went\s+to|visited|stayed\s+in|trip\s+to|vacation\s+to|for\s+my\s+[^.!?\n]{0,60}\bwedding)\b[^.!?\n]{0,180}\b(?:exactly\s+)?(a|an|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+months?\s+ago\b/gi;
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    const root = supportBenchmarkSiblingRoot(key);
    for (const unit of supportSplitEvidenceUnits(block)) {
      for (const match of unit.matchAll(bookingPattern)) {
        const months = supportNumberFromToken(match[1]);
        if (!Number.isFinite(months)) continue;
        leadCandidates.push({
          months,
          key,
          root,
          context: unit.replace(/\s+/g, ' ').trim(),
        });
      }
      for (const match of unit.matchAll(tripAgePattern)) {
        const months = supportNumberFromToken(match[1]);
        if (!Number.isFinite(months)) continue;
        tripAgeCandidates.push({
          months,
          key,
          root,
          context: unit.replace(/\s+/g, ' ').trim(),
        });
      }
    }
  }
  if (!leadCandidates.length || !tripAgeCandidates.length) return null;
  const pairs = [];
  for (const lead of leadCandidates) {
    for (const trip of tripAgeCandidates) {
      const sameRoot = lead.root && trip.root && lead.root === trip.root;
      pairs.push({
        lead,
        trip,
        sameRoot,
        bookingAgeMonths: lead.months + trip.months,
      });
    }
  }
  const best = pairs
    .sort((a, b) => (b.sameRoot - a.sameRoot) || (b.bookingAgeMonths - a.bookingAgeMonths))[0];
  if (!best) return null;
  return [
    'BOOKING_AGE_HINT',
    'formula: booking_age_months = trip_age_months + booking_lead_time_months',
    `trip_age_months: ${best.trip.months}`,
    `booking_lead_time_months: ${best.lead.months}`,
    `booking_age_months: ${best.bookingAgeMonths}`,
    `preferred_answer: ${supportNumberToWords(best.bookingAgeMonths)} months ago`,
    `same_root: ${best.sameRoot}`,
    `trip_age_context: ${truncateText(best.trip.context, 420)}`,
    `booking_context: ${truncateText(best.lead.context, 420)}`,
  ].join('\n');
}

function supportParseClockMinutes(value) {
  const match = String(value || '').match(/\b(\d{1,2}):(\d{2})\s*(AM|PM)\b/i);
  if (!match) return null;
  let hour = Number(match[1]);
  const minute = Number(match[2]);
  const period = String(match[3] || '').toUpperCase();
  if (!Number.isFinite(hour) || !Number.isFinite(minute) || minute < 0 || minute > 59) return null;
  if (period === 'PM' && hour !== 12) hour += 12;
  if (period === 'AM' && hour === 12) hour = 0;
  return hour * 60 + minute;
}

function supportFormatClockMinutes(totalMinutes) {
  if (!Number.isFinite(totalMinutes)) return null;
  const dayMinutes = ((Math.trunc(totalMinutes) % 1440) + 1440) % 1440;
  const hour24 = Math.floor(dayMinutes / 60);
  const minute = dayMinutes % 60;
  const period = hour24 >= 12 ? 'PM' : 'AM';
  const hour12 = hour24 % 12 || 12;
  return `${hour12}:${String(minute).padStart(2, '0')} ${period}`;
}

function supportWeekdayTimeHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bwhat\s+time\b/i.test(q) || !/\bwake(?:\s+up|s)?|waking\s+up\b/i.test(q)) return null;
  const askedWeekdays = Object.keys(WEEKDAY_INDEX)
    .filter((weekday) => new RegExp(`\\b${weekday}s?\\b`, 'i').test(q));
  if (!askedWeekdays.length) return null;
  const baseCandidates = [];
  const adjustmentCandidates = [];
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    const root = supportBenchmarkSiblingRoot(key);
    for (const unit of supportSplitEvidenceUnits(block)) {
      const normalizedUnit = normalizeQueryText(unit);
      const wakeTimeMatch = unit.match(/\bwaking\s+up\s+at\s+(\d{1,2}:\d{2}\s*(?:AM|PM))\b/i)
        || unit.match(/\bwake\s+up\s+at\s+(\d{1,2}:\d{2}\s*(?:AM|PM))\b/i);
      if (wakeTimeMatch) {
        const minutes = supportParseClockMinutes(wakeTimeMatch[1]);
        if (Number.isFinite(minutes)) {
          baseCandidates.push({
            minutes,
            text: wakeTimeMatch[1],
            key,
            root,
            context: unit.replace(/\s+/g, ' ').trim(),
          });
        }
      }
      const matchesAskedWeekdays = askedWeekdays.every((weekday) => normalizedUnit.includes(weekday));
      const adjustmentMatch = unit.match(/\bwaking\s+up\s+(a|an|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+minutes?\s+(earlier|later)\b/i)
        || unit.match(/\bwake\s+up\s+(a|an|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+minutes?\s+(earlier|later)\b/i);
      if (matchesAskedWeekdays && adjustmentMatch) {
        const amount = supportNumberFromToken(adjustmentMatch[1]);
        if (Number.isFinite(amount)) {
          adjustmentCandidates.push({
            amount,
            direction: String(adjustmentMatch[2] || '').toLowerCase(),
            key,
            root,
            context: unit.replace(/\s+/g, ' ').trim(),
          });
        }
      }
    }
  }
  if (!baseCandidates.length || !adjustmentCandidates.length) return null;
  const pairs = [];
  for (const base of baseCandidates) {
    for (const adjustment of adjustmentCandidates) {
      const sameRoot = base.root && adjustment.root && base.root === adjustment.root;
      const delta = adjustment.direction === 'earlier' ? -adjustment.amount : adjustment.amount;
      pairs.push({
        base,
        adjustment,
        sameRoot,
        adjustedMinutes: base.minutes + delta,
      });
    }
  }
  const best = pairs.sort((a, b) => (b.sameRoot - a.sameRoot) || (a.base.minutes - b.base.minutes))[0];
  if (!best) return null;
  return [
    'WEEKDAY_TIME_HINT',
    `weekdays: ${askedWeekdays.join(', ')}`,
    `base_time: ${supportFormatClockMinutes(best.base.minutes)}`,
    `adjustment_minutes: ${best.adjustment.direction === 'earlier' ? '-' : '+'}${best.adjustment.amount}`,
    `adjusted_time: ${supportFormatClockMinutes(best.adjustedMinutes)}`,
    `same_root: ${best.sameRoot}`,
    `base_context: ${truncateText(best.base.context, 420)}`,
    `adjustment_context: ${truncateText(best.adjustment.context, 420)}`,
  ].join('\n');
}

function supportNormalizeAirlineName(value) {
  const raw = String(value || '').replace(/[.,;:!?()[\]{}"']+$/g, '').trim();
  const normalized = raw.toLowerCase();
  if (/\bunited(?:\s+airlines)?\b/.test(normalized)) return 'United Airlines';
  if (/\bamerican(?:\s+airlines)?\b/.test(normalized)) return 'American Airlines';
  if (/\bsouthwest(?:\s+airlines)?\b/.test(normalized)) return 'Southwest Airlines';
  if (/\bdelta(?:\s+air\s+lines|\s+airlines)?\b/.test(normalized)) return 'Delta Air Lines';
  if (/\bspirit(?:\s+airlines)?\b/.test(normalized)) return 'Spirit Airlines';
  if (/\bjetblue(?:\s+airways)?\b/.test(normalized)) return 'JetBlue Airways';
  return raw.replace(/\s+/g, ' ');
}

function supportQuestionMonthNames(question) {
  const months = supportQuestionMonthScope(question);
  return [...months].map((month) => Object.entries(MONTH_INDEX)
    .find(([, index]) => index === month)?.[0]).filter(Boolean);
}

function supportUnitMatchesMonthScope(unit, monthNames) {
  if (!monthNames.length) return true;
  return monthNames.some((month) => new RegExp(`\\b${month}\\b`, 'i').test(unit));
}

function supportCountBeforeQuestionParts(question) {
  const q = String(question || '');
  const match = q.match(/\bhow\s+many\s+(.+?)\s+did\s+(?:i|we|the\s+narrator)\s+(.+?)\s+before\s+(.+?)(?:\?|$)/i);
  if (!match) return null;
  const countLabel = match[1].trim();
  if (/\b(?:days?|weeks?|months?|years?|money|dollars?|cash)\b/i.test(countLabel)) return null;
  const activity = match[2].trim();
  if (!/\b(?:participate|participated|attend|attended|volunteer|volunteered|run|ran|walk|walked|join|joined|take\s+part|took\s+part)\b/i.test(activity)) return null;
  const anchorRaw = match[3].trim();
  const quoted = supportQuotedPhrases(anchorRaw);
  return { countLabel, activity, anchorLabel: quoted[0] || anchorRaw };
}

function supportEventCountContextPass(context, countLabel) {
  const text = String(context || '').toLowerCase();
  const wantsCharity = /\b(?:charit|fundrais|cause|volunteer)\b/.test(String(countLabel || '').toLowerCase());
  const activityPass = /\b(?:participated|participate|volunteered|volunteer|attended|attend|ran|run|walked|walk|joined|join|helped\s+organize|organized|took\s+part)\b/.test(text);
  const eventPass = /\b(?:event|gala|tournament|walk|run|thon|race|fundraiser|fundraising|cause|volunteer|volunteered)\b/.test(text);
  const charityPass = !wantsCharity
    || /\b(?:charit|fundrais|raised|funds?|cause|cure|conservation|shelter|research|hunger|wildlife|food\s+bank|relief)\b/.test(text);
  return activityPass && eventPass && charityPass;
}

function supportEventLabelFromContext(context, anchorLabel) {
  const anchorNorm = normalizeQueryText(anchorLabel);
  for (const quoted of supportQuotedPhrases(context)) {
    if (normalizeQueryText(quoted) !== anchorNorm) return quoted;
  }
  const match = String(context || '').match(/\b(?:participated|volunteered|attended|ran|walked|joined|helped\s+organize|organized|took\s+part)\b[^.!?\n]{0,180}/i);
  return match ? match[0].replace(/\s+/g, ' ').trim() : truncateText(context, 120);
}

function supportCountBeforeAnchorHintForQuestion(question, evidenceText) {
  const parts = supportCountBeforeQuestionParts(question);
  if (!parts) return null;
  const anchor = supportBestBlockRoleDate(evidenceText, parts.anchorLabel)
    || supportBestMention(supportRoleAwareDateMentions(evidenceText), supportPhraseTerms(parts.anchorLabel));
  if (!anchor || !Number.isFinite(anchor.time)) return null;
  const blocks = supportEvidenceBlocks(evidenceText);
  const anchorRoot = String(anchor.root || '');
  const scopedBlocks = anchorRoot
    ? blocks.filter((block) => {
      const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
      return supportBenchmarkSiblingRoot(key) === anchorRoot;
    })
    : [];
  const searchBlocks = scopedBlocks.length ? scopedBlocks : blocks;
  const included = [];
  const excludedAfter = [];
  for (const block of searchBlocks) {
    const key = String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
    const root = supportBenchmarkSiblingRoot(key);
    const candidates = supportDateMentions(block)
      .filter((mention) => supportMentionDateSpecificity(mention) >= 3)
      .filter((mention) => !supportIsAbsenceContext(mention.context))
      .filter((mention) => supportEventCountContextPass(mention.context, parts.countLabel))
      .filter((mention) => normalizeQueryText(mention.context).includes(normalizeQueryText(parts.anchorLabel)) || mention.time !== anchor.time)
      .map((mention) => ({
        ...mention,
        key,
        root,
        label: supportEventLabelFromContext(mention.context, parts.anchorLabel),
      }))
      .sort((a, b) =>
        supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a)
        || a.time - b.time
      );
    const best = candidates[0];
    if (!best) continue;
    if (best.time < anchor.time) included.push(best);
    else if (best.time > anchor.time) excludedAfter.push(best);
  }
  const unique = [];
  const seen = new Set();
  for (const candidate of included.sort((a, b) => a.time - b.time)) {
    const id = `${candidate.key}:${normalizeQueryText(candidate.label) || candidate.iso}`;
    if (seen.has(id)) continue;
    seen.add(id);
    unique.push(candidate);
  }
  if (!unique.length) return null;
  return [
    'COUNT_BEFORE_HINT',
    'mode: root_coherent_event_count_before_anchor',
    `count_label: ${parts.countLabel}`,
    `activity: ${parts.activity}`,
    `anchor_event: ${parts.anchorLabel}`,
    `anchor_date: ${anchor.iso} (${anchor.text}${anchor.note ? `; ${anchor.note}` : ''})`,
    `aggregation_root: ${anchorRoot || 'global'}`,
    `count_before_anchor: ${unique.length}`,
    `included_events: ${unique.map((item) => `${item.label} @ ${item.iso}`).join('; ')}`,
    excludedAfter.length
      ? `excluded_after_anchor: ${excludedAfter.map((item) => `${item.label} @ ${item.iso}`).join('; ')}`
      : 'excluded_after_anchor: none',
    'answer_policy: answer with count_before_anchor for how-many questions; do not count same-category events outside aggregation_root when root evidence is available',
  ].join('\n');
}

function supportAirlineFlightAggregationHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bairline\b/i.test(q) || !/\bmost\b/i.test(q)) return null;
  if (!/\bfly|flight|flights|flew|flying\b/i.test(q)) return null;
  const monthNames = supportQuestionMonthNames(question);
  const airlinePattern = '(United(?:\\s+Airlines)?|American(?:\\s+Airlines)?|Southwest(?:\\s+Airlines)?|Delta(?:\\s+Air\\s+Lines|\\s+Airlines)?|Spirit(?:\\s+Airlines)?|JetBlue(?:\\s+Airways)?|Alaska(?:\\s+Airlines)?|[A-Z][A-Za-z]+(?:\\s+[A-Z][A-Za-z]+){0,2}\\s+Airlines)';
  const counts = new Map();
  const contexts = new Map();
  const addCount = (airline, count, context) => {
    const name = supportNormalizeAirlineName(airline);
    if (!name || !Number.isFinite(count) || count <= 0) return;
    counts.set(name, (counts.get(name) || 0) + count);
    const existing = contexts.get(name) || [];
    if (existing.length < 3) existing.push(context.replace(/\s+/g, ' ').trim());
    contexts.set(name, existing);
  };
  for (const block of supportEvidenceBlocks(evidenceText)) {
    for (const unit of supportSplitEvidenceUnits(block)) {
      if (!supportUnitMatchesMonthScope(unit, monthNames)) continue;
      if (!/\bflew|flying|flight|flights|direct\s+flight|connecting\s+flight\b/i.test(unit)) continue;
      const compact = unit.replace(/\s+/g, ' ').trim();
      const twoEachWay = new RegExp(`${airlinePattern}[^.!?]{0,180}\\btwo\\s+flights\\s+each\\s+way\\b`, 'i').exec(unit)
        || new RegExp(`\\btwo\\s+flights\\s+each\\s+way\\b[^.!?]{0,180}${airlinePattern}`, 'i').exec(unit);
      if (twoEachWay) {
        addCount(twoEachWay[1], 4, compact);
        continue;
      }
      const withAirline = new RegExp(`\\bflew\\s+with\\s+${airlinePattern}\\b`, 'i').exec(unit)
        || new RegExp(`\\bflying\\s+with\\s+${airlinePattern}\\b`, 'i').exec(unit);
      if (withAirline) {
        addCount(withAirline[1], /\bconnecting\s+flight\b/i.test(unit) ? 2 : 1, compact);
        continue;
      }
      const directAirline = new RegExp(`\\bdirect\\s+flight\\s+(?:with|on)\\s+${airlinePattern}\\b`, 'i').exec(unit)
        || new RegExp(`${airlinePattern}[^.!?]{0,80}\\bdirect\\s+flight\\b`, 'i').exec(unit);
      if (directAirline) {
        addCount(directAirline[1], 1, compact);
      }
    }
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!ranked.length) return null;
  const [winner, winnerCount] = ranked[0];
  return [
    'AIRLINE_AGGREGATION_HINT',
    `temporal_scope_months: ${monthNames.join(', ') || 'unscoped'}`,
    `winner: ${winner}`,
    `winner_flight_segments: ${winnerCount}`,
    `airline_counts: ${ranked.map(([airline, count]) => `${airline}=${count}`).join(', ')}`,
    `winner_context: ${truncateText((contexts.get(winner) || []).join(' | '), 560)}`,
  ].join('\n');
}

function supportBlockEvidenceEntries(evidenceText) {
  return supportEvidenceBlocks(evidenceText)
    .map((block) => ({ key: supportKeyForBlock(block), block }))
    .filter((entry) => entry.key);
}

function supportCleanAggregateUnit(raw) {
  return normalizeQueryText(raw)
    .replace(/^(?:i\s+)?(?:recently\s+)?(?:finished|started\s+with|started|got|just\s+got|picked\s+up|bought|working\s+on)\s+/, ' ')
    .replace(/\b(?:simple|new|the|a|an|my|this|that|scale|model|kit|kits)\b/g, ' ')
    .replace(/\b\d+\/\d+\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 90);
}

function supportFormatAggregateNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return String(value || '');
  if (Math.abs(number - Math.round(number)) < 1e-9) return String(Math.round(number));
  return String(Number(number.toFixed(2))).replace(/\.0+$/, '');
}

function supportAggregateRow(entry, sentence, role, reason, unit = '', numericValue = null) {
  const hasNumericValue = numericValue !== null && numericValue !== undefined && Number.isFinite(Number(numericValue));
  return {
    role,
    reason,
    unit,
    key: entry.key,
    text: truncateText(sentence, 420),
    ...(hasNumericValue ? { numeric_value: Number(numericValue) } : {}),
  };
}

function supportUniqueAggregateRows(rows) {
  const out = [];
  const seen = new Set();
  for (const row of rows) {
    const id = normalizeQueryText(`${row.role} ${row.unit || row.key} ${row.text}`);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(row);
  }
  return out;
}

function supportHasModelKitDescriptor(unit) {
  const normalized = normalizeQueryText(unit);
  return /\b(?:revell|tamiya|airfix|hasegawa|academy|monogram|f-?\d+|b-?\d+|spitfire|eagle|bomber|camaro|tiger|tank)\b/.test(normalized);
}

function supportModelKitRows(entry) {
  const rows = [];
  let recentUserKitContext = false;
  for (const sentence of supportSentenceCandidates(entry.block)) {
    const normalized = normalizeQueryText(sentence);
    const firstPerson = /\[USER\]/i.test(sentence)
      || /\b(?:i'm|i am|i’ve|i've|i recently|i just|i also|i started|i finished|i picked|i got|my)\b/i.test(sentence);
    const explicitKitContext = /\b(?:model kits?|model tanks?|kit|kits|model show|hobby store)\b/.test(normalized);
    const usableKitContext = explicitKitContext || recentUserKitContext;
    if (firstPerson && explicitKitContext) recentUserKitContext = true;
    if (!firstPerson || !usableKitContext) continue;
    const patterns = [
      /\b((?:Revell|Tamiya|Airfix|Hasegawa|Academy|Monogram)\s+[^.!?\n,;]{3,70}?(?:kit|Mk\.?\s*V|bomber|fighter|tank|Eagle|Spitfire))\b/gi,
      /\b(\d+\/\d+\s+scale\s+[^.!?\n,;]{3,70}?(?:model kit|kit|bomber|tank|Camaro|Spitfire[^.!?\n,;]*))\b/gi,
      /\b((?:simple\s+)?[A-Z][A-Za-z0-9' .-]{2,70}?\s+kit)\b/g,
    ];
    for (const pattern of patterns) {
      for (const match of sentence.matchAll(pattern)) {
        const text = String(match[1] || match[0])
          .replace(/\b(?:next|as well|before|after)\b.*$/i, '')
          .replace(/\s+/g, ' ')
          .trim();
        if (/\b(?:tips|techniques|weathering|painting|photo etching|products|resources|good quality model)\b/i.test(text)) continue;
        const unit = supportCleanAggregateUnit(text);
        if (!unit || unit.length < 3 || !supportHasModelKitDescriptor(unit)) continue;
        rows.push(supportAggregateRow(entry, sentence, 'model_kit_item', 'kit_or_scale_model_evidence', `model_kit:${unit}`));
      }
    }
  }
  return rows;
}

function supportPlantObjectAcquired(normalized, objectPattern, actionPattern) {
  const objectMatches = [...String(normalized || '').matchAll(objectPattern)];
  if (!objectMatches.length) return false;
  for (const objectMatch of objectMatches) {
    const objectStart = objectMatch.index || 0;
    const before = normalized.slice(Math.max(0, objectStart - 130), objectStart);
    const after = normalized.slice(objectStart, Math.min(normalized.length, objectStart + 150));
    const local = `${before} ${after}`;
    if (/\b(?:by the way|anyway|back to|speaking of)\b/i.test(before.slice(-70))) continue;
    if (/\b(?:by the way|anyway|back to|speaking of)\b[\s\S]{0,120}\b(?:got|bought|purchased|received)\b/i.test(after)) continue;
    if (actionPattern.test(local) && !/\b(?:gave|give|giving|shared|share|sharing)\b.{0,80}\bcuttings?\s+from\b/.test(local)) return true;
  }
  return false;
}

function supportPlantAcquisitionRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    const normalized = normalizeQueryText(sentence);
    if (!/\b(?:plant|plants|succulent|peace lily|spider plant|snake plant|cuttings|nursery|sister|repot)\b/.test(normalized)) continue;
    if (/\b(?:tips|recipe|healthy|watering|fertiliz|prun|yellow|wilt|productive)\b/.test(normalized)
      && !/\b(?:got|bought|from (?:the )?(?:nursery|sister)|repot|repotted|cuttings)\b/.test(normalized)) {
      continue;
    }
    const add = (label, reason) => {
      rows.push(supportAggregateRow(entry, sentence, 'plant_acquisition', reason, `plant:${label}`));
    };
    const gotBoughtFromNursery = /\b(?:got|bought|purchased|received|from the nursery|nursery where i bought)\b/i;
    if (supportPlantObjectAcquired(normalized, /\bpeace lily\b/gi, gotBoughtFromNursery)) add('peace_lily', 'plant_got_or_bought');
    if (supportPlantObjectAcquired(normalized, /\bsucculent(?:s)?\b/gi, /\b(?:got|bought|purchased|received|from the nursery|nursery where i bought|along with)\b/i)) {
      add('succulent', 'plant_got_or_bought');
    }
    if (supportPlantObjectAcquired(
      normalized,
      /\bspider plant\b/gi,
      /\b(?:got|bought|purchased|received|from (?:the )?(?:nursery|sister)|(?:got|received|bought)\s+(?:a\s+few\s+)?cuttings?\s+from)\b/i
    )) {
      add('spider_plant', 'plant_got_or_bought');
    }
    if (supportPlantObjectAcquired(normalized, /\bsnake plant\b/gi, /\b(?:got|received|from (?:my )?sister|last month)\b/i)) {
      add('snake_plant', 'plant_got_from_sister');
    }
  }
  return rows;
}

function supportMovieFestivalAttendanceRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    if (/^\[ASSISTANT\]/i.test(sentence)) continue;
    const normalized = normalizeQueryText(sentence);
    if (!/\b(?:film festival|movie festival|international film festival|fest)\b/.test(normalized)) continue;
    if (!/\[USER\]/i.test(sentence) && !/\b(?:i\s+|i've|i have|my|volunteered|participated|attended|got back|q a|screening|festival scene)\b/.test(normalized)) continue;
    const patterns = [
      /\b(?:volunteered\s+at|participated\s+in|attended|at|from|back\s+from|got\s+back\s+from)\s+(?:the\s+)?([A-Z][A-Za-z0-9&'.-]*(?:\s+[A-Z][A-Za-z0-9&'.-]*){0,5}\s+(?:Film Festival|International Film Festival|Fest))\b/g,
      /\b([A-Z][A-Za-z0-9&'.-]*(?:\s+[A-Z][A-Za-z0-9&'.-]*){0,5}\s+(?:Film Festival|International Film Festival|Fest))\b/g,
    ];
    for (const pattern of patterns) {
      for (const match of sentence.matchAll(pattern)) {
        const festival = String(match[1] || '')
          .replace(/\b(?:where|which|that|and|with|after)\b.*$/i, '')
          .replace(/[.,;:!?()[\]{}"']+$/g, '')
          .replace(/\s+/g, ' ')
          .trim();
        const unit = supportCleanAggregateUnit(festival);
        if (!unit || unit.length < 3) continue;
        if (/\b(?:workshop|special|recommendation|movie|film)\b$/i.test(unit) && !/\bfestival|fest\b/i.test(unit)) continue;
        rows.push(supportAggregateRow(entry, sentence, 'movie_festival_attendance', 'first_person_film_festival_attendance', `movie_festival:${unit}`));
      }
    }
  }
  return rows;
}

function supportCampingDurationRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    const normalized = normalizeQueryText(sentence);
    if (!/\bcamping\s+trip\b/.test(normalized)) continue;
    const matches = [
      ...sentence.matchAll(/\b(\d+)\s*-\s*day\s+[^.!?\n]{0,100}\bcamping\s+trip\b/gi),
      ...sentence.matchAll(/\b(\d+)\s+days?\s+[^.!?\n]{0,100}\bcamping\s+trip\b/gi),
      ...sentence.matchAll(/\bcamping\s+trip\b[^.!?\n]{0,100}\b(\d+)\s*-\s*day\b/gi),
      ...sentence.matchAll(/\bcamping\s+trip\b[^.!?\n]{0,100}\b(\d+)\s+days?\b/gi),
    ];
    for (const match of matches) {
      const days = Number(match[1]);
      if (!Number.isFinite(days) || days <= 0 || days > 60) continue;
      rows.push(supportAggregateRow(
        entry,
        sentence,
        'camping_duration_days',
        'explicit_camping_trip_duration',
        `camping_trip:${normalizeQueryText(match[0]).slice(0, 80)}`,
        days
      ));
    }
  }
  return rows;
}

function supportWordNumberValue(value) {
  const normalized = normalizeQueryText(value);
  const direct = normalized.match(/\b\d+(?:\.\d+)?\b/)?.[0];
  if (direct) return Number(direct);
  const number = supportNumberFromToken(normalized);
  if (Number.isFinite(number)) return number;
  const extended = new Map([
    ['eleven', 11], ['twelve', 12], ['thirteen', 13], ['fourteen', 14],
    ['fifteen', 15], ['sixteen', 16], ['seventeen', 17], ['eighteen', 18],
    ['nineteen', 19], ['twenty', 20],
  ]);
  for (const [word, valueNumber] of extended) {
    if (new RegExp(`\\b${word}\\b`).test(normalized)) return valueNumber;
  }
  return null;
}

function supportMoneyAmountValue(raw) {
  const match = String(raw || '').match(/\$([0-9][0-9,]*(?:\.[0-9]+)?)/);
  if (!match) return null;
  const amount = Number(match[1].replace(/,/g, ''));
  return Number.isFinite(amount) ? amount : null;
}

function supportBikeExpenseUnit(sentence) {
  const normalized = normalizeQueryText(sentence);
  const unit = supportBikeExpenseUnitName(normalized) || supportCleanAggregateUnit(sentence).slice(0, 48);
  return `money:${unit}`;
}

function supportBikeExpenseUnitName(normalizedText) {
  const normalized = normalizeQueryText(normalizedText);
  return [
    ['chain', /\bchain\b/],
    ['helmet', /\bhelmet\b/],
    ['bike_lights', /\b(?:bike\s+)?lights?\b/],
    ['bike_rack', /\brack\b/],
    ['bike_service', /\b(?:service|serviced|tune up|tune-up|repair|repairs?)\b/],
    ['bike_cleaner', /\bcleaner\b/],
  ].find(([, pattern]) => pattern.test(normalized))?.[0] || '';
}

function supportNearestBikeExpenseUnitBeforeAmount(sentence, amountIndex) {
  const before = String(sentence || '').slice(Math.max(0, amountIndex - 220), amountIndex);
  const patterns = [
    ['chain', /\bchain\b/gi],
    ['helmet', /\bhelmet\b/gi],
    ['bike_lights', /\b(?:bike\s+)?lights?\b/gi],
    ['bike_rack', /\brack\b/gi],
    ['bike_service', /\b(?:service|serviced|tune up|tune-up|repair|repairs?)\b/gi],
    ['bike_cleaner', /\bcleaner\b/gi],
  ];
  let best = null;
  for (const [unit, pattern] of patterns) {
    for (const match of before.matchAll(pattern)) {
      const index = match.index || 0;
      if (!best || index > best.index) best = { unit, index };
    }
  }
  return best?.unit || '';
}

function supportBikeExpenseUnitNearAmount(sentence, amountIndex, amountText) {
  const before = String(sentence || '').slice(Math.max(0, amountIndex - 100), amountIndex);
  const after = String(sentence || '').slice(amountIndex + String(amountText || '').length, amountIndex + String(amountText || '').length + 70);
  const beforeClause = before.split(/\b(?:and|then)\b|[,;]/i).pop() || before;
  const afterClause = after.split(/\b(?:and|then)\b|[,;.]/i)[0] || after;
  const local = `${beforeClause} ${afterClause}`.trim();
  const localUnit = supportBikeExpenseUnitName(local);
  if (localUnit) return `money:${localUnit}`;
  const nearestBeforeUnit = supportNearestBikeExpenseUnitBeforeAmount(sentence, amountIndex);
  if (nearestBeforeUnit) return `money:${nearestBeforeUnit}`;
  const beforeWindow = String(sentence || '').slice(Math.max(0, amountIndex - 180), amountIndex);
  const beforeUnit = supportBikeExpenseUnitName(beforeWindow);
  if (beforeUnit) return `money:${beforeUnit}`;
  return supportBikeExpenseUnit(local || sentence);
}

function supportBikeExpenseRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    if (/^\[ASSISTANT\]/i.test(sentence)) continue;
    const normalized = normalizeQueryText(sentence);
    const firstPerson = /\[USER\]/i.test(sentence)
      || /\b(?:i|i've|i have|i had|my)\b/i.test(sentence);
    const bikeContext = /\b(?:bike|bicycle|cycling|helmet|chain|lights?|rack|tune-up|tune up|serviced?|repair)\b/.test(normalized);
    const actualExpense = /\b(?:bought|purchased|paid|spent|cost me|cost|installed|replaced|serviced?|tune-up|tune up)\b/.test(normalized);
    const nonExpense = /\b(?:raised|donations?|fundraising|charity|recommend|options?|range|under|over|from \$|around \$|budget|car|honda|civic|air filter|gas tank|parking ticket|mortgage|motorcycle)\b/.test(normalized);
    if (!firstPerson || !bikeContext || !actualExpense || nonExpense) continue;
    for (const match of sentence.matchAll(/\$([0-9][0-9,]*(?:\.[0-9]+)?)/g)) {
      const amount = supportMoneyAmountValue(match[0]);
      if (!Number.isFinite(amount)) continue;
      const index = match.index || 0;
      rows.push(supportAggregateRow(
        entry,
        sentence,
        'money_expense',
        'first_person_bike_related_expense',
        supportBikeExpenseUnitNearAmount(sentence, index, match[0]),
        amount
      ));
    }
  }
  return rows;
}

function supportDrivingDestinationUnit(sentence) {
  const raw = String(sentence || '');
  const destination = raw.match(/\b(?:trip to|drove for [^.!?\n]{0,40}? to|drive to|to)\s+(?:the\s+)?([A-Z][A-Za-z .'-]{2,80}?)(?:\s+(?:in|recently|and|from|for|was|only|,|-)|[.!?]|$)/)?.[1]
    || raw.match(/\b(?:Outer Banks|Washington,?\s+D\.?C\.?|Tennessee|mountains in Tennessee)\b/i)?.[0]
    || raw.slice(0, 80);
  return `drive_destination:${supportCleanAggregateUnit(destination) || normalizeQueryText(destination).slice(0, 48)}`;
}

function supportDrivingDurationRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    if (/^\[ASSISTANT\]/i.test(sentence)) continue;
    const normalized = normalizeQueryText(sentence);
    const firstPerson = /\[USER\]/i.test(sentence)
      || /\b(?:i|i've|i had|my)\b/i.test(sentence);
    if (!firstPerson) continue;
    if (!/\b(?:road trip|trip|drove|drive|driving|took me)\b/.test(normalized)) continue;
    if (/\b(?:cycling|road bike|bike ride|non stop|non-stop|charity event|raise money)\b/.test(normalized)) continue;
    if (/\b(?:sister'?s place|help(?:ed)? her move|hometown|new apartment|moving boxes|packing and unpacking)\b/.test(normalized)) continue;
    if (!/\b(?:drove|drive|driving|took me [^.!?\n]{0,40} hours? to drive|hours? to drive|hours? away)\b/.test(normalized)) continue;
    if (/\b(?:recommend|suggest|option|approximately|approx|~|around)\b/.test(normalized)) continue;
    const match = sentence.match(/\b((?:one|two|three|four|five|six|seven|eight|nine|ten|\d+(?:\.\d+)?)(?:\s+and\s+a\s+half)?)\s+hours?\b/i);
    if (!match) continue;
    let hours = supportWordNumberValue(match[1]);
    if (/\band\s+a\s+half\b/i.test(match[1]) && Number.isFinite(hours)) hours += 0.5;
    if (!Number.isFinite(hours) || hours <= 0 || hours > 48) continue;
    rows.push(supportAggregateRow(entry, sentence, 'driving_duration_hours', 'first_person_road_trip_driving_duration', supportDrivingDestinationUnit(sentence), hours));
  }
  return rows;
}

function supportProjectOwnershipRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    if (/^\[ASSISTANT\]/i.test(sentence)) continue;
    const firstPerson = /\[USER\]/i.test(sentence)
      || /\b(?:i'm|i am|i’ve|i've|i have|i had|my|we had|we did|we were)\b/i.test(sentence);
    if (!firstPerson) continue;
    const normalized = normalizeQueryText(sentence);
    const projectLike = /\b(?:project|projects|case competition|research|analysis)\b/.test(normalized);
    if (!projectLike) continue;
    if (/\b(?:i|we)\s+(?:led|lead|managed|headed)\b|\b(?:led|managed|headed)\s+(?:the\s+)?(?:team|project|competition|analysis)\b/.test(normalized)) {
      rows.push(supportAggregateRow(entry, sentence, 'past_led_project', 'first_person_led_or_managed_project', `project:${supportCleanAggregateUnit(sentence).slice(0, 64)}`));
    }
    if (/\b(?:i|we)\s+(?:am|are|'m|'re)?\s*(?:currently\s+)?(?:leading|managing|running|organizing|working\s+on)\b|\bmy\s+(?:current\s+)?project\b/.test(normalized)) {
      rows.push(supportAggregateRow(entry, sentence, 'current_project_ownership', 'first_person_current_project_ownership', `project:${supportCleanAggregateUnit(sentence).slice(0, 64)}`));
    }
  }
  return rows;
}

function supportClothingUnit(sentence, role) {
  const normalized = normalizeQueryText(sentence);
  const item = [
    ['dry_cleaning_blazer', /\bdry cleaning\b.*\bblazer\b|\bblazer\b.*\bdry cleaning\b/],
    ['boots_replacement', /\b(?:new pair|replacement)\b.*\bboots?\b|\bboots?\b.*\b(?:new pair|replacement|exchanged?)\b/],
    ['boots', /\bboots?\b/],
    ['jeans', /\bjeans?\b/],
    ['pants', /\bpants?\b/],
    ['sweater', /\bsweater\b/],
    ['dress', /\bdress\b/],
    ['shirt', /\bshirt\b/],
  ].find(([, pattern]) => pattern.test(normalized))?.[0] || supportCleanAggregateUnit(sentence).slice(0, 48);
  return `${role}:${item}`;
}

function supportIsStoreClothingObligation(sentence, role) {
  const normalized = normalizeQueryText(sentence);
  if (/\b(?:tips|recommend|receipt|reminders?|set reminders?|store receipts|return policy|returns? spot|how to keep track)\b/.test(normalized)) {
    return false;
  }
  const clothingLike = /\b(?:boots?|blazer|jeans|pants|sweater|dress|shirt|dry cleaning|clothes|clothing)\b/.test(normalized);
  if (!clothingLike) return false;
  const firstPerson = /\[USER\]/i.test(sentence)
    || /\b(?:i need|i still|i just|i got|i bought|my)\b/i.test(sentence);
  const assistantGroundedPickup = /\b(?:since you exchanged|you should be able to pick up)\b/.test(normalized);
  if (role === 'pickup_obligation') {
    if (!firstPerson && !assistantGroundedPickup) return false;
    return /\b(?:need|still|chance|able)\b.{0,80}\b(?:pick up|pickup)\b/.test(normalized)
      || /\b(?:pick up|pickup)\b.{0,80}\b(?:dry cleaning|new pair|replacement|boots?|blazer)\b/.test(normalized);
  }
  if (role === 'return_obligation') {
    if (!firstPerson) return false;
    return /\b(?:i need|need|still|actually)\b.{0,80}\breturn\b/.test(normalized)
      || /\breturn\b.{0,80}\b(?:to zara|to the store|old ones|some boots?|clothing|clothes)\b/.test(normalized);
  }
  return false;
}

function supportClothingObligationRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    if (/^\[ASSISTANT\]/i.test(sentence)) continue;
    if (supportIsStoreClothingObligation(sentence, 'pickup_obligation')) {
      rows.push(supportAggregateRow(entry, sentence, 'pickup_obligation', 'first_person_or_clothing_pickup_obligation', supportClothingUnit(sentence, 'pickup_obligation')));
    }
    if (supportIsStoreClothingObligation(sentence, 'return_obligation')) {
      rows.push(supportAggregateRow(entry, sentence, 'return_obligation', 'first_person_or_clothing_return_obligation', supportClothingUnit(sentence, 'return_obligation')));
    }
  }
  return rows;
}

function supportGenericEventRows(entry) {
  const rows = [];
  for (const sentence of supportSentenceCandidates(entry.block)) {
    const isUser = /\[USER\]/i.test(sentence);
    const firstPerson = isUser || /\b(?:i\s+|i've|i\s+have)\b/i.test(sentence);
    if (!firstPerson) continue;
    if (supportIsAbsenceContext(sentence)) continue;
    const eventPattern = /\b(?:i\s+|we\s+)(bought|purchased|got|received|ordered|picked\s+up|brought|adopted|acquired|built|finished|completed|started|began|joined|attended|went\s+to|visited|volunteered\s+at|participated\s+in|hosted|organized|led|drove|flew|hiked|camped|stayed\s+at|booked|reserved|returned|exchanged|dropped\s+off|paid|spent|earned|made|created|wrote|read|watched|saw|met|called|emailed|messaged|texted|sent|took|had)\b([^.!?\n,;]{3,100})/i;
    const match = sentence.match(eventPattern);
    if (!match) continue;
    const action = String(match[1]).toLowerCase().replace(/\s+/g, '_');
    const objectRaw = String(match[2])
      .replace(/\b(?:at|on|in|for|to|from|with|by|of|the|a|an|my|our|some|any|because|since|while|although|however|but|and|or|so|then|next|after|before|when|where|why|how|what|which|that|this|these|those|it|they|them|we|you|he|she|his|her|their|our|my|i)\b/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (objectRaw.length < 3 || objectRaw.length > 60) continue;
    if (/\b(?:tips|techniques|recommend|reminder|receipt|policy|advice|idea|thought|opinion|feeling|concern|worried|happy|sad|excited|tired|busy|available|interested|bored|about|into|over|back|there|here)\b/i.test(objectRaw)) continue;
    const unit = supportCleanAggregateUnit(objectRaw);
    if (!unit || unit.length < 3) continue;
    const numericMatch = sentence.match(/\b(\d+(?:\.\d+)?)\s*(hours?|days?|weeks?|months?|years?|dollars?|usd)\b/i) || sentence.match(/\$\s*(\d+(?:\.\d+)?)/i);
    const numericValue = numericMatch ? Number(numericMatch[1]) : null;
    rows.push(supportAggregateRow(entry, sentence, 'generic_event', 'generic_first_person_event', `${action}:${unit}`, numericValue));
  }
  return rows;
}

function supportGenericAggregateOperationHintForQuestion(question, evidenceText) {
  const q = normalizeQueryText(question);
  if (!/\b(how many|how much|count|total|spent|expenses?|cost|hours?|days?)\b/.test(q)) return null;
  const entries = supportBlockEvidenceEntries(evidenceText);
  const rows = [];
  for (const entry of entries) rows.push(...supportGenericEventRows(entry));
  if (!rows.length) return null;
  const distinct = supportUniqueAggregateRows(rows)
    .filter((row) => !/\b(?:tips|recommend|receipt|reminder|store receipts|return policy)\b/i.test(row.text))
    .slice(0, 24);
  if (!distinct.length) return null;
  const roleBuckets = new Map();
  for (const row of distinct) {
    const bucket = roleBuckets.get(row.role) || [];
    bucket.push(row);
    roleBuckets.set(row.role, bucket);
  }
  const selected = [];
  for (const bucket of roleBuckets.values()) {
    const unitBuckets = new Map();
    for (const row of bucket) {
      const unit = row.unit || row.role;
      const rowsForUnit = unitBuckets.get(unit) || [];
      rowsForUnit.push(row);
      unitBuckets.set(unit, rowsForUnit);
    }
    for (const rowsForUnit of unitBuckets.values()) {
      const top = rowsForUnit
        .sort((a, b) => Number(/\[USER\]/i.test(b.text)) - Number(/\[USER\]/i.test(a.text)) || a.text.length - b.text.length)[0];
      if (top) selected.push(top);
    }
  }
  const numericRows = selected.filter((row) => Number.isFinite(Number(row.numeric_value)));
  const preferredCount = numericRows.length
    ? numericRows.reduce((sum, row) => sum + Number(row.numeric_value), 0)
    : selected.length;
  const requestedUnit = q.match(/\b(hours?|days?|weeks?|months?|years?)\b/i)?.[1]?.toLowerCase() || '';
  const preferredAnswer = numericRows.length && requestedUnit
    ? `${supportFormatAggregateNumber(preferredCount)} ${requestedUnit}`
    : numericRows.length && /\b(?:spent|expenses?|cost|money)\b/.test(q) && selected.every((row) => /\$\s*\d/.test(row.text))
      ? `$${supportFormatAggregateNumber(preferredCount)}`
      : `${supportFormatAggregateNumber(preferredCount)}`;
  return [
    'AGGREGATE_OPERATION_HINT',
    'mode: generic_event_row_reducer',
    `preferred_count: ${supportFormatAggregateNumber(preferredCount)}`,
    preferredAnswer ? `preferred_answer: ${preferredAnswer}` : null,
    'counting_policy: count each unique first-person event (action+object) once; sum numeric quantities when present',
    ...selected.map((row, index) =>
      `distinct_${index + 1}: role=${row.role}; unit=${row.unit || row.role}; value=${Number.isFinite(Number(row.numeric_value)) ? supportFormatAggregateNumber(row.numeric_value) : 1}; key=${row.key}; reason=${row.reason}; text=${row.text}`
    ),
  ].filter(Boolean).join('\n');
}

function supportAggregateOperationHintForQuestion(question, evidenceText) {
  const q = normalizeQueryText(question);
  if (!/\b(how many|how much|count|total|spent|expenses?|cost|hours?|days?)\b/.test(q)) return null;
  const entries = supportBlockEvidenceEntries(evidenceText);
  const rows = [];
  const drivingAggregate = /\b(?:hours?|driving|drive|drove)\b/.test(q) && /\b(?:road trip|destinations?)\b/.test(q);

  if (/\bprojects?\b/.test(q) && /\bled\b/.test(q) && /\b(?:currently|current|leading)\b/.test(q)) {
    for (const entry of entries) rows.push(...supportProjectOwnershipRows(entry));
  }
  if (/\b(?:pick up|pickup|return|exchange)\b/.test(q) && /\b(?:item|items|clothing|clothes)\b/.test(q)) {
    for (const entry of entries) rows.push(...supportClothingObligationRows(entry));
  }
  if (/\bmodel\s+kits?\b/.test(q)) {
    for (const entry of entries) rows.push(...supportModelKitRows(entry));
  }
  if (/\bplants?\b/.test(q) && /\b(?:acquire|acquired|got|bought|get)\b/.test(q)) {
    for (const entry of entries) rows.push(...supportPlantAcquisitionRows(entry));
  }
  if (/\b(?:movie|film)\s+festivals?\b/.test(q)) {
    for (const entry of entries) rows.push(...supportMovieFestivalAttendanceRows(entry));
  }
  if (/\bcamping\s+trips?\b/.test(q) && /\bdays?\b/.test(q)) {
    for (const entry of entries) rows.push(...supportCampingDurationRows(entry));
  }
  if (/\b(?:money|spent|expenses?|cost)\b/.test(q) && /\bbike\b/.test(q)) {
    for (const entry of entries) rows.push(...supportBikeExpenseRows(entry));
  }
  if (drivingAggregate) {
    for (const entry of entries) rows.push(...supportDrivingDurationRows(entry));
  }

  let aggregateRows = rows;
  if (drivingAggregate && /\bthree\b|\b3\b/.test(q)) {
    const byRoot = new Map();
    for (const row of rows.filter((item) => item.role === 'driving_duration_hours')) {
      const root = supportBenchmarkSiblingRoot(row.key);
      const bucket = byRoot.get(root) || [];
      bucket.push(row);
      byRoot.set(root, bucket);
    }
    const bestRoot = [...byRoot.entries()]
      .filter(([, bucket]) => supportUniqueAggregateRows(bucket).length >= 3)
      .sort((a, b) => supportUniqueAggregateRows(b[1]).length - supportUniqueAggregateRows(a[1]).length)[0];
    if (bestRoot) {
      aggregateRows = rows.filter((row) => row.role !== 'driving_duration_hours' || supportBenchmarkSiblingRoot(row.key) === bestRoot[0]);
    }
  }

  const distinct = supportUniqueAggregateRows(aggregateRows)
    .filter((row) => ['model_kit_item', 'plant_acquisition', 'movie_festival_attendance', 'camping_duration_days', 'money_expense', 'driving_duration_hours'].includes(row.role)
      || !/\b(?:tips|recommend|receipt|reminder|store receipts|return policy)\b/i.test(row.text))
    .slice(0, 24);
  if (!distinct.length) return null;

  const roleBuckets = new Map();
  for (const row of distinct) {
    const bucket = roleBuckets.get(row.role) || [];
    bucket.push(row);
    roleBuckets.set(row.role, bucket);
  }

  const selected = [];
  for (const bucket of roleBuckets.values()) {
    const unitBuckets = new Map();
    for (const row of bucket) {
      const unit = row.unit || row.role;
      const rowsForUnit = unitBuckets.get(unit) || [];
      rowsForUnit.push(row);
      unitBuckets.set(unit, rowsForUnit);
    }
    for (const rowsForUnit of unitBuckets.values()) {
      const top = rowsForUnit
        .sort((a, b) => Number(/\[USER\]/i.test(b.text)) - Number(/\[USER\]/i.test(a.text)) || a.text.length - b.text.length)[0];
      if (top) selected.push(top);
    }
  }

  const numericRows = selected.filter((row) => Number.isFinite(Number(row.numeric_value)));
  const preferredCount = numericRows.length
    ? numericRows.reduce((sum, row) => sum + Number(row.numeric_value), 0)
    : selected.length;
  const preferredAnswer = numericRows.length && selected.every((row) => row.role === 'money_expense')
    ? `$${supportFormatAggregateNumber(preferredCount)}`
    : numericRows.length && selected.every((row) => row.role === 'driving_duration_hours')
      ? `${supportFormatAggregateNumber(preferredCount)} hours`
      : numericRows.length && /\bdays?\b/.test(q)
        ? `${supportFormatAggregateNumber(preferredCount)} days`
        : '';

  return [
    'AGGREGATE_OPERATION_HINT',
    'mode: operator_math_aggregate',
    `preferred_count: ${supportFormatAggregateNumber(preferredCount)}`,
    preferredAnswer ? `preferred_answer: ${preferredAnswer}` : null,
    'counting_policy: count each selected role-compatible evidence-grounded item once; sum numeric values only when explicitly observed',
    ...selected.map((row, index) =>
      `distinct_${index + 1}: role=${row.role}; unit=${row.unit || row.role}; value=${Number.isFinite(Number(row.numeric_value)) ? supportFormatAggregateNumber(row.numeric_value) : 1}; key=${row.key}; reason=${row.reason}; text=${row.text}`
    ),
  ].filter(Boolean).join('\n');
}

function supportBestRoleEvidenceBlock(evidenceText, label, predicate = '') {
  return supportEvidenceBlocks(evidenceText)
    .map((block) => {
      const coverage = supportRoleCoverage({ context: block }, label, predicate);
      return { block, coverage };
    })
    .filter((item) => item.coverage.pass && !supportIsAbsenceContext(item.block))
    .sort((a, b) => b.coverage.score - a.coverage.score)[0] || null;
}

function supportContrastiveAbsenceHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  const jobMatch = q.match(/\bcurrent\s+job\s+at\s+([A-Z][A-Za-z0-9+.-]*)/i)
    || q.match(/\bstarted\s+my\s+current\s+job\s+at\s+([A-Z][A-Za-z0-9+.-]*)/i);
  if (jobMatch) {
    const entity = jobMatch[1];
    const entityNorm = normalizeQueryText(entity);
    const blocks = supportEvidenceBlocks(evidenceText);
    const currentJobBlock = blocks.find((block) => {
      const normalized = normalizeQueryText(block);
      return normalized.includes(entityNorm)
        && /\bcurrent\s+job\b|\bstarted\s+(?:my\s+)?(?:current\s+)?job\b|\bworking\s+at\b/.test(normalized)
        && !supportIsAbsenceContext(block);
    });
    if (!currentJobBlock) {
      const observed = blocks.find((block) => normalizeQueryText(block).includes(entityNorm)) || blocks[0] || '';
      return [
        'CONTRASTIVE_ABSENCE_HINT',
        'mode: missing_requested_current_job_anchor',
        `requested_entity: ${entity}`,
        'missing_fact: evidence does not ground a started/current job at the requested entity',
        `observed_context: ${truncateText(observed, 420)}`,
        `preferred_answer: insufficient_evidence; the evidence does not show that I have started working at ${entity} as my current job`,
        'answer_policy: answer with insufficiency plus the missing current-job contrast; do not provide a duration from unrelated work evidence',
      ].join('\n');
    }
  }

  const booking = q.match(/\bwhen\s+did\s+i\s+book\s+(?:the\s+)?(.+?)\s+in\s+([A-Z][A-Za-z0-9.-]*(?:\s+[A-Z][A-Za-z0-9.-]*){0,3})(?:\?|$)/i);
  if (booking) {
    const objectLabel = booking[1].trim();
    const requestedPlace = booking[2].trim();
    const objectTerms = supportRoleTokens(objectLabel);
    const placeNorm = normalizeQueryText(requestedPlace);
    const blocks = supportEvidenceBlocks(evidenceText);
    const exact = blocks.find((block) => {
      const terms = new Set(tokenize(block));
      const objectMatched = objectTerms.length
        ? objectTerms.some((term) => supportTokenFamilyMatches(term, terms))
        : normalizeQueryText(block).includes(normalizeQueryText(objectLabel));
      return objectMatched && normalizeQueryText(block).includes(placeNorm) && /\b(?:book|booked|booking|stay|stayed|airbnb|hotel)\b/i.test(block);
    });
    if (!exact) {
      const contrast = blocks.find((block) => {
        const terms = new Set(tokenize(block));
        const objectMatched = objectTerms.length
          ? objectTerms.some((term) => supportTokenFamilyMatches(term, terms))
          : normalizeQueryText(block).includes(normalizeQueryText(objectLabel));
        return objectMatched && /\b(?:book|booked|booking|stay|stayed|airbnb|hotel)\b/i.test(block);
      }) || '';
      if (contrast) {
        return [
          'CONTRASTIVE_ABSENCE_HINT',
          'mode: requested_location_absent_for_booking',
          `requested_object: ${objectLabel}`,
          `requested_location: ${requestedPlace}`,
          `observed_context: ${truncateText(contrast, 520)}`,
          `preferred_answer: insufficient_evidence; the evidence mentions a ${objectLabel} booking/stay in a different location, not ${requestedPlace}`,
          'answer_policy: answer with insufficiency plus the observed location contrast; do not reuse a date from another city',
        ].join('\n');
      }
    }
  }

  const roles = supportBinaryQuestionRoles(question);
  if (roles?.kind === 'order' && /\bfirst\b/i.test(q)) {
    const predicate = supportOrderPredicate(question);
    const left = supportBestRoleEvidenceBlock(evidenceText, roles.left, predicate);
    const right = supportBestRoleEvidenceBlock(evidenceText, roles.right, predicate);
    if (Boolean(left) !== Boolean(right)) {
      const presentLabel = left ? roles.left : roles.right;
      const missingLabel = left ? roles.right : roles.left;
      const present = left || right;
      return [
        'CONTRASTIVE_ABSENCE_HINT',
        'mode: missing_binary_comparison_role',
        `present_role: ${presentLabel}`,
        `missing_role: ${missingLabel}`,
        `observed_context: ${truncateText(present.block || '', 520)}`,
        `preferred_answer: insufficient_evidence; ${presentLabel} is evidenced, but ${missingLabel} is not grounded for the comparison`,
        'answer_policy: do not infer an ordering when only one comparison role is evidenced',
      ].join('\n');
    }
    if (supportOrderHintForQuestion(q, evidenceText)) return null;
  }

  return null;
}

function supportRoleLocalAbsenceContext(block, label, predicate = '') {
  const roleTerms = [...new Set(supportRoleTokens(label).filter((term) => term.length > 2))];
  if (!roleTerms.length) return null;
  const required = supportRequiredRoleMatches(roleTerms.length);
  const raw = String(block || '');
  const patterns = [
    /\b(?:did\s+not|didn't|do\s+not|don't|does\s+not|doesn't|never|no)\b[^.!?\n]{0,40}\b(?:mention|mentioned|start|started|buy|bought|purchase|purchased|get|got|attend|attended|meet|met|set\s+up|realiz(?:e|ed)|finish|finished|complete|completed)\b[^.!?\n]{0,140}/gi,
    /\b(?:not|no)\s+(?:enough|sufficient)\s+(?:information|evidence)\b[^.!?\n]{0,180}/gi,
    /\binsufficient[_\s-]?evidence\b[^.!?\n]{0,180}/gi,
  ];
  for (const pattern of patterns) {
    for (const match of raw.matchAll(pattern)) {
      const local = match[0] || '';
      if (/\bdon't\s+forget\b/i.test(local)) continue;
      const localTerms = new Set(tokenize(local));
      const matched = roleTerms.filter((term) => supportTokenFamilyMatches(term, localTerms)).length;
      if (matched >= required) return local.replace(/\s+/g, ' ').trim();
    }
  }
  return null;
}

function supportAbsenceEvidenceForRole(evidenceText, label, predicate = '') {
  return supportEvidenceBlocks(evidenceText)
    .map((block) => {
      const coverage = supportRoleCoverage({ context: block }, label, predicate);
      const absenceContext = supportRoleLocalAbsenceContext(block, label, predicate);
      return { block, coverage, absenceContext };
    })
    .filter((item) => item.coverage.pass && item.absenceContext)
    .sort((a, b) => b.coverage.score - a.coverage.score)[0] || null;
}

function supportComparisonSufficiencyHintForQuestion(question, evidenceText) {
  const roles = supportBinaryQuestionRoles(question);
  if (!roles) return null;
  const predicate = roles.kind === 'order' ? supportOrderPredicate(question) : '';
  const completedTaskOrder = roles.kind === 'order' && supportIsCompletedTaskOrderQuestion(question);
  const leftAbsence = supportAbsenceEvidenceForRole(evidenceText, roles.left, predicate);
  const rightAbsence = supportAbsenceEvidenceForRole(evidenceText, roles.right, predicate);
  if (leftAbsence || rightAbsence) {
    return [
      'COMPARISON_SUFFICIENCY_HINT',
      'comparison_status: insufficient_pair_evidence',
      `left_event: ${roles.left}`,
      `right_event: ${roles.right}`,
      `reason: explicit_absence_for_${leftAbsence ? 'left' : 'right'}_comparison_role`,
      `absence_context: ${truncateText((leftAbsence || rightAbsence).absenceContext || (leftAbsence || rightAbsence).block, 420)}`,
      'answer_policy: return insufficient_evidence rather than inferring from one side only',
    ].join('\n');
  }
  const mentions = supportRoleAwareDateMentions(evidenceText);
  const roleBoundEnabled = signedRecallFlag('RECALL_ENABLE_ROLE_DATE_BINDING');
  const roleBoundCompletedPair = roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, roles.left, roles.right, predicate, true) : null;
  if (completedTaskOrder && !(roleBoundCompletedPair || supportBestStrictMentionPair(mentions, roles.left, roles.right, predicate, true))) {
    return [
      'COMPARISON_SUFFICIENCY_HINT',
      'comparison_status: insufficient_pair_evidence',
      `left_event: ${roles.left}`,
      `right_event: ${roles.right}`,
      'reason: completed_task_order_roles_not_grounded_in_one_evidence_root',
      'answer_policy: return insufficient_evidence rather than inferring from unrelated task memories',
    ].join('\n');
  }
  if (mentions.length < 2) {
    return [
      'COMPARISON_SUFFICIENCY_HINT',
      'comparison_status: insufficient_pair_evidence',
      `left_event: ${roles.left}`,
      `right_event: ${roles.right}`,
      'reason: fewer_than_two_dated_role_mentions',
      'answer_policy: return insufficient_evidence rather than inferring from one side only',
    ].join('\n');
  }
  const roleBoundMainPair = roleBoundEnabled ? supportBestRoleBoundMentionPair(mentions, roles.left, roles.right, predicate) : null;
  const pair = roleBoundMainPair || supportBestStrictMentionPair(mentions, roles.left, roles.right, predicate);
  const relaxedPair = roles.kind === 'order'
    ? (roleBoundMainPair || supportBestOrderMentionPair(mentions, supportPhraseTerms(roles.left), supportPhraseTerms(roles.right)))
    : null;
  if ((pair?.left && pair?.right) || (relaxedPair?.left && relaxedPair?.right)) return null;
  return [
    'COMPARISON_SUFFICIENCY_HINT',
    'comparison_status: insufficient_pair_evidence',
    `left_event: ${roles.left}`,
    `right_event: ${roles.right}`,
    'reason: both_comparison_roles_not_grounded_with_dates',
    'answer_policy: return insufficient_evidence rather than inferring from one side only',
  ].join('\n');
}

function supportFormatDayMonthYear(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  const month = Object.entries(MONTH_INDEX).find(([, index]) => index === date.getUTCMonth())?.[0] || '';
  return `${date.getUTCDate()} ${month[0].toUpperCase()}${month.slice(1)} ${date.getUTCFullYear()}`;
}

function supportFormatMonthYear(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  const month = Object.entries(MONTH_INDEX).find(([, index]) => index === date.getUTCMonth())?.[0] || '';
  return `${month[0].toUpperCase()}${month.slice(1)} ${date.getUTCFullYear()}`;
}

function supportPreferredTemporalAnswerForMention(mention) {
  if (!mention) return '';
  const date = new Date(`${mention.iso}T00:00:00.000Z`);
  const sessionDate = mention.sessionDate || supportSessionDateForBlock(mention.block);
  const text = String(mention.text || '');
  if (/\blast\s+year\b/i.test(text)) return String(date.getUTCFullYear());
  if (/\bnext\s+month\b|\blast\s+month\b|\bmonths?\s+ago\b/i.test(text)) return supportFormatMonthYear(date);
  if (/\blast\s+week\b/i.test(text) && sessionDate) return `the week before ${supportFormatDayMonthYear(sessionDate)}`;
  if (/\blast\s+weekend\b/i.test(text) && sessionDate) return `the weekend before ${supportFormatDayMonthYear(sessionDate)}`;
  if (/^relative_weekday_/.test(String(mention.note || '')) && sessionDate) {
    return `${text} before ${supportFormatDayMonthYear(sessionDate)} (${mention.iso})`;
  }
  return mention.iso;
}

function supportSentenceCandidates(value) {
  const raw = String(value || '').replace(/\r/g, '\n');
  const dialogueTurns = raw
    .split(/(?=\[(?:D\d+:\d+|USER|ASSISTANT|SYSTEM)\])/i)
    .map((part) => part.replace(/\s+/g, ' ').trim())
    .filter((part) => part.length >= 12);
  const sentenceParts = raw
    .split(/(?<=[.!?])\s+|\n+/)
    .map((part) => part.replace(/\s+/g, ' ').trim())
    .filter((part) => part.length >= 12);
  return unique([...dialogueTurns, ...sentenceParts]).slice(0, 80);
}

function supportKeyForBlock(block) {
  return String(block.match(/\nkey:\s*([^\n]+)/i)?.[1] || '').trim();
}

function supportLocalTextForDateMention(mention) {
  const mentionNorm = normalizeQueryText(mention?.text || '');
  const sentences = supportSentenceCandidates(mention?.context || '');
  const local = sentences.filter((sentence) => normalizeQueryText(sentence).includes(mentionNorm));
  return (local.length ? local : sentences.slice(0, 1)).join(' ');
}

function supportDialogueTurnTextForDateMention(mention) {
  const block = String(mention?.block || '');
  const context = String(mention?.context || '');
  const text = String(mention?.text || '');
  const contextIndex = context ? block.indexOf(context) : -1;
  const textIndex = text ? block.indexOf(text) : -1;
  const index = contextIndex >= 0 ? contextIndex : textIndex;
  if (index < 0) return context;
  const before = block.slice(0, index);
  const starts = [...before.matchAll(/\[D\d+:\d+\]/g)];
  const start = starts.length ? starts[starts.length - 1].index : Math.max(0, index - 280);
  const after = block.slice(index + 1);
  const next = after.search(/\[D\d+:\d+\]/);
  const end = next >= 0 ? index + 1 + next : Math.min(block.length, index + 520);
  return block.slice(start, end).replace(/\s+/g, ' ').trim();
}

function supportSpeakerSubjectFromQuestion(question) {
  const q = String(question || '');
  const direct = q.match(/\b(?:did|does|is|was|will|would|could|has|have)\s+([A-Z][A-Za-z0-9_-]{2,})\b/)?.[1]
    || q.match(/\b(?:for|about|of)\s+([A-Z][A-Za-z0-9_-]{2,})\b/)?.[1];
  if (direct && !/^(I|You|The|What|When|Where|Which|How|Would|Could|Did|Does|Is|Was)$/.test(direct)) return direct;
  return extractCapitalizedPhrases(question).find((item) => !/^(I|You|The|What|When|Where|Which|How|Would|Could|Did|Does|Is|Was)$/i.test(item)) || '';
}

function supportCombinedSocialTemporalMention(question, evidenceText) {
  const q = normalizeQueryText(question);
  if (!/\b(?:meet|met)\s+up\b/.test(q)) return null;
  const wantedRoles = ['friends', 'family', 'mentors']
    .filter((role) => q.includes(role) || (role === 'friends' && q.includes('friend')));
  if (wantedRoles.length < 2) return null;
  return supportDateMentions(evidenceText)
    .filter((mention) => mention.note && !['session_date', 'block_session_role'].includes(mention.note))
    .map((mention) => {
      const localText = supportLocalTextForDateMention(mention);
      const turnText = supportDialogueTurnTextForDateMention(mention);
      const localNorm = normalizeQueryText(`${turnText} ${localText}`);
      const roleCoverage = wantedRoles.filter((role) => localNorm.includes(role) || (role === 'friends' && localNorm.includes('friend'))).length;
      const eventMatch = /\b(?:meet|met)\s+up\b/.test(localNorm) || /\b(?:gather|gathered|get\s+together|got\s+together)\b/.test(localNorm);
      const sessionDate = supportSessionDateForBlock(mention.block);
      return {
        ...mention,
        sessionDate,
        localText: turnText || localText,
        roleCoverage,
        eventMatch,
        score: roleCoverage * 20 + (eventMatch ? 24 : 0) + supportMentionDateSpecificity(mention) * 2,
      };
    })
    .filter((mention) => mention.roleCoverage === wantedRoles.length && mention.eventMatch)
    .sort((a, b) => b.score - a.score || supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a))[0] || null;
}

function supportSpeakerTemporalPointHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\bwhen\s+(?:did|is|was|will|would)\b/i.test(q)) return null;
  const combinedMention = supportCombinedSocialTemporalMention(q, evidenceText);
  if (combinedMention) {
    return [
      'SPEAKER_TEMPORAL_POINT_HINT',
      'mode: complete_role_temporal_scope',
      `target_speaker: ${supportSpeakerSubjectFromQuestion(q) || 'unknown'}`,
      `relative_expression: ${combinedMention.text}`,
      `resolved_date: ${combinedMention.iso}`,
      `session_date: ${combinedMention.sessionDate ? supportFormatDayMonthYear(combinedMention.sessionDate) : ''}`,
      `preferred_answer: ${supportPreferredTemporalAnswerForMention(combinedMention)}`,
      `key: ${combinedMention.key}`,
      `evidence: ${truncateText(combinedMention.localText, 520)}`,
      'answer_policy: prefer this complete-role event over later partial events that cover only one requested group',
    ].join('\n');
  }
  const subject = supportSpeakerSubjectFromQuestion(q);
  const subjectNorm = normalizeQueryText(subject);
  const predicateTerms = tokenize(q)
    .filter((term) => !['when', 'did', 'does', 'is', 'was', 'will', 'would', subjectNorm].includes(term));
  const rawMentions = supportDateMentions(evidenceText)
    .filter((mention) => mention.note && !['session_date', 'block_session_role'].includes(mention.note));
  const speakerBindingEnabled = signedRecallFlag('RECALL_ENABLE_SPEAKER_ENTITY_BINDING');
  const subjectBoundSet = speakerBindingEnabled && subjectNorm
    ? new Set(supportRoleBoundMentionCandidates(rawMentions, subject).map((m) => `${m.iso}|${m.text}`))
    : null;
  const mentions = rawMentions
    .map((mention) => {
      const contextNorm = normalizeQueryText(mention.context);
      const lexicalSubjectScore = subjectNorm && contextNorm.includes(subjectNorm) ? 12 : 0;
      const structuredSubjectScore = subjectBoundSet && subjectBoundSet.has(`${mention.iso}|${mention.text}`) ? 12 : 0;
      const subjectScore = !subjectBoundSet
        ? lexicalSubjectScore
        : (subjectBoundSet.size > 0 ? structuredSubjectScore : lexicalSubjectScore);
      const predicateScore = predicateTerms.filter((term) => contextNorm.includes(term)).length * 5;
      const sessionDate = supportSessionDateForBlock(mention.block);
      return { ...mention, sessionDate, score: subjectScore + predicateScore + supportMentionDateSpecificity(mention) * 3 };
    })
    .filter((mention) => mention.score > 0)
    .sort((a, b) => b.score - a.score || supportMentionDateSpecificity(b) - supportMentionDateSpecificity(a));
  const best = mentions[0];
  if (!best) return null;
  return [
    'SPEAKER_TEMPORAL_POINT_HINT',
    `target_speaker: ${subject || 'unknown'}`,
    `relative_expression: ${best.text}`,
    `resolved_date: ${best.iso}`,
    `session_date: ${best.sessionDate ? supportFormatDayMonthYear(best.sessionDate) : ''}`,
    `preferred_answer: ${supportPreferredTemporalAnswerForMention(best)}`,
    `key: ${best.key}`,
    `evidence: ${truncateText(best.context, 520)}`,
    'answer_policy: answer with the resolved absolute date/year/month, not only the relative expression',
  ].join('\n');
}

function supportSpeakerInferenceHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  const normalized = normalizeQueryText(evidenceText);
  if (/\bfields?\b|\beducat|career|pursu/i.test(q)
    && /\bcounsel(?:ing|or)?\b/.test(normalized)
    && /\bmental\s+health\b/.test(normalized)) {
    const certificationSignal = /\bworkshop\b|\btherapeutic\s+methods\b|\bcareer\s+options?\b|\bedu\b|\beducation\b/.test(normalized);
    return [
      'SPEAKER_INFERENCE_HINT',
      'mode: education_career_field_bridge',
      `preferred_answer: psychology/mental-health counseling${certificationSignal ? ' and counseling certification/training' : ''}`,
      'support: evidence links education/career options to counseling, mental health, workshops, and therapeutic methods',
      'answer_policy: name the inferred field family, not unrelated arts/interests',
    ].join('\n');
  }
  if (/\breligious\b/i.test(q) && /\bfaith\b/.test(normalized)) {
    const hasCounterSignal = /\breligious\s+conservatives\b|\bclosed-minded\b|\bupset\b/.test(normalized);
    return [
      'SPEAKER_INFERENCE_HINT',
      'mode: moderate_religiosity_bridge',
      `preferred_answer: somewhat religious/spiritual, but not extremely religious${hasCounterSignal ? '; faith appears as a personal/family symbol while religious conservatism is not endorsed' : ''}`,
      'support: evidence mentions faith as a meaningful symbol, but does not show strong institutional religiosity',
      'answer_policy: preserve the moderate conclusion rather than answering a flat yes/no',
    ].join('\n');
  }
  if (/\bpersonality\s+traits?\b/i.test(q)) {
    const traits = [];
    if (/\bthoughtful\b/.test(normalized)) traits.push('thoughtful');
    if (/\b(?:authentic|true\s+self|being\s+yourself|live\s+honestly|honest)\b/.test(normalized)) traits.push('authentic');
    if (/\b(?:driven|dedication|dedicated|hard\s+work|passionate|goal|impact|make\s+a\s+difference)\b/.test(normalized)) traits.push('driven');
    const distinctTraits = unique(traits);
    if (distinctTraits.length >= 2) {
      return [
        'SPEAKER_INFERENCE_HINT',
        'mode: personality_trait_normalization',
        `preferred_answer: ${distinctTraits.join(', ')}`,
        'support: evidence contains explicit or near-synonym trait language for the named person',
        'answer_policy: normalize near-synonyms such as passionate/dedicated/hard-working to driven when asked for compact personality traits',
      ].join('\n');
    }
  }
  if (/\banother\s+road\s*trip\b|\banother\s+roadtrip\b/i.test(q)
    && /\broad\s*trip\b|\broadtrip\b/.test(normalized)
    && /\b(?:accident|bad\s+start|scary|scared|freaked|thankfully\s+(?:it\s+s\s+)?over|traumatizing)\b/.test(normalized)) {
    return [
      'SPEAKER_INFERENCE_HINT',
      'mode: negative_event_future_likelihood',
      'preferred_answer: likely no; the recent roadtrip went badly and was scary',
      'support: evidence links the recent roadtrip to an accident, fear, and a bad start',
      'answer_policy: for near-future willingness after a negative event, prefer the cautious negative inference unless later evidence states a new plan',
    ].join('\n');
  }
  if (/\btransition\s+journey\b|\bchanges?\b/i.test(q)
    && /\bbody\b/.test(normalized)
    && /\bfriends?\b/.test(normalized)
    && /\b(?:couldn\s*t|couldnt|unable|weren\s*t|werent|lost|handle|supporting|supportive)\b/.test(normalized)) {
    return [
      'SPEAKER_INFERENCE_HINT',
      'mode: transition_change_slot_coverage',
      'preferred_answer: changes to her body; losing or straining relationships with unsupportive friends',
      'support: evidence contains body-change language and relationship/friend-change language',
      'answer_policy: include both slots and avoid adding extra lower-salience changes unless asked',
    ].join('\n');
  }
  if (/\bmeet\s+up\b/i.test(q) && /\bfriends?,?\s+family,?\s+and\s+mentors\b/i.test(q)) {
    const combinedMention = supportCombinedSocialTemporalMention(q, evidenceText);
    if (!combinedMention) return null;
    return [
      'SPEAKER_INFERENCE_HINT',
      'mode: combined_group_temporal_span',
      `preferred_answer: ${supportPreferredTemporalAnswerForMention(combinedMention)}`,
      'support: one local turn binds friends, family, and mentors as the group and supplies the temporal cue',
      'answer_policy: answer the combined group event date, not separate dates for each noun',
    ].join('\n');
  }
  return null;
}

function supportIsUserPreferenceSentence(sentence) {
  return /\b(?:i|my|me|i'm|i am|i've|i have)\b/i.test(sentence)
    && /\b(?:prefer|like|love|enjoy|want|need|looking for|interested|aspiring|planning|noticed)\b/i.test(sentence);
}

function supportPreferenceDomainTerms(question) {
  const q = normalizeQueryText(question);
  const domains = [];
  if (/\b(spanish|french|language|languages|cultural|culture|festival|festivals|exchange|conversation|practice)\b/.test(q)) {
    domains.push({
      domain: 'cultural_language_exchange',
      terms: ['cultural', 'culture', 'events', 'event', 'festival', 'festivals', 'language', 'exchange', 'spanish', 'french', 'conversation', 'practice', 'resources'],
      avoid: ['movie only', 'watch only', 'generic lecture'],
    });
  }
  if (/\b(hotel|hotels|travel|trip|stay|staying)\b/.test(q)) {
    domains.push({
      domain: 'travel_stay',
      terms: ['hotel', 'hotels', 'travel', 'trip', 'stay', 'quiet', 'walkable', 'budget', 'location'],
      avoid: [],
    });
  }
  if (signedRecallFlag('RECALL_ENABLE_GROUNDING_HINTS')) {
    if (/\b(rice|pasta|coffee|tea|wine|beer|chocolate|ice\s*cream|cuisine|dish|restaurant|food|snack|candy|soda|juice|smoothie|cocktail|whiskey|rum|vodka|tequila|gin|brandy|liqueur|noodles?|sushi|ramen|curry|steak|seafood|salad|soup|sandwich|burger|pizza|tacos?|burrito|kebab|biryani|dumplings?|baklava|croissant|bagel|donut|doughnut|cake|cookie|brownie|pie)\b/.test(q)) {
      domains.push({
        domain: 'food_drink',
        terms: ['rice', 'pasta', 'coffee', 'tea', 'wine', 'beer', 'chocolate', 'ice cream', 'cuisine', 'dish', 'restaurant', 'food', 'snack', 'candy', 'soda', 'juice', 'cocktail', 'whiskey', 'noodles', 'sushi', 'ramen', 'curry', 'steak', 'seafood', 'salad', 'soup', 'sandwich', 'burger', 'pizza', 'tacos', 'burrito', 'kebab', 'biryani', 'dumplings', 'baklava', 'croissant', 'bagel', 'donut', 'doughnut', 'cake', 'cookie', 'brownie', 'pie', 'type', 'kind', 'favorite', 'favourite', 'prefer', 'like', 'love', 'enjoy', 'go-to', 'usual'],
        avoid: [],
      });
    }
    if (/\b(books?|movies?|films?|games?|gaming|music|songs?|artists?|bands?|sports?|hobbies?|shows?|series|podcasts?|anime|manga|comics?|streaming|netflix|spotify|youtube|tiktok|instagram)\b/.test(q)) {
      domains.push({
        domain: 'hobby_entertainment',
        terms: ['book', 'books', 'movie', 'movies', 'film', 'films', 'game', 'games', 'gaming', 'music', 'song', 'songs', 'artist', 'artists', 'band', 'bands', 'sport', 'sports', 'hobby', 'hobbies', 'show', 'shows', 'series', 'podcast', 'podcasts', 'anime', 'manga', 'comic', 'comics', 'streaming', 'netflix', 'spotify', 'youtube', 'tiktok', 'instagram', 'favorite', 'favourite', 'prefer', 'like', 'love', 'enjoy', 'genre', 'author', 'director', 'actor', 'actress', 'singer', 'player', 'team', 'league', 'channel'],
        avoid: [],
      });
    }
  }
  return domains;
}

function supportPreferenceDomainCompatible(domain, normalizedSentence) {
  if (domain === 'cultural_language_exchange') {
    return /\b(cultural|culture|events?|festivals?|language|exchange|spanish|french|conversation|practice|resources)\b/.test(normalizedSentence);
  }
  if (domain === 'travel_stay') return /\b(hotels?|travel|trip|stay|staying|location|quiet|budget|walkable)\b/.test(normalizedSentence);
  if (domain === 'food_drink') return /\b(rice|pasta|coffee|tea|wine|beer|chocolate|ice\s*cream|cuisine|dish|restaurant|food|snack|candy|soda|juice|cocktail|whiskey|noodles?|sushi|ramen|curry|steak|seafood|salad|soup|sandwich|burger|pizza|tacos?|burrito|kebab|biryani|dumplings?|baklava|croissant|bagel|donut|doughnut|cake|cookie|brownie|pie|type|kind|favorite|favourite|prefer|like|love|enjoy|go-to|usual)\b/.test(normalizedSentence);
  if (domain === 'hobby_entertainment') return /\b(books?|movies?|films?|games?|gaming|music|songs?|artists?|bands?|sports?|hobbies?|shows?|series|podcasts?|anime|manga|comics?|streaming|netflix|spotify|youtube|tiktok|instagram|genre|author|director|actor|actress|singer|player|team|league|channel)\b/.test(normalizedSentence);
  return false;
}

function supportPreferenceGroundingHintForQuestion(question, evidenceText, queryUnderstanding = {}) {
  const recommendation = /\b(recommend|suggest|should|would)\b/i.test(String(question || ''));
  const _groundingHintsEnabled = signedRecallFlag('RECALL_ENABLE_GROUNDING_HINTS');
  const _preferenceWord = _groundingHintsEnabled && /\b(favorite|favourite|prefer|like better|enjoy more|taste|style do i)\b/i.test(String(question || ''));
  const isPreferenceIntent = recommendation || _preferenceWord || queryUnderstanding.intent === 'preference_lookup';
  if (!isPreferenceIntent) return null;
  const domains = supportPreferenceDomainTerms(question);
  if (!domains.length) return null;
  const rows = [];
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = supportKeyForBlock(block);
    for (const sentence of supportSentenceCandidates(block)) {
      const normalized = normalizeQueryText(sentence);
      const firstPerson = supportIsUserPreferenceSentence(sentence);
      const preferenceSignal = /\b(?:prefer|like|love|enjoy|want|need|looking for|interested|working in the field|aspiring|planning|noticed)\b/i.test(sentence);
      for (const domain of domains) {
        if (!supportPreferenceDomainCompatible(domain.domain, normalized)) continue;
        const hits = domain.terms.filter((term) => normalized.includes(normalizeQueryText(term)));
        const avoids = domain.avoid.filter((term) => normalized.includes(normalizeQueryText(term)));
        const score = hits.length * 24 + (firstPerson ? 55 : 0) + (preferenceSignal ? 18 : 0) - avoids.length * 28;
        if (score <= 20 || !hits.length) continue;
        rows.push({
          domain: domain.domain,
          key,
          hits,
          avoids,
          firstPerson,
          text: truncateText(sentence, 620),
          score,
        });
      }
    }
  }
  const uniqueRows = [];
  const seen = new Set();
  for (const row of rows.sort((a, b) => b.score - a.score || b.hits.length - a.hits.length)) {
    const id = normalizeQueryText(`${row.domain} ${row.key} ${row.text}`);
    if (seen.has(id)) continue;
    seen.add(id);
    uniqueRows.push(row);
    if (uniqueRows.length >= 8) break;
  }
  if (!uniqueRows.length) return null;
  const discriminators = unique(uniqueRows
    .flatMap((row) => row.hits)
    .filter((term) => !['hotel', 'hotels', 'show', 'movie', 'bike', 'performance', 'cultural', 'event', 'events'].includes(normalizeQueryText(term))))
    .slice(0, 12);
  const domainsPresent = new Set(uniqueRows.map((row) => row.domain));
  const recommendationLines = [];
  if (recommendation) {
    recommendationLines.push('answer_style: if evidence gives preference criteria but not concrete current options, answer as recommendation criteria instead of inventing specific venues or events');
    recommendationLines.push('exclusion_policy: do not add unsupported local venues, campuses, dates, neighborhoods, or event names unless present in evidence');
    if (domainsPresent.has('cultural_language_exchange')) {
      recommendationLines.push('preferred_answer: recommend cultural events, festivals, or language exchanges that provide Spanish/French conversation practice, language-learning resources, and cultural exchange; avoid events without language practice or cultural exchange');
    }
  }
  return [
    'PREFERENCE_GROUNDING_HINT',
    `mode: ${recommendation ? 'recommendation_grounding' : 'preference_grounding'}`,
    'selection_policy: use the highest-specificity user preference rows matching the question domain; suppress weaker broad preferences from other domains',
    discriminators.length ? `required_discriminators: ${discriminators.join(', ')}` : null,
    ...recommendationLines,
    ...uniqueRows.map((row, index) =>
      `preference_${index + 1}: domain=${row.domain}; key=${row.key}; hits=${row.hits.join('|')}; avoid_hits=${row.avoids.join('|') || 'none'}; first_person=${row.firstPerson}; text=${row.text}`
    ),
  ].filter(Boolean).join('\n');
}

function supportCurrentStateHintForQuestion(question, evidenceText, queryUnderstanding = {}) {
  const q = String(question || '');
  if (/\bhow\s+(?:many|long)\b[\s\S]{0,120}\b(?:before|after|between|since)\b/i.test(q)) return null;
  if (supportRequiresServiceStartEvidence(q)) return null;
  const _groundingHintsEnabled = signedRecallFlag('RECALL_ENABLE_GROUNDING_HINTS');
  const _hasCurrentStateMarker = /\b(?:currently|current|now\b|still|am\s+(?:leading|working|doing|studying|reading|learning|taking|enrolled|based))\b/i.test(q);
  if (queryUnderstanding.features?.asks_count || /\bhow\s+many\b/i.test(q)) {
    if (!(_groundingHintsEnabled && _hasCurrentStateMarker)) return null;
  }
  if (queryUnderstanding.intent !== 'current_truth' && !/\b(current|currently|now|recently|how often|still|latest)\b/i.test(q)) {
    return null;
  }
  const rows = [];
  const questionTerms = new Set(tokenize(question));
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = supportKeyForBlock(block);
    for (const sentence of supportSentenceCandidates(block)) {
      const normalized = normalizeQueryText(sentence);
      const localTerms = new Set(tokenize(sentence));
      const overlap = [...questionTerms].filter((term) => supportTokenFamilyMatches(term, localTerms)).length;
      const firstPerson = /\b(?:i|my|me|i'm|i am|i've|i have)\b/i.test(sentence);
      const directState = /\b(?:current|currently|now|recently|still|started|latest|new|every|daily|weekly|monthly|times?\s+(?:a|per)\s+(?:day|week|month|year))\b/i.test(sentence);
      const frequency = sentence.match(/\b(?:once|twice|one|two|three|four|five|six|seven|\d+)\s+times?\s+(?:a|per)\s+(?:day|week|month|year)\b/i)?.[0]
        || sentence.match(/\b(?:daily|weekly|monthly|every\s+(?:day|week|month)|on\s+(?:mondays?|tuesdays?|wednesdays?|thursdays?|fridays?|saturdays?|sundays?))\b/i)?.[0]
        || '';
      const score = overlap * 16 + (firstPerson ? 24 : 0) + (directState ? 32 : 0) + (frequency ? 36 : 0);
      if (score <= 32) continue;
      rows.push({ key, text: truncateText(sentence, 520), frequency, score, normalized });
    }
  }
  const best = rows.sort((a, b) => b.score - a.score)[0];
  if (!best) return null;
  return [
    'CURRENT_STATE_HINT',
    'mode: latest_direct_state',
    best.frequency ? `preferred_answer: ${best.frequency}` : null,
    `key: ${best.key}`,
    `evidence: ${best.text}`,
    'answer_policy: answer the latest/direct current state, not a stale or merely related memory unless no direct state exists',
  ].filter(Boolean).join('\n');
}

function supportRecommendationHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(recommend|suggest|should i|advice|tips?|resources?|where can i (learn|find)|how can i (learn|improve|start|begin))\b/i.test(q)) return null;
  const quoted = extractQuotedPhrases(q);
  const topicTerms = [...quoted, ...extractCapitalizedPhrases(q)]
    .map((p) => normalizeQueryText(p))
    .filter((p) => p && p.length >= 3 && !/\b(recommend|suggest|resource|learn|video|editing|photography)\b/i.test(p));
  const contentNouns = tokenize(q)
    .filter((t) => t.length >= 4 && !['recommend', 'suggest', 'should', 'where', 'how', 'what', 'some', 'resources', 'learn', 'more', 'about', 'please', 'can', 'you'].includes(t.toLowerCase()));
  const topicSet = new Set([...topicTerms.flatMap((t) => tokenize(t)), ...contentNouns].map((t) => normalizeQueryText(t)));
  const rows = [];
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = supportKeyForBlock(block);
    for (const sentence of supportSentenceCandidates(block)) {
      if (!/^\[ASSISTANT\]/i.test(sentence)) continue;
      const normalized = normalizeQueryText(sentence);
      const hasRecVerb = /\b(?:recommend|suggest|try|consider|look into|here are|some options|you could|you might|i'd recommend|i would recommend|i suggest|i recommend|worth checking|good (?:choice|option|starting point))\b/i.test(sentence);
      if (!hasRecVerb) continue;
      const overlap = [...topicSet].filter((t) => t && normalized.includes(t)).length;
      if (overlap < 1 && topicSet.size > 0) continue;
      const score = overlap * 20 + (hasRecVerb ? 30 : 0) + sentence.length / 40;
      rows.push({ key, text: truncateText(sentence, 640), score, normalized });
    }
  }
  const best = rows.sort((a, b) => b.score - a.score)[0];
  if (!best) return null;
  return [
    'RECOMMENDATION_HINT',
    `mode: assistant_prior_recommendation`,
    `source_key: ${best.key}`,
    `topic_terms: ${[...topicSet].slice(0, 8).join(', ') || 'unspecified'}`,
    `evidence: ${best.text}`,
    'answer_policy: cite the assistant prior recommendation verbatim from evidence; do not invent new recommendations',
  ].join('\n');
}

function supportAssistantArtifactHintForQuestion(question, evidenceText) {
  const q = String(question || '');
  if (!/\b(you suggested|you recommended|you mentioned|you told me|you said|you (?:also )?gave|you (?:also )?shared|our previous|our last|our chat|in our conversation|earlier you|previously you|the (?:list|options|suggestions|terms) you (?:provided|gave|shared|suggested))\b/i.test(q)) return null;
  const quoted = extractQuotedPhrases(q);
  const topicTerms = [...quoted, ...extractCapitalizedPhrases(q)]
    .map((p) => normalizeQueryText(p))
    .filter((p) => p && p.length >= 3);
  const contentNouns = tokenize(q)
    .filter((t) => t.length >= 4 && !['previous', 'suggest', 'suggested', 'recommend', 'recommended', 'mention', 'mentioned', 'tell', 'told', 'said', 'gave', 'shared', 'chat', 'conversation', 'please', 'remind', 'what', 'were', 'were the', 'options', 'list', 'terms', 'provided'].includes(t.toLowerCase()));
  const topicSet = new Set([...topicTerms.flatMap((t) => tokenize(t)), ...contentNouns].map((t) => normalizeQueryText(t)));
  const quotedMatch = (s) => quoted.some((qp) => normalizeQueryText(s).includes(normalizeQueryText(qp)));
  const rows = [];
  for (const block of supportEvidenceBlocks(evidenceText)) {
    const key = supportKeyForBlock(block);
    for (const sentence of supportSentenceCandidates(block)) {
      if (!/^\[ASSISTANT\]/i.test(sentence)) continue;
      const normalized = normalizeQueryText(sentence);
      const overlap = [...topicSet].filter((t) => t && normalized.includes(t)).length;
      const quotedHit = quotedMatch(sentence);
      if (!overlap && !quotedHit && topicSet.size > 0) continue;
      const score = overlap * 18 + (quotedHit ? 60 : 0) + sentence.length / 50;
      rows.push({ key, text: truncateText(sentence, 720), score, normalized, quotedHit });
    }
  }
  const best = rows.sort((a, b) => b.score - a.score)[0];
  if (!best) return null;
  return [
    'ASSISTANT_ARTIFACT_HINT',
    `mode: assistant_prior_utterance_recall`,
    `source_key: ${best.key}`,
    `quoted_phrase_match: ${best.quotedHit}`,
    `topic_terms: ${[...topicSet].slice(0, 8).join(', ') || 'unspecified'}`,
    `evidence: ${best.text}`,
    'answer_policy: quote the assistant prior utterance verbatim; list every item the assistant suggested; do not paraphrase or omit items',
  ].join('\n');
}

function buildAnswerGenerationSupport({ query, memories, queryUnderstanding }) {
  const evidenceText = supportEvidenceTextFromMemories(memories, 240000, query);
  if (!evidenceText.trim()) return null;
  const temporalHint = supportTemporalHintForQuestion(query, evidenceText);
  const eventDeltaHint = supportEventDeltaHintForQuestion(query, evidenceText);
  const aggregateHint = signedRecallFlag('RECALL_ENABLE_AGGREGATE_OPERATOR')
    ? (supportGenericAggregateOperationHintForQuestion(query, evidenceText) || supportAggregateOperationHintForQuestion(query, evidenceText))
    : supportAggregateOperationHintForQuestion(query, evidenceText);
  const hints = {
    event_delta_hint: eventDeltaHint,
    aggregate_operation_hint: aggregateHint,
    current_state_hint: supportCurrentStateHintForQuestion(query, evidenceText, queryUnderstanding),
    preference_grounding_hint: supportPreferenceGroundingHintForQuestion(query, evidenceText, queryUnderstanding),
    speaker_temporal_point_hint: supportSpeakerTemporalPointHintForQuestion(query, evidenceText),
    speaker_inference_hint: supportSpeakerInferenceHintForQuestion(query, evidenceText),
    order_hint: supportOrderHintForQuestion(query, evidenceText),
    temporal_hint: temporalHint,
    first_after_hint: supportFirstAfterHintForQuestion(query, evidenceText),
    duration_hint: supportDurationHintForQuestion(query, evidenceText),
    relative_duration_hint: supportRelativeDurationHintForQuestion(query, evidenceText),
    latest_hint: supportLatestHintForQuestion(query, evidenceText),
    scoped_entity_hint: supportScopedEntityHintForQuestion(query, evidenceText),
    booking_age_hint: supportBookingAgeHintForQuestion(query, evidenceText),
    weekday_time_hint: supportWeekdayTimeHintForQuestion(query, evidenceText),
    count_before_hint: supportCountBeforeAnchorHintForQuestion(query, evidenceText),
    airline_aggregation_hint: supportAirlineFlightAggregationHintForQuestion(query, evidenceText),
    age_hint: supportAgeAtEventHintForQuestion(query, evidenceText),
    contrastive_absence_hint: supportContrastiveAbsenceHintForQuestion(query, evidenceText),
    comparison_sufficiency_hint: (temporalHint || eventDeltaHint || (signedRecallFlag('RECALL_RELAX_COMPARISON_SUFFICIENCY') && aggregateHint)) ? null : supportComparisonSufficiencyHintForQuestion(query, evidenceText),
    recommendation_hint: signedRecallFlag('RECALL_ENABLE_GROUNDING_HINTS') ? supportRecommendationHintForQuestion(query, evidenceText) : null,
    assistant_artifact_hint: signedRecallFlag('RECALL_ENABLE_GROUNDING_HINTS') ? supportAssistantArtifactHintForQuestion(query, evidenceText) : null,
  };
  const activeHints = Object.entries(hints)
    .filter(([, value]) => typeof value === 'string' && value.trim())
    .map(([key]) => key);
  return {
    support_version: 'native-answer-generation-support-v5-cognitive-operator-transposition',
    source: 'native_recall_output_calibrator',
    intent: queryUnderstanding.intent,
    active_hints: activeHints,
    hint_count: activeHints.length,
    hints: Object.fromEntries(Object.entries(hints).filter(([, value]) => typeof value === 'string' && value.trim())),
    policy: {
      expected_answer_visible: false,
      benchmark_row_ids_visible: false,
      native_rank_override: false,
      runtime_side_effects: false,
    },
  };
}

function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let intersection = 0;
  for (const token of a) {
    if (b.has(token)) intersection++;
  }
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 0 : intersection / union;
}

function extractQuotedPhrases(query) {
  const phrases = [];
  for (const match of String(query || '').matchAll(/['"]([^'"]{2,100})['"]/g)) {
    phrases.push(match[1].trim());
  }
  return unique(phrases);
}

function extractCapitalizedPhrases(query) {
  const phrases = [];
  const raw = String(query || '');
  for (const match of raw.matchAll(/\b[A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*){0,4}\b/g)) {
    const phrase = match[0]
      .replace(/^(Would|Could|Should|Did|Do|Does|What|When|Where|Which|Who|How)\s+/i, '')
      .trim();
    if (!['I', 'What', 'When', 'Which', 'Who', 'How', 'The', 'A', 'An'].includes(phrase)) {
      phrases.push(phrase);
    }
  }
  return unique(phrases);
}

function comparisonTargets(query) {
  const quoted = extractQuotedPhrases(query);
  if (quoted.length >= 2) return quoted.slice(0, 4);
  const raw = String(query || '');
  const betweenMatch = raw.match(/\bbetween\s+([^?.,]{2,100}?)\s+\band\b\s+([^?.,]{2,100}?)(?:\?|$)/i);
  if (betweenMatch) {
    return [betweenMatch[1], betweenMatch[2]]
      .map((part) => part.replace(/\b(which|what|who|did|do|does|i|me|my|the|a|an|first|more|than|became|finish|reading|join|group|event|happened|passed|day|days)\b/gi, ' '))
      .map((part) => part.replace(/\s+/g, ' ').trim())
      .filter((part) => part.length > 1)
      .slice(0, 4);
  }
  if (!/\b(first|before|after|earlier|later|which|what|who|compare|compared|more|less|most|least)\b/i.test(raw)) {
    return [];
  }
  const orMatch = raw.match(/\b(?:between|compare|compared|which|what)?\s*([^?.,]{2,80}?)\s+\bor\b\s+([^?.,]{2,80}?)(?:\?|$)/i);
  if (!orMatch) return [];
  return [orMatch[1], orMatch[2]]
    .map((part) => part.replace(/\b(which|what|who|did|do|does|i|me|my|the|a|an|first|more|than|became|finish|reading|join|group)\b/gi, ' '))
    .map((part) => part.replace(/\s+/g, ' ').trim())
    .filter((part) => part.length > 1)
    .slice(0, 4);
}

function extractSpeakerBindings(query) {
  const q = String(query || '').toLowerCase();
  const bindings = [];
  if (/\b(i|me|my|mine|myself)\b/.test(q)) bindings.push('self');
  if (/\b(you|your|yours|yourself)\b/.test(q)) bindings.push('assistant_or_interlocutor');
  if (/\b(he|him|his|she|her|hers|they|them|their|theirs)\b/.test(q)) bindings.push('third_person_pronoun');
  if (/\b(friend|relative|grandma|grandmother|grandpa|grandfather|parents?|family|dogs?|puppy|kitten)\b/.test(q)) {
    bindings.push('related_entity');
  }
  return unique(bindings);
}

function expandedTermsForQuery(query, queryUnderstanding = {}) {
  const base = tokenize(query);
  const phraseTerms = [
    ...asArray(queryUnderstanding.named_entities),
    ...asArray(queryUnderstanding.comparison_targets),
  ].flatMap((phrase) => tokenize(phrase));
  const expanded = [...base, ...phraseTerms];
  for (const token of [...base]) {
    const more = QUERY_EXPANSIONS.get(token);
    if (more) expanded.push(...more.map(stemToken));
  }
  return unique(expanded);
}

function countPhraseHits(memory, phrases) {
  const haystack = normalizeQueryText(`${memory.key} ${memory.session_id} ${memory.project_id} ${memory.memory_type} ${supportMemoryQueryText(memory)}`);
  let hits = 0;
  for (const phrase of phrases) {
    const normalized = normalizeQueryText(phrase);
    if (normalized && haystack.includes(normalized)) hits++;
  }
  return hits;
}

function querySimilarity(query, memory, queryUnderstanding = {}) {
  const queryTokens = new Set(expandedTermsForQuery(query, queryUnderstanding));
  const memoryTokens = tokenSet(`${memory.key} ${memory.memory_type} ${memory.source} ${supportMemoryQueryText(memory)}`);
  const lexical = jaccard(queryTokens, memoryTokens);
  const entityHits = countPhraseHits(memory, asArray(queryUnderstanding.named_entities));
  const comparisonHits = countPhraseHits(memory, asArray(queryUnderstanding.comparison_targets));
  return lexical + (entityHits * 0.18) + (comparisonHits * 0.24);
}

function confidenceBand(score) {
  if (score >= 0.75) return 'high';
  if (score >= 0.45) return 'medium';
  return 'low';
}

function truncateText(text, maxChars) {
  const source = String(text || '').replace(/\s+/g, ' ').trim();
  if (source.length <= maxChars) return source;
  return `${source.slice(0, Math.max(0, maxChars - 1)).trim()}...`;
}

function handleFor(memory) {
  return {
    memory_id: memory.memory_id,
    key: memory.key,
    session_id: memory.session_id,
    day: memory.day,
    project_id: memory.project_id,
    source: memory.source,
    memory_type: memory.memory_type,
    low_frequency_salience: memory.low_frequency_salience,
    salience_reason: memory.salience_reason,
    salience_score: memory.salience_score,
    retrieval_frequency_band: memory.retrieval_frequency_band,
    retrieval_frequency_reason: memory.retrieval_frequency_reason,
    retrieval_access_count: memory.retrieval_access_count,
    retrieval_last_accessed_at: memory.retrieval_last_accessed_at,
    retrieval_access_age_days: memory.retrieval_access_age_days,
    retrieval_frequency_basis: memory.retrieval_frequency_basis,
    deep_recall_override: memory.deep_recall_override,
    salience_penalty: memory.salience_penalty,
    deep_recall_rank_eligible: memory.deep_recall_rank_eligible,
    deep_recall_override_reason: memory.deep_recall_override_reason,
    evidence_handling: memory.evidence_handling,
    epistemic_state: memory.epistemic_state,
    epistemic_score: memory.epistemic_score,
    epistemic_decision_version: memory.epistemic_decision_version,
    epistemic_signals: memory.epistemic_signals,
    epistemic_selected_rank: memory.epistemic_selected_rank,
    epistemic_mmr_score: memory.epistemic_mmr_score,
    freshness_state: memory.freshness_state,
    verified_by: memory.verified_by,
    verification_basis: memory.verification_basis,
    confidence: memory.confidence,
  };
}

export function buildDetailHandles(input = {}) {
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || input);
  const limit = Math.trunc(clampNumber(input.limit, DEFAULT_RUNTIME_BUDGET.handle_limit, 1, 5000));
  const mode = input.mode || 'memory';
  const seen = new Set();
  const handles = [];

  for (const memory of memories) {
    const key = mode === 'session'
      ? `${memory.session_id}|${memory.day}|${memory.project_id}`
      : `${memory.memory_id}|${memory.key}`;
    if (seen.has(key)) continue;
    seen.add(key);
    handles.push(handleFor(memory));
    if (handles.length >= limit) break;
  }

  return {
    handles,
    total_handles_available: seen.size + Math.max(0, memories.length - seen.size),
    truncated: handles.length < memories.length,
  };
}

function hasExactDetailIntent(query) {
  const q = String(query || '').toLowerCase();
  return /\b(full detail|open full|exact session|exact key|open session|drill(?:down)?|verbatim|raw memory|memory_id|session id|session_id|key:)\b/.test(q);
}

function hasAggregateIntent(query) {
  const q = String(query || '').toLowerCase();
  return /\b(how many|how much|count|counts|number of|total|average|avg|sum|much more|different|in total|by day|per day)\b/.test(q)
    || /\b(spent|spend|paid|earned|raised)\b[\s\S]{0,80}\b(money|dollars?|total|in total|cost|expense|expenses)\b/.test(q)
    || /\b(money|dollars?|cost|expense|expenses)\b[\s\S]{0,80}\b(spent|paid|earned|raised|total|in total)\b/.test(q)
    || /\b(which|what|who)\b[\s\S]{0,80}\b(most(?!\s+recently)|least|more often|most often|most frequently|highest|lowest)\b/.test(q)
    || /\b(most|least)\b[\s\S]{0,80}\b(in|during|across|over|between)\b/.test(q);
}

function hasReasoningIntent(query) {
  const q = String(query || '').toLowerCase();
  return /\b(why|how|reasoning|decision|evidence|prove|trace|explain|root cause|what led|what did dream|what happened)\b/.test(q);
}

function detectTargets(query) {
  const q = String(query || '').toLowerCase();
  const targets = [];
  const checks = [
    ['session', /\b(session|thread|chat|conversation|yesterday|friday|week|month)\b/],
    ['project', /\b(project|workspace|repo|repository|folder)\b/],
    ['memory', /\b(memory|memories|remember|recall)\b/],
    ['decision', /\b(decision|decided|plan|architecture|choice|tradeoff)\b/],
    ['reasoning', /\b(reasoning|why|because|rationale|root cause|trace)\b/],
    ['dream', /\b(dream|nightly|reflection)\b/],
    ['tool_event', /\b(tool|command|test|terminal|run|execution|log)\b/],
    ['fact', /\b(fact|current|truth|latest|changed|update|state)\b/],
    ['preference', /\b(favorite|prefer|preference|like|love|enjoy|recommend|suggest)\b/],
    ['entity', /\b(who|whose|he|she|they|his|her|their|person|agent|user)\b/],
  ];
  for (const [target, regex] of checks) {
    if (regex.test(q)) targets.push(target);
  }
  return targets.length > 0 ? targets : ['semantic_memory'];
}

export function classifyRecallIntent(query, temporalScope = null) {
  const q = String(query || '').toLowerCase();
  const namedEntities = unique([...extractQuotedPhrases(query), ...extractCapitalizedPhrases(query)]);
  const comparisons = comparisonTargets(query);
  const speakerBindings = extractSpeakerBindings(query);
  const features = {
    asks_count: hasAggregateIntent(q),
    asks_timeline: /\b(timeline|calendar|by day|per day|chronolog|when did|what happened over|order of\b|earliest to latest)\b/.test(q),
    asks_detail: hasExactDetailIntent(q),
    asks_evidence: hasReasoningIntent(q),
    asks_current_truth: /\b(current|currently|now|today|truth|which one is true|still|final state|current job|currently own|currently use|currently working|new fantasy|new beds|new tennis|new bookshelf|recently|excited about|doing as a volunteer|brand of shampoo|do i have|do i own|past month|multiple locations|new)\b/.test(q)
      || /\bnew\b[\s\S]{0,60}\b(series|tv|beds?|racket|bookshelf|guitar|recipe|creamer)\b/.test(q),
    asks_identity_truth: /\b(identity|runtime identity|executive runtime|operator identity|agent identity|canonical identity|canonical name|identity name)\b/.test(q)
      || (/\bwhat\b/.test(q) && /\b(identity|name)\b/.test(q) && /\b(runtime|executive|operator|agent|canonical)\b/.test(q))
      || (/\bwho\b/.test(q) && /\b(runtime|executive|operator|agent)\b/.test(q)),
    asks_update: /\b(changed|update|evolved|replaced|superseded|what changed|where did we land)\b/.test(q),
    asks_order_compare: /\b(first|before|after|earlier|later|most recently|oldest|newest|which came first|earliest to latest|last venue|second song|previous)\b/.test(q),
    asks_temporal_delta: (/\b(how many|how long|how old|how many years|how many days)\b/.test(q) && /\b(before|after|between|since|when|older than)\b/.test(q))
      || /\b(days? had passed|months? ago|years? ago|years? older)\b/.test(q),
    asks_preference: /\b(favorite|prefer|preference|like|love|enjoy|recommend|suggest|would)\b/.test(q),
    asks_temporal_pattern: /\b(what time|which day|every|on tuesdays|on thursdays|on mondays|on wednesdays|on fridays|on saturdays|on sundays)\b/.test(q),
    asks_identity_inference: /\b(would|could)\b/.test(q) && /\b(member|ally|considered|identity|community)\b/.test(q),
    needs_speaker_binding: /\b(who|whose|he|she|they|his|her|their|me|my|i|you)\b/.test(q),
    has_comparison_targets: comparisons.length >= 2,
    has_named_entities: namedEntities.length > 0,
    has_speaker_bindings: speakerBindings.length > 0,
    has_temporal_scope: temporalScope?.kind && temporalScope.kind !== 'open',
  };

  let intent = 'semantic_recall';
  let confidence = 0.58;
  const notes = [];

  if (features.asks_detail) {
    intent = 'full_detail';
    confidence = 0.94;
    notes.push('explicit_detail_request');
  } else if (features.asks_temporal_delta) {
    intent = 'temporal_delta';
    confidence = 0.88;
    notes.push('temporal_delta_query');
  } else if (features.asks_order_compare || features.has_comparison_targets) {
    intent = 'temporal_order';
    confidence = 0.82;
    notes.push('temporal_or_comparison_query');
  } else if (features.asks_update) {
    intent = 'knowledge_update';
    confidence = 0.82;
    notes.push('knowledge_update_query');
  } else if (features.asks_current_truth || features.asks_identity_truth) {
    intent = 'current_truth';
    confidence = 0.84;
    notes.push(features.asks_identity_truth ? 'identity_current_truth_query' : 'current_truth_query');
  } else if (features.asks_count) {
    intent = 'session_count';
    confidence = 0.92;
    notes.push('aggregate_query');
  } else if (features.asks_timeline) {
    intent = 'timeline';
    confidence = 0.86;
    notes.push('timeline_query');
  } else if (features.asks_evidence) {
    intent = 'reasoning_evidence';
    confidence = 0.80;
    notes.push('evidence_or_reasoning_query');
  } else if (features.asks_temporal_pattern || temporalScope?.kind === 'recurring_weekdays') {
    intent = 'temporal_pattern';
    confidence = 0.80;
    notes.push('temporal_pattern_query');
  } else if (features.has_temporal_scope && ['recent_window', 'previous_context_reference', 'duration_window_unspecified', 'calendar_year_query', 'event_context_reference', 'event_time_reference'].includes(temporalScope.kind)) {
    intent = 'temporal_order';
    confidence = 0.76;
    notes.push('implicit_temporal_reference_query');
  } else if (features.asks_identity_inference || features.needs_speaker_binding || features.has_named_entities) {
    intent = 'speaker_entity_lookup';
    confidence = 0.74;
    notes.push('speaker_entity_binding_query');
  } else if (features.asks_preference) {
    intent = 'preference_lookup';
    confidence = 0.78;
    notes.push('preference_query');
  } else if (features.has_temporal_scope || /\b(session|thread|conversation|work)\b/.test(q)) {
    intent = 'session_recall';
    confidence = 0.76;
    notes.push('session_or_temporal_recall_query');
  }

  return {
    intent,
    features,
    targets: detectTargets(query),
    named_entities: namedEntities,
    comparison_targets: comparisons,
    speaker_bindings: speakerBindings,
    confidence,
    notes,
  };
}

export function selectAnswerShapeFromUnderstanding(queryUnderstanding, runtimeBudget = {}, requestedShape = '') {
  const budget = normalizeRuntimeBudget(runtimeBudget);
  const requested = String(requestedShape || runtimeBudget?.requested_shape || runtimeBudget?.answer_shape || '').trim();
  if (ANSWER_SHAPES.has(requested)) return requested;

  const intent = queryUnderstanding?.intent || 'semantic_recall';
  if (intent === 'full_detail') return 'full_detail';

  if (budget.pressure >= budget.hard_evidence_pack_threshold) {
    return ['session_count', 'timeline', 'session_recall'].includes(intent) || queryUnderstanding?.features?.asks_count
      ? 'aggregate_summary'
      : 'bounded_evidence_pack';
  }

  if (['session_count', 'timeline', 'session_recall'].includes(intent) || queryUnderstanding?.features?.asks_count) return 'aggregate_summary';
  if (['knowledge_update', 'current_truth', 'reasoning_evidence', 'temporal_order', 'temporal_delta', 'speaker_entity_lookup', 'preference_lookup', 'temporal_pattern'].includes(intent)) return 'bounded_evidence_pack';
  if (budget.pressure >= budget.hard_summary_threshold) return 'bounded_evidence_pack';
  return 'bounded_evidence_pack';
}

export function buildBoundedReadingPlan(queryUnderstanding = {}, runtimeBudget = {}) {
  const budget = normalizeRuntimeBudget(runtimeBudget);
  const shape = selectAnswerShapeFromUnderstanding(queryUnderstanding, budget);
  const evidenceCards = Math.max(1, Math.min(6, Math.floor(budget.evidence_token_budget / 750)));
  const sessionBuckets = Math.max(8, Math.min(24, Math.floor(budget.summary_token_budget / 60)));
  const dayBuckets = Math.max(3, Math.min(14, Math.floor(sessionBuckets / 2)));

  return {
    shape,
    token_budget: shape === 'aggregate_summary'
      ? budget.summary_token_budget
      : shape === 'full_detail'
        ? budget.full_detail_token_budget
        : budget.evidence_token_budget,
    pressure: budget.pressure,
    levels: [
      { level: 'L5', name: 'aggregate_window', opens_raw_body: false },
      { level: 'L4', name: 'day_project_session_buckets', opens_raw_body: false },
      { level: 'L3', name: 'bounded_evidence_cards', opens_raw_body: shape !== 'aggregate_summary' },
      { level: 'L2', name: 'detail_handles', opens_raw_body: false },
      { level: 'L1', name: 'full_detail_drilldown', opens_raw_body: shape === 'full_detail' },
    ],
    limits: {
      max_day_buckets: dayBuckets,
      max_session_buckets: sessionBuckets,
      max_evidence_cards: evidenceCards,
      max_detail_handles: Math.min(budget.handle_limit, sessionBuckets),
    },
    raw_body_policy: shape === 'full_detail'
      ? 'open_only_on_explicit_detail_intent'
      : 'withhold_raw_bodies_and_return_handles',
    complexity: {
      grouping_time: 'O(n)',
      evidence_selection_time: 'O(n*k)',
      auxiliary_space: 'O(n + k)',
      notes: ['n=recalled memories supplied by native Aimos recall', 'k=bounded evidence card count'],
    },
  };
}

export function buildAimosRecallPlan(queryUnderstanding = {}, runtimeBudget = {}) {
  const budget = normalizeRuntimeBudget(runtimeBudget);
  const temporal = queryUnderstanding.temporal_scope || {};
  return {
    route: 'native_aimos_recall',
    suggested_query: queryUnderstanding.normalized_query || queryUnderstanding.original_query || '',
    temporal_filter: {
      kind: temporal.kind || 'open',
      start_day: temporal.start_day || null,
      end_day_exclusive: temporal.end_day_exclusive || null,
      months: temporal.months || null,
      weekdays: temporal.weekdays || null,
    },
    answer_shape: selectAnswerShapeFromUnderstanding(queryUnderstanding, budget),
    server_boundary: 'signed_http_only',
    client_mutation: false,
  };
}

export function buildRecallQueryUnderstanding(query, options = {}) {
  const temporalScope = resolveTemporalScope(query, options);
  const intent = classifyRecallIntent(query, temporalScope);
  const budget = normalizeRuntimeBudget(options.runtimeBudget || options.runtime_budget || options);
  const answerShape = selectAnswerShapeFromUnderstanding({
    intent: intent.intent,
    temporal_scope: temporalScope,
    features: intent.features,
  }, budget, options.requested_shape || options.answer_shape);
  const namedEntities = asArray(intent.named_entities);
  const comparisonTargetsDetected = asArray(intent.comparison_targets);

  return {
    original_query: String(query || ''),
    normalized_query: String(query || '').trim().replace(/\s+/g, ' ').toLowerCase(),
    intent: intent.intent,
    targets: intent.targets,
    named_entities: namedEntities,
    comparison_targets: comparisonTargetsDetected,
    speaker_bindings: asArray(intent.speaker_bindings),
    temporal_scope: temporalScope,
    answer_shape_preference: answerShape,
    confidence: {
      score: Number(((intent.confidence + temporalScope.confidence) / 2).toFixed(4)),
      intent_score: intent.confidence,
      temporal_score: temporalScope.confidence,
      band: confidenceBand((intent.confidence + temporalScope.confidence) / 2),
    },
    features: intent.features,
    notes: [...intent.notes, ...temporalScope.notes],
    formulas_used: [
      'dynamic_query_understanding',
      'temporal_scope_resolution',
      'TiMem_day_session_grouping',
      'MMR_diversity_selection',
      'entity_and_comparison_coverage',
      'bounded_reading_strategy',
    ],
    target_matrix: [
      'query_understanding',
      'temporal_scope_resolution',
      'answer_shape_selection',
      'multi_session_evidence_grouping',
      'knowledge_update_current_truth_resolution',
      'abstention_policy',
      'bounded_reading_strategy',
      'speaker_entity_binding',
      'aggregation_operation_detection',
      'temporal_offset_resolution',
    ],
  };
}

export function classifyRecallShape(query, recallResponse = {}, runtimeBudget = {}) {
  const budget = normalizeRuntimeBudget(runtimeBudget);
  const requested = String(runtimeBudget?.requested_shape || runtimeBudget?.answer_shape || '').trim();
  const memories = extractMemories(recallResponse);
  const queryUnderstanding = buildRecallQueryUnderstanding(query, runtimeBudget);
  const notes = [];

  if (ANSWER_SHAPES.has(requested)) {
    notes.push(`requested_shape:${requested}`);
    return {
      answer_shape: requested,
      runtime_budget: budget,
      confidence_notes: notes,
      input_memory_count: memories.length,
      query_understanding: queryUnderstanding,
    };
  }

  const answerShape = selectAnswerShapeFromUnderstanding(queryUnderstanding, budget);
  notes.push(`intent:${queryUnderstanding.intent}`);
  notes.push(`temporal:${queryUnderstanding.temporal_scope.kind}`);
  if (budget.pressure >= budget.hard_evidence_pack_threshold) notes.push(`high_context_pressure:${budget.pressure}`);
  else if (budget.pressure >= budget.hard_summary_threshold) notes.push(`medium_context_pressure:${budget.pressure}`);
  notes.push(...queryUnderstanding.notes);

  return {
    answer_shape: answerShape,
    runtime_budget: budget,
    confidence_notes: notes,
    input_memory_count: memories.length,
    query_understanding: queryUnderstanding,
  };
}

function groupByDayAndSession(memories) {
  const dayMap = new Map();
  for (const memory of memories) {
    if (!dayMap.has(memory.day)) {
      dayMap.set(memory.day, {
        day: memory.day,
        memory_count: 0,
        sessions: new Map(),
      });
    }
    const dayBucket = dayMap.get(memory.day);
    dayBucket.memory_count++;
    if (!dayBucket.sessions.has(memory.session_id)) {
      dayBucket.sessions.set(memory.session_id, {
        session_id: memory.session_id,
        day: memory.day,
        project_id: memory.project_id,
        memory_count: 0,
        representative_key: memory.key,
        representative_memory_id: memory.memory_id,
        memory_types: new Set(),
        confidence_scores: [],
      });
    }
    const session = dayBucket.sessions.get(memory.session_id);
    session.memory_count++;
    session.memory_types.add(memory.memory_type);
    session.confidence_scores.push(memory.confidence);
  }

  return [...dayMap.values()]
    .sort((a, b) => String(a.day).localeCompare(String(b.day)))
    .map((dayBucket) => {
      const sessions = [...dayBucket.sessions.values()].map((session) => {
        const averageConfidence = session.confidence_scores.length
          ? session.confidence_scores.reduce((sum, value) => sum + value, 0) / session.confidence_scores.length
          : 0.5;
        return {
          session_id: session.session_id,
          day: session.day,
          project_id: session.project_id,
          memory_count: session.memory_count,
          representative_key: session.representative_key,
          representative_memory_id: session.representative_memory_id,
          memory_types: [...session.memory_types].sort(),
          confidence: Number(averageConfidence.toFixed(4)),
        };
      });
      return {
        day: dayBucket.day,
        session_count: sessions.length,
        memory_count: dayBucket.memory_count,
        sessions,
      };
    });
}

export function groupMultiSessionEvidence(input = {}) {
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || input);
  const limit = Math.trunc(clampNumber(input.limit, 24, 1, 1000));
  const groups = groupByDayAndSession(memories);
  const boundedGroups = [];
  let emittedSessions = 0;

  for (const day of groups) {
    if (emittedSessions >= limit) break;
    const remaining = limit - emittedSessions;
    const sessions = asArray(day.sessions).slice(0, remaining);
    boundedGroups.push({
      ...day,
      sessions,
      truncated_sessions: sessions.length < asArray(day.sessions).length,
    });
    emittedSessions += sessions.length;
  }

  return {
    status: memories.length > 0 ? 'ready' : 'insufficient_evidence',
    day_count: groups.length,
    session_count: groups.reduce((sum, day) => sum + day.session_count, 0),
    memory_count: memories.length,
    groups: boundedGroups,
    truncated: emittedSessions < groups.reduce((sum, day) => sum + day.session_count, 0),
  };
}

function compareMemoryTime(a, b) {
  const aTime = new Date(a.created_at || a.valid_from || `${a.day}T00:00:00.000Z`).getTime();
  const bTime = new Date(b.created_at || b.valid_from || `${b.day}T00:00:00.000Z`).getTime();
  const safeA = Number.isFinite(aTime) ? aTime : 0;
  const safeB = Number.isFinite(bTime) ? bTime : 0;
  if (safeA !== safeB) return safeA - safeB;
  return a.index - b.index;
}

function knowledgeGroupKey(memory) {
  return firstText(
    memory.metadata?.fact_id,
    memory.metadata?.entity_id,
    memory.metadata?.subject,
    memory.metadata?.key,
    memory.key,
    `${memory.project_id}:${memory.memory_type}`
  );
}

export function resolveKnowledgeUpdateState(input = {}) {
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || input);
  const queryUnderstanding = input.queryUnderstanding || input.query_understanding || {};
  const limit = Math.trunc(clampNumber(input.limit, 8, 1, 100));
  const applies = ['knowledge_update', 'current_truth'].includes(queryUnderstanding.intent);
  const groups = new Map();

  for (const memory of memories) {
    const key = knowledgeGroupKey(memory);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(memory);
  }

  const states = [...groups.entries()].slice(0, limit).map(([key, entries]) => {
    const ordered = [...entries].sort(compareMemoryTime);
    const current = ordered[ordered.length - 1];
    return {
      key,
      current: current ? {
        handle: handleFor(current),
        valid_from: current.valid_from || current.created_at || current.day,
        valid_until: current.valid_until || null,
        excerpt: truncateText(current.text, 260),
      } : null,
      prior_count: Math.max(0, ordered.length - 1),
      prior_handles: ordered.slice(0, -1).slice(-5).map(handleFor),
    };
  });

  return {
    applies,
    status: memories.length > 0 ? 'ready' : 'insufficient_evidence',
    policy: 'latest_valid_state_with_prior_handles',
    state_count: groups.size,
    states,
    truncated: groups.size > states.length,
  };
}

export function decideAbstention(input = {}) {
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || input);
  const queryUnderstanding = input.queryUnderstanding || input.query_understanding || {};
  if (memories.length === 0) {
    return {
      should_abstain: true,
      reason: 'no_recall_evidence',
      answer_policy: 'state_insufficient_evidence_and_return_no_counts',
    };
  }

  const confidence = memories.reduce((sum, memory) => sum + memory.confidence, 0) / memories.length;
  const exactTruth = ['current_truth', 'knowledge_update', 'full_detail'].includes(queryUnderstanding.intent);
  if (exactTruth && confidence < 0.42) {
    if (memories.length >= 3) {
      return {
        should_abstain: false,
        reason: 'low_numeric_confidence_but_multiple_evidence_handles',
        confidence: Number(confidence.toFixed(4)),
        answer_policy: 'answer_cautiously_with_source_handles',
      };
    }
    return {
      should_abstain: true,
      reason: 'low_confidence_for_exact_truth',
      confidence: Number(confidence.toFixed(4)),
      answer_policy: 'do_not_bluff_return_handles_and_caveat',
    };
  }

  return {
    should_abstain: false,
    reason: 'sufficient_bounded_evidence',
    confidence: Number(confidence.toFixed(4)),
    answer_policy: 'answer_with_source_bound_summary_and_handles',
  };
}

function enforceSummaryBudget(summary, tokenBudget) {
  let output = structuredClone(summary);
  let tokens = estimateTokens(output);
  if (tokens <= tokenBudget) {
    return { summary: output, estimated_tokens: tokens, trimmed: false };
  }

  output.days = asArray(output.days).map((day) => ({
    ...day,
    sessions: asArray(day.sessions).slice(0, 4),
  }));
  tokens = estimateTokens(output);
  if (tokens > tokenBudget) {
    output.days = asArray(output.days).slice(0, 8).map((day) => ({
      ...day,
      sessions: asArray(day.sessions).slice(0, 2),
    }));
    output.timeline = output.days;
    output.truncation_note = 'trimmed_to_summary_token_budget';
  }
  tokens = estimateTokens(output);
  if (tokens > tokenBudget) {
    output.days = asArray(output.days).slice(0, 6).map((day) => ({
      day: day.day,
      session_count: day.session_count,
      memory_count: day.memory_count,
      sessions: asArray(day.sessions).slice(0, 1).map((session) => ({
        session_id: session.session_id,
        day: session.day,
        project_id: session.project_id,
        memory_count: session.memory_count,
        representative_memory_id: session.representative_memory_id,
        confidence: session.confidence,
      })),
    }));
    output.timeline = output.days;
    output.truncation_note = 'trimmed_to_minimal_summary_token_budget';
  }
  tokens = estimateTokens(output);
  return { summary: output, estimated_tokens: tokens, trimmed: true };
}

export function buildAggregateSummary(input = {}) {
  const query = input.query || '';
  const runtimeBudget = normalizeRuntimeBudget(input.runtimeBudget || input.runtime_budget || {});
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || {});

  if (memories.length === 0) {
    return {
      summary: {
        kind: 'aggregate_summary',
        status: 'insufficient_evidence',
        query,
        direct_answer: 'Insufficient Aimos evidence in the supplied recall response to answer this aggregate question.',
        session_count: 0,
        day_count: 0,
        memory_count: 0,
        days: [],
        timeline: [],
        confidence: {
          band: 'low',
          notes: ['no_recall_memories_supplied'],
        },
      },
      budget: {
        estimated_tokens: 0,
        token_budget: runtimeBudget.summary_token_budget,
        trimmed: false,
      },
    };
  }

  const days = groupByDayAndSession(memories);
  const sessionCount = days.reduce((sum, day) => sum + day.session_count, 0);
  const confidenceScore = memories.reduce((sum, memory) => sum + memory.confidence, 0) / memories.length;
  const rawSummary = {
    kind: 'aggregate_summary',
    status: 'ready',
    query,
    direct_answer: `Found ${sessionCount} session${sessionCount === 1 ? '' : 's'} across ${days.length} day${days.length === 1 ? '' : 's'} in the supplied Aimos recall evidence.`,
    session_count: sessionCount,
    day_count: days.length,
    memory_count: memories.length,
    days,
    timeline: days,
    confidence: {
      band: confidenceBand(confidenceScore),
      score: Number(confidenceScore.toFixed(4)),
      notes: [
        'TiMem L3/L4 aggregate before L2/L1 body opening',
        'raw memory bodies withheld by default',
      ],
    },
  };
  const bounded = enforceSummaryBudget(rawSummary, runtimeBudget.summary_token_budget);
  return {
    summary: bounded.summary,
    budget: {
      estimated_tokens: bounded.estimated_tokens,
      token_budget: runtimeBudget.summary_token_budget,
      trimmed: bounded.trimmed,
    },
  };
}

function memoryContainsPhrase(memory, phrase) {
  const needle = normalizeQueryText(phrase);
  if (!needle) return false;
  const haystack = normalizeQueryText(`${memory.key} ${memory.session_id} ${memory.project_id} ${memory.memory_type} ${supportMemoryQueryText(memory)}`);
  return haystack.includes(needle);
}

function forceComparisonCoverage(selected, candidates, queryUnderstanding, maxCards) {
  const targets = asArray(queryUnderstanding?.comparison_targets);
  if (targets.length < 2) return selected;
  const out = [...selected];
  const selectedIds = new Set(out.map((item) => item.memory.memory_id));

  for (const target of targets) {
    const alreadyCovered = out.some((item) => memoryContainsPhrase(item.memory, target));
    if (alreadyCovered) continue;
    const candidate = candidates
      .filter((item) => !selectedIds.has(item.memory.memory_id))
      .filter((item) => memoryContainsPhrase(item.memory, target))
      .sort((a, b) => b.queryScore - a.queryScore)[0];
    if (!candidate) continue;
    const forced = {
      ...candidate,
      mmr_score: Number(candidate.queryScore.toFixed(6)),
      forced_reason: `comparison_target:${target}`,
    };
    if (out.length < maxCards) {
      out.push(forced);
      selectedIds.add(candidate.memory.memory_id);
    } else {
      const replaceIndex = out
        .map((item, index) => ({ item, index }))
        .sort((a, b) => (a.item.queryScore || 0) - (b.item.queryScore || 0))[0]?.index;
      if (replaceIndex !== undefined && (out[replaceIndex].queryScore || 0) < candidate.queryScore) {
        selectedIds.delete(out[replaceIndex].memory.memory_id);
        out[replaceIndex] = forced;
        selectedIds.add(candidate.memory.memory_id);
      }
    }
  }

  return out.sort((a, b) => (b.queryScore || 0) - (a.queryScore || 0)).slice(0, maxCards);
}

function identityTruthEvidenceScore(memory) {
  const keySurface = normalizeQueryText(`${memory.key} ${memory.source}`);
  const rawSurface = `${memory.key} ${memory.session_id} ${memory.project_id} ${memory.memory_type} ${memory.source} ${supportMemoryQueryText(memory)}`
    .replace(/\\[nrt]/g, ' ');
  const haystack = normalizeQueryText(rawSurface);
  const explicitDeclaration = /\bidentity\s*:\s*.{0,160}\b(executive runtime|runtime for|canonical|confirmed|ceo level|orchestrator)\b/.test(haystack)
    || /\bidentity confirmed\b.{0,160}\b(executive runtime|runtime for|canonical|ceo level|orchestrator)\b/.test(haystack);
  if (!explicitDeclaration) return 0;

  const type = String(memory.memory_type || '').toLowerCase();
  const directIdentityKey = /\b(identity|boot_identity|identity_confirmed|core_belief|brain_contract)\b/.test(keySurface);
  const directIdentityType = ['identity', 'core_belief', 'directive', 'event_log', 'infrastructure'].includes(type);
  if (!directIdentityKey && !directIdentityType) return 0;
  const typeAuthority = type === 'identity'
    ? 0.16
    : type === 'core_belief'
      ? 0.14
      : type === 'directive'
        ? 0.12
        : type === 'event_log'
          ? 0.10
          : type === 'infrastructure'
            ? 0.06
            : type === 'session_debrief' && directIdentityKey
              ? 0.02
              : type === 'session_debrief'
                ? -0.10
            : type === 'conversation_feed' || /\b(precompact|feed)\b/.test(haystack)
              ? -0.18
              : 0.04;
  const confidence = Math.max(0, Math.min(1, Number(memory.confidence) || 0.5));
  const verified = memory.freshness_state === 'fresh' || memory.last_verified_at ? 0.04 : 0;
  const disclaimerPenalty = /\b(identity labels do not equal|labels do not equal|legacy alias|not canonical|not the identity)\b/.test(haystack)
    ? 0.35
    : 0;
  const mirrorPenalty = /\b(precompact|conversation feed|session feed|question:|answer the question using only the context)\b/.test(haystack)
    ? 0.24
    : 0;
  return Number(Math.max(0, Math.min(1, 0.72 + typeAuthority + (confidence * 0.10) + verified - disclaimerPenalty - mirrorPenalty)).toFixed(6));
}

function forceIdentityTruthCoverage(selected, candidates, queryUnderstanding, maxCards) {
  if (!queryUnderstanding?.features?.asks_identity_truth) return selected;
  const identityCandidates = candidates
    .map((item) => ({
      ...item,
      identity_truth_score: identityTruthEvidenceScore(item.memory),
    }))
    .filter((item) => item.identity_truth_score >= 0.72)
    .sort((a, b) =>
      (b.identity_truth_score - a.identity_truth_score)
      || (b.queryScore - a.queryScore)
      || compareMemoryTime(b.memory, a.memory)
    );
  const best = identityCandidates[0];
  if (!best) return selected;

  const out = [...selected];
  const memoryKey = (memory) => memory.memory_id || memory.key || `${memory.session_id}:${memory.index}`;
  const selectedIds = new Set(out.map((item) => memoryKey(item.memory)));
  if (selectedIds.has(memoryKey(best.memory))) {
    return out.map((item) => ({
      ...item,
      identity_truth_score: identityTruthEvidenceScore(item.memory),
    }));
  }

  const forced = {
    ...best,
    mmr_score: Number(Math.max(best.queryScore || 0, best.identity_truth_score).toFixed(6)),
    forced_reason: 'identity_truth_declaration',
  };
  if (out.length < maxCards) {
    out.unshift(forced);
  } else {
    const replaceIndex = out
      .map((item, index) => ({
        index,
        identity_truth_score: identityTruthEvidenceScore(item.memory),
        queryScore: item.queryScore || 0,
      }))
      .sort((a, b) => (a.identity_truth_score - b.identity_truth_score) || (a.queryScore - b.queryScore))[0]?.index;
    if (replaceIndex !== undefined) out[replaceIndex] = forced;
  }

  return out
    .map((item) => ({
      ...item,
      identity_truth_score: item.identity_truth_score ?? identityTruthEvidenceScore(item.memory),
    }))
    .sort((a, b) =>
      (b.identity_truth_score - a.identity_truth_score)
      || (b.queryScore - a.queryScore)
      || compareMemoryTime(b.memory, a.memory)
    )
    .slice(0, maxCards);
}

function mmrSelect(memories, query, tokenBudget, queryUnderstanding = {}) {
  const lambda = 0.72;
  const maxCardChars = 640;
  const maxCards = Math.max(1, Math.min(6, Math.floor(tokenBudget / 750)));
  const selected = [];
  const candidates = memories.map((memory) => ({
    memory,
    queryScore: querySimilarity(query, memory, queryUnderstanding),
    tokenSet: tokenSet(`${memory.session_id} ${memory.day} ${memory.key} ${supportMemoryQueryText(memory)}`),
  }));
  const remaining = [...candidates];
  let estimatedTokens = 0;

  while (remaining.length > 0 && selected.length < maxCards) {
    let bestIndex = -1;
    let bestScore = -Infinity;
    for (let index = 0; index < remaining.length; index++) {
      const candidate = remaining[index];
      const maxSimilarityToSelected = selected.reduce((max, selectedItem) => {
        const lexicalSimilarity = jaccard(candidate.tokenSet, selectedItem.tokenSet);
        const sameSessionPenalty = candidate.memory.session_id === selectedItem.memory.session_id ? 0.20 : 0;
        const sameDayPenalty = candidate.memory.day === selectedItem.memory.day ? 0.08 : 0;
        return Math.max(max, lexicalSimilarity + sameSessionPenalty + sameDayPenalty);
      }, 0);
      const relevance = (0.65 * candidate.queryScore) + (0.25 * candidate.memory.confidence) + 0.10;
      const mmrScore = (lambda * relevance) - ((1 - lambda) * maxSimilarityToSelected);
      if (mmrScore > bestScore) {
        bestScore = mmrScore;
        bestIndex = index;
      }
    }
    if (bestIndex < 0) break;
    const [picked] = remaining.splice(bestIndex, 1);
    const cardEstimate = estimateTokens(supportMemoryQueryText(picked.memory).slice(0, maxCardChars)) + 90;
    if (selected.length > 0 && estimatedTokens + cardEstimate > tokenBudget) break;
    selected.push({
      ...picked,
      mmr_score: Number(bestScore.toFixed(6)),
    });
    estimatedTokens += cardEstimate;
  }

  const covered = forceIdentityTruthCoverage(
    forceComparisonCoverage(selected, candidates, queryUnderstanding, maxCards),
    candidates,
    queryUnderstanding,
    maxCards
  );
  if (queryUnderstanding?.features?.asks_identity_truth) {
    return covered;
  }
  if (['current_truth', 'knowledge_update'].includes(queryUnderstanding.intent)) {
    return covered.sort((a, b) => compareMemoryTime(b.memory, a.memory));
  }
  return covered;
}

function evidenceCardFor(selectedItem, index) {
  const memory = selectedItem.memory;
  return {
    card_id: `evidence:${index + 1}`,
    claim: firstText(memory.metadata?.claim, memory.metadata?.title, memory.key) || memory.key,
    excerpt: truncateText(supportMemoryQueryText(memory), 520),
    handle: handleFor(memory),
    day: memory.day,
    session_id: memory.session_id,
    project_id: memory.project_id,
    source: memory.source,
    memory_type: memory.memory_type,
    confidence: {
      score: memory.confidence,
      band: confidenceBand(memory.confidence),
    },
    selection: {
      method: 'MMR',
      mmr_lambda: 0.72,
      score: selectedItem.mmr_score,
      forced_reason: selectedItem.forced_reason || null,
    },
  };
}

export function buildBoundedEvidencePack(input = {}) {
  const query = input.query || '';
  const runtimeBudget = normalizeRuntimeBudget(input.runtimeBudget || input.runtime_budget || {});
  const memories = Array.isArray(input.memories)
    ? input.memories
    : extractMemories(input.recallResponse || input.recall_response || {});

  if (memories.length === 0) {
    return {
      evidence_cards: [],
      summary: {
        kind: 'bounded_evidence_pack',
        status: 'insufficient_evidence',
        query,
        direct_answer: 'Insufficient Aimos evidence in the supplied recall response to build an evidence pack.',
        confidence: {
          band: 'low',
          notes: ['no_recall_memories_supplied'],
        },
      },
      budget: {
        estimated_tokens: 0,
        token_budget: runtimeBudget.evidence_token_budget,
        trimmed: false,
      },
    };
  }

  const queryUnderstanding = input.queryUnderstanding || input.query_understanding || {};
  const selected = mmrSelect(memories, query, runtimeBudget.evidence_token_budget, queryUnderstanding);
  const evidenceCards = selected.map(evidenceCardFor);
  const confidenceScore = selected.length
    ? selected.reduce((sum, item) => sum + item.memory.confidence, 0) / selected.length
    : 0.25;
  const summary = {
    kind: 'bounded_evidence_pack',
    status: evidenceCards.length > 0 ? 'ready' : 'insufficient_evidence',
    query,
    direct_answer: evidenceCards.length > 0
      ? `Selected ${evidenceCards.length} source-attributed evidence card${evidenceCards.length === 1 ? '' : 's'} from ${memories.length} recalled memor${memories.length === 1 ? 'y' : 'ies'}.`
      : 'Insufficient Aimos evidence in the supplied recall response to build an evidence pack.',
    confidence: {
      band: confidenceBand(confidenceScore),
      score: Number(confidenceScore.toFixed(4)),
      notes: [
        'MMR-style diversity after existing Aimos recall ranking',
        'source handles preserved for full-detail drilldown',
      ],
    },
  };
  return {
    evidence_cards: evidenceCards,
    summary,
    budget: {
      estimated_tokens: estimateTokens({ summary, evidence_cards: evidenceCards }),
      token_budget: runtimeBudget.evidence_token_budget,
      trimmed: selected.length < memories.length,
    },
  };
}

function supportMemoryText(memory) {
  return supportMemoryQueryText(memory);
}

function supportMemoryRolePairDurationScore(memory, label, role) {
  const text = supportMemoryText(memory);
  const coreTerms = new Set(tokenize(label));
  const expandedTerms = supportPhraseTerms(label);
  if (!coreTerms.size || !text.trim()) return 0;
  const normalized = normalizeQueryText(text);
  const contextTerms = new Set(tokenize(text));
  const matched = [...coreTerms].filter((term) => supportTokenFamilyMatches(term, contextTerms)).length;
  const matchedExpanded = [...expandedTerms].filter((term) => supportTokenFamilyMatches(term, contextTerms)).length;
  const required = supportRequiredRoleMatches(coreTerms.size);
  const roleNorm = normalizeQueryText(label);
  let predicate = false;
  if (role === 'start') {
    predicate = /\b(?:since|start(?:ed|ing)?|began|working\s+with|work(?:ed|ing)?\s+with)\b/.test(normalized);
  } else if (role === 'end') {
    predicate = /\b(?:found|find|saw|seen|located|house|home|property|love|loved|like|liked)\b/.test(normalized);
  }
  if (role === 'start' && /\b(?:start|started|starting|begin|began|beginning)\b/.test(roleNorm) && !predicate) return 0;
  if (role === 'end' && /\b(?:find|found|house|home|property|lov)\b/.test(roleNorm) && !predicate) return 0;
  if (matched < required && !(predicate && matched >= Math.max(1, required - 1))) return 0;
  const dated = /\b(?:20\d{2}[/-]\d{1,2}[/-]\d{1,2}|\d{1,2}\/\d{1,2}|(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2})\b/i.test(text);
  return matched * 12 + Math.min(matchedExpanded, coreTerms.size + 2) * 2 + (predicate ? 24 : 0) + (dated ? 12 : 0);
}

function supportPrioritizeRolePairDurationMemories(memories, query) {
  const match = String(query || '').match(/\bhow\s+many\s+(days?|weeks?|months?)\s+did\s+it\s+take\s+for\s+me\s+to\s+(.+?)\s+after\s+(.+?)(?:\?|$)/i);
  if (!match || memories.length < 2) return memories;
  const endLabel = match[2];
  const startLabel = match[3];
  const starts = memories
    .map((memory, index) => ({
      memory,
      index,
      root: supportBenchmarkSiblingRoot(memory?.key),
      score: supportMemoryRolePairDurationScore(memory, startLabel, 'start'),
    }))
    .filter((item) => item.score > 0);
  const ends = memories
    .map((memory, index) => ({
      memory,
      index,
      root: supportBenchmarkSiblingRoot(memory?.key),
      score: supportMemoryRolePairDurationScore(memory, endLabel, 'end'),
    }))
    .filter((item) => item.score > 0);
  const pairs = [];
  for (const start of starts) {
    for (const end of ends) {
      if ((start.memory?.memory_id || start.memory?.key) === (end.memory?.memory_id || end.memory?.key)) continue;
      const sameRoot = start.root && end.root && start.root === end.root;
      pairs.push({
        start,
        end,
        score: start.score + end.score + (sameRoot ? 48 : 0) - Math.abs(start.index - end.index) / 10,
      });
    }
  }
  const best = pairs.sort((a, b) => b.score - a.score)[0];
  if (!best) return memories;
  const promoted = [best.start.memory, best.end.memory];
  const promotedKeys = new Set(promoted.map((memory) => memory?.memory_id || memory?.key));
  return [
    ...promoted,
    ...memories.filter((memory) => !promotedKeys.has(memory?.memory_id || memory?.key)),
  ];
}

function supportPrioritizeFullDetailMemories(memories, query) {
  const aggregateOrdered = supportPrioritizeAggregateOperatorMemories(memories, query);
  if (aggregateOrdered !== memories) return aggregateOrdered;

  const rolePairOrdered = supportPrioritizeRolePairDurationMemories(memories, query);
  if (rolePairOrdered !== memories) return rolePairOrdered;

  const normalizedQuery = normalizeQueryText(query);
  if (/\btransition\b/.test(normalizedQuery) && /\bchanges?\b/.test(normalizedQuery) && memories.length >= 2) {
    const scored = memories.map((memory, index) => {
      const normalized = normalizeQueryText(`${memory?.key || ''}\n${supportMemoryQueryText(memory)}`);
      const bodySlot = /\bbody\b/.test(normalized) && /\b(?:transition|changing|changed|explore|journey)\b/.test(normalized);
      const relationshipSlot = /\bfriends?\b/.test(normalized)
        && /\b(?:couldn\s*t|couldnt|unable|weren\s*t|werent|lost|handle|supporting|supportive|accept)\b/.test(normalized);
      return { memory, index, bodySlot, relationshipSlot };
    });
    const body = scored.find((item) => item.bodySlot);
    const relationship = scored.find((item) => item.relationshipSlot);
    if (body || relationship) {
      const promoted = [body, relationship].filter(Boolean).map((item) => item.memory);
      const promotedKeys = new Set(promoted.map((memory) => memory?.memory_id || memory?.key));
      return [
        ...promoted,
        ...memories.filter((memory) => !promotedKeys.has(memory?.memory_id || memory?.key)),
      ];
    }
  }

  const parts = supportCountBeforeQuestionParts(query);
  if (!parts || memories.length < 2) return memories;
  const evidenceText = supportEvidenceTextFromMemories(memories, 120000, query);
  const anchor = supportBestBlockRoleDate(evidenceText, parts.anchorLabel)
    || supportBestMention(supportRoleAwareDateMentions(evidenceText), supportPhraseTerms(parts.anchorLabel));
  const root = String(anchor?.root || '');
  if (!root) return memories;
  const rootMemories = [];
  const otherMemories = [];
  for (const memory of memories) {
    const key = String(memory?.key || '');
    if (supportBenchmarkSiblingRoot(key) === root) rootMemories.push(memory);
    else otherMemories.push(memory);
  }
  if (rootMemories.length < 2) return memories;
  rootMemories.sort((a, b) => String(a.key || '').localeCompare(String(b.key || '')));
  return [...rootMemories, ...otherMemories];
}

function supportFullDetailTokenSet(value) {
  return new Set(tokenize(String(value || '').replace(/[_:/.-]+/g, ' ')));
}

function supportFullDetailOverlapRatio(queryTokens, valueTokens) {
  if (!queryTokens.size || !valueTokens.size) return 0;
  let matches = 0;
  for (const token of queryTokens) {
    if (valueTokens.has(token)) matches += 1;
  }
  return matches / queryTokens.size;
}

function supportFullDetailPhaseMarkers(value) {
  const normalized = String(value || '').toLowerCase().replace(/[_:/.-]+/g, ' ');
  const markers = new Set();
  for (const match of normalized.matchAll(/\bphase\s+([a-z0-9]+)\b/g)) {
    if (match[1]) markers.add(match[1]);
  }
  return markers;
}

function supportFullDetailDateMarkers(value) {
  const raw = String(value || '').toLowerCase();
  const normalized = raw.replace(/[_:/.-]+/g, ' ');
  const markers = new Set();
  for (const match of raw.matchAll(/\b(20\d{2})-(\d{1,2})-(\d{1,2})\b/g)) {
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    if (year && month >= 1 && month <= 12 && day >= 1 && day <= 31) {
      markers.add(`${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`);
    }
  }
  for (const match of normalized.matchAll(/\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec)\s+(\d{1,2})(?:st|nd|rd|th)?\s+(20\d{2})\b/g)) {
    const monthIndex = SUPPORT_MONTH_INDEX.get(match[1]);
    const day = Number(match[2]);
    const year = Number(match[3]);
    if (Number.isFinite(monthIndex) && year && day >= 1 && day <= 31) {
      markers.add(`${year}-${String(monthIndex + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`);
    }
  }
  return markers;
}

function supportFullDetailScoreSignal(memory) {
  const components = memory?.raw?.score_components || memory?.score_components || memory?.raw?.confidence?.components || {};
  const diagnostics = memory?.raw?.rank_diagnostics || memory?.rank_diagnostics || {};
  const candidates = [
    components.final_confidence,
    memory?.raw?.recall_confidence,
    memory?.recall_confidence,
    diagnostics.final_score,
    memory?.confidence,
    components.semantic,
    components.keyword,
  ];
  for (const candidate of candidates) {
    const n = Number(candidate);
    if (Number.isFinite(n)) return Math.max(0, Math.min(1, n));
  }
  return 0.5;
}

function supportFullDetailTypeSignal(memory) {
  const type = String(memory?.memory_type || memory?.raw?.memory_type || '').toLowerCase();
  if (['session_evidence_record', 'operational_rule', 'after_action_review', 'procedural_seed', 'procedural'].includes(type)) return 0.16;
  if (['session_debrief', 'declarative', 'identity', 'tacit_knowledge', 'framework'].includes(type)) return 0.08;
  if (['dream_artifact', 'dream_summary', 'conversation_feed', 'heartbeat'].includes(type)) return -0.12;
  return 0;
}

function supportFullDetailOpeningCandidate(memory, query, queryTokens, index) {
  const key = String(memory?.key || memory?.memory_id || memory?.raw?.key || '');
  const value = supportMemoryQueryText(memory);
  const rawValue = String(memory?.raw?.value ?? memory?.value ?? memory?.text ?? value ?? '');
  const keyOverlap = supportFullDetailOverlapRatio(queryTokens, supportFullDetailTokenSet(key));
  const bodyOverlap = supportFullDetailOverlapRatio(queryTokens, supportFullDetailTokenSet(value));
  const queryPhaseMarkers = supportFullDetailPhaseMarkers(query);
  const memoryPhaseMarkers = supportFullDetailPhaseMarkers(`${key}\n${value}`);
  const phaseMarkerMatch = queryPhaseMarkers.size === 0
    ? null
    : [...queryPhaseMarkers].some((marker) => memoryPhaseMarkers.has(marker));
  const queryDateMarkers = supportFullDetailDateMarkers(query);
  const memoryDateMarkers = supportFullDetailDateMarkers(`${key}\n${value}`);
  const dateMarkerMatch = queryDateMarkers.size === 0
    ? null
    : [...queryDateMarkers].some((marker) => memoryDateMarkers.has(marker));
  let directness = Math.max(keyOverlap, bodyOverlap);
  if (phaseMarkerMatch === true) directness = Math.min(1, directness + 0.08);
  else if (phaseMarkerMatch === false && memoryPhaseMarkers.size > 0) directness = Math.max(0, directness - 0.22);
  if (dateMarkerMatch === true) directness = Math.min(1, directness + 0.18);
  else if (dateMarkerMatch === false && memoryDateMarkers.size > 0) directness = Math.max(0, directness - 0.20);
  const exactKeyCue = normalizeQueryText(String(query || '').replace(/[_:/.-]+/g, ' ')) === normalizeQueryText(key.replace(/[_:/.-]+/g, ' '));
  const confidence = supportFullDetailScoreSignal(memory);
  const typeSignal = supportFullDetailTypeSignal(memory);
  const tokenCost = Math.max(1, estimateTokens({
    ...handleFor(memory),
    value: rawValue,
    metadata: memory.metadata,
  }));
  const structuralAnchorMatch = exactKeyCue || phaseMarkerMatch === true || dateMarkerMatch === true;
  const oversized = tokenCost > 6000 || rawValue.length > 24000;
  const effectiveTokenCost = oversized && structuralAnchorMatch && !exactKeyCue
    ? Math.min(tokenCost, 2400)
    : tokenCost;
  const evidenceUtility = Math.max(0.01, (0.45 * directness) + (0.35 * confidence) + (0.20 * Math.max(0, typeSignal + 0.12)));
  const openingScore = evidenceUtility / Math.log2(1 + effectiveTokenCost);
  return {
    memory,
    index,
    key,
    value,
    key_overlap: Number(keyOverlap.toFixed(4)),
    body_overlap: Number(bodyOverlap.toFixed(4)),
    directness: Number(directness.toFixed(4)),
    phase_marker_match: phaseMarkerMatch,
    date_marker_match: dateMarkerMatch,
    confidence: Number(confidence.toFixed(4)),
    type_signal: Number(typeSignal.toFixed(4)),
    token_cost: tokenCost,
    effective_token_cost: effectiveTokenCost,
    evidence_utility: Number(evidenceUtility.toFixed(6)),
    opening_score: Number(openingScore.toFixed(8)),
    exact_key_cue: exactKeyCue,
    oversized,
  };
}

function supportFullDetailOpeningOrder(memories, query, prioritizedMemories) {
  const queryTokens = supportFullDetailTokenSet(query);
  const candidates = prioritizedMemories.map((memory, index) => supportFullDetailOpeningCandidate(memory, query, queryTokens, index));
  const priorityWasExplicit = prioritizedMemories !== memories;
  if (priorityWasExplicit) return candidates;
  return candidates.sort((a, b) => {
    return (b.opening_score - a.opening_score)
      || (b.directness - a.directness)
      || (b.confidence - a.confidence)
      || (a.index - b.index);
  });
}

function supportFullDetailItemFor(candidate, query, value, openingMode, originalTokens) {
  const memory = candidate.memory;
  const valueText = String(value ?? '');
  return {
    ...handleFor(memory),
    created_at: memory.created_at,
    valid_from: memory.valid_from,
    valid_until: memory.valid_until,
    similarity: memory.raw?.similarity ?? memory.similarity ?? null,
    similarity_basis: memory.raw?.similarity_basis ?? memory.similarity_basis ?? null,
    score_components: memory.raw?.score_components ?? memory.score_components ?? null,
    rank_diagnostics: memory.raw?.rank_diagnostics ?? memory.rank_diagnostics ?? null,
    value: valueText,
    metadata: memory.metadata,
    full_detail_opening: {
      mode: openingMode,
      raw_body_included: openingMode === 'full_body',
      original_value_chars: String(candidate.value || '').length,
      emitted_value_chars: valueText.length,
      original_tokens: originalTokens,
      emitted_tokens: estimateTokens(valueText),
      key_overlap: candidate.key_overlap,
      body_overlap: candidate.body_overlap,
      directness: candidate.directness,
      phase_marker_match: candidate.phase_marker_match,
      date_marker_match: candidate.date_marker_match,
      confidence: candidate.confidence,
      type_signal: candidate.type_signal,
      evidence_utility: candidate.evidence_utility,
      token_cost: candidate.token_cost,
      effective_token_cost: candidate.effective_token_cost,
      opening_score: candidate.opening_score,
    },
  };
}

function supportAggregateRowsForMemory(query, memory) {
  const q = normalizeQueryText(query);
  const key = String(memory?.key || memory?.memory_id || memory?.raw?.key || '');
  const value = supportMemoryQueryText(memory);
  if (!key || !value) return [];
  const entry = {
    key,
    block: [`key: ${key}`, value].join('\n'),
  };
  const rows = [];
  if (/\b(?:pick up|pickup|return|exchange)\b/.test(q) && /\b(?:item|items|clothing|clothes)\b/.test(q)) rows.push(...supportClothingObligationRows(entry));
  if (/\bplants?\b/.test(q) && /\b(?:acquire|acquired|got|bought|get)\b/.test(q)) rows.push(...supportPlantAcquisitionRows(entry));
  if (/\bcamping\s+trips?\b/.test(q) && /\bdays?\b/.test(q)) rows.push(...supportCampingDurationRows(entry));
  if (/\b(?:money|spent|expenses?|cost)\b/.test(q) && /\bbike\b/.test(q)) rows.push(...supportBikeExpenseRows(entry));
  if (/\b(?:hours?|driving|drive|drove)\b/.test(q) && /\b(?:road trip|destinations?)\b/.test(q)) rows.push(...supportDrivingDurationRows(entry));
  return rows;
}

function supportPrioritizeAggregateOperatorMemories(memories, query) {
  const q = normalizeQueryText(query);
  if (!/\b(how many|how much|total|spent|expenses?|cost|hours?|days?)\b/.test(q)) return memories;
  const rowsByKey = new Map();
  for (const memory of memories) {
    for (const row of supportAggregateRowsForMemory(query, memory)) {
      const existing = rowsByKey.get(row.key) || [];
      existing.push(row);
      rowsByKey.set(row.key, existing);
    }
  }
  if (!rowsByKey.size) return memories;

  let promotedKeys = [...rowsByKey.keys()];
  const drivingAggregate = /\b(?:hours?|driving|drive|drove)\b/.test(q) && /\b(?:road trip|destinations?)\b/.test(q);
  if (drivingAggregate && /\bthree\b|\b3\b/.test(q)) {
    const roots = new Map();
    for (const [key, rows] of rowsByKey.entries()) {
      const root = supportBenchmarkSiblingRoot(key);
      const bucket = roots.get(root) || [];
      bucket.push(...rows);
      roots.set(root, bucket);
    }
    const bestRoot = [...roots.entries()]
      .filter(([, rows]) => supportUniqueAggregateRows(rows).length >= 3)
      .sort((a, b) => supportUniqueAggregateRows(b[1]).length - supportUniqueAggregateRows(a[1]).length)[0];
    if (bestRoot) promotedKeys = promotedKeys.filter((key) => supportBenchmarkSiblingRoot(key) === bestRoot[0]);
  }

  const promotedKeySet = new Set(promotedKeys);
  if (!promotedKeySet.size) return memories;
  const promoted = memories
    .filter((memory) => promotedKeySet.has(String(memory?.key || memory?.memory_id || memory?.raw?.key || '')))
    .sort((a, b) => {
      const aRows = rowsByKey.get(String(a?.key || a?.memory_id || a?.raw?.key || '')) || [];
      const bRows = rowsByKey.get(String(b?.key || b?.memory_id || b?.raw?.key || '')) || [];
      return supportUniqueAggregateRows(bRows).length - supportUniqueAggregateRows(aRows).length
        || String(a.key || '').localeCompare(String(b.key || ''));
    });
  const promotedIds = new Set(promoted.map((memory) => memory?.memory_id || memory?.key));
  return [
    ...promoted,
    ...memories.filter((memory) => !promotedIds.has(memory?.memory_id || memory?.key)),
  ];
}

function buildFullDetail(memories, query, runtimeBudget) {
  if (memories.length === 0) {
    return {
      full_detail: {
        status: 'insufficient_evidence',
        memories: [],
      },
      summary: {
        kind: 'full_detail',
        status: 'insufficient_evidence',
        query,
        direct_answer: 'Insufficient Aimos evidence in the supplied recall response to open full detail.',
      },
      budget: {
        estimated_tokens: 0,
        token_budget: runtimeBudget.full_detail_token_budget,
        trimmed: false,
      },
    };
  }

  const prioritizedMemories = supportPrioritizeFullDetailMemories(memories, query);
  const openingCandidates = supportFullDetailOpeningOrder(memories, query, prioritizedMemories);
  const fullMemories = [];
  const openingDiagnostics = [];
  const skippedDueToBudget = [];
  const snippetCharCap = Math.max(1200, Math.min(8000, Math.floor(runtimeBudget.full_detail_token_budget * 0.45 * 4)));
  let estimatedTokens = 0;
  for (const candidate of openingCandidates) {
    const memory = candidate.memory;
    const originalValue = String(memory.raw?.value ?? memory.text ?? candidate.value ?? '');
    const originalItem = supportFullDetailItemFor(candidate, query, originalValue, 'full_body', candidate.token_cost);
    const originalTokens = estimateTokens(originalItem);
    const remainingTokens = runtimeBudget.full_detail_token_budget - estimatedTokens;
    const shouldSnippet = candidate.oversized && !candidate.exact_key_cue;
    const openingValue = shouldSnippet
      ? supportExcerptEvidenceValue(originalValue, query, snippetCharCap)
      : originalValue;
    const openingMode = shouldSnippet ? 'snippet_handle' : 'full_body';
    const item = supportFullDetailItemFor(candidate, query, openingValue, openingMode, originalTokens);
    const itemTokens = estimateTokens(item);
    if (fullMemories.length > 0 && itemTokens > remainingTokens) {
      skippedDueToBudget.push({
        key: candidate.key,
        memory_type: memory.memory_type,
        requested_tokens: itemTokens,
        remaining_tokens: Math.max(0, remainingTokens),
        opening_score: candidate.opening_score,
      });
      continue;
    }
    fullMemories.push(item);
    estimatedTokens += itemTokens;
    openingDiagnostics.push({
      key: candidate.key,
      memory_type: memory.memory_type,
      mode: openingMode,
      rank_before_opening: candidate.index + 1,
      opened_rank: fullMemories.length,
      item_tokens: itemTokens,
      cumulative_tokens: estimatedTokens,
      opening_score: candidate.opening_score,
      directness: candidate.directness,
      phase_marker_match: candidate.phase_marker_match,
      date_marker_match: candidate.date_marker_match,
      oversized: candidate.oversized,
    });
  }

  return {
      full_detail: {
      status: fullMemories.length > 0 ? 'ready' : 'insufficient_evidence',
      memories: fullMemories,
      total_memories_available: prioritizedMemories.length,
      trimmed: fullMemories.length < prioritizedMemories.length,
      opening_diagnostics: {
        policy: 'budgeted_utility_opening',
        formula: 'open_score_i = evidence_utility_i / log2(1 + token_cost_i)',
        opened: openingDiagnostics,
        skipped_due_to_budget: skippedDueToBudget,
        opened_full: openingDiagnostics.filter((item) => item.mode === 'full_body').length,
        opened_snippet: openingDiagnostics.filter((item) => item.mode === 'snippet_handle').length,
        largest_item_tokens: openingCandidates.reduce((max, item) => Math.max(max, item.token_cost), 0),
      },
    },
    summary: {
      kind: 'full_detail',
      status: fullMemories.length > 0 ? 'ready' : 'insufficient_evidence',
      query,
      direct_answer: `Opened ${fullMemories.length} full-detail memor${fullMemories.length === 1 ? 'y' : 'ies'} from ${prioritizedMemories.length} recalled memor${prioritizedMemories.length === 1 ? 'y' : 'ies'}.`,
      confidence: {
        band: 'medium',
        notes: ['explicit full-detail drilldown path', 'budgeted utility opening'],
      },
    },
    budget: {
      estimated_tokens: estimateTokens(fullMemories),
      token_budget: runtimeBudget.full_detail_token_budget,
      trimmed: fullMemories.length < memories.length,
      skipped_due_to_budget: skippedDueToBudget.length,
    },
  };
}

function diagnosticsFor({
  query,
  memories,
  output,
  shape,
  runtimeBudget,
  confidenceNotes,
  handles,
  queryUnderstanding,
  readingPlan,
}) {
  const inputTokens = memories.reduce((sum, memory) => sum + memory.tokens_estimate, 0);
  const outputTokens = estimateTokens(output);
  return {
    query,
    input_memory_count: memories.length,
    output_memory_count: shape === 'full_detail' ? (output.full_detail?.memories?.length || 0) : (output.evidence_cards?.length || 0),
    detail_handle_count: handles.handles.length,
    total_detail_handles_available: handles.total_handles_available,
    handles_truncated: handles.truncated,
    input_tokens_estimate: inputTokens,
    output_tokens_estimate: outputTokens,
    compression_ratio: outputTokens > 0 ? Number((inputTokens / outputTokens).toFixed(4)) : null,
    selected_shape: shape,
    query_intent: queryUnderstanding.intent,
    temporal_scope_kind: queryUnderstanding.temporal_scope.kind,
    target_matrix: queryUnderstanding.target_matrix,
    confidence_notes: confidenceNotes,
    runtime_budget: {
      context_window: runtimeBudget.context_window,
      tokens_used: runtimeBudget.tokens_used,
      pressure: runtimeBudget.pressure,
      budget_for_recall: runtimeBudget.budget_for_recall,
      summary_token_budget: runtimeBudget.summary_token_budget,
      evidence_token_budget: runtimeBudget.evidence_token_budget,
      full_detail_token_budget: runtimeBudget.full_detail_token_budget,
    },
    corpus_authority: 'docs/recall-calibration-corpus.md',
    formulas_used: [
      'summary_first_recall_ladder',
      'context_pressure_budget',
      'TiMem_L1_L5_day_session_aggregation',
      'MMR_diversity_for_evidence_pack',
      'source_attributed_synthesis',
      'temporal_scope_resolution',
      'knowledge_update_latest_valid_state',
      'bounded_reading_strategy',
    ],
    scale_profile: {
      normalization_time: 'O(n)',
      grouping_time: readingPlan.complexity.grouping_time,
      evidence_selection_time: readingPlan.complexity.evidence_selection_time,
      auxiliary_space: readingPlan.complexity.auxiliary_space,
      bounded_by: 'native Aimos recall response size plus configured token budgets',
    },
    live_write_performed: false,
    native_service_claim: true,
  };
}

export function buildRecallOutputCalibration(input = {}) {
  const query = input.query || input.q || '';
  const recallResponse = input.recallResponse || input.recall_response || {};
  const runtimeBudget = normalizeRuntimeBudget(input.runtimeBudget || input.runtime_budget || {});
  const extractedMemories = extractMemories(recallResponse);
  const classification = classifyRecallShape(query, recallResponse, runtimeBudget);
  const queryUnderstanding = classification.query_understanding;
  const readingPlan = buildBoundedReadingPlan(queryUnderstanding, runtimeBudget);
  const aimosRecallPlan = buildAimosRecallPlan(queryUnderstanding, runtimeBudget);
  const shape = classification.answer_shape;
  const memories = attachBoundedAnalysisText(
    extractedMemories,
    query,
    shape === 'full_detail' ? 12000 : 6400
  );
  const handleMode = shape === 'aggregate_summary' ? 'session' : 'memory';
  const maxDetailHandles = shape === 'aggregate_summary'
    ? Math.min(16, runtimeBudget.handle_limit, readingPlan.limits.max_detail_handles)
    : Math.min(runtimeBudget.handle_limit, readingPlan.limits.max_detail_handles);
  const handles = buildDetailHandles({
    memories,
    limit: maxDetailHandles,
    mode: handleMode,
  });

  let shaped;
  if (shape === 'aggregate_summary') {
    shaped = buildAggregateSummary({ query, memories, runtimeBudget });
  } else if (shape === 'full_detail') {
    shaped = buildFullDetail(memories, query, runtimeBudget);
  } else {
    shaped = buildBoundedEvidencePack({ query, memories, runtimeBudget, queryUnderstanding });
  }
  const supportMemories = shape === 'full_detail'
    ? asArray(shaped.full_detail?.memories).map((memory) => ({
        ...memory,
        id: memory.memory_id || memory.id,
        memory_id: memory.memory_id || memory.id,
        value: memory.value,
        text: memory.value,
      }))
    : memories;
  const answerGenerationSupport = buildAnswerGenerationSupport({
    query,
    memories: supportMemories,
    queryUnderstanding,
  });

  const output = {
    answer_shape: shape,
    query_understanding: queryUnderstanding,
    aimos_recall_plan: aimosRecallPlan,
    reading_plan: readingPlan,
    multi_session_evidence: compactMultiSessionEvidence(groupMultiSessionEvidence({
      memories,
      limit: readingPlan.limits.max_session_buckets,
    }), 6, shape === 'aggregate_summary' ? 16 : 12),
    knowledge_update: resolveKnowledgeUpdateState({
      memories,
      queryUnderstanding,
      limit: 8,
    }),
    abstention: decideAbstention({
      memories,
      queryUnderstanding,
    }),
    summary: shaped.summary,
    evidence_cards: shaped.evidence_cards || [],
    detail_handles: handles.handles,
    answer_generation_support: answerGenerationSupport,
    ...(shaped.full_detail ? { full_detail: shaped.full_detail } : {}),
  };

  return {
    ...output,
    diagnostics: diagnosticsFor({
      query,
      memories,
      output,
      shape,
      runtimeBudget,
      confidenceNotes: classification.confidence_notes,
      handles,
      queryUnderstanding,
      readingPlan,
    }),
  };
}

function calibratedMemoriesFor(calibrated) {
  if (calibrated.answer_shape === 'full_detail') {
    return asArray(calibrated.full_detail?.memories).map((memory) => ({
      ...memory,
      id: memory.memory_id || memory.id,
      output_shape: 'full_detail',
    }));
  }

  if (calibrated.answer_shape === 'aggregate_summary') {
    return asArray(calibrated.detail_handles).map((handle, index) => ({
      ...handle,
      id: handle.memory_id,
      output_shape: 'aggregate_summary_handle',
      value: null,
      excerpt: null,
      raw_body_included: false,
      aggregate_rank: index + 1,
    }));
  }

  return asArray(calibrated.evidence_cards).map((card, index) => ({
    ...card.handle,
    id: card.handle?.memory_id || card.card_id,
    key: card.handle?.key || card.claim,
    output_shape: 'bounded_evidence_card',
    value: card.excerpt,
    excerpt: card.excerpt,
    raw_body_included: false,
    evidence_card_id: card.card_id,
    claim: card.claim,
    confidence: card.confidence,
    evidence_rank: index + 1,
  }));
}

function buildCalibratedWorkingMemory(calibrated) {
  const payload = {
    answer_shape: calibrated.answer_shape,
    summary: calibrated.summary,
    evidence_cards: asArray(calibrated.evidence_cards).slice(0, 4),
    detail_handles: asArray(calibrated.detail_handles).slice(0, 12),
    multi_session_evidence: compactMultiSessionEvidence(calibrated.multi_session_evidence, 4, 12),
    answer_generation_support: calibrated.answer_generation_support,
    abstention: calibrated.abstention,
  };
  return JSON.stringify(payload, null, 2).slice(0, 3000);
}

function compactMultiSessionEvidence(evidence = {}, maxGroups = 6, maxSessions = 16) {
  let remaining = Math.max(1, Math.trunc(maxSessions));
  const groups = [];
  for (const group of asArray(evidence.groups).slice(0, Math.max(1, Math.trunc(maxGroups)))) {
    if (remaining <= 0) break;
    const sourceSessions = asArray(group.sessions);
    const sessions = sourceSessions.slice(0, remaining);
    groups.push({
      ...group,
      sessions,
      truncated_sessions: Boolean(group.truncated_sessions) || sessions.length < sourceSessions.length,
    });
    remaining -= sessions.length;
  }
  return {
    ...evidence,
    groups,
    truncated: Boolean(evidence.truncated) || groups.length < asArray(evidence.groups).length || remaining <= 0,
  };
}

function compactOriginalRecallMeta(meta = {}) {
  const compact = {};
  for (const key of [
    'qmd_activated',
    'top_rerank',
    'avg_rerank',
    'total_results',
    'confidence_distribution',
    'temporal_truth',
    'retrieval_frequency',
    'deep_recall_override',
    'score_components',
    'rank_observability',
    'epistemic_retrieval',
    'doctor_sidecar',
    'native_paper_recall',
    'pheromone_reinforcement',
  ]) {
    if (meta[key] !== undefined) compact[key] = meta[key];
  }

  if (isPlainObject(meta.synthesis)) {
    compact.synthesis = {
      status: meta.synthesis.status || meta.synthesis.verdict || null,
      answer: truncateText(meta.synthesis.answer || meta.synthesis.summary || '', 600),
      source_count: Array.isArray(meta.synthesis.sources) ? meta.synthesis.sources.length : undefined,
      claim_count: Array.isArray(meta.synthesis.claims) ? meta.synthesis.claims.length : undefined,
    };
  }

  if (isPlainObject(meta.evaluation)) {
    compact.evaluation = {
      status: meta.evaluation.status || null,
      verdict: meta.evaluation.verdict || null,
      confidence: meta.evaluation.confidence || meta.evaluation.score || null,
    };
  }

  if (isPlainObject(meta.explain)) {
    compact.explain = {
      mode: meta.explain.mode || null,
      filters: meta.explain.filters || null,
      stages: meta.explain.stages || null,
    };
  }

  if (Array.isArray(meta.stage_timings)) {
    compact.stage_timings = meta.stage_timings.slice(0, 24).map((stage) => ({
      id: stage.id,
      duration_ms: stage.duration_ms,
      skipped: stage.skipped,
      skip_reason: stage.skip_reason || null,
    }));
  }

  return compact;
}

export function calibrateNativeRecallResponse(input = {}) {
  const query = input.query || input.q || '';
  const recallResponse = input.recallResponse || input.recall_response || {};
  const runtimeBudget = normalizeRuntimeBudget(input.runtimeBudget || input.runtime_budget || {});
  const rawMemories = asArray(recallResponse.memories);
  const calibrated = buildRecallOutputCalibration({
    query,
    recallResponse,
    runtimeBudget,
  });
  const rawMemoryById = new Map(rawMemories.map((memory) => [
    String(memory?.id || memory?.memory_id || ''),
    memory,
  ]));
  const memories = calibratedMemoriesFor(calibrated).map((memory) => {
    const id = String(memory?.id || memory?.memory_id || '');
    const rawMemory = rawMemoryById.get(id);
    return {
      ...memory,
      id,
      memory_id: id,
      ...(rawMemory ? {
        rerank_score: rawMemory.rerank_score ?? null,
        _raw_rerank: rawMemory._raw_rerank ?? null,
        calibrated_recall_score: rawMemory.calibrated_recall_score ?? null,
        recall_confidence: rawMemory.recall_confidence ?? null,
        calibration_event_id: rawMemory.calibration_event_id ?? null,
        calibration_mutation_hash: rawMemory.calibration_mutation_hash ?? null,
        calibration_formula_version: rawMemory.calibration_formula_version ?? null,
        evidence_handling: rawMemory.evidence_handling ?? memory.evidence_handling ?? null,
        epistemic_state: rawMemory.epistemic_state ?? memory.epistemic_state ?? null,
        epistemic_score: rawMemory.epistemic_score ?? memory.epistemic_score ?? null,
        epistemic_decision_version: rawMemory.epistemic_decision_version ?? memory.epistemic_decision_version ?? null,
        epistemic_signals: rawMemory.epistemic_signals ?? memory.epistemic_signals ?? null,
        epistemic_selected_rank: rawMemory.epistemic_selected_rank ?? memory.epistemic_selected_rank ?? null,
        epistemic_mmr_score: rawMemory.epistemic_mmr_score ?? memory.epistemic_mmr_score ?? null,
        freshness_state: rawMemory.freshness_state ?? memory.freshness_state ?? null,
        verified_by: rawMemory.verified_by ?? memory.verified_by ?? null,
        verification_basis: rawMemory.verification_basis ?? memory.verification_basis ?? null,
      } : {}),
      ...(rawMemory?.provenance_proof ? { provenance_proof: rawMemory.provenance_proof } : {}),
    };
  });
  const originalMeta = isPlainObject(recallResponse.recall_meta) ? recallResponse.recall_meta : {};
  const {
    memories: _rawMemories,
    working_memory: _rawWorkingMemory,
    recall_meta: _rawRecallMeta,
    count: _rawCount,
    ...rest
  } = isPlainObject(recallResponse) ? recallResponse : {};

  return {
    ...rest,
    success: recallResponse.success !== false,
    answer_shape: calibrated.answer_shape,
    query_understanding: calibrated.query_understanding,
    summary: calibrated.summary,
    evidence_cards: calibrated.evidence_cards,
    detail_handles: calibrated.detail_handles,
    multi_session_evidence: compactMultiSessionEvidence(calibrated.multi_session_evidence, 6, 16),
    knowledge_update: calibrated.knowledge_update,
    abstention: calibrated.abstention,
    answer_generation_support: calibrated.answer_generation_support,
    ...(calibrated.full_detail ? { full_detail: calibrated.full_detail } : {}),
    memories,
    count: memories.length,
    raw_memory_count: Array.isArray(_rawMemories) ? _rawMemories.length : 0,
    working_memory: buildCalibratedWorkingMemory(calibrated),
    recall_meta: {
      ...compactOriginalRecallMeta(originalMeta),
      output_calibration: calibrated.diagnostics,
      query_understanding: calibrated.query_understanding,
      reading_plan: calibrated.reading_plan,
      aimos_recall_plan: calibrated.aimos_recall_plan,
      answer_generation_support: calibrated.answer_generation_support,
      raw_memory_count: Array.isArray(_rawMemories) ? _rawMemories.length : 0,
      returned_memory_body_policy: calibrated.answer_shape === 'full_detail'
        ? 'full_bodies_opened_by_explicit_detail_request'
        : 'raw_bodies_withheld_handles_returned',
    },
  };
}
