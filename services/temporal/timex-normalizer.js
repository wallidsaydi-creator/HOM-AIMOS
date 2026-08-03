/**
 * timex-normalizer.js — Native temporal expression normalization
 *
 * Status: Live in /aimos/recall via native_paper_recall_operators; exported by
 * temporal/index.js.
 * Runtime note: this file does not mutate memory, prune evidence, apply decay,
 * delete records, or call providers. In recall it contributes temporal parsing
 * signals to bounded native scoring only.
 *
 * Paper authority:
 * - 2010_SEMEVAL_StroetgenGertz_HeidelTime.pdf
 * - SUTIME.pdf
 * - TempEval-3.pdf
 * - An Annotation Framework for Dense Event Ordering.pdf
 * - Time-Aware / Temporal KB / SituatedQA family rows from the 58-paper corpus
 *
 * Core formulas implemented:
 * - te_i = <h_i, t_i, v_i>
 * - t_i in {Date, Time, Duration, Set}
 * - rule = <expression_rule, normalization_function, type_information>
 * - normMonth("June") = "06"
 * - date r1 = (reMonth)g1 (reDay)g2, (reFullYear)g3
 * - norm r1(g1,g2,g3) = g3-normMonth(g1)-normDay(g2)
 * - date r2 = (reHoliday)g1 (reFullYear)g2
 * - norm r2(g1,g2) = g2-normHoliday(g1)
 * - DCT anchoring for now/today/relative ranges
 */

export const TIMEX_TYPES = Object.freeze({
  DATE: 'Date',
  TIME: 'Time',
  DURATION: 'Duration',
  SET: 'Set',
});

export const ALADDIN_TIMEX_GUARDRAILS = Object.freeze({
  mutates_canonical_memory: false,
  prunes_canonical_memory: false,
  applies_decay: false,
  deletes_memory: false,
  changes_recall_ranking: false,
  note: 'Normalization may omit invalid annotations from returned CAS output, but it never removes or mutates canonical memory.',
});

export const HEIDELTIME_PIPELINE_STAGES = Object.freeze([
  'sentence_splitter',
  'tokenizer',
  'pos_tagger',
  'heideltime',
]);

export const HEIDELTIME_CAS_CONSUMERS = Object.freeze({
  rule_design: ['tempeval2_evaluator', 'tp_fp_fn_rule_feedback'],
  usage: ['timex3_cas_writer'],
});

export const HEIDELTIME_RULE_COUNTS = Object.freeze({
  precision: 43,
  recall: 45,
});

export const SUTIME_OBJECT_TYPES = Object.freeze({
  TIME: 'Time',
  DURATION: 'Duration',
  INTERVAL: 'Interval',
  SET: 'Set',
});

export const SUTIME_RULE_STAGES = Object.freeze([
  'text_regex_rules',
  'token_regex_rules',
  'temporal_composition_rules',
]);

export const SUTIME_TE_UNITS = Object.freeze({
  day: 'D',
  week: 'W',
  month: 'M',
  year: 'Y',
  hour: 'H',
  minute: 'M',
  second: 'S',
});

const DAY_MS = 24 * 60 * 60 * 1000;

const MONTHS = Object.freeze({
  january: '01',
  jan: '01',
  february: '02',
  feb: '02',
  march: '03',
  mar: '03',
  april: '04',
  apr: '04',
  may: '05',
  june: '06',
  jun: '06',
  july: '07',
  jul: '07',
  august: '08',
  aug: '08',
  september: '09',
  sept: '09',
  sep: '09',
  october: '10',
  oct: '10',
  november: '11',
  nov: '11',
  december: '12',
  dec: '12',
});

const SEASONS = Object.freeze({
  spring: 'SP',
  summer: 'SU',
  fall: 'FA',
  autumn: 'FA',
  winter: 'WI',
});

const HOLIDAYS = Object.freeze({
  'new year': '01-01',
  'new years': '01-01',
  "new year's day": '01-01',
  'independence day': '07-04',
  'halloween': '10-31',
  'christmas': '12-25',
  'christmas day': '12-25',
  'new year eve': '12-31',
  "new year's eve": '12-31',
});

const WEEKDAYS = Object.freeze({
  sunday: 0,
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
});

const NUMBER_WORDS = Object.freeze({
  zero: 0,
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
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
  fifteen: 15,
  sixteen: 16,
  seventeen: 17,
  eighteen: 18,
  nineteen: 19,
  twenty: 20,
  couple: 2,
  few: 3,
});

const RE_MONTH = '(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?|tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)';
const RE_SEASON = '(?:spring|summer|fall|autumn|winter)';
const RE_DAY = '(?:0?[1-9]|[12][0-9]|3[01])(?:st|nd|rd|th)?';
const RE_FULL_YEAR = '(?:19|20)\\d{2}';
const RE_HOLIDAY = Object.keys(HOLIDAYS).sort((a, b) => b.length - a.length).map(escapeRegex).join('|');

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function clean(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}' ]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function pad2(value) {
  const n = Number.parseInt(String(value || '').replace(/\D/g, ''), 10);
  return Number.isInteger(n) ? String(n).padStart(2, '0') : '';
}

function parseDct(value) {
  const parsed = new Date(value || '');
  if (!Number.isNaN(parsed.getTime())) {
    return new Date(Date.UTC(parsed.getUTCFullYear(), parsed.getUTCMonth(), parsed.getUTCDate()));
  }
  return new Date(Date.UTC(2026, 5, 21));
}

export function formatIsoDate(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  return [
    date.getUTCFullYear(),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
  ].join('-');
}

export function normMonth(monthToken) {
  return MONTHS[clean(monthToken)] || '';
}

export function normSeason(seasonToken) {
  return SEASONS[clean(seasonToken)] || '';
}

export function normDay(dayToken) {
  const day = Number.parseInt(String(dayToken || '').replace(/\D/g, ''), 10);
  return Number.isInteger(day) && day >= 1 && day <= 31 ? String(day).padStart(2, '0') : '';
}

export function normHoliday(holidayToken) {
  return HOLIDAYS[clean(holidayToken)] || '';
}

export function normR1(g1, g2, g3) {
  const year = String(g3 || '').match(/\d{4}/)?.[0] || '';
  const month = normMonth(g1);
  const day = normDay(g2);
  return year && month && day ? `${year}-${month}-${day}` : '';
}

export function normR2(g1, g2) {
  const year = String(g2 || '').match(/\d{4}/)?.[0] || '';
  const holiday = normHoliday(g1);
  return year && holiday ? `${year}-${holiday}` : '';
}

export function makeTimexTuple({ surface, type, value, span = [0, 0], ruleId = '', confidence = 1, metadata = {} } = {}) {
  if (!Object.values(TIMEX_TYPES).includes(type)) {
    throw new Error(`invalid_timex_type:${type}`);
  }
  return {
    surface: String(surface || ''),
    type,
    value: String(value || ''),
    span,
    ruleId,
    confidence: Math.max(0, Math.min(1, Number(confidence) || 0)),
    metadata,
  };
}

export function makeTemporalRule({ id, pattern, type, normalize, priority = 0 } = {}) {
  if (!id) throw new Error('temporal_rule_requires_id');
  if (!(pattern instanceof RegExp)) throw new Error(`temporal_rule_requires_regexp:${id}`);
  if (!Object.values(TIMEX_TYPES).includes(type)) throw new Error(`temporal_rule_invalid_type:${id}`);
  if (typeof normalize !== 'function') throw new Error(`temporal_rule_requires_normalizer:${id}`);
  return Object.freeze({ id, pattern, type, normalize, priority });
}

function addDays(date, amount) {
  return new Date(date.getTime() + amount * DAY_MS);
}

function monthStart(year, monthIndex) {
  return new Date(Date.UTC(year, monthIndex, 1));
}

function monthEnd(year, monthIndex) {
  return new Date(Date.UTC(year, monthIndex + 1, 0));
}

function daysInMonth(year, monthIndex) {
  return monthEnd(year, monthIndex).getUTCDate();
}

function startOfWeek(date, weekStartsOn = 1) {
  const diff = (date.getUTCDay() - weekStartsOn + 7) % 7;
  return addDays(date, -diff);
}

function endOfWeek(date, weekStartsOn = 1) {
  return addDays(startOfWeek(date, weekStartsOn), 6);
}

function normalizeRelativeDay(surface, dct) {
  const value = clean(surface);
  if (value === 'yesterday') return formatIsoDate(addDays(dct, -1));
  if (value === 'tomorrow') return formatIsoDate(addDays(dct, 1));
  return formatIsoDate(dct);
}

function normalizeRelativeWeek(surface, dct) {
  const value = clean(surface);
  const base = value.startsWith('last') || value.startsWith('previous') ? addDays(dct, -7)
    : value.startsWith('next') ? addDays(dct, 7)
      : dct;
  const start = startOfWeek(base);
  const end = endOfWeek(base);
  if (value.includes('weekend')) {
    return `${formatIsoDate(addDays(start, 5))}/${formatIsoDate(addDays(start, 6))}`;
  }
  return `${formatIsoDate(start)}/${formatIsoDate(end)}`;
}

function normalizeRelativeMonth(surface, dct) {
  const value = clean(surface);
  const offset = value.startsWith('last') || value.startsWith('previous') ? -1
    : value.startsWith('next') ? 1
      : 0;
  const start = monthStart(dct.getUTCFullYear(), dct.getUTCMonth() + offset);
  const end = monthEnd(start.getUTCFullYear(), start.getUTCMonth());
  return `${formatIsoDate(start)}/${formatIsoDate(end)}`;
}

function normalizeRelativeYear(surface, dct) {
  const value = clean(surface);
  const offset = value.startsWith('last') || value.startsWith('previous') ? -1
    : value.startsWith('next') ? 1
      : 0;
  return String(dct.getUTCFullYear() + offset);
}

function normalizeWeekday(surface, dct) {
  const match = clean(surface).match(/\b(last|previous|next|this)?\s*(sunday|monday|tuesday|wednesday|thursday|friday|saturday)\b/);
  if (!match) return '';
  const modifier = match[1] || 'this';
  const target = WEEKDAYS[match[2]];
  let diff = target - dct.getUTCDay();
  if ((modifier === 'last' || modifier === 'previous') && diff >= 0) diff -= 7;
  if (modifier === 'next' && diff <= 0) diff += 7;
  return formatIsoDate(addDays(dct, diff));
}

function normalizeDuration(countToken, unitToken) {
  const normalizedCount = clean(countToken);
  const count = Object.hasOwn(NUMBER_WORDS, normalizedCount)
    ? NUMBER_WORDS[normalizedCount]
    : Number.parseInt(String(countToken || '').replace(/\D/g, ''), 10);
  if (!Number.isInteger(count)) return '';
  const unit = clean(unitToken).replace(/s$/, '');
  const code = { day: 'D', week: 'W', month: 'M', year: 'Y', hour: 'H', minute: 'M' }[unit];
  if (!code) return '';
  return unit === 'hour' || unit === 'minute' ? `PT${count}${code}` : `P${count}${code}`;
}

function normalizeClock(match) {
  let hour = Number.parseInt(match[1], 10);
  const minute = match[2] || '00';
  const suffix = clean(match[3]);
  if (suffix === 'pm' && hour < 12) hour += 12;
  if (suffix === 'am' && hour === 12) hour = 0;
  return `T${String(hour).padStart(2, '0')}:${minute}`;
}

function isoWeek(date) {
  const target = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNumber = (target.getUTCDay() + 6) % 7;
  target.setUTCDate(target.getUTCDate() - dayNumber + 3);
  const firstThursday = new Date(Date.UTC(target.getUTCFullYear(), 0, 4));
  const firstDayNumber = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - firstDayNumber + 3);
  const week = 1 + Math.round((target.getTime() - firstThursday.getTime()) / (7 * DAY_MS));
  return `${target.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

export function buildHeidelTimeWorkflow({ mode = 'usage' } = {}) {
  const workflowMode = mode === 'rule_design' ? 'rule_design' : 'usage';
  return {
    aladdin: ALADDIN_TIMEX_GUARDRAILS,
    mode: workflowMode,
    shared_pipeline: [...HEIDELTIME_PIPELINE_STAGES],
    cas_consumers: [...HEIDELTIME_CAS_CONSUMERS[workflowMode]],
    state_model: 'cas_timex3_objects_with_type_value_span',
  };
}

export function buildHeidelTimeWorkflows() {
  return {
    rule_design: buildHeidelTimeWorkflow({ mode: 'rule_design' }),
    usage: buildHeidelTimeWorkflow({ mode: 'usage' }),
  };
}

export function detectSentenceTense(input = {}) {
  const source = typeof input === 'string' ? { sentence: input } : input;
  const sentence = clean(source.sentence || (source.tokens || []).map(token => token.text || token.token || token).join(' '));
  const tags = (source.tokens || []).map(token => String(token.pos || token.tag || '').toUpperCase());
  const evidence = [];
  if (/\b(will|shall|going to|about to)\b/.test(sentence) || tags.includes('MD_FUTURE')) {
    evidence.push('future_modal');
    return { tense: 'future', evidence };
  }
  if (tags.some(tag => tag === 'VBD' || tag === 'VBN') || /\b(was|were|had|did|went|flew|bought|worked|visited|met|saw|made|finished|started)\b/.test(sentence) || /\b\w+ed\b/.test(sentence)) {
    evidence.push('past_verb');
    return { tense: 'past', evidence };
  }
  if (tags.some(tag => tag === 'VBP' || tag === 'VBZ') || /\b(am|is|are|do|does|has|have|currently|now)\b/.test(sentence)) {
    evidence.push('present_marker');
    return { tense: 'present', evidence };
  }
  return { tense: 'present', evidence: ['default_present'] };
}

export function shiftTemporalValueByYears(value, amount = -1) {
  const text = String(value || '').trim();
  const delta = Number.isFinite(Number(amount)) ? Number(amount) : 0;
  const ymd = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (ymd) {
    const year = Number(ymd[1]) + delta;
    const month = Number(ymd[2]);
    const day = Math.min(Number(ymd[3]), daysInMonth(year, month - 1));
    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
  }
  const ym = text.match(/^(\d{4})-(\d{2})$/);
  if (ym) return `${Number(ym[1]) + delta}-${ym[2]}`;
  const yq = text.match(/^(\d{4})-Q([1-4])$/i);
  if (yq) return `${Number(yq[1]) + delta}-Q${yq[2]}`;
  const year = text.match(/^(\d{4})$/);
  if (year) return String(Number(year[1]) + delta);
  return '';
}

export function resolveMonthByTense(monthToken, { documentTime = new Date(), sentence = '', tokens = [], forcedTense = '' } = {}) {
  const month = normMonth(monthToken);
  if (!month) return { value: '', tense: 'unknown', source: 'invalid_month' };
  const dct = parseDct(documentTime);
  const tense = forcedTense || detectSentenceTense({ sentence, tokens }).tense;
  const monthIndex = Number(month) - 1;
  let year = dct.getUTCFullYear();
  const candidateStart = monthStart(year, monthIndex);
  if (tense === 'future' && candidateStart.getTime() <= dct.getTime()) year += 1;
  if (tense === 'past' && candidateStart.getTime() > dct.getTime()) year -= 1;
  return {
    value: `${year}-${month}`,
    tense,
    source: 'tense_driven_month_resolution',
  };
}

export function resolveUnderspecifiedValue(value, {
  previousDate = '',
  documentTime = new Date(),
  sentence = '',
  tokens = [],
} = {}) {
  const raw = String(value || '').trim();
  const lowered = clean(raw);
  const dct = formatIsoDate(parseDct(documentTime));
  if (!raw) return { value: '', source: 'empty' };
  if (/^undef-ref-last-year$/i.test(raw)) {
    const anchor = previousDate || dct;
    return {
      value: shiftTemporalValueByYears(anchor, -1),
      source: previousDate ? 'previous_date_minus_one_year' : 'dct_minus_one_year',
      reference: anchor,
    };
  }
  if (/^undef-ref/i.test(raw)) {
    return {
      value: previousDate || dct,
      source: previousDate ? 'previous_date' : 'dct_fallback',
      reference: previousDate || dct,
    };
  }
  const explicitMonth = lowered.match(/\b(last|next)?\s*(january|jan|february|feb|march|mar|april|apr|may|june|jun|july|jul|august|aug|september|sept|sep|october|oct|november|nov|december|dec)\b/);
  if (explicitMonth) {
    const forcedTense = explicitMonth[1] === 'next' ? 'future' : explicitMonth[1] === 'last' ? 'past' : '';
    return resolveMonthByTense(explicitMonth[2], { documentTime, sentence, tokens, forcedTense });
  }
  if (/^undef/i.test(raw)) {
    return { value: dct, source: 'dct_fallback', reference: dct };
  }
  return { value: raw, source: 'already_specified' };
}

export const TEMPORAL_RULES = Object.freeze([
  makeTemporalRule({
    id: 'date-r1-month-day-year',
    type: TIMEX_TYPES.DATE,
    pattern: new RegExp(`\\b(${RE_MONTH})\\s+(${RE_DAY}),?\\s+(${RE_FULL_YEAR})\\b`, 'giu'),
    normalize: match => normR1(match[1], match[2], match[3]),
    priority: 100,
  }),
  makeTemporalRule({
    id: 'date-r2-holiday-year',
    type: TIMEX_TYPES.DATE,
    pattern: new RegExp(`\\b(${RE_HOLIDAY})\\s+(${RE_FULL_YEAR})\\b`, 'giu'),
    normalize: match => normR2(match[1], match[2]),
    priority: 98,
  }),
  makeTemporalRule({
    id: 'date-iso',
    type: TIMEX_TYPES.DATE,
    pattern: /\b((?:19|20)\d{2})[-/](\d{1,2})[-/](\d{1,2})\b/giu,
    normalize: match => `${match[1]}-${pad2(match[2])}-${pad2(match[3])}`,
    priority: 96,
  }),
  makeTemporalRule({
    id: 'date-month-year',
    type: TIMEX_TYPES.DATE,
    pattern: new RegExp(`\\b(${RE_MONTH})\\s+(${RE_FULL_YEAR})\\b`, 'giu'),
    normalize: match => `${match[2]}-${normMonth(match[1])}`,
    priority: 92,
  }),
  makeTemporalRule({
    id: 'date-season-year',
    type: TIMEX_TYPES.DATE,
    pattern: new RegExp(`\\b(${RE_SEASON})\\s+(${RE_FULL_YEAR})\\b`, 'giu'),
    normalize: match => `${match[2]}-${normSeason(match[1])}`,
    priority: 90,
  }),
  makeTemporalRule({
    id: 'date-relative-day',
    type: TIMEX_TYPES.DATE,
    pattern: /\b(today|tonight|now|yesterday|tomorrow)\b/giu,
    normalize: (match, context) => normalizeRelativeDay(match[1], context.documentTime),
    priority: 86,
  }),
  makeTemporalRule({
    id: 'date-relative-week',
    type: TIMEX_TYPES.DATE,
    pattern: /\b((?:last|previous|this|next)\s+(?:week|weekend))\b/giu,
    normalize: (match, context) => normalizeRelativeWeek(match[1], context.documentTime),
    priority: 84,
  }),
  makeTemporalRule({
    id: 'date-relative-month',
    type: TIMEX_TYPES.DATE,
    pattern: /\b((?:last|previous|this|next)\s+month)\b/giu,
    normalize: (match, context) => normalizeRelativeMonth(match[1], context.documentTime),
    priority: 82,
  }),
  makeTemporalRule({
    id: 'date-relative-year',
    type: TIMEX_TYPES.DATE,
    pattern: /\b((?:last|previous|this|next)\s+year)\b/giu,
    normalize: (match, context) => normalizeRelativeYear(match[1], context.documentTime),
    priority: 80,
  }),
  makeTemporalRule({
    id: 'date-weekday',
    type: TIMEX_TYPES.DATE,
    pattern: /\b((?:last|previous|this|next)?\s*(?:sunday|monday|tuesday|wednesday|thursday|friday|saturday))\b/giu,
    normalize: (match, context) => normalizeWeekday(match[1], context.documentTime),
    priority: 78,
  }),
  makeTemporalRule({
    id: 'duration-count-unit',
    type: TIMEX_TYPES.DURATION,
    pattern: /\b(\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|couple|few)\s+(days?|weeks?|months?|years?|hours?|minutes?)\b/giu,
    normalize: match => normalizeDuration(match[1], match[2]),
    priority: 70,
  }),
  makeTemporalRule({
    id: 'set-recurring-weekday',
    type: TIMEX_TYPES.SET,
    pattern: /\b(every|each)\s+(sunday|monday|tuesday|wednesday|thursday|friday|saturday)\b/giu,
    normalize: match => `XXXX-WXX-${WEEKDAYS[clean(match[2])]}`,
    priority: 62,
  }),
  makeTemporalRule({
    id: 'time-clock',
    type: TIMEX_TYPES.TIME,
    pattern: /\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/giu,
    normalize: normalizeClock,
    priority: 60,
  }),
]);

export const RECALL_EXTRA_TEMPORAL_RULES = Object.freeze([
  makeTemporalRule({
    id: 'date-recall-month-day-dct-year',
    type: TIMEX_TYPES.DATE,
    pattern: new RegExp(`\\b(${RE_MONTH})\\s+(${RE_DAY})\\b`, 'giu'),
    normalize: (match, context) => {
      const month = resolveMonthByTense(match[1], { documentTime: context.documentTime }).value;
      return month ? `${month}-${normDay(match[2])}` : '';
    },
    priority: 52,
  }),
  makeTemporalRule({
    id: 'duration-recall-indefinite-unit',
    type: TIMEX_TYPES.DURATION,
    pattern: /\b(a|an)\s+(day|week|month|year|hour|minute)\b/giu,
    normalize: match => normalizeDuration('1', match[2]),
    priority: 50,
  }),
]);

export function buildTimexRuleSet({ mode = 'precision' } = {}) {
  const ruleMode = mode === 'recall' ? 'recall' : 'precision';
  const rules = ruleMode === 'recall'
    ? [...TEMPORAL_RULES, ...RECALL_EXTRA_TEMPORAL_RULES]
    : [...TEMPORAL_RULES];
  return {
    mode: ruleMode,
    declaredRuleCount: HEIDELTIME_RULE_COUNTS[ruleMode],
    rules,
    ruleIds: rules.map(rule => rule.id),
    extraRules: ruleMode === 'recall' ? RECALL_EXTRA_TEMPORAL_RULES.map(rule => rule.id) : [],
  };
}

export function createSutimeTemporalObject({
  type = SUTIME_OBJECT_TYPES.TIME,
  value = '',
  begin = '',
  end = '',
  periodicity = '',
  attributes = {},
} = {}) {
  if (!Object.values(SUTIME_OBJECT_TYPES).includes(type)) throw new Error(`invalid_sutime_object_type:${type}`);
  return {
    type,
    value: String(value || ''),
    begin: String(begin || ''),
    end: String(end || ''),
    periodicity: String(periodicity || ''),
    attributes,
  };
}

export function dateToWholeDayInterval(value) {
  const date = String(value || '').match(/\b\d{4}-\d{2}-\d{2}\b/)?.[0] || '';
  if (!date) return createSutimeTemporalObject({ type: SUTIME_OBJECT_TYPES.INTERVAL });
  return createSutimeTemporalObject({
    type: SUTIME_OBJECT_TYPES.INTERVAL,
    value: date,
    begin: `${date}T00:00:00`,
    end: `${date}T24:00:00`,
  });
}

export function parseExtendedIsoDateTime(text) {
  const match = String(text || '').match(/\b(\d{4})-?(\d{2})-?(\d{2})-?T(\d{2})(?::?(\d{2})(?::?(\d{2})(?:[.,](\d{1,3}))?)?)?\b/);
  if (!match) return null;
  const [, year, month, day, hour, minute = '00', second = '00', millis = ''] = match;
  return {
    value: `${year}-${month}-${day}T${hour}:${minute}:${second}${millis ? `.${millis.padEnd(3, '0')}` : ''}`,
    groups: { year, month, day, hour, minute, second, millis },
  };
}

export function temporalCompose(operation, left, right) {
  const op = String(operation || '').toUpperCase();
  const a = left?.value || left;
  const b = right?.value || right;
  if (op !== 'INTERSECT') return createSutimeTemporalObject({ type: SUTIME_OBJECT_TYPES.INTERVAL, attributes: { operation: op } });
  const date = String(a || '').match(/\b\d{4}-\d{2}-\d{2}\b/)?.[0] || String(b || '').match(/\b\d{4}-\d{2}-\d{2}\b/)?.[0] || '';
  const time = String(a || '').match(/\bT\d{2}:\d{2}(?::\d{2})?\b/)?.[0] || String(b || '').match(/\bT\d{2}:\d{2}(?::\d{2})?\b/)?.[0] || '';
  if (!date || !time) return createSutimeTemporalObject({ type: SUTIME_OBJECT_TYPES.INTERVAL, attributes: { operation: op, unresolved: true } });
  return createSutimeTemporalObject({
    type: SUTIME_OBJECT_TYPES.TIME,
    value: `${date}${time}`,
    attributes: { operation: op },
  });
}

export function isAmbiguousTemporalWordToken(token = {}) {
  const word = clean(token.word || token.text || token.token || '');
  const pos = String(token.pos || token.tag || '').toUpperCase();
  return /^(fall|spring|second|march|may)$/.test(word) && !/^NN/.test(pos);
}

export function passesSutimeTemporalPosGate(token = {}) {
  return !isAmbiguousTemporalWordToken(token);
}

export function selectSutimeRuleMatch(matches = []) {
  return [...matches].sort((a, b) =>
    (Number(b.priority) || 0) - (Number(a.priority) || 0)
    || (Number(b.length) || 0) - (Number(a.length) || 0)
    || (Number(a.order) || 0) - (Number(b.order) || 0)
  )[0] || null;
}

export function makeSutimeDuration({ from = '', to = '', unit = '', count = '' } = {}) {
  const unitCode = SUTIME_TE_UNITS[clean(unit).replace(/s$/, '')] || '';
  if (!unitCode) return createSutimeTemporalObject({ type: SUTIME_OBJECT_TYPES.DURATION });
  if (from !== '' && to !== '') {
    return createSutimeTemporalObject({
      type: SUTIME_OBJECT_TYPES.DURATION,
      value: `P${from}-${to}${unitCode}`,
      attributes: { from: Number(from), to: Number(to), unit: clean(unit).replace(/s$/, '') },
    });
  }
  const n = count || from || 1;
  return createSutimeTemporalObject({
    type: SUTIME_OBJECT_TYPES.DURATION,
    value: unitCode === 'H' || unitCode === 'M' || unitCode === 'S' ? `PT${n}${unitCode}` : `P${n}${unitCode}`,
    attributes: { count: Number(n), unit: clean(unit).replace(/s$/, '') },
  });
}

export function parseSutimeDurationText(text) {
  const unitPattern = Object.keys(SUTIME_TE_UNITS).join('|');
  const range = String(text || '').match(new RegExp(`\\b(\\d+)\\s*(?:to|-)\\s*(\\d+)\\s*-?\\s*(${unitPattern})s?\\b`, 'i'));
  if (range) return makeSutimeDuration({ from: range[1], to: range[2], unit: range[3] });
  const compact = String(text || '').match(new RegExp(`\\b(\\d+)[-\\s](${unitPattern})s?(?:[-\\s]old)?\\b`, 'i'));
  if (compact) return makeSutimeDuration({ count: compact[1], unit: compact[2] });
  return createSutimeTemporalObject({ type: SUTIME_OBJECT_TYPES.DURATION });
}

export function intervalAsDurationObject({ begin = '', end = '', value = '' } = {}) {
  return createSutimeTemporalObject({
    type: SUTIME_OBJECT_TYPES.DURATION,
    value: value || `${begin}/${end}`,
    begin,
    end,
    attributes: { represents_interval: true },
  });
}

export function toJodaTimeLikeObject(object = {}) {
  const temporal = createSutimeTemporalObject(object);
  return {
    class: temporal.type === SUTIME_OBJECT_TYPES.DURATION ? 'Period' : temporal.type === SUTIME_OBJECT_TYPES.INTERVAL ? 'Interval' : 'DateTime',
    value: temporal.value,
    begin: temporal.begin,
    end: temporal.end,
    chronology: 'ISOChronology',
  };
}

export function expandSutimeMacros(pattern, macros = {}) {
  return Object.entries(macros).reduce((current, [name, value]) => {
    const token = `$${name}`;
    return current.split(token).join(String(value));
  }, String(pattern || ''));
}

export function sutimeTimex3Tag({
  tid = '',
  type = TIMEX_TYPES.DATE,
  value = '',
  text = '',
  attributes = {},
} = {}) {
  const attrs = Object.entries({ tid, type, value, ...attributes })
    .filter(([, attrValue]) => attrValue !== undefined && attrValue !== null && attrValue !== '')
    .map(([key, attrValue]) => `${key}="${String(attrValue).replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"`)
    .join(' ');
  return `<TIMEX3${attrs ? ` ${attrs}` : ''}>${String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')}</TIMEX3>`;
}

export function temporalExpressionStateTransition({ expression = '', temporalObject = {}, tid = 't1' } = {}) {
  const object = createSutimeTemporalObject(temporalObject);
  const timex3 = sutimeTimex3Tag({
    tid,
    type: object.type === SUTIME_OBJECT_TYPES.TIME ? TIMEX_TYPES.DATE : object.type,
    value: object.value,
    text: expression,
    attributes: object.attributes,
  });
  return {
    expression,
    temporalObject: object,
    timex3,
    state_path: ['expression', 'temporal_object', 'timex3_annotation'],
  };
}

export function inferIsoWeek(value, { documentTime = new Date() } = {}) {
  const parsed = parseDct(value || documentTime);
  return isoWeek(parsed);
}

export function applySutimeStagedRules(text, {
  documentTime = new Date(),
  tokens = [],
  maxIterations = 4,
  rules = buildTimexRuleSet({ mode: 'recall' }),
  keepNested = false,
} = {}) {
  const source = String(text || '');
  const stages = [];
  const textRegex = normalizeTemporalExpressions(source, { documentTime, rules });
  let timexes = [...textRegex.timexes];
  const parsedDuration = parseSutimeDurationText(source);
  if (parsedDuration.value) {
    timexes.push(makeTimexTuple({
      surface: source.match(/\b\d+\s*(?:to|-)\s*\d+\s*-?\s*(?:day|week|month|year|hour|minute|second)s?\b/i)?.[0]
        || source.match(/\b\d+[-\s](?:day|week|month|year|hour|minute|second)s?(?:[-\s]old)?\b/i)?.[0]
        || parsedDuration.value,
      type: TIMEX_TYPES.DURATION,
      value: parsedDuration.value,
      span: [0, 0],
      ruleId: 'sutime-duration-range-or-compact',
      metadata: { priority: 55, sutimeObject: parsedDuration },
    }));
  }
  stages.push({ stage: SUTIME_RULE_STAGES[0], count: timexes.length });

  const tokenObjects = [];
  for (const token of tokens) {
    const word = clean(token.word || token.text || token.token || '');
    if (/^(fall|spring|second|march|may)$/.test(word) && passesSutimeTemporalPosGate(token)) {
      tokenObjects.push(createSutimeTemporalObject({
        type: SUTIME_OBJECT_TYPES.TIME,
        value: resolveMonthByTense(token.word || token.text || token.token, { documentTime }).value || clean(token.word || token.text || token.token),
        attributes: { token_gate: 'pos_noun' },
      }));
    }
  }
  stages.push({ stage: SUTIME_RULE_STAGES[1], count: tokenObjects.length });

  let previousSignature = '';
  let iterations = 0;
  let composedObjects = [];
  while (iterations < maxIterations) {
    iterations += 1;
    const composed = [];
    for (const date of timexes.filter(row => row.type === TIMEX_TYPES.DATE && /^\d{4}-\d{2}-\d{2}$/.test(row.value))) {
      for (const time of timexes.filter(row => row.type === TIMEX_TYPES.TIME)) {
        const between = source.slice(Math.min(date.span[1], time.span[1]), Math.max(date.span[0], time.span[0])).toLowerCase();
        if (/\bat\b|,/.test(between)) composed.push(temporalCompose('INTERSECT', date, time));
      }
    }
    const signature = JSON.stringify({ timexes: timexes.map(row => row.value), composed: composed.map(row => row.value) });
    if (signature === previousSignature) break;
    previousSignature = signature;
    composedObjects = composed;
    stages.push({ stage: SUTIME_RULE_STAGES[2], count: composed.length, iteration: iterations });
  }
  return {
    aladdin: ALADDIN_TIMEX_GUARDRAILS,
    documentTime: formatIsoDate(parseDct(documentTime)),
    timexes,
    tokenObjects,
    composedObjects,
    nestedTimexes: keepNested ? textRegex.timexes : [],
    stages,
    iterations,
  };
}

export function scoreTimexAttributes(systemMentions = [], goldMentions = [], attribute = 'value') {
  const spanKey = row => `${row.span?.[0] ?? ''}:${row.span?.[1] ?? ''}:${String(row.surface || row.text || '').toLowerCase()}`;
  const goldBySpan = new Map(goldMentions.map(row => [spanKey(row), row]));
  let correct = 0;
  for (const row of systemMentions) {
    const gold = goldBySpan.get(spanKey(row));
    if (gold && String(gold[attribute] || '') === String(row[attribute] || '')) correct += 1;
  }
  const precision = systemMentions.length ? correct / systemMentions.length : 0;
  const recall = goldMentions.length ? correct / goldMentions.length : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    correct,
    mentions_response: systemMentions.length,
    mentions_gold: goldMentions.length,
    precision,
    recall,
    f1,
  };
}

export function convertToTempEval2Format(timexes = []) {
  return timexes.map((row, index) => ({
    tid: row.tid || `t${index + 1}`,
    type: row.type,
    value: row.value,
    span: row.span,
    timex3: sutimeTimex3Tag({
      tid: row.tid || `t${index + 1}`,
      type: row.type,
      value: row.value,
      text: row.surface || row.text || '',
    }),
  }));
}

export function buildCoreNlpSutimeAnnotator({ name = 'sutime', mode = 'rule_based' } = {}) {
  return {
    name,
    mode,
    annotates: 'TIMEX3',
    temporal_object_model: Object.values(SUTIME_OBJECT_TYPES),
    stages: [...SUTIME_RULE_STAGES],
    provider_calls: false,
  };
}

export function hybridCrfRuleNormalize(text, { crfRecognizer = null, documentTime = new Date() } = {}) {
  const recognized = typeof crfRecognizer === 'function' ? crfRecognizer(String(text || '')) : [];
  const normalized = recognized.map((mention, index) => {
    const resolved = normalizeTemporalExpressions(mention.text || mention.surface || '', { documentTime });
    return {
      ...mention,
      tid: mention.tid || `crf${index + 1}`,
      normalized: resolved.timexes[0]?.value || '',
      normalizer: 'rule_based',
    };
  });
  return {
    recognizer: 'conditional_random_field',
    normalizer: 'rule_based',
    mentions: normalized,
  };
}

export function gibbsSampleTemporalAssignments({
  variables = [],
  domain = [],
  score = () => 1,
  iterations = 100,
  seed = 1,
} = {}) {
  const labels = domain.length ? domain : ['TEMPORAL', 'NON_TEMPORAL'];
  let state = Object.fromEntries(variables.map((variable, index) => [variable, labels[index % labels.length]]));
  let rng = Number(seed) || 1;
  const random = () => {
    rng = (1103515245 * rng + 12345) % 2147483648;
    return rng / 2147483648;
  };
  for (let step = 0; step < iterations; step += 1) {
    for (const variable of variables) {
      const weights = labels.map(label => Math.max(0, Number(score(variable, label, state)) || 0));
      const rawTotal = weights.reduce((sum, value) => sum + value, 0);
      const total = rawTotal || labels.length;
      let draw = random() * total;
      let selected = labels[0];
      for (let i = 0; i < labels.length; i += 1) {
        draw -= rawTotal ? weights[i] : 1;
        if (draw <= 0) {
          selected = labels[i];
          break;
        }
      }
      state = { ...state, [variable]: selected };
    }
  }
  return { state, iterations, sampler: 'gibbs' };
}

export function timeMlDocument({ events = [], timexes = [], relations = [] } = {}) {
  const eventTags = events.map((event, index) => `<EVENT eid="${event.id || `e${index + 1}`}">${String(event.text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')}</EVENT>`);
  const timexTags = timexes.map((timex, index) => sutimeTimex3Tag({
    tid: timex.tid || `t${index + 1}`,
    type: timex.type || TIMEX_TYPES.DATE,
    value: timex.value,
    text: timex.text || timex.surface || '',
  }));
  const relationTags = relations.map((relation, index) => `<TLINK lid="${relation.id || `l${index + 1}`}" eventInstanceID="${relation.event || relation.left || ''}" relatedToTime="${relation.time || relation.right || ''}" relType="${relation.type || relation.relation || ''}"/>`);
  return `<TimeML>${[...eventTags, ...timexTags, ...relationTags].join('')}</TimeML>`;
}

export function buildFastusCascade({ stages = SUTIME_RULE_STAGES } = {}) {
  return {
    transducer: 'cascaded_finite_state',
    stages: [...stages],
    deterministic: true,
  };
}

export function buildTarsqiTemporalProcessingPlan() {
  return {
    toolkit: 'TARSQI',
    role: 'temporal_processing_toolkit_compatibility',
    produces: ['TimeML', 'TIMEX3'],
    native_equivalent_services: ['timex-normalizer', 'event-ordering-graph'],
  };
}

function overlaps(left, right) {
  return Math.max(left.span[0], right.span[0]) < Math.min(left.span[1], right.span[1]);
}

function nonOverlapping(tuples) {
  const ranked = [...tuples]
    .filter(tuple => tuple.value)
    .sort((a, b) => b.confidence - a.confidence || b.metadata.priority - a.metadata.priority || a.span[0] - b.span[0]);
  const kept = [];
  for (const tuple of ranked) {
    if (kept.some(existing => overlaps(existing, tuple))) continue;
    kept.push(tuple);
  }
  return kept.sort((a, b) => a.span[0] - b.span[0]);
}

export function normalizeTemporalExpressions(text, { documentTime = new Date(), rules = TEMPORAL_RULES } = {}) {
  const source = String(text || '');
  const dct = parseDct(documentTime);
  const context = { documentTime: dct };
  const raw = [];
  const invalid = [];
  const activeRules = Array.isArray(rules) ? rules : rules?.rules || TEMPORAL_RULES;
  for (const rule of activeRules) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (const match of source.matchAll(pattern)) {
      const value = rule.normalize(match, context);
      const tuple = makeTimexTuple({
        surface: match[0],
        type: rule.type,
        value,
        span: [match.index, match.index + match[0].length],
        ruleId: rule.id,
        confidence: value ? 1 : 0,
        metadata: { priority: rule.priority },
      });
      if (value) raw.push(tuple);
      else invalid.push(tuple);
    }
  }
  const timexes = nonOverlapping(raw);
  return {
    aladdin: ALADDIN_TIMEX_GUARDRAILS,
    documentTime: formatIsoDate(dct),
    timexes,
    invalid,
    byType: Object.fromEntries(Object.values(TIMEX_TYPES).map(type => [
      type,
      timexes.filter(tuple => tuple.type === type),
    ])),
  };
}

export function temporalWindowFromTimex(timex) {
  if (!timex || timex.type !== TIMEX_TYPES.DATE || !timex.value) return null;
  const value = String(timex.value);
  if (value.includes('/')) {
    const [from, to] = value.split('/');
    return { from, to, granularity: 'range', source: timex };
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return { from: `${value}T00:00:00.000Z`, to: `${value}T23:59:59.999Z`, granularity: 'day', source: timex };
  }
  if (/^\d{4}-\d{2}$/.test(value)) {
    const [year, month] = value.split('-').map(Number);
    const start = monthStart(year, month - 1);
    const end = monthEnd(year, month - 1);
    return { from: `${formatIsoDate(start)}T00:00:00.000Z`, to: `${formatIsoDate(end)}T23:59:59.999Z`, granularity: 'month', source: timex };
  }
  if (/^\d{4}$/.test(value)) {
    return { from: `${value}-01-01T00:00:00.000Z`, to: `${value}-12-31T23:59:59.999Z`, granularity: 'year', source: timex };
  }
  return null;
}

export function evaluateTemporalExtraction(predicted = [], gold = []) {
  const key = row => `${row.type}|${row.value}|${row.span?.[0] ?? ''}|${row.span?.[1] ?? ''}`;
  const predictedKeys = new Set(predicted.map(key));
  const goldKeys = new Set(gold.map(key));
  let tp = 0;
  let fp = 0;
  let fn = 0;
  for (const item of predictedKeys) {
    if (goldKeys.has(item)) tp += 1;
    else fp += 1;
  }
  for (const item of goldKeys) {
    if (!predictedKeys.has(item)) fn += 1;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    tp,
    fp,
    fn,
    precision,
    recall,
    f1,
    adaptation: {
      add_rules_for_false_negatives: fn,
      tighten_rules_for_false_positives: fp,
    },
  };
}
