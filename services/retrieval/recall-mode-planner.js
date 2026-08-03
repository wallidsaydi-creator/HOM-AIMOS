/**
 * recall-mode-planner.js — TEM-first recall intent routing
 * Sources: TimeR4 (2024), MRAG (2025), Enhancing Temporal Sensitivity and
 *          Reasoning for Time-Sensitive Question Answering (2024),
 *          Improving Time Sensitivity for Question Answering over Temporal
 *          Knowledge Graphs (2022), Set the Clock (2024),
 *          RAGChecker (2024), BRIGHT (2024),
 *          Chronos (Sen et al., arXiv:2603.16862, 2026),
 *          MAGMA (Jiang et al., arXiv:2601.03236, 2026),
 *          Generative Retrieval identifier ambiguity paper (Batch 6/7),
 *          From Guessing to Placeholding (Batch 6/7),
 *          Multi-Faceted Self-Consistent Preference Alignment for Query
 *          Rewriting in Conversational Search (Batch8 Wave 3)
 *
 * Purpose: choose the correct recall mode before semantic retrieval starts.
 * Aimos should not force temporal, continuity, reasoning, and browse-style
 * asks through the same nearest-neighbor path.
 * Batch8 guardrail: rewrite candidates are labeled diagnostics only. Aimos
 * does not silently substitute the user query or train preference objectives.
 */

import { buildRecallEvaluation } from './recall-diagnostics.js';
import { extractIdentifierHints, hasIdentifierRecallCue } from './identifier-recall.js';

export const RECALL_MODES = {
  EXACT_ARTIFACT: 'exact_artifact',
  TEMPORAL: 'temporal',
  SESSION_CONTINUITY: 'session_continuity',
  REASONING_TRACE: 'reasoning_trace',
  LINEAGE_NAVIGATION: 'lineage_navigation',
  CORPUS_ANALYTICS: 'corpus_analytics',
  SEMANTIC_GENERAL: 'semantic_general',
};

const MONTHS = new Map([
  ['january', 0], ['jan', 0],
  ['february', 1], ['feb', 1],
  ['march', 2], ['mar', 2],
  ['april', 3], ['apr', 3],
  ['may', 4],
  ['june', 5], ['jun', 5],
  ['july', 6], ['jul', 6],
  ['august', 7], ['aug', 7],
  ['september', 8], ['sep', 8], ['sept', 8],
  ['october', 9], ['oct', 9],
  ['november', 10], ['nov', 10],
  ['december', 11], ['dec', 11],
]);

const DATE_EXPR_PATTERN = '(?:\\d{4}-\\d{2}-\\d{2}|(?:january|jan|february|feb|march|mar|april|apr|may|june|jun|july|jul|august|aug|september|sep|sept|october|oct|november|nov|december|dec)\\s+\\d{1,2}(?:,?\\s*\\d{4})?)';

const TEMPORAL_PATTERNS = [
  /\b(today|yesterday|tonight|last night|last week|last month|this morning|this afternoon|this evening)\b/i,
  /\b(what happened|what changed|recall|show|tell|timeline|history)\b.*\b(before|after|since|until|through|between|during|around)\b/i,
  /\b(on|from|during|around)\s+(january|jan|february|feb|march|mar|april|apr|may|june|jun|july|jul|august|aug|september|sep|sept|october|oct|november|nov|december|dec)\s+\d{1,2}(?:,\s*\d{4})?\b/i,
  /\b\d{4}-\d{2}-\d{2}\b/,
];

const SESSION_PATTERNS = [
  /\blast safe session\b/i,
  /\blast session\b/i,
  /\bresume (the )?(session|work|context)\b/i,
  /\bwhat were we doing\b/i,
  /\bcontinue (from|where)\b/i,
  /\bprecompact\b/i,
  /\bpost[-\s]?compaction\b/i,
  /\bafter (?:compact|compaction)\b/i,
  /\bcompaction (?:handoff|summary|delivery)\b/i,
  /\bwhat did .*compaction (?:give|gave|deliver|produce)\b/i,
  /\bhandoff\b/i,
];

const REASONING_PATTERNS = [
  /\breasoning\b/i,
  /\bwhy did\b/i,
  /\bhow did you fix\b/i,
  /\bwhat was the reasoning\b/i,
  /\bshow (me )?(the )?(reasoning|trace)\b/i,
  /\bdecision path\b/i,
  /\bderive(?:d|s)?\b/i,
];

const LINEAGE_PATTERNS = [
  /\bconnected to\b/i,
  /\brelated to\b/i,
  /\blineage\b/i,
  /\bwhat led to\b/i,
  /\bwhat followed from\b/i,
  /\bwhat happened around\b/i,
  /\baround this session\b/i,
  /\bshow .* linked\b/i,
  /\bconsequences of\b/i,
];

const ANALYTICS_PATTERNS = [
  /\bwhat topics\b/i,
  /\bwhat does aimos know\b/i,
  /\bdistribution\b/i,
  /\bmost recalled\b/i,
  /\bblind spots\b/i,
  /\bgaps\b/i,
  /\bcorpus\b/i,
  /\banalytics\b/i,
];

function startOfDay(date) {
  const value = new Date(date);
  value.setHours(0, 0, 0, 0);
  return value;
}

function endOfDay(date) {
  const value = new Date(date);
  value.setHours(23, 59, 59, 999);
  return value;
}

function addDays(date, amount) {
  const value = new Date(date);
  value.setDate(value.getDate() + amount);
  return value;
}

function daysInMonth(year, monthIndex) {
  return new Date(Date.UTC(year, monthIndex + 1, 0)).getUTCDate();
}

function buildTemporalResult({ from, to, label, matchedText, operator = 'on', granularity = 'day' }) {
  return {
    from,
    to,
    label,
    matched_text: matchedText,
    operator,
    granularity,
    temporal_constraint: {
      operator,
      range: { from, to },
      label,
      granularity,
    },
  };
}

function parseDatePhrase(phrase, now = new Date()) {
  const text = String(phrase || '').trim();
  const isoMatch = text.match(/\b(\d{4}-\d{2}-\d{2})\b/);
  if (isoMatch) {
    const parsed = new Date(`${isoMatch[1]}T00:00:00Z`);
    if (!Number.isNaN(parsed.getTime())) {
      return {
        from: startOfDay(parsed).toISOString(),
        to: endOfDay(parsed).toISOString(),
        label: isoMatch[1],
        matched_text: isoMatch[1],
      };
    }
  }

  const monthMatch = text.match(/\b([A-Za-z]+)\s+(\d{1,2})(?:,\s*(\d{4}))?\b/i);
  if (!monthMatch) return null;

  const month = MONTHS.get(monthMatch[1].toLowerCase());
  if (month == null) return null;
  const day = Number(monthMatch[2]);
  const year = Number(monthMatch[3] || now.getFullYear());
  const parsed = new Date(Date.UTC(year, month, day, 0, 0, 0, 0));
  if (Number.isNaN(parsed.getTime())) return null;

  return {
    from: startOfDay(parsed).toISOString(),
    to: endOfDay(parsed).toISOString(),
    label: `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`,
    matched_text: monthMatch[0],
  };
}

function parseExplicitDate(query, now = new Date()) {
  const scopedMatch = query.match(new RegExp(`\\b(?:on|from|during|around)\\s+(${DATE_EXPR_PATTERN})\\b`, 'i'));
  const parsed = parseDatePhrase(scopedMatch?.[1] || query, now);
  if (!parsed) return null;
  return buildTemporalResult({
    from: parsed.from,
    to: parsed.to,
    label: parsed.label,
    matchedText: scopedMatch?.[0] || parsed.matched_text,
    operator: 'on',
    granularity: 'day',
  });
}

function parseNamedWeekOfMonth(query, now = new Date()) {
  const monthAlternates = '(january|jan|february|feb|march|mar|april|apr|may|june|jun|july|jul|august|aug|september|sep|sept|october|oct|november|nov|december|dec)';
  const match = String(query || '').match(new RegExp(`\\b(first|second|third|fourth|last|final)\\s+week\\s+(?:of|in)\\s+${monthAlternates}(?:\\s+(\\d{4}))?\\b`, 'i'));
  if (!match) return null;

  const ordinal = match[1].toLowerCase();
  const month = MONTHS.get(match[2].toLowerCase());
  if (month == null) return null;
  const year = Number(match[3] || now.getFullYear());
  const monthDays = daysInMonth(year, month);

  const ordinalStarts = { first: 1, second: 8, third: 15, fourth: 22 };
  const startDay = (ordinal === 'last' || ordinal === 'final')
    ? Math.max(1, monthDays - 7)
    : ordinalStarts[ordinal];
  if (!startDay || startDay > monthDays) return null;

  const endDay = (ordinal === 'last' || ordinal === 'final')
    ? monthDays
    : Math.min(monthDays, startDay + 6);
  const from = new Date(Date.UTC(year, month, startDay, 0, 0, 0, 0));
  const to = new Date(Date.UTC(year, month, endDay, 23, 59, 59, 999));
  const monthLabel = String(match[2]).toLowerCase();

  return buildTemporalResult({
    from: from.toISOString(),
    to: to.toISOString(),
    label: `${ordinal} week of ${monthLabel} ${year}`,
    matchedText: match[0],
    operator: 'during',
    granularity: 'month_week_range',
  });
}

function parseRelativeTemporal(query, now = new Date()) {
  const lower = query.toLowerCase();
  if (lower.includes('today')) {
    return buildTemporalResult({
      from: startOfDay(now).toISOString(),
      to: endOfDay(now).toISOString(),
      label: 'today',
      matchedText: 'today',
      operator: 'on',
    });
  }
  if (lower.includes('yesterday') || lower.includes('last night')) {
    const target = addDays(now, -1);
    return buildTemporalResult({
      from: startOfDay(target).toISOString(),
      to: endOfDay(target).toISOString(),
      label: lower.includes('last night') ? 'last night' : 'yesterday',
      matchedText: lower.includes('last night') ? 'last night' : 'yesterday',
      operator: 'on',
    });
  }
  if (lower.includes('last week')) {
    const to = endOfDay(addDays(now, -1));
    const from = startOfDay(addDays(now, -7));
    return buildTemporalResult({
      from: from.toISOString(),
      to: to.toISOString(),
      label: 'last week',
      matchedText: 'last week',
      operator: 'during',
      granularity: 'range',
    });
  }
  if (lower.includes('last month')) {
    const to = endOfDay(addDays(now, -1));
    const from = startOfDay(addDays(now, -30));
    return buildTemporalResult({
      from: from.toISOString(),
      to: to.toISOString(),
      label: 'last month',
      matchedText: 'last month',
      operator: 'during',
      granularity: 'range',
    });
  }
  return null;
}

function parseTemporalConstraint(query, now = new Date()) {
  const namedWeek = parseNamedWeekOfMonth(query, now);
  if (namedWeek) return namedWeek;

  const betweenRe = new RegExp(`\\bbetween\\s+(${DATE_EXPR_PATTERN})\\s+(?:and|to)\\s+(${DATE_EXPR_PATTERN})\\b`, 'i');
  const betweenMatch = query.match(betweenRe);
  if (betweenMatch) {
    const start = parseDatePhrase(betweenMatch[1], now);
    const end = parseDatePhrase(betweenMatch[2], now);
    if (start && end) {
      return buildTemporalResult({
        from: start.from,
        to: end.to,
        label: `${start.label}..${end.label}`,
        matchedText: betweenMatch[0],
        operator: 'between',
        granularity: 'range',
      });
    }
  }

  const directionalRe = new RegExp(`\\b(before|after|since|until|through)\\s+(${DATE_EXPR_PATTERN})\\b`, 'i');
  const directionalMatch = query.match(directionalRe);
  if (directionalMatch) {
    const operator = directionalMatch[1].toLowerCase();
    const parsed = parseDatePhrase(directionalMatch[2], now);
    if (parsed) {
      if (operator === 'before') {
        return buildTemporalResult({
          from: '1970-01-01T00:00:00.000Z',
          to: new Date(Date.parse(parsed.from) - 1).toISOString(),
          label: `before ${parsed.label}`,
          matchedText: directionalMatch[0],
          operator,
          granularity: 'open_range',
        });
      }
      if (operator === 'after' || operator === 'since') {
        return buildTemporalResult({
          from: operator === 'after' ? new Date(Date.parse(parsed.to) + 1).toISOString() : parsed.from,
          to: endOfDay(now).toISOString(),
          label: `${operator} ${parsed.label}`,
          matchedText: directionalMatch[0],
          operator,
          granularity: 'open_range',
        });
      }
      return buildTemporalResult({
        from: '1970-01-01T00:00:00.000Z',
        to: parsed.to,
        label: `${operator} ${parsed.label}`,
        matchedText: directionalMatch[0],
        operator,
        granularity: 'open_range',
      });
    }
  }

  return parseExplicitDate(query, now) || parseRelativeTemporal(query, now);
}

function extractContentHint(query, matchedText = '') {
  const genericPrefixes = /\b(recall|show|tell|what happened|what did|what was|resume|continue|please|can you|could you|find|the|last|safe|session|reasoning|trace)\b/gi;
  return String(query || '')
    .replace(matchedText, ' ')
    .replace(genericPrefixes, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function findCueMatches(query) {
  const groups = [
    ['temporal', TEMPORAL_PATTERNS],
    ['session_continuity', SESSION_PATTERNS],
    ['reasoning_trace', REASONING_PATTERNS],
    ['lineage_navigation', LINEAGE_PATTERNS],
    ['corpus_analytics', ANALYTICS_PATTERNS],
  ];
  return groups
    .map(([mode, patterns]) => ({
      mode,
      matched: patterns.some((pattern) => pattern.test(query)),
    }))
    .filter((entry) => entry.matched)
    .map((entry) => entry.mode);
}

function buildRewriteDiagnostics({
  query = '',
  plan = {},
  temporal = null,
  identifierHints = [],
} = {}) {
  const cueMatches = findCueMatches(query);
  const selectedMode = plan.mode || 'unknown';
  const rejectedModes = cueMatches.filter((mode) => mode !== selectedMode);
  const candidates = [];

  if (plan.content_hint && plan.content_hint !== query) {
    candidates.push({
      candidate: plan.content_hint,
      label: 'content_hint',
      selected: true,
      reason: 'Planner removed routing words while preserving the user ask.',
    });
  }
  if (temporal?.temporal_constraint) {
    candidates.push({
      candidate: `${plan.content_hint || query} @ ${temporal.temporal_constraint.label}`,
      label: 'temporal_decomposition',
      selected: selectedMode === RECALL_MODES.TEMPORAL,
      reason: 'MRAG/TimeR4-style split between main content and temporal constraint.',
    });
  }
  if (identifierHints.length) {
    candidates.push({
      candidate: identifierHints[0],
      label: 'identifier_hint',
      selected: selectedMode === RECALL_MODES.EXACT_ARTIFACT,
      reason: 'Stable key-like artifact can be checked before semantic recall.',
    });
  }
  if (!candidates.length) {
    candidates.push({
      candidate: query,
      label: 'original_query',
      selected: true,
      reason: 'No safer rewrite candidate was generated.',
    });
  }

  return {
    source_paper: 'Multi-Faceted Self-Consistent Preference Alignment for Query Rewriting in Conversational Search',
    diagnostic_only: true,
    original_query: query,
    selected_mode: selectedMode,
    cue_matches: cueMatches,
    rejected_modes: rejectedModes,
    ambiguity_flags: {
      multiple_mode_cues: cueMatches.length > 1,
      unsupported_selected_mode: plan.supported === false,
      unresolved_temporal: selectedMode === RECALL_MODES.TEMPORAL && !temporal,
    },
    candidates,
    automatic_query_substitution_enabled: false,
    preference_training_enabled: false,
    ranking_math_changed: false,
  };
}

function attachRewriteDiagnostics(plan, context = {}) {
  return {
    ...plan,
    rewrite_diagnostics: buildRewriteDiagnostics({
      query: context.normalizedQuery || '',
      plan,
      temporal: context.temporal || plan.temporal || null,
      identifierHints: context.identifierHints || plan.identifier_hints || [],
    }),
  };
}

export function planRecallMode({
  query = '',
  key = '',
  memoryId = '',
  sessionId = '',
  memoryTypeFilter = '',
} = {}) {
  const normalizedQuery = String(query || '').trim();
  const normalizedTypeFilter = String(memoryTypeFilter || '').trim().toLowerCase();

  if (['bibliographic_reference', 'book_extract', 'framework'].includes(normalizedTypeFilter)) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.SEMANTIC_GENERAL,
      confidence: 0.98,
      supported: true,
      cues: ['explicit_memory_type_filter'],
      content_hint: normalizedQuery,
      reasoning: 'An explicit research-memory filter was supplied, so planner should preserve the paper lookup path.',
    }, { normalizedQuery });
  }

  if (String(key || '').trim() || String(memoryId || '').trim()) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.EXACT_ARTIFACT,
      confidence: 1,
      supported: true,
      cues: ['explicit_key_or_memory_id'],
      content_hint: normalizedQuery,
      reasoning: 'Exact artifact identifiers were supplied, so semantic routing is unnecessary.',
    }, { normalizedQuery });
  }

  const temporal = parseTemporalConstraint(normalizedQuery);
  const hasTemporalCue = TEMPORAL_PATTERNS.some((pattern) => pattern.test(normalizedQuery));
  const hasLineageCue = LINEAGE_PATTERNS.some((pattern) => pattern.test(normalizedQuery));
  const hasReasoningCue = REASONING_PATTERNS.some((pattern) => pattern.test(normalizedQuery));
  const identifierHints = extractIdentifierHints(normalizedQuery);
  if (hasIdentifierRecallCue({ queryText: normalizedQuery }) && !hasLineageCue && !hasReasoningCue) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.EXACT_ARTIFACT,
      confidence: 0.96,
      supported: true,
      cues: ['identifier_hint'],
      content_hint: normalizedQuery,
      identifier_hints: identifierHints,
      paper_method: {
        identifier_first: 'Generative Retrieval-style identifier surface with explicit ambiguity guard',
        uncertainty_action: 'Guessing-to-Placeholding-style insufficiency payload when identifier is ambiguous',
      },
      reasoning: 'The query contains a stable artifact/key-like identifier, so Aimos should try exact or bounded identifier lookup before semantic recall.',
    }, { normalizedQuery, identifierHints });
  }

  if (hasReasoningCue && !temporal) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.REASONING_TRACE,
      confidence: 0.94,
      supported: true,
      cues: ['reasoning_request'],
      content_hint: extractContentHint(normalizedQuery),
      reasoning: 'The user is asking for a derivation path rather than generic related memories.',
    }, { normalizedQuery });
  }

  if ((temporal || hasTemporalCue) && !(hasTemporalCue && !temporal && hasLineageCue)) {
    const contentHint = extractContentHint(normalizedQuery, temporal?.matched_text || '');
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.TEMPORAL,
      confidence: temporal ? 0.98 : 0.8,
      supported: Boolean(temporal),
      cues: [temporal ? 'temporal_reference' : 'unresolved_temporal_reference'],
      temporal,
      content_hint: contentHint,
      rewrite: {
        original_query: normalizedQuery,
        main_content: contentHint,
        temporal_constraint: temporal?.temporal_constraint || null,
      },
      paper_method: {
        question_processing: 'MRAG-style main content + temporal constraint decomposition',
        retrieve_rewrite: 'TimeR4-style explicit temporal constraint extraction',
      },
      reasoning: temporal
        ? 'Temporal cues should be handled through time-aware retrieval before semantic recall.'
        : 'The query contains temporal language, but Aimos could not extract a concrete temporal constraint safely.',
    }, { normalizedQuery, temporal });
  }

  if (hasReasoningCue) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.REASONING_TRACE,
      confidence: 0.94,
      supported: true,
      cues: ['reasoning_request'],
      content_hint: extractContentHint(normalizedQuery),
      reasoning: 'The user is asking for a derivation path rather than generic related memories.',
    }, { normalizedQuery });
  }

  if (SESSION_PATTERNS.some((pattern) => pattern.test(normalizedQuery)) || String(sessionId || '').trim()) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.SESSION_CONTINUITY,
      confidence: String(sessionId || '').trim() ? 0.99 : 0.9,
      supported: true,
      cues: [String(sessionId || '').trim() ? 'explicit_session_id' : 'continuity_request'],
      content_hint: extractContentHint(normalizedQuery),
      reasoning: 'Continuity asks should privilege session artifacts and debriefs over broad recall.',
    }, { normalizedQuery });
  }

  if (hasLineageCue) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.LINEAGE_NAVIGATION,
      confidence: 0.82,
      supported: true,
      cues: ['lineage_request'],
      content_hint: extractContentHint(normalizedQuery),
      paper_method: {
        intent_router: 'MAGMA-style graph-view selection across semantic, temporal, causal, and entity views',
      },
      reasoning: 'Relationship traversal should use bounded evidence paths over Aimos graph substrates rather than silent semantic fallback.',
    }, { normalizedQuery });
  }

  if (ANALYTICS_PATTERNS.some((pattern) => pattern.test(normalizedQuery))) {
    return attachRewriteDiagnostics({
      mode: RECALL_MODES.CORPUS_ANALYTICS,
      confidence: 0.82,
      supported: false,
      cues: ['analytics_request'],
      content_hint: extractContentHint(normalizedQuery),
      reasoning: 'Corpus analytics should use a dedicated analytic path instead of mixed recall candidates.',
    }, { normalizedQuery });
  }

  return attachRewriteDiagnostics({
    mode: RECALL_MODES.SEMANTIC_GENERAL,
    confidence: 0.6,
    supported: true,
    cues: ['semantic_default'],
    content_hint: normalizedQuery,
    reasoning: 'No exact, temporal, continuity, reasoning, or analytics cue dominated the request.',
  }, { normalizedQuery });
}

export function buildInsufficientRecallResponse(plan, reason, extras = {}) {
  return {
    memories: [],
    working_memory: [],
    cache_hit: false,
    recall_meta: {
      qmd_activated: false,
      top_rerank: 0,
      avg_rerank: 0,
      total_results: 0,
      confidence_distribution: { high: 0, medium: 0, low: 0 },
      temporal_truth: null,
      insufficient_evidence: true,
      insufficiency_reason: reason,
      planner: plan,
      evaluation: buildRecallEvaluation({
        planner: plan,
        directMode: plan.mode,
        recallMeta: extras,
        insufficientEvidence: true,
        insufficiencyReason: reason,
      }),
      ...extras,
    },
    _guide: [
      `Recall planner selected '${plan.mode}' but Aimos could not produce evidence-heavy results.`,
      'Refine the identifier/date/session scope instead of falling back to generic semantic search.',
    ],
  };
}
