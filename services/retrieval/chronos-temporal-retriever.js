/**
 * chronos-temporal-retriever.js — Chronos-compatible temporal evidence read path
 * Source: Chronos: Temporal-Aware Conversational Agents with Structured Event
 * Retrieval for Long-Term Memory (Sen et al., arXiv:2603.16862, 2026)
 * Additive TEM authority: MEMORY-T1: Reinforcement Learning for Temporal
 * Reasoning in Multi-Session Agents
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js when recall-mode-planner selects temporal mode
 * 2. → Pulls from: aimos_events as structured event candidates
 * 3. → Pulls from: aimos_memories as raw conversational/source turns
 * 4. ↔ Interacts with: services/retrieval/recall-mode-planner.js for resolved time range
 *
 * LOGIC GUIDE:
 * Chronos separates structured event retrieval from raw turn retrieval. This file
 * implements that separation using existing Aimos tables only. It does not add a
 * new event-calendar schema, does not change calibrated ranking math, and never
 * silently falls back to generic semantic recall. Memory-T1 observations are
 * emitted by the route layer; no RL policy/reward updates happen here.
 */

import { query as defaultQuery } from '../../db/connection.js';

const MAX_LIMIT = 100;
const DEFAULT_MIN_EVIDENCE = 2;

function clampLimit(limit) {
  return Math.min(Math.max(Number(limit || 10), 1), MAX_LIMIT);
}

function asIso(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function parseMetadata(metadata) {
  if (!metadata) return {};
  if (typeof metadata === 'object' && !Array.isArray(metadata)) return metadata;
  try {
    const parsed = JSON.parse(String(metadata));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function truncate(text, max = 600) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

const CONTENT_STOPWORDS = new Set([
  'about', 'after', 'before', 'could', 'during', 'give', 'happened', 'have',
  'how', 'into', 'last', 'please', 'recall', 'show', 'tell', 'that', 'the',
  'then', 'there', 'this', 'what', 'when', 'where', 'which', 'with', 'would',
  'week', 'were', 'we', 'you', 'and', 'did', 'in', 'of', 'on', 'or', 'to'
]);

function normalizeContentTerm(term) {
  const value = String(term || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').trim();
  if (!value || CONTENT_STOPWORDS.has(value) || value.length < 3) return '';
  if (/^solv(?:e|ed|es|ing)?$/.test(value)) return 'solv';
  if (/^fix(?:ed|es|ing)?$/.test(value)) return 'fix';
  if (/^issu(?:e|es)$/.test(value)) return 'issue';
  if (/^fail(?:ed|ure|ures|ing)?$/.test(value)) return 'fail';
  return value;
}

function extractContentTerms(contentHint) {
  const terms = String(contentHint || '')
    .split(/\s+/)
    .map(normalizeContentTerm)
    .filter(Boolean);
  return Array.from(new Set(terms)).slice(0, 8);
}

function evidenceSearchText(entry) {
  return [
    entry?.key,
    entry?.value,
    entry?.memory_type,
    entry?.source,
    entry?.chronos_role,
    entry?.event_tuple?.verb,
    entry?.event_tuple?.object,
    JSON.stringify(entry?.metadata || {}),
  ].filter(Boolean).join(' ').toLowerCase();
}

function contentRelevanceScore(entry, contentTerms = []) {
  if (!contentTerms.length) return 0;
  const text = evidenceSearchText(entry);
  let score = 0;
  for (const term of contentTerms) {
    if (text.includes(term)) score += 1;
  }
  if ((text.includes('problem') || text.includes('issue')) && (text.includes('solv') || text.includes('fix'))) {
    score += 2;
  }
  if (text.includes('benchmark') && (text.includes('breakthrough') || text.includes('fix'))) {
    score += 2;
  }
  return score;
}

function buildContentClause({ params, fields, contentHint }) {
  const hint = String(contentHint || '').trim();
  if (hint.length < 3) return '';
  const terms = extractContentTerms(hint);
  if (!terms.length) return '';
  const clauses = [];
  for (const term of terms) {
    params.push(`%${term}%`);
    const param = `$${params.length}`;
    clauses.push(...fields.map((field) => `${field} ILIKE ${param}`));
  }
  return `AND (${clauses.join(' OR ')})`;
}

function normalizeTemporalWindow(planner) {
  const from = asIso(planner?.temporal?.from || planner?.rewrite?.temporal_constraint?.range?.from);
  const to = asIso(planner?.temporal?.to || planner?.rewrite?.temporal_constraint?.range?.to);
  if (!from || !to) {
    return { valid: false, from, to, reason: 'missing_resolved_temporal_range' };
  }
  if (Date.parse(from) > Date.parse(to)) {
    return { valid: false, from, to, reason: 'invalid_temporal_range' };
  }
  return {
    valid: true,
    from,
    to,
    label: planner?.temporal?.label || planner?.rewrite?.temporal_constraint?.label || null,
    operator: planner?.temporal?.operator || planner?.rewrite?.temporal_constraint?.operator || 'on',
    granularity: planner?.temporal?.granularity || planner?.rewrite?.temporal_constraint?.granularity || 'unknown',
  };
}

function buildRetrievalGuidance({ queryText, contentHint, window, strict }) {
  const label = window.label || `${window.from}..${window.to}`;
  const target = contentHint || queryText || 'the requested event';
  return [
    `Search structured Aimos events inside ${label} before general memory recall.`,
    `Cross-check raw Aimos memories/source turns in the same datetime range for conversational context.`,
    `Focus on ${target}; if strict evidence is sparse, broaden only within the same temporal window.`,
    'Do not claim generic semantic recall as temporal evidence unless it is explicitly labeled as a fallback.',
  ].concat(strict ? ['Strict content filtering was attempted before temporal broadening.'] : []);
}

function rowTimeRange(value) {
  const timestamp = asIso(value);
  return { from: timestamp, to: timestamp };
}

function objectFromEvent(row) {
  const metadata = parseMetadata(row.metadata);
  return (
    row.key ||
    metadata.summary ||
    metadata.reasoning ||
    metadata.result ||
    metadata.status ||
    metadata.error ||
    metadata.message ||
    row.operation ||
    'aimos event'
  );
}

function eventRowToCandidate(row, index, clearanceLevel) {
  const metadata = parseMetadata(row.metadata);
  const object = objectFromEvent(row);
  const createdAt = asIso(row.ts) || new Date().toISOString();
  return {
    id: String(row.id),
    key: row.key || `event:${row.operation}:${row.id}`,
    value: truncate(`${row.operation}${row.key ? ` — ${row.key}` : ''}${Object.keys(metadata).length ? ` — ${JSON.stringify(metadata)}` : ''}`),
    agent_id: row.agent_id,
    memory_type: 'aimos_event',
    scope: 'event',
    source: 'aimos_events',
    clearance_level: clearanceLevel,
    created_at: createdAt,
    updated_at: createdAt,
    similarity: Math.max(0.72, 0.9 - index * 0.02),
    rerank_score: Math.max(0.72, 0.9 - index * 0.02),
    recall_confidence: Math.max(0.68, 0.86 - index * 0.02),
    chronos_role: 'structured_event_candidate',
    event_tuple: {
      subject: row.agent_id || 'aimos',
      verb: row.operation || 'recorded',
      object: truncate(object, 220),
    },
    datetime_range: rowTimeRange(row.ts),
    evidence_table: 'aimos_events',
    metadata,
  };
}

function memoryRowToCandidate(row, index) {
  const createdAt = asIso(row.created_at) || new Date().toISOString();
  const updatedAt = asIso(row.updated_at) || createdAt;
  return {
    ...row,
    id: String(row.id),
    created_at: createdAt,
    updated_at: updatedAt,
    similarity: Math.max(0.72, 0.88 - index * 0.02),
    rerank_score: Math.max(0.72, 0.88 - index * 0.02),
    recall_confidence: Math.max(0.68, 0.84 - index * 0.02),
    chronos_role: 'raw_source_turn',
    datetime_range: rowTimeRange(row.created_at),
    evidence_table: 'aimos_memories',
  };
}

async function readMemoryTurns({
  queryFn,
  companyId,
  agentId,
  clearanceLevel,
  window,
  contentHint,
  limit,
  memoryTypeFilter,
  sourceFilter,
  dataClassFilter,
  strict,
}) {
  const params = [companyId, clearanceLevel, window.from, window.to, agentId];
  let whereClause = `
    company_id = $1
    AND clearance_level <= $2
    AND created_at >= $3::timestamptz
    AND created_at <= $4::timestamptz
    AND (clearance_level > 2 OR agent_id = $5 OR agent_id IS NULL)
  `;

  if (Array.isArray(dataClassFilter) && dataClassFilter.length) {
    params.push(dataClassFilter);
    whereClause += ` AND COALESCE(data_class, 'public') = ANY($${params.length}::text[])`;
  }
  if (memoryTypeFilter) {
    params.push(memoryTypeFilter);
    whereClause += ` AND memory_type = $${params.length}`;
  }
  if (sourceFilter) {
    params.push(sourceFilter);
    whereClause += ` AND source = $${params.length}`;
  }
  if (strict) {
    whereClause += ` ${buildContentClause({
      params,
      fields: ['key', 'value'],
      contentHint,
    })}`;
  }

  params.push(limit);
  const result = await queryFn(
    `SELECT id, key, value, agent_id, memory_type, scope, source, clearance_level,
            retrieval_weight, created_at, updated_at, last_verified_at,
            verified_by, verification_basis, freshness_state
     FROM aimos_memories
     WHERE ${whereClause}
     ORDER BY created_at ASC
     LIMIT $${params.length}`,
    params
  );

  return (result.rows || []).map((row, index) => memoryRowToCandidate(row, index));
}

async function readEventCandidates({
  queryFn,
  companyId,
  agentId,
  clearanceLevel,
  window,
  contentHint,
  limit,
  strict,
}) {
  const params = [companyId, window.from, window.to, clearanceLevel, agentId];
  let whereClause = `
    company_id = $1
    AND ts >= $2::timestamptz
    AND ts <= $3::timestamptz
    AND ($4::int >= 8 OR agent_id = $5)
  `;

  if (strict) {
    whereClause += ` ${buildContentClause({
      params,
      fields: ['operation', 'key', 'metadata::text'],
      contentHint,
    })}`;
  }

  params.push(limit);
  const result = await queryFn(
    `SELECT id, agent_id, operation, key, metadata, ts
     FROM aimos_events
     WHERE ${whereClause}
     ORDER BY ts ASC
     LIMIT $${params.length}`,
    params
  );

  return (result.rows || []).map((row, index) => eventRowToCandidate(row, index, clearanceLevel));
}

function mergeEvidence({ structuredEvents, rawTurns, limit, contentTerms = [] }) {
  const seen = new Set();
  const combined = [...structuredEvents, ...rawTurns]
    .filter((entry) => {
      const id = `${entry.evidence_table}:${entry.id}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    })
    .sort((a, b) => {
      const relevanceDelta = contentRelevanceScore(b, contentTerms) - contentRelevanceScore(a, contentTerms);
      if (relevanceDelta !== 0) return relevanceDelta;
      return Date.parse(a.created_at || 0) - Date.parse(b.created_at || 0);
    });
  return combined.slice(0, limit);
}

export async function retrieveChronosTemporalEvidence({
  queryText = '',
  planner,
  companyId,
  agentId,
  clearanceLevel = 10,
  limit = 10,
  memoryTypeFilter = '',
  sourceFilter = '',
  dataClassFilter = null,
  queryFn = defaultQuery,
  minEvidence = DEFAULT_MIN_EVIDENCE,
} = {}) {
  const window = normalizeTemporalWindow(planner);
  const maxRows = clampLimit(limit);
  const contentHint = String(planner?.content_hint || '').trim();
  const contentTerms = extractContentTerms(contentHint);
  const strict = contentTerms.length > 0;
  const startedAt = Date.now();

  if (!window.valid) {
    return {
      memories: [],
      structured_event_candidates: [],
      raw_turns: [],
      retrieval_guidance: [],
      diagnostics: {
        attempted_range: { from: window.from, to: window.to },
        fallback_used: false,
        fallback_reason: window.reason,
        semantic_fallback: false,
        evidence_count: 0,
        latency_ms: Date.now() - startedAt,
      },
    };
  }

  const readLimit = Math.min(MAX_LIMIT, Math.max(maxRows * 2, maxRows));
  let rawTurns = await readMemoryTurns({
    queryFn,
    companyId,
    agentId,
    clearanceLevel,
    window,
    contentHint,
    limit: readLimit,
    memoryTypeFilter,
    sourceFilter,
    dataClassFilter,
    strict,
  });
  let structuredEvents = await readEventCandidates({
    queryFn,
    companyId,
    agentId,
    clearanceLevel,
    window,
    contentHint,
    limit: readLimit,
    strict,
  });

  let fallbackUsed = false;
  let fallbackReason = null;
  const strictEvidenceCount = rawTurns.length + structuredEvents.length;

  if (strict && strictEvidenceCount < minEvidence) {
    fallbackUsed = true;
    fallbackReason = 'temporal_range_broadening_after_sparse_strict_match';
    const broadRawTurns = await readMemoryTurns({
      queryFn,
      companyId,
      agentId,
      clearanceLevel,
      window,
      contentHint,
      limit: readLimit,
      memoryTypeFilter,
      sourceFilter,
      dataClassFilter,
      strict: false,
    });
    const broadEvents = await readEventCandidates({
      queryFn,
      companyId,
      agentId,
      clearanceLevel,
      window,
      contentHint,
      limit: readLimit,
      strict: false,
    });
    rawTurns = mergeEvidence({ structuredEvents: [], rawTurns: [...rawTurns, ...broadRawTurns], limit: readLimit, contentTerms });
    structuredEvents = mergeEvidence({ structuredEvents: [...structuredEvents, ...broadEvents], rawTurns: [], limit: readLimit, contentTerms });
  }

  const memories = mergeEvidence({ structuredEvents, rawTurns, limit: maxRows, contentTerms });
  const evidenceCount = structuredEvents.length + rawTurns.length;
  if (evidenceCount === 0) {
    fallbackReason = fallbackReason || 'temporal_window_empty';
  }

  const retrievalGuidance = buildRetrievalGuidance({
    queryText,
    contentHint,
    window,
    strict,
  });

  return {
    memories,
    structured_event_candidates: structuredEvents.slice(0, maxRows),
    raw_turns: rawTurns.slice(0, maxRows),
    retrieval_guidance: retrievalGuidance,
    diagnostics: {
      attempted_range: {
        from: window.from,
        to: window.to,
        label: window.label,
        operator: window.operator,
        granularity: window.granularity,
      },
      content_hint: contentHint || null,
      content_terms: contentTerms,
      strict_content_filter: strict,
      strict_evidence_count: strictEvidenceCount,
      structured_event_count: structuredEvents.length,
      raw_turn_count: rawTurns.length,
      evidence_count: evidenceCount,
      returned_count: memories.length,
      fallback_used: fallbackUsed,
      fallback_reason: fallbackReason,
      semantic_fallback: false,
      retrieval_path: 'chronos_existing_aimos_tables',
      source_tables: ['aimos_events', 'aimos_memories'],
      latency_ms: Date.now() - startedAt,
    },
  };
}
