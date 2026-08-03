/**
 * timeline-reconstructor.js — Retrieval Agent 3: Chronological Synthesis
 * Source: ASMR pipeline (MemGPT, Packer 2023), Temporal Memory (Dynamic Theory of Mind, arXiv 2026)
 * Additive Priority TEM authority: Chronos (Sen et al., arXiv:2603.16862, 2026)
 * for separating temporal event evidence from raw conversational/source turns.
 * Additive Batch9/9.5 Wave1 authority: SepSeq, Forget Then Recall, and
 * RNNs Are Not Transformers (Yet). Aimos exposes segmented timeline-pack
 * diagnostics only; chronological ordering, supersession semantics, and raw
 * timeline retention remain unchanged.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: retrieval-orchestrator.js (Parallel agent 3)
 * 2. → Pulls from: aimos_memories (supersedes_id and created_at)
 * 3. ↔ Interacts with: services/temporal/temporal-resolver.js (Chain validity)
 * 4. → Benefits: Answering domain (Provides chronological context)
 *
 * LOGIC GUIDE: Queries memory by temporal markers and orders results chronologically. 
 * Detects supersession chains to ensure latest "Truth" takes precedence over stale history.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────


// ─── Temporal keyword extraction ──────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

const TEMPORAL_KEYWORDS = [
  'yesterday', 'today', 'tomorrow', 'last week', 'next week', 'last month',
  'next month', 'last year', 'this year', 'ago', 'recently', 'before', 'after',
  'since', 'until', 'during', 'when', 'previously', 'formerly', 'now', 'current',
  'latest', 'recent', 'past', 'future', 'history', 'changed', 'updated', 'moved',
  'was', 'used to', 'started', 'ended', 'began', 'stopped'
];

const BATCH9_SEGMENTED_TIMELINE_AUTHORITIES = [
  'SepSeq: A Training-Free Framework for Long Numerical Sequence Processing in LLMs',
  'Forget, Then Recall',
  'RNNs Are Not Transformers (Yet): The Key Bottleneck on In-Context Retrieval',
];

function estimateTokensFromChars(value = '') {
  return Math.max(1, Math.ceil(String(value || '').length / 4));
}

function compactText(value = '', max = 220) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function extractTemporalKeywords(query) {
  const lower = query.toLowerCase();
  return TEMPORAL_KEYWORDS.filter(kw => lower.includes(kw));
}

// ─── Date range helpers ───────────────────────────────────────────────────────

function parseDateRange(query) {
  const lower = query.toLowerCase();
  const now = new Date();

  // "last N days/weeks/months"
  const lastN = lower.match(/last\s+(\d+)\s+(day|week|month|year)s?/);
  if (lastN) {
    const n = parseInt(lastN[1], 10);
    const unit = lastN[2];
    const from = new Date(now);
    if (unit === 'day') from.setDate(from.getDate() - n);
    else if (unit === 'week') from.setDate(from.getDate() - n * 7);
    else if (unit === 'month') from.setMonth(from.getMonth() - n);
    else if (unit === 'year') from.setFullYear(from.getFullYear() - n);
    return { from, to: now };
  }

  // "yesterday"
  if (lower.includes('yesterday')) {
    const from = new Date(now);
    from.setDate(from.getDate() - 1);
    from.setHours(0, 0, 0, 0);
    const to = new Date(from);
    to.setHours(23, 59, 59, 999);
    return { from, to };
  }

  // "today"
  if (lower.includes('today')) {
    const from = new Date(now);
    from.setHours(0, 0, 0, 0);
    return { from, to: now };
  }

  // Default: no date restriction — but we still order chronologically
  return null;
}

// ─── Live DB timeline query ───────────────────────────────────────────────────

async function liveTimelineFn(pool, query, opts = {}) {
  const { companyId = AIMOS_COMPANY_ID, clientId, limit = 30 } = opts;

  const temporalKws = extractTemporalKeywords(query);
  const dateRange = parseDateRange(query);

  // Build token set for keyword match on value
  const tokens = query
    .toLowerCase()
    .split(/\W+/)
    .filter(t => t.length > 2)
    .slice(0, 6);

  // Temporal keywords count as search tokens too
  temporalKws.forEach(kw => {
    kw.split(/\s+/).forEach(w => { if (w.length > 2 && !tokens.includes(w)) tokens.push(w); });
  });

  const params = [companyId];
  const conditions = [];

  if (tokens.length > 0) {
    const tokenConditions = tokens.map((t, i) => `LOWER(m.value) LIKE $${params.length + i + 1}`);
    params.push(...tokens.map(t => `%${t}%`));
    conditions.push(`(${tokenConditions.join(' OR ')})`);
  }

  if (dateRange) {
    params.push(dateRange.from.toISOString());
    conditions.push(`m.created_at >= $${params.length}`);
    params.push(dateRange.to.toISOString());
    conditions.push(`m.created_at <= $${params.length}`);
  }

  if (clientId) {
    params.push(clientId);
    conditions.push(`m.agent_id = $${params.length}`);
  }

  const whereClause = conditions.length > 0 ? `AND ${conditions.join(' AND ')}` : '';

  const sql = `
    SELECT
      m.id::text,
      m.key,
      m.value,
      m.agent_id,
      m.memory_type,
      m.source,
      m.created_at,
      m.is_correction,
      m.supersedes_id::text
    FROM aimos_memories m
    WHERE m.company_id = $1
      ${whereClause}
    ORDER BY m.created_at ASC
    LIMIT ${Math.min(Number(limit) || 30, 100)}
  `;

  const result = await pool.query(sql, params);
  return result.rows.map(r => ({
    id: r.id,
    key: r.key,
    value: r.value,
    entity: r.key,   // use key as the entity discriminator for supersession tracking
    date: r.created_at,
    created_at: r.created_at,
    memory_type: r.memory_type,
    source: r.source,
    is_correction: r.is_correction,
    supersedes_id: r.supersedes_id || null
  }));
}

// ─── Supersession chain builder ───────────────────────────────────────────────

/**
 * Given a sorted timeline, build supersession chain records and mark latest values.
 * A supersession occurs when:
 *   - event.supersedes_id is set (explicit chain pointer), OR
 *   - event.is_correction is true
 *
 * @param {Array} sorted - chronologically sorted events
 * @returns {{ supersessions: Array, latestValues: Object, annotated: Array }}
 */
function buildSupersessionChains(sorted) {
  const supersessions = [];
  const supersededIds = new Set(sorted.map(e => e.supersedes_id).filter(Boolean));
  const byId = new Map(sorted.map((event) => [event.id, event]));

  // Pass 1: current state is the sole retained topology head. Chronological
  // order remains useful for presentation, but transaction timestamps are not
  // a current-truth authority.
  const entityHistory = {};
  const headByEntity = new Map();
  const grouped = new Map();
  for (const event of sorted) {
    const entity = event.entity || event.key;
    if (!entity) continue;
    if (!grouped.has(entity)) grouped.set(entity, []);
    grouped.get(entity).push(event);
  }
  for (const [entity, events] of grouped) {
    const heads = events.filter((event) => event.id && !supersededIds.has(event.id));
    if (heads.length === 1) {
      headByEntity.set(entity, heads[0]);
      entityHistory[entity] = heads[0].value;
    }
  }

  // Pass 2: annotate each event with supersession context and isLatest
  const entitySeen = {}; // entity -> latest value seen so far (for supersession oldValue)
  const annotated = sorted.map(event => {
    const entity = event.entity || event.key;
    const oldValue = event.supersedes_id
      ? byId.get(event.supersedes_id)?.value || null
      : entitySeen[entity] || null;

    if (entity) {
      entitySeen[entity] = event.value;
    }

    if (event.supersedes_id || event.is_correction) {
      supersessions.push({
        entity,
        oldValue,
        newValue: event.value,
        supersededId: event.supersedes_id || null,
        when: event.date || event.created_at,
        isCorrection: !!event.is_correction
      });
    }

    return {
      id: event.id,
      value: event.value,
      key: event.key || null,
      date: event.date || event.created_at,
      entity,
      memoryType: event.memory_type || null,
      // isLatest: true only if this event's value matches the final known state for this entity
      isLatest: entity
        ? headByEntity.get(entity)?.id === event.id
        : Boolean(event.id) && !supersededIds.has(event.id),
      isSupersession: !!event.supersedes_id || !!event.is_correction,
      supersedes_id: event.supersedes_id || null
    };
  });

  return { supersessions, latestValues: entityHistory, annotated };
}

export function buildSegmentedTimelinePack(timeline = [], {
  query = '',
  budgetTokens = 2048,
  maxSegments = 8,
} = {}) {
  const events = Array.isArray(timeline) ? timeline : [];
  const safeBudget = Math.max(1, Number(budgetTokens || 2048));
  const buckets = new Map();

  for (const event of events) {
    const date = new Date(event.date || event.created_at || 0);
    const bucket = Number.isNaN(date.getTime())
      ? 'unknown'
      : date.toISOString().slice(0, 10);
    if (!buckets.has(bucket)) buckets.set(bucket, []);
    buckets.get(bucket).push(event);
  }

  const segments = [];
  let usedTokens = 0;
  for (const [bucket, items] of buckets.entries()) {
    if (segments.length >= maxSegments) break;
    const excerpt = compactText(items.map((item) => item.value).join(' '), 260);
    const estimatedTokens = estimateTokensFromChars(excerpt);
    if (segments.length > 0 && usedTokens + estimatedTokens > safeBudget) break;
    usedTokens += estimatedTokens;
    segments.push({
      segment_type: 'timeline_day',
      bucket,
      event_count: items.length,
      latest_keys: items.slice(-3).map((item) => item.key).filter(Boolean),
      summary: excerpt,
      open_memory_handles: items.slice(0, 4).map((item) => item.id
        ? `hom_open_memory:id:${item.id}`
        : (item.key ? `hom_open_memory:key:${item.key}` : null)
      ).filter(Boolean),
    });
  }

  return {
    source_papers: BATCH9_SEGMENTED_TIMELINE_AUTHORITIES,
    diagnostic_only: true,
    pack_type: 'segmented_timeline_pack',
    query: String(query || '').slice(0, 180),
    budget_tokens: safeBudget,
    used_tokens_estimate: usedTokens,
    segment_count: segments.length,
    total_event_count: events.length,
    omitted_event_count: Math.max(0, events.length - segments.reduce((sum, seg) => sum + seg.event_count, 0)),
    segments,
    raw_timeline_deleted: false,
    timeline_order_changed: false,
    guarded_math: {
      learned_sequence_model: false,
      kv_cache_recall: false,
    },
  };
}

/**
 * Reconstruct a chronological timeline of events/facts matching a query.
 *
 * @param {string} query - User question or time-scoped query
 * @param {Object} opts
 * @param {Function} [opts.timelineFn]  - Async (query, opts) => [{id, value, date, entity, is_correction, supersedes_id}]
 *                                        If omitted, uses live DB query (requires opts.pool)
 * @param {Object}   [opts.pool]         - pg Pool (required when timelineFn not provided)
 * @param {number}   [opts.limit=30]     - Max events to return
 * @param {string}   [opts.clientId]     - Filter by agent/client id
 * @param {string}   [opts.companyId]    - Tenant scope
 * @returns {Promise<{
 *   timeline: Array,
 *   supersessions: Array,
 *   latestValues: Object,
 *   temporalKeywords: string[],
 *   latencyMs: number,
 *   agentType: string
 * }>}
 */
export async function reconstructTimeline(query, opts = {}) {
  const start = Date.now();
  const { timelineFn, pool, clientId, companyId, limit = 30 } = opts;

  if (!timelineFn && !pool) {
    throw new Error('timeline-reconstructor: either timelineFn or pool is required');
  }

  let events;
  if (timelineFn) {
    events = await timelineFn(query, { clientId, companyId });
  } else {
    events = await liveTimelineFn(pool, query, { clientId, companyId, limit });
  }

  // Sort chronologically (oldest first)
  const sorted = (events || []).sort((a, b) => {
    const da = new Date(a.date || a.created_at || 0);
    const db = new Date(b.date || b.created_at || 0);
    return da - db;
  });

  const { supersessions, latestValues, annotated } = buildSupersessionChains(sorted);

  return {
    timeline: annotated,
    supersessions,
    latestValues,
    temporalKeywords: extractTemporalKeywords(query),
    segmented_timeline_pack: buildSegmentedTimelinePack(annotated, { query }),
    latencyMs: Date.now() - start,
    agentType: 'timeline-reconstructor'
  };
}
