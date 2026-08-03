/**
 * timem-hierarchy.js — Temporal Memory Tree metadata for Aimos memories
 * Source: TiMem: Temporal-Hierarchical Memory Consolidation for Long-Horizon
 * Conversational Agents (Li et al., arXiv:2601.02845, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: routes/aimos.js recall/dream visibility surfaces
 * 2. → Adds: Temporal Memory Tree (TMT) level/bucket metadata to memories
 * 3. ↔ Interacts with: freshness-metadata.js, dream-feedback.js, context-renewal.js
 *
 * LOGIC GUIDE:
 * TiMem organizes memory through five temporal hierarchy levels:
 * L1 segment, L2 session, L3 day, L4 week, L5 profile. This service exposes
 * the hierarchy envelope over existing Aimos timestamps. It does not change
 * recall scoring, recall gating, dream consolidation, or schema.
 */

const MS_PER_DAY = 24 * 60 * 60 * 1000;

export const TIMEM_LEVELS = {
  SEGMENT: { id: 'L1', name: 'segment', role: 'fine-grained factual evidence' },
  SESSION: { id: 'L2', name: 'session', role: 'non-redundant session/event summary' },
  DAY: { id: 'L3', name: 'day', role: 'daily routine and recurrent context' },
  WEEK: { id: 'L4', name: 'week', role: 'evolving pattern and preference summary' },
  PROFILE: { id: 'L5', name: 'profile', role: 'stable persona/identity representation' },
};

function toDate(value) {
  const date = value ? new Date(value) : new Date();
  return Number.isFinite(date.getTime()) ? date : new Date();
}

function isoDate(date) {
  return date.toISOString().slice(0, 10);
}

function startOfUtcDay(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function addDays(date, days) {
  return new Date(date.getTime() + days * MS_PER_DAY);
}

function startOfUtcWeek(date) {
  const day = startOfUtcDay(date);
  const weekday = day.getUTCDay() || 7;
  return addDays(day, 1 - weekday);
}

function startOfUtcMonth(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
}

function classifyTimemLevel({ memoryType = '', key = '', scope = '' } = {}) {
  const type = String(memoryType || '').toLowerCase();
  const normalizedKey = String(key || '').toLowerCase();
  const normalizedScope = String(scope || '').toLowerCase();

  if (['identity', 'crew_identity', 'core_belief', 'profile', 'product'].includes(type)) {
    return TIMEM_LEVELS.PROFILE;
  }
  if (type === 'dream_summary' || type === 'dream_pattern' || normalizedKey.includes('weekly')) {
    return TIMEM_LEVELS.WEEK;
  }
  if (type === 'dream_artifact' || normalizedKey.includes('daily')) {
    return TIMEM_LEVELS.DAY;
  }
  if (['session_debrief', 'session_reasoning', 'session_exchange', 'session_manifest'].includes(type)
    || normalizedScope === 'session') {
    return TIMEM_LEVELS.SESSION;
  }
  return TIMEM_LEVELS.SEGMENT;
}

export function buildTiMemEnvelope({
  createdAt = null,
  updatedAt = null,
  lastVerifiedAt = null,
  memoryType = '',
  key = '',
  scope = '',
} = {}) {
  const basis = toDate(lastVerifiedAt || updatedAt || createdAt);
  const dayStart = startOfUtcDay(basis);
  const weekStart = startOfUtcWeek(basis);
  const monthStart = startOfUtcMonth(basis);
  const level = classifyTimemLevel({ memoryType, key, scope });

  return {
    source_paper: 'TiMem',
    tmt_level: level.id,
    tmt_level_name: level.name,
    consolidation_role: level.role,
    time_interval: {
      start: basis.toISOString(),
      end: basis.toISOString(),
      basis: lastVerifiedAt ? 'last_verified_at' : updatedAt ? 'updated_at' : createdAt ? 'created_at' : 'now',
    },
    temporal_bucket: {
      day: isoDate(dayStart),
      week_start: isoDate(weekStart),
      month: `${monthStart.getUTCFullYear()}-${String(monthStart.getUTCMonth() + 1).padStart(2, '0')}`,
    },
    parent_buckets: {
      session: key && String(scope || '').toLowerCase() === 'session' ? String(key).split(':').slice(0, 2).join(':') || null : null,
      day: isoDate(dayStart),
      week: isoDate(weekStart),
      profile: 'profile',
    },
    containment: {
      temporal_containment_visible: true,
      parent_interval_covers_child: true,
      schema_rewrite: false,
    },
    guarded_math: {
      dual_channel_leaf_scoring: false,
      llm_recall_gating: false,
      consolidation_scheduler: false,
    },
  };
}

export function selectTiMemLevels({ complexity = 'hybrid', mode = '' } = {}) {
  const normalized = String(complexity || '').toLowerCase();
  const recallMode = String(mode || '').toLowerCase();
  if (recallMode === 'temporal' || normalized === 'simple') {
    return ['L1', 'L2', 'L5'];
  }
  if (normalized === 'complex' || recallMode === 'lineage_navigation' || recallMode === 'reasoning_trace') {
    return ['L1', 'L2', 'L3', 'L4', 'L5'];
  }
  return ['L1', 'L2', 'L3', 'L5'];
}

export function summarizeTiMemHierarchy(memories = [], planner = {}) {
  const counts = { L1: 0, L2: 0, L3: 0, L4: 0, L5: 0 };
  const buckets = new Set();
  for (const memory of memories) {
    const envelope = memory.timem || buildTiMemEnvelope({
      createdAt: memory.created_at,
      updatedAt: memory.updated_at,
      lastVerifiedAt: memory.last_verified_at,
      memoryType: memory.memory_type,
      key: memory.key,
      scope: memory.scope,
    });
    if (counts[envelope.tmt_level] != null) counts[envelope.tmt_level] += 1;
    if (envelope.temporal_bucket?.day) buckets.add(envelope.temporal_bucket.day);
  }

  return {
    source_paper: 'TiMem',
    tmt_levels_present: counts,
    temporal_bucket_count: buckets.size,
    selected_levels: selectTiMemLevels({
      complexity: planner?.complexity || planner?.rewrite?.complexity || 'hybrid',
      mode: planner?.mode,
    }),
    full_tmt_math: {
      scoring_formula_7: false,
      ancestor_propagation_formula_8_9: false,
      recall_gating_formula_10_11: false,
    },
  };
}
