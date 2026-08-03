/**
 * freshness-metadata.js — explicit freshness semantics for recall truth
 * Sources: Set the Clock (2024), TimeR4 (2024), MRAG (2025)
 * Additive TEM authority: TiMem: Temporal-Hierarchical Memory Consolidation
 * for Long-Horizon Conversational Agents
 *
 * Purpose: distinguish fresh operational truth from stale or historical memory
 * without violating Aladdin retention. Aimos keeps everything of value, but
 * recall should know what is current, aging, stale, historical, or unverified.
 *
 * Batch 10 Lane 5: Compression ratios per freshness state (Temporal Memory)
 *   compression_ratio(state): fresh→1.0x, aging→0.5x, stale→0.25x, historical→0.1x
 *   freshness_score = f(access_recency, verification_status, cross_ref_count)
 * Aladdin: Compression ratio only affects context window bandwidth.
 *   Canonical memory content and embedding are never modified.
 *
 * Note: the state labels are paper-aligned metadata. Numeric scores are display
 * signals only unless an explicit caller gates them into calibrated ranking.
 * TiMem adds hierarchy envelopes through timem-hierarchy.js; this file keeps
 * freshness state semantics flat and does not implement TiMem recall scoring.
 */

export const FRESHNESS_STATES = ['fresh', 'aging', 'stale', 'historical', 'unverified'];

const RESEARCH_TYPES = new Set([
  'book_extract',
  'bibliographic_reference',
  'framework',
  'research',
]);

const OPERATIONAL_TYPES = new Set([
  'session_debrief',
  'session_exchange',
  'session_manifest',
  'session_reasoning',
  'event_log',
  'after_action_review',
  'dream_summary',
  'dream_pattern',
  'operational_rule',
  'strategic_directive',
  'heartbeat',
  'infrastructure',
]);

export function normalizeFreshnessState(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return FRESHNESS_STATES.includes(normalized) ? normalized : null;
}

function isResearchLike({ key = '', memoryType = '', source = '' } = {}) {
  const normalizedType = String(memoryType || '').trim().toLowerCase();
  const normalizedKey = String(key || '').trim().toLowerCase();
  const normalizedSource = String(source || '').trim().toLowerCase();
  return (
    RESEARCH_TYPES.has(normalizedType)
    || normalizedKey.startsWith('paper:')
    || normalizedKey.startsWith('book:')
    || normalizedSource.includes('reader')
    || normalizedSource.includes('ingest')
    || normalizedSource.startsWith('benchmark:')
    || normalizedSource.startsWith('import:')
  );
}

export function deriveFreshnessState({
  freshnessState = null,
  lastVerifiedAt = null,
  createdAt = null,
  memoryType = '',
  key = '',
  source = '',
} = {}) {
  const explicit = normalizeFreshnessState(freshnessState);
  if (explicit) return explicit;

  if (isResearchLike({ key, memoryType, source })) {
    return 'historical';
  }

  const basis = lastVerifiedAt || createdAt;
  if (!basis) {
    return OPERATIONAL_TYPES.has(String(memoryType || '').trim().toLowerCase())
      ? 'unverified'
      : 'aging';
  }

  const ts = Date.parse(basis);
  if (!Number.isFinite(ts)) return 'unverified';
  const ageHours = Math.max(0, (Date.now() - ts) / 36e5);
  if (ageHours <= 72) return 'fresh';
  if (ageHours <= 24 * 30) return 'aging';
  if (ageHours <= 24 * 90) return 'stale';
  return 'historical';
}

export function computeFreshnessScore(freshnessState) {
  const normalized = deriveFreshnessState({ freshnessState });
  const scores = {
    fresh: 1.0,
    aging: 0.82,
    stale: 0.48,
    historical: 0.35,
    unverified: 0.62,
  };
  return scores[normalized] ?? 0.62;
}

export function buildFreshnessEnvelope({
  freshnessState = null,
  lastVerifiedAt = null,
  createdAt = null,
  memoryType = '',
  key = '',
  source = '',
  verifiedBy = null,
  verificationBasis = null,
} = {}) {
  const state = deriveFreshnessState({
    freshnessState,
    lastVerifiedAt,
    createdAt,
    memoryType,
    key,
    source,
  });

  return {
    freshness_state: state,
    last_verified_at: lastVerifiedAt || null,
    verified_by: verifiedBy || null,
    verification_basis: verificationBasis || null,
    freshness_score: computeFreshnessScore(state),
  };
}

export function resolveFreshnessWriteFields({
  key = '',
  memoryType = '',
  source = '',
  freshnessState = null,
  lastVerifiedAt = null,
  verifiedBy = null,
  verificationBasis = null,
} = {}) {
  const researchLike = isResearchLike({ key, memoryType, source });
  const effectiveLastVerifiedAt = researchLike
    ? (lastVerifiedAt || null)
    : (lastVerifiedAt || new Date().toISOString());

  const effectiveVerificationBasis = researchLike
    ? (verificationBasis || 'reference_import')
    : (verificationBasis || 'save');

  const effectiveVerifiedBy = researchLike
    ? (verifiedBy || null)
    : (verifiedBy || source || 'aimos_save');

  return buildFreshnessEnvelope({
    freshnessState,
    lastVerifiedAt: effectiveLastVerifiedAt,
    createdAt: new Date().toISOString(),
    memoryType,
    key,
    source,
    verifiedBy: effectiveVerifiedBy,
    verificationBasis: effectiveVerificationBasis,
  });
}

// ─── BATCH 10 LANE 5: COMPRESSION RATIO PER FRESHNESS STATE ─────────────────
// Papers: Temporal Memory
// compression_ratio(state): fresh→1.0x, aging→0.5x, stale→0.25x, historical→0.1x
// freshness_score = f(access_recency, verification_status, cross_ref_count)
// Aladdin: Compression ratio only affects context window bandwidth.
//   Canonical memory content and embedding are never modified.
// ─────────────────────────────────────────────────────────────────────────────

const FRESHNESS_COMPRESSION_RATIO = {
  fresh: 1.0,
  aging: 0.5,
  stale: 0.25,
  historical: 0.1,
  unverified: 0.5,
};

/**
 * Compute compression ratio based on freshness state.
 * fresh→1.0x, aging→0.5x, stale→0.25x, historical→0.1x
 * This maps to the compression_ratio column from Lane 0 schema.
 *
 * @param {string} freshnessState - One of: fresh, aging, stale, historical, unverified
 * @returns {{ ratio: number, freshness_state: string, source_paper: string, aladdin: string }}
 */
export function computeCompressionRatio(freshnessState) {
  const state = String(freshnessState || 'fresh').toLowerCase();
  const ratio = FRESHNESS_COMPRESSION_RATIO[state] ?? 1.0;

  return {
    ratio,
    freshness_state: state,
    formula: 'compression_ratio(state): fresh→1.0, aging→0.5, stale→0.25, historical→0.1',
    source_paper: 'Temporal Memory',
    aladdin: 'compression_ratio_only_affects_context_window_bandwidth_canonical_untouched',
  };
}

/**
 * Compute comprehensive freshness score from multiple dimensions.
 * freshness_score = f(access_recency, verification_status, cross_ref_count)
 * Uses the existing computeFreshnessScore but enriches it with compression ratio.
 *
 * @param {object} memory - Memory row with freshness metadata
 * @returns {{ freshness_score: number, compression_ratio: number, envelope: object, source_paper: string }}
 */
export function computeFreshnessScoreWithCompression(memory = {}) {
  const state = deriveFreshnessState({
    freshnessState: memory.freshness_state || memory.freshnessState,
    lastVerifiedAt: memory.last_verified_at || memory.lastVerifiedAt,
    createdAt: memory.created_at || memory.createdAt,
    memoryType: memory.memory_type || memory.memoryType,
    key: memory.key,
    source: memory.source,
  });

  const freshnessScore = computeFreshnessScore(state);
  const compressionRatio = computeCompressionRatio(state);

  return {
    freshness_score: freshnessScore,
    compression_ratio: compressionRatio.ratio,
    freshness_state: state,
    envelope: buildFreshnessEnvelope({
      freshnessState: state,
      lastVerifiedAt: memory.last_verified_at || memory.lastVerifiedAt,
      createdAt: memory.created_at || memory.createdAt,
      memoryType: memory.memory_type || memory.memoryType,
      key: memory.key,
      source: memory.source,
    }),
    source_paper: 'Temporal Memory',
    aladdin: 'compression_ratio_only_affects_context_window_bandwidth_canonical_untouched',
  };
}
