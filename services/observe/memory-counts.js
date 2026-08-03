// ─── MEMORY COUNTS (single source of truth) ─────────────────────────────────
// Status: Pure read aggregation — no schema, no mutations.
// Purpose: One query, one truth for memory population stats. Eliminates the
//          /status vs /layer-status N-divergence without relying on deprecated
//          is_active=false lifecycle semantics.
// Math invariant (enforced by callers and asserted in tests):
//          retained       = total
//          recall_surface = retained - quarantined_by_metadata
//          active         = recall_surface       (legacy compatibility alias)
//          inactive       = quarantined metadata (legacy compatibility alias)
// Source:  Aladdin Law (no delete; quarantine/supersession are metadata overlays).
// Compliance: Knowledge Gate [—] (read-only) | Aladdin Law [X]
// ─────────────────────────────────────────────────────────────────────────────

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (buildAimosStatusSnapshot, /layer-status handler)
// → Calls: db.query (PostgreSQL count with FILTER clauses, single roundtrip)
// Pipeline: STATUS_PIPELINE
// Position: read-side count aggregation
// ─────────────────────────────────────────────────────────────────────────────

import { query as defaultQuery } from '../../db/connection.js';

/**
 * Single source of truth for aimos_memories population stats.
 *
 * Runs ONE query with PostgreSQL FILTER aggregations — metadata counts, one scan.
 * Cheaper than running separate COUNT queries and avoids banned is_active=false
 * lifecycle reads.
 *
 * @param {string} companyId - Tenant identifier (e.g. "hom").
 * @param {object} [opts]
 * @param {Function} [opts.queryImpl] - Injected query function (for tests).
 * @returns {Promise<{
 *   total: number,
 *   retained: number,
 *   recall_surface: number,
 *   active: number,    // legacy alias of recall_surface
 *   inactive: number,  // legacy alias of quarantined_by_metadata
 *   quarantined: number,
 *   quarantined_by_metadata: number,
 *   superseded: number,
 *   superseded_versions: number,
 *   captured_at: string
 * }>}
 *
 * Invariant: `total === active + inactive`. Callers may assert this.
 */
export async function getMemoryCounts(companyId, { queryImpl = defaultQuery } = {}) {
  if (!companyId || typeof companyId !== 'string') {
    throw new TypeError('getMemoryCounts: companyId must be a non-empty string');
  }
  const result = await queryImpl(
    `SELECT
       COUNT(*)                                                            AS total,
       COUNT(*) FILTER (WHERE memory_type = 'quarantine')                  AS quarantined,
       COUNT(*) FILTER (WHERE supersedes_id IS NOT NULL)                   AS superseded
     FROM aimos_memories
     WHERE company_id = $1`,
    [companyId]
  );
  const row = result.rows[0] || {};
  const total = parseInt(row.total ?? 0, 10);
  const quarantinedByMetadata = parseInt(row.quarantined ?? 0, 10);
  const supersededVersions = parseInt(row.superseded ?? 0, 10);
  const recallSurface = Math.max(0, total - quarantinedByMetadata);
  const counts = {
    total,
    retained: total,
    recall_surface: recallSurface,
    active: recallSurface,
    inactive: quarantinedByMetadata,
    quarantined: quarantinedByMetadata,
    quarantined_by_metadata: quarantinedByMetadata,
    superseded: supersededVersions,
    superseded_versions: supersededVersions,
    captured_at: new Date().toISOString(),
  };
  // Cheap runtime invariant — the only way this fails is a DB read race
  // (extremely rare under PG snapshot isolation for a single statement).
  // We don't throw; we surface the discrepancy so an alert can fire.
  if (counts.total !== counts.active + counts.inactive) {
    counts.invariant_violation = {
      expected: 'total === active + inactive',
      actual: { total: counts.total, active: counts.active, inactive: counts.inactive },
    };
  }
  return counts;
}
