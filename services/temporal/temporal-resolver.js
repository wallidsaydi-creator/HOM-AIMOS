/**
 * temporal-resolver.js — Temporal State Preservation (P1-4)
 *
 * Problem: Pre-update state retrieval is only 27.7% accurate vs 63.9% post-update.
 * Prior states get shadowed when supersession happens.
 *
 * Fix: Store prior states as independently addressable records with validity windows.
 * Dual retrieval modes: "latest trusted source" for current queries vs
 * "valid-at-time-t" for historical.
 *
 * NOTE: Enforces Aladdin Law. No is_active checks (neurons never die).
 * Validity windows describe temporal truth; they never delete or deactivate a row.
 *
 * Source: Dynamic Theory of Mind as Temporal Memory (arXiv 2026)
 * Additive Priority TEM authority: Chronos (Sen et al., arXiv:2603.16862, 2026)
 * for query-time datetime windows and structured temporal evidence diagnostics.
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';

const COMPANY = AIMOS_COMPANY_ID;

export function orderMemoryVersionsByTopology(rows = []) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const byId = new Map();
  const successorByPredecessor = new Map();
  const roots = [];
  for (const row of rows) {
    const id = String(row.id || '');
    const predecessor = row.supersedes_id ? String(row.supersedes_id) : null;
    if (!id || byId.has(id)) throw new Error('memory_topology_duplicate_or_missing_id');
    if (predecessor && successorByPredecessor.has(predecessor)) throw new Error('memory_topology_fork');
    byId.set(id, row);
    if (predecessor) successorByPredecessor.set(predecessor, id);
    else roots.push(id);
  }
  if (roots.length !== 1) throw new Error('memory_topology_root_invalid');
  const ordered = [];
  const visited = new Set();
  let cursor = roots[0];
  while (cursor) {
    if (visited.has(cursor) || !byId.has(cursor)) throw new Error('memory_topology_cycle_or_missing_link');
    visited.add(cursor);
    ordered.push(byId.get(cursor));
    cursor = successorByPredecessor.get(cursor) || null;
  }
  if (visited.size !== rows.length) throw new Error('memory_topology_disconnected');
  return ordered;
}

// ─── MIGRATION VERIFICATION ────────────────────────────────────────────────
let _schemaEnsured = false;
async function ensureTemporalSchema() {
  if (_schemaEnsured) return;
  const result = await query(
    `SELECT
       to_regclass(current_schema() || '.supersession_events') IS NOT NULL AS events_present,
       EXISTS (
         SELECT 1 FROM information_schema.columns
          WHERE table_schema = current_schema()
            AND table_name = 'aimos_memories'
            AND column_name = 'valid_from'
       ) AS valid_from_present,
       EXISTS (
         SELECT 1 FROM information_schema.columns
          WHERE table_schema = current_schema()
            AND table_name = 'aimos_memories'
            AND column_name = 'valid_until'
       ) AS valid_until_present`
  );
  const state = result.rows[0] || {};
  if (!state.events_present || !state.valid_from_present || !state.valid_until_present) {
    throw new Error('temporal_schema_missing:run_migrations');
  }
  _schemaEnsured = true;
}

/**
 * Resolve temporal truth for a key.
 * Precision: validity_window > supersession_flag > latest_trusted_source
 */
export async function resolveCurrentTruth(key, companyId = COMPANY) {
  await ensureTemporalSchema();

  try {
    // Get ALL memories for this key (Aladdin: is_active check removed)
    const result = await query(
      `SELECT id, key, value, created_at, updated_at, valid_from, valid_until,
              credit_score, supersedes_id
       FROM aimos_memories
       WHERE company_id = $1 AND key = $2`,
      [companyId, key]
    );

    if (result.rows.length === 0) return { winner: null, losers: [], rule: 'no_matches' };
    const ordered = orderMemoryVersionsByTopology(result.rows);
    
    // Rule 1: Validity window (Temporal Ground Truth)
    const nowMs = Date.now();
    const currentlyValid = ordered.filter(r => {
      const from = r.valid_from ? Date.parse(r.valid_from) : 0;
      const until = r.valid_until ? Date.parse(r.valid_until) : Infinity;
      return from <= nowMs && nowMs < until;
    });
    
    if (currentlyValid.length >= 1) {
      const winner = currentlyValid.at(-1);
      const losers = ordered.filter(r => r.id !== winner.id);
      return { winner, losers, rule: 'validity_window' };
    }

    // Rule 2: the retained version with no successor is current truth. Credit
    // and timestamps rank evidence but cannot redefine signed topology.
    const winner = ordered.at(-1);
    return {
      winner,
      losers: ordered.slice(0, -1),
      rule: 'supersession_topology'
    };
  } catch (err) {
    console.warn('[temporal-resolver] truth resolution failed:', err.message);
    return { winner: null, losers: [], rule: 'error' };
  }
}

/**
 * Historical query.
 */
export async function resolveAtTime(key, asOfDate, companyId = COMPANY) {
  await ensureTemporalSchema();
  const targetTime = new Date(asOfDate).toISOString();

  try {
    const result = await query(
      `SELECT id, key, value, created_at, valid_from, valid_until, credit_score, supersedes_id
       FROM aimos_memories
       WHERE company_id = $1 AND key = $2`,
      [companyId, key]
    );
    if (result.rows.length === 0) {
      return {
        memory: null,
        temporalContext: { mode: 'fallback_by_creation', asOf: targetTime }
      };
    }
    const ordered = orderMemoryVersionsByTopology(result.rows);
    const targetMs = Date.parse(targetTime);
    const valid = ordered.filter((row) => {
      const from = row.valid_from ? Date.parse(row.valid_from) : -Infinity;
      const until = row.valid_until ? Date.parse(row.valid_until) : Infinity;
      return from <= targetMs && targetMs < until;
    });
    if (!valid.length) {
      const observed = ordered.filter((row) => Date.parse(row.created_at) <= targetMs);
      return {
        memory: observed.at(-1) || null,
        temporalContext: { mode: 'fallback_by_creation', asOf: targetTime }
      };
    }

    return {
      memory: valid.at(-1),
      temporalContext: { mode: 'validity_window', asOf: targetTime }
    };
  } catch (err) {
    console.warn('[temporal-resolver] historical query failed:', err.message);
    return { memory: null, temporalContext: { mode: 'error', asOf: targetTime } };
  }
}

export async function auditSupersessionChains(companyId = COMPANY) {
  await ensureTemporalSchema();
  try {
    const result = await query(
      `SELECT se.prior_memory_id, se.post_memory_id, se.trigger_type,
              pm.value as prior_value, nm.id as post_exists
       FROM supersession_events se
       LEFT JOIN aimos_memories pm ON pm.id = se.prior_memory_id AND pm.company_id = se.company_id
       LEFT JOIN aimos_memories nm ON nm.id = se.post_memory_id AND nm.company_id = se.company_id
       WHERE se.company_id = $1`,
      [companyId]
    );

    let intact = 0;
    const broken = [];

    for (const row of result.rows) {
      if (!row.post_exists) {
        broken.push({ priorId: row.prior_memory_id, reason: 'successor_missing' });
      } else {
        intact++;
      }
    }
    return { intact, broken };
  } catch (err) {
    console.warn('[temporal-resolver] audit failed:', err.message);
    return { intact: 0, broken: [] };
  }
}

export async function getSupersessionChain(memoryId, companyId = COMPANY) {
  await ensureTemporalSchema();
  try {
    const backwards = await query(
      `WITH RECURSIVE chain AS (
        SELECT id, key, value, created_at, supersedes_id, 0 as depth
        FROM aimos_memories WHERE id = $1::uuid AND company_id = $2
        UNION ALL
        SELECT m.id, m.key, m.value, m.created_at, m.supersedes_id, c.depth + 1
        FROM aimos_memories m
        JOIN chain c ON m.id = c.supersedes_id::uuid
        WHERE m.company_id = $2 AND c.depth < 10
      )
      SELECT * FROM chain ORDER BY depth DESC`,
      [memoryId, companyId]
    );

    const forwards = await query(
      `WITH RECURSIVE chain AS (
        SELECT id, key, value, created_at, supersedes_id, 0 as depth
        FROM aimos_memories WHERE id = $1::uuid AND company_id = $2
        UNION ALL
        SELECT m.id, m.key, m.value, m.created_at, m.supersedes_id, c.depth + 1
        FROM aimos_memories m
        JOIN chain c ON m.supersedes_id::uuid = c.id
        WHERE m.company_id = $2 AND c.depth < 10
      )
      SELECT * FROM chain WHERE depth > 0 ORDER BY depth ASC`,
      [memoryId, companyId]
    );

    const chain = [...backwards.rows, ...forwards.rows];
    return { chain, position: backwards.rows.length - 1 };
  } catch (err) {
    console.warn('[temporal-resolver] chain walk failed:', err.message);
    return { chain: [], position: -1 };
  }
}
