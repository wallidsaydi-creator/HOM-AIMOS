// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (Phase 2.1) — masterPubkeyCache.get consumed by auth-tier.deriveTier for cert-chain verify; SECURITY_VERIFY_SIGNATURES is shadow-first (default OFF = log-only, flag ON = enforce) with { failClosedValue: true } per BUG-02. TTL 60s; invalidatable on enrolled-identity rotation.
// Purpose: Cached lookup of the single master public key from
//          aimos_master_identity. TTL-bounded; explicitly invalidatable.
// Wire into: auth-tier.js (Phase 4A.ii server.js wiring).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * master-pubkey-cache.js — Master public key cache
 * Source: standard application caching pattern.
 *
 * Factory pattern: createMasterPubkeyCache(opts) returns an instance with its
 * own cached state and injected query function (for tests). The exported
 * `masterPubkeyCache` singleton is wired to the live `pool` for production.
 */

import { pool } from '../../db/connection.js';

const DEFAULT_TTL_MS = 60_000;

export function createMasterPubkeyCache(opts = {}) {
  const queryFn = typeof opts.queryFn === 'function'
    ? opts.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const ttlMs = Number.isFinite(opts.ttlMs) ? opts.ttlMs : DEFAULT_TTL_MS;
  const nowFn = typeof opts.nowFn === 'function'
    ? opts.nowFn
    : () => Date.now();

  let cached = null;     // { pubkey, fingerprint, fetchedAt }
  let queryCount = 0;    // for tests

  async function get() {
    const now = nowFn();
    if (cached && (now - cached.fetchedAt) < ttlMs) {
      return cached.pubkey;
    }
    queryCount++;
    const r = await queryFn(
      'SELECT master_pubkey, fingerprint FROM aimos_master_identity WHERE id = 1'
    );
    if (!r || !Array.isArray(r.rows) || r.rows.length === 0) {
      cached = null;
      return null;
    }
    cached = {
      pubkey: r.rows[0].master_pubkey,
      fingerprint: r.rows[0].fingerprint,
      fetchedAt: now
    };
    return cached.pubkey;
  }

  function invalidate() { cached = null; }

  return {
    get,
    invalidate,
    _peek: () => cached,
    _queryCount: () => queryCount
  };
}

export const masterPubkeyCache = createMasterPubkeyCache();
