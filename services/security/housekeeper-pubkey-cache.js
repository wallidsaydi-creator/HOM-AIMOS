// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: LIVE — housekeeperPubkeyCache.get consumed by auth-tier.deriveTier
// for the T1_SYSTEM_SELF path (self-signed housekeeper cert verified against
// the housekeeper's own pubkey, not the user master). TTL 60s; invalidatable
// on housekeeper re-provisioning. Mirrors master-pubkey-cache.js shape.
// Pipeline: AUTH GATE → AUTH-TIER | Position: housekeeper pubkey lookup
// ─────────────────────────────────────────────────────────────────────────────

/**
 * housekeeper-pubkey-cache.js — Housekeeper public key cache
 *
 * The housekeeper is the non-user-enrollable system operational identity,
 * provisioned at deployment. Its cert is self-signed during Genesis A5
 * (issuer='housekeeper', verified against the housekeeper's own pubkey).
 *
 * This cache provides the housekeeper pubkey for T1_SYSTEM_SELF tier
 * verification in auth-tier.js. Mirrors master-pubkey-cache.js.
 *
 * Factory pattern: createHousekeeperPubkeyCache(opts) returns an instance
 * with its own cached state + injected query function (for tests). The
 * exported `housekeeperPubkeyCache` singleton is wired to the live `pool`.
 */

import { pool } from '../../db/connection.js';
import { getAgentCert } from './agent-identity.js';

const DEFAULT_TTL_MS = 60_000;

export function createHousekeeperPubkeyCache(opts = {}) {
  const queryFn = typeof opts.queryFn === 'function'
    ? opts.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const ttlMs = Number.isFinite(opts.ttlMs) ? opts.ttlMs : DEFAULT_TTL_MS;
  const nowFn = typeof opts.nowFn === 'function'
    ? opts.nowFn
    : () => Date.now();

  let cached = null;     // { pubkey, fetchedAt }
  let queryCount = 0;    // for tests

  async function get() {
    const now = nowFn();
    if (cached && (now - cached.fetchedAt) < ttlMs) {
      return cached.pubkey;
    }
    queryCount++;
    let cert;
    try {
      cert = await getAgentCert('housekeeper', { queryFn, nowFn });
    } catch {
      cached = null;
      return null;
    }
    let pubkey = null;
    try {
      pubkey = JSON.parse(Buffer.from(cert, 'base64url').toString('utf8'))?.body?.pubkey || null;
    } catch { /* malformed certificate was already rejected by getAgentCert */ }
    if (!pubkey) return null;
    cached = {
      pubkey,
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

export const housekeeperPubkeyCache = createHousekeeperPubkeyCache();
