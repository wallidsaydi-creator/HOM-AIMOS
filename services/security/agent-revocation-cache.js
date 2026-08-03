// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — auth-tier consumes exact-epoch effective revocation truth.
// Only verified terminal revocations are cached. Active/missing epochs are
// never cached, so every process observes a newly committed terminal event on
// its next request without a cross-process invalidation hook.
// Wire into: auth-tier.js (Phase 4A.ii server.js wiring).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * agent-revocation-cache.js — Per-enrollment revocation status cache
 * Source: standard application caching pattern.
 *
 * Lookup returns { found: bool, revoked: bool|null }. Distinguishes
 * "agent not enrolled at this valid_from" (found=false) from "agent
 * enrolled and revoked" (found=true, revoked=true) so the auth tier
 * can issue the correct rejection reason.
 */

import { pool } from '../../db/connection.js';
import { verifyAgentRevocationProof } from './agent-identity.js';

export function createAgentRevocationCache(opts = {}) {
  const queryFn = typeof opts.queryFn === 'function'
    ? opts.queryFn
    : ((sql, params = []) => pool.query(sql, params));

  // key: agent_id + '|' + valid_from_iso
  const cache = new Map();

  function key(agentId, validFromIso) {
    return agentId + '|' + validFromIso;
  }

  async function lookup(agentId, validFromIso) {
    const k = key(agentId, validFromIso);
    const hit = cache.get(k);
    if (hit) {
      return { ...hit };
    }
    const r = await queryFn(
      `SELECT ai.agent_id, ai.valid_from AS agent_valid_from, ai.cert,
              re.master_fingerprint, re.target_cert_hash, re.prior_identity_hash,
              re.signed_body, re.content_hash, re.mutation_hash,
              re.ts_signed, re.nonce, re.sig,
              mi.master_pubkey, mi.fingerprint AS enrolled_master_fingerprint
         FROM agent_identity ai
         LEFT JOIN aimos_agent_revocation_events re
           ON re.agent_id = ai.agent_id AND re.agent_valid_from = ai.valid_from
         LEFT JOIN aimos_master_identity mi ON mi.id = re.master_identity_id
        WHERE ai.agent_id = $1 AND ai.valid_from = $2`,
      [agentId, validFromIso]
    );
    if (!r || !Array.isArray(r.rows) || r.rows.length === 0) {
      return { found: false, revoked: null };
    }
    const row = r.rows[0];
    if (!row.signed_body) return { found: true, revoked: false, proofVerified: false };
    if (!row.master_pubkey || row.master_fingerprint !== row.enrolled_master_fingerprint) {
      return { found: true, revoked: true, proofInvalid: true };
    }
    const verified = verifyAgentRevocationProof(row, row.master_pubkey, row.cert);
    if (!verified.valid) {
      return { found: true, revoked: true, proofInvalid: true, proofReason: verified.reason };
    }
    const terminal = { found: true, revoked: true, proofVerified: true };
    cache.set(k, terminal);
    return { ...terminal };
  }

  function invalidate(agentId, validFromIso) {
    if (agentId && validFromIso) {
      cache.delete(key(agentId, validFromIso));
    } else {
      cache.clear();
    }
  }

  return {
    lookup,
    invalidate,
    _peek: () => cache
  };
}

export const agentRevocationCache = createAgentRevocationCache();
