// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live 2026-07-05 (Phase 1) — the in-memory verified store for
// operator delegation rows (aimos_system_config). It carries typed signed
// config (OPERATOR_AGENT_ID, etc.). The DB row is the
// audit trail; the in-memory store is the runtime truth.
//
// Load triggers:
//   - Startup: loadAll() called before the server accepts traffic.
//   - SIGHUP: set-system-config.js sends SIGHUP after a commit; the server's
//     SIGHUP handler calls reload(). Classic Unix config-reload pattern.
//
// Initial-load failure is fail-to-null: the store remains empty and callers
// receive no ambient fallback. Reload is atomic: a failed replacement keeps
// the last fully verified snapshot.
//
// No fallback to raw DB on readConfigString. The store IS the only path.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * system-config-store.js — in-memory verified store for system config
 *
 * Source: HOM Agent-Free Architecture Phase 1. Loads and verifies the complete
 * retained chain before publishing string-valued config rows
 * in aimos_system_config. The config is the operator's delegation; the store
 * is the runtime cache that holds it.
 *
 * Sig verification happens ONCE per delegation (at load time), not per
 * request. The master pubkey is fetched via masterPubkeyCache (60s TTL).
 */

import { pool } from '../../db/connection.js';
import { pubkeyFingerprint, verifyStoredPayloadSig } from './agent-identity.js';
import { contentHash } from './identity-chain.js';
import { masterPubkeyCache } from './master-pubkey-cache.js';
import { logEvent } from '../observe/event-ledger.js';
import {
  SYSTEM_CONFIG_CONSTANTS,
  computeSystemConfigMutationHash,
  validateSystemConfigValue,
} from './system-config-ledger.js';

function sameBytes(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
}

async function verifyConfigRow(row, masterPubkey, previous = null) {
  // Persisted ledger signatures are integrity evidence, not live requests.
  // Their age is not an expiry condition. Request replay/freshness remains in
  // auth-tier; this path verifies the original signed bytes indefinitely.
  const bodyObj = typeof row.body_json === 'string'
    ? JSON.parse(row.body_json)
    : row.body_json;
  if (!bodyObj || typeof bodyObj !== 'object') {
    return { ok: false, reason: 'INVALID_BODY' };
  }

  const signedTs = Number(row.ts_signed);
  if (!Number.isInteger(signedTs)) {
    return { ok: false, reason: 'INVALID_TIMESTAMP' };
  }
  // Bind the signature-covered body to the materialized row columns. Without
  // this check an attacker with DB write access could alter value_text while
  // leaving the valid body_json/signature untouched.
  if (
    bodyObj.config_key !== row.config_key ||
    bodyObj.value_text !== row.value_text ||
    Number(bodyObj.ts_signed) !== signedTs ||
    bodyObj.identity_tier !== SYSTEM_CONFIG_CONSTANTS.IDENTITY_TIER
  ) {
    return { ok: false, reason: 'SIGNED_BODY_ROW_MISMATCH' };
  }
  if ((bodyObj.prev_value ?? null) !== (previous?.value_text ?? null)) {
    return { ok: false, reason: 'SIGNED_PREVIOUS_VALUE_MISMATCH' };
  }

  const expectedFingerprint = pubkeyFingerprint(masterPubkey);
  if (row.cert_fingerprint !== expectedFingerprint) {
    return { ok: false, reason: 'MASTER_FINGERPRINT_MISMATCH' };
  }

  const computedContentHash = contentHash(bodyObj);
  if (!sameBytes(computedContentHash, row.content_hash)) {
    return { ok: false, reason: 'CONTENT_HASH_MISMATCH' };
  }

  const expectedPreviousHash = previous?.mutation_hash || null;
  const genesis = previous == null;
  if (Boolean(row.is_genesis) !== genesis) {
    return { ok: false, reason: 'GENESIS_FLAG_MISMATCH' };
  }
  if (genesis ? row.prev_mutation_hash != null : !sameBytes(row.prev_mutation_hash, expectedPreviousHash)) {
    return { ok: false, reason: 'CHAIN_LINK_MISMATCH' };
  }
  const computedMutationHash = computeSystemConfigMutationHash(
    computedContentHash,
    expectedPreviousHash,
    String(row.nonce),
    signedTs
  );
  if (!sameBytes(computedMutationHash, row.mutation_hash)) {
    return { ok: false, reason: 'MUTATION_HASH_MISMATCH' };
  }

  const ok = verifyStoredPayloadSig(
    masterPubkey,
    bodyObj,
    String(row.nonce),
    signedTs,
    Buffer.from(row.sig).toString('base64url')
  );
  if (!ok || ok.valid !== true) {
    return { ok: false, reason: (ok && ok.reason) || 'INVALID_SIGNATURE' };
  }
  const validated = validateSystemConfigValue(row.config_key, row.value_text);
  if (!validated.ok) {
    return { ok: false, reason: `INVALID_VALUE:${validated.reason}` };
  }
  return {
    ok: true,
    value: validated.value,
    mutationHash: Buffer.from(row.mutation_hash).toString('hex'),
  };
}

export function createSystemConfigStore(deps = {}) {
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const nowFn = typeof deps.nowFn === 'function' ? deps.nowFn : () => Date.now();
  const masterPubkeyFn = typeof deps.masterPubkeyFn === 'function'
    ? deps.masterPubkeyFn
    : () => masterPubkeyCache.get();
  const logEventFn = typeof deps.logEventFn === 'function' ? deps.logEventFn : logEvent;

  // name → { value, mutation_hash, verified_at, source }. The mutation hash
  // is retained from the same fully verified row; consumers never re-query a
  // raw configuration row to recover policy identity.
  const store = new Map();
  let loaded = false;
  let loading = null;

  async function emit(operation, key, metadata) {
    await Promise.resolve(logEventFn('hom', null, operation, key, metadata)).catch(() => {});
  }

  function replaceStore(next) {
    store.clear();
    for (const [key, value] of next) store.set(key, value);
  }

  async function buildVerifiedSnapshot() {
    let masterPubkey;
    try {
      masterPubkey = await masterPubkeyFn();
    } catch {
      masterPubkey = null;
    }
    if (!masterPubkey) {
      await emit('system_config_store_load_failed', 'master_pubkey', {
        reason: 'master pubkey unavailable',
        source_knowledge: 'system-config-store.js — buildVerifiedSnapshot'
      });
      return { ok: false, reason: 'MASTER_PUBKEY_UNAVAILABLE' };
    }

    let rows;
    try {
      const result = await queryFn(
        `SELECT config_id, config_key, value_text, cert_fingerprint,
                content_hash, mutation_hash, prev_mutation_hash,
                nonce, ts_signed, sig, is_genesis, body_json, created_at
           FROM aimos_system_config
           ORDER BY config_key, created_at ASC, config_id ASC`
      );
      rows = result.rows || [];
    } catch (error) {
      await emit('system_config_store_load_failed', 'db_query', {
        reason: String(error?.message || error),
        source_knowledge: 'system-config-store.js — buildVerifiedSnapshot'
      });
      return { ok: false, reason: 'DB_QUERY_FAILED' };
    }

    const next = new Map();
    const previousByKey = new Map();
    for (const row of rows) {
      let verification;
      try {
        verification = await verifyConfigRow(row, masterPubkey, previousByKey.get(row.config_key) || null);
      } catch {
        verification = { ok: false, reason: 'INVALID_BODY' };
      }
      if (!verification.ok) {
        await emit('system_config_verify_failed', 'config:' + row.config_key, {
          reason: verification.reason,
          source_knowledge: 'system-config-store.js — buildVerifiedSnapshot'
        });
        return { ok: false, reason: verification.reason, configKey: row.config_key };
      }
      next.set(row.config_key, {
        value: verification.value,
        mutation_hash: verification.mutationHash,
        verified_at: nowFn(),
        source: 'verified'
      });
      previousByKey.set(row.config_key, row);
    }
    return { ok: true, next };
  }

  async function refresh({ preserveCurrent }) {
    if (loading) return loading;
    loading = (async () => {
      const snapshot = await buildVerifiedSnapshot();
      if (snapshot.ok) {
        replaceStore(snapshot.next);
      } else if (!preserveCurrent) {
        // Initial boot has no prior verified state. Preserve the existing
        // fail-to-null contract while marking the store loaded so callers do
        // not accidentally fall back to ambient authority.
        store.clear();
      }
      loaded = true;
      return { ok: snapshot.ok, reason: snapshot.reason || null };
    })();
    try {
      return await loading;
    } finally {
      loading = null;
    }
  }

  async function loadAll() {
    return refresh({ preserveCurrent: false });
  }

  function readConfigString(name) {
    const entry = store.get(name);
    if (!entry) return null;
    return entry.value;
  }

  function readVerifiedConfig(name) {
    const entry = store.get(name);
    if (!entry) return null;
    return Object.freeze({
      value: entry.value,
      mutation_hash: entry.mutation_hash,
      verified_at: entry.verified_at,
      source: entry.source,
    });
  }

  function isLoaded() {
    return loaded;
  }

  function _peek() {
    return Object.fromEntries(store.entries());
  }

  async function reload() {
    return refresh({ preserveCurrent: true });
  }

  return { loadAll, reload, readConfigString, readVerifiedConfig, isLoaded, _peek };
}

export const systemConfigStore = createSystemConfigStore();

// ─── Operator-agent helpers (Phase 2 — agent-free architecture) ─────────────
// The operator agent is the privileged runner (Windows SYSTEM / Linux daemon
// analog). Designated by the operator via a signed config-ledger row. The
// system itself has no identity — these helpers read the operator's
// delegation from the in-memory store (load-once at boot, SIGHUP-reload).
//
// All helpers are CALL-TIME reads (not module-load constants) so they reflect
// the latest SIGHUP-reloaded state. With no delegation row → null → callers
// handle null explicitly (skip + logEvent, or require explicit agent_id).

/**
 * Returns the designated operator agent_id (string) or null if no delegation
 * row exists. Callers MUST handle null — no fallback to any hardcoded agent.
 */
export function getOperatorAgentId() {
  return systemConfigStore.readConfigString('OPERATOR_AGENT_ID');
}

/**
 * Returns true if the given agent_id matches the designated operator agent.
 * False if no operator is designated OR if the agent_id doesn't match.
 */
export function isOperatorAgentId(agentId = '') {
  const op = getOperatorAgentId();
  if (!op) return false;
  return String(agentId || '').trim().toLowerCase() === op.toLowerCase();
}

/**
 * Normalize an agent_id. If the input matches the operator agent (case-
 * insensitive), return the canonical operator agent_id. If the input is
 * empty, return the operator agent_id (or null if none designated). Otherwise
 * return the input lowercased.
 */
export function normalizeOperatorAgentId(agentId) {
  const normalized = String(agentId || '').trim().toLowerCase();
  if (!normalized) return getOperatorAgentId();
  const op = getOperatorAgentId();
  if (op && normalized === op.toLowerCase()) return op;
  return normalized;
}

export default systemConfigStore;
