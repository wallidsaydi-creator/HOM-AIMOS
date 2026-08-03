// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live 2026-07-04 — replaces `process.env.X === 'ON'` reads for
// governor flags with a signed, hash-chained, replay-protected toggle
// record. The HOM architecture is "Three Orthogonal Guarantees" — every
// state mutation is signed, hash-chained, and auditable. Env vars are
// silently editable, unsigned, unchained — exactly the drift the
// architecture prevents. This ledger puts governor toggles in the same
// audit plane as the mutations they gate.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * governor-config-ledger.js — cert-enveloped toggle ledger for governor flags
 *
 * Each row in `aimos_governor_config` (migration 025) is one signed toggle
 * event for a config_key. The latest row per config_key is the live flag
 * state. Toggling = appending a signed row (NEVER UPDATE/DELETE — Aladdin).
 *
 * Signing identity: `housekeeper` — the system operational identity, which is
 * not user-enrollable.
 * The same identity signs governor REWEIGHT mutations in
 * governor-provenance.js and corpus mutations
 * in the historical corpus-mutation ledger. Active governor owners import from
 * housekeeper-signer.js — single source of truth for the identity.
 *
 * Chain shape (mirrors migration 018 + 021 keyed on config_key):
 *   . ONE GENESIS PER config_key (partial unique index)
 *   . NO FORK-RACE on prev link (partial unique index)
 *   . CONSISTENCY is_genesis ⟺ prev IS NULL (CHECK)
 *   . NONCE UNIQUENESS (replay protection)
 *   . mutation_hash = sha256(content_hash || prev_mutation_hash || nonce || ts)
 *
 * Reader cache (mirrors agent-revocation-cache.js:22-64):
 *   30s TTL in-memory Map. Cache hit = no DB round-trip on `applyRewardSignal`.
 *   `commitConfigFlag` invalidates the key after commit; the CLI's toggle
 *   lands within the TTL window.
 *
 * Fail-closed semantics:
 *   . cert missing / DB error / sign failure → logEvent + return {ok:false}
 *     or readFlag→false. The dream cycle NEVER crashes on a toggle-path
 *     error. Governors' OFF (shadow-first) is the safe default.
 *
 * Source: HOM Security Wiring Plan MASTER §11 (Aimos-2 / Paper 2 territory).
 */

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';
import { contentHash } from '../security/identity-chain.js';
import { verifyCertChain, verifyStoredPayloadSig } from '../security/agent-identity.js';
import {
  detectTierFromCert,
  getHousekeeperCert,
  signAsHousekeeper,
  HOUSEKEEPER_SIGNER_CONSTANTS,
} from '../security/housekeeper-signer.js';
import { pool as defaultPool } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

export const GOVERNOR_CONFIG_CONSTANTS = Object.freeze({
  CACHE_TTL_MS: 30_000,
  ALLOWED_CONFIG_KEYS: Object.freeze([
    'COHEN_GROSSBERG_GOVERNOR',
    'OJA_NORMALIZATION_GOVERNOR',
    // Authorization toggle for the cert-enveloped corpus cleanup CLI
    // (scripts/identity/quarantine-leaked-canaries.js). When ON, the CLI
    // is permitted to run; when OFF (default), the CLI refuses. The
    // toggle itself is cert-enveloped + hash-chained — the control plane
    // IS the audit plane.
    'QUARANTINE_LEAKED_CANARIES',
    // Authorization toggle for the REVIEWER backfill ceremony
    // (scripts/backfill-ledger-reviewer.mjs). When ON, the ceremony is
    // permitted to run; when OFF (default), the ceremony refuses. The
    // START row records "ceremony began at T with target N rows"; the
    // COMPLETE row records "ceremony completed at T with N rows
    // backfilled." Two rows, chained, both honest. If the ceremony
    // crashes, the START row is evidence it began; no COMPLETE row = the
    // next run detects the incomplete ceremony + resumes. See
    // docs/security/backfill-ceremony-design.md.
    'BACKFILL_CEREMONY_LEDGER',
    // Relational (Hebbian) consensus consolidation — the nightly-dream Stage 20
    // sleep pass (services/dream/hebbian-consensus.js). When ON, supported hubs
    // are elevated and divergent members attenuated through the signed cognitive-
    // weight chain; when OFF (default), the pass is a no-op. Shadow-first: the
    // toggle is cert-enveloped + hash-chained. The Hebbian consensus record
    // binds the complete signed configuration.
    'HEBBIAN_CONSENSUS'
  ])
});

const DEFAULT_TTL_MS = GOVERNOR_CONFIG_CONSTANTS.CACHE_TTL_MS;

// ─── In-memory cache (mirrors agent-revocation-cache.js:32-64) ─────────────
const _cache = new Map(); // key: config_key → { enabled: boolean, fetchedAt: number }

function _cacheGet(configKey, nowFn = Date.now) {
  const hit = _cache.get(configKey);
  if (!hit) return undefined;
  if ((nowFn() - hit.fetchedAt) >= DEFAULT_TTL_MS) {
    _cache.delete(configKey);
    return undefined;
  }
  return hit.enabled;
}

function _cacheSet(configKey, enabled, nowFn = Date.now) {
  _cache.set(configKey, { enabled, fetchedAt: nowFn() });
}

function _cacheInvalidate(configKey) {
  if (configKey) _cache.delete(configKey);
  else _cache.clear();
}

// ─── Hash helpers (mirrors memory-provenance.js:66-79) ─────────────────────
function _tsBuf(ts) { return Buffer.from(String(ts), 'utf8'); }
function _nonceBuf(nonce) { return Buffer.from(nonce, 'utf8'); }

function _computeMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts) {
  const parts = prevMutationHashBuf
    ? [contentHashBuf, prevMutationHashBuf, _nonceBuf(nonce), _tsBuf(ts)]
    : [contentHashBuf, _nonceBuf(nonce), _tsBuf(ts)];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

function _validateConfigKey(configKey) {
  if (typeof configKey !== 'string' || configKey.length === 0) return false;
  return GOVERNOR_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes(configKey);
}

function _sameBytes(left, right) {
  const a = Buffer.from(left || []);
  const b = Buffer.from(right || []);
  return a.length === b.length && a.equals(b);
}

function _decodeCertBody(certString) {
  try {
    const envelope = JSON.parse(Buffer.from(String(certString || ''), 'base64url').toString('utf8'));
    return envelope?.body || null;
  } catch {
    return null;
  }
}

/**
 * Verify every retained toggle before allowing it to become live authority.
 * The chain is ordered oldest-first and must be complete: column edits, body
 * edits, signature substitution, row removal, or predecessor reordering all
 * fail closed.
 */
export function verifyGovernorConfigChain(rows = [], identities = [], masterPubkey = null) {
  let previousMutationHash = null;
  let previousEnabled = null;
  const identityByCertHash = new Map();

  for (const identity of identities) {
    const certHash = createHash('sha256').update(String(identity.cert || ''), 'utf8').digest('hex');
    identityByCertHash.set(certHash, identity);
  }

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const body = typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json;
    const expectedGenesis = index === 0;
    const storedPrevious = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    const identity = identityByCertHash.get(String(row.cert_fingerprint || ''));

    if (
      !_validateConfigKey(row.config_key)
      || !body
      || !identity
      || body.config_key !== row.config_key
      || body.enabled !== row.enabled
      || body.prev_enabled !== previousEnabled
      || Number(body.ts_signed) !== Number(row.ts_signed)
      || !['T1', 'T1_SYSTEM_SELF'].includes(String(body.identity_tier || ''))
      || Boolean(row.is_genesis) !== expectedGenesis
      || (expectedGenesis ? storedPrevious !== null : !_sameBytes(storedPrevious, previousMutationHash))
    ) {
      throw new Error('governor_config_chain_row_mismatch');
    }

    const certBody = _decodeCertBody(identity.cert);
    if (
      !certBody
      || certBody.agent_id !== HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID
      || certBody.pubkey !== identity.pubkey
    ) {
      throw new Error('governor_config_identity_mismatch');
    }
    const certAuthority = certBody.issuer === HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID
      ? identity.pubkey
      : masterPubkey;
    if (!certAuthority) throw new Error('governor_config_master_identity_missing');
    const certProof = verifyCertChain(identity.cert, certAuthority, {
      nowFn: () => Number(row.ts_signed),
    });
    if (!certProof.valid) throw new Error(`governor_config_cert_invalid:${certProof.reason}`);

    const signedAt = Number(row.ts_signed);
    const signedRevocationAt = identity.revocation_ts_signed == null
      ? null
      : Number(identity.revocation_ts_signed);
    if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= signedAt) {
      throw new Error('governor_config_signer_revoked_at_signature_time');
    }

    const calculatedContentHash = contentHash(body);
    const calculatedMutationHash = _computeMutationHash(
      calculatedContentHash,
      previousMutationHash,
      row.nonce,
      signedAt,
    );
    if (
      !_sameBytes(calculatedContentHash, row.content_hash)
      || !_sameBytes(calculatedMutationHash, row.mutation_hash)
    ) {
      throw new Error('governor_config_chain_hash_mismatch');
    }
    const signature = verifyStoredPayloadSig(
      identity.pubkey,
      body,
      row.nonce,
      signedAt,
      Buffer.from(row.sig || []).toString('base64url'),
    );
    if (!signature.valid) throw new Error(`governor_config_signature_invalid:${signature.reason}`);

    previousMutationHash = Buffer.from(row.mutation_hash);
    previousEnabled = row.enabled;
  }

  return {
    verified: true,
    rowCount: rows.length,
    enabled: rows.length ? rows[rows.length - 1].enabled === true : false,
    mutationHash: previousMutationHash,
  };
}

// ─── Factory (mirrors memory-provenance.js:81 createMemoryProvenanceLedger) ─
export function createGovernorConfigLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const nowFn = typeof deps.nowFn === 'function' ? deps.nowFn : Date.now;

  async function readVerifiedChain(configKey) {
    const [configRows, identityRows, masterRows] = await Promise.all([
      queryFn(
        `SELECT config_id, config_key, enabled, cert_fingerprint, content_hash,
                mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
                is_genesis, body_json, created_at
           FROM aimos_governor_config
          WHERE config_key = $1
          ORDER BY created_at ASC, config_id ASC`,
        [configKey],
      ),
      queryFn(
        `SELECT identity.cert, identity.pubkey, identity.valid_from,
                identity.valid_until,
                revocation.ts_signed AS revocation_ts_signed
           FROM agent_identity identity
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE identity.agent_id = $1`,
        [HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID],
      ),
      queryFn('SELECT master_pubkey FROM aimos_master_identity WHERE id = 1'),
    ]);
    const rows = Array.isArray(configRows?.rows) ? configRows.rows : [];
    return verifyGovernorConfigChain(
      rows,
      Array.isArray(identityRows?.rows) ? identityRows.rows : [],
      masterRows?.rows?.[0]?.master_pubkey || null,
    );
  }

  async function getLatestMutationHash(configKey) {
    const verified = await readVerifiedChain(configKey);
    if (verified.rowCount === 0) {
      return { prevMutationHash: null, isGenesis: true, prevEnabled: null };
    }
    return {
      prevMutationHash: verified.mutationHash,
      isGenesis: false,
      prevEnabled: verified.enabled,
    };
  }

  /**
   * Read the live flag state for a config_key. Returns boolean.
   * Shadow-first default: no row → false (governor OFF).
   * Fail-closed: DB error → logEvent + return false.
   */
  async function readFlag(configKey) {
    if (!_validateConfigKey(configKey)) return false;
    const cached = _cacheGet(configKey, nowFn);
    if (cached !== undefined) return cached;

    try {
      const verified = await readVerifiedChain(configKey);
      const enabled = verified.enabled === true;
      _cacheSet(configKey, enabled, nowFn);
      return enabled;
    } catch (err) {
      await logEvent(COMPANY, 'governor_config', 'read_failed', configKey, {
        error: String(err?.message || err),
        config_key: configKey
      }).catch(() => {});
      return false; // fail-closed → shadow-first
    }
  }

  /**
   * Append a signed toggle row. Returns { ok:true, ... } | { ok:false, reason }.
   */
  async function commitConfigFlag({ configKey, enabled, reason, operator } = {}) {
    if (!_validateConfigKey(configKey)) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (typeof enabled !== 'boolean') {
      return { ok: false, reason: 'malformed_input' };
    }
    if (typeof reason !== 'string' || reason.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }

    // Fetch the latest mutation hash + prev enabled state BEFORE signing so
    // the persisted body_json EXACTLY matches the signed body (signature
    // covers prev_enabled — audit-trail integrity). A fork-race between
    // this SELECT and the INSERT below returns 'fork_race' to the caller,
    // who retries the whole call (re-fetch + re-sign). The retry loop only
    // handles duplicate_genesis (another writer beat us to the genesis row).
    const { prevMutationHash, isGenesis, prevEnabled } = await getLatestMutationHash(configKey);

    let signed;
    try {
      const certificate = await getHousekeeperCert();
      const identityTier = detectTierFromCert(certificate);
      const body = {
        config_key: configKey,
        enabled,
        reason,
        operator: operator || 'unknown',
        identity_tier: identityTier,
        prev_enabled: prevEnabled
        // ts_signed injected by signAsHousekeeper BEFORE signing — sig covers
        // the same body that gets persisted (verifyPayloadSig invariant).
      };
      signed = await signAsHousekeeper(body);
      if (signed.certString !== certificate || signed.identityTier !== identityTier) {
        throw new Error('housekeeper_identity_epoch_changed_during_governor_sign');
      }
    } catch (err) {
      await logEvent(COMPANY, 'governor_config', 'sign_failed_skip', configKey, {
        error: String(err?.message || err),
        config_key: configKey
      }).catch(() => {});
      return { ok: false, reason: 'sign_failed' };
    }

    const { sigBytes, signedTs, nonce, certString } = signed;
    const cHash = contentHash(signed.body);
    const certFingerprint = createHash('sha256')
      .update(String(certString || ''), 'utf8')
      .digest('hex');

    for (let attempt = 0; attempt < 2; attempt++) {
      const mutationHash = _computeMutationHash(cHash, prevMutationHash, nonce, signedTs);

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO aimos_governor_config
              (config_key, enabled, cert_fingerprint, content_hash,
               mutation_hash, prev_mutation_hash, ts_signed, nonce, sig,
               is_genesis, body_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            configKey, enabled, certFingerprint, cHash,
            mutationHash, prevMutationHash, signedTs, nonce, sigBytes,
            isGenesis,
            JSON.stringify(signed.body)
          ]
        );
        await client.query('COMMIT');
        _cacheInvalidate(configKey);
        return { ok: true, contentHash: cHash, mutationHash, prevMutationHash, isGenesis, tsSigned: signedTs };
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        if (err.code === '23505' && err.constraint === 'aimos_governor_config_one_genesis') {
          // Another writer beat us to genesis. Re-fetch as non-genesis and retry once.
          if (attempt === 0) {
            const fresh = await getLatestMutationHash(configKey);
            // Re-sign with the fresh prev_enabled (the body changed → sig + hashes stale)
            // For simplicity, return duplicate_genesis and let the operator retry the
            // CLI call. Re-signing inline would require restructuring; the race is rare
            // (two operators toggling the SAME never-toggled key within ms).
            return { ok: false, reason: 'duplicate_genesis', detail: 'another writer claimed genesis; retry the CLI call' };
          }
          return { ok: false, reason: 'duplicate_genesis' };
        }
        if (err.code === '23505' && err.constraint === 'aimos_governor_config_next_unique') {
          return { ok: false, reason: 'fork_race', currentPrev: prevMutationHash };
        }
        if (err.code === '23505' && err.constraint === 'aimos_governor_config_nonce_unique') {
          return { ok: false, reason: 'nonce_collision' };
        }
        await logEvent(COMPANY, 'governor_config', 'commit_error', configKey, {
          error: String(err?.message || err),
          config_key: configKey
        }).catch(() => {});
        return { ok: false, reason: 'commit_error', detail: String(err?.message || err) };
      } finally {
        client.release();
      }
    }
    return { ok: false, reason: 'retry_exhausted' };
  }

  return { readFlag, commitConfigFlag, _cacheInvalidate, _cacheGet };
}

export const governorConfigLedger = createGovernorConfigLedger();

export default governorConfigLedger;
