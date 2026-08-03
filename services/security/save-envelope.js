// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — POST /save handler calls saveEnvelopeOrchestrator.preSaveCheck (T2/T3 fork detection) before any wall runs and commitEnvelope (atomic envelope INSERT + CAS-guarded chain_head UPDATE) after persistMemory. BUG-03 (cross-process replay) — durable backstop is migration 016 aimos_save_envelope_nonce_unique; the in-process nonce-window in auth-tier is a hot-path aid, the unique constraint is the source of truth. CAS UPDATE replaces explicit advisory locks.
// Purpose: Atomic chain advancement + envelope sidecar insertion for T2/T3
//          saves. Pre-flight fork check + post-persist commit. CAS-guarded
//          UPDATE serves as the per-agent lock without explicit advisory lock.
// Wire into: routes/aimos.js POST /save handler (Phase 4B.ii).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * save-envelope.js — T2/T3 save chain advancement orchestrator
 * Source: composite of Phase 1 (cert), Phase 3 (chain), Phase 4A (tier).
 *
 * Two functions, both dependency-injected so tests use a mock pool:
 *   preSaveCheck(...)  — read-only fork detection BEFORE walls/gate run
 *   commitEnvelope(...) — INSERT envelope + UPDATE chain_head on the active
 *                         memory transaction (or a self-owned transaction for
 *                         legacy non-memory callers)
 *
 * The architect's design decision (locked): client-supplied prev_chain_hash,
 * server enforces fork detection via a CAS-guarded UPDATE. No server-side
 * serialization, no advisory locks, no chain mutation by Aimos.
 */

import { createHash } from 'node:crypto';
import {
  contentHash,
  chainHashOf,
  genesisHashFor,
  detectForkAdvanced,
  detectForkInitial
} from './identity-chain.js';
import { pool as defaultPool } from '../../db/connection.js';

const HASH_BYTES = 32;

export function createSaveEnvelopeOrchestrator(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));

  // ─── preSaveCheck ──────────────────────────────────────────────────────────
  // Read-only: fetches current chain_head and validates the caller's claimed
  // prev against it (or against derived genesis if first save). Run BEFORE
  // walls/gate so we short-circuit obvious forks without wasting compute.
  // No locks, no transaction. A second writer racing past this point will
  // be caught by the CAS in commitEnvelope.
  async function preSaveCheck({ agentId, validFromIso, claimedPrev }) {
    if (typeof agentId !== 'string' || agentId.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (typeof validFromIso !== 'string' || validFromIso.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (!Buffer.isBuffer(claimedPrev) || claimedPrev.length !== HASH_BYTES) {
      return { ok: false, reason: 'malformed_input' };
    }
    const r = await queryFn(
      `SELECT chain_head FROM agent_identity ai
        WHERE agent_id = $1 AND valid_from = $2
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events r
             WHERE r.agent_id = ai.agent_id
               AND r.agent_valid_from = ai.valid_from
          )`,
      [agentId, validFromIso]
    );
    if (!r || !Array.isArray(r.rows) || r.rows.length === 0) {
      return { ok: false, reason: 'agent_not_active' };
    }
    const storedHead = r.rows[0].chain_head;
    if (storedHead === null || storedHead === undefined) {
      return detectForkInitial(claimedPrev, agentId, validFromIso);
    }
    return detectForkAdvanced(claimedPrev, storedHead);
  }

  // ─── commitEnvelope ────────────────────────────────────────────────────────
  // Called after the memory INSERT returned a memory_id. When `client` is
  // supplied, the caller owns the transaction containing all three operations:
  //   1. CAS-guarded UPDATE on agent_identity.chain_head (the per-agent lock)
  //   2. INSERT into aimos_save_envelope
  //   3. caller COMMIT
  // Without `client`, this primitive owns BEGIN/COMMIT for non-memory callers.
  // If CAS fails (rowCount=0), another writer advanced the chain between
  // preSaveCheck and here. It returns fork_detected; an injected transaction
  // owner must throw so its complete memory mutation rolls back.
  async function commitEnvelope({
    memoryId,
    body,
    agentId,
    validFromIso,
    claimedPrev,
    certString,
    signedTs,
    nonce,
    sigBytes,
    identityTier,
    requestSigForm,
    signedMethod,
    signedPath,
    signedClaims,
    client = null
  }) {
    if (typeof memoryId !== 'string' || memoryId.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (!Buffer.isBuffer(claimedPrev) || claimedPrev.length !== HASH_BYTES) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (!Number.isInteger(signedTs)) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (identityTier !== 'T2' && identityTier !== 'T3') {
      return { ok: false, reason: 'malformed_input' };
    }
    if (requestSigForm !== 4 || !signedMethod || !signedPath || !signedClaims?.prev_chain_hash) {
      return { ok: false, reason: 'signature_context_missing' };
    }
    if (signedClaims.prev_chain_hash !== claimedPrev.toString('base64url')) {
      return { ok: false, reason: 'signature_context_mismatch' };
    }

    const cHash = contentHash(body);
    const newChainHash = chainHashOf(claimedPrev, cHash, signedTs, agentId, memoryId);
    const certFingerprint = createHash('sha256').update(String(certString || ''), 'utf8').digest('hex');

    const isInitial = claimedPrev.equals(genesisHashFor(agentId, validFromIso));

    const conn = client || await pool.connect();
    const ownsTransaction = !client;
    try {
      if (ownsTransaction) await conn.query('BEGIN');

      const identityState = await conn.query(
        `SELECT 1
           FROM agent_identity
          WHERE agent_id = $1 AND valid_from = $2
          FOR UPDATE`,
        [agentId, validFromIso]
      );
      const terminal = identityState.rows[0]
        ? await conn.query(
            `SELECT 1 FROM aimos_agent_revocation_events
              WHERE agent_id = $1 AND agent_valid_from = $2
              LIMIT 1`,
            [agentId, validFromIso]
          )
        : { rows: [] };
      if (!identityState.rows[0] || terminal.rows[0]) {
        if (ownsTransaction) await conn.query('ROLLBACK');
        return { ok: false, reason: identityState.rows[0] ? 'agent_revoked' : 'agent_not_active' };
      }

      const updateQuery = isInitial
        ? `UPDATE agent_identity
              SET chain_head = $1
            WHERE agent_id = $2 AND valid_from = $3
              AND chain_head IS NULL`
        : `UPDATE agent_identity
              SET chain_head = $1
            WHERE agent_id = $2 AND valid_from = $3
              AND chain_head = $4`;
      const updateParams = isInitial
        ? [newChainHash, agentId, validFromIso]
        : [newChainHash, agentId, validFromIso, claimedPrev];

      const ur = await conn.query(updateQuery, updateParams);
      if (ur.rowCount === 0) {
        if (ownsTransaction) await conn.query('ROLLBACK');
        // Read on the same client so an injected transaction observes its own
        // chain state and never consults a second, potentially stale snapshot.
        const headRow = await conn.query(
          `SELECT chain_head FROM agent_identity
            WHERE agent_id = $1 AND valid_from = $2`,
          [agentId, validFromIso]
        );
        const liveHead = headRow?.rows?.[0]?.chain_head ?? null;
        return { ok: false, reason: 'fork_detected', currentHead: liveHead };
      }

      await conn.query(
        `INSERT INTO aimos_save_envelope
            (memory_id, agent_id, agent_valid_from, cert_fingerprint,
             content_hash, chain_hash, prev_chain_hash,
             ts_signed, nonce, sig, identity_tier,
             request_sig_form, signed_method, signed_path, signed_claims)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [
          memoryId, agentId, validFromIso, certFingerprint,
          cHash, newChainHash, claimedPrev,
          signedTs, nonce, sigBytes, identityTier,
          requestSigForm, signedMethod, signedPath, JSON.stringify(signedClaims)
        ]
      );

      if (ownsTransaction) await conn.query('COMMIT');
      return { ok: true, chainHash: newChainHash, contentHash: cHash };
    } catch (err) {
      if (ownsTransaction) {
        try { await conn.query('ROLLBACK'); } catch { /* ignore */ }
      }
      // Cross-process replay backstop. Migration 016 defines
      // aimos_save_envelope_nonce_unique UNIQUE (nonce); match by constraint name
      // (authoritative) with detail-string fallback so a future rename doesn't
      // silently bypass replay detection.
      if (
        err.code === '23505' &&
        ((err.constraint && err.constraint === 'aimos_save_envelope_nonce_unique') ||
         (err.detail && err.detail.includes('Key (nonce)=')))
      ) {
        // An injected PostgreSQL transaction is aborted by the unique
        // violation, so querying it again would mask replay_detected with
        // 25P02. A self-owned transaction has already rolled back and may read
        // the live head safely; the injected owner will roll back everything.
        let liveHead = null;
        if (ownsTransaction) {
          const headRow = await conn.query(
            `SELECT chain_head FROM agent_identity
             WHERE agent_id = $1 AND valid_from = $2`,
            [agentId, validFromIso]
          );
          liveHead = headRow?.rows?.[0]?.chain_head ?? null;
        }
        return { ok: false, reason: 'replay_detected', currentHead: liveHead };
      }
      throw err;
    } finally {
      if (ownsTransaction) conn.release();
    }
  }

  return { preSaveCheck, commitEnvelope };
}

// Live singleton bound to the default pool
export const saveEnvelopeOrchestrator = createSaveEnvelopeOrchestrator();
