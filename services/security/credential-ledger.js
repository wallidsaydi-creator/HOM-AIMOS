// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: Genesis, native credential save, identity vault, credential CLI
// → Calls: identity epoch/certificate verification + append-only lifecycle table
// Pipeline: CREDENTIAL | Position: sole cryptographic lifecycle authority
// Technique authority: Crosby & Wallach, "Efficient Data Structures for
// Tamper-Evident Logging" — historical consistency and fork detection.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * credential-ledger.js — cert-bound, append-only credential lifecycle
 *
 * Plaintext remains in versioned Keychain slots. This ledger binds the exact
 * service, logical slot, lifecycle event, credential hash, signer epoch,
 * predecessor, timestamp, nonce, and signature. Every append verifies the
 * complete oldest-first chain before deriving its predecessor.
 */

import { createHash, randomUUID } from 'node:crypto';
import { contentHash } from './identity-chain.js';
import {
  canonicalJson,
  verifyCertChain,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import { agentPool as defaultPool } from '../../db/connection.js';
import { signAsHousekeeper } from './housekeeper-signer.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';
import { readVerifiedRequestReceiptById } from './request-receipt-ledger.js';

const HASH_BYTES = 32;
const ALLOWED_EVENT_TYPES = Object.freeze([
  'STORE',
  'ROTATE',
  'REVOKE',
  'VERIFY',
  'USE_RESERVED',
  'USE_COMPLETED',
  'USE_FAILED',
]);
const USE_TERMINAL_TYPES = new Set(['USE_COMPLETED', 'USE_FAILED']);

function tsBuf(ts) { return Buffer.from(String(ts), 'utf8'); }
function nonceBuf(nonce) { return Buffer.from(String(nonce), 'utf8'); }
function sameBytes(left, right) {
  const a = Buffer.from(left || []);
  const b = Buffer.from(right || []);
  return a.length === b.length && a.equals(b);
}
function bodyOf(row) {
  return typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json;
}
function certBodyOf(certString) {
  try {
    return JSON.parse(Buffer.from(String(certString || ''), 'base64url').toString('utf8'))?.body || null;
  } catch {
    return null;
  }
}

function mutationKey(value, error) {
  const bytes = Buffer.from(value || []);
  if (bytes.length !== HASH_BYTES) throw new Error(error);
  return bytes.toString('hex');
}

/**
 * Derive ledger chronology exclusively from authenticated predecessor hashes.
 * Database timestamps and UUIDs are retained observations, never chain order.
 */
export function orderCredentialLifecycleRows(rows = []) {
  if (rows.length === 0) return [];

  const byMutation = new Map();
  const children = new Map();
  const roots = [];
  const referenced = new Set();

  for (const row of rows) {
    const mutation = mutationKey(row.mutation_hash, 'credential_chain_mutation_hash_malformed');
    if (byMutation.has(mutation)) throw new Error('credential_chain_duplicate_mutation_hash');
    byMutation.set(mutation, row);
  }

  for (const row of rows) {
    const mutation = mutationKey(row.mutation_hash, 'credential_chain_mutation_hash_malformed');
    if (row.prev_mutation_hash == null) {
      roots.push(row);
      continue;
    }
    const predecessor = mutationKey(
      row.prev_mutation_hash,
      'credential_chain_predecessor_hash_malformed',
    );
    if (!byMutation.has(predecessor)) throw new Error('credential_chain_disconnected_predecessor');
    if (children.has(predecessor)) throw new Error('credential_chain_fork_detected');
    children.set(predecessor, row);
    referenced.add(predecessor);
    if (predecessor === mutation) throw new Error('credential_chain_cycle_detected');
  }

  if (roots.length === 0) throw new Error('credential_chain_zero_genesis');
  if (roots.length > 1) throw new Error('credential_chain_multiple_genesis');

  const heads = rows.filter((row) => !referenced.has(
    mutationKey(row.mutation_hash, 'credential_chain_mutation_hash_malformed'),
  ));
  if (heads.length === 0) throw new Error('credential_chain_zero_heads');
  if (heads.length > 1) throw new Error('credential_chain_multiple_heads');

  const ordered = [];
  const visited = new Set();
  let current = roots[0];
  while (current) {
    const mutation = mutationKey(current.mutation_hash, 'credential_chain_mutation_hash_malformed');
    if (visited.has(mutation)) throw new Error('credential_chain_cycle_detected');
    visited.add(mutation);
    ordered.push(current);
    current = children.get(mutation) || null;
  }
  if (ordered.length !== rows.length) throw new Error('credential_chain_disconnected');
  if (ordered[ordered.length - 1] !== heads[0]) throw new Error('credential_chain_head_mismatch');
  return ordered;
}

export function computeMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts) {
  const parts = prevMutationHashBuf
    ? [contentHashBuf, Buffer.from(prevMutationHashBuf), nonceBuf(nonce), tsBuf(ts)]
    : [contentHashBuf, nonceBuf(nonce), tsBuf(ts)];
  return createHash('sha256').update(Buffer.concat(parts)).digest();
}

export function verifyMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts, expectedHashBuf) {
  return Buffer.isBuffer(expectedHashBuf)
    && expectedHashBuf.length === HASH_BYTES
    && computeMutationHash(contentHashBuf, prevMutationHashBuf, nonce, ts).equals(expectedHashBuf);
}

export function credentialUseEvidenceHash(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function verifyCredentialLifecycleChain(rows = [], masterPubkey = null) {
  const orderedRows = orderCredentialLifecycleRows(rows);
  let previousMutationHash = null;
  let slotId = null;
  let serviceName = null;
  let effectiveStore = null;
  let revoked = false;
  const reservations = new Map();
  const terminalUseIds = new Set();

  for (let index = 0; index < orderedRows.length; index += 1) {
    const row = orderedRows[index];
    const body = bodyOf(row);
    const certBody = certBodyOf(row.cert);
    const proofVersion = Number(row.proof_version || (body?.signer_agent_id ? 2 : 1));
    const expectedGenesis = index === 0;
    const storedPrevious = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    if (index === 0) {
      slotId = String(row.slot_id);
      serviceName = String(row.service_name);
    }
    if (
      !body
      || !certBody
      || String(row.slot_id) !== slotId
      || String(row.service_name) !== serviceName
      || body.slot_id !== row.slot_id
      || body.service !== row.service_name
      || body.event_type !== row.event_type
      || ![1, 2].includes(proofVersion)
      || (proofVersion === 1 && body.signer_agent_id != null)
      || (proofVersion === 2 && body.signer_agent_id !== row.agent_id)
      || Number(body.ts_signed) !== Number(row.ts_signed)
      || !ALLOWED_EVENT_TYPES.includes(row.event_type)
      || !/^[0-9a-f]{64}$/.test(String(body.credential_hash || ''))
      || Boolean(row.is_genesis) !== expectedGenesis
      || (expectedGenesis ? storedPrevious !== null : !sameBytes(storedPrevious, previousMutationHash))
      || certBody.agent_id !== row.agent_id
      || certBody.pubkey !== row.pubkey
      || new Date(certBody.valid_from * 1000).toISOString() !== new Date(row.agent_valid_from).toISOString()
    ) {
      throw new Error('credential_chain_row_mismatch');
    }
    const certFingerprint = createHash('sha256').update(String(row.cert), 'utf8').digest('hex');
    if (certFingerprint !== row.cert_fingerprint) throw new Error('credential_chain_certificate_mismatch');
    const expectedTier = certBody.issuer === certBody.agent_id ? 'T1_SYSTEM_SELF' : 'T1';
    if (row.identity_tier !== expectedTier) throw new Error('credential_chain_identity_tier_mismatch');
    const certAuthority = certBody.issuer === certBody.agent_id ? row.pubkey : masterPubkey;
    if (!certAuthority) throw new Error('credential_chain_master_identity_missing');
    const certProof = verifyCertChain(row.cert, certAuthority, { nowFn: () => Number(row.ts_signed) });
    if (!certProof.valid) throw new Error(`credential_chain_certificate_invalid:${certProof.reason}`);
    const signedRevocationAt = row.revocation_ts_signed == null ? null : Number(row.revocation_ts_signed);
    if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= Number(row.ts_signed)) {
      throw new Error('credential_chain_signer_revoked_at_signature_time');
    }
    const calculatedContentHash = contentHash(body);
    const calculatedMutationHash = computeMutationHash(
      calculatedContentHash,
      previousMutationHash,
      row.nonce,
      Number(row.ts_signed),
    );
    if (!sameBytes(calculatedContentHash, row.content_hash)
      || !sameBytes(calculatedMutationHash, row.mutation_hash)) {
      throw new Error('credential_chain_hash_mismatch');
    }
    const signature = verifyStoredPayloadSig(
      row.pubkey,
      body,
      row.nonce,
      Number(row.ts_signed),
      Buffer.from(row.sig).toString('base64url'),
    );
    if (!signature.valid) throw new Error(`credential_chain_signature_invalid:${signature.reason}`);

    if (row.event_type === 'STORE' || row.event_type === 'ROTATE') {
      effectiveStore = row;
      revoked = false;
    } else if (row.event_type === 'REVOKE') {
      revoked = true;
    } else if (row.event_type === 'VERIFY') {
      const effectiveBody = effectiveStore ? bodyOf(effectiveStore) : null;
      if (!effectiveStore || revoked || body.credential_hash !== effectiveBody?.credential_hash) {
        throw new Error('credential_verify_without_effective_store');
      }
    } else if (row.event_type === 'USE_RESERVED') {
      const effectiveBody = effectiveStore ? bodyOf(effectiveStore) : null;
      const requestAuthorityComplete = body.authority_kind === 'housekeeper_observation_of_verified_request'
        && typeof body.request_receipt_id === 'string'
        && /^[0-9a-f]{64}$/.test(String(body.request_receipt_mutation_hash || ''))
        && typeof body.request_admission_event_id === 'string'
        && /^[0-9a-f]{64}$/.test(String(body.request_admission_mutation_hash || ''));
      const autonomousAuthorityComplete = body.authority_kind === 'housekeeper_autonomous'
        && body.subject_agent_id === 'housekeeper'
        && body.request_receipt_id == null
        && body.request_admission_event_id == null;
      const exactAuthorityComplete = typeof body.autonomous_action_event_id === 'string'
        && /^[0-9a-f]{64}$/.test(String(body.autonomous_action_mutation_hash || ''))
        && (requestAuthorityComplete || autonomousAuthorityComplete);
      // Retained USE reservations signed before exact event-mutation/admission
      // binding remain valid chain evidence, but are never reused as current
      // authorization. New appends are rejected by validate() unless exact.
      const retainedLegacyUse = body.autonomous_action_mutation_hash == null
        && body.request_admission_event_id == null;
      if (
        !effectiveStore
        || revoked
        || body.credential_hash !== effectiveBody?.credential_hash
        || body.effective_provenance_id !== String(effectiveStore.provenance_id)
        || body.effective_mutation_hash !== Buffer.from(effectiveStore.mutation_hash).toString('hex')
        || typeof body.use_id !== 'string'
        || !body.use_id
        || (!exactAuthorityComplete && !retainedLegacyUse)
        || reservations.has(body.use_id)
      ) {
        throw new Error('credential_use_without_effective_store');
      }
      reservations.set(body.use_id, {
        row,
        mutationHash: calculatedMutationHash.toString('hex'),
        exactAuthority: exactAuthorityComplete,
      });
    } else if (USE_TERMINAL_TYPES.has(row.event_type)) {
      const reservation = reservations.get(body.use_id);
      if (
        !reservation
        || terminalUseIds.has(body.use_id)
        || body.reservation_provenance_id !== String(reservation.row.provenance_id)
        || body.reservation_mutation_hash !== reservation.mutationHash
        || body.credential_hash !== bodyOf(reservation.row)?.credential_hash
      ) {
        throw new Error('credential_use_terminal_without_reservation');
      }
      terminalUseIds.add(body.use_id);
    } else {
      throw new Error('credential_verify_without_effective_store');
    }
    previousMutationHash = Buffer.from(row.mutation_hash);
  }

  return {
    verified: true,
    rows: orderedRows,
    rowCount: orderedRows.length,
    slotId,
    serviceName,
    mutationHash: previousMutationHash,
    effectiveStore: revoked ? null : effectiveStore,
    revoked,
    openCredentialUses: Array.from(reservations.entries())
      .filter(([useId]) => !terminalUseIds.has(useId))
      .map(([, reservation]) => reservation.row),
  };
}

export function createCredentialLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const verifyRequestAuthority = deps.verifyRequestAuthorityFn || readVerifiedRequestReceiptById;
  const verifyAutonomousEvent = deps.verifyAutonomousEventFn || readVerifiedEventById;
  const appendAutonomousAuthority = deps.appendAutonomousAuthorityFn || logEvent;

  function runner(client) {
    return client ? client.query.bind(client) : queryFn;
  }

  async function verifyAuthority({ certString, body, agentId, validFromIso, signedTs, nonce, sigBytes, identityTier }) {
    if (typeof deps.verifyAuthorityFn === 'function') {
      return deps.verifyAuthorityFn({ certString, body, agentId, validFromIso, signedTs, nonce, sigBytes, identityTier });
    }
    const [identityResult, masterResult] = await Promise.all([
      queryFn(
        `SELECT identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed
           FROM agent_identity identity
          LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE identity.agent_id = $1 AND identity.valid_from = $2`,
        [agentId, validFromIso],
      ),
      queryFn('SELECT master_pubkey FROM aimos_master_identity WHERE id = 1'),
    ]);
    const identity = identityResult.rows[0];
    if (!identity || identity.cert !== certString) return { ok: false, reason: 'credential_signer_epoch_missing' };
    const certBody = certBodyOf(certString);
    if (!certBody || certBody.agent_id !== agentId || certBody.pubkey !== identity.pubkey) {
      return { ok: false, reason: 'credential_signer_identity_mismatch' };
    }
    const expectedTier = certBody.issuer === certBody.agent_id ? 'T1_SYSTEM_SELF' : 'T1';
    if (identityTier !== expectedTier) return { ok: false, reason: 'credential_signer_tier_mismatch' };
    const certAuthority = certBody.issuer === certBody.agent_id
      ? identity.pubkey
      : masterResult.rows[0]?.master_pubkey;
    if (!certAuthority) return { ok: false, reason: 'master_pubkey_unavailable' };
    const cert = verifyCertChain(certString, certAuthority, { nowFn: () => signedTs });
    if (!cert.valid) return { ok: false, reason: cert.reason || 'cert_invalid' };
    const signedRevocationAt = identity.revocation_ts_signed == null ? null : Number(identity.revocation_ts_signed);
    if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= signedTs) {
      return { ok: false, reason: 'credential_signer_revoked_at_signature_time' };
    }
    const signature = verifyStoredPayloadSig(
      identity.pubkey,
      body,
      nonce,
      signedTs,
      sigBytes.toString('base64url'),
    );
    return signature.valid ? { ok: true } : { ok: false, reason: signature.reason || 'sig_invalid' };
  }

  function validate(args) {
    const { serviceName, slotId, body, bodyJson, agentId, validFromIso, signedTs, nonce, sigBytes, identityTier, eventType } = args;
    if (typeof serviceName !== 'string' || !serviceName) return 'malformed_service_name';
    if (typeof slotId !== 'string' || !slotId) return 'malformed_slot_id';
    if (!body || typeof body !== 'object' || !bodyJson || typeof bodyJson !== 'object') return 'malformed_body';
    if (canonicalJson(body) !== canonicalJson(bodyJson)) return 'signed_body_mismatch';
    if (body.service !== serviceName) return 'signed_service_mismatch';
    if (body.slot_id !== slotId) return 'signed_slot_mismatch';
    if (body.event_type !== eventType) return 'signed_event_type_mismatch';
    if (body.signer_agent_id !== agentId) return 'signed_agent_mismatch';
    if (!/^[0-9a-f]{64}$/.test(String(body.credential_hash || ''))) return 'malformed_credential_hash';
    if (typeof agentId !== 'string' || !agentId) return 'malformed_agent_id';
    if (typeof validFromIso !== 'string' || !Number.isFinite(Date.parse(validFromIso))) return 'malformed_agent_epoch';
    if (!Number.isInteger(signedTs) || signedTs <= 0 || Number(body.ts_signed) !== signedTs) return 'malformed_signed_ts';
    if (typeof nonce !== 'string' || !nonce) return 'malformed_nonce';
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) return 'malformed_sig';
    if (!['T1', 'T1_SYSTEM_SELF'].includes(identityTier)) return 'malformed_identity_tier';
    if (!ALLOWED_EVENT_TYPES.includes(eventType)) return 'malformed_event_type';
    if (eventType === 'USE_RESERVED') {
      if (typeof body.use_id !== 'string' || !body.use_id) return 'malformed_credential_use_id';
      if (typeof body.operation !== 'string' || !body.operation) return 'malformed_credential_use_operation';
      if (typeof body.endpoint !== 'string' || !body.endpoint) return 'malformed_credential_use_endpoint';
      if (!/^[0-9a-f]{64}$/.test(String(body.request_hash || ''))) return 'malformed_credential_use_request_hash';
      if (typeof body.effective_provenance_id !== 'string' || !body.effective_provenance_id) {
        return 'malformed_credential_use_store_provenance';
      }
      if (!/^[0-9a-f]{64}$/.test(String(body.effective_mutation_hash || ''))) {
        return 'malformed_credential_use_store_mutation';
      }
      if (typeof body.autonomous_action_event_id !== 'string' || !body.autonomous_action_event_id) {
        return 'malformed_credential_use_authority_event';
      }
      if (!/^[0-9a-f]{64}$/.test(String(body.autonomous_action_mutation_hash || ''))) {
        return 'malformed_credential_use_authority_mutation';
      }
      if (body.authority_kind === 'housekeeper_observation_of_verified_request') {
        if (!body.request_receipt_id
          || !/^[0-9a-f]{64}$/.test(String(body.request_receipt_mutation_hash || ''))
          || !body.request_admission_event_id
          || !/^[0-9a-f]{64}$/.test(String(body.request_admission_mutation_hash || ''))) {
          return 'malformed_credential_use_request_authority';
        }
      } else if (body.authority_kind !== 'housekeeper_autonomous'
        || body.subject_agent_id !== 'housekeeper'
        || body.request_receipt_id != null
        || body.request_admission_event_id != null) {
        return 'malformed_credential_use_autonomous_authority';
      }
    }
    if (USE_TERMINAL_TYPES.has(eventType)) {
      if (typeof body.use_id !== 'string' || !body.use_id) return 'malformed_credential_use_id';
      if (typeof body.reservation_provenance_id !== 'string' || !body.reservation_provenance_id) {
        return 'malformed_credential_use_reservation_provenance';
      }
      if (!/^[0-9a-f]{64}$/.test(String(body.reservation_mutation_hash || ''))) {
        return 'malformed_credential_use_reservation_mutation';
      }
      if (!/^[0-9a-f]{64}$/.test(String(body.outcome_hash || ''))) return 'malformed_credential_use_outcome_hash';
    }
    return null;
  }

  async function readVerifiedSlotChain(slotId, client = null) {
    const run = runner(client);
    const [chainResult, masterResult] = await Promise.all([
      run(
        `SELECT lifecycle.provenance_id, lifecycle.service_name, lifecycle.slot_id,
                lifecycle.event_type, lifecycle.agent_id,
                lifecycle.agent_valid_from, lifecycle.cert_fingerprint,
                lifecycle.identity_tier, lifecycle.proof_version, lifecycle.body_json,
                lifecycle.content_hash, lifecycle.mutation_hash,
                lifecycle.prev_mutation_hash, lifecycle.ts_signed,
                lifecycle.nonce, lifecycle.sig, lifecycle.is_genesis,
                lifecycle.created_at, identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed
           FROM aimos_credential_lifecycle lifecycle
           JOIN agent_identity identity
             ON identity.agent_id = lifecycle.agent_id
            AND identity.valid_from = lifecycle.agent_valid_from
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE lifecycle.slot_id = $1`,
        [slotId],
      ),
      run('SELECT master_pubkey FROM aimos_master_identity WHERE id = 1'),
    ]);
    return verifyCredentialLifecycleChain(chainResult.rows || [], masterResult.rows?.[0]?.master_pubkey || null);
  }

  async function getLatestMutationHash(slotId, client = null) {
    const verified = await readVerifiedSlotChain(slotId, client);
    return verified.rowCount
      ? { prevMutationHash: verified.mutationHash, isGenesis: false, verified }
      : { prevMutationHash: null, isGenesis: true, verified };
  }

  function validateAppendAgainstChain(body, eventType, verified) {
    if (eventType === 'USE_RESERVED') {
      const effective = verified.effectiveStore;
      const effectiveBody = effective ? bodyOf(effective) : null;
      if (
        !effective
        || body.credential_hash !== effectiveBody?.credential_hash
        || body.effective_provenance_id !== String(effective.provenance_id)
        || body.effective_mutation_hash !== Buffer.from(effective.mutation_hash).toString('hex')
      ) return 'credential_use_effective_store_mismatch';
    }
    if (USE_TERMINAL_TYPES.has(eventType)) {
      const reservation = verified.openCredentialUses.find(
        (row) => bodyOf(row)?.use_id === body.use_id,
      );
      if (
        !reservation
        || body.reservation_provenance_id !== String(reservation.provenance_id)
        || body.reservation_mutation_hash !== Buffer.from(reservation.mutation_hash).toString('hex')
        || body.credential_hash !== bodyOf(reservation)?.credential_hash
      ) return 'credential_use_open_reservation_mismatch';
    }
    return null;
  }

  async function commitCredentialLifecycle(args) {
    const bad = validate(args);
    if (bad) return { ok: false, reason: bad };
    let authority;
    try { authority = await verifyAuthority(args); }
    catch { authority = { ok: false, reason: 'authority_verification_failed' }; }
    if (!authority?.ok) return { ok: false, reason: authority?.reason || 'authority_verification_failed' };

    const {
      serviceName, slotId, body, agentId, validFromIso, certString,
      signedTs, nonce, sigBytes, identityTier, eventType, bodyJson,
      client = null,
    } = args;
    const conn = client || await pool.connect();
    const ownsTransaction = !client;
    try {
      if (ownsTransaction) await conn.query('BEGIN');
      await conn.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`${slotId.length}:${slotId}:credential-lifecycle`],
      );
      const { prevMutationHash, isGenesis, verified } = await getLatestMutationHash(slotId, conn);
      if (isGenesis && eventType !== 'STORE') throw new Error('credential_genesis_must_store');
      const chainMismatch = validateAppendAgainstChain(body, eventType, verified);
      if (chainMismatch) throw new Error(chainMismatch);
      const cHash = contentHash(body);
      const mutationHash = computeMutationHash(cHash, prevMutationHash, nonce, signedTs);
      const certFingerprint = createHash('sha256').update(String(certString), 'utf8').digest('hex');
      const inserted = await conn.query(
        `INSERT INTO aimos_credential_lifecycle
          (service_name, slot_id, event_type, agent_id, agent_valid_from,
           cert_fingerprint, identity_tier, body_json, content_hash,
           mutation_hash, prev_mutation_hash, ts_signed, nonce, sig, is_genesis)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING provenance_id, created_at`,
        [
          serviceName, slotId, eventType, agentId, validFromIso,
          certFingerprint, identityTier, JSON.stringify(bodyJson), cHash,
          mutationHash, prevMutationHash, signedTs, nonce, sigBytes, isGenesis,
        ],
      );
      if (ownsTransaction) await conn.query('COMMIT');
      return {
        ok: true,
        provenanceId: inserted.rows?.[0]?.provenance_id || null,
        createdAt: inserted.rows?.[0]?.created_at || null,
        contentHash: cHash,
        mutationHash,
        prevMutationHash,
        isGenesis,
      };
    } catch (error) {
      if (ownsTransaction) {
        try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
      }
      if (error?.code === '23505') return { ok: false, reason: 'fork_race' };
      if (String(error?.message || '').startsWith('credential_')) {
        return { ok: false, reason: String(error.message) };
      }
      throw error;
    } finally {
      if (ownsTransaction) conn.release();
    }
  }

  async function getLifecycleRow(provenanceId) {
    const locator = await queryFn(
      'SELECT slot_id FROM aimos_credential_lifecycle WHERE provenance_id = $1',
      [provenanceId],
    );
    if (!locator.rows[0]) return null;
    const verified = await readVerifiedSlotChain(locator.rows[0].slot_id);
    return verified.rows.find((row) => String(row.provenance_id) === String(provenanceId)) || null;
  }

  async function getSlotChain(slotId, limit = 100) {
    const verified = await readVerifiedSlotChain(slotId);
    return verified.rows.slice(-Math.max(1, Math.min(Number(limit) || 100, 10000))).reverse();
  }

  async function getLatestStoreForSlot(slotId) {
    return (await readVerifiedSlotChain(slotId)).effectiveStore;
  }

  async function verifyCredentialLifecycle(row) {
    if (!row?.slot_id || !row?.provenance_id) return { overall_ok: false, reason: 'no_row' };
    try {
      const verified = await readVerifiedSlotChain(row.slot_id);
      const present = verified.rows.some((entry) => String(entry.provenance_id) === String(row.provenance_id));
      return {
        overall_ok: present,
        complete_chain_ok: true,
        chain_length: verified.rowCount,
        effective: Boolean(verified.effectiveStore),
        revoked: verified.revoked,
      };
    } catch (error) {
      return { overall_ok: false, reason: String(error?.message || error) };
    }
  }

  async function reserveCredentialUse({
    serviceName,
    slotId,
    credentialHash,
    effectiveProvenanceId,
    effectiveMutationHash,
    operation,
    endpoint,
    requestHash,
    subjectAgentId = 'housekeeper',
    requestReceiptId = null,
    requestReceiptMutationHash = null,
    requestAdmissionEventId = null,
    requestAdmissionMutationHash = null,
    autonomousActionEventId = null,
    useGroupId = null,
  }) {
    const normalizedEndpoint = String(endpoint || '').trim();
    if (!normalizedEndpoint || normalizedEndpoint.includes('?')) {
      throw new Error('credential_use_endpoint_must_be_credential_free_template');
    }
    const subject = String(subjectAgentId || '').trim();
    const hasReceiptId = Boolean(requestReceiptId);
    const hasReceiptHash = Boolean(requestReceiptMutationHash);
    const hasAdmissionId = Boolean(requestAdmissionEventId);
    const hasAdmissionHash = Boolean(requestAdmissionMutationHash);
    if (hasReceiptId !== hasReceiptHash) {
      throw new Error('credential_use_request_receipt_incomplete');
    }
    if (hasAdmissionId !== hasAdmissionHash || hasReceiptId !== hasAdmissionId) {
      throw new Error('credential_use_request_admission_incomplete');
    }
    let requestAuthority = null;
    let verifiedAdmissionEventId = null;
    if (hasReceiptId) {
      requestAuthority = await verifyRequestAuthority({
        companyId: AIMOS_COMPANY_ID,
        requestReceiptId,
        requestReceiptMutationHash,
        actorAgentId: subject,
      });
      const admission = await verifyAutonomousEvent(
        requestAdmissionEventId,
        AIMOS_COMPANY_ID,
      );
      const admissionMetadata = typeof admission.metadata === 'string'
        ? JSON.parse(admission.metadata)
        : admission.metadata;
      if (
        admission.operation !== 'request_admission_verified'
        || String(admission.key) !== String(requestReceiptId)
        || admission.agent_id !== subject
        || admission.authority_kind !== 'housekeeper_observation_of_verified_request'
        || Buffer.from(admission.mutation_hash || []).toString('hex') !== String(requestAdmissionMutationHash)
        || admissionMetadata?.request_receipt_id !== String(requestReceiptId)
        || admissionMetadata?.request_receipt_mutation_hash !== String(requestReceiptMutationHash)
        || admissionMetadata?.request_hash !== requestAuthority.requestHash
        || admissionMetadata?.actor_agent_id !== subject
        || new Date(admissionMetadata?.actor_valid_from).toISOString() !== requestAuthority.actorValidFromIso
      ) {
        throw new Error('credential_use_request_admission_invalid');
      }
      verifiedAdmissionEventId = String(admission.id);
    } else if (subject !== 'housekeeper') {
      throw new Error('credential_use_non_housekeeper_requires_verified_request');
    }
    let verifiedParentEventId = null;
    if (autonomousActionEventId) {
      const event = await verifyAutonomousEvent(
        autonomousActionEventId,
        AIMOS_COMPANY_ID,
      );
      if (event.signer_agent_id !== 'housekeeper') throw new Error('credential_use_parent_event_invalid');
      verifiedParentEventId = String(event.id || autonomousActionEventId);
    }
    const verified = await readVerifiedSlotChain(slotId);
    const effective = verified.effectiveStore;
    if (
      !effective
      || effective.service_name !== serviceName
      || String(effective.provenance_id) !== String(effectiveProvenanceId)
      || Buffer.from(effective.mutation_hash).toString('hex') !== effectiveMutationHash
      || bodyOf(effective)?.credential_hash !== credentialHash
    ) {
      throw new Error('credential_use_checkout_stale');
    }
    const useId = randomUUID();
    const exactAuthority = await appendAutonomousAuthority(
      AIMOS_COMPANY_ID,
      subject || 'housekeeper',
      'credential_use_authorized',
      useId,
      {
        credential_use_id: useId,
        service: serviceName,
        slot_id: slotId,
        credential_hash: credentialHash,
        effective_provenance_id: String(effectiveProvenanceId),
        effective_mutation_hash: effectiveMutationHash,
        operation: String(operation || '').trim(),
        endpoint: normalizedEndpoint,
        request_hash: requestHash,
        subject_agent_id: subject || 'housekeeper',
        request_receipt_id: requestReceiptId,
        request_receipt_mutation_hash: requestReceiptMutationHash,
        request_admission_event_id: verifiedAdmissionEventId,
        request_admission_mutation_hash: requestAdmissionMutationHash,
        reasoning: 'The housekeeper authorized one exact credential version for one credential-free endpoint template and request-evidence hash.',
      },
      verifiedParentEventId || verifiedAdmissionEventId,
      { returnReceipt: true },
    );
    if (!exactAuthority?.event_id
      || !/^[0-9a-f]{64}$/.test(String(exactAuthority.mutation_hash || ''))) {
      throw new Error('credential_use_exact_authority_unavailable');
    }
    const body = {
      event_type: 'USE_RESERVED',
      service: serviceName,
      slot_id: slotId,
      credential_hash: credentialHash,
      effective_provenance_id: String(effectiveProvenanceId),
      effective_mutation_hash: effectiveMutationHash,
      use_id: useId,
      use_group_id: useGroupId || null,
      operation: String(operation || '').trim(),
      endpoint: normalizedEndpoint,
      request_hash: requestHash,
      subject_agent_id: subject || 'housekeeper',
      signer_agent_id: 'housekeeper',
      authority_kind: requestReceiptId
        ? 'housekeeper_observation_of_verified_request'
        : 'housekeeper_autonomous',
      request_receipt_id: requestReceiptId,
      request_receipt_mutation_hash: requestReceiptMutationHash,
      request_admission_event_id: verifiedAdmissionEventId,
      request_admission_mutation_hash: requestAdmissionMutationHash,
      parent_action_event_id: verifiedParentEventId,
      autonomous_action_event_id: exactAuthority.event_id,
      autonomous_action_mutation_hash: exactAuthority.mutation_hash,
    };
    const signed = await signAsHousekeeper(body);
    const committed = await commitCredentialLifecycle({
      serviceName,
      slotId,
      body: signed.body,
      bodyJson: signed.body,
      agentId: signed.agentId,
      validFromIso: signed.validFromIso,
      certString: signed.certString,
      signedTs: signed.signedTs,
      nonce: signed.nonce,
      sigBytes: signed.sigBytes,
      identityTier: signed.identityTier,
      eventType: 'USE_RESERVED',
    });
    if (!committed.ok) throw new Error(`credential_use_reservation_failed:${committed.reason}`);
    return Object.freeze({
      useId,
      useGroupId: useGroupId || null,
      serviceName,
      slotId,
      credentialHash,
      subjectAgentId: body.subject_agent_id,
      reservationProvenanceId: committed.provenanceId,
      reservationMutationHash: committed.mutationHash.toString('hex'),
    });
  }

  async function finalizeCredentialUse({
    reservation,
    outcome,
    outcomeHash,
    outcomeClass = null,
    errorClass = null,
  }) {
    if (!reservation?.useId || !['completed', 'failed'].includes(outcome)) {
      throw new Error('credential_use_terminal_malformed');
    }
    const eventType = outcome === 'completed' ? 'USE_COMPLETED' : 'USE_FAILED';
    const body = {
      event_type: eventType,
      service: reservation.serviceName,
      slot_id: reservation.slotId,
      credential_hash: reservation.credentialHash,
      use_id: reservation.useId,
      use_group_id: reservation.useGroupId || null,
      reservation_provenance_id: reservation.reservationProvenanceId,
      reservation_mutation_hash: reservation.reservationMutationHash,
      outcome_hash: outcomeHash,
      outcome_class: String(outcomeClass || (outcome === 'completed' ? 'completed' : 'failed')),
      error_class: outcome === 'failed' ? String(errorClass || 'external_operation_failed') : null,
      subject_agent_id: reservation.subjectAgentId,
      signer_agent_id: 'housekeeper',
    };
    const findMatchingTerminal = async () => {
      const verified = await readVerifiedSlotChain(reservation.slotId);
      const terminals = verified.rows.filter((row) => (
        (row.event_type === 'USE_COMPLETED' || row.event_type === 'USE_FAILED')
        && bodyOf(row)?.use_id === reservation.useId
      ));
      if (terminals.length > 1) throw new Error('credential_use_terminal_fork');
      if (!terminals.length) return null;
      const existing = terminals[0];
      const existingBody = bodyOf(existing);
      if (
        existing.event_type !== eventType
        || existing.service_name !== reservation.serviceName
        || existing.slot_id !== reservation.slotId
        || existingBody?.credential_hash !== reservation.credentialHash
        || String(existingBody?.reservation_provenance_id) !== String(reservation.reservationProvenanceId)
        || existingBody?.reservation_mutation_hash !== reservation.reservationMutationHash
        || existingBody?.outcome_hash !== outcomeHash
        || existingBody?.outcome_class !== body.outcome_class
        || existingBody?.error_class !== body.error_class
        || existingBody?.subject_agent_id !== reservation.subjectAgentId
      ) {
        throw new Error('credential_use_terminal_conflict');
      }
      return Object.freeze({
        useId: reservation.useId,
        outcome,
        terminalProvenanceId: existing.provenance_id,
        terminalMutationHash: Buffer.from(existing.mutation_hash).toString('hex'),
      });
    };
    const existing = await findMatchingTerminal();
    if (existing) return existing;
    const signed = await signAsHousekeeper(body);
    const committed = await commitCredentialLifecycle({
      serviceName: reservation.serviceName,
      slotId: reservation.slotId,
      body: signed.body,
      bodyJson: signed.body,
      agentId: signed.agentId,
      validFromIso: signed.validFromIso,
      certString: signed.certString,
      signedTs: signed.signedTs,
      nonce: signed.nonce,
      sigBytes: signed.sigBytes,
      identityTier: signed.identityTier,
      eventType,
    });
    if (!committed.ok) {
      if (committed.reason === 'fork_race') {
        const raced = await findMatchingTerminal();
        if (raced) return raced;
      }
      throw new Error(`credential_use_terminal_failed:${committed.reason}`);
    }
    return Object.freeze({
      useId: reservation.useId,
      outcome,
      terminalProvenanceId: committed.provenanceId,
      terminalMutationHash: committed.mutationHash.toString('hex'),
    });
  }

  return {
    commitCredentialLifecycle,
    verifyCredentialLifecycle,
    readVerifiedSlotChain,
    getLifecycleRow,
    getSlotChain,
    getLatestStoreForSlot,
    getLatestMutationHash,
    reserveCredentialUse,
    finalizeCredentialUse,
  };
}

export const credentialLedger = createCredentialLedger();

export default {
  credentialLedger,
  createCredentialLedger,
  verifyCredentialLifecycleChain,
  credentialUseEvidenceHash,
};
