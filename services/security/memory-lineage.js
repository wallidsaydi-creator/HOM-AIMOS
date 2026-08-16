// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — POST /aimos/lineage endpoint calls commitLineage after the
// cert-envelope auth-tier validates the request. The /aimos/lineage route is
// a sibling to /save; both use the same cert-envelope auth middleware. The
// lineage ledger records the cross-memory derivation DAG (horizontal); the
// provenance ledger (memory-provenance.js) records a memory's mutations
// (vertical). Phase 4 wires only the D3 'agent_reasoning' path.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * memory-lineage.js — cross-memory derivation DAG (Phase 4)
 *
 * Each row records "memory `child_id` was derived from {parent_ids...} by
 * `derivation_type`." Sibling to the provenance ledger. The two ledgers
 * share the vertex set (memory_id) but encode different graphs:
 *   . provenance  — linked-list per memory_id (prev_mutation_hash)
 *   . lineage     — DAG across memory_ids (parent_ids[])
 *
 * ── Wiring shape (Option C — separate endpoint) ──────────────────────────────
 *
 * The D3 'agent_reasoning' sig must cryptographically bind child_id to
 * parent_ids, but child_id is only assigned by persistMemory at save time.
 * A two-phase protocol resolves the chicken-and-egg:
 *
 *   Phase 1 — POST /save with body containing parent_memory_ids and the
 *             derived memory's value. Server persists the memory, returns
 *             saved.id in the response. Provenance row committed here.
 *             NO lineage row yet.
 *
 *   Phase 2 — POST /aimos/lineage with body = {child_id, parent_ids,
 *             derivation_type} and standard cert-envelope auth headers
 *             (cert, sig, nonce, timestamp). The auth-tier validates the
 *             sig over canonicalJson(body)+'\n'+nonce+'\n'+String(ts) —
 *             the SAME signed-message form the envelope and provenance
 *             ledgers use. Server extracts validated sigBytes, persists
 *             the D3 lineage row.
 *
 * The sig binds child_id (now known) cryptographically to parent_ids. If
 * the same signed bytes were replayed for a different child_id, the
 * canonical form would differ (child_id differs) and the auth-tier sig
 * would not verify — replay-proof by construction.
 *
 * ── Canonical form (for SIGN and VERIFY) ─────────────────────────────────────
 *
 *   body        = {child_id: <uuid-string>, parent_ids: <uuid-string-array>,
 *                  derivation_type: 'agent_reasoning'}
 *   signedMsg   = canonicalJson(body) + '\n' + nonce + '\n' + String(ts_signed)
 *
 * Exactly three body fields. Sort parent_ids ascending by string compare
 * via sortParentIds (helper export) before signing so the verifier
 * reproduces an equivalent canonical form. RFC 8783 JCS does NOT sort
 * array elements; this rule is a harness/audit convention.
 *
 * ── FK semantics (migration 019) ─────────────────────────────────────────────
 *
 *   . child_id  ON DELETE CASCADE  — lineage row destroyed if child deleted
 *                                    (no audit on non-existent memory)
 *   . parent_id ON DELETE SET NULL — lineage row preserved if parent deleted;
 *                                    parent_ids[] retains the orphaned UUID
 *                                    as audit record
 *
 * UNIQUE(child_id, derivation_type, ts_signed) from migration 019 — prevents
 * duplicate D3 events for the same (child, derivation, ts). NULLs-distinct
 * for D1 rows; this constraint only fires for D3 (ts_signed NOT NULL).
 *
 * ── Phase 4 scope: ONLY 'agent_reasoning'. D1 (structural, sig=NULL) and
 * D2 (server-attested) are written by the 020 backfill and future Phase 5
 * code paths. Commit-ting any other derivation_type returns
 * 'derivation_type_not_wired_in_phase4'. ─────────────────────────────────────
 *
 * Dependency-injected like save-envelope.js / memory-provenance.js.
 */

import { createHash } from 'node:crypto';
import {
  canonicalJson,
  resolveCertificateAuthorityPubkey,
  verifyCertChain,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import { contentHash } from './identity-chain.js';
import { signAsHousekeeper } from './housekeeper-signer.js';
import { pool as defaultPool } from '../../db/connection.js';

const DERIVATION_TYPE_PHASE_4 = 'agent_reasoning';
const ATTESTATION_TIER_D3 = 'D3';
const ATTESTATION_TIER_D2 = 'D2';

export function lineageMutationHash(contentHashBytes, prevMutationHash, nonce, signedTs) {
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(contentHashBytes),
    ...(prevMutationHash ? [Buffer.from(prevMutationHash)] : []),
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ])).digest();
}

function certBody(certString) {
  try {
    const serialized = String(certString || '');
    const parsed = serialized.startsWith('{')
      ? JSON.parse(serialized)
      : JSON.parse(Buffer.from(serialized, 'base64url').toString('utf8'));
    return parsed?.body || parsed;
  } catch {
    return null;
  }
}

export async function commitHousekeeperSupersession({
  client,
  companyId,
  key,
  childId,
  parentId,
  childLiveContentHash,
  parentLiveContentHash,
  supersessionEventId,
  triggerType,
  metadata,
  correction = false,
  attestationReason = 'native_save_commit',
} = {}) {
  if (!client || !companyId || !key || !childId || !parentId
    || !Buffer.isBuffer(childLiveContentHash) || childLiveContentHash.length !== 32
    || !Buffer.isBuffer(parentLiveContentHash) || parentLiveContentHash.length !== 32
    || !Number.isInteger(Number(supersessionEventId))) {
    throw new Error('signed_supersession_lineage_input_invalid');
  }
  const retained = await client.query(
    `SELECT mutation_hash
       FROM aimos_memory_lineage
      WHERE child_id = $1 AND attestation_tier = 'D2'
      LIMIT 1`,
    [childId]
  );
  if (retained.rows[0]) throw new Error('signed_supersession_lineage_already_exists');
  const metadataHash = createHash('sha256')
    .update(canonicalJson(metadata || {}), 'utf8')
    .digest('hex');
  const body = {
    event_type: 'LINEAGE',
    binding_schema_version: 2,
    company_id: companyId,
    key,
    child_id: childId,
    parent_ids: [parentId],
    derivation_type: correction ? 'correct' : 'supersede',
    supersession_event_id: Number(supersessionEventId),
    trigger_type: triggerType,
    supersession_metadata_sha256: metadataHash,
    child_live_content_hash: childLiveContentHash.toString('hex'),
    parent_live_content_hash: parentLiveContentHash.toString('hex'),
    attestation_reason: attestationReason,
    historical_origin_authority_claimed: attestationReason === 'native_save_commit',
  };
  const signed = await signAsHousekeeper(body);
  const cHash = contentHash(signed.body);
  const mutationHash = lineageMutationHash(cHash, null, signed.nonce, signed.signedTs);
  const certFingerprint = createHash('sha256').update(String(signed.certString), 'utf8').digest('hex');
  const inserted = await client.query(
    `INSERT INTO aimos_memory_lineage
       (child_id, parent_id, parent_ids, derivation_type, attestation_tier,
        attesting_agent_id, attesting_agent_valid_from,
        attesting_cert_fingerprint, sig, nonce, ts_signed, backfilled,
        body_json, content_hash, mutation_hash, prev_mutation_hash, is_genesis,
        request_sig_form, signed_method, signed_path, signed_claims,
        binding_schema_version)
     VALUES ($1, $2, ARRAY[$2]::uuid[], $3, $4, $5, $6, $7, $8, $9, $10,
             false, $11::jsonb, $12, $13, NULL, true, $14, NULL, NULL, NULL, 2)
     RETURNING lineage_id`,
    [
      childId,
      parentId,
      body.derivation_type,
      ATTESTATION_TIER_D2,
      signed.agentId,
      signed.validFromIso,
      certFingerprint,
      signed.sigBytes,
      signed.nonce,
      signed.signedTs,
      JSON.stringify(signed.body),
      cHash,
      mutationHash,
      signed.sigForm ?? 1,
    ]
  );
  return Object.freeze({
    lineageId: inserted.rows[0].lineage_id,
    contentHash: cHash,
    mutationHash,
    body: signed.body,
  });
}

export function verifyHousekeeperSupersessionLineage(row = {}) {
  const body = row.body_json && typeof row.body_json === 'object'
    ? row.body_json
    : (() => { try { return JSON.parse(String(row.body_json || '')); } catch { return null; } })();
  if (!body || row.attestation_tier !== ATTESTATION_TIER_D2 || Number(row.binding_schema_version) !== 2) {
    return { valid: false, reason: 'signed_lineage_body_missing' };
  }
  const cHash = contentHash(body);
  if (!Buffer.isBuffer(row.content_hash) || !cHash.equals(row.content_hash)) {
    return { valid: false, reason: 'signed_lineage_content_hash_mismatch' };
  }
  const mutation = lineageMutationHash(cHash, row.prev_mutation_hash, row.nonce, Number(row.ts_signed));
  if (!Buffer.isBuffer(row.mutation_hash) || !mutation.equals(row.mutation_hash)) {
    return { valid: false, reason: 'signed_lineage_mutation_hash_mismatch' };
  }
  if (Boolean(row.is_genesis) !== (row.prev_mutation_hash == null)) {
    return { valid: false, reason: 'signed_lineage_genesis_shape_invalid' };
  }
  const certificate = certBody(row.signer_cert);
  const authority = resolveCertificateAuthorityPubkey({
    certificateBody: certificate,
    subjectPubkey: row.signer_pubkey,
    masterPubkey: row.master_pubkey,
    masterFingerprint: row.master_fingerprint,
  });
  if (!authority) return { valid: false, reason: 'signed_lineage_certificate_issuer_invalid' };
  const certProof = verifyCertChain(row.signer_cert, authority, { nowFn: () => Number(row.ts_signed) });
  const fingerprint = createHash('sha256').update(String(row.signer_cert || ''), 'utf8').digest('hex');
  if (!certProof.valid
    || certificate?.agent_id !== row.attesting_agent_id
    || certificate?.pubkey !== row.signer_pubkey
    || Number(certificate?.valid_from) !== Math.floor(new Date(row.attesting_agent_valid_from).getTime() / 1000)
    || fingerprint !== row.attesting_cert_fingerprint) {
    return { valid: false, reason: certProof.reason || 'signed_lineage_signer_mismatch' };
  }
  const signature = verifyStoredPayloadSig(
    row.signer_pubkey,
    body,
    String(row.nonce || ''),
    Number(row.ts_signed),
    Buffer.from(row.sig || []).toString('base64url'),
  );
  if (!signature.valid) return { valid: false, reason: signature.reason || 'signed_lineage_signature_invalid' };
  const expectedParentHash = row.parent_live_content_hash
    ? Buffer.from(row.parent_live_content_hash).toString('hex')
    : null;
  const expectedChildHash = row.child_live_content_hash
    ? Buffer.from(row.child_live_content_hash).toString('hex')
    : null;
  const metadataHash = createHash('sha256')
    .update(canonicalJson(row.supersession_metadata || {}), 'utf8')
    .digest('hex');
  const exact = body.event_type === 'LINEAGE'
    && body.binding_schema_version === 2
    && body.company_id === row.company_id
    && body.key === row.key
    && body.child_id === String(row.child_id)
    && Array.isArray(body.parent_ids)
    && body.parent_ids.length === 1
    && body.parent_ids[0] === String(row.parent_id)
    && body.derivation_type === row.derivation_type
    && Number(body.supersession_event_id) === Number(row.supersession_event_id)
    && body.trigger_type === row.trigger_type
    && body.supersession_metadata_sha256 === metadataHash
    && body.child_live_content_hash === expectedChildHash
    && body.parent_live_content_hash === expectedParentHash;
  return exact
    ? { valid: true, reason: null, mutationHash: mutation.toString('hex'), body }
    : { valid: false, reason: 'signed_lineage_row_binding_mismatch' };
}

export function sortParentIds(parentIds) {
  if (!Array.isArray(parentIds)) return [];
  return parentIds.slice().sort((a, b) => String(a).localeCompare(String(b)));
}

// ─── buildLineageSignedMessageFor ─────────────────────────────────────────────
// Harness/audit helper: produces the canonical signed-message string for a
// lineage assertion. The agent signs the bytes of this string; the audit
// verifier reproduces the same string from the stored lineage row.
//
// Body shape: {child_id, parent_ids (sorted), derivation_type} — exactly three
// fields, no extras. The auth-tier canonical form is `canonicalJson(body) +
// '\n' + nonce + '\n' + String(ts_signed)` (signed-message form shared with
// envelope + provenance ledgers per agent-identity.js#buildSignedMessage).
export function buildLineageSignedMessageFor({
  child_id,
  parent_ids,
  derivation_type,
  ts_signed,
  nonce
}) {
  if (typeof child_id !== 'string' || child_id.length === 0) {
    throw new Error('buildLineageSignedMessageFor: child_id required (string)');
  }
  if (!Array.isArray(parent_ids) || parent_ids.length === 0) {
    throw new Error('buildLineageSignedMessageFor: parent_ids required (non-empty array)');
  }
  if (typeof derivation_type !== 'string' || derivation_type.length === 0) {
    throw new Error('buildLineageSignedMessageFor: derivation_type required');
  }
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new Error('buildLineageSignedMessageFor: nonce required');
  }
  if (!Number.isInteger(ts_signed) || ts_signed <= 0) {
    throw new Error('buildLineageSignedMessageFor: ts_signed required (positive integer)');
  }
  const body = {
    child_id,
    parent_ids: sortParentIds(parent_ids),
    derivation_type
  };
  return canonicalJson(body) + '\n' + nonce + '\n' + String(ts_signed);
}

export function createMemoryLineageLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));

  function _validate(args) {
    const { childId, parentIds, derivationType, agentId, tsSigned, nonce, sigBytes } = args;
    if (typeof childId !== 'string' || childId.length === 0) return 'malformed_input';
    if (!Array.isArray(parentIds) || parentIds.length === 0) return 'malformed_input';
    if (derivationType !== DERIVATION_TYPE_PHASE_4) return 'derivation_type_not_wired_in_phase4';
    if (typeof agentId !== 'string' || agentId.length === 0) return 'malformed_input';
    if (!Number.isInteger(tsSigned) || tsSigned <= 0) return 'malformed_input';
    if (typeof nonce !== 'string' || nonce.length === 0) return 'malformed_input';
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) return 'malformed_input';
    return null;
  }

  // ─── commitLineage ──────────────────────────────────────────────────────────
  // Called from the /aimos/lineage route AFTER the auth-tier middleware has
  // already validated the cert-envelope sig over the request body. sigBytes
  // is the validated sig for the lineage assertion body {child_id, parent_ids,
  // derivation_type} — passed through auth-tier as req.identitySigBytes.
  //
  // certString is the raw cert header value (same as /save's req.identityCertString).
  // The fingerprint matches the envelope / provenance pattern: sha256(cert)
  // hex — service-side to keep cert-shape uniform across ledgers and avoid
  // polluting routes with crypto imports.
  //
  // Stores the sig in the D3 row. The audit verifier reproduces the canonical
  // body from the row fields and verifies the sig against the agent's pubkey.
  async function commitLineage({
    childId,
    parentIds,
    derivationType,
    agentId,
    certString,
    sigBytes,
    nonce,
    tsSigned
  }) {
    const bad = _validate({ childId, parentIds, derivationType, agentId, tsSigned, nonce, sigBytes });
    if (bad) return { ok: false, reason: bad };

    const certFingerprint = createHash('sha256')
      .update(String(certString || ''), 'utf8')
      .digest('hex');
    const sortedParentIds = sortParentIds(parentIds);
    const parentId = sortedParentIds[0];

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO aimos_memory_lineage
            (child_id, parent_id, parent_ids, derivation_type,
             attestation_tier, attesting_agent_id, attesting_cert_fingerprint,
             sig, nonce, ts_signed, backfilled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)`,
        [
          childId, parentId, sortedParentIds, derivationType,
          ATTESTATION_TIER_D3, agentId, certFingerprint,
          sigBytes, nonce, tsSigned
        ]
      );
      await client.query('COMMIT');
      return {
        ok: true,
        derivationType,
        attestationTier: ATTESTATION_TIER_D3,
        parentIds: sortedParentIds
      };
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      if (err.code === '23505' && err.constraint === 'aimos_memory_lineage_child_deriv_ts_unique') {
        return { ok: false, reason: 'duplicate_d3_event' };
      }
      if (err.code === '23503' && err.constraint === 'aimos_memory_lineage_child_id_fkey') {
        return { ok: false, reason: 'child_id_missing' };
      }
      if (err.code === '23503' && err.constraint === 'aimos_memory_lineage_parent_id_fkey') {
        return { ok: false, reason: 'parent_id_missing' };
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async function getLineageRow(childId, derivationType, tsSigned, { retry = 5, sleepMs = 50 } = {}) {
    for (let i = 0; i < retry; i++) {
      const r = await queryFn(
        `SELECT lineage_id, child_id, parent_id, parent_ids, derivation_type,
                attestation_tier, attesting_agent_id, attesting_cert_fingerprint,
                sig, nonce, ts_signed, backfilled, created_at
           FROM aimos_memory_lineage
          WHERE child_id = $1 AND derivation_type = $2 AND ts_signed = $3`,
        [childId, derivationType, tsSigned]
      );
      if (r && Array.isArray(r.rows) && r.rows.length > 0) return r.rows[0];
      await new Promise(res => setTimeout(res, sleepMs));
    }
    return null;
  }

  async function getLineageByDerivationType(derivationType) {
    const r = await queryFn(
      `SELECT lineage_id, child_id, parent_id, parent_ids, derivation_type,
              attestation_tier, attesting_agent_id, attesting_cert_fingerprint,
              sig, nonce, ts_signed, backfilled, created_at
         FROM aimos_memory_lineage
        WHERE derivation_type = $1
        ORDER BY created_at ASC, lineage_id ASC`,
      [derivationType]
    );
    return r?.rows || [];
  }

  async function getLineageByChild(childId) {
    const r = await queryFn(
      `SELECT lineage_id, child_id, parent_id, parent_ids, derivation_type,
              attestation_tier, attesting_agent_id, attesting_cert_fingerprint,
              sig, nonce, ts_signed, backfilled, created_at
         FROM aimos_memory_lineage
        WHERE child_id = $1
        ORDER BY created_at ASC, lineage_id ASC`,
      [childId]
    );
    return r?.rows || [];
  }

  return { commitLineage, getLineageRow, getLineageByDerivationType, getLineageByChild };
}

export const memoryLineageLedger = createMemoryLineageLedger();
