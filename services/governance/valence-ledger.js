// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (substrate) — appendValence called from stdp-kernel.js
// applyRewardSignal inside the same restricted transaction as the weight
// mutation and its provenance. The judge (valence-judge.js) reads from this
// ledger; the governors consume that signed, age-neutral evidence.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * valence-ledger.js — append-only valence ledger writer (Aimos-2 / Paper 2)
 *
 * Records every reward signal applied to a memory:
 *   (memory_id, reward_sign, context_hash, prev_hash, row_hash, signature)
 *
 * Aladdin Law: append-only. No UPDATE/DELETE path. "The synapse changes.
 * The neuron persists." Memory of valence is itself a memory — never deleted.
 *
 * Substrate for the tanh judge (valence-judge.js) which feeds the cognitive
 * governors (Cohen-Grossberg bounded energy, Oja bounded normalization, and
 * the signed reference-point update). Without this ledger, the system has no valence
 * memory — rewardSign = ±1 is applied at stdp-kernel.js:285 then the sign
 * is lost. With it, the judge computes cumulative signed valence over all
 * retained evidence, and the governors can do dynamic mutation good↔bad.
 *
 * Scale: the ledger grows monotonically. The judge aggregates all retained
 * positive and negative evidence by sign; time is not a coefficient and no
 * event ages out of influence.
 *
 * Dependency-injected like memory-provenance.js so tests use a mock pool.
 */

import { createHash } from 'node:crypto';
import { pool as defaultPool } from '../../db/connection.js';
import {
  canonicalJson,
  verifyCertChain,
  verifyStoredPayloadSig,
} from '../security/agent-identity.js';
import {
  detectTierFromCert,
  extractValidFromIso,
  getHousekeeperCert,
  signAsHousekeeper,
} from '../security/housekeeper-signer.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

export function createValenceLedger(deps = {}) {
  const pool = deps.pool || defaultPool;
  const queryFn = typeof deps.queryFn === 'function'
    ? deps.queryFn
    : ((sql, params = []) => pool.query(sql, params));
  const signer = deps.signer || signAsHousekeeper;

  function rowHash(body, prevHash, nonce, signedTs) {
    const contentHash = createHash('sha256').update(canonicalJson(body), 'utf8').digest();
    const pieces = prevHash
      ? [contentHash, prevHash, Buffer.from(nonce), Buffer.from(String(signedTs))]
      : [contentHash, Buffer.from(nonce), Buffer.from(String(signedTs))];
    return { contentHash, rowHash: createHash('sha256').update(Buffer.concat(pieces)).digest() };
  }

  /**
   * Append one valence event to the ledger.
   *
   * @param {object} args
   * @param {string} args.memoryId — UUID string
   * @param {number} args.rewardSign — +1 or -1
   * @param {string} [args.contextHash] — optional hash of recall context
   * @returns {Promise<{ ok: true, id: number } | { ok: false, reason: string }>}
   */
  async function appendValence({
    memoryId,
    rewardSign,
    contextHash = null,
    attribution = null,
    outcomeReceipt = null,
    client = null,
  } = {}) {
    if (typeof memoryId !== 'string' || memoryId.length === 0) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (rewardSign !== 1 && rewardSign !== -1) {
      return { ok: false, reason: 'malformed_input' };
    }
    if (!client || typeof client.query !== 'function') {
      return { ok: false, reason: 'transaction_client_required' };
    }
    const evidenceVersion = attribution == null ? 1 : 2;
    if (evidenceVersion === 2 && (!outcomeReceipt?.event_id
        || !/^[0-9a-f]{64}$/.test(String(outcomeReceipt.mutation_hash || ''))
        || attribution.memory_id !== memoryId)) {
      return { ok: false, reason: 'mutation_outcome_attribution_invalid' };
    }

    try {
      const certString = await getHousekeeperCert();
      const signerValidFrom = extractValidFromIso(certString);
      const certFingerprint = createHash('sha256').update(certString, 'utf8').digest('hex');
      const identityTier = detectTierFromCert(certString);
      const body = {
        event_type: 'VALENCE',
        memory_id: memoryId,
        company_id: AIMOS_COMPANY_ID,
        reward_sign: rewardSign,
        context_hash: contextHash || null,
        signer_agent_id: 'housekeeper',
        signer_valid_from: signerValidFrom,
        cert_fingerprint: certFingerprint,
        identity_tier: identityTier,
        ...(evidenceVersion === 2 ? {
          evidence_schema: 'hom.aimos.mutation-outcome-evidence/v2',
          target_scope: attribution.target_scope,
          target_live_content_hash: attribution.live_content_hash,
          target_occurrence_ref: attribution.occurrence_ref,
          recall_event_id: attribution.recall_event_id,
          recall_event_mutation_hash: attribution.recall_event_mutation_hash,
          recall_merkle_root: attribution.recall_merkle_root,
          security_closure_sha256: attribution.security_closure_sha256,
          outcome_id: attribution.outcome_id,
          outcome_event_id: outcomeReceipt.event_id,
          outcome_event_mutation_hash: outcomeReceipt.mutation_hash,
        } : {}),
      };
      const signed = await signer(body);
      if (
        signed.agentId !== body.signer_agent_id
        || new Date(signed.validFromIso).toISOString() !== signerValidFrom
        || signed.certString !== certString
        || signed.identityTier !== identityTier
      ) {
        return { ok: false, reason: 'signer_identity_mismatch' };
      }
      const previous = await client.query(
        `SELECT row_hash FROM memory_valence_ledger
          WHERE memory_id = $1 ORDER BY id DESC LIMIT 1`,
        [memoryId]
      );
      const prevHash = previous?.rows?.[0]?.row_hash || null;
      const hashes = rowHash(signed.body, prevHash, signed.nonce, signed.signedTs);
      const r = await client.query(
        `INSERT INTO memory_valence_ledger
           (memory_id, company_id, reward_sign, context_hash, body_json,
            content_hash, prev_hash, row_hash, ts_signed, nonce, sig,
            signer_agent_id, signer_valid_from, cert_fingerprint, identity_tier,
            evidence_schema_version,target_scope,target_live_content_hash,
            target_occurrence_ref,recall_event_id,recall_event_mutation_hash,
            recall_merkle_root,security_closure_hash,outcome_id,outcome_event_id,
            outcome_event_mutation_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                 $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
         RETURNING id`,
        [
          memoryId, AIMOS_COMPANY_ID, rewardSign, contextHash || null,
          JSON.stringify(signed.body), hashes.contentHash, prevHash, hashes.rowHash,
          signed.signedTs, signed.nonce, signed.sigBytes,
          signed.agentId, signed.validFromIso, certFingerprint, signed.identityTier,
          evidenceVersion,
          evidenceVersion === 2 ? attribution.target_scope : null,
          evidenceVersion === 2 ? Buffer.from(attribution.live_content_hash, 'hex') : null,
          evidenceVersion === 2 ? Buffer.from(attribution.occurrence_ref, 'hex') : null,
          evidenceVersion === 2 ? attribution.recall_event_id : null,
          evidenceVersion === 2 ? Buffer.from(attribution.recall_event_mutation_hash, 'hex') : null,
          evidenceVersion === 2 ? Buffer.from(attribution.recall_merkle_root, 'hex') : null,
          evidenceVersion === 2 ? Buffer.from(attribution.security_closure_sha256, 'hex') : null,
          evidenceVersion === 2 ? attribution.outcome_id : null,
          evidenceVersion === 2 ? outcomeReceipt.event_id : null,
          evidenceVersion === 2 ? Buffer.from(outcomeReceipt.mutation_hash, 'hex') : null,
        ]
      );
      const id = r?.rows?.[0]?.id;
      if (!(typeof id === 'number' || /^\d+$/.test(String(id || '')))) {
        return { ok: false, reason: 'no_row_returned' };
      }
      return { ok: true, id: Number(id), rowHash: hashes.rowHash, prevHash, contentHash: hashes.contentHash };
    } catch (err) {
      if (err?.code === '23503') {
        return { ok: false, reason: 'foreign_key_violation' };
      }
      throw err;
    }
  }

  /**
   * Read all reward evidence for a memory. Evidence never loses influence merely
   * because time passed; aggregation happens in SQL to keep the read bounded.
   *
   * @param {string} memoryId
   * @param {object} [opts]
   * @returns {Promise<Array<{ reward_sign: number, evidence_count: number }>>}
   */
  async function readValenceEvents(memoryId, opts = {}) {
    const run = opts.client && typeof opts.client.query === 'function'
      ? opts.client.query.bind(opts.client)
      : queryFn;
    const r = await run(
      `SELECT reward_sign, COUNT(*)::int AS evidence_count
         FROM memory_valence_ledger
        WHERE memory_id = $1
          AND (evidence_schema_version=1 OR target_scope='principal_state')
        GROUP BY reward_sign
        ORDER BY reward_sign`,
      [memoryId]
    );
    return r?.rows || [];
  }

  /**
   * Diagnostic: count of valence events for a memory.
   *
   * @param {string} memoryId
   * @returns {Promise<number>}
   */
  async function countValenceEvents(memoryId) {
    const r = await queryFn(
      `SELECT COUNT(*)::int AS n FROM memory_valence_ledger WHERE memory_id = $1`,
      [memoryId]
    );
    return r?.rows?.[0]?.n || 0;
  }

  async function verifyValenceChain(memoryId, { masterPubkey = null, client = null } = {}) {
    const run = client && typeof client.query === 'function'
      ? client.query.bind(client)
      : queryFn;
    const r = await run(
      `SELECT ledger.id, ledger.memory_id, ledger.company_id, ledger.reward_sign,
              ledger.context_hash, ledger.body_json, ledger.content_hash,
              ledger.prev_hash, ledger.row_hash, ledger.ts_signed, ledger.nonce,
              ledger.sig, ledger.proof_required, ledger.signer_agent_id,
              ledger.signer_valid_from, ledger.cert_fingerprint,
              ledger.identity_tier, identity.pubkey, identity.cert,
              ledger.evidence_schema_version,ledger.target_scope,
              ledger.target_live_content_hash,ledger.target_occurrence_ref,
              ledger.recall_event_id,ledger.recall_event_mutation_hash,
              ledger.recall_merkle_root,ledger.security_closure_hash,
              ledger.outcome_id,ledger.outcome_event_id,
              ledger.outcome_event_mutation_hash,
              revocation.ts_signed AS revocation_ts_signed
         FROM memory_valence_ledger ledger
         LEFT JOIN agent_identity identity
           ON identity.agent_id = ledger.signer_agent_id
          AND identity.valid_from = ledger.signer_valid_from
         LEFT JOIN aimos_agent_revocation_events revocation
           ON revocation.agent_id = identity.agent_id
          AND revocation.agent_valid_from = identity.valid_from
        WHERE ledger.memory_id = $1
        ORDER BY ledger.id`,
      [memoryId]
    );
    let previous = null;
    let legacyRows = 0;
    for (const row of r?.rows || []) {
      if (row.proof_required !== true && (!row.body_json || !row.row_hash)) {
        legacyRows += 1;
        continue;
      }
      const body = typeof row.body_json === 'string' ? JSON.parse(row.body_json) : row.body_json;
      const hashes = rowHash(body, previous, row.nonce, Number(row.ts_signed));
      if (!Buffer.from(row.content_hash).equals(hashes.contentHash)
        || !Buffer.from(row.row_hash).equals(hashes.rowHash)
        || (previous ? !Buffer.from(row.prev_hash || []).equals(previous) : row.prev_hash !== null)) {
        return { ok: false, failedId: row.id };
      }
      if (row.proof_required !== true) {
        legacyRows += 1;
        previous = Buffer.from(row.row_hash);
        continue;
      }
      let certBody = null;
      try {
        certBody = JSON.parse(Buffer.from(String(row.cert || ''), 'base64url').toString('utf8'))?.body || null;
      } catch { /* handled by the exact identity check below */ }
      const certFingerprint = createHash('sha256').update(String(row.cert || ''), 'utf8').digest('hex');
      if (
        !body
        || !certBody
        || body.memory_id !== row.memory_id
        || body.company_id !== row.company_id
        || Number(body.reward_sign) !== Number(row.reward_sign)
        || body.context_hash !== (row.context_hash || null)
        || body.signer_agent_id !== row.signer_agent_id
        || new Date(body.signer_valid_from).toISOString() !== new Date(row.signer_valid_from).toISOString()
        || body.cert_fingerprint !== row.cert_fingerprint
        || body.identity_tier !== row.identity_tier
        || certBody.agent_id !== row.signer_agent_id
        || certBody.pubkey !== row.pubkey
        || certFingerprint !== row.cert_fingerprint
      ) {
        return { ok: false, failedId: row.id, reason: 'identity_or_body_mismatch' };
      }
      if (Number(row.evidence_schema_version || 1) === 2) {
        const exactAttribution = body.evidence_schema === 'hom.aimos.mutation-outcome-evidence/v2'
          && body.target_scope === row.target_scope
          && body.target_live_content_hash === Buffer.from(row.target_live_content_hash || []).toString('hex')
          && body.target_occurrence_ref === Buffer.from(row.target_occurrence_ref || []).toString('hex')
          && body.recall_event_id === String(row.recall_event_id)
          && body.recall_event_mutation_hash === Buffer.from(row.recall_event_mutation_hash || []).toString('hex')
          && body.recall_merkle_root === Buffer.from(row.recall_merkle_root || []).toString('hex')
          && body.security_closure_sha256 === Buffer.from(row.security_closure_hash || []).toString('hex')
          && body.outcome_id === String(row.outcome_id)
          && body.outcome_event_id === String(row.outcome_event_id)
          && body.outcome_event_mutation_hash === Buffer.from(row.outcome_event_mutation_hash || []).toString('hex');
        if (!exactAttribution) {
          return { ok: false, failedId: row.id, reason: 'mutation_outcome_attribution_mismatch' };
        }
      }
      const certAuthority = certBody.issuer === row.signer_agent_id ? row.pubkey : masterPubkey;
      if (!certAuthority) return { ok: false, failedId: row.id, reason: 'master_identity_missing' };
      const certProof = verifyCertChain(row.cert, certAuthority, { nowFn: () => Number(row.ts_signed) });
      if (!certProof.valid) return { ok: false, failedId: row.id, reason: certProof.reason };
      const signedRevocationAt = row.revocation_ts_signed == null ? null : Number(row.revocation_ts_signed);
      if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= Number(row.ts_signed)) {
        return { ok: false, failedId: row.id, reason: 'signer_revoked_at_signature_time' };
      }
      const verified = verifyStoredPayloadSig(
        row.pubkey,
        body,
        row.nonce,
        Number(row.ts_signed),
        Buffer.from(row.sig).toString('base64url')
      );
      if (!verified.valid) return { ok: false, failedId: row.id, reason: 'signature_invalid' };
      previous = Buffer.from(row.row_hash);
    }
    return { ok: true, length: r?.rows?.length || 0, legacyRows, head: previous };
  }

  return { appendValence, readValenceEvents, countValenceEvents, verifyValenceChain };
}

export const valenceLedger = createValenceLedger();

export default { valenceLedger, createValenceLedger };
