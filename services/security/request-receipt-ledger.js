// Durable certificate-envelope admission receipts.
//
// Every protected request reserves its actor/epoch nonce before route code can
// act. The original signed body is never persisted here because credential
// requests may contain plaintext secrets; its RFC 8785 digest is retained.
// Technique authority: Crosby & Wallach, "Efficient Data Structures for
// Tamper-Evident Logging" (historical consistency), and Argyraki et al.,
// "Accountability of Things" (durable receipts and continuous hash chains).

import { createHash } from 'node:crypto';
import { agentPool } from '../../db/connection.js';
import {
  canonicalJson,
  verifyCertChain,
  verifyStoredPayloadSigWithContext,
  verifyStoredPayloadSigWithEnvelopeClaims,
} from './agent-identity.js';

const REQUEST_RECEIPT_DOMAIN = Buffer.from('aimos-request-receipt-v1\0', 'utf8');

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sameBytes(left, right) {
  const a = Buffer.from(left || []);
  const b = Buffer.from(right || []);
  return a.length === b.length && a.equals(b);
}

function mutationKey(value, error) {
  const bytes = Buffer.from(value || []);
  if (bytes.length !== 32) throw new Error(error);
  return bytes.toString('hex');
}

/**
 * Derive receipt chronology only from prev_mutation_hash topology. Wall-clock
 * timestamps and generated UUIDs are signed/audited data, not ordering authority.
 */
export function orderRequestReceiptRows(rows = []) {
  if (rows.length === 0) return [];

  const byMutation = new Map();
  const children = new Map();
  const roots = [];
  const referenced = new Set();

  for (const row of rows) {
    const mutation = mutationKey(row.mutation_hash, 'request_receipt_mutation_hash_malformed');
    if (byMutation.has(mutation)) throw new Error('request_receipt_duplicate_mutation_hash');
    byMutation.set(mutation, row);
  }

  for (const row of rows) {
    const mutation = mutationKey(row.mutation_hash, 'request_receipt_mutation_hash_malformed');
    if (row.prev_mutation_hash == null) {
      roots.push(row);
      continue;
    }
    const predecessor = mutationKey(
      row.prev_mutation_hash,
      'request_receipt_predecessor_hash_malformed',
    );
    if (!byMutation.has(predecessor)) {
      throw new Error('request_receipt_chain_link_invalid:disconnected_predecessor');
    }
    if (children.has(predecessor)) throw new Error('request_receipt_fork_detected');
    children.set(predecessor, row);
    referenced.add(predecessor);
    if (predecessor === mutation) throw new Error('request_receipt_cycle_detected');
  }

  if (roots.length === 0) throw new Error('request_receipt_zero_genesis');
  if (roots.length > 1) throw new Error('request_receipt_multiple_genesis');

  const heads = rows.filter((row) => !referenced.has(
    mutationKey(row.mutation_hash, 'request_receipt_mutation_hash_malformed'),
  ));
  if (heads.length === 0) throw new Error('request_receipt_zero_heads');
  if (heads.length > 1) throw new Error('request_receipt_multiple_heads');

  const ordered = [];
  const visited = new Set();
  let current = roots[0];
  while (current) {
    const mutation = mutationKey(current.mutation_hash, 'request_receipt_mutation_hash_malformed');
    if (visited.has(mutation)) throw new Error('request_receipt_cycle_detected');
    visited.add(mutation);
    ordered.push(current);
    current = children.get(mutation) || null;
  }
  if (ordered.length !== rows.length) throw new Error('request_receipt_chain_disconnected');
  if (ordered[ordered.length - 1] !== heads[0]) throw new Error('request_receipt_chain_head_mismatch');
  return ordered;
}

export function requestReceiptMutationHash({
  previousMutationHash = null,
  requestHash,
  claimsHash = null,
  signature,
  method,
  path,
  nonce,
  signedTs,
}) {
  const previous = previousMutationHash ? Buffer.from(previousMutationHash) : Buffer.alloc(32);
  const claims = claimsHash ? Buffer.from(claimsHash) : Buffer.alloc(32);
  return sha256(Buffer.concat([
    REQUEST_RECEIPT_DOMAIN,
    previous,
    Buffer.from(requestHash),
    claims,
    Buffer.from(signature),
    Buffer.from(String(method), 'utf8'),
    Buffer.from(String(path), 'utf8'),
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ]));
}

export function verifyRequestReceiptProof(row, { body, pubkey } = {}) {
  try {
    const requestHash = sha256(Buffer.from(canonicalJson(body || {}), 'utf8'));
    const claims = row.signed_claims == null
      ? null
      : (typeof row.signed_claims === 'string' ? JSON.parse(row.signed_claims) : row.signed_claims);
    const claimsHash = claims == null ? null : sha256(Buffer.from(canonicalJson(claims), 'utf8'));
    const expectedMutation = requestReceiptMutationHash({
      previousMutationHash: row.prev_mutation_hash,
      requestHash,
      claimsHash,
      signature: row.sig,
      method: row.signed_method,
      path: row.signed_path,
      nonce: row.nonce,
      signedTs: Number(row.ts_signed),
    });
    if (
      !sameBytes(requestHash, row.request_hash)
      || !sameBytes(claimsHash, row.signed_claims_hash)
      || !sameBytes(expectedMutation, row.mutation_hash)
    ) {
      return { valid: false, reason: 'request_receipt_hash_mismatch' };
    }
    const signature = Number(row.request_sig_form) === 4
      ? verifyStoredPayloadSigWithEnvelopeClaims(
          pubkey,
          body || {},
          row.signed_method,
          row.signed_path,
          claims,
          row.nonce,
          Number(row.ts_signed),
          Buffer.from(row.sig).toString('base64url'),
        )
      : verifyStoredPayloadSigWithContext(
          pubkey,
          body || {},
          row.signed_method,
          row.signed_path,
          row.nonce,
          Number(row.ts_signed),
          Buffer.from(row.sig).toString('base64url'),
        );
    return signature.valid ? { valid: true, reason: null } : signature;
  } catch {
    return { valid: false, reason: 'request_receipt_malformed' };
  }
}

export function verifyRequestReceiptChain(rows = []) {
  const orderedRows = orderRequestReceiptRows(rows);
  let previous = null;
  let stream = null;
  for (let index = 0; index < orderedRows.length; index += 1) {
    const row = orderedRows[index];
    const rowStream = `${row.company_id}\0${row.actor_agent_id}\0${new Date(row.actor_valid_from).toISOString()}`;
    if (stream === null) stream = rowStream;
    const storedPrevious = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    if (
      rowStream !== stream
      || Boolean(row.is_genesis) !== (index === 0)
      || (index === 0 ? storedPrevious !== null : !sameBytes(storedPrevious, previous))
    ) {
      throw new Error('request_receipt_chain_link_invalid');
    }
    const expected = requestReceiptMutationHash({
      previousMutationHash: previous,
      requestHash: row.request_hash,
      claimsHash: row.signed_claims_hash,
      signature: row.sig,
      method: row.signed_method,
      path: row.signed_path,
      nonce: row.nonce,
      signedTs: Number(row.ts_signed),
    });
    if (!sameBytes(expected, row.mutation_hash)) throw new Error('request_receipt_chain_hash_invalid');
    previous = Buffer.from(row.mutation_hash);
  }
  return { verified: true, rowCount: orderedRows.length, mutationHash: previous, rows: orderedRows };
}

function certificateBody(certString) {
  try {
    return JSON.parse(Buffer.from(String(certString || ''), 'base64url').toString('utf8'))?.body || null;
  } catch {
    return null;
  }
}

/**
 * Re-read an admitted request as causal authority for a later domain action.
 * Request bodies are intentionally not retained because credential requests
 * may contain plaintext secrets. The admission path verified the request
 * signature before this row existed. This later lookup does not pretend to
 * re-run that body-signature check; it verifies the retained actor epoch,
 * certificate, complete receipt topology, exact receipt id, and mutation hash.
 */
export async function readVerifiedRequestReceiptById({
  companyId,
  requestReceiptId,
  requestReceiptMutationHash,
  actorAgentId,
  client = null,
} = {}) {
  const company = String(companyId || '').trim();
  const receiptId = String(requestReceiptId || '').trim();
  const actor = String(actorAgentId || '').trim();
  const expectedMutation = String(requestReceiptMutationHash || '').toLowerCase();
  if (!company || !receiptId || !actor || !/^[0-9a-f]{64}$/.test(expectedMutation)) {
    throw new Error('request_receipt_authority_scope_required');
  }

  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) await conn.query('BEGIN');
    await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
    await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    const locator = await conn.query(
      `SELECT receipt.*, identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed
           FROM aimos_request_receipts receipt
           JOIN agent_identity identity
             ON identity.agent_id = receipt.actor_agent_id
            AND identity.valid_from = receipt.actor_valid_from
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE receipt.request_receipt_id = $1
            AND receipt.company_id = $2
            AND receipt.actor_agent_id = $3`,
      [receiptId, company, actor],
    );
    const stream = await conn.query(
      `SELECT request_receipt_id, company_id, actor_agent_id, actor_valid_from,
                request_sig_form, signed_method, signed_path, signed_claims,
                signed_claims_hash, request_hash, prev_mutation_hash, mutation_hash,
                ts_signed, nonce, sig, is_genesis
           FROM aimos_request_receipts
          WHERE company_id = $1 AND actor_agent_id = $2`,
      [company, actor],
    );
    const master = await conn.query(
      'SELECT master_pubkey FROM aimos_master_identity WHERE id = 1',
    );
    const row = locator.rows[0];
    if (!row) throw new Error('request_receipt_authority_not_found');
    const actorEpoch = new Date(row.actor_valid_from).toISOString();
    const epochRows = stream.rows.filter(
      (entry) => new Date(entry.actor_valid_from).toISOString() === actorEpoch,
    );
    const verified = verifyRequestReceiptChain(epochRows);
    const retained = verified.rows.find(
      (entry) => String(entry.request_receipt_id) === receiptId,
    );
    if (!retained || Buffer.from(retained.mutation_hash).toString('hex') !== expectedMutation) {
      throw new Error('request_receipt_authority_hash_mismatch');
    }
    if (row.revocation_ts_signed != null) {
      throw new Error('request_receipt_actor_epoch_revoked');
    }
    const certBody = certificateBody(row.cert);
    const certFingerprint = sha256(Buffer.from(String(row.cert), 'utf8')).toString('hex');
    if (
      !certBody
      || certBody.agent_id !== actor
      || certBody.pubkey !== row.pubkey
      || certFingerprint !== row.cert_fingerprint
    ) {
      throw new Error('request_receipt_actor_identity_mismatch');
    }
    const authorityPubkey = certBody.issuer === certBody.agent_id
      ? row.pubkey
      : master.rows[0]?.master_pubkey;
    if (!authorityPubkey) throw new Error('request_receipt_master_identity_missing');
    const certProof = verifyCertChain(row.cert, authorityPubkey, {
      nowFn: () => Number(row.ts_signed),
    });
    if (!certProof.valid) throw new Error(`request_receipt_certificate_invalid:${certProof.reason}`);
    if (ownsTransaction) await conn.query('COMMIT');
    return Object.freeze({
      requestReceiptId: receiptId,
      requestReceiptMutationHash: expectedMutation,
      actorAgentId: actor,
      actorValidFromIso: actorEpoch,
      signedMethod: row.signed_method,
      signedPath: row.signed_path,
      requestHash: Buffer.from(row.request_hash).toString('hex'),
    });
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}

export async function reserveVerifiedRequest({
  companyId,
  actorAgentId,
  actorValidFromIso,
  certString,
  pubkey,
  body = {},
  requestSigForm,
  signedMethod,
  signedPath,
  signedClaims = null,
  nonce,
  signedTs,
  sigBytes,
} = {}) {
  if (
    !companyId
    || !actorAgentId
    || !actorValidFromIso
    || !certString
    || !pubkey
    || ![3, 4].includes(Number(requestSigForm))
    || !signedMethod
    || !signedPath
    || !nonce
    || !Number.isInteger(signedTs)
    || !Buffer.isBuffer(sigBytes)
    || sigBytes.length !== 64
  ) {
    throw new Error('verified_request_receipt_input_required');
  }

  const requestHash = sha256(Buffer.from(canonicalJson(body || {}), 'utf8'));
  const claimsHash = signedClaims == null
    ? null
    : sha256(Buffer.from(canonicalJson(signedClaims), 'utf8'));
  const certFingerprint = sha256(Buffer.from(String(certString), 'utf8')).toString('hex');
  const proof = verifyRequestReceiptProof({
    request_hash: requestHash,
    signed_claims_hash: claimsHash,
    signed_claims: signedClaims,
    request_sig_form: requestSigForm,
    signed_method: signedMethod,
    signed_path: signedPath,
    ts_signed: signedTs,
    nonce,
    sig: sigBytes,
    prev_mutation_hash: null,
    mutation_hash: requestReceiptMutationHash({
      requestHash,
      claimsHash,
      signature: sigBytes,
      method: signedMethod,
      path: signedPath,
      nonce,
      signedTs,
    }),
  }, { body, pubkey });
  if (!proof.valid) throw new Error(`request_receipt_signature_invalid:${proof.reason}`);

  const client = await agentPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', String(companyId)]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', String(actorAgentId)]);
    const streamKey = `${String(companyId).length}:${companyId}${String(actorAgentId).length}:${actorAgentId}${new Date(actorValidFromIso).toISOString()}`;
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [streamKey]);
    const identity = await client.query(
      `SELECT 1 FROM agent_identity identity
        WHERE identity.agent_id = $1 AND identity.valid_from = $2
          AND identity.cert = $3 AND identity.pubkey = $4
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events revocation
             WHERE revocation.agent_id = identity.agent_id
               AND revocation.agent_valid_from = identity.valid_from
          )
        FOR SHARE`,
      [actorAgentId, new Date(actorValidFromIso).toISOString(), certString, pubkey],
    );
    if (!identity.rows[0]) throw new Error('request_receipt_actor_epoch_not_active');
    const stream = await client.query(
      `SELECT request_receipt_id, company_id, actor_agent_id, actor_valid_from,
              request_sig_form, signed_method, signed_path, signed_claims,
              signed_claims_hash, request_hash, prev_mutation_hash, mutation_hash,
              ts_signed, nonce, sig, is_genesis
         FROM aimos_request_receipts
        WHERE company_id = $1 AND actor_agent_id = $2 AND actor_valid_from = $3`,
      [companyId, actorAgentId, new Date(actorValidFromIso).toISOString()],
    );
    const verifiedStream = verifyRequestReceiptChain(stream.rows || []);
    const previousMutationHash = verifiedStream.mutationHash;
    const mutationHash = requestReceiptMutationHash({
      previousMutationHash,
      requestHash,
      claimsHash,
      signature: sigBytes,
      method: signedMethod,
      path: signedPath,
      nonce,
      signedTs,
    });
    const inserted = await client.query(
      `INSERT INTO aimos_request_receipts
        (company_id, actor_agent_id, actor_valid_from, cert_fingerprint,
         request_sig_form, signed_method, signed_path, signed_claims,
         signed_claims_hash, request_hash, prev_mutation_hash, mutation_hash,
         ts_signed, nonce, sig, is_genesis)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING request_receipt_id, request_hash, mutation_hash, created_at`,
      [
        companyId, actorAgentId, new Date(actorValidFromIso).toISOString(), certFingerprint,
        Number(requestSigForm), String(signedMethod).toUpperCase(), String(signedPath),
        signedClaims == null ? null : JSON.stringify(signedClaims), claimsHash, requestHash,
        previousMutationHash, mutationHash, signedTs, nonce, sigBytes,
        previousMutationHash === null,
      ],
    );
    await client.query('COMMIT');
    return inserted.rows[0];
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    if (error.code === '23505') {
      const replay = new Error('request_replay_detected');
      replay.code = 'AIMOS_REQUEST_REPLAY';
      throw replay;
    }
    throw error;
  } finally {
    client.release();
  }
}

export default {
  reserveVerifiedRequest,
  readVerifiedRequestReceiptById,
  verifyRequestReceiptProof,
  verifyRequestReceiptChain,
};
