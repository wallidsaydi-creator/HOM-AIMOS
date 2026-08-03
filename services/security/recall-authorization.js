// Native master authority for ordinary-agent memory read/write clearance.
// Generic actor-signed permissions are deliberately insufficient: every grant
// or revoke here is signed by the enrolled master and bound to one agent epoch.
// Chain order follows Traceability Through a Cryptographic Ledger, §3.3:
// prev_mutation_hash topology is authority; timestamps and UUIDs are metadata.

import { createHash, randomBytes } from 'node:crypto';
import { pool as defaultPool } from '../../db/connection.js';
import { canonicalJson, signPayload, verifyStoredPayloadSig } from './agent-identity.js';

export const RECALL_AUTHORIZATION_SCHEMA = 'hom.aimos.recall-authorization/v1';
const RECALL_AUTHORIZATION_DOMAIN = Buffer.from('aimos-recall-authorization-v1\0', 'utf8');
const DATA_CLASS_ORDER = Object.freeze(['public', 'internal', 'confidential', 'restricted']);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function normalizeDataClass(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!DATA_CLASS_ORDER.includes(normalized)) throw new Error('recall_data_class_invalid');
  return normalized;
}

function normalizeReason(value) {
  const reason = String(value || '').trim();
  if (!reason || reason.length > 500) throw new Error('recall_authorization_reason_invalid');
  return reason;
}

export function recallAuthorizationMutationHash(prevMutationHash, contentHash, nonce, signedTs) {
  const prev = prevMutationHash ? Buffer.from(prevMutationHash) : Buffer.alloc(32);
  if (prev.length !== 32 || !Buffer.isBuffer(contentHash) || contentHash.length !== 32) {
    throw new Error('recall_authorization_hash_input_invalid');
  }
  return sha256(Buffer.concat([
    RECALL_AUTHORIZATION_DOMAIN,
    prev,
    contentHash,
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ]));
}

export function createRecallAuthorizationProof(masterPrivkeyB64u, {
  companyId,
  subjectAgentId,
  subjectValidFrom,
  allowed,
  writeAllowed = false,
  clearanceCeiling,
  dataClassCeiling,
  masterFingerprint,
  reason,
  prevMutationHash = null,
}, opts = {}) {
  const company = String(companyId || '').trim();
  const subject = String(subjectAgentId || '').trim();
  const validFrom = new Date(subjectValidFrom).toISOString();
  const clearance = Number(clearanceCeiling);
  if (!company || !subject || !Number.isInteger(clearance) || clearance < 0 || clearance > 12) {
    throw new Error('recall_authorization_input_invalid');
  }
  const signedTs = Number.isInteger(opts.signedTs) ? opts.signedTs : Math.floor(Date.now() / 1000);
  const nonce = opts.nonce || randomBytes(16).toString('base64url');
  const normalizedDataClass = normalizeDataClass(dataClassCeiling);
  const body = {
    schema: RECALL_AUTHORIZATION_SCHEMA,
    company_id: company,
    subject_agent_id: subject,
    subject_valid_from: validFrom,
    allowed: Boolean(allowed),
    write_allowed: Boolean(writeAllowed),
    clearance_ceiling: clearance,
    data_class_ceiling: normalizedDataClass,
    master_fingerprint: String(masterFingerprint || ''),
    reason: normalizeReason(reason),
    prev_mutation_hash: prevMutationHash ? Buffer.from(prevMutationHash).toString('hex') : null,
    ts_signed: signedTs,
  };
  if (!/^[0-9a-f]{64}$/.test(body.master_fingerprint)) {
    throw new Error('recall_master_fingerprint_invalid');
  }
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = recallAuthorizationMutationHash(prevMutationHash, contentHash, nonce, signedTs);
  const sigBytes = Buffer.from(signPayload(masterPrivkeyB64u, body, nonce, signedTs), 'base64url');
  return { body, contentHash, mutationHash, prevMutationHash, signedTs, nonce, sigBytes };
}

export function verifyRecallAuthorizationProof(row, masterPubkeyB64u) {
  try {
    const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
    const prev = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationHash = recallAuthorizationMutationHash(prev, contentHash, row.nonce, Number(row.ts_signed));
    const exact = body?.schema === RECALL_AUTHORIZATION_SCHEMA
      && body.company_id === row.company_id
      && body.subject_agent_id === row.subject_agent_id
      && new Date(body.subject_valid_from).toISOString() === new Date(row.subject_valid_from).toISOString()
      && Boolean(body.allowed) === Boolean(row.allowed)
      && Boolean(body.write_allowed) === Boolean(row.write_allowed)
      && Number(body.clearance_ceiling) === Number(row.clearance_ceiling)
      && body.data_class_ceiling === row.data_class_ceiling
      && body.master_fingerprint === row.master_fingerprint
      && Number(body.ts_signed) === Number(row.ts_signed)
      && body.prev_mutation_hash === (prev ? prev.toString('hex') : null)
      && Boolean(row.is_genesis) === !prev
      && Buffer.from(row.content_hash).equals(contentHash)
      && Buffer.from(row.mutation_hash).equals(mutationHash);
    if (!exact) return { valid: false, reason: 'recall_authorization_row_mismatch' };
    const signature = verifyStoredPayloadSig(
      masterPubkeyB64u,
      body,
      String(row.nonce),
      Number(row.ts_signed),
      Buffer.from(row.sig).toString('base64url'),
    );
    return signature.valid ? { valid: true, reason: null } : signature;
  } catch {
    return { valid: false, reason: 'recall_authorization_malformed' };
  }
}

export function verifyRecallAuthorizationChain(rows = []) {
  if (!rows.length) throw new Error('recall_authorization_chain_head_invalid');
  const byMutationHash = new Map();
  const childByPredecessor = new Map();
  const referencedPredecessors = new Set();
  const genesis = [];

  for (const row of rows) {
    const mutationHash = Buffer.from(row.mutation_hash || []);
    if (mutationHash.length !== 32) throw new Error('recall_authorization_chain_hash_malformed');
    const mutationKey = mutationHash.toString('hex');
    if (byMutationHash.has(mutationKey)) throw new Error('recall_authorization_chain_mutation_duplicate');
    byMutationHash.set(mutationKey, row);
    if (!row.prev_mutation_hash) {
      genesis.push(row);
      continue;
    }
    const predecessorHash = Buffer.from(row.prev_mutation_hash);
    if (predecessorHash.length !== 32) throw new Error('recall_authorization_chain_predecessor_malformed');
    const predecessorKey = predecessorHash.toString('hex');
    referencedPredecessors.add(predecessorKey);
    const children = childByPredecessor.get(predecessorKey) || [];
    children.push(row);
    childByPredecessor.set(predecessorKey, children);
  }

  if (genesis.length !== 1) throw new Error('recall_authorization_chain_genesis_invalid');
  for (const predecessorKey of referencedPredecessors) {
    if (!byMutationHash.has(predecessorKey)) throw new Error('recall_authorization_chain_disconnected');
  }
  const heads = rows.filter((row) => !referencedPredecessors.has(Buffer.from(row.mutation_hash).toString('hex')));
  if (heads.length !== 1) throw new Error('recall_authorization_chain_head_invalid');
  for (const children of childByPredecessor.values()) {
    if (children.length !== 1) throw new Error('recall_authorization_chain_head_invalid');
  }

  const orderedRows = [];
  const visited = new Set();
  let current = genesis[0];
  while (current) {
    const mutationKey = Buffer.from(current.mutation_hash).toString('hex');
    if (visited.has(mutationKey)) throw new Error('recall_authorization_chain_cycle');
    visited.add(mutationKey);
    orderedRows.push(current);
    current = childByPredecessor.get(mutationKey)?.[0] || null;
  }
  if (orderedRows.length !== rows.length) throw new Error('recall_authorization_chain_disconnected');
  if (orderedRows[orderedRows.length - 1] !== heads[0]) throw new Error('recall_authorization_chain_head_invalid');

  let previousMutationHash = null;
  let subject = null;
  for (let index = 0; index < orderedRows.length; index += 1) {
    const row = orderedRows[index];
    const rowSubject = `${row.company_id}\0${row.subject_agent_id}\0${new Date(row.subject_valid_from).toISOString()}`;
    if (subject === null) subject = rowSubject;
    const storedPrevious = row.prev_mutation_hash ? Buffer.from(row.prev_mutation_hash) : null;
    const predecessorMatches = index === 0
      ? storedPrevious === null
      : storedPrevious !== null
        && storedPrevious.equals(previousMutationHash);
    if (rowSubject !== subject || !predecessorMatches || Boolean(row.is_genesis) !== (index === 0)) {
      throw new Error('recall_authorization_chain_link_invalid');
    }
    const verification = verifyRecallAuthorizationProof(row, row.master_pubkey);
    if (!verification.valid) {
      throw new Error(`recall_authorization_proof_invalid:${verification.reason}`);
    }
    previousMutationHash = Buffer.from(row.mutation_hash);
  }
  return {
    verified: true,
    rowCount: orderedRows.length,
    orderedRows,
    latest: orderedRows[orderedRows.length - 1],
    mutationHash: previousMutationHash,
  };
}

export function createRecallAuthorizationService({ pool = defaultPool } = {}) {
  async function commit({
    companyId,
    subjectAgentId,
    subjectValidFrom,
    allowed,
    writeAllowed = false,
    clearanceCeiling,
    dataClassCeiling,
    masterPrivkeyB64u,
    masterFingerprint,
    reason,
    dryRun = false,
  }) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const company = String(companyId || '').trim();
      const subject = String(subjectAgentId || '').trim();
      const validFrom = new Date(subjectValidFrom).toISOString();
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`${company.length}:${company}${subject.length}:${subject}${validFrom}`],
      );
      const identity = await client.query(
        `SELECT 1 FROM agent_identity ai
          WHERE ai.agent_id = $1 AND ai.valid_from = $2
            AND NOT EXISTS (
              SELECT 1 FROM aimos_agent_revocation_events r
               WHERE r.agent_id = ai.agent_id AND r.agent_valid_from = ai.valid_from
            )
          FOR UPDATE`,
        [subject, validFrom],
      );
      if (!identity.rows[0]) throw new Error('recall_subject_epoch_not_active');
      const master = await client.query(
        'SELECT master_pubkey FROM aimos_master_identity WHERE fingerprint = $1',
        [masterFingerprint],
      );
      if (!master.rows[0]) throw new Error('recall_master_not_found');
      const previous = await client.query(
        `SELECT r.*, m.master_pubkey
           FROM aimos_recall_authorization_events r
           JOIN aimos_master_identity m ON m.fingerprint = r.master_fingerprint
          WHERE r.company_id = $1
            AND r.subject_agent_id = $2
            AND r.subject_valid_from = $3`,
        [company, subject, validFrom],
      );
      const prevMutationHash = previous.rows.length
        ? verifyRecallAuthorizationChain(previous.rows).mutationHash
        : null;
      const proof = createRecallAuthorizationProof(masterPrivkeyB64u, {
        companyId: company,
        subjectAgentId: subject,
        subjectValidFrom: validFrom,
        allowed,
        writeAllowed,
        clearanceCeiling,
        dataClassCeiling,
        masterFingerprint,
        reason,
        prevMutationHash,
      });
      const selfCheck = verifyRecallAuthorizationProof({
        company_id: company,
        subject_agent_id: subject,
        subject_valid_from: validFrom,
        allowed: Boolean(allowed),
        write_allowed: Boolean(writeAllowed),
        clearance_ceiling: Number(clearanceCeiling),
        data_class_ceiling: normalizeDataClass(dataClassCeiling),
        master_fingerprint: masterFingerprint,
        signed_body: proof.body,
        content_hash: proof.contentHash,
        mutation_hash: proof.mutationHash,
        prev_mutation_hash: proof.prevMutationHash,
        ts_signed: proof.signedTs,
        nonce: proof.nonce,
        sig: proof.sigBytes,
        is_genesis: !proof.prevMutationHash,
      }, master.rows[0].master_pubkey);
      if (!selfCheck.valid) throw new Error(`recall_authorization_self_check_failed:${selfCheck.reason}`);
      if (dryRun) {
        await client.query('ROLLBACK');
        return { dryRun: true, ...proof };
      }
      const inserted = await client.query(
        `INSERT INTO aimos_recall_authorization_events
          (company_id, subject_agent_id, subject_valid_from, allowed, write_allowed,
           clearance_ceiling, data_class_ceiling, master_fingerprint,
           signed_body, content_hash, mutation_hash, prev_mutation_hash,
           ts_signed, nonce, sig, is_genesis)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         RETURNING recall_authorization_event_id, created_at`,
        [
          company, subject, validFrom, Boolean(allowed), Boolean(writeAllowed),
          Number(clearanceCeiling), normalizeDataClass(dataClassCeiling), masterFingerprint,
          JSON.stringify(proof.body), proof.contentHash, proof.mutationHash,
          proof.prevMutationHash, proof.signedTs, proof.nonce, proof.sigBytes,
          !proof.prevMutationHash,
        ],
      );
      await client.query('COMMIT');
      return { ...inserted.rows[0], ...proof };
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
      throw error;
    } finally {
      client.release();
    }
  }

  async function getEffective({ companyId, subjectAgentId, subjectValidFrom, client = null }) {
    const run = client ? client.query.bind(client) : pool.query.bind(pool);
    const result = await run(
      `SELECT r.*, m.master_pubkey
        FROM aimos_recall_authorization_events r
         JOIN aimos_master_identity m ON m.fingerprint = r.master_fingerprint
        WHERE r.company_id = $1 AND r.subject_agent_id = $2 AND r.subject_valid_from = $3
       `,
      [String(companyId), String(subjectAgentId), new Date(subjectValidFrom).toISOString()],
    );
    if (!result.rows[0]) return null;
    const verification = verifyRecallAuthorizationChain(result.rows);
    const latest = verification.latest;
    return {
      allowed: Boolean(latest.allowed),
      writeAllowed: Boolean(latest.write_allowed),
      clearanceCeiling: Number(latest.clearance_ceiling),
      dataClassCeiling: latest.data_class_ceiling,
      mutationHash: Buffer.from(latest.mutation_hash),
      eventId: latest.recall_authorization_event_id,
    };
  }

  return { commit, getEffective };
}

export const recallAuthorizationService = createRecallAuthorizationService();
