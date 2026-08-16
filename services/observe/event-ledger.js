// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: save, recall, agent-run, dream, heartbeat, weekly, governance,
//              security, temporal, learning, and observation services
// → Calls: restricted agentPool + housekeeper identity primitives
// Pipeline: universal append-only cryptographic event evidence
// Sources: RFC 6962 Certificate Transparency; Accountability of Things:
// Large-Scale Tamper-Evident Logging for Smart Devices; Efficient Data
// Structures for Tamper-Evident Logging; RFC 8032; RFC 8785.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { agentPool } from '../../db/connection.js';
import {
  canonicalJson,
  signPayload,
  verifyCertChain,
  verifyStoredPayloadSig,
} from '../security/agent-identity.js';
import {
  HOUSEKEEPER_SIGNER_CONSTANTS,
  detectTierFromCert,
  extractValidFromIso,
  getHousekeeperCert,
  loadHousekeeperPrivkey,
} from '../security/housekeeper-signer.js';
import { eventGenesisHash, eventMutationHash } from '../security/protocol/mutmem-protocol.js';
export { eventGenesisHash, eventMutationHash } from '../security/protocol/mutmem-protocol.js';

export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const EVENT_LEDGER_VERSION = 1;

const SECRET_KEY = /(?:password|passphrase|secret|token|authorization|api[_-]?key|private[_-]?key|credential)/i;
const PASSIVE_OPS = new Set([
  'recall',
  'boot',
  'heartbeat',
  'health_check',
  'pipeline_stage_timing',
  'pipeline_recall_summary',
  'pipeline_timings_reset',
  'endpoint_latency_sample',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sanitizeMetadata(value, key = '', depth = 0) {
  if (depth > 16) throw new Error('event_metadata_depth_exceeded');
  if (SECRET_KEY.test(key)) return '[REDACTED]';
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'string') {
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(value)) return '[REDACTED]';
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => sanitizeMetadata(entry, key, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      if (childValue === undefined || typeof childValue === 'function') continue;
      out[childKey] = sanitizeMetadata(childValue, childKey, depth + 1);
    }
    return out;
  }
  return String(value);
}

function requestEnvelopeDigest(authority) {
  if (!authority) return null;
  const body = {
    actor_agent_id: authority.actorAgentId || authority.agentId || null,
    actor_valid_from: authority.actorValidFromIso || authority.validFromIso || null,
    request_sig_form: authority.requestSigForm || null,
    signed_method: authority.signedMethod || null,
    signed_path: authority.signedPath || null,
    signed_ts: authority.signedTs || null,
    nonce: authority.nonce || null,
    cert_fingerprint: authority.certString
      ? sha256(Buffer.from(String(authority.certString), 'utf8')).toString('hex')
      : null,
    signature_hash: Buffer.isBuffer(authority.sigBytes)
      ? sha256(authority.sigBytes).toString('hex')
      : null,
  };
  return sha256(Buffer.from(canonicalJson(body), 'utf8')).toString('hex');
}

/**
 * Optional fail-closed signer constraint for high-consequence evidence owners.
 * Ordinary event callers retain the existing behavior. A ceremony that has
 * already verified one exact housekeeper certificate can require logEvent()
 * to use that same certificate epoch, fingerprint, and tier; an intervening
 * identity rotation then aborts before an event is appended.
 */
export function assertEventSignerConstraint(actual = {}, expected = null) {
  if (expected == null) return true;
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) {
    throw new Error('event_signer_constraint_invalid');
  }
  const normalizedActual = {
    agent_id: String(actual.agent_id || ''),
    valid_from: actual.valid_from ? new Date(actual.valid_from).toISOString() : null,
    cert_fingerprint: String(actual.cert_fingerprint || ''),
    identity_tier: String(actual.identity_tier || ''),
  };
  const normalizedExpected = {
    agent_id: String(expected.agent_id || ''),
    valid_from: expected.valid_from ? new Date(expected.valid_from).toISOString() : null,
    cert_fingerprint: String(expected.cert_fingerprint || ''),
    identity_tier: String(expected.identity_tier || ''),
  };
  if (!normalizedExpected.agent_id || !normalizedExpected.valid_from
      || !/^[0-9a-f]{64}$/.test(normalizedExpected.cert_fingerprint)
      || !normalizedExpected.identity_tier) {
    throw new Error('event_signer_constraint_invalid');
  }
  if (canonicalJson(normalizedActual) !== canonicalJson(normalizedExpected)) {
    throw new Error('event_signer_constraint_mismatch');
  }
  return true;
}

export function verifyEventProof(row, signerPubkey) {
  try {
    const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
    if (!body || row.proof_required !== true || Number(row.ledger_version) !== EVENT_LEDGER_VERSION) {
      return { valid: false, reason: 'event_proof_version' };
    }
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationHash = eventMutationHash(
      Buffer.from(row.prev_mutation_hash),
      contentHash,
      String(row.nonce),
      Number(row.ts_signed),
    );
    const rowMetadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
    const exact = body.event_id === row.id
      && body.company_id === row.company_id
      && body.subject_agent_id === row.agent_id
      && body.signer_agent_id === row.signer_agent_id
      && new Date(body.signer_valid_from).toISOString() === new Date(row.signer_valid_from).toISOString()
      && body.cert_fingerprint === row.cert_fingerprint
      && body.identity_tier === row.identity_tier
      && body.authority_kind === row.authority_kind
      && body.operation === row.operation
      && body.key === row.key
      && canonicalJson(body.metadata) === canonicalJson(rowMetadata)
      && body.parent_event_id === (row.parent_event_id || null)
      && Number(body.ledger_seq) === Number(row.ledger_seq)
      && body.prev_mutation_hash === Buffer.from(row.prev_mutation_hash).toString('hex')
      && Number(body.ts_signed) === Number(row.ts_signed)
      && new Date(row.ts).getTime() === Number(row.ts_signed) * 1000
      && Buffer.from(row.content_hash).equals(contentHash)
      && Buffer.from(row.mutation_hash).equals(mutationHash);
    if (!exact) return { valid: false, reason: 'event_proof_hash_mismatch' };
    const signature = verifyStoredPayloadSig(
      signerPubkey,
      body,
      String(row.nonce),
      Number(row.ts_signed),
      Buffer.from(row.sig).toString('base64url'),
    );
    return signature.valid ? { valid: true, reason: null } : { valid: false, reason: signature.reason };
  } catch {
    return { valid: false, reason: 'event_proof_malformed' };
  }
}

function decodeCertificateBody(certString) {
  try {
    return JSON.parse(Buffer.from(String(certString || ''), 'base64url').toString('utf8'))?.body || null;
  } catch {
    return null;
  }
}

/**
 * Verify a complete event stream oldest-first. A prefix is not accepted as a
 * full stream: sequence one must link to the deterministic stream genesis.
 * Supplying a ceremony checkpoint additionally detects tail removal.
 */
export function verifyEventLedgerChain(rows = [], {
  expectedHeadMutationHash = null,
  expectedHeadSequence = null,
  masterPubkey = null,
} = {}) {
  let companyId = null;
  let signerAgentId = null;
  let signerValidFrom = null;
  let previousMutationHash = null;

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const validFrom = new Date(row.signer_valid_from).toISOString();
    if (index === 0) {
      companyId = String(row.company_id);
      signerAgentId = String(row.signer_agent_id);
      signerValidFrom = validFrom;
      previousMutationHash = eventGenesisHash(companyId, signerAgentId, signerValidFrom);
    }
    if (
      String(row.company_id) !== companyId
      || String(row.signer_agent_id) !== signerAgentId
      || validFrom !== signerValidFrom
      || Number(row.ledger_seq) !== index + 1
      || !Buffer.from(row.prev_mutation_hash || []).equals(previousMutationHash)
    ) {
      throw new Error('event_ledger_chain_link_invalid');
    }

    const signerPubkey = row.signer_pubkey || row.pubkey;
    const signerCertificate = row.signer_certificate || row.cert;
    if (!signerPubkey || !signerCertificate) throw new Error('event_ledger_identity_material_missing');
    const certBody = decodeCertificateBody(signerCertificate);
    const certFingerprint = sha256(Buffer.from(String(signerCertificate), 'utf8')).toString('hex');
    if (
      !certBody
      || certBody.agent_id !== signerAgentId
      || certBody.pubkey !== signerPubkey
      || certFingerprint !== row.cert_fingerprint
    ) {
      throw new Error('event_ledger_identity_mismatch');
    }
    const certAuthority = certBody.issuer === signerAgentId ? signerPubkey : masterPubkey;
    if (!certAuthority) throw new Error('event_ledger_master_identity_missing');
    const certProof = verifyCertChain(signerCertificate, certAuthority, {
      nowFn: () => Number(row.ts_signed),
    });
    if (!certProof.valid) throw new Error(`event_ledger_certificate_invalid:${certProof.reason}`);

    const signedAt = Number(row.ts_signed);
    const signedRevocationAt = row.revocation_ts_signed == null ? null : Number(row.revocation_ts_signed);
    if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= signedAt) {
      throw new Error('event_ledger_signer_revoked_at_signature_time');
    }

    const proof = verifyEventProof(row, signerPubkey);
    if (!proof.valid) throw new Error(`event_ledger_proof_invalid:${proof.reason}`);
    previousMutationHash = Buffer.from(row.mutation_hash);
  }

  if (expectedHeadSequence !== null && Number(expectedHeadSequence) !== rows.length) {
    throw new Error('event_ledger_checkpoint_sequence_mismatch');
  }
  if (
    expectedHeadMutationHash !== null
    && !Buffer.from(expectedHeadMutationHash).equals(previousMutationHash || Buffer.alloc(0))
  ) {
    throw new Error('event_ledger_checkpoint_hash_mismatch');
  }

  return {
    verified: true,
    rowCount: rows.length,
    companyId,
    signerAgentId,
    signerValidFrom,
    headMutationHash: previousMutationHash,
  };
}

/** Read and verify one complete signer-epoch stream using the restricted role. */
export async function readVerifiedEventStream(companyId, {
  client = null,
  signerAgentId = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
  signerValidFrom = null,
} = {}) {
  const company = String(companyId || '').trim();
  const signer = String(signerAgentId || '').trim();
  if (!company || !signer) throw new Error('event_stream_scope_required');
  let validFrom = signerValidFrom ? new Date(signerValidFrom).toISOString() : null;
  if (!validFrom && signer === HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID) {
    validFrom = extractValidFromIso(await getHousekeeperCert());
  }
  if (!validFrom) throw new Error('event_stream_signer_epoch_required');

  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) {
      await conn.query('BEGIN');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', signer]);
    }
    const events = await conn.query(
      `SELECT event.*, identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed
           FROM aimos_events event
           JOIN agent_identity identity
             ON identity.agent_id = event.signer_agent_id
            AND identity.valid_from = event.signer_valid_from
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE event.company_id = $1
            AND event.signer_agent_id = $2
            AND event.signer_valid_from = $3
            AND event.ledger_version = 1
          ORDER BY event.ledger_seq`,
      [company, signer, validFrom],
    );
    const master = await conn.query(
      'SELECT master_pubkey FROM aimos_master_identity WHERE id = 1',
    );
    if (events.rows.length) {
      verifyEventLedgerChain(events.rows, { masterPubkey: master.rows[0]?.master_pubkey || null });
    }
    if (ownsTransaction) await conn.query('COMMIT');
    return events.rows;
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}

/**
 * Read every retained signer epoch for one agent and verify each complete
 * stream independently. Identity rotation starts a new deterministic stream;
 * it must not make control events signed by an earlier valid epoch disappear.
 */
export async function readVerifiedEventHistory(companyId, {
  client = null,
  signerAgentId = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
} = {}) {
  const company = String(companyId || '').trim();
  const signer = String(signerAgentId || '').trim();
  if (!company || !signer) throw new Error('event_history_scope_required');

  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) {
      await conn.query('BEGIN');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', signer]);
    }
    const events = await conn.query(
      `SELECT event.*, identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed
           FROM aimos_events event
           JOIN agent_identity identity
             ON identity.agent_id = event.signer_agent_id
            AND identity.valid_from = event.signer_valid_from
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
          WHERE event.company_id = $1
            AND event.signer_agent_id = $2
            AND event.ledger_version = 1
          ORDER BY event.signer_valid_from, event.ledger_seq`,
      [company, signer],
    );
    const master = await conn.query(
      'SELECT master_pubkey FROM aimos_master_identity WHERE id = 1',
    );

    const rowsByEpoch = new Map();
    for (const row of events.rows) {
      const epoch = new Date(row.signer_valid_from).toISOString();
      if (!rowsByEpoch.has(epoch)) rowsByEpoch.set(epoch, []);
      rowsByEpoch.get(epoch).push(row);
    }
    for (const rows of rowsByEpoch.values()) {
      verifyEventLedgerChain(rows, { masterPubkey: master.rows[0]?.master_pubkey || null });
    }

    if (ownsTransaction) await conn.query('COMMIT');
    return events.rows;
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}

/**
 * Verify one retained event and its immediate stream link in O(1). This is the
 * native authority lookup for a domain mutation that consumes a previously
 * committed event receipt. Full-stream/checkpoint verification remains the
 * ceremony proof for prefix deletion; this lookup proves the exact signed row,
 * signer epoch, certificate chain, revocation state at signing, and predecessor.
 */
export async function readVerifiedEventById(eventId, companyId, { client = null } = {}) {
  const id = String(eventId || '').trim();
  const company = String(companyId || '').trim();
  if (!id || !company) throw new Error('event_receipt_scope_required');

  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) {
      await conn.query('BEGIN');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID]);
    }
    const eventResult = await conn.query(
      `SELECT event.*, identity.pubkey, identity.cert,
                revocation.ts_signed AS revocation_ts_signed,
                predecessor.mutation_hash AS stored_predecessor_hash
           FROM aimos_events event
           JOIN agent_identity identity
             ON identity.agent_id = event.signer_agent_id
            AND identity.valid_from = event.signer_valid_from
           LEFT JOIN aimos_agent_revocation_events revocation
             ON revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from
           LEFT JOIN aimos_events predecessor
             ON predecessor.company_id = event.company_id
            AND predecessor.signer_agent_id = event.signer_agent_id
            AND predecessor.signer_valid_from = event.signer_valid_from
            AND predecessor.ledger_version = event.ledger_version
            AND predecessor.ledger_seq = event.ledger_seq - 1
          WHERE event.id = $1
            AND event.company_id = $2
            AND event.ledger_version = $3`,
      [id, company, EVENT_LEDGER_VERSION],
    );
    const masterResult = await conn.query(
      'SELECT master_pubkey FROM aimos_master_identity WHERE id = 1',
    );
    const row = eventResult.rows[0];
    if (!row) throw new Error('event_receipt_not_found');

    const certBody = decodeCertificateBody(row.cert);
    const certFingerprint = sha256(Buffer.from(String(row.cert), 'utf8')).toString('hex');
    if (
      !certBody
      || certBody.agent_id !== row.signer_agent_id
      || certBody.pubkey !== row.pubkey
      || certFingerprint !== row.cert_fingerprint
    ) throw new Error('event_ledger_identity_mismatch');
    const certAuthority = certBody.issuer === row.signer_agent_id
      ? row.pubkey
      : masterResult.rows[0]?.master_pubkey;
    if (!certAuthority) throw new Error('event_ledger_master_identity_missing');
    const certProof = verifyCertChain(row.cert, certAuthority, {
      nowFn: () => Number(row.ts_signed),
    });
    if (!certProof.valid) throw new Error(`event_ledger_certificate_invalid:${certProof.reason}`);
    if (row.revocation_ts_signed != null && Number(row.revocation_ts_signed) <= Number(row.ts_signed)) {
      throw new Error('event_ledger_signer_revoked_at_signature_time');
    }

    const expectedPredecessor = Number(row.ledger_seq) === 1
      ? eventGenesisHash(row.company_id, row.signer_agent_id, row.signer_valid_from)
      : Buffer.from(row.stored_predecessor_hash || []);
    if (expectedPredecessor.length !== 32 || !Buffer.from(row.prev_mutation_hash).equals(expectedPredecessor)) {
      throw new Error('event_ledger_chain_link_invalid');
    }
    const proof = verifyEventProof(row, row.pubkey);
    if (!proof.valid) throw new Error(`event_ledger_proof_invalid:${proof.reason}`);
    if (ownsTransaction) await conn.query('COMMIT');
    return row;
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}

/**
 * Append one signed event to the housekeeper stream for a company.
 * Existing positional arguments are retained because 170 native callers share
 * this service boundary. The implementation itself is the single ledger owner.
 */
export async function logEvent(companyId, subjectAgentId, operation, key = null, metadata = {}, parentEventId = null, options = {}) {
  const cid = String(companyId || '').trim();
  const subject = String(subjectAgentId || 'unknown').trim() || 'unknown';
  const op = String(operation || '').trim();
  if (!cid) throw new Error('event_company_required');
  if (!op) throw new Error('event_operation_required');
  const eventKey = key == null ? null : String(key);
  const safeMetadata = sanitizeMetadata(metadata || {});
  const serializedMetadata = canonicalJson(safeMetadata);
  if (Buffer.byteLength(serializedMetadata, 'utf8') > 1_048_576) throw new Error('event_metadata_too_large');

  const reasoning = typeof safeMetadata.reasoning === 'string' && safeMetadata.reasoning.trim()
    ? safeMetadata.reasoning.trim()
    : (typeof safeMetadata.reason === 'string' && safeMetadata.reason.trim() ? safeMetadata.reason.trim() : '');
  if (!reasoning && !PASSIVE_OPS.has(op)) {
    console.warn(`[Event Ledger] WARNING: '${op}' on '${eventKey || 'n/a'}' has no reasoning. Every decision needs a WHY.`);
  }

  const certString = await getHousekeeperCert(
    typeof options.identityQueryFn === 'function'
      ? { queryFn: options.identityQueryFn }
      : {},
  );
  const signerValidFrom = extractValidFromIso(certString);
  const signerAgentId = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID;
  const identityTier = detectTierFromCert(certString);
  const certFingerprint = sha256(Buffer.from(certString, 'utf8')).toString('hex');
  assertEventSignerConstraint({
    agent_id: signerAgentId,
    valid_from: signerValidFrom,
    cert_fingerprint: certFingerprint,
    identity_tier: identityTier,
  }, options.signerConstraint || null);
  const privkey = loadHousekeeperPrivkey();
  const authority = options.authority || null;
  const authorityKind = authority
    ? 'housekeeper_observation_of_verified_request'
    : 'housekeeper_autonomous';
  const actorAgentId = authority?.actorAgentId || authority?.agentId || null;
  const actorValidFrom = authority?.actorValidFromIso || authority?.validFromIso || null;
  const envelopeDigest = requestEnvelopeDigest(authority);

  const ownsTransaction = !options.client;
  const client = options.client || await agentPool.connect();
  try {
    if (ownsTransaction) await client.query('BEGIN');
    await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', cid]);
    await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', signerAgentId]);
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
      [`${cid.length}:${cid}${signerAgentId.length}:${signerAgentId}${signerValidFrom}`],
    );

    if (options.exclusiveOperationKey === true) {
      if (eventKey === null) throw new Error('event_exclusive_key_required');
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
        [`event-operation-key:${cid.length}:${cid}:${op.length}:${op}:${eventKey.length}:${eventKey}`],
      );
      const existing = await client.query(
        `SELECT 1
           FROM aimos_events
          WHERE company_id = $1
            AND operation = $2
            AND key = $3
            AND ledger_version = 1
          LIMIT 1`,
        [cid, op, eventKey],
      );
      if (existing.rows[0]) throw new Error('event_operation_key_exists');
    }

    if (parentEventId) {
      const parent = await client.query(
        'SELECT 1 FROM aimos_events WHERE id = $1 AND company_id = $2',
        [parentEventId, cid],
      );
      if (!parent.rows[0]) throw new Error('event_parent_not_found_or_cross_company');
    }

    const latest = await client.query(
      `SELECT ledger_seq, mutation_hash
         FROM aimos_events
        WHERE company_id = $1
          AND signer_agent_id = $2
          AND signer_valid_from = $3
          AND ledger_version = 1
        ORDER BY ledger_seq DESC
        LIMIT 1`,
      [cid, signerAgentId, signerValidFrom],
    );
    const ledgerSeq = Number(latest.rows[0]?.ledger_seq || 0) + 1;
    const prevMutationHash = latest.rows[0]?.mutation_hash
      ? Buffer.from(latest.rows[0].mutation_hash)
      : eventGenesisHash(cid, signerAgentId, signerValidFrom);
    const eventId = randomUUID();
    const signedTs = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(16).toString('base64url');
    const body = {
      ledger_version: EVENT_LEDGER_VERSION,
      event_id: eventId,
      company_id: cid,
      subject_agent_id: subject,
      actor_agent_id: actorAgentId,
      actor_valid_from: actorValidFrom,
      signer_agent_id: signerAgentId,
      signer_valid_from: signerValidFrom,
      cert_fingerprint: certFingerprint,
      identity_tier: identityTier,
      authority_kind: authorityKind,
      request_envelope_digest: envelopeDigest,
      operation: op,
      key: eventKey,
      metadata: safeMetadata,
      parent_event_id: parentEventId || null,
      ledger_seq: ledgerSeq,
      prev_mutation_hash: prevMutationHash.toString('hex'),
      ts_signed: signedTs,
    };
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationHash = eventMutationHash(prevMutationHash, contentHash, nonce, signedTs);
    const sig = Buffer.from(signPayload(privkey, body, nonce, signedTs), 'base64url');

    await client.query(
      `INSERT INTO aimos_events
         (id, ts, company_id, agent_id, operation, key, metadata, parent_event_id,
          ledger_version, ledger_seq, signer_agent_id, signer_valid_from,
          cert_fingerprint, identity_tier, authority_kind, signed_body,
          content_hash, mutation_hash, prev_mutation_hash, ts_signed, nonce, sig)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
      [
        eventId, new Date(signedTs * 1000), cid, subject, op, eventKey,
        JSON.stringify(safeMetadata), parentEventId || null,
        EVENT_LEDGER_VERSION, ledgerSeq, signerAgentId, signerValidFrom,
        certFingerprint, identityTier, authorityKind, JSON.stringify(body),
        contentHash, mutationHash, prevMutationHash, signedTs, nonce, sig,
      ],
    );
    if (ownsTransaction) await client.query('COMMIT');
    const receipt = {
      event_id: eventId,
      proof_required: true,
      ledger_version: EVENT_LEDGER_VERSION,
      ledger_seq: ledgerSeq,
      signed_body: body,
      content_hash: contentHash.toString('hex'),
      mutation_hash: mutationHash.toString('hex'),
      prev_mutation_hash: prevMutationHash.toString('hex'),
      signer_agent_id: signerAgentId,
      signer_valid_from: signerValidFrom,
      cert_fingerprint: certFingerprint,
      signer_certificate: certString,
      identity_tier: identityTier,
      ts_signed: signedTs,
      nonce,
      signature: sig.toString('base64url'),
    };
    return options.returnReceipt ? receipt : eventId;
  } catch (error) {
    if (ownsTransaction) {
      try { await client.query('ROLLBACK'); } catch { /* connection may be gone */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) client.release();
  }
}

export function buildEventLedgerRuntimeDiagnostics({ operation = '', key = null, metadata = {}, parentEventId = null } = {}) {
  const op = String(operation || '').trim();
  const reasoning = typeof metadata?.reasoning === 'string' && metadata.reasoning.trim()
    ? metadata.reasoning.trim()
    : typeof metadata?.reason === 'string' && metadata.reason.trim()
      ? metadata.reason.trim()
      : '';
  const passive = PASSIVE_OPS.has(op);
  return {
    status: op ? 'ready' : 'missing_operation',
    source_paper: AGENTPULSE_SOURCE,
    proof_model: 'housekeeper_signed_linear_receipt',
    proof_complexity: { append: 'O(1) expected after indexed head lookup', full_chain_verify: 'O(n)' },
    diagnostic_only: true,
    event_shape: {
      operation: op || null,
      key: key == null ? null : String(key).slice(0, 160),
      has_reasoning: Boolean(reasoning),
      passive_operation: passive,
      parent_event_present: Boolean(parentEventId),
    },
    audit_contract: {
      missing_reasoning_warning_expected: !reasoning && !passive,
      event_written_by_diagnostic: false,
      metadata_mutated: false,
      canonical_memory_deleted: false,
    },
  };
}
