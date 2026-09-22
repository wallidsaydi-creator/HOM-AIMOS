// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: save, recall, agent-run, dream, heartbeat, weekly, governance,
//              security, temporal, learning, and observation services
// → Calls: restricted agentPool + housekeeper identity primitives
// Pipeline: universal append-only cryptographic event evidence
// Sources: RFC 6962 Certificate Transparency; Accountability of Things:
// Large-Scale Tamper-Evident Logging for Smart Devices; Efficient Data
// Structures for Tamper-Evident Logging; RFC 8032; RFC 8785.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, createPublicKey, verify as verifySignature, randomBytes, randomUUID } from 'node:crypto';
import { agentPool } from '../../db/connection.js';
import { beginServingWork } from '../runtime/serving-control.js';
import {
  buildSignedMessage,
  canonicalJson,
  signRaw,
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
import { eventGenesisHash, eventMutationHash, signedJsonBytesCommitmentV1, eventPayloadCommitment } from '../security/protocol/mutmem-protocol.js';
export { eventGenesisHash, eventMutationHash } from '../security/protocol/mutmem-protocol.js';

export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const EVENT_LEDGER_VERSION = 1;
// Ledger linkage stays v1; this explicitly versions the signed payload bytes.
// Default emission stays historical until the coordinated SQL/consumer cutover.
export const EVENT_EXACT_PAYLOAD_SCHEMA = 'hom.aimos.event/v2';

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
  // A null optional field carries no secret bytes and must remain null so
  // exact signed schemas can distinguish "not supplied" from redaction.
  if (value === null) return null;
  if (SECRET_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'boolean' || typeof value === 'number') return value;
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

// Callers that commit nested projection hashes must hash the same bytes the
// native ledger retains, including its existing secret-field redaction.
export { sanitizeMetadata as prepareEventMetadata };

export function requestEnvelopeDigest(authority) {
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
  return verifyEventProofWithKey(row, signerPubkey, null);
}

function verifyEventProofWithKey(row, signerPubkey, verifiedPublicKey) {
  try {
    const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
    if (!body || row.proof_required !== true || Number(row.ledger_version) !== EVENT_LEDGER_VERSION) {
      return { valid: false, reason: 'event_proof_version' };
    }
    const exactPayload = body.payload_schema === EVENT_EXACT_PAYLOAD_SCHEMA;
    if (Object.hasOwn(body, 'payload_schema') && !exactPayload) return { valid: false, reason: 'event_payload_schema_invalid' };
    const contentHash = eventPayloadCommitment(body, row.nonce, row.signed_body_bytes);
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
    if (exactPayload) {
      const key = verifiedPublicKey || createPublicKey({ format: 'der', type: 'spki', key: Buffer.from(signerPubkey, 'base64url') });
      return verifySignature(null, contentHash, key, Buffer.from(row.sig))
        ? { valid: true, reason: null } : { valid: false, reason: 'sig_invalid' };
    }
    if (verifiedPublicKey) {
      const message = Buffer.from(buildSignedMessage(body, String(row.nonce), Number(row.ts_signed)), 'utf8');
      return verifySignature(null, message, verifiedPublicKey, Buffer.from(row.sig))
        ? { valid: true, reason: null } : { valid: false, reason: 'sig_invalid' };
    }
    const signature = verifyStoredPayloadSig(signerPubkey, body, String(row.nonce),
      Number(row.ts_signed), Buffer.from(row.sig).toString('base64url'));
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
  const verifier=createEventStreamVerifier(masterPubkey);
  for(const row of rows)verifier.accept(row);
  return verifier.finish({expectedHeadMutationHash,expectedHeadSequence});
}

// One native row verifier, shared by retained array proofs and cursor reads.
// A continuation state is private: callers cannot bless an arbitrary prefix.
function createEventStreamVerifier(masterPubkey, initial = null) {
  let companyId = initial?.companyId || null;
  let signerAgentId = initial?.signerAgentId || null;
  let signerValidFrom = initial?.signerValidFrom || null;
  let previousMutationHash = initial?.previousMutationHash
    ? Buffer.from(initial.previousMutationHash)
    : null;
  const previousSequence = Number(initial?.previousSequence || 0);
  let rowCount = 0;
  let verifiedCertificate = null;
  let verifiedSignerKey = null;
  let verifiedSignerPubkey = null;

  return {
  accept(row) {
    const index=rowCount;
    const validFrom = new Date(row.signer_valid_from).toISOString();
    if (index === 0 && !initial) {
      companyId = String(row.company_id);
      signerAgentId = String(row.signer_agent_id);
      signerValidFrom = validFrom;
      previousMutationHash = eventGenesisHash(companyId, signerAgentId, signerValidFrom);
    }
    if (
      String(row.company_id) !== companyId
      || String(row.signer_agent_id) !== signerAgentId
      || validFrom !== signerValidFrom
      || Number(row.ledger_seq) !== previousSequence + index + 1
      || !Buffer.from(row.prev_mutation_hash || []).equals(previousMutationHash)
    ) {
      throw new Error('event_ledger_chain_link_invalid');
    }

    const signerPubkey = row.signer_pubkey || row.pubkey;
    const signerCertificate = row.signer_certificate || row.cert;
    if (!signerPubkey || !signerCertificate) throw new Error('event_ledger_identity_material_missing');
    const sameCertificate = verifiedCertificate?.certificate === signerCertificate
      && verifiedCertificate.authority === (verifiedCertificate.body.issuer === signerAgentId
        ? signerPubkey : masterPubkey);
    const certBody = sameCertificate ? verifiedCertificate.body : decodeCertificateBody(signerCertificate);
    const certFingerprint = sameCertificate ? verifiedCertificate.fingerprint
      : sha256(Buffer.from(String(signerCertificate), 'utf8')).toString('hex');
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
    const signedAt = Number(row.ts_signed);
    if (sameCertificate) {
      if (signedAt < certBody.valid_from) throw new Error('event_ledger_certificate_invalid:cert_not_yet_valid');
      if (signedAt > certBody.valid_until) throw new Error('event_ledger_certificate_invalid:cert_expired');
    } else {
      const certProof = verifyCertChain(signerCertificate, certAuthority, { nowFn: () => signedAt });
      if (!certProof.valid) throw new Error(`event_ledger_certificate_invalid:${certProof.reason}`);
      verifiedCertificate = { certificate: signerCertificate, authority: certAuthority,
        body: certProof.body, fingerprint: certFingerprint };
    }

    const signedRevocationAt = row.revocation_ts_signed == null ? null : Number(row.revocation_ts_signed);
    if (Number.isFinite(signedRevocationAt) && signedRevocationAt <= signedAt) {
      throw new Error('event_ledger_signer_revoked_at_signature_time');
    }

    if (verifiedSignerPubkey !== signerPubkey) {
      verifiedSignerKey = createPublicKey({ format: 'der', type: 'spki',
        key: Buffer.from(signerPubkey, 'base64url') });
      verifiedSignerPubkey = signerPubkey;
    }
    const proof = verifyEventProofWithKey(row, signerPubkey, verifiedSignerKey);
    if (!proof.valid) throw new Error(`event_ledger_proof_invalid:${proof.reason}`);
    previousMutationHash = Buffer.from(row.mutation_hash);
    rowCount += 1;
  },

  finish({expectedHeadSequence=null,expectedHeadMutationHash=null}={}) {
  if (expectedHeadSequence !== null && Number(expectedHeadSequence) !== previousSequence + rowCount) {
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
    rowCount,
    companyId,
    signerAgentId,
    signerValidFrom,
    previousSequence,
    headMutationHash: previousMutationHash,
  };
  },
  };
}

const EVENT_HISTORY_PAGE_ROWS = 16;
const EVENT_HISTORY_CHAIN_DOMAIN = Buffer.from('hom.aimos.verified-event-history-chain/v1\0', 'utf8');
const RECOVERY_CHECKPOINT_SCHEMA = 'hom.aimos.event-recovery-checkpoint/v1';
const RECOVERY_CHECKPOINT_OPERATION = 'event_history_recovery_checkpoint';

function initialEventHistoryChain(companyId, signerAgentId) {
  return sha256(Buffer.concat([
    EVENT_HISTORY_CHAIN_DOMAIN,
    Buffer.from(canonicalJson({ company_id: companyId, signer_agent_id: signerAgentId }), 'utf8'),
  ]));
}

function advanceEventHistoryChain(previous, mutationHash) {
  return sha256(Buffer.concat([
    EVENT_HISTORY_CHAIN_DOMAIN,
    Buffer.from(previous),
    Buffer.from(mutationHash),
  ]));
}

function unresolvedRoot(entries = []) {
  return sha256(Buffer.concat([
    Buffer.from('hom.aimos.event-recovery-unresolved/v1\0', 'utf8'),
    Buffer.from(canonicalJson(entries), 'utf8'),
  ])).toString('hex');
}

/**
 * Native bounded-memory full-history reader. WITHOUT HOLD keeps one PostgreSQL
 * snapshot without materializing a held cursor. Every row, certificate, chain
 * link and epoch is verified; no timestamp cutoff or retention cap is applied.
 * Memory is O(page rows * largest row), independent of total retained history.
 * Only exhausting the iterator yields a complete-history summary. Consumers
 * must finish verification before treating their reconstruction as authoritative.
 */
export async function* iterateVerifiedEventHistory(companyId, {
  client=null,signerAgentId=HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
  checkpointExpectation=null,
}={}) {
  const company=String(companyId||'').trim(), signer=String(signerAgentId||'').trim();
  if(!company||!signer)throw new Error('event_history_scope_required');
  const owned=!client,conn=client||await agentPool.connect();
  const cursor='aimos_history_'+randomUUID().replaceAll('-','');
  let declared=false,complete=false,connectionError=null,failure=null;
  const onError=error=>{connectionError=error;};
  if(owned)conn.on('error',onError);
  try {
    if(owned){
      await conn.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await conn.query('SELECT set_config($1,$2,true)',['app.current_client_id',company]);
      await conn.query('SELECT set_config($1,$2,true)',['app.current_agent_id',signer]);
    }
    await conn.query(`DECLARE ${cursor} NO SCROLL CURSOR WITHOUT HOLD FOR
      SELECT event.*,identity.pubkey,identity.cert,revocation.ts_signed AS revocation_ts_signed,
        master.master_pubkey
      FROM aimos_events event JOIN agent_identity identity
        ON identity.agent_id=event.signer_agent_id AND identity.valid_from=event.signer_valid_from
      LEFT JOIN aimos_agent_revocation_events revocation
        ON revocation.agent_id=identity.agent_id AND revocation.agent_valid_from=identity.valid_from
      LEFT JOIN aimos_master_identity master ON master.id=1
      WHERE event.company_id=$1 AND event.signer_agent_id=$2 AND event.ledger_version=1
      ORDER BY event.signer_valid_from,event.ledger_seq`,[company,signer]);
    declared=true;
    let epoch=null,verifier=null,rowCount=0,epochCount=0;
    let historyChain=initialEventHistoryChain(company,signer);
    const epochHeads=[];
    let checkpointMatched=false;
    while(true){
      if(connectionError)throw connectionError;
      const page=(await conn.query(`FETCH FORWARD ${EVENT_HISTORY_PAGE_ROWS} FROM ${cursor}`)).rows;
      if(!page.length)break;
      for(const row of page){
        const nextEpoch=new Date(row.signer_valid_from).toISOString();
        if(nextEpoch!==epoch){
          if(epoch!==null&&nextEpoch<=epoch)throw new Error('event_history_epoch_order_invalid');
          if(verifier){
            const prior=verifier.finish();
            epochHeads.push(Object.freeze({valid_from:prior.signerValidFrom,
              ledger_seq:prior.previousSequence+prior.rowCount,
              mutation_sha256:Buffer.from(prior.headMutationHash).toString('hex')}));
          }
          epoch=nextEpoch;epochCount+=1;verifier=createEventStreamVerifier(row.master_pubkey);
        }
        verifier.accept(row);
        if(row.company_id!==company||row.signer_agent_id!==signer)throw new Error('event_history_scope_mismatch');
        if (checkpointExpectation?.eventId === row.id) {
          const expected = checkpointExpectation;
          const actualHeads = [...epochHeads,{valid_from:epoch,ledger_seq:Number(row.ledger_seq)-1,
            mutation_sha256:Buffer.from(row.prev_mutation_hash).toString('hex')}];
          if (rowCount !== expected.prefix_event_count
              || historyChain.toString('hex') !== expected.prefix_history_sha256
              || canonicalJson(actualHeads) !== canonicalJson(expected.prefix_epoch_heads)) {
            throw new Error('event_recovery_checkpoint_verified_prefix_mismatch');
          }
          checkpointMatched=true;
        }
        historyChain=advanceEventHistoryChain(historyChain,row.mutation_hash);rowCount+=1;
        yield row;
      }
    }
    if(checkpointExpectation&&!checkpointMatched)throw new Error('event_recovery_checkpoint_missing_from_verified_history');
    if(verifier){
      const prior=verifier.finish();
      epochHeads.push(Object.freeze({valid_from:prior.signerValidFrom,
        ledger_seq:prior.previousSequence+prior.rowCount,
        mutation_sha256:Buffer.from(prior.headMutationHash).toString('hex')}));
    }
    await conn.query(`CLOSE ${cursor}`);declared=false;
    if(owned)await conn.query('COMMIT');
    complete=true;
    return Object.freeze({verified:true,companyId:company,signerAgentId:signer,rowCount,epochCount,
      historySha256:historyChain.toString('hex'),pageRows:EVENT_HISTORY_PAGE_ROWS,
      epochHeads:Object.freeze(epochHeads),complete:true});
  } catch(error) {
    failure=error;throw error;
  } finally {
    let cleanupError=null;
    try {
      if(declared&&!connectionError&&!failure)await conn.query(`CLOSE ${cursor}`);
      if(owned&&!complete&&!connectionError&&!failure)await conn.query('ROLLBACK');
    } catch(error) {
      cleanupError=error;throw error;
    } finally {
      if(owned){conn.release(failure||cleanupError||connectionError||undefined);conn.removeListener('error',onError);}
    }
  }
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
  operations = null,
} = {}) {
  // Materializing compatibility for explicit historical/offline callers.
  // Native recovery owners consume the iterator directly as they are migrated.
  const selected = operations == null ? null : new Set(operations.map((value) => String(value)));
  const rows=[];
  for await(const row of iterateVerifiedEventHistory(companyId,{client,signerAgentId})) {
    if (!selected || selected.has(String(row.operation))) rows.push(row);
  }
  return rows;
}

async function consumeVerifiedHistory(iterator, onRow) {
  while (true) {
    const step = await iterator.next();
    if (step.done) return step.value;
    await onRow(step.value);
  }
}

/**
 * Database-grouped recovery projection. The ledger verifies the entire chain
 * in the same snapshot first. Native reconstructors consume one action trace
 * at a time, including completed identity reuse. PostgreSQL owns spillable
 * ordering; production callers reconcile open groups without collecting them.
 */
export function createVerifiedOpenEventReducer(definitions = []) {
  if (!Array.isArray(definitions) || !definitions.length) throw new Error('event_recovery_reducer_definitions_required');
  const sqlIdentities = {
    // These native reconstructors require their derived identity to equal
    // the retained key. Group by that key, then check the native derivation;
    // this also preserves JavaScript's existing empty/falsy fallbacks.
    material_effect: 'e.key',
    agent_run: 'e.key',
    session_lane: 'e.key',
    system_job: 'e.key',
    schedule_run: "e.metadata->>'run_id'",
    tool_action: "CASE WHEN e.operation='tool_execution_started' THEN e.id::text ELSE e.metadata->>'tool_action_event_id' END",
    model_context: "CASE WHEN e.operation='tool_context_prepared' THEN e.id::text ELSE e.key END",
    canonical_save_action: "CASE WHEN e.operation='canonical_save_action_started' THEN e.id::text WHEN e.operation='canonical_save_action_recovery_terminal' THEN e.key WHEN e.metadata#>>'{stages,1,evidence,kind}'='verified_housekeeper_action' THEN e.metadata#>>'{stages,1,evidence,event_id}' END",
  };
  const normalized = definitions.map(definition => {
    if (!sqlIdentities[definition?.name] || !Array.isArray(definition.startOperations)
        || !Array.isArray(definition.terminalOperations) || typeof definition.startId !== 'function'
        || typeof definition.terminalId !== 'function' || typeof definition.validate !== 'function') {
      throw new Error('event_recovery_reducer_definition_invalid');
    }
    return { relatedOperations:[], ...definition };
  });
  if (new Set(normalized.map(d => d.name)).size !== normalized.length) throw new Error('event_recovery_reducer_name_duplicate');
  return Object.freeze({
    async reduce(client, company, signer, { onOpenGroup = null, completedPrefix = null } = {}) {
      const retained = [];
      const metrics = { acceptedRows:0, completedActions:0, openActions:0,
        peakOpenActions:0, peakRetainedRows:0, retainedRows:0,
        spaceComplexity:'O(cursor_page_plus_largest_action_trace)',
        storage:'PostgreSQL grouped cursor; sort spills under work_mem' };
      for (const definition of normalized) {
        const cursor = 'aimos_groups_' + randomUUID().replaceAll('-', '');
        const operations = [...definition.startOperations,...definition.terminalOperations,...definition.relatedOperations];
        // SQL groups by precisely the native action identity. Related evidence
        // follows parent links from that action's start. Unlike lifetime Maps,
        // the sort may spill on PostgreSQL and completed identity reuse remains
        // in the same group, where the native reconstructor rejects the fork.
        const sql = [
          'WITH RECURSIVE selected AS MATERIALIZED (',
          ' SELECT e.*,i.pubkey,i.cert,revocation.ts_signed AS revocation_ts_signed,master.master_pubkey',
          ' FROM aimos_events e JOIN agent_identity i ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from',
          ' LEFT JOIN aimos_agent_revocation_events revocation ON revocation.agent_id=i.agent_id AND revocation.agent_valid_from=i.valid_from',
          ' LEFT JOIN aimos_master_identity master ON master.id=1',
          ' WHERE e.company_id=$1 AND e.signer_agent_id=$2 AND e.ledger_version=1 AND e.operation=ANY($3::text[])',
          '), direct AS (SELECT e.id,e.operation,' + sqlIdentities[definition.name] + ' AS group_id FROM selected e',
          ' WHERE e.operation=ANY($4::text[])), linked(event_id,group_id,path) AS (',
          ' SELECT d.id,d.group_id,ARRAY[d.id] FROM direct d WHERE d.operation=ANY($5::text[]) AND d.group_id IS NOT NULL',
          ' UNION ALL SELECT e.id,p.group_id,p.path||e.id FROM selected e JOIN linked p ON e.parent_event_id=p.event_id',
          ' WHERE e.operation=ANY($6::text[]) AND NOT e.id=ANY(p.path)',
          "), grouped AS (SELECT e.*,coalesce(d.group_id,l.group_id,'unbound:'||e.id::text) AS recovery_group_id FROM selected e",
          ' LEFT JOIN direct d ON d.id=e.id LEFT JOIN linked l ON l.event_id=e.id',
          ')',
          ' SELECT * FROM grouped WHERE $7::timestamptz IS NULL OR recovery_group_id IN (',
          ' SELECT recovery_group_id FROM grouped WHERE signer_valid_from>$7::timestamptz',
          ' OR (signer_valid_from=$7::timestamptz AND ledger_seq>$8::bigint))',
          ' ORDER BY recovery_group_id,signer_valid_from,ledger_seq',
        ].join('\n');
        await client.query('DECLARE ' + cursor + ' NO SCROLL CURSOR WITHOUT HOLD FOR ' + sql,
          [company,signer,operations,[...definition.startOperations,...definition.terminalOperations],
            definition.startOperations,definition.relatedOperations,
            completedPrefix?.validFrom || null, completedPrefix?.sequence || null]);
        let key = null, group = [];
        const finishGroup = async () => {
          if (!group.length) return;
          const snapshot = definition.validate(group);
          if (snapshot.complete.length + snapshot.open.length === 0) return; // Native ignored historical schema.
          if (snapshot.complete.length + snapshot.open.length !== 1) throw new Error('event_recovery_group_identity_invalid');
          metrics.completedActions += snapshot.complete.length;
          metrics.openActions += snapshot.open.length;
          metrics.peakOpenActions = Math.max(metrics.peakOpenActions,snapshot.open.length);
          metrics.peakRetainedRows = Math.max(metrics.peakRetainedRows,group.length);
          if (snapshot.open.length) {
            if (onOpenGroup) await onOpenGroup(group,{family:definition.name,
              readHistoryFn:() => readVerifiedRecoveryAction(company,group)});
            else retained.push(...group);
          }
        };
        try {
          while (true) {
            const page = (await client.query('FETCH FORWARD ' + EVENT_HISTORY_PAGE_ROWS + ' FROM ' + cursor)).rows;
            if (!page.length) break;
            for (const row of page) {
              const identity = definition.startOperations.includes(row.operation) ? definition.startId(row)
                : definition.terminalOperations.includes(row.operation) ? definition.terminalId(row)
                  : row.recovery_group_id;
              // Retained earlier schemas are handled by the native predicate,
              // never promoted to the current action protocol by SQL grouping.
              if (identity == null) {
                const ignored=definition.validate([row]);
                if (ignored.complete.length || ignored.open.length) throw new Error('event_recovery_sql_identity_missing');
                continue;
              }
              if (String(identity) !== row.recovery_group_id) throw new Error('event_recovery_sql_identity_mismatch');
              const verifier = createEventStreamVerifier(row.master_pubkey,{
                companyId:company,signerAgentId:signer,signerValidFrom:new Date(row.signer_valid_from).toISOString(),
                previousMutationHash:row.prev_mutation_hash,previousSequence:Number(row.ledger_seq)-1 });
              verifier.accept(row);
              if (key !== row.recovery_group_id) { await finishGroup(); group=[]; key=row.recovery_group_id; }
              group.push(row); metrics.acceptedRows += 1;
            }
          }
          await finishGroup();
        } finally { await client.query('CLOSE ' + cursor); }
      }
      metrics.retainedRows = retained.length;
      if (!onOpenGroup) metrics.spaceComplexity = 'O(cursor_page_plus_largest_action_trace_plus_returned_open_rows)';
      return Object.freeze({rows:Object.freeze(retained),metrics:Object.freeze(metrics)});
    },
  });
}

// Reconciliation rereads only this action and its immediate native terminals,
// on a fresh scope-owned connection, so it observes the owner's committed
// terminal while the grouped recovery cursor retains its original snapshot.
export async function readVerifiedRecoveryAction(companyId, originalRows) {
  const signer = originalRows[0]?.signer_agent_id;
  if (!signer || originalRows.some(row => row.company_id !== companyId
      || row.signer_agent_id !== signer || Number(row.ledger_version) !== 1)) {
    throw new Error('event_recovery_action_scope_invalid');
  }
  const ids = originalRows.map(row => row.id);
  const client = await agentPool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query('SELECT set_config($1,$2,true)',['app.current_client_id',companyId]);
    await client.query('SELECT set_config($1,$2,true)',['app.current_agent_id',signer]);
    const additional = (await client.query(
      "SELECT id FROM aimos_events WHERE company_id=$1 AND signer_agent_id=$4 AND ledger_version=1 AND (parent_event_id=ANY($2::uuid[]) OR "
      + "(operation='canonical_save_terminal' AND metadata#>>'{stages,1,evidence,event_id}'=ANY($3::text[])))",
      [companyId,ids,ids,signer])).rows.map(row => row.id);
    const verified = await readVerifiedEventsByIds([...new Set([...ids,...additional])],companyId,{client});
    await client.query('COMMIT');
    return [...verified.values()].sort((a,b) => new Date(a.signer_valid_from)-new Date(b.signer_valid_from)
      || Number(a.ledger_seq)-Number(b.ledger_seq));
  } catch(error) {
    try { await client.query('ROLLBACK'); } catch {}
    throw error;
  } finally { client.release(); }
}

function checkpointMetadata(row, company, signer) {
  const metadata = typeof row?.metadata === 'string' ? JSON.parse(row.metadata) : row?.metadata;
  const epochHeads = metadata?.prefix_epoch_heads;
  const currentEpoch = Array.isArray(epochHeads)
    ? epochHeads.find((entry) => entry?.valid_from === new Date(row.signer_valid_from).toISOString())
    : null;
  const prefixCount = Number(metadata?.prefix_event_count);
  const unresolved = Array.isArray(metadata?.unresolved_events)
    ? metadata.unresolved_events.map((entry) => ({
      event_id: String(entry?.event_id || '').toLowerCase(),
      mutation_sha256: String(entry?.mutation_sha256 || '').toLowerCase(),
      operation: String(entry?.operation || ''),
      key: entry?.key == null ? null : String(entry.key),
    })).sort((left, right) => left.event_id.localeCompare(right.event_id))
    : null;
  const exactCount = Array.isArray(epochHeads)
    && epochHeads.every((entry) => Number.isSafeInteger(Number(entry?.ledger_seq))
      && Number(entry.ledger_seq) >= 1
      && /^[0-9a-f]{64}$/.test(String(entry?.mutation_sha256 || '')))
    ? epochHeads.reduce((sum, entry) => sum + Number(entry.ledger_seq), 0)
    : -1;
  if (row?.operation !== RECOVERY_CHECKPOINT_OPERATION
      || row.company_id !== company
      || row.signer_agent_id !== signer
      || row.agent_id !== 'housekeeper'
      || metadata?.schema !== RECOVERY_CHECKPOINT_SCHEMA
      || metadata?.algorithm !== 'verified-event-history-chain/v1'
      || metadata?.company_id !== company
      || metadata?.signer_agent_id !== signer
      || !unresolved
      || !Number.isSafeInteger(Number(metadata?.unresolved_count))
      || Number(metadata.unresolved_count) !== unresolved.length
      || unresolved.some((entry) => !EVENT_ID_PATTERN.test(entry.event_id)
        || !/^[0-9a-f]{64}$/.test(entry.mutation_sha256)
        || !entry.operation)
      || metadata?.unresolved_root_sha256 !== unresolvedRoot(unresolved)
      || !Number.isSafeInteger(prefixCount) || prefixCount < 0 || prefixCount !== exactCount
      || !/^[0-9a-f]{64}$/.test(String(metadata?.prefix_history_sha256 || ''))
      || !currentEpoch
      || Number(currentEpoch.ledger_seq) !== Number(row.ledger_seq) - 1
      || currentEpoch.mutation_sha256 !== Buffer.from(row.prev_mutation_hash).toString('hex')) {
    throw new Error('event_recovery_checkpoint_invalid');
  }
  const body = {
    schema: metadata.schema,
    algorithm: metadata.algorithm,
    company_id: metadata.company_id,
    signer_agent_id: metadata.signer_agent_id,
    prefix_event_count: prefixCount,
    prefix_history_sha256: metadata.prefix_history_sha256,
    prefix_epoch_heads: epochHeads,
    unresolved_count: Number(metadata.unresolved_count),
    unresolved_root_sha256: metadata.unresolved_root_sha256,
    unresolved_events: unresolved,
  };
  if (metadata.checkpoint_sha256 !== sha256(Buffer.from(canonicalJson(body), 'utf8')).toString('hex')) {
    throw new Error('event_recovery_checkpoint_commitment_invalid');
  }
  return Object.freeze({ ...body, checkpoint_sha256: metadata.checkpoint_sha256 });
}

async function assertCheckpointUnresolvedCommitment(client, checkpointRow, checkpoint) {
  const result = await client.query(
    `WITH starts AS (
       SELECT id,operation,key,mutation_hash
         FROM aimos_events
        WHERE company_id=$1 AND signer_agent_id=$2 AND ledger_version=1
          AND operation=ANY($5::text[])
          AND (signer_valid_from<$3::timestamptz
            OR (signer_valid_from=$3::timestamptz AND ledger_seq<$4))
     ), terminals AS (
       SELECT CASE
                WHEN operation='canonical_save_terminal'
                 AND metadata->'stages'->1->'evidence'->>'kind'='verified_housekeeper_action'
                THEN metadata->'stages'->1->'evidence'->>'event_id'
                ELSE parent_event_id::text
              END AS start_id,
              CASE
                WHEN operation='material_effect_terminal' THEN 'material_effect_started'
                WHEN operation=ANY($6::text[]) THEN 'tool_execution_started'
                WHEN operation=ANY($7::text[]) THEN 'tool_context_prepared'
                WHEN operation IN ('canonical_save_terminal','canonical_save_action_recovery_terminal')
                  THEN 'canonical_save_action_started'
                WHEN operation='agent_run_terminal' THEN 'agent_run_started'
                WHEN operation='session_lane_terminal' THEN 'session_lane_started'
                WHEN operation='system_job_terminal' THEN 'system_job_started'
                WHEN operation=ANY($8::text[]) THEN 'schedule_run_reserved'
                ELSE NULL
              END AS start_operation
         FROM aimos_events
        WHERE company_id=$1 AND signer_agent_id=$2 AND ledger_version=1
          AND operation=ANY($9::text[])
          AND (signer_valid_from<$3::timestamptz
            OR (signer_valid_from=$3::timestamptz AND ledger_seq<$4))
     )
     SELECT s.id::text,s.operation,s.key,encode(s.mutation_hash,'hex') AS mutation_sha256
       FROM starts s
       LEFT JOIN terminals t ON t.start_id=s.id::text AND t.start_operation=s.operation
      WHERE t.start_id IS NULL`,
    [checkpointRow.company_id, checkpointRow.signer_agent_id,
      new Date(checkpointRow.signer_valid_from).toISOString(), Number(checkpointRow.ledger_seq),
      ['material_effect_started', 'tool_execution_started', 'tool_context_prepared',
        'canonical_save_action_started', 'agent_run_started', 'session_lane_started',
        'system_job_started', 'schedule_run_reserved'],
      ['tool_execution_terminal', 'tool_execution_succeeded', 'tool_execution_failed',
        'tool_execution_indeterminate'],
      ['model_context_completed', 'model_context_terminal'],
      ['schedule_run_completed', 'schedule_run_failed'],
      ['material_effect_terminal', 'tool_execution_terminal', 'tool_execution_succeeded',
        'tool_execution_failed', 'tool_execution_indeterminate', 'model_context_completed',
        'model_context_terminal', 'canonical_save_terminal', 'canonical_save_action_recovery_terminal',
        'agent_run_terminal', 'session_lane_terminal', 'system_job_terminal',
        'schedule_run_completed', 'schedule_run_failed']],
  );
  const actual = result.rows.map((entry) => ({
    event_id: String(entry.id).toLowerCase(),
    mutation_sha256: String(entry.mutation_sha256).toLowerCase(),
    operation: String(entry.operation),
    key: entry.key == null ? null : String(entry.key),
  })).sort((left, right) => left.event_id.localeCompare(right.event_id));
  if (canonicalJson(actual) !== canonicalJson(checkpoint.unresolved_events)) {
    throw new Error(`event_recovery_checkpoint_unresolved_omission:${actual.length}:${checkpoint.unresolved_events.length}:${actual.slice(0, 8).map((entry) => entry.operation).join(',')}`);
  }
}

/**
 * Read only the verified suffix required for boot recovery. A Housekeeper-
 * signed checkpoint authenticates the fully verified prefix and its exact
 * unresolved-start set; every referenced start and every suffix row is then
 * checked in canonical signer-epoch/sequence order. The operation filter is
 * applied only after proof verification.
 */
export async function readVerifiedRecoveryHistory(companyId, {
  signerAgentId = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
  operations = [],
  reducer = null,
  onOpenGroup = null,
} = {}) {
  const company = String(companyId || '').trim();
  const signer = String(signerAgentId || '').trim();
  const selected = new Set((Array.isArray(operations) ? operations : []).map((value) => String(value)));
  if (!company || !signer || !selected.size) throw new Error('event_recovery_scope_required');
  const conn = await agentPool.connect();
  const cursor = `aimos_recovery_${randomUUID().replaceAll('-', '')}`;
  let declared = false;
  let failure = null;
  try {
    await conn.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
    await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', signer]);
    const locator = await conn.query(
      `SELECT id FROM aimos_events
        WHERE company_id=$1 AND signer_agent_id=$2 AND ledger_version=1
          AND operation=$3
        ORDER BY signer_valid_from DESC,ledger_seq DESC LIMIT 1`,
      [company, signer, RECOVERY_CHECKPOINT_OPERATION],
    );
    const checkpointRow = locator.rows[0]
      ? await readVerifiedEventById(locator.rows[0].id, company, { client: conn })
      : null;
    const checkpointMaster = checkpointRow
      ? (await conn.query('SELECT master_pubkey FROM aimos_master_identity WHERE id=1')).rows[0]?.master_pubkey
      : null;
  const retained = [];
  let completedPrefix = null;
  const retain = async (row) => {
    if (!selected.has(String(row.operation))) return;
    if (!reducer) retained.push(row);
  };
  const finishRetained = () => reducer
    ? reducer.reduce(conn, company, signer, { onOpenGroup, completedPrefix })
    : Object.freeze({ rows: Object.freeze(retained), metrics: null });
  if (!checkpointRow || reducer) {
      let checkpointExpectation=null;
      if (checkpointRow) {
        const checkpoint = checkpointMetadata(checkpointRow, company, signer);
        checkpointExpectation={...checkpoint,eventId:checkpointRow.id};
        await assertCheckpointUnresolvedCommitment(conn, checkpointRow, checkpoint);
        if (checkpoint.unresolved_count === 0) completedPrefix = {
          validFrom:new Date(checkpointRow.signer_valid_from).toISOString(),
          sequence:Number(checkpointRow.ledger_seq),
        };
      }
      // Grouping may bring pre-checkpoint evidence into an action trace. Its
      // chain membership must be verified, not inferred from individual valid
      // signatures. Full verification remains cursor-bounded; do not claim
      // suffix-only replay for this mode.
      const summary = await consumeVerifiedHistory(
        iterateVerifiedEventHistory(company, { client: conn, signerAgentId: signer, checkpointExpectation }),
        retain,
      );
      const reduced = await finishRetained();
      await conn.query('COMMIT');
      return Object.freeze({
        rows: reduced.rows,
        reduction: reduced.metrics,
        summary: Object.freeze({ ...summary, usedCheckpoint: Boolean(completedPrefix),
          checkpointEventId: checkpointRow?.id || null,
          checkpointValidated: Boolean(checkpointRow), fullPrefixVerified: true,
          suffixRowCount: summary.rowCount, retainedRowCount: reduced.rows.length }),
      });
    }

    const checkpoint = checkpointMetadata(checkpointRow, company, signer);
    await assertCheckpointUnresolvedCommitment(conn, checkpointRow, checkpoint);
    const checkpointEpoch = new Date(checkpointRow.signer_valid_from).toISOString();
    let historyChain = advanceEventHistoryChain(
      Buffer.from(checkpoint.prefix_history_sha256, 'hex'),
      checkpointRow.mutation_hash,
    );
    let rowCount = checkpoint.prefix_event_count + 1;
    let suffixRowCount = 0;
    const epochHeads = checkpoint.prefix_epoch_heads.map((entry) => ({ ...entry }));
    const currentIndex = epochHeads.findIndex((entry) => entry.valid_from === checkpointEpoch);
    epochHeads[currentIndex] = {
      valid_from: checkpointEpoch,
      ledger_seq: Number(checkpointRow.ledger_seq),
      mutation_sha256: Buffer.from(checkpointRow.mutation_hash).toString('hex'),
    };
    for (let index = 0; index < checkpoint.unresolved_events.length; index += VERIFIED_EVENT_BATCH_MAX_IDS) {
      const page = checkpoint.unresolved_events.slice(index, index + VERIFIED_EVENT_BATCH_MAX_IDS);
      const verified = await readVerifiedEventsByIds(page.map((entry) => entry.event_id), company, { client: conn });
      for (const expected of page) {
        const row = verified.get(expected.event_id);
        if (!row
            || Buffer.from(row.mutation_hash).toString('hex') !== expected.mutation_sha256
            || row.operation !== expected.operation
            || (row.key == null ? null : String(row.key)) !== expected.key) {
          throw new Error('event_recovery_checkpoint_unresolved_binding_invalid');
        }
        await retain(row);
      }
    }
    await conn.query(`DECLARE ${cursor} NO SCROLL CURSOR WITHOUT HOLD FOR
      SELECT event.*,identity.pubkey,identity.cert,revocation.ts_signed AS revocation_ts_signed,
        master.master_pubkey
      FROM aimos_events event JOIN agent_identity identity
        ON identity.agent_id=event.signer_agent_id AND identity.valid_from=event.signer_valid_from
      LEFT JOIN aimos_agent_revocation_events revocation
        ON revocation.agent_id=identity.agent_id AND revocation.agent_valid_from=identity.valid_from
      LEFT JOIN aimos_master_identity master ON master.id=1
      WHERE event.company_id=$1 AND event.signer_agent_id=$2 AND event.ledger_version=1
        AND (event.signer_valid_from>$3::timestamptz
          OR (event.signer_valid_from=$3::timestamptz AND event.ledger_seq>$4))
      ORDER BY event.signer_valid_from,event.ledger_seq`,
    [company, signer, checkpointEpoch, Number(checkpointRow.ledger_seq)]);
    declared = true;
    let epoch = checkpointEpoch;
    let verifier = createEventStreamVerifier(checkpointMaster, {
      companyId: company,
      signerAgentId: signer,
      signerValidFrom: checkpointEpoch,
      previousMutationHash: checkpointRow.mutation_hash,
      previousSequence: Number(checkpointRow.ledger_seq),
    });
    while (true) {
      const page = (await conn.query(`FETCH FORWARD ${EVENT_HISTORY_PAGE_ROWS} FROM ${cursor}`)).rows;
      if (!page.length) break;
      for (const row of page) {
        const nextEpoch = new Date(row.signer_valid_from).toISOString();
        if (nextEpoch !== epoch) {
          const completed = verifier.finish();
          const completedIndex = epochHeads.findIndex((entry) => entry.valid_from === epoch);
          epochHeads[completedIndex] = { valid_from: epoch,
            ledger_seq: completed.previousSequence + completed.rowCount,
            mutation_sha256: Buffer.from(completed.headMutationHash).toString('hex') };
          if (nextEpoch <= epoch) throw new Error('event_history_epoch_order_invalid');
          epoch = nextEpoch;
          verifier = createEventStreamVerifier(row.master_pubkey);
          epochHeads.push({ valid_from: epoch, ledger_seq: 0, mutation_sha256: '' });
        }
        verifier.accept(row);
        historyChain = advanceEventHistoryChain(historyChain, row.mutation_hash);
        rowCount += 1;
        suffixRowCount += 1;
        await retain(row);
      }
    }
    const completed = verifier.finish();
    const completedIndex = epochHeads.findIndex((entry) => entry.valid_from === epoch);
    epochHeads[completedIndex] = { valid_from: epoch,
      ledger_seq: completed.previousSequence + completed.rowCount,
      mutation_sha256: Buffer.from(completed.headMutationHash).toString('hex') };
    await conn.query(`CLOSE ${cursor}`);
    declared = false;
    const reduced = await finishRetained();
    await conn.query('COMMIT');
    return Object.freeze({
      rows: reduced.rows,
      reduction: reduced.metrics,
      summary: Object.freeze({ verified: true, companyId: company, signerAgentId: signer,
        rowCount, epochCount: epochHeads.length, historySha256: historyChain.toString('hex'),
        epochHeads: Object.freeze(epochHeads.map((entry) => Object.freeze(entry))),
        pageRows: EVENT_HISTORY_PAGE_ROWS, complete: true, usedCheckpoint: true,
        checkpointEventId: checkpointRow.id, suffixRowCount, retainedRowCount: reduced.rows.length }),
    });
  } catch (error) {
    failure = error;
    try { if (declared) await conn.query(`CLOSE ${cursor}`); } catch { /* discard below */ }
    try { await conn.query('ROLLBACK'); } catch { /* discard below */ }
    throw error;
  } finally {
    conn.release(failure || undefined);
  }
}

export async function writeVerifiedRecoveryCheckpoint(companyId, summary, {
  signerAgentId = HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
  unresolvedEvents = [],
} = {}) {
  const company = String(companyId || '').trim();
  const signer = String(signerAgentId || '').trim();
  const epochHeads = Array.isArray(summary?.epochHeads)
    ? summary.epochHeads.map((entry) => ({ valid_from: new Date(entry.valid_from).toISOString(),
      ledger_seq: Number(entry.ledger_seq), mutation_sha256: String(entry.mutation_sha256) }))
    : [];
  const head = epochHeads.at(-1);
  const unresolved = (Array.isArray(unresolvedEvents) ? unresolvedEvents : []).map((row) => ({
    event_id: String(row?.id || row?.event_id || '').toLowerCase(),
    mutation_sha256: Buffer.from(row?.mutation_hash || [], typeof row?.mutation_hash === 'string' ? 'hex' : undefined).toString('hex'),
    operation: String(row?.operation || ''),
    key: row?.key == null ? null : String(row.key),
  })).sort((left, right) => left.event_id.localeCompare(right.event_id));
  if (!company || signer !== HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID
      || !summary?.verified || !summary?.complete || !head
      || !Number.isSafeInteger(Number(summary.rowCount)) || Number(summary.rowCount) < 0
      || !/^[0-9a-f]{64}$/.test(String(summary.historySha256 || ''))
      || !/^[0-9a-f]{64}$/.test(head.mutation_sha256)
      || unresolved.some((entry) => !EVENT_ID_PATTERN.test(entry.event_id)
        || !/^[0-9a-f]{64}$/.test(entry.mutation_sha256) || !entry.operation)) {
    throw new Error('event_recovery_checkpoint_summary_invalid');
  }
  if (summary.usedCheckpoint && Number(summary.suffixRowCount) === 0 && unresolved.length === 0) {
    return Object.freeze({ existing: true, event_id: summary.checkpointEventId });
  }
  const body = {
    schema: RECOVERY_CHECKPOINT_SCHEMA,
    algorithm: 'verified-event-history-chain/v1',
    company_id: company,
    signer_agent_id: signer,
    prefix_event_count: Number(summary.rowCount),
    prefix_history_sha256: summary.historySha256,
    prefix_epoch_heads: epochHeads,
    unresolved_count: unresolved.length,
    unresolved_root_sha256: unresolvedRoot(unresolved),
    unresolved_events: unresolved,
  };
  const checkpointSha256 = sha256(Buffer.from(canonicalJson(body), 'utf8')).toString('hex');
  return logEvent(company, 'housekeeper', RECOVERY_CHECKPOINT_OPERATION, checkpointSha256, {
    ...body,
    checkpoint_sha256: checkpointSha256,
    reasoning: 'Housekeeper signed the completely verified event-history prefix after every retained open action was reconciled without replay.',
    source_knowledge: 'event-ledger.js — RFC 6962 / RFC 8032 bounded recovery checkpoint',
  }, null, {
    returnReceipt: true,
    exclusiveOperationKey: true,
    expectedPreviousMutationHash: head.mutation_sha256,
    expectedLedgerSequence: Number(head.ledger_seq) + 1,
  });
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

const VERIFIED_EVENT_BATCH_MAX_IDS = 4_000;
const EVENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Read and independently verify a bounded set of exact retained events in one
 * database round trip. This is the batch form of readVerifiedEventById() for a
 * request-scoped owner that must verify many relational authority references
 * without creating an N+1 query path.
 */
export async function readVerifiedEventsByIds(eventIds, companyId, {
  client = null,
  queryFn = null,
} = {}) {
  const company = String(companyId || '').trim();
  const ids = [...new Set((Array.isArray(eventIds) ? eventIds : [])
    .map((value) => String(value || '').trim().toLowerCase()))].sort();
  if (!company || (!client && typeof queryFn !== 'function')) {
    throw new Error('event_receipt_batch_scope_required');
  }
  if (!ids.length) return new Map();
  if (ids.length > VERIFIED_EVENT_BATCH_MAX_IDS || ids.some((id) => !EVENT_ID_PATTERN.test(id))) {
    throw new Error('event_receipt_batch_bound_invalid');
  }
  const idSet = new Set(ids);

  const execute = typeof queryFn === 'function' ? queryFn : client.query.bind(client);
  const result = await execute(
    `SELECT event.*, identity.pubkey, identity.cert,
            revocation.ts_signed AS revocation_ts_signed,
            predecessor.mutation_hash AS stored_predecessor_hash,
            master.master_pubkey
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
       LEFT JOIN aimos_master_identity master
         ON master.id = 1
      WHERE event.id = ANY($1::uuid[])
        AND event.company_id = $2
        AND event.ledger_version = $3
      ORDER BY event.id`,
    [ids, company, EVENT_LEDGER_VERSION],
  );
  if (result.rows.length !== ids.length) throw new Error('event_receipt_batch_incomplete');

  const verified = new Map();
  for (const row of result.rows) {
    const id = String(row.id || '').toLowerCase();
    if (!idSet.has(id) || verified.has(id)) throw new Error('event_receipt_batch_result_invalid');
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
      : row.master_pubkey;
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
    if (expectedPredecessor.length !== 32
      || !Buffer.from(row.prev_mutation_hash).equals(expectedPredecessor)) {
      throw new Error('event_ledger_chain_link_invalid');
    }
    const proof = verifyEventProof(row, row.pubkey);
    if (!proof.valid) throw new Error(`event_ledger_proof_invalid:${proof.reason}`);
    verified.set(id, row);
  }
  return verified;
}

/**
 * Append one signed event to the housekeeper stream for a company.
 * Existing positional arguments are retained because 170 native callers share
 * this service boundary. The implementation itself is the single ledger owner.
 */
export async function logEvent(companyId, subjectAgentId, operation, key = null, metadata = {}, parentEventId = null, options = {}) {
  const finishWork = beginServingWork('signed_event');
  try {
  if (options.payloadSchema != null && options.payloadSchema !== EVENT_EXACT_PAYLOAD_SCHEMA) {
    throw new Error('event_payload_schema_invalid');
  }
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
  // External event logging must not mint calibration-owner authority. The
  // native feedback route binds its full admitted request separately.
  if (authority && (['recall_calibration_genesis', 'recall_calibration_update',
      'memory_credit_projection', 'memory_credit_evaluation', 'memory_credit_observation_processed'].includes(op)
      || (op === 'recall_calibration_observation_batch'
        && (authority.signedMethod !== 'POST'
          || authority.signedPath !== '/aimos/recall/calibration/observe')))) {
    throw Object.assign(new Error('calibration_operation_owner_required'), { statusCode: 403 });
  }
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
    if (options.expectedLedgerSequence != null
        && Number(options.expectedLedgerSequence) !== ledgerSeq) {
      throw new Error('event_expected_ledger_sequence_mismatch');
    }
    if (options.expectedPreviousMutationHash != null
        && !Buffer.from(String(options.expectedPreviousMutationHash), 'hex').equals(prevMutationHash)) {
      throw new Error('event_expected_predecessor_mismatch');
    }
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
    body.payload_schema = EVENT_EXACT_PAYLOAD_SCHEMA;
    body.nonce = nonce;
    const bodyBytes = Buffer.from(canonicalJson(body), 'utf8');
    const contentHash = signedJsonBytesCommitmentV1(EVENT_EXACT_PAYLOAD_SCHEMA, bodyBytes);
    const mutationHash = eventMutationHash(prevMutationHash, contentHash, nonce, signedTs);
    const sig = signRaw(privkey, contentHash);

    await client.query(
      `INSERT INTO aimos_events
         (id, ts, company_id, agent_id, operation, key, metadata, parent_event_id,
          ledger_version, ledger_seq, signer_agent_id, signer_valid_from,
          cert_fingerprint, identity_tier, authority_kind, signed_body,
          content_hash, mutation_hash, prev_mutation_hash, ts_signed, nonce, sig, signed_body_bytes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
      [
        eventId, new Date(signedTs * 1000), cid, subject, op, eventKey,
        JSON.stringify(safeMetadata), parentEventId || null,
        EVENT_LEDGER_VERSION, ledgerSeq, signerAgentId, signerValidFrom,
        certFingerprint, identityTier, authorityKind, JSON.stringify(body),
        contentHash, mutationHash, prevMutationHash, signedTs, nonce, sig,
        bodyBytes,
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
      signed_body_bytes_b64u: bodyBytes.toString('base64url'),
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
  } finally { finishWork(); }
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
