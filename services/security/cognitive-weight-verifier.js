// Native portable verifier for the certified cognitive-weight state.
//
// Reproduces the fixed-width baseline, projection, and transition commitments;
// verifies exact signer epochs, retained JCS provenance, and Ed25519 signatures;
// and classifies every memory. It is independent of the SECURITY DEFINER SQL
// verifier and is used to prove parity at ceremony time.
//
// Sources: docs/security/cognitive-weight-chain-SPEC.md; RFC 8032; RFC 6962;
// Efficient Data Structures for Tamper-Evident Logging.

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

import { agentPool } from '../../db/connection.js';
import {
  canonicalJson,
  verifyAgentRevocationProof,
  verifyCertChain,
} from './agent-identity.js';
import { cognitiveBaselineHash, cognitiveTransitionHash } from './housekeeper-signer.js';
import { verifyRecallEvidenceRow } from './memory-provenance.js';
import { verifyEventLedgerChain, verifyEventProof } from '../observe/event-ledger.js';

const CHAIN_DOMAIN = Buffer.from('aimos.cwc/v1\0', 'utf8');
const CORPUS_DOMAIN = Buffer.from('aimos.cognitive-corpus-proof/v1\0', 'utf8');

function uuidBytes(value) {
  const bytes = Buffer.from(String(value || '').replaceAll('-', ''), 'hex');
  if (bytes.length !== 16) throw new Error('cognitive_uuid_malformed');
  return bytes;
}

function int64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64BE(BigInt(value));
  return bytes;
}

function float4(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatBE(Number(value));
  return bytes;
}

function isoOrNull(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function rawVerify(pubkeyB64u, message, signature) {
  try {
    const key = createPublicKey({
      key: Buffer.from(String(pubkeyB64u), 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return verifySignature(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

export function cognitiveProjectionHash({ memoryId, oldWeightMilli, newWeightMilli, provenanceMutationHash, previousHash = null }) {
  const previous = previousHash ? Buffer.from(previousHash) : Buffer.alloc(32);
  const provenance = Buffer.from(provenanceMutationHash || []);
  if (previous.length !== 32 || provenance.length !== 32) throw new Error('cognitive_projection_hash_input_invalid');
  return createHash('sha256').update(Buffer.concat([
    CHAIN_DOMAIN,
    uuidBytes(memoryId),
    int64(oldWeightMilli),
    int64(newWeightMilli),
    provenance,
    previous,
  ])).digest();
}

function epochValidAt(identity, revocation, signedTs) {
  if (!identity) return false;
  const from = Math.floor(new Date(identity.valid_from).getTime() / 1000);
  const until = Math.floor(new Date(identity.valid_until).getTime() / 1000);
  if (!Number.isFinite(from) || !Number.isFinite(until)
      || !Number.isInteger(signedTs) || signedTs < from || signedTs >= until) return false;
  return !revocation || Number(revocation.ts_signed) > signedTs;
}

function certificateBody(cert) {
  try {
    return JSON.parse(Buffer.from(String(cert || ''), 'base64url').toString('utf8'))?.body || null;
  } catch {
    return null;
  }
}

function verifyIdentityEpoch(identity, revocation, signedTs) {
  const certBody = certificateBody(identity?.cert);
  const authorityPubkey = certBody?.issuer === certBody?.agent_id
    ? identity?.pubkey
    : identity?.master_pubkey;
  const cert = authorityPubkey
    ? verifyCertChain(identity.cert, authorityPubkey, { nowFn: () => signedTs })
    : { valid: false, reason: 'certificate_authority_missing' };
  const validFrom = Math.floor(new Date(identity?.valid_from).getTime() / 1000);
  const validUntil = Math.floor(new Date(identity?.valid_until).getTime() / 1000);
  const exact = cert.valid
    && certBody?.agent_id === identity?.agent_id
    && certBody?.pubkey === identity?.pubkey
    && certBody?.device_fp === identity?.device_fp
    && Number(certBody?.valid_from) === validFrom
    && Number(certBody?.valid_until) === validUntil
    && (certBody?.issuer === certBody?.agent_id
      || certBody?.issuer === identity?.master_fingerprint)
    && epochValidAt(identity, revocation, signedTs);
  if (!exact) return { valid: false, reason: cert.reason || 'identity_epoch_mismatch' };
  if (!revocation?.signed_body) return { valid: true, reason: null };
  if (!identity?.master_pubkey
      || revocation.master_fingerprint !== identity.master_fingerprint) {
    return { valid: false, reason: 'revocation_master_mismatch' };
  }
  const revocationProof = verifyAgentRevocationProof(
    revocation,
    identity.master_pubkey,
    identity.cert,
  );
  if (!revocationProof.valid) {
    return { valid: false, reason: `revocation_${revocationProof.reason}` };
  }
  return Number(revocation.ts_signed) > signedTs
    ? { valid: true, reason: null }
    : { valid: false, reason: 'identity_revoked_before_signature' };
}

export function verifyPortableCognitiveBaseline({ baseline, memory, identity, revocation, event }) {
  if (!baseline) return { valid: false, reason: 'baseline_missing' };
  const observedFloat = float4(baseline.observed_weight);
  const certFingerprint = createHash('sha256').update(String(identity?.cert || ''), 'utf8').digest('hex');
  const identityProof = verifyIdentityEpoch(identity, revocation, Number(baseline.observed_ts));
  const exact = baseline.company_id === memory.company_id
    && String(baseline.memory_id) === String(memory.id)
    && Buffer.from(baseline.live_content_hash).equals(Buffer.from(memory.content_hash))
    && observedFloat.equals(Buffer.from(baseline.observed_weight_float4))
    && !observedFloat.equals(float4(1))
    && Math.round(Number(baseline.observed_weight) * 1000) === Number(baseline.retrieval_weight_milli)
    && baseline.attestation_reason === 'retained_nondefault_weight_baseline'
    && baseline.historical_origin_claimed === false
    && baseline.signer_agent_id === 'housekeeper'
    && isoOrNull(identity?.valid_from) !== null
    && isoOrNull(identity?.valid_from) === isoOrNull(baseline.signer_valid_from)
    && certFingerprint === baseline.cert_fingerprint
    && identityProof.valid;
  if (!exact) return { valid: false, reason: identityProof.reason || 'baseline_binding_invalid' };
  if (!event || String(event.id) !== String(baseline.event_id)
      || Buffer.from(event.mutation_hash).toString('hex') !== Buffer.from(baseline.event_mutation_hash).toString('hex')) {
    return { valid: false, reason: 'baseline_event_missing' };
  }
  if (event.company_id !== baseline.company_id
      || event.signer_agent_id !== baseline.signer_agent_id
      || isoOrNull(event.signer_valid_from) === null
      || isoOrNull(event.signer_valid_from) !== isoOrNull(baseline.signer_valid_from)
      || event.cert_fingerprint !== baseline.cert_fingerprint
      || event.event_stream_verified !== true
      || Math.abs(Number(event.ts_signed) - Number(baseline.observed_ts)) > 5
      || !verifyIdentityEpoch(identity, revocation, Number(event.ts_signed)).valid) {
    return { valid: false, reason: 'baseline_event_epoch_invalid' };
  }
  const eventProof = verifyEventProof(event, identity.pubkey);
  if (!eventProof.valid) return { valid: false, reason: `baseline_event_${eventProof.reason}` };
  const metadata = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
  if (event.operation !== 'cognitive_initial_weight_attested'
      || event.key !== String(memory.id)
      || metadata?.schema !== 'hom.aimos.cognitive-initial-weight/v1'
      || metadata?.observed_weight_float4 !== observedFloat.toString('hex')
      || Number(metadata?.weight_milli) !== Number(baseline.retrieval_weight_milli)
      || Number(metadata?.observed_ts) !== Number(baseline.observed_ts)
      || metadata?.memory_content_hash !== Buffer.from(memory.content_hash).toString('hex')
      || metadata?.historical_origin_claimed !== false
      || metadata?.canonical_memory_mutation !== false) {
    return { valid: false, reason: 'baseline_event_binding_invalid' };
  }
  const expectedHash = cognitiveBaselineHash({
    companyId: baseline.company_id,
    memoryId: baseline.memory_id,
    eventId: baseline.event_id,
    eventMutationHash: Buffer.from(baseline.event_mutation_hash),
    liveContentHash: Buffer.from(baseline.live_content_hash),
    observedWeight: Number(baseline.observed_weight),
    weightMilli: Number(baseline.retrieval_weight_milli),
    observedTs: Number(baseline.observed_ts),
    signerValidFromIso: baseline.signer_valid_from,
    certFingerprint: baseline.cert_fingerprint,
  });
  if (!expectedHash.equals(Buffer.from(baseline.baseline_hash))) {
    return { valid: false, reason: 'baseline_hash_invalid' };
  }
  if (!rawVerify(identity.pubkey, expectedHash, baseline.baseline_sig)) {
    return { valid: false, reason: 'baseline_signature_invalid' };
  }
  return { valid: true, reason: null, baselineHash: expectedHash };
}

function orderProjectionRows(rows) {
  if (!rows.length) return [];
  const byHash = new Map();
  const childByPrevious = new Map();
  const genesis = [];
  for (const row of rows) {
    const hash = Buffer.from(row.projection_hash).toString('hex');
    const previous = row.prev_projection_hash ? Buffer.from(row.prev_projection_hash).toString('hex') : null;
    if (byHash.has(hash) || (previous && childByPrevious.has(previous))) throw new Error('cognitive_projection_fork');
    byHash.set(hash, row);
    if (previous) childByPrevious.set(previous, row);
    else genesis.push(row);
  }
  if (genesis.length !== 1) throw new Error('cognitive_projection_genesis_invalid');
  const ordered = [];
  const visited = new Set();
  let current = genesis[0];
  while (current) {
    const hash = Buffer.from(current.projection_hash).toString('hex');
    if (visited.has(hash)) throw new Error('cognitive_projection_cycle');
    visited.add(hash);
    ordered.push(current);
    current = childByPrevious.get(hash) || null;
  }
  if (ordered.length !== rows.length) throw new Error('cognitive_projection_disconnected');
  return ordered;
}

export function verifyPortableCognitiveState({ memory, baseline = null, baselineEvent = null, projections = [] }) {
  const baselineProof = baseline
    ? verifyPortableCognitiveBaseline({
        baseline,
        memory,
        identity: baseline.identity,
        revocation: baseline.revocation,
        event: baselineEvent,
      })
    : null;
  if (!projections.length) {
    if (baseline) {
      const valid = baselineProof.valid
        && float4(memory.retrieval_weight).equals(float4(baseline.observed_weight));
      return {
        memory_id: String(memory.id),
        certification_status: 'signed_initial_weight',
        ok: valid,
        chain_length: 0,
        sigs_verified: 0,
        reason: valid ? null : baselineProof.reason || 'baseline_terminal_weight_mismatch',
      };
    }
    const isDefault = float4(memory.retrieval_weight).equals(float4(1));
    return {
      memory_id: String(memory.id),
      certification_status: isDefault ? 'default_empty_chain' : 'unattested_initial_weight',
      ok: isDefault,
      chain_length: 0,
      sigs_verified: 0,
      reason: isDefault ? null : 'unattested_initial_weight',
    };
  }

  let ordered;
  try { ordered = orderProjectionRows(projections); } catch (error) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: 0, sigs_verified: 0, reason: error.message };
  }
  let previousHash = null;
  let previousMilli = null;
  let signatures = 0;
  for (const [index, row] of ordered.entries()) {
    const oldMilli = Number(row.old_weight_milli);
    const newMilli = Number(row.new_weight_milli);
    if (!Number.isInteger(oldMilli) || !Number.isInteger(newMilli)
        || oldMilli < 100 || oldMilli > 3000
        || newMilli < 100 || newMilli > 3000
        || oldMilli === newMilli
        || !float4(row.old_weight).equals(float4(oldMilli / 1000))
        || !float4(row.new_weight).equals(float4(newMilli / 1000))) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'projection_display_invalid' };
    }
    if (previousMilli !== null && oldMilli !== previousMilli) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'continuity_break' };
    }
    const provenance = row.provenance;
    const provenanceProof = verifyRecallEvidenceRow(provenance);
    let provenanceBody = provenance.body_json;
    if (typeof provenanceBody === 'string') {
      try { provenanceBody = JSON.parse(provenanceBody); } catch { provenanceBody = null; }
    }
    const provenanceBound = provenance.event_type === 'REWEIGHT'
      && Number(provenance.binding_schema_version) === 2
      && provenance.provenance_agent_id === 'housekeeper'
      && provenance.backfilled === false
      && provenanceBody?.event_type === 'REWEIGHT'
      && provenanceBody?.company_id === memory.company_id
      && String(provenanceBody?.memory_id) === String(memory.id)
      && Math.round(Number(provenanceBody?.old_weight) * 1000) === oldMilli
      && Math.round(Number(provenanceBody?.new_weight) * 1000) === newMilli
      && String(row.company_id) === String(memory.company_id)
      && String(row.memory_id) === String(memory.id)
      && Buffer.from(row.provenance_mutation_hash).equals(Buffer.from(provenance.mutation_hash));
    if (!provenanceProof.valid || !provenanceBound) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: `provenance_${provenanceProof.reason || 'event_type_invalid'}` };
    }
    const expectedProjection = cognitiveProjectionHash({
      memoryId: memory.id,
      oldWeightMilli: oldMilli,
      newWeightMilli: newMilli,
      provenanceMutationHash: Buffer.from(row.provenance_mutation_hash),
      previousHash,
    });
    if (!expectedProjection.equals(Buffer.from(row.projection_hash))) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'projection_hash_invalid' };
    }
    const expectedTransition = cognitiveTransitionHash({
      companyId: memory.company_id,
      memoryId: memory.id,
      oldWeight: oldMilli / 1000,
      newWeight: newMilli / 1000,
      provenanceMutationHash: Buffer.from(row.provenance_mutation_hash),
    });
    if (!expectedTransition.equals(Buffer.from(row.transition_hash))
        || !rawVerify(provenance.signer_pubkey, expectedTransition, row.transition_sig)) {
      return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: index, sigs_verified: signatures, reason: 'transition_signature_invalid' };
    }
    previousHash = expectedProjection;
    previousMilli = newMilli;
    signatures += 1;
  }
  if (baseline && (!baselineProof.valid || Number(baseline.retrieval_weight_milli) !== Number(ordered[0].old_weight_milli))) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: ordered.length, sigs_verified: signatures, reason: 'baseline_chain_anchor_invalid' };
  }
  if (!baseline && Number(ordered[0].old_weight_milli) !== 1000) {
    return { memory_id: String(memory.id), certification_status: 'certified_chain', ok: false, chain_length: ordered.length, sigs_verified: signatures, reason: 'default_chain_anchor_invalid' };
  }
  const terminalValid = float4(memory.retrieval_weight).equals(float4(previousMilli / 1000));
  return {
    memory_id: String(memory.id),
    certification_status: 'certified_chain',
    ok: terminalValid,
    chain_length: ordered.length,
    sigs_verified: signatures,
    reason: terminalValid ? null : 'terminal_weight_mismatch',
  };
}

export async function verifyCognitiveWeightCorpus({ companyId, client = null } = {}) {
  const company = String(companyId || '').trim();
  if (!company) throw new Error('cognitive_company_scope_required');
  const ownsTransaction = !client;
  const conn = client || await agentPool.connect();
  try {
    if (ownsTransaction) {
      await conn.query('BEGIN');
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_client_id', company]);
      await conn.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', 'housekeeper']);
    }
    // A single PostgreSQL client owns this snapshot. Execute sequentially so
    // every query observes one explicit transaction without driver-level
    // concurrent-query ambiguity.
    const master = await conn.query(
      `SELECT master_pubkey, fingerprint AS master_fingerprint
         FROM aimos_master_identity WHERE id=1`,
    );
    const masterIdentity = master.rows[0] || {};
    const memories = await conn.query(
      `SELECT id::text, company_id, content_hash, retrieval_weight FROM aimos_memories WHERE company_id=$1 ORDER BY id`,
      [company],
    );
    const baselines = await conn.query(
        `SELECT b.*, i.agent_id, i.pubkey, i.cert, i.device_fp,
                i.valid_from, i.valid_until,
                master.master_pubkey, master.master_fingerprint,
                rev.master_fingerprint AS revocation_master_fingerprint,
                rev.target_cert_hash AS revocation_target_cert_hash,
                rev.prior_identity_hash AS revocation_prior_identity_hash,
                rev.signed_body AS revocation_signed_body,
                rev.content_hash AS revocation_content_hash,
                rev.mutation_hash AS revocation_mutation_hash,
                rev.ts_signed AS revocation_ts_signed,
                rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
           FROM aimos_cognitive_weight_baselines b
           JOIN agent_identity i ON i.agent_id=b.signer_agent_id AND i.valid_from=b.signer_valid_from
           LEFT JOIN LATERAL (
             SELECT master_pubkey, fingerprint AS master_fingerprint
               FROM aimos_master_identity WHERE id=1
           ) master ON true
           LEFT JOIN aimos_agent_revocation_events rev ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
          WHERE b.company_id=$1`,
        [company],
      );
    const events = await conn.query(
        `SELECT e.*, i.pubkey, i.cert, i.device_fp, i.valid_until,
                rev.master_fingerprint AS revocation_master_fingerprint,
                rev.target_cert_hash AS revocation_target_cert_hash,
                rev.prior_identity_hash AS revocation_prior_identity_hash,
                rev.signed_body AS revocation_signed_body,
                rev.content_hash AS revocation_content_hash,
                rev.mutation_hash AS revocation_mutation_hash,
                rev.ts_signed AS revocation_ts_signed,
                rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
           FROM aimos_events e
           JOIN agent_identity i ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
           LEFT JOIN aimos_agent_revocation_events rev ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
          WHERE e.company_id=$1 AND e.signer_agent_id='housekeeper'
            AND e.ledger_version=1
          ORDER BY e.signer_valid_from,e.ledger_seq`,
        [company],
      );
    const projections = await conn.query(
        `SELECT p.*,
                pr.provenance_id, pr.body_json, pr.content_hash AS prov_content_hash,
                pr.mutation_hash, pr.prev_mutation_hash, pr.ts_signed, pr.nonce,
                pr.sig, pr.event_type, pr.binding_schema_version, pr.agent_id AS provenance_agent_id,
                pr.agent_valid_from, pr.cert_fingerprint, pr.identity_tier,
                pr.sig_form_version, pr.request_sig_form, pr.signed_method,
                pr.signed_path, pr.signed_claims, pr.is_genesis, pr.backfilled,
                pr.memory_originated_at, i.pubkey AS signer_pubkey,
                i.cert AS signer_cert, i.valid_until AS signer_valid_until,
                i.device_fp AS signer_device_fp,
                master.master_pubkey, master.fingerprint AS master_fingerprint,
                rev.master_fingerprint AS revocation_master_fingerprint,
                rev.target_cert_hash AS revocation_target_cert_hash,
                rev.prior_identity_hash AS revocation_prior_identity_hash,
                rev.signed_body AS revocation_signed_body,
                rev.content_hash AS revocation_content_hash,
                rev.mutation_hash AS revocation_mutation_hash,
                rev.ts_signed AS revocation_ts_signed,
                rev.nonce AS revocation_nonce, rev.sig AS revocation_sig
           FROM aimos_cognitive_weight_projections p
           JOIN aimos_memory_provenance pr
             ON pr.memory_id=p.memory_id AND pr.mutation_hash=p.provenance_mutation_hash
           JOIN agent_identity i ON i.agent_id=pr.agent_id AND i.valid_from=pr.agent_valid_from
           LEFT JOIN aimos_agent_revocation_events rev ON rev.agent_id=i.agent_id AND rev.agent_valid_from=i.valid_from
           LEFT JOIN LATERAL (
             SELECT master_pubkey, fingerprint FROM aimos_master_identity WHERE id=1
           ) master ON true
          WHERE p.company_id=$1
          ORDER BY p.memory_id,p.projection_id`,
        [company],
      );
    const sqlRows = await conn.query(
      `SELECT * FROM public.verify_all_cognitive_weight_chains() ORDER BY memory_id`,
    );

    const verifiedEventIds = new Set();
    const eventsByEpoch = new Map();
    for (const row of events.rows) {
      const epoch = isoOrNull(row.signer_valid_from);
      if (!epoch) throw new Error('cognitive_event_epoch_malformed');
      if (!eventsByEpoch.has(epoch)) eventsByEpoch.set(epoch, []);
      eventsByEpoch.get(epoch).push(row);
    }
    for (const rows of eventsByEpoch.values()) {
      let streamValid = true;
      for (const row of rows) {
        const revocation = row.revocation_signed_body ? {
          agent_id: row.signer_agent_id,
          agent_valid_from: row.signer_valid_from,
          master_fingerprint: row.revocation_master_fingerprint,
          target_cert_hash: row.revocation_target_cert_hash,
          prior_identity_hash: row.revocation_prior_identity_hash,
          signed_body: row.revocation_signed_body,
          content_hash: row.revocation_content_hash,
          mutation_hash: row.revocation_mutation_hash,
          ts_signed: row.revocation_ts_signed,
          nonce: row.revocation_nonce,
          sig: row.revocation_sig,
        } : null;
        const identityProof = verifyIdentityEpoch({
          ...row,
          agent_id: row.signer_agent_id,
          valid_from: row.signer_valid_from,
          master_pubkey: masterIdentity.master_pubkey,
          master_fingerprint: masterIdentity.master_fingerprint,
        }, revocation, Number(row.ts_signed));
        if (!identityProof.valid) streamValid = false;
      }
      if (streamValid) {
        try {
          verifyEventLedgerChain(rows, { masterPubkey: masterIdentity.master_pubkey || null });
        } catch {
          streamValid = false;
        }
      }
      if (streamValid) {
        for (const row of rows) verifiedEventIds.add(String(row.id));
      }
    }

    const baselineByMemory = new Map(baselines.rows.map((row) => [String(row.memory_id), {
      ...row,
      identity: row,
      revocation: row.revocation_signed_body ? {
        agent_id: row.signer_agent_id,
        agent_valid_from: row.signer_valid_from,
        master_fingerprint: row.revocation_master_fingerprint,
        target_cert_hash: row.revocation_target_cert_hash,
        prior_identity_hash: row.revocation_prior_identity_hash,
        signed_body: row.revocation_signed_body,
        content_hash: row.revocation_content_hash,
        mutation_hash: row.revocation_mutation_hash,
        ts_signed: row.revocation_ts_signed,
        nonce: row.revocation_nonce,
        sig: row.revocation_sig,
      } : null,
    }]));
    const eventById = new Map(events.rows.map((row) => [String(row.id), {
      ...row,
      event_stream_verified: verifiedEventIds.has(String(row.id)),
    }]));
    const projectionByMemory = new Map();
    for (const row of projections.rows) {
      const id = String(row.memory_id);
      if (!projectionByMemory.has(id)) projectionByMemory.set(id, []);
      projectionByMemory.get(id).push({ ...row, provenance: { ...row, memory_id: id } });
    }
    const records = memories.rows.map((memory) => {
      const baseline = baselineByMemory.get(String(memory.id)) || null;
      const memoryProjections = projectionByMemory.get(String(memory.id)) || [];
      try {
        return verifyPortableCognitiveState({
          memory,
          baseline,
          baselineEvent: baseline ? eventById.get(String(baseline.event_id)) : null,
          projections: memoryProjections,
        });
      } catch {
        return {
          memory_id: String(memory.id),
          certification_status: memoryProjections.length
            ? 'certified_chain'
            : baseline
              ? 'signed_initial_weight'
              : 'unattested_initial_weight',
          ok: false,
          chain_length: 0,
          sigs_verified: 0,
          reason: 'portable_evidence_malformed',
        };
      }
    });
    const sqlById = new Map(sqlRows.rows.map((row) => [String(row.memory_id), row]));
    const parity = records.every((record) => {
      const sql = sqlById.get(record.memory_id);
      return sql && Boolean(sql.ok) === record.ok
        && sql.certification_status === record.certification_status
        && Number(sql.chain_length) === record.chain_length
        && Number(sql.sigs_verified) === record.sigs_verified;
    }) && sqlRows.rows.length === records.length;
    const proofRecords = records.map((record) => ({
      memory_id: record.memory_id,
      certification_status: record.certification_status,
      ok: record.ok,
      chain_length: record.chain_length,
      sigs_verified: record.sigs_verified,
      reason: record.reason,
    }));
    const proofRoot = createHash('sha256').update(Buffer.concat([
      CORPUS_DOMAIN,
      Buffer.from(canonicalJson(proofRecords), 'utf8'),
    ])).digest();
    if (ownsTransaction) await conn.query('COMMIT');
    return { records, sqlRows: sqlRows.rows, parity, proofRoot };
  } catch (error) {
    if (ownsTransaction) {
      try { await conn.query('ROLLBACK'); } catch { /* connection may be unavailable */ }
    }
    throw error;
  } finally {
    if (ownsTransaction) conn.release();
  }
}
