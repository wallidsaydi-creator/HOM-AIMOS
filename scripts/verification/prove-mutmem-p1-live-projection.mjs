#!/usr/bin/env node

// P1 live projection proof. One signed native RECALL is projected into the
// portable v2 envelope. The script performs no SAVE, classification, weight,
// authorization, schema, or configuration mutation.

import { createHash } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentPool, pool } from '../../db/connection.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  createMutMemPortableEvidenceEnvelopeV2,
  createMutMemPortableObjectV2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2 as SCHEMA,
  evaluateMutMemPortablePredicatesV2,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import { normalizeNativeRecallCommand } from '../../services/retrieval/native-recall.js';
import {
  occurrenceReferenceForProvenanceRow,
} from '../../services/security/memory-provenance.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'artifacts/security/mutmem-v2/p1-live-projection');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX32 = /^[0-9a-f]{64}$/;

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function isoEpoch(value) {
  const number = Number(value);
  const date = Number.isFinite(number)
    ? new Date(number < 10_000_000_000 ? number * 1000 : number)
    : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('p1_live_identity_epoch_invalid');
  return date.toISOString();
}

function hex(value) {
  if (value == null) return null;
  return Buffer.from(value).toString('hex');
}

function b64u(value) {
  if (value == null) return null;
  return Buffer.from(value).toString('base64url');
}

function decodeCertificate(certificate) {
  const envelope = JSON.parse(Buffer.from(String(certificate), 'base64url').toString('utf8'));
  if (!envelope?.body) throw new Error('p1_live_certificate_invalid');
  return envelope.body;
}

async function eventById(id) {
  if (!UUID.test(String(id || ''))) throw new Error('p1_live_event_id_invalid');
  const result = await pool.query(
    `SELECT id::text,company_id,agent_id,operation,key,metadata,parent_event_id::text,
            proof_required,ledger_version,ledger_seq,signer_agent_id,signer_valid_from,
            cert_fingerprint,identity_tier,authority_kind,signed_body,
            encode(content_hash,'hex') content_hash,
            encode(mutation_hash,'hex') mutation_hash,
            encode(prev_mutation_hash,'hex') prev_mutation_hash,
            ts_signed,nonce,encode(sig,'base64') sig_base64
       FROM aimos_events WHERE id=$1::uuid`,
    [id],
  );
  if (result.rowCount !== 1) throw new Error('p1_live_event_missing');
  return result.rows[0];
}

function eventReceiptProjection(row, signerCertificate) {
  const signature = Buffer.from(String(row.sig_base64 || ''), 'base64').toString('base64url');
  return {
    event_id: row.id,
    proof_required: row.proof_required,
    ledger_version: Number(row.ledger_version),
    ledger_seq: Number(row.ledger_seq),
    signed_body: asObject(row.signed_body),
    content_hash: row.content_hash,
    mutation_hash: row.mutation_hash,
    prev_mutation_hash: row.prev_mutation_hash,
    signer_agent_id: row.signer_agent_id,
    signer_valid_from: new Date(row.signer_valid_from).toISOString(),
    cert_fingerprint: row.cert_fingerprint,
    identity_tier: row.identity_tier,
    ts_signed: Number(row.ts_signed),
    nonce: row.nonce,
    signature_b64u: signature,
    signer_certificate: signerCertificate,
  };
}

async function identityProjection(agentId, validFromIso, certificate, schema) {
  const result = await pool.query(
    `SELECT agent_id,valid_from,valid_until,pubkey,cert
       FROM agent_identity WHERE agent_id=$1 AND valid_from=$2`,
    [agentId, validFromIso],
  );
  if (result.rowCount !== 1 || result.rows[0].cert !== certificate) {
    throw new Error('p1_live_identity_row_missing');
  }
  const certificateBody = decodeCertificate(certificate);
  const identityTier = certificateBody.agent_id === 'housekeeper'
    && certificateBody.issuer === 'housekeeper'
    ? 'T1_SYSTEM_SELF'
    : 'T1';
  return {
    schema,
    company_id: 'hom',
    agent_id: agentId,
    valid_from: new Date(result.rows[0].valid_from).toISOString(),
    valid_until: new Date(result.rows[0].valid_until).toISOString(),
    cert_fingerprint: sha(Buffer.from(certificate, 'utf8')),
    certificate,
    public_key_b64u: result.rows[0].pubkey,
    identity_tier: identityTier,
  };
}

async function revokedAt(agentId, validFromIso, signedTs) {
  const result = await pool.query(
    `SELECT count(*)::int n FROM aimos_agent_revocation_events
      WHERE agent_id=$1 AND agent_valid_from=$2 AND ts_signed <= $3`,
    [agentId, validFromIso, signedTs],
  );
  return Number(result.rows[0]?.n || 0) > 0;
}

async function provenanceRows(memoryId) {
  const result = await pool.query(
    `SELECT p.*,identity.cert AS signer_cert
       FROM aimos_memory_provenance p
       LEFT JOIN agent_identity identity
         ON identity.agent_id=p.agent_id AND identity.valid_from=p.agent_valid_from
      WHERE p.memory_id=$1::uuid`,
    [memoryId],
  );
  return result.rows;
}

function portableProvenanceRow(row) {
  return {
    provenance_id: String(row.provenance_id),
    memory_id: String(row.memory_id),
    agent_id: row.agent_id,
    agent_valid_from: row.agent_valid_from ? new Date(row.agent_valid_from).toISOString() : null,
    cert_fingerprint: row.cert_fingerprint,
    content_hash: hex(row.content_hash),
    mutation_hash: hex(row.mutation_hash),
    prev_mutation_hash: hex(row.prev_mutation_hash),
    ts_signed: row.ts_signed == null ? null : Number(row.ts_signed),
    nonce: row.nonce,
    signature_b64u: b64u(row.sig),
    identity_tier: row.identity_tier,
    event_type: row.event_type,
    body_json: asObject(row.body_json),
    sig_form_version: Number(row.sig_form_version || 1),
    live_content_hash: hex(row.live_content_hash),
    signer_certificate: row.signer_cert || null,
  };
}

async function epistemicRows(memoryId) {
  const result = await pool.query(
    `SELECT classification_id::text,company_id,memory_id::text,label,confidence_milli,
            authority_event_id::text,encode(event_mutation_hash,'hex') event_mutation_hash,
            encode(live_content_hash,'hex') live_content_hash,
            encode(prev_classification_hash,'hex') prev_classification_hash,
            encode(classification_hash,'hex') classification_hash,classified_at
       FROM aimos_memory_epistemic_classifications
      WHERE memory_id=$1::uuid ORDER BY classified_at,classification_id`,
    [memoryId],
  );
  return result.rows.map((row) => ({
    ...row,
    confidence_milli: Number(row.confidence_milli),
    classified_at: new Date(row.classified_at).toISOString(),
  }));
}

async function main() {
  if (!process.argv.includes('--live')) throw new Error('p1_live_flag_required');
  const health = await fetch('http://127.0.0.1:9100/health').then((response) => response.json());
  if (health.ready !== true || health.runtime?.database_name !== 'aimos') {
    throw new Error('p1_live_server_not_ready');
  }
  const selected = await pool.query(
    `SELECT memory.id::text
       FROM aimos_memories memory
      WHERE memory.company_id='hom'
        AND EXISTS (
          SELECT 1 FROM aimos_memory_provenance provenance
           WHERE provenance.memory_id=memory.id AND provenance.sig_form_version=3
        )
        AND memory.clearance_level <= 10
        AND memory.data_class IN ('public','internal','confidential')
        AND (
          (
            memory.scope IN ('global','executive','system')
            AND (
              memory.clearance_level > 2
              OR memory.agent_id IS NULL
              OR memory.agent_id='codex-auditor'
            )
          )
          OR (
            memory.scope IN ('agent','private','codex-auditor')
            AND memory.agent_id='codex-auditor'
          )
        )
      ORDER BY memory.id LIMIT 1`,
  );
  const memoryId = selected.rows[0]?.id;
  if (!UUID.test(String(memoryId || ''))) throw new Error('p1_live_v3_memory_unavailable');

  const requestBody = {
    memory_id: memoryId,
    limit: 1,
    cache: false,
    answer_shape: 'full_detail',
  };
  const headers = await buildEnvelopeHeaders('codex-auditor', 'POST', '/aimos/recall', requestBody);
  const response = await fetch('http://127.0.0.1:9100/aimos/recall', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody),
  });
  const responseBody = await response.json();
  if (response.status !== 200 || responseBody.memories?.length !== 1
      || String(responseBody.memories[0]?.id) !== memoryId) {
    throw new Error(`p1_live_recall_failed:${response.status}`);
  }
  const nativeReceipt = responseBody.recall_receipt;
  const eventReceipt = nativeReceipt?.event_receipt;
  if (!eventReceipt || nativeReceipt.merkle_schema
      !== 'hom-aimos/recall-merkle/v3-epistemic-and-security-closure') {
    throw new Error('p1_live_v3_receipt_missing');
  }
  const actorCert = headers['Aimos-Agent-Cert'];
  const actorCertBody = decodeCertificate(actorCert);
  const actorValidFrom = isoEpoch(actorCertBody.valid_from);
  const signerCert = eventReceipt.signer_certificate;
  const signerCertBody = decodeCertificate(signerCert);
  const signerValidFrom = isoEpoch(signerCertBody.valid_from);
  const terminalEvent = await eventById(eventReceipt.event_id);
  if (terminalEvent.mutation_hash !== eventReceipt.mutation_hash) {
    throw new Error('p1_live_terminal_event_mismatch');
  }
  const master = (await pool.query(
    'SELECT master_pubkey,fingerprint FROM aimos_master_identity WHERE id=1',
  )).rows[0];
  const actorIdentity = await identityProjection(
    'codex-auditor', actorValidFrom, actorCert, SCHEMA.actor_identity_epoch,
  );
  const housekeeperIdentity = await identityProjection(
    'housekeeper', signerValidFrom, signerCert, SCHEMA.housekeeper_identity_epoch,
  );
  const signedTs = Number(eventReceipt.ts_signed);
  const actorRevoked = await revokedAt('codex-auditor', actorValidFrom, signedTs);
  const housekeeperRevoked = await revokedAt('housekeeper', signerValidFrom, signedTs);
  if (actorRevoked || housekeeperRevoked) throw new Error('p1_live_revoked_epoch');

  const requestReceiptResult = await pool.query(
    `SELECT * FROM aimos_request_receipts WHERE request_receipt_id=$1::uuid`,
    [nativeReceipt.request_receipt_id],
  );
  const requestRow = requestReceiptResult.rows[0];
  if (!requestRow) throw new Error('p1_live_request_receipt_missing');
  const grantResult = await pool.query(
    `SELECT * FROM aimos_recall_authorization_events
      WHERE mutation_hash=$1 ORDER BY created_at DESC LIMIT 2`,
    [Buffer.from(nativeReceipt.authority_mutation_hash, 'hex')],
  );
  if (grantResult.rowCount !== 1) throw new Error('p1_live_grant_ambiguous');
  const grantRow = grantResult.rows[0];

  const epistemicEventId = responseBody.recall_meta?.epistemic_retrieval
    ?.decision_receipt?.event_id;
  const securityEventId = responseBody.recall_meta?.recall_security_closure?.receipt?.event_id;
  const [epistemicEvent, securityEvent] = await Promise.all([
    eventById(epistemicEventId), eventById(securityEventId),
  ]);
  const epistemicMetadata = asObject(epistemicEvent.metadata);
  const securityMetadata = asObject(securityEvent.metadata);
  const admission = responseBody.recall_meta?.content_state_occurrence_admission;
  const returnProjection = nativeReceipt.return_projection;
  const evidence = nativeReceipt.evidence;
  if (!admission || !returnProjection || !Array.isArray(evidence)
      || evidence.length !== 1) throw new Error('p1_live_decision_projection_missing');

  const memory = responseBody.memories[0];
  const proof = memory.provenance_proof;
  const allProvenance = await provenanceRows(memoryId);
  const selectedOccurrence = allProvenance.find(
    (row) => occurrenceReferenceForProvenanceRow(row, 'hom') === evidence[0].occurrence_ref,
  );
  if (!selectedOccurrence) throw new Error('p1_live_occurrence_not_found');
  const occurrenceForm = Number(selectedOccurrence.sig_form_version || 1) === 3
    ? 'v3' : 'legacy_v1';
  const occurrenceBody = occurrenceForm === 'v3'
    ? asObject(selectedOccurrence.body_json)
    : portableProvenanceRow(selectedOccurrence);
  const occurrenceNativeSchema = occurrenceForm === 'v3'
    ? 'hom.aimos.memory-occurrence/v3'
    : 'hom.aimos.memory-occurrence-ref/legacy-v1';
  const classificationRows = await epistemicRows(memoryId);
  const persistedMemory = (await pool.query(
    `SELECT id::text,key,value,scope,memory_type,clearance_level,data_class,source,
            current_epistemic_label,current_epistemic_confidence_milli
       FROM aimos_memories WHERE company_id='hom' AND id=$1::uuid`,
    [memoryId],
  )).rows[0];
  if (!persistedMemory) throw new Error('p1_live_memory_state_missing');

  const singletonBodies = {
    trust_anchor: {
      schema: SCHEMA.trust_anchor,
      master_fingerprint: master.fingerprint,
      master_public_key_b64u: master.master_pubkey,
    },
    actor_identity_epoch: actorIdentity,
    actor_revocation_state: {
      schema: SCHEMA.actor_revocation_state,
      company_id: 'hom', agent_id: 'codex-auditor', valid_from: actorValidFrom,
      evaluated_at_unix_seconds: signedTs, revoked: false,
      source_event_mutation_hash: eventReceipt.mutation_hash,
    },
    housekeeper_identity_epoch: housekeeperIdentity,
    housekeeper_revocation_state: {
      schema: SCHEMA.housekeeper_revocation_state,
      company_id: 'hom', agent_id: 'housekeeper', valid_from: signerValidFrom,
      evaluated_at_unix_seconds: signedTs, revoked: false,
      source_event_mutation_hash: eventReceipt.mutation_hash,
    },
    effective_recall_grant: {
      schema: SCHEMA.effective_recall_grant,
      authority_kind: 'master_signed_recall_grant',
      company_id: grantRow.company_id,
      subject_agent_id: grantRow.subject_agent_id,
      subject_valid_from: new Date(grantRow.subject_valid_from).toISOString(),
      allowed: Boolean(grantRow.allowed),
      write_allowed: Boolean(grantRow.write_allowed),
      clearance_ceiling: Number(grantRow.clearance_ceiling),
      data_class_ceiling: grantRow.data_class_ceiling,
      master_fingerprint: grantRow.master_fingerprint,
      signed_body: asObject(grantRow.signed_body),
      content_hash: hex(grantRow.content_hash),
      mutation_hash: hex(grantRow.mutation_hash),
      prev_mutation_hash: hex(grantRow.prev_mutation_hash),
      ts_signed: Number(grantRow.ts_signed),
      nonce: grantRow.nonce,
      signature_b64u: b64u(grantRow.sig),
    },
    request_envelope: {
      schema: SCHEMA.request_envelope,
      company_id: 'hom', actor_agent_id: 'codex-auditor', actor_valid_from: actorValidFrom,
      cert_fingerprint: sha(Buffer.from(actorCert, 'utf8')),
      request_sig_form: Number(headers['X-Aimos-Sig-Form']),
      signed_method: 'POST', signed_path: '/aimos/recall',
      request_body: requestBody,
      request_body_hash: sha(Buffer.from(canonicalJson(requestBody), 'utf8')),
      outer_request_hash: nativeReceipt.outer_request_hash,
      normalized_command: normalizeNativeRecallCommand(requestBody),
      command_hash: nativeReceipt.command_hash,
      requested_clearance_level: null,
      requested_data_class: null,
      nonce: headers['Aimos-Agent-Nonce'],
      ts_signed: Number(headers['Aimos-Agent-Timestamp']),
      signature_b64u: headers['Aimos-Agent-Signature'],
    },
    request_receipt: {
      schema: SCHEMA.request_receipt,
      request_receipt_id: String(requestRow.request_receipt_id),
      mutation_hash: hex(requestRow.mutation_hash),
      company_id: requestRow.company_id,
      actor_agent_id: requestRow.actor_agent_id,
      actor_valid_from: new Date(requestRow.actor_valid_from).toISOString(),
      cert_fingerprint: requestRow.cert_fingerprint,
      request_sig_form: Number(requestRow.request_sig_form),
      signed_method: requestRow.signed_method,
      signed_path: requestRow.signed_path,
      request_hash: hex(requestRow.request_hash),
      signed_claims: requestRow.signed_claims == null ? null : asObject(requestRow.signed_claims),
      signed_claims_hash: hex(requestRow.signed_claims_hash),
      prev_mutation_hash: hex(requestRow.prev_mutation_hash),
      nonce: requestRow.nonce,
      ts_signed: Number(requestRow.ts_signed),
      signature_b64u: b64u(requestRow.sig),
    },
    content_state_projection: {
      schema: SCHEMA.content_state_projection,
      native_decision_schema: 'hom.aimos.content-state-occurrence-kernel/v1',
      admission_decision_sha256: admission.decision_sha256,
      return_selection_decision_sha256: returnProjection.content_state_selection_sha256,
      state_view_root_sha256: admission.state_view_root_sha256,
      occurrence_view_root_sha256: admission.occurrence_view_root_sha256,
      selected_occurrence_refs: evidence.map((entry) => entry.occurrence_ref),
      native_response_projection: admission,
    },
    epistemic_recall_decision: {
      schema: SCHEMA.epistemic_recall_decision,
      decision_sha256: nativeReceipt.epistemic_decision_sha256,
      selected_memory_ids: returnProjection.projected_memory_ids,
      native_event_id: epistemicEvent.id,
      native_event_mutation_hash: epistemicEvent.mutation_hash,
      native_decision: epistemicMetadata,
    },
    final_security_closure: {
      schema: SCHEMA.final_security_closure,
      native_decision_schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
      decision_sha256: nativeReceipt.canary_final_security_closure_sha256,
      return_path: returnProjection.return_path,
      epistemic_decision_sha256: nativeReceipt.epistemic_decision_sha256,
      state_view_root_sha256: admission.state_view_root_sha256,
      occurrence_view_root_sha256: admission.occurrence_view_root_sha256,
      selected_clean_memory_ids: returnProjection.projected_memory_ids,
      native_event_id: securityEvent.id,
      native_event_mutation_hash: securityEvent.mutation_hash,
      native_decision: securityMetadata,
    },
    return_projection: returnProjection,
    native_recall_receipt: {
      schema: SCHEMA.native_recall_receipt,
      ...nativeReceipt,
      result_count: evidence.length,
      event_receipt: eventReceiptProjection(terminalEvent, signerCert),
    },
  };

  const resultBodies = {
    memory_state: {
      schema: SCHEMA.memory_state,
      memory_id: memoryId,
      live_content_hash: evidence[0].live_content_hash,
      key: persistedMemory.key,
      value: persistedMemory.value,
      scope: persistedMemory.scope,
      memory_type: persistedMemory.memory_type,
      clearance_level: Number(persistedMemory.clearance_level),
      data_class: persistedMemory.data_class,
      source: persistedMemory.source,
    },
    provenance_chain: {
      schema: SCHEMA.provenance_chain,
      memory_id: memoryId,
      live_content_hash: evidence[0].live_content_hash,
      save_mutation_hash: evidence[0].save_mutation_hash,
      binding_mutation_hash: evidence[0].binding_mutation_hash,
      rows: allProvenance.map(portableProvenanceRow),
    },
    occurrence: {
      schema: SCHEMA.occurrence,
      memory_id: memoryId,
      live_content_hash_hex: evidence[0].live_content_hash,
      occurrence_ref: evidence[0].occurrence_ref,
      occurrence_form: occurrenceForm,
      native_schema: occurrenceNativeSchema,
      native_body: occurrenceBody,
      signature_b64u: b64u(selectedOccurrence.sig),
      signer_certificate: selectedOccurrence.signer_cert,
    },
    epistemic_projection: {
      schema: SCHEMA.epistemic_projection,
      memory_id: memoryId,
      live_content_hash: evidence[0].live_content_hash,
      label: persistedMemory.current_epistemic_label || memory.epistemic_state || 'unverified',
      confidence_milli: Number(persistedMemory.current_epistemic_confidence_milli || 0),
      decision_sha256: nativeReceipt.epistemic_decision_sha256,
      chain_rows: classificationRows,
    },
    receipt_evidence: {
      schema: SCHEMA.receipt_evidence,
      ...evidence[0],
    },
  };

  const objects = [
    ...Object.entries(singletonBodies).map(([kind, body]) => {
      try {
        return createMutMemPortableObjectV2({ kind, schema: body.schema, body });
      } catch (error) {
        throw new Error(`p1_live_object_invalid:${kind}:${error.message}`);
      }
    }),
    ...Object.entries(resultBodies).map(([kind, body]) => {
      try {
        return createMutMemPortableObjectV2({
          kind, schema: body.schema, subjectId: memoryId, resultOrdinal: 0, body,
        });
      } catch (error) {
        throw new Error(`p1_live_object_invalid:${kind}:${error.message}`);
      }
    }),
  ];
  const bundle = createMutMemPortableEvidenceEnvelopeV2({
    bundleId: `P1-LIVE-${eventReceipt.event_id}`,
    companyId: 'hom',
    expectedMasterFingerprint: master.fingerprint,
    resultCount: 1,
    objects,
  });
  const reference = evaluateMutMemPortablePredicatesV2(bundle);
  if (reference.valid !== true) throw new Error('p1_live_reference_invalid');

  await mkdir(OUTPUT, { recursive: true, mode: 0o700 });
  const artifact = path.join(OUTPUT, `${eventReceipt.event_id}.json`);
  const bytes = Buffer.from(`${JSON.stringify({
    schema: 'hom.aimos.mutmem-p1-live-projection/v1',
    private_identity_bearing_artifact: true,
    memory_write: false,
    domain_database_mutation: false,
    bundle,
    reference_result: reference,
  }, null, 2)}\n`, 'utf8');
  await writeFile(artifact, bytes, { mode: 0o600, flag: 'wx' });
  await chmod(artifact, 0o600);
  console.log(JSON.stringify({
    success: true,
    status: 'P1_LIVE_NATIVE_RECALL_V3_PROJECTED',
    recall_event_id: eventReceipt.event_id,
    bundle_sha256: bundle.bundle_sha256,
    object_root_sha256: bundle.object_root_sha256,
    occurrence_form: occurrenceForm,
    result_count: bundle.result_count,
    object_count: bundle.object_count,
    reference_predicates_valid: true,
    artifact,
    artifact_sha256: sha(bytes),
    memory_write: false,
    domain_database_mutation: false,
  }, null, 2));
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await Promise.allSettled([pool.end(), agentPool.end()]);
  });
