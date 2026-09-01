// Pure reference predicates for the MutMem V2 recall-disclosure envelope.
//
// This module defines exact schema membership and relational equality rules.
// It recomputes deterministic hashes and Merkle membership, but deliberately
// does not verify Ed25519 signatures or establish external trust. P2 must
// implement those cryptographic checks independently.

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import { eventMutationHash, recallMerkleRoot } from './mutmem-protocol.js';
import {
  MUTMEM_PORTABLE_EVIDENCE_V2,
  createMutMemPortableEvidenceEnvelopeV2,
} from './mutmem-portable-evidence-v2.js';

export const MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2 = Object.freeze({
  trust_anchor: 'hom.aimos.mutmem-trust-anchor/v2',
  actor_identity_epoch: 'hom.aimos.mutmem-actor-identity-epoch/v2',
  actor_revocation_state: 'hom.aimos.mutmem-actor-revocation-state/v2',
  housekeeper_identity_epoch: 'hom.aimos.mutmem-housekeeper-identity-epoch/v2',
  housekeeper_revocation_state: 'hom.aimos.mutmem-housekeeper-revocation-state/v2',
  effective_recall_grant: 'hom.aimos.mutmem-effective-recall-grant/v2',
  request_envelope: 'hom.aimos.mutmem-request-envelope/v2',
  request_receipt: 'hom.aimos.mutmem-request-receipt/v2',
  content_state_projection: 'hom.aimos.mutmem-content-state-projection/v2',
  epistemic_recall_decision: 'hom.aimos.mutmem-epistemic-recall-decision/v2',
  final_security_closure: 'hom.aimos.mutmem-final-security-closure/v2',
  return_projection: 'hom-aimos/native-recall-return-projection/v1',
  native_recall_receipt: 'hom.aimos.mutmem-native-recall-receipt/v2',
  memory_state: 'hom.aimos.mutmem-memory-state/v2',
  provenance_chain: 'hom.aimos.mutmem-provenance-chain/v2',
  occurrence: 'hom.aimos.mutmem-occurrence-evidence/v2',
  epistemic_projection: 'hom.aimos.mutmem-epistemic-projection/v2',
  receipt_evidence: 'hom.aimos.mutmem-recall-evidence-entry/v2',
});

export const MUTMEM_PORTABLE_PREDICATE_CODES_V2 = Object.freeze([
  'ENVELOPE_COMMITMENT_INVALID',
  'OBJECT_SCHEMA_INVALID',
  'TRUST_ROOT_MISMATCH',
  'TRUST_ANCHOR_KEY_MISMATCH',
  'IDENTITY_SCOPE_MISMATCH',
  'IDENTITY_CERTIFICATE_BINDING_INVALID',
  'IDENTITY_EPOCH_INVALID',
  'REVOCATION_STATE_INVALID',
  'HOUSEKEEPER_IDENTITY_INVALID',
  'HOUSEKEEPER_REVOCATION_STATE_INVALID',
  'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID',
  'GRANT_SCOPE_MISMATCH',
  'GRANT_NOT_EFFECTIVE',
  'GRANT_COMMITMENT_INVALID',
  'REQUEST_CONTEXT_INVALID',
  'REQUEST_BODY_HASH_MISMATCH',
  'COMMAND_HASH_MISMATCH',
  'REQUEST_RECEIPT_BINDING_INVALID',
  'REQUEST_RECEIPT_COMMITMENT_INVALID',
  'AUTHORITY_MUTATION_BINDING_INVALID',
  'DECISION_HASH_MALFORMED',
  'CONTENT_STATE_BINDING_INVALID',
  'EPISTEMIC_BINDING_INVALID',
  'SECURITY_CLOSURE_BINDING_INVALID',
  'RETURN_PROJECTION_BINDING_INVALID',
  'RESULT_CARDINALITY_INVALID',
  'RESULT_IDENTITY_BINDING_INVALID',
  'PROVENANCE_BINDING_INVALID',
  'OCCURRENCE_BINDING_INVALID',
  'OCCURRENCE_NATIVE_BODY_INVALID',
  'EPISTEMIC_PROJECTION_BINDING_INVALID',
  'RECEIPT_EVIDENCE_BINDING_INVALID',
  'MERKLE_ENTRY_BINDING_INVALID',
  'MERKLE_ROOT_MISMATCH',
  'EVENT_RECEIPT_BINDING_INVALID',
  'EVENT_RECEIPT_COMMITMENT_INVALID',
  'REVOCATION_EVENT_BINDING_INVALID',
]);

const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DATA_CLASS = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
const RETURN_PATHS = new Set([
  'identifier_exact',
  'post_compaction_handoff',
  'semantic_cache',
  'adaptive_early_exit',
  'normal_recall',
]);
const RECALL_AUTHORIZATION_DOMAIN = Buffer.from('aimos-recall-authorization-v1\0', 'utf8');
const REQUEST_RECEIPT_DOMAIN = Buffer.from('aimos-request-receipt-v1\0', 'utf8');

export const MUTMEM_PORTABLE_DOMAIN_HEX_V2 = Object.freeze({
  portable_object_v2: MUTMEM_PORTABLE_EVIDENCE_V2.object_domain.toString('hex'),
  portable_bundle_v2: MUTMEM_PORTABLE_EVIDENCE_V2.bundle_domain.toString('hex'),
  recall_authorization_v1: RECALL_AUTHORIZATION_DOMAIN.toString('hex'),
  request_receipt_v1: REQUEST_RECEIPT_DOMAIN.toString('hex'),
  event_link_v1: Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8').toString('hex'),
  recall_leaf: '00',
  recall_node: '01',
  occurrence_v3: Buffer.from('hom.aimos.memory-occurrence/v3\0', 'utf8').toString('hex'),
  occurrence_signature_v3:
    Buffer.from('hom.aimos.memory-occurrence-signature/v3\0', 'utf8').toString('hex'),
});

function fail(code) {
  if (!MUTMEM_PORTABLE_PREDICATE_CODES_V2.includes(code)) {
    throw new Error('mutmem_portable_predicates_v2:UNDECLARED_FAILURE_CODE');
  }
  throw new Error(`mutmem_portable_predicates_v2:${code}`);
}

function sha256Canonical(value) {
  return createHash('sha256').update(Buffer.from(canonicalJson(value), 'utf8')).digest('hex');
}

function sha256Buffer(value) {
  return createHash('sha256').update(value).digest();
}

function hashBytes(value, code) {
  const normalized = requireHash(value, code);
  return Buffer.from(normalized, 'hex');
}

function signatureBytes(value, code) {
  const normalized = string(value);
  const bytes = Buffer.from(normalized, 'base64url');
  if (bytes.length !== 64 || bytes.toString('base64url') !== normalized) fail(code);
  return bytes;
}

export function recallAuthorizationMutationHashV1({
  previousMutationHash = null,
  contentHash,
  nonce,
  signedTs,
} = {}) {
  const previous = previousMutationHash == null
    ? Buffer.alloc(32) : hashBytes(previousMutationHash, 'GRANT_COMMITMENT_INVALID');
  return sha256Buffer(Buffer.concat([
    RECALL_AUTHORIZATION_DOMAIN,
    previous,
    hashBytes(contentHash, 'GRANT_COMMITMENT_INVALID'),
    Buffer.from(string(nonce), 'utf8'),
    Buffer.from(string(signedTs), 'utf8'),
  ])).toString('hex');
}

export function requestReceiptMutationHashV1({
  previousMutationHash = null,
  requestHash,
  claimsHash = null,
  signature,
  method,
  path,
  nonce,
  signedTs,
} = {}) {
  const previous = previousMutationHash == null
    ? Buffer.alloc(32) : hashBytes(previousMutationHash, 'REQUEST_RECEIPT_COMMITMENT_INVALID');
  const claims = claimsHash == null
    ? Buffer.alloc(32) : hashBytes(claimsHash, 'REQUEST_RECEIPT_COMMITMENT_INVALID');
  return sha256Buffer(Buffer.concat([
    REQUEST_RECEIPT_DOMAIN,
    previous,
    hashBytes(requestHash, 'REQUEST_RECEIPT_COMMITMENT_INVALID'),
    claims,
    signatureBytes(signature, 'REQUEST_RECEIPT_COMMITMENT_INVALID'),
    Buffer.from(string(method), 'utf8'),
    Buffer.from(string(path), 'utf8'),
    Buffer.from(string(nonce), 'utf8'),
    Buffer.from(string(signedTs), 'utf8'),
  ])).toString('hex');
}

export function housekeeperSystemPrincipalHashV1({
  companyId,
  agentId,
  validFrom,
} = {}) {
  const body = {
    kind: 'housekeeper_system_principal',
    company_id: string(companyId),
    agent_id: string(agentId),
    valid_from: iso(validFrom, 'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID'),
  };
  if (!body.company_id || body.agent_id !== 'housekeeper') {
    fail('HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID');
  }
  return sha256Canonical(body);
}

function equal(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function iso(value, code) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) fail(code);
  return date.toISOString();
}

function string(value) {
  return String(value ?? '');
}

function withoutSchema(value = {}) {
  const { schema: _schema, ...rest } = value;
  return rest;
}

function requireHash(value, code = 'DECISION_HASH_MALFORMED') {
  const normalized = string(value).toLowerCase();
  if (!HEX32.test(normalized)) fail(code);
  return normalized;
}

function objectMaps(envelope) {
  const singletons = new Map();
  const results = Array.from({ length: envelope.result_count }, () => new Map());
  for (const object of envelope.objects) {
    if (object.result_ordinal == null) singletons.set(object.kind, object);
    else results[object.result_ordinal].set(object.kind, object);
  }
  return { singletons, results };
}

function validateEnvelopeCommitment(envelope) {
  let reconstructed;
  try {
    const sourceObjects = Array.isArray(envelope?.objects)
      ? envelope.objects.map(({ ordinal: _ordinal, ...object }) => object)
      : envelope?.objects;
    reconstructed = createMutMemPortableEvidenceEnvelopeV2({
      bundleId: envelope?.bundle_id,
      companyId: envelope?.company_id,
      expectedMasterFingerprint: envelope?.expected_master_fingerprint,
      resultCount: envelope?.result_count,
      objects: sourceObjects,
    });
  } catch {
    fail('ENVELOPE_COMMITMENT_INVALID');
  }
  if (envelope?.format?.schema !== MUTMEM_PORTABLE_EVIDENCE_V2.schema
      || envelope?.format?.version !== MUTMEM_PORTABLE_EVIDENCE_V2.version
      || envelope?.format?.profile !== MUTMEM_PORTABLE_EVIDENCE_V2.profile
      || envelope?.object_count !== reconstructed.object_count
      || envelope?.object_root_sha256 !== reconstructed.object_root_sha256
      || envelope?.bundle_sha256 !== reconstructed.bundle_sha256) {
    fail('ENVELOPE_COMMITMENT_INVALID');
  }
  return reconstructed;
}

function requireSchemas(envelope) {
  for (const object of envelope.objects) {
    if (object.schema !== MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2[object.kind]
        || object.body?.schema !== object.schema) {
      fail('OBJECT_SCHEMA_INVALID');
    }
  }
}

function validateAuthority(envelope, singletons) {
  const trust = singletons.get('trust_anchor').body;
  const identity = singletons.get('actor_identity_epoch').body;
  const revocation = singletons.get('actor_revocation_state').body;
  const housekeeperIdentity = singletons.get('housekeeper_identity_epoch').body;
  const housekeeperRevocation = singletons.get('housekeeper_revocation_state').body;
  const grant = singletons.get('effective_recall_grant').body;
  const request = singletons.get('request_envelope').body;
  const requestReceipt = singletons.get('request_receipt').body;
  const nativeReceipt = singletons.get('native_recall_receipt').body;

  if (requireHash(trust.master_fingerprint) !== envelope.expected_master_fingerprint) {
    fail('TRUST_ROOT_MISMATCH');
  }
  const masterKey = Buffer.from(string(trust.master_public_key_b64u), 'base64url');
  if (!masterKey.length || masterKey.toString('base64url') !== trust.master_public_key_b64u
      || sha256Buffer(masterKey).toString('hex') !== trust.master_fingerprint) {
    fail('TRUST_ANCHOR_KEY_MISMATCH');
  }
  const agentId = string(identity.agent_id);
  const authorityKind = string(grant.authority_kind);
  const validFrom = iso(identity.valid_from, 'IDENTITY_SCOPE_MISMATCH');
  const certFingerprint = requireHash(identity.cert_fingerprint, 'IDENTITY_SCOPE_MISMATCH');
  if (!identity.certificate || !identity.public_key_b64u
      || sha256Buffer(Buffer.from(string(identity.certificate), 'utf8')).toString('hex')
        !== certFingerprint) {
    fail('IDENTITY_CERTIFICATE_BINDING_INVALID');
  }
  if (!agentId || identity.company_id !== envelope.company_id
      || request.company_id !== envelope.company_id
      || request.actor_agent_id !== agentId
      || iso(request.actor_valid_from, 'IDENTITY_SCOPE_MISMATCH') !== validFrom
      || request.cert_fingerprint !== certFingerprint
      || requestReceipt.company_id !== envelope.company_id
      || requestReceipt.actor_agent_id !== agentId
      || iso(requestReceipt.actor_valid_from, 'IDENTITY_SCOPE_MISMATCH') !== validFrom
      || requestReceipt.cert_fingerprint !== certFingerprint) {
    fail('IDENTITY_SCOPE_MISMATCH');
  }
  const housekeeperValidFrom = iso(
    housekeeperIdentity.valid_from,
    'HOUSEKEEPER_IDENTITY_INVALID',
  );
  const housekeeperCertFingerprint = requireHash(
    housekeeperIdentity.cert_fingerprint,
    'HOUSEKEEPER_IDENTITY_INVALID',
  );
  if (housekeeperIdentity.company_id !== envelope.company_id
      || housekeeperIdentity.agent_id !== 'housekeeper'
      || !housekeeperIdentity.certificate || !housekeeperIdentity.public_key_b64u
      || sha256Buffer(Buffer.from(string(housekeeperIdentity.certificate), 'utf8')).toString('hex')
        !== housekeeperCertFingerprint) {
    fail('HOUSEKEEPER_IDENTITY_INVALID');
  }
  if (agentId === 'housekeeper'
      && ((identity.identity_tier !== 'T1' && identity.identity_tier !== 'T1_SYSTEM_SELF')
        || validFrom !== housekeeperValidFrom
        || identity.cert_fingerprint !== housekeeperCertFingerprint
        || identity.certificate !== housekeeperIdentity.certificate
        || identity.public_key_b64u !== housekeeperIdentity.public_key_b64u)) {
    fail('HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID');
  }
  const requestTs = Number(request.ts_signed);
  const validFromSeconds = Math.floor(new Date(validFrom).getTime() / 1000);
  const validUntilSeconds = Math.floor(new Date(
    iso(identity.valid_until, 'IDENTITY_EPOCH_INVALID'),
  ).getTime() / 1000);
  if (!Number.isSafeInteger(requestTs) || requestTs < validFromSeconds
      || requestTs > validUntilSeconds) {
    fail('IDENTITY_EPOCH_INVALID');
  }
  if (!Number.isSafeInteger(requestTs)
      || revocation.company_id !== envelope.company_id
      || revocation.agent_id !== agentId
      || iso(revocation.valid_from, 'REVOCATION_STATE_INVALID') !== validFrom
      || revocation.revoked !== false
      || !Number.isSafeInteger(Number(revocation.evaluated_at_unix_seconds))
      || Number(revocation.evaluated_at_unix_seconds) < requestTs) {
    fail('REVOCATION_STATE_INVALID');
  }
  if (housekeeperRevocation.company_id !== envelope.company_id
      || housekeeperRevocation.agent_id !== 'housekeeper'
      || iso(housekeeperRevocation.valid_from, 'HOUSEKEEPER_REVOCATION_STATE_INVALID')
        !== housekeeperValidFrom
      || housekeeperRevocation.revoked !== false
      || !Number.isSafeInteger(Number(housekeeperRevocation.evaluated_at_unix_seconds))) {
    fail('HOUSEKEEPER_REVOCATION_STATE_INVALID');
  }
  const clearance = Number(grant.clearance_ceiling);
  const requestedClearance = request.requested_clearance_level == null
    ? clearance : Number(request.requested_clearance_level);
  const dataClassIndex = DATA_CLASS.indexOf(grant.data_class_ceiling);
  if (grant.company_id !== envelope.company_id
      || grant.subject_agent_id !== agentId
      || iso(grant.subject_valid_from, 'GRANT_SCOPE_MISMATCH') !== validFrom
      || grant.master_fingerprint !== envelope.expected_master_fingerprint
      || !Number.isInteger(clearance) || clearance < 0 || clearance > 12
      || !Number.isInteger(requestedClearance) || requestedClearance < 0
      || requestedClearance > clearance || dataClassIndex < 0) {
    fail('GRANT_SCOPE_MISMATCH');
  }
  if (grant.allowed !== true) fail('GRANT_NOT_EFFECTIVE');
  if (request.requested_data_class != null
      && DATA_CLASS.indexOf(request.requested_data_class) > dataClassIndex) {
    fail('GRANT_NOT_EFFECTIVE');
  }
  if (authorityKind === 'master_signed_recall_grant') {
    if (agentId === 'housekeeper'
        || !grant.signed_body || grant.signed_body.schema !== 'hom.aimos.recall-authorization/v1'
        || grant.signed_body.company_id !== grant.company_id
        || grant.signed_body.subject_agent_id !== grant.subject_agent_id
        || iso(grant.signed_body.subject_valid_from, 'GRANT_COMMITMENT_INVALID')
          !== validFrom
        || Boolean(grant.signed_body.allowed) !== grant.allowed
        || Number(grant.signed_body.clearance_ceiling) !== clearance
        || grant.signed_body.data_class_ceiling !== grant.data_class_ceiling
        || grant.signed_body.master_fingerprint !== grant.master_fingerprint
        || sha256Canonical(grant.signed_body) !== grant.content_hash
        || recallAuthorizationMutationHashV1({
          previousMutationHash: grant.prev_mutation_hash,
          contentHash: grant.content_hash,
          nonce: grant.nonce,
          signedTs: grant.ts_signed,
        }) !== grant.mutation_hash
        || signatureBytes(grant.signature_b64u, 'GRANT_COMMITMENT_INVALID').length !== 64) {
      fail('GRANT_COMMITMENT_INVALID');
    }
  } else if (authorityKind === 'housekeeper_system_principal') {
    const system = grant.system_principal_body;
    const forbiddenGrantFields = [
      'signed_body', 'content_hash', 'prev_mutation_hash',
      'ts_signed', 'nonce', 'signature_b64u',
    ];
    if (agentId !== 'housekeeper'
        || forbiddenGrantFields.some((field) => Object.hasOwn(grant, field))
        || !system || system.kind !== 'housekeeper_system_principal'
        || system.company_id !== envelope.company_id
        || system.agent_id !== 'housekeeper'
        || iso(system.valid_from, 'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID') !== validFrom
        || clearance !== 12 || grant.data_class_ceiling !== 'restricted'
        || grant.mutation_hash !== housekeeperSystemPrincipalHashV1({
          companyId: system.company_id,
          agentId: system.agent_id,
          validFrom: system.valid_from,
        })) {
      fail('HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID');
    }
  } else {
    fail('GRANT_COMMITMENT_INVALID');
  }
  if (request.request_sig_form !== 3
      || request.signed_method !== 'POST'
      || request.signed_path !== '/aimos/recall'
      || !string(request.nonce)
      || signatureBytes(request.signature_b64u, 'REQUEST_CONTEXT_INVALID').length !== 64
      || !request.request_body || typeof request.request_body !== 'object'
      || Array.isArray(request.request_body)) {
    fail('REQUEST_CONTEXT_INVALID');
  }
  const requestBodyHash = sha256Canonical(request.request_body);
  if (request.request_body_hash !== requestBodyHash
      || request.outer_request_hash !== requestBodyHash) {
    fail('REQUEST_BODY_HASH_MISMATCH');
  }
  if (!request.normalized_command || sha256Canonical(request.normalized_command) !== request.command_hash) {
    fail('COMMAND_HASH_MISMATCH');
  }
  if (!UUID.test(string(requestReceipt.request_receipt_id))
      || requestReceipt.request_sig_form !== request.request_sig_form
      || requestReceipt.signed_method !== request.signed_method
      || requestReceipt.signed_path !== request.signed_path
      || Number(requestReceipt.ts_signed) !== requestTs
      || requestReceipt.nonce !== request.nonce
      || requestReceipt.request_hash !== requestBodyHash
      || nativeReceipt.request_receipt_id !== requestReceipt.request_receipt_id
      || nativeReceipt.request_receipt_mutation_hash !== requestReceipt.mutation_hash) {
    fail('REQUEST_RECEIPT_BINDING_INVALID');
  }
  const claimsHash = requestReceipt.signed_claims == null
    ? null : sha256Canonical(requestReceipt.signed_claims);
  if ((requestReceipt.signed_claims_hash ?? null) !== claimsHash
      || requestReceipt.signature_b64u !== request.signature_b64u
      || requestReceiptMutationHashV1({
        previousMutationHash: requestReceipt.prev_mutation_hash,
        requestHash: requestReceipt.request_hash,
        claimsHash,
        signature: requestReceipt.signature_b64u,
        method: requestReceipt.signed_method,
        path: requestReceipt.signed_path,
        nonce: requestReceipt.nonce,
        signedTs: requestReceipt.ts_signed,
      }) !== requestReceipt.mutation_hash) {
    fail('REQUEST_RECEIPT_COMMITMENT_INVALID');
  }
  if (nativeReceipt.authority_mutation_hash !== grant.mutation_hash) {
    fail('AUTHORITY_MUTATION_BINDING_INVALID');
  }
  if (nativeReceipt.outer_request_hash !== request.outer_request_hash
      || nativeReceipt.command_hash !== request.command_hash) {
    fail('REQUEST_CONTEXT_INVALID');
  }
  return {
    identity,
    revocation,
    housekeeperIdentity,
    housekeeperRevocation,
    request,
    requestReceipt,
    grant,
    nativeReceipt,
  };
}

function validateDecisions(singletons, nativeReceipt) {
  const content = singletons.get('content_state_projection').body;
  const epistemic = singletons.get('epistemic_recall_decision').body;
  const security = singletons.get('final_security_closure').body;
  const projection = singletons.get('return_projection').body;
  const contentHash = requireHash(content.admission_decision_sha256);
  const returnSelectionHash = requireHash(content.return_selection_decision_sha256);
  const stateRoot = requireHash(content.state_view_root_sha256);
  const occurrenceRoot = requireHash(content.occurrence_view_root_sha256);
  const epistemicHash = requireHash(epistemic.decision_sha256);
  const securityHash = requireHash(security.decision_sha256);
  const projectionHash = requireHash(projection.decision_sha256);
  if (content.native_decision_schema !== 'hom.aimos.content-state-occurrence-kernel/v1'
      || security.native_decision_schema
        !== 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope') {
    fail('OBJECT_SCHEMA_INVALID');
  }
  if (projection.content_state_selection_sha256 !== returnSelectionHash
      || security.state_view_root_sha256 !== stateRoot
      || security.occurrence_view_root_sha256 !== occurrenceRoot) {
    fail('CONTENT_STATE_BINDING_INVALID');
  }
  if (security.epistemic_decision_sha256 !== epistemicHash
      || nativeReceipt.epistemic_decision_sha256 !== epistemicHash) {
    fail('EPISTEMIC_BINDING_INVALID');
  }
  if (projection.final_security_closure_sha256 !== securityHash
      || nativeReceipt.canary_final_security_closure_sha256 !== securityHash) {
    fail('SECURITY_CLOSURE_BINDING_INVALID');
  }
  if (!Array.isArray(epistemic.selected_memory_ids)
      || !Array.isArray(security.selected_clean_memory_ids)
      || !Array.isArray(projection.projected_memory_ids)
      || !Array.isArray(projection.projected_live_content_hashes)
      || projection.return_path !== security.return_path
      || !RETURN_PATHS.has(projection.return_path)
      || projection.ordered_unique_subset_of_final_clean_security_closure !== true
      || projection.output_content_commitments_unchanged !== true
      || projection.canonical_memory_mutated !== false
      || projection.retention_changed !== false
      || nativeReceipt.return_projection_event_body_bound !== true
      || !equal(nativeReceipt.return_projection, projection)) {
    fail('RETURN_PROJECTION_BINDING_INVALID');
  }
  return {
    content,
    epistemic,
    security,
    projection,
    contentHash,
    returnSelectionHash,
    epistemicHash,
    securityHash,
    projectionHash,
  };
}

function validateResults(envelope, resultGroups, decisions, nativeReceipt) {
  if (nativeReceipt.merkle_schema !== MUTMEM_PORTABLE_EVIDENCE_V2.native_receipt_schema
      || Number(nativeReceipt.result_count) !== envelope.result_count
      || !Array.isArray(nativeReceipt.evidence)
      || nativeReceipt.evidence.length !== envelope.result_count
      || decisions.projection.projected_output_count !== envelope.result_count
      || decisions.projection.projected_memory_ids.length !== envelope.result_count
      || decisions.projection.projected_live_content_hashes.length !== envelope.result_count) {
    fail('RESULT_CARDINALITY_INVALID');
  }
  const evidence = [];
  for (let ordinal = 0; ordinal < resultGroups.length; ordinal += 1) {
    const group = resultGroups[ordinal];
    const memory = group.get('memory_state').body;
    const provenance = group.get('provenance_chain').body;
    const occurrence = group.get('occurrence').body;
    const epistemic = group.get('epistemic_projection').body;
    const receiptEvidence = group.get('receipt_evidence').body;
    const memoryId = string(memory.memory_id).toLowerCase();
    const liveHash = requireHash(memory.live_content_hash, 'RESULT_IDENTITY_BINDING_INVALID');
    if (!UUID.test(memoryId)
        || group.get('memory_state').subject_id !== memoryId
        || [provenance, occurrence, epistemic, receiptEvidence]
          .some((body) => string(body.memory_id).toLowerCase() !== memoryId)
        || [provenance.live_content_hash, occurrence.live_content_hash_hex,
          epistemic.live_content_hash, receiptEvidence.live_content_hash]
          .some((hash) => string(hash).toLowerCase() !== liveHash)) {
      fail('RESULT_IDENTITY_BINDING_INVALID');
    }
    if (provenance.save_mutation_hash !== receiptEvidence.save_mutation_hash
        || provenance.binding_mutation_hash !== receiptEvidence.binding_mutation_hash
        || !HEX32.test(string(provenance.save_mutation_hash))
        || !HEX32.test(string(provenance.binding_mutation_hash))) {
      fail('PROVENANCE_BINDING_INVALID');
    }
    if (occurrence.occurrence_ref !== receiptEvidence.occurrence_ref
        || !HEX32.test(string(occurrence.occurrence_ref))) {
      fail('OCCURRENCE_BINDING_INVALID');
    }
    if (occurrence.occurrence_form === 'v3') {
      if (occurrence.native_schema !== 'hom.aimos.memory-occurrence/v3'
          || occurrence.native_body?.schema !== occurrence.native_schema
          || occurrence.native_body?.memory_id !== memoryId
          || occurrence.native_body?.live_content_hash_hex !== liveHash
          || occurrence.native_body?.occurrence_commitment !== occurrence.occurrence_ref
          || !string(occurrence.signature_b64u)
          || !string(occurrence.signer_certificate)) {
        fail('OCCURRENCE_NATIVE_BODY_INVALID');
      }
    } else if (occurrence.occurrence_form === 'legacy_v1') {
      if (occurrence.native_schema !== 'hom.aimos.memory-occurrence-ref/legacy-v1'
          || !occurrence.native_body || occurrence.native_body.memory_id !== memoryId) {
        fail('OCCURRENCE_NATIVE_BODY_INVALID');
      }
    } else {
      fail('OCCURRENCE_NATIVE_BODY_INVALID');
    }
    if (epistemic.decision_sha256 !== decisions.epistemicHash
        || !decisions.epistemic.selected_memory_ids.includes(memoryId)) {
      fail('EPISTEMIC_PROJECTION_BINDING_INVALID');
    }
    if (receiptEvidence.ordinal !== ordinal
        || !equal(withoutSchema(receiptEvidence), nativeReceipt.evidence[ordinal])) {
      fail('RECEIPT_EVIDENCE_BINDING_INVALID');
    }
    if (decisions.projection.projected_memory_ids[ordinal] !== memoryId
        || decisions.projection.projected_live_content_hashes[ordinal] !== liveHash
        || decisions.security.selected_clean_memory_ids[ordinal] !== memoryId) {
      fail('RETURN_PROJECTION_BINDING_INVALID');
    }
    if (!Array.isArray(decisions.content.selected_occurrence_refs)
        || !decisions.content.selected_occurrence_refs.includes(receiptEvidence.occurrence_ref)) {
      fail('CONTENT_STATE_BINDING_INVALID');
    }
    evidence.push(withoutSchema(receiptEvidence));
  }
  if (!equal(decisions.epistemic.selected_memory_ids, decisions.projection.projected_memory_ids)
      || !equal(decisions.security.selected_clean_memory_ids, decisions.projection.projected_memory_ids)) {
    fail('RETURN_PROJECTION_BINDING_INVALID');
  }
  return evidence;
}

function validateMerkleAndEvent(nativeReceipt, decisions, evidence, authority) {
  const expectedEntries = [
    { entry_type: 'epistemic_decision', decision_sha256: decisions.epistemicHash },
    { entry_type: 'canary_final_security_closure', decision_sha256: decisions.securityHash },
    ...evidence,
  ];
  if (!equal(nativeReceipt.merkle_entries, expectedEntries)) {
    fail('MERKLE_ENTRY_BINDING_INVALID');
  }
  const root = recallMerkleRoot(expectedEntries).toString('hex');
  if (nativeReceipt.merkle_root !== root) fail('MERKLE_ROOT_MISMATCH');
  const event = nativeReceipt.event_receipt;
  const metadata = event?.signed_body?.metadata;
  if (!event || !metadata
      || event.signed_body.operation !== 'recall_receipt'
      || event.signed_body.company_id !== authority.identity.company_id
      || event.signed_body.actor_agent_id !== authority.identity.agent_id
      || iso(event.signed_body.actor_valid_from, 'EVENT_RECEIPT_BINDING_INVALID')
        !== iso(authority.identity.valid_from, 'EVENT_RECEIPT_BINDING_INVALID')
      || metadata.command_hash !== nativeReceipt.command_hash
      || metadata.outer_request_hash !== nativeReceipt.outer_request_hash
      || metadata.authority_mutation_hash !== nativeReceipt.authority_mutation_hash
      || metadata.request_receipt_id !== nativeReceipt.request_receipt_id
      || metadata.request_receipt_mutation_hash !== nativeReceipt.request_receipt_mutation_hash
      || metadata.merkle_root !== root
      || metadata.result_count !== evidence.length
      || !equal(metadata.evidence, evidence)
      || !equal(metadata.return_projection, nativeReceipt.return_projection)) {
    fail('EVENT_RECEIPT_BINDING_INVALID');
  }
  const housekeeperValidFrom = iso(
    authority.housekeeperIdentity.valid_from,
    'HOUSEKEEPER_IDENTITY_INVALID',
  );
  if (event.signed_body.signer_agent_id !== 'housekeeper'
      || iso(event.signed_body.signer_valid_from, 'HOUSEKEEPER_IDENTITY_INVALID')
        !== housekeeperValidFrom
      || event.signed_body.cert_fingerprint
        !== authority.housekeeperIdentity.cert_fingerprint
      || event.signer_certificate !== authority.housekeeperIdentity.certificate
      || sha256Buffer(Buffer.from(string(event.signer_certificate), 'utf8')).toString('hex')
        !== authority.housekeeperIdentity.cert_fingerprint) {
    fail('HOUSEKEEPER_IDENTITY_INVALID');
  }
  const contentHash = sha256Canonical(event.signed_body);
  const mutationHash = eventMutationHash(
    hashBytes(event.prev_mutation_hash, 'EVENT_RECEIPT_COMMITMENT_INVALID'),
    Buffer.from(contentHash, 'hex'),
    event.nonce,
    Number(event.ts_signed),
  ).toString('hex');
  if (event.content_hash !== contentHash
      || event.mutation_hash !== mutationHash
      || event.signed_body.prev_mutation_hash !== event.prev_mutation_hash
      || Number(event.signed_body.ts_signed) !== Number(event.ts_signed)
      || signatureBytes(event.signature_b64u, 'EVENT_RECEIPT_COMMITMENT_INVALID').length !== 64) {
    fail('EVENT_RECEIPT_COMMITMENT_INVALID');
  }
  if (authority.revocation.source_event_mutation_hash !== event.mutation_hash
      || Number(authority.revocation.evaluated_at_unix_seconds) !== Number(event.ts_signed)
      || authority.housekeeperRevocation.source_event_mutation_hash !== event.mutation_hash
      || Number(authority.housekeeperRevocation.evaluated_at_unix_seconds)
        !== Number(event.ts_signed)) {
    fail('REVOCATION_EVENT_BINDING_INVALID');
  }
}

export function evaluateMutMemPortablePredicatesV2(envelope) {
  const reconstructed = validateEnvelopeCommitment(envelope);
  requireSchemas(reconstructed);
  const maps = objectMaps(reconstructed);
  const authority = validateAuthority(reconstructed, maps.singletons);
  const decisions = validateDecisions(maps.singletons, authority.nativeReceipt);
  const evidence = validateResults(
    reconstructed,
    maps.results,
    decisions,
    authority.nativeReceipt,
  );
  validateMerkleAndEvent(authority.nativeReceipt, decisions, evidence, authority);
  return Object.freeze({
    schema: 'hom.aimos.mutmem-portable-predicate-result/v2',
    valid: true,
    bundle_sha256: reconstructed.bundle_sha256,
    object_root_sha256: reconstructed.object_root_sha256,
    result_count: reconstructed.result_count,
    predicate_count: MUTMEM_PORTABLE_PREDICATE_CODES_V2.length,
    cryptographic_signatures_verified: false,
    external_trust_established: false,
    next_required_owner: 'P2_INDEPENDENT_CRYPTOGRAPHIC_VERIFIER',
  });
}

export default {
  MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2,
  MUTMEM_PORTABLE_PREDICATE_CODES_V2,
  MUTMEM_PORTABLE_DOMAIN_HEX_V2,
  evaluateMutMemPortablePredicatesV2,
  recallAuthorizationMutationHashV1,
  requestReceiptMutationHashV1,
  housekeeperSystemPrincipalHashV1,
};
