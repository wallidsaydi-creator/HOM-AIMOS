// Test-only producer for P1 portable predicate vectors.
// No private keys, signer, database, runtime, model, or network dependency.

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { eventMutationHash, recallMerkleRoot } from '../../services/security/protocol/mutmem-protocol.js';
import {
  computeOccurrenceCommitmentV3,
} from '../../services/security/protocol/content-state-occurrence-v3.js';
import {
  createMutMemPortableEvidenceEnvelopeV2,
  createMutMemPortableObjectV2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2 as SCHEMA,
  housekeeperSystemPrincipalHashV1,
  recallAuthorizationMutationHashV1,
  requestReceiptMutationHashV1,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';

export const fixtureSha = (value) => createHash('sha256').update(value).digest('hex');
const canonicalSha = (value) => fixtureSha(Buffer.from(canonicalJson(value), 'utf8'));
const MASTER_KEY_BYTES = Buffer.from('fixture-master-public-key');
const MASTER_PUBLIC_KEY = MASTER_KEY_BYTES.toString('base64url');
const MASTER = fixtureSha(MASTER_KEY_BYTES);
const ACTOR_CERTIFICATE = 'fixture-actor-certificate';
const ACTOR_PUBLIC_KEY = Buffer.from('fixture-actor-public-key').toString('base64url');
const CERT = fixtureSha(ACTOR_CERTIFICATE);
const HOUSEKEEPER_CERTIFICATE = 'fixture-housekeeper-certificate';
const HOUSEKEEPER_PUBLIC_KEY = Buffer.from('fixture-housekeeper-public-key').toString('base64url');
const HOUSEKEEPER_CERT = fixtureSha(HOUSEKEEPER_CERTIFICATE);
const SIGNATURE = Buffer.alloc(64, 7).toString('base64url');
const CONTENT = fixtureSha('content-state');
const STATE_ROOT = fixtureSha('state-view');
const OCCURRENCE_ROOT = fixtureSha('occurrence-view');
const EPISTEMIC = fixtureSha('epistemic-decision');
const SECURITY = fixtureSha('security-closure');
const PROJECTION = fixtureSha('return-projection');
const SAVE = fixtureSha('save-provenance');
const BINDING = fixtureSha('binding-provenance');
const OCCURRENCE = fixtureSha('occurrence');
const MEMORY = '11111111-1111-4111-8111-111111111111';
const RECEIPT_ID = '22222222-2222-4222-8222-222222222222';
const VALID_FROM = '2026-08-10T18:49:54.000Z';
const TS = 1_788_002_807;

export function baseMutMemPortablePredicateBodies() {
  const requestBody = { query: 'portable current recall', limit: 1, cache: false };
  const outerRequestHash = canonicalSha(requestBody);
  const normalizedCommand = {
    ...requestBody,
    q: requestBody.query,
    key: null,
    memory_id: null,
    company_id: 'hom',
    agent_id: null,
    clearance_level: 10,
    max_hops: null,
  };
  const commandHash = canonicalSha(normalizedCommand);
  const grantSignedBody = {
    schema: 'hom.aimos.recall-authorization/v1',
    company_id: 'hom',
    subject_agent_id: 'codex-auditor',
    subject_valid_from: VALID_FROM,
    allowed: true,
    write_allowed: true,
    clearance_ceiling: 10,
    data_class_ceiling: 'confidential',
    master_fingerprint: MASTER,
    reason: 'P1 portable predicate fixture',
    prev_mutation_hash: null,
    ts_signed: TS - 100,
  };
  const grantContentHash = canonicalSha(grantSignedBody);
  const grantMutationHash = recallAuthorizationMutationHashV1({
    contentHash: grantContentHash, nonce: 'grant-nonce', signedTs: TS - 100,
  });
  const requestPreviousHash = fixtureSha('request-previous');
  const requestReceiptMutationHash = requestReceiptMutationHashV1({
    previousMutationHash: requestPreviousHash,
    requestHash: outerRequestHash,
    claimsHash: null,
    signature: SIGNATURE,
    method: 'POST',
    path: '/aimos/recall',
    nonce: 'request-nonce',
    signedTs: TS,
  });
  const evidence = {
    ordinal: 0,
    memory_id: MEMORY,
    live_content_hash: CONTENT,
    occurrence_ref: OCCURRENCE,
    save_mutation_hash: SAVE,
    binding_mutation_hash: BINDING,
    truth_state: 'current',
    raw_calibration_score: 0.75,
    calibrated_score: 0.75,
    calibration_event_id: null,
    calibration_mutation_hash: null,
    calibration_formula_version: null,
  };
  const occurrenceRecord = {
    company_id: 'hom',
    occurrence_event_id: '33333333-3333-4333-8333-333333333333',
    memory_id: MEMORY,
    event_type: 'SAVE_REASSERT',
    live_content_hash_hex: CONTENT,
    predecessor_present: 1,
    predecessor_commitment_hex: fixtureSha('occurrence-predecessor'),
    agent_id: 'housekeeper',
    signer_valid_from_unix_ms: new Date(VALID_FROM).getTime(),
    cert_fingerprint_hex: HOUSEKEEPER_CERT,
    identity_tier: 'T1',
    sig_form_version: 3,
    nonce_hex: '11'.repeat(16),
    ts_signed_unix_seconds: TS - 200,
    signed_method: 'POST',
    signed_path: '/aimos/save',
    request_body_hash_hex: fixtureSha('save-request-body'),
    request_receipt_present: 1,
    request_receipt_mutation_hash_hex: fixtureSha('save-request-receipt'),
    authorization_event_present: 1,
    authorization_event_id: '44444444-4444-4444-8444-444444444444',
  };
  const occurrenceCommitment = computeOccurrenceCommitmentV3(occurrenceRecord);
  if (occurrenceCommitment !== OCCURRENCE) {
    evidence.occurrence_ref = occurrenceCommitment;
  }
  const effectiveOccurrence = evidence.occurrence_ref;
  occurrenceRecord.occurrence_commitment = effectiveOccurrence;
  occurrenceRecord.schema = 'hom.aimos.memory-occurrence/v3';
  const content = {
    schema: SCHEMA.content_state_projection,
    native_decision_schema: 'hom.aimos.content-state-occurrence-kernel/v1',
    admission_decision_sha256: fixtureSha('content-admission-decision'),
    return_selection_decision_sha256: fixtureSha('content-return-selection-decision'),
    state_view_root_sha256: STATE_ROOT,
    occurrence_view_root_sha256: OCCURRENCE_ROOT,
    selected_occurrence_refs: [effectiveOccurrence],
  };
  const epistemic = {
    schema: SCHEMA.epistemic_recall_decision,
    decision_sha256: EPISTEMIC,
    selected_memory_ids: [MEMORY],
  };
  const security = {
    schema: SCHEMA.final_security_closure,
    native_decision_schema: 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope',
    decision_sha256: SECURITY,
    return_path: 'normal_recall',
    epistemic_decision_sha256: EPISTEMIC,
    state_view_root_sha256: STATE_ROOT,
    occurrence_view_root_sha256: OCCURRENCE_ROOT,
    selected_clean_memory_ids: [MEMORY],
  };
  const projection = {
    schema: SCHEMA.return_projection,
    decision_sha256: PROJECTION,
    return_path: 'normal_recall',
    final_security_closure_sha256: SECURITY,
    content_state_selection_sha256: content.return_selection_decision_sha256,
    selected_clean_count: 1,
    projected_output_count: 1,
    projected_memory_ids: [MEMORY],
    projected_live_content_hashes: [CONTENT],
    ordered_unique_subset_of_final_clean_security_closure: true,
    output_content_commitments_unchanged: true,
    canonical_memory_mutated: false,
    retention_changed: false,
    disclosure_expansion_performed: false,
  };
  const merkleEntries = [
    { entry_type: 'epistemic_decision', decision_sha256: EPISTEMIC },
    { entry_type: 'canary_final_security_closure', decision_sha256: SECURITY },
    evidence,
  ];
  const merkleRoot = recallMerkleRoot(merkleEntries).toString('hex');
  const eventMetadata = {
    command_hash: commandHash,
    outer_request_hash: outerRequestHash,
    authority_mutation_hash: grantMutationHash,
    request_receipt_id: RECEIPT_ID,
    request_receipt_mutation_hash: requestReceiptMutationHash,
    merkle_root: merkleRoot,
    result_count: 1,
    evidence: [evidence],
    return_projection: projection,
  };
  const eventPreviousHash = fixtureSha('event-previous');
  const eventSignedBody = {
    company_id: 'hom',
    actor_agent_id: 'codex-auditor',
    actor_valid_from: VALID_FROM,
    signer_agent_id: 'housekeeper',
    signer_valid_from: VALID_FROM,
    cert_fingerprint: HOUSEKEEPER_CERT,
    operation: 'recall_receipt',
    metadata: eventMetadata,
    prev_mutation_hash: eventPreviousHash,
    ts_signed: TS + 1,
  };
  const eventContentHash = canonicalSha(eventSignedBody);
  const eventMutation = eventMutationHash(
    Buffer.from(eventPreviousHash, 'hex'),
    Buffer.from(eventContentHash, 'hex'),
    'event-nonce',
    TS + 1,
  ).toString('hex');
  return {
    trust_anchor: {
      schema: SCHEMA.trust_anchor,
      master_fingerprint: MASTER,
      master_public_key_b64u: MASTER_PUBLIC_KEY,
    },
    actor_identity_epoch: {
      schema: SCHEMA.actor_identity_epoch,
      company_id: 'hom', agent_id: 'codex-auditor', valid_from: VALID_FROM,
      valid_until: '2026-09-09T18:49:54.000Z', cert_fingerprint: CERT,
      certificate: ACTOR_CERTIFICATE, public_key_b64u: ACTOR_PUBLIC_KEY,
      identity_tier: 'T2',
    },
    actor_revocation_state: {
      schema: SCHEMA.actor_revocation_state,
      company_id: 'hom', agent_id: 'codex-auditor', valid_from: VALID_FROM,
      evaluated_at_unix_seconds: TS + 1, revoked: false,
      source_event_mutation_hash: eventMutation,
    },
    housekeeper_identity_epoch: {
      schema: SCHEMA.housekeeper_identity_epoch,
      company_id: 'hom', agent_id: 'housekeeper', valid_from: VALID_FROM,
      valid_until: '2026-09-09T18:49:54.000Z', cert_fingerprint: HOUSEKEEPER_CERT,
      certificate: HOUSEKEEPER_CERTIFICATE, public_key_b64u: HOUSEKEEPER_PUBLIC_KEY,
      identity_tier: 'T1',
    },
    housekeeper_revocation_state: {
      schema: SCHEMA.housekeeper_revocation_state,
      company_id: 'hom', agent_id: 'housekeeper', valid_from: VALID_FROM,
      evaluated_at_unix_seconds: TS + 1, revoked: false,
      source_event_mutation_hash: eventMutation,
    },
    effective_recall_grant: {
      schema: SCHEMA.effective_recall_grant,
      authority_kind: 'master_signed_recall_grant',
      company_id: 'hom', subject_agent_id: 'codex-auditor', subject_valid_from: VALID_FROM,
      allowed: true, write_allowed: true, clearance_ceiling: 10,
      data_class_ceiling: 'confidential', master_fingerprint: MASTER,
      signed_body: grantSignedBody, content_hash: grantContentHash,
      mutation_hash: grantMutationHash, prev_mutation_hash: null,
      ts_signed: TS - 100, nonce: 'grant-nonce', signature_b64u: SIGNATURE,
    },
    request_envelope: {
      schema: SCHEMA.request_envelope,
      company_id: 'hom', actor_agent_id: 'codex-auditor', actor_valid_from: VALID_FROM,
      cert_fingerprint: CERT, request_sig_form: 3, signed_method: 'POST',
      signed_path: '/aimos/recall', request_body: requestBody,
      request_body_hash: outerRequestHash, outer_request_hash: outerRequestHash,
      normalized_command: normalizedCommand, command_hash: commandHash,
      requested_clearance_level: 10, requested_data_class: 'confidential',
      nonce: 'request-nonce', ts_signed: TS, signature_b64u: SIGNATURE,
    },
    request_receipt: {
      schema: SCHEMA.request_receipt,
      request_receipt_id: RECEIPT_ID, mutation_hash: requestReceiptMutationHash,
      company_id: 'hom', actor_agent_id: 'codex-auditor', actor_valid_from: VALID_FROM,
      cert_fingerprint: CERT, request_sig_form: 3, signed_method: 'POST',
      signed_path: '/aimos/recall', request_hash: outerRequestHash,
      signed_claims: null, signed_claims_hash: null,
      prev_mutation_hash: requestPreviousHash,
      nonce: 'request-nonce', ts_signed: TS, signature_b64u: SIGNATURE,
    },
    content_state_projection: content,
    epistemic_recall_decision: epistemic,
    final_security_closure: security,
    return_projection: projection,
    native_recall_receipt: {
      schema: SCHEMA.native_recall_receipt,
      command_hash: commandHash,
      outer_request_hash: outerRequestHash,
      authority_mutation_hash: grantMutationHash,
      request_receipt_id: RECEIPT_ID,
      request_receipt_mutation_hash: requestReceiptMutationHash,
      result_count: 1,
      merkle_schema: 'hom-aimos/recall-merkle/v3-epistemic-and-security-closure',
      epistemic_decision_sha256: EPISTEMIC,
      canary_final_security_closure_sha256: SECURITY,
      evidence: [evidence],
      merkle_entries: merkleEntries,
      merkle_root: merkleRoot,
      return_projection: projection,
      return_projection_event_body_bound: true,
      event_receipt: {
        signed_body: eventSignedBody,
        content_hash: eventContentHash,
        mutation_hash: eventMutation,
        prev_mutation_hash: eventPreviousHash,
        nonce: 'event-nonce',
        ts_signed: TS + 1,
        signature_b64u: SIGNATURE,
        signer_certificate: HOUSEKEEPER_CERTIFICATE,
      },
    },
    memory_state: {
      schema: SCHEMA.memory_state,
      memory_id: MEMORY, live_content_hash: CONTENT,
    },
    provenance_chain: {
      schema: SCHEMA.provenance_chain,
      memory_id: MEMORY, live_content_hash: CONTENT,
      save_mutation_hash: SAVE, binding_mutation_hash: BINDING,
    },
    occurrence: {
      schema: SCHEMA.occurrence,
      memory_id: MEMORY, live_content_hash_hex: CONTENT,
      occurrence_ref: effectiveOccurrence,
      occurrence_form: 'v3',
      native_schema: 'hom.aimos.memory-occurrence/v3',
      native_body: occurrenceRecord,
      signature_b64u: SIGNATURE,
      signer_certificate: HOUSEKEEPER_CERTIFICATE,
    },
    epistemic_projection: {
      schema: SCHEMA.epistemic_projection,
      memory_id: MEMORY, live_content_hash: CONTENT,
      label: 'unverified', decision_sha256: EPISTEMIC,
    },
    receipt_evidence: { schema: SCHEMA.receipt_evidence, ...evidence },
  };
}

export function convertMutMemPortableFixtureToHousekeeper(bodies) {
  bodies.actor_identity_epoch = {
    ...bodies.housekeeper_identity_epoch,
    schema: SCHEMA.actor_identity_epoch,
  };
  bodies.actor_revocation_state = {
    ...bodies.housekeeper_revocation_state,
    schema: SCHEMA.actor_revocation_state,
  };
  const systemPrincipalBody = {
    kind: 'housekeeper_system_principal',
    company_id: 'hom',
    agent_id: 'housekeeper',
    valid_from: VALID_FROM,
  };
  const authorityMutationHash = housekeeperSystemPrincipalHashV1({
    companyId: 'hom', agentId: 'housekeeper', validFrom: VALID_FROM,
  });
  bodies.effective_recall_grant = {
    schema: SCHEMA.effective_recall_grant,
    authority_kind: 'housekeeper_system_principal',
    company_id: 'hom',
    subject_agent_id: 'housekeeper',
    subject_valid_from: VALID_FROM,
    allowed: true,
    write_allowed: true,
    clearance_ceiling: 12,
    data_class_ceiling: 'restricted',
    master_fingerprint: MASTER,
    system_principal_body: systemPrincipalBody,
    mutation_hash: authorityMutationHash,
  };
  Object.assign(bodies.request_envelope, {
    actor_agent_id: 'housekeeper', cert_fingerprint: HOUSEKEEPER_CERT,
  });
  Object.assign(bodies.request_receipt, {
    actor_agent_id: 'housekeeper', cert_fingerprint: HOUSEKEEPER_CERT,
  });
  bodies.native_recall_receipt.authority_mutation_hash = authorityMutationHash;
  const event = bodies.native_recall_receipt.event_receipt;
  event.signed_body.actor_agent_id = 'housekeeper';
  event.signed_body.metadata.authority_mutation_hash = authorityMutationHash;
  event.content_hash = canonicalSha(event.signed_body);
  event.mutation_hash = eventMutationHash(
    Buffer.from(event.prev_mutation_hash, 'hex'),
    Buffer.from(event.content_hash, 'hex'),
    event.nonce,
    event.ts_signed,
  ).toString('hex');
  bodies.actor_revocation_state.source_event_mutation_hash = event.mutation_hash;
  bodies.housekeeper_revocation_state.source_event_mutation_hash = event.mutation_hash;
}

export function buildMutMemPortablePredicateEnvelope(mutator = null, schemaOverrides = {}) {
  const bodies = baseMutMemPortablePredicateBodies();
  if (mutator) mutator(bodies);
  const singletons = [
    'trust_anchor', 'actor_identity_epoch', 'actor_revocation_state',
    'housekeeper_identity_epoch', 'housekeeper_revocation_state',
    'effective_recall_grant', 'request_envelope', 'request_receipt',
    'content_state_projection', 'epistemic_recall_decision',
    'final_security_closure', 'return_projection', 'native_recall_receipt',
  ].map((kind) => createMutMemPortableObjectV2({
    kind,
    schema: schemaOverrides[kind] || bodies[kind].schema,
    body: schemaOverrides[kind]
      ? { ...bodies[kind], schema: schemaOverrides[kind] }
      : bodies[kind],
  }));
  const results = [
    'memory_state', 'provenance_chain', 'occurrence',
    'epistemic_projection', 'receipt_evidence',
  ].map((kind) => createMutMemPortableObjectV2({
    kind, schema: bodies[kind].schema, subjectId: MEMORY, resultOrdinal: 0, body: bodies[kind],
  }));
  return createMutMemPortableEvidenceEnvelopeV2({
    bundleId: 'P1-PRED-CV-001', companyId: 'hom', expectedMasterFingerprint: MASTER,
    resultCount: 1, objects: [...singletons, ...results],
  });
}

const negativeDefinitions = [
  ['OBJECT_SCHEMA_INVALID', null, { trust_anchor: 'hom.aimos.wrong/v9' }],
  ['TRUST_ROOT_MISMATCH', (b) => { b.trust_anchor.master_fingerprint = fixtureSha('wrong'); }],
  ['TRUST_ANCHOR_KEY_MISMATCH', (b) => { b.trust_anchor.master_public_key_b64u = Buffer.from('wrong').toString('base64url'); }],
  ['IDENTITY_SCOPE_MISMATCH', (b) => { b.request_envelope.actor_agent_id = 'wrong-agent'; }],
  ['IDENTITY_CERTIFICATE_BINDING_INVALID', (b) => { b.actor_identity_epoch.certificate = 'wrong-certificate'; }],
  ['IDENTITY_EPOCH_INVALID', (b) => { b.actor_identity_epoch.valid_until = '2026-08-11T18:49:54.000Z'; }],
  ['REVOCATION_STATE_INVALID', (b) => { b.actor_revocation_state.revoked = true; }],
  ['HOUSEKEEPER_IDENTITY_INVALID', (b) => { b.housekeeper_identity_epoch.certificate = 'wrong-certificate'; }],
  ['HOUSEKEEPER_REVOCATION_STATE_INVALID', (b) => { b.housekeeper_revocation_state.revoked = true; }],
  ['HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID', (b) => {
    b.effective_recall_grant.authority_kind = 'housekeeper_system_principal';
    b.effective_recall_grant.system_principal_body = {
      kind: 'housekeeper_system_principal', company_id: 'hom',
      agent_id: 'codex-auditor', valid_from: VALID_FROM,
    };
  }],
  ['GRANT_SCOPE_MISMATCH', (b) => { b.effective_recall_grant.company_id = 'other'; }],
  ['GRANT_NOT_EFFECTIVE', (b) => { b.effective_recall_grant.allowed = false; }],
  ['GRANT_COMMITMENT_INVALID', (b) => { b.effective_recall_grant.content_hash = fixtureSha('wrong'); }],
  ['REQUEST_CONTEXT_INVALID', (b) => { b.request_envelope.signed_method = 'GET'; }],
  ['REQUEST_BODY_HASH_MISMATCH', (b) => { b.request_envelope.request_body_hash = fixtureSha('wrong'); }],
  ['COMMAND_HASH_MISMATCH', (b) => { b.request_envelope.normalized_command.limit = 2; }],
  ['REQUEST_RECEIPT_BINDING_INVALID', (b) => { b.request_receipt.nonce = 'other'; }],
  ['REQUEST_RECEIPT_COMMITMENT_INVALID', (b) => { b.request_receipt.prev_mutation_hash = fixtureSha('wrong'); }],
  ['AUTHORITY_MUTATION_BINDING_INVALID', (b) => { b.native_recall_receipt.authority_mutation_hash = fixtureSha('wrong'); }],
  ['DECISION_HASH_MALFORMED', (b) => { b.content_state_projection.admission_decision_sha256 = 'bad'; }],
  ['CONTENT_STATE_BINDING_INVALID', (b) => {
    b.return_projection.content_state_selection_sha256 = fixtureSha('wrong');
    b.native_recall_receipt.return_projection = b.return_projection;
    b.native_recall_receipt.event_receipt.signed_body.metadata.return_projection = b.return_projection;
  }],
  ['EPISTEMIC_BINDING_INVALID', (b) => { b.final_security_closure.epistemic_decision_sha256 = fixtureSha('wrong'); }],
  ['SECURITY_CLOSURE_BINDING_INVALID', (b) => {
    b.return_projection.final_security_closure_sha256 = fixtureSha('wrong');
    b.native_recall_receipt.return_projection = b.return_projection;
    b.native_recall_receipt.event_receipt.signed_body.metadata.return_projection = b.return_projection;
  }],
  ['RETURN_PROJECTION_BINDING_INVALID', (b) => {
    b.return_projection.projected_memory_ids = ['22222222-2222-4222-8222-222222222222'];
    b.native_recall_receipt.return_projection = b.return_projection;
    b.native_recall_receipt.event_receipt.signed_body.metadata.return_projection = b.return_projection;
  }],
  ['RESULT_CARDINALITY_INVALID', (b) => { b.native_recall_receipt.result_count = 2; }],
  ['RESULT_IDENTITY_BINDING_INVALID', (b) => { b.provenance_chain.memory_id = '22222222-2222-4222-8222-222222222222'; }],
  ['PROVENANCE_BINDING_INVALID', (b) => { b.provenance_chain.save_mutation_hash = fixtureSha('wrong'); }],
  ['OCCURRENCE_BINDING_INVALID', (b) => { b.occurrence.occurrence_ref = fixtureSha('wrong'); }],
  ['OCCURRENCE_NATIVE_BODY_INVALID', (b) => {
    b.occurrence.native_body.memory_id = '22222222-2222-4222-8222-222222222222';
  }],
  ['EPISTEMIC_PROJECTION_BINDING_INVALID', (b) => { b.epistemic_projection.decision_sha256 = fixtureSha('wrong'); }],
  ['RECEIPT_EVIDENCE_BINDING_INVALID', (b) => { b.receipt_evidence.calibrated_score = 0.5; }],
  ['MERKLE_ENTRY_BINDING_INVALID', (b) => { b.native_recall_receipt.merkle_entries[0].decision_sha256 = fixtureSha('wrong'); }],
  ['MERKLE_ROOT_MISMATCH', (b) => {
    b.native_recall_receipt.merkle_root = fixtureSha('wrong');
    b.native_recall_receipt.event_receipt.signed_body.metadata.merkle_root = fixtureSha('wrong');
  }],
  ['EVENT_RECEIPT_BINDING_INVALID', (b) => { b.native_recall_receipt.event_receipt.signed_body.metadata.command_hash = fixtureSha('wrong'); }],
  ['EVENT_RECEIPT_COMMITMENT_INVALID', (b) => { b.native_recall_receipt.event_receipt.content_hash = fixtureSha('wrong'); }],
  ['REVOCATION_EVENT_BINDING_INVALID', (b) => { b.actor_revocation_state.source_event_mutation_hash = fixtureSha('wrong'); }],
];

export function createMutMemPortablePredicateVectorsV2() {
  const ordinary = buildMutMemPortablePredicateEnvelope();
  const housekeeper = buildMutMemPortablePredicateEnvelope(
    convertMutMemPortableFixtureToHousekeeper,
  );
  const vectors = [
    { id: 'P1-PRED-CV-VALID-ORDINARY', expected: 'valid', reason: null, bundle: ordinary },
    { id: 'P1-PRED-CV-VALID-HOUSEKEEPER', expected: 'valid', reason: null, bundle: housekeeper },
    ...negativeDefinitions.map(([reason, mutate, schemaOverrides = {}], index) => ({
      id: `P1-PRED-CV-${String(index + 1).padStart(3, '0')}`,
      expected: 'invalid',
      reason,
      bundle: buildMutMemPortablePredicateEnvelope(mutate, schemaOverrides),
    })),
  ];
  const tamperedEnvelope = structuredClone(ordinary);
  tamperedEnvelope.bundle_sha256 = fixtureSha('tampered-envelope');
  vectors.push({
    id: 'P1-PRED-CV-ENVELOPE-COMMITMENT',
    expected: 'invalid',
    reason: 'ENVELOPE_COMMITMENT_INVALID',
    bundle: tamperedEnvelope,
  });
  return Object.freeze(vectors.map((vector) => Object.freeze(vector)));
}
