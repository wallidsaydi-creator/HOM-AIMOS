// Independent MutMem V2 recall-disclosure verifier.
// Imports only the sibling authority-free cryptographic kernel.

import {
  canonicalBytes,
  canonicalJson,
  decodeCertificate,
  retainedProvenanceMessage,
  legacyOccurrenceReference,
  verifyEd25519,
  eventPayloadCommitment,
  eventPayloadBody,
  exactBase64url,
  exactHashBytes,
  framedUtf8,
  occurrenceCommitmentV3,
  recallMerkleRoot,
  sha256,
  sha256Hex,
  u32,
  u64,
  verifyCertificate,
  verifyOccurrenceSignatureV3,
  verifyPayloadSignature,
  verifyEventPayloadSignature,
  verifyRequestContextSignature,
} from './crypto-kernel.mjs';

export const RECALL_SCHEMAS = Object.freeze({
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

const ORIGIN_DISCLOSURE_FAILURE_CODES = Object.freeze([
  'ORIGIN_FAMILY_PROFILE_INVALID', 'ORIGIN_DISCLOSURE_LABEL_INVALID',
  'ORIGIN_DISCLOSURE_ROOT_INVALID', 'ORIGIN_DISCLOSURE_EVENT_BINDING_INVALID',
]);
const ORIGIN_PROFILE_HASH = '49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24';
const CURRENT_RECEIPT_SCHEMA = 'hom-aimos/recall-merkle/v4-origin-family-disclosure';
const PROVENANCE_FAILURE_CODES = Object.freeze([
  'PROVENANCE_BYTES_INVALID', 'PROVENANCE_CONTEXT_INVALID', 'PROVENANCE_COMMITMENT_INVALID',
  'PROVENANCE_CERTIFICATE_INVALID', 'PROVENANCE_REVOCATION_INVALID',
  'PROVENANCE_SIGNATURE_INVALID', 'PROVENANCE_CHAIN_INVALID', 'PROVENANCE_SAVE_BINDING_INVALID',
]);
const CURRENT_OBJECT_SCHEMAS = Object.freeze({ ...RECALL_SCHEMAS,
  native_recall_receipt: 'hom.aimos.mutmem-native-recall-receipt/v3',
  receipt_evidence: 'hom.aimos.mutmem-recall-evidence-entry/v3',
  provenance_chain: 'hom.aimos.mutmem-provenance-chain/v3',
  occurrence: 'hom.aimos.mutmem-occurrence-evidence/v3',
});

export const STRUCTURAL_FAILURE_CODES = Object.freeze([
  'ENVELOPE_COMMITMENT_INVALID', 'OBJECT_SCHEMA_INVALID', 'TRUST_ROOT_MISMATCH',
  'TRUST_ANCHOR_KEY_MISMATCH', 'IDENTITY_SCOPE_MISMATCH',
  'IDENTITY_CERTIFICATE_BINDING_INVALID', 'IDENTITY_EPOCH_INVALID',
  'REVOCATION_STATE_INVALID', 'HOUSEKEEPER_IDENTITY_INVALID',
  'HOUSEKEEPER_REVOCATION_STATE_INVALID', 'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID',
  'GRANT_SCOPE_MISMATCH', 'GRANT_NOT_EFFECTIVE', 'GRANT_COMMITMENT_INVALID',
  'REQUEST_CONTEXT_INVALID', 'REQUEST_BODY_HASH_MISMATCH', 'COMMAND_HASH_MISMATCH',
  'REQUEST_RECEIPT_BINDING_INVALID', 'REQUEST_RECEIPT_COMMITMENT_INVALID',
  'AUTHORITY_MUTATION_BINDING_INVALID', 'DECISION_HASH_MALFORMED',
  'CONTENT_STATE_BINDING_INVALID', 'EPISTEMIC_BINDING_INVALID',
  'SECURITY_CLOSURE_BINDING_INVALID', 'RETURN_PROJECTION_BINDING_INVALID',
  'RESULT_CARDINALITY_INVALID', 'RESULT_IDENTITY_BINDING_INVALID',
  'PROVENANCE_BINDING_INVALID', 'OCCURRENCE_BINDING_INVALID',
  'OCCURRENCE_NATIVE_BODY_INVALID', 'EPISTEMIC_PROJECTION_BINDING_INVALID',
  'RECEIPT_EVIDENCE_BINDING_INVALID', 'MERKLE_ENTRY_BINDING_INVALID',
  'MERKLE_ROOT_MISMATCH', 'EVENT_RECEIPT_BINDING_INVALID',
  'EVENT_RECEIPT_COMMITMENT_INVALID', 'REVOCATION_EVENT_BINDING_INVALID',
]);

export const CRYPTOGRAPHIC_FAILURE_CODES = Object.freeze([
  'EXPECTED_TRUST_ANCHOR_REQUIRED',
  'ACTOR_CERTIFICATE_SIGNATURE_INVALID',
  'HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID',
  'MASTER_GRANT_SIGNATURE_INVALID',
  'ACTOR_REQUEST_SIGNATURE_INVALID',
  'HOUSEKEEPER_EVENT_SIGNATURE_INVALID',
  'HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID',
]);

const SINGLETON_KINDS = Object.freeze([
  'trust_anchor', 'actor_identity_epoch', 'actor_revocation_state',
  'housekeeper_identity_epoch', 'housekeeper_revocation_state',
  'effective_recall_grant', 'request_envelope', 'request_receipt',
  'content_state_projection', 'epistemic_recall_decision',
  'final_security_closure', 'return_projection', 'native_recall_receipt',
]);
const RESULT_KINDS = Object.freeze([
  'memory_state', 'provenance_chain', 'occurrence',
  'epistemic_projection', 'receipt_evidence',
]);
const SINGLETON_ORDER = new Map(SINGLETON_KINDS.map((kind, index) => [kind, index]));
const RESULT_ORDER = new Map(RESULT_KINDS.map((kind, index) => [kind, index]));
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DATA_CLASSES = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
const RETURN_PATHS = new Set([
  'identifier_exact', 'post_compaction_handoff', 'semantic_cache',
  'adaptive_early_exit', 'normal_recall',
]);
const OBJECT_DOMAIN = Buffer.from('hom.aimos.mutmem-portable-object/v2\0', 'utf8');
const BUNDLE_DOMAIN = Buffer.from('hom.aimos.mutmem-portable-evidence/v2\0', 'utf8');
const RECALL_AUTHORIZATION_DOMAIN = Buffer.from('aimos-recall-authorization-v1\0', 'utf8');
const REQUEST_RECEIPT_DOMAIN = Buffer.from('aimos-request-receipt-v1\0', 'utf8');
const EVENT_LINK_DOMAIN = Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8');

export class MutMemRecallVerificationError extends Error {
  constructor(reason) {
    super(`mutmem_v2_recall:${reason}`);
    this.name = 'MutMemRecallVerificationError';
    this.reason = reason;
  }
}

function fail(reason) {
  if (!STRUCTURAL_FAILURE_CODES.includes(reason)
      && !PROVENANCE_FAILURE_CODES.includes(reason)
      && !ORIGIN_DISCLOSURE_FAILURE_CODES.includes(reason)
      && !CRYPTOGRAPHIC_FAILURE_CODES.includes(reason)) {
    throw new MutMemRecallVerificationError('UNDECLARED_FAILURE_CODE');
  }
  throw new MutMemRecallVerificationError(reason);
}

function string(value) { return String(value ?? ''); }
function equal(left, right) { return canonicalJson(left) === canonicalJson(right); }
function withoutSchema(value = {}) { const { schema: _, ...rest } = value; return rest; }
function hash(value, reason = 'DECISION_HASH_MALFORMED') {
  const normalized = string(value).toLowerCase();
  if (!HEX32.test(normalized)) fail(reason);
  return normalized;
}
function iso(value, reason) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) fail(reason);
  return date.toISOString();
}
function signature(value, reason) {
  try {
    const bytes = exactBase64url(value, reason);
    if (bytes.length !== 64) fail(reason);
    return bytes;
  } catch { fail(reason); }
}
function canonicalSha(value) { return sha256Hex(canonicalBytes(value)); }

function recallAuthorizationMutationHash({ previousMutationHash = null, contentHash, nonce, signedTs }) {
  return sha256Hex(Buffer.concat([
    RECALL_AUTHORIZATION_DOMAIN,
    previousMutationHash == null ? Buffer.alloc(32) : exactHashBytes(previousMutationHash),
    exactHashBytes(contentHash),
    Buffer.from(string(nonce), 'utf8'),
    Buffer.from(string(signedTs), 'utf8'),
  ]));
}

function requestReceiptMutationHash({
  previousMutationHash = null, requestHash, claimsHash = null,
  signature: signatureB64u, method, path, nonce, signedTs,
}) {
  return sha256Hex(Buffer.concat([
    REQUEST_RECEIPT_DOMAIN,
    previousMutationHash == null ? Buffer.alloc(32) : exactHashBytes(previousMutationHash),
    exactHashBytes(requestHash),
    claimsHash == null ? Buffer.alloc(32) : exactHashBytes(claimsHash),
    signature(signatureB64u, 'REQUEST_RECEIPT_COMMITMENT_INVALID'),
    Buffer.from(string(method), 'utf8'),
    Buffer.from(string(path), 'utf8'),
    Buffer.from(string(nonce), 'utf8'),
    Buffer.from(string(signedTs), 'utf8'),
  ]));
}

function eventMutationHash(previous, content, nonce, signedTs) {
  return sha256Hex(Buffer.concat([
    EVENT_LINK_DOMAIN, exactHashBytes(previous), exactHashBytes(content),
    Buffer.from(string(nonce), 'utf8'), Buffer.from(string(signedTs), 'utf8'),
  ]));
}

function systemPrincipalHash(body) { return canonicalSha(body); }

function objectHash({ kind, schema, body }) {
  const bodyBytes = canonicalBytes(body);
  if (bodyBytes.length > 1024 * 1024) fail('ENVELOPE_COMMITMENT_INVALID');
  return sha256Hex(Buffer.concat([
    OBJECT_DOMAIN,
    framedUtf8(kind),
    framedUtf8(schema),
    u32(bodyBytes.length),
    bodyBytes,
  ]));
}

function reconstructEnvelope(envelope) {
  try {
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || !Array.isArray(envelope.objects)
        || !Number.isSafeInteger(envelope.result_count)
        || envelope.result_count < 0 || envelope.result_count > 200) {
      fail('ENVELOPE_COMMITMENT_INVALID');
    }
    if (envelope.objects.length !== 13 + 5 * envelope.result_count) {
      fail('ENVELOPE_COMMITMENT_INVALID');
    }
    const singletons = new Map();
    const results = Array.from({ length: envelope.result_count }, () => new Map());
    const subjects = new Map();
    for (const object of envelope.objects) {
      const expectedKeys = ['ordinal', 'kind', 'schema', 'subject_id', 'result_ordinal', 'body_sha256', 'body'];
      if (!object || typeof object !== 'object' || Array.isArray(object)
          || Object.keys(object).sort().join('\0') !== expectedKeys.sort().join('\0')
          || (!SINGLETON_ORDER.has(object.kind) && !RESULT_ORDER.has(object.kind))
          || object.body?.schema !== object.schema
          || object.body_sha256 !== objectHash(object)) fail('ENVELOPE_COMMITMENT_INVALID');
      if (SINGLETON_ORDER.has(object.kind)) {
        if (object.subject_id !== null || object.result_ordinal !== null
            || singletons.has(object.kind)) fail('ENVELOPE_COMMITMENT_INVALID');
        singletons.set(object.kind, object);
      } else {
        const ordinal = object.result_ordinal;
        const subject = string(object.subject_id).toLowerCase();
        if (!Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal >= envelope.result_count
            || !UUID.test(subject) || results[ordinal].has(object.kind)) {
          fail('ENVELOPE_COMMITMENT_INVALID');
        }
        if (subjects.has(ordinal) && subjects.get(ordinal) !== subject) {
          fail('ENVELOPE_COMMITMENT_INVALID');
        }
        subjects.set(ordinal, subject);
        results[ordinal].set(object.kind, object);
      }
    }
    if (SINGLETON_KINDS.some((kind) => !singletons.has(kind))
        || results.some((group) => RESULT_KINDS.some((kind) => !group.has(kind)))) {
      fail('ENVELOPE_COMMITMENT_INVALID');
    }
    const ordered = [
      ...SINGLETON_KINDS.map((kind) => singletons.get(kind)),
      ...results.flatMap((group) => RESULT_KINDS.map((kind) => group.get(kind))),
    ];
    if (ordered.length !== 13 + 5 * envelope.result_count
        || ordered.length !== envelope.object_count
        || ordered.some((object, ordinal) => object.ordinal !== ordinal)) {
      fail('ENVELOPE_COMMITMENT_INVALID');
    }
    const objectRoot = recallMerkleRoot(ordered.map((object) => ({
      ordinal: object.ordinal,
      kind: object.kind,
      schema: object.schema,
      subject_id: object.subject_id,
      result_ordinal: object.result_ordinal,
      body_sha256: object.body_sha256,
    }))).toString('hex');
    const fingerprint = string(envelope.expected_master_fingerprint).toLowerCase();
    if (!HEX32.test(fingerprint) || !HEX32.test(objectRoot)) fail('ENVELOPE_COMMITMENT_INVALID');
    const current = envelope.format?.schema === 'hom.aimos.mutmem-portable-evidence/v3';
    const bundleHash = sha256Hex(Buffer.concat([
      current ? Buffer.from('hom.aimos.mutmem-portable-evidence/v3\0') : BUNDLE_DOMAIN,
      framedUtf8(envelope.bundle_id),
      framedUtf8(envelope.company_id),
      Buffer.from(fingerprint, 'hex'),
      u64(envelope.result_count),
      Buffer.from(objectRoot, 'hex'),
    ]));
    const format = envelope.format;
    if (!equal(Object.keys(format || {}).sort(), ['schema', 'version', 'profile', 'canonicalization', 'hash', 'signature', 'trust_anchor_mode', 'native_receipt_schema'].sort())
        || format?.schema !== `hom.aimos.mutmem-portable-evidence/v${current ? 3 : 2}`
        || format?.version !== (current ? 3 : 2) || format?.profile !== 'recall_disclosure'
        || format?.canonicalization !== 'hom-aimos/canonical-json/v1'
        || format?.hash !== 'sha256' || format?.signature !== 'ed25519'
        || format?.trust_anchor_mode !== 'external_expected_master_fingerprint_required'
        || format?.native_receipt_schema
          !== (current ? CURRENT_RECEIPT_SCHEMA : 'hom-aimos/recall-merkle/v3-epistemic-and-security-closure')
        || envelope.object_root_sha256 !== objectRoot
        || envelope.bundle_sha256 !== bundleHash) fail('ENVELOPE_COMMITMENT_INVALID');
    return { envelope, singletons, results, objectRoot, bundleHash };
  } catch (error) {
    if (error instanceof MutMemRecallVerificationError) throw error;
    fail('ENVELOPE_COMMITMENT_INVALID');
  }
}

function requireSchemas(state) {
  const schemas = state.envelope.format.version === 3 ? CURRENT_OBJECT_SCHEMAS : RECALL_SCHEMAS;
  for (const object of state.envelope.objects) {
    const retainedShape = state.envelope.format.version === 3
      && ['provenance_chain', 'occurrence'].includes(object.kind) && object.schema === RECALL_SCHEMAS[object.kind];
    if ((!retainedShape && object.schema !== schemas[object.kind]) || object.body?.schema !== object.schema) {
      fail('OBJECT_SCHEMA_INVALID');
    }
  }
}

function validateAuthority(state) {
  const get = (kind) => state.singletons.get(kind).body;
  const trust = get('trust_anchor');
  const identity = get('actor_identity_epoch');
  const revocation = get('actor_revocation_state');
  const housekeeperIdentity = get('housekeeper_identity_epoch');
  const housekeeperRevocation = get('housekeeper_revocation_state');
  const grant = get('effective_recall_grant');
  const request = get('request_envelope');
  const requestReceipt = get('request_receipt');
  const nativeReceipt = get('native_recall_receipt');
  if (hash(trust.master_fingerprint) !== state.envelope.expected_master_fingerprint) {
    fail('TRUST_ROOT_MISMATCH');
  }
  let masterBytes;
  try { masterBytes = exactBase64url(trust.master_public_key_b64u); } catch { fail('TRUST_ANCHOR_KEY_MISMATCH'); }
  if (sha256Hex(masterBytes) !== trust.master_fingerprint) fail('TRUST_ANCHOR_KEY_MISMATCH');
  const agentId = string(identity.agent_id);
  const validFrom = iso(identity.valid_from, 'IDENTITY_SCOPE_MISMATCH');
  const certFingerprint = hash(identity.cert_fingerprint, 'IDENTITY_SCOPE_MISMATCH');
  if (!identity.certificate || !identity.public_key_b64u
      || sha256Hex(Buffer.from(string(identity.certificate), 'utf8')) !== certFingerprint) {
    fail('IDENTITY_CERTIFICATE_BINDING_INVALID');
  }
  if (!agentId || identity.company_id !== state.envelope.company_id
      || request.company_id !== state.envelope.company_id || request.actor_agent_id !== agentId
      || iso(request.actor_valid_from, 'IDENTITY_SCOPE_MISMATCH') !== validFrom
      || request.cert_fingerprint !== certFingerprint
      || requestReceipt.company_id !== state.envelope.company_id
      || requestReceipt.actor_agent_id !== agentId
      || iso(requestReceipt.actor_valid_from, 'IDENTITY_SCOPE_MISMATCH') !== validFrom
      || requestReceipt.cert_fingerprint !== certFingerprint) fail('IDENTITY_SCOPE_MISMATCH');
  const hkValidFrom = iso(housekeeperIdentity.valid_from, 'HOUSEKEEPER_IDENTITY_INVALID');
  const hkFingerprint = hash(
    housekeeperIdentity.cert_fingerprint,
    'HOUSEKEEPER_IDENTITY_INVALID',
  );
  if (housekeeperIdentity.company_id !== state.envelope.company_id
      || housekeeperIdentity.agent_id !== 'housekeeper'
      || !housekeeperIdentity.certificate || !housekeeperIdentity.public_key_b64u
      || sha256Hex(Buffer.from(string(housekeeperIdentity.certificate), 'utf8')) !== hkFingerprint) {
    fail('HOUSEKEEPER_IDENTITY_INVALID');
  }
  if (agentId === 'housekeeper'
      && ((identity.identity_tier !== 'T1' && identity.identity_tier !== 'T1_SYSTEM_SELF')
        || validFrom !== hkValidFrom || certFingerprint !== hkFingerprint
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
      || requestTs > validUntilSeconds) fail('IDENTITY_EPOCH_INVALID');
  if (revocation.company_id !== state.envelope.company_id || revocation.agent_id !== agentId
      || iso(revocation.valid_from, 'REVOCATION_STATE_INVALID') !== validFrom
      || revocation.revoked !== false
      || !Number.isSafeInteger(Number(revocation.evaluated_at_unix_seconds))
      || Number(revocation.evaluated_at_unix_seconds) < requestTs) fail('REVOCATION_STATE_INVALID');
  if (housekeeperRevocation.company_id !== state.envelope.company_id
      || housekeeperRevocation.agent_id !== 'housekeeper'
      || iso(housekeeperRevocation.valid_from, 'HOUSEKEEPER_REVOCATION_STATE_INVALID') !== hkValidFrom
      || housekeeperRevocation.revoked !== false
      || !Number.isSafeInteger(Number(housekeeperRevocation.evaluated_at_unix_seconds))) {
    fail('HOUSEKEEPER_REVOCATION_STATE_INVALID');
  }
  const clearance = Number(grant.clearance_ceiling);
  const requestedClearance = request.requested_clearance_level == null
    ? clearance : Number(request.requested_clearance_level);
  const dataClassIndex = DATA_CLASSES.indexOf(grant.data_class_ceiling);
  if (grant.company_id !== state.envelope.company_id || grant.subject_agent_id !== agentId
      || iso(grant.subject_valid_from, 'GRANT_SCOPE_MISMATCH') !== validFrom
      || grant.master_fingerprint !== state.envelope.expected_master_fingerprint
      || !Number.isInteger(clearance) || clearance < 0 || clearance > 12
      || !Number.isInteger(requestedClearance) || requestedClearance < 0
      || requestedClearance > clearance || dataClassIndex < 0) fail('GRANT_SCOPE_MISMATCH');
  if (grant.allowed !== true || (request.requested_data_class != null
      && DATA_CLASSES.indexOf(request.requested_data_class) > dataClassIndex)) {
    fail('GRANT_NOT_EFFECTIVE');
  }
  if (grant.authority_kind === 'master_signed_recall_grant') {
    if (agentId === 'housekeeper' || grant.signed_body?.schema !== 'hom.aimos.recall-authorization/v1'
        || grant.signed_body.company_id !== grant.company_id
        || grant.signed_body.subject_agent_id !== grant.subject_agent_id
        || iso(grant.signed_body.subject_valid_from, 'GRANT_COMMITMENT_INVALID') !== validFrom
        || Boolean(grant.signed_body.allowed) !== grant.allowed
        || Number(grant.signed_body.clearance_ceiling) !== clearance
        || grant.signed_body.data_class_ceiling !== grant.data_class_ceiling
        || grant.signed_body.master_fingerprint !== grant.master_fingerprint
        || canonicalSha(grant.signed_body) !== grant.content_hash
        || recallAuthorizationMutationHash({
          previousMutationHash: grant.prev_mutation_hash,
          contentHash: grant.content_hash,
          nonce: grant.nonce,
          signedTs: grant.ts_signed,
        }) !== grant.mutation_hash) fail('GRANT_COMMITMENT_INVALID');
    signature(grant.signature_b64u, 'GRANT_COMMITMENT_INVALID');
  } else if (grant.authority_kind === 'housekeeper_system_principal') {
    const system = grant.system_principal_body;
    const forbidden = ['signed_body', 'content_hash', 'prev_mutation_hash', 'ts_signed', 'nonce', 'signature_b64u'];
    if (agentId !== 'housekeeper' || forbidden.some((field) => Object.hasOwn(grant, field))
        || system?.kind !== 'housekeeper_system_principal'
        || system.company_id !== state.envelope.company_id || system.agent_id !== 'housekeeper'
        || iso(system.valid_from, 'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID') !== validFrom
        || clearance !== 12 || grant.data_class_ceiling !== 'restricted'
        || grant.mutation_hash !== systemPrincipalHash({
          kind: 'housekeeper_system_principal', company_id: system.company_id,
          agent_id: system.agent_id, valid_from: iso(system.valid_from, 'HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID'),
        })) fail('HOUSEKEEPER_SYSTEM_PRINCIPAL_INVALID');
  } else fail('GRANT_COMMITMENT_INVALID');
  if (![3, 5].includes(request.request_sig_form) || request.signed_method !== 'POST'
      || String(request.signed_path || '').split('?')[0] !== '/aimos/recall'
      || (request.request_sig_form === 3 && request.signed_path.includes('?')) || !string(request.nonce)
      || !request.request_body || typeof request.request_body !== 'object'
      || Array.isArray(request.request_body)) fail('REQUEST_CONTEXT_INVALID');
  signature(request.signature_b64u, 'REQUEST_CONTEXT_INVALID');
  const requestHash = canonicalSha(request.request_body);
  if (request.request_body_hash !== requestHash || request.outer_request_hash !== requestHash) {
    fail('REQUEST_BODY_HASH_MISMATCH');
  }
  if (!request.normalized_command || canonicalSha(request.normalized_command) !== request.command_hash) {
    fail('COMMAND_HASH_MISMATCH');
  }
  if (!UUID.test(string(requestReceipt.request_receipt_id))
      || requestReceipt.request_sig_form !== request.request_sig_form
      || requestReceipt.signed_method !== request.signed_method
      || requestReceipt.signed_path !== request.signed_path
      || Number(requestReceipt.ts_signed) !== requestTs
      || requestReceipt.nonce !== request.nonce || requestReceipt.request_hash !== requestHash
      || nativeReceipt.request_receipt_id !== requestReceipt.request_receipt_id
      || nativeReceipt.request_receipt_mutation_hash !== requestReceipt.mutation_hash) {
    fail('REQUEST_RECEIPT_BINDING_INVALID');
  }
  const claimsHash = requestReceipt.signed_claims == null
    ? null : canonicalSha(requestReceipt.signed_claims);
  if ((requestReceipt.signed_claims_hash ?? null) !== claimsHash
      || requestReceipt.signature_b64u !== request.signature_b64u
      || requestReceiptMutationHash({
        previousMutationHash: requestReceipt.prev_mutation_hash,
        requestHash: requestReceipt.request_hash,
        claimsHash,
        signature: requestReceipt.signature_b64u,
        method: requestReceipt.signed_method,
        path: requestReceipt.signed_path,
        nonce: requestReceipt.nonce,
        signedTs: requestReceipt.ts_signed,
      }) !== requestReceipt.mutation_hash) fail('REQUEST_RECEIPT_COMMITMENT_INVALID');
  if (nativeReceipt.authority_mutation_hash !== grant.mutation_hash) {
    fail('AUTHORITY_MUTATION_BINDING_INVALID');
  }
  if (nativeReceipt.outer_request_hash !== request.outer_request_hash
      || nativeReceipt.command_hash !== request.command_hash) fail('REQUEST_CONTEXT_INVALID');
  return {
    trust, identity, revocation, housekeeperIdentity, housekeeperRevocation,
    grant, request, requestReceipt, nativeReceipt, requestTs,
  };
}

function validateDecisions(state, nativeReceipt) {
  const get = (kind) => state.singletons.get(kind).body;
  const content = get('content_state_projection');
  const epistemic = get('epistemic_recall_decision');
  const security = get('final_security_closure');
  const projection = get('return_projection');
  const admissionHash = hash(content.admission_decision_sha256);
  const returnSelectionHash = hash(content.return_selection_decision_sha256);
  const stateRoot = hash(content.state_view_root_sha256);
  const occurrenceRoot = hash(content.occurrence_view_root_sha256);
  const epistemicHash = hash(epistemic.decision_sha256);
  const securityHash = hash(security.decision_sha256);
  hash(projection.decision_sha256);
  if (content.native_decision_schema !== 'hom.aimos.content-state-occurrence-kernel/v1'
      || security.native_decision_schema !== 'hom-aimos/canary-recall-final-closure/v2-epistemic-scope') {
    fail('OBJECT_SCHEMA_INVALID');
  }
  if (projection.content_state_selection_sha256 !== returnSelectionHash
      || security.state_view_root_sha256 !== stateRoot
      || security.occurrence_view_root_sha256 !== occurrenceRoot) fail('CONTENT_STATE_BINDING_INVALID');
  if (security.epistemic_decision_sha256 !== epistemicHash
      || nativeReceipt.epistemic_decision_sha256 !== epistemicHash) fail('EPISTEMIC_BINDING_INVALID');
  if (projection.final_security_closure_sha256 !== securityHash
      || nativeReceipt.canary_final_security_closure_sha256 !== securityHash) {
    fail('SECURITY_CLOSURE_BINDING_INVALID');
  }
  if (!Array.isArray(epistemic.selected_memory_ids)
      || !Array.isArray(security.selected_clean_memory_ids)
      || !Array.isArray(projection.projected_memory_ids)
      || !Array.isArray(projection.projected_live_content_hashes)
      || projection.return_path !== security.return_path || !RETURN_PATHS.has(projection.return_path)
      || projection.ordered_unique_subset_of_final_clean_security_closure !== true
      || projection.output_content_commitments_unchanged !== true
      || projection.canonical_memory_mutated !== false || projection.retention_changed !== false
      || nativeReceipt.return_projection_event_body_bound !== true
      || !equal(nativeReceipt.return_projection, projection)) fail('RETURN_PROJECTION_BINDING_INVALID');
  return {
    content, epistemic, security, projection, admissionHash,
    returnSelectionHash, epistemicHash, securityHash,
  };
}

function validateResults(state, decisions, nativeReceipt) {
  if (nativeReceipt.merkle_schema !== state.envelope.format.native_receipt_schema
      || Number(nativeReceipt.result_count) !== state.envelope.result_count
      || !Array.isArray(nativeReceipt.evidence)
      || nativeReceipt.evidence.length !== state.envelope.result_count
      || decisions.projection.projected_output_count !== state.envelope.result_count
      || decisions.projection.projected_memory_ids.length !== state.envelope.result_count
      || decisions.projection.projected_live_content_hashes.length !== state.envelope.result_count) {
    fail('RESULT_CARDINALITY_INVALID');
  }
  const evidence = [];
  const occurrenceObjects = [];
  for (let ordinal = 0; ordinal < state.results.length; ordinal += 1) {
    const group = state.results[ordinal];
    const memory = group.get('memory_state').body;
    const provenance = group.get('provenance_chain').body;
    const occurrence = group.get('occurrence').body;
    if (provenance.schema.endsWith('/v3') !== occurrence.schema.endsWith('/v3')) fail('OBJECT_SCHEMA_INVALID');
    const epistemic = group.get('epistemic_projection').body;
    const receipt = group.get('receipt_evidence').body;
    const memoryId = string(memory.memory_id).toLowerCase();
    const liveHash = hash(memory.live_content_hash, 'RESULT_IDENTITY_BINDING_INVALID');
    if (!UUID.test(memoryId) || group.get('memory_state').subject_id !== memoryId
        || [provenance, occurrence, epistemic, receipt]
          .some((body) => string(body.memory_id).toLowerCase() !== memoryId)
        || [provenance.live_content_hash, occurrence.live_content_hash_hex,
          epistemic.live_content_hash, receipt.live_content_hash]
          .some((value) => string(value).toLowerCase() !== liveHash)) {
      fail('RESULT_IDENTITY_BINDING_INVALID');
    }
    if (provenance.save_mutation_hash !== receipt.save_mutation_hash
        || provenance.binding_mutation_hash !== receipt.binding_mutation_hash
        || !HEX32.test(string(provenance.save_mutation_hash))
        || !HEX32.test(string(provenance.binding_mutation_hash))) fail('PROVENANCE_BINDING_INVALID');
    if (occurrence.occurrence_ref !== receipt.occurrence_ref
        || !HEX32.test(string(occurrence.occurrence_ref))) fail('OCCURRENCE_BINDING_INVALID');
    if (occurrence.occurrence_form === 'v3') {
      let commitment;
      try { commitment = occurrenceCommitmentV3(occurrence.native_body); }
      catch { fail('OCCURRENCE_NATIVE_BODY_INVALID'); }
      if (occurrence.native_schema !== 'hom.aimos.memory-occurrence/v3'
          || occurrence.native_body?.schema !== occurrence.native_schema
          || occurrence.native_body?.memory_id !== memoryId
          || occurrence.native_body?.live_content_hash_hex !== liveHash
          || occurrence.native_body?.occurrence_commitment !== occurrence.occurrence_ref
          || commitment !== occurrence.occurrence_ref
          || !string(occurrence.signature_b64u) || !string(occurrence.signer_certificate)) {
        fail('OCCURRENCE_NATIVE_BODY_INVALID');
      }
    } else if (occurrence.occurrence_form === 'legacy_v1') {
      if (occurrence.native_schema !== 'hom.aimos.memory-occurrence-ref/legacy-v1'
          || occurrence.native_body?.memory_id !== memoryId) fail('OCCURRENCE_NATIVE_BODY_INVALID');
    } else fail('OCCURRENCE_NATIVE_BODY_INVALID');
    if (epistemic.decision_sha256 !== decisions.epistemicHash
        || !decisions.epistemic.selected_memory_ids.includes(memoryId)) {
      fail('EPISTEMIC_PROJECTION_BINDING_INVALID');
    }
    if (receipt.ordinal !== ordinal || !equal(withoutSchema(receipt), nativeReceipt.evidence[ordinal])) {
      fail('RECEIPT_EVIDENCE_BINDING_INVALID');
    }
    if (decisions.projection.projected_memory_ids[ordinal] !== memoryId
        || decisions.projection.projected_live_content_hashes[ordinal] !== liveHash
        || decisions.security.selected_clean_memory_ids[ordinal] !== memoryId) {
      fail('RETURN_PROJECTION_BINDING_INVALID');
    }
    if (!Array.isArray(decisions.content.selected_occurrence_refs)
        || !decisions.content.selected_occurrence_refs.includes(receipt.occurrence_ref)) {
      fail('CONTENT_STATE_BINDING_INVALID');
    }
    evidence.push(withoutSchema(receipt));
    occurrenceObjects.push(occurrence);
  }
  if (!equal(decisions.epistemic.selected_memory_ids, decisions.projection.projected_memory_ids)
      || !equal(decisions.security.selected_clean_memory_ids, decisions.projection.projected_memory_ids)) {
    fail('RETURN_PROJECTION_BINDING_INVALID');
  }
  return { evidence, occurrenceObjects };
}

function validateEvent(authority, decisions, evidence) {
  const receipt = authority.nativeReceipt;
  const entries = [
    { entry_type: 'epistemic_decision', decision_sha256: decisions.epistemicHash },
    { entry_type: 'canary_final_security_closure', decision_sha256: decisions.securityHash },
    ...evidence,
  ];
  if (!equal(receipt.merkle_entries, entries)) fail('MERKLE_ENTRY_BINDING_INVALID');
  const root = recallMerkleRoot(entries).toString('hex');
  if (receipt.merkle_root !== root) fail('MERKLE_ROOT_MISMATCH');
  let event;
  try { event = receipt.event_receipt && { ...receipt.event_receipt, signed_body: eventPayloadBody(receipt.event_receipt) }; }
  catch { fail('EVENT_RECEIPT_COMMITMENT_INVALID'); }
  const metadata = event?.signed_body?.metadata;
  if (!event || !metadata || event.signed_body.operation !== 'recall_receipt'
      || event.signed_body.company_id !== authority.identity.company_id
      || event.signed_body.actor_agent_id !== authority.identity.agent_id
      || iso(event.signed_body.actor_valid_from, 'EVENT_RECEIPT_BINDING_INVALID')
        !== iso(authority.identity.valid_from, 'EVENT_RECEIPT_BINDING_INVALID')
      || metadata.command_hash !== receipt.command_hash
      || metadata.outer_request_hash !== receipt.outer_request_hash
      || metadata.authority_mutation_hash !== receipt.authority_mutation_hash
      || metadata.request_receipt_id !== receipt.request_receipt_id
      || metadata.request_receipt_mutation_hash !== receipt.request_receipt_mutation_hash
      || metadata.merkle_schema !== receipt.merkle_schema
      || metadata.merkle_root !== root || metadata.result_count !== evidence.length
      || !equal(metadata.evidence, evidence)
      || !equal(metadata.return_projection, receipt.return_projection)) {
    fail('EVENT_RECEIPT_BINDING_INVALID');
  }
  const hkValidFrom = iso(authority.housekeeperIdentity.valid_from, 'HOUSEKEEPER_IDENTITY_INVALID');
  if (event.signed_body.signer_agent_id !== 'housekeeper'
      || iso(event.signed_body.signer_valid_from, 'HOUSEKEEPER_IDENTITY_INVALID') !== hkValidFrom
      || event.signed_body.cert_fingerprint !== authority.housekeeperIdentity.cert_fingerprint
      || event.signer_certificate !== authority.housekeeperIdentity.certificate
      || sha256Hex(Buffer.from(string(event.signer_certificate), 'utf8'))
        !== authority.housekeeperIdentity.cert_fingerprint) fail('HOUSEKEEPER_IDENTITY_INVALID');
  let contentHash;
  try { contentHash = eventPayloadCommitment(event).toString('hex'); }
  catch { fail('EVENT_RECEIPT_COMMITMENT_INVALID'); }
  const mutationHash = eventMutationHash(
    event.prev_mutation_hash, contentHash, event.nonce, Number(event.ts_signed),
  );
  if (event.content_hash !== contentHash || event.mutation_hash !== mutationHash
      || event.signed_body.prev_mutation_hash !== event.prev_mutation_hash
      || Number(event.signed_body.ts_signed) !== Number(event.ts_signed)) {
    fail('EVENT_RECEIPT_COMMITMENT_INVALID');
  }
  signature(event.signature_b64u, 'EVENT_RECEIPT_COMMITMENT_INVALID');
  if (authority.revocation.source_event_mutation_hash !== event.mutation_hash
      || Number(authority.revocation.evaluated_at_unix_seconds) !== Number(event.ts_signed)
      || authority.housekeeperRevocation.source_event_mutation_hash !== event.mutation_hash
      || Number(authority.housekeeperRevocation.evaluated_at_unix_seconds)
        !== Number(event.ts_signed)) fail('REVOCATION_EVENT_BINDING_INVALID');
  return { event, root };
}

function validateLegacyOccurrence(state, authority, occurrence, ordinal) {
  try {
    if (state.envelope.format.version !== 3 || occurrence.schema !== CURRENT_OBJECT_SCHEMAS.occurrence) fail('HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID');
    const group = state.results[ordinal], memory = group.get('memory_state').body;
    const provenance = group.get('provenance_chain').body, rows = provenance.rows;
    if (!Array.isArray(rows) || !rows.length) fail('PROVENANCE_CHAIN_INVALID');
    const byHash = new Map(), successors = new Map(), decoded = new Map(), certificates = new Map();
    let genesis = null;
    for (const row of rows) {
      if (!row || typeof row !== 'object' || Array.isArray(row)
          || row.memory_id !== memory.memory_id || !UUID.test(row.provenance_id)
          || byHash.has(row.mutation_hash)) fail('PROVENANCE_CHAIN_INVALID');
      const payload = retainedProvenanceMessage(row);
      const cert = decodeCertificate(row.signer_certificate).body;
      const fingerprint = sha256Hex(Buffer.from(row.signer_certificate));
      const epochMs = new Date(row.agent_valid_from).getTime();
      if (row.cert_fingerprint !== fingerprint || cert.agent_id !== row.agent_id
          || !Number.isSafeInteger(epochMs) || epochMs !== cert.valid_from * 1000
          || new Date(epochMs).toISOString() !== row.agent_valid_from
          || (row.identity_tier === 'T3' && row.signed_claims?.device_fp !== cert.device_fp)) fail('PROVENANCE_CERTIFICATE_INVALID');
      const selfHousekeeper = cert.issuer === 'housekeeper' && row.signer_certificate === authority.housekeeperIdentity.certificate;
      if (!selfHousekeeper && !['aimos-master', state.envelope.expected_master_fingerprint].includes(cert.issuer)) fail('PROVENANCE_CERTIFICATE_INVALID');
      if (!certificates.has(fingerprint)) {
        const verification = verifyCertificate({ certificate: row.signer_certificate,
          authorityPublicKey: selfHousekeeper ? authority.housekeeperIdentity.public_key_b64u : authority.trust.master_public_key_b64u,
          expectedAgentId: row.agent_id, expectedSubjectPublicKey: cert.pubkey, atUnixSeconds: row.ts_signed });
        if (!verification.valid) fail('PROVENANCE_CERTIFICATE_INVALID');
        certificates.set(fingerprint, cert);
      }
      if (row.ts_signed < cert.valid_from || row.ts_signed > cert.valid_until) fail('PROVENANCE_CERTIFICATE_INVALID');
      if (!Array.isArray(row.revocation_events) || !Object.hasOwn(row, 'identity_revoked_at')) fail('PROVENANCE_REVOCATION_INVALID');
      if (row.identity_revoked_at !== null) {
        const revokedMs = new Date(row.identity_revoked_at).getTime();
        if (!Number.isSafeInteger(revokedMs) || new Date(revokedMs).toISOString() !== row.identity_revoked_at
            || revokedMs <= row.ts_signed * 1000) fail('PROVENANCE_REVOCATION_INVALID');
      }
      for (const revocation of row.revocation_events) {
        if (!revocation || typeof revocation !== 'object' || Array.isArray(revocation)
            || ['signed_body', 'agent_id', 'agent_valid_from', 'master_fingerprint', 'target_cert_hash', 'prior_identity_hash', 'content_hash', 'mutation_hash', 'ts_signed', 'nonce', 'signature_b64u'].some(key => !Object.hasOwn(revocation, key))
            || !revocation.signed_body || typeof revocation.signed_body !== 'object' || Array.isArray(revocation.signed_body)) fail('PROVENANCE_REVOCATION_INVALID');
        const body = revocation.signed_body;
        const prior = canonicalSha({ agent_id: row.agent_id, agent_valid_from: iso(row.agent_valid_from, 'PROVENANCE_REVOCATION_INVALID'), target_cert_hash: fingerprint });
        const content = canonicalSha(body);
        if (body?.schema !== 'hom.aimos.agent-revocation/v1' || body.event_type !== 'REVOKE_AGENT_IDENTITY'
            || body.agent_id !== row.agent_id || iso(body.agent_valid_from, 'PROVENANCE_REVOCATION_INVALID') !== iso(row.agent_valid_from, 'PROVENANCE_REVOCATION_INVALID')
            || revocation.agent_id !== row.agent_id || iso(revocation.agent_valid_from, 'PROVENANCE_REVOCATION_INVALID') !== iso(row.agent_valid_from, 'PROVENANCE_REVOCATION_INVALID')
            || body.target_cert_hash !== fingerprint || revocation.target_cert_hash !== fingerprint
            || body.prior_identity_hash !== prior || revocation.prior_identity_hash !== prior
            || body.master_fingerprint !== state.envelope.expected_master_fingerprint || revocation.master_fingerprint !== body.master_fingerprint
            || content !== revocation.content_hash || !Number.isSafeInteger(revocation.ts_signed)
            || Math.floor(new Date(body.revoked_at).getTime() / 1000) !== revocation.ts_signed
            || revocation.mutation_hash !== sha256Hex(Buffer.concat([Buffer.from('aimos-agent-revocation-v1\0'), exactHashBytes(prior), exactHashBytes(content), exactBase64url(revocation.signature_b64u)]))
            || !verifyPayloadSignature({ publicKey: authority.trust.master_public_key_b64u, body, nonce: revocation.nonce, signedTs: revocation.ts_signed, signature: revocation.signature_b64u })
            || revocation.ts_signed <= row.ts_signed) fail('PROVENANCE_REVOCATION_INVALID');
      }
      if (!verifyEd25519(cert.pubkey, payload.message, row.signature_b64u)) fail('PROVENANCE_SIGNATURE_INVALID');
      if (payload.body.memory_id != null && payload.body.memory_id !== memory.memory_id) fail('PROVENANCE_SAVE_BINDING_INVALID');
      if (payload.body.company_id != null && payload.body.company_id !== state.envelope.company_id) fail('PROVENANCE_SAVE_BINDING_INVALID');
      byHash.set(row.mutation_hash, row); decoded.set(row.mutation_hash, payload.body);
      if (row.prev_mutation_hash === null) { if (genesis) fail('PROVENANCE_CHAIN_INVALID'); genesis = row; }
      else { if (successors.has(row.prev_mutation_hash)) fail('PROVENANCE_CHAIN_INVALID'); successors.set(row.prev_mutation_hash, row); }
    }
    const visited = new Set(); let cursor = genesis;
    while (cursor) { if (visited.has(cursor.mutation_hash)) fail('PROVENANCE_CHAIN_INVALID'); visited.add(cursor.mutation_hash); cursor = successors.get(cursor.mutation_hash); }
    if (visited.size !== rows.length) fail('PROVENANCE_CHAIN_INVALID');
    const selected = byHash.get(occurrence.native_body?.mutation_hash);
    if (!selected || !equal(selected, occurrence.native_body) || occurrence.signature_b64u !== selected.signature_b64u
        || occurrence.signer_certificate !== selected.signer_certificate
        || legacyOccurrenceReference(selected, state.envelope.company_id) !== occurrence.occurrence_ref) fail('PROVENANCE_SAVE_BINDING_INVALID');
    const binding = byHash.get(provenance.binding_mutation_hash), save = byHash.get(provenance.save_mutation_hash);
    const bindBody = decoded.get(provenance.binding_mutation_hash);
    if (!binding || binding.event_type !== 'BIND' || binding.agent_id !== 'housekeeper'
        || !bindBody || ![3, 4].includes(bindBody.binding_schema_version)
        || bindBody.memory_id !== memory.memory_id || bindBody.company_id !== state.envelope.company_id
        || bindBody.key !== memory.key || bindBody.live_content_hash !== memory.live_content_hash
        || binding.live_content_hash !== memory.live_content_hash) fail('PROVENANCE_SAVE_BINDING_INVALID');
    const liveFields = Object.fromEntries(['key', 'value', 'scope', 'memory_type', 'clearance_level', 'data_class', 'source']
      .map(key => [key, memory[key] == null ? '' : String(memory[key])]));
    if (['key', 'value', 'scope', 'memory_type', 'data_class', 'source'].some(key => memory[key] !== null && typeof memory[key] !== 'string')
        || !Number.isSafeInteger(memory.clearance_level) || memory.clearance_level < 0 || memory.clearance_level > 12) fail('PROVENANCE_SAVE_BINDING_INVALID');
    if (canonicalSha(liveFields) !== memory.live_content_hash) fail('PROVENANCE_SAVE_BINDING_INVALID');
    if (save) {
      if (save.event_type !== 'SAVE' || bindBody.request_mutation_hash !== save.mutation_hash
          || bindBody.request_content_hash !== save.content_hash || bindBody.request_signature_hash !== sha256Hex(exactBase64url(save.signature_b64u))
          || bindBody.request_signer_agent_id !== save.agent_id
          || iso(bindBody.request_signer_valid_from, 'PROVENANCE_SAVE_BINDING_INVALID') !== iso(save.agent_valid_from, 'PROVENANCE_SAVE_BINDING_INVALID')
          || binding.prev_mutation_hash !== save.mutation_hash) fail('PROVENANCE_SAVE_BINDING_INVALID');
    } else if (selected.event_type === 'SAVE') fail('PROVENANCE_SAVE_BINDING_INVALID');
    return rows.length + certificates.size + rows.reduce((count, row) => count + row.revocation_events.length, 0);
  } catch (error) {
    if (error instanceof MutMemRecallVerificationError) throw error;
    fail(PROVENANCE_FAILURE_CODES.includes(error?.reason) ? error.reason : 'PROVENANCE_CONTEXT_INVALID');
  }
}

function validateCryptography(state, authority, occurrences, event, expectedMasterFingerprint) {
  const expected = string(expectedMasterFingerprint).toLowerCase();
  if (!HEX32.test(expected) || expected !== state.envelope.expected_master_fingerprint) {
    fail('EXPECTED_TRUST_ANCHOR_REQUIRED');
  }
  const masterKey = authority.trust.master_public_key_b64u;
  const actorCert = verifyCertificate({
    certificate: authority.identity.certificate,
    authorityPublicKey: masterKey,
    expectedAgentId: authority.identity.agent_id,
    expectedSubjectPublicKey: authority.identity.public_key_b64u,
    atUnixSeconds: authority.requestTs,
  });
  if (!actorCert.valid
      || actorCert.body.valid_from !== Math.floor(new Date(authority.identity.valid_from).getTime() / 1000)
      || actorCert.body.valid_until !== Math.floor(new Date(authority.identity.valid_until).getTime() / 1000)
      || !['aimos-master', expected].includes(actorCert.body.issuer)) {
    fail('ACTOR_CERTIFICATE_SIGNATURE_INVALID');
  }
  const hkCert = verifyCertificate({
    certificate: authority.housekeeperIdentity.certificate,
    authorityPublicKey: masterKey,
    expectedAgentId: 'housekeeper',
    expectedSubjectPublicKey: authority.housekeeperIdentity.public_key_b64u,
    atUnixSeconds: Number(event.ts_signed),
  });
  if (!hkCert.valid
      || hkCert.body.valid_from
        !== Math.floor(new Date(authority.housekeeperIdentity.valid_from).getTime() / 1000)
      || hkCert.body.valid_until
        !== Math.floor(new Date(authority.housekeeperIdentity.valid_until).getTime() / 1000)
      || !['aimos-master', expected].includes(hkCert.body.issuer)) {
    fail('HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID');
  }
  let signatureCount = 2;
  if (authority.grant.authority_kind === 'master_signed_recall_grant') {
    if (!verifyPayloadSignature({
      publicKey: masterKey,
      body: authority.grant.signed_body,
      nonce: authority.grant.nonce,
      signedTs: Number(authority.grant.ts_signed),
      signature: authority.grant.signature_b64u,
    })) fail('MASTER_GRANT_SIGNATURE_INVALID');
    signatureCount += 1;
  }
  if (!verifyRequestContextSignature({
    requestForm: authority.request.request_sig_form,
    claims: authority.requestReceipt.signed_claims,
    publicKey: authority.identity.public_key_b64u,
    body: authority.request.request_body,
    method: authority.request.signed_method,
    path: authority.request.signed_path,
    nonce: authority.request.nonce,
    signedTs: Number(authority.request.ts_signed),
    signature: authority.request.signature_b64u,
  })) fail('ACTOR_REQUEST_SIGNATURE_INVALID');
  signatureCount += 1;
  if (!verifyEventPayloadSignature(event, authority.housekeeperIdentity.public_key_b64u)) {
    fail('HOUSEKEEPER_EVENT_SIGNATURE_INVALID');
  }
  signatureCount += 1;
  for (const [ordinal, occurrence] of occurrences.entries()) {
    if (occurrence.occurrence_form === 'legacy_v1' && occurrence.schema === CURRENT_OBJECT_SCHEMAS.occurrence) {
      signatureCount += validateLegacyOccurrence(state, authority, occurrence, ordinal);
      continue;
    }
    if (occurrence.occurrence_form !== 'v3'
        || occurrence.signer_certificate !== authority.housekeeperIdentity.certificate
        || !verifyOccurrenceSignatureV3(
          occurrence.native_body,
          occurrence.signature_b64u,
          authority.housekeeperIdentity.public_key_b64u,
        )) fail('HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID');
    signatureCount += 1;
  }
  return signatureCount;
}

// These are authenticated disclosure labels, not a proof of the origin DAG or
// an action authorization. The profile is public data checked against its
// versioned protocol commitment, never a trust root supplied by the artifact.
function validateOriginDisclosure(state, receipt, evidence, event) {
  if (state.envelope.format.version === 2) {
    if (['origin_family_profile', 'disclosure_labels', 'disclosure_label_root_sha256']
      .some((key) => Object.hasOwn(receipt, key))
      || evidence.some((entry) => Object.hasOwn(entry, 'origin_disclosure'))) fail('OBJECT_SCHEMA_INVALID');
    return;
  }
  const profile = receipt.origin_family_profile;
  try {
    const bytes = canonicalBytes(profile);
    if (profile?.schema !== 'hom.aimos.origin-family-profile/v1'
        || sha256Hex(Buffer.concat([Buffer.from('hom.aimos.origin-family-profile/v1\0'), u32(bytes.length), bytes])) !== ORIGIN_PROFILE_HASH) {
      fail('ORIGIN_FAMILY_PROFILE_INVALID');
    }
  } catch { fail('ORIGIN_FAMILY_PROFILE_INVALID'); }
  const families = new Map(profile.families.map((entry) => [entry.id, entry]));
  const keys = ['schema', 'memory_id', 'live_content_hash', 'family_profile_sha256',
    'family_ids', 'family_set_root_sha256', 'origin_binding_sha256s', 'origin_ledger_hashes',
    'origin_event_ids', 'origin_event_mutation_sha256s', 'confidentiality', 'integrity',
    'effective_action_class', 'legacy_unbound', 'unclassified', 'disclosure_label_sha256'].sort();
  const labels = [];
  for (let ordinal = 0; ordinal < evidence.length; ordinal += 1) {
    try {
      const label = evidence[ordinal].origin_disclosure;
      const memory = state.results[ordinal].get('memory_state').body;
      if (!label || !equal(Object.keys(label).sort(), keys)
          || label.schema !== 'hom.aimos.native-recall-origin-disclosure/v1'
          || label.memory_id !== memory.memory_id || label.live_content_hash !== memory.live_content_hash
          || label.family_profile_sha256 !== ORIGIN_PROFILE_HASH
          || !Array.isArray(label.family_ids) || !label.family_ids.length
          || label.family_ids.length > profile.maximum_family_count
          || !profile.confidentiality_order.includes(label.confidentiality)
          || !profile.confidentiality_order.includes(memory.data_class)
          || profile.confidentiality_order.indexOf(label.confidentiality) < profile.confidentiality_order.indexOf(memory.data_class)
          || !profile.integrity_order.includes(label.integrity)
          || !profile.action_class_order.includes(label.effective_action_class)
          || typeof label.legacy_unbound !== 'boolean' || label.unclassified !== label.legacy_unbound) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      const familySet = new Set(label.family_ids);
      for (let i = 0; i < label.family_ids.length; i += 1) {
        const id = label.family_ids[i], entry = families.get(id);
        if (!entry || (i && label.family_ids[i - 1] >= id)
            || (entry.parent_id !== null && !familySet.has(entry.parent_id))) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      }
      if (label.family_set_root_sha256 !== recallMerkleRoot(label.family_ids.map((family_id, i) => ({ ordinal: i, family_id }))).toString('hex')) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      for (const key of ['origin_binding_sha256s', 'origin_ledger_hashes', 'origin_event_ids', 'origin_event_mutation_sha256s']) {
        const refs = label[key], pattern = key === 'origin_event_ids' ? UUID : HEX32;
        if (!Array.isArray(refs) || (label.legacy_unbound ? refs.length !== 0 : refs.length === 0)
            || refs.some((ref, i) => typeof ref !== 'string' || ref !== ref.toLowerCase()
              || !pattern.test(ref) || (i > 0 && refs[i - 1] >= ref))) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      }
      if (label.legacy_unbound && (!equal(label.family_ids, ['unknown_protected'])
          || label.confidentiality !== 'restricted' || label.integrity !== 'untrusted'
          || label.effective_action_class !== 'none')) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      const { disclosure_label_sha256: commitment, ...body } = label;
      const bytes = canonicalBytes(body);
      if (commitment !== sha256Hex(Buffer.concat([Buffer.from('hom.aimos.native-recall-origin-disclosure/v1\0'), u32(bytes.length), bytes]))) fail('ORIGIN_DISCLOSURE_LABEL_INVALID');
      labels.push(label);
    } catch { fail('ORIGIN_DISCLOSURE_LABEL_INVALID'); }
  }
  const root = recallMerkleRoot(labels.map((label, ordinal) => ({ ordinal,
    memory_id: label.memory_id, live_content_hash: label.live_content_hash,
    disclosure_label_sha256: label.disclosure_label_sha256,
  }))).toString('hex');
  if (!Array.isArray(receipt.disclosure_labels) || root !== receipt.disclosure_label_root_sha256
      || !equal(labels, receipt.disclosure_labels)) fail('ORIGIN_DISCLOSURE_ROOT_INVALID');
  let metadata;
  try { metadata = eventPayloadBody(event)?.metadata; }
  catch { fail('EVENT_RECEIPT_COMMITMENT_INVALID'); }
  if (metadata?.disclosure_label_root_sha256 !== root || !Array.isArray(metadata.disclosure_labels)
      || !equal(labels, metadata.disclosure_labels)) fail('ORIGIN_DISCLOSURE_EVENT_BINDING_INVALID');
}

export function verifyRecallEnvelope(envelope, {
  expectedMasterFingerprint = null,
  verifyCryptography = true,
} = {}) {
  const state = reconstructEnvelope(envelope);
  requireSchemas(state);
  const authority = validateAuthority(state);
  const decisions = validateDecisions(state, authority.nativeReceipt);
  const results = validateResults(state, decisions, authority.nativeReceipt);
  validateOriginDisclosure(state, authority.nativeReceipt, results.evidence, authority.nativeReceipt.event_receipt);
  const terminal = validateEvent(authority, decisions, results.evidence);
  const signatureCount = verifyCryptography
    ? validateCryptography(
      state,
      authority,
      results.occurrenceObjects,
      terminal.event,
      expectedMasterFingerprint,
    )
    : 0;
  return Object.freeze({
    schema: `hom.aimos.mutmem-independent-recall-result/v${state.envelope.format.version}`,
    valid: true,
    bundle_sha256: state.bundleHash,
    object_root_sha256: state.objectRoot,
    result_count: state.envelope.result_count,
    structural_predicate_count: STRUCTURAL_FAILURE_CODES.length
      + (state.envelope.format.version === 3 ? ORIGIN_DISCLOSURE_FAILURE_CODES.length : 0),
    cryptographic_signatures_verified: Boolean(verifyCryptography),
    external_trust_established: Boolean(verifyCryptography),
    verified_signature_count: signatureCount,
    ...(state.envelope.format.version === 3 ? {
      origin_family_disclosure_verified: Boolean(verifyCryptography),
      origin_ancestry_verified: false,
      independent_corroboration_verified: false,
      action_authority_granted: false,
    } : {}),
  });
}

export const recallByteParity = Object.freeze({
  recallAuthorizationMutationHash,
  requestReceiptMutationHash,
  eventMutationHash,
});

export default { verifyRecallEnvelope };
