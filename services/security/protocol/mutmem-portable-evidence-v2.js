// Authority-free MutMem V2 portable evidence envelope.
//
// This module owns only evidence-object framing, mandatory recall-disclosure
// membership, deterministic ordering, and artifact commitments. It does not
// verify signatures, select trust, read a database, call a model, mutate
// runtime state, or authorize an operation. Independent verification belongs
// to P2.
//
// Sources: RFC 6962 §2.1 ordered Merkle hashing; RFC 8032 Ed25519 message
// verification; Boneh/Shoup prefix-free encoding and domain-separation
// discipline; MutMem V1 §§5–7. Pure Ed25519 has no application context, so
// AIMOS protocol separation remains inside the signed/hashed message bytes.

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import { recallMerkleRoot } from './mutmem-protocol.js';

export const MUTMEM_PORTABLE_EVIDENCE_V2 = Object.freeze({
  schema: 'hom.aimos.mutmem-portable-evidence/v2',
  version: 2,
  profile: 'recall_disclosure',
  canonicalization: 'hom-aimos/canonical-json/v1',
  hash: 'sha256',
  signature: 'ed25519',
  trust_anchor_mode: 'external_expected_master_fingerprint_required',
  native_receipt_schema: 'hom-aimos/recall-merkle/v3-epistemic-and-security-closure',
  object_domain: Buffer.from('hom.aimos.mutmem-portable-object/v2\0', 'utf8'),
  bundle_domain: Buffer.from('hom.aimos.mutmem-portable-evidence/v2\0', 'utf8'),
  maximum_results: 200,
  maximum_object_body_bytes: 1024 * 1024,
});

export const MUTMEM_RECALL_SINGLETON_KINDS_V2 = Object.freeze([
  'trust_anchor',
  'actor_identity_epoch',
  'actor_revocation_state',
  'housekeeper_identity_epoch',
  'housekeeper_revocation_state',
  'effective_recall_grant',
  'request_envelope',
  'request_receipt',
  'content_state_projection',
  'epistemic_recall_decision',
  'final_security_closure',
  'return_projection',
  'native_recall_receipt',
]);

export const MUTMEM_RECALL_RESULT_KINDS_V2 = Object.freeze([
  'memory_state',
  'provenance_chain',
  'occurrence',
  'epistemic_projection',
  'receipt_evidence',
]);

const SINGLETON_ORDER = new Map(
  MUTMEM_RECALL_SINGLETON_KINDS_V2.map((kind, ordinal) => [kind, ordinal]),
);
const RESULT_ORDER = new Map(
  MUTMEM_RECALL_RESULT_KINDS_V2.map((kind, ordinal) => [kind, ordinal]),
);
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(code) {
  throw new Error(`mutmem_portable_evidence_v2:${code}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('u32_invalid');
  }
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function u64(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('u64_invalid');
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function framedUtf8(value, code) {
  const bytes = Buffer.from(String(value || ''), 'utf8');
  if (!bytes.length || bytes.length > 0xffffffff) fail(code);
  return Buffer.concat([u32(bytes.length), bytes]);
}

function exactKeys(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    fail(code);
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function validateJsonNumbers(value, depth = 0) {
  if (depth > 32) fail('object_body_depth_invalid');
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      fail('object_body_number_invalid');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) validateJsonNumbers(child, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) validateJsonNumbers(child, depth + 1);
  }
}

function immutableCanonicalBody(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('object_body_invalid');
  }
  validateJsonNumbers(value);
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  if (!bytes.length || bytes.length > MUTMEM_PORTABLE_EVIDENCE_V2.maximum_object_body_bytes) {
    fail('object_body_size_invalid');
  }
  return Object.freeze({ body: deepFreeze(JSON.parse(bytes.toString('utf8'))), bytes });
}

export function mutMemPortableObjectHashV2({ kind, schema, body } = {}) {
  const normalizedKind = String(kind || '');
  const normalizedSchema = String(schema || '');
  if (!SINGLETON_ORDER.has(normalizedKind) && !RESULT_ORDER.has(normalizedKind)) {
    fail('object_kind_invalid');
  }
  if (!normalizedSchema || normalizedSchema.length > 200) fail('object_schema_invalid');
  const canonical = immutableCanonicalBody(body);
  if (canonical.body.schema !== normalizedSchema) fail('object_body_schema_mismatch');
  return sha256(Buffer.concat([
    MUTMEM_PORTABLE_EVIDENCE_V2.object_domain,
    framedUtf8(normalizedKind, 'object_kind_invalid'),
    framedUtf8(normalizedSchema, 'object_schema_invalid'),
    u32(canonical.bytes.length),
    canonical.bytes,
  ]));
}

export function createMutMemPortableObjectV2({
  kind,
  schema,
  subjectId = null,
  resultOrdinal = null,
  body,
} = {}) {
  const normalizedKind = String(kind || '');
  const singleton = SINGLETON_ORDER.has(normalizedKind);
  const result = RESULT_ORDER.has(normalizedKind);
  if (!singleton && !result) fail('object_kind_invalid');
  if (singleton && (subjectId != null || resultOrdinal != null)) {
    fail('singleton_scope_invalid');
  }
  const normalizedSubject = subjectId == null ? null : String(subjectId).toLowerCase();
  if (result && (!UUID.test(normalizedSubject || '')
      || !Number.isSafeInteger(resultOrdinal) || resultOrdinal < 0
      || resultOrdinal >= MUTMEM_PORTABLE_EVIDENCE_V2.maximum_results)) {
    fail('result_scope_invalid');
  }
  const canonical = immutableCanonicalBody(body);
  const bodySha256 = mutMemPortableObjectHashV2({
    kind: normalizedKind,
    schema,
    body: canonical.body,
  }).toString('hex');
  return Object.freeze({
    kind: normalizedKind,
    schema: String(schema),
    subject_id: normalizedSubject,
    result_ordinal: resultOrdinal,
    body_sha256: bodySha256,
    body: canonical.body,
  });
}

function validatePortableObject(object) {
  exactKeys(
    object,
    ['kind', 'schema', 'subject_id', 'result_ordinal', 'body_sha256', 'body'],
    'object_shape_invalid',
  );
  const reconstructed = createMutMemPortableObjectV2({
    kind: object.kind,
    schema: object.schema,
    subjectId: object.subject_id,
    resultOrdinal: object.result_ordinal,
    body: object.body,
  });
  if (object.body_sha256 !== reconstructed.body_sha256) fail('object_hash_mismatch');
  return reconstructed;
}

function orderObjects(objects, resultCount) {
  if (!Array.isArray(objects)) fail('object_set_invalid');
  const normalized = objects.map(validatePortableObject);
  const singletonByKind = new Map();
  const resultByOrdinal = Array.from({ length: resultCount }, () => new Map());
  const resultSubjectByOrdinal = new Map();
  for (const object of normalized) {
    if (SINGLETON_ORDER.has(object.kind)) {
      if (singletonByKind.has(object.kind)) fail('singleton_duplicate');
      singletonByKind.set(object.kind, object);
      continue;
    }
    if (object.result_ordinal >= resultCount) fail('result_ordinal_out_of_range');
    const group = resultByOrdinal[object.result_ordinal];
    if (group.has(object.kind)) fail('result_kind_duplicate');
    const priorSubject = resultSubjectByOrdinal.get(object.result_ordinal);
    if (priorSubject != null && priorSubject !== object.subject_id) fail('result_subject_mismatch');
    resultSubjectByOrdinal.set(object.result_ordinal, object.subject_id);
    group.set(object.kind, object);
  }
  for (const kind of MUTMEM_RECALL_SINGLETON_KINDS_V2) {
    if (!singletonByKind.has(kind)) fail(`singleton_missing:${kind}`);
  }
  for (let ordinal = 0; ordinal < resultCount; ordinal += 1) {
    const group = resultByOrdinal[ordinal];
    for (const kind of MUTMEM_RECALL_RESULT_KINDS_V2) {
      if (!group.has(kind)) fail(`result_kind_missing:${ordinal}:${kind}`);
    }
  }
  const expectedCount = MUTMEM_RECALL_SINGLETON_KINDS_V2.length
    + resultCount * MUTMEM_RECALL_RESULT_KINDS_V2.length;
  if (normalized.length !== expectedCount) fail('object_count_invalid');
  return Object.freeze([
    ...MUTMEM_RECALL_SINGLETON_KINDS_V2.map((kind) => singletonByKind.get(kind)),
    ...resultByOrdinal.flatMap((group) => (
      MUTMEM_RECALL_RESULT_KINDS_V2.map((kind) => group.get(kind))
    )),
  ].map((object, ordinal) => Object.freeze({ ordinal, ...object })));
}

function objectRoot(objects) {
  return recallMerkleRoot(objects.map((object) => Object.freeze({
    ordinal: object.ordinal,
    kind: object.kind,
    schema: object.schema,
    subject_id: object.subject_id,
    result_ordinal: object.result_ordinal,
    body_sha256: object.body_sha256,
  })));
}

export function mutMemPortableEnvelopeHashV2({
  bundleId,
  companyId,
  expectedMasterFingerprint,
  resultCount,
  objectRootSha256,
} = {}) {
  const fingerprint = String(expectedMasterFingerprint || '').toLowerCase();
  const root = String(objectRootSha256 || '').toLowerCase();
  if (!HEX32.test(fingerprint)) fail('expected_master_fingerprint_invalid');
  if (!HEX32.test(root)) fail('object_root_invalid');
  if (!Number.isSafeInteger(resultCount) || resultCount < 0
      || resultCount > MUTMEM_PORTABLE_EVIDENCE_V2.maximum_results) {
    fail('result_count_invalid');
  }
  return sha256(Buffer.concat([
    MUTMEM_PORTABLE_EVIDENCE_V2.bundle_domain,
    framedUtf8(bundleId, 'bundle_id_invalid'),
    framedUtf8(companyId, 'company_id_invalid'),
    Buffer.from(fingerprint, 'hex'),
    u64(resultCount),
    Buffer.from(root, 'hex'),
  ]));
}

export function createMutMemPortableEvidenceEnvelopeV2({
  bundleId,
  companyId,
  expectedMasterFingerprint,
  resultCount,
  objects,
} = {}) {
  const id = String(bundleId || '');
  const company = String(companyId || '');
  const fingerprint = String(expectedMasterFingerprint || '').toLowerCase();
  if (!id || id.length > 200) fail('bundle_id_invalid');
  if (!company || company.length > 200) fail('company_id_invalid');
  if (!HEX32.test(fingerprint)) fail('expected_master_fingerprint_invalid');
  if (!Number.isSafeInteger(resultCount) || resultCount < 0
      || resultCount > MUTMEM_PORTABLE_EVIDENCE_V2.maximum_results) {
    fail('result_count_invalid');
  }
  const orderedObjects = orderObjects(objects, resultCount);
  const objectRootSha256 = objectRoot(orderedObjects).toString('hex');
  const body = Object.freeze({
    format: Object.freeze({
      schema: MUTMEM_PORTABLE_EVIDENCE_V2.schema,
      version: MUTMEM_PORTABLE_EVIDENCE_V2.version,
      profile: MUTMEM_PORTABLE_EVIDENCE_V2.profile,
      canonicalization: MUTMEM_PORTABLE_EVIDENCE_V2.canonicalization,
      hash: MUTMEM_PORTABLE_EVIDENCE_V2.hash,
      signature: MUTMEM_PORTABLE_EVIDENCE_V2.signature,
      trust_anchor_mode: MUTMEM_PORTABLE_EVIDENCE_V2.trust_anchor_mode,
      native_receipt_schema: MUTMEM_PORTABLE_EVIDENCE_V2.native_receipt_schema,
    }),
    bundle_id: id,
    company_id: company,
    expected_master_fingerprint: fingerprint,
    result_count: resultCount,
    object_count: orderedObjects.length,
    object_root_sha256: objectRootSha256,
    objects: orderedObjects,
  });
  return Object.freeze({
    ...body,
    bundle_sha256: mutMemPortableEnvelopeHashV2({
      bundleId: id,
      companyId: company,
      expectedMasterFingerprint: fingerprint,
      resultCount,
      objectRootSha256,
    }).toString('hex'),
  });
}

export default {
  MUTMEM_PORTABLE_EVIDENCE_V2,
  MUTMEM_RECALL_SINGLETON_KINDS_V2,
  MUTMEM_RECALL_RESULT_KINDS_V2,
  mutMemPortableObjectHashV2,
  createMutMemPortableObjectV2,
  mutMemPortableEnvelopeHashV2,
  createMutMemPortableEvidenceEnvelopeV2,
};
