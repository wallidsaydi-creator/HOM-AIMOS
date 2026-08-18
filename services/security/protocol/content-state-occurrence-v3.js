/**
 * content-state-occurrence-v3.js — canonical successor occurrence protocol
 *
 * R7 activates the R1/R3 byte contract for exact-state save reassertions.
 * The protocol separates immutable content identity from the ordered events
 * that reassert that content. It owns no database or policy authority.
 *
 * Sources: RFC 6962 domain separation, RFC 8032 Ed25519, and the prefix-free
 * encoding discipline described by Boneh/Shoup and Cryptography Engineering.
 */

import {
  createHash,
  createPublicKey,
  verify as verifyEd25519,
} from 'node:crypto';

export const CONTENT_STATE_OCCURRENCE_V3 = Object.freeze({
  schema: 'hom.aimos.memory-occurrence/v3',
  legacy_reference_schema: 'hom.aimos.memory-occurrence-ref/legacy-v1',
  signature_schema: 'hom.aimos.memory-occurrence-signature/v3',
  legacy_domain: 'hom.aimos.memory-occurrence-ref/legacy-v1\0',
  occurrence_domain: 'hom.aimos.memory-occurrence/v3\0',
  signature_domain: 'hom.aimos.memory-occurrence-signature/v3\0',
  tlv: 'u16be_tag_u32be_length_value',
  signature_algorithm: 'Ed25519',
});

const LEGACY_DOMAIN = Buffer.from(CONTENT_STATE_OCCURRENCE_V3.legacy_domain, 'utf8');
const OCCURRENCE_DOMAIN = Buffer.from(CONTENT_STATE_OCCURRENCE_V3.occurrence_domain, 'utf8');
const SIGNATURE_DOMAIN = Buffer.from(CONTENT_STATE_OCCURRENCE_V3.signature_domain, 'utf8');
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function invalid() {
  throw new Error('content_state_occurrence_v3_encoding_invalid');
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function frame(tag, value) {
  const bytes = Buffer.from(value);
  const header = Buffer.alloc(6);
  header.writeUInt16BE(tag, 0);
  header.writeUInt32BE(bytes.length, 2);
  return Buffer.concat([header, bytes]);
}

function text(value, { empty = false, uppercase = false } = {}) {
  const normalized = String(value ?? '');
  if ((!empty && !normalized) || (uppercase && normalized !== normalized.toUpperCase())) invalid();
  return Buffer.from(normalized, 'utf8');
}

function uuid(value, { empty = false } = {}) {
  const normalized = String(value || '').toLowerCase();
  if (empty && !normalized) return Buffer.alloc(0);
  if (!UUID.test(normalized)) invalid();
  return Buffer.from(normalized.replaceAll('-', ''), 'hex');
}

function hash32(value, { empty = false } = {}) {
  const normalized = String(value || '').toLowerCase();
  if (empty && !normalized) return Buffer.alloc(0);
  if (!HEX32.test(normalized)) invalid();
  return Buffer.from(normalized, 'hex');
}

function u8(value) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 255) invalid();
  return Buffer.from([normalized]);
}

function u16(value) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 0xffff) invalid();
  const output = Buffer.alloc(2);
  output.writeUInt16BE(normalized);
  return output;
}

function i64(value) {
  const output = Buffer.alloc(8);
  try { output.writeBigInt64BE(BigInt(value)); } catch { invalid(); }
  return output;
}

function u64(value) {
  let normalized;
  try { normalized = BigInt(value); } catch { invalid(); }
  if (normalized < 0n) invalid();
  const output = Buffer.alloc(8);
  try { output.writeBigUInt64BE(normalized); } catch { invalid(); }
  return output;
}

function present(flag, value, decode) {
  const normalized = Number(flag);
  if (normalized === 0 && String(value || '') === '') return [u8(0), Buffer.alloc(0)];
  if (normalized === 1) return [u8(1), decode(value)];
  invalid();
}

function normalizeNonce(value) {
  const normalized = String(value || '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) invalid();
  const bytes = Buffer.from(normalized, 'hex');
  if (bytes.length < 16 || bytes.length > 32) invalid();
  return bytes;
}

export function computeLegacyOccurrenceReference(record = {}) {
  const fields = [
    text(record.company_id),
    uuid(record.memory_id),
    uuid(record.provenance_id),
    hash32(record.mutation_hash_hex),
    text(record.agent_id),
    i64(record.signer_valid_from_unix_ms),
    hash32(record.cert_fingerprint_hex),
    text(record.event_type, { uppercase: true }),
    u16(record.sig_form_version),
  ];
  return sha256(Buffer.concat([
    LEGACY_DOMAIN,
    ...fields.map((value, index) => frame(index + 1, value)),
  ])).toString('hex');
}

function occurrenceFields(record = {}) {
  const [predecessorFlag, predecessor] = present(
    record.predecessor_present,
    record.predecessor_commitment_hex,
    (value) => hash32(value),
  );
  const [receiptFlag, receipt] = present(
    record.request_receipt_present,
    record.request_receipt_mutation_hash_hex,
    (value) => hash32(value),
  );
  const [authorizationFlag, authorization] = present(
    record.authorization_event_present,
    record.authorization_event_id,
    (value) => uuid(value),
  );
  const eventType = String(record.event_type || '');
  const method = String(record.signed_method || '');
  const signedPath = String(record.signed_path || '');
  if (Number(record.sig_form_version) !== 3
      || eventType !== eventType.toUpperCase()
      || String(record.identity_tier || '') !== String(record.identity_tier || '').toUpperCase()
      || method !== method.toUpperCase()) invalid();
  const internalEvent = eventType.startsWith('INTERNAL_');
  if ((method.length === 0 || signedPath.length === 0)
      && !(method.length === 0 && signedPath.length === 0 && internalEvent)) invalid();
  return [
    text(record.company_id),
    uuid(record.occurrence_event_id),
    uuid(record.memory_id),
    text(eventType, { uppercase: true }),
    hash32(record.live_content_hash_hex),
    predecessorFlag,
    predecessor,
    text(record.agent_id),
    i64(record.signer_valid_from_unix_ms),
    hash32(record.cert_fingerprint_hex),
    text(record.identity_tier, { uppercase: true }),
    u16(record.sig_form_version),
    normalizeNonce(record.nonce_hex),
    u64(record.ts_signed_unix_seconds),
    text(method, { empty: true, uppercase: true }),
    text(signedPath, { empty: true }),
    hash32(record.request_body_hash_hex),
    receiptFlag,
    receipt,
    authorizationFlag,
    authorization,
  ];
}

export function encodeOccurrenceCommitmentV3(record = {}) {
  return Buffer.concat([
    OCCURRENCE_DOMAIN,
    ...occurrenceFields(record).map((value, index) => frame(index + 1, value)),
  ]);
}

export function computeOccurrenceCommitmentV3(record = {}) {
  return sha256(encodeOccurrenceCommitmentV3(record)).toString('hex');
}

export function occurrenceSignatureMessageV3(commitmentHex) {
  return Buffer.concat([SIGNATURE_DOMAIN, hash32(commitmentHex)]);
}

export function verifyOccurrenceSignatureV3(record, signature, publicKeyBase64url) {
  try {
    const signatureBytes = Buffer.isBuffer(signature)
      ? Buffer.from(signature)
      : Buffer.from(String(signature || ''), 'base64url');
    if (signatureBytes.length !== 64) return false;
    const publicKey = createPublicKey({
      key: Buffer.from(String(publicKeyBase64url || ''), 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return verifyEd25519(
      null,
      occurrenceSignatureMessageV3(computeOccurrenceCommitmentV3(record)),
      publicKey,
      signatureBytes,
    );
  } catch {
    return false;
  }
}

export function canonicalOccurrenceBody(record, commitmentHex = computeOccurrenceCommitmentV3(record)) {
  if (!HEX32.test(String(commitmentHex || '').toLowerCase())) invalid();
  return Object.freeze({
    schema: CONTENT_STATE_OCCURRENCE_V3.schema,
    occurrence_commitment: String(commitmentHex).toLowerCase(),
    ...record,
  });
}
