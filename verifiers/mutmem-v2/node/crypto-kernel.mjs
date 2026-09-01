// Independent MutMem V2 byte and cryptographic kernel.
//
// This verifier leaf imports only Node.js standard-library cryptography. It has
// no HOM-AIMOS runtime, database, filesystem, network, signer, route, policy, or
// mutable configuration authority.
//
// Protocol authorities: MutMem V1 Sections 5-7; RFC 6962 Section 2.1;
// RFC 8032; RFC 8785; Boneh/Shoup domain separation; Cryptography
// Engineering's Horton principle and unique-parsing requirement.

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';

export const KERNEL_LIMITS = Object.freeze({
  maximum_depth: 32,
  maximum_array_items: 1_000_000,
  maximum_object_keys: 1_000_000,
  maximum_canonical_bytes: 64 * 1024 * 1024,
});

const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OCCURRENCE_DOMAIN = Buffer.from('hom.aimos.memory-occurrence/v3\0', 'utf8');
const OCCURRENCE_SIGNATURE_DOMAIN = Buffer.from(
  'hom.aimos.memory-occurrence-signature/v3\0',
  'utf8',
);

export class MutMemKernelError extends Error {
  constructor(reason) {
    super(`mutmem_v2_kernel:${reason}`);
    this.name = 'MutMemKernelError';
    this.reason = reason;
  }
}

function fail(reason) {
  throw new MutMemKernelError(reason);
}

export function canonicalJson(value, depth = 0) {
  if (depth > KERNEL_LIMITS.maximum_depth) fail('CANONICAL_DEPTH_INVALID');
  if (value === null) return 'null';
  if (value === undefined) fail('CANONICAL_UNDEFINED');
  const kind = typeof value;
  if (kind === 'boolean') return value ? 'true' : 'false';
  if (kind === 'number') {
    if (!Number.isFinite(value)) fail('CANONICAL_NUMBER_INVALID');
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      fail('CANONICAL_NUMBER_INVALID');
    }
    return JSON.stringify(value);
  }
  if (kind === 'string') return JSON.stringify(value);
  if (kind === 'bigint') fail('CANONICAL_BIGINT_INVALID');
  if (Array.isArray(value)) {
    if (value.length > KERNEL_LIMITS.maximum_array_items) fail('CANONICAL_ARRAY_TOO_LARGE');
    return `[${value.map((entry) => canonicalJson(entry, depth + 1)).join(',')}]`;
  }
  if (kind === 'object') {
    const keys = Object.keys(value).sort();
    if (keys.length > KERNEL_LIMITS.maximum_object_keys) fail('CANONICAL_OBJECT_TOO_LARGE');
    return `{${keys.map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`
    )).join(',')}}`;
  }
  fail('CANONICAL_TYPE_INVALID');
}

export function canonicalBytes(value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  if (bytes.length > KERNEL_LIMITS.maximum_canonical_bytes) fail('CANONICAL_BYTES_TOO_LARGE');
  return bytes;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest();
}

export function sha256Hex(value) {
  return sha256(value).toString('hex');
}

export function exactBase64url(value, reason = 'BASE64URL_INVALID') {
  if (typeof value !== 'string' || !value || !/^[A-Za-z0-9_-]+$/.test(value)) fail(reason);
  const bytes = Buffer.from(value, 'base64url');
  if (!bytes.length || bytes.toString('base64url') !== value) fail(reason);
  return bytes;
}

export function exactHashBytes(value, reason = 'HASH_INVALID') {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) fail(reason);
  return Buffer.from(normalized, 'hex');
}

export function uuidBytes(value, reason = 'UUID_INVALID') {
  const normalized = String(value || '').toLowerCase();
  if (!UUID.test(normalized)) fail(reason);
  return Buffer.from(normalized.replaceAll('-', ''), 'hex');
}

export function u16(value, reason = 'U16_INVALID') {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) fail(reason);
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

export function u32(value, reason = 'U32_INVALID') {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail(reason);
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

export function i64(value, reason = 'I64_INVALID') {
  if (!Number.isSafeInteger(value)) fail(reason);
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64BE(BigInt(value));
  return bytes;
}

export function u64(value, reason = 'U64_INVALID') {
  if (!Number.isSafeInteger(value) || value < 0) fail(reason);
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

export function framedUtf8(value, reason = 'FRAME_INVALID') {
  const bytes = Buffer.from(String(value ?? ''), 'utf8');
  if (!bytes.length || bytes.length > 0xffffffff) fail(reason);
  return Buffer.concat([u32(bytes.length, reason), bytes]);
}

export function recallMerkleRoot(entries = []) {
  if (!Array.isArray(entries)) fail('MERKLE_INPUT_INVALID');
  const peaks = [];
  for (const entry of entries) {
    let node = sha256(Buffer.concat([Buffer.from([0x00]), canonicalBytes(entry)]));
    let height = 0;
    while (peaks.length && peaks.at(-1).height === height) {
      const left = peaks.pop().node;
      node = sha256(Buffer.concat([Buffer.from([0x01]), left, node]));
      height += 1;
    }
    peaks.push({ height, node });
  }
  if (!peaks.length) return sha256(Buffer.alloc(0));
  let result = peaks.at(-1).node;
  for (let index = peaks.length - 2; index >= 0; index -= 1) {
    result = sha256(Buffer.concat([Buffer.from([0x01]), peaks[index].node, result]));
  }
  return result;
}

export function verifyEd25519(publicKeyBase64url, message, signatureBase64url) {
  try {
    const publicKey = createPublicKey({
      key: exactBase64url(publicKeyBase64url, 'PUBLIC_KEY_INVALID'),
      format: 'der',
      type: 'spki',
    });
    const signature = exactBase64url(signatureBase64url, 'SIGNATURE_INVALID');
    if (signature.length !== 64) return false;
    return verifySignature(null, Buffer.from(message), publicKey, signature);
  } catch {
    return false;
  }
}

export function payloadMessage(body, nonce, signedTs) {
  if (typeof nonce !== 'string' || !nonce || !Number.isSafeInteger(signedTs)) {
    fail('PAYLOAD_CONTEXT_INVALID');
  }
  return Buffer.from(`${canonicalJson(body)}\n${nonce}\n${signedTs}`, 'utf8');
}

export function requestContextMessage(body, method, path, nonce, signedTs) {
  if (typeof nonce !== 'string' || !nonce || !Number.isSafeInteger(signedTs)) {
    fail('REQUEST_CONTEXT_INVALID');
  }
  const normalizedMethod = String(method || '').toUpperCase();
  const normalizedPath = String(path || '').split('?')[0];
  if (!normalizedMethod || !normalizedPath) fail('REQUEST_CONTEXT_INVALID');
  return Buffer.from(
    `${canonicalJson(body)}\n${normalizedMethod}\n${normalizedPath}\n${nonce}\n${signedTs}`,
    'utf8',
  );
}

export function verifyPayloadSignature({ publicKey, body, nonce, signedTs, signature } = {}) {
  try {
    return verifyEd25519(publicKey, payloadMessage(body, nonce, signedTs), signature);
  } catch {
    return false;
  }
}

export function verifyRequestContextSignature({
  publicKey, body, method, path, nonce, signedTs, signature,
} = {}) {
  try {
    return verifyEd25519(
      publicKey,
      requestContextMessage(body, method, path, nonce, signedTs),
      signature,
    );
  } catch {
    return false;
  }
}

export function decodeCertificate(certificate) {
  try {
    const envelope = JSON.parse(exactBase64url(certificate, 'CERTIFICATE_INVALID').toString('utf8'));
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || !envelope.body || typeof envelope.body !== 'object' || Array.isArray(envelope.body)
        || typeof envelope.sig !== 'string') {
      fail('CERTIFICATE_INVALID');
    }
    return envelope;
  } catch (error) {
    if (error instanceof MutMemKernelError) throw error;
    fail('CERTIFICATE_INVALID');
  }
}

export function verifyCertificate({
  certificate,
  authorityPublicKey,
  expectedAgentId,
  expectedSubjectPublicKey,
  atUnixSeconds,
} = {}) {
  try {
    if (!Number.isSafeInteger(atUnixSeconds)) return { valid: false, reason: 'CERTIFICATE_TIME_INVALID' };
    const envelope = decodeCertificate(certificate);
    const body = envelope.body;
    const required = [
      'v', 'agent_id', 'pubkey', 'device_fp',
      'valid_from', 'valid_until', 'issuer', 'issued_at',
    ];
    if (required.some((key) => !Object.hasOwn(body, key))
        || body.v !== 1
        || !Number.isSafeInteger(body.valid_from)
        || !Number.isSafeInteger(body.valid_until)
        || body.valid_until <= body.valid_from
        || body.agent_id !== expectedAgentId
        || body.pubkey !== expectedSubjectPublicKey) {
      return { valid: false, reason: 'CERTIFICATE_BODY_INVALID' };
    }
    if (!verifyEd25519(authorityPublicKey, canonicalBytes(body), envelope.sig)) {
      return { valid: false, reason: 'CERTIFICATE_SIGNATURE_INVALID' };
    }
    if (atUnixSeconds < body.valid_from || atUnixSeconds > body.valid_until) {
      return { valid: false, reason: 'CERTIFICATE_EPOCH_INVALID' };
    }
    return { valid: true, reason: null, body };
  } catch {
    return { valid: false, reason: 'CERTIFICATE_MALFORMED' };
  }
}

function tlv(tag, value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u16(tag), u32(bytes.length), bytes]);
}

function occurrenceText(value, { empty = false, uppercase = false } = {}) {
  const normalized = String(value ?? '');
  if ((!empty && !normalized) || (uppercase && normalized !== normalized.toUpperCase())) {
    fail('OCCURRENCE_ENCODING_INVALID');
  }
  return Buffer.from(normalized, 'utf8');
}

function occurrenceHash(value, empty = false) {
  if (empty && !String(value || '')) return Buffer.alloc(0);
  return exactHashBytes(value, 'OCCURRENCE_ENCODING_INVALID');
}

function occurrenceUuid(value, empty = false) {
  if (empty && !String(value || '')) return Buffer.alloc(0);
  return uuidBytes(value, 'OCCURRENCE_ENCODING_INVALID');
}

function presence(flag, value, decoder) {
  if (Number(flag) === 0 && String(value || '') === '') return [Buffer.from([0]), Buffer.alloc(0)];
  if (Number(flag) === 1) return [Buffer.from([1]), decoder(value)];
  fail('OCCURRENCE_ENCODING_INVALID');
}

export function encodeOccurrenceV3(record = {}) {
  const [predecessorFlag, predecessor] = presence(
    record.predecessor_present,
    record.predecessor_commitment_hex,
    (value) => occurrenceHash(value),
  );
  const [receiptFlag, receipt] = presence(
    record.request_receipt_present,
    record.request_receipt_mutation_hash_hex,
    (value) => occurrenceHash(value),
  );
  const [authorizationFlag, authorization] = presence(
    record.authorization_event_present,
    record.authorization_event_id,
    (value) => occurrenceUuid(value),
  );
  const nonceHex = String(record.nonce_hex || '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(nonceHex) || nonceHex.length % 2 !== 0) {
    fail('OCCURRENCE_ENCODING_INVALID');
  }
  const nonce = Buffer.from(nonceHex, 'hex');
  if (nonce.length < 16 || nonce.length > 32) fail('OCCURRENCE_ENCODING_INVALID');
  const eventType = String(record.event_type || '');
  const method = String(record.signed_method || '');
  const path = String(record.signed_path || '');
  if (Number(record.sig_form_version) !== 3
      || eventType !== eventType.toUpperCase()
      || String(record.identity_tier || '') !== String(record.identity_tier || '').toUpperCase()
      || method !== method.toUpperCase()) fail('OCCURRENCE_ENCODING_INVALID');
  if ((!method || !path) && !(!method && !path && eventType.startsWith('INTERNAL_'))) {
    fail('OCCURRENCE_ENCODING_INVALID');
  }
  const fields = [
    occurrenceText(record.company_id),
    occurrenceUuid(record.occurrence_event_id),
    occurrenceUuid(record.memory_id),
    occurrenceText(eventType, { uppercase: true }),
    occurrenceHash(record.live_content_hash_hex),
    predecessorFlag,
    predecessor,
    occurrenceText(record.agent_id),
    i64(record.signer_valid_from_unix_ms, 'OCCURRENCE_ENCODING_INVALID'),
    occurrenceHash(record.cert_fingerprint_hex),
    occurrenceText(record.identity_tier, { uppercase: true }),
    u16(Number(record.sig_form_version), 'OCCURRENCE_ENCODING_INVALID'),
    nonce,
    u64(Number(record.ts_signed_unix_seconds), 'OCCURRENCE_ENCODING_INVALID'),
    occurrenceText(method, { empty: true, uppercase: true }),
    occurrenceText(path, { empty: true }),
    occurrenceHash(record.request_body_hash_hex),
    receiptFlag,
    receipt,
    authorizationFlag,
    authorization,
  ];
  return Buffer.concat([
    OCCURRENCE_DOMAIN,
    ...fields.map((value, index) => tlv(index + 1, value)),
  ]);
}

export function occurrenceCommitmentV3(record) {
  return sha256Hex(encodeOccurrenceV3(record));
}

export function occurrenceSignatureMessageV3(commitmentHex) {
  return Buffer.concat([
    OCCURRENCE_SIGNATURE_DOMAIN,
    exactHashBytes(commitmentHex, 'OCCURRENCE_ENCODING_INVALID'),
  ]);
}

export function verifyOccurrenceSignatureV3(record, signature, publicKey) {
  try {
    const commitment = occurrenceCommitmentV3(record);
    return verifyEd25519(publicKey, occurrenceSignatureMessageV3(commitment), signature);
  } catch {
    return false;
  }
}

export default {
  KERNEL_LIMITS,
  canonicalJson,
  canonicalBytes,
  sha256,
  sha256Hex,
  exactBase64url,
  exactHashBytes,
  uuidBytes,
  u16,
  u32,
  i64,
  u64,
  framedUtf8,
  recallMerkleRoot,
  verifyEd25519,
  payloadMessage,
  requestContextMessage,
  verifyPayloadSignature,
  verifyRequestContextSignature,
  decodeCertificate,
  verifyCertificate,
  encodeOccurrenceV3,
  occurrenceCommitmentV3,
  occurrenceSignatureMessageV3,
  verifyOccurrenceSignatureV3,
};
