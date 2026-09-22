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

// Independent wire admission. Never let JSON.parse erase duplicate members
// before inspecting them; escaped property names are compared after decoding.
export function parseJsonWire(text) {
  if (typeof text !== 'string') fail('JSON_WIRE_INVALID');
  const frames = [];
  let offset = 0;
  while (offset < text.length) {
    const start = offset;
    let value = text[offset++];
    if (value === '"') {
      let closed = false;
      while (offset < text.length) {
        const char = text[offset++];
        if (char === '\\') offset++;
        else if (char === '"') { closed = true; break; }
      }
      if (!closed) fail('JSON_WIRE_INVALID');
      value = text.slice(start, offset);
    }
    const top = frames.at(-1);
    if (value === '{' || value === '[') {
      if (frames.length > KERNEL_LIMITS.maximum_depth) fail('CANONICAL_DEPTH_INVALID');
      frames.push(value === '{' ? { names: new Set(), expectName: true } : {});
    } else if (value === '}' || value === ']') frames.pop();
    else if (value === ',') { if (top?.names) top.expectName = true; }
    else if (value[0] === '"' && top?.names && top.expectName) {
      const key = JSON.parse(value);
      if (top.names.has(key)) fail('JSON_DUPLICATE_MEMBER');
      top.names.add(key); top.expectName = false;
    }
  }
  return JSON.parse(text);
}

export function signedJsonBytesCommitmentV1(schema, wire) {
  if (typeof schema !== 'string' || schema.length > 200
      || !/^[a-z][a-z0-9._/-]*\/v[1-9][0-9]*$/.test(schema)) throw new Error('signed_json_schema_invalid');
  if (!Buffer.isBuffer(wire) || wire.length < 1 || wire.length > KERNEL_LIMITS.maximum_canonical_bytes) {
    throw new Error('signed_json_size_invalid');
  }
  try {
    const value = parseJsonWire(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(wire));
    const pending = [[value, 0]];
    function textValid(text) {
      for (const ch of text) {
        const c = ch.codePointAt(0);
        if (c === 0 || (c >= 0xd800 && c <= 0xdfff)) throw new Error();
      }
    }
    while (pending.length) {
      const [node, depth] = pending.pop();
      if (depth > KERNEL_LIMITS.maximum_depth) throw new Error();
      if (typeof node === 'string') textValid(node);
      else if (Array.isArray(node)) for (const child of node) pending.push([child, depth + 1]);
      else if (node && typeof node === 'object') for (const key of Object.keys(node)) {
        textValid(key); pending.push([node[key], depth + 1]);
      }
    }
  } catch { throw new Error('signed_json_wire_invalid'); }
  const type = Buffer.from(schema, 'ascii');
  return createHash('sha256').update(Buffer.from('hom.aimos.signed-json-bytes/v1\0'))
    .update(u32(type.length)).update(type).update(u32(wire.length)).update(wire).digest();
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

// Independent version dispatch for portable event witnesses. This checks the
// committed projection; callers still verify row, identity and operation scope.
export function eventPayloadBody(event) {
  if (!Object.hasOwn(event ?? {}, 'signed_body_bytes_b64u')) return event?.signed_body;
  const wire = exactBase64url(event.signed_body_bytes_b64u, 'EVENT_PAYLOAD_BYTES_INVALID');
  signedJsonBytesCommitmentV1('hom.aimos.event/v2', wire);
  const body = parseJsonWire(wire.toString('utf8'));
  const pending = [body];
  while (pending.length) {
    const value = pending.pop();
    if (typeof value === 'number' && !Number.isFinite(value)) fail('EVENT_PAYLOAD_PROJECTION_INVALID');
    if (value && typeof value === 'object') for (const child of Object.values(value)) pending.push(child);
  }
  if (!body || body.payload_schema !== 'hom.aimos.event/v2') fail('EVENT_PAYLOAD_VERSION_INVALID');
  // Original bytes are authoritative. Any redundant presentation must agree
  // under the native finite binary64 JSON-value interpretation, never rehash it.
  function same(a, b) {
    if (typeof a !== typeof b || Array.isArray(a) !== Array.isArray(b)) return false;
    if (a === null || b === null || typeof a !== 'object') return a === b;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every(k => Object.hasOwn(b, k) && same(a[k], b[k]));
  }
  if (Object.hasOwn(event, 'signed_body') && !same(body, event.signed_body)) fail('EVENT_PAYLOAD_PROJECTION_INVALID');
  return body;
}

export function eventPayloadCommitment(event) {
  const body = eventPayloadBody(event);
  if (!body || typeof body !== 'object' || Array.isArray(body)) fail('EVENT_PAYLOAD_INVALID');
  if (!Object.hasOwn(body, 'payload_schema')) {
    if (Object.hasOwn(event, 'signed_body_bytes_b64u')) fail('EVENT_PAYLOAD_VERSION_INVALID');
    return sha256(canonicalBytes(body));
  }
  if (body.payload_schema !== 'hom.aimos.event/v2') fail('EVENT_PAYLOAD_VERSION_INVALID');
  const wire = exactBase64url(event.signed_body_bytes_b64u, 'EVENT_PAYLOAD_BYTES_INVALID');
  const hash = signedJsonBytesCommitmentV1(body.payload_schema, wire);
  if (typeof event.nonce !== 'string' || !event.nonce.length || body.nonce !== event.nonce
      || body.ledger_version !== 1 || !Number.isSafeInteger(body.ledger_seq) || body.ledger_seq < 1
      || !Number.isSafeInteger(body.ts_signed) || body.ts_signed < 1) fail('EVENT_PAYLOAD_PROJECTION_INVALID');
  return hash;
}

export function verifyEventPayloadSignature(event, publicKey) {
  try {
    const commitment = eventPayloadCommitment(event);
    return eventPayloadBody(event).payload_schema === 'hom.aimos.event/v2'
      ? verifyEd25519(publicKey, commitment, event.signature_b64u)
      : verifyPayloadSignature({ publicKey, body: event.signed_body, nonce: event.nonce,
        signedTs: event.ts_signed, signature: event.signature_b64u });
  } catch { return false; }
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

export function requestTargetMessageV5(body, method, target, claims, nonce, signedTs, wire = null) {
  const m = String(method || '').toUpperCase();
  if (!/^[A-Z]+$/.test(m) || typeof nonce !== 'string' || !nonce || !Number.isSafeInteger(signedTs) || signedTs <= 0
      || typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')
      || /[^\x21-\x7e]|[#\\]/.test(target) || /%(?![0-9a-fA-F]{2})/.test(target)) fail('REQUEST_CONTEXT_INVALID');
  const keys = new Set();
  for (const field of (target.includes('?') ? target.slice(target.indexOf('?') + 1) : '').split('&')) {
    if (!field) continue;
    const key = decodeURIComponent(field.split('=', 1)[0].replace(/\+/g, ' '));
    if (key.includes('\0') || keys.has(key)) fail('REQUEST_CONTEXT_INVALID');
    keys.add(key);
  }
  if (!claims || typeof claims !== 'object' || Object.keys(claims).sort().join(',') !== 'device_fp,prev_chain_hash') fail('REQUEST_CONTEXT_INVALID');
  const prev = claims.prev_chain_hash, device = claims.device_fp;
  if (prev !== null && (typeof prev !== 'string' || exactBase64url(prev).length !== 32)) fail('REQUEST_CONTEXT_INVALID');
  if (device !== null && (typeof device !== 'string' || !device || prev === null)) fail('REQUEST_CONTEXT_INVALID');
  return Buffer.concat([Buffer.from('hom.aimos.request-envelope/v5\0'),
    ...[wire || Buffer.from(canonicalJson(body)), Buffer.from(m), Buffer.from(target),
      Buffer.from(canonicalJson(claims)), Buffer.from(nonce), Buffer.from(String(signedTs))]
      .flatMap(bytes => { const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return [length, bytes]; })]);
}

export function verifyPayloadSignature({ publicKey, body, nonce, signedTs, signature } = {}) {
  try {
    return verifyEd25519(publicKey, payloadMessage(body, nonce, signedTs), signature);
  } catch {
    return false;
  }
}

export function verifyRequestContextSignature({
  publicKey, body, method, path, nonce, signedTs, signature, requestForm = 3, claims = null,
} = {}) {
  try {
    if (![3, 5].includes(requestForm)) return false;
    return verifyEd25519(
      publicKey,
      requestForm === 5 ? requestTargetMessageV5(body, method, path, claims, nonce, signedTs)
        : requestContextMessage(body, method, path, nonce, signedTs),
      signature,
    );
  } catch {
    return false;
  }
}

// Decode retained native signing bytes without serializing metadata numbers.
// The caller must verify the original signature and its relational bindings.
export function retainedProvenanceMessage(row) {
  if (row?.body_json_encoding !== 'hom-aimos/canonical-json/v1' || Object.hasOwn(row, 'body_json')) fail('PROVENANCE_BYTES_INVALID');
  if (['signed_method', 'signed_path', 'signed_claims', 'memory_originated_at', 'prev_mutation_hash'].some(key => !Object.hasOwn(row, key))) fail('PROVENANCE_CONTEXT_INVALID');
  const wire = exactBase64url(row.body_json_bytes_b64u, 'PROVENANCE_BYTES_INVALID');
  if (!wire.length || wire.length > KERNEL_LIMITS.maximum_canonical_bytes) fail('PROVENANCE_BYTES_INVALID');
  let body;
  try { body = parseJsonWire(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(wire)); }
  catch { fail('PROVENANCE_BYTES_INVALID'); }
  if (body === null || typeof body !== 'object') fail('PROVENANCE_BYTES_INVALID');
  const pending = [[body, 0]];
  while (pending.length) {
    const [value, depth] = pending.pop();
    if (depth > KERNEL_LIMITS.maximum_depth || (typeof value === 'number' && !Number.isFinite(value))) fail('PROVENANCE_BYTES_INVALID');
    if (value && typeof value === 'object') for (const child of Object.values(value)) pending.push([child, depth + 1]);
  }
  const form = row.sig_form_version, requestForm = row.request_sig_form;
  if (requestForm === 5 && form !== 1) fail('PROVENANCE_CONTEXT_INVALID');
  if (![1, 2].includes(form) || ![1, 3, 4, 5].includes(requestForm)
      || !Number.isSafeInteger(row.ts_signed) || row.ts_signed <= 0
      || typeof row.nonce !== 'string' || !row.nonce
      || typeof row.is_genesis !== 'boolean' || row.is_genesis !== (row.prev_mutation_hash === null)
      || !['T1', 'T2', 'T3'].includes(row.identity_tier)
      || (['T2', 'T3'].includes(row.identity_tier) && ![4, 5].includes(requestForm))) fail('PROVENANCE_CONTEXT_INVALID');
  const contentHash = sha256Hex(wire);
  if (contentHash !== row.content_hash) fail('PROVENANCE_COMMITMENT_INVALID');
  let suffix = '';
  let originSeconds = null;
  if (form === 2) {
    const originMs = new Date(row.memory_originated_at).getTime();
    if (typeof row.memory_originated_at !== 'string' || !Number.isSafeInteger(originMs)
        || new Date(originMs).toISOString() !== row.memory_originated_at) fail('PROVENANCE_CONTEXT_INVALID');
    originSeconds = Math.floor(originMs / 1000);
    suffix = `\n${row.nonce}\n${row.ts_signed}\n${originSeconds}`;
  } else if (requestForm === 5) {
    if (['T2', 'T3'].includes(row.identity_tier) && !row.signed_claims?.prev_chain_hash) fail('PROVENANCE_CONTEXT_INVALID');
    requestTargetMessageV5(body, row.signed_method, row.signed_path, row.signed_claims, row.nonce, row.ts_signed, wire);
  } else if (requestForm === 1) {
    if (row.signed_method !== null || row.signed_path !== null || row.signed_claims !== null) fail('PROVENANCE_CONTEXT_INVALID');
    suffix = `\n${row.nonce}\n${row.ts_signed}`;
  } else {
    if (typeof row.signed_method !== 'string' || !row.signed_method
        || typeof row.signed_path !== 'string' || !row.signed_path) fail('PROVENANCE_CONTEXT_INVALID');
    suffix = `\n${row.signed_method.toUpperCase()}\n${row.signed_path.split('?')[0]}`;
    if (requestForm === 4) {
      const claims = row.signed_claims;
      const deviceFp = claims?.device_fp ?? null;
      if (!claims || typeof claims.prev_chain_hash !== 'string'
          || exactBase64url(claims.prev_chain_hash).length !== 32
          || (deviceFp !== null && (typeof deviceFp !== 'string' || !deviceFp))) fail('PROVENANCE_CONTEXT_INVALID');
      suffix += `\n${canonicalJson({ prev_chain_hash: claims.prev_chain_hash, device_fp: deviceFp })}`;
    } else if (row.signed_claims !== null) fail('PROVENANCE_CONTEXT_INVALID');
    suffix += `\n${row.nonce}\n${row.ts_signed}`;
  }
  const mutation = sha256Hex(Buffer.concat([exactHashBytes(contentHash),
    row.prev_mutation_hash === null ? Buffer.alloc(0) : exactHashBytes(row.prev_mutation_hash),
    Buffer.from(row.nonce), Buffer.from(String(row.ts_signed)),
    originSeconds === null ? Buffer.alloc(0) : Buffer.from(String(originSeconds)),
  ]));
  if (mutation !== row.mutation_hash) fail('PROVENANCE_COMMITMENT_INVALID');
  return { body, wire, message: requestForm === 5 && form !== 2
    ? requestTargetMessageV5(body, row.signed_method, row.signed_path, row.signed_claims, row.nonce, row.ts_signed, wire)
    : Buffer.concat([wire, Buffer.from(suffix)]), contentHash, mutationHash: mutation };
}

export function legacyOccurrenceReference(row, companyId) {
  if (typeof companyId !== 'string' || !companyId || typeof row.agent_id !== 'string' || !row.agent_id
      || typeof row.event_type !== 'string' || !row.event_type || row.event_type !== row.event_type.toUpperCase()) fail('PROVENANCE_CONTEXT_INVALID');
  const fields = [Buffer.from(companyId), uuidBytes(row.memory_id), uuidBytes(row.provenance_id),
    exactHashBytes(row.mutation_hash), Buffer.from(row.agent_id), i64(new Date(row.agent_valid_from).getTime()),
    exactHashBytes(row.cert_fingerprint), Buffer.from(row.event_type), u16(row.sig_form_version)];
  return sha256Hex(Buffer.concat([Buffer.from('hom.aimos.memory-occurrence-ref/legacy-v1\0'),
    ...fields.map((bytes, i) => Buffer.concat([u16(i + 1), u32(bytes.length), bytes]))]));
}

export function decodeCertificate(certificate) {
  try {
    const envelope = parseJsonWire(exactBase64url(certificate, 'CERTIFICATE_INVALID').toString('utf8'));
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
        || !envelope.body || typeof envelope.body !== 'object' || Array.isArray(envelope.body)
        || typeof envelope.sig !== 'string') {
      fail('CERTIFICATE_INVALID');
    }
    return envelope;
  } catch (error) {
    if (error?.reason === 'JSON_DUPLICATE_MEMBER') fail('CERTIFICATE_INVALID');
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
  if (flag === 0 && String(value || '') === '') return [Buffer.from([0]), Buffer.alloc(0)];
  if (flag === 1) return [Buffer.from([1]), decoder(value)];
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
  if (record.sig_form_version !== 3
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
    u16(record.sig_form_version, 'OCCURRENCE_ENCODING_INVALID'),
    nonce,
    u64(record.ts_signed_unix_seconds, 'OCCURRENCE_ENCODING_INVALID'),
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
