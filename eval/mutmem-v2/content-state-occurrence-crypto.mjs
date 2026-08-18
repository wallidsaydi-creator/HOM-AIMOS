/**
 * content-state-occurrence-crypto.mjs — isolated R3 occurrence commitments
 *
 * Research authority: RFC 6962 domain separation; Boneh/Shoup prefix-free
 * encoding; Ferguson/Schneier/Kohno protocol/message identity and nonce
 * discipline; RFC 8032 Ed25519.
 *
 * This module is not imported by the runtime. It owns no database, migration,
 * writer, server, policy, environment, or credential-custody path.
 */

import {
  createHash,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'node:crypto';

export const OCCURRENCE_CRYPTO_CONTRACT = Object.freeze({
  schema: 'hom.aimos.content-state-occurrence-crypto/v1',
  legacy_domain: 'hom.aimos.memory-occurrence-ref/legacy-v1\0',
  successor_domain: 'hom.aimos.memory-occurrence/v3\0',
  successor_signature_domain: 'hom.aimos.memory-occurrence-signature/v3\0',
  tlv: 'u16be_tag_u32be_length_value',
  successor_tags: 21,
  signature_algorithm: 'Ed25519',
  database_authority: false,
  migration_authority: false,
  writer_authority: false,
  environment_authority: false,
});

const LEGACY_DOMAIN = Buffer.from(OCCURRENCE_CRYPTO_CONTRACT.legacy_domain, 'utf8');
const SUCCESSOR_DOMAIN = Buffer.from(OCCURRENCE_CRYPTO_CONTRACT.successor_domain, 'utf8');
const SIGNATURE_DOMAIN = Buffer.from(OCCURRENCE_CRYPTO_CONTRACT.successor_signature_domain, 'utf8');
const HEX_32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function fail(code) {
  throw new Error(`content_state_occurrence_crypto:${code}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function utf8(value, { allowEmpty = false, uppercase = false } = {}) {
  const text = String(value ?? '');
  if ((!allowEmpty && !text) || (uppercase && text !== text.toUpperCase())) {
    fail('occurrence_commitment_encoding_invalid');
  }
  return Buffer.from(text, 'utf8');
}

function uuidBytes(value, { allowEmpty = false } = {}) {
  const text = String(value || '').toLowerCase();
  if (allowEmpty && !text) return Buffer.alloc(0);
  if (!UUID.test(text)) fail('occurrence_commitment_encoding_invalid');
  return Buffer.from(text.replaceAll('-', ''), 'hex');
}

function hex32(value, { allowEmpty = false } = {}) {
  const text = String(value || '').toLowerCase();
  if (allowEmpty && !text) return Buffer.alloc(0);
  if (!HEX_32.test(text)) fail('occurrence_commitment_encoding_invalid');
  return Buffer.from(text, 'hex');
}

function unsigned8(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > 255) {
    fail('occurrence_commitment_encoding_invalid');
  }
  return Buffer.from([number]);
}

function unsigned16(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > 0xffff) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const output = Buffer.alloc(2);
  output.writeUInt16BE(number);
  return output;
}

function signed64(value) {
  let number;
  try { number = BigInt(value); } catch { fail('occurrence_commitment_encoding_invalid'); }
  const output = Buffer.alloc(8);
  try { output.writeBigInt64BE(number); } catch { fail('occurrence_commitment_encoding_invalid'); }
  return output;
}

function unsigned64(value) {
  let number;
  try { number = BigInt(value); } catch { fail('occurrence_commitment_encoding_invalid'); }
  if (number < 0n) fail('occurrence_commitment_encoding_invalid');
  const output = Buffer.alloc(8);
  try { output.writeBigUInt64BE(number); } catch { fail('occurrence_commitment_encoding_invalid'); }
  return output;
}

function tlv(tag, value) {
  const payload = Buffer.from(value);
  const header = Buffer.alloc(6);
  header.writeUInt16BE(tag, 0);
  header.writeUInt32BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

function decodeStrictUtf8(value) {
  try { return UTF8_DECODER.decode(value); } catch { fail('occurrence_commitment_encoding_invalid'); }
}

function normalizePresence(present, value, decoder) {
  const flag = Number(present);
  if (flag !== 0 && flag !== 1) fail('occurrence_commitment_encoding_invalid');
  if (flag === 0) {
    if (String(value || '') !== '') fail('occurrence_commitment_encoding_invalid');
    return [unsigned8(0), Buffer.alloc(0)];
  }
  return [unsigned8(1), decoder(value)];
}

export function encodeLegacyOccurrenceReferencePreimage(record = {}) {
  const fields = [
    [1, utf8(record.company_id)],
    [2, uuidBytes(record.memory_id)],
    [3, uuidBytes(record.provenance_id)],
    [4, hex32(record.mutation_hash_hex)],
    [5, utf8(record.agent_id)],
    [6, signed64(record.signer_valid_from_unix_ms)],
    [7, hex32(record.cert_fingerprint_hex)],
    [8, utf8(record.event_type, { uppercase: true })],
    [9, unsigned16(record.sig_form_version)],
  ];
  return Buffer.concat([LEGACY_DOMAIN, ...fields.map(([tag, value]) => tlv(tag, value))]);
}

export function computeLegacyOccurrenceReference(record = {}) {
  return sha256(encodeLegacyOccurrenceReferencePreimage(record)).toString('hex');
}

function successorFields(record = {}) {
  const [predecessorPresent, predecessor] = normalizePresence(
    record.predecessor_present,
    record.predecessor_commitment_hex,
    (value) => hex32(value),
  );
  const [receiptPresent, requestReceipt] = normalizePresence(
    record.request_receipt_present,
    record.request_receipt_mutation_hash_hex,
    (value) => hex32(value),
  );
  const [authorizationPresent, authorizationEvent] = normalizePresence(
    record.authorization_event_present,
    record.authorization_event_id,
    (value) => uuidBytes(value),
  );
  const nonce = Buffer.from(String(record.nonce_hex || ''), 'hex');
  if (!/^[0-9a-f]+$/i.test(String(record.nonce_hex || ''))
      || String(record.nonce_hex).length % 2 !== 0
      || nonce.length < 16 || nonce.length > 32) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const eventType = utf8(record.event_type, { uppercase: true });
  const method = utf8(record.signed_method, { allowEmpty: true, uppercase: true });
  const signedPath = utf8(record.signed_path, { allowEmpty: true });
  const internalEvent = decodeStrictUtf8(eventType).startsWith('INTERNAL_');
  if ((method.length === 0 || signedPath.length === 0)
      && !(method.length === 0 && signedPath.length === 0 && internalEvent)) {
    fail('occurrence_commitment_encoding_invalid');
  }
  if (Number(record.sig_form_version) !== 3) fail('occurrence_commitment_encoding_invalid');
  return [
    [1, utf8(record.company_id)],
    [2, uuidBytes(record.occurrence_event_id)],
    [3, uuidBytes(record.memory_id)],
    [4, eventType],
    [5, hex32(record.live_content_hash_hex)],
    [6, predecessorPresent],
    [7, predecessor],
    [8, utf8(record.agent_id)],
    [9, signed64(record.signer_valid_from_unix_ms)],
    [10, hex32(record.cert_fingerprint_hex)],
    [11, utf8(record.identity_tier, { uppercase: true })],
    [12, unsigned16(record.sig_form_version)],
    [13, nonce],
    [14, unsigned64(record.ts_signed_unix_seconds)],
    [15, method],
    [16, signedPath],
    [17, hex32(record.request_body_hash_hex)],
    [18, receiptPresent],
    [19, requestReceipt],
    [20, authorizationPresent],
    [21, authorizationEvent],
  ];
}

export function encodeOccurrenceCommitmentV3Preimage(record = {}) {
  return Buffer.concat([
    SUCCESSOR_DOMAIN,
    ...successorFields(record).map(([tag, value]) => tlv(tag, value)),
  ]);
}

export function computeOccurrenceCommitmentV3(record = {}) {
  return sha256(encodeOccurrenceCommitmentV3Preimage(record)).toString('hex');
}

function parseTlvSequence(bytes) {
  const input = Buffer.from(bytes);
  if (!input.subarray(0, SUCCESSOR_DOMAIN.length).equals(SUCCESSOR_DOMAIN)) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const fields = [];
  let offset = SUCCESSOR_DOMAIN.length;
  while (offset < input.length) {
    if (offset + 6 > input.length) fail('occurrence_commitment_encoding_invalid');
    const tag = input.readUInt16BE(offset);
    const length = input.readUInt32BE(offset + 2);
    offset += 6;
    if (offset + length > input.length) fail('occurrence_commitment_encoding_invalid');
    fields.push({ tag, value: input.subarray(offset, offset + length) });
    offset += length;
  }
  if (fields.length !== 21 || fields.some((field, index) => field.tag !== index + 1)) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const fixedLengths = new Map([[2, 16], [3, 16], [5, 32], [6, 1], [9, 8], [10, 32],
    [12, 2], [14, 8], [17, 32], [18, 1], [20, 1]]);
  for (const field of fields) {
    if (fixedLengths.has(field.tag) && field.value.length !== fixedLengths.get(field.tag)) {
      fail('occurrence_commitment_encoding_invalid');
    }
  }
  if (fields[12].value.length < 16 || fields[12].value.length > 32) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const presencePairs = [[5, 6, 32], [17, 18, 32], [19, 20, 16]];
  for (const [flagIndex, valueIndex, presentLength] of presencePairs) {
    const flag = fields[flagIndex].value[0];
    const length = fields[valueIndex].value.length;
    if ((flag !== 0 && flag !== 1) || (flag === 0 && length !== 0)
        || (flag === 1 && length !== presentLength)) {
      fail('occurrence_commitment_encoding_invalid');
    }
  }
  for (const index of [0, 3, 7, 10, 14, 15]) decodeStrictUtf8(fields[index].value);
  const company = decodeStrictUtf8(fields[0].value);
  const eventType = decodeStrictUtf8(fields[3].value);
  const agentId = decodeStrictUtf8(fields[7].value);
  const identityTier = decodeStrictUtf8(fields[10].value);
  const signatureForm = fields[11].value.readUInt16BE(0);
  const method = decodeStrictUtf8(fields[14].value);
  const signedPath = decodeStrictUtf8(fields[15].value);
  if (!company || !agentId || !eventType || !identityTier || signatureForm !== 3
      || eventType !== eventType.toUpperCase()
      || identityTier !== identityTier.toUpperCase()
      || method !== method.toUpperCase()) {
    fail('occurrence_commitment_encoding_invalid');
  }
  const internalEvent = eventType.startsWith('INTERNAL_');
  if ((method.length === 0 || signedPath.length === 0)
      && !(method.length === 0 && signedPath.length === 0 && internalEvent)) {
    fail('occurrence_commitment_encoding_invalid');
  }
  return fields;
}

export function verifyEncodedOccurrenceCommitmentV3(preimage, expectedCommitmentHex) {
  parseTlvSequence(preimage);
  const expected = String(expectedCommitmentHex || '').toLowerCase();
  if (!HEX_32.test(expected)) fail('occurrence_commitment_encoding_invalid');
  return sha256(Buffer.from(preimage)).toString('hex') === expected;
}

export function occurrenceSignatureMessageV3(commitmentHex) {
  return Buffer.concat([SIGNATURE_DOMAIN, hex32(commitmentHex)]);
}

export function signOccurrenceCommitmentV3(record, privateKey) {
  if (!privateKey) fail('occurrence_signing_key_required');
  const commitment = computeOccurrenceCommitmentV3(record);
  return ed25519Sign(null, occurrenceSignatureMessageV3(commitment), privateKey).toString('base64url');
}

export function verifyOccurrenceSignatureV3(record, signatureBase64url, publicKey) {
  if (!publicKey || typeof signatureBase64url !== 'string') return false;
  try {
    const commitment = computeOccurrenceCommitmentV3(record);
    const signature = Buffer.from(signatureBase64url, 'base64url');
    return signature.length === 64
      && ed25519Verify(null, occurrenceSignatureMessageV3(commitment), publicKey, signature);
  } catch {
    return false;
  }
}

export function successorNonceScopeKey(record = {}) {
  const nonce = String(record.nonce_hex || '').toLowerCase();
  if (!/^[0-9a-f]{32,64}$/.test(nonce) || nonce.length % 2 !== 0) {
    fail('occurrence_commitment_encoding_invalid');
  }
  return sha256(Buffer.concat([
    Buffer.from('hom.aimos.memory-occurrence-nonce-scope/v3\0', 'utf8'),
    tlv(1, utf8(record.company_id)),
    tlv(2, utf8(record.agent_id)),
    tlv(3, signed64(record.signer_valid_from_unix_ms)),
    tlv(4, Buffer.from(nonce, 'hex')),
  ])).toString('hex');
}

export function assertSuccessorNonceSetUnique(records = []) {
  if (!Array.isArray(records)) fail('occurrence_commitment_encoding_invalid');
  const observed = new Set();
  for (const record of records) {
    const key = successorNonceScopeKey(record);
    if (observed.has(key)) fail('occurrence_nonce_replay');
    observed.add(key);
  }
  return true;
}

export function verifySuccessorOccurrenceChain(records = []) {
  if (!Array.isArray(records) || records.length === 0) fail('occurrence_predecessor_invalid');
  assertSuccessorNonceSetUnique(records);
  const rows = records.map((record) => ({ record, commitment: computeOccurrenceCommitmentV3(record) }));
  const companies = new Set(records.map((record) => String(record.company_id)));
  const memories = new Set(records.map((record) => String(record.memory_id).toLowerCase()));
  if (companies.size !== 1 || memories.size !== 1) fail('occurrence_predecessor_invalid');
  const byCommitment = new Map();
  const eventIds = new Set();
  for (const row of rows) {
    if (byCommitment.has(row.commitment)) fail('occurrence_predecessor_invalid');
    byCommitment.set(row.commitment, row);
    const eventId = String(row.record.occurrence_event_id).toLowerCase();
    if (eventIds.has(eventId)) fail('occurrence_predecessor_invalid');
    eventIds.add(eventId);
  }
  const roots = rows.filter((row) => Number(row.record.predecessor_present) === 0);
  if (roots.length !== 1) fail('occurrence_predecessor_invalid');
  const successorByPredecessor = new Map();
  for (const row of rows) {
    if (Number(row.record.predecessor_present) === 0) continue;
    const predecessor = String(row.record.predecessor_commitment_hex || '').toLowerCase();
    if (!byCommitment.has(predecessor) || successorByPredecessor.has(predecessor)) {
      fail('occurrence_predecessor_invalid');
    }
    successorByPredecessor.set(predecessor, row.commitment);
  }
  let cursor = roots[0].commitment;
  const visited = new Set();
  while (cursor) {
    if (visited.has(cursor)) fail('occurrence_predecessor_invalid');
    visited.add(cursor);
    cursor = successorByPredecessor.get(cursor) || null;
  }
  if (visited.size !== rows.length) fail('occurrence_predecessor_invalid');
  return Object.freeze({
    valid: true,
    row_count: rows.length,
    genesis_commitment: roots[0].commitment,
    head_commitment: [...visited].at(-1),
  });
}
