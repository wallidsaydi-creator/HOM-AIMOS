/**
 * occurrence-session-binding-v1.js — signed occurrence/session projection
 *
 * Extends the retained occurrence-v3 request-hash commitment without changing
 * its frozen bytes. The Housekeeper event ledger signs this prefix-free
 * projection atomically with an exact-state SAVE_REASSERT transaction.
 *
 * Sources: RFC 6962 domain separation, RFC 8032, and the prefix-free encoding
 * discipline described by Boneh/Shoup and Cryptography Engineering.
 */

import { createHash } from 'node:crypto';

export const OCCURRENCE_SESSION_BINDING_V1 = Object.freeze({
  schema: 'hom.aimos.occurrence-session-binding/v1',
  domain: 'hom.aimos.occurrence-session-binding/v1\0',
  hash: 'SHA-256',
  encoding: 'u16be_tag_u32be_length_value',
});

const DOMAIN = Buffer.from(OCCURRENCE_SESSION_BINDING_V1.domain, 'utf8');
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function invalid() { throw new Error('occurrence_session_binding_v1_encoding_invalid'); }
function sha256(value) { return createHash('sha256').update(value).digest(); }
function frame(tag, value) {
  const bytes = Buffer.from(value);
  const header = Buffer.alloc(6);
  header.writeUInt16BE(tag, 0);
  header.writeUInt32BE(bytes.length, 2);
  return Buffer.concat([header, bytes]);
}
function u8(value) { return Buffer.from([value]); }
function text(value) {
  const normalized = String(value ?? '');
  if (!normalized) invalid();
  return Buffer.from(normalized, 'utf8');
}
function uuid(value) {
  const normalized = String(value || '').toLowerCase();
  if (!UUID.test(normalized)) invalid();
  return Buffer.from(normalized.replaceAll('-', ''), 'hex');
}
function hash32(value) {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) invalid();
  return Buffer.from(normalized, 'hex');
}
function u64(value) {
  if (!Number.isSafeInteger(value) || value < 0) invalid();
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}
function optional(value, decode) {
  return value == null ? [u8(0), Buffer.alloc(0)] : [u8(1), decode(value)];
}

export function buildOccurrenceSessionBindingV1({
  company_id,
  memory_id,
  occurrence_event_id,
  occurrence_commitment,
  request_body_sha256,
  session_id = null,
  source_dataset_sha256 = null,
  source_session_sha256 = null,
  source_session_ordinal = null,
} = {}) {
  const [sessionFlag, session] = optional(session_id, (value) => {
    const bytes = text(value);
    if (bytes.length > 256) invalid();
    return bytes;
  });
  const [datasetFlag, dataset] = optional(source_dataset_sha256, hash32);
  const [sourceSessionFlag, sourceSession] = optional(source_session_sha256, hash32);
  const [ordinalFlag, ordinal] = optional(source_session_ordinal, u64);
  const body = {
    schema: OCCURRENCE_SESSION_BINDING_V1.schema,
    company_id: String(company_id || ''),
    memory_id: String(memory_id || '').toLowerCase(),
    occurrence_event_id: String(occurrence_event_id || '').toLowerCase(),
    occurrence_commitment: String(occurrence_commitment || '').toLowerCase(),
    request_body_sha256: String(request_body_sha256 || '').toLowerCase(),
    session_id: session_id == null ? null : String(session_id),
    source_dataset_sha256: source_dataset_sha256 == null
      ? null : String(source_dataset_sha256).toLowerCase(),
    source_session_sha256: source_session_sha256 == null
      ? null : String(source_session_sha256).toLowerCase(),
    source_session_ordinal: source_session_ordinal == null
      ? null : Number(source_session_ordinal),
  };
  const fields = [
    text(body.company_id),
    uuid(body.memory_id),
    uuid(body.occurrence_event_id),
    hash32(body.occurrence_commitment),
    hash32(body.request_body_sha256),
    sessionFlag,
    session,
    datasetFlag,
    dataset,
    sourceSessionFlag,
    sourceSession,
    ordinalFlag,
    ordinal,
  ];
  const bindingSha256 = sha256(Buffer.concat([
    DOMAIN,
    ...fields.map((value, index) => frame(index + 1, value)),
  ])).toString('hex');
  return Object.freeze({ ...body, binding_sha256: bindingSha256 });
}

export function verifyOccurrenceSessionBindingV1(value) {
  try {
    if (value?.schema !== OCCURRENCE_SESSION_BINDING_V1.schema
        || typeof value.binding_sha256 !== 'string') {
      return { valid: false, reason: 'occurrence_session_binding_shape_invalid' };
    }
    const expected = buildOccurrenceSessionBindingV1(value);
    return expected.binding_sha256 === value.binding_sha256
      ? { valid: true, reason: null, binding: expected }
      : { valid: false, reason: 'occurrence_session_binding_hash_invalid' };
  } catch {
    return { valid: false, reason: 'occurrence_session_binding_encoding_invalid' };
  }
}
