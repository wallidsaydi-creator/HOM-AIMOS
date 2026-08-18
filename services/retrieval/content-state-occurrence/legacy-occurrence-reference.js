/**
 * legacy-occurrence-reference.js — production R4 derived occurrence identity
 *
 * Implements the exact R1 legacy TLV reference. It does not verify provenance;
 * callers must supply a row already verified by the native provenance owner.
 * It owns no database, writer, mutation, classification, or policy authority.
 */

import { createHash } from 'node:crypto';

export const LEGACY_OCCURRENCE_REFERENCE_CONTRACT = Object.freeze({
  schema: 'hom.aimos.memory-occurrence-ref/legacy-v1',
  domain: 'hom.aimos.memory-occurrence-ref/legacy-v1\0',
  tlv: 'u16be_tag_u32be_length_value',
  authority: 'derived_only_after_native_provenance_verification',
});

const DOMAIN = Buffer.from(LEGACY_OCCURRENCE_REFERENCE_CONTRACT.domain, 'utf8');
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail() {
  throw new Error('legacy_occurrence_reference_invalid');
}

function frame(tag, value) {
  const bytes = Buffer.from(value);
  const header = Buffer.alloc(6);
  header.writeUInt16BE(tag, 0);
  header.writeUInt32BE(bytes.length, 2);
  return Buffer.concat([header, bytes]);
}

function text(value, uppercase = false) {
  const normalized = String(value || '');
  if (!normalized || (uppercase && normalized !== normalized.toUpperCase())) fail();
  return Buffer.from(normalized, 'utf8');
}

function uuid(value) {
  const normalized = String(value || '').toLowerCase();
  if (!UUID.test(normalized)) fail();
  return Buffer.from(normalized.replaceAll('-', ''), 'hex');
}

function hash32(value) {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) fail();
  return Buffer.from(normalized, 'hex');
}

function signed64(value) {
  const output = Buffer.alloc(8);
  try { output.writeBigInt64BE(BigInt(value)); } catch { fail(); }
  return output;
}

function unsigned16(value) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 0xffff) fail();
  const output = Buffer.alloc(2);
  output.writeUInt16BE(normalized);
  return output;
}

export function computeVerifiedLegacyOccurrenceReference(record = {}) {
  const fields = [
    text(record.company_id),
    uuid(record.memory_id),
    uuid(record.provenance_id),
    hash32(record.mutation_hash_hex),
    text(record.agent_id),
    signed64(record.signer_valid_from_unix_ms),
    hash32(record.cert_fingerprint_hex),
    text(record.event_type, true),
    unsigned16(record.sig_form_version),
  ];
  return createHash('sha256')
    .update(Buffer.concat([DOMAIN, ...fields.map((value, index) => frame(index + 1, value))]))
    .digest('hex');
}
