// OB-2 correction 1: exact native operation-authority representation.
// Sources: Louck 2606.24322 §§II–IV; Cecchetti–Myers–Arden 1708.08596 §§2–3.
// This is a commitment to existing evidence, not a signer, permission grant,
// content-trust label or alternative execution path. No I/O or v1 byte changes.
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical-json.js';

export const ORIGIN_OPERATION_AUTHORITY_SCHEMA_V2 = 'hom.aimos.origin-operation-authority/v2';
export const ORIGIN_OPERATION_AUTHORITY_KINDS_V2 = Object.freeze([
  'verified_request', 'verified_housekeeper_action', 'verified_tool_action',
]);
const DOMAIN = Buffer.from(`${ORIGIN_OPERATION_AUTHORITY_SCHEMA_V2}\0`, 'utf8');
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDENTIFIER = /^[a-z0-9](?:[a-z0-9._:-]{0,198}[a-z0-9])?$/;
const COMMON = ['schema', 'kind', 'company_id', 'actor', 'signer', 'subject_agent_id', 'evidence'];

function requireValue(condition, reason) {
  if (!condition) throw new Error(`origin_authority_${reason}`);
}
function exactKeys(value, keys) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), 'shape_invalid');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  requireValue(actual.length === keys.length
    && actual.every((key, index) => key === expected[index]), 'shape_invalid');
}
function hash(value) { requireValue(typeof value === 'string' && HASH.test(value), 'hash_invalid'); return value; }
function uuid(value) { requireValue(typeof value === 'string' && UUID.test(value), 'reference_invalid'); return value; }
function identifier(value) {
  requireValue(typeof value === 'string' && IDENTIFIER.test(value), 'identifier_invalid');
  return value;
}
function timestamp(value) {
  requireValue(typeof value === 'string' && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value, 'timestamp_invalid');
  return value;
}
function principal(value) {
  exactKeys(value, ['agent_id', 'valid_from', 'cert_fingerprint_sha256']);
  return Object.freeze({ agent_id: identifier(value.agent_id),
    valid_from: timestamp(value.valid_from),
    cert_fingerprint_sha256: hash(value.cert_fingerprint_sha256) });
}

function evidence(kind, value) {
  if (kind === 'verified_request') {
    exactKeys(value, ['receipt_id', 'mutation_sha256', 'request_sha256', 'signature_form',
      'signed_method', 'signed_path', 'signed_at']);
    requireValue([3, 4, 5].includes(value.signature_form), 'request_signature_form_invalid');
    requireValue(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(value.signed_method)
      && typeof value.signed_path === 'string' && value.signed_path.startsWith('/')
      && Buffer.byteLength(value.signed_path, 'utf8') <= 2048
      && !/[\u0000-\u0020\u007f]/.test(value.signed_path), 'request_context_invalid');
    return Object.freeze({ receipt_id: uuid(value.receipt_id), mutation_sha256: hash(value.mutation_sha256),
      request_sha256: hash(value.request_sha256), signature_form: value.signature_form,
      signed_method: value.signed_method, signed_path: value.signed_path, signed_at: timestamp(value.signed_at) });
  }
  if (kind === 'verified_housekeeper_action') {
    exactKeys(value, ['event_id', 'mutation_sha256', 'action_sha256', 'action_context_sha256', 'signed_at']);
    return Object.freeze({ event_id: uuid(value.event_id), mutation_sha256: hash(value.mutation_sha256),
      action_sha256: hash(value.action_sha256), action_context_sha256: hash(value.action_context_sha256),
      signed_at: timestamp(value.signed_at) });
  }
  exactKeys(value, ['event_id', 'mutation_sha256', 'tool', 'args_sha256', 'runtime_agent_id',
    'purpose_authorization_sha256', 'signed_at']);
  return Object.freeze({ event_id: uuid(value.event_id), mutation_sha256: hash(value.mutation_sha256),
    tool: identifier(value.tool), args_sha256: hash(value.args_sha256),
    runtime_agent_id: identifier(value.runtime_agent_id),
    purpose_authorization_sha256: value.purpose_authorization_sha256 === null
      ? null : hash(value.purpose_authorization_sha256), signed_at: timestamp(value.signed_at) });
}

export function createOriginOperationAuthorityV2(input) {
  exactKeys(input, COMMON);
  requireValue(input.schema === ORIGIN_OPERATION_AUTHORITY_SCHEMA_V2, 'schema_invalid');
  requireValue(ORIGIN_OPERATION_AUTHORITY_KINDS_V2.includes(input.kind), 'kind_invalid');
  const actor = principal(input.actor);
  const signer = principal(input.signer);
  const subject = identifier(input.subject_agent_id);
  if (input.kind === 'verified_request') {
    requireValue(canonicalJson(actor) === canonicalJson(signer) && subject === actor.agent_id,
      'request_principal_mismatch');
  } else {
    requireValue(signer.agent_id === 'housekeeper', 'action_signer_invalid');
    if (input.kind === 'verified_housekeeper_action') {
      requireValue(actor.agent_id === 'housekeeper' && canonicalJson(actor) === canonicalJson(signer),
        'housekeeper_principal_mismatch');
    } else {
      requireValue(subject === actor.agent_id, 'tool_subject_mismatch');
    }
  }
  const body = Object.freeze({ schema: input.schema, kind: input.kind,
    company_id: identifier(input.company_id), actor, signer, subject_agent_id: subject,
    evidence: evidence(input.kind, input.evidence) });
  requireValue(Date.parse(body.evidence.signed_at) >= Date.parse(actor.valid_from)
    && Date.parse(body.evidence.signed_at) >= Date.parse(signer.valid_from), 'epoch_order_invalid');
  const bytes = Buffer.from(canonicalJson(body), 'utf8');
  requireValue(bytes.length <= 8192, 'size_invalid');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Object.freeze({ ...body, authority_sha256: createHash('sha256')
    .update(Buffer.concat([DOMAIN, length, bytes])).digest('hex') });
}

export function verifyOriginOperationAuthorityV2(record) {
  exactKeys(record, [...COMMON, 'authority_sha256']);
  const { authority_sha256: supplied, ...body } = record;
  const rebuilt = createOriginOperationAuthorityV2(body);
  requireValue(hash(supplied) === rebuilt.authority_sha256, 'commitment_mismatch');
  return rebuilt;
}
