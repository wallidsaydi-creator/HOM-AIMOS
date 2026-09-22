// Pure master-signed authorization for one exact consequential action.
// No database, route, model, tool, credential, or dispatch authority lives here.

import { createHash, randomBytes, randomUUID } from 'node:crypto';

import {
  canonicalJson,
  pubkeyFingerprint,
  signPayload,
  verifyStoredPayloadSig,
} from '../agent-identity.js';

export const OPERATOR_ACTION_AUTHORIZATION_SCHEMA_V1 =
  'hom.aimos.operator-action-authorization/v1';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function exactHash(value, code) {
  const normalized = String(value || '').toLowerCase();
  if (!HASH.test(normalized)) throw new Error(code);
  return normalized;
}

function exactText(value, code) {
  const normalized = String(value || '').trim();
  if (!normalized || Buffer.byteLength(normalized, 'utf8') > 200) throw new Error(code);
  return normalized;
}

function exactUuid(value, code) {
  const normalized = String(value || '').toLowerCase();
  if (!UUID.test(normalized)) throw new Error(code);
  return normalized;
}

function exactIso(value, code) {
  const normalized = String(value || '');
  const parsed = new Date(normalized);
  if (!normalized || Number.isNaN(parsed.getTime()) || parsed.toISOString() !== normalized) {
    throw new Error(code);
  }
  return normalized;
}

function normalizeBody(input = {}) {
  const expected = [
    'schema','proof_id','company_id','subject_agent_id','subject_valid_from',
    'subject_cert_fingerprint_sha256','approval_request_id',
    'approval_request_mutation_sha256','tool_name','action_scope','risk_class',
    'arguments_sha256','security_value_sha256','maximum_uses','created_at',
    'valid_until','master_fingerprint',
  ].sort();
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || canonicalJson(Object.keys(input).sort()) !== canonicalJson(expected)) {
    throw new Error('operator_action_authorization_shape_invalid');
  }
  if (input.schema !== OPERATOR_ACTION_AUTHORIZATION_SCHEMA_V1) {
    throw new Error('operator_action_authorization_schema_invalid');
  }
  const createdAt = exactIso(input.created_at, 'operator_action_authorization_time_invalid');
  const validUntil = exactIso(input.valid_until, 'operator_action_authorization_time_invalid');
  if (Date.parse(validUntil) <= Date.parse(createdAt)
      || Date.parse(validUntil) > Date.parse(createdAt) + 5 * 60 * 1000) {
    throw new Error('operator_action_authorization_window_invalid');
  }
  if (input.maximum_uses !== 1) throw new Error('operator_action_authorization_use_invalid');
  if (!['consequential','high_impact'].includes(input.risk_class)) {
    throw new Error('operator_action_authorization_risk_invalid');
  }
  return Object.freeze({
    schema: input.schema,
    proof_id: exactUuid(input.proof_id, 'operator_action_authorization_id_invalid'),
    company_id: exactText(input.company_id, 'operator_action_authorization_company_invalid'),
    subject_agent_id: exactText(input.subject_agent_id, 'operator_action_authorization_subject_invalid'),
    subject_valid_from: exactIso(input.subject_valid_from, 'operator_action_authorization_epoch_invalid'),
    subject_cert_fingerprint_sha256: exactHash(input.subject_cert_fingerprint_sha256, 'operator_action_authorization_subject_invalid'),
    approval_request_id: exactUuid(input.approval_request_id, 'operator_action_authorization_request_invalid'),
    approval_request_mutation_sha256: exactHash(input.approval_request_mutation_sha256, 'operator_action_authorization_request_invalid'),
    tool_name: exactText(input.tool_name, 'operator_action_authorization_tool_invalid'),
    action_scope: exactText(input.action_scope, 'operator_action_authorization_scope_invalid'),
    risk_class: input.risk_class,
    arguments_sha256: exactHash(input.arguments_sha256, 'operator_action_authorization_arguments_invalid'),
    security_value_sha256: exactHash(input.security_value_sha256, 'operator_action_authorization_value_invalid'),
    maximum_uses: 1,
    created_at: createdAt,
    valid_until: validUntil,
    master_fingerprint: exactHash(input.master_fingerprint, 'operator_action_authorization_master_invalid'),
  });
}

export function createOperatorActionAuthorizationProof(masterPrivkeyB64u, input, options = {}) {
  const createdAt = options.createdAt || new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
  const body = normalizeBody({
    schema: OPERATOR_ACTION_AUTHORIZATION_SCHEMA_V1,
    proof_id: options.proofId || randomUUID(),
    ...input,
    maximum_uses: 1,
    created_at: createdAt,
    valid_until: options.validUntil
      || new Date(Date.parse(createdAt) + 5 * 60 * 1000).toISOString(),
  });
  const tsSigned = Number.isInteger(options.tsSigned)
    ? options.tsSigned : Math.floor(Date.parse(createdAt) / 1000);
  const nonce = options.nonce || randomBytes(16).toString('base64url');
  const sig = signPayload(masterPrivkeyB64u, body, nonce, tsSigned);
  const unsigned = Object.freeze({
    body,
    ts_signed: tsSigned,
    nonce,
    sig,
    content_sha256: sha256(Buffer.from(canonicalJson(body), 'utf8')),
  });
  return Object.freeze({
    ...unsigned,
    proof_sha256: sha256(Buffer.from(canonicalJson(unsigned), 'utf8')),
  });
}

export function verifyOperatorActionAuthorizationProof(serialized, masterPubkeyB64u, expected = {}, nowMs = Date.now()) {
  try {
    const body = normalizeBody(serialized?.body);
    const unsigned = {
      body,
      ts_signed: Number(serialized?.ts_signed),
      nonce: String(serialized?.nonce || ''),
      sig: String(serialized?.sig || ''),
      content_sha256: String(serialized?.content_sha256 || ''),
    };
    if (!Number.isSafeInteger(unsigned.ts_signed) || !unsigned.nonce
        || Buffer.from(unsigned.sig, 'base64url').length !== 64
        || unsigned.content_sha256 !== sha256(Buffer.from(canonicalJson(body), 'utf8'))
        || serialized.proof_sha256 !== sha256(Buffer.from(canonicalJson(unsigned), 'utf8'))
        || pubkeyFingerprint(masterPubkeyB64u) !== body.master_fingerprint) {
      return { valid: false, reason: 'operator_action_authorization_binding_invalid' };
    }
    const signature = verifyStoredPayloadSig(
      masterPubkeyB64u, body, unsigned.nonce, unsigned.ts_signed, unsigned.sig,
    );
    if (!signature.valid) return { valid: false, reason: signature.reason };
    const exact = Object.entries(expected).every(([key, value]) => body[key] === value);
    if (!exact) return { valid: false, reason: 'operator_action_authorization_scope_mismatch' };
    const now = Number(nowMs);
    if (!Number.isFinite(now) || now < Date.parse(body.created_at) || now >= Date.parse(body.valid_until)) {
      return { valid: false, reason: 'operator_action_authorization_expired' };
    }
    return Object.freeze({ valid: true, reason: null, body, proofSha256: serialized.proof_sha256 });
  } catch (error) {
    return { valid: false, reason: error?.message || 'operator_action_authorization_invalid' };
  }
}
