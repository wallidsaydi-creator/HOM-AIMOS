// Master-signed, purpose-bound authority for narrow non-memory operations.
//
// This is not an ambient role or a generic capability token. Each proof is
// bound to one company, one exact agent certificate epoch, one protocol
// commitment, one source root, one corpus root, one operation, one tool, one
// owner-only filesystem root, and the agent certificate's terminal time.
// Runtime consumers independently verify the master signature and scope before
// executing the operation. No environment value participates in authority.

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  canonicalJson,
  pubkeyFingerprint,
  signPayload,
  verifyStoredPayloadSig,
} from './agent-identity.js';

export const PURPOSE_AUTHORIZATION_SCHEMA = 'hom.aimos.purpose-authorization/v1';
export const LOCAL_FILE_READ_OPERATION = 'local_file_read';

const ALLOWED_TOOLS = Object.freeze({
  read_file: LOCAL_FILE_READ_OPERATION,
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requireText(value, reason) {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(reason);
  return normalized;
}

function requireSha256(value, reason) {
  const normalized = requireText(value, reason).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(reason);
  return normalized;
}

function normalizeIso(value, reason) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error(reason);
  return parsed.toISOString();
}

function normalizeReadRoot(value) {
  const absolute = path.resolve(requireText(value, 'purpose_authorization_root_required'));
  if (!path.isAbsolute(absolute)) throw new Error('purpose_authorization_root_not_absolute');
  const stat = fs.lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('purpose_authorization_root_custody_invalid');
  }
  const real = fs.realpathSync(absolute);
  if (real !== absolute) throw new Error('purpose_authorization_root_realpath_invalid');
  return real;
}

function normalizeBody(input) {
  const tool = requireText(input.tool, 'purpose_authorization_tool_required');
  const operation = requireText(input.operation, 'purpose_authorization_operation_required');
  if (ALLOWED_TOOLS[tool] !== operation) throw new Error('purpose_authorization_tool_operation_invalid');
  const subjectValidFrom = normalizeIso(input.subjectValidFrom, 'purpose_authorization_subject_epoch_invalid');
  const subjectValidUntil = normalizeIso(input.subjectValidUntil, 'purpose_authorization_subject_expiry_invalid');
  if (Date.parse(subjectValidUntil) <= Date.parse(subjectValidFrom)) {
    throw new Error('purpose_authorization_subject_window_invalid');
  }
  const clearance = Number(input.clearanceCeiling);
  if (!Number.isInteger(clearance) || clearance < 1 || clearance > 12) {
    throw new Error('purpose_authorization_clearance_invalid');
  }
  return {
    schema: PURPOSE_AUTHORIZATION_SCHEMA,
    purpose_id: requireText(input.purposeId, 'purpose_authorization_purpose_required'),
    protocol_id: requireText(input.protocolId, 'purpose_authorization_protocol_required'),
    protocol_confirmation_sha256: requireSha256(
      input.protocolConfirmationSha256,
      'purpose_authorization_protocol_commitment_invalid',
    ),
    source_root_sha256: requireSha256(input.sourceRootSha256, 'purpose_authorization_source_root_invalid'),
    corpus_root_sha256: requireSha256(input.corpusRootSha256, 'purpose_authorization_corpus_root_invalid'),
    database_name_sha256: requireSha256(input.databaseNameSha256, 'purpose_authorization_database_invalid'),
    company_id: requireText(input.companyId, 'purpose_authorization_company_required'),
    subject_agent_id: requireText(input.subjectAgentId, 'purpose_authorization_subject_required'),
    subject_valid_from: subjectValidFrom,
    subject_valid_until: subjectValidUntil,
    operation,
    tool,
    read_root: normalizeReadRoot(input.readRoot),
    clearance_ceiling: clearance,
    master_fingerprint: requireSha256(
      input.masterFingerprint,
      'purpose_authorization_master_fingerprint_invalid',
    ),
  };
}

export function createPurposeAuthorizationProof(masterPrivkeyB64u, input, opts = {}) {
  const body = normalizeBody(input);
  const signedTs = Number.isInteger(opts.signedTs) ? opts.signedTs : Math.floor(Date.now() / 1000);
  const nonce = opts.nonce || randomBytes(16).toString('base64url');
  const sigBytes = Buffer.from(signPayload(masterPrivkeyB64u, body, nonce, signedTs), 'base64url');
  return Object.freeze({
    body: Object.freeze(body),
    signedTs,
    nonce,
    sigBytes,
    contentSha256: sha256(Buffer.from(canonicalJson(body), 'utf8')),
  });
}

export function serializePurposeAuthorizationProof(proof) {
  if (proof?.body && Number.isInteger(proof.ts_signed)
      && typeof proof.nonce === 'string' && typeof proof.sig === 'string') {
    return Object.freeze({
      body: proof.body,
      ts_signed: proof.ts_signed,
      nonce: proof.nonce,
      sig: proof.sig,
      content_sha256: proof.content_sha256,
    });
  }
  return Object.freeze({
    body: proof.body,
    ts_signed: Number(proof.signedTs),
    nonce: String(proof.nonce),
    sig: Buffer.from(proof.sigBytes).toString('base64url'),
    content_sha256: String(proof.contentSha256),
  });
}

export function purposeAuthorizationArtifactSha256(proof) {
  return sha256(Buffer.from(canonicalJson(serializePurposeAuthorizationProof(proof)), 'utf8'));
}

export function verifyPurposeAuthorizationProof(serialized, masterPubkeyB64u) {
  try {
    const normalizedBody = normalizeBody({
      purposeId: serialized?.body?.purpose_id,
      protocolId: serialized?.body?.protocol_id,
      protocolConfirmationSha256: serialized?.body?.protocol_confirmation_sha256,
      sourceRootSha256: serialized?.body?.source_root_sha256,
      corpusRootSha256: serialized?.body?.corpus_root_sha256,
      databaseNameSha256: serialized?.body?.database_name_sha256,
      companyId: serialized?.body?.company_id,
      subjectAgentId: serialized?.body?.subject_agent_id,
      subjectValidFrom: serialized?.body?.subject_valid_from,
      subjectValidUntil: serialized?.body?.subject_valid_until,
      operation: serialized?.body?.operation,
      tool: serialized?.body?.tool,
      readRoot: serialized?.body?.read_root,
      clearanceCeiling: serialized?.body?.clearance_ceiling,
      masterFingerprint: serialized?.body?.master_fingerprint,
    });
    if (canonicalJson(normalizedBody) !== canonicalJson(serialized.body)) {
      return { valid: false, reason: 'purpose_authorization_body_noncanonical' };
    }
    if (pubkeyFingerprint(masterPubkeyB64u) !== normalizedBody.master_fingerprint) {
      return { valid: false, reason: 'purpose_authorization_master_mismatch' };
    }
    const contentSha256 = sha256(Buffer.from(canonicalJson(normalizedBody), 'utf8'));
    if (contentSha256 !== serialized.content_sha256) {
      return { valid: false, reason: 'purpose_authorization_content_hash_mismatch' };
    }
    const signature = verifyStoredPayloadSig(
      masterPubkeyB64u,
      normalizedBody,
      String(serialized.nonce),
      Number(serialized.ts_signed),
      String(serialized.sig),
    );
    if (!signature.valid) return signature;
    return { valid: true, reason: null, body: normalizedBody, contentSha256 };
  } catch (error) {
    return { valid: false, reason: String(error?.message || 'purpose_authorization_malformed') };
  }
}

function assertNoSymlinkPath(root, candidate) {
  const relative = path.relative(root, candidate);
  if (!relative || relative === '.') throw new Error('purpose_authorization_file_required');
  if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('purpose_authorization_path_escape');
  }
  let cursor = root;
  for (const segment of relative.split(path.sep)) {
    cursor = path.join(cursor, segment);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) throw new Error('purpose_authorization_symlink_forbidden');
  }
}

export function authorizePurposeLocalFileRead({
  serialized,
  masterPubkeyB64u,
  executionContext,
  agentId,
  tool,
  filepath,
  clearanceLevel,
  expectedProtocolConfirmationSha256 = null,
  nowMs = Date.now(),
} = {}) {
  const verification = verifyPurposeAuthorizationProof(serialized, masterPubkeyB64u);
  if (!verification.valid) {
    throw new Error(`purpose_authorization_invalid:${verification.reason}`);
  }
  const body = verification.body;
  const actorAgentId = String(executionContext?.actorAgentId || '').trim();
  const actorValidFrom = normalizeIso(
    executionContext?.actorValidFromIso,
    'purpose_authorization_execution_epoch_missing',
  );
  const exact = body.subject_agent_id === String(agentId || '')
    && body.subject_agent_id === actorAgentId
    && body.subject_valid_from === actorValidFrom
    && body.company_id === String(executionContext?.companyId || '')
    && body.tool === String(tool || '')
    && body.operation === LOCAL_FILE_READ_OPERATION
    && Number(clearanceLevel) <= body.clearance_ceiling
    && String(executionContext?.identityTier || '').toUpperCase() === 'T1';
  if (!exact) throw new Error('purpose_authorization_execution_scope_mismatch');
  if (expectedProtocolConfirmationSha256
      && body.protocol_confirmation_sha256 !== expectedProtocolConfirmationSha256) {
    throw new Error('purpose_authorization_protocol_scope_mismatch');
  }
  const now = Number(nowMs);
  if (!Number.isFinite(now)
      || now < Date.parse(body.subject_valid_from)
      || now >= Date.parse(body.subject_valid_until)) {
    throw new Error('purpose_authorization_expired_or_not_yet_valid');
  }
  const requested = path.resolve(requireText(filepath, 'purpose_authorization_filepath_required'));
  if (!fs.existsSync(requested)) {
    throw new Error('purpose_authorization_file_invalid');
  }
  if (fs.lstatSync(requested).isSymbolicLink()) {
    throw new Error('purpose_authorization_symlink_forbidden');
  }
  if (!fs.lstatSync(requested).isFile()) throw new Error('purpose_authorization_file_invalid');
  const real = fs.realpathSync(requested);
  if (real !== requested) throw new Error('purpose_authorization_file_realpath_invalid');
  assertNoSymlinkPath(body.read_root, real);
  return Object.freeze({
    valid: true,
    contentSha256: verification.contentSha256,
    artifactSha256: sha256(Buffer.from(canonicalJson(serialized), 'utf8')),
    operation: body.operation,
    tool: body.tool,
    readRootSha256: sha256(body.read_root),
    protocolConfirmationSha256: body.protocol_confirmation_sha256,
  });
}
