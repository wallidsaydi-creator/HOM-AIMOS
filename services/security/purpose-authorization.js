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
import os from 'node:os';
import path from 'node:path';
import { AIMOS_COMPANY_ID, AIMOS_STATE_ROOT } from '../core/runtime-config.js';
import { verifyToolActionAuthority } from '../orchestration/tool-action-ledger.js';
import { readVerifiedEventById } from '../observe/event-ledger.js';

import {
  canonicalJson,
  pubkeyFingerprint,
  signPayload,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import {
  materialEffectTargetHash,
  materialEffectOwner,
} from './material-effect-owner.js';

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
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
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
    if (cursor !== candidate && (!stat.isDirectory() || (stat.mode & 0o022) !== 0)) {
      throw new Error('purpose_authorization_directory_custody_invalid');
    }
  }
}

function isWithin(candidate, root) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

export function allowedLocalWriteRoots() {
  const home = os.homedir();
  return Object.freeze([
    path.join(home, '.aimos', 'exports'),
    path.join(home, 'Desktop'),
    path.join(home, 'Documents'),
  ]);
}

export function localFileWriteInputProjection({ content, toolActionEventId }) {
  if (typeof content !== 'string' || !String(toolActionEventId || '').trim()) {
    throw new Error('local_file_write_projection_invalid');
  }
  return Object.freeze({
    tool_action_event_id: String(toolActionEventId),
    content_sha256: sha256(Buffer.from(content, 'utf8')),
    byte_length: Buffer.byteLength(content, 'utf8'),
  });
}

const PROTECTED_LOCAL_ROOTS = Object.freeze([
  path.join(os.homedir(), '.aimos'),
  AIMOS_STATE_ROOT,
  path.join(os.homedir(), '.ssh'),
  path.join(os.homedir(), '.gnupg'),
  path.join(os.homedir(), '.aws'),
  path.join(os.homedir(), 'Library', 'Keychains'),
]);

export function assertLocalFileNotProtected(filepath, protectedRoots = PROTECTED_LOCAL_ROOTS) {
  const absolute = path.resolve(filepath);
  if (protectedRoots.some((root) => isWithin(absolute, path.resolve(root)))
      || path.basename(absolute).match(/^(?:\.env(?:\..*)?|id_(?:rsa|ed25519)|.*\.(?:key|pem|p12|pfx))$/i)) {
    throw new Error('local_file_protected_path');
  }
}

function lstatIfExists(filepath) {
  try { return fs.lstatSync(filepath); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
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
  if (!/^[0-9a-f]{64}$/.test(String(expectedProtocolConfirmationSha256 || ''))) {
    throw new Error('purpose_authorization_protocol_commitment_required');
  }
  if (body.protocol_confirmation_sha256 !== expectedProtocolConfirmationSha256) {
    throw new Error('purpose_authorization_protocol_scope_mismatch');
  }
  const now = Number(nowMs);
  if (!Number.isFinite(now)
      || now < Date.parse(body.subject_valid_from)
      || now >= Date.parse(body.subject_valid_until)) {
    throw new Error('purpose_authorization_expired_or_not_yet_valid');
  }
  const requested = path.resolve(requireText(filepath, 'purpose_authorization_filepath_required'));
  assertLocalFileNotProtected(requested);
  if (!fs.existsSync(requested)) {
    throw new Error('purpose_authorization_file_invalid');
  }
  if (fs.lstatSync(requested).isSymbolicLink()) {
    throw new Error('purpose_authorization_symlink_forbidden');
  }
  const named = fs.lstatSync(requested);
  if (!named.isFile()) throw new Error('purpose_authorization_file_invalid');
  if (named.nlink !== 1) throw new Error('purpose_authorization_hardlink_forbidden');
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

// Recheck the proof at the native read and bind the bytes to a regular-file
// descriptor. A path substitution after pre-action admission must fail closed.
export function readPurposeAuthorizedLocalFile(input) {
  authorizePurposeLocalFileRead(input);
  const requested = path.resolve(input.filepath);
  const fd = fs.openSync(requested, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    const named = fs.lstatSync(requested);
    if (!opened.isFile() || !named.isFile() || opened.nlink !== 1 || named.nlink !== 1
        || opened.dev !== named.dev || opened.ino !== named.ino) {
      throw new Error('purpose_authorization_file_changed');
    }
    // The tool exposes at most 50,000 characters. Bound I/O even if the file
    // grows while the descriptor is open.
    const bytes = Buffer.alloc(200_001);
    let count = 0;
    while (count < bytes.length) {
      const read = fs.readSync(fd, bytes, count, bytes.length - count, count);
      if (read === 0) break;
      count += read;
    }
    const after = fs.fstatSync(fd);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.nlink !== 1
        || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs
        || after.ctimeMs !== opened.ctimeMs) {
      throw new Error('purpose_authorization_file_changed');
    }
    const content = bytes.subarray(0, count).toString('utf8');
    return content.length > 50_000
      ? `${content.substring(0, 50_000)}\n\n...[TRUNCATED: File too large]...`
      : content;
  } finally {
    fs.closeSync(fd);
  }
}

function assertSafeDirectory(directory) {
  const absolute = path.resolve(directory);
  let cursor = path.parse(absolute).root;
  for (const segment of path.relative(cursor, absolute).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const stat = fs.lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()
        || (stat.mode & 0o022) !== 0
        || (typeof process.getuid === 'function' && stat.uid !== 0 && stat.uid !== process.getuid())) {
      throw new Error('local_file_directory_custody_invalid');
    }
  }
  if (fs.realpathSync(absolute) !== absolute) throw new Error('local_file_directory_realpath_invalid');
  return absolute;
}

function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

// A new inode is written in the authorized directory and renamed over the
// destination. Existing hard links are replaced, never modified in place.
export function inspectAllowedLocalFileWrite({ filepath, content, allowedRoots }) {
  if (typeof filepath !== 'string' || !path.isAbsolute(filepath)) {
    throw new Error('local_file_absolute_path_required');
  }
  if (typeof content !== 'string') throw new Error('local_file_content_required');
  const requested = path.resolve(filepath);
  const roots = (allowedRoots || []).map((root) => path.resolve(root));
  const root = roots.find((candidate) => requested !== candidate && isWithin(requested, candidate));
  if (!root) throw new Error('local_file_write_root_invalid');
  assertSafeDirectory(root);
  const parent = assertSafeDirectory(path.dirname(requested));
  {
    const prior = lstatIfExists(requested);
    if (prior
        && (!prior.isFile() || prior.isSymbolicLink())) throw new Error('local_file_target_invalid');
  }
  return Object.freeze({ requested, root, parent });
}

function writeAllowedLocalFileNative({ requested, parent, content, actionId }) {
  const parentBefore = fs.lstatSync(parent);
  const temporary = path.join(parent, `.${path.basename(requested)}.aimos-${actionId}`);
  let created = false;
  try {
    const fd = fs.openSync(temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600);
    created = true;
    try {
      fs.writeFileSync(fd, content, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    const parentAfter = fs.lstatSync(parent);
    if (parentAfter.dev !== parentBefore.dev || parentAfter.ino !== parentBefore.ino) {
      throw new Error('local_file_parent_changed');
    }
    assertSafeDirectory(parent);
    const prior = lstatIfExists(requested);
    if (prior && (!prior.isFile() || prior.isSymbolicLink())) throw new Error('local_file_target_invalid');
    fs.renameSync(temporary, requested);
    created = false;
    syncDirectory(parent);
    const stat = fs.lstatSync(requested);
    return {
      path: requested,
      contentSha256: sha256(Buffer.from(content, 'utf8')),
      byteLength: Buffer.byteLength(content, 'utf8'),
      mode: stat.mode & 0o777,
    };
  } finally {
    if (created) {
      try {
        fs.rmSync(temporary, { force: true });
        syncDirectory(parent);
      }
      catch (error) {
        error.localFileTemporaryCleanupFailed = true;
        throw error;
      }
    }
  }
}

// The effecting writer is private. Native callers present a verified tool
// action; this owner rechecks it, appends the signed material start, performs
// the atomic write, and appends exactly one terminal or leaves an open start.
export async function writeAllowedLocalFile({
  filepath,
  content,
  toolActionAuthority,
  executionContext,
  agentId,
}) {
  const actorAgentId = String(executionContext?.actorAgentId || '');
  if (!actorAgentId || actorAgentId !== String(agentId || '')
      || !executionContext?.actorValidFromIso
      || String(executionContext?.companyId || '') !== AIMOS_COMPANY_ID
      || String(toolActionAuthority?.actorAgentId || '') !== actorAgentId
      || !Number.isFinite(Date.parse(executionContext.actorValidFromIso))
      || Date.parse(executionContext.actorValidFromIso)
        !== Date.parse(toolActionAuthority?.actorValidFromIso)
      || (executionContext?.requestReceiptId ?? null)
        !== (toolActionAuthority?.requestReceiptId ?? null)
      || (executionContext?.requestReceiptMutationHash ?? null)
        !== (toolActionAuthority?.requestReceiptMutationHash ?? null)) {
    throw new Error('local_file_write_actor_epoch_required');
  }
  const verified = await verifyToolActionAuthority(toolActionAuthority, {
    expectedCompanyId: AIMOS_COMPANY_ID,
    expectedTool: 'write_file',
    expectedActorAgentId: actorAgentId,
    expectedArguments: { filepath, content },
  });
  const { requested, parent } = inspectAllowedLocalFileWrite({
    filepath, content, allowedRoots: allowedLocalWriteRoots(),
  });
  const effect = await materialEffectOwner.begin({
    kind: 'filesystem',
    operation: 'local_file_write',
    targetIdentifier: requested,
    inputProjection: localFileWriteInputProjection({
      content, toolActionEventId: verified.actionEventId,
    }),
    subjectAgentId: actorAgentId,
    authority: executionContext,
    parentEventId: verified.actionEventId,
    companyId: AIMOS_COMPANY_ID,
  });
  let written;
  try {
    written = writeAllowedLocalFileNative({
      requested, parent, content, actionId: effect.actionId,
    });
  } catch (error) {
    if (!error.localFileTemporaryCleanupFailed) {
      try {
        await materialEffectOwner.finish({
          action: effect, disposition: 'INDETERMINATE',
          resultProjection: { error_code: String(error?.message || 'local_file_write_failed') },
          resultClass: 'local_file_write_attempt_indeterminate',
        });
      } catch (terminalError) {
        error.materialEffectTerminalError = terminalError?.message || String(terminalError);
      }
    }
    error.httpOutcome = 'INDETERMINATE';
    throw error;
  }
  try {
    await materialEffectOwner.finish({
      action: effect, disposition: 'SUCCEEDED',
      resultProjection: {
        content_sha256: written.contentSha256,
        byte_length: written.byteLength,
        mode: written.mode,
      },
      resultClass: 'local_file_write_committed',
    });
  } catch (error) {
    error.httpOutcome = 'INDETERMINATE';
    throw error;
  }
  return written;
}

function effectMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { return {}; }
}

// The production reconciler has fixed native roots and the signed event owner.
// The factory permits an isolated scratch instance to exercise the same code.
export function createLocalFileWriteOrphanReconciler({
  roots,
  effectOwner,
  verifyStartFn = readVerifiedEventById,
  maxEntries = 250_000,
} = {}) {
  if (!Array.isArray(roots) || !effectOwner?.begin || !effectOwner?.finish
      || typeof verifyStartFn !== 'function'
      || !Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new Error('local_file_orphan_recovery_owner_invalid');
  }
  const scanRoots = roots.map((root) => path.resolve(root));
  // Called only during pre-listen recovery with starts from verified history.
  // No filename is authority by itself: action ID and reconstructed target
  // must match one signed, still-open local_file_write start before deletion.
  return async function reconcileLocalFileWriteOrphansFromVerifiedStarts(verifiedOpenTraces) {
  if (!Array.isArray(verifiedOpenTraces)) {
    throw new Error('local_file_orphan_recovery_input_invalid');
  }
  const starts = new Map();
  for (const trace of verifiedOpenTraces) {
    const metadata = effectMetadata(trace?.start);
    if (metadata.schema !== 'hom.aimos.material-effect/v1'
        || metadata.effect_kind !== 'filesystem'
        || metadata.effect_operation !== 'local_file_write') continue;
    const actionId = String(metadata.action_id || '');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actionId)
        || actionId !== trace.actionId
        || !/^[0-9a-f]{64}$/.test(String(metadata.target_sha256 || ''))
        || !String(trace.start.id || trace.start.event_id || '')) {
      throw new Error('local_file_orphan_start_invalid');
    }
    if (starts.has(actionId)) throw new Error('local_file_orphan_start_duplicate');
    starts.set(actionId, {
      metadata,
      startEventId: String(trace.start.id || trace.start.event_id),
      startMutationHash: typeof trace.start.mutation_hash === 'string'
        ? trace.start.mutation_hash : Buffer.from(trace.start.mutation_hash || []).toString('hex'),
    });
  }
  if (starts.size === 0) return Object.freeze({ scanned: 0, removed: 0, unmatched: 0 });
  let scanned = 0;
  let removed = 0;
  const matched = new Set();
  for (const root of scanRoots) {
    if (!lstatIfExists(root)) continue;
    assertSafeDirectory(root);
    const pending = [root];
    while (pending.length) {
      const directory = pending.pop();
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        scanned += 1;
        if (scanned > maxEntries) throw new Error('local_file_orphan_scan_limit');
        const candidate = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          assertSafeDirectory(candidate);
          pending.push(candidate);
          continue;
        }
        if (!entry.isFile()) continue;
        const match = /^\.(.+)\.aimos-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(entry.name);
        if (!match) continue;
        const start = starts.get(match[2]);
        if (!start) continue;
        const target = path.join(directory, match[1]);
        if (materialEffectTargetHash('filesystem', target) !== start.metadata.target_sha256) continue;
        if (matched.has(match[2])) throw new Error('local_file_orphan_multiple_artifacts');
        const before = fs.lstatSync(candidate);
        if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
            || (before.mode & 0o077) !== 0
            || (typeof process.getuid === 'function' && before.uid !== process.getuid())
            || fs.realpathSync(candidate) !== candidate) {
          throw new Error('local_file_orphan_custody_invalid');
        }
        const verifiedStart = await verifyStartFn(start.startEventId, AIMOS_COMPANY_ID);
        const verifiedMetadata = effectMetadata(verifiedStart);
        const verifiedMutationHash = typeof verifiedStart?.mutation_hash === 'string'
          ? verifiedStart.mutation_hash
          : Buffer.from(verifiedStart?.mutation_hash || []).toString('hex');
        if (verifiedStart?.operation !== 'material_effect_started'
            || verifiedStart?.key !== match[2]
            || String(verifiedStart?.id || verifiedStart?.event_id || '') !== start.startEventId
            || verifiedStart?.company_id !== AIMOS_COMPANY_ID
            || verifiedStart?.signer_agent_id !== 'housekeeper'
            || verifiedMutationHash !== start.startMutationHash
            || verifiedMetadata.schema !== 'hom.aimos.material-effect/v1'
            || verifiedMetadata.effect_kind !== 'filesystem'
            || verifiedMetadata.effect_operation !== 'local_file_write'
            || verifiedMetadata.target_sha256 !== start.metadata.target_sha256) {
          throw new Error('local_file_orphan_start_unverified');
        }
        const cleanup = await effectOwner.begin({
          kind: 'filesystem',
          operation: 'local_file_orphan_cleanup',
          targetIdentifier: candidate,
          inputProjection: {
            recovered_action_id: match[2],
            recovered_start_event_id: start.startEventId,
            original_target_sha256: start.metadata.target_sha256,
          },
          subjectAgentId: 'housekeeper',
        });
        try {
          const current = fs.lstatSync(candidate);
          if (current.dev !== before.dev || current.ino !== before.ino
              || current.nlink !== 1 || current.size !== before.size
              || current.mtimeMs !== before.mtimeMs || current.ctimeMs !== before.ctimeMs) {
            throw new Error('local_file_orphan_changed');
          }
          fs.unlinkSync(candidate);
          syncDirectory(directory);
        } catch (error) {
          // Leave the cleanup start open if its terminal cannot be appended.
          // A later boot will reconcile it as INDETERMINATE without replay.
          try {
            await effectOwner.finish({
              action: cleanup,
              disposition: 'INDETERMINATE',
              resultProjection: { error_code: String(error?.message || 'local_file_orphan_cleanup_failed') },
              resultClass: 'local_file_orphan_cleanup_indeterminate',
            });
          } catch (terminalError) {
            error.materialEffectTerminalError = terminalError?.message || String(terminalError);
          }
          throw error;
        }
        // A failed terminal append leaves a detectable open cleanup start;
        // never turn a possibly committed deletion into a second disposition.
        await effectOwner.finish({
          action: cleanup,
          disposition: 'SUCCEEDED',
          resultProjection: { recovered_action_id: match[2], removed: true },
          resultClass: 'local_file_orphan_removed',
        });
        matched.add(match[2]);
        removed += 1;
      }
    }
  }
  return Object.freeze({ scanned, removed, unmatched: starts.size - matched.size });
  };
}

export const reconcileLocalFileWriteOrphans = createLocalFileWriteOrphanReconciler({
  roots: allowedLocalWriteRoots(),
  effectOwner: materialEffectOwner,
  verifyStartFn: readVerifiedEventById,
});
