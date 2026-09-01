/**
 * Canonical SAVE owner.
 *
 * This module owns the complete ordered SAVE state machine, the restricted
 * transaction, and its signed terminal. It is the only production importer of
 * persistMemory. Callers provide authenticated intent; they cannot inject a
 * database client, security disposition, stage order, or terminal result.
 *
 * Mathematical contract: every stage is an ordered monotonic conjunction.
 * Governing What You Cannot Observe motivates monotonic restriction; later
 * stages may preserve or restrict an earlier decision, never relax it. RPE is
 * a HOM-AIMOS routing adaptation inspired by Sutton--Barto, not the paper's TD
 * error and not an authorization gate.
 */

import { createHash } from 'node:crypto';

import { withTransaction } from '../../db/connection.js';
import { semanticCache } from '../caching/semantic-cache.js';
import { detectEncodingStyle } from '../context/mnemonic-encoder.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { enforceVersionOnlyMemoryPolicy } from '../governance/aladdin-compliance.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { evaluateCanaryWrite } from '../security/canary-write-gate.js';
import { canonicalJson } from '../security/protocol/canonical-json.js';
import { serializeMemoryValue } from '../security/protocol/memory-value.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import {
  detectTierFromCert,
  extractValidFromIso,
  getHousekeeperCert,
} from '../security/housekeeper-signer.js';
import { isCredentialLaneSave } from './credential-lane.js';
import { persistMemory, redactAimosValue } from './persist-memory.js';
import { assessQuality } from './quality-gate.js';
import { computeRPE } from './rpe-gate.js';
import { monitorRPEGateQuality } from './sensible-screening.js';
import { cacheTransformation, computeSchemaHash, getCachedTransformation } from './transformation-cache.js';
import { validateWrite } from './write-validator.js';
import {
  appendCanonicalSaveStage,
  canonicalSaveActionCommitment,
  createCanonicalSaveTrace,
  finalizeCanonicalSaveTrace,
  reconcileOpenCanonicalSaveActionsWithDeps,
  reconstructCanonicalSaveActionTraces,
  verifyCanonicalSaveTrace,
} from './canonical-save-contract.js';

const VALIDATION_EXEMPT_TYPES = new Set([
  'agent_session', 'event_log', 'dream_summary', 'dream_pattern',
  'reasoning_state', 'session_debrief', 'strategic_directive', 'procedural',
  'tacit_knowledge', 'core_belief',
]);
const DATA_CLASS_RANK = Object.freeze({ public: 0, internal: 1, confidential: 2, restricted: 3 });
const HOUSEKEEPER_AUTHORITY_BRAND = Symbol('hom.aimos.verified-housekeeper-save-action');
function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function evidenceHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function safeFailureCode(error, fallback = 'canonical_save_failed') {
  const candidate = String(error?.code || error?.message || fallback)
    .toLowerCase().replace(/[^a-z0-9:_-]+/g, '_').slice(0, 160);
  return candidate || fallback;
}

function authorityKind(authority) {
  if (authority?.kind === 'verified_housekeeper_action'
      && authority[HOUSEKEEPER_AUTHORITY_BRAND] === true) return 'verified_housekeeper_action';
  if (authority?.kind === 'verified_request') return 'verified_request';
  if (authority?.kind === 'verified_tool_action') return 'verified_tool_action';
  return 'invalid';
}

function actorFor(authority, requestedAgentId) {
  if (authorityKind(authority) === 'verified_housekeeper_action') return 'housekeeper';
  return authority?.agentId || authority?.actorAgentId || requestedAgentId || 'unknown';
}

function authorityForEvent(authority) {
  return ['verified_request', 'verified_tool_action'].includes(authorityKind(authority))
    ? authority
    : null;
}

async function resolveAuthority(spec, authority, recallService) {
  const kind = authorityKind(authority);
  if (kind === 'invalid') throw Object.assign(new Error('canonical_save_authority_required'), { stage: 'AUTH' });
  const companyId = String(spec.company_id || AIMOS_COMPANY_ID);
  if (companyId !== AIMOS_COMPANY_ID) {
    throw Object.assign(new Error('canonical_save_company_scope_mismatch'), { stage: 'AUTH' });
  }
  const requestedAgentId = String(spec.agent_id || '').trim();
  if (kind === 'verified_housekeeper_action') {
    const clearance = Number(spec.clearance_level || 1);
    if (!Number.isInteger(clearance) || clearance < 1 || clearance > 12) {
      throw Object.assign(new Error('canonical_save_clearance_invalid'), { stage: 'AUTH' });
    }
    if (authority.actorAgentId !== 'housekeeper'
        || !authority.actorValidFromIso
        || !['T1', 'T1_SYSTEM_SELF'].includes(String(authority.actorIdentityTier).toUpperCase())
        || authority.companyId !== companyId
        || !authority.actionEventId
        || !/^[0-9a-f]{64}$/.test(String(authority.actionMutationHash || ''))
        || !/^[0-9a-f]{64}$/.test(String(authority.actionSha256 || ''))
        || !/^[0-9a-f]{64}$/.test(String(authority.actionContextSha256 || ''))) {
      throw Object.assign(new Error('canonical_save_housekeeper_action_incomplete'), { stage: 'AUTH' });
    }
    return {
      kind,
      companyId,
      actorAgentId: 'housekeeper',
      subjectAgentId: requestedAgentId || 'housekeeper',
      actorValidFromIso: new Date(authority.actorValidFromIso).toISOString(),
      clearanceCeiling: 12,
      dataClassCeiling: 'restricted',
      actionSha256: authority.actionSha256,
      actionContextSha256: authority.actionContextSha256,
    };
  }
  const actorAgentId = String(authority.agentId || authority.actorAgentId || '').trim();
  const actorValidFromIso = authority.validFromIso || authority.actorValidFromIso;
  if (!actorAgentId || !actorValidFromIso) {
    throw Object.assign(new Error('canonical_save_actor_epoch_required'), { stage: 'AUTH' });
  }
  if (requestedAgentId && requestedAgentId !== actorAgentId) {
    throw Object.assign(new Error('canonical_save_agent_identity_mismatch'), { stage: 'AUTH' });
  }
  if (kind === 'verified_request') {
    if (!authority.body || !authority.certString || !Buffer.isBuffer(authority.sigBytes)
        || !authority.requestReceiptId || !authority.requestReceiptMutationHash
        || !authority.requestAdmissionEventId || !authority.requestAdmissionMutationHash
        || !authority.signedMethod || !authority.signedPath) {
      throw Object.assign(new Error('canonical_save_verified_request_incomplete'), { stage: 'AUTH' });
    }
    if (authority.companyId && authority.companyId !== companyId) {
      throw Object.assign(new Error('canonical_save_authority_company_mismatch'), { stage: 'AUTH' });
    }
    if (actorAgentId === 'housekeeper' && ['T1', 'T1_SYSTEM_SELF'].includes(String(authority.identityTier).toUpperCase())) {
      return {
        kind, companyId, actorAgentId, subjectAgentId: actorAgentId,
        actorValidFromIso, clearanceCeiling: 12, dataClassCeiling: 'restricted',
      };
    }
    const grant = await recallService.getEffective({
      companyId,
      subjectAgentId: actorAgentId,
      subjectValidFrom: actorValidFromIso,
    });
    if (!grant?.allowed || !grant.writeAllowed) {
      throw Object.assign(new Error('master_signed_memory_write_grant_required'), { stage: 'AUTH' });
    }
    const requestedClearance = Number(spec.clearance_level || 1);
    if (!Number.isInteger(requestedClearance) || requestedClearance < 1
        || requestedClearance > grant.clearanceCeiling) {
      throw Object.assign(new Error('clearance_exceeds_verified_authority'), { stage: 'AUTH' });
    }
    const requestedDataClass = String(spec.data_class || 'public').trim().toLowerCase();
    if (!(requestedDataClass in DATA_CLASS_RANK)
        || !(grant.dataClassCeiling in DATA_CLASS_RANK)
        || DATA_CLASS_RANK[requestedDataClass] > DATA_CLASS_RANK[grant.dataClassCeiling]) {
      throw Object.assign(new Error('data_class_exceeds_verified_authority'), { stage: 'AUTH' });
    }
    return {
      kind, companyId, actorAgentId, subjectAgentId: actorAgentId,
      actorValidFromIso, clearanceCeiling: grant.clearanceCeiling,
      dataClassCeiling: grant.dataClassCeiling,
      grantMutationHash: Buffer.from(grant.mutationHash).toString('hex'),
    };
  }
  if (!authority.actionEventId || !authority.actionMutationHash) {
    throw Object.assign(new Error('canonical_save_tool_action_incomplete'), { stage: 'AUTH' });
  }
  return {
    kind, companyId, actorAgentId, subjectAgentId: requestedAgentId || actorAgentId,
    actorValidFromIso, clearanceCeiling: Number(spec.clearance_level || 1),
    dataClassCeiling: null,
  };
}

function actionProjection(spec, authority, resolved) {
  const value = serializeMemoryValue(spec.value);
  const requestBodyHash = authority?.kind === 'verified_request'
    ? evidenceHash(authority.body) : null;
  return {
    schema: 'hom.aimos.canonical-save-action/v1',
    company_id: resolved.companyId,
    subject_agent_id: resolved.subjectAgentId,
    actor_agent_id: resolved.actorAgentId,
    actor_valid_from: resolved.actorValidFromIso,
    authority_kind: resolved.kind,
    request_body_sha256: requestBodyHash,
    internal_action_context_sha256: resolved.kind === 'verified_housekeeper_action'
      ? authority.actionContextSha256
      : null,
    value_sha256: sha256(Buffer.from(value, 'utf8')),
    key: String(spec.key || ''),
    memory_type: String(spec.memory_type || 'declarative'),
    source: String(spec.source || 'canonical-save'),
    scope: String(spec.scope || 'global'),
    clearance_level: Number(spec.clearance_level || 1),
    session_id: spec.session_id || null,
  };
}

async function bindReceipt({ spec, authority, resolved, actionSha256, logEventFn }) {
  if (resolved.kind === 'verified_request') {
    return {
      parentEventId: authority.requestAdmissionEventId,
      evidence: {
        kind: 'verified_request_receipt',
        request_receipt_id: String(authority.requestReceiptId),
        request_receipt_mutation_hash: String(authority.requestReceiptMutationHash),
        request_admission_event_id: String(authority.requestAdmissionEventId),
        request_admission_mutation_hash: String(authority.requestAdmissionMutationHash),
      },
    };
  }
  if (resolved.kind === 'verified_tool_action') {
    return {
      parentEventId: authority.actionEventId,
      evidence: {
        kind: 'verified_tool_action',
        action_event_id: String(authority.actionEventId),
        action_mutation_hash: String(authority.actionMutationHash),
      },
    };
  }
  if (resolved.kind === 'verified_housekeeper_action') {
    if (authority.actionSha256 !== actionSha256) {
      throw new Error('canonical_save_housekeeper_action_commitment_mismatch');
    }
    return {
      parentEventId: authority.actionEventId,
      evidence: {
        kind: 'verified_housekeeper_action',
        event_id: authority.actionEventId,
        mutation_hash: authority.actionMutationHash,
        action_sha256: authority.actionSha256,
        action_context_sha256: authority.actionContextSha256,
      },
    };
  }
  throw new Error('canonical_save_receipt_authority_invalid');
}

async function appendTerminal({ spec, authority, resolved, trace, outcome, failedStage, failureCode, parentEventId, terminalEvidence, client = null, logEventFn }) {
  const finalized = finalizeCanonicalSaveTrace(trace, {
    outcome,
    failedStage,
    failureCode,
    terminalEvidence,
  });
  const verification = verifyCanonicalSaveTrace(finalized);
  if (!verification.valid) throw new Error(`canonical_save_trace_self_check_failed:${verification.reason}`);
  const receipt = await logEventFn(resolved?.companyId || AIMOS_COMPANY_ID,
    resolved?.subjectAgentId || actorFor(authority, spec.agent_id),
    'canonical_save_terminal', String(spec.key || ''), {
      ...finalized,
      failed_stage: failedStage,
      failure_code: failureCode,
      reasoning: outcome === 'SUCCESS'
        ? 'The canonical SAVE transaction committed every mandatory stage and this signed terminal atomically with the memory evidence.'
        : 'The canonical SAVE owner retained a signed non-success terminal and did not emit a success result.',
      source_knowledge: 'canonical-save-owner.js — I3/I4/I6 terminal contract',
    }, parentEventId, {
      client,
      authority: authorityForEvent(authority),
      returnReceipt: true,
    });
  return { trace: finalized, receipt };
}

function appendFailureAtCurrentStage(trace, stage, status, code, evidence = {}) {
  const expected = trace.stages.length;
  const target = ['AUTH', 'RECEIPT', 'CANARY', 'SE', 'ALADDIN', 'VALIDATOR', 'QUALITY',
    'SECRET_BOUNDARY', 'EMBEDDING', 'PERSISTENCE', 'PROVENANCE', 'LINEAGE', 'GRAPH', 'EPISTEMIC']
    .indexOf(stage);
  while (trace.stages.length < target) {
    const missing = ['AUTH', 'RECEIPT', 'CANARY', 'SE', 'ALADDIN', 'VALIDATOR', 'QUALITY',
      'SECRET_BOUNDARY', 'EMBEDDING', 'PERSISTENCE', 'PROVENANCE', 'LINEAGE', 'GRAPH', 'EPISTEMIC'][trace.stages.length];
    appendCanonicalSaveStage(trace, missing, 'INDETERMINATE_ROLLED_BACK', { failure_code: code });
  }
  if (trace.stages.length === target) {
    appendCanonicalSaveStage(trace, stage, status, { failure_code: code, ...evidence });
  } else if (expected > target) {
    throw new Error('canonical_save_failure_stage_regression');
  }
}

const DEFAULT_SAVE_DEPS = Object.freeze({
  withTransaction,
  semanticCache,
  detectEncodingStyle,
  enforceVersionOnlyMemoryPolicy,
  logEvent,
  evaluateCanaryWrite,
  recallAuthorizationService,
  persistMemory,
  assessQuality,
  computeRPE,
  monitorRPEGateQuality,
  cacheTransformation,
  computeSchemaHash,
  getCachedTransformation,
  validateWrite,
});

/** Create the only canonical SAVE contract owner; overrides are for isolated proof only. */
export function createCanonicalSaveOwner(overrides = {}) {
  const deps = Object.freeze({ ...DEFAULT_SAVE_DEPS, ...overrides });
  return async function executeCanonicalSaveOwned(input = {}) {
  const spec = { ...input };
  const authority = spec.mutation_authority;
  delete spec.client;
  delete spec.canary_disposition;
  delete spec.security_disposition;
  delete spec.mutation_authority;
  const provisionalProjection = {
    schema: 'hom.aimos.canonical-save-action-unverified/v1',
    company_id: String(spec.company_id || AIMOS_COMPANY_ID),
    subject_agent_id: String(spec.agent_id || ''),
    authority_kind: authorityKind(authority),
    key: String(spec.key || ''),
    value_sha256: sha256(Buffer.from(serializeMemoryValue(spec.value), 'utf8')),
  };
  let actionSha256 = canonicalSaveActionCommitment(provisionalProjection);
  let trace = createCanonicalSaveTrace(actionSha256);
  let resolved = null;
  let receiptBinding = { parentEventId: null, evidence: null };
  let currentParentEventId = null;

  const reject = async (stage, reason, httpStatus = 400, status = 'REJECTED', evidence = {}) => {
    appendFailureAtCurrentStage(trace, stage, status, reason, evidence);
    const terminal = await appendTerminal({
      spec, authority, resolved, trace,
      outcome: status === 'REJECTED' ? 'REJECTED' : 'FAILED',
      failedStage: stage,
      failureCode: reason,
      parentEventId: currentParentEventId,
      terminalEvidence: { domain_mutation_committed: false },
      logEventFn: deps.logEvent,
    });
    return {
      rejected: true,
      reason,
      http_status: httpStatus,
      canonical_save_trace: terminal.trace,
      terminal_receipt: terminal.receipt,
    };
  };

  try {
    resolved = await resolveAuthority(spec, authority, deps.recallAuthorizationService);
    const projection = actionProjection(spec, authority, resolved);
    actionSha256 = canonicalSaveActionCommitment(projection);
    trace = createCanonicalSaveTrace(actionSha256);
    appendCanonicalSaveStage(trace, 'AUTH', 'PASS', {
      authority_kind: resolved.kind,
      actor_agent_id: resolved.actorAgentId,
      actor_valid_from: resolved.actorValidFromIso,
      subject_agent_id: resolved.subjectAgentId,
      clearance_ceiling: resolved.clearanceCeiling,
      data_class_ceiling: resolved.dataClassCeiling,
      grant_mutation_hash: resolved.grantMutationHash || null,
      action_sha256: resolved.actionSha256 || null,
      action_context_sha256: resolved.actionContextSha256 || null,
    });
  } catch (error) {
    resolved = {
      companyId: AIMOS_COMPANY_ID,
      subjectAgentId: actorFor(authority, spec.agent_id),
      actorAgentId: actorFor(authority, spec.agent_id),
    };
    return reject('AUTH', safeFailureCode(error), 403);
  }

  try {
    receiptBinding = await bindReceipt({ spec, authority, resolved, actionSha256, logEventFn: deps.logEvent });
    currentParentEventId = receiptBinding.parentEventId;
    appendCanonicalSaveStage(trace, 'RECEIPT', 'PASS', receiptBinding.evidence);
  } catch (error) {
    return reject('RECEIPT', safeFailureCode(error), 503, 'FAILED');
  }

  let canaryDecision;
  try {
    canaryDecision = await deps.evaluateCanaryWrite({
      key: spec.key,
      value: spec.value,
      companyId: resolved.companyId,
      agentId: resolved.subjectAgentId,
      runId: authority?.requestReceiptId || receiptBinding.evidence?.event_id || '',
      authority: authorityForEvent(authority),
      parentEventId: currentParentEventId,
    });
    currentParentEventId = canaryDecision.event_receipt?.event_id || currentParentEventId;
    appendCanonicalSaveStage(trace, 'CANARY', canaryDecision.quarantine ? 'RETAIN_QUARANTINE' : 'PASS', {
      detected: Boolean(canaryDecision.detected),
      marker_count: canaryDecision.tokens?.length || 0,
      event_id: canaryDecision.event_receipt?.event_id || null,
      mutation_hash: canaryDecision.event_receipt?.mutation_hash || null,
    });
  } catch (error) {
    return reject('CANARY', safeFailureCode(error), 503, 'FAILED');
  }

  appendCanonicalSaveStage(trace, 'SE', 'DISABLED', {
    runtime_authority: false,
    reason: 'operator_disabled',
  });

  const aladdin = deps.enforceVersionOnlyMemoryPolicy({
    key: spec.key,
    value: spec.value,
    source: spec.source,
    memoryType: spec.memory_type,
    isCorrection: spec.is_correction,
    supersedesId: spec.supersedes_id,
    verifyTargetId: spec.verify_target_id,
    verifyTargetKey: spec.verify_target_key,
  });
  if (aladdin.status === 'blocked_requires_supersession') {
    return reject('ALADDIN', aladdin.reason || 'aladdin_supersession_required', 409);
  }
  appendCanonicalSaveStage(trace, 'ALADDIN', 'PASS', {
    retention: 'long_term',
    deletion: false,
    policy_status: aladdin.status || 'pass',
  });

  const validationExempt = VALIDATION_EXEMPT_TYPES.has(String(spec.memory_type || ''));
  if (validationExempt) {
    appendCanonicalSaveStage(trace, 'VALIDATOR', 'EXEMPT', {
      reason: 'explicit_internal_memory_type',
      memory_type: String(spec.memory_type || ''),
    });
  } else {
    let validation;
    try {
      validation = await deps.validateWrite(
        resolved.subjectAgentId,
        spec.key,
        serializeMemoryValue(spec.value),
        undefined,
        resolved.kind === 'verified_housekeeper_action'
          ? {
              identityTier: 'T1',
              verifiedAgentId: 'housekeeper',
            }
          : {
              identityTier: authority.identityTier,
              verifiedAgentId: resolved.actorAgentId,
              executionContext: {
                actorAgentId: resolved.actorAgentId,
                actorValidFromIso: resolved.actorValidFromIso,
                identityTier: authority.identityTier,
                companyId: resolved.companyId,
              },
            },
      );
    } catch (error) {
      return reject('VALIDATOR', 'write_validator_unavailable', 503, 'FAILED', {
        error_class: error?.name || 'Error',
      });
    }
    if (!validation.valid) {
      return reject('VALIDATOR', validation.reason || 'write_validation_failed', validation.retryable ? 503 : 400);
    }
    appendCanonicalSaveStage(trace, 'VALIDATOR', 'PASS', {
      diagnostics_sha256: evidenceHash(validation.diagnostics || {}),
      retryable: false,
    });
  }

  const securityInput = serializeMemoryValue(spec.value);
  const safeValue = redactAimosValue(spec.value);
  const quality = deps.assessQuality(spec.key, safeValue, spec.memory_type, {
    agent_id: resolved.subjectAgentId,
    source: spec.source,
    scope: spec.scope,
    clearance_level: spec.clearance_level,
  });
  if (!quality.pass) {
    return reject('QUALITY', quality.reason || 'quality_gate_rejected', 422, 'REJECTED', {
      quality_score: quality.score,
      walls_sha256: evidenceHash(quality.walls || {}),
    });
  }
  appendCanonicalSaveStage(trace, 'QUALITY', 'PASS', {
    quality_score: quality.score,
    walls_sha256: evidenceHash(quality.walls || {}),
  });

  const credentialLane = isCredentialLaneSave(spec);
  if (authority?.kind === 'verified_request' && safeValue !== securityInput && !credentialLane) {
    return reject('SECRET_BOUNDARY', 'secret_material_requires_credential_lane', 422);
  }
  appendCanonicalSaveStage(trace, 'SECRET_BOUNDARY', credentialLane ? 'CREDENTIAL_ISOLATED' : safeValue !== securityInput ? 'REDACTED' : 'PASS', {
    sensitive_lane_isolated: credentialLane,
    redaction_applied: safeValue !== securityInput,
  });

  const diagnostics = { rpe: null, encoding: null, transformation_cache: null, sensible_screening: null };
  let pendingTransform = null;
  if (credentialLane) {
    // The credential lane is decided before every diagnostic consumer. The
    // plaintext may reach only signed custody/Keychain and the native
    // credential transaction. It must never be embedded, scored, encoded,
    // transformed, cached, graphed, or sent to a provider as a diagnostic.
    diagnostics.rpe = { status: 'SKIPPED_CREDENTIAL_LANE' };
    diagnostics.sensible_screening = { status: 'SKIPPED_CREDENTIAL_LANE' };
    diagnostics.encoding = { style: null, status: 'SKIPPED_CREDENTIAL_LANE' };
    diagnostics.transformation_cache = { status: 'SKIPPED_CREDENTIAL_LANE' };
  } else {
    try {
      diagnostics.rpe = await deps.computeRPE(securityInput, resolved.companyId, { memoryType: spec.memory_type });
    } catch (error) {
      diagnostics.rpe = { status: 'DEGRADED', error_code: safeFailureCode(error, 'rpe_unavailable') };
    }
    try {
      diagnostics.sensible_screening = await deps.monitorRPEGateQuality(resolved.companyId);
    } catch (error) {
      diagnostics.sensible_screening = { status: 'DEGRADED', error_code: safeFailureCode(error, 'sensible_screening_unavailable') };
    }
    try {
      diagnostics.encoding = deps.detectEncodingStyle(spec.value, spec.memory_type || '');
    } catch (error) {
      diagnostics.encoding = { style: null, status: 'DEGRADED', error_code: safeFailureCode(error, 'mnemonic_unavailable') };
    }
    try {
      const valueObject = typeof spec.value === 'string' ? { raw: spec.value } : (spec.value || {});
      const inputHash = deps.computeSchemaHash(Object.fromEntries(Object.keys(valueObject).map((key) => [key, typeof valueObject[key]])));
      const outputHash = deps.computeSchemaHash({ memory_type: spec.memory_type || 'episodic', scope: spec.scope || 'agent' });
      const cached = await deps.getCachedTransformation(inputHash, outputHash);
      pendingTransform = cached ? null : { inputHash, outputHash };
      diagnostics.transformation_cache = { hit: Boolean(cached), input_hash: inputHash, output_hash: outputHash };
    } catch (error) {
      diagnostics.transformation_cache = { status: 'DEGRADED', error_code: safeFailureCode(error, 'transformation_cache_unavailable') };
    }
  }

  const transactionBaseStages = [...trace.stages];
  let committed;
  try {
    committed = await deps.withTransaction(async (client) => {
      const protectedHead = await client.query(
        `SELECT clearance_level FROM aimos_memories
          WHERE company_id=$1 AND key=$2 AND clearance_level>=12
          LIMIT 1`,
        [resolved.companyId, spec.key],
      );
      if (protectedHead.rows[0] && resolved.clearanceCeiling < 12) {
        const error = new Error('sudo_protected_memory');
        throw error;
      }
      const saved = await deps.persistMemory({
        ...spec,
        company_id: resolved.companyId,
        agent_id: resolved.subjectAgentId,
        canary_disposition: {
          decision: canaryDecision,
          receipt: canaryDecision.event_receipt,
        },
        mutation_authority: authority,
        client,
      });
      if (saved?.rejected || !saved?.id) {
        const error = new Error(saved?.reason || 'canonical_persistence_rejected');
        error.stage = saved?.reason === 'secret_material_requires_credential_lane' ? 'SECRET_BOUNDARY' : 'QUALITY';
        error.rejectedResult = saved;
        throw error;
      }
      appendCanonicalSaveStage(trace, 'EMBEDDING', saved.embedding_disposition?.degraded ? 'DEGRADED' : 'PASS', {
        ...(saved.embedding_disposition || {}),
      });
      appendCanonicalSaveStage(trace, 'PERSISTENCE', saved.occurrence_reasserted ? 'NO_OP_REASSERT' : 'COMMITTED', {
        memory_id: saved.id,
        live_content_hash: saved.live_content_hash?.toString('hex') || null,
        occurrence_reasserted: saved.occurrence_reasserted === true,
      });
      appendCanonicalSaveStage(trace, 'PROVENANCE', 'COMMITTED', {
        save_mutation_hash: saved.ledger_commit?.mutationHash?.toString('hex') || saved.credential_ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: saved.binding_commit?.mutationHash?.toString('hex') || null,
        envelope_mutation_hash: saved.envelope_commit?.chainHash?.toString('hex') || null,
      });
      appendCanonicalSaveStage(trace, 'LINEAGE', saved.lineage_disposition?.status || 'NO_OP', saved.lineage_disposition || {});
      appendCanonicalSaveStage(trace, 'GRAPH', saved.graph_disposition?.status || 'NO_OP', saved.graph_disposition || {});
      appendCanonicalSaveStage(trace, 'EPISTEMIC', saved.epistemic_transition_appended ? 'COMMITTED' : 'RETAINED_EXISTING', {
        event_id: saved.epistemic_classification_event_id || null,
        classification_hash: saved.epistemic_classification_hash || null,
        label: saved.epistemic_label || 'unverified',
      });
      const terminal = await appendTerminal({
        spec, authority, resolved, trace,
        outcome: 'SUCCESS',
        failedStage: null,
        failureCode: null,
        parentEventId: currentParentEventId,
        terminalEvidence: {
          domain_mutation_committed: true,
          memory_id: saved.id,
          live_content_hash: saved.live_content_hash?.toString('hex') || null,
          save_mutation_hash: saved.ledger_commit?.mutationHash?.toString('hex') || null,
          binding_mutation_hash: saved.binding_commit?.mutationHash?.toString('hex') || null,
          epistemic_event_id: saved.epistemic_classification_event_id || null,
        },
        client,
        logEventFn: deps.logEvent,
      });
      return { saved, terminal };
    }, {
      restricted: true,
      client_id: resolved.companyId,
      agent_id: resolved.subjectAgentId,
      knowledge_proof: spec.knowledge_proof,
    });
  } catch (error) {
    trace = createCanonicalSaveTrace(actionSha256);
    for (const entry of transactionBaseStages) {
      appendCanonicalSaveStage(trace, entry.stage, entry.status, entry.evidence);
    }
    const stage = error.stage || (error.provenanceReason || error.envelopeReason ? 'PROVENANCE' : 'PERSISTENCE');
    const code = safeFailureCode(error);
    if (error.rejectedResult) {
      return reject(stage, code, stage === 'QUALITY' || stage === 'SECRET_BOUNDARY' ? 422 : 400);
    }
    appendFailureAtCurrentStage(trace, stage, 'FAILED', code, { transaction_rolled_back: true });
    const terminal = await appendTerminal({
      spec, authority, resolved, trace,
      outcome: 'FAILED', failedStage: stage, failureCode: code,
      parentEventId: currentParentEventId,
      terminalEvidence: { domain_mutation_committed: false, transaction_rolled_back: true },
      logEventFn: deps.logEvent,
    });
    error.canonicalSaveTerminal = terminal.receipt;
    error.canonicalSaveTrace = terminal.trace;
    throw error;
  }

  if (pendingTransform) {
    try {
      await deps.cacheTransformation(pendingTransform.inputHash, pendingTransform.outputHash, {
        memory_id: committed.saved.id,
        memory_tier: committed.saved.memory_tier,
        encoding_style: diagnostics.encoding?.style || null,
      });
    } catch (error) {
      diagnostics.transformation_cache = {
        ...diagnostics.transformation_cache,
        store_status: 'DEGRADED',
        store_error_code: safeFailureCode(error, 'transformation_cache_store_unavailable'),
      };
    }
  }
  deps.semanticCache.invalidate('canonical_save_commit');
  return {
    ...committed.saved,
    canonical_save_trace: committed.terminal.trace,
    terminal_receipt: committed.terminal.receipt,
    save_diagnostics: diagnostics,
  };
  };
}

export const executeCanonicalSave = createCanonicalSaveOwner();

/**
 * Typed autonomous entrypoint. The caller supplies only the SAVE intent; this
 * owner derives and signs an exact Housekeeper action before invoking the same
 * canonical pipeline. A route cannot turn request data into Housekeeper
 * authority by setting a field on the SAVE body.
 */
export function createHousekeeperCanonicalSaveOwner(overrides = {}) {
  const executeSaveFn = overrides.executeCanonicalSave || executeCanonicalSave;
  const logEventFn = overrides.logEvent || logEvent;
  const getHousekeeperCertFn = overrides.getHousekeeperCert || getHousekeeperCert;
  return async function executeHousekeeperCanonicalSaveOwned(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('housekeeper_save_spec_invalid');
  }
  if (Object.hasOwn(input, 'mutation_authority')
      || Object.hasOwn(input, 'client')
      || Object.hasOwn(input, 'security_disposition')) {
    throw new Error('housekeeper_save_authority_injection_forbidden');
  }
  const spec = { ...input };
  const companyId = String(spec.company_id || AIMOS_COMPANY_ID);
  const subjectAgentId = String(spec.agent_id || 'housekeeper').trim();
  const source = String(spec.source || '').trim();
  const key = String(spec.key || '').trim();
  if (companyId !== AIMOS_COMPANY_ID) throw new Error('housekeeper_save_company_scope_mismatch');
  if (!subjectAgentId) throw new Error('housekeeper_save_subject_required');
  if (!source) throw new Error('housekeeper_save_source_required');
  if (!key) throw new Error('housekeeper_save_key_required');

  const certString = await getHousekeeperCertFn();
  const actorValidFromIso = extractValidFromIso(certString);
  const actorIdentityTier = detectTierFromCert(certString);
  if (!actorValidFromIso
      || !['T1', 'T1_SYSTEM_SELF'].includes(String(actorIdentityTier).toUpperCase())) {
    throw new Error('housekeeper_save_identity_epoch_invalid');
  }
  const actionContext = {
    schema: 'hom.aimos.housekeeper-save-action-context/v1',
    company_id: companyId,
    subject_agent_id: subjectAgentId,
    source,
    key,
    memory_type: String(spec.memory_type || 'declarative'),
    session_id: spec.session_id || null,
  };
  const actionContextSha256 = evidenceHash(actionContext);
  const provisionalAuthority = {
    kind: 'verified_housekeeper_action',
    actorAgentId: 'housekeeper',
    actorValidFromIso,
    actorIdentityTier,
    companyId,
    actionContextSha256,
  };
  Object.defineProperty(provisionalAuthority, HOUSEKEEPER_AUTHORITY_BRAND, {
    value: true,
    enumerable: false,
  });
  const resolved = await resolveAuthority(spec, {
    ...provisionalAuthority,
    actionEventId: 'pending',
    actionMutationHash: '0'.repeat(64),
    actionSha256: '0'.repeat(64),
    [HOUSEKEEPER_AUTHORITY_BRAND]: true,
  }, recallAuthorizationService);
  const actionSha256 = canonicalSaveActionCommitment(actionProjection(
    spec,
    provisionalAuthority,
    resolved,
  ));
  const actionReceipt = await logEventFn(
    companyId,
    subjectAgentId,
    'canonical_save_action_started',
    key,
    {
      schema: 'hom.aimos.canonical-save-action-start/v2',
      action_sha256: actionSha256,
      action_context_sha256: actionContextSha256,
      source,
      memory_type: String(spec.memory_type || 'declarative'),
      reasoning: 'Housekeeper committed the exact autonomous SAVE action projection before any canonical SAVE stage executed.',
      source_knowledge: 'canonical-save-owner.js — typed Housekeeper action ownership',
    },
    null,
    { returnReceipt: true },
  );
  if (actionReceipt.signer_agent_id !== 'housekeeper'
      || new Date(actionReceipt.signer_valid_from).toISOString() !== actorValidFromIso) {
    throw new Error('housekeeper_save_action_signer_mismatch');
  }
  const authority = {
    ...provisionalAuthority,
    actionEventId: actionReceipt.event_id,
    actionMutationHash: actionReceipt.mutation_hash,
    actionSha256,
  };
  Object.defineProperty(authority, HOUSEKEEPER_AUTHORITY_BRAND, {
    value: true,
    enumerable: false,
  });
  Object.freeze(authority);
  return executeSaveFn({ ...spec, mutation_authority: authority });
  };
}

export const executeHousekeeperCanonicalSave = createHousekeeperCanonicalSaveOwner();

export { reconstructCanonicalSaveActionTraces };

export async function reconcileOpenCanonicalSaveActions({
  companyId = AIMOS_COMPANY_ID,
  events = null,
  readHistoryFn = readVerifiedEventHistory,
  logEventFn = logEvent,
} = {}) {
  return reconcileOpenCanonicalSaveActionsWithDeps({
    companyId, events, readHistoryFn, logEventFn,
  });
}

export default executeCanonicalSave;
