// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: native filesystem, provider, MCP, process and security owners
// → Calls: observe/event-ledger.js
// Pipeline: CR7 durable-action trace | Position: non-database effect owner
// Sources: RFC 6962 tamper-evident logging; RFC 8032 Ed25519; RFC 8785 JCS.
// This service changes no retrieval, ranking, security-classification or
// paper-derived mathematical formula. It commits only non-reconstructive hashes.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash, randomUUID } from 'node:crypto';

import { canonicalJson } from './agent-identity.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

const SCHEMA = 'hom.aimos.material-effect/v1';
const START_OPERATION = 'material_effect_started';
const TERMINAL_OPERATION = 'material_effect_terminal';
const EFFECT_KINDS = new Set(['filesystem', 'external', 'process']);
const DISPOSITIONS = new Set(['SUCCEEDED', 'FAILED', 'INDETERMINATE']);
const MAX_RECOVERY_EVENTS = 100_000;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function materialEffectProjectionHash(value) {
  return sha256(Buffer.from(canonicalJson(value ?? null), 'utf8'));
}

export function materialEffectTargetHash(kind, targetIdentifier) {
  const normalizedKind = String(kind || '').trim().toLowerCase();
  const target = String(targetIdentifier || '').trim();
  if (!EFFECT_KINDS.has(normalizedKind) || !target) {
    throw new Error('material_effect_target_invalid');
  }
  return sha256(Buffer.from(`HOM-AIMOS-MATERIAL-EFFECT-TARGET-v1\0${normalizedKind}\0${target}`, 'utf8'));
}

function metadataOf(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { return {}; }
}

function mutationHashOf(receiptOrRow) {
  const value = receiptOrRow?.mutation_hash;
  if (typeof value === 'string') return value;
  return Buffer.from(value || []).toString('hex');
}

export function reconstructMaterialEffectTraces(rows = []) {
  if (!Array.isArray(rows) || rows.length > MAX_RECOVERY_EVENTS) throw new Error('material_effect_recovery_limit');
  const actions = new Map();
  for (const row of rows) {
    if (row?.operation !== START_OPERATION && row?.operation !== TERMINAL_OPERATION) continue;
    const metadata = metadataOf(row);
    if (metadata.schema !== SCHEMA) continue;
    const actionId = String(metadata.action_id || row.key || '');
    if (!actionId || String(row.key || '') !== actionId) {
      throw new Error('material_effect_action_key_mismatch');
    }
    const current = actions.get(actionId) || { actionId, start: null, terminal: null };
    if (row.operation === START_OPERATION) {
      if (current.start) throw new Error('material_effect_start_fork');
      if (!EFFECT_KINDS.has(String(metadata.effect_kind || ''))
          || !/^[0-9a-f]{64}$/.test(String(metadata.target_sha256 || ''))
          || !/^[0-9a-f]{64}$/.test(String(metadata.input_sha256 || ''))) {
        throw new Error('material_effect_start_malformed');
      }
      current.start = row;
    } else {
      if (current.terminal) throw new Error('material_effect_terminal_fork');
      if (!DISPOSITIONS.has(String(metadata.disposition || ''))
          || !/^[0-9a-f]{64}$/.test(String(metadata.result_sha256 || ''))
          || !metadata.start_event_id
          || !/^[0-9a-f]{64}$/.test(String(metadata.start_mutation_hash || ''))) {
        throw new Error('material_effect_terminal_malformed');
      }
      current.terminal = row;
    }
    actions.set(actionId, current);
  }

  const complete = [];
  const open = [];
  const orderedActions = [...actions.values()]
    .sort((left, right) => left.actionId.localeCompare(right.actionId));
  for (const action of orderedActions) {
    if (!action.start) throw new Error('material_effect_terminal_without_start');
    if (!action.terminal) {
      open.push(action);
      continue;
    }
    const startMetadata = metadataOf(action.start);
    const terminalMetadata = metadataOf(action.terminal);
    if (String(action.terminal.parent_event_id || '') !== String(action.start.id || action.start.event_id || '')
        || terminalMetadata.start_event_id !== String(action.start.id || action.start.event_id || '')
        || terminalMetadata.start_mutation_hash !== mutationHashOf(action.start)
        || terminalMetadata.effect_kind !== startMetadata.effect_kind
        || terminalMetadata.effect_operation !== startMetadata.effect_operation
        || terminalMetadata.target_sha256 !== startMetadata.target_sha256
        || terminalMetadata.input_sha256 !== startMetadata.input_sha256) {
      throw new Error('material_effect_terminal_start_binding_invalid');
    }
    complete.push(action);
  }
  return Object.freeze({
    actionCount: actions.size,
    complete: Object.freeze(complete),
    open: Object.freeze(open),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export function createMaterialEffectOwner({
  logEventFn = logEvent,
  readEventHistoryFn = readVerifiedEventHistory,
  uuidFn = randomUUID,
} = {}) {
  async function begin({
    kind,
    operation,
    targetIdentifier,
    inputProjection,
    subjectAgentId = null,
    authority = null,
    parentEventId = null,
    companyId = AIMOS_COMPANY_ID,
  } = {}) {
    const effectKind = String(kind || '').trim().toLowerCase();
    const effectOperation = String(operation || '').trim();
    if (!EFFECT_KINDS.has(effectKind) || !effectOperation) {
      throw new Error('material_effect_start_invalid');
    }
    const actionId = uuidFn();
    const authorityActor = String(authority?.actorAgentId || authority?.agentId || '').trim();
    const authorityValidFrom = authority?.actorValidFromIso || authority?.validFromIso || null;
    const verifiedAuthority = authorityActor && authorityValidFrom ? authority : null;
    const targetSha256 = materialEffectTargetHash(effectKind, targetIdentifier);
    const inputSha256 = materialEffectProjectionHash(inputProjection);
    const subject = String(verifiedAuthority ? authorityActor : (subjectAgentId || 'housekeeper')).trim();
    if (subject !== 'housekeeper' && !verifiedAuthority) {
      throw new Error('material_effect_verified_request_authority_required');
    }
    const receipt = await logEventFn(companyId, subject, START_OPERATION, actionId, {
      schema: SCHEMA,
      action_id: actionId,
      effect_kind: effectKind,
      effect_operation: effectOperation,
      target_sha256: targetSha256,
      input_sha256: inputSha256,
      parent_request_receipt_id: verifiedAuthority?.requestReceiptId || null,
      parent_request_receipt_mutation_hash: verifiedAuthority?.requestReceiptMutationHash || null,
      reasoning: 'The Housekeeper signed the exact non-reconstructive target and input projection before allowing one material effect attempt.',
      source_knowledge: 'material-effect-owner.js — RFC 6962 / RFC 8032 / RFC 8785',
    }, parentEventId, { authority: verifiedAuthority, returnReceipt: true, exclusiveOperationKey: true });
    return Object.freeze({
      actionId,
      kind: effectKind,
      operation: effectOperation,
      targetSha256,
      inputSha256,
      subjectAgentId: subject,
      companyId,
      authority: verifiedAuthority,
      receipt,
    });
  }

  async function finish({ action, disposition, resultProjection, resultClass = null } = {}) {
    const normalizedDisposition = String(disposition || '').trim().toUpperCase();
    if (!action?.actionId || !action?.receipt?.event_id || !DISPOSITIONS.has(normalizedDisposition)) {
      throw new Error('material_effect_terminal_invalid');
    }
    const resultSha256 = materialEffectProjectionHash(resultProjection);
    return logEventFn(action.companyId, action.subjectAgentId, TERMINAL_OPERATION, action.actionId, {
      schema: SCHEMA,
      action_id: action.actionId,
      effect_kind: action.kind,
      effect_operation: action.operation,
      target_sha256: action.targetSha256,
      input_sha256: action.inputSha256,
      start_event_id: action.receipt.event_id,
      start_mutation_hash: action.receipt.mutation_hash,
      disposition: normalizedDisposition,
      result_sha256: resultSha256,
      result_class: String(resultClass || normalizedDisposition.toLowerCase()),
      reasoning: 'The Housekeeper signed one terminal disposition bound to the exact material-effect start and result projection.',
      source_knowledge: 'material-effect-owner.js — append-only signed terminal',
    }, action.receipt.event_id, {
      authority: action.authority,
      returnReceipt: true,
      exclusiveOperationKey: true,
    });
  }

  async function findOpen({ companyId = AIMOS_COMPANY_ID } = {}) {
    const rows = await readEventHistoryFn(companyId, { signerAgentId: 'housekeeper' });
    return reconstructMaterialEffectTraces(rows).open;
  }

  async function reconcileOpen({ companyId = AIMOS_COMPANY_ID } = {}) {
    const rows = await readEventHistoryFn(companyId, { signerAgentId: 'housekeeper' });
    const before = reconstructMaterialEffectTraces(rows);
    const reconciled = [];
    for (const trace of before.open) {
      const metadata = metadataOf(trace.start);
      const startEventId = String(trace.start.id || trace.start.event_id || '');
      const action = Object.freeze({
        actionId: trace.actionId,
        kind: metadata.effect_kind,
        operation: metadata.effect_operation,
        targetSha256: metadata.target_sha256,
        inputSha256: metadata.input_sha256,
        subjectAgentId: String(trace.start.agent_id || trace.start.subject_agent_id || 'housekeeper'),
        companyId: String(trace.start.company_id || companyId),
        authority: null,
        receipt: Object.freeze({
          event_id: startEventId,
          mutation_hash: mutationHashOf(trace.start),
        }),
      });
      try {
        const receipt = await finish({
          action,
          disposition: 'INDETERMINATE',
          resultProjection: {
            start_event_id: startEventId,
            recovery_reason: 'process_restart_orphan',
            external_effect_replayed: false,
          },
          resultClass: 'process_restart_orphan_reconciled_without_replay',
        });
        reconciled.push(Object.freeze({ actionId: trace.actionId, receipt }));
      } catch (error) {
        if (error?.message !== 'event_operation_key_exists') throw error;
        const racedRows = await readEventHistoryFn(companyId, { signerAgentId: 'housekeeper' });
        const raced = reconstructMaterialEffectTraces(racedRows).complete
          .find((entry) => entry.actionId === trace.actionId);
        if (!raced) throw new Error('material_effect_recovery_race_unverified');
        reconciled.push(Object.freeze({ actionId: trace.actionId, existing: true }));
      }
    }
    const afterRows = await readEventHistoryFn(companyId, { signerAgentId: 'housekeeper' });
    const after = reconstructMaterialEffectTraces(afterRows);
    return Object.freeze({
      scanned: before.actionCount,
      reconciled: Object.freeze(reconciled),
      remainingOpen: after.open.length,
      externalEffectsReplayed: 0,
      timeComplexity: 'O(n)',
      spaceComplexity: 'O(n)',
    });
  }

  return Object.freeze({ begin, finish, findOpen, reconcileOpen });
}

export const materialEffectOwner = createMaterialEffectOwner();

export default materialEffectOwner;
