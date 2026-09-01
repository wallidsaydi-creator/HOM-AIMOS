// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js and canonical mutations caused by tools
// → Calls: observe/event-ledger.js
// Pipeline: TOOL EXECUTION | Position: signed derived-action authority
// Sources: RFC 6962 tamper-evident logging; RFC 8032 Ed25519; confused-deputy
// authority discipline. This service changes no retrieval/ranking mathematics.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

import { canonicalJson } from '../security/agent-identity.js';
import { logEvent, readVerifiedEventById, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

const SCHEMA = 'aimos.tool-action/v1';
const STARTED = 'tool_execution_started';
const SUCCEEDED = 'tool_execution_succeeded';
const FAILED = 'tool_execution_failed';
const INDETERMINATE = 'tool_execution_indeterminate';
const TERMINAL = 'tool_execution_terminal';
const MAX_RECOVERY_EVENTS = 100_000;

function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value ?? null), 'utf8').digest('hex');
}

function rowMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  try { return JSON.parse(row?.metadata || '{}'); } catch { return {}; }
}

export function toolActionArgumentsHash(args = {}) {
  return sha256Canonical(args || {});
}

export async function beginToolAction({
  tool,
  args = {},
  runtimeAgentId,
  executionContext,
  parentEventId = null,
  purposeAuthorizationReceipt = null,
} = {}) {
  const name = String(tool || '').trim();
  const runtimeAgent = String(runtimeAgentId || '').trim();
  const actorAgentId = String(executionContext?.actorAgentId || '').trim();
  const actorValidFromIso = executionContext?.actorValidFromIso
    ? new Date(executionContext.actorValidFromIso).toISOString()
    : null;
  const actorIdentityTier = String(executionContext?.identityTier || '').trim().toUpperCase();
  const companyId = String(executionContext?.companyId || '').trim();
  if (!name || !runtimeAgent || !actorAgentId || !actorValidFromIso || !companyId) {
    throw new Error('verified_tool_execution_context_required');
  }
  const argsHash = toolActionArgumentsHash(args);
  const receipt = await logEvent(companyId, runtimeAgent, STARTED, name, {
    schema: SCHEMA,
    tool: name,
    args_sha256: argsHash,
    runtime_agent_id: runtimeAgent,
    actor_agent_id: actorAgentId,
    actor_valid_from: actorValidFromIso,
    actor_identity_tier: actorIdentityTier,
    request_receipt_id: executionContext.requestReceiptId || null,
    request_receipt_mutation_hash: executionContext.requestReceiptMutationHash || null,
    purpose_authorization_sha256: purposeAuthorizationReceipt?.artifactSha256 || null,
    purpose_authorization_content_sha256: purposeAuthorizationReceipt?.contentSha256 || null,
    purpose_authorization_operation: purposeAuthorizationReceipt?.operation || null,
    purpose_authorization_read_root_sha256: purposeAuthorizationReceipt?.readRootSha256 || null,
    reasoning: `Housekeeper signed the exact derived ${name} action before execution; arguments are hash-bound and not copied into the event ledger.`,
    source_knowledge: 'tool-action-ledger.js — RFC 6962 / RFC 8032 derived-action authority',
  }, parentEventId, { authority: executionContext, returnReceipt: true });
  return Object.freeze({
    receipt,
    authority: Object.freeze({
      kind: 'verified_tool_action',
      eventId: receipt.event_id,
      eventMutationHash: receipt.mutation_hash,
      tool: name,
      argsHash,
      runtimeAgentId: runtimeAgent,
      actorAgentId,
      actorValidFromIso,
      actorIdentityTier,
      companyId,
      purposeAuthorizationSha256: purposeAuthorizationReceipt?.artifactSha256 || null,
    }),
  });
}

export async function finishToolAction({ action, executionContext, succeeded, disposition = null, result = null, error = null } = {}) {
  if (!action?.receipt?.event_id || !action?.authority) throw new Error('tool_action_start_receipt_required');
  const normalizedDisposition = String(disposition || (succeeded ? 'SUCCEEDED' : 'FAILED')).toUpperCase();
  if (!['SUCCEEDED', 'FAILED', 'INDETERMINATE'].includes(normalizedDisposition)) {
    throw new Error('tool_action_terminal_disposition_invalid');
  }
  const operation = TERMINAL;
  return logEvent(action.authority.companyId, action.authority.runtimeAgentId, operation, action.receipt.event_id, {
    schema: SCHEMA,
    tool_action_event_id: action.receipt.event_id,
    tool: action.authority.tool,
    args_sha256: action.authority.argsHash,
    runtime_agent_id: action.authority.runtimeAgentId,
    actor_agent_id: action.authority.actorAgentId,
    actor_valid_from: action.authority.actorValidFromIso,
    actor_identity_tier: action.authority.actorIdentityTier,
    outcome_sha256: sha256Canonical(normalizedDisposition === 'SUCCEEDED' ? result : String(error || 'unknown_error')),
    outcome: normalizedDisposition.toLowerCase(),
    disposition: normalizedDisposition,
    reasoning: `Housekeeper signed the terminal ${operation} outcome for the exact derived tool action.`,
    source_knowledge: 'tool-action-ledger.js — append-only signed tool outcome',
  }, action.receipt.event_id, {
    authority: executionContext,
    returnReceipt: true,
    exclusiveOperationKey: true,
  });
}

export function reconstructToolActionTraces(rows = []) {
  if (!Array.isArray(rows) || rows.length > MAX_RECOVERY_EVENTS) throw new Error('tool_action_recovery_limit');
  const actions = new Map();
  for (const row of rows) {
    if (![STARTED, TERMINAL, SUCCEEDED, FAILED, INDETERMINATE].includes(row?.operation)) continue;
    const metadata = rowMetadata(row);
    if (metadata.schema !== SCHEMA) continue;
    if (row.operation === STARTED) {
      const startId = String(row.id || row.event_id || '');
      const action = actions.get(startId) || { actionId: startId, start: null, terminal: null };
      if (!startId || action.start) throw new Error('tool_action_start_fork');
      action.start = row;
      actions.set(startId, action);
      continue;
    }
    const startId = String(metadata.tool_action_event_id || '');
    const action = actions.get(startId) || { actionId: startId, start: null, terminal: null };
    if (action.terminal) throw new Error('tool_action_terminal_fork');
    action.terminal = row;
    actions.set(startId, action);
  }
  const values = [...actions.values()].sort((left, right) => left.actionId.localeCompare(right.actionId));
  for (const action of values) {
    if (!action.start) throw new Error('tool_action_terminal_without_start');
    if (!action.terminal) continue;
    const metadata = rowMetadata(action.terminal);
    if (String(action.terminal.key || '') !== action.actionId
        || String(action.terminal.parent_event_id || '') !== action.actionId
        || metadata.args_sha256 !== rowMetadata(action.start).args_sha256
        || metadata.tool !== rowMetadata(action.start).tool) {
      throw new Error('tool_action_terminal_start_binding_invalid');
    }
  }
  return Object.freeze({
    complete: Object.freeze(values.filter((action) => action.terminal)),
    open: Object.freeze(values.filter((action) => !action.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenToolActions({
  companyId = AIMOS_COMPANY_ID,
  rows = null,
  readHistoryFn = readVerifiedEventHistory,
  finishFn = finishToolAction,
} = {}) {
  const load = async () => rows || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructToolActionTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const metadata = rowMetadata(trace.start);
    const startId = String(trace.start.id || trace.start.event_id || '');
    const mutationHash = typeof trace.start.mutation_hash === 'string'
      ? trace.start.mutation_hash
      : Buffer.from(trace.start.mutation_hash || []).toString('hex');
    const action = Object.freeze({
      receipt: Object.freeze({ event_id: startId, mutation_hash: mutationHash }),
      authority: Object.freeze({
        kind: 'verified_tool_action',
        eventId: startId,
        eventMutationHash: mutationHash,
        tool: metadata.tool,
        argsHash: metadata.args_sha256,
        runtimeAgentId: metadata.runtime_agent_id,
        actorAgentId: metadata.actor_agent_id,
        actorValidFromIso: metadata.actor_valid_from,
        actorIdentityTier: metadata.actor_identity_tier,
        companyId: String(trace.start.company_id || companyId),
        purposeAuthorizationSha256: metadata.purpose_authorization_sha256 || null,
      }),
    });
    try {
      const receipt = await finishFn({
        action,
        executionContext: null,
        disposition: 'INDETERMINATE',
        error: 'process_restart_orphan_reconciled_without_tool_replay',
      });
      reconciled.push(Object.freeze({ actionId: trace.actionId, receipt }));
    } catch (error) {
      if (error?.message !== 'event_operation_key_exists') throw error;
      const raced = reconstructToolActionTraces(await load()).complete
        .find((entry) => entry.actionId === trace.actionId);
      if (!raced) throw new Error('tool_action_recovery_race_unverified');
      reconciled.push(Object.freeze({ actionId: trace.actionId, existing: true }));
    }
  }
  const after = reconstructToolActionTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    toolInvocationsReplayed: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function verifyToolActionAuthority(authority, {
  client = null,
  expectedCompanyId,
  expectedTool,
  expectedActorAgentId,
  expectedArguments = null,
} = {}) {
  if (authority?.kind !== 'verified_tool_action') throw new Error('verified_tool_action_required');
  const companyId = String(expectedCompanyId || authority.companyId || '').trim();
  const row = await readVerifiedEventById(authority.eventId, companyId, { client });
  const body = typeof row.signed_body === 'string' ? JSON.parse(row.signed_body) : row.signed_body;
  const metadata = rowMetadata(row);
  const exact = row.operation === STARTED
    && row.key === authority.tool
    && metadata.schema === SCHEMA
    && metadata.tool === authority.tool
    && metadata.args_sha256 === authority.argsHash
    && metadata.runtime_agent_id === authority.runtimeAgentId
    && metadata.actor_agent_id === authority.actorAgentId
    && new Date(metadata.actor_valid_from).toISOString() === new Date(authority.actorValidFromIso).toISOString()
    && String(metadata.actor_identity_tier || '').toUpperCase() === String(authority.actorIdentityTier || '').toUpperCase()
    && body?.event_id === authority.eventId
    && Buffer.from(row.mutation_hash).toString('hex') === authority.eventMutationHash
    && (metadata.purpose_authorization_sha256 || null)
      === (authority.purposeAuthorizationSha256 || null)
    && companyId === authority.companyId
    && (!expectedTool || expectedTool === authority.tool)
    && (!expectedActorAgentId || expectedActorAgentId === authority.actorAgentId)
    && (expectedArguments === null || toolActionArgumentsHash(expectedArguments) === metadata.args_sha256);
  if (!exact) throw new Error('verified_tool_action_binding_invalid');
  return Object.freeze({
    body,
    agentId: row.signer_agent_id,
    validFromIso: new Date(row.signer_valid_from).toISOString(),
    certString: row.cert,
    signedTs: Number(row.ts_signed),
    nonce: String(row.nonce),
    sigBytes: Buffer.from(row.sig),
    identityTier: row.identity_tier,
    requestSigForm: 1,
    signedMethod: null,
    signedPath: null,
    signedClaims: null,
    actionEventId: authority.eventId,
    actionMutationHash: authority.eventMutationHash,
    actionArgsHash: metadata.args_sha256,
  });
}

export const TOOL_ACTION_OPERATIONS = Object.freeze({ STARTED, SUCCEEDED, FAILED });
