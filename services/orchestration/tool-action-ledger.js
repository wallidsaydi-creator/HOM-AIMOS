// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js and canonical mutations caused by tools
// → Calls: observe/event-ledger.js
// Pipeline: TOOL EXECUTION | Position: signed derived-action authority
// Sources: RFC 6962 tamper-evident logging; RFC 8032 Ed25519; confused-deputy
// authority discipline. This service changes no retrieval/ranking mathematics.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

import { canonicalJson } from '../security/agent-identity.js';
import { logEvent, readVerifiedEventById } from '../observe/event-ledger.js';

const SCHEMA = 'aimos.tool-action/v1';
const STARTED = 'tool_execution_started';
const SUCCEEDED = 'tool_execution_succeeded';
const FAILED = 'tool_execution_failed';

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
    }),
  });
}

export async function finishToolAction({ action, executionContext, succeeded, result = null, error = null } = {}) {
  if (!action?.receipt?.event_id || !action?.authority) throw new Error('tool_action_start_receipt_required');
  const operation = succeeded ? SUCCEEDED : FAILED;
  return logEvent(action.authority.companyId, action.authority.runtimeAgentId, operation, action.authority.tool, {
    schema: SCHEMA,
    tool_action_event_id: action.receipt.event_id,
    tool: action.authority.tool,
    args_sha256: action.authority.argsHash,
    runtime_agent_id: action.authority.runtimeAgentId,
    actor_agent_id: action.authority.actorAgentId,
    actor_valid_from: action.authority.actorValidFromIso,
    actor_identity_tier: action.authority.actorIdentityTier,
    outcome_sha256: sha256Canonical(succeeded ? result : String(error || 'unknown_error')),
    outcome: succeeded ? 'succeeded' : 'failed',
    reasoning: `Housekeeper signed the terminal ${operation} outcome for the exact derived tool action.`,
    source_knowledge: 'tool-action-ledger.js — append-only signed tool outcome',
  }, action.receipt.event_id, { authority: executionContext, returnReceipt: true });
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
