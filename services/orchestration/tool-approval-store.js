// ─── PIPELINE CONNECTIONS ───────────────────────────────────
// ← Called by: tool-registry.js and routes/tools.js
// → Calls: observe/event-ledger.js and restricted transaction owner
// Pipeline: TOOL_REGISTRY | Position: append-only signed approval authority
// ────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

import { withTransaction } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { canonicalJson } from '../security/agent-identity.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const SCHEMA = 'aimos.tool-approval/v1';
const OPERATIONS = Object.freeze({
  REQUESTED: 'tool_approval_requested',
  APPROVED: 'tool_approval_approved',
  REJECTED: 'tool_approval_rejected',
  RESERVED: 'tool_approval_execution_reserved',
  CLAIMED: 'tool_approval_execution_claimed',
  EXECUTED: 'tool_approval_executed',
  FAILED: 'tool_approval_failed',
});

function clone(value) {
  return JSON.parse(canonicalJson(value ?? null));
}

function metadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  if (typeof row?.metadata !== 'string') return {};
  try { return JSON.parse(row.metadata); } catch { return {}; }
}

function mutationHashHex(row) {
  return row?.mutation_hash ? Buffer.from(row.mutation_hash).toString('hex') : null;
}

export function toolArgumentsHash(args = {}) {
  return createHash('sha256').update(canonicalJson(args || {}), 'utf8').digest('hex');
}

export function projectToolApprovalHistory(rows = []) {
  const relevant = (Array.isArray(rows) ? rows : [])
    .filter((row) => Object.values(OPERATIONS).includes(row.operation))
    .sort((a, b) => Number(a.ledger_seq || 0) - Number(b.ledger_seq || 0));
  const requests = new Map();

  for (const row of relevant) {
    const body = metadata(row);
    if (body.schema !== SCHEMA) continue;
    if (row.operation === OPERATIONS.REQUESTED) {
      const exactArgs = clone(body.args || {});
      if (
        String(body.args_sha256 || '') !== toolArgumentsHash(exactArgs)
        || (row.key != null && String(row.key) !== String(body.tool || ''))
        || (row.agent_id != null && String(row.agent_id) !== String(body.agent_id || ''))
      ) continue;
      requests.set(String(row.id), {
        id: String(row.id),
        tool: String(body.tool || ''),
        args: exactArgs,
        argsHash: String(body.args_sha256 || ''),
        agentId: String(body.agent_id || ''),
        plan: body.plan ? clone(body.plan) : null,
        status: 'pending',
        result: null,
        error: null,
        createdAt: row.ts ? new Date(row.ts).toISOString() : null,
        updatedAt: row.ts ? new Date(row.ts).toISOString() : null,
        decidedAt: null,
        requestMutationHash: mutationHashHex(row),
        decisionEventId: null,
        decisionMutationHash: null,
        reservationEventId: null,
        reservationMutationHash: null,
        claimEventId: null,
        claimMutationHash: null,
        stateHeadEventId: String(row.id),
      });
      continue;
    }

    const requestId = String(body.approval_request_id || '');
    const current = requests.get(requestId);
    if (
      !current
      || String(row.parent_event_id || '') !== current.stateHeadEventId
      || String(body.tool || '') !== current.tool
      || String(body.args_sha256 || '') !== current.argsHash
      || String(body.agent_id || '') !== current.agentId
      || (row.key != null && String(row.key) !== current.tool)
      || (row.agent_id != null && String(row.agent_id) !== current.agentId)
    ) continue;
    current.updatedAt = row.ts ? new Date(row.ts).toISOString() : current.updatedAt;

    if (row.operation === OPERATIONS.APPROVED && current.status === 'pending') {
      current.status = 'approved';
      current.decidedAt = current.updatedAt;
      current.decisionEventId = String(row.id);
      current.decisionMutationHash = mutationHashHex(row);
      current.error = null;
      current.stateHeadEventId = String(row.id);
    } else if (row.operation === OPERATIONS.REJECTED && ['pending', 'approved'].includes(current.status)) {
      current.status = 'rejected';
      current.decidedAt = current.updatedAt;
      current.decisionEventId = String(row.id);
      current.decisionMutationHash = mutationHashHex(row);
      current.error = String(body.reason || 'Rejected by operator');
      current.stateHeadEventId = String(row.id);
    } else if (row.operation === OPERATIONS.RESERVED && current.status === 'approved') {
      current.status = 'executing';
      current.reservationEventId = String(row.id);
      current.reservationMutationHash = mutationHashHex(row);
      current.stateHeadEventId = String(row.id);
    } else if (row.operation === OPERATIONS.CLAIMED && current.status === 'executing') {
      current.status = 'claimed';
      current.claimEventId = String(row.id);
      current.claimMutationHash = mutationHashHex(row);
      current.stateHeadEventId = String(row.id);
    } else if (row.operation === OPERATIONS.EXECUTED && current.status === 'claimed') {
      current.status = 'executed';
      current.result = clone(body.result ?? null);
      current.error = null;
      current.stateHeadEventId = String(row.id);
    } else if (row.operation === OPERATIONS.FAILED && current.status === 'claimed') {
      current.status = 'failed';
      current.error = String(body.error || 'Unknown execution error');
      current.stateHeadEventId = String(row.id);
    }
  }
  return [...requests.values()];
}

async function readApprovals(client = null) {
  const rows = await readVerifiedEventHistory(COMPANY, { client });
  return projectToolApprovalHistory(rows);
}

export async function createToolApprovalRequest({
  tool,
  args = {},
  agentId = 'unknown',
  plan = null,
  authority = null,
  parentEventId = null,
} = {}) {
  const normalizedTool = String(tool || '').trim();
  const normalizedAgent = String(agentId || '').trim();
  if (!normalizedTool || !normalizedAgent) throw new Error('tool_approval_subject_required');
  const exactArgs = clone(args || {});
  const receipt = await logEvent(COMPANY, normalizedAgent, OPERATIONS.REQUESTED, normalizedTool, {
    schema: SCHEMA,
    tool: normalizedTool,
    args: exactArgs,
    args_sha256: toolArgumentsHash(exactArgs),
    agent_id: normalizedAgent,
    plan: plan ? clone(plan) : null,
    reasoning: `A bounded autonomous tool action requested explicit operator approval for ${normalizedTool}.`,
    source_knowledge: 'tool-approval-store.js append-only certificate-envelope approval authority',
  }, parentEventId, { authority, returnReceipt: true });
  const projected = projectToolApprovalHistory([{
    id: receipt.event_id,
    operation: OPERATIONS.REQUESTED,
    key: normalizedTool,
    agent_id: normalizedAgent,
    metadata: receipt.signed_body.metadata,
    mutation_hash: Buffer.from(receipt.mutation_hash, 'hex'),
    ledger_seq: receipt.ledger_seq,
    ts: new Date(receipt.ts_signed * 1000),
  }]);
  return projected[0];
}

export async function getToolApprovalRequest(id, { client = null } = {}) {
  const key = String(id || '').trim();
  if (!key) return null;
  return (await readApprovals(client)).find((item) => item.id === key) || null;
}

export async function listToolApprovalRequests({ status = null, agentId = null, limit = 50 } = {}) {
  const normalizedStatus = status ? String(status).toLowerCase() : null;
  const normalizedAgent = agentId ? String(agentId).toLowerCase() : null;
  const safeLimit = Math.max(1, Math.min(500, Number(limit || 50)));
  return (await readApprovals())
    .filter((item) => !normalizedStatus || item.status.toLowerCase() === normalizedStatus)
    .filter((item) => !normalizedAgent || item.agentId.toLowerCase() === normalizedAgent)
    .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0))
    .slice(0, safeLimit);
}

async function appendTransition(id, operation, {
  authority = null,
  reason = null,
  result = null,
  error = null,
  expectedExecution = null,
} = {}) {
  const requestId = String(id || '').trim();
  if (!requestId) throw new Error('tool_approval_id_required');
  return withTransaction(async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`tool-approval:${requestId}`]);
    const current = await getToolApprovalRequest(requestId, { client });
    if (!current) throw new Error('tool_approval_not_found');
    const allowed = operation === OPERATIONS.APPROVED
      ? ['pending']
      : operation === OPERATIONS.REJECTED
        ? ['pending', 'approved']
        : operation === OPERATIONS.RESERVED
          ? ['approved']
          : operation === OPERATIONS.CLAIMED
            ? ['executing']
            : [operation === OPERATIONS.EXECUTED || operation === OPERATIONS.FAILED ? 'claimed' : 'never'];
    if (!allowed.includes(current.status)) throw new Error(`tool_approval_invalid_transition:${current.status}:${operation}`);
    if (operation === OPERATIONS.CLAIMED) {
      const expected = expectedExecution || {};
      const exact = current.tool === String(expected.tool || '')
        && current.agentId === String(expected.agentId || '')
        && current.argsHash === toolArgumentsHash(expected.args || {})
        && current.reservationEventId === String(expected.reservationEventId || '')
        && current.reservationMutationHash === String(expected.reservationMutationHash || '');
      if (!exact) throw new Error('signed_tool_approval_execution_evidence_invalid');
    }
    const receipt = await logEvent(COMPANY, current.agentId, operation, current.tool, {
      schema: SCHEMA,
      approval_request_id: requestId,
      tool: current.tool,
      args_sha256: current.argsHash,
      agent_id: current.agentId,
      ...(reason ? { reason: String(reason) } : {}),
      ...(result !== null ? { result: clone(result) } : {}),
      ...(error !== null ? { error: String(error) } : {}),
      reasoning: `Signed tool approval state advanced from ${current.status} via ${operation}.`,
      source_knowledge: 'tool-approval-store.js append-only certificate-envelope approval authority',
    }, current.stateHeadEventId, { client, authority, returnReceipt: true });
    return {
      approval: {
        ...current,
        status: operation === OPERATIONS.APPROVED ? 'approved'
          : operation === OPERATIONS.REJECTED ? 'rejected'
            : operation === OPERATIONS.RESERVED ? 'executing'
              : operation === OPERATIONS.CLAIMED ? 'claimed'
              : operation === OPERATIONS.EXECUTED ? 'executed' : 'failed',
        decisionEventId: operation === OPERATIONS.APPROVED || operation === OPERATIONS.REJECTED
          ? receipt.event_id : current.decisionEventId,
        decisionMutationHash: operation === OPERATIONS.APPROVED || operation === OPERATIONS.REJECTED
          ? receipt.mutation_hash : current.decisionMutationHash,
        reservationEventId: operation === OPERATIONS.RESERVED ? receipt.event_id : current.reservationEventId,
        reservationMutationHash: operation === OPERATIONS.RESERVED ? receipt.mutation_hash : current.reservationMutationHash,
        claimEventId: operation === OPERATIONS.CLAIMED ? receipt.event_id : current.claimEventId,
        claimMutationHash: operation === OPERATIONS.CLAIMED ? receipt.mutation_hash : current.claimMutationHash,
        stateHeadEventId: receipt.event_id,
        result: operation === OPERATIONS.EXECUTED ? clone(result) : current.result,
        error: operation === OPERATIONS.REJECTED ? String(reason || 'Rejected by operator')
          : operation === OPERATIONS.FAILED ? String(error || 'Unknown execution error') : null,
      },
      receipt,
    };
  }, { restricted: true, clientId: COMPANY, agentId: 'housekeeper' });
}

export async function markToolApprovalApproved(id, authority) {
  return appendTransition(id, OPERATIONS.APPROVED, { authority });
}

export async function markToolApprovalRejected(id, reason = 'Rejected by operator', authority = null) {
  return appendTransition(id, OPERATIONS.REJECTED, { authority, reason });
}

export async function reserveToolApprovalExecution(id, authority = null) {
  return appendTransition(id, OPERATIONS.RESERVED, { authority });
}

export async function markToolApprovalExecuted(id, result, authority = null) {
  return appendTransition(id, OPERATIONS.EXECUTED, { authority, result });
}

export async function markToolApprovalFailed(id, error, authority = null) {
  return appendTransition(id, OPERATIONS.FAILED, { authority, error });
}

export async function claimToolApprovalExecution({
  approvalId,
  reservationEventId,
  reservationMutationHash,
  tool,
  args,
  agentId,
  authority = null,
} = {}) {
  return appendTransition(approvalId, OPERATIONS.CLAIMED, {
    authority,
    expectedExecution: { reservationEventId, reservationMutationHash, tool, args, agentId },
  });
}

export const TOOL_APPROVAL_OPERATIONS = OPERATIONS;
