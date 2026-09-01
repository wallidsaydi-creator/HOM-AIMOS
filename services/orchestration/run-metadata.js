// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-execution.js
// → Calls: db (connection.js), run-events.js
// Pipeline: AGENT_RUN | Position: Run tracking (metadata persistence)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';
import { withTransaction } from '../../db/connection.js';
import { publishRunEvent } from './run-events.js';
import { canonicalJson } from '../security/agent-identity.js';
import { logEvent, readVerifiedEventById, readVerifiedEventHistory } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const MAX_RECOVERY_EVENTS = 100_000;

function normalizeQueueWaitMs(value, fallback = null) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  return fallback;
}

function previewText(input, limit = 1200) {
  const text = String(input || '');
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}...`;
}

function projectionHash(value) {
  return createHash('sha256').update(Buffer.from(canonicalJson(value), 'utf8')).digest('hex');
}

function eventMetadata(event) {
  if (event?.metadata && typeof event.metadata === 'object') return event.metadata;
  try { return JSON.parse(event?.metadata || '{}'); } catch { return {}; }
}

function eventMutationHash(event) {
  return typeof event?.mutation_hash === 'string'
    ? event.mutation_hash
    : Buffer.from(event?.mutation_hash || []).toString('hex');
}

export function reconstructRunTraces(events = []) {
  if (!Array.isArray(events) || events.length > MAX_RECOVERY_EVENTS) throw new Error('agent_run_recovery_limit');
  const runs = new Map();
  for (const event of events) {
    if (!['agent_run_started', 'agent_run_awaiting_approval', 'agent_run_terminal'].includes(event?.operation)) continue;
    const metadata = eventMetadata(event);
    if (metadata.schema !== 'hom.aimos.agent-run-state/v1') continue;
    const runId = String(metadata.run_id || event.key || '');
    if (!runId || String(event.key || '') !== runId) throw new Error('agent_run_key_mismatch');
    const trace = runs.get(runId) || { runId, start: null, awaitingApproval: null, terminal: null };
    if (event.operation === 'agent_run_started') {
      if (trace.start) throw new Error('agent_run_start_fork');
      trace.start = event;
    } else if (event.operation === 'agent_run_terminal') {
      if (trace.terminal) throw new Error('agent_run_terminal_fork');
      trace.terminal = event;
    } else {
      if (trace.awaitingApproval) throw new Error('agent_run_awaiting_approval_fork');
      trace.awaitingApproval = event;
    }
    runs.set(runId, trace);
  }
  const ordered = [...runs.values()].sort((left, right) => left.runId.localeCompare(right.runId));
  for (const trace of ordered) {
    if (!trace.start) throw new Error('agent_run_transition_without_start');
    const startId = String(trace.start.id || trace.start.event_id || '');
    const startMutationHash = eventMutationHash(trace.start);
    for (const transition of [trace.awaitingApproval, trace.terminal].filter(Boolean)) {
      const metadata = eventMetadata(transition);
      if (String(transition.parent_event_id || '') !== startId
          || metadata.start_event_id !== startId
          || metadata.start_mutation_hash !== startMutationHash) {
        throw new Error('agent_run_transition_start_binding_invalid');
      }
    }
  }
  return Object.freeze({
    complete: Object.freeze(ordered.filter((trace) => trace.terminal)),
    open: Object.freeze(ordered.filter((trace) => !trace.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenRuns({
  companyId = COMPANY,
  events = null,
  readHistoryFn = readVerifiedEventHistory,
  appendFn = appendRunState,
} = {}) {
  const load = async () => events || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructRunTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const start = eventMetadata(trace.start);
    const receipt = await appendFn({
      companyId,
      agentId: String(trace.start.agent_id || start.source_agent_id || 'housekeeper'),
      operation: 'agent_run_terminal',
      runId: trace.runId,
      authority: null,
      projection: {
        run_id: trace.runId,
        company_id: companyId,
        source_agent_id: start.source_agent_id || null,
        resolved_agent_id: start.resolved_agent_id || null,
        status: 'indeterminate',
        disposition: 'INDETERMINATE_PROCESS_RESTART',
        error: 'process_restart_orphan_reconciled_without_run_replay',
      },
    });
    reconciled.push(Object.freeze({ runId: trace.runId, receipt }));
  }
  const after = reconstructRunTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    runsReplayed: 0,
    responsesPublished: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

async function readRunEvent(companyId, operation, key, agentId = null) {
  return withTransaction(async (client) => {
    const result = await client.query(
      `SELECT id FROM aimos_events
        WHERE company_id = $1 AND operation = $2 AND key = $3
          AND ledger_version = 1
          AND ($4::text IS NULL OR agent_id = $4)
        ORDER BY ts DESC, signer_valid_from DESC, ledger_seq DESC LIMIT 1`,
      [companyId, operation, key, agentId],
    );
    if (!result.rows[0]) return null;
    return readVerifiedEventById(result.rows[0].id, companyId, { client });
  }, { restricted: true, client_id: companyId, agent_id: agentId || 'housekeeper' });
}

export async function listVerifiedRunStates({ companyId = COMPANY, limit = 500, sinceMs = null } = {}) {
  const boundedLimit = Math.max(1, Math.min(Number(limit) || 500, 1000));
  return withTransaction(async (client) => {
    const result = await client.query(
      `SELECT id FROM aimos_events
        WHERE company_id = $1
          AND operation IN ('agent_run_started','agent_run_awaiting_approval','agent_run_terminal')
          AND ledger_version = 1
          AND ($2::timestamptz IS NULL OR ts >= $2)
        ORDER BY ts DESC, signer_valid_from DESC, ledger_seq DESC LIMIT $3`,
      [companyId, sinceMs == null ? null : new Date(Number(sinceMs)).toISOString(), boundedLimit],
    );
    const events = [];
    for (const locator of [...result.rows].reverse()) {
      events.push(await readVerifiedEventById(locator.id, companyId, { client }));
    }
    const runs = new Map();
    for (const event of events) {
      const metadata = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
      if (metadata?.schema !== 'hom.aimos.agent-run-state/v1' || !metadata?.run_id) continue;
      const prior = runs.get(metadata.run_id) || {};
      runs.set(metadata.run_id, {
        ...prior,
        ...metadata,
        run_id: metadata.run_id,
        created_at: prior.created_at || event.ts,
        updated_at: event.ts,
        authority_event_id: event.id,
        authority_mutation_hash: Buffer.from(event.mutation_hash).toString('hex'),
      });
    }
    return [...runs.values()].sort((left, right) => new Date(right.updated_at) - new Date(left.updated_at));
  }, { restricted: true, client_id: companyId, agent_id: 'housekeeper' });
}

async function appendRunState({ companyId, agentId, operation, runId, projection, authority = null }) {
  let parentEventId = authority?.requestAdmissionEventId || null;
  let boundProjection = projection;
  if (operation !== 'agent_run_started') {
    const start = await readRunEvent(companyId, 'agent_run_started', runId, agentId || null);
    if (!start) throw new Error('agent_run_start_missing');
    parentEventId = start.id;
    boundProjection = {
      ...projection,
      start_event_id: start.id,
      start_mutation_hash: Buffer.from(start.mutation_hash).toString('hex'),
    };
  }
  const hash = projectionHash(boundProjection);
  try {
    return await logEvent(companyId, agentId || 'housekeeper', operation, runId, {
      schema: 'hom.aimos.agent-run-state/v1',
      ...boundProjection,
      projection_sha256: hash,
      reasoning: `The exact ${operation} operational projection is retained as the authoritative run transition.`,
    }, parentEventId, {
      authority,
      exclusiveOperationKey: true,
      returnReceipt: true,
    });
  } catch (error) {
    if (error?.message !== 'event_operation_key_exists') throw error;
    const existing = await readRunEvent(companyId, operation, runId, agentId || null);
    const metadata = existing && (typeof existing.metadata === 'string' ? JSON.parse(existing.metadata) : existing.metadata);
    if (metadata?.projection_sha256 !== hash) throw new Error('agent_run_transition_conflict');
    return { event_id: existing.id, mutation_hash: Buffer.from(existing.mutation_hash).toString('hex'), existing: true };
  }
}

export async function getIdempotentResponse({ companyId = COMPANY, agentId, idempotencyKey }) {
  if (!idempotencyKey) return null;
  const event = await readRunEvent(companyId, 'run_idempotency_committed', `${agentId}:${idempotencyKey}`, agentId);
  if (!event) return null;
  const metadata = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
  if (metadata?.schema !== 'hom.aimos.run-idempotency/v1'
      || metadata?.agent_id !== agentId
      || metadata?.idempotency_key !== idempotencyKey
      || metadata?.response_sha256 !== projectionHash(metadata.response || {})) {
    throw new Error('run_idempotency_event_invalid');
  }
  return metadata.response || null;
}

export async function saveIdempotentResponse({ companyId = COMPANY, agentId, idempotencyKey, response, authority = null }) {
  if (!idempotencyKey) return;
  const normalized = response || {};
  const key = `${agentId}:${idempotencyKey}`;
  const terminal = normalized.runId
    ? await readRunEvent(companyId, 'agent_run_terminal', normalized.runId, agentId)
    : null;
  if (!terminal) throw new Error('run_idempotency_terminal_missing');
  try {
    await logEvent(companyId, agentId, 'run_idempotency_committed', key, {
      schema: 'hom.aimos.run-idempotency/v1',
      agent_id: agentId,
      idempotency_key: idempotencyKey,
      response: normalized,
      response_sha256: projectionHash(normalized),
      run_terminal_event_id: terminal.id,
      run_terminal_mutation_hash: Buffer.from(terminal.mutation_hash).toString('hex'),
      reasoning: 'The verified run response is retained once for this actor-scoped idempotency key.',
    }, terminal.id, {
      authority,
      exclusiveOperationKey: true,
      returnReceipt: true,
    });
  } catch (error) {
    if (error?.message !== 'event_operation_key_exists') throw error;
    const existing = await getIdempotentResponse({ companyId, agentId, idempotencyKey });
    if (projectionHash(existing || {}) !== projectionHash(normalized)) throw new Error('run_idempotency_conflict');
  }
}

export async function markRunStarted({
  runId,
  companyId = COMPANY,
  sessionKey,
  idempotencyKey,
  sourceAgentId,
  resolvedAgentId,
  personaVersion,
  modelRequested,
  modelResolved,
  fallbackUsed = false,
  delegatedTo = null,
  queueWaitMs = 0,
  channel = null,
  peerId = null,
  intent = null,
  authorizationTrajectory = null,
  authorizationChainHash = null,
  authority = null,
}) {
  const normalizedAuthorizationTrajectory = Array.isArray(authorizationTrajectory)
    ? authorizationTrajectory
    : [];
  const normalizedAuthorizationChainHash = authorizationChainHash
    ? String(authorizationChainHash).trim().slice(0, 128)
    : null;

  await appendRunState({
    companyId,
    agentId: sourceAgentId,
    operation: 'agent_run_started',
    runId,
    authority,
    projection: {
      run_id: runId,
      company_id: companyId,
      session_key: sessionKey,
      idempotency_key: idempotencyKey || null,
      source_agent_id: sourceAgentId,
      resolved_agent_id: resolvedAgentId,
      persona_version: Number(personaVersion || 1),
      model_requested: modelRequested || null,
      model_resolved: modelResolved || null,
      fallback_used: Boolean(fallbackUsed),
      delegated_to: delegatedTo || null,
      queue_wait_ms: normalizeQueueWaitMs(queueWaitMs, 0),
      channel: channel || null,
      peer_id: peerId || null,
      intent: intent || null,
      authorization_trajectory: normalizedAuthorizationTrajectory,
      authorization_chain_hash: normalizedAuthorizationChainHash,
      status: 'running',
    },
  });

  publishRunEvent('run.started', {
    status: 'running',
    runId,
    companyId,
    sessionKey,
    sourceAgentId,
    resolvedAgentId,
    modelRequested: modelRequested || null,
    modelResolved: modelResolved || null,
    fallbackUsed: !!fallbackUsed,
    delegatedTo: delegatedTo || null,
    queueWaitMs: normalizeQueueWaitMs(queueWaitMs, 0),
    channel: channel || null,
    peerId: peerId || null,
    intent: intent || null,
    authorizationTrajectory: normalizedAuthorizationTrajectory,
    authorizationChainHash: normalizedAuthorizationChainHash
  });
}

export async function markRunCompleted({
  runId,
  companyId = COMPANY,
  sourceAgentId = null,
  resolvedAgentId = null,
  modelResolved,
  fallbackUsed,
  delegatedTo,
  queueWaitMs,
  response,
  promptChars = null,
  responseChars = null,
  contextCompacted = null,
  contextCompactionRatio = null,
  confidence = null,
  authority = null,
}) {
  const preview = previewText(response);
  const normalizedConfidence = Number.isFinite(confidence) ? Number(confidence) : null;
  await appendRunState({
    companyId,
    agentId: sourceAgentId || resolvedAgentId || 'housekeeper',
    operation: 'agent_run_terminal',
    runId,
    authority,
    projection: {
      run_id: runId,
      company_id: companyId,
      source_agent_id: sourceAgentId,
      resolved_agent_id: resolvedAgentId,
      status: 'completed',
      model_resolved: modelResolved || null,
      fallback_used: typeof fallbackUsed === 'boolean' ? fallbackUsed : null,
      delegated_to: delegatedTo || null,
      queue_wait_ms: normalizeQueueWaitMs(queueWaitMs),
      response_preview: preview,
      prompt_chars: Number.isFinite(promptChars) ? Number(promptChars) : null,
      response_chars: Number.isFinite(responseChars) ? Number(responseChars) : null,
      context_compacted: typeof contextCompacted === 'boolean' ? contextCompacted : null,
      context_compaction_ratio: Number.isFinite(contextCompactionRatio) ? Number(contextCompactionRatio) : null,
      confidence: normalizedConfidence,
    },
  });

  publishRunEvent('run.completed', {
    status: 'completed',
    runId,
    companyId,
    sourceAgentId,
    resolvedAgentId,
    modelResolved: modelResolved || null,
    fallbackUsed: typeof fallbackUsed === 'boolean' ? fallbackUsed : null,
    delegatedTo: delegatedTo || null,
    queueWaitMs: normalizeQueueWaitMs(queueWaitMs),
    promptChars: Number.isFinite(promptChars) ? Number(promptChars) : null,
    responseChars: Number.isFinite(responseChars) ? Number(responseChars) : null,
    contextCompacted: typeof contextCompacted === 'boolean' ? contextCompacted : null,
    contextCompactionRatio: Number.isFinite(contextCompactionRatio) ? Number(contextCompactionRatio) : null,
    confidence: normalizedConfidence,
    preview
  });
}

export async function markRunAwaitingApproval({
  runId,
  companyId = COMPANY,
  sourceAgentId = null,
  resolvedAgentId = null,
  error,
  approvalRequestId = null,
  queueWaitMs = null,
  authority = null,
}) {
  const summarizedError = previewText(error, 800);
  await appendRunState({
    companyId,
    agentId: sourceAgentId || resolvedAgentId || 'housekeeper',
    operation: 'agent_run_awaiting_approval',
    runId,
    authority,
    projection: {
      run_id: runId,
      company_id: companyId,
      source_agent_id: sourceAgentId,
      resolved_agent_id: resolvedAgentId,
      status: 'awaiting_approval',
      error: summarizedError,
      approval_request_id: approvalRequestId || null,
      queue_wait_ms: normalizeQueueWaitMs(queueWaitMs),
    },
  });

  publishRunEvent('run.awaiting_approval', {
    status: 'awaiting_approval',
    runId,
    companyId,
    sourceAgentId,
    resolvedAgentId,
    error: summarizedError,
    approvalRequestId: approvalRequestId || null,
    queueWaitMs: normalizeQueueWaitMs(queueWaitMs)
  });
}

export async function markRunFailed({
  runId,
  companyId = COMPANY,
  error,
  queueWaitMs = null,
  lifecycleStatus = 'failed',
  authority = null,
  sourceAgentId = null,
  resolvedAgentId = null,
}) {
  const normalizedLifecycleStatus = String(lifecycleStatus || '').trim().toLowerCase() === 'timeout'
    ? 'timeout'
    : 'failed';
  const eventType = normalizedLifecycleStatus === 'timeout' ? 'run.timeout' : 'run.failed';
  const summarizedError = previewText(error, 800);
  await appendRunState({
    companyId,
    agentId: sourceAgentId || resolvedAgentId || 'housekeeper',
    operation: 'agent_run_terminal',
    runId,
    authority,
    projection: {
      run_id: runId,
      company_id: companyId,
      source_agent_id: sourceAgentId,
      resolved_agent_id: resolvedAgentId,
      status: normalizedLifecycleStatus,
      error: summarizedError,
      queue_wait_ms: normalizeQueueWaitMs(queueWaitMs),
    },
  });

  publishRunEvent(eventType, {
    status: normalizedLifecycleStatus,
    runId,
    companyId,
    sourceAgentId,
    resolvedAgentId,
    error: summarizedError,
    queueWaitMs: normalizeQueueWaitMs(queueWaitMs)
  });
}
