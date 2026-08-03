// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-execution.js
// → Calls: db (connection.js), run-events.js
// Pipeline: AGENT_RUN | Position: Run tracking (metadata persistence)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { publishRunEvent } from './run-events.js';

const COMPANY = AIMOS_COMPANY_ID;

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

export async function getIdempotentResponse({ companyId = COMPANY, agentId, idempotencyKey }) {
  if (!idempotencyKey) return null;
  const result = await query(
    `SELECT response
     FROM run_idempotency
     WHERE company_id = $1 AND agent_id = $2 AND idempotency_key = $3`,
    [companyId, agentId, idempotencyKey]
  );
  if (!result.rows.length) return null;
  return result.rows[0].response || null;
}

export async function saveIdempotentResponse({ companyId = COMPANY, agentId, idempotencyKey, response }) {
  if (!idempotencyKey) return;
  await query(
    `INSERT INTO run_idempotency (company_id, agent_id, idempotency_key, response, created_at)
     VALUES ($1, $2, $3, $4, NOW())
     ON CONFLICT (company_id, agent_id, idempotency_key) DO NOTHING`,
    [companyId, agentId, idempotencyKey, JSON.stringify(response || {})]
  );
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
  authorizationChainHash = null
}) {
  const normalizedAuthorizationTrajectory = Array.isArray(authorizationTrajectory)
    ? authorizationTrajectory
    : [];
  const normalizedAuthorizationChainHash = authorizationChainHash
    ? String(authorizationChainHash).trim().slice(0, 128)
    : null;

  await query(
    `INSERT INTO agent_runs
       (run_id, company_id, session_key, idempotency_key, source_agent_id, resolved_agent_id,
        persona_version, model_requested, model_resolved, fallback_used, delegated_to,
        queue_wait_ms, channel, peer_id, intent, authorization_trajectory, authorization_chain_hash,
        status, created_at, updated_at)
     VALUES
       ($1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10, $11,
        $12, $13, $14, $15, $16::jsonb, $17, 'running', NOW(), NOW())
     ON CONFLICT (run_id) DO UPDATE
     SET updated_at = NOW(),
         status = 'running',
         queue_wait_ms = EXCLUDED.queue_wait_ms,
         model_requested = EXCLUDED.model_requested,
         model_resolved = EXCLUDED.model_resolved,
         authorization_trajectory = EXCLUDED.authorization_trajectory,
         authorization_chain_hash = EXCLUDED.authorization_chain_hash`,
    [
      runId,
      companyId,
      sessionKey,
      idempotencyKey || null,
      sourceAgentId,
      resolvedAgentId,
      Number(personaVersion || 1),
      modelRequested || null,
      modelResolved || null,
      !!fallbackUsed,
      delegatedTo,
      normalizeQueueWaitMs(queueWaitMs, 0),
      channel,
      peerId,
      intent,
      JSON.stringify(normalizedAuthorizationTrajectory),
      normalizedAuthorizationChainHash
    ]
  );

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
  confidence = null
}) {
  const preview = previewText(response);
  const normalizedConfidence = Number.isFinite(confidence) ? Number(confidence) : null;
  await query(
    `UPDATE agent_runs
     SET status = 'completed',
         model_resolved = COALESCE($3, model_resolved),
         fallback_used = COALESCE($4, fallback_used),
         delegated_to = COALESCE($5, delegated_to),
         queue_wait_ms = COALESCE($6, queue_wait_ms),
         response_preview = $7,
         prompt_chars = COALESCE($8, prompt_chars),
         response_chars = COALESCE($9, response_chars),
         context_compacted = COALESCE($10, context_compacted),
         context_compaction_ratio = COALESCE($11, context_compaction_ratio),
         confidence = COALESCE($12, confidence),
         updated_at = NOW()
     WHERE run_id = $1 AND company_id = $2`,
    [
      runId,
      companyId,
      modelResolved || null,
      typeof fallbackUsed === 'boolean' ? fallbackUsed : null,
      delegatedTo || null,
      normalizeQueueWaitMs(queueWaitMs),
      preview,
      Number.isFinite(promptChars) ? Number(promptChars) : null,
      Number.isFinite(responseChars) ? Number(responseChars) : null,
      typeof contextCompacted === 'boolean' ? contextCompacted : null,
      Number.isFinite(contextCompactionRatio) ? Number(contextCompactionRatio) : null,
      normalizedConfidence
    ]
  );

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
  queueWaitMs = null
}) {
  const summarizedError = previewText(error, 800);
  await query(
    `UPDATE agent_runs
     SET status = 'awaiting_approval',
         error = $3,
         queue_wait_ms = COALESCE($4, queue_wait_ms),
         updated_at = NOW()
     WHERE run_id = $1 AND company_id = $2`,
    [runId, companyId, summarizedError, normalizeQueueWaitMs(queueWaitMs)]
  );

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
  lifecycleStatus = 'failed'
}) {
  const normalizedLifecycleStatus = String(lifecycleStatus || '').trim().toLowerCase() === 'timeout'
    ? 'timeout'
    : 'failed';
  const eventType = normalizedLifecycleStatus === 'timeout' ? 'run.timeout' : 'run.failed';
  let sourceAgentId = null;
  let resolvedAgentId = null;
  try {
    const existing = await query(
      `SELECT source_agent_id, resolved_agent_id
       FROM agent_runs
       WHERE run_id = $1
         AND company_id = $2
       LIMIT 1`,
      [runId, companyId]
    );
    sourceAgentId = existing.rows[0]?.source_agent_id || null;
    resolvedAgentId = existing.rows[0]?.resolved_agent_id || null;
  } catch {
    sourceAgentId = null;
    resolvedAgentId = null;
  }

  const summarizedError = previewText(error, 800);
  await query(
    `UPDATE agent_runs
     SET status = $5,
         error = $3,
         queue_wait_ms = COALESCE($4, queue_wait_ms),
         updated_at = NOW()
     WHERE run_id = $1 AND company_id = $2`,
    [runId, companyId, summarizedError, normalizeQueueWaitMs(queueWaitMs), normalizedLifecycleStatus]
  );

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
