// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js
// → Calls: db (connection.js)
// Pipeline: AGENT_RUN | Position: Conversation history management
// Source: Session Management patterns, TTL-based caching (Redis patterns)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { pool, query } from '../../db/connection.js';
import { sessionMemoryOwner } from './session-memory-owner.js';

const COMPANY = AIMOS_COMPANY_ID;
const MAX_CONCURRENT_RUNS = 6;
const CONVERSATION_TTL_MS = 5 * 60 * 1000;
const CONVERSATION_MAX_TURNS = 20;
const SESSION_TURNS_CHAR_BUDGET = 30_000;
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const AGENTICCACHE_SOURCE = 'AGENTICCACHE: Cache-Driven Asynchronous Planning for Embodied AI Agents';

let activeRuns = 0;
const waiters = [];
const conversationSessions = new Map();
const sessionLaneTails = new Map();
let cleanupTimer = null;

async function acquireGlobalSlot() {
  if (activeRuns < MAX_CONCURRENT_RUNS) {
    activeRuns += 1;
    return;
  }

  await new Promise((resolve) => waiters.push({ resolve, queuedAt: Date.now() }));
  activeRuns += 1;
}

function releaseGlobalSlot() {
  activeRuns = Math.max(0, activeRuns - 1);
  const next = waiters.shift();
  if (next?.resolve) next.resolve();
}

function getWaiterStats(now = Date.now()) {
  if (!waiters.length) {
    return {
      waitingOldestMs: 0,
      waitingAverageMs: 0
    };
  }
  const waits = waiters
    .map((entry) => Number(now - Number(entry?.queuedAt || now)))
    .filter((value) => Number.isFinite(value) && value >= 0);
  const waitingOldestMs = waits.length ? Math.max(...waits) : 0;
  const waitingAverageMs = waits.length
    ? Math.round(waits.reduce((sum, value) => sum + value, 0) / waits.length)
    : 0;
  return {
    waitingOldestMs,
    waitingAverageMs
  };
}

function nowMs() {
  return Date.now();
}

function normalizeSessionKey(sessionKey) {
  const key = String(sessionKey || '').trim();
  return key || 'default';
}

function purgeExpiredConversationSessions(now = nowMs()) {
  for (const [sessionKey, session] of conversationSessions.entries()) {
    const lastActivityAt = Number(session?.lastActivityAt || 0);
    if (!lastActivityAt || now - lastActivityAt > CONVERSATION_TTL_MS) {
      conversationSessions.delete(sessionKey);
    }
  }
}

function ensureConversationSession(sessionKey) {
  const key = normalizeSessionKey(sessionKey);
  const existing = conversationSessions.get(key);
  if (existing) return existing;
  const created = { turns: [], lastActivityAt: nowMs() };
  conversationSessions.set(key, created);
  return created;
}

function turnChars(turn) {
  return String(turn?.content || '').length;
}

function trimConversationTurns(turns = []) {
  const normalized = Array.isArray(turns) ? turns : [];
  let trimmed = normalized.slice(-CONVERSATION_MAX_TURNS);
  let totalChars = trimmed.reduce((sum, turn) => sum + turnChars(turn), 0);

  while (trimmed.length > 0 && totalChars > SESSION_TURNS_CHAR_BUDGET) {
    totalChars -= turnChars(trimmed[0]);
    trimmed = trimmed.slice(1);
  }

  return trimmed;
}

export async function getConversationHistory(sessionKey, options = {}) {
  const key = normalizeSessionKey(sessionKey);
  let session = conversationSessions.get(key);
  if (!session && options.loadDurable !== false) {
    const durableTurns = await sessionMemoryOwner.loadVerifiedTurns({ session_id: key }, {
      companyId: options.companyId || COMPANY,
      agentId: options.agentId || 'housekeeper',
    });
    if (durableTurns.length) {
      session = {
        turns: durableTurns.map((turn) => ({
          role: turn.role,
          content: turn.content,
          at: turn.observed_at,
        })),
        lastActivityAt: nowMs(),
      };
      session.turns = trimConversationTurns(session.turns);
      conversationSessions.set(key, session);
    }
  }
  if (!session) return [];
  session.lastActivityAt = nowMs();
  const turns = trimConversationTurns(Array.isArray(session.turns) ? session.turns : []);
  session.turns = turns;
  return turns
    .filter((turn) => turn && typeof turn.role === 'string' && typeof turn.content === 'string')
    .map((turn) => ({ role: turn.role, content: turn.content }));
}

export async function addConversationTurn(sessionKey, role, content, options = {}) {
  const normalizedRole = String(role || '').trim().toLowerCase();
  if (!['user', 'assistant'].includes(normalizedRole)) return null;
  const normalizedContent = String(content || '').trim();
  if (!normalizedContent) return null;
  const key = normalizeSessionKey(sessionKey);
  const observedAt = options.observedAt || new Date().toISOString();
  let persistence = null;
  if (options.persist !== false) {
    persistence = await sessionMemoryOwner.appendTurn({
      session_id: key,
      turn_id: options.turnId,
      role: normalizedRole,
      content: normalizedContent,
      observed_at: observedAt,
      source_ref: options.sourceRef || null,
      source: options.source || 'agent-runner:session-turn',
      clearance_level: options.clearanceLevel || 1,
    }, {
      companyId: options.companyId || COMPANY,
      agentId: options.agentId,
      mutationAuthority: 'housekeeper',
    });
  }
  const session = ensureConversationSession(sessionKey);
  session.turns.push({
    role: normalizedRole,
    content: normalizedContent,
    at: observedAt,
  });
  session.turns = trimConversationTurns(session.turns);
  session.lastActivityAt = nowMs();
  return persistence;
}

export async function finalizeConversationSession(sessionKey, options = {}) {
  const key = normalizeSessionKey(sessionKey);
  const result = await sessionMemoryOwner.finalizeSession({
    session_id: key,
    source: options.source || 'housekeeper:session-finalization',
    clearance_level: options.clearanceLevel || 1,
  }, {
    companyId: options.companyId || COMPANY,
    agentId: options.agentId,
    requestAuthority: options.requestAuthority || null,
  });
  conversationSessions.delete(key);
  return result;
}

export function clearConversationSession(sessionKey) {
  conversationSessions.delete(normalizeSessionKey(sessionKey));
}

export function clearAllConversationSessions() {
  conversationSessions.clear();
}

export function getAllSessionStats() {
  const now = nowMs();
  return Array.from(conversationSessions.entries()).map(([key, session]) => {
    const turns = Array.isArray(session.turns) ? session.turns : [];
    const chars = turns.reduce((sum, t) => sum + String(t?.content || '').length, 0);
    return {
      sessionKey: key,
      turnCount: turns.length,
      charCount: chars,
      charBudget: SESSION_TURNS_CHAR_BUDGET,
      maxTurns: CONVERSATION_MAX_TURNS,
      usageRatio: Math.min(1, chars / SESSION_TURNS_CHAR_BUDGET),
      idleSecs: Math.floor((now - (session.lastActivityAt || now)) / 1000),
    };
  });
}

export function buildSessionRunQueueDiagnostics({
  queueWaitMs = 0,
  activeRunsOverride = null,
  waitingRunsOverride = null,
  conversationCharCount = 0,
  sessionKey = 'default',
} = {}) {
  const waiterStats = getWaiterStats();
  const effectiveActiveRuns = activeRunsOverride == null ? activeRuns : Number(activeRunsOverride);
  const effectiveWaitingRuns = waitingRunsOverride == null ? waiters.length : Number(waitingRunsOverride);
  const wait = Math.max(0, Number(queueWaitMs || waiterStats.waitingOldestMs || 0));
  const charPressure = Math.min(1, Math.max(0, Number(conversationCharCount || 0) / SESSION_TURNS_CHAR_BUDGET));
  const queuePressure = Math.min(1, Math.max(0, effectiveActiveRuns / MAX_CONCURRENT_RUNS));
  const waitingPressure = Math.min(1, Math.max(0, effectiveWaitingRuns / MAX_CONCURRENT_RUNS));

  return {
    status: wait > 10000 || waitingPressure > 0.8 ? 'watch' : 'stable',
    source_papers: [AGENTPULSE_SOURCE, AGENTICCACHE_SOURCE],
    diagnostic_only: true,
    session_key: normalizeSessionKey(sessionKey),
    queue: {
      queue_wait_ms: wait,
      max_concurrency: MAX_CONCURRENT_RUNS,
      active_runs: Math.max(0, effectiveActiveRuns),
      waiting_runs: Math.max(0, effectiveWaitingRuns),
      queue_pressure: Number(queuePressure.toFixed(6)),
      waiting_pressure: Number(waitingPressure.toFixed(6)),
    },
    conversation_context: {
      char_count: Math.max(0, Number(conversationCharCount || 0)),
      char_budget: SESSION_TURNS_CHAR_BUDGET,
      pressure: Number(charPressure.toFixed(6)),
      cache_scope: 'ephemeral_conversation_session',
    },
    action_contract: {
      run_reordered_by_diagnostic: false,
      session_cleared_by_diagnostic: false,
      canonical_memory_deleted: false,
    },
  };
}

export function startConversationSessionCleanup() {
  clearAllConversationSessions();
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    purgeExpiredConversationSessions();
  }, 60_000);
}

export function stopConversationSessionCleanup() {
  if (!cleanupTimer) return;
  clearInterval(cleanupTimer);
  cleanupTimer = null;
}

async function withSessionMutex(sessionKey, fn) {
  const laneKey = normalizeSessionKey(sessionKey);
  const previousTail = sessionLaneTails.get(laneKey) || Promise.resolve();
  let releaseCurrent = null;
  const currentTail = new Promise((resolve) => {
    releaseCurrent = resolve;
  });
  const chainedTail = previousTail
    .catch(() => {})
    .then(() => currentTail);

  // Chain this run behind the previous run for the same session key.
  sessionLaneTails.set(laneKey, chainedTail);

  const queuedAt = Date.now();

  try {
    await previousTail.catch(() => {});
    const queueWaitMs = Date.now() - queuedAt;
    return await fn({ queueWaitMs, sessionKey: laneKey });
  } finally {
    releaseCurrent?.();
    if (sessionLaneTails.get(laneKey) === chainedTail) {
      sessionLaneTails.delete(laneKey);
    }
  }
}

async function markSessionLane(client, { companyId, sessionKey, runId, agentId, model }) {
  await client.query(
    `INSERT INTO session_lanes
       (company_id, session_key, run_status, active_run_id, last_agent_id, last_model, last_run_at, updated_at)
     VALUES ($1, $2, 'running', $3, $4, $5, NOW(), NOW())
     ON CONFLICT (company_id, session_key) DO UPDATE
     SET run_status = 'running',
         active_run_id = EXCLUDED.active_run_id,
         last_agent_id = EXCLUDED.last_agent_id,
         last_model = EXCLUDED.last_model,
         last_run_at = NOW(),
         updated_at = NOW()`,
    [companyId, sessionKey, runId, agentId, model || null]
  );
}

async function clearSessionLane(client, { companyId, sessionKey, runId, agentId, model }) {
  await client.query(
    `UPDATE session_lanes
     SET run_status = 'idle',
         active_run_id = NULL,
         last_agent_id = $4,
         last_model = $5,
         last_run_at = NOW(),
         updated_at = NOW()
     WHERE company_id = $1
       AND session_key = $2
       AND ($3::text IS NULL OR active_run_id = $3::text OR run_status = 'running')`,
    [companyId, sessionKey, runId || null, agentId || null, model || null]
  );
}

export async function withSessionLane({
  companyId = COMPANY,
  sessionKey,
  runId,
  agentId,
  model
}, fn) {
  const effectiveSessionKey = sessionKey || `agent:${agentId || 'unknown'}`;
  await acquireGlobalSlot();

  try {
    return await withSessionMutex(effectiveSessionKey, async ({ queueWaitMs, sessionKey: lockedSessionKey }) => {
      const client = await pool.connect();
      try {
        await markSessionLane(client, {
          companyId,
          sessionKey: lockedSessionKey,
          runId,
          agentId,
          model
        });
      } catch (markError) {
        // Keep agent execution healthy even if telemetry state fails.
        console.warn('[session-runner] Failed to mark session lane:', markError?.message || String(markError));
      } finally {
        client.release();
      }

      try {
        const result = await fn({ queueWaitMs, sessionKey: lockedSessionKey });
        return {
          result,
          queueWaitMs,
          sessionKey: lockedSessionKey
        };
      } catch (error) {
        throw error;
      } finally {
        const clearClient = await pool.connect();
        try {
          await clearSessionLane(clearClient, {
            companyId,
            sessionKey: lockedSessionKey,
            runId,
            agentId,
            model
          });
        } catch (clearError) {
          console.warn('[session-runner] Failed to clear session lane:', clearError?.message || String(clearError));
        } finally {
          clearClient.release();
        }
      }
    });
  } finally {
    releaseGlobalSlot();
  }
}

export async function getSessionRunnerStats(companyId = COMPANY) {
  const laneRows = await query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE run_status = 'running')::int AS running
     FROM session_lanes
     WHERE company_id = $1`,
    [companyId]
  );

  const waiterStats = getWaiterStats();
  return {
    maxConcurrency: MAX_CONCURRENT_RUNS,
    activeGlobalRuns: activeRuns,
    waitingGlobalRuns: waiters.length,
    waitingOldestMs: waiterStats.waitingOldestMs,
    waitingAverageMs: waiterStats.waitingAverageMs,
    activeSessionMutexes: sessionLaneTails.size,
    trackedSessionLanes: laneRows.rows[0]?.total || 0,
    runningSessionLanes: laneRows.rows[0]?.running || 0,
    conversationSessions: conversationSessions.size,
    conversationTtlMs: CONVERSATION_TTL_MS,
    conversationMaxTurns: CONVERSATION_MAX_TURNS,
    sessionTurnsCharBudget: SESSION_TURNS_CHAR_BUDGET
  };
}

// Ensure stale sessions never survive process restarts.
startConversationSessionCleanup();
