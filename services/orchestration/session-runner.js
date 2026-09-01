// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js
// → Calls: db (connection.js)
// Pipeline: AGENT_RUN | Position: Conversation history management
// Source: Session Management patterns, TTL-based caching (Redis patterns)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { sessionMemoryOwner } from './session-memory-owner.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const MAX_CONCURRENT_RUNS = 6;
const CONVERSATION_TTL_MS = 5 * 60 * 1000;
const CONVERSATION_MAX_TURNS = 20;
const SESSION_TURNS_CHAR_BUDGET = 30_000;
const MAX_RECOVERY_EVENTS = 100_000;
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
      requestAuthority: options.requestAuthority || null,
      autonomousHousekeeper: options.autonomousHousekeeper === true,
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
    autonomousHousekeeper: options.autonomousHousekeeper === true,
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

async function markSessionLane({ companyId, sessionKey, runId, agentId, model, authority }) {
  return logEvent(companyId, agentId || 'housekeeper', 'session_lane_started', `${sessionKey}:${runId}`, {
    schema: 'hom.aimos.session-lane-transition/v1',
    company_id: companyId,
    session_key: sessionKey,
    run_id: runId,
    agent_id: agentId || null,
    model: model || null,
    status: 'running',
    reasoning: 'The verified run acquired the bounded in-process session mutex before execution.',
  }, authority?.requestAdmissionEventId || null, {
    authority,
    exclusiveOperationKey: true,
    returnReceipt: true,
  });
}

async function clearSessionLane({ companyId, sessionKey, runId, agentId, model, authority, disposition, startEventId, startMutationHash }) {
  return logEvent(companyId, agentId || 'housekeeper', 'session_lane_terminal', `${sessionKey}:${runId}`, {
    schema: 'hom.aimos.session-lane-transition/v1',
    company_id: companyId,
    session_key: sessionKey,
    run_id: runId,
    start_event_id: startEventId,
    start_mutation_hash: startMutationHash,
    agent_id: agentId || null,
    model: model || null,
    status: 'idle',
    disposition,
    reasoning: `The bounded session mutex was released after ${String(disposition).toLowerCase()} execution.`,
  }, startEventId, {
    authority,
    exclusiveOperationKey: true,
    returnReceipt: true,
  });
}

function sessionEventMetadata(event) {
  if (event?.metadata && typeof event.metadata === 'object') return event.metadata;
  try { return JSON.parse(event?.metadata || '{}'); } catch { return {}; }
}

function sessionEventMutationHash(event) {
  return typeof event?.mutation_hash === 'string'
    ? event.mutation_hash
    : Buffer.from(event?.mutation_hash || []).toString('hex');
}

export function reconstructSessionLaneTraces(events = []) {
  if (!Array.isArray(events) || events.length > MAX_RECOVERY_EVENTS) throw new Error('session_lane_recovery_limit');
  const lanes = new Map();
  for (const event of events) {
    if (!['session_lane_started', 'session_lane_terminal'].includes(event?.operation)) continue;
    const metadata = sessionEventMetadata(event);
    if (metadata.schema !== 'hom.aimos.session-lane-transition/v1') continue;
    const laneId = `${metadata.session_key}:${metadata.run_id}`;
    if (!metadata.session_key || !metadata.run_id || String(event.key || '') !== laneId) {
      throw new Error('session_lane_key_mismatch');
    }
    const trace = lanes.get(laneId) || { laneId, start: null, terminal: null };
    if (event.operation === 'session_lane_started') {
      if (trace.start) throw new Error('session_lane_start_fork');
      trace.start = event;
    } else {
      if (trace.terminal) throw new Error('session_lane_terminal_fork');
      trace.terminal = event;
    }
    lanes.set(laneId, trace);
  }
  const ordered = [...lanes.values()].sort((left, right) => left.laneId.localeCompare(right.laneId));
  for (const trace of ordered) {
    if (!trace.start) throw new Error('session_lane_terminal_without_start');
    if (!trace.terminal) continue;
    const metadata = sessionEventMetadata(trace.terminal);
    const startId = String(trace.start.id || trace.start.event_id || '');
    if (String(trace.terminal.parent_event_id || '') !== startId
        || metadata.start_event_id !== startId
        || metadata.start_mutation_hash !== sessionEventMutationHash(trace.start)) {
      throw new Error('session_lane_terminal_start_binding_invalid');
    }
  }
  return Object.freeze({
    complete: Object.freeze(ordered.filter((trace) => trace.terminal)),
    open: Object.freeze(ordered.filter((trace) => !trace.terminal)),
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function reconcileOpenSessionLanes({
  companyId = COMPANY,
  events = null,
  readHistoryFn = readVerifiedEventHistory,
  terminalFn = clearSessionLane,
} = {}) {
  const load = async () => events || readHistoryFn(companyId, { signerAgentId: 'housekeeper' });
  const before = reconstructSessionLaneTraces(await load());
  const reconciled = [];
  for (const trace of before.open) {
    const start = sessionEventMetadata(trace.start);
    const receipt = await terminalFn({
      companyId,
      sessionKey: start.session_key,
      runId: start.run_id,
      agentId: trace.start.agent_id || start.agent_id || 'housekeeper',
      model: start.model || null,
      authority: null,
      disposition: 'INDETERMINATE_PROCESS_RESTART',
      startEventId: String(trace.start.id || trace.start.event_id || ''),
      startMutationHash: sessionEventMutationHash(trace.start),
    });
    reconciled.push(Object.freeze({ laneId: trace.laneId, receipt }));
  }
  const after = reconstructSessionLaneTraces(await load());
  return Object.freeze({
    scanned: before.complete.length + before.open.length,
    reconciled: Object.freeze(reconciled),
    remainingOpen: after.open.length,
    sessionCallbacksReplayed: 0,
    timeComplexity: 'O(n)',
    spaceComplexity: 'O(n)',
  });
}

export async function withSessionLane({
  companyId = COMPANY,
  sessionKey,
  runId,
  agentId,
  model,
  authority = null,
}, fn) {
  const effectiveSessionKey = sessionKey || `agent:${agentId || 'unknown'}`;
  await acquireGlobalSlot();

  try {
    return await withSessionMutex(effectiveSessionKey, async ({ queueWaitMs, sessionKey: lockedSessionKey }) => {
      const startReceipt = await markSessionLane({
        companyId,
        sessionKey: lockedSessionKey,
        runId,
        agentId,
        model,
        authority,
      });

      let disposition = 'FAILED';
      try {
        const result = await fn({ queueWaitMs, sessionKey: lockedSessionKey });
        disposition = 'COMPLETED';
        return {
          result,
          queueWaitMs,
          sessionKey: lockedSessionKey
        };
      } catch (error) {
        disposition = String(error?.message || '').includes('timed out') ? 'TIMEOUT' : 'FAILED';
        throw error;
      } finally {
        await clearSessionLane({
          companyId,
          sessionKey: lockedSessionKey,
          runId,
          agentId,
          model,
          authority,
          disposition,
          startEventId: startReceipt.event_id,
          startMutationHash: startReceipt.mutation_hash,
        });
      }
    });
  } finally {
    releaseGlobalSlot();
  }
}

export async function getSessionRunnerStats(companyId = COMPANY) {
  const waiterStats = getWaiterStats();
  return {
    maxConcurrency: MAX_CONCURRENT_RUNS,
    activeGlobalRuns: activeRuns,
    waitingGlobalRuns: waiters.length,
    waitingOldestMs: waiterStats.waitingOldestMs,
    waitingAverageMs: waiterStats.waitingAverageMs,
    activeSessionMutexes: sessionLaneTails.size,
    trackedSessionLanes: sessionLaneTails.size,
    runningSessionLanes: activeRuns,
    conversationSessions: conversationSessions.size,
    conversationTtlMs: CONVERSATION_TTL_MS,
    conversationMaxTurns: CONVERSATION_MAX_TURNS,
    sessionTurnsCharBudget: SESSION_TURNS_CHAR_BUDGET
  };
}

// Ensure stale sessions never survive process restarts.
startConversationSessionCleanup();
