// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js
// → Calls: db (connection.js)
// Pipeline: AGENT_RUN | Position: Conversation history management
// Source: Session Management patterns, TTL-based caching (Redis patterns)
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { sessionMemoryOwner } from './session-memory-owner.js';
import { logEvent, readVerifiedEventHistory } from '../observe/event-ledger.js';
import { performance } from 'node:perf_hooks';
import { beginServingWork } from '../runtime/serving-control.js';

const COMPANY = AIMOS_COMPANY_ID;
const MAX_CONCURRENT_RUNS = 6;
// Admission policy, not retained-history limits: at most six waiting turns per
// session and six waves of globally waiting work. Running capacity is unchanged.
const MAX_QUEUED_PER_SESSION = MAX_CONCURRENT_RUNS;
const MAX_QUEUED_RUNS = MAX_CONCURRENT_RUNS * MAX_CONCURRENT_RUNS;
const MAX_QUEUE_WAIT_MS = 30_000;
const CONVERSATION_TTL_MS = 5 * 60 * 1000;
const CONVERSATION_MAX_TURNS = 20;
const SESSION_TURNS_CHAR_BUDGET = 30_000;
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const AGENTICCACHE_SOURCE = 'AGENTICCACHE: Cache-Driven Asynchronous Planning for Embodied AI Agents';

let activeRuns = 0;
const waiters = new Map();
const conversationSessions = new Map();
const sessionLanes = new Map();
const readySessions = new Map();
const idleWaiters = new Set();
let admissionOpen = true;
let cleanupTimer = null;

function admissionError(code, statusCode = 503) {
  return Object.assign(new Error(code), { code, statusCode, executionStarted: false });
}

function removeWaiting(entry) {
  entry.lane.queue.delete(entry);
  waiters.delete(entry);
  clearTimeout(entry.timer);
  entry.signal?.removeEventListener('abort', entry.cancel);
}

function refreshReady(lane) {
  if (!lane.active && lane.queue.size) readySessions.set(lane.key, lane);
  if (!lane.queue.size) {
    readySessions.delete(lane.key);
    if (!lane.active) sessionLanes.delete(lane.key);
  }
}

function cancelWaiting(entry, error) {
  if (!waiters.has(entry)) return;
  removeWaiting(entry);
  refreshReady(entry.lane);
  entry.reject(error);
  dispatchReady();
}

function dispatchReady() {
  while (admissionOpen && activeRuns < MAX_CONCURRENT_RUNS && readySessions.size) {
    const lane = readySessions.values().next().value;
    readySessions.delete(lane.key);
    const entry = lane.queue.keys().next().value;
    if (entry.signal?.aborted || performance.now() >= entry.deadlineAt) {
      removeWaiting(entry);
      entry.reject(admissionError(entry.signal?.aborted ? 'session_queue_cancelled' : 'session_queue_timed_out', 408));
      refreshReady(lane);
      continue;
    }
    removeWaiting(entry);
    lane.active = true;
    activeRuns += 1;
    let released = false;
    entry.resolve({
      queueWaitMs: performance.now() - entry.queuedAt,
      assertReady() {
        if (!admissionOpen || entry.signal?.aborted) throw admissionError('session_queue_cancelled', 408);
        if (performance.now() >= entry.deadlineAt) throw admissionError('session_queue_timed_out', 408);
      },
      release() {
        if (released) throw new Error('session_slot_double_release');
        released = true;
        lane.active = false;
        activeRuns -= 1;
        refreshReady(lane);
        dispatchReady();
        if (!activeRuns && !waiters.size) for (const done of idleWaiters) done();
      },
    });
  }
}

function acquireSessionSlot(companyId, sessionKey, signal, deadlineAt) {
  if (!admissionOpen) return Promise.reject(admissionError('session_admission_draining'));
  if (signal?.aborted) return Promise.reject(admissionError('session_queue_cancelled', 408));
  const now = performance.now();
  if (deadlineAt !== undefined && !Number.isFinite(deadlineAt)) return Promise.reject(admissionError('session_queue_deadline_invalid', 400));
  const deadline = Math.min(now + MAX_QUEUE_WAIT_MS, deadlineAt ?? Infinity);
  if (deadline <= now) return Promise.reject(admissionError('session_queue_timed_out', 408));
  const key = JSON.stringify([companyId, sessionKey]);
  const lane = sessionLanes.get(key) || { key, active: false, queue: new Map() };
  if (waiters.size >= MAX_QUEUED_RUNS || lane.queue.size >= MAX_QUEUED_PER_SESSION) {
    return Promise.reject(admissionError('session_queue_overloaded', 429));
  }
  sessionLanes.set(key, lane);
  return new Promise((resolve, reject) => {
    const entry = { lane, resolve, reject, queuedAt: now, deadlineAt: deadline, signal };
    entry.cancel = () => cancelWaiting(entry, admissionError('session_queue_cancelled', 408));
    entry.timer = setTimeout(() => cancelWaiting(entry, admissionError('session_queue_timed_out', 408)), Math.ceil(deadline - now));
    signal?.addEventListener('abort', entry.cancel, { once: true });
    lane.queue.set(entry, entry);
    waiters.set(entry, entry);
    refreshReady(lane);
    dispatchReady();
  });
}

export function stopSessionAdmission() {
  admissionOpen = false;
  for (const entry of waiters.values()) cancelWaiting(entry, admissionError('session_admission_draining'));
  stopConversationSessionCleanup();
}

export function waitForSessionIdle() {
  if (!activeRuns && !waiters.size) return Promise.resolve();
  return new Promise(resolve => {
    const done = () => { idleWaiters.delete(done); resolve(); };
    idleWaiters.add(done);
  });
}

function getWaiterStats(now = performance.now()) {
  if (!waiters.size) {
    return {
      waitingOldestMs: 0,
      waitingAverageMs: 0
    };
  }
  const waits = [...waiters.values()]
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
  if (Array.isArray(options.canonicalMemories)) {
    const canonicalized = sessionMemoryOwner.canonicalizeRetainedTurns
      ? sessionMemoryOwner.canonicalizeRetainedTurns(options.canonicalMemories, key)
      : null;
    if (canonicalized?.canonical?.length) {
      session = {
        turns: canonicalized.canonical.map((turn) => ({
          memory_id: String(turn.row.id),
          role: turn.record.role,
          content: turn.record.content,
          at: turn.record.observed_at,
        })),
        lastActivityAt: nowMs(),
      };
      session.turns = trimConversationTurns(session.turns);
      conversationSessions.set(key, session);
    } else {
      session = null;
      conversationSessions.delete(key);
    }
  }
  if (!session && options.loadDurable !== false) {
    const durableTurns = await sessionMemoryOwner.loadVerifiedTurns({ session_id: key }, {
      companyId: options.companyId || COMPANY,
      agentId: options.agentId || 'housekeeper',
    });
    if (durableTurns.length) {
      session = {
        turns: durableTurns.map((turn) => ({
          memory_id: turn.memory_id,
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
    .map((turn) => ({ role: turn.role, content: turn.content, memory_id: turn.memory_id || null }));
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
      nativeToolInputs: options.nativeToolInputs || null,
    });
  }
  const session = ensureConversationSession(sessionKey);
  session.turns.push({
    memory_id: persistence?.memory_id || null,
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
  const effectiveWaitingRuns = waitingRunsOverride == null ? waiters.size : Number(waitingRunsOverride);
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
  if (!Array.isArray(events)) throw new Error('session_lane_recovery_input_invalid');
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
  signal = null,
  deadlineAt,
}, fn) {
  const finishWork = beginServingWork('session_run');
  try {
  const effectiveSessionKey = normalizeSessionKey(sessionKey || `agent:${agentId || 'unknown'}`);
  let slot;
  try {
    slot = await acquireSessionSlot(companyId, effectiveSessionKey, signal, deadlineAt);
  } catch (error) {
    await logEvent(companyId, agentId || 'housekeeper', 'session_lane_admission_denied', `${effectiveSessionKey}:${runId}`, {
      run_id: runId, session_key: effectiveSessionKey, disposition: error.code,
      execution_started: false, reasoning: 'The bounded native session queue did not admit a callback; no session execution started.',
    }, authority?.requestAdmissionEventId || null, { authority });
    throw error;
  }

  try {
      const queueWaitMs = slot.queueWaitMs;
      const lockedSessionKey = effectiveSessionKey;
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
        slot.assertReady();
        const result = await fn({ queueWaitMs, sessionKey: lockedSessionKey });
        disposition = 'COMPLETED';
        return {
          result,
          queueWaitMs,
          sessionKey: lockedSessionKey
        };
      } catch (error) {
        disposition = error.executionStarted === false ? 'CANCELLED_BEFORE_EXECUTION'
          : String(error?.message || '').includes('timed out') ? 'TIMEOUT' : 'FAILED';
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
  } finally {
    slot.release();
  }
  } finally { finishWork(); }
}

export async function getSessionRunnerStats(companyId = COMPANY) {
  const waiterStats = getWaiterStats();
  return {
    maxConcurrency: MAX_CONCURRENT_RUNS,
    activeGlobalRuns: activeRuns,
    waitingGlobalRuns: waiters.size,
    admissionOpen,
    maxQueuedRuns: MAX_QUEUED_RUNS,
    maxQueuedPerSession: MAX_QUEUED_PER_SESSION,
    maxQueueWaitMs: MAX_QUEUE_WAIT_MS,
    waitingOldestMs: waiterStats.waitingOldestMs,
    waitingAverageMs: waiterStats.waitingAverageMs,
    activeSessionMutexes: activeRuns,
    trackedSessionLanes: sessionLanes.size,
    runningSessionLanes: activeRuns,
    conversationSessions: conversationSessions.size,
    conversationTtlMs: CONVERSATION_TTL_MS,
    conversationMaxTurns: CONVERSATION_MAX_TURNS,
    sessionTurnsCharBudget: SESSION_TURNS_CHAR_BUDGET
  };
}

// Ensure stale sessions never survive process restarts.
startConversationSessionCleanup();
