// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-execution.js
// Pipeline: AGENT_RUN | Position: Event bus (run event broadcasting)
// Batch9.75 Wave 1 authority: Toolformer, ReAct. Event-stream diagnostics
// for tool-use truth and thought-act-observe traces; no hidden tool
// execution, no pipeline mutation.
// ─────────────────────────────────────────────────────────────────────────────
import { EventEmitter } from 'events';
import { buildToolformerToolTruthDiagnostics } from './cooperative-action-arbitration.js';

export const TOOLFORMER_EVENT_SOURCE = 'Toolformer — Language Models Can Teach Themselves to Use Tools';
export const REACT_EVENT_SOURCE = 'ReAct — Synergizing Reasoning and Acting';

const runEvents = new EventEmitter();
runEvents.setMaxListeners(100);
const RUN_EVENT_BUFFER_LIMIT = 500;
let runEventSequence = 0;
const runEventBuffer = [];

function parseEventId(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return parsed;
}

function toPayload(type, payload = {}, id = null) {
  return {
    id: id == null ? null : String(id),
    type: String(type || 'run.unknown'),
    payload: payload || {},
    at: new Date().toISOString()
  };
}

export function publishRunEvent(type, payload = {}) {
  runEventSequence += 1;
  const event = toPayload(type, payload, runEventSequence);
  runEventBuffer.push(event);
  if (runEventBuffer.length > RUN_EVENT_BUFFER_LIMIT) {
    runEventBuffer.splice(0, runEventBuffer.length - RUN_EVENT_BUFFER_LIMIT);
  }
  runEvents.emit('run-event', event);
}

export function publishRuntimeStateEvent({
  runId = null,
  provider = null,
  model = null,
  streamState = 'initialized',
  recoveryReason = null,
  diagnostics = null,
} = {}) {
  const payload = {
    run_id: runId,
    provider,
    model,
    stream_state: String(streamState || 'initialized'),
    recovery_reason: recoveryReason || null,
    diagnostics: diagnostics || null,
    raw_protocol_user_visible: false,
    diagnostic_only: true,
  };
  publishRunEvent('runtime.stream_state', payload);
  return payload;
}

export function buildRunEventStreamSnapshot(events = []) {
  const rows = Array.isArray(events) ? events : [];
  const streamEvents = rows.filter((event) => String(event?.type || '') === 'runtime.stream_state');
  const latest = streamEvents[streamEvents.length - 1] || null;
  return {
    status: latest ? 'observed' : 'empty',
    diagnostic_only: true,
    event_count: streamEvents.length,
    latest_stream_state: latest?.payload?.stream_state || null,
    latest_recovery_reason: latest?.payload?.recovery_reason || null,
    raw_protocol_user_visible: false,
  };
}

export function buildRunEventToolTruthSnapshot(events = []) {
  const rows = Array.isArray(events) ? events : [];
  const observedToolEvents = rows
    .filter((event) => String(event?.type || '').includes('tool') && String(event?.type || '') !== 'tool.claimed')
    .map((event) => event?.payload || event);
  const claimedToolCalls = rows
    .filter((event) => String(event?.type || '') === 'tool.claimed')
    .map((event) => event?.payload || event);

  return {
    status: 'diagnostic',
    diagnostic_only: true,
    event_count: rows.length,
    tool_truth: buildToolformerToolTruthDiagnostics({ claimedToolCalls, observedToolEvents }),
    raw_protocol_user_visible: false,
    hidden_tool_execution_enabled: false,
    guarded_math: {
      toolformer_event: true,
      react_event: true,
    },
    guarded_math_implemented: {
      toolformer_event: { enabled: true, diagnostic_only: true, source_paper: TOOLFORMER_EVENT_SOURCE },
      react_event: { enabled: true, diagnostic_only: true, source_paper: REACT_EVENT_SOURCE },
    },
  };
}

export function getRunEventsSince(afterEventId = null, limit = RUN_EVENT_BUFFER_LIMIT) {
  const normalizedAfterId = parseEventId(afterEventId);
  const boundedLimit = Math.max(1, Math.min(Number(limit || RUN_EVENT_BUFFER_LIMIT), RUN_EVENT_BUFFER_LIMIT));
  const filtered = normalizedAfterId == null
    ? runEventBuffer
    : runEventBuffer.filter((evt) => parseEventId(evt.id) > normalizedAfterId);
  if (filtered.length <= boundedLimit) return filtered.slice();
  return filtered.slice(filtered.length - boundedLimit);
}

export function subscribeRunEvents(listener, options = {}) {
  if (typeof listener !== 'function') return () => {};
  const replayAfterId = parseEventId(options?.replayAfterId);
  const replayLimit = Math.max(1, Math.min(Number(options?.replayLimit || RUN_EVENT_BUFFER_LIMIT), RUN_EVENT_BUFFER_LIMIT));
  if (options?.replay !== false) {
    const replayEvents = getRunEventsSince(replayAfterId, replayLimit);
    for (const event of replayEvents) {
      try {
        listener(event);
      } catch {
        // Listener failures must not break stream subscriptions.
      }
    }
  }
  runEvents.on('run-event', listener);
  return () => runEvents.off('run-event', listener);
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Alongside-path event diagnostics
// ---------------------------------------------------------------------------

/**
 * Toolformer Event Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Toolformer — Language Models Can Teach Themselves to Use Tools
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Assesses whether a run event represents a self-inserted tool call
 * (Toolformer pattern). The diagnostic examines tool-call events for
 * indicators of model-initiated tool insertion versus user-specified tools.
 * It is an observable metric; production tool-truth interception in
 * cooperative-action-arbitration remains authoritative. Guarded by
 * guarded_math flag toolformer_event (knowledge-gated).
 */
export function buildToolformerEventDiagnostic(event = {}) {
  const type = String(event?.type || event?.payload?.type || '');
  const payload = event?.payload || event || {};
  const isToolCall = type.includes('tool') || String(payload.tool_name || '').length > 0;
  const isUserSpecified = Boolean(payload.user_specified || payload.explicit_tool_call);
  const isModelInserted = isToolCall && !isUserSpecified;
  const toolName = String(payload.tool_name || payload.tool || 'unknown');
  const hasInputSchema = Boolean(payload.input_schema || payload.parameters || payload.args);
  const hasOutputValidation = Boolean(payload.output_validated || payload.verified);

  return {
    diagnostic: true,
    source_paper: TOOLFORMER_EVENT_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    event_type: type,
    tool_call_detected: isToolCall,
    model_inserted_tool: isModelInserted,
    user_specified_tool: isUserSpecified,
    tool_name: isToolCall ? toolName : null,
    input_schema_present: hasInputSchema,
    output_validation_present: hasOutputValidation,
    tool_truth_interception_unchanged: true,
    note: 'Alongside-path diagnostic. Tool-use truth assessment does not replace production tool-truth interception.',
  };
}

/**
 * ReAct Event Diagnostic — Alongside-path diagnostic
 *
 * Source paper: ReAct — Synergizing Reasoning and Acting
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Assesses whether a run event follows the Thought→Act→Observe trace
 * pattern (ReAct). The diagnostic examines event sequences for structured
 * reasoning-acting interleaving. It is an observable metric; production
 * reasoning trace checking in reasoning-trace-check remains authoritative.
 * Guarded by guarded_math flag react_event (knowledge-gated).
 */
export function buildReActEventDiagnostic(event = {}) {
  const type = String(event?.type || event?.payload?.type || '');
  const payload = event?.payload || event || {};
  const isThought = /thought|reason|think|plan/i.test(type) || Boolean(payload.thought || payload.reasoning);
  const isAct = /act|action|tool|execute/i.test(type) || Boolean(payload.action || payload.tool_name);
  const isObserve = /observ|result|output|response/i.test(type) || Boolean(payload.observation || payload.result);
  const phase = isThought ? 'thought' : isAct ? 'act' : isObserve ? 'observe' : 'unknown';
  const hasInterleaving = isThought || isAct || isObserve;

  return {
    diagnostic: true,
    source_paper: REACT_EVENT_SOURCE,
    coexistence_class: 'side_by_side_overlay',
    event_type: type,
    react_phase: phase,
    thought_detected: isThought,
    action_detected: isAct,
    observation_detected: isObserve,
    interleaving_present: hasInterleaving,
    reasoning_trace_check_unchanged: true,
    note: 'Alongside-path diagnostic. ReAct trace assessment does not replace production reasoning-trace-check.',
  };
}
