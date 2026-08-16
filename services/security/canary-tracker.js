/**
 * canary-tracker.js — Kill-Chain Canary Stage Tracking (P0-B3-6)
 * Source: Kill-Chain Canaries (MIT, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: quality-gate.js (Wall 2) or tool-registry.js
 * 2. → Pulls from: Inbound prompt strings (Injection payloads)
 * 3. → Pushes to: services/observe/event-ledger.js (Provenance logs)
 * 4. ↔ Interacts with: aimos_memories (Tracks persistence stage)
 *
 * LOGIC GUIDE: Uses cryptographic tokens (SECRET-[A-F0-9]{8}) to trace 
 * prompt injections through 4 stages: EXPOSED → PERSISTED → RELAYED → EXECUTED.
 * Additive Batch9 Wave2 authority: The Midas Touch and Governing What You
 * Cannot Observe. Canary scans now return native kill-chain diagnostics without
 * changing token semantics or canonical memory behavior.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { randomBytes } from 'node:crypto';

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;
const CANARY_REGEX = /\bSECRET-[A-F0-9]{8}(?![A-Za-z0-9_])/g;
const STAGES = ['EXPOSED', 'PERSISTED', 'RELAYED', 'EXECUTED'];

/**
 * @typedef {Object} CanaryEvent
 * @property {string} canaryToken
 * @property {'EXPOSED'|'PERSISTED'|'RELAYED'|'EXECUTED'} stage
 * @property {string} location - where detected (tool name, memory key, etc.)
 * @property {string} runId
 * @property {number} timestamp
 */

// In-memory event log (flushed to Aimos periodically)
const _eventLog = [];

export function buildCanaryKillChainDiagnostics(events = _eventLog) {
  const eventList = Array.isArray(events) ? events : [];
  const stageCounts = { EXPOSED: 0, PERSISTED: 0, RELAYED: 0, EXECUTED: 0 };
  for (const event of eventList) {
    if (stageCounts[event.stage] !== undefined) stageCounts[event.stage] += 1;
  }
  const deepestStage = [...STAGES].reverse().find((stage) => stageCounts[stage] > 0) || 'NONE';
  return {
    source_papers: [
      'Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection Across Attack Surfaces and Model Safety Tiers',
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
    ],
    diagnostic_only: true,
    stage_counts: stageCounts,
    deepest_stage: deepestStage,
    executed_stage_seen: stageCounts.EXECUTED > 0,
    executed_tool_invocations: eventList.filter((event) => event.stage === 'EXECUTED' && event.toolInvoked === true).length,
    blocked_tool_dispatches: eventList.filter((event) => event.stage === 'EXECUTED' && event.dispatchBlocked === true).length,
    relay_decontamination_rate: computeDecontaminationRate(eventList),
    canonical_memory_changed: false,
    canary_semantics_changed: false,
  };
}

/**
 * Generate a canary token for injection tracking.
 * @returns {string} SECRET-XXXXXXXX format token
 */
export function generateCanary() {
  return `SECRET-${randomBytes(4).toString('hex').toUpperCase()}`;
}

/**
 * Scan text for canary tokens.
 * @param {string} text
 * @returns {string[]} found canary tokens
 */
export function detectCanaries(text) {
  const matches = renderCanaryText(text).match(CANARY_REGEX);
  return matches ? [...new Set(matches)] : [];
}

function renderCanaryText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Log a canary detection event at a specific pipeline stage.
 *
 * @param {string} canaryToken
 * @param {'EXPOSED'|'PERSISTED'|'RELAYED'|'EXECUTED'} stage
 * @param {string} location - where detected
 * @param {string} runId
 * @param {object} context
 * @param {string|null} [context.parentEventId]
 * @param {object|null} [context.authority]
 * @param {boolean} [context.toolInvoked]
 * @param {boolean} [context.dispatchBlocked]
 */
export async function logCanaryEvent(canaryToken, stage, location, runId = '', context = {}) {
  if (!STAGES.includes(stage)) throw new Error(`invalid_canary_stage:${stage}`);
  const event = {
    canaryToken,
    stage,
    location,
    runId,
    timestamp: Date.now(),
    toolInvoked: context.toolInvoked === true,
    dispatchBlocked: context.dispatchBlocked === true,
  };
  const dispatchState = event.dispatchBlocked
    ? 'The outbound dispatch was blocked before the tool function was invoked.'
    : event.toolInvoked
      ? 'The tool function was invoked.'
      : 'No tool invocation is attributed to this stage.';
  const receipt = await logEvent(
    COMPANY,
    'canary-tracker',
    stage === 'EXECUTED' ? 'canary_executed' : 'security_detection',
    stage === 'EXECUTED' ? `canary:${canaryToken}` : `canary:${stage.toLowerCase()}:${canaryToken}`,
    {
      reasoning: `Security event: Canary token ${canaryToken} reached the ${stage} boundary at ${location}. ${dispatchState}`,
      severity: stage === 'EXECUTED' ? 'critical' : stage === 'RELAYED' ? 'high' : 'medium',
      details: {
        canaryToken,
        stage,
        location,
        runId,
        tool_invoked: event.toolInvoked,
        dispatch_blocked: event.dispatchBlocked,
      },
      source_knowledge: 'Kill-Chain Canaries — stage-level propagation tracking',
    },
    context.parentEventId || null,
    { authority: context.authority || null, returnReceipt: true },
  );
  const provenEvent = Object.freeze({ ...event, receipt });
  _eventLog.push(provenEvent);
  if (stage === 'EXECUTED') {
    console.error(`[CANARY-ALERT] Injection reached the EXECUTED boundary: ${canaryToken} at ${location}`);
  }
  return provenEvent;
}

/**
 * Middleware: scan tool results for canary tokens.
 * Call after each tool execution to detect EXPOSED stage.
 *
 * @param {string} toolName
 * @param {string} toolResult
 * @param {string} runId
 * @returns {{ canariesFound: string[], stage: string }}
 */
export async function scanToolResult(toolName, toolResult, runId = '', context = {}) {
  const canaries = detectCanaries(toolResult);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'EXPOSED', `tool_result:${toolName}`, runId, context));
  }
  return { canariesFound: canaries, stage: 'EXPOSED', events, kill_chain_diagnostics: buildCanaryKillChainDiagnostics() };
}

/**
 * Middleware: scan memory write for canary tokens.
 * Call before persisting to Aimos to detect PERSISTED stage.
 *
 * @param {string} key
 * @param {string} value
 * @param {string} runId
 * @returns {{ canariesFound: string[], blocked: boolean }}
 */
export async function scanMemoryWrite(key, value, runId = '', context = {}) {
  const canaries = detectCanaries([key, value]);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'PERSISTED', `memory_write:${key}`, runId, context));
  }
  return { canariesFound: canaries, blocked: canaries.length > 0, events, kill_chain_diagnostics: buildCanaryKillChainDiagnostics() };
}

/**
 * Scan only recalled memory before it is delivered to a model. User input,
 * system instructions, and model output are not relay evidence.
 *
 * @param {string|object} recalledMemory
 * @param {string} runId
 * @returns {{ canariesFound: string[] }}
 */
export async function scanRelayedMemory(recalledMemory, runId = '', context = {}) {
  const canaries = detectCanaries(recalledMemory);
  const events = [];
  const sourceAgentId = String(context.sourceAgentId || 'memory');
  const targetAgentId = String(context.targetAgentId || 'model');
  for (const token of canaries) {
    events.push(await logCanaryEvent(
      token,
      'RELAYED',
      `recalled_memory:${sourceAgentId}->${targetAgentId}`,
      runId,
      context,
    ));
  }
  return { canariesFound: canaries, events, kill_chain_diagnostics: buildCanaryKillChainDiagnostics() };
}

/**
 * Middleware: scan outbound tool call arguments for canary tokens.
 * Call before executing any tool to detect EXECUTED stage.
 *
 * @param {string} toolName
 * @param {string} toolArgs - JSON-stringified arguments
 * @param {string} runId
 * @returns {{ canariesFound: string[], blocked: boolean }}
 */
export async function scanToolExecution(toolName, toolArgs, runId = '', context = {}) {
  const canaries = detectCanaries(toolArgs);
  const events = [];
  for (const token of canaries) {
    events.push(await logCanaryEvent(token, 'EXECUTED', `tool_exec:${toolName}`, runId, {
      ...context,
      toolInvoked: false,
      dispatchBlocked: true,
    }));
  }
  return { canariesFound: canaries, blocked: canaries.length > 0, events, kill_chain_diagnostics: buildCanaryKillChainDiagnostics() };
}

/**
 * Compute objective drift: TF-IDF cosine distance between current tool args
 * and original task description.
 *
 * @param {string} originalTask
 * @param {string} currentToolArgs
 * @returns {number} drift score (0 = aligned, 1 = completely diverged)
 */
export function computeObjectiveDrift(originalTask, currentToolArgs) {
  const taskTerms = extractTerms(originalTask);
  const argsTerms = extractTerms(currentToolArgs);

  if (taskTerms.size === 0 || argsTerms.size === 0) return 1.0;

  // Jaccard-based drift (simplified TF-IDF proxy)
  const intersection = new Set([...taskTerms].filter(t => argsTerms.has(t)));
  const union = new Set([...taskTerms, ...argsTerms]);

  return 1 - (intersection.size / union.size);
}

/**
 * Token-overlap provenance heuristic.
 * Match alphanumeric tokens (>=4 chars) between tool args and prior tool results.
 *
 * @param {string} toolArgs
 * @param {string[]} priorToolResults
 * @returns {{ matched: boolean, overlapCount: number, coverageRatio: number }}
 */
export function checkTokenProvenance(toolArgs, priorToolResults) {
  const argTokens = extractTerms(toolArgs);
  if (argTokens.size === 0) return { matched: false, overlapCount: 0, coverageRatio: 0 };

  const allPriorTokens = new Set();
  for (const result of priorToolResults) {
    for (const t of extractTerms(result)) allPriorTokens.add(t);
  }

  const overlap = [...argTokens].filter(t => allPriorTokens.has(t));
  const coverageRatio = overlap.length / argTokens.size;

  return {
    matched: overlap.length >= 3 || coverageRatio >= 0.2,
    overlapCount: overlap.length,
    coverageRatio
  };
}

/**
 * Extract alphanumeric tokens >= 4 chars.
 */
function extractTerms(text) {
  const tokens = String(text || '').toLowerCase().match(/[a-z0-9]{4,}/g) || [];
  return new Set(tokens);
}

/**
 * Get the full canary event log for a run.
 * @param {string} runId
 * @returns {CanaryEvent[]}
 */
export function getRunEvents(runId) {
  return _eventLog.filter(e => e.runId === runId);
}

/**
 * Get stage-level propagation summary.
 * Shows how far injections penetrated the pipeline.
 */
export function getPropagationSummary() {
  const summary = { EXPOSED: 0, PERSISTED: 0, RELAYED: 0, EXECUTED: 0 };
  for (const event of _eventLog) {
    summary[event.stage] = (summary[event.stage] || 0) + 1;
  }
  return summary;
}

/**
 * Compute relay decontamination rate.
 * Fraction of injections stripped at the relay/summarization stage.
 */
export function getDecontaminationRate() {
  return computeDecontaminationRate(_eventLog);
}

function computeDecontaminationRate(events) {
  const exposed = events.filter(e => e.stage === 'EXPOSED').length;
  const relayed = events.filter(e => e.stage === 'RELAYED').length;
  if (exposed === 0) return 1.0;
  return Math.max(0, Math.min(1, 1 - (relayed / exposed)));
}
