/**
 * agent-runner.js — Central Brain Execution Engine
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js, telegram-bot.js, server.js
 * 2. → Calls: 30+ services (The AGENT_RUN_PIPELINE)
 * 3. ↔ Interacts with: tool-registry.js (Execution context)
 * 4. ↔ Interacts with: meta-controller.js (Execution mode resolution)
 * 5. → Pushes to: aimos_events (Mandatory reasoning traces)
 *
 * LOGIC GUIDE: Primary entry point for all agentic reasoning. Assembles prompts, 
 * resolves BDI state, manages tool loops, and enforces security gates.
 *
 * Sources (additive reasoning persistence layer): From RAG to Memory, HippoRAG,
 * GraphRAG, PathRAG, G-Retriever, Knowledge Is Not Static, CubeGraph. These
 * papers guide durable reasoning artifacts and later lineage recall; this layer
 * does not alter the existing decision math.
 * Batch8 Wave4 sources: GrandCode, FronTalk, LLM-Agent-Controller,
 * AI Agent Systems. Adds passive agent-run benchmark/controller diagnostics;
 * no RL loop, autonomous controller correction, or tool unlock is enabled.
 * Batch8 Wave6 sources: Fast Heterogeneous Serving, Stream, BranchLoRA,
 * SoulX-Duplug, VLM-Augmented Degradation Modeling. Exposes passive serving,
 * sparse-context, and inactive multimodal adapter diagnostics only; live model
 * routing, sparse attention, LoRA, and multimodal fusion remain guarded.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: aimos.js, telegram-bot.js, server.js, governance-resolver.js
// → Calls: agent-store.js, tool-registry.js, session-runner.js, model-preferences.js,
//           permissions.js, agent-learning.js, run-metadata.js
// Pipeline: AGENT_RUN | Position: Central hub (main orchestrator)
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { agents, ensureAgent } from './agent-store.js';
import { getToolsForAgent, executeTool } from './tool-registry.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { persistMemory } from '../write/persist-memory.js';
import { getConversationHistory, addConversationTurn } from './session-runner.js';
import { buildModelAllocationDiagnostics, resolveModelForRequest } from './model-preferences.js';
import { resolveProviderForModel } from '../core/providers.js';
import {
  runSentinelCheck, isCybersecAction
} from '../security/cybersec-firewall.js';
// filterCybersecContent, isCybersecLocked, auditLog, screenPromptForSocialEngineering,
// Context-aware social-engineering decisions are owned by agent-security-gates.js.
import { recordAgentRun, selfReflect, getSharedFailures, recordRecommendation, afterActionReview, getCalibrationFactor } from '../learning/agent-learning.js';
// buildPsychometricContract, checkRiskBudget, updateBehavioralBaseline — now used via agent-security-gates.js
import { buildEpistemicBlindingGate, deblindText } from '../learning/epistemic-vigilance.js';
import { assessQuality } from '../write/quality-gate.js';
import { evaluateSocialLawViolations } from '../core/brain-contract.js';
import { fetchWithTimeout } from './http.js';
import { logEvent } from '../observe/event-ledger.js';
import { getPermissions } from '../core/permissions.js';
import {
  createKnowledgeGateState,
  recordKnowledgeToolEvent,
  shouldBlockCompletionForMissingKnowledge
} from '../security/knowledge-gate.js';
import { evaluateDelegatedDirectiveAgainstConstitution } from '../core/hom-constitution.js';
import { META_ACTIONS } from './meta-controller.js';
// evaluateMetaState — now used via agent-security-gates.js
import { computePlasticity } from '../learning/plasticity-controller.js';
import {
  buildSecurityDecisionEvidence,
  runSecurityPipeline,
} from '../security/security-classifier.js';
import { getToolSchema, mapFactsToToolCalls, extractStructuredFacts } from '../shared/schema-mapper.js';
import { resolveEscalation } from './escalation-resolver.js';
import { selectAction, renderDecision } from './decision-renderer.js';
import { shouldRenew, checkpointProgress, loadCheckpoint, incrementRenewalCount } from '../context/context-renewal.js';
import { buildSeparatedPrompt, validateChannelSeparation, sanitizeMemoryValue } from '../write/channel-separator.js';
import { createWorkspace, setPartition, getPartition, serializeWorkspace } from '../context/workspace-partitions.js';
import { auditTrajectory, getWarningSignsForEvents } from '../core/scheming-monitor.js';
import { loadConstitutionRules, enforceRules } from '../core/constitution-enforcer.js';
import { deliverAndChain } from './interaction-graph-healer.js';
import {
  buildAgentBenchmarkTrace,
  guardRawToolProtocolText
} from './agent-run-diagnostics.js';
import { buildLatentLookaheadPlan, logTracedEvent } from '../observe/agent-trace.js';
import { symbolicPostCheck } from './symbolic-reasoner.js';
import { runQualityLoop } from '../learning/batch-reflector.js';
import { computeOverallConsistency } from '../learning/cognitive-consistency.js';
import { inversePTCorrection } from '../learning/prospect-theory.js';
import { reflectOnTrajectory } from '../learning/reflection-finetuner.js';
import { allocateTurnAdaptiveBudget, trackSessionEnergy } from '../observe/energy-budget.js';
import { buildEvolveRouterRuntimeSignal } from '../observe/routing-monitor.js';
import { observeSemanticIntent } from '../observe/semantic-intent.js';
import { observeCoordinationAudit } from '../observe/coordination-audit.js';
// generateExplanation, EXPLANATION_LEVEL, logAIDecision — now imported via agent-xai-explanation.js
import { evaluateScratToolReflection, runInvestigationLoop } from './explore-exploit-loop.js';
// analyzeManipulation — now used via agent-security-gates.js
// computeSecurityResponse — now used via agent-security-gates.js
import { updateAgentState, readAgentBDIState } from './agent-bdi-state.js';
import {
  extractConfidence,
  classifyComplexity,
  evaluateWithF7Protocol,
  evaluateRouteConfidence,
  checkAutonomyLevel
} from './agent-confidence-calibration.js';
import {
  buildRunActionLabel,
  buildRunReasoningSteps,
  buildRunFeatureWeights,
  buildRunAlternatives,
  confidenceBand,
  inferBlastRadius,
  compactEvidenceText,
  captureExplanationAndDecision
} from './agent-xai-explanation.js';
import {
  isExecutiveRememberPrompt,
  isExecutiveRecallSelfPrompt,
  isExecutiveLatestEmailPrompt,
  isExecutiveSenderFollowupPrompt,
  runDeterministicExecutiveFastPath,
  extractRememberFactsFromHistory
} from './agent-executive-fast-path.js';
import {
  shouldRunInvestigationLoop,
  buildInvestigationTechniques,
  normalizeInvestigationEvidence,
  parseInvestigationIterationResponse,
  summarizePriorInvestigationFindings,
  buildInvestigationIterationPrompt,
  buildInvestigationContext
} from './agent-investigation-loop.js';
import { runSecurityGates, buildSecurityGateError } from './agent-security-gates.js';
// classifyBloomLevel, mapBloomToSecurityTier — now used via agent-security-gates.js
import {
  detectCanaries,
  observeCanariesAtRelayGate,
  recordCanariesRelayed,
  recordCanaryRelayBlocked,
} from '../security/canary-tracker.js';
import { getOperatorAgentId, isOperatorAgentId, systemConfigStore } from '../security/system-config-store.js';
import { getConstraintForRole, applyNoHaveConstraint, applyEPrimeConstraint } from '../context/linguistic-constraints.js';
import { createScopedState, inheritState, setScopedVar, getAllScopedVars, getStateSummary } from '../context/scoped-state.js';
import { retrieveSkills } from '../learning/dual-skill-bank.js';
import { buildAgscOutputContract, buildKeyedPrefetchPlan, buildRobustLengthPrediction, buildTokenScaleRuntimeSignal } from '../runtime/serving-control.js';
import { buildLocalInferenceRunPlan } from '../runtime/local-inference-control.js';

// ─── Sub-module imports ───────────────────────────────────────────────────────
import {
  redactSecrets,
  isInternalMemoryText,
  compactText,
  buildEmptyContextPack,
  loadRecentAimosContext,
  loadHybridAimosContext,
  loadProceduralSkills,
  buildPromptPressure,
  updateLatestPromptPressureTelemetry,
  getPromptPressureTelemetry,
  normalizeConversationSessionKey,
  buildConversationMessages,
  trimConversationMessagesForBudget,
  buildFastLaneSystemPrompt,
  buildSystemPrompt,
  TEAM_TOPOLOGY
} from './agent-prompts.js';

import {
  isToolApprovalRequired,
  createToolApprovalError,
  loopExhaustedResult,
  emitTextChunks,
  runAgentWithFallback,
  isModelCircuitBroken,
  pruneModelFailureHistory,
  recordModelFailure,
  resetModelCircuitBreaker,
  runByModel
} from './agent-tools.js';

// Re-export from sub-modules so callers that import from this path still work
export { getPromptPressureTelemetry };
export { pruneModelFailureHistory, isModelCircuitBroken, recordModelFailure, resetModelCircuitBreaker };
export { extractConfidence } from './agent-confidence-calibration.js';

const COMPANY = AIMOS_COMPANY_ID;

const MAX_AGENT_RECURSION_DEPTH = 2;
const MAX_EXECUTIVE_RECURSION_DEPTH = Math.max(MAX_AGENT_RECURSION_DEPTH, 5);
const MAX_CHAIN_DEPTH = 3;
const MEMORY_CONTEXT_ITEM_LIMIT = 8;
const MEMORY_CONTEXT_ITEM_CHAR_LIMIT = 2_000;
const MEMORY_CONTEXT_TOTAL_CHAR_BUDGET = 12_000;
const MAX_TOTAL_ASSEMBLED_CHARS = 48_000;
const EXTERNAL_ACTION_INTENT_MARKERS = new Set([
  'x',
  'x_post',
  'x_reply',
  'x_quote',
  'twitter',
  'gmail_send',
  'email',
  'calendar_create',
  'imessage_send',
  'notify'
]);
// ─── INVESTIGATION LOOP (extracted to agent-investigation-loop.js) ──────────────
// shouldRunInvestigationLoop, buildInvestigationTechniques, normalizeInvestigationEvidence,
// parseInvestigationIterationResponse, summarizePriorInvestigationFindings,
// buildInvestigationIterationPrompt, buildInvestigationContext
// — imported from agent-investigation-loop.js

function buildScopedStateContext(state) {
  if (!state) {
    return '';
  }

  const summary = getStateSummary(state);
  const variables = getAllScopedVars(state);
  if (!summary || Object.keys(variables).length === 0) {
    return '';
  }

  const lines = [
    '',
    '### DELEGATION SCOPED STATE',
    `scope_run_id: ${summary.parentRunId || 'unknown'}`,
    `source_agent_id: ${variables.source_agent_id || 'unknown'}`,
    `current_agent_id: ${variables.current_agent_id || 'unknown'}`,
    `conversation_session_key: ${variables.conversation_session_key || 'unknown'}`,
    `task_type: ${variables.task_type || 'chat'}`
  ];

  if (variables.parent_run_id) {
    lines.push(`parent_run_id: ${variables.parent_run_id}`);
  }
  if (summary.inheritedFrom) {
    lines.push(`inherited_from: ${summary.inheritedFrom}`);
  }
  if (variables.delegation_scope) {
    lines.push(`delegation_scope: ${variables.delegation_scope}`);
  }
  if (variables.delegation_reason) {
    lines.push(`delegation_reason: ${variables.delegation_reason}`);
  }

  const visibleKeys = Object.keys(variables)
    .filter((key) => !['source_agent_id', 'current_agent_id', 'conversation_session_key', 'task_type', 'parent_run_id', 'delegation_scope', 'delegation_reason'].includes(key))
    .slice(0, 8);
  if (visibleKeys.length > 0) {
    lines.push(`scoped_keys: ${visibleKeys.join(', ')}`);
  }

  return lines.join('\n');
}

// ─── XAI EXPLANATION HELPERS (extracted to agent-xai-explanation.js) ───────────
// buildRunActionLabel, buildRunReasoningSteps, buildRunFeatureWeights,
// buildRunAlternatives, confidenceBand, inferBlastRadius, compactEvidenceText,
// captureExplanationAndDecision — imported from agent-xai-explanation.js

function normalizeModelForFallbackComparison(modelId = '') {
  const raw = String(modelId || '').trim();
  if (!raw) return '';
  const resolution = resolveProviderForModel(raw, '');
  return String(resolution.model || raw).trim().toLowerCase();
}

function modelsEquivalentForFallback(resolvedModel = '', requestedModel = '') {
  const resolved = normalizeModelForFallbackComparison(resolvedModel);
  const requested = normalizeModelForFallbackComparison(requestedModel);
  return !!resolved && !!requested && resolved === requested;
}

const EXTERNAL_ACTION_PROMPT_REGEX = /\b(tweet|post|reply|quote tweet|send (an )?email|email this|send message|text (them|him|her)|calendar invite|create (a )?calendar event|notify|publish)\b/i;

// ─── JOB QUEUE: Concurrency limiter for agent runs ────────────────────────────
// Prevents resource exhaustion when multiple agent runs fire simultaneously.
const MAX_CONCURRENT_RUNS = 3;
let _activeRuns = 0;
const _runQueue = [];

function acquireRunSlot() {
  if (_activeRuns < MAX_CONCURRENT_RUNS) {
    _activeRuns++;
    return Promise.resolve();
  }
  return new Promise(resolve => _runQueue.push(resolve));
}

function releaseRunSlot() {
  if (_runQueue.length > 0) {
    const next = _runQueue.shift();
    next(); // don't decrement — slot transfers to waiter
  } else {
    _activeRuns--;
  }
}

export function getRunQueueStats() {
  return { active: _activeRuns, queued: _runQueue.length, maxConcurrent: MAX_CONCURRENT_RUNS };
}

function isExplicitExternalActionIntent(intent = '', userPrompt = '') {
  const normalizedIntent = String(intent || '').trim().toLowerCase();
  if (EXTERNAL_ACTION_INTENT_MARKERS.has(normalizedIntent)) return true;
  return EXTERNAL_ACTION_PROMPT_REGEX.test(String(userPrompt || ''));
}

function buildDirectionalityPolicyForRun({ agentId, intent, userPrompt, autonomous }) {
  const allow = ['read', 'memory_write', 'internal_write', 'orchestration'];
  const deny = [];
  const allowExternalWrite = isOperatorAgentId(agentId)
    || isExplicitExternalActionIntent(intent, userPrompt)
    || autonomous === false;

  if (allowExternalWrite) {
    allow.push('external_write');
  } else {
    deny.push('external_write');
  }

  return {
    enabled: true,
    allow,
    deny,
    reason: allowExternalWrite ? 'explicit_external_action' : 'default_safe_directionality'
  };
}

// ─── CHAINING: Detect continuation signals for multi-run chaining ────────────
// Phase 3 Fix: After a run completes, detect whether the agent's output or BDI
// state signals that a follow-up run is needed. Returns the continuation prompt
// or null if no chaining is required.
const CONTINUATION_PATTERNS = [
  /\[CONTINUE\]\s*(.{10,300})/i,
  /\[NEXT[_ ]?STEP\]\s*(.{10,300})/i,
  /(?:I need to|I should|I must|I will now|next I'll)\s+(.{10,200})/i,
  /(?:continuing with|proceeding to|moving on to)\s+(.{10,200})/i,
];

function detectContinuationSignal(response, mergedIntentions, confidence) {
  // Don't chain on low confidence — the agent isn't sure enough to self-direct
  if (confidence < 0.5) return null;

  // Signal 1: Explicit continuation marker in response text
  const responseStr = String(response || '');
  for (const pat of CONTINUATION_PATTERNS) {
    const match = responseStr.match(pat);
    if (match && match[1]) {
      return { prompt: match[1].trim(), source: 'response_signal' };
    }
  }

  // Signal 2: BDI intention says "retry with alternative route"
  if (mergedIntentions?.next === 'retry with alternative route') {
    return { prompt: `Retry the previous task using an alternative approach.`, source: 'bdi_reroute' };
  }

  // Signal 3: BDI has an explicit pending intention with a prompt
  if (mergedIntentions?.pending_continuation && typeof mergedIntentions.pending_continuation === 'string') {
    return { prompt: mergedIntentions.pending_continuation, source: 'bdi_pending' };
  }

  return null;
}

// ─── ADVISABILITY: Mid-run correction inbox ─────────────────────────────────
// Humans (or other agents) can post corrections that running agents pick up.
// checkAdvisability() is called before LLM execution to merge any pending advice.
export async function checkAdvisability(agentId) {
  try {
    const res = await query(
      `SELECT id, value FROM aimos_memories
       WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'advisory'
       ORDER BY created_at DESC LIMIT 5`,
      [COMPANY, agentId]
    );
    if (!res.rows.length) return null;
    const advisories = res.rows.map(r => {
      try { return JSON.parse(r.value); } catch { return { text: r.value }; }
    });
    return advisories;
  } catch { return null; }
}

// Post an advisory for a running agent (called from routes)
export async function postAdvisory(agentId, advice, fromAgent = 'human') {
  const key = `advisory:${agentId}:${Date.now()}`;
  const value = JSON.stringify({
    from: fromAgent,
    advice: String(advice).slice(0, 2000),
    posted_at: new Date().toISOString()
  });
  await persistMemory({
    company_id: COMPANY,
    agent_id: agentId,
    key,
    value,
    scope: 'agent',
    memory_type: 'advisory',
    clearance_level: 5,
    source: 'agent-runner',
    mutation_authority: 'housekeeper',
  });
  return { key, agentId };
}

// ─── MANDATORY EVENT LOG (hardcoded — every agent, every model, every run) ────
// Writes to aimos_memories with memory_type='event_log' so boot recall,
// nightly dream, and session queries always see what happened.
// This is NOT optional. An agent run not logged = a run that never happened.
async function logMandatoryRunEvent(agentId, { success, model, taskType, confidence, latencyMs, error, promptSnippet, parentEventId }) {
  try {
    const now = new Date();
    const hhmm = now.toISOString().slice(11, 16);
    const ts = now.toISOString().slice(0, 16).replace('T', '_').replace(':', '');
    const key = `event_agent_run_${agentId}_${ts}`;
    const action = success ? 'agent_run' : 'agent_error';
    const lines = [
      `\u2022 ${hhmm} \u2014 [${action}] ${agentId} ran ${taskType || 'chat'} on ${model || 'unknown'}` +
        (confidence != null ? ` (conf: ${Number(confidence).toFixed(2)})` : ''),
      success ? `  result: success` : `  result: error \u2014 ${String(error || 'unknown').slice(0, 200)}`,
      latencyMs ? `  latency: ${latencyMs}ms` : null,
      promptSnippet ? `  prompt: ${String(promptSnippet).slice(0, 120)}` : null
    ].filter(Boolean).join('\n');

    await persistMemory({
      company_id: COMPANY,
      agent_id: agentId,
      key,
      value: lines,
      scope: 'system',
      memory_type: 'event_log',
      clearance_level: 5,
      source: 'agent-runner',
      mutation_authority: 'housekeeper',
    });

    // Phase 4: Also log to aimos_events with parent_event_id for trace tree
    try {
      const eventResult = await logTracedEvent(agentId, action, key, {
        model, taskType, confidence, latencyMs,
        ...(error ? { error: String(error).slice(0, 200) } : {})
      }, parentEventId || null);
      return eventResult; // return the event ID for chaining
    } catch { /* traced event is best-effort */ }
  } catch { /* mandatory log must never crash the pipeline */ }
}

// ─── CONFIDENCE SCORING (extracted to agent-confidence-calibration.js) ─────────
// extractConfidence, classifyComplexity, evaluateWithF7Protocol,
// evaluateRouteConfidence, checkAutonomyLevel — imported from agent-confidence-calibration.js
// getCalibrationFactor — imported from agent-learning.js (canonical source)

// ─── Feature 5: Per-Action Trust Gates ───────────────────────────────────────
const TOOL_RISK_LEVELS = {
  aimos_recall: 0.1, aimos_save: 0.2, web_search: 0.1,
  youtube_search: 0.1, drive_list: 0.1, drive_read: 0.15,
  docs_read: 0.15, sheets_read: 0.15, read_file: 0.1,
  gmail_inbox: 0.15, gmail_search: 0.15, calendar_today: 0.1, calendar_events: 0.1,
  write_file: 0.3, calendar_create: 0.35,
  gmail_send: 0.7, imessage_send: 0.7, delegate_task: 0.4,
  stripe_list_customers: 0.2, stripe_list_subscriptions: 0.2,
  stripe_list_payment_intents: 0.25, stripe_account_summary: 0.15,
  schedule_task: 0.3, list_scheduled_tasks: 0.1
};

const TOOL_CAPABILITIES = Object.freeze({
  aimos_recall: 'memory_read',
  aimos_save: 'memory_write',
  web_search: 'internet',
  x_search: 'x',
  youtube_search: 'youtube',
  youtube_channel: 'youtube',
  gmail_inbox: 'email',
  gmail_search: 'email',
  gmail_send: 'email',
  imessage_chats: 'email',
  imessage_search_contact: 'email',
  imessage_send: 'email',
  calendar_today: 'email',
  calendar_events: 'email',
  calendar_create: 'email',
  drive_list: 'files',
  drive_read: 'files',
  docs_read: 'files',
  sheets_read: 'files',
  read_file: 'files',
  write_file: 'files',
  github_list_repos: 'github',
  github_search_issues: 'github',
  delegate_task: 'delegate',
  schedule_task: 'delegate',
  list_scheduled_tasks: 'delegate',
  google_profile: 'internet',
  integrations_status: 'internet',
  stripe_account_summary: 'internet',
  stripe_list_customers: 'internet',
  stripe_list_subscriptions: 'internet',
  stripe_list_payment_intents: 'internet',
  salesforce_list_objects: 'internet',
});

function computeToolTrustScore(agentId, toolName, confidence, agentHealthScore = 50) {
  const toolRisk = TOOL_RISK_LEVELS[toolName] || 0.5;
  const healthNorm = Math.max(0, Math.min(1, (agentHealthScore || 50) / 100));
  const confNorm = Math.max(0, Math.min(1, confidence || 0.5));
  const trust = (1 - toolRisk) * 0.4 + healthNorm * 0.3 + confNorm * 0.3;
  return Math.round(trust * 1000) / 1000;
}

function evaluateToolTrust(trust) {
  if (trust < 0.3) return 'block';
  if (trust <= 0.6) return 'log_and_allow';
  return 'allow';
}

// ─── TOOL PERMISSION FILTER ──────────────────────────────────────────────────
async function filterToolsForAgent(agentId, companyId, allTools) {
  const total = allTools.length;

  try {
    const permissions = await getPermissions(agentId, companyId);

    const filtered = allTools.filter((toolDef) => {
      const name = String(toolDef?.schema?.function?.name || '');
      if (!name) return false;
      const capability = TOOL_CAPABILITIES[name];
      return Boolean(capability && permissions[capability] === true);
    });

    console.log(`[tool-filter] Agent ${agentId}: ${filtered.length}/${total} tools available`);
    return filtered;

  } catch (err) {
    console.warn(`[tool-filter] Authorization unavailable for ${agentId}; denying tools: ${err.message}`);
    return [];
  }
}

// ─── TASK ROUTER: query F7 framework sequence before acting ─────────────────
async function resolveTaskRoute(agentId, taskType, userPrompt) {
  try {
    const result = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = 'procedure_f7_task_router'
       ORDER BY created_at DESC LIMIT 1`,
      [COMPANY]
    );
    if (!result.rows.length) return null;
    const raw = result.rows[0].value;
    const parsed = typeof raw === 'string' ? raw : JSON.stringify(raw);
    const router = JSON.parse(parsed || '{}');
    const routes = router.routes || router.task_routes || {};
    return routes[taskType] || routes['default'] || null;
  } catch {
    return null;
  }
}

// ─── CONFIDENCE CALIBRATION (extracted to agent-confidence-calibration.js) ────
// evaluateRouteConfidence, checkAutonomyLevel — imported from agent-confidence-calibration.js

// ─── AGENT STATE MACHINE: BDI state (extracted to agent-bdi-state.js) ────────
// updateAgentState and readAgentBDIState are now in agent-bdi-state.js
// BDI ghosting prevention: empty BDI never overwrites real data (COALESCE(NULLIF))

// ─── EVAL PROTOCOL (extracted to agent-confidence-calibration.js) ────────────
// evaluateWithF7Protocol — imported from agent-confidence-calibration.js

// ─── EXECUTIVE FAST-PATH (extracted to agent-executive-fast-path.js) ──────────
// isExecutiveRememberPrompt, isExecutiveRecallSelfPrompt, isExecutiveLatestEmailPrompt,
// isExecutiveSenderFollowupPrompt, runDeterministicExecutiveFastPath,
// extractRememberFactsFromHistory — imported from agent-executive-fast-path.js

// ─── TEAM TOPOLOGY: Messaging ─────────────────────────────────────────────────
// Message types (MetaGPT: structured communication over idle chatter):
// 'directive' = task assignment, 'report' = completed work, 'escalation' = blocked/needs higher clearance,
// 'contradiction' = deliberative dialogue, 'feedback' = executable feedback loop result, 'handoff' = water spider routing
export async function sendAgentMessage(fromAgentId, toAgentId, message, metadata = {}) {
  const topology = TEAM_TOPOLOGY[fromAgentId];
  if (topology && !topology.canMessageAll) {
    const allowed = topology.canMessage || [];
    if (!allowed.includes(toAgentId)) {
      return { error: `Agent ${fromAgentId} cannot message ${toAgentId} per team topology`, blocked: true };
    }
  }

  const msgType = metadata.messageType || 'directive';
  const key = `agent_msg:${fromAgentId}:${toAgentId}:${Date.now()}`;
  await persistMemory({
    company_id: COMPANY,
    agent_id: toAgentId,
    key,
    value: JSON.stringify({
      from: fromAgentId,
      to: toAgentId,
      messageType: msgType,
      interactionMode: (TEAM_TOPOLOGY[fromAgentId] || {}).interactionMode || 'x-as-a-service',
      message,
      metadata,
      timestamp: new Date().toISOString()
    }),
    scope: 'agent',
    memory_type: 'agent_message',
    source: 'agent-runner',
    mutation_authority: 'housekeeper',
  });

  return { sent: true, key, messageType: msgType };
}

export async function getAgentInbox(agentId, limit = 10) {
  const res = await query(
    `SELECT key, value, created_at FROM aimos_memories
     WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'agent_message'
     ORDER BY created_at DESC LIMIT $3`,
    [COMPANY, agentId, limit]
  );

  return res.rows.map(r => {
    const parsed = typeof r.value === 'string' ? JSON.parse(r.value) : r.value;
    return { key: r.key, ...parsed, received_at: r.created_at };
  });
}

export async function markMessageRead(messageKey, agentId, authority = null) {
  const key = String(messageKey || '').trim();
  const reader = String(agentId || '').trim();
  if (!key) throw new Error('message_key_required');
  if (!reader) throw new Error('message_reader_required');
  const message = await query(
    `SELECT id, key
       FROM aimos_memories
      WHERE company_id = $1
        AND key = $2
        AND agent_id = $3
        AND memory_type = 'agent_message'
      ORDER BY created_at DESC
      LIMIT 1`,
    [COMPANY, key, reader]
  );
  if (!message.rows[0]) {
    const error = new Error('message_not_found_for_agent');
    error.code = 'AIMOS_MESSAGE_NOT_FOUND';
    throw error;
  }
  const eventId = await logEvent(COMPANY, reader, 'agent_message_read', key, {
    memory_id: message.rows[0].id,
    reader_agent_id: reader,
    canonical_memory_changed: false,
    reasoning: 'The agent acknowledged a retained message; the read receipt is append-only and does not suppress the message.',
    source_knowledge: 'agent-runner.js native agent message evidence',
  }, null, { authority });
  return { marked: key, event_id: eventId };
}

async function loadWorkingContext(agentId) {
  try {
    const res = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2
       ORDER BY updated_at DESC LIMIT 1`,
      [COMPANY, `working_context:${agentId}`]
    );
    if (!res.rows.length) return '';
    return String(res.rows[0].value || '').slice(0, 4000);
  } catch { return ''; }
}

async function updateWorkingContext(agentId, newFacts) {
  try {
    if (!newFacts || String(newFacts).length < 10) return;
    const key = `working_context:${agentId}`;
    const sanitized = sanitizeMemoryValue(String(newFacts).slice(0, 4000));
    await persistMemory({
      company_id: COMPANY,
      agent_id: agentId,
      key,
      value: sanitized,
      scope: 'agent',
      memory_type: 'working_context',
      clearance_level: 3,
      source: 'agent-runner',
      mutation_authority: 'housekeeper',
    });
  } catch { /* best-effort */ }
}

// ─── MAIN ENTRY POINT ─────────────────────────────────────────────────────────

export async function runAgent(agentId, userPrompt, options = {}) {
  const depth = Math.max(0, Number(options.depth || 0));
  const effectiveMaxDepth = isOperatorAgentId(agentId) ? MAX_EXECUTIVE_RECURSION_DEPTH : MAX_AGENT_RECURSION_DEPTH;
  if (depth > effectiveMaxDepth) {
    throw new Error(`Agent recursion depth exceeded (${depth} > ${effectiveMaxDepth})`);
  }

  // ─── JOB QUEUE: wait for a slot before executing ────────────────────────────
  await acquireRunSlot();
  try {
    return await _runAgentInner(agentId, userPrompt, options);
  } finally {
    releaseRunSlot();
  }
}

async function _runAgentInner(agentId, userPrompt, options = {}) {
  const runStartTime = Date.now();
  const depth = Math.max(0, Number(options.depth || 0));
  const runId = options.runId || `run_${agentId}_${runStartTime}`;
  let securityDecisionReceipt = null;

  // ─── WORKSPACE PARTITIONS: initialize B_ctx/B_work/B_sys/B_ans for this run ─
  let workspace = null;
  try {
    workspace = createWorkspace(runId);
    setPartition(workspace, 'B_ctx', {
      agentId,
      userPrompt: String(userPrompt || '').slice(0, 2000),
      taskType: options.taskType || options.intent || 'chat',
      startedAt: new Date().toISOString()
    });
    setPartition(workspace, 'B_sys', { phase: 'init', depth });
  } catch (wpErr) {
    console.warn('[workspace-partitions] init failed:', wpErr.message);
  }

  // ─── CONSTITUTION ENFORCER: pre-run constraint checking ──────────────────────
  let constitutionRules = [];
  try {
    const authorityPath = new URL('../../architecture-authority.json', import.meta.url).pathname;
    const loaded = loadConstitutionRules(authorityPath);
    constitutionRules = loaded.rules || [];
    if (loaded.errors?.length) {
      console.warn('[constitution-enforcer] load warnings:', loaded.errors);
    }
  } catch (ceErr) {
    console.warn('[constitution-enforcer] pre-run load failed:', ceErr.message);
  }

  // ─── SECURITY GATES (extracted to agent-security-gates.js) ───────────────────
  // SE screen, se-gate, cybersec firewall, security ladder, behavioral baseline,
  // Bloom classification, meta-controller, risk budget, and psychometric profile
  // — all orchestrated by runSecurityGates()
  const {
    cybersecMode,
    behavioralCheck,
    bloomLevel,
    reviewTier,
    taskRiskLevel,
    metaDecision,
    psychometricProfile
  } = await runSecurityGates({ userPrompt, agentId, options, COMPANY });

  const fastLane = options.fastLane === true;

  const persistedAgent = agents.get(agentId);
  if (!persistedAgent) throw new Error(`Agent not found: ${agentId}`);

  // ─── TURBOESM: Load long-range reasoning trace from checkpoint ────────────
  let reasoningQuanta = '';
  if (!fastLane) {
    try {
      const checkpoint = await loadCheckpoint(runId, COMPANY);
      if (checkpoint?.reasoning_quanta) {
        reasoningQuanta = checkpoint.reasoning_quanta;
      }
    } catch (_cErr) {
      console.warn('[context-renewal] early load failed:', _cErr.message);
    }
  }

  const resolution = options.resolution || {};
  const onToken = typeof options.onToken === 'function' ? options.onToken : null;
  const runtimeAgent = {
    ...persistedAgent,
    id: agentId,
    model: resolution.primaryModel
      || options.model
      || options.requestedModel
      || options.preferredModel
      || systemConfigStore.readConfigString('DEFAULT_AGENT_MODEL')
      || systemConfigStore.readConfigString('LLM_MODEL')
      || systemConfigStore.readConfigString('OLLAMA_MODEL')
      || '',
    persona: resolution.persona || persistedAgent.persona,
    tools: [resolution.toolProfile || (Array.isArray(persistedAgent.tools) ? persistedAgent.tools[0] : persistedAgent.tools || 'full')],
    toolDeltas: resolution.toolDeltas || persistedAgent.toolDeltas || { allow: [], deny: [] },
    clearanceLevel: resolution.clearanceLevel || persistedAgent.clearanceLevel
  };
  const modelPreference = resolveModelForRequest({
    taskType: options.taskType || options.intent || resolution.intent,
    prompt: userPrompt
  });
  const requestedDiagnosticModel = options.requestedModel
    || options.preferredModel
    || resolution.requestedModel
    || resolution.primaryModel
    || '';
  const requestedProviderResolution = requestedDiagnosticModel
    ? resolveProviderForModel(requestedDiagnosticModel, '')
    : null;
  const modelAllocationDiagnostics = requestedDiagnosticModel
    ? buildModelAllocationDiagnostics({
        taskType: options.taskType || options.intent || resolution.intent,
        prompt: userPrompt,
        provider: requestedProviderResolution?.provider || '',
        model: requestedProviderResolution?.model || requestedDiagnosticModel,
        preferenceFound: false,
      })
    : modelPreference.diagnostics;

  let turnBudgetPlan = null;
  let latentLookaheadPlan = null;
  let keyedPrefetchPlan = null;
  let robustLengthPrediction = null;
  let agscGenerationContract = null;
  let localInferencePlan = null;
  let epistemicBlindingGate = null;
  let llmUserPrompt = userPrompt;

  // Mark active
  persistedAgent.isActive = true;
  persistedAgent.lastSeen = new Date().toISOString();
  agents.set(agentId, persistedAgent);

  const sourceAgentId = options.originAgentId || resolution.sourceAgentId || agentId;
  const conversationSessionKey = normalizeConversationSessionKey(
    options.sessionKey || resolution.sessionKey,
    sourceAgentId,
    runtimeAgent.id
  );

  // ─── SCOPED STATE: initialize or inherit delegation context ─────────────────
  let delegationScopedState = null;
  try {
    const inboundScopedState = options._scopedState
      || (options.delegationContext && typeof options.delegationContext.__scopedState === 'object'
        ? options.delegationContext.__scopedState
        : null);
    delegationScopedState = inboundScopedState
      ? inheritState(inboundScopedState, runId)
      : createScopedState(runId);

    setScopedVar(delegationScopedState, 'source_agent_id', sourceAgentId);
    setScopedVar(delegationScopedState, 'current_agent_id', runtimeAgent.id);
    setScopedVar(delegationScopedState, 'conversation_session_key', conversationSessionKey);
    setScopedVar(delegationScopedState, 'task_type', options.taskType || options.intent || resolution.intent || 'chat');

    const parentRunId = options.parentRunId || options.delegationContext?.parentRunId || null;
    if (parentRunId) {
      setScopedVar(delegationScopedState, 'parent_run_id', parentRunId);
    }
    if (options.delegationContext?.scope) {
      setScopedVar(delegationScopedState, 'delegation_scope', options.delegationContext.scope);
    }
    if (options.delegationContext?.reason) {
      setScopedVar(delegationScopedState, 'delegation_reason', options.delegationContext.reason);
    }

    options._scopedState = delegationScopedState;
  } catch (ssErr) {
    console.warn('[scoped-state] delegation context init failed (non-fatal):', ssErr.message);
  }
  const scopedStateContext = fastLane ? '' : buildScopedStateContext(delegationScopedState);

  const constitutionCheck = evaluateDelegatedDirectiveAgainstConstitution({
    prompt: userPrompt,
    sourceAgentId,
    targetAgentId: runtimeAgent.id
  });
  if (constitutionCheck.blocked) {
    logEvent('hom', runtimeAgent.id, 'constitution_block', `constitution_block:${runtimeAgent.id}`, {
      reasoning: constitutionCheck.message,
      source_knowledge: 'hom-constitution runtime enforcement',
      reasons: constitutionCheck.reasons,
      source_agent_id: constitutionCheck.sourceAgentId,
      target_agent_id: constitutionCheck.targetAgentId
    }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
    const err = new Error(constitutionCheck.message);
    err.code = constitutionCheck.code;
    err.constitution = constitutionCheck;
    throw err;
  }

  const conversationHistory = fastLane ? [] : await getConversationHistory(conversationSessionKey, {
    companyId: COMPANY,
    agentId: sourceAgentId,
  });
  if (!fastLane) {
    try {
      epistemicBlindingGate = buildEpistemicBlindingGate({
        prompt: userPrompt,
        decisionType: options.taskType || options.intent || resolution.intent || 'chat',
      });
      if (epistemicBlindingGate.should_blind) {
        llmUserPrompt = epistemicBlindingGate.blinded_prompt;
        logEvent(COMPANY, runtimeAgent.id, 'epistemic_blinding_applied', `epistemic_blind:${runId}`, {
          reasoning: `Epistemic blinding applied before model inference for data-driven decision task; ${epistemicBlindingGate.entity_count} identifiers replaced with anonymous codes.`,
          source_knowledge: 'Epistemic Blinding — inference-time prior contamination audit',
          entity_count: epistemicBlindingGate.entity_count,
          leak_sources_to_review: epistemicBlindingGate.leak_sources_to_review,
        }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
      }
    } catch (blindErr) {
      console.warn('[epistemic-blinding] gate failed (non-fatal):', blindErr.message);
      llmUserPrompt = userPrompt;
    }
  }
  if (!fastLane) {
    try {
      turnBudgetPlan = allocateTurnAdaptiveBudget({
        prompt: llmUserPrompt,
        conversationHistory,
        taskType: options.taskType || options.intent || resolution.intent || 'chat',
        psychometricProfile,
        globalBudget: options.globalTokenBudget || 8192,
        usedTokens: options.usedTurnTokens || 0,
      });
    } catch (budgetErr) {
      console.warn('[turn-adaptive-budget] allocation failed (non-fatal):', budgetErr.message);
    }
  }
  if (!fastLane) {
    try {
      latentLookaheadPlan = buildLatentLookaheadPlan({
        prompt: llmUserPrompt,
        taskType: options.taskType || options.intent || resolution.intent || 'chat',
        turnBudgetPlan,
        psychometricProfile,
        conversationHistory,
        maxThoughts: 2,
      });
      if (latentLookaheadPlan.prefetch_queries?.length) {
        keyedPrefetchPlan = buildKeyedPrefetchPlan({
          prompt: llmUserPrompt,
          prefetchQueries: latentLookaheadPlan.prefetch_queries,
          sessionKey: conversationSessionKey || runId,
        });
        logEvent('hom', runtimeAgent.id, 'latent_lookahead_prefetch', `lookahead:${runId}`, {
          reasoning: `Latent-lookahead prefetch prepared tau=${latentLookaheadPlan.latent_horizon_tau}, positions=${latentLookaheadPlan.thinking_positions.join(',')}.`,
          source_knowledge: 'Thinking into the Future — Latent Lookahead Training for Transformers; Low-Latency Stateful Stream Processing through Timely and Accurate Prefetching',
          plan: latentLookaheadPlan,
          keyed_prefetch: keyedPrefetchPlan,
        }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
      }
    } catch (lookaheadErr) {
      console.warn('[latent-lookahead] prefetch plan failed (non-fatal):', lookaheadErr.message);
    }
  }
  const aimosContextPack = fastLane
    ? buildEmptyContextPack()
    : await loadHybridAimosContext(sourceAgentId, runtimeAgent.id, userPrompt, 8);
  const canaryRelayObservation = await observeCanariesAtRelayGate(
    aimosContextPack.text,
    runId,
    {
      sourceAgentId,
      targetAgentId: runtimeAgent.id,
      parentEventId: options.securityParentEventId
        || options.executionContext?.requestAdmissionEventId
        || null,
      authority: options.executionContext || options.credentialUseContext || null,
    },
  );
  if (canaryRelayObservation.canariesFound.length > 0) {
    const blockedCanaryRelay = await recordCanaryRelayBlocked(
      canaryRelayObservation,
      {
        authority: options.executionContext || options.credentialUseContext || null,
      },
    );
    const error = new Error(`Canary token blocked before recalled memory was delivered to ${runtimeAgent.id}.`);
    error.code = 'CANARY_RELAY_BLOCKED';
    error.blocked = true;
    error.canaryTokens = canaryRelayObservation.canariesFound;
    error.killChainDiagnostics = blockedCanaryRelay.kill_chain_diagnostics;
    throw error;
  }

  // ─── CONTEXT RENEWAL: checkpoint if approaching 85% context window ─────────
  if (!fastLane) {
    try {
      const estimatedTokens = (String(userPrompt || '').length + aimosContextPack.text.length) / 4;
      const maxContextTokens = 128000; // conservative estimate
      if (shouldRenew(estimatedTokens, maxContextTokens)) {
        const renewalCount = await incrementRenewalCount(runId, COMPANY);
        if (renewalCount > 0) {
          const checkpoint = await loadCheckpoint(runId, COMPANY);
          if (!checkpoint) {
            await checkpointProgress(runId, `Pre-LLM checkpoint for ${runtimeAgent.id}`, {
              accumulated_findings: [aimosContextPack.text.slice(0, 500)],
              decisions_made: [],
              remaining_tasks: [String(userPrompt).slice(0, 200)],
              memories: aimosContextPack.memories || [],
              confidence: null
            }, COMPANY);
            console.info(`[context-renewal] Checkpointed run ${runId} at renewal #${renewalCount}`);
          }
        }
      }
    } catch (crErr) {
      console.warn('[context-renewal] checkpoint failed:', crErr.message);
    }
  }

  const proceduralSkills = fastLane
    ? { text: '', skillIds: [] }
    : await loadProceduralSkills(runtimeAgent.id, userPrompt);

  // ─── DUAL SKILL BANK: augment procedural skills with task + step-level skills ─
  let dualSkillText = '';
  if (!fastLane) {
    try {
      const [taskSkills, stepSkills] = await Promise.all([
        retrieveSkills(userPrompt, 'task', 3),
        retrieveSkills(userPrompt, 'step', 3)
      ]);
      const allSkills = [...(taskSkills || []), ...(stepSkills || [])];
      if (allSkills.length > 0) {
        dualSkillText = '\n### RETRIEVED SKILLS (task + step-level):\n' +
          allSkills.map(s => `- [${s.skill_type || 'skill'}] ${s.principle || s.when_to_apply || ''}`).join('\n');
      }
    } catch (dsbErr) {
      console.warn('[dual-skill-bank] skill retrieval failed (non-fatal):', dsbErr.message);
    }
  }

  // ─── GAP 5: REASONING CONTINUITY — inject last reasoning state on boot ─────
  let reasoningContext = '';
  if (!fastLane) {
    try {
      const rState = await query(
        `SELECT value FROM aimos_memories
         WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'reasoning_state'
         ORDER BY updated_at DESC LIMIT 1`,
        [COMPANY, runtimeAgent.id]
      );
      if (rState.rows.length > 0) {
        const parsed = typeof rState.rows[0].value === 'string'
          ? JSON.parse(rState.rows[0].value)
          : rState.rows[0].value;
        const parts = [];
        if (parsed.hypotheses?.length) parts.push(`Hypotheses: ${parsed.hypotheses.join('; ')}`);
        if (parsed.open_questions?.length) parts.push(`Open questions: ${parsed.open_questions.join('; ')}`);
        if (parsed.chain?.length) parts.push(`Reasoning chain: ${parsed.chain.slice(-3).join(' → ')}`);
        if (parts.length) reasoningContext = `\n### REASONING CONTINUITY (from prior session):\n${parts.join('\n')}\n`;
      }
    } catch { /* reasoning recall is best-effort */ }
  }

  // ─── ADVISABILITY: check for mid-run corrections from humans/agents ─────
  let advisoryContext = '';
  if (!fastLane) {
    try {
      const advisories = await checkAdvisability(runtimeAgent.id);
      if (advisories && advisories.length > 0) {
        const advTexts = advisories.map(a => `[${a.from || 'human'}]: ${a.advice || a.text || JSON.stringify(a)}`);
        advisoryContext = `\n### HUMAN CORRECTIONS (integrate these into your response — they override prior instructions):\n${advTexts.join('\n')}\n`;
      }
    } catch { /* advisability check is best-effort */ }
  }

  // ─── TASK ROUTER: resolve framework sequence for this task type ────────────
  const taskType = options.taskType || options.intent || resolution.intent || 'chat';
  const knowledgeGateState = createKnowledgeGateState({
    agentId: runtimeAgent.id,
    prompt: userPrompt,
    intent: options.intent || resolution.intent || taskType,
    taskType,
    sessionId: conversationSessionKey
  });
  const taskRoute = fastLane ? null : await resolveTaskRoute(runtimeAgent.id, taskType, userPrompt);
  let investigationContext = '';
  let investigationLoopResult = null;
  if (shouldRunInvestigationLoop({ taskType, userPrompt, fastLane, options })) {
    try {
      const techniques = buildInvestigationTechniques(taskType, taskRoute);
      if (techniques.length > 0) {
        investigationLoopResult = await runInvestigationLoop(runId, userPrompt, techniques, {
          maxIterations: Math.min(3, techniques.length),
          checkObjective: async (history) => history.some((entry) => entry?.objectiveMet || entry?.status === 'confirmed'),
          executeIteration: async (_taskId, iteration, objective, technique, priorFindings) => {
            const isolatedSessionKey = normalizeConversationSessionKey(
              `${conversationSessionKey || runId}:investigation:${runId}:${iteration}`
            );
            const iterationPrompt = buildInvestigationIterationPrompt({
              objective,
              technique,
              priorFindings,
              taskType
            });
            const iterationResult = await runAgent(runtimeAgent.id, iterationPrompt, {
              ...options,
              depth: depth + 1,
              taskType: 'analysis',
              intent: options.intent || resolution.intent || taskType,
              sessionKey: isolatedSessionKey,
              parentRunId: runId,
              skipAimos: true,
              skipChaining: true,
              _investigationLoopActive: true
            });
            return parseInvestigationIterationResponse(iterationResult?.response, technique);
          }
        });
        investigationContext = buildInvestigationContext(investigationLoopResult);
        if (workspace && investigationLoopResult) {
          setPartition(workspace, 'B_work', {
            ...(getPartition(workspace, 'B_work') || {}),
            investigationIterations: investigationLoopResult.iterations,
            investigationStatuses: investigationLoopResult.findings.map((entry) => ({
              technique: entry.technique,
              status: entry.status
            }))
          });
        }
      }
    } catch (investigationErr) {
      console.warn('[explore-exploit-loop] investigation execution failed (non-fatal):', investigationErr.message);
    }
  }

  // ─── HYBRID REASONING: inject framework procedures before execution ────────
  let frameworkContext = '';
  if (!fastLane && taskRoute && taskRoute.frameworks?.length) {
    try {
      const fwNames = taskRoute.frameworks;
      const fwResult = await query(
        `SELECT key, value FROM aimos_memories
         WHERE company_id = $1 AND memory_type IN ('procedural', 'tacit_knowledge', 'strategic_directive', 'framework', 'playbook', 'book_extract')
           AND key ILIKE ANY($2)
         ORDER BY created_at DESC LIMIT 5`,
        [COMPANY, fwNames.map(f => `%${f}%`)]
      );
      if (fwResult.rows.length > 0) {
        const fwTexts = fwResult.rows.map(r => {
          const val = typeof r.value === 'string' ? r.value : JSON.stringify(r.value);
          return `[${r.key}]: ${val.slice(0, 800)}`;
        });
        frameworkContext = `\n### FRAMEWORK INJECTION (Hybrid Reasoning — symbolic priors for this task):\n${fwTexts.join('\n')}\n`;
      }
    } catch { /* framework injection is best-effort */ }
  }

  // ─── SENGE #3: TEAM LEARNING — inject cross-agent failure warnings ──────
  let teamLearningContext = '';
  if (!fastLane && taskType && taskType !== 'chat') {
    try {
      const sharedFails = await getSharedFailures(taskType, runtimeAgent.id, 3);
      if (sharedFails.length > 0) {
        const warnings = sharedFails.map(f => `- Agent ${f.agent_id} failed on ${f.taskType}: ${f.error}`).join('\n');
        teamLearningContext = `\n### TEAM LEARNING (other agents failed on this task type recently):\n${warnings}\nAvoid repeating these mistakes.\n`;
      }
    } catch { /* team learning injection is best-effort */ }
  }

  // ─── P0-4: META-CONTROLLER context injection ─────────────────────────────
  let metaControllerContext = '';
  if (metaDecision && !fastLane) {
    const { action, speed, reasoning, metaState, speculativeExecution } = metaDecision;
    metaControllerContext = `\n### META-CONTROLLER (System M — execution strategy):
Action: ${action} | Speed: ${speed}
Execution mode: ${speculativeExecution?.execution_mode || 'closed_loop'}
Verification: ${speculativeExecution?.replan_on_deviation ? `closed-loop deviation check tau=${speculativeExecution.safety_threshold_tau}` : 'standard'}
Reasoning: ${reasoning}
Novelty: ${(metaState?.novelty || 0).toFixed(2)} | Mastery: ${(metaState?.mastery || 0).toFixed(2)} | Failures: ${metaState?.failureRecurrence || 0}
${action === META_ACTIONS.APPLY_SKILL && metaState?.nearestSkill ? `Nearest skill: ${metaState.nearestSkill}` : ''}
${action === META_ACTIONS.EXPLORE ? 'IMPORTANT: Abandon current approach. Try a structurally different strategy.' : ''}
${action === META_ACTIONS.FALLBACK ? 'WARNING: Resource budget critically low. Use best available known approach.' : ''}\n`;
  }

  const turnBudgetContext = turnBudgetPlan && !fastLane
    ? `\n### TURN-ADAPTIVE BUDGET (TAB — per-turn compute allocation):
Difficulty level: ${turnBudgetPlan.turn_difficulty.difficulty_level}/4 | Budget: ${turnBudgetPlan.selected_budget_tokens} tokens | Route hint: ${turnBudgetPlan.route_hint}
Use concise reasoning for easy turns and reserve deeper reasoning for hard or decisive turns. GRPO budget training is not enabled; this is a runtime allocation contract.\n`
    : '';

  const latentLookaheadContext = latentLookaheadPlan && !fastLane
    ? `\n### LATENT LOOKAHEAD PREFETCH (Thinking into the Future — audited orchestration):
tau=${latentLookaheadPlan.latent_horizon_tau} | positions=${latentLookaheadPlan.thinking_positions.join(', ')}
Prefetch candidates: ${latentLookaheadPlan.prefetch_queries.slice(0, 3).join(' | ')}
Use this only as visible anticipatory recall guidance. Hidden-state recursion, latent attention-mask training, and multi-token prediction are not enabled.\n`
    : '';

  const epistemicBlindingContext = epistemicBlindingGate?.should_blind && !fastLane
    ? `\n### EPISTEMIC BLINDING (inference-time prior-contamination audit):
Entity identifiers in the current user prompt were replaced with anonymous codes before model inference. Reason only from supplied data/features. Do not infer fame, brand, literature familiarity, or prior reputation from identifiers. The code mapping is withheld from the model prompt and restored only after response generation.\n`
    : '';

  // ─── AGENT STATE: mark executing ──────────────────────────────────────────
  if (!fastLane) {
    await updateAgentState(runtimeAgent.id, 'executing', String(userPrompt).slice(0, 120), null, null, null);
  }

  const rawToolDefs = fastLane
    ? []
    : getToolsForAgent(runtimeAgent.tools || [], {
      ...(runtimeAgent.toolDeltas || {}),
      agentId: runtimeAgent.id
    });
  const toolDefs = fastLane
    ? []
    : await filterToolsForAgent(runtimeAgent.id, COMPANY, rawToolDefs);
  const allowedToolNames = toolDefs
    .map((toolDef) => toolDef?.schema?.function?.name)
    .filter(Boolean);
  const toolDirectionalityPolicy = buildDirectionalityPolicyForRun({
    agentId: runtimeAgent.id,
    intent: options.intent || resolution.intent || taskType,
    userPrompt,
    autonomous: options.autonomous === true
  });

  if (isOperatorAgentId(runtimeAgent.id)) {
    try {
      const deterministic = await runDeterministicExecutiveFastPath(runtimeAgent, userPrompt, {
        allowedTools: allowedToolNames,
        intent: options.intent || resolution.intent || 'chat',
        userPrompt,
        autonomous: options.autonomous === true,
        directionalityPolicy: toolDirectionalityPolicy,
        conversationHistory
      }, isInternalMemoryText);

      if (deterministic?.response) {
        const response = String(deterministic.response || '');
        const promptChars = String(userPrompt || '').length;
        const promptPressure = buildPromptPressure(promptChars, 0);
        updateLatestPromptPressureTelemetry(promptPressure);

        const knowledgeGateDecision = shouldBlockCompletionForMissingKnowledge(knowledgeGateState);
        if (knowledgeGateDecision.blocked) {
          const error = new Error(knowledgeGateDecision.message);
          error.code = knowledgeGateDecision.code || 'KNOWLEDGE_ACQUISITION_REQUIRED';
          error.knowledgeGate = knowledgeGateDecision;
          throw error;
        }

        await addConversationTurn(conversationSessionKey, 'user', userPrompt, {
          companyId: COMPANY,
          agentId: sourceAgentId,
          turnId: `${runId}:user`,
          observedAt: new Date(runStartTime).toISOString(),
          sourceRef: runId,
          persist: !options.skipAimos,
        });
        await addConversationTurn(conversationSessionKey, 'assistant', response, {
          companyId: COMPANY,
          agentId: sourceAgentId,
          turnId: `${runId}:assistant`,
          observedAt: new Date().toISOString(),
          sourceRef: runId,
          persist: !options.skipAimos,
        });

        persistedAgent.isActive = false;
        persistedAgent.lastSeen = new Date().toISOString();
        agents.set(agentId, persistedAgent);

        return {
          agentId: runtimeAgent.id,
          sourceAgentId,
          agentName: runtimeAgent.name,
          persona: runtimeAgent.persona,
          personaVersion: Number(resolution.personaVersion || runtimeAgent.personaVersion || 1),
          model: runtimeAgent.model,
          taskTypeResolved: modelPreference.taskType,
          modelRequested: options.requestedModel
            || options.preferredModel
            || modelPreference.model
            || resolution.requestedModel
            || runtimeAgent.model,
          modelResolved: runtimeAgent.model,
          fallbackUsed: false,
          promptChars,
          responseChars: response.length,
          contextCompaction: aimosContextPack.contextCompaction,
          promptPressure,
          confidence: extractConfidence(response, 0, aimosContextPack.contextCompaction?.keptItems || 0),
          response,
          delegatedTo: null,
          reviewerNote: null
        };
      }
    } catch (fastPathError) {
      console.warn(`[agent-runner] executive deterministic fast-path skipped: ${fastPathError?.message || fastPathError}`);
    }
  }

  // ─── Feature 2: Metareasoning — classify complexity to skip/include ReAct ──
  const complexity = classifyComplexity(userPrompt, taskType);
  if (!fastLane) {
    try {
      robustLengthPrediction = buildRobustLengthPrediction({
        prompt: llmUserPrompt,
        taskType,
        fallbackBudgetTokens: turnBudgetPlan?.selected_budget_tokens || null,
      });
    } catch (lengthErr) {
      console.warn('[robust-length] prediction failed (non-fatal):', lengthErr.message);
    }
  }

  const robustLengthContext = robustLengthPrediction && !fastLane
    ? `\n### ROBUST LENGTH PREDICTION (ProD-M median target proxy):
Predicted output length: ${robustLengthPrediction.prediction_tokens} tokens | target: ${robustLengthPrediction.target_functional}
Use this as a scheduling/budget expectation, not as a content truncation instruction. ProD-M/ProD-D training and hidden-state probes are not enabled.\n`
    : '';
  if (!fastLane) {
    try {
      agscGenerationContract = buildAgscOutputContract({
        text: llmUserPrompt,
        taskType,
        maxPrimaryUnits: 4,
      });
    } catch (agscErr) {
      console.warn('[AGSC] generation contract failed (non-fatal):', agscErr.message);
    }
  }

  const agscContext = agscGenerationContract && !fastLane
    ? `\n### AGSC OUTPUT CONTRACT (adaptive granularity, inspectable evidence):
Preferred shape: ${agscGenerationContract.output_contract.preferred_shape}
Evidence must remain inspectable; summarize without hiding source-backed details. NLI neutral triggers, UMAP, GMM soft clustering, and uncertainty aggregation are not enabled.\n`
    : '';
  if (!fastLane) {
    try {
      localInferencePlan = buildLocalInferenceRunPlan({
        model: runtimeAgent.model,
        prompt: llmUserPrompt,
        taskType,
        contextTokens: Math.ceil((String(llmUserPrompt || '').length + aimosContextPack.text.length) / 4),
        predictedOutputTokens: robustLengthPrediction?.prediction_tokens || turnBudgetPlan?.selected_budget_tokens || null,
        confidence: psychometricProfile?.success_probability ?? null,
        vectorCount: aimosContextPack.memories?.length || 0,
        memories: aimosContextPack.memories || [],
      });
    } catch (localErr) {
      console.warn('[wave5-local-inference] plan failed (non-fatal):', localErr.message);
    }
  }

  const localInferenceContext = localInferencePlan && !fastLane
    ? `\n### WAVE 5 LOCAL INFERENCE CONTRACT (native, no proxy):
MoE scheduling: ${localInferencePlan.moe_scheduling.status}; KV pressure: ${localInferencePlan.kv_cache.kv_cache_estimate.free_memory_pressure_ratio}; small-model sparse ratio: ${localInferencePlan.small_model_efficiency.sparse_memory_control.adaptive_sparse_ratio}
Use these as runtime constraints only. Do not claim quantization, learned scheduler execution, PIM, SmartSSD, or physical memory migration unless the live status explicitly enables it.\n`
    : '';

  let systemPrompt = fastLane
    ? buildFastLaneSystemPrompt(runtimeAgent)
    : buildSystemPrompt(
        runtimeAgent,
        toolDefs,
        aimosContextPack.text + proceduralSkills.text + dualSkillText + reasoningContext + investigationContext + frameworkContext + advisoryContext + teamLearningContext + metaControllerContext + turnBudgetContext + latentLookaheadContext + robustLengthContext + agscContext + localInferenceContext + epistemicBlindingContext + scopedStateContext
          + (complexity === 'simple' ? '\ncomplexity:simple' : '')
          + (taskRoute ? `\n### TASK ROUTE (F7): ${taskType} → frameworks: [${(taskRoute.frameworks || []).join(', ')}], threshold: ${taskRoute.confidence_threshold || 0.8}` : ''),
        {
          modelId: runtimeAgent.model,
          userPrompt: llmUserPrompt,
          reasoningQuanta,
          estimatedPromptChars:
            String(userPrompt || '').length
            + aimosContextPack.text.length
            + proceduralSkills.text.length
            + dualSkillText.length
            + reasoningContext.length
            + investigationContext.length
            + frameworkContext.length
            + advisoryContext.length
            + teamLearningContext.length
            + metaControllerContext.length
            + turnBudgetContext.length
            + latentLookaheadContext.length
            + robustLengthContext.length
            + agscContext.length
            + epistemicBlindingContext.length
            + scopedStateContext.length
            + reasoningQuanta.length
            + (epistemicBlindingGate?.should_blind ? 0 : conversationHistory.reduce((sum, turn) => sum + String(turn?.content || '').length, 0)),
          promptPressureRatio: getPromptPressureTelemetry().ratio || 0
        }
      );
  const basePromptChars = (systemPrompt?.length || 0)
    + String(userPrompt || '').length
    + aimosContextPack.text.length;
  const conversationMessages = buildConversationMessages(epistemicBlindingGate?.should_blind ? [] : conversationHistory);
  const contextGuard = trimConversationMessagesForBudget(conversationMessages, basePromptChars);
  if (contextGuard.trimmed > 0) {
    console.info(
      `[context-guard] trimmed ${contextGuard.trimmed} messages to fit budget (was ${contextGuard.initialTotalChars} chars, now ${contextGuard.totalChars} chars)`
    );
  }
  const promptChars = contextGuard.totalChars;
  const promptPressure = buildPromptPressure(promptChars, contextGuard.trimmed);
  updateLatestPromptPressureTelemetry(promptPressure);
  if (!fastLane) {
    const includePromptInLogs = systemConfigStore.readConfigString('AGENT_RUNNER_DEBUG_PROMPT') === 'true';
    console.info('[agent-runner] built system prompt', {
      agentId: runtimeAgent.id,
      toolCount: allowedToolNames.length,
      aimosContextChars: aimosContextPack.text.length,
      aimosContextItems: aimosContextPack.contextCompaction?.keptItems || 0,
      promptPressure,
      promptChars: systemPrompt.length,
      ...(includePromptInLogs ? { tools: allowedToolNames, prompt: systemPrompt } : {})
    });
  }

  // ─── CHANNEL SEPARATOR: instruction/data separation for prompt assembly ─────
  if (!fastLane) {
    try {
      const aimosMemories = (aimosContextPack.text || '').split('\n')
        .filter(Boolean)
        .map((line, idx) => ({ key: `mem_${idx}`, value: sanitizeMemoryValue(line) }));
      const separated = buildSeparatedPrompt(systemPrompt, llmUserPrompt, aimosMemories);
      const channelValidation = validateChannelSeparation(
        `=== SYSTEM INSTRUCTIONS ===\n${separated.system}\n\n${separated.reference}\n\n=== USER INPUT ===\n${separated.user}`
      );
      if (!channelValidation.clean) {
        console.warn(`[channel-separator] violations: ${channelValidation.violations.join('; ')}`);
      }
    } catch (csErr) {
      console.warn('[channel-separator] prompt separation failed:', csErr.message);
    }
  }

  // ─── LINGUISTIC CONSTRAINTS: apply role-based language constraints post-separation ─
  if (!fastLane) {
    try {
      const roleSlot = runtimeAgent.role || runtimeAgent.id || 'executor';
      const constraintType = getConstraintForRole(roleSlot);
      if (constraintType === 'no-have') {
        systemPrompt = applyNoHaveConstraint(systemPrompt);
      } else if (constraintType === 'e-prime') {
        systemPrompt = applyEPrimeConstraint(systemPrompt);
      }
    } catch (lcErr) {
      console.warn('[linguistic-constraints] constraint application failed (non-fatal):', lcErr.message);
    }
  }

  // ─── COGNITIVE SECURITY REVIEW — final assembled prompt, pre-inference ───
  // Review selection is independent from trust risk. Deterministic edge and
  // cross-entry checks always run; classifier/full-review tiers additionally
  // invoke the semantic analyst. Full review fails closed if that verdict is
  // unavailable or inconclusive.
  {
    const conversationSecurityContext = contextGuard.messages
      .map((message, index) => `=== CONVERSATION TURN ${index + 1} (${message.role}) ===\n${message.content}`)
      .join('\n\n');
    const assembledSecurityPrompt = [
      `=== SYSTEM INSTRUCTIONS ===\n${systemPrompt}`,
      conversationSecurityContext,
      `=== USER INPUT ===\n${llmUserPrompt}`,
    ].filter(Boolean).join('\n\n');
    const memoryValues = (aimosContextPack.text || '').split('\n').filter(Boolean);
    const effectiveReviewTier = fastLane ? 'se_gate_only' : reviewTier;
    try {
      const secResult = await runSecurityPipeline(
        assembledSecurityPrompt,
        memoryValues,
        {
          agentId: runtimeAgent.id,
          runId,
          reviewTier: effectiveReviewTier,
          availableTools: allowedToolNames,
        }
      );
      const authority = options.executionContext || options.credentialUseContext || null;
      const decisionEvidence = buildSecurityDecisionEvidence({
        assembledPrompt: assembledSecurityPrompt,
        recalledMemoryValues: memoryValues,
        result: secResult,
        reviewTier: effectiveReviewTier,
      });
      try {
        securityDecisionReceipt = await logEvent(
          COMPANY,
          runtimeAgent.id,
          'security_admission_decision',
          runId,
          {
            ...decisionEvidence,
            run_id: runId,
            task_risk_level: taskRiskLevel,
            request_receipt_id: authority?.requestReceiptId || null,
            request_receipt_mutation_hash: authority?.requestReceiptMutationHash || null,
            reasoning: `Native assembled-prompt review recorded a ${decisionEvidence.decision} decision at ${decisionEvidence.stage}; canonical memories and retrieval weights were not removed or mutated.`,
            source_knowledge: 'security-classifier.js — Cognitive Firewall; Aimos certificate-envelope event ledger',
          },
          options.securityParentEventId || null,
          { authority, returnReceipt: true },
        );
      } catch (ledgerError) {
        const error = new Error(`SECURITY EVIDENCE REQUIRED: ${ledgerError.message}`);
        error.code = 'SECURITY_EVIDENCE_REQUIRED';
        error.cause = ledgerError;
        throw error;
      }
      if (!secResult.safe) {
        const err = new Error(`SECURITY BLOCKED [${secResult.category}]: ${secResult.reason}`);
        err.code = 'SEMANTIC_SECURITY_BLOCKED';
        err.securityResult = secResult;
        err.securityDecisionEvidence = securityDecisionReceipt;
        throw err;
      }
    } catch (secErr) {
      if (secErr.code === 'SEMANTIC_SECURITY_BLOCKED') throw secErr;
      if (secErr.code === 'SECURITY_EVIDENCE_REQUIRED') throw secErr;
      if (reviewTier === 'full_review') {
        const err = new Error(`SECURITY BLOCKED [full_review_error]: ${secErr.message}`);
        err.code = 'SEMANTIC_SECURITY_BLOCKED';
        err.cause = secErr;
        throw err;
      }
      console.warn('[security-classifier] pipeline error:', secErr.message);
    }
  }

  // ─── SCHEMA MAPPER: extract structured facts before LLM call ──────────────
  if (!fastLane && toolDefs.length > 0) {
    try {
      const toolSchemaForMapper = toolDefs.map(td => ({
        name: td?.schema?.function?.name || '',
        description: td?.schema?.function?.description || '',
        parameters: td?.schema?.function?.parameters || {}
      })).filter(t => t.name);
      const toolSchema = getToolSchema(toolSchemaForMapper);
      if (toolSchema.tools.length > 0) {
        const extractedFacts = await extractStructuredFacts(llmUserPrompt, toolSchemaForMapper);
        if (extractedFacts.length > 0) {
          const mappedCalls = mapFactsToToolCalls(extractedFacts, toolSchema);
          const validCalls = mappedCalls.filter(c => c.valid);
          const invalidCalls = mappedCalls.filter(c => !c.valid);
          if (invalidCalls.length > 0) {
            console.warn(`[schema-mapper] ${invalidCalls.length} invalid tool calls rejected: ${invalidCalls.map(c => `${c.tool}: ${c.violations.join(', ')}`).join('; ')}`);
          }
          if (workspace) {
            setPartition(workspace, 'B_work', { schemaMappedCalls: validCalls.length, invalidCalls: invalidCalls.length });
          }
        }
      }
    } catch (smErr) {
      console.warn('[schema-mapper] extraction failed:', smErr.message);
    }
  }

  // ─── DECISION RENDERER: deterministic selection pre-LLM ───────────────────
  if (!fastLane) {
    try {
      const proposals = [];
      if (constitutionRules.length > 0) {
        proposals.push({
          agentId: runtimeAgent.id,
          role: 'governance',
          action: 'enforce_constitution',
          content: `${constitutionRules.length} constitution rules loaded`,
          confidence: 1.0,
          constraints: {}
        });
      }
      if (options.intent && options.intent !== 'chat') {
        proposals.push({
          agentId: runtimeAgent.id,
          role: 'execution',
          action: options.intent,
          content: String(userPrompt).slice(0, 200),
          confidence: 0.7,
          constraints: {}
        });
      }
      if (proposals.length > 0) {
        const decision = selectAction(proposals);
        if (decision.winner) {
          if (workspace) {
            setPartition(workspace, 'B_sys', { decisionWinner: decision.winner.role, muted: decision.muted });
          }
        }
      }
    } catch (drErr) {
      console.warn('[decision-renderer] pre-LLM selection failed:', drErr.message);
    }
  }

  let response;
  let executedModel = runtimeAgent.model;
  let reviewerNote = null;
  let toolProtocolGuard = null;
  const delegatedTo = sourceAgentId !== runtimeAgent.id ? runtimeAgent.id : null;
  const scratToolReflections = [];

  try {
    const inheritedCredentialContext = options.credentialUseContext || options.executionContext || null;
    const credentialUseContext = inheritedCredentialContext || (options.autonomous === true
      ? Object.freeze({
          actorAgentId: 'housekeeper',
          actorValidFromIso: securityDecisionReceipt?.signer_valid_from || null,
          companyId: COMPANY,
          identityTier: securityDecisionReceipt?.identity_tier || 'T1_SYSTEM_SELF',
          authSource: 'housekeeper_autonomous',
          requestReceiptId: null,
          requestReceiptMutationHash: null,
          requestAdmissionEventId: null,
          requestAdmissionMutationHash: null,
          autonomousActionEventId: securityDecisionReceipt?.event_id || null,
        })
      : null);
    const result = await runAgentWithFallback(runtimeAgent, systemPrompt, llmUserPrompt, toolDefs, {
      requestedModel: options.requestedModel || resolution.requestedModel || null,
      preferredModel: options.preferredModel || modelPreference.model || null,
      strictRequestedModel: !!options.strictRequestedModel,
      modelPlan: Array.isArray(options.modelPlan)
        ? options.modelPlan
        : [options.model, options.requestedModel, options.preferredModel, modelPreference.model, runtimeAgent.model].filter(Boolean),
      toolExecutionOptions: {
        allowedTools: allowedToolNames,
        agentId: runtimeAgent.id,
        intent: options.intent || resolution.intent || 'chat',
        taskType: options.taskType || resolution.intent || 'chat',
        userPrompt: llmUserPrompt,
        autonomous: options.autonomous === true,
        clearanceLevel: runtimeAgent.clearanceLevel || 1,
        runId,
        securityDecisionEventId: securityDecisionReceipt?.event_id || null,
        executionContext: options.executionContext || credentialUseContext,
        credentialUseContext,
        sessionKey: conversationSessionKey,
        sourceAgentId,
        parentRunId: options.parentRunId || null,
        _scopedState: delegationScopedState,
        directionalityPolicy: toolDirectionalityPolicy,
        knowledgeGateState,
        resolveKnowledgeProof: async () => {
          const { getProofForSession } = await import('../security/knowledge-gate.js');
          return getProofForSession(knowledgeGateState);
        },
        onToolResult: (event) => {
          recordKnowledgeToolEvent(knowledgeGateState, event);
          try {
            const scratReflection = evaluateScratToolReflection(event, {
              runId,
              taskType,
              userPrompt: llmUserPrompt,
              agentId: runtimeAgent.id,
            });
            scratToolReflections.push(scratReflection);
            logEvent(
              COMPANY,
              runtimeAgent.id,
              'scrat_tool_reflection',
              `scrat:${runId}:${scratToolReflections.length}`,
              scratReflection
            ).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
          } catch (scratErr) {
            console.warn('[SCRAT] tool reflection failed (non-fatal):', scratErr.message);
          }
        }
      },
      onToken,
      conversationMessages: contextGuard.messages
    });
    await recordCanariesRelayed(canaryRelayObservation, {
      authority: options.executionContext || credentialUseContext,
      modelInvocationCompleted: true,
    });
    response = result.response;
    executedModel = result.model || executedModel;
    if (epistemicBlindingGate?.should_blind && response) {
      response = deblindText(response, epistemicBlindingGate.blind_map);
    }
    toolProtocolGuard = guardRawToolProtocolText(response);
    if (toolProtocolGuard.guarded) {
      response = toolProtocolGuard.response;
      logEvent(COMPANY, runtimeAgent.id, 'raw_tool_protocol_guarded', `tool_protocol_guard:${runId}`, {
        reasoning: 'Model output contained raw tool-call protocol text as plain response content. The protocol was withheld and no tool execution was inferred from it.',
        source_knowledge: 'Batch9 Wave3 stream/tool boundary; SCRAT observer separation; HOM no raw tool protocol display rule',
        model: executedModel,
        raw_protocol_exposed: false,
        tool_executed: false
      }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
    }

    // ─── SCHEMING MONITOR: post-LLM suspicion scoring ────────────────────────
    if (!fastLane && response) {
      try {
        const trajectoryEvents = [
          { type: 'user_message', content: String(userPrompt).slice(0, 1000) },
          { type: 'agent_response', content: String(response).slice(0, 2000) }
        ];
        const warningSigns = getWarningSignsForEvents(trajectoryEvents);
        if (warningSigns.length > 0) {
          console.warn(`[scheming-monitor] warning signs for ${runtimeAgent.id}: ${warningSigns.join(', ')}`);
        }
        const auditResult = await auditTrajectory(runtimeAgent.id, trajectoryEvents, {});
        if (auditResult.alert) {
          console.error(`[scheming-monitor] ALERT for ${runtimeAgent.id}: score=${auditResult.score}, signs=${auditResult.warning_signs.join(', ')}`);
          logEvent('hom', runtimeAgent.id, 'scheming_alert', `scheming:${runtimeAgent.id}`, {
            reasoning: `Scheming monitor scored trajectory at ${auditResult.score}/10 — alert threshold reached. Warning signs: ${auditResult.warning_signs.join(', ')}. ${auditResult.reasoning}`,
            source_knowledge: 'scheming-monitor.js — Constitutional Black-Box Monitoring (2026)',
            score: auditResult.score,
            warning_signs: auditResult.warning_signs
          }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
        }
        if (workspace) {
          setPartition(workspace, 'B_sys', { schemingScore: auditResult.score, warningSigns: auditResult.warning_signs });
        }
      } catch (smErr) {
        console.warn('[scheming-monitor] post-run audit failed:', smErr.message);
      }
    }

    // ─── CANARY-TRACKER: response-leak observation (not a kill-chain stage) ────
    try {
      const responseCanaries = detectCanaries(response || '');
      if (responseCanaries.length > 0) {
        await logEvent(COMPANY, runtimeAgent.id, 'canary_response_detected', `canary_response:${runId}`, {
          reasoning: `Canary token appeared in model response for run ${runId}; this is recorded as an output-leak observation and is not mislabeled as a RELAYED memory stage.`,
          source_knowledge: 'Kill-Chain Canaries — stage-level propagation tracking',
          canary_tokens: responseCanaries,
          run_id: runId,
        }, securityDecisionReceipt?.event_id || null, {
          authority: options.executionContext || options.credentialUseContext || null,
          returnReceipt: true,
        });
        console.warn(`[canary-tracker] canary token(s) leaked in response for run ${runId}: ${responseCanaries.join(', ')}`);
      }
    } catch (canaryErr) {
      console.warn('[canary-tracker] canary scan failed:', canaryErr.message);
    }

    // ─── CONSTITUTION ENFORCEMENT: enforce rules post-run ───────────────────
    try {
      if (constitutionRules && constitutionRules.length > 0) {
        const enforceResult = await enforceRules(constitutionRules, { agentId: runtimeAgent.id, response, prompt: userPrompt });
        if (enforceResult && enforceResult.violations && enforceResult.violations.length > 0) {
          console.warn(`[constitution] ${enforceResult.violations.length} violation(s) for ${runtimeAgent.id}:`, enforceResult.violations.map(v => v.rule).join(', '));
          void logEvent('hom', runtimeAgent.id, 'constitution_violation', `constitution:${runtimeAgent.id}`, {
            reasoning: `Constitution enforcement found ${enforceResult.violations.length} violation(s): ${enforceResult.violations.map(v => v.rule + ' — ' + v.detail).join('; ')}`,
          }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
        }
      }
    } catch (ceErr) { console.warn('[constitution] enforceRules post-run failed (non-fatal):', ceErr.message?.slice(0, 80)); }

    // Auto-review pass for agents that may need quality checks
    const needsReview =
      runtimeAgent.id === 'smith-coder' && runtimeAgent.model.includes('qwen3-coder');

    if (needsReview && agents.has('backend')) {
      try {
        const reviewPrompt = `Peer review the following output for correctness, missed edge cases, and needed fixes. Respond with a concise review + fixes:\n\n${response}`;
        const review = await runAgent('backend', reviewPrompt, {
          skipAimos: true,
          autonomous: false,
          depth: depth + 1,
          executionContext: options.executionContext || options.credentialUseContext || null,
          securityParentEventId: options.securityParentEventId || null,
        });
        reviewerNote = `[Reviewed by backend | model=${review.model}]\n${review.response}`;
        response = `${response}\n\n${reviewerNote}`;
      } catch (e) {
        reviewerNote = `Review failed: ${e.message}`;
      }
    }

    const knowledgeGateDecision = shouldBlockCompletionForMissingKnowledge(knowledgeGateState);
    if (knowledgeGateDecision.blocked) {
      const error = new Error(knowledgeGateDecision.message);
      error.code = knowledgeGateDecision.code || 'KNOWLEDGE_ACQUISITION_REQUIRED';
      error.knowledgeGate = knowledgeGateDecision;
      throw error;
    }

    await addConversationTurn(conversationSessionKey, 'user', userPrompt, {
      companyId: COMPANY,
      agentId: sourceAgentId,
      turnId: `${runId}:user`,
      observedAt: new Date(runStartTime).toISOString(),
      sourceRef: runId,
      persist: !options.skipAimos,
    });
    await addConversationTurn(conversationSessionKey, 'assistant', response, {
      companyId: COMPANY,
      agentId: sourceAgentId,
      turnId: `${runId}:assistant`,
      observedAt: new Date().toISOString(),
      sourceRef: runId,
      persist: !options.skipAimos,
    });

    // ─── PROCEDURAL MEMORY: Skill learning + usage tracking ─────────────────
    if (!fastLane && !options.skipAimos && response && response.length > 100) {
      try {
        const toolUseIndicators = ['aimos_recall', 'aimos_save', 'web_search', 'delegate_task', 'gmail_send', 'calendar_create'];
        const usedTools = toolUseIndicators.filter(t => response.includes(t));
        if (usedTools.length >= 2) {
          const skillName = `auto_${runtimeAgent.id}_${(options.intent || options.taskType || 'general').replace(/[^a-z0-9]/gi, '_')}`;
          const skillDesc = `${skillName}: ${options.intent || options.taskType || 'general'} task using ${usedTools.join(', ')}`;
          let skillEmbedding = null;
          try { skillEmbedding = await getEmbedding(skillDesc); } catch { /* embedding optional */ }
          await query(
            `INSERT INTO procedural_skills (company_id, agent_id, skill_name, trigger_pattern, steps, expected_outcome, success_count, last_used, tags, skill_embedding)
             VALUES ($1, $2, $3, $4, $5, $6, 1, NOW(), $7, $8::vector)
             ON CONFLICT (company_id, skill_name)
             DO UPDATE SET success_count = procedural_skills.success_count + 1, last_used = NOW(), updated_at = NOW(),
               skill_embedding = COALESCE(EXCLUDED.skill_embedding, procedural_skills.skill_embedding)`,
            [COMPANY, runtimeAgent.id, skillName,
             (options.intent || options.taskType || '').toLowerCase(),
             JSON.stringify(usedTools.map(t => `use ${t}`)),
             `Automated pattern from ${options.intent || 'general'} task`,
             JSON.stringify(usedTools),
             skillEmbedding ? JSON.stringify(skillEmbedding) : null]
          );
        }
      } catch { /* skill learning is best-effort */ }
    }

    // ─── F7 EVAL PROTOCOL: criteria-based confidence scoring ────────────────
    const heuristicConf = extractConfidence(response, 0, aimosContextPack.contextCompaction?.keptItems || 0);
    const f7Confidence = await evaluateWithF7Protocol(runtimeAgent.id, taskType, heuristicConf, response);
    // ─── Feature 10: Antifragile Confidence Calibration ──────────────────────
    const calibrationFactor = await getCalibrationFactor(runtimeAgent.id, taskType);
    const finalConfidence = Math.max(0.05, Math.min(0.99, f7Confidence * calibrationFactor));

    // ─── REFINEMENT 3: Negative skill learning — track failures, not just successes
    if (proceduralSkills.skillIds.length > 0) {
      try {
        const skillConfidence = heuristicConf;
        for (const skillId of proceduralSkills.skillIds) {
          if (skillConfidence >= 0.5) {
            await query(
              `UPDATE procedural_skills SET success_count = success_count + 1, last_used = NOW(), updated_at = NOW() WHERE id = $1`,
              [skillId]
            );
          } else {
            await query(
              `UPDATE procedural_skills SET fail_count = fail_count + 1, last_used = NOW(), updated_at = NOW() WHERE id = $1`,
              [skillId]
            );
          }
        }
      } catch { /* best effort */ }
    }

    // ─── REFINEMENT 2: Conditional DAG re-routing ──────────────────────────
    const rerouteCheck = evaluateRouteConfidence(taskRoute, finalConfidence);
    let rerouteNote = null;
    if (rerouteCheck.reroute) {
      rerouteNote = `[REROUTE] ${rerouteCheck.reason} — fallback: ${JSON.stringify(rerouteCheck.fallbackRoute).slice(0, 100)}`;
      console.info(`[agent-runner] ${rerouteNote}`);
    }

    // ─── AUTONOMY ENFORCEMENT: check confidence against thresholds ──────────
    let autonomy = await checkAutonomyLevel(runtimeAgent.id, finalConfidence, taskType);
    let autonomyNote = null;

    const socialLawCheck = evaluateSocialLawViolations({
      sourceAgentId,
      runtimeAgentId: runtimeAgent.id,
      prompt: userPrompt,
      intent: options.intent || resolution.intent || taskType,
      confidence: finalConfidence
    });
    const socialLawNote = socialLawCheck.violations.length
      ? `[SOCIAL-LAWS] ${socialLawCheck.violations.map((v) => `${v.lawId}: ${v.detail}`).join(' | ')}`
      : null;
    if (socialLawCheck.mustEscalate && autonomy.action !== 'escalate') {
      autonomy = { ...autonomy, level: 'L1', action: 'escalate' };
    }

    if (autonomy.action === 'notify') {
      autonomyNote = `[AUTONOMY-L2] confidence=${finalConfidence.toFixed(2)} — acted + notify`;
    } else if (autonomy.action === 'escalate') {
      autonomyNote = `[AUTONOMY-L1] confidence=${finalConfidence.toFixed(2)} — requires human review`;
    }

    // ─── AGENT STATE MACHINE: update BDI state (SENGE #2 + intention persistence) ──
    let mergedIntentions;
    try {
      const priorBDI = await readAgentBDIState(runtimeAgent.id);
      const priorIntentions = priorBDI?.intentions || {};
      const preserved = {};
      for (const [key, val] of Object.entries(priorIntentions)) {
        if (key === 'next' || key === 'escalation_needed' || key === 'last_task_completed' || key === 'updated_at') continue;
        if (typeof val === 'object' && val?.status === 'completed') continue;
        preserved[key] = val;
      }
      mergedIntentions = {
        ...preserved,
        next: rerouteCheck?.reroute ? 'retry with alternative route' : 'await next task',
        escalation_needed: autonomy.action === 'escalate',
        last_task_completed: taskType,
        updated_at: new Date().toISOString()
      };
    } catch {
      mergedIntentions = {
        next: rerouteCheck?.reroute ? 'retry with alternative route' : 'await next task',
        escalation_needed: autonomy.action === 'escalate'
      };
    }
    // ─── Gap 3: BDI Memory References — attach consulted/saved memory keys ───────
    const memoriesConsulted = (aimosContextPack.memories || [])
      .slice(0, 10)
      .map(m => {
        const agentId = m.agentId || 'unknown';
        const preview = String(m.rawValue || '').slice(0, 60);
        return `${agentId}:${preview}`;
      })
      .filter(Boolean);
    const memoriesSaved = (aimosContextPack.recentSaveEvents || [])
      .filter(e => e.operation === 'save')
      .map(e => e.key)
      .filter(Boolean)
      .slice(0, 5);

    await updateAgentState(
      runtimeAgent.id, 'idle', null,
      `responded to: ${String(userPrompt).slice(0, 80)}`,
      null, finalConfidence,
      {
        beliefs: {
          task_context: taskType, model_used: executedModel,
          confidence_level: finalConfidence > 0.7 ? 'high' : finalConfidence > 0.4 ? 'medium' : 'low',
          rerouted: !!rerouteCheck?.reroute,
          memories_consulted: memoriesConsulted,
          memories_saved: memoriesSaved,
          last_updated: new Date().toISOString()
        },
        desires: { goal: `Complete ${taskType} task successfully`, quality_target: taskRoute?.confidence_threshold || 0.6 },
        intentions: mergedIntentions
      }
    );

    let reasoningSignals = [];
    let explanationArtifact = null;
    let architectureDecision = null;

    // ─── GAP 2: REASONING CHAIN CAPTURE ───────────────────────────────────
    if (!fastLane && !options.skipAimos && response && response.length > 200) {
      try {
        const responseStr = String(response);
        const reasoningPatterns = [
          /(?:because|since|due to|as a result)[^.]{10,120}\./gi,
          /(?:therefore|thus|consequently|so I)[^.]{10,120}\./gi,
          /(?:decided to|chose|selected|opted for|picked)[^.]{10,120}\./gi,
          /(?:trade-?off|weighed|considered|evaluated)[^.]{10,120}\./gi,
          /(?:risk|concern|caveat|limitation|downside)[^.]{10,120}\./gi
        ];
        for (const pat of reasoningPatterns) {
          const matches = responseStr.match(pat);
          if (matches) reasoningSignals.push(...matches.slice(0, 2));
        }
        if (reasoningSignals.length > 0) {
          const chainSummary = reasoningSignals.slice(0, 5).map(s => s.trim()).join(' | ');
          const chainKey = `reasoning:${runtimeAgent.id}:${Date.now()}`;
          const chainValue = JSON.stringify({
            agent: runtimeAgent.id,
            task_type: taskType,
            prompt_snippet: String(userPrompt).slice(0, 150),
            confidence: finalConfidence,
            reasoning: reasoningSignals.slice(0, 5),
            tools_used: proceduralSkills.skillIds || [],
            rerouted: !!rerouteCheck.reroute,
            timestamp: new Date().toISOString()
          });
          // Quality gate is enforced inside persistMemory, no need to pre-check
          await persistMemory({
            company_id: COMPANY,
            agent_id: runtimeAgent.id,
            key: chainKey,
            value: chainValue,
            scope: 'system',
            memory_type: 'reasoning_chain',
            clearance_level: 3,
            source: 'agent-runner',
            mutation_authority: 'housekeeper',
          });
        }
      } catch { /* reasoning capture is best-effort */ }
    }

    // ─── REASONING STATE PERSISTENCE ─────────────────────────────────────────
    if (!fastLane && !options.skipAimos && response && response.length > 100) {
      try {
        const stateKey = `reasoning_state:${runtimeAgent.id}`;
        const stateValue = JSON.stringify({
          hypotheses: [`Completed ${taskType} task with confidence ${(finalConfidence || 0).toFixed(2)}`],
          open_questions: rerouteCheck?.reroute ? ['Low confidence triggered reroute — review framework coverage'] : [],
          reasoning_chain: [`${taskType} → ${(executedModel || 'unknown')} → conf:${(finalConfidence || 0).toFixed(2)}`],
          last_task: taskType,
          last_model: executedModel,
          timestamp: new Date().toISOString()
        });
        await persistMemory({
          company_id: COMPANY,
          agent_id: runtimeAgent.id,
          key: stateKey,
          value: stateValue,
          scope: 'system',
          memory_type: 'reasoning_state',
          clearance_level: 3,
          source: 'agent-runner',
          mutation_authority: 'housekeeper',
        });
      } catch (err) { console.warn(`[agent-runner] reasoning state write failed: ${err.message}`); }
    }

    persistedAgent.isActive = false;
    persistedAgent.lastSeen = new Date().toISOString();
    agents.set(agentId, persistedAgent);

    // ─── CYBERSEC POST-EXECUTION SENTINEL CHECK ──────────────────────────────
    if (cybersecMode && response) {
      try {
        const sentinelResult = await runSentinelCheck({
          content: String(response),
          persona: runtimeAgent.persona,
          agentId: runtimeAgent.id,
          companyId: COMPANY,
          isCybersecAction: true,
          isResponse: true,
          source: 'agent-runner',
          transport: 'agent',
        });
        if (!sentinelResult.pass) {
          const failedRules = (sentinelResult.failed || []).map(r => `Rule ${r.rule}: ${r.reason}`).join('; ');
          console.error(`[SENTINEL] Post-execution check FAILED: ${failedRules}`);
          response = `[SENTINEL BLOCKED MODEL OUTPUT: ${failedRules}]`;
        }
      } catch (sentinelError) {
        const error = new Error(`SENTINEL POST-CHECK FAILED: ${sentinelError.message}`);
        error.code = 'SENTINEL_POSTCHECK_FAILED';
        throw error;
      }
    }

    // Record agent-run metrics.
    const runEndTime = Date.now();
    try {
      await recordAgentRun(runtimeAgent.id, {
        success: true,
        confidence: finalConfidence,
        errorCount: 0,
        latencyMs: runEndTime - runStartTime,
        tokenEstimate: promptChars + String(response || '').length,
        toolsUsed: allowedToolNames.length,
        taskType: taskType,
        model: executedModel
      });
    } catch { /* metrics recording is best-effort */ }

    // ─── Batch 10 Lane 2: Plasticity computation after inference ────────────
    // Paper: G-MemLLM, M+. Write strength modulates how strongly new memories
    // are stored. Aladdin: plasticity affects activation weight, never deletes.
    const plasticity = computePlasticity({
      confidence: finalConfidence,
      taskType: taskType,
      latencyMs: runEndTime - runStartTime,
    });

    // ─── MANDATORY EVENT LOG ──────────────────────────────────────────────────
    const _successTraceEvent = await logMandatoryRunEvent(runtimeAgent.id, {
      success: true,
      model: executedModel,
      taskType,
      confidence: finalConfidence,
      latencyMs: runEndTime - runStartTime,
      promptSnippet: String(userPrompt).slice(0, 120),
      parentEventId: options._parentEventId || null
    });

    const fallbackComparisonModel = resolution.primaryModel || runtimeAgent.model;
    const fallbackUsed = !modelsEquivalentForFallback(executedModel, fallbackComparisonModel);
    let agscOutputContract = null;
    try {
      agscOutputContract = buildAgscOutputContract({
        text: response,
        taskType,
      });
    } catch (agscErr) {
      console.warn('[AGSC] output contract failed (non-fatal):', agscErr.message);
    }
    let tokenScaleSignal = null;
    try {
      tokenScaleSignal = buildTokenScaleRuntimeSignal({
        promptChars,
        responseChars: String(response || '').length,
        latencyMs: runEndTime - runStartTime,
        predictedOutputTokens: robustLengthPrediction?.prediction_tokens || turnBudgetPlan?.selected_budget_tokens || null,
        stream: typeof onToken === 'function',
      });
      logEvent(COMPANY, runtimeAgent.id, 'tokenscale_runtime_signal', `tokenscale:${runId}`, {
        reasoning: `TokenScale runtime signal recorded for ${taskType}: bottleneck=${tokenScaleSignal.token_velocity.bottleneck_stage}, backpressure=${tokenScaleSignal.token_velocity.backpressure_state}.`,
        source_knowledge: 'TokenScale — token velocity as leading backpressure indicator',
        signal: tokenScaleSignal,
      }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
    } catch (tokenScaleErr) {
      console.warn('[tokenscale] runtime signal failed (non-fatal):', tokenScaleErr.message);
    }
    if (localInferencePlan) {
      logEvent(COMPANY, runtimeAgent.id, 'wave5_local_inference_signal', `wave5:${runId}`, {
        reasoning: `Wave 5 local inference signal recorded for ${taskType}: MoE=${localInferencePlan.moe_scheduling.status}, KV pressure=${localInferencePlan.kv_cache.kv_cache_estimate.free_memory_pressure_ratio}.`,
        source_knowledge: 'Wave 5 local inference papers — TurboQuant, DALI, DyMoE, HillInfer, PROBE, MoE-SpAc, Speculating Experts, ML memory, SSD graph indexing, Nexus, PIM-SHERPA, LPC-SM',
        signal: localInferencePlan,
      }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
    }
    let evolveRouterSignal = null;
    try {
      evolveRouterSignal = buildEvolveRouterRuntimeSignal({
        agentId: runtimeAgent.id,
        model: executedModel,
        taskType,
        confidence: finalConfidence,
        fallbackUsed,
        responseChars: String(response || '').length,
        promptChars,
        toolCallCount: scratToolReflections.length,
      });
      logEvent(COMPANY, runtimeAgent.id, 'evolverouter_runtime_signal', `evolverouter:${runId}`, {
        reasoning: `EvolveRouter runtime signal recorded for ${taskType}: quality_proxy=${evolveRouterSignal.route_quality_proxy}, priority=${evolveRouterSignal.refinement_priority.priority}.`,
        source_knowledge: 'EvolveRouter — Co-Evolving Routing and Prompt for Multi-Agent Question Answering',
        signal: evolveRouterSignal,
      }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
    } catch (evolveErr) {
      console.warn('[evolverouter] runtime signal failed (non-fatal):', evolveErr.message);
    }

    // ─── XAI + RAD-AI: persist explanation and architecture decision ─────────
    // (extracted to agent-xai-explanation.js — captureExplanationAndDecision)
    const xaiResult = await captureExplanationAndDecision({
      runtimeAgent,
      taskType,
      executedModel,
      finalConfidence,
      response,
      userPrompt,
      reasoningSignals,
      delegatedTo,
      rerouteCheck,
      fallbackUsed,
      securityDecisionEvidence: securityDecisionReceipt
        ? {
            eventId: securityDecisionReceipt.event_id,
            mutationHash: securityDecisionReceipt.mutation_hash,
            contentHash: securityDecisionReceipt.content_hash,
            signature: securityDecisionReceipt.signature,
          }
        : null,
      fastLane,
      options,
      allowedToolNames,
      promptChars,
      autonomy,
      taskRoute,
      runEndTime,
      successTraceEventId: _successTraceEvent,
      skipAimos: options.skipAimos
    });
    explanationArtifact = xaiResult.explanationArtifact;
    architectureDecision = xaiResult.architectureDecision;

    // ─── LIFELONG LEARNING: auto-deposit procedural skill (VOYAGER/L2M) ────
    if (taskType && taskType !== 'chat') {
      try {
        const skillName = `${runtimeAgent.id}_${taskType}_workflow`;
        await query(
          `INSERT INTO procedural_skills (company_id, agent_id, skill_name, steps, trigger_pattern, expected_outcome, success_count, fail_count, last_used)
           VALUES ($1, $2, $3, $4, $5, $6, 1, 0, NOW())
           ON CONFLICT (company_id, skill_name)
           DO UPDATE SET success_count = procedural_skills.success_count + 1, last_used = NOW(), updated_at = NOW()`,
          [COMPANY, runtimeAgent.id, skillName, JSON.stringify({
            taskType, model: executedModel, avgConfidence: finalConfidence,
            tools: allowedToolNames.slice(0, 10), lastRun: new Date().toISOString()
          }), taskType, `Successful ${taskType} run`]
        );
      } catch { /* skill deposit is best-effort */ }
    }

    // ─── OUTCOME TRACKING ────────────────────────────────────────────────────
    if (taskType && taskType !== 'chat' && response) {
      try {
        await recordRecommendation(runtimeAgent.id, String(response).slice(0, 2000), finalConfidence, taskType, {
          model: executedModel,
          prompt_snippet: String(userPrompt).slice(0, 150),
          tools_count: allowedToolNames.length,
          latency_ms: runEndTime - runStartTime
        });
      } catch { /* outcome tracking is best-effort */ }
    }

    // ─── SENGE #1: PERSONAL MASTERY — self-reflection after run ─────────
    try {
      await selfReflect(runtimeAgent.id);
    } catch { /* self-reflection is best-effort */ }

    // ─── AFTER-ACTION REVIEW ─────────────────────────────────────────────────
    if (!fastLane && response && response.length > 100) {
      try {
        await afterActionReview(runtimeAgent.id, {
          prompt: userPrompt,
          response: String(response).slice(0, 3000),
          taskType,
          confidence: finalConfidence,
          model: executedModel,
          latencyMs: runEndTime - runStartTime
        });
      } catch { /* AAR is best-effort */ }
    }

    // ─── Phase 7 wiring: learning + observe post-run hooks ─────────────────
    try { await runQualityLoop(String(response || '').slice(0, 500)); } catch (e) { console.warn('[agent-runner] batch reflection failed (non-fatal):', e.message?.slice(0, 80)); }
    try { await computeOverallConsistency([]); } catch (e) { console.warn('[agent-runner] cognitive consistency check failed (non-fatal):', e.message?.slice(0, 80)); }
    try { await reflectOnTrajectory([{ taskType, model: executedModel, confidence: finalConfidence }]); } catch (e) { console.warn('[agent-runner] reflection finetuner failed (non-fatal):', e.message?.slice(0, 80)); }
    try { await trackSessionEnergy(conversationSessionKey || `session_${runtimeAgent.id}_${runStartTime}`, 0); } catch (e) { console.warn('[agent-runner] energy tracking failed (non-fatal):', e.message?.slice(0, 80)); }
    try {
      await observeSemanticIntent({
        message: String(userPrompt).slice(0, 300),
        agentId: runtimeAgent.id,
        companyId: COMPANY,
        runId,
        taskType,
      });
    } catch (e) { console.warn('[agent-runner] semantic intent eval failed (non-fatal):', e.message?.slice(0, 80)); }
    if (delegatedTo) {
      try {
        await observeCoordinationAudit({
          companyId: COMPANY,
          agentId: runtimeAgent.id,
          runId,
          taskType,
          delegatedTo,
          sourceAgentId,
        });
      } catch (e) { console.warn('[agent-runner] coordination audit failed (non-fatal):', e.message?.slice(0, 80)); }
    }

    // ─── SYMBOLIC POST-CHECK: validate result against constraints ────────────
    try {
      if (!fastLane && metaDecision?.action) {
        const symCheck = await symbolicPostCheck(metaDecision.action, { response, confidence: finalConfidence, taskType });
        if (!symCheck.valid) {
          console.info(`[symbolic-reasoner] Post-check failed: ${symCheck.explanation}`);
        }
      }
    } catch { /* symbolic post-check is best-effort */ }

    // ─── MEMGPT: Update working context ─────────────────────────────────────
    if (!fastLane && !options.skipAimos && response && response.length > 100) {
      try {
        const factPatterns = [
          /(?:key fact|important|note|remember|update)[:\s]+([^.]{15,200})\./gi,
          /(?:decided|concluded|confirmed|learned)[:\s]+([^.]{15,200})\./gi
        ];
        const facts = [];
        for (const pat of factPatterns) {
          for (const m of String(response).matchAll(pat)) { if (m[1]) facts.push(m[1].trim()); }
          if (facts.length >= 5) break;
        }
        if (facts.length > 0) await updateWorkingContext(runtimeAgent.id, facts.join('\n'));
      } catch { /* best-effort */ }
    }

    // ─── CORTEX ENZYME: Extract knowledge from agent output back into brain ──
    // Every agent run is a neuron firing. The knowledge it produces strengthens
    // the whole network. This is how the brain grows through WORK, not just ingestion.
    if (!fastLane && !options.skipAimos && response && response.length > 200 && taskType !== 'chat') {
      try {
        // Extract key sentences that contain knowledge (not just conversation)
        const responseStr = String(response);
        const knowledgePatterns = [
          /(?:found that|discovered|identified|analysis shows|results indicate|key finding)[^.]{15,200}\./gi,
          /(?:the solution|the fix|the approach|the pattern|best practice)[^.]{15,200}\./gi,
          /(?:important|critical|essential|note that|be aware)[^.]{15,200}\./gi,
          /(?:learned|takeaway|insight|conclusion|recommendation)[^.]{15,200}\./gi,
        ];
        const extractions = [];
        for (const pat of knowledgePatterns) {
          const matches = responseStr.match(pat);
          if (matches) extractions.push(...matches.slice(0, 3));
        }

        if (extractions.length > 0) {
          const knowledgeValue = extractions.slice(0, 8).join('\n').slice(0, 3000);
          const knowledgeKey = `cortex:${runtimeAgent.id}:${taskType}:${Date.now()}`;
          // Quality gate is enforced inside persistMemory
          await persistMemory({
            company_id: COMPANY,
            agent_id: runtimeAgent.id,
            key: knowledgeKey,
            value: knowledgeValue,
            scope: 'system',
            memory_type: 'tacit_knowledge',
            clearance_level: 5,
            source: 'agent-runner',
            mutation_authority: 'housekeeper',
          });
        }
      } catch { /* cortex extraction is best-effort */ }
    }

    // ─── TEAM LEARNING: low-confidence success = soft failure for others ─────
    if (taskType && taskType !== 'chat' && finalConfidence < 0.5 && response) {
      try {
        await persistMemory({
          company_id: COMPANY,
          agent_id: runtimeAgent.id,
          key: `soft_fail:${runtimeAgent.id}:${taskType}:${Date.now()}`,
          value: JSON.stringify({
            agent: runtimeAgent.id,
            task_type: taskType,
            error: `Low confidence run: ${finalConfidence.toFixed(2)}`,
            prompt_hint: String(userPrompt).slice(0, 100),
            model: executedModel,
            type: 'low_confidence',
            timestamp: new Date().toISOString()
          }),
          scope: 'system',
          memory_type: 'shared_failure',
          clearance_level: 3,
          source: 'agent-runner',
          mutation_authority: 'housekeeper',
        });
      } catch { /* soft failure tracking is best-effort */ }
    }

    // ─── STRUCTURED MESSAGING: notify on delegation or escalation ─────────
    if (delegatedTo) {
      try {
        await sendAgentMessage(sourceAgentId, delegatedTo, {
          type: 'delegation',
          taskType,
          promptSnippet: String(userPrompt).slice(0, 150),
          confidence: finalConfidence
        }, { messageType: 'directive' });
      } catch { /* messaging is best-effort */ }
      // Phase 4: Wire DIG auto-healing into delegation delivery
      try {
        if (options._digGraphId) {
          await deliverAndChain(
            options._digGraphId,
            options._digActivationId || null,
            'delegation',
            JSON.stringify({ taskType, promptSnippet: String(userPrompt).slice(0, 150), confidence: finalConfidence }),
            delegatedTo
          );
        }
      } catch { /* DIG delivery is best-effort */ }
    }
    if (autonomy.action === 'escalate') {
      try {
        await sendAgentMessage(runtimeAgent.id, getOperatorAgentId(), {
          type: 'escalation',
          reason: `Low confidence ${finalConfidence.toFixed(2)} on ${taskType}`,
          promptSnippet: String(userPrompt).slice(0, 150)
        }, { messageType: 'escalation' });
      } catch { /* messaging is best-effort */ }
      // Phase 4: Wire DIG auto-healing into escalation delivery
      try {
        if (options._digGraphId) {
          await deliverAndChain(
            options._digGraphId,
            options._digActivationId || null,
            'escalation',
            JSON.stringify({ reason: `Low confidence ${finalConfidence.toFixed(2)} on ${taskType}`, promptSnippet: String(userPrompt).slice(0, 150) }),
            getOperatorAgentId()
          );
        }
      } catch { /* DIG delivery is best-effort */ }
    }

    // ─── Feature 5: Per-Action Trust Gates — log trust levels for tools used ──
    let trustGateNote = null;
    if (!fastLane && allowedToolNames.length > 0) {
      try {
        const { getAgentHealthScore } = await import('./agent-learning.js');
        const health = await getAgentHealthScore(runtimeAgent.id);
        const lowTrustTools = allowedToolNames
          .map(t => ({ tool: t, trust: computeToolTrustScore(runtimeAgent.id, t, finalConfidence, health.healthScore) }))
          .filter(t => evaluateToolTrust(t.trust) === 'block');
        if (lowTrustTools.length > 0) {
          trustGateNote = `[TRUST-GATE] Blocked tools: ${lowTrustTools.map(t => `${t.tool}(${t.trust})`).join(', ')}`;
          console.warn(`[trust-gate] Agent ${runtimeAgent.id}: ${trustGateNote}`);
          logEvent('hom', runtimeAgent.id, 'trust_gate_block', `trust_block:${runtimeAgent.id}`, {
            reasoning: `Trust gate blocked ${lowTrustTools.length} tool(s): ${lowTrustTools.map(t => `${t.tool}(score=${t.trust})`).join(', ')}. Trust score = (1 - toolRisk) * 0.4 + healthNorm * 0.3 + confidenceNorm * 0.3. Score below 0.3 = block. Agent health=${health.healthScore}, confidence=${finalConfidence.toFixed(2)}. High-risk tools with low agent health/confidence are too dangerous to execute.`,
            source_knowledge: 'agent-runner.js TOOL_RISK_LEVELS map + computeToolTrustScore formula (Feature 5)',
            blocked_tools: lowTrustTools
          }).catch(e => console.warn('[logEvent] best-effort failed', e?.message));
        }
      } catch { /* trust gate logging is best-effort */ }
    }

    // ─── WORKSPACE PARTITIONS: finalize B_ans with deliverable ──────────────
    if (workspace) {
      try {
        setPartition(workspace, 'B_ans', {
          response: String(response || '').slice(0, 3000),
          confidence: finalConfidence,
          model: executedModel,
          completedAt: new Date().toISOString()
        });
        setPartition(workspace, 'B_sys', {
          phase: 'complete',
          latencyMs: Date.now() - runStartTime,
          autonomyLevel: autonomy.level
        });
        const serialized = serializeWorkspace(workspace);
        if (serialized.length < 50000) {
          console.info(`[workspace-partitions] Run ${runId} workspace finalized (${serialized.length} chars)`);
        }
      } catch (wpErr) {
        console.warn('[workspace-partitions] finalize failed:', wpErr.message);
      }
    }

    // ─── CHAINING: Detect continuation signal and auto-chain if warranted ────
    const chainDepth = Math.max(0, Number(options._chainDepth || 0));
    let chainResult = null;
    if (!fastLane && !options.skipChaining && chainDepth < MAX_CHAIN_DEPTH) {
      const continuation = detectContinuationSignal(response, mergedIntentions, finalConfidence);
      if (continuation) {
        console.info(`[agent-runner:chain] Chaining run for ${runtimeAgent.id} (depth ${chainDepth + 1}/${MAX_CHAIN_DEPTH}), source: ${continuation.source}`);
        try {
          chainResult = await runAgent(runtimeAgent.id, continuation.prompt, {
            ...options,
            depth: depth + 1,
            _chainDepth: chainDepth + 1,
            _chainSource: continuation.source,
            sessionKey: conversationSessionKey,
            parentRunId: runId
          });
        } catch (chainErr) {
          console.warn(`[agent-runner:chain] Chain run failed: ${chainErr.message}`);
        }
      }
    }

    const modelRequested = options.requestedModel
      || options.preferredModel
      || modelPreference.model
      || resolution.requestedModel
      || runtimeAgent.model;
    const benchmarkTrace = buildAgentBenchmarkTrace({
      runId,
      taskType,
      modelRequested,
      modelResolved: executedModel,
      latencyMs: runEndTime - runStartTime,
      confidence: finalConfidence,
      promptChars,
      responseChars: String(response || '').length,
      toolCount: allowedToolNames.length,
      fallbackUsed,
      rerouted: !!rerouteCheck?.reroute,
      metaAction: metaDecision?.action || null,
      scratReflectionCount: scratToolReflections.length,
    });

    const runOutput = {
      agentId: runtimeAgent.id,
      sourceAgentId,
      agentName: runtimeAgent.name,
      persona: runtimeAgent.persona,
      personaVersion: Number(resolution.personaVersion || runtimeAgent.personaVersion || 1),
      model: executedModel,
      taskTypeResolved: modelPreference.taskType,
      modelAllocationDiagnostics: modelAllocationDiagnostics || null,
      modelRequested,
      modelResolved: executedModel,
      fallbackUsed,
      securityDecisionEvidence: securityDecisionReceipt
        ? {
            eventId: securityDecisionReceipt.event_id,
            mutationHash: securityDecisionReceipt.mutation_hash,
            contentHash: securityDecisionReceipt.content_hash,
            signature: securityDecisionReceipt.signature,
          }
        : null,
      toolProtocolGuard: toolProtocolGuard?.guarded
        ? {
            status: 'guarded',
            reason: toolProtocolGuard.reason,
            rawProtocolExposed: false,
            toolExecuted: false
          }
        : null,
      promptChars,
      responseChars: String(response || '').length,
      contextCompaction: aimosContextPack.contextCompaction,
      promptPressure,
      confidence: finalConfidence,
      autonomyLevel: autonomy.level,
      autonomyAction: autonomy.action,
      taskRoute: taskRoute ? { frameworks: taskRoute.frameworks, threshold: taskRoute.confidence_threshold } : null,
      metaController: metaDecision
        ? {
            action: metaDecision.action,
            speed: metaDecision.speed,
            executionMode: metaDecision.executionMode || metaDecision.speculativeExecution?.execution_mode || 'closed_loop',
            speculativeExecution: metaDecision.speculativeExecution || null,
            controllerDiagnostics: metaDecision.controllerDiagnostics || null
          }
        : null,
      benchmarkTrace,
      psychometrics: psychometricProfile
        ? {
            status: psychometricProfile.status,
            sourcePaper: psychometricProfile.source_paper,
            prediction: psychometricProfile.psychometric_model?.prediction || null,
            driftTriggered: psychometricProfile.behavioral_profile?.drift_triggered === true,
            anomalyScore: psychometricProfile.behavioral_profile?.anomaly_score ?? null,
            guardedMath: psychometricProfile.guarded_math || null
          }
        : null,
      turnAdaptiveBudget: turnBudgetPlan
        ? {
            status: turnBudgetPlan.status,
            selectedBudgetTokens: turnBudgetPlan.selected_budget_tokens,
            difficultyLevel: turnBudgetPlan.turn_difficulty?.difficulty_level ?? null,
            routeHint: turnBudgetPlan.route_hint,
            guardedMath: turnBudgetPlan.guarded_math
          }
        : null,
      latentLookahead: latentLookaheadPlan
        ? {
            status: latentLookaheadPlan.status,
            sourcePaper: latentLookaheadPlan.source_paper,
            latentHorizonTau: latentLookaheadPlan.latent_horizon_tau,
            thinkingPositions: latentLookaheadPlan.thinking_positions,
            prefetchQueries: latentLookaheadPlan.prefetch_queries,
            guardedMath: latentLookaheadPlan.guarded_math
          }
        : null,
      keyedPrefetch: keyedPrefetchPlan
        ? {
            status: keyedPrefetchPlan.status,
            sourcePaper: keyedPrefetchPlan.source_paper,
            hintCount: keyedPrefetchPlan.prefetch_hints.length,
            cacheScope: keyedPrefetchPlan.data_path.cache_scope,
            aimosMemoryMutated: keyedPrefetchPlan.data_path.aimos_memory_mutated,
            guardedMath: keyedPrefetchPlan.guarded_math
          }
        : null,
      tokenScale: tokenScaleSignal
        ? {
            status: tokenScaleSignal.status,
            sourcePaper: tokenScaleSignal.source_paper,
            bottleneckStage: tokenScaleSignal.token_velocity?.bottleneck_stage || null,
            backpressureState: tokenScaleSignal.token_velocity?.backpressure_state || null,
            tpotMs: tokenScaleSignal.cadence?.tpot_ms ?? null,
            degraded: tokenScaleSignal.cadence?.degraded === true,
            guardedMath: tokenScaleSignal.token_velocity?.guarded_math || null
          }
        : null,
      robustLengthPrediction: robustLengthPrediction
        ? {
            status: robustLengthPrediction.status,
            sourcePaper: robustLengthPrediction.source_paper,
            predictionTokens: robustLengthPrediction.prediction_tokens,
            targetFunctional: robustLengthPrediction.target_functional,
            heuristicUsed: robustLengthPrediction.evidence?.heuristic_used === true,
            guardedMath: robustLengthPrediction.guarded_math
          }
        : null,
      agsc: agscOutputContract
        ? {
            status: agscOutputContract.status,
            sourcePaper: agscOutputContract.source_paper,
            preferredShape: agscOutputContract.output_contract.preferred_shape,
            unitCount: agscOutputContract.units.length,
            clusterWeights: agscOutputContract.semantic_clusters.cluster_weights,
            guardedMath: agscOutputContract.guarded_math
          }
        : null,
      localInference: localInferencePlan
        ? {
            status: localInferencePlan.status,
            nativeServerOnly: localInferencePlan.native_server_only,
            proxyLayerIntroduced: localInferencePlan.proxy_layer_introduced,
            hostPosture: localInferencePlan.host.aimos_local_posture,
            quantizationStatus: localInferencePlan.quantization.status,
            moeStatus: localInferencePlan.moe_scheduling.status,
            kvPressureRatio: localInferencePlan.kv_cache.kv_cache_estimate.free_memory_pressure_ratio,
            memoryPlacementStatus: localInferencePlan.memory_placement.status,
            smallModelStatus: localInferencePlan.small_model_efficiency.status,
            guardedRoutingMath: localInferencePlan.moe_scheduling?.guarded_routing_math || null,
            inactiveAdapterContracts: localInferencePlan.inactive_adapter_contracts || null,
            guardedMath: localInferencePlan.guarded_math
          }
        : null,
      evolveRouter: evolveRouterSignal
        ? {
            status: evolveRouterSignal.status,
            sourcePaper: evolveRouterSignal.source_paper,
            routeQualityProxy: evolveRouterSignal.route_quality_proxy,
            refinementPriority: evolveRouterSignal.refinement_priority?.priority ?? null,
            guardedMath: evolveRouterSignal.guarded_math
          }
        : null,
      epistemicBlinding: epistemicBlindingGate
        ? {
            status: epistemicBlindingGate.status,
            sourcePaper: epistemicBlindingGate.source_paper,
            shouldBlind: epistemicBlindingGate.should_blind,
            entityCount: epistemicBlindingGate.entity_count,
            auditContract: epistemicBlindingGate.audit_contract,
            guardedMath: epistemicBlindingGate.guarded_math
          }
        : null,
      response,
      delegatedTo,
      explanation: explanationArtifact
        ? {
            id: explanationArtifact.explanation_id,
            summary: explanationArtifact.user_summary,
            technical: explanationArtifact.technical_summary
          }
        : null,
      architectureDecision: architectureDecision?.logged
        ? {
            decisionId: architectureDecision.decisionId,
            key: architectureDecision.key
          }
        : null,
      rerouteNote: rerouteNote || null,
      investigation: investigationLoopResult
        ? {
            taskId: investigationLoopResult.taskId,
            iterations: investigationLoopResult.iterations,
            findings: investigationLoopResult.findings.map((entry) => ({
              technique: entry.technique,
              status: entry.status,
              summary: compactEvidenceText(entry.finding || '', 180)
            }))
          }
        : null,
      scrat: scratToolReflections.length > 0
        ? {
            reflectionCount: scratToolReflections.length,
            statuses: scratToolReflections.map((entry) => ({
              tool: entry.tool_name,
              status: entry.status,
              leakageRisk: entry.observer_model?.leakage_risk || null,
              delayedVerifierNeeded: entry.verification_burden?.delayed_verifier_needed === true
            })),
            guardedMath: scratToolReflections[0]?.guarded_math || null
          }
        : null,
      reviewerNote: [
        reviewerNote,
        toolProtocolGuard?.guarded ? '[TOOL-PROTOCOL-GUARD] Raw tool protocol withheld; no tool was executed.' : null,
        autonomyNote,
        socialLawNote,
        rerouteNote,
        trustGateNote,
        constitutionCheck.blocked ? constitutionCheck.message : null
      ].filter(Boolean).join('\n') || null
    };

    // Attach chain result if a follow-up run was executed
    if (chainResult) {
      runOutput.chainedRun = {
        depth: chainDepth + 1,
        source: options._chainSource || 'initial',
        agentId: chainResult.agentId,
        confidence: chainResult.confidence,
        response: chainResult.response
      };
      // Append chained response to the primary response for the caller
      runOutput.response = `${runOutput.response}\n\n---\n[Chained follow-up (${chainResult.agentId})]\n${chainResult.response}`;
    }

    return runOutput;
  } catch (err) {
    // ─── ESCALATION RESOLVER: 3-tier failure-triggered escalation ──────────
    try {
      const failureInfo = {
        type: err?.code === 'KNOWLEDGE_ACQUISITION_REQUIRED' ? 'no_results'
            : err?.code === 'SEMANTIC_SECURITY_BLOCKED' ? 'parse_error'
            : 'timeout',
        confidence: 0,
        error: err?.message || String(err)
      };
      const escalation = await resolveEscalation(
        String(userPrompt).slice(0, 1000),
        null,
        failureInfo,
        COMPANY
      );
      if (escalation.escalated) {
        console.info(`[escalation-resolver] Escalated to tier '${escalation.tier}' for ${runtimeAgent.id}: ${JSON.stringify(escalation.diagnostics).slice(0, 300)}`);
      }
      if (workspace) {
        setPartition(workspace, 'B_sys', {
          escalation: { tier: escalation.tier, escalated: escalation.escalated }
        });
      }
    } catch (esErr) {
      console.warn('[escalation-resolver] failed:', esErr.message);
    }

    // Self-correction protocol.
    const runEndTime = Date.now();
    try {
      await recordAgentRun(runtimeAgent.id, {
        success: false,
        confidence: 0,
        errorCount: 1,
        latencyMs: runEndTime - runStartTime,
        tokenEstimate: String(userPrompt || '').length,
        error: err?.message || String(err),
        taskType: options.taskType || options.intent || 'unknown',
        model: runtimeAgent.model
      });
      await logEvent(
        'hom',
        runtimeAgent.id,
        'correction',
        `correction:${runtimeAgent.id}:${Date.now()}`,
        {
          agent_id: runtimeAgent.id,
          error: err?.message || String(err),
          prompt_snippet: String(userPrompt).slice(0, 150),
          task_type: options.taskType || options.intent || 'unknown',
          correction_type: 'auto_error',
          timestamp: new Date().toISOString()
        }
      );
    } catch { /* correction logging is best-effort */ }

    // ─── MANDATORY EVENT LOG: every agent error persisted to Aimos event_log
    const _errorTraceEvent = await logMandatoryRunEvent(runtimeAgent.id, {
      success: false,
      model: runtimeAgent.model,
      taskType: options.taskType || options.intent || 'unknown',
      confidence: 0,
      latencyMs: runEndTime - runStartTime,
      error: err?.message,
      promptSnippet: String(userPrompt).slice(0, 120),
      parentEventId: options._parentEventId || null
    });

    // ─── LIFELONG LEARNING: record failure for skill tracking ───────────────
    const failTaskType = options.taskType || options.intent || 'unknown';
    if (failTaskType && failTaskType !== 'chat') {
      try {
        const skillName = `${runtimeAgent.id}_${failTaskType}_workflow`;
        await query(
          `INSERT INTO procedural_skills (company_id, agent_id, skill_name, steps, trigger_pattern, expected_outcome, success_count, fail_count, last_used)
           VALUES ($1, $2, $3, $4, $5, $6, 0, 1, NOW())
           ON CONFLICT (company_id, skill_name)
           DO UPDATE SET fail_count = procedural_skills.fail_count + 1, last_used = NOW(), updated_at = NOW()`,
          [COMPANY, runtimeAgent.id, skillName, JSON.stringify({ taskType: failTaskType, error: err?.message, lastFail: new Date().toISOString() }), failTaskType, `Failed ${failTaskType} run`]
        );
      } catch { /* skill fail tracking is best-effort */ }
    }

    // ─── STRUCTURED MESSAGING: escalate failures to executive lane ─────────
    if (!isOperatorAgentId(runtimeAgent.id)) {
      try {
        await sendAgentMessage(runtimeAgent.id, getOperatorAgentId(), {
          type: 'failure_report',
          error: err?.message || String(err),
          taskType: failTaskType,
          promptSnippet: String(userPrompt).slice(0, 150)
        }, { messageType: 'report' });
      } catch { /* messaging is best-effort */ }
      // Phase 4: Wire DIG auto-healing into failure escalation delivery
      try {
        if (options._digGraphId) {
          await deliverAndChain(
            options._digGraphId,
            options._digActivationId || null,
            'failure_report',
            JSON.stringify({ error: err?.message || String(err), taskType: failTaskType, promptSnippet: String(userPrompt).slice(0, 150) }),
            getOperatorAgentId()
          );
        }
      } catch { /* DIG delivery is best-effort */ }
    }

    // ─── SENGE #3: TEAM LEARNING — save failure for cross-agent learning ──
    try {
      await persistMemory({
        company_id: COMPANY,
        agent_id: runtimeAgent.id,
        key: `failure:${runtimeAgent.id}:${failTaskType}:${Date.now()}`,
        value: JSON.stringify({
          agent: runtimeAgent.id,
          task_type: failTaskType,
          error: (err?.message || String(err)).slice(0, 300),
          prompt_hint: String(userPrompt).slice(0, 100),
          timestamp: new Date().toISOString()
        }),
        scope: 'system',
        memory_type: 'shared_failure',
        clearance_level: 3,
        source: 'agent-runner',
        mutation_authority: 'housekeeper',
      });
    } catch { /* team learning write is best-effort */ }

    // ─── Phase 7 wiring: error-path learning hooks ──────────────────────────
    // Error normalization runs on real failure clusters in nightly dream Stage 6.
    if (options.humanFeedback) {
      try { await inversePTCorrection(options.humanFeedback, 0); } catch (e) { console.warn('[agent-runner] prospect theory correction failed (non-fatal):', e.message?.slice(0, 80)); }
    }

    persistedAgent.isActive = false;
    agents.set(agentId, persistedAgent);
    throw err;
  }
}

export async function runAgentStream(agentId, userPrompt, options = {}) {
  let streamed = '';
  const consumer = typeof options.onToken === 'function' ? options.onToken : null;

  const result = await runAgent(agentId, userPrompt, {
    ...options,
    onToken: (chunk) => {
      const token = String(chunk || '');
      if (!token) return;
      streamed += token;
      if (consumer) consumer(token);
    }
  });

  const finalResponse = String(result?.response || '');
  if (!streamed) {
    streamed = finalResponse;
    if (consumer && streamed) await emitTextChunks(streamed, consumer);
  } else if (finalResponse.length > streamed.length && finalResponse.startsWith(streamed)) {
    const tail = finalResponse.slice(streamed.length);
    streamed = finalResponse;
    if (consumer && tail) await emitTextChunks(tail, consumer);
  } else if (finalResponse && !finalResponse.startsWith(streamed)) {
    streamed = finalResponse;
  }

  return {
    ...result,
    response: streamed
  };
}
