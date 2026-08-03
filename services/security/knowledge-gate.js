/**
 * knowledge-gate.js — Evidence-based action authorization
 * Source: ContextCov (2026), NIST 800-207 Zero Trust
 *
 * This module restores the orchestration contract while preserving the
 * ContextCov-facing exports that other internal tooling expects.
 */

import { existsSync, readFileSync } from 'fs';
import { createHash } from 'crypto';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';
import { detectRefusal, shouldRetryWithoutAuth, classifyTaskCategory } from './refusal-detector.js';
import {
  ENFORCEMENT_DOMAINS,
  parseMarkdownAST,
  sliceConstraints
} from '../core/constitution-enforcer.js';

const KNOWLEDGE_ACQUISITION_TOOLS = Object.freeze({
  aimos_recall: 'aimos_memory',
  web_search: 'web_research',
  x_search: 'social_research',
  read_file: 'codebase_read',
  drive_read: 'document_read',
  docs_read: 'document_read',
  sheets_read: 'document_read',
  youtube_search: 'video_research',
  youtube_transcribe: 'video_research',
  gmail_inbox: 'inbox_context',
  gmail_search: 'inbox_context',
  calendar_today: 'calendar_context',
  calendar_events: 'calendar_context',
  github_list_repos: 'repo_context',
  github_search_issues: 'repo_context',
  stripe_account_summary: 'billing_context',
  stripe_list_customers: 'billing_context',
  stripe_list_subscriptions: 'billing_context',
  stripe_list_payment_intents: 'billing_context',
  salesforce_list_objects: 'crm_context',
  contacts_search: 'contact_context'
});

const HIGH_IMPACT_ACTION_TOOLS = Object.freeze({
  write_file: 'code_write',
  gmail_send: 'outbound_send',
  imessage_send: 'outbound_send',
  calendar_create: 'calendar_write',
  schedule_task: 'automation_schedule',
  x_post: 'public_post',
  x_reply: 'public_post',
  x_quote: 'public_post',
  aimos_save: 'memory_write'
});

const KNOWLEDGE_REQUIRED_INTENTS = new Set([
  'research',
  'analysis',
  'verification',
  'deploy',
  'security',
  'architecture',
  'governance'
]);

const KNOWLEDGE_REQUIRED_PATTERNS = [
  /\blatest\b/i,
  /\bcurrent\b/i,
  /\btoday\b/i,
  /\bresearch\b/i,
  /\binvestigate\b/i,
  /\bverify\b/i,
  /\bverification\b/i,
  /\blook up\b/i,
  /\bcheck\b/i,
  /\bcompare\b/i,
  /\banaly[sz]e\b/i,
  /\bfind out\b/i
];

const PROCESS_HINTS = /\b(run|build|test|deploy|pnpm|npm|yarn|shell|command|pm2|cron|scheduler|boot|restart)\b/i;
const SOURCE_HINTS = /\b(style|lint|format|syntax|typescript|javascript|async|await|promise|tree-sitter|naming)\b/i;
const ARCH_DET_HINTS = /\b(import|dependency|dependencies|module|layer|table|schema|route|service|graph|connection|edge|networkx)\b/i;
const ARCH_SEM_HINTS = /\b(architecture|semantic|meaning|intent|coverage|boundary|role|invariant|constraint)\b/i;
const HIGH_IMPACT_INTENT_PATTERNS = /\b(save|write|modify|delete|deploy|restart|publish|post|schedule|send|migrate|promote)\b/i;

function normalizeText(value = '') {
  return String(value || '').trim();
}

function normalizeIntent(value = '') {
  return normalizeText(value).toLowerCase();
}

function toolResultSucceeded(result, error = null) {
  if (error) return false;
  if (result == null) return true;
  if (typeof result !== 'object') return true;
  if (result.blocked || result.requiresApproval) return false;
  if (Object.prototype.hasOwnProperty.call(result, 'success')) {
    return result.success !== false && !result.error;
  }
  if (result.error) return false;
  return true;
}

function buildEvidenceLabel(toolName = '', evidenceType = '') {
  return `${toolName}:${evidenceType}`;
}

function summarizeKnowledgeEvidence(state) {
  if (!state || !Array.isArray(state.knowledgeEvidence) || state.knowledgeEvidence.length === 0) {
    return 'none';
  }
  return state.knowledgeEvidence
    .map((entry) => buildEvidenceLabel(entry.toolName, entry.evidenceType))
    .join(', ');
}

function promptNeedsKnowledge(state) {
  if (!state) return false;
  if (KNOWLEDGE_REQUIRED_INTENTS.has(state.intent) || KNOWLEDGE_REQUIRED_INTENTS.has(state.taskType)) {
    return true;
  }
  const combined = `${state.prompt} ${state.intent} ${state.taskType}`;
  return KNOWLEDGE_REQUIRED_PATTERNS.some((pattern) => pattern.test(combined));
}

function routeIntentToDomain(text = '') {
  const normalized = normalizeText(text);
  if (!normalized) return ENFORCEMENT_DOMAINS.ARCH_SEM;
  if (PROCESS_HINTS.test(normalized)) return ENFORCEMENT_DOMAINS.PROCESS;
  if (SOURCE_HINTS.test(normalized)) return ENFORCEMENT_DOMAINS.SOURCE;
  if (ARCH_DET_HINTS.test(normalized)) return ENFORCEMENT_DOMAINS.ARCH_DET;
  if (ARCH_SEM_HINTS.test(normalized)) return ENFORCEMENT_DOMAINS.ARCH_SEM;
  return ENFORCEMENT_DOMAINS.ARCH_SEM;
}

function tokenize(text = '') {
  return new Set(
    normalizeText(text)
      .toLowerCase()
      .split(/[^a-z0-9_./-]+/)
      .filter((token) => token.length >= 3)
  );
}

function detectSemanticDrift(subject = '', constraints = []) {
  const subjectTokens = tokenize(subject);
  if (!subjectTokens.size || !Array.isArray(constraints) || constraints.length === 0) {
    return { drift: false, score: 1, matched: 0, total: 0 };
  }

  let matched = 0;
  for (const constraint of constraints) {
    const constraintText = typeof constraint === 'string' ? constraint : constraint?.constraint || '';
    const constraintTokens = tokenize(constraintText);
    const hasOverlap = [...constraintTokens].some((token) => subjectTokens.has(token));
    if (hasOverlap) matched += 1;
  }

  const score = matched / constraints.length;
  return {
    drift: score < 0.35,
    score,
    matched,
    total: constraints.length
  };
}

function isHighImpactIntent(text = '') {
  return HIGH_IMPACT_INTENT_PATTERNS.test(normalizeText(text));
}

async function generateAndPersistProof(state) {
  if (!state?.knowledgeEvidence?.length) return null;

  const sessionId = normalizeText(state.sessionId) || 'active_session';
  const lastMemoryId = normalizeText(state.lastRecalledMemoryId) || 'initial_boot';
  const rotatingNonce = Math.floor(Date.now() / (30 * 60 * 1000)).toString();

  const proofHash = createHash('sha256')
    .update(`${sessionId}:${lastMemoryId}:${rotatingNonce}`)
    .digest('hex');

  // Make the proof usable immediately inside this process, even if persistence
  // fails and we need to fall back to the in-memory value for the current run.
  state.currentProof = proofHash;

  await query(
    `INSERT INTO security.active_proofs (proof_hash, session_id, nonce, created_at, expires_at)
     VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '30 minutes')
     ON CONFLICT (proof_hash) DO UPDATE
       SET expires_at = NOW() + INTERVAL '30 minutes'`,
    [proofHash, sessionId, rotatingNonce]
  );

  return proofHash;
}

export function createKnowledgeGateState({
  agentId = '',
  prompt = '',
  intent = '',
  taskType = '',
  sessionId = ''
} = {}) {
  const normalizedPrompt = normalizeText(prompt);
  const normalizedIntent = normalizeIntent(intent);
  const normalizedTaskType = normalizeIntent(taskType);

  return {
    agentId: normalizeText(agentId),
    prompt: normalizedPrompt,
    intent: normalizedIntent,
    taskType: normalizedTaskType,
    sessionId: normalizeText(sessionId),
    contextDomain: routeIntentToDomain(`${normalizedIntent} ${normalizedTaskType} ${normalizedPrompt}`),
    toolEvents: [],
    knowledgeEvidence: [],
    highImpactActions: [],
    lastRecalledMemoryId: null,
    currentProof: null
  };
}

export function recordKnowledgeToolEvent(state, event = {}) {
  if (!state || typeof state !== 'object') return state;

  const toolName = normalizeIntent(event.toolName || event.tool || '');
  if (!toolName) return state;

  const succeeded = toolResultSucceeded(event.result, event.error);
  const blocked = Boolean(event.blocked || event.result?.blocked);
  const requiresApproval = Boolean(event.result?.requiresApproval);
  state.toolEvents.push({
    toolName,
    succeeded,
    blocked,
    requiresApproval,
    at: new Date().toISOString()
  });

  if (succeeded && KNOWLEDGE_ACQUISITION_TOOLS[toolName]) {
    const evidenceType = KNOWLEDGE_ACQUISITION_TOOLS[toolName];

    if (toolName === 'aimos_recall') {
      const rows = Array.isArray(event.result?.items)
        ? event.result.items
        : Array.isArray(event.result)
          ? event.result
          : [];
      state.lastRecalledMemoryId = rows[0]?.id || rows[0]?.key || state.lastRecalledMemoryId;
    }

    const exists = state.knowledgeEvidence.some(
      (entry) => entry.toolName === toolName && entry.evidenceType === evidenceType
    );
    if (!exists) {
      state.knowledgeEvidence.push({ toolName, evidenceType });
      generateAndPersistProof(state).catch((err) => {
        console.warn('[knowledge-gate] failed to persist proof:', err.message);
      });
    }
  }

  if (succeeded && HIGH_IMPACT_ACTION_TOOLS[toolName]) {
    const actionType = HIGH_IMPACT_ACTION_TOOLS[toolName];
    if (!state.highImpactActions.some((entry) => entry.toolName === toolName)) {
      state.highImpactActions.push({ toolName, actionType });
    }
  }

  return state;
}

export function getProofForSession(state) {
  return state?.currentProof || null;
}

export function shouldBlockToolForMissingKnowledge(state, toolName = '') {
  const normalizedTool = normalizeIntent(toolName);
  const actionType = HIGH_IMPACT_ACTION_TOOLS[normalizedTool];
  if (!actionType) {
    return { blocked: false };
  }

  const evidenceCount = state?.knowledgeEvidence?.length || 0;
  if (evidenceCount > 0) {
    return { blocked: false };
  }

  const blockResult = {
    blocked: true,
    phase: 'tool',
    tool: normalizedTool,
    actionType,
    code: 'KNOWLEDGE_ACQUISITION_REQUIRED',
    knowledgeEvidenceCount: evidenceCount,
    evidenceSummary: summarizeKnowledgeEvidence(state),
    message: `Knowledge gate blocked '${normalizedTool}': acquire context first via recall/search/read before attempting ${actionType}.`
  };

  logEvent('hom', state?.agentId || 'system', 'security_detection', 'knowledge-gate:tool_blocked', {
    reasoning: `Security event: Knowledge gate blocked tool '${normalizedTool}' — no knowledge evidence acquired before high-impact action ${actionType}`,
    severity: 'high',
    details: { tool: normalizedTool, actionType, evidenceCount }
  }).catch(() => {});

  return blockResult;
}

export function shouldBlockCompletionForMissingKnowledge(state) {
  const reasons = [];

  if (promptNeedsKnowledge(state)) {
    reasons.push('knowledge_required_prompt');
  }

  if (Array.isArray(state?.highImpactActions) && state.highImpactActions.length > 0) {
    reasons.push(
      `high_impact_actions:${state.highImpactActions.map((entry) => entry.toolName).join(',')}`
    );
  }

  if (reasons.length === 0) {
    return {
      blocked: false,
      required: false,
      knowledgeEvidenceCount: state?.knowledgeEvidence?.length || 0,
      evidenceSummary: summarizeKnowledgeEvidence(state)
    };
  }

  const evidenceCount = state?.knowledgeEvidence?.length || 0;
  if (evidenceCount > 0) {
    return {
      blocked: false,
      required: true,
      reasons,
      knowledgeEvidenceCount: evidenceCount,
      evidenceSummary: summarizeKnowledgeEvidence(state)
    };
  }

  const completionBlock = {
    blocked: true,
    required: true,
    phase: 'completion',
    code: 'KNOWLEDGE_ACQUISITION_REQUIRED',
    reasons,
    knowledgeEvidenceCount: evidenceCount,
    evidenceSummary: summarizeKnowledgeEvidence(state),
    message: 'Knowledge gate blocked run completion: the run reached a knowledge-required or high-impact path without acquiring evidence via recall/search/read tools.'
  };

  logEvent('hom', state?.agentId || 'system', 'security_detection', 'knowledge-gate:completion_blocked', {
    reasoning: `Security event: Knowledge gate blocked completion — reasons: ${reasons.join(', ')}`,
    severity: 'high',
    details: { reasons, evidenceCount, agentId: state?.agentId }
  }).catch(() => {});

  return completionBlock;
}

export function formatKnowledgeGateReviewerNote(decision) {
  if (!decision || !decision.blocked) return null;
  const reasonText = Array.isArray(decision.reasons) && decision.reasons.length
    ? ` reasons=${decision.reasons.join('|')}`
    : '';
  return `[KNOWLEDGE-GATE] ${decision.message}${reasonText}`;
}

export async function evaluateWithRefusalMitigation(prompt, agentContext, llmCall) {
  const taskCategory = classifyTaskCategory(prompt);
  const result = await llmCall(prompt, agentContext);

  const refusal = detectRefusal(result.text || '');
  if (
    refusal.refused &&
    ['malware_analysis', 'vuln_assessment', 'incident_response', 'system_hardening'].includes(taskCategory)
  ) {
    const retry = shouldRetryWithoutAuth(result.text || '', prompt);
    if (retry.retry) {
      const retryResult = await llmCall(retry.strippedPrompt, agentContext);
      return { ...retryResult, refusal_mitigated: true, original_refusal: refusal.category };
    }
  }

  return result;
}

export function extractHierarchicalConstraints(input, targetPath = null) {
  let markdown = '';

  if (typeof input === 'string' && existsSync(input)) {
    markdown = readFileSync(input, 'utf-8');
  } else {
    markdown = normalizeText(input);
  }

  if (!markdown) return [];

  const ast = parseMarkdownAST(markdown);
  return sliceConstraints(ast, targetPath).map((constraint) => ({
    ...constraint,
    domain: routeIntentToDomain(constraint.constraint)
  }));
}

function normalizeGraphEdges(graph = {}) {
  if (Array.isArray(graph)) return graph;
  if (Array.isArray(graph.edges)) return graph.edges;
  return [];
}

export function validateArchitectureGraph(graph = {}, constraints = []) {
  const edges = normalizeGraphEdges(graph);
  const nodes = new Set();
  const adjacency = new Map();
  const violations = [];

  for (const edge of edges) {
    const from = normalizeText(edge?.from || edge?.source || '');
    const to = normalizeText(edge?.to || edge?.target || '');
    if (!from || !to) continue;

    nodes.add(from);
    nodes.add(to);
    if (!adjacency.has(from)) adjacency.set(from, new Set());
    adjacency.get(from).add(to);

    if (from === to) {
      violations.push({
        type: 'self_cycle',
        message: `Module '${from}' cannot depend on itself.`
      });
    }
  }

  const visiting = new Set();
  const visited = new Set();

  function walk(node, trail = []) {
    if (visiting.has(node)) {
      violations.push({
        type: 'cycle',
        message: `Cycle detected: ${[...trail, node].join(' -> ')}`
      });
      return;
    }
    if (visited.has(node)) return;

    visiting.add(node);
    const nextNodes = adjacency.get(node) || new Set();
    for (const next of nextNodes) {
      walk(next, [...trail, node]);
    }
    visiting.delete(node);
    visited.add(node);
  }

  for (const node of nodes) {
    walk(node);
  }

  const semantic = detectSemanticDrift(
    edges.map((edge) => `${edge?.from || edge?.source || ''} ${edge?.to || edge?.target || ''}`).join(' '),
    constraints
  );
  if (semantic.drift && constraints.length > 0) {
    violations.push({
      type: 'semantic_drift',
      message: `Architecture graph only matched ${semantic.matched}/${semantic.total} extracted constraints.`
    });
  }

  return {
    valid: violations.length === 0,
    nodeCount: nodes.size,
    edgeCount: edges.length,
    violations
  };
}

export function verifyContextualCoverage(input = {}) {
  const options = typeof input === 'string' ? { prompt: input } : (input || {});
  const prompt = normalizeText(options.prompt || options.intent || '');
  const evidence = Array.isArray(options.evidence) ? options.evidence : [];
  const constraints = Array.isArray(options.constraints)
    ? options.constraints
    : options.instructionFile
      ? extractHierarchicalConstraints(options.instructionFile, options.targetPath || null)
      : [];

  const domain = routeIntentToDomain(prompt);
  const semantic = detectSemanticDrift(prompt, constraints);
  const highImpact = isHighImpactIntent(prompt);
  const evidenceCount = evidence.length;
  const evidenceDomains = new Set(
    evidence.map((entry) => normalizeText(entry?.evidenceType || entry?.domain || '')).filter(Boolean)
  );

  const covered = semantic.drift === false || evidenceCount > 0;

  return {
    covered,
    domain,
    highImpact,
    evidenceCount,
    evidenceDomains: [...evidenceDomains],
    semanticDrift: semantic,
    constraintCount: constraints.length,
    requiresAdditionalContext: (!covered && highImpact) || (constraints.length > 0 && semantic.drift),
    summary: covered
      ? 'Context coverage acceptable.'
      : 'Context coverage weak relative to extracted constraints.'
  };
}

export { HIGH_IMPACT_ACTION_TOOLS, KNOWLEDGE_ACQUISITION_TOOLS };
