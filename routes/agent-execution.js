/**
 * agent-execution.js — core execution routes for agents.
 *
 * Mounts under the /agents prefix (via agents.js main router).
 * Routes: POST /:id/run, POST /:id/stream
 *
 * Contains: executeAgentRun(), all execution helpers (fast-lane, intelligence
 * pipeline, SSE helpers, lifecycle building, approval handling, briefing).
 */

import express from 'express';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { agents } from '../services/orchestration/agent-store.js';
import { runAgent, runAgentStream, extractConfidence } from '../services/orchestration/agent-runner.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { providerStatus } from '../services/core/providers.js';
import { resolveExecutionContext } from '../services/orchestration/governance-resolver.js';
import { withSessionLane } from '../services/orchestration/session-runner.js';
import {
  getIdempotentResponse,
  saveIdempotentResponse,
  markRunStarted,
  markRunCompleted,
  markRunAwaitingApproval,
  markRunFailed
} from '../services/orchestration/run-metadata.js';
import { publishRunEvent } from '../services/orchestration/run-events.js';
import { selectTokenScaleChunkSize } from '../services/runtime/serving-control.js';
import { claimDirective, completeDirectiveClaim } from '../services/core/directive-claims.js';
import {
  COMPANY,
  INTELLIGENCE_ARTIFACT_DIR,
  INTELLIGENCE_KEYWORDS,
  X_INTENT_MARKERS,
  FAST_LANE_MODEL,
  FAST_LANE_MAX_CHARS,
  FAST_LANE_TOOL_INTENT_KEYWORDS,
  FAST_LANE_EXTERNAL_DATA_MARKERS,
  hasKeyword,
  normalizeLifecycleStatus,
  attachLifecycle,
  buildLifecycleEnvelope,
  coerceBoolean,
  mergeToolDeltas
} from './agent-shared.js';
import { getOperatorAgentId, isOperatorAgentId, normalizeOperatorAgentId } from '../services/security/system-config-store.js';
import { syncGovernance } from './agent-management.js';
import { getPermissions } from '../services/core/permissions.js';

const router = express.Router();
const AGENT_RUN_TIMEOUT_MS = 120_000;

async function authorizeExecutionTarget(req, targetAgentId) {
  const actorAgentId = req.executionContext?.actorAgentId || req.agentId || null;
  if (!actorAgentId) {
    return { ok: false, status: 401, error: 'envelope_actor_required' };
  }
  if (actorAgentId === targetAgentId) return { ok: true, actorAgentId };
  const permissions = await getPermissions(actorAgentId, COMPANY);
  if (permissions.delegate === true || permissions.admin_override === true) {
    return { ok: true, actorAgentId };
  }
  return {
    ok: false,
    status: 403,
    error: 'target_agent_not_authorized',
    actorAgentId,
    targetAgentId,
    requiredCapability: 'delegate',
  };
}

// ─── Intent / routing helpers ─────────────────────────────────────────────────

function inferIntent(prompt = '', explicitIntent = '') {
  const normalizedExplicit = String(explicitIntent || '').trim().toLowerCase();
  if (normalizedExplicit && normalizedExplicit !== 'chat') return normalizedExplicit;

  const text = String(prompt || '').toLowerCase();
  const hasEmailKeyword = text.includes('gmail') || text.includes('email') || text.includes('e-mail');
  const hasRecipient = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(text);
  const wantsSend = text.includes('send') || text.includes('draft email') || text.includes('write an email');
  const wantsInbox = text.includes('inbox') || text.includes('unread') || text.includes('latest emails');
  const wantsSearch = text.includes('search') || text.includes('find email') || text.includes('find emails');

  if ((hasEmailKeyword && wantsSend) || (hasRecipient && wantsSend)) return 'gmail_send';
  if (hasEmailKeyword && wantsSearch) return 'gmail_search';
  if (hasEmailKeyword && wantsInbox) return 'gmail_read';
  return normalizedExplicit || 'chat';
}

function isSimpleQuery(prompt = '') {
  const text = String(prompt || '').trim().toLowerCase();
  if (!text) return false;
  if (text.length >= FAST_LANE_MAX_CHARS) return false;

  const hasToolIntent = FAST_LANE_TOOL_INTENT_KEYWORDS.some((keyword) => hasKeyword(text, keyword));
  if (hasToolIntent) return false;

  const hasExternalDataMarker = FAST_LANE_EXTERNAL_DATA_MARKERS.some((keyword) => hasKeyword(text, keyword));
  if (hasExternalDataMarker) return false;

  if (/\bwho\b/i.test(text)) return false;
  return true;
}

function isFastLaneModelAvailable() {
  if (!FAST_LANE_MODEL) return false;
  return providerStatus(FAST_LANE_MODEL) === 'available';
}

function buildFastLaneResolution({ sourceAgent, sessionKey, channel, peerId, intent }) {
  return {
    sourceAgentId: sourceAgent.id,
    resolvedAgentId: sourceAgent.id,
    persona: sourceAgent.persona,
    personaVersion: Number(sourceAgent.personaVersion || 1),
    primaryModel: FAST_LANE_MODEL,
    fallbackChain: [],
    toolProfile: 'minimal',
    toolDeltas: { allow: [], deny: ['delegate_task', 'x_search'] },
    channel: channel || null,
    peerId: peerId || null,
    intent: intent || 'chat',
    sessionKey: sessionKey || null,
    delegationPolicy: {
      delegated: false,
      matchedRuleId: 'fast_lane',
      matchedRuleReason: 'simple_query'
    }
  };
}

function isExplicitXIntent(prompt = '', explicitIntent = '') {
  const normalizedPrompt = String(prompt || '').toLowerCase();
  const normalizedIntent = String(explicitIntent || '').toLowerCase();
  return X_INTENT_MARKERS.some((marker) =>
    normalizedPrompt.includes(marker) || normalizedIntent.includes(marker)
  );
}

function isIntelligenceTask(prompt = '', intent = '', artifactFormatHint = null) {
  if (artifactFormatHint === 'html_briefing') return true;
  const normalizedPrompt = String(prompt || '').toLowerCase();
  const normalizedIntent = String(intent || '').toLowerCase();
  return INTELLIGENCE_KEYWORDS.some((marker) =>
    normalizedPrompt.includes(marker) || normalizedIntent.includes(marker)
  );
}

function chooseSpecialistAgentId(prompt = '', resolvedAgentId = null) {
  if (resolvedAgentId && !isOperatorAgentId(resolvedAgentId) && resolvedAgentId !== 'checker') {
    return resolvedAgentId;
  }

  const text = String(prompt || '').toLowerCase();
  if (/(finance|pricing|revenue|budget|cash|runway|cost|unit economics|stripe)/.test(text)) {
    return 'finance-lead';
  }
  if (/(competitor|competitive|market|news|trend|x\.com|twitter|social)/.test(text)) {
    return 'market-analyst';
  }
  if (/(technical|architecture|security|deep research|deep dive|protocol)/.test(text)) {
    return 'google-deep-research';
  }
  return 'research-lead';
}

function toolProfileOverrideForIntent(intent = '') {
  switch (String(intent || '').toLowerCase()) {
    case 'gmail_send':
      return 'gmail-send';
    case 'gmail_read':
      return 'gmail-read';
    case 'gmail_search':
      return 'gmail-search';
    default:
      return null;
  }
}

// ─── SSE helpers ──────────────────────────────────────────────────────────────

function openSse(res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
}

function writeSse(res, payload) {
  return writeSseEvent(res, null, payload);
}

function writeSseEvent(res, eventName, payload) {
  if (res.writableEnded) return false;
  if (eventName) {
    res.write(`event: ${String(eventName)}\n`);
  }
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
  return true;
}

function emitLifecycleSse(res, status, details = {}) {
  const lifecycleStatus = normalizeLifecycleStatus(status, 'failed');
  return writeSseEvent(res, 'run.lifecycle', {
    status: lifecycleStatus,
    ...details,
    at: new Date().toISOString()
  });
}

function streamTextAsChunks(res, text = '', chunkSize = 24) {
  const value = String(text || '');
  if (!value) return;
  const chunks = value.match(new RegExp(`.{1,${chunkSize}}(\\s|$)`, 'g')) || [value];
  for (const chunk of chunks) {
    writeSse(res, { chunk: String(chunk || '') });
  }
}

// ─── Tool approval helpers ────────────────────────────────────────────────────

function compactApprovalText(value = '', limit = 120) {
  const normalized = String(value || '').replace(/\s+/g, ' ').trim();
  if (!normalized) return '';
  if (normalized.length <= limit) return normalized;
  return `${normalized.slice(0, Math.max(0, limit - 3))}...`;
}

function normalizeToolApprovalPayload(raw, sourceAgentId = '') {
  if (!raw || typeof raw !== 'object') return null;
  const tool = String(raw.tool || raw?.approvalRequest?.tool || 'unknown_tool').trim() || 'unknown_tool';
  const approvalRequestId = String(raw.approvalRequestId || raw?.approvalRequest?.id || '').trim() || null;

  const normalized = {
    ...raw,
    tool,
    approvalRequestId
  };

  let summary = String(raw.summary || raw?.plan?.preview || '').trim();
  if (!summary && raw?.error) summary = String(raw.error).trim();
  if (!summary) summary = `Approval required for ${tool}.`;

  // Avoid dumping full memory payloads back to chat/UI for aimos_save approvals.
  if (tool === 'aimos_save') {
    const rawContent = raw?.approvalRequest?.args?.content ?? raw?.plan?.args?.content;
    const rawTags = raw?.approvalRequest?.args?.tags ?? raw?.plan?.args?.tags;
    const sanitizedArgs = {};
    const contentPreview = compactApprovalText(rawContent, 120);
    const tagsPreview = Array.isArray(rawTags)
      ? rawTags.join(', ')
      : compactApprovalText(rawTags, 80);

    if (contentPreview) sanitizedArgs.contentPreview = contentPreview;
    if (tagsPreview) sanitizedArgs.tags = tagsPreview;
    if (!Object.keys(sanitizedArgs).length) sanitizedArgs.summary = 'aimos_save request';

    summary = `Save to memory${contentPreview ? `: "${compactApprovalText(contentPreview, 90)}"` : ''}${tagsPreview ? ` (tags: ${tagsPreview})` : ''}.`;

    if (normalized.plan && typeof normalized.plan === 'object') {
      normalized.plan = {
        ...normalized.plan,
        preview: JSON.stringify(sanitizedArgs),
        args: sanitizedArgs
      };
    }
    if (normalized.approvalRequest && typeof normalized.approvalRequest === 'object') {
      normalized.approvalRequest = {
        ...normalized.approvalRequest,
        args: sanitizedArgs,
        plan: normalized.approvalRequest.plan && typeof normalized.approvalRequest.plan === 'object'
          ? {
              ...normalized.approvalRequest.plan,
              preview: JSON.stringify(sanitizedArgs),
              args: sanitizedArgs
            }
          : normalized.approvalRequest.plan
      };
    }
  }

  normalized.summary = summary;

  if (sourceAgentId && !normalized.agentId) {
    normalized.agentId = sourceAgentId;
  }

  return normalized;
}

function toolApprovalResponseMessage(toolName = '') {
  const tool = String(toolName || '').trim();
  switch (tool) {
    case 'aimos_save':
      return 'Saving that to memory for you. Please approve this save first.';
    case 'delegate_task':
      return 'I am ready to delegate this task. Please approve delegation first.';
    case 'gmail_send':
      return 'I drafted that email. Please approve before I send it.';
    case 'write_file':
      return 'I can write that file after you approve this action.';
    default:
      return `I need your approval before running \`${tool || 'this tool'}\`.`;
  }
}

// ─── Intelligence pipeline helpers ───────────────────────────────────────────

function escapeHtml(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function stripMarkdown(value = '') {
  return String(value)
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function compactPreview(value = '', limit = 420) {
  const normalized = stripMarkdown(value).replace(/\s+/g, ' ').trim();
  if (normalized.length <= limit) return normalized;
  return `${normalized.slice(0, limit - 3)}...`;
}

function extractSources(...texts) {
  const urls = new Set();
  const urlRegex = /https?:\/\/[^\s)>\]]+/gi;
  for (const text of texts) {
    const matches = String(text || '').match(urlRegex) || [];
    for (const match of matches) urls.add(match);
  }
  return [...urls];
}

function assessVerification(checkerResponse = '') {
  const text = String(checkerResponse || '').toLowerCase();
  const failedMarkers = [
    'verification failed',
    'cannot verify',
    'unsupported',
    'insufficient evidence',
    'contradiction',
    'unverified',
    'incomplete'
  ];
  const failed = failedMarkers.some((marker) => text.includes(marker));
  return {
    checked: true,
    checkerAgentId: 'checker',
    status: failed ? 'failed' : 'passed'
  };
}

function sanitizeBriefingSlug(prompt = '') {
  const base = String(prompt || 'briefing')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return base || 'briefing';
}

function buildHtmlBriefing({
  title,
  summary,
  specialistAgentId,
  specialistResponse,
  checkerResponse,
  verification,
  delegationChain,
  sources
}) {
  const confidence = verification?.status === 'passed' ? 'High' : 'Needs review';
  const sourceItems = (sources || [])
    .map((url) => `<li><a href="${escapeHtml(url)}">${escapeHtml(url)}</a></li>`)
    .join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f4f1ea;
        --panel: #fffdf8;
        --ink: #1e293b;
        --muted: #52606d;
        --accent: #0f766e;
        --line: #d6d3d1;
      }
      body {
        margin: 0;
        padding: 32px;
        background: radial-gradient(circle at top, #fef3c7 0%, var(--bg) 42%, #e2e8f0 100%);
        color: var(--ink);
        font: 16px/1.6 Georgia, "Iowan Old Style", serif;
      }
      main {
        max-width: 980px;
        margin: 0 auto;
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 20px;
        padding: 36px;
        box-shadow: 0 24px 60px rgba(15, 23, 42, 0.08);
      }
      h1, h2 { margin: 0 0 12px; line-height: 1.15; }
      h1 { font-size: 2.1rem; }
      h2 { font-size: 1.2rem; margin-top: 28px; color: var(--accent); }
      .lede { color: var(--muted); font-size: 1.02rem; }
      .meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
        margin: 24px 0;
      }
      .card {
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 14px;
        background: rgba(255,255,255,0.72);
      }
      pre {
        white-space: pre-wrap;
        word-break: break-word;
        background: #f8fafc;
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 16px;
      }
      footer {
        margin-top: 28px;
        padding-top: 16px;
        border-top: 1px solid var(--line);
        color: var(--muted);
        font-size: 0.94rem;
      }
      a { color: var(--accent); }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(title)}</h1>
      <p class="lede">${escapeHtml(summary)}</p>
      <section class="meta">
        <div class="card"><strong>Specialist</strong><br />${escapeHtml(specialistAgentId)}</div>
        <div class="card"><strong>Checker</strong><br />${escapeHtml(verification?.checkerAgentId || 'checker')}</div>
        <div class="card"><strong>Confidence</strong><br />${escapeHtml(confidence)}</div>
        <div class="card"><strong>Verification</strong><br />${escapeHtml(verification?.status || 'not_required')}</div>
      </section>
      <h2>Executive Summary</h2>
      <p>${escapeHtml(summary)}</p>
      <h2>Key Findings</h2>
      <pre>${escapeHtml(stripMarkdown(specialistResponse))}</pre>
      <h2>Evidence / Sources</h2>
      ${sourceItems ? `<ul>${sourceItems}</ul>` : '<p>No explicit source URLs were returned in the draft.</p>'}
      <h2>Confidence / Gaps</h2>
      <pre>${escapeHtml(stripMarkdown(checkerResponse))}</pre>
      <h2>Recommended Actions</h2>
      <p>${escapeHtml(verification?.status === 'passed' ? 'Proceed using the vetted findings, while preserving the cited sources for traceability.' : 'Do not treat the findings as final until the checker concerns are resolved and the gaps are closed.')}</p>
      <footer>Provenance: ${escapeHtml((delegationChain || []).join(' -> '))}</footer>
    </main>
  </body>
</html>`;
}

function saveHtmlBriefing(prompt = '', html = '') {
  fs.mkdirSync(INTELLIGENCE_ARTIFACT_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `${stamp}-${sanitizeBriefingSlug(prompt)}.html`;
  const filepath = path.join(INTELLIGENCE_ARTIFACT_DIR, filename);
  fs.writeFileSync(filepath, html, 'utf8');
  return filepath;
}

function buildCheckerPrompt({ userPrompt, specialistAgentId, specialistResponse }) {
  return [
    'Verify the specialist draft below.',
    'Check for factual gaps, unsupported claims, contradictions, and missing caveats.',
    'If verification fails, say so explicitly with the phrase "verification failed".',
    `Original user request:\n${userPrompt}`,
    `Specialist agent: ${specialistAgentId}`,
    `Specialist draft:\n${specialistResponse}`
  ].join('\n\n');
}

function buildExecutiveDeliveryPrompt({ userPrompt, specialistAgentId, specialistResponse, checkerResponse }) {
  return [
    'Deliver the final response as Reviewer.',
    'Stay in first person as Reviewer.',
    'Do not delegate. Do not call external tools.',
    'Return plain text only. This chat reply is a preview of a separate HTML briefing artifact.',
    'If the checker found unresolved issues, state clearly that verification is incomplete.',
    `Original user request:\n${userPrompt}`,
    `Specialist agent: ${specialistAgentId}`,
    `Specialist findings:\n${specialistResponse}`,
    `Checker review:\n${checkerResponse}`
  ].join('\n\n');
}

async function runIntelligencePipeline({
  sourceAgentId,
  sourceAgent,
  prompt,
  delegationPrompt,
  inferredIntent,
  sessionKey,
  channel,
  peerId,
  specialistResolution,
  preferredModel,
  strictModel,
  requestedModel,
  skipAimos,
  executionContext,
}) {
  const specialistAgentId = specialistResolution.resolvedAgentId;
  const specialistExecutionResolution = {
    ...specialistResolution,
    resolvedAgentId: specialistAgentId,
    toolDeltas: mergeToolDeltas(specialistResolution.toolDeltas, { deny: ['delegate_task'] }),
    delegationPolicy: {
      ...(specialistResolution.delegationPolicy || {}),
      delegated: false,
      matchedRuleId: null,
      matchedRuleReason: 'intelligence_specialist_locked'
    }
  };
  const specialistResult = await runAgent(specialistAgentId, prompt, {
    skipAimos: true,
    resolution: specialistExecutionResolution,
    requestedModel: null,
    preferredModel: null,
    strictRequestedModel: false,
    originAgentId: sourceAgentId,
    sessionKey,
    intent: inferredIntent,
    autonomous: false,
    executionContext,
  });

  const checkerPrompt = buildCheckerPrompt({
    userPrompt: delegationPrompt,
    specialistAgentId,
    specialistResponse: specialistResult.response
  });
  const checkerResolution = await resolveExecutionContext({
    companyId: COMPANY,
    agentId: 'checker',
    prompt: checkerPrompt,
    sessionKey,
    channel,
    peerId,
    requestedModel: null,
    intent: 'verification',
    disableDelegation: true
  });
  const checkerExecutionResolution = {
    ...checkerResolution,
    toolDeltas: mergeToolDeltas(checkerResolution.toolDeltas, { deny: ['delegate_task'] }),
    delegationPolicy: {
      ...(checkerResolution.delegationPolicy || {}),
      delegated: false,
      matchedRuleId: null,
      matchedRuleReason: 'checker_locked'
    }
  };

  let checkerResult;
  let verification;
  try {
    checkerResult = await runAgent('checker', checkerPrompt, {
      skipAimos: true,
      resolution: checkerExecutionResolution,
      requestedModel: null,
      preferredModel: null,
      strictRequestedModel: false,
      originAgentId: sourceAgentId,
      sessionKey,
      intent: 'verification',
      autonomous: false,
      executionContext,
    });
    verification = assessVerification(checkerResult.response);
  } catch (error) {
    checkerResult = {
      agentId: 'checker',
      agentName: 'Auditor',
      response: `verification failed: checker execution error: ${error.message}`,
      model: checkerResolution.primaryModel,
      modelResolved: checkerResolution.primaryModel
    };
    verification = {
      checked: true,
      checkerAgentId: 'checker',
      status: 'failed'
    };
  }

  const deliveryResolution = {
    ...specialistExecutionResolution,
    resolvedAgentId: sourceAgentId,
    primaryModel: preferredModel || requestedModel || sourceAgent?.model || specialistResolution.primaryModel,
    fallbackChain: (specialistResolution.fallbackChain || []).filter(
      (modelId) => modelId !== (preferredModel || requestedModel || sourceAgent?.model || specialistResolution.primaryModel)
    ),
    persona: sourceAgent?.persona || specialistResolution.persona,
    personaVersion: Number(sourceAgent?.personaVersion || specialistResolution.personaVersion || 1),
    toolProfile: 'minimal',
    toolDeltas: { allow: [], deny: ['delegate_task', 'x_search'] },
    delegationPolicy: {
      ...(specialistResolution.delegationPolicy || {}),
      delegated: false,
      matchedRuleId: null,
      matchedRuleReason: 'final_delivery'
    }
  };

  let deliveryResult;
  try {
    deliveryResult = await runAgent(sourceAgentId, buildExecutiveDeliveryPrompt({
      userPrompt: delegationPrompt,
      specialistAgentId,
      specialistResponse: specialistResult.response,
      checkerResponse: checkerResult.response
    }), {
      skipAimos: true,
      resolution: deliveryResolution,
      requestedModel: strictModel ? requestedModel : null,
      preferredModel: strictModel ? null : preferredModel,
      strictRequestedModel: strictModel,
      originAgentId: sourceAgentId,
      sessionKey,
      intent: 'final_delivery',
      autonomous: false,
      executionContext,
    });
  } catch {
    deliveryResult = {
      agentId: sourceAgentId,
      agentName: sourceAgent?.name || 'Reviewer (CEO)',
      persona: sourceAgent?.persona || deliveryResolution.persona,
      personaVersion: deliveryResolution.personaVersion,
      model: deliveryResolution.primaryModel,
      modelResolved: deliveryResolution.primaryModel,
      response: compactPreview(specialistResult.response, 1200)
    };
  }

  const delegationChain = [sourceAgentId, specialistAgentId, 'checker', sourceAgentId];
  const summary = compactPreview(deliveryResult.response || specialistResult.response, 600);
  const sources = extractSources(specialistResult.response, checkerResult.response);
  const html = buildHtmlBriefing({
    title: `Intelligence Briefing: ${compactPreview(delegationPrompt, 90)}`,
    summary,
    specialistAgentId,
    specialistResponse: specialistResult.response,
    checkerResponse: checkerResult.response,
    verification,
    delegationChain,
    sources
  });
  const artifactPath = saveHtmlBriefing(delegationPrompt, html);

  if (!skipAimos) {
    try {
      await persistMemory({
        company_id: COMPANY,
        agent_id: sourceAgentId,
        key: `briefing:${Date.now()}`,
        value: artifactPath,
        scope: 'global',
        clearance_level: 5,
        memory_type: 'briefing_output',
        source: 'agent-execution.js',
        mutation_authority: 'housekeeper'
      });
    } catch (error) {
      console.warn('[agents] briefing persistence failed:', error.message);
    }
  }

  const response = `${deliveryResult.response}\n\nHTML briefing saved to ${artifactPath}`;
  return {
    ...deliveryResult,
    response,
    responseChars: response.length,
    modelRequested: requestedModel || null,
    modelResolved: deliveryResult.modelResolved || deliveryResult.model || deliveryResolution.primaryModel,
    delegatedTo: specialistAgentId,
    resolvedAgentId: specialistAgentId,
    checkerAgentId: 'checker',
    delegationChain,
    verification,
    artifact: {
      format: 'html_briefing',
      html,
      summary,
      path: artifactPath,
      sources,
      confidence: verification.status === 'passed' ? 0.82 : 0.46
    },
    alreadyFinalizedAsExecutive: true
  };
}

// ─── executeAgentRun — shared execution core ──────────────────────────────────

/**
 * executeAgentRun — shared execution core for /:id/run and /:id/stream.
 *
 * Handles: param normalisation, governance sync, agent lookup, fast-lane
 * detection, idempotency check, fast-lane execution path, normal resolution +
 * intelligence-mode path, directive claiming, session-lane management, agent
 * execution, payload assembly, run-metadata persistence, and idempotent-save.
 *
 * @param {object} params
 *   @param {string}   params.agentIdFromRoute   - req.params.id
 *   @param {string}   params.prompt
 *   @param {string}   [params.routingPrompt]
 *   @param {string}   [params.userPrompt]
 *   @param {boolean}  [params.skipAimos]
 *   @param {string}   [params.sessionKey]
 *   @param {string}   [params.sessionId]
 *   @param {string}   [params.idempotencyKey]
 *   @param {string}   [params.channel]
 *   @param {string}   [params.peerId]
 *   @param {string}   [params.intent]
 *   @param {string}   [params.taskType]
 *   @param {string}   [params.requestedModel]
 *   @param {string}   [params.providerModel]
 *   @param {string}   [params.delegationMode]
 *   @param {string}   [params.artifactFormatHint]
 *   @param {boolean}  [params.strictRequestedModel]
 *   @param {boolean}  [params.disableDelegation]
 *   @param {string}   [params.directiveId]
 *   @param {number}   [params.leaseSeconds]
 *   @param {boolean}  [params.includeDiagnostics]
 *   @param {Function} params.agentRunner
 *   @param {object}   [params.hooks]
 *
 * @returns {Promise<object>}
 */
async function executeAgentRun(params) {
  const {
    agentIdFromRoute,
    actorAgentId = agentIdFromRoute,
    credentialUseContext = {},
    prompt,
    routingPrompt,
    userPrompt,
    skipAimos = false,
    sessionKey,
    sessionId,
    idempotencyKey,
    channel,
    peerId,
    intent,
    taskType: bodyTaskType,
    requestedModel,
    providerModel,
    delegationMode = 'auto',
    artifactFormatHint = null,
    strictRequestedModel = false,
    disableDelegation = false,
    directiveId,
    leaseSeconds,
    humanFeedback = null,
    userId = null,
    includeDiagnostics = false,
    agentRunner,
    hooks = {}
  } = params;

  const {
    onFastLaneAccepted = () => {},
    onFastLaneClaimed = () => {},
    onAccepted = () => {},
    onRunning = () => {}
  } = hooks;

  // --- Param normalisation ---
  const delegationPrompt = String(routingPrompt || userPrompt || prompt || '').trim() || prompt;
  const inferredTaskType = bodyTaskType || intent || null;
  const normalizedSessionKey = sessionKey || sessionId || null;
  let runId = null;
  let acceptedAt = null;
  let runningAt = null;
  let sourceAgentId = agentIdFromRoute;

  const normalizedSkipAimos = coerceBoolean(skipAimos, false);
  const potentialFastLane = isOperatorAgentId(sourceAgentId) && isSimpleQuery(delegationPrompt) && isFastLaneModelAvailable();
  let fastLaneEnabled = potentialFastLane;
  let effectiveSkipAimos = normalizedSkipAimos || fastLaneEnabled;
  const normalizedDelegationMode = String(delegationMode || '').trim().toLowerCase() === 'locked'
    || coerceBoolean(strictRequestedModel, false)
    || coerceBoolean(disableDelegation, false)
    ? 'locked'
    : 'auto';
  const inferredIntent = inferIntent(delegationPrompt, intent);
  const normalizedArtifactFormatHint = artifactFormatHint === 'html_briefing' ? 'html_briefing' : null;
  const delegationDisabled = normalizedDelegationMode === 'locked';

  // --- Governance sync + agent resolution ---
  await syncGovernance();
  sourceAgentId = normalizeOperatorAgentId(sourceAgentId);

  let effectiveRequestedModel = requestedModel;

  if (!agents.has(sourceAgentId)) {
    const err = new Error(`Agent '${sourceAgentId}' not found`);
    err.statusCode = 404;
    throw err;
  }

  // --- Fast-lane eligibility check ---
  if (potentialFastLane) {
    if (isIntelligenceTask(delegationPrompt, inferredIntent, normalizedArtifactFormatHint)) {
      fastLaneEnabled = false;
    } else {
      try {
        const previewResolution = await resolveExecutionContext({
          companyId: COMPANY,
          agentId: sourceAgentId,
          prompt: delegationPrompt,
          sessionKey: normalizedSessionKey,
          channel,
          peerId,
          requestedModel: null,
          intent: inferredIntent,
          disableDelegation: delegationDisabled
        });
        if (previewResolution.resolvedAgentId !== sourceAgentId) {
          fastLaneEnabled = false;
        }
      } catch {
        fastLaneEnabled = false;
      }
    }
  }

  effectiveSkipAimos = normalizedSkipAimos || fastLaneEnabled;

  // --- Idempotency gate ---
  if (!effectiveSkipAimos && !idempotencyKey) {
    const err = new Error('idempotencyKey is required for side-effecting runs (skipAimos=false)');
    err.statusCode = 400;
    throw err;
  }

  // --- Idempotent replay ---
  if (!effectiveSkipAimos) {
    const replay = await getIdempotentResponse({
      companyId: COMPANY,
      agentId: sourceAgentId,
      idempotencyKey
    });
    if (replay) {
      const replayStatus = normalizeLifecycleStatus(
        replay?.lifecycleStatus || replay?.status || 'completed',
        'completed'
      );
      const finalPayload = attachLifecycle(
        { success: true, ...replay, idempotentReplay: true },
        { status: replayStatus, runId: replay?.runId || null, finishedAt: new Date().toISOString() }
      );
      return {
        type: 'replay',
        actorAgentId,
        finalPayload,
        replayStatus,
        runId: replay?.runId || null,
        sourceAgentId,
        acceptedAt: null,
        runningAt: null,
        directiveClaimStatus: null
      };
    }
  }

  // =========================================================
  // FAST-LANE PATH
  // =========================================================
  if (fastLaneEnabled) {
    const sourceAgent = agents.get(sourceAgentId);
    if (!sourceAgent) {
      const err = new Error(`Agent '${sourceAgentId}' not found`);
      err.statusCode = 404;
      throw err;
    }

    console.info(`[fast-lane] routing to ${FAST_LANE_MODEL} (prompt: ${String(delegationPrompt || '').length} chars)`);
    const fastResolution = buildFastLaneResolution({
      sourceAgent,
      sessionKey: normalizedSessionKey,
      channel,
      peerId,
      intent: inferredIntent
    });

    let directiveClaimStatus = null;
    runId = randomUUID();
    acceptedAt = new Date().toISOString();
    publishRunEvent('run.accepted', {
      status: 'accepted',
      runId,
      companyId: COMPANY,
      sessionKey: normalizedSessionKey,
      sourceAgentId,
      resolvedAgentId: sourceAgentId,
      queueWaitMs: 0,
      channel: channel || null,
      peerId: peerId || null,
      intent: inferredIntent
    });
    onFastLaneAccepted({ runId, sourceAgentId });

    if (directiveId) {
      directiveClaimStatus = await claimDirective({
        companyId: COMPANY,
        directiveId,
        agentId: sourceAgentId,
        runId,
        leaseSeconds,
        authority: credentialUseContext,
      });
      if (!directiveClaimStatus.claimed) {
        const err = new Error('directive_claim_failed');
        err.statusCode = 409;
        err.directiveClaimStatus = directiveClaimStatus;
        err.runId = runId;
        err.acceptedAt = acceptedAt;
        throw err;
      }
    }

    const timeoutMs = AGENT_RUN_TIMEOUT_MS;
    const laneResult = await withSessionLane({
      companyId: COMPANY,
      sessionKey: normalizedSessionKey,
      runId,
      agentId: sourceAgentId,
      model: FAST_LANE_MODEL
    }, async ({ queueWaitMs, sessionKey: lockedSessionKey }) => {
      runningAt = new Date().toISOString();
      onFastLaneClaimed({ runId, sourceAgentId, queueWaitMs });
      const fastAuthorizationTrajectory = [
        {
          step: 'fast_lane',
          at: new Date().toISOString(),
          sourceAgentId,
          resolvedAgentId: sourceAgentId,
          reason: 'fast_lane_direct'
        }
      ];
      await markRunStarted({
        runId,
        companyId: COMPANY,
        sessionKey: lockedSessionKey,
        idempotencyKey,
        sourceAgentId,
        resolvedAgentId: sourceAgentId,
        personaVersion: Number(sourceAgent.personaVersion || 1),
        modelRequested: FAST_LANE_MODEL,
        modelResolved: FAST_LANE_MODEL,
        fallbackUsed: false,
        delegatedTo: null,
        queueWaitMs,
        channel: channel || null,
        peerId: peerId || null,
        intent: inferredIntent,
        authorizationTrajectory: fastAuthorizationTrajectory,
        authorizationChainHash: null
      });

      return Promise.race([
        agentRunner(sourceAgentId, prompt, {
          skipAimos: true,
          fastLane: true,
          taskType: inferredTaskType || inferredIntent,
          resolution: {
            ...fastResolution,
            sessionKey: lockedSessionKey
          },
          requestedModel: FAST_LANE_MODEL,
          preferredModel: FAST_LANE_MODEL,
          strictRequestedModel: true,
          modelPlan: [FAST_LANE_MODEL],
          originAgentId: sourceAgentId,
          runId,
          sessionKey: lockedSessionKey,
          intent: inferredIntent,
          humanFeedback,
          userId,
          autonomous: Boolean(directiveId),
          credentialUseContext,
          executionContext: credentialUseContext,
        }),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error(`Agent run timed out after ${timeoutMs}ms`)), timeoutMs);
        })
      ]);
    });

    const result = laneResult.result;
    const payload = {
      success: true,
      actor_agent_id: actorAgentId,
      runId,
      sessionKey: laneResult.sessionKey,
      queueWaitMs: laneResult.queueWaitMs,
      agentId: sourceAgentId,
      sourceAgentId,
      resolvedAgentId: sourceAgentId,
      agentName: sourceAgent.name,
      persona: sourceAgent.persona,
      personaVersion: Number(sourceAgent.personaVersion || 1),
      model: result.modelResolved || result.model || FAST_LANE_MODEL,
      modelRequested: FAST_LANE_MODEL,
      modelResolved: result.modelResolved || result.model || FAST_LANE_MODEL,
      fallbackUsed: false,
      delegatedTo: null,
      checkerAgentId: null,
      delegationMode: 'fast_lane',
      delegationChain: [sourceAgentId],
      verification: { checked: false, status: 'not_required' },
      artifact: null,
      promptChars: result.promptChars ?? null,
      responseChars: result.responseChars ?? null,
      contextCompaction: result.contextCompaction ?? null,
      promptPressure: result.promptPressure ?? null,
      response: result.response,
      fastLane: true,
      directiveClaimStatus
    };

    await markRunCompleted({
      runId,
      companyId: COMPANY,
      sourceAgentId,
      resolvedAgentId: sourceAgentId,
      modelResolved: payload.modelResolved,
      fallbackUsed: false,
      delegatedTo: null,
      queueWaitMs: laneResult.queueWaitMs,
      response: payload.response,
      promptChars: result.promptChars,
      responseChars: result.responseChars,
      contextCompacted: result.contextCompaction?.compacted,
      contextCompactionRatio: result.contextCompaction?.ratio,
      confidence: extractConfidence(
        payload.response,
        0,
        result.contextCompaction?.keptItems ?? 0
      )
    });

    if (directiveId) {
      await completeDirectiveClaim({
        companyId: COMPANY,
        directiveId,
        agentId: sourceAgentId,
        status: 'completed',
        authority: credentialUseContext,
      });
    }

    const finalPayload = attachLifecycle(payload, {
      status: 'completed',
      runId,
      acceptedAt,
      runningAt,
      finishedAt: new Date().toISOString()
    });

    return {
      type: 'fast_lane',
      actorAgentId,
      finalPayload,
      payload,
      runId,
      acceptedAt,
      runningAt,
      sourceAgentId,
      directiveClaimStatus
    };
  }

  // =========================================================
  // NORMAL PATH
  // =========================================================
  const normalizedRequestedModel = requestedModel || providerModel || null;
  const strictModel = normalizedDelegationMode === 'locked';
  const preferredModel = strictModel ? null : normalizedRequestedModel;
  const requestedModelForResolution = strictModel ? normalizedRequestedModel : null;
  let resolution = await resolveExecutionContext({
    companyId: COMPANY,
    agentId: sourceAgentId,
    prompt: delegationPrompt,
    sessionKey: normalizedSessionKey,
    channel,
    peerId,
    requestedModel: requestedModelForResolution,
    intent: inferredIntent,
    disableDelegation: delegationDisabled
  });
  const profileOverride = toolProfileOverrideForIntent(inferredIntent);
  if (profileOverride) {
    resolution = {
      ...resolution,
      intent: inferredIntent,
      toolProfile: profileOverride,
      toolDeltas: { allow: [], deny: [] }
    };
  }

  const sourceAgent = agents.get(sourceAgentId);
  if (!sourceAgent) {
    const err = new Error(`Agent '${sourceAgentId}' not found`);
    err.statusCode = 404;
    throw err;
  }

  const intelligenceMode = isOperatorAgentId(sourceAgentId) && isIntelligenceTask(
    delegationPrompt,
    inferredIntent,
    normalizedArtifactFormatHint
  );
  const specialistAgentId = intelligenceMode
    ? chooseSpecialistAgentId(delegationPrompt, resolution.resolvedAgentId)
    : resolution.resolvedAgentId;
  let executionResolution = resolution;
  if (intelligenceMode && specialistAgentId !== resolution.resolvedAgentId) {
    executionResolution = await resolveExecutionContext({
      companyId: COMPANY,
      agentId: specialistAgentId,
      prompt: delegationPrompt,
      sessionKey: normalizedSessionKey,
      channel,
      peerId,
      requestedModel: null,
      intent: inferredIntent,
      disableDelegation: true
    });
  }

  runId = randomUUID();
  acceptedAt = new Date().toISOString();
  publishRunEvent('run.accepted', {
    status: 'accepted',
    runId,
    companyId: COMPANY,
    sessionKey: normalizedSessionKey,
    sourceAgentId,
    resolvedAgentId: intelligenceMode ? specialistAgentId : resolution.resolvedAgentId,
    queueWaitMs: 0,
    channel: channel || null,
    peerId: peerId || null,
    intent: inferredIntent
  });
  onAccepted({ runId, sourceAgentId });

  let directiveClaimStatus = null;
  if (directiveId) {
    directiveClaimStatus = await claimDirective({
      companyId: COMPANY,
      directiveId,
      agentId: sourceAgentId,
      runId,
      leaseSeconds,
      authority: credentialUseContext,
    });
    if (!directiveClaimStatus.claimed) {
      const err = new Error('directive_claim_failed');
      err.statusCode = 409;
      err.directiveClaimStatus = directiveClaimStatus;
      err.runId = runId;
      err.acceptedAt = acceptedAt;
      throw err;
    }
  }

  const timeoutMs = AGENT_RUN_TIMEOUT_MS;
  const executionModelPlan = [
    effectiveRequestedModel,
    executionResolution.primaryModel,
    ...(executionResolution.fallbackChain || [])
  ].filter(Boolean);

  const laneResult = await withSessionLane({
    companyId: COMPANY,
    sessionKey: executionResolution.sessionKey || normalizedSessionKey,
    runId,
    agentId: intelligenceMode ? specialistAgentId : executionResolution.resolvedAgentId,
    model: executionResolution.primaryModel
  }, async ({ queueWaitMs, sessionKey: lockedSessionKey }) => {
    runningAt = new Date().toISOString();
    onRunning({ runId, sourceAgentId, queueWaitMs });
    await markRunStarted({
      runId,
      companyId: COMPANY,
      sessionKey: lockedSessionKey,
      idempotencyKey,
      sourceAgentId,
      resolvedAgentId: intelligenceMode ? specialistAgentId : executionResolution.resolvedAgentId,
      personaVersion: executionResolution.personaVersion,
      modelRequested: normalizedRequestedModel || null,
      modelResolved: executionResolution.primaryModel,
      fallbackUsed: false,
      delegatedTo: intelligenceMode
        ? specialistAgentId
        : (executionResolution.delegationPolicy?.delegated ? executionResolution.resolvedAgentId : null),
      queueWaitMs,
      channel: executionResolution.channel,
      peerId: executionResolution.peerId,
      intent: executionResolution.intent,
      authorizationTrajectory: executionResolution.authorizationTrajectory || resolution.authorizationTrajectory || [],
      authorizationChainHash: executionResolution.authorizationChainHash || resolution.authorizationChainHash || null
    });

    return Promise.race([
      intelligenceMode
        ? runIntelligencePipeline({
            sourceAgentId,
            sourceAgent,
            prompt,
            delegationPrompt,
            inferredIntent,
            sessionKey: lockedSessionKey,
            channel: executionResolution.channel,
            peerId: executionResolution.peerId,
            specialistResolution: executionResolution,
            preferredModel,
            strictModel,
            requestedModel: normalizedRequestedModel,
            skipAimos: effectiveSkipAimos,
            executionContext: credentialUseContext,
          })
        : agentRunner(executionResolution.resolvedAgentId, prompt, {
            skipAimos: effectiveSkipAimos,
            taskType: inferredTaskType || inferredIntent,
            resolution: executionResolution,
            requestedModel: effectiveRequestedModel,
            preferredModel: effectiveRequestedModel,
            strictRequestedModel: strictModel,
            modelPlan: executionModelPlan,
            originAgentId: sourceAgentId,
            runId,
            sessionKey: lockedSessionKey,
            intent: inferredIntent,
            humanFeedback,
            userId,
            autonomous: Boolean(directiveId),
            credentialUseContext,
            executionContext: credentialUseContext,
          }),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Agent run timed out after ${timeoutMs}ms`)), timeoutMs);
      })
    ]);
  });

  const result = laneResult.result;
  const modelResolved = result.modelResolved || result.model || executionResolution.primaryModel;
  const fallbackUsed = Boolean(result.fallbackUsed || modelResolved !== executionResolution.primaryModel);
  const delegatedTo = result.delegatedTo || (
    intelligenceMode
      ? specialistAgentId
      : (executionResolution.delegationPolicy?.delegated ? executionResolution.resolvedAgentId : null)
  );

  let deliveryAgentId = result.agentId;
  let deliveryAgentName = result.agentName;
  let deliveryPersona = result.persona || executionResolution.persona;
  let deliveryPersonaVersion = result.personaVersion || executionResolution.personaVersion;
  let deliveryModelResolved = modelResolved;
  let deliveryFallbackUsed = fallbackUsed;
  let deliveryResponse = result.response;

  // Executive lane remains the only user-facing speaker; delegated agents report through it.
  if (isOperatorAgentId(sourceAgentId) && delegatedTo && !result.alreadyFinalizedAsExecutive) {
    const specialistLabel = result.agentName || delegatedTo;
    deliveryAgentId = sourceAgentId;
    deliveryAgentName = sourceAgent?.name || 'Reviewer (CEO)';
    deliveryPersona = sourceAgent?.persona || deliveryPersona;
    deliveryPersonaVersion = Number(sourceAgent?.personaVersion || deliveryPersonaVersion || 1);
    deliveryModelResolved = executionResolution.primaryModel || normalizedRequestedModel || modelResolved;
    deliveryFallbackUsed = false;
    deliveryResponse = `I delegated this task to ${specialistLabel}. Here is the specialist report:\n\n${String(result.response || '')}`;
  }

  const delegationChain = Array.isArray(result.delegationChain)
    ? result.delegationChain
    : [sourceAgentId, ...(delegatedTo ? [delegatedTo] : [])];
  const verification = result.verification || { checked: false, status: 'not_required' };

  const payload = {
    success: true,
    actor_agent_id: actorAgentId,
    runId,
    sessionKey: laneResult.sessionKey,
    queueWaitMs: laneResult.queueWaitMs,
    agentId: deliveryAgentId,
    sourceAgentId,
    resolvedAgentId: result.resolvedAgentId || executionResolution.resolvedAgentId,
    agentName: deliveryAgentName,
    persona: deliveryPersona,
    personaVersion: deliveryPersonaVersion,
    model: deliveryModelResolved,
    modelRequested: normalizedRequestedModel || null,
    modelResolved: deliveryModelResolved,
    fallbackUsed: deliveryFallbackUsed,
    delegatedTo,
    checkerAgentId: result.checkerAgentId || null,
    delegationMode: normalizedDelegationMode,
    delegationChain,
    verification,
    artifact: result.artifact || null,
    promptChars: result.promptChars ?? null,
    responseChars: result.responseChars ?? null,
    contextCompaction: result.contextCompaction ?? null,
    promptPressure: result.promptPressure ?? null,
    confidence: result.confidence ?? null,
    autonomyLevel: result.autonomyLevel ?? null,
    autonomyAction: result.autonomyAction ?? null,
    taskRoute: result.taskRoute ?? null,
    diagnostics: coerceBoolean(includeDiagnostics, false)
      ? {
          modelAllocationDiagnostics: result.modelAllocationDiagnostics ?? null,
          localInference: result.localInference ?? null,
          tokenScale: result.tokenScale ?? null,
          robustLengthPrediction: result.robustLengthPrediction ?? null,
          agsc: result.agsc ?? null,
          keyedPrefetch: result.keyedPrefetch ?? null,
          metaController: result.metaController ?? null
        }
      : undefined,
    rerouteNote: result.rerouteNote ?? null,
    response: deliveryResponse,
    directiveClaimStatus
  };
  const finalPayload = attachLifecycle(payload, {
    status: 'completed',
    runId,
    acceptedAt,
    runningAt,
    finishedAt: new Date().toISOString()
  });

  await markRunCompleted({
    runId,
    companyId: COMPANY,
    sourceAgentId,
    resolvedAgentId: result.resolvedAgentId || executionResolution.resolvedAgentId,
    modelResolved: deliveryModelResolved,
    fallbackUsed: deliveryFallbackUsed,
    delegatedTo,
    queueWaitMs: laneResult.queueWaitMs,
    response: deliveryResponse,
    promptChars: result.promptChars,
    responseChars: result.responseChars,
    contextCompacted: result.contextCompaction?.compacted,
    contextCompactionRatio: result.contextCompaction?.ratio,
    confidence: result.confidence ?? extractConfidence(
      deliveryResponse,
      0,
      result.contextCompaction?.keptItems ?? 0
    )
  });

  if (!effectiveSkipAimos) {
    await saveIdempotentResponse({
      companyId: COMPANY,
      agentId: sourceAgentId,
      idempotencyKey,
      response: finalPayload
    });
  }

  if (directiveId) {
    await completeDirectiveClaim({
      companyId: COMPANY,
      directiveId,
      agentId: sourceAgentId,
      status: 'completed',
      authority: credentialUseContext,
    });
  }

  return {
    type: 'normal',
    actorAgentId,
    finalPayload,
    payload,
    deliveryResponse,
    runId,
    acceptedAt,
    runningAt,
    sourceAgentId,
    directiveClaimStatus,
    effectiveSkipAimos,
    idempotencyKey
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.post('/:id/run', async (req, res, next) => {
  const body = req.body || {};
  const {
    prompt,
    directiveId,
    directiveClaimStatus: _unused
  } = body;

  if (!prompt) {
    return res.status(400).json(attachLifecycle(
      { success: false, error: 'prompt is required' },
      { status: 'failed', finishedAt: new Date().toISOString(), error: 'prompt is required' }
    ));
  }

  const targetAuthorization = await authorizeExecutionTarget(req, req.params.id);
  if (!targetAuthorization.ok) {
    return res.status(targetAuthorization.status).json({ success: false, ...targetAuthorization });
  }

  let runId = null;
  let acceptedAt = null;
  let runningAt = null;
  let sourceAgentId = req.params.id;

  try {
    const outcome = await executeAgentRun({
      agentIdFromRoute: req.params.id,
      actorAgentId: targetAuthorization.actorAgentId,
      credentialUseContext: req.executionContext,
      ...body,
      agentRunner: runAgent
      // No hooks needed — JSON route has no lifecycle event side-effects
    });

    runId = outcome.runId;
    acceptedAt = outcome.acceptedAt;
    runningAt = outcome.runningAt;
    sourceAgentId = outcome.sourceAgentId;

    if (outcome.type === 'replay') {
      return res.json(outcome.finalPayload);
    }

    // fast_lane and normal both return res.json of finalPayload
    return res.json(outcome.finalPayload);
  } catch (err) {
    runId = err.runId || runId;
    acceptedAt = err.acceptedAt || acceptedAt;
    runningAt = err.runningAt || runningAt;

    // directive_claim_failed is a structured early-exit, not a run error
    if (err.message === 'directive_claim_failed') {
      return res.status(409).json(attachLifecycle({
        success: false,
        error: 'directive_claim_failed',
        directiveClaimStatus: err.directiveClaimStatus
      }, {
        status: 'failed',
        runId,
        acceptedAt,
        finishedAt: new Date().toISOString(),
        error: 'directive_claim_failed'
      }));
    }

    if (err.statusCode === 400) {
      err.publicMessage = err.message;
      return next(err);
    }

    if (err.statusCode === 404) {
      err.publicMessage = err.message;
      return next(err);
    }

    const isToolApproval = err?.code === 'TOOL_APPROVAL_REQUIRED';
    const isConstitutionBlock = err?.code === 'HOM_CONSTITUTION_VIOLATION';
    const isKnowledgeGate = err?.code === 'KNOWLEDGE_ACQUISITION_REQUIRED';
    const isTimeout = String(err.message || '').includes('timed out');
    if (runId && isToolApproval) {
      await markRunAwaitingApproval({
        runId,
        companyId: COMPANY,
        sourceAgentId,
        resolvedAgentId: null,
        error: err.message,
        approvalRequestId: err?.toolApproval?.approvalRequestId || null
      });
    } else if (runId) {
      await markRunFailed({
        runId,
        companyId: COMPANY,
        error: err.message,
        lifecycleStatus: isTimeout ? 'timeout' : 'failed'
      });
    }
    if (directiveId) {
      await completeDirectiveClaim({
        companyId: COMPANY,
        directiveId,
        agentId: sourceAgentId,
        status: 'failed',
        authority: credentialUseContext,
      });
    }
    const status = isToolApproval
      ? 'awaiting_approval'
      : (isTimeout ? 'timeout' : 'failed');
    const errorPayload = attachLifecycle(
      { success: false, error: err.message },
      {
        status,
        runId,
        acceptedAt,
        runningAt,
        finishedAt: new Date().toISOString(),
        error: err.message
      }
    );
    if (err.code) errorPayload.code = err.code;
    if (Array.isArray(err.failures)) errorPayload.failures = err.failures;
    if (err?.knowledgeGate) errorPayload.knowledgeGate = err.knowledgeGate;
    if (err?.constitution) errorPayload.constitution = err.constitution;
    if (isToolApproval) {
      const toolApproval = normalizeToolApprovalPayload(err?.toolApproval, sourceAgentId);
      if (toolApproval) {
        errorPayload.toolApproval = toolApproval;
        errorPayload.response = toolApprovalResponseMessage(toolApproval.tool);
      }
    }
    // Structured protocol responses (tool approval / constitution / knowledge gate
    // / timeout) are intentional application-level payloads, not error leaks.
    // The generic 500 fall-through must route through the global error handler.
    if (isToolApproval || isConstitutionBlock || isKnowledgeGate || isTimeout) {
      const statusCode = isToolApproval ? 409 : (isConstitutionBlock ? 409 : (isKnowledgeGate ? 428 : 504));
      return res.status(statusCode).json(errorPayload);
    }
    err.statusCode = 500;
    next(err);
  }
});

router.post('/:id/stream', async (req, res, next) => {
  const body = req.body || {};
  const { prompt, directiveId } = body;

  if (!prompt) {
    return res.status(400).json({ error: 'prompt is required', status: 'failed', lifecycleStatus: 'failed' });
  }

  const targetAuthorization = await authorizeExecutionTarget(req, req.params.id);
  if (!targetAuthorization.ok) {
    return res.status(targetAuthorization.status).json({ success: false, ...targetAuthorization });
  }

  openSse(res);

  let runId = null;
  let acceptedAt = null;
  let runningAt = null;
  let sourceAgentId = req.params.id;
  let clientClosed = false;
  let streamedAny = false;
  let streamBuffer = '';
  let streamLastFlushAt = Date.now();
  req.on('close', () => { clientClosed = true; });

  function flushStreamBuffer(force = false) {
    if (clientClosed || !streamBuffer) return;
    const now = Date.now();
    const chunkSize = selectTokenScaleChunkSize({
      qosTier: 'interactive',
      predictedOutputTokens: Math.max(64, Math.ceil(streamBuffer.length / 4)),
    });
    const shouldFlush = force
      || streamBuffer.length >= chunkSize
      || now - streamLastFlushAt >= 80
      || /[\n.!?]\s*$/.test(streamBuffer);
    if (!shouldFlush) return;
    streamedAny = true;
    writeSse(res, { chunk: streamBuffer });
    streamBuffer = '';
    streamLastFlushAt = now;
  }

  // Build the streaming agentRunner: wraps runAgentStream with onToken injected.
  // The executeAgentRun core calls agentRunner(agentId, prompt, opts) —
  // we append onToken into opts here for the stream path.
  function makeStreamRunner(agentId, runPrompt, opts) {
    return runAgentStream(agentId, runPrompt, {
      ...opts,
      onToken: (chunk) => {
        if (clientClosed) return;
        streamBuffer += String(chunk || '');
        flushStreamBuffer(false);
      }
    });
  }

  try {
    const outcome = await executeAgentRun({
      agentIdFromRoute: req.params.id,
      actorAgentId: targetAuthorization.actorAgentId,
      credentialUseContext: req.executionContext,
      ...body,
      agentRunner: makeStreamRunner,
      hooks: {
        onFastLaneAccepted: ({ runId: rid, sourceAgentId: sid }) => {
          emitLifecycleSse(res, 'accepted', { runId: rid, sourceAgentId: sid });
        },
        onFastLaneClaimed: ({ runId: rid, sourceAgentId: sid, queueWaitMs }) => {
          emitLifecycleSse(res, 'running', { runId: rid, sourceAgentId: sid, queueWaitMs });
        },
        onAccepted: ({ runId: rid, sourceAgentId: sid }) => {
          emitLifecycleSse(res, 'accepted', { runId: rid, sourceAgentId: sid });
        },
        onRunning: ({ runId: rid, sourceAgentId: sid, queueWaitMs }) => {
          emitLifecycleSse(res, 'running', { runId: rid, sourceAgentId: sid, queueWaitMs });
        }
      }
    });

    runId = outcome.runId;
    acceptedAt = outcome.acceptedAt;
    runningAt = outcome.runningAt;
    sourceAgentId = outcome.sourceAgentId;

    if (outcome.type === 'replay') {
      const replayPayload = outcome.finalPayload;
      const fullResponse = String(replayPayload?.response?.response || replayPayload?.response || '');
      emitLifecycleSse(res, outcome.replayStatus, { runId: replayPayload.runId || null, replay: true });
      flushStreamBuffer(true);
      writeSse(res, { done: true, fullResponse, payload: replayPayload });
      res.end();
      return;
    }

    if (outcome.type === 'fast_lane') {
      const { payload, finalPayload } = outcome;
      flushStreamBuffer(true);
      if (!streamedAny && payload.response) {
        streamTextAsChunks(res, payload.response, 4);
      }
      emitLifecycleSse(res, 'completed', { runId, sourceAgentId });
      writeSse(res, { done: true, fullResponse: payload.response, payload: finalPayload });
      res.end();
      return;
    }

    // normal path
    const { finalPayload, deliveryResponse } = outcome;
    flushStreamBuffer(true);
    if (!streamedAny && deliveryResponse) {
      streamTextAsChunks(res, deliveryResponse);
    }
    emitLifecycleSse(res, 'completed', { runId, sourceAgentId });
    writeSse(res, { done: true, fullResponse: deliveryResponse, payload: finalPayload });
    res.end();
  } catch (err) {
    runId = err.runId || runId;
    acceptedAt = err.acceptedAt || acceptedAt;
    runningAt = err.runningAt || runningAt;

    // directive_claim_failed: structured early-exit with SSE error
    if (err.message === 'directive_claim_failed') {
      emitLifecycleSse(res, 'failed', { runId, sourceAgentId, error: 'directive_claim_failed' });
      writeSse(res, {
        error: 'directive_claim_failed',
        directiveClaimStatus: err.directiveClaimStatus,
        status: 'failed',
        lifecycleStatus: 'failed'
      });
      res.end();
      return;
    }

    if (err.statusCode === 400 || err.statusCode === 404) {
      writeSse(res, { error: err.message, status: 'failed', lifecycleStatus: 'failed' });
      res.end();
      return;
    }

    const isToolApproval = err?.code === 'TOOL_APPROVAL_REQUIRED';
    const isConstitutionBlock = err?.code === 'HOM_CONSTITUTION_VIOLATION';
    const isKnowledgeGate = err?.code === 'KNOWLEDGE_ACQUISITION_REQUIRED';
    const isTimeout = String(err.message || '').includes('timed out');
    if (runId && isToolApproval) {
      await markRunAwaitingApproval({
        runId,
        companyId: COMPANY,
        sourceAgentId,
        resolvedAgentId: null,
        error: err.message,
        approvalRequestId: err?.toolApproval?.approvalRequestId || null
      });
    } else if (runId) {
      await markRunFailed({
        runId,
        companyId: COMPANY,
        error: err.message,
        lifecycleStatus: isTimeout ? 'timeout' : 'failed'
      });
    }

    if (directiveId) {
      await completeDirectiveClaim({
        companyId: COMPANY,
        directiveId,
        agentId: sourceAgentId,
        status: 'failed',
        authority: credentialUseContext,
      });
    }

    if (isToolApproval) {
      const toolApproval = normalizeToolApprovalPayload(err?.toolApproval, sourceAgentId);
      const response = toolApprovalResponseMessage(toolApproval?.tool);
      const payload = {
        success: false,
        code: 'TOOL_APPROVAL_REQUIRED',
        error: err.message || 'tool_approval_required',
        response,
        toolApproval,
        status: 'awaiting_approval',
        lifecycleStatus: 'awaiting_approval'
      };
      emitLifecycleSse(res, 'awaiting_approval', {
        runId,
        sourceAgentId,
        approvalRequestId: toolApproval?.approvalRequestId || null,
        error: err.message || 'tool_approval_required'
      });
      writeSse(res, payload);
      writeSse(res, { done: true, fullResponse: response, payload });
      res.end();
      return;
    }

    const status = isTimeout ? 'timeout' : 'failed';
    emitLifecycleSse(res, status, { runId, sourceAgentId, error: err.message || 'stream_failed' });
    writeSse(res, {
      code: isConstitutionBlock ? 'HOM_CONSTITUTION_VIOLATION' : (isKnowledgeGate ? 'KNOWLEDGE_ACQUISITION_REQUIRED' : undefined),
      error: err.message || 'stream_failed',
      constitution: err?.constitution || undefined,
      knowledgeGate: err?.knowledgeGate || undefined,
      status,
      lifecycleStatus: status
    });
    res.end();
  }
});

export default router;
