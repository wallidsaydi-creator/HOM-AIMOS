/**
 * agent-tools.js
 * Source: OpenAI Function Calling, Anthropic Tool Use, ReAct pattern
 *
 * Tool execution loop: provider-native dispatch, Gemini tools, generic adapters,
 * inline tool-code parsing, streaming helpers, and the fallback chain.
 *
 * Imported by agent-runner.js — not a public API surface.
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (during step 20)
// → Calls: services/orchestration/tool-registry.js (executeTool)
// → Calls: services/core/providers.js (runProvider)
// Pipeline: AGENT_RUN_PIPELINE
// Position: LLM inference + tool loop
// ─────────────────────────────────────────────────────────────────────────────

import { executeTool } from './tool-registry.js';
import { runProvider, resolveProviderForModel } from '../core/providers.js';
import { fetchWithTimeout } from './http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';

const MAX_TOOL_LOOPS = 8;
const MODEL_PROVIDER_REQUEST_TIMEOUT_MS = 30_000;
const MODEL_CIRCUIT_BREAKER_WINDOW_MS = 5 * 60 * 1000;
const MODEL_CIRCUIT_BREAKER_THRESHOLD = 3;
const modelFailureHistory = new Map();

const INLINE_TOOL_NAME_ALIASES = {
  aimos_recall: 'aimos_recall',
  aimos_save: 'aimos_save',
  web_search: 'web_search',
  // x_search: 'x_search', // DISABLED 2026-03-17 — credit drain prevention
  gmail_inbox: 'gmail_inbox',
  gmail_search: 'gmail_search',
  gmail_send: 'gmail_send',
  calendar_today: 'calendar_today',
  calendar_events: 'calendar_events',
  calendar_create: 'calendar_create',
  youtube_search: 'youtube_search',
  drive_list: 'drive_list',
  drive_read: 'drive_read',
  docs_read: 'docs_read',
  sheets_read: 'sheets_read',
  delegate_task: 'delegate_task'
};
const INLINE_TOOL_ARG_KEYS = {
  aimos_recall: ['query'],
  aimos_save: ['content'],
  web_search: ['query'],
  // x_search: ['query'], // DISABLED 2026-03-17 — credit drain prevention
  gmail_inbox: ['max'],
  gmail_search: ['query'],
  gmail_send: ['to', 'subject', 'body'],
  calendar_events: ['max'],
  calendar_create: ['summary', 'start', 'end'],
  youtube_search: ['query'],
  drive_read: ['file_id'],
  docs_read: ['document_id'],
  sheets_read: ['spreadsheet_id', 'range'],
  delegate_task: ['agent_id', 'prompt']
};

// ─── CIRCUIT BREAKER ─────────────────────────────────────────────────────────

export function pruneModelFailureHistory(modelId, now = Date.now()) {
  const key = String(modelId || '').trim();
  if (!key) return [];

  const kept = (modelFailureHistory.get(key) || []).filter(
    (timestamp) => Number.isFinite(timestamp) && (now - timestamp) <= MODEL_CIRCUIT_BREAKER_WINDOW_MS
  );

  if (kept.length) {
    modelFailureHistory.set(key, kept);
  } else {
    modelFailureHistory.delete(key);
  }

  return kept;
}

export function isModelCircuitBroken(modelId) {
  const failures = pruneModelFailureHistory(modelId);
  return failures.length > MODEL_CIRCUIT_BREAKER_THRESHOLD;
}

export function recordModelFailure(modelId) {
  const key = String(modelId || '').trim();
  if (!key) return;
  const now = Date.now();
  const failures = pruneModelFailureHistory(key, now);
  failures.push(now);
  modelFailureHistory.set(key, failures);
}

export function resetModelCircuitBreaker(modelIds = []) {
  for (const modelId of modelIds) {
    const key = String(modelId || '').trim();
    if (!key) continue;
    modelFailureHistory.delete(key);
  }
}

// ─── TOOL APPROVAL HELPERS ─────────────────────────────────────────────────────

export function isToolApprovalRequired(result) {
  return !!(result && typeof result === 'object' && result.requiresApproval);
}

export function createToolApprovalError(toolName, toolResult) {
  const approvalRequestId = toolResult?.approvalRequestId || null;
  const error = new Error(
    `Tool approval required for '${toolName}'${approvalRequestId ? ` (${approvalRequestId})` : ''}`
  );
  error.code = 'TOOL_APPROVAL_REQUIRED';
  error.toolApproval = {
    tool: toolName,
    ...toolResult
  };
  return error;
}

export function loopExhaustedResult(model) {
  return {
    response: 'Max tool loops reached without final answer.',
    model
  };
}

// ─── INLINE TOOL PARSING ──────────────────────────────────────────────────────

function splitInlineArgs(argsText = '') {
  const value = String(argsText || '').trim();
  if (!value) return [];
  const parts = [];
  let current = '';
  let depth = 0;
  let quote = null;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    const prev = i > 0 ? value[i - 1] : '';
    if (quote) {
      current += ch;
      if (ch === quote && prev !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === '\'' || ch === '`') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '{' || ch === '[' || ch === '(') {
      depth += 1;
      current += ch;
      continue;
    }
    if (ch === '}' || ch === ']' || ch === ')') {
      depth = Math.max(0, depth - 1);
      current += ch;
      continue;
    }
    if (ch === ',' && depth === 0) {
      if (current.trim()) parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseInlineValue(raw = '') {
  const value = String(raw || '').trim();
  if (!value) return '';
  if (
    (value.startsWith('{') && value.endsWith('}')) ||
    (value.startsWith('[') && value.endsWith(']'))
  ) {
    try { return JSON.parse(value); } catch { /* noop */ }
  }
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith('\'') && value.endsWith('\'')) ||
    (value.startsWith('`') && value.endsWith('`'))
  ) {
    return value.slice(1, -1);
  }
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === 'true';
  if (/^null$/i.test(value)) return null;
  const n = Number(value);
  if (Number.isFinite(n)) return n;
  return value;
}

function parseInlineToolArgs(toolName, argsText = '') {
  const text = String(argsText || '').trim();
  if (!text) return {};
  if (text.startsWith('{') && text.endsWith('}')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object') return parsed;
    } catch {
      // fall through
    }
  }

  const orderedKeys = INLINE_TOOL_ARG_KEYS[toolName] || ['query'];
  const result = {};
  const tokens = splitInlineArgs(text);
  tokens.forEach((token, index) => {
    const colonIndex = token.indexOf(':');
    if (colonIndex > 0) {
      const key = token.slice(0, colonIndex).trim().replace(/^['"`]|['"`]$/g, '');
      const value = parseInlineValue(token.slice(colonIndex + 1).trim());
      if (key) result[key] = value;
      return;
    }
    const key = orderedKeys[index] || `arg${index + 1}`;
    result[key] = parseInlineValue(token);
  });
  return result;
}

function mapInlineToolName(name = '') {
  const normalized = String(name || '').trim().toLowerCase();
  if (!normalized) return '';
  return INLINE_TOOL_NAME_ALIASES[normalized] || normalized;
}

// interceptOllamaToolCode removed — Ollama retired 2026-03-25

// ─── STREAMING HELPERS ────────────────────────────────────────────────────────

export async function emitTextChunks(text, onToken) {
  if (typeof onToken !== 'function') return;
  const value = String(text || '');
  if (!value) return;
  const chunks = value.match(/.{1,24}(\s|$)/g) || [value];
  for (const chunk of chunks) {
    const token = String(chunk || '');
    if (!token) continue;
    onToken(token);
  }
}

// ─── NORMALIZE HELPERS ────────────────────────────────────────────────────────

function normalizeOpenAIMessages(messages = []) {
  if (!Array.isArray(messages) || messages.length === 0) return [];
  return messages
    .filter((entry) => entry && typeof entry.role === 'string' && typeof entry.content === 'string')
    .map((entry) => {
      const role = entry.role === 'assistant' ? 'assistant' : (entry.role === 'system' ? 'system' : 'user');
      return { role, content: String(entry.content || '').trim() };
    })
    .filter((entry) => entry.content.length > 0);
}

function buildGeminiPayload(messages = [], fallbackUserPrompt = '') {
  const normalized = normalizeOpenAIMessages(messages);
  const systemText = normalized
    .filter((entry) => entry.role === 'system')
    .map((entry) => entry.content)
    .join('\n\n')
    .trim();
  const contents = normalized
    .filter((entry) => entry.role !== 'system')
    .map((entry) => ({
      role: entry.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: entry.content }]
    }));

  if (contents.length === 0) {
    const fallback = String(fallbackUserPrompt || '').trim();
    if (fallback) {
      contents.push({ role: 'user', parts: [{ text: fallback }] });
    }
  }

  const systemInstruction = systemText
    ? { parts: [{ text: systemText }] }
    : undefined;

  const latestUserPrompt =
    [...normalized].reverse().find((entry) => entry.role === 'user')?.content
    || String(fallbackUserPrompt || '');

  return {
    systemInstruction,
    contents,
    latestUserPrompt
  };
}

function renderPromptFromMessages(messages = []) {
  const normalized = normalizeOpenAIMessages(messages);
  if (!normalized.length) return '';
  return normalized
    .map((entry) => `${entry.role.toUpperCase()}: ${entry.content}`)
    .join('\n\n');
}

// ─── GEMINI STREAMING ─────────────────────────────────────────────────────────

async function streamGeminiPrompt(model, messages, onToken, toolExecutionOptions = {}) {
  const credential = checkoutCachedCredential('gemini_api_key')
    || checkoutCachedCredential('google_api_key');
  if (!credential) throw new Error('Gemini credential missing');
  const geminiPayload = buildGeminiPayload(messages);
  const requestBody = {
    contents: geminiPayload.contents,
    ...(geminiPayload.systemInstruction ? { systemInstruction: geminiPayload.systemInstruction } : {})
  };
  const useContext = toolExecutionOptions.credentialUseContext || {};
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'gemini_stream_generate_content',
    endpoint: `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent`,
    requestHash: credentialUseEvidenceHash({ method: 'POST', model, alt: 'sse', body: requestBody }),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });
  let res;
  try {
    res = await fetchWithTimeout(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${credential.value}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      }
    , MODEL_PROVIDER_REQUEST_TIMEOUT_MS);
  } catch (error) {
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
      outcomeClass: 'transport_error',
      errorClass: error?.name || 'transport_error',
    });
    throw error;
  }
  try {
    if (!res.ok) {
      const errorText = await res.text();
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(errorText) }),
        outcomeClass: `http_${res.status}`,
      });
      throw new Error(`Gemini stream error (${res.status}): ${errorText}`);
    }

    if (!res.body) {
      throw new Error('Gemini stream response body missing');
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let full = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('data:')) continue;
        const payload = line.slice(5).trim();
        if (!payload || payload === '[DONE]') continue;

        let parsed;
        try {
          parsed = JSON.parse(payload);
        } catch {
          continue;
        }

        const text = parsed?.candidates?.[0]?.content?.parts
          ?.map((part) => (typeof part?.text === 'string' ? part.text : ''))
          .join('') || '';
        if (!text) continue;

        const delta = text.startsWith(full) ? text.slice(full.length) : text;
        if (!delta) continue;
        full += delta;
        if (typeof onToken === 'function') onToken(delta);
      }
    }

    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(full) }),
      outcomeClass: `http_${res.status}`,
    });
    return full;
  } catch (error) {
    if (!res.ok) throw error;
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'stream_processing_error' }),
      outcomeClass: 'stream_processing_error',
      errorClass: error?.name || 'stream_processing_error',
    });
    throw error;
  }
}

// ─── PROVIDER-SPECIFIC TOOL PATHS ───────────────────────────────────────────



// ─── GEMINI WITH TOOLS ────────────────────────────────────────────────────────

async function runGeminiWithTools(agent, messages, toolDefs, toolExecutionOptions = {}, onToken = null) {
  const credential = checkoutCachedCredential('gemini_api_key')
    || checkoutCachedCredential('google_api_key');
  if (!credential) throw new Error('Gemini credential missing');
  const model = agent.model.startsWith('gemini') ? agent.model : agent.model;
  const geminiPayload = buildGeminiPayload(messages);

  const functionDeclarations = toolDefs.map(t => ({
    name: t.schema.function.name,
    description: t.schema.function.description,
    parameters: t.schema.function.parameters
  }));

  if (functionDeclarations.length === 0 && typeof onToken === 'function') {
    return streamGeminiPrompt(model, messages, onToken, toolExecutionOptions);
  }

  let contents = [...geminiPayload.contents];

  for (let loop = 0; loop < MAX_TOOL_LOOPS; loop++) {
    const body = {
      contents,
      tools: functionDeclarations.length > 0 ? [{ functionDeclarations }] : undefined,
      ...(geminiPayload.systemInstruction ? { systemInstruction: geminiPayload.systemInstruction } : {})
    };

    const useContext = toolExecutionOptions.credentialUseContext || {};
    const reservation = await credentialLedger.reserveCredentialUse({
      ...credential,
      operation: 'gemini_generate_content',
      endpoint: `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
      requestHash: credentialUseEvidenceHash({ method: 'POST', model, body }),
      subjectAgentId: useContext.actorAgentId || 'housekeeper',
      requestReceiptId: useContext.requestReceiptId || null,
      requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
      requestAdmissionEventId: useContext.requestAdmissionEventId || null,
      requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
      autonomousActionEventId: useContext.autonomousActionEventId || null,
    });
    let res;
    try {
      res = await fetchWithTimeout(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${credential.value}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
      , MODEL_PROVIDER_REQUEST_TIMEOUT_MS);
    } catch (error) {
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
        outcomeClass: 'transport_error',
        errorClass: error?.name || 'transport_error',
      });
      throw error;
    }
    let data;
    try {
      const responseText = await res.text();
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(responseText) }),
        outcomeClass: `http_${res.status}`,
      });
      if (!res.ok) throw new Error(`Gemini error (${res.status}): ${responseText}`);
      data = JSON.parse(responseText);
    } catch (error) {
      if (!res.ok) throw error;
      throw new Error(`Gemini response invalid: ${error?.message || error}`);
    }
    const parts = data.candidates?.[0]?.content?.parts || [];

    const fnCalls = parts.filter(p => p.functionCall);
    if (fnCalls.length === 0) {
      const finalText = parts.map(p => p.text || '').join('').trim();
      if (typeof onToken === 'function') await emitTextChunks(finalText, onToken);
      return finalText;
    }

    contents.push({ role: 'model', parts });

    const toolResponseParts = await Promise.all(fnCalls.map(async (part) => {
      let result;
      try {
        result = await executeTool(part.functionCall.name, part.functionCall.args || {}, agent.id, toolExecutionOptions);
        if (isToolApprovalRequired(result)) {
          throw createToolApprovalError(part.functionCall.name, result);
        }
      } catch (err) {
        if (err?.code === 'TOOL_APPROVAL_REQUIRED') throw err;
        result = { error: err.message };
      }
      return {
        functionResponse: {
          name: part.functionCall.name,
          response: { result: JSON.stringify(result) }
        }
      };
    }));
    contents.push({ role: 'user', parts: toolResponseParts });
  }

  return loopExhaustedResult(model);
}

// ─── MODEL DISPATCH ───────────────────────────────────────────────────────────

function summarizeModelError(error, maxLength = 220) {
  const raw = String(error?.message || error || 'unknown error')
    .replace(/\s+/g, ' ')
    .trim();
  if (!raw) return 'unknown error';
  if (raw.length <= maxLength) return raw;
  return `${raw.slice(0, maxLength - 3)}...`;
}

export async function runByModel(agent, systemPrompt, userPrompt, toolDefs, messages, modelOverride = null, toolExecutionOptions = {}, onToken = null) {
  // Preserve the caller-selected model so live smoke tests and production runs
  // exercise the real provider path instead of a temporary rebuild override.
  const requestedModel = modelOverride || agent.model || systemConfigStore.readConfigString('LLM_MODEL') || '';
  const providerResolution = resolveProviderForModel(requestedModel, '');
  const providerKey = providerResolution.provider || '';
  const resolvedModel = providerResolution.model || requestedModel;
  const runtimeAgent = { ...agent, model: resolvedModel };
  const normalizeResult = (result) => {
    if (result && typeof result === 'object' && ('response' in result || 'model' in result)) {
      return {
        response: result.response ?? '',
        model: result.model || resolvedModel
      };
    }
    return {
      response: result,
      model: resolvedModel
    };
  };

  if (providerKey === 'gemini') {
    return normalizeResult(
      await runGeminiWithTools(runtimeAgent, messages, toolDefs, toolExecutionOptions, onToken)
    );
  }
  if (providerKey === 'perplexity') {
    const allToolDefs = Array.isArray(toolDefs) ? toolDefs : [];
    const promptLower = String(userPrompt || '').toLowerCase();
    const requestedToolDefs = allToolDefs.filter((toolDef) => {
      const toolName = String(toolDef?.schema?.function?.name || '').toLowerCase();
      return toolName && promptLower.includes(toolName);
    });
    const activeToolDefs = requestedToolDefs.length > 0 ? requestedToolDefs : [];
    const toolList = activeToolDefs
      .map((toolDef) => `- ${toolDef?.schema?.function?.name}: ${toolDef?.schema?.function?.description || ''}`)
      .filter((line) => !line.includes('undefined'))
      .join('\n');
    const sonarSystemPrompt = [
      `You are ${runtimeAgent.name}.`,
      `Persona: ${runtimeAgent.persona}`,
      'Follow system and user instructions exactly.',
      'Never identify yourself as Perplexity or mention provider limitations.',
      'If the user asks for an exact output string, return exactly that string with no extra text.',
      'Use available tools when the user asks for tool actions.',
      toolList ? `Available tools:\n${toolList}` : ''
    ].join('\n\n');

    return normalizeResult(
      await runProvider({
        provider: 'perplexity',
        model: resolvedModel,
        messages,
        systemPrompt: sonarSystemPrompt,
        userPrompt,
        toolDefs: activeToolDefs,
        onToken,
        useContext: toolExecutionOptions.credentialUseContext || {},
        toolExecutionOptions: {
          ...toolExecutionOptions,
          returnAfterSingleToolCall: activeToolDefs.length > 0,
          forcedToolName: activeToolDefs.length === 1
            ? String(activeToolDefs[0]?.schema?.function?.name || '')
            : '',
          executeToolFn: async (name, args) => {
            const result = await executeTool(name, args, runtimeAgent.id, toolExecutionOptions);
            if (isToolApprovalRequired(result)) {
              throw createToolApprovalError(name, result);
            }
            return result;
          }
        }
      })
    );
  }
  return normalizeResult(
    await runProvider({
      provider: providerKey,
      model: resolvedModel,
      messages,
      systemPrompt,
      userPrompt,
      toolDefs,
      onToken,
      useContext: toolExecutionOptions.credentialUseContext || {},
      toolExecutionOptions: {
        ...toolExecutionOptions,
        executeToolFn: async (name, args) => {
          const result = await executeTool(name, args, runtimeAgent.id, toolExecutionOptions);
          if (isToolApprovalRequired(result)) {
            throw createToolApprovalError(name, result);
          }
          return result;
        }
      }
    })
  );
}

export function buildConversationMessagesForFallback(history = []) {
  if (!Array.isArray(history) || history.length === 0) return [];
  return history
    .filter((turn) => turn && typeof turn.role === 'string' && typeof turn.content === 'string')
    .map((turn) => ({
      role: turn.role === 'assistant' ? 'assistant' : 'user',
      content: String(turn.content || '')
    }))
    .filter((turn) => turn.content.trim().length > 0);
}

export async function runAgentWithFallback(agent, systemPrompt, userPrompt, toolDefs, options = {}) {
  const conversationMessages = Array.isArray(options.conversationMessages)
    ? options.conversationMessages
    : buildConversationMessagesForFallback(options.conversationHistory);
  const messages = [
    { role: 'system', content: systemPrompt },
    ...conversationMessages,
    { role: 'user', content: userPrompt }
  ];

  const requestedPlan = Array.isArray(options.modelPlan)
    ? options.modelPlan
    : (options.model ? [options.model] : []);
  let modelPlan = Array.from(new Set([...requestedPlan, agent.model].filter(Boolean)));

  if (!options.strictRequestedModel && options.preferredModel) {
    modelPlan = Array.from(new Set([options.preferredModel, ...modelPlan].filter(Boolean)));
  }

  if (options.strictRequestedModel) {
    const strictModel = options.requestedModel || agent.model;
    modelPlan = strictModel ? [strictModel] : [];
  }

  const candidates = modelPlan.length ? modelPlan : [agent.model];
  const brokenCandidates = [];
  const runnableCandidates = [];

  for (const modelId of candidates) {
    if (isModelCircuitBroken(modelId)) {
      const count = pruneModelFailureHistory(modelId).length;
      console.warn(`[CircuitBreaker] Skipping ${modelId} — ${count} failures in last 5m`);
      brokenCandidates.push(modelId);
      continue;
    }
    runnableCandidates.push(modelId);
  }

  const executionCandidates = runnableCandidates.length ? runnableCandidates : candidates;
  if (!runnableCandidates.length && brokenCandidates.length) {
    resetModelCircuitBreaker(brokenCandidates);
  }

  const failures = [];

  for (const modelId of executionCandidates) {
    try {
      const result = await runByModel(
        agent,
        systemPrompt,
        userPrompt,
        toolDefs,
        messages,
        modelId,
        options.toolExecutionOptions || {},
        options.onToken || null
      );
      return result;
    } catch (error) {
      if (error?.code === 'TOOL_APPROVAL_REQUIRED') throw error;
      const reason = summarizeModelError(error);
      failures.push({ model: modelId, reason });
      recordModelFailure(modelId);
      console.warn(`[AgentRunner] model candidate failed`, {
        agentId: agent.id,
        model: modelId,
        reason
      });
      continue;
    }
  }

  const summary = failures
    .map((failure, index) => `${index + 1}. ${failure.model}: ${failure.reason}`)
    .join(' | ');

  const message = summary
    ? `All candidate models failed for this run. ${summary}`
    : 'All candidate models failed for this run.';

  const error = new Error(message);
  error.code = 'MODEL_FALLBACK_EXHAUSTED';
  error.failures = failures;
  throw error;
}
