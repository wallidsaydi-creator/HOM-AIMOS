/**
 * agent-executive-fast-path.js — Executive Agent Fast-Path (Gap 4 extraction)
 *
 * Handles deterministic short-circuit responses for executive agent prompts:
 * remember, recall-self, latest-email, sender-followup, model-identity, etc.
 * These bypass the full LLM pipeline for simple, predictable commands.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (before LLM pipeline)
 * 2. → Calls: tool-registry.js (executeTool for aimos_save, aimos_recall, gmail_inbox)
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: pre-LLM fast-path
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { executeTool } from './tool-registry.js';
import { getOperatorAgentId, isOperatorAgentId } from '../security/system-config-store.js';
import { shouldBlockToolForMissingKnowledge } from '../security/knowledge-gate.js';

// ─── PROMPT CLASSIFICATION HELPERS ──────────────────────────────────────────────

export function isExecutiveRememberPrompt(prompt = '') {
  return /^\s*remember\b/i.test(String(prompt || '').trim());
}

export function isExecutiveRecallSelfPrompt(prompt = '') {
  const value = String(prompt || '').trim().toLowerCase();
  return (
    value.includes('what do you know about me')
    || value.includes('what do you remember about me')
    || value.includes('what do you know abt me')
  );
}

export function isExecutiveLatestEmailPrompt(prompt = '') {
  const value = String(prompt || '').toLowerCase();
  return (
    /\b(last|latest|recent)\b.*\b(email|gmail)\b/.test(value)
    || /\b(email|gmail)\b.*\b(last|latest|recent)\b/.test(value)
  );
}

export function isExecutiveSenderFollowupPrompt(prompt = '') {
  return /^\s*who\s+sent\s+it\??\s*$/i.test(String(prompt || ''));
}

export function isExecutiveModelIdentityPrompt(prompt = '') {
  const value = String(prompt || '').toLowerCase();
  return (
    /\bwhat\s+model\b/.test(value)
    || /\bwhich\s+model\b/.test(value)
    || /\bmodel\s+are\s+you\b/.test(value)
  );
}

export function isExecutiveModelCountPrompt(prompt = '') {
  const value = String(prompt || '').toLowerCase();
  return (
    /\bhow\s+many\b.*\b(models|agents)\b/.test(value)
    || /\bnumber\b.*\b(models|agents)\b/.test(value)
    || /\bhive\s*mind\b/.test(value)
  );
}

export function isExecutiveBuilderPrompt(prompt = '') {
  return /\bwho\s+built\s+you\b/i.test(String(prompt || ''));
}

export function isExecutiveContactsPrompt(prompt = '') {
  const value = String(prompt || '').toLowerCase();
  return /\bcontacts?\b/.test(value) && /\b(can|access|read|see|open)\b/.test(value);
}

export function isExecutiveInstagramPostPrompt(prompt = '') {
  const value = String(prompt || '').toLowerCase();
  return /\binstagram\b/.test(value) && /\b(post|publish|share)\b/.test(value);
}

// ─── CONTENT HELPERS ─────────────────────────────────────────────────────────────

export function trimRememberContent(prompt = '') {
  const text = String(prompt || '').trim();
  const stripped = text.replace(/^remember\b[:\s-]*/i, '').trim();
  return stripped || '';
}

export function compactSingleLine(text = '') {
  return String(text || '').replace(/\s+/g, ' ').trim();
}

export function extractRememberFactsFromHistory(history = [], { isInternalMemoryText } = {}) {
  if (!Array.isArray(history) || history.length === 0) return [];
  const facts = [];
  const seen = new Set();
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const turn = history[i];
    if (!turn || String(turn.role || '').toLowerCase() !== 'user') continue;
    const content = String(turn.content || '').trim();
    if (!isExecutiveRememberPrompt(content)) continue;
    const fact = compactSingleLine(trimRememberContent(content));
    if (!fact || seen.has(fact)) continue;
    seen.add(fact);
    facts.push(fact);
    if (facts.length >= 5) break;
  }
  return facts;
}

// ─── DETERMINISTIC EXECUTIVE FAST-PATH ──────────────────────────────────────────

/**
 * Handle deterministic short-circuit prompts for the executive agent.
 * Returns { response: string } for handled prompts, or null for unhandled.
 *
 * @param {Object} runtimeAgent - Agent object with id
 * @param {string} userPrompt - User prompt text
 * @param {Object} toolExecutionOptions - Options for tool execution
 * @param {Function} isInternalMemoryText - Filter for internal memory text
 * @returns {Promise<{response: string}|null>}
 */
export async function runDeterministicExecutiveFastPath(runtimeAgent, userPrompt, toolExecutionOptions = {}, isInternalMemoryTextFn = null) {
  const prompt = String(userPrompt || '').trim();
  if (!prompt) return null;
  const operator = isOperatorAgentId(runtimeAgent.id);
  if (!operator && !isExecutiveRememberPrompt(prompt) && !isExecutiveRecallSelfPrompt(prompt)) return null;

  if (operator && isExecutiveModelIdentityPrompt(prompt)) {
    return { response: `I'm ${getOperatorAgentId() || 'the assistant'}, your AI assistant.` };
  }

  if (operator && isExecutiveModelCountPrompt(prompt)) {
    return {
      response: `I'm ${getOperatorAgentId() || 'the assistant'}, and I can help with execution directly: email, calendar, web research, memory, and task coordination.`
    };
  }

  if (operator && isExecutiveBuilderPrompt(prompt)) {
    return { response: `I'm ${getOperatorAgentId() || 'the assistant'}, the operator's designated agent.` };
  }

  if (operator && isExecutiveContactsPrompt(prompt)) {
    return {
      response: "Contacts access isn't available yet. I can check your Gmail inbox or review your calendar instead."
    };
  }

  if (operator && isExecutiveInstagramPostPrompt(prompt)) {
    return {
      response: "Instagram posting isn't available yet. I can post to X/Twitter or send a Telegram message instead."
    };
  }

  if (operator && (isExecutiveLatestEmailPrompt(prompt) || isExecutiveSenderFollowupPrompt(prompt))) {
    const inbox = await executeTool(
      'gmail_inbox',
      { max: 1 },
      runtimeAgent.id,
      toolExecutionOptions
    );
    const latest = Array.isArray(inbox) ? inbox[0] : null;
    if (!latest) {
      return {
        response: 'I checked your inbox, but there are no recent emails.'
      };
    }
    const subject = compactSingleLine(latest.subject || '(No subject)');
    const from = compactSingleLine(latest.from || 'Unknown sender');
    if (isExecutiveSenderFollowupPrompt(prompt)) {
      return { response: `The last email was sent by ${from}.` };
    }
    return {
      response: `Your latest email is "${subject}" from ${from}.`
    };
  }

  if (isExecutiveRememberPrompt(prompt)) {
    const content = trimRememberContent(prompt);
    if (!content) {
      return { response: 'Tell me what you want me to remember.' };
    }
    if (toolExecutionOptions.allowedTools?.includes('aimos_save')
      && shouldBlockToolForMissingKnowledge(toolExecutionOptions.knowledgeGateState,'aimos_save').blocked) {
      // Satisfy the existing knowledge gate with an actual signed native read.
      // Prefetched context is not relabeled as a tool execution or a grant.
      await executeTool('aimos_recall',{ query:content,limit:5 },runtimeAgent.id,toolExecutionOptions);
    }
    const save = await executeTool(
      'aimos_save',
      { content },
      runtimeAgent.id,
      toolExecutionOptions
    );
    if (save?.success) {
      return { response: `Saved. I'll remember: ${content}` };
    }
    return {
      response: `I couldn't save that memory: ${save?.error || 'unknown error'}`
    };
  }

  if (isExecutiveRecallSelfPrompt(prompt)) {
    const historyFacts = extractRememberFactsFromHistory(
      toolExecutionOptions.conversationHistory,
      { isInternalMemoryText: isInternalMemoryTextFn }
    );
    const recalled = await executeTool(
      'aimos_recall',
      { query: 'me preferences identity profile', limit: 5 },
      runtimeAgent.id,
      toolExecutionOptions
    );
    if (recalled?.error || recalled?.blocked || recalled?.success === false) {
      return { response: `I couldn't recall your memory: ${recalled?.error || 'native recall denied'}` };
    }
    const memories = Array.isArray(recalled)
      ? recalled
      : (Array.isArray(recalled?.memories) ? recalled.memories : []);
    if (!memories.length) {
      return { response: "I don't have any saved personal memory for you yet." };
    }
    const lines = memories
      .slice(0, 3)
      .map((m) => compactSingleLine(m?.content || m?.value || m?.key || ''))
      .filter((line) => isInternalMemoryTextFn ? !isInternalMemoryTextFn(line) : true)
      .filter(Boolean);
    const merged = [];
    const seen = new Set();
    for (const value of [...historyFacts, ...lines]) {
      if (!value || seen.has(value)) continue;
      seen.add(value);
      merged.push(value);
    }
    if (!merged.length) {
      return { response: "I don't have any saved personal memory for you yet." };
    }
    return {
      response: `Here's what I know about you: ${merged.slice(0, 3).join(' | ')}`
    };
  }

  return null;
}
