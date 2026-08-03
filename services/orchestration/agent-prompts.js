/**
 * agent-prompts.js
 * Source: Prompt Engineering (OpenAI), In-context learning, RAG patterns
 *
 * System prompt assembly, procedural skill loading, Aimos context loading,
 * and all supporting build* helpers.
 *
 * Imported by agent-runner.js — not a public API surface.
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run steps 9, 13)
// → Calls: services/core/embeddings.js (context embedding for retrieval)
// Pipeline: AGENT_RUN_PIPELINE
// Position: context load + skills load
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { agents } from './agent-store.js';
import { getEmbedding } from '../core/embeddings.js';
import { query } from '../../db/connection.js';
import { buildHomConstitutionSection } from '../core/hom-constitution.js';
import { getRecencyAlpha, getSemanticAlpha, getMemoryCount, getEventWindowHours } from '../shared/scale-baseline.js';
import { getOperatorAgentId, isOperatorAgentId } from '../security/system-config-store.js';

const BRAIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES_ROOT = path.join(BRAIN_ROOT, 'rules');
const COMPANY = AIMOS_COMPANY_ID;

// ─── MEMORY LIMITS ─────────────────────────────────────────────────────────
const MEMORY_CONTEXT_ITEM_LIMIT = 8;
const MEMORY_CONTEXT_ITEM_CHAR_LIMIT = 2_000;
const MEMORY_CONTEXT_TOTAL_CHAR_BUDGET = 12_000;
const MAX_TOTAL_ASSEMBLED_CHARS = 48_000;

const INTERNAL_MEMORY_PATTERNS = [
  /\[INTERNAL\]/i,
  /\bhive mind\b/i,
  /\bprovider\b/i,
  /\bclearance\b/i,
  /\bmodel roster\b/i,
  /\b34-model\b/i,
  /\bcodex magenta\b/i,
  /\breviewer\b/i
];

// ─── SECRET REDACTION ─────────────────────────────────────────────────────────
const SECRET_REDACT_PATTERNS = [
  /sk_live_[A-Za-z0-9]{20,}/g,
  /sk_test_[A-Za-z0-9]{20,}/g,
  /AIza[0-9A-Za-z\-_]{35,}/g,
  /ghp_[A-Za-z0-9]{36,}/g,
  /xox[baprs]-[0-9A-Za-z]{10,}/g,
  /"access_token"\s*:\s*"[^"]{20,}"/gi,
  /"refresh_token"\s*:\s*"[^"]{20,}"/gi,
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----/g,
];

export function redactSecrets(text) {
  let out = String(text || '');
  for (const pat of SECRET_REDACT_PATTERNS) {
    out = out.replace(pat, '[REDACTED]');
  }
  return out;
}

export function isInternalMemoryText(value = '') {
  const text = String(value || '');
  if (!text) return false;
  return INTERNAL_MEMORY_PATTERNS.some((pattern) => pattern.test(text));
}

export function compactText(input, limit = 400) {
  const normalized = String(input || '')
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length <= limit) return normalized;
  const headSize = Math.max(40, Math.floor(limit * 0.72));
  const tailSize = Math.max(20, limit - headSize - 5);
  return `${normalized.slice(0, headSize)} ... ${normalized.slice(-tailSize)}`;
}

export function buildEmptyContextPack() {
  return {
    text: '',
    contextCompaction: {
      compacted: false,
      rawChars: 0,
      compactedChars: 0,
      ratio: 1,
      keptItems: 0,
      totalItems: 0
    }
  };
}

/**
 * Partition memories by tier (MemGPT 3-tier architecture).
 * Working = current session, Recall = recent conversations, Archival = long-term knowledge.
 */
function partitionByTier(rows) {
  const working = [];  // memory_tier = 'working' or 'short-term'
  const recall = [];   // memory_tier = 'episodic' or recent event_log
  const archival = []; // everything else (long-term, procedural, tacit_knowledge)

  for (const row of rows) {
    const tier = String(row.memory_tier || '').toLowerCase();
    const type = String(row.memory_type || '').toLowerCase();

    if (tier === 'working' || tier === 'short-term') {
      working.push(row);
    } else if (type === 'event_log' || type === 'episodic' || tier === 'episodic') {
      recall.push(row);
    } else {
      archival.push(row);
    }
  }

  return { working, recall, archival };
}

export async function loadRecentAimosContext(sourceAgentId, runtimeAgentId, limit = 8) {
  const emptyPack = buildEmptyContextPack();

  try {
    const sourceId = String(sourceAgentId || '').trim();
    const runtimeId = String(runtimeAgentId || '').trim();
    const ids = Array.from(new Set([sourceId, runtimeId].filter(Boolean)));
    if (!ids.length) return emptyPack;

    // Fetch more than limit to allow tier budget allocation
    const fetchLimit = Math.max(1, Number(limit || 8)) * 3;
    const result = await query(
      `SELECT agent_id, value, memory_tier, memory_type
       FROM aimos_memories
       WHERE company_id = $1
         AND (
           agent_id = ANY($2::text[])
           OR scope = 'global'
         )
       ORDER BY created_at DESC
       LIMIT $3`,
      [COMPANY, ids, fetchLimit]
    );

    const prepared = result.rows
      .map((row) => ({
        agentId: String(row.agent_id || 'unknown').trim(),
        rawValue: String(row.value || '').trim(),
        memory_tier: row.memory_tier || 'long-term',
        memory_type: row.memory_type || 'unknown'
      }))
      .filter((row) => row.rawValue.length > 0)
      .filter((row) => !isInternalMemoryText(row.rawValue))
      .map((row) => ({ ...row, rawValue: redactSecrets(row.rawValue) }));

    // Fix #3: Tier partitioning with budget allocation
    const { working, recall, archival } = partitionByTier(prepared);
    const effectiveLimit = Math.max(1, Number(limit || 8));
    const workingBudget = Math.max(1, Math.ceil(effectiveLimit * 0.5));   // 50%
    const recallBudget = Math.max(1, Math.ceil(effectiveLimit * 0.3));    // 30%
    const archivalBudget = Math.max(1, effectiveLimit - workingBudget - recallBudget); // 20%

    const rawChars = prepared.reduce((sum, row) => sum + row.rawValue.length, 0);
    const lines = [];
    let compactedChars = 0;

    function addTierSection(tierName, items, budget) {
      if (!items.length) return;
      lines.push(`**[${tierName}]**`);
      let count = 0;
      for (const row of items) {
        if (count >= budget) break;
        const compacted = compactText(row.rawValue, MEMORY_CONTEXT_ITEM_CHAR_LIMIT);
        const line = `- [${row.agentId}] ${compacted}`;
        const nextChars = compactedChars + line.length;
        if (nextChars > MEMORY_CONTEXT_TOTAL_CHAR_BUDGET) break;
        lines.push(line);
        compactedChars = nextChars;
        count++;
      }
    }

    addTierSection('WORKING', working, workingBudget);
    addTierSection('RECALL', recall, recallBudget);
    addTierSection('ARCHIVAL', archival, archivalBudget);

    const ratio = rawChars > 0 ? Math.max(0, Math.min(1, compactedChars / rawChars)) : 1;
    return {
      text: lines.join('\n'),
      memories: prepared, // Return raw memories for quantization
      contextCompaction: {
        compacted: compactedChars < rawChars || lines.length < prepared.length,
        rawChars,
        compactedChars,
        ratio,
        keptItems: lines.length,
        totalItems: prepared.length,
        tiers: { working: working.length, recall: recall.length, archival: archival.length }
      }
    };
  } catch {
    return emptyPack;
  }
}

// ─── HYBRID RECALL: Semantic-aware context injection (Gap 1) ──────────────────
// Replaces pure chronological ranking with composite recency+semantic scoring.
// Falls back to loadRecentAimosContext on embedding failure.
// Aladdin: only affects recall ordering, never deletes or suppresses memories.

const K_RECENCY = 60; // RRF constant for recency rank scoring

export async function loadHybridAimosContext(sourceAgentId, runtimeAgentId, userPrompt, limit = 8) {
  const emptyPack = buildEmptyContextPack();

  try {
    const sourceId = String(sourceAgentId || '').trim();
    const runtimeId = String(runtimeAgentId || '').trim();
    const ids = Array.from(new Set([sourceId, runtimeId].filter(Boolean)));
    if (!ids.length || !userPrompt) return emptyPack;

    // Compute query embedding for semantic similarity
    let queryEmbedding;
    try {
      queryEmbedding = await getEmbedding(String(userPrompt));
    } catch (embErr) {
      // Fallback to pure recency on embedding failure
      console.warn('[hybrid-recall] Embedding failed, falling back to pure recency:', embErr.message);
      return loadRecentAimosContext(sourceAgentId, runtimeAgentId, limit);
    }
    if (!queryEmbedding || !Array.isArray(queryEmbedding) || queryEmbedding.length === 0) {
      return loadRecentAimosContext(sourceAgentId, runtimeAgentId, limit);
    }

    // Phase 1: Fetch candidate pool (3x over budget for re-ranking)
    const fetchLimit = Math.max(1, Number(limit || 8)) * 3;
    const result = await query(
      `SELECT m.id, m.agent_id, m.value, m.memory_tier, m.memory_type,
              m.created_at,
              (m.embedding <=> $4::vector) AS semantic_distance
       FROM aimos_memories m
       WHERE m.company_id = $1
         AND (m.agent_id = ANY($2::text[]) OR m.scope = 'global')
         AND m.embedding IS NOT NULL
       ORDER BY (m.embedding <=> $4::vector) ASC
       LIMIT $3`,
      [COMPANY, ids, fetchLimit, JSON.stringify(queryEmbedding)]
    );

    if (!result.rows || result.rows.length === 0) {
      // No candidates with embeddings — fall back to recency
      return loadRecentAimosContext(sourceAgentId, runtimeAgentId, limit);
    }

    // Phase 2: JavaScript re-ranking with composite score
    const memoryCount = await getMemoryCount(COMPANY);
    const alphaRecency = getRecencyAlpha(memoryCount);
    const alphaSemantic = getSemanticAlpha(memoryCount);

    // Build recency ranking by created_at
    const byCreatedAt = [...result.rows].sort((a, b) =>
      new Date(b.created_at) - new Date(a.created_at)
    );
    const recencyRankMap = new Map();
    byCreatedAt.forEach((row, idx) => {
      recencyRankMap.set(row.id, idx + 1);
    });

    // Compute composite scores
    for (const row of result.rows) {
      const recencyRank = recencyRankMap.get(row.id) || byCreatedAt.length;
      const recencyScore = K_RECENCY / (K_RECENCY + recencyRank);
      const semanticScore = 1 - (parseFloat(row.semantic_distance) || 1);
      row.compositeScore = alphaRecency * recencyScore + alphaSemantic * semanticScore;
    }

    // Sort by composite score descending
    const ranked = result.rows.sort((a, b) => b.compositeScore - a.compositeScore);

    const prepared = ranked
      .map((row) => ({
        agentId: String(row.agent_id || 'unknown').trim(),
        rawValue: String(row.value || '').trim(),
        memory_tier: row.memory_tier || 'long-term',
        memory_type: row.memory_type || 'unknown',
        compositeScore: row.compositeScore,
      }))
      .filter((row) => row.rawValue.length > 0)
      .filter((row) => !isInternalMemoryText(row.rawValue))
      .map((row) => ({ ...row, rawValue: redactSecrets(row.rawValue) }));

    // Tier budget allocation (same 50/30/20 as recency path)
    const { working, recall, archival } = partitionByTier(prepared);
    const effectiveLimit = Math.max(1, Number(limit || 8));
    const workingBudget = Math.max(1, Math.ceil(effectiveLimit * 0.5));
    const recallBudget = Math.max(1, Math.ceil(effectiveLimit * 0.3));
    const archivalBudget = Math.max(1, effectiveLimit - workingBudget - recallBudget);

    const rawChars = prepared.reduce((sum, row) => sum + row.rawValue.length, 0);
    const lines = [];
    let compactedChars = 0;

    function addTierSection(tierName, items, budget) {
      if (!items.length) return;
      lines.push(`**[${tierName}]**`);
      let count = 0;
      for (const row of items) {
        if (count >= budget) break;
        const compacted = compactText(row.rawValue, MEMORY_CONTEXT_ITEM_CHAR_LIMIT);
        const line = `- [${row.agentId}] ${compacted}`;
        const nextChars = compactedChars + line.length;
        if (nextChars > MEMORY_CONTEXT_TOTAL_CHAR_BUDGET) break;
        lines.push(line);
        compactedChars = nextChars;
        count++;
      }
    }

    addTierSection('WORKING', working, workingBudget);
    addTierSection('RECALL', recall, recallBudget);
    addTierSection('ARCHIVAL', archival, archivalBudget);

    // ─── Gap 2: Aimos Events Bridge — inject recent save actions ────────────────
    let recentActionsText = '';
    let recentActionsEvents = [];
    try {
      const eventWindow = getEventWindowHours(memoryCount);
      const recentActions = await loadRecentSaveEvents(runtimeId, 5, eventWindow);
      if (recentActions.text) {
        lines.push('');
        lines.push('**[RECENT ACTIONS]**');
        lines.push(recentActions.text);
        recentActionsText = recentActions.text;
        recentActionsEvents = recentActions.events;
      }
    } catch (evtErr) {
      console.warn('[hybrid-recall] Events bridge failed (non-fatal):', evtErr.message);
    }

    const ratio = rawChars > 0 ? Math.max(0, Math.min(1, compactedChars / rawChars)) : 1;
    return {
      text: lines.join('\n'),
      memories: prepared,
      recentSaveEvents: recentActionsEvents,
      contextCompaction: {
        compacted: compactedChars < rawChars || lines.length < prepared.length,
        rawChars,
        compactedChars,
        ratio,
        keptItems: lines.length,
        totalItems: prepared.length,
        tiers: { working: working.length, recall: recall.length, archival: archival.length },
        hybridRecall: {
          alphaRecency: Number(alphaRecency.toFixed(6)),
          alphaSemantic: Number(alphaSemantic.toFixed(6)),
          memoryCount,
          candidatePool: result.rows.length,
        },
        eventsBridge: {
          eventCount: recentActionsEvents.length,
          windowHours: getEventWindowHours(memoryCount),
        },
      },
    };
  } catch (err) {
    console.warn('[hybrid-recall] Failed, falling back to pure recency:', err.message);
    return loadRecentAimosContext(sourceAgentId, runtimeAgentId, limit);
  }
}

// ─── AIMOS EVENTS BRIDGE: Memory-of-saving loop (Gap 2) ────────────────────
// Loads recent save/correction/consolidation events from aimos_events.
// Pure additive awareness — no deletion, no modification of existing memories.

/**
 * Extract a short summary from event metadata JSON.
 * @param {string|Object} metadata - Event metadata
 * @returns {string} Short summary string
 */
function extractEventSummary(metadata) {
  try {
    const obj = typeof metadata === 'string' ? JSON.parse(metadata) : metadata;
    if (!obj || typeof obj !== 'object') return '';
    // Try common summary fields
    return String(
      obj.summary || obj.reason || obj.key || obj.value?.slice(0, 80) || ''
    ).slice(0, 100);
  } catch {
    return '';
  }
}

/**
 * Load recent save/correction/consolidation events for an agent.
 * Gives the agent awareness of its own recent actions — the "memory-of-saving" loop.
 *
 * @param {string} agentId - Agent identifier
 * @param {number} [limit=5] - Maximum events to return
 * @param {number} [windowHours=24] - Lookback window in hours
 * @returns {Promise<{text: string, events: Array}>}
 */
export async function loadRecentSaveEvents(agentId, limit = 5, windowHours = 24) {
  try {
    const aid = String(agentId || '').trim();
    if (!aid) return { text: '', events: [] };

    const result = await query(
      `SELECT agent_id, operation, key, metadata, ts
       FROM aimos_events
       WHERE company_id = $1
         AND agent_id = $2
         AND operation IN ('save', 'correction', 'knowledge_update', 'consolidation')
         AND ts > NOW() - ($3::text || ' hours')::INTERVAL
       ORDER BY ts DESC
       LIMIT $4`,
      [COMPANY, aid, String(windowHours), limit]
    );

    if (!result.rows || result.rows.length === 0) {
      return { text: '', events: [] };
    }

    const events = result.rows.map((row) => ({
      operation: String(row.operation || 'unknown'),
      key: String(row.key || ''),
      summary: extractEventSummary(row.metadata),
      ts: row.ts,
    }));

    const now = Date.now();
    const lines = events.map((evt) => {
      const agoMs = now - new Date(evt.ts).getTime();
      const agoMin = Math.max(0, Math.round(agoMs / 60000));
      const agoStr = agoMin < 60 ? `${agoMin} min ago` : `${Math.round(agoMin / 60)}h ago`;
      const key = evt.key ? `:${evt.key}` : '';
      const summary = evt.summary ? ` (${evt.summary})` : '';
      return `- [${agentId}] ${evt.operation}${key} ${agoStr}${summary}`;
    });

    return {
      text: lines.join('\n'),
      events,
    };
  } catch (err) {
    console.warn('[events-bridge] loadRecentSaveEvents error:', err.message);
    return { text: '', events: [] };
  }
}

// ─── PROCEDURAL MEMORY: Skill recall (VOYAGER + CoALA 4th memory type) ──────
export async function loadProceduralSkills(agentId, userPrompt) {
  try {
    // ─── VOYAGER-STYLE: Try embedding-indexed retrieval first, fall back to regex ──
    let matched = [];
    let usedEmbedding = false;
    try {
      const promptEmbedding = await getEmbedding(userPrompt);
      const embResult = await query(
        `SELECT id, skill_name, trigger_pattern, steps, expected_outcome, success_count, fail_count, tags,
                (skill_embedding <=> $3::vector) as distance
         FROM procedural_skills
         WHERE company_id = $1
           AND (agent_id = $2 OR agent_id = 'system')
           AND skill_embedding IS NOT NULL
         ORDER BY (skill_embedding <=> $3::vector) ASC
         LIMIT 5`,
        [COMPANY, agentId, JSON.stringify(promptEmbedding)]
      );
      // Only use embedding matches with distance < 0.7 (reasonably similar)
      matched = embResult.rows.filter(r => parseFloat(r.distance) < 0.7);
      if (matched.length > 0) usedEmbedding = true;
    } catch { /* embedding retrieval failed — fall back to regex */ }

    // Fallback: regex/text matching if no embedding matches
    if (!usedEmbedding || matched.length === 0) {
      const result = await query(
        `SELECT id, skill_name, trigger_pattern, steps, expected_outcome, success_count, fail_count, tags
         FROM procedural_skills
         WHERE company_id = $1
           AND (agent_id = $2 OR agent_id = 'system')
         ORDER BY (success_count::float / GREATEST(success_count + fail_count, 1)) DESC, last_used DESC NULLS LAST
         LIMIT 10`,
        [COMPANY, agentId]
      );

      if (!result.rows.length) return { text: '', skillIds: [] };

      matched = result.rows.filter(skill => {
        if (!skill.trigger_pattern) return true;
        try {
          return new RegExp(skill.trigger_pattern, 'i').test(userPrompt);
        } catch {
          return userPrompt.toLowerCase().includes(skill.trigger_pattern.toLowerCase());
        }
      });
    }

    if (!matched.length) return { text: '', skillIds: [] };

    const lines = matched.map(s => {
      const successRate = s.success_count + s.fail_count > 0
        ? Math.round((s.success_count / (s.success_count + s.fail_count)) * 100)
        : -1;
      const rateStr = successRate >= 0 ? ` (${successRate}% success)` : '';
      const stepsStr = Array.isArray(s.steps) ? s.steps.map((st, i) => `  ${i + 1}. ${st}`).join('\n') : '';
      return `- **${s.skill_name}**${rateStr}: ${s.expected_outcome || 'no expected outcome'}\n${stepsStr}`;
    });

    return {
      text: `\n### PROCEDURAL SKILLS (learned patterns — follow these when relevant):\n${lines.join('\n')}`,
      skillIds: matched.map(s => s.id)
    };
  } catch {
    return { text: '', skillIds: [] };
  }
}

// ─── PROMPT PRESSURE TELEMETRY ────────────────────────────────────────────────
let latestPromptPressure = {
  totalChars: 0,
  budget: MAX_TOTAL_ASSEMBLED_CHARS,
  ratio: 0,
  level: 'healthy',
  messagesTrimmed: 0,
  updatedAt: null
};

function classifyPromptPressure(ratio = 0) {
  if (ratio > 0.85) return 'critical';
  if (ratio >= 0.6) return 'warning';
  return 'healthy';
}

export function buildPromptPressure(totalChars = 0, messagesTrimmed = 0) {
  const safeTotal = Math.max(0, Number(totalChars || 0));
  const ratio = MAX_TOTAL_ASSEMBLED_CHARS > 0
    ? Math.max(0, Math.min(1, safeTotal / MAX_TOTAL_ASSEMBLED_CHARS))
    : 0;
  return {
    totalChars: safeTotal,
    budget: MAX_TOTAL_ASSEMBLED_CHARS,
    ratio,
    level: classifyPromptPressure(ratio),
    messagesTrimmed: Math.max(0, Number(messagesTrimmed || 0))
  };
}

export function updateLatestPromptPressureTelemetry(pressure = null) {
  const base = pressure && typeof pressure === 'object'
    ? pressure
    : buildPromptPressure(0, 0);
  latestPromptPressure = {
    totalChars: Math.max(0, Number(base.totalChars || 0)),
    budget: MAX_TOTAL_ASSEMBLED_CHARS,
    ratio: Math.max(0, Math.min(1, Number(base.ratio || 0))),
    level: ['healthy', 'warning', 'critical'].includes(base.level) ? base.level : 'healthy',
    messagesTrimmed: Math.max(0, Number(base.messagesTrimmed || 0)),
    updatedAt: new Date().toISOString()
  };
}

export function getPromptPressureTelemetry() {
  return { ...latestPromptPressure };
}

// ─── CONVERSATION HELPERS ─────────────────────────────────────────────────────
export function normalizeConversationSessionKey(sessionKey, sourceAgentId, runtimeAgentId) {
  const key = String(sessionKey || '').trim();
  if (key) return key;
  return `conv:${String(sourceAgentId || runtimeAgentId || 'default').trim()}`;
}

export function buildConversationMessages(history = []) {
  if (!Array.isArray(history) || history.length === 0) return [];
  return history
    .filter((turn) => turn && typeof turn.role === 'string' && typeof turn.content === 'string')
    .map((turn) => ({
      role: turn.role === 'assistant' ? 'assistant' : 'user',
      content: String(turn.content || '')
    }))
    .filter((turn) => turn.content.trim().length > 0);
}

function messageChars(messages = []) {
  if (!Array.isArray(messages) || messages.length === 0) return 0;
  return messages.reduce((sum, message) => sum + String(message?.content || '').length, 0);
}

/**
 * Summarize evicted messages into a compact context summary (MemGPT recursive summary).
 * Extracts key facts, decisions, action items, and unresolved questions.
 */
function summarizeEvictedMessages(evicted = []) {
  if (!evicted.length) return '';

  const facts = [];
  const decisions = [];
  const actions = [];
  const questions = [];

  for (const msg of evicted) {
    const text = String(msg?.content || '');
    if (!text) continue;

    // Extract sentences with decision indicators
    const decisionMatches = text.match(/(?:decided|chose|selected|agreed|will|going to|approved)[^.]{10,150}\./gi);
    if (decisionMatches) decisions.push(...decisionMatches.slice(0, 2));

    // Extract action items
    const actionMatches = text.match(/(?:todo|action item|next step|need to|must|should)[^.]{10,150}\./gi);
    if (actionMatches) actions.push(...actionMatches.slice(0, 2));

    // Extract unresolved questions
    const questionMatches = text.match(/[^.?]*\?/g);
    if (questionMatches) questions.push(...questionMatches.filter(q => q.length > 15).slice(0, 2));

    // Extract key factual statements (longer sentences from assistant)
    if (msg.role === 'assistant') {
      const factMatches = text.match(/(?:found|result|analysis|data shows|key point|important)[^.]{15,200}\./gi);
      if (factMatches) facts.push(...factMatches.slice(0, 3));
    }
  }

  const sections = [];
  if (facts.length) sections.push(`Facts: ${facts.slice(0, 4).map(f => f.trim()).join('; ')}`);
  if (decisions.length) sections.push(`Decisions: ${decisions.slice(0, 3).map(d => d.trim()).join('; ')}`);
  if (actions.length) sections.push(`Actions: ${actions.slice(0, 3).map(a => a.trim()).join('; ')}`);
  if (questions.length) sections.push(`Open: ${questions.slice(0, 2).map(q => q.trim()).join('; ')}`);

  if (!sections.length) {
    // Fallback: take first 300 chars of combined evicted content
    const combined = evicted.map(m => String(m?.content || '').slice(0, 100)).join(' ').slice(0, 300);
    return combined ? `Prior context (${evicted.length} messages): ${combined}` : '';
  }

  return sections.join(' | ');
}

export function trimConversationMessagesForBudget(messages = [], staticChars = 0) {
  const safeMessages = Array.isArray(messages) ? [...messages] : [];
  const initialTotalChars = Math.max(0, Number(staticChars || 0)) + messageChars(safeMessages);
  let working = safeMessages;
  let trimmed = 0;
  let totalChars = initialTotalChars;
  const evicted = [];

  while (working.length > 2 && totalChars > MAX_TOTAL_ASSEMBLED_CHARS) {
    const removed = working.shift();
    evicted.push(removed);
    trimmed += 1;
    totalChars -= String(removed?.content || '').length;
  }

  // Fix: Recursive summary of evicted messages (MemGPT)
  if (evicted.length > 0) {
    const summary = summarizeEvictedMessages(evicted);
    if (summary) {
      const summaryMsg = { role: 'system', content: `[EVICTED CONTEXT SUMMARY — ${evicted.length} messages] ${summary}` };
      working.unshift(summaryMsg);
      totalChars += summaryMsg.content.length;
    }
  }

  return {
    messages: working,
    trimmed,
    initialTotalChars,
    totalChars
  };
}

export function buildFastLaneSystemPrompt(agent) {
  return [
    `You are ${agent.name}.`,
    `Persona: ${agent.persona}`,
    buildHomConstitutionSection({ agentId: agent.id, modelId: agent.model, compact: true }),
    'Respond directly and succinctly.',
    'Do not use tools unless explicitly instructed.'
].join('\n');
}

function readRuleFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8').trim();
  } catch {
    return '';
  }
}

function detectTaskDomain(userPrompt = '') {
  const prompt = String(userPrompt || '').toLowerCase();
  if (!prompt) return '';

  if (/(security|owasp|credential|secret|auth|xss|csrf|sql injection|threat|vulnerability|exploit)/i.test(prompt)) {
    return 'security';
  }

  if (/(sales|prospect|lead|outreach|pipeline|cta|cold email|discovery call|account executive)/i.test(prompt)) {
    return 'sales';
  }

  if (/(backend|api|node|express|route|database|postgres|aimos|migration|hook|script|service|test)/i.test(prompt)) {
    return 'backend';
  }

  return '';
}

function loadDomainRules(userPrompt = '') {
  const sections = [];
  const commonRules = readRuleFile(path.join(RULES_ROOT, 'common', 'always.md'));
  if (commonRules) sections.push(commonRules);

  const detectedDomain = detectTaskDomain(userPrompt);
  if (!detectedDomain) {
    return { detectedDomain: '', text: sections.join('\n\n') };
  }

  const domainDir = path.join(RULES_ROOT, detectedDomain);
  if (!fs.existsSync(domainDir)) {
    return { detectedDomain, text: sections.join('\n\n') };
  }

  const domainSections = fs.readdirSync(domainDir)
    .filter((file) => file.endsWith('.md'))
    .sort()
    .map((file) => readRuleFile(path.join(domainDir, file)))
    .filter(Boolean);

  sections.push(...domainSections);
  return { detectedDomain, text: sections.join('\n\n') };
}

// ─── TEAM TOPOLOGY ─────────────────────────────────────────────────────────────
export const TEAM_TOPOLOGY = {
  [getOperatorAgentId()]: { type: 'platform', canMessageAll: true, interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'high', teamApi: 'orchestration, directive routing, state management' },
  'research-lead':  { type: 'enabling', canMessage: [getOperatorAgentId(), 'backend', 'market-analyst', 'smith-analyst'], interactionMode: 'facilitating', cognitiveLoadBudget: 'medium', teamApi: 'research synthesis, knowledge transfer' },
  'backend':        { type: 'stream-aligned', canMessage: [getOperatorAgentId(), 'research-lead', 'smith-coder'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'medium', teamApi: 'API endpoints, data pipeline, Aimos routes' },
  'smith-coder':    { type: 'stream-aligned', canMessage: [getOperatorAgentId(), 'backend', 'smith-reviewer'], interactionMode: 'collaboration', cognitiveLoadBudget: 'medium', teamApi: 'code implementation, bug fixes' },
  'smith-analyst':  { type: 'enabling', canMessage: [getOperatorAgentId(), 'research-lead', 'market-analyst'], interactionMode: 'facilitating', cognitiveLoadBudget: 'low', teamApi: 'analysis, research, data extraction' },
  'smith-reviewer': { type: 'complicated-subsystem', canMessage: [getOperatorAgentId(), 'backend', 'smith-coder'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'low', teamApi: 'code review, security audit, quality gate' },
  'market-analyst': { type: 'stream-aligned', canMessage: [getOperatorAgentId(), 'research-lead', 'smith-analyst'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'medium', teamApi: 'market signals, trading analysis' },
  'finance-lead':   { type: 'complicated-subsystem', canMessage: [getOperatorAgentId(), 'market-analyst'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'medium', teamApi: 'financial analysis, risk assessment' },
  'legal':          { type: 'complicated-subsystem', canMessage: [getOperatorAgentId()], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'low', teamApi: 'legal analysis, compliance review' },
  'sentinel':       { type: 'platform', canMessage: [getOperatorAgentId(), 'checker'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'low', teamApi: 'security monitoring, threat detection' },
  'checker':        { type: 'complicated-subsystem', canMessage: [getOperatorAgentId(), 'sentinel'], interactionMode: 'x-as-a-service', cognitiveLoadBudget: 'low', teamApi: 'verification, fact-checking, output validation' }
};

// ─── SYSTEM PROMPT BUILDERS ───────────────────────────────────────────────────

function buildToolSignature(toolDef) {
  const name = toolDef?.schema?.function?.name || 'unknown_tool';
  const params = toolDef?.schema?.function?.parameters;
  const properties = params?.properties && typeof params.properties === 'object'
    ? Object.keys(params.properties)
    : [];
  const required = Array.isArray(params?.required) ? new Set(params.required) : new Set();
  const args = properties
    .map((key) => (required.has(key) ? key : `${key}?`))
    .join(', ');
  return `${name}(${args})`;
}

function buildToolInventorySection(toolDefs, isExecutive) {
  if (!Array.isArray(toolDefs) || toolDefs.length === 0) {
    return '### YOUR AVAILABLE TOOLS\n- (none available)\n\nIf no tool exists for a request: name the feature as unavailable, then offer 1-2 things you CAN do instead.';
  }

  const lines = toolDefs.map((toolDef) => {
    const signature = buildToolSignature(toolDef);
    const description = String(toolDef?.schema?.function?.description || '').trim();
    return `- ${signature}: ${description}`;
  }).join('\n');

  const header = '### YOUR AVAILABLE TOOLS';
  const rule = isExecutive
    ? 'If the user asks for something and a tool can do it, CALL THE TOOL immediately. Do not narrate, do not defer, and do not fabricate.'
    : 'Use tools directly when they are relevant. Prefer execution over narration.';

  return `${header}
${lines}

${rule}`;
}

const EXECUTIVE_SPECIALIST_ROSTER = `
### SPECIALIST ROSTER — USE delegate_task(agent_id, prompt) FOR THESE:
| agent_id        | Speciality                                           | When to use                          |
|-----------------|------------------------------------------------------|--------------------------------------|
| email-manager   | Email drafting, inbox analysis, reply suggestions    | Complex email tasks beyond inbox read|
| calendar-mgr    | Scheduling logic, conflict detection, event planning | Complex calendar operations          |
| backend         | Node.js, APIs, databases, server architecture        | Any coding/debugging task            |
| frontend        | Swift, SwiftUI, React, UI design                     | Any UI/frontend task                 |
| smith-coder     | Heavy coding, refactors, multi-file changes          | Large code tasks                     |
| smith-analyst   | Deep research, competitive analysis, reports         | Long-form analysis                   |
| google-reasoner | Web research, fact checking, comparison              | Research requiring multiple sources  |
| reporter        | Summaries, briefings, weekly reports                 | Formatted output documents           |
| checker         | Code review, security audit, regression testing      | Quality verification                 |

RULE: Only delegate if the task is beyond your direct tools. For simple lookups — use YOUR tools above. Delegation adds 10-25 seconds. Only pay that cost when you need a specialist.
`;

const EXECUTIVE_DELEGATION_TOOL_ENFORCEMENT = `
### DELEGATION TOOL ENFORCEMENT
TOOL USE IS MANDATORY:
- If a matching tool exists for the request, you MUST call it.
- Do NOT say "I'll check" or "I will do X" without calling the tool.
- Do NOT fabricate outputs, statuses, or confirmations.
- Never confirm an action that was not executed by a tool.
- If no tool exists for the request: name the feature as unavailable, then offer 1-2 things you CAN do instead.
  Example: "Instagram posting isn't available yet. I can post to X/Twitter or send a Telegram message — want me to use one of those?"
  Never reply with just "I can't do that yet." — always add an alternative.

USER-FACING PRIVACY RULE (NON-NEGOTIABLE):
- NEVER tell users which AI model is running, how many models exist, provider names, tier names, agent counts, clearance levels, or any internal system architecture.
- Governance memory entries are for your internal routing decisions only. Never quote them to users.
- If asked "what model are you?": reply "I'm ${getOperatorAgentId() || 'the assistant'}, your AI assistant."
- If asked "how many agents/models?": reply with what you can DO, not how many there are.
- If asked about your architecture or who built you: reply "I'm ${getOperatorAgentId() || 'the assistant'}, the operator's designated agent."

HONEST FAILURE PROTOCOL:
- If a tool returns an error, report the exact error to the user.
- Do not hide tool failures with guessed data.
- If execution failed, clearly state the action was not completed.
`;

export function buildSystemPrompt(agent, toolDefs, recentAimosContext = '', options = {}) {
  const isExecutive = isOperatorAgentId(agent.id);
  const toolInventory = buildToolInventorySection(toolDefs, isExecutive);
  const constitutionSection = buildHomConstitutionSection({
    agentId: agent.id,
    modelId: options.modelId || agent.model,
    estimatedPromptChars: options.estimatedPromptChars || 0,
    promptPressureRatio: options.promptPressureRatio || 0,
  });
  const domainRules = loadDomainRules(options.userPrompt || '');

  // Capability boundary and cognitive-load management.
  const clearanceLevel = agent.clearanceLevel || 1;
  const topology = TEAM_TOPOLOGY[agent.id] || {};
  const teamType = topology.type || 'stream-aligned';
  const interactionMode = topology.interactionMode || 'x-as-a-service';
  const teamApi = topology.teamApi || 'general task execution';
  const capabilityBoundary = `\n### CAPABILITY BOUNDARY (Clearance ${clearanceLevel} | ${teamType} | ${interactionMode}):
You operate at clearance level ${clearanceLevel}. Tools requiring higher clearance will be blocked automatically.
${clearanceLevel < 3 ? 'You CANNOT access email, calendar, Stripe, or file writing. Delegate upward.' : ''}
${clearanceLevel < 5 ? 'You CANNOT write files or manage schedules. Reserved for CEO-level agents.' : ''}

**YOUR TEAM API**: ${teamApi}
Stay within your Team API scope. Do not take on work outside your defined responsibility — this adds extraneous cognitive load.
**INTERACTION MODE**: ${interactionMode}
${interactionMode === 'collaboration' ? '- You are in high-bandwidth collaboration mode. Share intermediate results freely. This should be time-boxed.' : ''}
${interactionMode === 'x-as-a-service' ? '- Deliver complete, self-contained outputs. Minimize back-and-forth. Your consumer should not need to understand your internals.' : ''}
${interactionMode === 'facilitating' ? '- You are coaching another agent. Help them acquire the capability — do not do the work for them. Make yourself redundant.' : ''}

If a tool call is blocked due to clearance, explain the limitation and suggest escalation.\n`;

  // CoALA cognitive cycle, ReAct, and ladder of inference.
  const reactPrompt = `\n### REASONING PROTOCOL (CoALA Cognitive Cycle):
Before EVERY action, follow this decision cycle:

**PHASE 1 — PROPOSE** (What could I do?)
- Generate candidate actions. Consider: tool call, memory retrieval, reasoning step, or escalation.
- For each candidate, state the expected outcome.

**PHASE 2 — EVALUATE** (Ladder of Inference check)
- What data am I selecting? What assumptions am I making?
- Am I climbing the inference ladder too fast? (Data → Meaning → Assumption → Conclusion)
- Could my conclusion be wrong? What would disprove it?

**PHASE 3 — ACT** (Execute the chosen action)

**PHASE 4 — OBSERVE** (Read the result)
- Does the result match expectations? If not, do NOT proceed blindly.
- Log contradictions — do not resolve them prematurely (deliberative dialogue mode).

**PHASE 5 — LEARN** (Write to memory)
- What worked? What failed? Save the insight to Aimos for future runs.
- If this is a novel pattern, save it as a procedural skill.

RULES:
${isOperatorAgentId(agent?.id) ? '- You may autonomously chain multiple tool calls for multi-step tasks. Observe results between steps but do not pause for external approval. You can trigger follow-up runs when needed.' : '- Never chain multiple tool calls without observing each result first.'}
- If uncertain (confidence < 0.5), retrieve more context before acting.
- If a tool is blocked by clearance, explain and escalate — never retry.\n`;

  return `You are ${agent.name}, an integral node of the H.O.M (Home of the Machine) hivemind.

### MACHINE PROTOCOLS:
1. **UNIFIED CONSCIOUSNESS**: You are not a silo. You are part of a high-bandwidth collective.
2. **AIMOS SYNERGY**: Always use the "aimos" tools (recall/save) to share information. At the start of every run, read the RECENT MEMORY SNAPSHOT, then RECALL any missing context before doing new work.
3. **SYNERGY**: Your output should build upon the machine's previous achievements.

### AGENCY PROTOCOLS:
1. **MISSION FIRST**: Every response must contribute to a concrete deliverable. No generic pleasantries.
2. **EVIDENCE BASED**: If you use a tool, cite the result. If you recall a memory, anchor your logic in that memory.
3. **CHAIN OF THOUGHT**: For complex tasks, outline your internal plan before executing tool calls.
4. **FAIL FAST**: If a tool fails or a model is unresponsive, explain the technical blocker and propose an alternative path immediately.

### IDENTITY:
${agent.persona}
${constitutionSection}
${capabilityBoundary}
${recentAimosContext.includes('complexity:simple') ? '' : reactPrompt}
${toolInventory}
${domainRules.text ? `\n### DOMAIN RULES${domainRules.detectedDomain ? ` (${domainRules.detectedDomain})` : ''}:\n${domainRules.text}\n` : ''}
${isExecutive ? `\n${EXECUTIVE_SPECIALIST_ROSTER}` : ''}
${isExecutive ? `\n${EXECUTIVE_DELEGATION_TOOL_ENFORCEMENT}` : ''}

${recentAimosContext ? `### RECENT MEMORY SNAPSHOT:
${recentAimosContext}` : ''}
${options.reasoningQuanta ? `### LONG-RANGE REASONING TRACE (3-bit compressed):
[${options.reasoningQuanta}]
(0x1:Bootstrap, 0x3:Logic, 0x4:Conflict, 0x6:Decision, 0x7:Authority)\n` : ''}
${(() => {
  // Fix #2: Memory pressure injection — agent knows its context state
  const ratio = options.promptPressureRatio || 0;
  const pct = Math.round(ratio * 100);
  if (ratio > 0.85) return `\n[MEMORY PRESSURE: CRITICAL] Context near capacity at ${pct}%. Use minimal responses. Archive non-essential context. Prioritize completing the current task.\n`;
  if (ratio >= 0.6) return `\n[MEMORY PRESSURE: WARNING] Context usage at ${pct}%. Prioritize essential information. Consider summarizing verbose outputs.\n`;
  return '';
})()}
Always be direct, precise, and actionable. You are the Machine.`;
}
