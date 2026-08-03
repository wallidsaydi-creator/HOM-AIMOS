/**
 * agent-shared.js — constants and helpers shared across agent sub-routers.
 */

import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import path from 'path';
import os from 'os';
import { systemConfigStore } from '../services/security/system-config-store.js';

export const COMPANY = AIMOS_COMPANY_ID;
export const INTELLIGENCE_ARTIFACT_DIR = path.join(os.homedir(), '.aimos', 'briefings');

export const INTELLIGENCE_KEYWORDS = [
  'research', 'intelligence', 'briefing', 'brief', 'market', 'competitor', 'competitive', 'news', 'external fact', 'report', 'analysis', 'trend'
];

export const X_INTENT_MARKERS = [
  'twitter', 'x.com', 'tweet', 'tweets', 'x api', 'twitter api', 'social listening', 'social-listening', 'search x', 'search on x', 'search twitter'
];

// Technique: Provider-Agnostic Rebuild (Doc 09)
// Fast lane is opt-in. No retired/default model is hardwired into Aimos.
export const DEFAULT_AGENT_MODEL = systemConfigStore.readConfigString('DEFAULT_AGENT_MODEL') || systemConfigStore.readConfigString('LLM_MODEL') || systemConfigStore.readConfigString('OLLAMA_MODEL') || '';
export const FAST_LANE_MODEL = systemConfigStore.readConfigString('FAST_LANE_MODEL') || '';
export const FAST_LANE_MAX_CHARS = Math.max(20, Number(systemConfigStore.readConfigString('FAST_LANE_MAX_CHARS') || 120));

export const FAST_LANE_TOOL_INTENT_KEYWORDS = [
  'search', 'send', 'check', 'find', 'list', 'open', 'create', 'show', 'read', 'write', 'get', 'use', 'call', 'look up', 'email', 'message', 'calendar', 'github', 'stripe', 'drive', 'remember', 'recall', 'memory'
];

export const FAST_LANE_EXTERNAL_DATA_MARKERS = ['today', 'latest', 'current', 'recent', 'my', 'the'];

export const LIFECYCLE_STATUSES = new Set(['accepted', 'running', 'awaiting_approval', 'completed', 'failed', 'timeout']);

export const TOOL_SUITES = {
  full: ['web-search', 'gmail-read', 'gmail-send', 'gmail-search', 'youtube', 'drive', 'calendar', 'docs', 'sheets', 'google-profile', 'stripe', 'integrations', 'aimos'],
  minimal: ['aimos']
};

export function getDefaultToolset(toolSuiteKey) { return [toolSuiteKey || 'full']; }
export function escapeRegex(value = '') { return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
export function hasKeyword(text, keyword) { return text.includes(String(keyword).toLowerCase()); }
export function normalizeLifecycleStatus(status, fallback = 'failed') { return LIFECYCLE_STATUSES.has(status) ? status : fallback; }

export function buildLifecycleEnvelope({ status, runId = null, acceptedAt = null, runningAt = null, finishedAt = null, error = null } = {}) {
  return { status, runId, acceptedAt, runningAt, finishedAt, updatedAt: new Date().toISOString(), error, history: [status] };
}

export function attachLifecycle(payload = {}, lifecycleInput = {}) {
  const lifecycle = buildLifecycleEnvelope(lifecycleInput);
  return { ...payload, status: lifecycle.status, lifecycleStatus: lifecycle.status, lifecycle, lifecycleHistory: lifecycle.history };
}

export function coerceBoolean(value, fallback = false) { return !!value; }
export function mergeToolDeltas(base = {}, extra = {}) {
  const normalize = (values) => Array.from(new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value ?? '').trim())
      .filter(Boolean)
  )).sort();

  const deny = normalize([
    ...(Array.isArray(base?.deny) ? base.deny : []),
    ...(Array.isArray(extra?.deny) ? extra.deny : [])
  ]);
  const denied = new Set(deny);
  const allow = normalize([
    ...(Array.isArray(base?.allow) ? base.allow : []),
    ...(Array.isArray(extra?.allow) ? extra.allow : [])
  ])
    .filter((toolName) => !denied.has(toolName));

  return { allow, deny };
}
