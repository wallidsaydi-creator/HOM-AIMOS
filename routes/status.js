import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import express from 'express';
import { query } from '../db/connection.js';
import { listAgents, tasks } from '../services/orchestration/agent-store.js';
import { ensureGovernanceReady, getGovernanceStats } from '../services/orchestration/governance-resolver.js';
import { getSessionRunnerStats } from '../services/orchestration/session-runner.js';
import { getModelContextWindow, normalizeModelId } from '../services/orchestration/model-context.js';
import { subscribeRunEvents, getRunEventsSince } from '../services/orchestration/run-events.js';
import { fetchWithTimeout } from '../services/orchestration/http.js';
import { getOperatorAgentId, isOperatorAgentId } from '../services/security/system-config-store.js';
import { peekCachedCredential } from '../services/security/credential-cache.js';
import { systemConfigStore } from '../services/security/system-config-store.js';
import {
  discoverActiveProviders,
  getProviderRegistry,
  resolveProviderForModel
} from '../services/core/providers.js';

const router = express.Router();

const CONTEXT_AVG_CHARS_PER_TOKEN = 4;
const COMPANY = AIMOS_COMPANY_ID;
const HEALTH_CACHE_TTL_MS = 60_000;
const STATUS_CACHE_TTL_MS = 2_000;
const STATUS_REQUEST_TIMEOUT_MS = 4_000;
const providerHealthCache = new Map();
let statusSnapshotCache = { at: 0, value: null };
const COST_AVG_CHARS_PER_TOKEN = 4;
const MODEL_PRICING_PER_1M = [
  { pattern: /gemini-2\.5-pro/i, input: 1.25, output: 5.00 },
  { pattern: /gemini-2\.5-flash/i, input: 0.30, output: 1.20 },
  { pattern: /sonar|perplexity/i, input: 1.00, output: 1.00 },
  { pattern: /qwen|kimi|glm|deepseek|llama|mistral|gemma/i, input: 0.00, output: 0.00 }
];

function sseWrite(res, eventName, payload, options = {}) {
  const event = String(eventName || 'message');
  const data = JSON.stringify(payload || {});
  const eventId = options?.id == null ? null : String(options.id);
  if (eventId) {
    res.write(`id: ${eventId}\n`);
  }
  res.write(`event: ${event}\n`);
  res.write(`data: ${data}\n\n`);
}

function parseEventId(value) {
  const parsed = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return parsed;
}

function normalizeLifecycleStatus(status, fallback = 'running') {
  const normalized = String(status || '').trim().toLowerCase();
  if (['accepted', 'running', 'awaiting_approval', 'completed', 'failed', 'timeout'].includes(normalized)) {
    return normalized;
  }
  return fallback;
}

function eventTypeToLifecycleStatus(eventType = '') {
  const normalized = String(eventType || '').trim().toLowerCase();
  switch (normalized) {
    case 'run.accepted': return 'accepted';
    case 'run.started': return 'running';
    case 'run.awaiting_approval': return 'awaiting_approval';
    case 'run.completed': return 'completed';
    case 'run.timeout': return 'timeout';
    case 'run.failed': return 'failed';
    default: return null;
  }
}

function getRunEventMeta(evt, nameLookup) {
  const payload = evt?.payload || {};
  const runId = payload.runId || null;
  const agentId = String(
    payload.resolvedAgentId
    || payload.delegatedTo
    || payload.sourceAgentId
    || 'unknown'
  );
  return {
    runId,
    agentId,
    agentName: nameLookup.get(agentId) || agentId
  };
}

function emitLifecycleEvent(res, evt, nameLookup, { replayed = false } = {}) {
  if (!evt || !evt.payload) return false;
  const status = normalizeLifecycleStatus(evt.payload.status || eventTypeToLifecycleStatus(evt.type), 'running');
  const meta = getRunEventMeta(evt, nameLookup);
  sseWrite(
    res,
    'run.lifecycle',
    {
      ...meta,
      status,
      runId: meta.runId,
      queueWaitMs: evt.payload.queueWaitMs ?? null,
      approvalRequestId: evt.payload.approvalRequestId || null,
      model: evt.payload.modelResolved || evt.payload.modelRequested || null,
      error: evt.payload.error || null,
      replayed,
      at: evt.at
    },
    { id: evt.id }
  );
  return true;
}

function asNumber(input, fallback = 0) {
  const n = Number(input);
  return Number.isFinite(n) ? n : fallback;
}

function clamp01(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function hasGeminiKey() {
  return peekCachedCredential('gemini_api_key') || peekCachedCredential('google_api_key');
}

function providerFromModel(model = '') {
  const { provider } = resolveProviderForModel(model);
  return provider || 'other';
}

function resolveModelPricing(model = '') {
  const normalized = String(model || '').trim();
  if (!normalized) return { input: 0, output: 0 };
  const matched = MODEL_PRICING_PER_1M.find((entry) => entry.pattern.test(normalized));
  if (matched) return { input: matched.input, output: matched.output };
  return { input: 0.8, output: 2.4 };
}

function estimateUsdCost({ model = '', promptChars = 0, responseChars = 0 }) {
  const pricing = resolveModelPricing(model);
  const promptTokens = Math.max(0, Number(promptChars || 0)) / COST_AVG_CHARS_PER_TOKEN;
  const responseTokens = Math.max(0, Number(responseChars || 0)) / COST_AVG_CHARS_PER_TOKEN;
  const promptCost = (promptTokens / 1_000_000) * pricing.input;
  const responseCost = (responseTokens / 1_000_000) * pricing.output;
  return promptCost + responseCost;
}

async function withHealthCache(cacheKey, checkFn) {
  const now = Date.now();
  const cached = providerHealthCache.get(cacheKey);
  if (cached && (now - cached.at) < HEALTH_CACHE_TTL_MS) {
    return cached.value;
  }
  const value = await checkFn();
  providerHealthCache.set(cacheKey, { at: now, value });
  return value;
}

function resolveContextModel(req, allAgents) {
  const requestedModel = String(req.query?.model || '').trim();
  if (requestedModel) return requestedModel;

  const requestedAgentId = String(req.query?.agentId || '').trim().toLowerCase();
  if (requestedAgentId) {
    const match = allAgents.find((agent) => String(agent.id || '').toLowerCase() === requestedAgentId);
    if (match?.model) return String(match.model);
  }

  const opAgent = getOperatorAgentId();
  const executive = opAgent
    ? allAgents.find((agent) => isOperatorAgentId(String(agent.id || '')))
    : null;
  if (executive?.model) return String(executive.model);

  return '';
}

function buildContextUsageQuery(contextModel) {
  const canonical = normalizeModelId(contextModel);
  const values = [COMPANY];

  let sql = `SELECT
      COALESCE(SUM(prompt_chars), 0)::bigint AS prompt_chars_30m,
      COALESCE(SUM(response_chars), 0)::bigint AS response_chars_30m,
      COUNT(*)::int AS runs_30m,
      COUNT(*) FILTER (WHERE context_compacted = true)::int AS compacted_runs_30m,
      COALESCE(AVG(context_compaction_ratio), 1)::double precision AS avg_compaction_ratio
    FROM agent_runs
    WHERE company_id = $1
      AND created_at >= NOW() - INTERVAL '30 minutes'`;

  if (canonical) {
    values.push(canonical);
    sql += `
      AND (
        LOWER(COALESCE(model_resolved, model_requested, '')) = $2
        OR REGEXP_REPLACE(LOWER(COALESCE(model_resolved, model_requested, '')), '^perplexity[:/]', '') = $2
      )`;
  }

  return { sql, values };
}

router.get('/events/stream', async (req, res) => {
  await ensureGovernanceReady(COMPANY);
  const companyId = String(req.query?.company_id || COMPANY);
  const replayAfterId = parseEventId(req.get('last-event-id') || req.query?.lastEventId);
  const nameLookup = new Map(listAgents().map((agent) => [String(agent.id), String(agent.name || agent.id)]));

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  sseWrite(res, 'engine.started', {
    companyId,
    message: 'HOM event stream connected',
    connectedAt: new Date().toISOString(),
    replayAfterId
  });

  const forwardEvent = (evt, replayed = false) => {
    if (!evt || !evt.payload) return;
    const payloadCompany = String(evt.payload.companyId || '');
    if (payloadCompany && payloadCompany !== companyId) return;

    emitLifecycleEvent(res, evt, nameLookup, { replayed });
    const { runId, agentId, agentName } = getRunEventMeta(evt, nameLookup);
    const status = normalizeLifecycleStatus(evt.payload.status || eventTypeToLifecycleStatus(evt.type), 'running');

    if (evt.type === 'run.started') {
      sseWrite(res, 'agent.started', {
        runId,
        agentId,
        agentName,
        status,
        model: evt.payload.modelResolved || evt.payload.modelRequested || null,
        task: evt.payload.intent || evt.payload.sessionKey || 'run started',
        queueWaitMs: evt.payload.queueWaitMs ?? null,
        replayed,
        at: evt.at
      }, { id: evt.id });
      return;
    }

    if (evt.type === 'run.completed') {
      sseWrite(res, 'agent.completed', {
        runId,
        agentId,
        agentName,
        status,
        model: evt.payload.modelResolved || null,
        preview: evt.payload.preview || '',
        fallbackUsed: evt.payload.fallbackUsed ?? null,
        delegatedTo: evt.payload.delegatedTo || null,
        queueWaitMs: evt.payload.queueWaitMs ?? null,
        replayed,
        at: evt.at
      }, { id: evt.id });
      return;
    }

    if (evt.type === 'run.failed' || evt.type === 'run.timeout') {
      sseWrite(res, 'agent.error', {
        runId,
        agentId,
        agentName,
        status,
        error: evt.payload.error || 'run failed',
        queueWaitMs: evt.payload.queueWaitMs ?? null,
        replayed,
        at: evt.at
      }, { id: evt.id });
      return;
    }

    if (evt.type === 'run.awaiting_approval') {
      sseWrite(res, 'agent.awaiting_approval', {
        runId,
        agentId,
        agentName,
        status,
        error: evt.payload.error || 'approval required',
        approvalRequestId: evt.payload.approvalRequestId || null,
        queueWaitMs: evt.payload.queueWaitMs ?? null,
        replayed,
        at: evt.at
      }, { id: evt.id });
    }
  };

  if (replayAfterId != null) {
    const replayEvents = getRunEventsSince(replayAfterId, 500);
    for (const event of replayEvents) {
      forwardEvent(event, true);
    }
  }

  const unsubscribe = subscribeRunEvents((evt) => {
    forwardEvent(evt, false);
  }, {
    replay: false
  });

  const keepAlive = setInterval(() => {
    res.write(':keep-alive\n\n');
  }, 15_000);

  req.on('close', () => {
    clearInterval(keepAlive);
    unsubscribe();
    res.end();
  });
});

router.get('/', async (req, res) => {
  const now = Date.now();
  if (statusSnapshotCache.value && now - statusSnapshotCache.at < STATUS_CACHE_TTL_MS) {
    return res.json(statusSnapshotCache.value);
  }

  // Keep startup and health checks responsive while governance warms up in background.
  void ensureGovernanceReady(COMPANY).catch(() => {});

  let engineConnected = false;
  let totalMemories = 0;
  try {
    const result = await query('SELECT COUNT(*) as total FROM aimos_memories WHERE company_id = $1', [COMPANY]);
    engineConnected = true;
    totalMemories = parseInt(result.rows[0].total);
  } catch {
    engineConnected = false;
  }

  const allAgents = listAgents();
  const contextModel = resolveContextModel(req, allAgents);
  const contextPolicy = getModelContextWindow(contextModel);
  const contextQuery = buildContextUsageQuery(contextPolicy.model);

  const discoveredProviders = discoverActiveProviders();
  const providerRegistry = getProviderRegistry();
  const providerMatrix = discoveredProviders.map((provider) => {
    const registryEntry = providerRegistry[provider.provider] || {};
    return {
      provider: provider.provider,
      type: provider.type,
      active: provider.active,
      reason: provider.reason,
      defaultModel: provider.defaultModel || registryEntry.defaultModel || null,
      modelHints: provider.modelHints || registryEntry.modelHints || []
    };
  });
  const providerIndex = Object.fromEntries(
    providerMatrix.map((provider) => [provider.provider, provider])
  );
  const providers = Object.fromEntries(
    providerMatrix.map((provider) => [
      provider.provider,
      { connected: !!provider.active }
    ])
  );

  const webTools = {
    perplexity: peekCachedCredential('perplexity_api_key'),
    brave: peekCachedCredential('brave_api_key'),
    x: !!(peekCachedCredential('x_bearer_token') || peekCachedCredential('x_api_key')),
    stripe: peekCachedCredential('stripe_secret_key'),
    google: !!(systemConfigStore.readConfigString('GOOGLE_CLIENT_ID') && peekCachedCredential('google_client_secret') && systemConfigStore.readConfigString('GOOGLE_REDIRECT_URI')),
    github: !!(systemConfigStore.readConfigString('GITHUB_CLIENT_ID') && peekCachedCredential('github_client_secret') && systemConfigStore.readConfigString('GITHUB_REDIRECT_URI')),
    salesforce: !!(systemConfigStore.readConfigString('SALESFORCE_CLIENT_ID') && peekCachedCredential('salesforce_client_secret') && systemConfigStore.readConfigString('SALESFORCE_REDIRECT_URI')),
    imessage: true
  };

  const activeSessions = allAgents.filter(a => a.isActive).length;
  const pendingTasks = Array
    .from(tasks.values())
    .filter(t => !['completed', 'failed'].includes(String(t.status || '').toLowerCase()))
    .length;

  let policy = {
    companyId: COMPANY,
    profileCount: 0,
    modelPolicyCount: 0,
    routingRuleCount: 0
  };
  let runtime = {
    maxConcurrency: 0,
    activeGlobalRuns: 0,
    waitingGlobalRuns: 0,
    activeSessionMutexes: 0,
    trackedSessionLanes: 0,
    runningSessionLanes: 0,
    conversationSessions: 0,
    conversationTtlMs: 0,
    conversationMaxTurns: 0,
    sessionTurnsCharBudget: 0
  };
  let contextRow = {};
  try {
    const [resolvedPolicy, resolvedRuntime, contextUsage] = await Promise.all([
      getGovernanceStats(COMPANY),
      getSessionRunnerStats(COMPANY),
      query(contextQuery.sql, contextQuery.values)
    ]);
    policy = resolvedPolicy;
    runtime = resolvedRuntime;
    contextRow = contextUsage.rows[0] || {};
  } catch {
    // During boot/migrations, keep /status available with conservative defaults.
  }

  const promptChars30m = asNumber(contextRow.prompt_chars_30m);
  const responseChars30m = asNumber(contextRow.response_chars_30m);
  const charsInUse30m = promptChars30m + responseChars30m;
  const estimatedTokensInUse = Math.round(charsInUse30m / CONTEXT_AVG_CHARS_PER_TOKEN);
  const estimatedUsageRatio = clamp01(estimatedTokensInUse / contextPolicy.windowTokens);
  const compactedRuns30m = asNumber(contextRow.compacted_runs_30m);
  const runs30m = asNumber(contextRow.runs_30m);
  const avgCompactionRatio = clamp01(asNumber(contextRow.avg_compaction_ratio, 1));
  const contextLevel = estimatedUsageRatio >= 0.85 ? 'critical' : estimatedUsageRatio >= 0.65 ? 'warning' : 'healthy';
  const compactionActive = compactedRuns30m > 0 || estimatedUsageRatio >= 0.75;
  const promptPressure = null;
  const contextPromptPressure = {
    totalChars: asNumber(promptPressure?.totalChars, 0),
    budget: asNumber(promptPressure?.budget, 0),
    ratio: clamp01(asNumber(promptPressure?.ratio, 0)),
    level: ['healthy', 'warning', 'critical'].includes(promptPressure?.level) ? promptPressure.level : 'healthy',
    messagesTrimmed: asNumber(promptPressure?.messagesTrimmed, 0),
    updatedAt: promptPressure?.updatedAt || null
  };
  const normalizedRuntime = {
    maxConcurrency: Math.max(1, asNumber(runtime.maxConcurrency, 1)),
    activeGlobalRuns: Math.max(0, asNumber(runtime.activeGlobalRuns, 0)),
    waitingGlobalRuns: Math.max(0, asNumber(runtime.waitingGlobalRuns, 0)),
    activeSessionMutexes: Math.max(0, asNumber(runtime.activeSessionMutexes, 0)),
    trackedSessionLanes: Math.max(0, asNumber(runtime.trackedSessionLanes, 0)),
    runningSessionLanes: Math.max(0, asNumber(runtime.runningSessionLanes, 0)),
    conversationSessions: Math.max(0, asNumber(runtime.conversationSessions, 0)),
    conversationTtlMs: Math.max(0, asNumber(runtime.conversationTtlMs, 0)),
    conversationMaxTurns: Math.max(0, asNumber(runtime.conversationMaxTurns, 0)),
    sessionTurnsCharBudget: Math.max(0, asNumber(runtime.sessionTurnsCharBudget, 0))
  };
  const globalUtilization = clamp01(normalizedRuntime.activeGlobalRuns / normalizedRuntime.maxConcurrency);
  const laneUtilization = normalizedRuntime.trackedSessionLanes > 0
    ? clamp01(normalizedRuntime.runningSessionLanes / normalizedRuntime.trackedSessionLanes)
    : 0;
  const queueBacklog = normalizedRuntime.waitingGlobalRuns;
  const queuePressureLevel = queueBacklog > 0 || globalUtilization >= 0.9
    ? 'high'
    : (globalUtilization >= 0.65 || laneUtilization >= 0.65 ? 'medium' : 'low');
  const runtimeReady = engineConnected && normalizedRuntime.maxConcurrency > 0;

  const payload = {
    engine: { connected: engineConnected, totalMemories },
    // Backward-compatible flat stats used by desktop StatsView.
    memory: totalMemories,
    agents: allAgents.length,
    pendingTasks,
    activeSessions,
    providers,
    providerMatrix,
    webTools,
    policy,
    runtime: {
      ...normalizedRuntime,
      ready: runtimeReady,
      pressure: {
        level: queuePressureLevel,
        globalUtilization,
        laneUtilization,
        queueBacklog
      }
    },
    runtimePressure: {
      level: queuePressureLevel,
      globalUtilization,
      laneUtilization,
      queueBacklog
    },
    context: {
      model: contextModel || null,
      modelCanonical: contextPolicy.model || null,
      modelSource: contextPolicy.source,
      windowTokens: contextPolicy.windowTokens,
      averageCharsPerToken: CONTEXT_AVG_CHARS_PER_TOKEN,
      promptChars30m,
      responseChars30m,
      estimatedTokensInUse,
      estimatedUsageRatio,
      runs30m,
      compactedRuns30m,
      avgCompactionRatio,
      compactionActive,
      level: contextLevel,
      promptPressure: contextPromptPressure
    },
    timestamp: new Date().toISOString()
  };

  statusSnapshotCache = { at: Date.now(), value: payload };
  res.json(payload);
});

router.get('/model-suite', async (req, res) => {
  await ensureGovernanceReady(COMPANY);
  const allAgents = listAgents();
  const discoveredProviders = discoverActiveProviders();
  const providerIndex = Object.fromEntries(
    discoveredProviders.map((provider) => [provider.provider, provider])
  );
  const byProvider = {};
  const byModel = {};

  for (const agent of allAgents) {
    const provider = providerFromModel(agent.model);
    byProvider[provider] = (byProvider[provider] || 0) + 1;
    byModel[agent.model] = (byModel[agent.model] || 0) + 1;
  }

  const [governance, runtime, runHealth] = await Promise.all([
    getGovernanceStats(COMPANY),
    getSessionRunnerStats(COMPANY),
    query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE fallback_used = true)::int AS fallback_runs,
              COUNT(*) FILTER (WHERE delegated_to IS NOT NULL)::int AS delegated_runs
       FROM agent_runs
       WHERE company_id = $1
         AND created_at >= NOW() - INTERVAL '24 hours'`,
      [COMPANY]
    )
  ]);

  res.json({
    providersConfigured: Object.fromEntries(
      discoveredProviders.map((provider) => [
        provider.provider,
        { connected: !!provider.active }
      ])
    ),
    providerMatrix: discoveredProviders,
    modelUsage: Object.entries(byModel)
      .map(([model, count]) => ({ model, count }))
      .sort((a, b) => b.count - a.count),
    providerUsage: Object.entries(byProvider)
      .map(([provider, count]) => ({ provider, count }))
      .sort((a, b) => b.count - a.count),
    policy: governance,
    runtime,
    runtimeResolutionHealth: {
      runs24h: runHealth.rows[0]?.total || 0,
      fallbackRuns24h: runHealth.rows[0]?.fallback_runs || 0,
      delegatedRuns24h: runHealth.rows[0]?.delegated_runs || 0
    }
  });
});

router.get('/tooling', async (req, res) => {
  const allAgents = listAgents();
  const internetReady = allAgents.filter((a) => {
    const tools = Array.isArray(a.tools) ? a.tools : [];
    return tools.includes('web-search') || tools.includes('full');
  }).length;
  res.json({
    totalAgents: allAgents.length,
    internetReadyAgents: internetReady,
    webTools: {
      perplexity: peekCachedCredential('perplexity_api_key'),
      brave: peekCachedCredential('brave_api_key'),
      x: !!(peekCachedCredential('x_bearer_token') || peekCachedCredential('x_api_key')),
      stripe: peekCachedCredential('stripe_secret_key'),
      google: !!(systemConfigStore.readConfigString('GOOGLE_CLIENT_ID') && peekCachedCredential('google_client_secret') && systemConfigStore.readConfigString('GOOGLE_REDIRECT_URI')),
      github: !!(systemConfigStore.readConfigString('GITHUB_CLIENT_ID') && peekCachedCredential('github_client_secret') && systemConfigStore.readConfigString('GITHUB_REDIRECT_URI')),
      salesforce: !!(systemConfigStore.readConfigString('SALESFORCE_CLIENT_ID') && peekCachedCredential('salesforce_client_secret') && systemConfigStore.readConfigString('SALESFORCE_REDIRECT_URI')),
      imessage: true
    },
    googleSuite: {
      oauthConfigured: !!(systemConfigStore.readConfigString('GOOGLE_CLIENT_ID') && peekCachedCredential('google_client_secret') && systemConfigStore.readConfigString('GOOGLE_REDIRECT_URI')),
      apiConfigured: !!(peekCachedCredential('google_api_key') || peekCachedCredential('gemini_api_key'))
    }
  });
});

router.get('/cost', async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days || '7', 10), 1), 30);

  try {
    const [byModelResult, byDayResult] = await Promise.all([
      query(
        `SELECT
           COALESCE(NULLIF(model_resolved, ''), NULLIF(model_requested, ''), 'unknown') AS model,
           COUNT(*)::int AS request_count,
           COALESCE(SUM(prompt_chars), 0)::bigint AS prompt_chars,
           COALESCE(SUM(response_chars), 0)::bigint AS response_chars
         FROM agent_runs
         WHERE company_id = $1
           AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
           AND status IN ('completed', 'failed', 'timeout', 'awaiting_approval', 'running')
         GROUP BY 1
         ORDER BY request_count DESC, model ASC`,
        [COMPANY, days]
      ),
      query(
        `SELECT
           TO_CHAR(created_at::date, 'YYYY-MM-DD') AS day,
           COALESCE(SUM(prompt_chars), 0)::bigint AS prompt_chars,
           COALESCE(SUM(response_chars), 0)::bigint AS response_chars,
           ARRAY_AGG(COALESCE(NULLIF(model_resolved, ''), NULLIF(model_requested, ''), 'unknown')) AS models
         FROM agent_runs
         WHERE company_id = $1
           AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
           AND status IN ('completed', 'failed', 'timeout', 'awaiting_approval', 'running')
         GROUP BY created_at::date
         ORDER BY created_at::date ASC`,
        [COMPANY, days]
      )
    ]);

    const models = byModelResult.rows.map((row) => {
      const model = String(row.model || 'unknown');
      const promptChars = Number(row.prompt_chars || 0);
      const responseChars = Number(row.response_chars || 0);
      const estimatedCost = estimateUsdCost({ model, promptChars, responseChars });
      return {
        model,
        provider: providerFromModel(model),
        requestCount: Number(row.request_count || 0),
        promptChars,
        responseChars,
        estimatedCost: Number(estimatedCost.toFixed(6))
      };
    });

    const trend = byDayResult.rows.map((row) => {
      const modelHints = Array.isArray(row.models) ? row.models : [];
      const representativeModel = String(modelHints[0] || 'unknown');
      const promptChars = Number(row.prompt_chars || 0);
      const responseChars = Number(row.response_chars || 0);
      const totalCost = estimateUsdCost({
        model: representativeModel,
        promptChars,
        responseChars
      });
      return {
        date: String(row.day || ''),
        totalCost: Number(totalCost.toFixed(6)),
        promptChars,
        responseChars
      };
    });

    const totalCost = models.reduce((acc, item) => acc + Number(item.estimatedCost || 0), 0);
    res.json({
      success: true,
      windowDays: days,
      totalCost: Number(totalCost.toFixed(6)),
      models,
      trend
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error?.message || String(error),
      windowDays: days,
      totalCost: 0,
      models: [],
      trend: []
    });
  }
});

export default router;
