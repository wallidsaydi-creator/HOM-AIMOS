import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'crypto';
import { readFileSync } from 'node:fs';
import { pool, agentPool, schedulerLockPool } from './db/connection.js';
import { beginServingWork, beginServingDrain, finishServingDrain, getServingWorkState, cancelServingWork } from './services/runtime/serving-control.js';
import statusRoutes from './routes/status.js';
import { authGate } from './services/security/auth-gate.js';
import { systemConfigStore } from './services/security/system-config-store.js';
import { loadCredentialCache, reloadCredentialCache, peekCachedCredential } from './services/security/credential-cache.js';
import { assertUniqueJsonMembers } from './services/security/protocol/canonical-json.js';

const app = express();
let listener = null;
let shutdownPromise = null;
let listenerClosed = false;
const sockets = new Set();
const responses = new Set();
const DRAIN_WAIT_MS = 20_000;

// Native ingress stops before parsing/authentication. Work already admitted
// retains its original owners and DB access until they settle or the bounded
// stop is explicitly recorded as indeterminate.
app.use((req, res, next) => {
  if (getServingWorkState().phase !== 'running') {
    res.setHeader('Connection', 'close');
    return res.status(503).json({ error: { code: 'runtime_draining' }, ready: false });
  }
  if (!backgroundReady && !['/', '/health', '/healthz'].includes(req.path)) {
    res.setHeader('Retry-After', '1');
    return res.status(503).json({ error: { code: 'runtime_initializing' }, ready: false });
  }
  const finish = beginServingWork('http_response');
  responses.add(res);
  let done = false;
  const release = () => { if (!done) { done = true; responses.delete(res); finish(); } };
  res.once('finish', release);
  res.once('close', release);
  next();
});
// AIMOS owns 9100. Reserved legacy ports are never part of this runtime.
// Runtime configuration is ledger-backed; an environment override here would
// reintroduce an unverified authority path before the ledger is even loaded.
import {
  AIMOS_COMPANY_ID,
  AIMOS_SERVER_PORT,
  resolveAimosDatabaseName,
} from './services/core/runtime-config.js';

const PORT = AIMOS_SERVER_PORT;
const DATABASE_NAME = resolveAimosDatabaseName();
let backgroundBootPromise = null;
let backgroundReady = false;
let backgroundBootError = null;
let cr7BootRecoveryComplete = false;
let schedulerStatus = Object.freeze({ ready: false, state: 'not_started', required_jobs: 5 });

app.use(cors({ origin: /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/ }));
// Keep Express's native flat query parser; no qs extended/comma/prototype mode.
app.set('query parser', 'simple');
app.use(express.json({ limit: '1mb', verify(_req, _res, bytes, encoding) {
  try { assertUniqueJsonMembers(new TextDecoder(encoding, { fatal: true }).decode(bytes)); }
  catch (error) { error.status = 400; throw error; }
} }));

// ─── Request id — correlates client responses with server log lines ──────────
// Assigned as early as possible so every downstream middleware, route, and the
// terminal error handler can reference the same id.
app.use((req, res, next) => {
  req.id = randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// ─── R1 Step 6: rate limiting PRECEDES auth ───────────────────────────────────
// The auth gate does full cert-chain verification plus a DB revocation lookup —
// the expensive work. If the limiter sits AFTER the gate, an attacker floods
// unauthenticated requests straight into that expensive path (auth-flood DoS).
// General limit first, then a tighter per-IP limit for requests that arrive
// carrying an envelope (the ones that trigger the expensive verify), THEN auth.

// General rate limit: 100 requests per minute per IP
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Strict rate limit for sensitive routes: 60 req/min, no localhost bypass (CRIT-04 fix)
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests to sensitive endpoint, please try again later.' }
});

// Dedicated tight limiter for envelope-bearing requests. A request presenting a
// cert header forces a full cert-chain verify + revocation DB lookup even when
// it ultimately fails verification — that is the costliest path and was
// previously unthrottled. 30/min per IP is generous for a legitimate signer.
const envelopeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many cryptographic-envelope requests, please try again later.' }
});

function hasEnvelopeHeader(req) {
  // Express lowercases header names.
  return Boolean(req.headers['aimos-agent-cert'] || req.headers['aimos-agent-signature']);
}

// 1) General limiter — before anything expensive.
app.use(generalLimiter);
// 2) Envelope limiter — only for requests carrying an envelope, still before auth.
app.use((req, res, next) => (hasEnvelopeHeader(req) ? envelopeLimiter(req, res, next) : next()));

// Auth gate — single auth authority (Phase 10C: consolidated from two middleware into one)
// Authority: Miller 2006 Robust Composition, Hardy 1988 The Confused Deputy.
// No dual auth paths. No bearer tokens. Envelope or internal-service-token only.
if (!peekCachedCredential('aimos_api_token')) {
  console.warn('[SECURITY] aimos_api_token not present in keychain — internal service tokens only. Cryptographic envelope auth is active.');
}
// 3) Auth gate — now runs only for requests that survived the limiters.
app.use(authGate);

function lazyRouter(modulePath, label) {
  let routerPromise = null;
  return async (req, res, next) => {
    try {
      if (!routerPromise) {
        routerPromise = import(modulePath).then((moduleRef) => {
          if (typeof moduleRef?.default !== 'function') {
            throw new Error(`Route module ${modulePath} has no default Express router`);
          }
          return moduleRef.default;
        });
      }
      const router = await routerPromise;
      return router(req, res, next);
    } catch (error) {
      console.error(`[router:${label}] Failed to load route module:`, error?.message || String(error));
      return next(error);
    }
  };
}

// Apply strict rate limit to sensitive endpoints
app.use('/aimos/save', sensitiveLimiter);
app.use('/setup/aimos/identity', sensitiveLimiter);
app.use('/agents/:agentId/run', sensitiveLimiter);
app.use('/v1/ingest', sensitiveLimiter);
app.use('/security/campaign', sensitiveLimiter);
// R1 Step 6: extend strict limits to tool execution and MCP connect/execute.
// (/setup/aimos/identity/agents is already covered by the '/setup/aimos/identity'
// prefix mount above — do not duplicate.)
app.use('/tools', sensitiveLimiter);
app.use('/mcp/connect', sensitiveLimiter);
app.use('/mcp/execute', sensitiveLimiter);
app.use('/mcp/bridge/connect', sensitiveLimiter);
app.use('/mcp/bridge/execute', sensitiveLimiter);

app.use('/status', statusRoutes);
app.use('/stats', statusRoutes); // Backward-compatible alias consumed by desktop StatsView
app.use('/aimos', lazyRouter('./routes/aimos.js', 'aimos'));
app.use('/agents', lazyRouter('./routes/agents.js', 'agents'));
app.use('/task', lazyRouter('./routes/task.js', 'task'));
app.use('/tasks', lazyRouter('./routes/task.js', 'tasks')); // Backward-compatible alias used by desktop UI
app.use('/tools', lazyRouter('./routes/tools.js', 'tools'));
app.use('/permissions', lazyRouter('./routes/permissions.js', 'permissions'));
app.use('/integrations', lazyRouter('./routes/integrations.js', 'integrations'));
app.use('/memory', lazyRouter('./routes/memory.js', 'memory'));
app.use('/governance', lazyRouter('./routes/governance.js', 'governance'));
app.use('/settings', lazyRouter('./routes/settings.js', 'settings'));
app.use('/briefing', lazyRouter('./routes/briefing.js', 'briefing'));
app.use('/skills', lazyRouter('./routes/skills.js', 'skills'));
app.use('/command-center', lazyRouter('./routes/command-center.js', 'command-center'));
// Native StreamableHTTP MCP server — exposes Aimos as an MCP server to external clients
// (LM Studio, Goose, Claude Desktop, Cursor, etc.). Bridge routes moved to /mcp/bridge/*
app.use('/mcp', lazyRouter('./routes/aimos-mcp-streamable.js', 'aimos-mcp-streamable'));
// Legacy MCP bridge (external server management) — moved to /mcp/bridge/*
app.use('/mcp/bridge', lazyRouter('./routes/mcp.js', 'mcp-bridge'));
app.use('/setup', lazyRouter('./routes/setup.js', 'setup'));
app.use('/mobile', lazyRouter('./routes/mobile.js', 'mobile'));
app.use('/security', lazyRouter('./routes/security.js', 'security'));
app.use('/v1', lazyRouter('./routes/v1-api.js', 'v1-api'));

function buildHealthPayload() {
  return {
    service: 'FORGE Memory Aimos',
    version: '1.0.0',
    ready: getServingWorkState().phase === 'running' && backgroundReady && schedulerStatus.ready === true,
    bootError: backgroundBootError,
    readiness: {
      scheduler: schedulerStatus,
    },
    uptimeSec: Math.round(process.uptime()),
    runtime: {
      company_id: AIMOS_COMPANY_ID,
      database_name: DATABASE_NAME,
      server_port: PORT,
      benchmark_scratch: DATABASE_NAME.startsWith('aimos_benchmark_'),
      lifecycle: getServingWorkState(),
    },
  };
}

app.get('/healthz', (req, res) => {
  res.json(buildHealthPayload());
});

app.get('/health', (req, res) => {
  res.json(buildHealthPayload());
});

app.get('/', (req, res) => {
  res.json({ service: 'FORGE Memory Aimos', version: '1.0.0' });
});

// ─── TERMINAL ERROR HANDLER — must be registered AFTER all routes ─────────────
// Express identifies error middleware by its 4-arg signature. lazyRouter and any
// throwing handler call next(err) into here. Uniform shape:
//   { error: { code, message, requestId } }
// On a 500 the client gets a GENERIC message; the full detail (message + stack)
// goes to stderr only. Never leak err.message or a stack to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = Number(err?.statusCode || err?.status) || 500;
  const code = err?.code || (status === 500 ? 'internal_error' : 'request_error');
  console.error('[req-failed]', {
    reqId: req?.id,
    path: req?.path,
    method: req?.method,
    status,
    code,
    err: err?.message,
    stack: err?.stack
  });
  if (res.headersSent) {
    return next(err);
  }
  res.status(status).json({
    error: {
      code,
      // Generic message on 500; for <500 the caller-supplied publicMessage or the
      // code, but never the raw err.message and never a stack.
      message: status === 500 ? 'Internal error' : (err?.publicMessage || code),
      requestId: req?.id
    }
  });
});

async function startBackgroundServices() {
  if (backgroundBootPromise) return backgroundBootPromise;

  const finishBoot = beginServingWork('background_boot');
  backgroundBootPromise = (async () => {
    const companyId = 'hom';
    // Readiness checks the required native deployment, never applies DDL or
    // invokes installation. Source and SQL must agree before SAVE is ready.
    for (const [file,name,args,executable] of [
      ['atomic-save-origin.sql','ob3_native_save_input_ids','text,text,text,text,jsonb',true],
      ['atomic-save-origin.sql','commit_memory_origin_binding_v2','jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea,json',true],
      ['signed-json-bytes.sql','signed_json_shape_v1','json,integer',false],
      ['signed-json-bytes.sql','signed_json_bytes_commitment_v1','text,bytea',false],
      ['signed-event-bytes.sql','ob2_verify_signed_event','uuid,text',false],
      ['signed-event-bytes.sql','require_signed_event_bytes_v1','',false],
      ['cognitive-ancestry.sql','verify_cognitive_ancestry_bridge_v1','uuid,bytea,bytea,bytea',false],
      ['cognitive-ancestry.sql','apply_signed_cognitive_reweight','uuid,double precision,double precision,bytea,bytea',true],
      ['cognitive-ancestry.sql','verify_cognitive_weight_chain','uuid',true],
      ['request-target.sql','request_target_valid_v5','text',false],
      ['request-target.sql','request_signature_message_v5','bytea,text,text,jsonb,text,bigint',false],
    ]) {
      const nativeSql=readFileSync(new URL('./db/'+file,import.meta.url),'utf8');
      const definition=nativeSql.indexOf('CREATE OR REPLACE FUNCTION public.'+name+'(');
      const bodyStart=nativeSql.indexOf('AS $function$',definition)+'AS $function$'.length;
      const bodyEnd=nativeSql.indexOf('$function$;',bodyStart);
      const row=(await pool.query(`SELECT prosrc,has_function_privilege('agent_runtime',oid,'EXECUTE') AS executable
        FROM pg_proc WHERE oid=to_regprocedure($1)`,['public.'+name+'('+args+')'])).rows[0];
      if (definition<0 || bodyEnd<bodyStart || row?.prosrc!==nativeSql.slice(bodyStart,bodyEnd) || row.executable!==executable) {
        throw new Error('native_save_definition_not_deployed:'+name);
      }
    }
    const { ensureGovernanceReady } = await import('./services/orchestration/governance-resolver.js');
    const skillsRuntime = await import('./services/orchestration/skills-runtime.js');
    const { startScheduler, getSchedulerReadiness } = await import('./services/orchestration/scheduler.js');
    await ensureGovernanceReady(companyId);

    // ─── Wire #30: HNSW Optimizer — startup pg_prewarm + index verify ────────
    try {
      const { optimizeHNSWIndex, prewarmIndex, verifyIndexParams } = await import('./services/retrieval/hnsw-optimizer.js');
      const indexResult = await optimizeHNSWIndex(companyId);
      console.log(`[HNSW] Index status: created=${indexResult.created}, name=${indexResult.indexName}`);
      const verifyResult = await verifyIndexParams();
      if (verifyResult.warning) {
        console.warn(`[HNSW] Index warning: ${verifyResult.warning}`);
      }
      try {
        const prewarmResult = await prewarmIndex(companyId);
        console.log(`[HNSW] Prewarmed ${prewarmResult.pagesLoaded} pages`);
      } catch (prewarmErr) {
        console.warn('[HNSW] Prewarm skipped (pg_prewarm may not be installed):', prewarmErr.message);
      }
    } catch (hnswErr) {
      console.warn('[HNSW] Optimizer startup failed (non-fatal):', hnswErr.message);
    }

    if (typeof skillsRuntime.loadSkillsFromDiskAsync === 'function') {
      await skillsRuntime.loadSkillsFromDiskAsync();
    } else {
      skillsRuntime.loadSkillsFromDisk();
    }

    // A server is not recall-ready while its pinned local embedding model is
    // still cold. Complete one authority-free deterministic inference before
    // health advertises readiness; this prevents first-user requests from
    // absorbing model initialization and post-load memory pressure.
    const { prewarmEmbeddingRuntime } = await import('./services/core/embeddings.js');
    const embeddingReadiness = await prewarmEmbeddingRuntime();
    console.log(`[embeddings] Runtime ready: ${embeddingReadiness.dimension}d in ${embeddingReadiness.runtime_ms}ms`);

    // Freeze the completely verified recovery prefix before scheduler
    // admission can append a new Housekeeper event. Starting the scheduler
    // first creates a TOCTOU race between recovery-head verification and the
    // guarded checkpoint append.
    await checkpointCr7RecoveryAtBoot();
    // Recall readiness includes the retained calibration stream. Verify it
    // during boot so the first signed recall does not perform a cold full-
    // history proof inside the request deadline.
    const { getVerifiedCalibrationSnapshot } = await import('./services/retrieval/recall-calibrator.js');
    const calibrationSnapshot = await getVerifiedCalibrationSnapshot(companyId);
    console.log(`[calibration] Verified at boot: ${calibrationSnapshot.calibrationMutationHash}`);
    try {
      schedulerStatus = await startScheduler({ bootRecoveryComplete: cr7BootRecoveryComplete });
    } catch (error) {
      schedulerStatus = getSchedulerReadiness();
      throw error;
    }

    // ─── BOOT: run pending outcome scoring (don't wait for nightly dream) ─────
    const finishScoring = beginServingWork('boot_scoring');
    import('./services/agent-learning.js').then(async ({ scoreDueRecommendations }) => {
      await scoreDueRecommendations().then(r => {
        if (r?.scored?.length) console.log(`📊 Boot: scored ${r.scored.length} pending recommendations`);
      }).catch(() => {});
    }).catch(() => {}).finally(finishScoring);

    // ─── BOOT INTEGRITY: auto-verify architecture + services on startup ────
    try {
      const { runBootIntegrity } = await import('./jobs/boot-integrity.js');
      await runBootIntegrity();
    } catch (intErr) {
      console.warn('[BOOT-INTEGRITY] Check failed (non-fatal):', intErr.message);
    }

    // Readiness means the complete background boot has reached a terminal
    // state, including integrity inspection. Advertising ready before this
    // point lets a controlled restart terminate the process mid-audit.
    backgroundReady = getServingWorkState().phase === 'running';
    backgroundBootError = null;
    console.log('🧩 Background services ready');
  })().catch((error) => {
    backgroundReady = false;
    backgroundBootError = error?.message || String(error);
    console.error('Background boot failed:', backgroundBootError);
  }).finally(finishBoot);

  return backgroundBootPromise;
}

function cr7Metadata(event) {
  if (event?.metadata && typeof event.metadata === 'object') return event.metadata;
  try { return JSON.parse(event?.metadata || '{}'); } catch { return {}; }
}

function createCr7OpenReducer(createReducer, owners) {
  const eventId = (event) => String(event?.id || event?.event_id || '');
  const parentId = (event) => String(event?.parent_event_id || '');
  const schemaId = (schema) => (event) => cr7Metadata(event).schema === schema;
  const material = schemaId('hom.aimos.material-effect/v1');
  const tool = schemaId('aimos.tool-action/v1');
  const contextStart = schemaId('hom.aimos.tool-context/v1');
  const contextTerminal = (event) => ['hom.aimos.model-context-result/v1',
    'hom.aimos.model-context-terminal/v1'].includes(cr7Metadata(event).schema);
  const saveStart = schemaId('hom.aimos.canonical-save-action-start/v2');
  const run = schemaId('hom.aimos.agent-run-state/v1');
  const session = schemaId('hom.aimos.session-lane-transition/v1');
  const systemJob = schemaId('hom.aimos.system-job-run/v1');
  const schedule = schemaId('hom.aimos.schedule/v1');
  const definitions = [
    {
      name: 'material_effect', startOperations: ['material_effect_started'],
      terminalOperations: ['material_effect_terminal'],
      startId: (event) => material(event) ? cr7Metadata(event).action_id || event.key : null,
      terminalId: (event) => material(event) ? cr7Metadata(event).action_id || event.key : null,
      validate: owners.reconstructMaterialEffectTraces,
    },
    {
      name: 'tool_action', startOperations: ['tool_execution_started'],
      terminalOperations: ['tool_execution_terminal', 'tool_execution_succeeded',
        'tool_execution_failed', 'tool_execution_indeterminate'],
      startId: (event) => tool(event) ? eventId(event) : null,
      terminalId: (event) => tool(event) ? cr7Metadata(event).tool_action_event_id : null,
      validate: owners.reconstructToolActionTraces,
    },
    {
      name: 'model_context', startOperations: ['tool_context_prepared'],
      terminalOperations: ['model_context_completed', 'model_context_terminal'],
      startId: (event) => contextStart(event) ? eventId(event) : null,
      terminalId: (event) => contextTerminal(event)
        ? cr7Metadata(event).context_event_id || parentId(event) : null,
      validate: owners.reconstructModelContextTraces,
    },
    {
      name: 'canonical_save_action', startOperations: ['canonical_save_action_started'],
      terminalOperations: ['canonical_save_terminal', 'canonical_save_action_recovery_terminal'],
      relatedOperations: ['canary_write_scan_passed', 'canary_write_retained_quarantine',
        'security_content_decision'],
      relatedParentId: parentId,
      startId: (event) => saveStart(event) ? eventId(event) : null,
      terminalId: (event) => {
        const metadata = cr7Metadata(event);
        if (event.operation === 'canonical_save_action_recovery_terminal') {
          return metadata.start_event_id || parentId(event) || null;
        }
        const receipt = metadata.stages?.[1]?.evidence;
        return receipt?.kind === 'verified_housekeeper_action' ? receipt.event_id || null : null;
      },
      validate: owners.reconstructCanonicalSaveActionTraces,
    },
    {
      name: 'agent_run', startOperations: ['agent_run_started'],
      terminalOperations: ['agent_run_terminal'], relatedOperations: ['agent_run_awaiting_approval'],
      relatedParentId: parentId,
      startId: (event) => run(event) ? cr7Metadata(event).run_id || event.key : null,
      terminalId: (event) => run(event) ? cr7Metadata(event).run_id || event.key : null,
      validate: owners.reconstructRunTraces,
    },
    {
      name: 'session_lane', startOperations: ['session_lane_started'],
      terminalOperations: ['session_lane_terminal'],
      startId: (event) => session(event) ? `${cr7Metadata(event).session_key}:${cr7Metadata(event).run_id}` : null,
      terminalId: (event) => session(event) ? `${cr7Metadata(event).session_key}:${cr7Metadata(event).run_id}` : null,
      validate: owners.reconstructSessionLaneTraces,
    },
    {
      name: 'system_job', startOperations: ['system_job_started'],
      terminalOperations: ['system_job_terminal'],
      startId: (event) => systemJob(event) ? cr7Metadata(event).run_id || event.key : null,
      terminalId: (event) => systemJob(event) ? cr7Metadata(event).run_id || event.key : null,
      validate: owners.reconstructSystemJobRuns,
    },
    {
      name: 'schedule_run', startOperations: ['schedule_run_reserved'],
      terminalOperations: ['schedule_run_completed', 'schedule_run_failed'],
      startId: (event) => schedule(event) ? cr7Metadata(event).run_id || null : null,
      terminalId: (event) => schedule(event) ? cr7Metadata(event).run_id || null : null,
      validate: owners.reconstructDelegatedScheduleRuns,
    },
  ];
  return createReducer(definitions.filter(definition => typeof definition.validate === 'function'));
}

async function reconcileCr7OpenActionsAtBoot() {
  const { readVerifiedRecoveryHistory, createVerifiedOpenEventReducer } = await import('./services/observe/event-ledger.js');
  const { materialEffectOwner, reconstructMaterialEffectTraces } = await import('./services/security/material-effect-owner.js');
  const { reconcileOpenToolActions, reconstructToolActionTraces,
    reconcileOpenModelContexts, reconstructModelContextTraces } = await import('./services/orchestration/tool-action-ledger.js');
  const { credentialLedger } = await import('./services/security/credential-ledger.js');
  const { reconcileOpenCanonicalSaveActions, reconstructCanonicalSaveActionTraces } = await import('./services/write/canonical-save-owner.js');
  const { reconcileOpenRuns, reconstructRunTraces } = await import('./services/orchestration/run-metadata.js');
  const { reconcileOpenSessionLanes, reconstructSessionLaneTraces } = await import('./services/orchestration/session-runner.js');
  const operations = [
    'material_effect_started', 'material_effect_terminal',
    'tool_execution_started', 'tool_execution_terminal', 'tool_execution_succeeded',
    'tool_execution_failed', 'tool_execution_indeterminate',
    'tool_context_prepared', 'model_context_completed', 'model_context_terminal',
    'canonical_save_action_started', 'canonical_save_terminal',
    'canonical_save_action_recovery_terminal', 'canary_write_scan_passed',
    'canary_write_retained_quarantine', 'security_content_decision',
    'agent_run_started', 'agent_run_awaiting_approval', 'agent_run_terminal',
    'session_lane_started', 'session_lane_terminal',
  ];
  const reducerOwners = { reconstructMaterialEffectTraces, reconstructToolActionTraces,
    reconstructModelContextTraces, reconstructCanonicalSaveActionTraces,
    reconstructRunTraces, reconstructSessionLaneTraces };
  const handlers = {
    material_effect: readHistoryFn => materialEffectOwner.reconcileOpen({ historyFn:readHistoryFn }),
    tool_action: readHistoryFn => reconcileOpenToolActions({ readHistoryFn }),
    model_context: readHistoryFn => reconcileOpenModelContexts({ readHistoryFn }),
    canonical_save_action: readHistoryFn => reconcileOpenCanonicalSaveActions({ readHistoryFn }),
    agent_run: readHistoryFn => reconcileOpenRuns({ readHistoryFn }),
    session_lane: readHistoryFn => reconcileOpenSessionLanes({ readHistoryFn }),
  };
  const counts = Object.fromEntries(Object.keys(handlers).map(name => [name,0]));
  await readVerifiedRecoveryHistory(AIMOS_COMPANY_ID, {
    signerAgentId: 'housekeeper', operations,
    reducer: createCr7OpenReducer(createVerifiedOpenEventReducer, reducerOwners),
    onOpenGroup: async (_rows,{family,readHistoryFn}) => {
      const result=await handlers[family](readHistoryFn);
      if(result.remainingOpen!==0)throw new Error('cr7_recovery_open_actions_remain:'+family+':'+result.remainingOpen);
      counts[family]+=result.reconciled.length;
    },
  });
  const openCredentialUses = await credentialLedger.findOpenCredentialUses();
  if(openCredentialUses.length) {
    const result=await credentialLedger.reconcileOpenCredentialUses();
    if(result.remainingOpen!==0)throw new Error('cr7_recovery_open_actions_remain:credential_use:'+result.remainingOpen);
    counts.credential_use=result.reconciled.length;
  } else {
    counts.credential_use=0;
  }
  console.log('[BOOT] CR7 action recovery complete:', Object.entries(counts).map(([family, count]) => (
    `${family}=${count}`
  )).join(' '));
}

async function checkpointCr7RecoveryAtBoot() {
  const { readVerifiedRecoveryHistory, writeVerifiedRecoveryCheckpoint,
    createVerifiedOpenEventReducer } = await import('./services/observe/event-ledger.js');
  const { reconstructMaterialEffectTraces } = await import('./services/security/material-effect-owner.js');
  const { reconstructToolActionTraces, reconstructModelContextTraces } = await import('./services/orchestration/tool-action-ledger.js');
  const { reconstructCanonicalSaveActionTraces } = await import('./services/write/canonical-save-owner.js');
  const { reconstructRunTraces } = await import('./services/orchestration/run-metadata.js');
  const { reconstructSessionLaneTraces } = await import('./services/orchestration/session-runner.js');
  const { reconstructSystemJobRuns, reconstructDelegatedScheduleRuns } = await import('./services/orchestration/scheduler.js');
  const operations = [
    'material_effect_started', 'material_effect_terminal',
    'tool_execution_started', 'tool_execution_terminal', 'tool_execution_succeeded',
    'tool_execution_failed', 'tool_execution_indeterminate',
    'tool_context_prepared', 'model_context_completed', 'model_context_terminal',
    'canonical_save_action_started', 'canonical_save_terminal',
    'canonical_save_action_recovery_terminal', 'canary_write_scan_passed',
    'canary_write_retained_quarantine', 'security_content_decision',
    'agent_run_started', 'agent_run_awaiting_approval', 'agent_run_terminal',
    'session_lane_started', 'session_lane_terminal',
    'system_job_started', 'system_job_terminal',
    'schedule_run_reserved', 'schedule_run_completed', 'schedule_run_failed',
  ];
  let remaining = 0;
  const recovery = await readVerifiedRecoveryHistory(AIMOS_COMPANY_ID, {
    signerAgentId: 'housekeeper', operations,
    reducer: createCr7OpenReducer(createVerifiedOpenEventReducer, {
      reconstructMaterialEffectTraces, reconstructToolActionTraces,
      reconstructModelContextTraces, reconstructCanonicalSaveActionTraces,
      reconstructRunTraces, reconstructSessionLaneTraces,
      reconstructSystemJobRuns, reconstructDelegatedScheduleRuns,
    }),
    onOpenGroup: async () => { remaining += 1; },
  });
  if (remaining !== 0) throw new Error(`event_recovery_checkpoint_open_actions:${remaining}`);
  const receipt = await writeVerifiedRecoveryCheckpoint(AIMOS_COMPANY_ID, recovery.summary);
  console.log('[BOOT] verified recovery checkpoint:', receipt.existing ? 'current' : receipt.event_id);
}

async function startServer() {
  // Load operator delegation config (OPERATOR_AGENT_ID, etc.) into the
  // in-memory verified store BEFORE accepting traffic. The store is the
  // runtime truth — readConfigString() never hits the DB on the request
  // path. If loadAll fails (DB down, master pubkey unavailable), the store
  // stays empty and readConfigString returns null → callers handle null
  // explicitly (no fallback to any hardcoded agent). Agent-free invariant.
  try {
    await systemConfigStore.loadAll();
    console.log('[BOOT] systemConfigStore loaded — config:', JSON.stringify(systemConfigStore._peek()));
  } catch (err) {
    console.error('[BOOT] systemConfigStore loadAll failed — readConfigString returns null:', err?.message || String(err));
  }
  // Load credentials from versioned Keychain slots into the sync-boot cache.
  // Keychain plus signed lifecycle evidence is the only credential authority.
  try {
    await loadCredentialCache();
  } catch (err) {
    console.error('[BOOT] credentialCache load failed — server admission remains closed:', err?.message || String(err));
    throw err;
  }
  // Reconstruct and close every retained orphan before accepting traffic.
  // Recovery appends INDETERMINATE terminals only; it never replays SAVE,
  // provider, tool, credential, file, process, run, response, or session work.
  await reconcileCr7OpenActionsAtBoot();
  cr7BootRecoveryComplete = true;
  if (getServingWorkState().phase !== 'running') return;
  listener = app.listen(PORT, '127.0.0.1', () => {
    if (getServingWorkState().phase !== 'running') return;
    console.log(`🧠 FORGE Aimos running on 127.0.0.1:${PORT} (localhost only)`);
    // Warm heavy dependencies in the background so health/status can respond immediately.
    void startBackgroundServices();
  });
  listener.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
}

const finishServerBoot = beginServingWork('server_boot');
startServer().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
}).finally(finishServerBoot);

// ─── UNCAUGHT EXCEPTION / REJECTION HANDLER ───────────────────────────────────
// uncaughtException leaves the process in an unknown state → exit so the process
// manager (launchd plist, PM2, or the heartbeat cron) restarts cleanly.
//
// unhandledRejection is DIFFERENT: it is often a forgotten `await` on a
// diagnostic call whose dependency momentarily failed.
// Exiting on it converts a logged warning into a full outage. We LOG and stay
// alive. The floating promises are individually hardened with
// `.catch(e => console.warn(...))` (see Step 7), so this is a backstop, not the
// primary defense.
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception — server will restart:', err?.message, err?.stack);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[unhandled-rejection]', {
    reason: reason?.message || String(reason),
    stack: reason?.stack
  });
  // Deliberately do NOT exit — see rationale above.
});

function shutdown(signal) {
  if (shutdownPromise) return shutdownPromise;
  beginServingDrain();
  const workAtSignal = getServingWorkState();
  backgroundReady = false;
  const startedAt = performance.now();
  // The manager grants40s. This watchdog reports failure, never successful
  // rollback, if even the terminal ledger or pool close cannot settle in30s.
  const watchdog = setTimeout(() => {
    console.error('[shutdown-indeterminate]', JSON.stringify({ signal, runtime: getServingWorkState(),
      reason: 'shutdown_terminal_or_resource_close_deadline', durable_actions_replayed: false }));
    process.exit(1);
  }, 30_000);
  shutdownPromise = (async () => {
    if (listener) {
      listener.close(() => { listenerClosed = true; });
      listener.closeIdleConnections();
    } else listenerClosed = true;
    const scheduler = await import('./services/orchestration/scheduler.js');
    scheduler.stopScheduler();
    const sessions = await import('./services/orchestration/session-runner.js');
    sessions.stopSessionAdmission();
    const mcp = await import('./routes/aimos-mcp-streamable.js');
    mcp.closeMcpStreamsForShutdown();
    const { logEvent } = await import('./services/observe/event-ledger.js');
    const start = await logEvent(AIMOS_COMPANY_ID, 'housekeeper', 'runtime_shutdown_started', String(process.pid), {
      signal, pid: process.pid, deadline_ms: DRAIN_WAIT_MS, work_at_signal: workAtSignal,
      reasoning: 'Managed shutdown stopped native request, session and scheduler admission before joining accepted work.',
    }, null, { returnReceipt: true });
    while (performance.now() - startedAt < DRAIN_WAIT_MS) {
      if (!getServingWorkState().active && !scheduler.getSchedulerWorkState().activeJobs && listenerClosed) break;
      const state = getServingWorkState();
      if (state.active === (state.counts.http_response || 0) && !scheduler.getSchedulerWorkState().activeJobs) {
        for (const res of responses) {
          if (String(res.getHeader('Content-Type') || '').includes('text/event-stream') && !res.writableEnded) res.end();
        }
      }
      if (performance.now() - startedAt >= 15_000) {
        cancelServingWork();
        scheduler.cancelSchedulerWork();
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    const remaining = getServingWorkState();
    const jobs = scheduler.getSchedulerWorkState();
    const drained = remaining.active === 0 && jobs.activeJobs === 0 && listenerClosed;
    await logEvent(AIMOS_COMPANY_ID, 'housekeeper', 'runtime_shutdown_terminal', String(process.pid), {
      signal, pid: process.pid, disposition: drained ? 'DRAINED' : 'INDETERMINATE',
      remaining_work: remaining, remaining_jobs: jobs.activeJobs,
      start_event_id: start.event_id, start_mutation_hash: start.mutation_hash,
      reasoning: drained ? 'Accepted native owners settled before database closure.'
        : 'The drain deadline expired; retained action starts remain for independent restart reconciliation. No rollback or successful completion is inferred.',
    }, start.event_id);
    if (!drained) {
      listener?.closeAllConnections();
      for (const socket of sockets) socket.destroy();
      // In-flight owners may still hold transactions. Exiting closes their
      // connections; next boot reconstructs commit truth, never replays effects.
      process.exitCode = 1;
      return;
    }
    finishServingDrain();
    await Promise.all([schedulerLockPool.end(), agentPool.end(), pool.end()]);
    process.exitCode = 0;
  })().catch(error => {
    console.error('[shutdown-indeterminate]', error?.stack || error);
    process.exitCode = 1;
  }).finally(() => {
    clearTimeout(watchdog);
    process.exit(process.exitCode || 0);
  });
  return shutdownPromise;
}

process.on('SIGINT', () => { void shutdown('SIGINT'); });
process.on('SIGTERM', () => { void shutdown('SIGTERM'); });

// ─── SIGHUP — config reload (Unix pattern: nginx/apache/synapse) ───────────────
// set-system-config.js sends SIGHUP after a delegation commit to
// aimos_system_config. The server reloads signed configuration and credentials
// without dropping traffic. If reload fails, the store keeps its
// last-known-good values — the server does NOT silently shadow. Operator can
// diagnose via /status.
process.on('SIGHUP', async () => {
  if (getServingWorkState().phase !== 'running') return;
  const finishReload = beginServingWork('configuration_reload');
  try {
  console.log('[SIGHUP] received — reloading systemConfigStore + credentialCache from signed authority');
  try {
    await systemConfigStore.reload();
    console.log('[SIGHUP] systemConfigStore reloaded — config:', JSON.stringify(systemConfigStore._peek()));
  } catch (err) {
    console.error('[SIGHUP] systemConfigStore reload failed — keeping last-known-good values:', err?.message || String(err));
  }
  try {
    await reloadCredentialCache();
    console.log('[SIGHUP] credentialCache reloaded');
  } catch (err) {
    console.error('[SIGHUP] credentialCache reload published explicit unavailable state for affected slots:', err?.message || String(err));
  }
  } finally { finishReload(); }
});
