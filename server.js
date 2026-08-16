import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'crypto';
import { pool } from './db/connection.js';
import statusRoutes from './routes/status.js';
import { authGate } from './services/security/auth-gate.js';
import { systemConfigStore } from './services/security/system-config-store.js';
import { loadCredentialCache, reloadCredentialCache, peekCachedCredential } from './services/security/credential-cache.js';

const app = express();
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

app.use(cors({ origin: /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/ }));
app.use(express.json({ limit: '1mb' }));

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
    ready: backgroundReady,
    bootError: backgroundBootError,
    uptimeSec: Math.round(process.uptime()),
    runtime: {
      company_id: AIMOS_COMPANY_ID,
      database_name: DATABASE_NAME,
      server_port: PORT,
      benchmark_scratch: DATABASE_NAME.startsWith('aimos_benchmark_'),
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

  backgroundBootPromise = (async () => {
    const companyId = 'hom';
    const { ensureGovernanceReady } = await import('./services/orchestration/governance-resolver.js');
    const skillsRuntime = await import('./services/orchestration/skills-runtime.js');
    const { startScheduler } = await import('./services/orchestration/scheduler.js');
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

    await startScheduler();
    backgroundReady = true;
    backgroundBootError = null;

    // ─── BOOT: run pending outcome scoring (don't wait for nightly dream) ─────
    import('./services/agent-learning.js').then(({ scoreDueRecommendations }) => {
      scoreDueRecommendations().then(r => {
        if (r?.scored?.length) console.log(`📊 Boot: scored ${r.scored.length} pending recommendations`);
      }).catch(() => {});
    }).catch(() => {});

    // ─── BOOT INTEGRITY: auto-verify architecture + services on startup ────
    try {
      const { runBootIntegrity } = await import('./jobs/boot-integrity.js');
      await runBootIntegrity();
    } catch (intErr) {
      console.warn('[BOOT-INTEGRITY] Check failed (non-fatal):', intErr.message);
    }

    console.log('🧩 Background services ready');
  })().catch((error) => {
    backgroundReady = false;
    backgroundBootError = error?.message || String(error);
    console.error('Background boot failed:', backgroundBootError);
  });

  return backgroundBootPromise;
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
    console.error('[BOOT] credentialCache loadAll failed — getCachedCredential returns null:', err?.message || String(err));
  }
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`🧠 FORGE Aimos running on 127.0.0.1:${PORT} (localhost only)`);
    // Warm heavy dependencies in the background so health/status can respond immediately.
    void startBackgroundServices();
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
});

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

async function shutdown() {
  try {
    const { stopScheduler } = await import('./services/orchestration/scheduler.js');
    stopScheduler();
  } catch (error) {
    console.warn('Shutdown warning:', error?.message || String(error));
  }
  // session-runner.js starts a conversation-session cleanup interval at module
  // load (line 383) but nothing was clearing it on shutdown — the only genuine
  // setInterval gap of defect 11 (the other three watchers already stop cleanly).
  // Without this, the lingering interval keeps the event loop alive past SIGTERM.
  try {
    const { stopConversationSessionCleanup } = await import('./services/orchestration/session-runner.js');
    stopConversationSessionCleanup();
  } catch { /* already stopped */ }
  await pool.end();
}

process.on('SIGINT', async () => {
  await shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await shutdown();
  process.exit(0);
});

// ─── SIGHUP — config reload (Unix pattern: nginx/apache/synapse) ───────────────
// set-system-config.js sends SIGHUP after a delegation commit to
// aimos_system_config. The server reloads signed configuration and credentials
// without dropping traffic. If reload fails, the store keeps its
// last-known-good values — the server does NOT silently shadow. Operator can
// diagnose via /status.
process.on('SIGHUP', async () => {
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
    console.error('[SIGHUP] credentialCache reload failed — keeping last-known-good values:', err?.message || String(err));
  }
});
