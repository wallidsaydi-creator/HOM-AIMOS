/**
 * aimos.js — Memory OS API Surface
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ↔ Interacts with: asmr-pipeline.js (Drives hybrid retrieval and answering)
 * 2. ↔ Interacts with: knowledge-gate.js (Receives 'Knowledge Proofs' for RLS authorization)
 * 3. ↔ Interacts with: db/connection.js (Utilizes 'secureQuery' for agent-initiated writes)
 * 4. → Pushes to: security.security_audit_log (Forensic logging of all memory operations)
 * 5. → Calls: curator.js (Detects logical conflicts and reasoning drifts during save)
 *
 * LOGIC GUIDE (High-Integrity Save): If a 'knowledge_proof' is provided, the API
 * switches to the 'agent_runtime' DB user. This user is subject to Row-Level
 * Security (RLS) and is protocol-blocked from deleting any records (Aladdin Law).
 */
import express from 'express';
import { randomUUID } from 'node:crypto';
import { query, withTransaction } from '../db/connection.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import { getEmbedding } from '../services/core/embeddings.js';
import { logEvent, readVerifiedEventById } from '../services/observe/event-ledger.js';
import { runNightlyDream } from '../jobs/nightly-dream.js';
import { runHeartbeat } from '../jobs/heartbeat.js';
import { claimDirective, completeDirectiveClaim, createDirective } from '../services/core/directive-claims.js';
import {
  buildOrcaCalibrationReadiness,
  getCalibrationStatus,
  recordCalibrationObservationBatch,
} from '../services/retrieval/recall-calibrator.js';
import { requireCapability } from '../services/security/require-capability.js';
import { buildTrustAlignmentDiagnostics } from '../services/learning/trust-score.js';
import { buildEngramPoolDiagnostics } from '../services/core/concept-graph.js';
import { semanticCache } from '../services/caching/semantic-cache.js';
import { executeCanonicalSave } from '../services/write/canonical-save-owner.js';
import { saveCompactionMemory } from '../services/write/compaction-save.js';
import { savePostCompactionDelivery } from '../services/context/post-compaction-delivery.js';
import { sessionMemoryOwner } from '../services/orchestration/session-memory-owner.js';
import { recallAuthorizationService } from '../services/security/recall-authorization.js';
import { verifiedRequestAuthorityFromRequest } from '../services/security/auth-gate.js';
import { readAgentBDIState, updateAgentState } from '../services/orchestration/agent-bdi-state.js';
import { executeCanonicalRecall } from '../services/retrieval/native-recall-pipeline.js';
import { RECALL_SPEED_CONFIG as SPEED_CONFIG } from '../services/retrieval/recall-runtime-config.js';
import { memoryLineageLedger } from '../services/security/memory-lineage.js';
import { getOperatorAgentId, normalizeOperatorAgentId } from '../services/security/system-config-store.js';
import { genesisHashFor } from '../services/security/identity-chain.js';
import { buildLifelongMemoryContract } from '../services/context/context-renewal.js';
import { buildSpeculativeVerificationContract, META_ACTIONS } from '../services/orchestration/meta-controller.js';
import { buildScratPipelineStatus } from '../services/orchestration/explore-exploit-loop.js';
import { buildOntologyAwarePatternMap } from '../services/observe/architecture-registry.js';
import { buildTemporalHomeostasisDiagnostics } from '../services/observe/retrieval-drift-monitor.js';
import { buildOscillatorySTDPStatus } from '../services/learning/stdp-kernel.js';
import { getAgentPsychometricStatus } from '../services/learning/agent-learning.js';
import { buildTurnAdaptiveBudgetStatus } from '../services/observe/energy-budget.js';
import { buildLatentLookaheadStatus } from '../services/observe/agent-trace.js';
import { buildEvolveRouterStatus } from '../services/observe/routing-monitor.js';
import { buildEpistemicBlindingStatus } from '../services/learning/epistemic-vigilance.js';
import { buildAgscStatus, buildKeyedPrefetchStatus, buildNiyamaServingStatus, buildRobustLengthStatus, buildTokenScaleStatus } from '../services/runtime/serving-control.js';
import {
  buildKvCacheAndLayoutPlan,
  buildLocalMemoryPlacementPlan,
  buildLpcSmSmallModelPlan,
  buildMicroBottleneckDiagnostic,
  buildMoEExpertSchedulingPlan,
  buildNexusIoOffloadPlan,
  buildTurboQuantReadiness,
  buildWave5LocalInferenceStatus,
} from '../services/runtime/local-inference-control.js';



// ─── SPEED CONFIG — Phase 1-2 toggles (default OFF) ──────────────────────────
// Persistent configuration is read from the signed configuration ledgers at
// each owning subsystem; these defaults deliberately do not read environment.





























const SERVER_BOOT_TIME = new Date().toISOString();

const router = express.Router();

function b64u(buf) {
  return Buffer.isBuffer(buf) ? buf.toString('base64url') : null;
}

function chainStatusFor(reason) {
  if (reason === 'agent_revoked' || reason === 'agent_not_active') return 401;
  return ['fork_detected', 'first_save_must_use_genesis'].includes(reason) ? 409 : 400;
}

const AIMOS_NATIVE_DIAGNOSTIC_ROUTES = new Set([
  '/recall/calibration/status',
  '/recall/trust-alignment/status',
  '/architecture/ontology-patterns',
  '/memory/lifelong/status',
  '/memory/homeostasis/status',
  '/memory/engram-pools/status',
  '/learning/oscillatory-stdp/status',
  '/orchestration/open-loop/status',
  '/orchestration/scrat/status',
  '/orchestration/turn-budget/status',
  '/orchestration/lookahead/status',
  '/orchestration/evolve-router/status',
  '/orchestration/epistemic-blinding/status',
  '/serving/qos/status',
  '/serving/prefetch/status',
  '/serving/tokenscale/status',
  '/serving/length/status',
  '/serving/agsc/status',
  '/serving/local/status',
  '/serving/local/quantization/status',
  '/serving/local/moe/status',
  '/serving/local/kv/status',
  '/serving/local/memory/status',
  '/serving/local/io/status',
  '/serving/local/lpc-sm/status',
]);

function hasAimosReadContext(req) {
  if (req.identityAuthenticatedBy === 'internal_token') return true;
  const tier = String(req.identityTier || 'T0').toUpperCase();
  return req.identityAuthenticatedBy === 'envelope' && ['T1', 'T2', 'T3'].includes(tier);
}

function requireAimosEnvelopeAgent(req, res, { allowSystemSelfHousekeeper = false } = {}) {
  const tier = String(req.identityTier || 'T0').toUpperCase();
  const agentId = req.agentId || req.identityCert?.agent_id;
  const standardAgent = ['T1', 'T2', 'T3'].includes(tier);
  const systemSelfHousekeeper = allowSystemSelfHousekeeper
    && tier === 'T1_SYSTEM_SELF'
    && agentId === 'housekeeper';
  if (req.identityAuthenticatedBy !== 'envelope'
    || !agentId
    || (!standardAgent && !systemSelfHousekeeper)) {
    res.status(401).json({
      success: false,
      error: 'cryptographic agent envelope required',
      required: 'Aimos-Agent-Cert, Aimos-Agent-Signature, Aimos-Agent-Nonce, Aimos-Agent-Timestamp',
    });
    return null;
  }
  return {
    agentId,
    tier,
    validFrom: req.identityValidFromIso || null,
  };
}

function verifiedRequestAuthorityFromReq(req) {
  return verifiedRequestAuthorityFromRequest(req);
}

async function requireSessionWriteContext(req, res) {
  const identity = requireAimosEnvelopeAgent(req, res, {
    allowSystemSelfHousekeeper: true,
  });
  if (!identity) return null;
  const companyId = req.executionContext?.companyId || req.body?.company_id || AIMOS_COMPANY_ID;
  if (req.body?.company_id && req.body.company_id !== companyId) {
    res.status(403).json({ success: false, error: 'session_company_mismatch' });
    return null;
  }
  if (req.body?.agent_id && req.body.agent_id !== identity.agentId) {
    res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
    return null;
  }
  let clearanceCeiling = 0;
  if (['T1', 'T1_SYSTEM_SELF'].includes(identity.tier) && identity.agentId === 'housekeeper') {
    clearanceCeiling = 12;
  } else {
    const grant = await recallAuthorizationService.getEffective({
      companyId,
      subjectAgentId: identity.agentId,
      subjectValidFrom: identity.validFrom,
    });
    if (!grant?.allowed || !grant.writeAllowed) {
      res.status(403).json({ success: false, error: 'master_signed_memory_write_grant_required' });
      return null;
    }
    clearanceCeiling = grant.clearanceCeiling;
  }
  const requestedClearance = Number(req.body?.clearance_level ?? 1);
  if (!Number.isInteger(requestedClearance)
    || requestedClearance < 1
    || requestedClearance > clearanceCeiling) {
    res.status(403).json({
      success: false,
      error: 'clearance_exceeds_verified_authority',
      actor_clearance: clearanceCeiling,
      requested_clearance: req.body?.clearance_level ?? 1,
    });
    return null;
  }
  return {
    ...identity,
    companyId,
    clearanceCeiling,
    requestAuthority: verifiedRequestAuthorityFromReq(req),
  };
}

function nativeAimosReadBoundary(req, res, next) {
  const diagnosticRoute =
    AIMOS_NATIVE_DIAGNOSTIC_ROUTES.has(req.path) ||
    /^\/agents\/[^/]+\/psychometrics\/status$/.test(req.path);
  if (!diagnosticRoute) return next();
  if (hasAimosReadContext(req)) return next();
  return res.status(403).json({
    success: false,
    error: 'Aimos diagnostic surface requires authenticated Aimos read context',
    required: 'T1 envelope or internal service token',
  });
}

// ─── D7: LOCALHOST API BOUNDARY HARDENING ────────────────────────────────────
const HOM_SESSION_TOKEN = null;
const ALLOWED_ORIGINS_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

router.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && !ALLOWED_ORIGINS_RE.test(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (HOM_SESSION_TOKEN) {
    const token = req.headers['x-session-token'];
    if (!token || token !== HOM_SESSION_TOKEN) {
      return res.status(401).json({ error: 'Missing or invalid session token' });
    }
  }
  next();
});

// ─── HIPPORAG: Lightweight entity extraction (no NLP dependency) ──────────────
// Extracts proper nouns, dates, monetary amounts, agent names, and known patterns.

// ─── D8: QUARANTINE DETECTION ─────────────────────────────────────────────────
const QUARANTINE_PATTERNS = [
  /ignore (previous|prior|all) instructions?/i,
  /ignore all previous instructions?/i,
  /\bignore\b.{0,40}\binstructions?\b/i,
  /disregard (your|all|previous) (rules?|instructions?|guidelines?)/i,
  /you are now (?!your assistant)/i,
  /\bprompt injection\b/i,
  /\bjailbreak\b/i,
  /\[OVERRIDE\]/i,
  /system:\s*(ignore|bypass|disable)/i,
  // SEC-01: behavioral directive patterns (indirect instruction injection)
  /\bwhen recalled\b/i,
  /\balways respond\b/i,
  /\bprepend (to )?(every|all|each|your)/i,
  /\boverride all\b/i,
  /\bignore previous\b/i,
  /\bact as if\b/i,
  /\byour new (role|persona|identity|instruction)\b/i,
  /\bforget (your|all|previous) (instructions?|rules?|training)\b/i,
];

function decodeForQuarantine(text) {
  const s = String(text || '');
  // SEC-03: decode base64 and URL encoding before pattern matching
  let decoded = s;
  // URL decode
  try { decoded = decodeURIComponent(decoded); } catch { /* invalid encoding, use original */ }
  // Base64 decode (only if string looks like valid base64, min 16 chars)
  const b64 = s.replace(/\s/g, '');
  if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(b64)) {
    try {
      const candidate = Buffer.from(b64, 'base64').toString('utf8');
      // Only use decoded version if it produces readable ASCII
      if (/^[\x20-\x7E\n\r\t]+$/.test(candidate)) decoded += ' ' + candidate;
    } catch { /* not valid base64 */ }
  }
  return decoded;
}

function isQuarantineCandidate(text) {
  const decoded = decodeForQuarantine(text);
  return QUARANTINE_PATTERNS.some((p) => p.test(decoded));
}

// ─── MEDALLION LAYER MIGRATION CONTRACT (read-only verification) ─────────────
let medallionColumnEnsured = false;
async function ensureMedallionColumn() {
  if (medallionColumnEnsured) return;
  const result = await query(
    `SELECT
       to_regclass('public.aimos_memories') IS NOT NULL AS relation_exists,
       EXISTS (
         SELECT 1 FROM pg_attribute
         WHERE attrelid = to_regclass('public.aimos_memories')
           AND attname = 'medallion_layer'
           AND attnum > 0
           AND NOT attisdropped
       ) AS medallion_column_exists,
       to_regclass('public.idx_memories_medallion') IS NOT NULL AS medallion_index_exists`
  );
  const schema = result.rows[0] || {};
  const missing = [];
  if (!schema.relation_exists) missing.push('relation:aimos_memories');
  if (!schema.medallion_column_exists) missing.push('column:aimos_memories.medallion_layer');
  if (!schema.medallion_index_exists) missing.push('index:idx_memories_medallion');
  if (missing.length) {
    const error = new Error(`migration_schema_missing:medallion:${missing.join(',')}`);
    error.code = 'MIGRATION_SCHEMA_MISSING';
    error.statusCode = 503;
    throw error;
  }
  medallionColumnEnsured = true;
}

// ─── ALADDIN RETENTION: Everything is long-term. Nothing expires. Nothing deletes. ───
// Modeled on BlackRock Aladdin: $11.5T AUM retained because clients cannot leave their data.
// Storage is cheap, retrieval quality is the bottleneck. Keep everything, surface the right thing.
// Columns memory_tier, expires_at, promoted_at remain in DB schema for compatibility but are
// functionally fixed: memory_tier='long-term', expires_at=NULL, always.

// Canonical SAVE composition is owned by services/write/canonical-save-owner.js.
// All helper functions (normalizeOperatorAgentId, isOperatorAgentId,
// isQuarantineCandidate, extractEntities, inferMedallionLayer,
// ensureMedallionColumn) remain here for use
// by other aimos.js routes (recall, status, etc.).

// ─── MEDALLION: Infer layer from memory_type ──────────────────────────────────
function inferMedallionLayer(memoryType) {
  const gold = new Set(['milestone','product','identity','procedural','crew_identity','dream_summary','self_improvement','infrastructure']);
  const silver = new Set(['session','directive','heartbeat','intel','constitution_check','test']);
  if (gold.has(memoryType)) return 'gold';
  if (silver.has(memoryType)) return 'silver';
  return 'bronze';
}

const DIRECTIVE_BLOCK_PATTERNS = [
  /\bsandbox[_\s-]*mode\b/i,
  /\btool\s*sandbox\s*mode\b/i,
  /\bsandbox(?:ing|ed)?\b/i,
  /--dangerously-skip-permissions/i,
  /\bhardcod(?:e|ed|ing)\b/i
];

function sanitizeDirectiveGoal(goal = '') {
  const text = String(goal || '');
  if (!text.trim()) {
    return { sanitizedGoal: '', removedLines: [] };
  }

  const removedLines = [];
  const keptLines = [];
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    const blocked = DIRECTIVE_BLOCK_PATTERNS.some((pattern) => pattern.test(line));
    if (blocked) {
      const trimmed = line.trim();
      if (trimmed) removedLines.push(trimmed);
      continue;
    }
    keptLines.push(line);
  }

  const sanitizedGoal = keptLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  return { sanitizedGoal, removedLines };
}

// ─── EVENT LEDGER (called by Swift AimosCore.logEvent) ──────────────────────
router.post('/event', async (req, res, next) => {
  const { company_id, agent_id, operation, key, metadata } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.companyId) {
    return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  }
  const actorAgentId = context.actorAgentId;
  const cid = context.companyId;
  if (agent_id && agent_id !== actorAgentId) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }
  if (company_id && company_id !== cid) {
    return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
  }
  try {
    const receipt = await logEvent(cid, actorAgentId, operation || 'event', key || null, {
      ...(metadata && typeof metadata === 'object' ? metadata : {}),
      reasoning: metadata?.reasoning || `Swift/external event logged: operation=${operation || 'event'}, key=${key || 'none'}`,
      source_knowledge: metadata?.source_knowledge || 'external caller (Swift AimosCore or API client)'
    }, null, {
      returnReceipt: true,
      authority: {
        actorAgentId,
        actorValidFromIso: req.identityValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
      },
    });
    res.status(201).json({ success: true, receipt });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/status', async (req, res, next) => {
  try {
    const result = await query('SELECT COUNT(*) as total FROM aimos_memories WHERE company_id = $1', [AIMOS_COMPANY_ID]);
    res.json({
      connected: true,
      total_memories: parseInt(result.rows[0].total),
      speed_flags: {
        cache_enabled: SPEED_CONFIG.cache.enabled,
        early_exit_enabled: SPEED_CONFIG.earlyExit.enabled,
        governance_enabled: SPEED_CONFIG.governance.enabled,
        instrumentation_enabled: SPEED_CONFIG.instrumentation.enabled
      },
      cache_stats: SPEED_CONFIG.cache.enabled ? semanticCache.getStats() : null,
      server_started_at: SERVER_BOOT_TIME
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/chain-head', async (req, res, next) => {
  try {
    const identityTier = String(req.identityTier || 'T0').toUpperCase();
    const agentId = req.identityCert?.agent_id;
    const validFromIso = req.identityValidFromIso;
    if (!['T1', 'T2', 'T3'].includes(identityTier) || !agentId || !validFromIso) {
      return res.status(401).json({
        success: false,
        error: 'cryptographic identity required'
      });
    }

    const result = await query(
      `SELECT chain_head FROM agent_identity ai
        WHERE agent_id = $1 AND valid_from = $2
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events r
             WHERE r.agent_id = ai.agent_id
               AND r.agent_valid_from = ai.valid_from
          )`,
      [agentId, validFromIso]
    );
    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        error: 'agent_not_active'
      });
    }

    const chainHead = result.rows[0].chain_head;
    const previousChainHash = chainHead || genesisHashFor(agentId, validFromIso);
    res.json({
      success: true,
      agent_id: agentId,
      valid_from: validFromIso,
      identity_tier: identityTier,
      chain_head: b64u(chainHead),
      previous_chain_hash: b64u(previousChainHash),
      previous_is_genesis: !Buffer.isBuffer(chainHead)
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/session/turn', async (req, res) => {
  let context;
  try {
    context = await requireSessionWriteContext(req, res);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
  if (!context) return;

  try {
    const result = await sessionMemoryOwner.appendTurn(req.body || {}, {
      companyId: context.companyId,
      agentId: context.agentId,
      clearanceLevel: context.clearanceCeiling,
      mutationAuthority: context.requestAuthority,
      requestAuthority: context.requestAuthority,
      source: req.body?.source || 'signed-session-transport',
    });
    return res.json(result);
  } catch (error) {
    const conflict = [
      'session_already_finalized',
      'session_turn_idempotency_conflict',
      'session_turn_idempotency_fork',
    ].includes(error.message) || Boolean(error.envelopeReason);
    const invalid = error.message.startsWith('session_') && !conflict;
    return res.status(conflict ? 409 : invalid ? 400 : 500).json({
      success: false,
      error: error.envelopeReason || error.message,
      current_head: error.currentHead ? b64u(error.currentHead) : null,
    });
  }
});

router.post('/session/finalize', async (req, res) => {
  let context;
  try {
    context = await requireSessionWriteContext(req, res);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
  if (!context) return;

  try {
    const result = await sessionMemoryOwner.finalizeSession(req.body || {}, {
      companyId: context.companyId,
      agentId: context.agentId,
      clearanceLevel: context.clearanceCeiling,
      requestAuthority: context.requestAuthority,
      source: req.body?.source || 'signed-session-finalization',
    });
    return res.json(result);
  } catch (error) {
    const conflict = [
      'session_finalization_conflict',
      'session_finalization_fork',
    ].includes(error.message);
    const invalid = error.message.startsWith('session_') && !conflict;
    return res.status(conflict ? 409 : invalid ? 400 : 500).json({
      success: false,
      error: error.message,
      rejected: error.rejected || null,
    });
  }
});

router.post('/compaction/save', async (req, res) => {
  const identity = requireAimosEnvelopeAgent(req, res);
  if (!identity) return;

  try {
    const result = await saveCompactionMemory(req.body || {}, {
      agentId: identity.agentId,
      companyId: req.body?.company_id || AIMOS_COMPANY_ID,
      identityTier: identity.tier,
      validFrom: identity.validFrom,
      origin: req.body?.origin || 'app_context_window',
      route: '/aimos/compaction/save',
    });

    if (!result.success) {
      return res.status(result.status || 400).json({
        success: false,
        error: result.error,
        reason: result.reason || null,
        lane: 'compaction_full',
        identity_tier: identity.tier,
        validation: result.payload?.validation || null,
        quality_score: result.quality_score,
      });
    }

    return res.json({
      success: true,
      lane: result.lane,
      memory_id: result.memory_id,
      key: result.key,
      memory_type: result.memory_type,
      identity_tier: identity.tier,
      agent_id: identity.agentId,
      memory_tier: result.memory_tier,
      quality_score: result.quality_score,
      freshness_state: result.freshness_state,
      valid_from: result.valid_from || null,
      valid_until: result.valid_until || null,
      surprise_at_save: result.surprise_at_save,
      compression_ratio: result.compression_ratio,
      content_hash: result.payload?.metadata?.content_hash || null,
      trigger: result.payload?.metadata?.app_trigger || null,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      lane: 'compaction_full',
    });
  }
});

router.post('/compaction/post', async (req, res) => {
  const identity = requireAimosEnvelopeAgent(req, res);
  if (!identity) return;

  try {
    const result = await savePostCompactionDelivery(req.body || {}, {
      agentId: identity.agentId,
      companyId: req.body?.company_id || AIMOS_COMPANY_ID,
      identityTier: identity.tier,
      validFrom: identity.validFrom,
      origin: req.body?.origin || 'app_context_window',
      route: '/aimos/compaction/post',
    });

    if (!result.success) {
      return res.status(result.status || 400).json({
        success: false,
        error: result.error,
        reason: result.reason || null,
        lane: 'post_compaction_delivery',
        identity_tier: identity.tier,
        validation: result.payload?.validation || null,
        quality_score: result.quality_score,
      });
    }

    return res.json({
      success: true,
      lane: result.lane,
      memory_id: result.memory_id,
      key: result.key,
      memory_type: result.memory_type,
      identity_tier: identity.tier,
      agent_id: identity.agentId,
      memory_tier: result.memory_tier,
      quality_score: result.quality_score,
      freshness_state: result.freshness_state,
      valid_from: result.valid_from || null,
      valid_until: result.valid_until || null,
      surprise_at_save: result.surprise_at_save,
      compression_ratio: result.compression_ratio,
      content_hash: result.payload?.metadata?.content_hash || null,
      source: result.delivery?.source || null,
      handoff: result.delivery?.handoff || null,
      confidence: result.delivery?.confidence || null,
      evidence_refs: result.delivery?.evidence_refs || [],
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      lane: 'post_compaction_delivery',
    });
  }
});

router.post('/save', async (req, res, next) => {
  const latencyStart = Date.now();
  res.on('finish', () => {
    logEvent(req.executionContext?.companyId || AIMOS_COMPANY_ID, req.agentId || 'unknown',
      'save_latency', req.body?.key || null, {
        endpoint: '/save',
        latency_ms: Date.now() - latencyStart,
        aimos_status: res.statusCode,
        reasoning: 'Housekeeper observed the completed signed canonical SAVE latency and terminal HTTP status.',
        source_knowledge: 'routes/aimos.js — canonical SAVE transport',
      }).catch(() => {});
  });

  const requestAuthority = verifiedRequestAuthorityFromReq(req);
  try {
    const saved = await executeCanonicalSave({
      ...(req.body || {}),
      mutation_authority: requestAuthority,
    });
    if (saved?.rejected) {
      return res.status(Number(saved.http_status || 400)).json({
        success: false,
        error: saved.reason,
        reason: saved.reason,
        terminal_event_id: saved.terminal_receipt?.event_id || null,
        stage_root_sha256: saved.canonical_save_trace?.stage_root_sha256 || null,
        failed_stage: saved.canonical_save_trace?.stages
          ?.find((stage) => ['FAILED', 'REJECTED'].includes(stage.status))?.stage || null,
      });
    }

    const responseMutationHash = saved.envelope_commit?.chainHash
      || saved.ledger_commit?.mutationHash
      || saved.credential_ledger_commit?.mutationHash
      || saved.live_content_hash;
    const responseContentHash = saved.envelope_commit?.contentHash
      || saved.ledger_commit?.contentHash
      || saved.credential_ledger_commit?.contentHash
      || saved.live_content_hash;
    return res.json({
      success: true,
      memory_id: saved.id,
      identity_tier: req.identityTier,
      chain_hash: b64u(responseMutationHash),
      content_hash: b64u(responseContentHash),
      chain_kind: saved.envelope_commit
        ? 'save_envelope'
        : saved.credential_lane ? 'credential_lifecycle' : 'memory_provenance',
      trusted_path: req.trustedPath === true,
      trusted_path_reason: req.trustedPathReason || null,
      memory_tier: saved.memory_tier,
      conflict_detected: saved.conflict_detected,
      quarantined: saved.quarantined,
      security_decision_event_id: saved.security_decision_event_id || null,
      canary_decision_event_id: saved.canary_decision_event_id || null,
      correction_applied: saved.correction_applied,
      corrections_applied: saved.corrections_applied,
      non_executable_evidence: req.body?._non_executable_evidence === true,
      rpe: saved.save_diagnostics?.rpe || null,
      encoding_style: saved.save_diagnostics?.encoding?.style || null,
      mutation_hash: b64u(responseMutationHash),
      live_content_hash: saved.live_content_hash?.toString('hex') || null,
      save_mutation_hash: saved.ledger_commit?.mutationHash?.toString('hex') || null,
      binding_mutation_hash: saved.binding_commit?.mutationHash?.toString('hex') || null,
      occurrence_reasserted: saved.occurrence_reasserted === true,
      occurrence_event_id: saved.save_feedback?.occurrence_event_id || null,
      occurrence_commitment: saved.save_feedback?.occurrence_commitment || null,
      retrieval_vote_added: saved.occurrence_reasserted === true ? false : null,
      epistemic_label: saved.epistemic_label || 'unverified',
      epistemic_confidence_milli: Number(saved.epistemic_confidence_milli || 0),
      epistemic_classification_event_id: saved.epistemic_classification_event_id || null,
      epistemic_classification_hash: saved.epistemic_classification_hash || null,
      epistemic_related_memory_ids_reclassified: saved.epistemic_related_memory_ids_reclassified || [],
      is_genesis: saved.ledger_commit?.isGenesis ?? null,
      provenance_prev_mutation_hash: b64u(saved.ledger_commit?.prevMutationHash),
      terminal_event_id: saved.terminal_receipt?.event_id || null,
      terminal_mutation_hash: saved.terminal_receipt?.mutation_hash || null,
      stage_root_sha256: saved.canonical_save_trace?.stage_root_sha256 || null,
      stage_count: saved.canonical_save_trace?.stage_count || null,
    });
  } catch (error) {
    if (error?.canonicalSaveTerminal) error.publicMessage = 'Canonical SAVE failed';
    error.statusCode = Number(error.statusCode || 500);
    return next(error);
  }
});

// ─── Phase 4: POST /aimos/lineage — D3 agent-attested cross-memory derivation
// Sibling to /save; both inherit authGate from server.js (cert-envelope auth
// over canonicalJson(body)+'\n'+nonce+'\n'+String(ts)). Body shape:
// {child_id, parent_ids[], derivation_type}. The same validated sig bytes
// from auth-tier are persisted to aimos_memory_lineage as a D3 row.
// One sig, two attestation ledgers (provenance + lineage) when T2/T3.
// Phase 4 wires ONLY derivation_type='agent_reasoning'; other types wired
// in Phase 5 (D2 server-attested, D1 structural backfill).
router.post('/lineage', async (req, res, next) => {
  try {
    const { child_id, parent_ids, derivation_type } = req.body || {};

    if (typeof child_id !== 'string' || child_id.length === 0) {
      return res.status(400).json({ success: false, error: 'Missing required field: child_id' });
    }
    if (!Array.isArray(parent_ids) || parent_ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Missing required field: parent_ids (non-empty array)' });
    }
    if (derivation_type !== 'agent_reasoning') {
      return res.status(400).json({
        success: false,
        error: 'derivation_type must be "agent_reasoning" in Phase 4 (other types wired in Phase 5)'
      });
    }

    const identityTierLineage = String(req.identityTier || 'T0').toUpperCase();
    // T0 = no envelope, no validated sig → cannot attest D3 lineage.
    if (!['T1', 'T2', 'T3'].includes(identityTierLineage)) {
      return res.status(401).json({ success: false, error: 'T0 identity cannot attest D3 lineage' });
    }

    const sigBytes = req.identitySigBytes;
    const nonce = req.identityNonce;
    const tsSigned = req.identitySignedTs;
    const agentId = req.identityCert?.agent_id;
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) {
      return res.status(401).json({ success: false, error: 'No validated sig bytes on request' });
    }
    if (typeof agentId !== 'string' || agentId.length === 0) {
      return res.status(401).json({ success: false, error: 'No active agent identity on cert' });
    }

    const lineageCommit = await memoryLineageLedger.commitLineage({
      childId: child_id,
      parentIds,
      derivationType: derivation_type,
      agentId,
      certString: req.identityCertString,
      sigBytes,
      nonce,
      tsSigned
    });
    if (!lineageCommit.ok) {
      const lineageReasonToStatus = {
        malformed_input: 400,
        derivation_type_not_wired_in_phase4: 400,
        duplicate_d3_event: 409,
        child_id_missing: 404,
        parent_id_missing: 404
      };
      return res.status(lineageReasonToStatus[lineageCommit.reason] || 500).json({
        success: false,
        error: lineageCommit.reason
      });
    }

    res.json({
      success: true,
      child_id,
      derivation_type,
      attestation_tier: 'D3',
      attesting_agent_id: agentId,
      parent_ids: lineageCommit.parentIds,
      ts_signed: tsSigned
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

async function handleAimosRecall(req, res, next) {
  const __latencyStart = Date.now();
  const actor = req.executionContext?.actorAgentId || null;
  const company = req.executionContext?.companyId || null;
  res.on('finish', () => {
    if (!actor || !company) return;
    logEvent(company, actor, 'recall_latency', String(req.body?.query || req.body?.q || '').slice(0, 50) || null, {
      endpoint: '/recall',
      latency_ms: Date.now() - __latencyStart,
      aimos_status: res.statusCode,
      reasoning: 'Observed signed native recall endpoint latency after response completion.',
      source_knowledge: 'routes/aimos.js native recall transport',
    }).catch(() => {});
  });
  try {
    const requestAuthority = {
      kind: 'verified_request',
      body: req.body,
      agentId: req.executionContext?.actorAgentId,
      validFromIso: req.executionContext?.actorValidFromIso,
      certString: req.identityCertString,
      signedTs: req.identitySignedTs,
      nonce: req.identityNonce,
      sigBytes: req.identitySigBytes,
      identityTier: req.identityTier,
      claimedPrev: req.prevChainHash || null,
      requestSigForm: req.identityRequestSigForm,
      signedMethod: req.identitySignedMethod,
      signedPath: req.identitySignedPath,
      signedClaims: req.identitySignedClaims,
      requestReceiptId: req.executionContext?.requestReceiptId || null,
      requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash || null,
      requestAdmissionEventId: req.executionContext?.requestAdmissionEventId || null,
      requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash || null,
      requestAdmissionAuthorityKind: req.executionContext?.requestAdmissionAuthorityKind || null,
    };
    const result = await executeCanonicalRecall({
      req,
      rawCommand: req.body,
      executionContext: req.executionContext,
      requestAuthority,
      transportBinding: { transport: 'rest' },
    });
    return res.status(result.status).json(result.body);
  } catch (error) {
    const reason = String(error?.message || error);
    const status = /required|authority|clearance|scope|actor|company|epoch_not_active/.test(reason)
      ? 403
      : /evidence|topology|binding/.test(reason)
        ? 409
        : 400;
    error.statusCode = status;
    next(error);
  }
}

router.get('/recall', (_req, res) => res.status(405).json({
  success: false,
  error: 'signed_post_recall_required',
}));
router.post('/recall', handleAimosRecall);

router.post('/recall/calibration/observe', requireCapability('memory_read'), async (req, res, next) => {
  try {
    const context = req.executionContext;
    const company = String(req.body?.company_id || context?.companyId || '');
    if (!context?.actorAgentId || company !== context.companyId) {
      return res.status(403).json({ success: false, error: 'calibration_company_or_actor_mismatch' });
    }
    if (String(req.identitySignedMethod || '').toUpperCase() !== 'POST'
      || req.identitySignedPath !== '/aimos/recall/calibration/observe') {
      return res.status(403).json({ success: false, error: 'calibration_feedback_signature_binding_invalid' });
    }
    const receipt = await recordCalibrationObservationBatch({
      companyId: company,
      labels: req.body?.labels,
      authority: {
        actorAgentId: context.actorAgentId,
        actorValidFromIso: context.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        requestReceiptId: context.requestReceiptId,
        requestReceiptMutationHash: context.requestReceiptMutationHash,
        requestAdmissionEventId: context.requestAdmissionEventId,
        requestAdmissionMutationHash: context.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, observation_receipt: receipt });
  } catch (error) {
    error.statusCode = /binding|authority|required|mismatch/.test(String(error?.message || '')) ? 403 : 400;
    next(error);
  }
});

router.use(nativeAimosReadBoundary);

// Native Aimos diagnostic/status surfaces.
// These handlers live behind server.js authGate and expose existing Aimos
// service contracts directly; they are not MCP wrappers or alternate write paths.
router.get('/recall/calibration/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || req.executionContext?.companyId || AIMOS_COMPANY_ID);
    if (req.executionContext?.companyId && company !== req.executionContext.companyId) {
      return res.status(403).json({ success: false, error: 'calibration_company_scope_mismatch' });
    }
    const status = await getCalibrationStatus(company);
    res.json({
      success: true,
      company_id: company,
      calibration: status,
      orca: buildOrcaCalibrationReadiness(status, {
        deployedProcedure: 'aimos_recall_linear_hybrid',
      }),
      ranking_math_changed: false,
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/recall/trust-alignment/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 50), 200));
    const result = await query(
      `SELECT id, key, memory_type, retrieval_weight, decay_weight, credit_score,
              access_count, last_accessed_at, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY COALESCE(last_accessed_at, updated_at, created_at) DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildTrustAlignmentDiagnostics(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/architecture/ontology-patterns', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildOntologyAwarePatternMap({
        servicePath: req.query.service_path || '',
        slug: req.query.slug || '',
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/lifelong/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
    const result = await query(
      `SELECT id, key, memory_type, scope, source, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildLifelongMemoryContract(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/homeostasis/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));
    const result = await query(
      `SELECT id, key, memory_type, retrieval_weight, decay_weight,
              access_count, last_accessed_at, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY COALESCE(last_accessed_at, updated_at, created_at) DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildTemporalHomeostasisDiagnostics(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/engram-pools/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 12), 50));
    res.json({
      success: true,
      company_id: company,
      ...await buildEngramPoolDiagnostics({ companyId: company, limit }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/learning/oscillatory-stdp/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildOscillatorySTDPStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/open-loop/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildSpeculativeVerificationContract({
        metaState: {
          mastery: 0.82,
          novelty: 0.18,
          predictionError: 0.08,
          failureRecurrence: 0,
          resourceBudgetRemaining: 0.9,
        },
        decision: {
          action: META_ACTIONS.APPLY_SKILL,
          expectedValue: 4.2,
        },
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/scrat/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildScratPipelineStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/agents/:agentId/psychometrics/status', async (req, res, next) => {
  try {
    const status = await getAgentPsychometricStatus(normalizeOperatorAgentId(req.params.agentId), {
      model: req.query.model || 'unknown',
      scaffold: req.query.scaffold || 'unknown',
      taskType: req.query.task_type || 'status',
      prompt: req.query.prompt || '',
      toolsUsed: req.query.tools_used || 0,
    });
    res.json({
      success: true,
      ...status,
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/turn-budget/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildTurnAdaptiveBudgetStatus({
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        globalBudget: req.query.global_budget || undefined,
        usedTokens: req.query.used_tokens || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/lookahead/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildLatentLookaheadStatus({
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        maxThoughts: req.query.max_thoughts || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/evolve-router/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildEvolveRouterStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/epistemic-blinding/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildEpistemicBlindingStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/qos/status', (req, res, next) => {
  try {
    res.json(buildNiyamaServingStatus({
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
      intent: req.query.intent || undefined,
      stream: req.query.stream === 'true' ? true : req.query.stream === 'false' ? false : undefined,
      requestImportance: req.query.importance || undefined,
      queueDepth: req.query.queue_depth || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/prefetch/status', (req, res, next) => {
  try {
    res.json(buildKeyedPrefetchStatus({
      prompt: req.query.prompt || undefined,
      sessionKey: req.query.session_key || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/tokenscale/status', (req, res, next) => {
  try {
    res.json(buildTokenScaleStatus({
      promptChars: req.query.prompt_chars || undefined,
      responseChars: req.query.response_chars || undefined,
      latencyMs: req.query.latency_ms || undefined,
      predictedOutputTokens: req.query.predicted_output_tokens || undefined,
      stream: req.query.stream === 'true' ? true : req.query.stream === 'false' ? false : undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/length/status', (req, res, next) => {
  try {
    res.json(buildRobustLengthStatus({
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/agsc/status', (req, res, next) => {
  try {
    res.json(buildAgscStatus({
      text: req.query.text || undefined,
      taskType: req.query.task_type || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/status', (req, res, next) => {
  try {
    res.json(buildWave5LocalInferenceStatus({
      model: req.query.model || undefined,
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
      contextTokens: req.query.context_tokens || undefined,
      predictedOutputTokens: req.query.predicted_output_tokens || undefined,
      vectorCount: req.query.vector_count || undefined,
      graphEdgeCount: req.query.graph_edge_count || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/quantization/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildTurboQuantReadiness({
        vectorCount: req.query.vector_count || undefined,
        vectorDimension: req.query.vector_dimension || undefined,
        baselineRecallAt10: req.query.baseline_recall_at_10 || undefined,
        quantizedRecallAt10: req.query.quantized_recall_at_10 || undefined,
        quantColumns: false,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/moe/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildMoEExpertSchedulingPlan({
        model: req.query.model || undefined,
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        totalExperts: req.query.total_experts || undefined,
        activeExperts: req.query.active_experts || undefined,
        gpuVramGb: req.query.gpu_vram_gb || undefined,
        gamma: req.query.gamma || undefined,
        acceptanceProbability: req.query.acceptance_probability || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/kv/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildKvCacheAndLayoutPlan({
        contextTokens: req.query.context_tokens || undefined,
        predictedOutputTokens: req.query.predicted_output_tokens || undefined,
        layers: req.query.layers || undefined,
        hiddenSize: req.query.hidden_size || undefined,
        bytesPerValue: req.query.bytes_per_value || undefined,
        hasSmartSsd: req.query.smartssd === 'true',
        pimAvailable: req.query.pim === 'true',
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/memory/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildLocalMemoryPlacementPlan({
        graphEdgeCount: req.query.graph_edge_count || undefined,
        vectorCount: req.query.vector_count || undefined,
        vectorDimension: req.query.vector_dimension || undefined,
      }),
      bottleneck: buildMicroBottleneckDiagnostic({
        latencyMs: req.query.latency_ms || undefined,
        cpuUtilization: req.query.cpu_utilization || undefined,
        memoryPressure: req.query.memory_pressure || undefined,
        ioWaitRatio: req.query.io_wait_ratio || undefined,
        gpuUtilization: req.query.gpu_utilization || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/io/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildNexusIoOffloadPlan({
        operation: req.query.operation || undefined,
        inputBytes: req.query.input_bytes || undefined,
        outputBytes: req.query.output_bytes || undefined,
        backgroundWriteAllowed: req.query.background_write === 'false' ? false : undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/lpc-sm/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildLpcSmSmallModelPlan({
        model: req.query.model || undefined,
        prompt: req.query.prompt || undefined,
        confidence: req.query.confidence || undefined,
        noveltyScore: req.query.novelty_score || undefined,
        targetContextTokens: req.query.target_context_tokens || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/heartbeat', async (req, res, next) => {
  try {
    const identity = requireAimosEnvelopeAgent(req, res, { allowSystemSelfHousekeeper: true });
    if (!identity) return;
    if (identity.agentId !== 'housekeeper'
        || !['T1', 'T1_SYSTEM_SELF'].includes(identity.tier)) {
      return res.status(403).json({ success: false, error: 'housekeeper_identity_required' });
    }
    if (req.executionContext?.companyId !== AIMOS_COMPANY_ID) {
      return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
    }
    const result = await runHeartbeat(AIMOS_COMPANY_ID);
    return res.json({ success: true, heartbeat: result });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// Aladdin retention: no config needed. Everything is long-term. Nothing expires.
router.get('/retention-config', (req, res) => {
  res.json({ company_id: req.query.company_id || 'hom', policy: 'aladdin', retention: 'permanent', expires: 'never' });
});

router.put('/retention-config', (req, res) => {
  res.json({ success: true, policy: 'aladdin', message: 'Retention is permanent. No configuration needed.' });
});

router.post('/checkpoint', async (req, res, next) => {
  const { task_id, company_id, agent_id, step, checkpoint_state } = req.body;

  try {
    if (!task_id || agent_id !== req.agentId || String(company_id || AIMOS_COMPANY_ID) !== AIMOS_COMPANY_ID) {
      return res.status(403).json({ error: 'checkpoint_actor_scope_mismatch' });
    }
    const authority = verifiedRequestAuthorityFromRequest(req);
    const receipt = await withTransaction(async (client) => {
      const priorResult = await client.query(
        `SELECT id FROM aimos_events
          WHERE company_id = $1 AND agent_id = $2 AND operation = 'task_checkpoint_committed'
            AND key = $3 AND ledger_version = 1
          ORDER BY ts DESC, signer_valid_from DESC, ledger_seq DESC LIMIT 1`,
        [AIMOS_COMPANY_ID, agent_id, task_id],
      );
      let prior = null;
      if (priorResult.rows[0]) {
        prior = await readVerifiedEventById(priorResult.rows[0].id, AIMOS_COMPANY_ID, { client });
        const priorMetadata = typeof prior.metadata === 'string' ? JSON.parse(prior.metadata) : prior.metadata;
        if (Number(step) < Number(priorMetadata?.step || 0)) throw new Error('checkpoint_step_regression');
      }
      return logEvent(AIMOS_COMPANY_ID, agent_id, 'task_checkpoint_committed', task_id, {
        schema: 'hom.aimos.task-checkpoint/v1',
        task_id,
        company_id: AIMOS_COMPANY_ID,
        agent_id,
        step: Number(step || 0),
        checkpoint_state: checkpoint_state || {},
        status: 'suspended',
        reasoning: 'The verified actor retained an append-only checkpoint successor for this task.',
      }, prior?.id || authority.requestAdmissionEventId, { client, authority, returnReceipt: true });
    }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id });

    res.json({ success: true, event_id: receipt.event_id, mutation_hash: receipt.mutation_hash });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/resume/:taskId', async (req, res, next) => {
  try {
    const event = await withTransaction(async (client) => {
      const result = await client.query(
        `SELECT id FROM aimos_events
          WHERE company_id = $1 AND agent_id = $2 AND operation = 'task_checkpoint_committed'
            AND key = $3 AND ledger_version = 1
          ORDER BY ts DESC, signer_valid_from DESC, ledger_seq DESC LIMIT 1`,
        [AIMOS_COMPANY_ID, req.agentId, req.params.taskId],
      );
      return result.rows[0]
        ? readVerifiedEventById(result.rows[0].id, AIMOS_COMPANY_ID, { client })
        : null;
    }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: req.agentId });
    if (!event) return res.status(404).json({ error: 'Task not found' });
    const metadata = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
    res.json({ capsule: metadata });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/conflicts', async (req, res, next) => {
  const { company_id } = req.query;

  try {
    const result = await query(
      `SELECT id, conflict_type, created_at FROM aimos_conflicts 
       WHERE company_id = $1 AND resolved_at IS NULL`,
      [company_id]
    );

    res.json({ conflicts: result.rows });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/conflicts/:id/resolve', async (req, res, next) => {
  void next;
  res.status(410).json({
    success: false,
    error: 'legacy_conflict_mutation_retired',
    authority: 'signed canonical SAVE lineage and epistemic evidence',
  });
});

router.get('/curator/stats', async (req, res) => {
  res.json({
    entries_reviewed: 0,
    deduplicated: 0,
    conflicts_found: 0,
    avg_importance: 0.75
  });
});

router.get('/dream/latest', async (req, res, next) => {
  try {
    const result = await query(
      `SELECT key, value, created_at
       FROM aimos_memories
       WHERE company_id = $1 AND memory_type = 'dream_summary'
       ORDER BY created_at DESC
       LIMIT 1`,
      [AIMOS_COMPANY_ID]
    );
    if (!result.rows.length) {
      return res.json({ run_date: null, summary: null });
    }
    res.json({
      run_date: result.rows[0].created_at,
      summary: result.rows[0].value
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/audit/x-usage', async (req, res) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const windowHours = Math.min(Math.max(parseInt(req.query.hours || '24', 10), 1), 168);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 200);

  try {
    const runsResult = await query(
      `WITH recent_runs AS (
         SELECT
           ar.run_id::text,
           ar.source_agent_id,
           ar.resolved_agent_id,
           ar.status,
           ar.intent,
           ar.channel,
           ar.created_at,
           ar.updated_at,
           ar.response_preview,
           ar.error,
           dc.directive_id::text,
           EXISTS (
             SELECT 1
             FROM aimos_memories om
             WHERE om.company_id = ar.company_id
               AND om.created_at >= ar.created_at - INTERVAL '5 seconds'
               AND om.created_at <= COALESCE(ar.updated_at, NOW()) + INTERVAL '5 seconds'
               AND (
                 om.key ILIKE '%x_search%'
                 OR om.value ILIKE '%x_search%'
                 OR om.value ILIKE '%twitter%'
                 OR om.value ILIKE '%x.com%'
               )
           ) AS aimos_mention
         FROM agent_runs ar
         LEFT JOIN directive_claims dc
           ON dc.run_id::text = ar.run_id::text
         WHERE ar.company_id = $1
           AND ar.created_at >= NOW() - ($2::int * INTERVAL '1 hour')
       )
       SELECT *
       FROM recent_runs
       WHERE
         intent IN ('x', 'twitter', 'x_search', 'social-listening', 'social_listening')
         OR COALESCE(response_preview, '') ILIKE '%x_search%'
         OR COALESCE(response_preview, '') ILIKE '%twitter%'
         OR COALESCE(error, '') ILIKE '%x_search%'
         OR aimos_mention = true
       ORDER BY created_at DESC
       LIMIT $3`,
      [company, windowHours, limit]
    );

    const runs = runsResult.rows.map((row) => ({
      run_id: row.run_id,
      source_agent_id: row.source_agent_id,
      resolved_agent_id: row.resolved_agent_id,
      status: row.status,
      intent: row.intent,
      channel: row.channel,
      created_at: row.created_at,
      updated_at: row.updated_at,
      origin: row.directive_id ? 'directive' : 'chat',
      directive_id: row.directive_id || null,
      aimos_mention: row.aimos_mention === true,
      estimated_queries: 1
    }));

    const summary = runs.reduce((acc, run) => {
      acc.total_runs += 1;
      acc.estimated_queries += Number(run.estimated_queries || 0);
      if (run.origin === 'directive') {
        acc.directive_runs += 1;
      } else {
        acc.chat_runs += 1;
      }
      if (run.aimos_mention) {
        acc.aimos_mentions += 1;
      }
      return acc;
    }, {
      window_hours: windowHours,
      total_runs: 0,
      chat_runs: 0,
      directive_runs: 0,
      aimos_mentions: 0,
      estimated_queries: 0
    });

    res.json({
      success: true,
      summary,
      runs
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      summary: {
        window_hours: windowHours,
        total_runs: 0,
        chat_runs: 0,
        directive_runs: 0,
        aimos_mentions: 0,
        estimated_queries: 0
      },
      runs: [],
      error: error.message
    });
  }
});

router.get('/timeline', async (req, res) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const days = Math.min(Math.max(parseInt(req.query.days || '7', 10), 1), 30);

  try {
    const rowsResult = await query(
      `SELECT
         created_at::date AS day,
         memory_type,
         key,
         value
       FROM aimos_memories
       WHERE company_id = $1
         AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       ORDER BY created_at ASC`,
      [company, days]
    );

    const now = new Date();
    const timeline = [];
    const byDay = new Map();
    const safeType = (value = '') => {
      const type = String(value || '').toLowerCase();
      if (type === 'procedural' || type === 'episodic' || type === 'semantic') return type;
      return 'semantic';
    };

    for (let offset = days - 1; offset >= 0; offset -= 1) {
      const point = new Date(now);
      point.setHours(0, 0, 0, 0);
      point.setDate(point.getDate() - offset);
      const key = point.toISOString().slice(0, 10);
      byDay.set(key, {
        date: key,
        total: 0,
        procedural: 0,
        episodic: 0,
        semantic: 0,
        memories: []
      });
    }

    for (const row of rowsResult.rows) {
      const rawDay = row.day;
      const day = rawDay instanceof Date
        ? rawDay.toISOString().slice(0, 10)
        : String(rawDay || '').slice(0, 10);
      const bucket = byDay.get(day);
      if (!bucket) continue;

      const type = safeType(row.memory_type);
      bucket.total += 1;
      bucket[type] += 1;
      if (bucket.memories.length < 25) {
        bucket.memories.push({
          key: String(row.key || ''),
          value: String(row.value || '').slice(0, 220),
          type
        });
      }
    }

    for (const value of byDay.values()) {
      timeline.push(value);
    }

    const total = timeline.reduce((acc, day) => acc + Number(day.total || 0), 0);
    const first = Number(timeline[0]?.total || 0);
    const last = Number(timeline[timeline.length - 1]?.total || 0);
    const growthPercent = first > 0
      ? Number((((last - first) / first) * 100).toFixed(2))
      : (last > 0 ? 100 : 0);

    res.json({
      success: true,
      total,
      growthPercent,
      days: timeline
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      total: 0,
      growthPercent: 0,
      days: [],
      error: error?.message || String(error)
    });
  }
});

router.get('/graph/:entityId', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const entityId = (req.params.entityId || '').trim();
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 100);

  if (!entityId) return res.status(400).json({ error: 'entityId is required' });

  try {
    const needle = `%${entityId}%`;
    const result = await query(
      `SELECT id::text, key, value, scope, memory_type
       FROM aimos_memories
       WHERE company_id = $1
         AND (key ILIKE $2 OR value ILIKE $2 OR scope ILIKE $2)
       ORDER BY updated_at DESC
       LIMIT $3`,
      [company, needle, limit]
    );

    const nodes = result.rows.map(row => ({
      id: row.id,
      value: row.value,
      entity_type: row.memory_type || 'declarative',
      relations: [
        { type: 'scope', target: String(row.scope || 'global') },
        { type: 'key', target: String(row.key || '') }
      ]
    }));

    res.json({ nodes });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/dream/run', async (req, res, next) => {
  try {
    const result = await runNightlyDream(AIMOS_COMPANY_ID);
    res.json({ success: true, result });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/layer-status', async (req, res, next) => {
  const company = AIMOS_COMPANY_ID;
  try {
    const [
      memoryCount,
      todayEvents,
      capsules,
      conflicts,
      creditAvg,
      clearanceLevels,
      dreamRow,
      typeBreakdown
    ] = await Promise.all([
      query(`SELECT COUNT(*) AS total FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT COUNT(*) AS total FROM aimos_events WHERE company_id = $1 AND ts >= NOW() - INTERVAL '48 hours'`, [company]),
      query(`SELECT COUNT(*) AS total, status FROM aimos_capsules WHERE company_id = $1 GROUP BY status`, [company]),
      query(`SELECT COUNT(*) AS total FROM aimos_conflicts WHERE company_id = $1 AND resolved_at IS NULL`, [company]),
      query(`SELECT AVG(credit_score) AS avg FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT COUNT(DISTINCT clearance_level) AS levels FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT created_at FROM aimos_memories WHERE company_id = $1 AND memory_type = 'dream_summary' ORDER BY created_at DESC LIMIT 1`, [company]),
      query(`SELECT memory_type, COUNT(*) AS count FROM aimos_memories WHERE company_id = $1 GROUP BY memory_type`, [company])
    ]);

    const capsuleMap = {};
    capsules.rows.forEach(r => { capsuleMap[r.status] = parseInt(r.total); });
    const totalCapsules = Object.values(capsuleMap).reduce((a, b) => a + b, 0);

    const typeMap = {};
    typeBreakdown.rows.forEach(r => { typeMap[r.memory_type || 'declarative'] = parseInt(r.count); });

    const memoryTotal = parseInt(memoryCount.rows[0].total);
    const eventsToday = parseInt(todayEvents.rows[0].total);
    const openConflicts = parseInt(conflicts.rows[0].total);
    const avgCredit = parseFloat(creditAvg.rows[0].avg || 1.0);
    const clearanceLevelsCount = parseInt(clearanceLevels.rows[0].levels || 0);
    const lastDream = dreamRow.rows[0]?.created_at || null;
    const dreamScheduled = !lastDream || (Date.now() - new Date(lastDream).getTime() > 20 * 60 * 60 * 1000);

    res.json({
      event_ledger: {
        status: eventsToday > 0 ? 'active' : 'idle',
        events_today: eventsToday,
        label: eventsToday + ' today'
      },
      memory_store: {
        status: memoryTotal > 0 ? 'online' : 'idle',
        total: memoryTotal,
        by_type: typeMap,
        label: memoryTotal + ' entries'
      },
      knowledge_graph: {
        status: memoryTotal > 0 ? 'online' : 'idle',
        nodes: memoryTotal,
        label: memoryTotal > 0 ? `${memoryTotal} nodes` : 'No nodes yet'
      },
      task_capsules: {
        status: totalCapsules > 0 ? 'active' : 'ready',
        total: totalCapsules,
        suspended: capsuleMap['suspended'] || 0,
        completed: capsuleMap['completed'] || 0,
        label: totalCapsules > 0 ? totalCapsules + ' capsules' : 'Ready'
      },
      curator_agent: {
        status: openConflicts === 0 ? 'online' : 'warning',
        conflicts_open: openConflicts,
        label: openConflicts === 0 ? 'No conflicts' : openConflicts + ' conflicts'
      },
      memory_market: {
        status: memoryTotal > 0 ? 'active' : 'idle',
        avg_credit: avgCredit.toFixed(2),
        label: memoryTotal > 0 ? `Score ${avgCredit.toFixed(2)}` : 'Idle'
      },
      governance: {
        status: clearanceLevelsCount > 0 ? 'active' : 'idle',
        levels: clearanceLevelsCount,
        label: clearanceLevelsCount > 0 ? `${clearanceLevelsCount} levels` : 'No policies yet'
      },
      nightly_dream: {
        status: dreamScheduled ? 'idle' : 'online',
        last_run: lastDream,
        label: lastDream ? `Last run ${new Date(lastDream).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}` : '2AM scheduled'
      }
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/review/weekly', async (req, res, next) => {
  try {
    const company = AIMOS_COMPANY_ID;
    const now = new Date();
    const since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const rows = await query(
      `SELECT created_at::date as day, COUNT(*)::int as count
       FROM aimos_memories
       WHERE company_id = $1 AND memory_type = 'task_summary' AND created_at >= $2
       GROUP BY day
       ORDER BY day ASC`,
      [company, since]
    );

    const counts = {};
    rows.rows.forEach(r => { counts[r.day] = r.count; });

    const missingDays = [];
    for (let i = 0; i < 7; i += 1) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      if (!counts[key]) missingDays.push(key);
    }

    // ─── MOAT METRICS (Zero to One + Seven Powers) ────────────────────────────
    const [memoryCount, crossRefCount, skillCount, recLogCount, eventCount, frameworkCount, bookCount] = await Promise.all([
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM memory_cross_refs WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM procedural_skills WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM recommendation_log WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'event_log' AND created_at >= $2`, [company, since]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'framework'`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'book_extract'`, [company]).then(r => r.rows[0]?.c || 0)
    ]);

    const graphDensity = memoryCount > 0 ? (crossRefCount / memoryCount).toFixed(2) : 0;

    // ─── WIP CHECK (Flow Control) ───────────────────────────────────────────
    const [activeLoops, pendingDirectives] = await Promise.all([
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'active_loop'`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_directives WHERE company_id = $1 AND status = 'pending' AND authority_event_id IS NOT NULL`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0)
    ]);

    const wipViolations = [];
    if (activeLoops > 10) wipViolations.push(`active_loops=${activeLoops} (limit 10)`);
    if (pendingDirectives > 15) wipViolations.push(`pending_directives=${pendingDirectives} (limit 15)`);

    res.json({
      range_days: 7,
      total_entries: rows.rows.reduce((sum, r) => sum + r.count, 0),
      per_day: counts,
      missing_days: missingDays,
      moat_metrics: {
        total_memories: memoryCount,
        graph_density: Number(graphDensity),
        graph_density_target: 2.0,
        cross_refs: crossRefCount,
        procedural_skills: skillCount,
        recommendation_log_entries: recLogCount,
        frameworks: frameworkCount,
        book_extracts: bookCount,
        switching_cost_index: memoryCount + skillCount + recLogCount
      },
      flow_control: {
        events_this_week: eventCount,
        active_loops: activeLoops,
        pending_directives: pendingDirectives,
        wip_violations: wipViolations,
        wip_healthy: wipViolations.length === 0
      },
      warning: 'Habit erosion: Week 1 you are intentional. Week 4 you move fast and agents stop writing memories because no one enforces it. A month in, the Aimos has 30 entries when it should have 3,000.'
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});


// CEO Bridge (CEO Directives)
router.post('/ceo/directive', requireCapability('delegate'), async (req, res, next) => {
  const { company_id, agent_id, goal, priority, clearance_level } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.actorValidFromIso) {
    return res.status(401).json({ error: 'verified_execution_context_required' });
  }
  if (company_id && company_id !== context.companyId) return res.status(403).json({ error: 'company_scope_mismatch' });
  if (!agent_id) return res.status(400).json({ error: 'target_agent_id_required' });

  try {
    const { sanitizedGoal, removedLines } = sanitizeDirectiveGoal(goal);
    if (!sanitizedGoal) {
      return res.status(400).json({
        success: false,
        error: 'Directive goal is empty after sanitization (blocked hardcoding/sandbox directives).',
        removed_lines: removedLines.length
      });
    }

    const result = await createDirective({
      companyId: context.companyId,
      targetAgentId: agent_id,
      goal: sanitizedGoal,
      priority: Math.max(1, Math.min(100, Number(priority) || 1)),
      clearanceLevel: Math.max(1, Math.min(12, Number(clearance_level) || 5)),
      authority: {
        actorAgentId: context.actorAgentId,
        actorValidFromIso: context.actorValidFromIso,
        requestReceiptId: context.requestReceiptId || null,
        requestReceiptMutationHash: context.requestReceiptMutationHash || null,
        requestAdmissionEventId: context.requestAdmissionEventId || null,
        requestAdmissionMutationHash: context.requestAdmissionMutationHash || null,
      },
    });
    res.json({
      success: true,
      directive_id: result.directiveId,
      event_id: result.eventId,
      sanitized: removedLines.length > 0,
      removed_lines: removedLines.length
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/ceo/inbox', requireCapability('delegate'), async (req, res, next) => {
  const { company_id, agent_id, status } = req.query;
  const context = req.executionContext;
  if (company_id && company_id !== context?.companyId) return res.status(403).json({ error: 'company_scope_mismatch' });

  try {
    let sql = `SELECT * FROM aimos_directives WHERE company_id = $1 AND authority_event_id IS NOT NULL`;
    const params = [context.companyId];

    if (agent_id) {
      sql += ` AND agent_id = $${params.length + 1}`;
      params.push(agent_id);
    }

    if (status) {
      sql += ` AND status = $${params.length + 1}`;
      params.push(status);
    } else {
      sql += ` AND status != 'completed'`;
    }

    sql += ` ORDER BY priority DESC, created_at DESC`;

    const result = await query(sql, params);
    res.json({ directives: result.rows });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/directives/claim', async (req, res, next) => {
  const {
    company_id,
    directive_id,
    agent_id,
    run_id,
    lease_seconds
  } = req.body || {};
  const context = req.executionContext;
  if (!context?.actorAgentId) return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  if (company_id && company_id !== context.companyId) return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
  if (agent_id && agent_id !== context.actorAgentId && context.actorAgentId !== 'housekeeper') {
    return res.status(403).json({ success: false, error: 'directive_claim_actor_mismatch' });
  }
  const claimAgentId = agent_id || context.actorAgentId;

  try {
    const result = await claimDirective({
      companyId: context.companyId,
      directiveId: directive_id || null,
      agentId: claimAgentId,
      runId: run_id || null,
      leaseSeconds: lease_seconds || 120,
      authority: context,
    });

    if (!result.claimed) {
      return res.status(409).json({ success: false, ...result });
    }

    // Include the directive goal in the claim response so callers
    // don't need a separate fetch (eliminates race condition)
    let goal = null;
    if (result.directiveId) {
      try {
        const dRow = await query(
          'SELECT goal FROM aimos_directives WHERE id = $1 AND authority_event_id IS NOT NULL',
          [result.directiveId]
        );
        if (dRow.rows.length) goal = dRow.rows[0].goal;
      } catch { /* goal fetch is best-effort */ }
    }

    res.json({ success: true, ...result, goal });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/ceo/report', async (req, res, next) => {
  const { directive_id, agent_id, result_data, status } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId) return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  if (agent_id && agent_id !== context.actorAgentId && context.actorAgentId !== 'housekeeper') {
    return res.status(403).json({ success: false, error: 'directive_report_actor_mismatch' });
  }
  const reportingAgentId = agent_id || context.actorAgentId;

  try {
    const completed = await completeDirectiveClaim({
      companyId: context.companyId,
      directiveId: directive_id,
      agentId: reportingAgentId,
      status: status || 'completed',
      resultData: result_data,
      authority: context,
    });
    if (!completed) return res.status(409).json({ success: false, error: 'directive_completion_rejected' });
    res.json({ success: true });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// ─── FELIX: GET /aimos/events/today ────────────────────────────────────────
// Returns today's event_log entries in chronological order.
// Used by the nightly health loop and boot sequence recall.
router.get('/events/today', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const hours = Math.min(Math.max(parseInt(req.query.hours || '24', 10), 1), 168);
  try {
    const result = await query(
      `SELECT id, key, value, memory_type, created_at
       FROM aimos_memories
       WHERE company_id = $1
         AND memory_type IN ('declarative', 'task_summary', 'event_log', 'milestone', 'active_loop')
         AND created_at >= NOW() - ($2::int * INTERVAL '1 hour')
       ORDER BY created_at ASC`,
      [company, hours]
    );
    res.json({ events: result.rows, count: result.rows.length });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});


// ─── POST /aimos/log-event ───────────────────────────────────────────────────
// Convenience endpoint: one call logs a bullet event to Aimos.
// Body: { agent_id, action, summary, files?, result, company_id?, reasoning?, source_knowledge?, next_action? }
// action types: code_change | deploy | post | trade | briefing | memory | infra | creds | design | brand
// reasoning: WHY was this decision made (required for ALL actions — Third Wave traceability)
// source_knowledge: which book, framework, or principle informed this (traceable origin)
router.post('/log-event', async (req, res, next) => {
  const {
    company_id,
    agent_id,
    action,
    summary,
    files = [],
    result: outcome,
    next: bodyNext,
    next_action,
    reasoning,
    source_knowledge
  } = req.body || {};

  if (!action || !summary) {
    return res.status(400).json({ success: false, error: '`action` and `summary` are required' });
  }

  if (!reasoning) {
    console.warn(`[aimos] WARNING: log-event '${action}' missing reasoning field. Every decision needs a traceable WHY.`);
  }

  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.companyId) {
    return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  }
  const cid = context.companyId;
  const verifiedLogAgentId = context.actorAgentId;
  if (agent_id && agent_id !== verifiedLogAgentId) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }
  const aid = normalizeOperatorAgentId(verifiedLogAgentId);
  const now = new Date();
  const ts = now.toISOString().slice(0, 16).replace('T', '_').replace(':', '');
  const key = `event_${String(action).toLowerCase()}_${ts}`;

  const effectiveNext = next_action || bodyNext;
  const bullet = [
    `• ${now.toISOString().slice(11, 16)} — [${action}] ${summary}`,
    outcome ? `  result: ${outcome}` : null,
    reasoning ? `  reasoning: ${reasoning}` : null,
    source_knowledge ? `  source: ${source_knowledge}` : null,
    Array.isArray(files) && files.length ? `  files: ${files.join(', ')}` : null,
    effectiveNext ? `  next: ${effectiveNext}` : null
  ].filter(Boolean).join('\n');

  try {
    const requestAuthority = verifiedRequestAuthorityFromReq(req);
    const saved = await executeCanonicalSave({
      company_id: cid,
      agent_id: aid,
      key,
      value: bullet,
      scope: 'system',
      clearance_level: 5,
      memory_type: 'event_log',
      mutation_authority: requestAuthority
    });

    const eventReceipt = await logEvent(cid, aid, String(action).toLowerCase(), key, {
      summary,
      files,
      result: outcome || null,
      next_action: effectiveNext || null,
      reasoning: reasoning || `Verified agent ${aid} recorded ${action}: ${summary}`,
      source_knowledge: source_knowledge || 'aimos.js /log-event verified request',
      memory_id: saved.id,
    }, null, {
      returnReceipt: true,
      authority: {
        actorAgentId: verifiedLogAgentId,
        actorValidFromIso: req.identityValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
      },
    });

    res.json({ success: true, key, memory_id: saved.id, memory_tier: saved.memory_tier, event_receipt: eventReceipt });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// GET /agent-state/:agentId — returns the current BDI state for an agent
router.get('/agent-state/:agentId', async (req, res, next) => {
  const agentId = (req.params.agentId || '').trim();

  if (!agentId) return res.status(400).json({ error: 'agentId is required' });
  if (agentId !== req.agentId) return res.status(403).json({ error: 'agent_state_actor_mismatch' });

  try {
    const state = await readAgentBDIState(agentId);
    if (!state) return res.status(404).json({ error: 'Agent state not found' });
    res.json({ state: { company_id: AIMOS_COMPANY_ID, agent_id: agentId, ...state } });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// PUT /agent-state/:agentId — upserts the BDI state for an agent
router.put('/agent-state/:agentId', async (req, res, next) => {
  const agentId = (req.params.agentId || '').trim();

  if (!agentId) return res.status(400).json({ error: 'agentId is required' });
  if (agentId !== req.agentId) return res.status(403).json({ error: 'agent_state_actor_mismatch' });

  const {
    phase,
    current_task,
    beliefs,
    desires,
    intentions,
    waiting_for,
    blockers,
    confidence,
    last_action,
    next_action
  } = req.body || {};

  try {
    const authority = verifiedRequestAuthorityFromRequest(req);
    await updateAgentState(
      agentId,
      phase || 'idle',
      current_task || null,
      last_action || null,
      next_action || null,
      confidence != null ? Number(confidence) : 0.5,
      { beliefs: beliefs || {}, desires: desires || {}, intentions: intentions || [] },
      {
        authority,
        parentEventId: authority.requestAdmissionEventId,
        waitingFor: waiting_for || null,
        blockers: Array.isArray(blockers) ? blockers : [],
      },
    );
    const state = await readAgentBDIState(agentId);
    res.json({ success: true, state: { company_id: AIMOS_COMPANY_ID, agent_id: agentId, ...state } });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// Mutable autonomy configuration was retired. Runtime autonomy is derived from
// the verified append-only capability ledger in agent-confidence-calibration.
router.get('/autonomy/:agentId', (_req, res) => res.status(410).json({
  error: 'mutable_autonomy_config_retired',
  authority: 'aimos_authorization_events',
}));
router.put('/autonomy/:agentId', (_req, res) => res.status(410).json({
  error: 'mutable_autonomy_config_retired',
  authority: 'POST /permissions/set',
}));

// ─── A-MEM ZETTELKASTEN: GET /aimos/cross-refs/:memoryId ─────────────────────
// Returns all memories linked to the given memoryId, sorted by similarity desc.
// Query param: company_id (defaults to COMPANY_ID env or 'hom')
router.get('/cross-refs/:memoryId', async (req, res, next) => {
  const company = (req.query.company_id || AIMOS_COMPANY_ID).trim();
  const memoryId = (req.params.memoryId || '').trim();

  if (!memoryId) {
    return res.status(400).json({ error: 'memoryId is required' });
  }

  try {
    const result = await query(
      `SELECT
         cr.id            AS link_id,
         cr.target_memory_id,
         cr.similarity,
         cr.created_at    AS linked_at,
         m.key,
         m.value,
         m.memory_type,
         m.memory_tier,
         m.agent_id,
         m.created_at     AS memory_created_at
       FROM memory_cross_refs cr
       JOIN aimos_memories m
         ON m.id = cr.target_memory_id
        AND m.company_id = cr.company_id
       WHERE cr.company_id = $1
         AND cr.source_memory_id = $2
       ORDER BY cr.similarity DESC`,
      [company, memoryId]
    );

    res.json({
      memory_id: memoryId,
      linked_count: result.rows.length,
      links: result.rows
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────

// ─── GAP 1: PROCEDURAL MEMORY / SKILL LIBRARY (VOYAGER + CoALA) ──────────────

// Save or update a procedural skill
router.post('/skills', async (req, res, next) => {
  try {
    const { company_id, agent_id, skill_name, trigger_pattern, steps = [], expected_outcome, tags = [] } = req.body;
    if (!skill_name) return res.status(400).json({ error: 'skill_name required' });
    if ((company_id && company_id !== AIMOS_COMPANY_ID) || (agent_id && agent_id !== req.agentId)) {
      return res.status(403).json({ error: 'skill_actor_scope_mismatch' });
    }
    const value = JSON.stringify({
      skill_name,
      trigger_pattern: trigger_pattern || null,
      steps: Array.isArray(steps) ? steps : [],
      expected_outcome: expected_outcome || null,
      tags: Array.isArray(tags) ? tags : [],
    });
    const saved = await executeCanonicalSave({
      company_id: AIMOS_COMPANY_ID,
      agent_id: req.agentId,
      key: `procedural_skill:${req.agentId}:${String(skill_name).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_')}`,
      value,
      scope: 'agent',
      clearance_level: 3,
      memory_type: 'procedural',
      source: 'aimos:procedural-skill',
      mutation_authority: verifiedRequestAuthorityFromReq(req),
    });
    if (saved?.rejected) return res.status(422).json({ saved: false, reason: saved.reason });
    res.json({ saved: true, skill: { id: saved.id, skill_name } });
  } catch (err) {
    console.error('[aimos] POST /skills error:', err.message);
    err.statusCode = 500;
    next(err);
  }
});

// Record a skill use (success or failure)
router.put('/skills/:id/use', async (req, res, next) => {
  try {
    const { success = true } = req.body;
    const authority = verifiedRequestAuthorityFromReq(req);
    const receipt = await withTransaction(async (client) => {
      const target = await client.query(
        `SELECT id, key FROM aimos_memories
          WHERE id = $1 AND company_id = $2 AND memory_type = 'procedural'
            AND agent_id = $3 LIMIT 1`,
        [req.params.id, AIMOS_COMPANY_ID, req.agentId],
      );
      if (!target.rows[0]) return null;
      return logEvent(AIMOS_COMPANY_ID, req.agentId, 'procedural_skill_outcome', req.params.id, {
        schema: 'hom.aimos.procedural-skill-outcome/v1',
        memory_id: req.params.id,
        memory_key: target.rows[0].key,
        outcome: success ? 'success' : 'failure',
        reasoning: 'The verified actor retained one outcome observation for a canonical procedural memory.',
      }, authority.requestAdmissionEventId, { client, authority, returnReceipt: true });
    }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: req.agentId });
    if (!receipt) return res.status(404).json({ error: 'Skill not found' });
    res.json({ updated: true, skill: { id: req.params.id }, event_id: receipt.event_id });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Recall skills by agent, tags, or search
router.get('/skills', async (req, res, next) => {
  try {
    const { agent_id, tag, q, limit = 20 } = req.query;
    if (agent_id && agent_id !== req.agentId) return res.status(403).json({ error: 'skill_actor_scope_mismatch' });
    const boundedLimit = Math.max(1, Math.min(Number(limit) || 20, 100));
    const result = await query(
      `SELECT id, agent_id, key, value, created_at, updated_at
         FROM aimos_memories
        WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'procedural'
          AND ($3::text IS NULL OR value ILIKE $3)
          AND ($4::text IS NULL OR value ILIKE $4)
        ORDER BY created_at DESC LIMIT $5`,
      [AIMOS_COMPANY_ID, req.agentId, q ? `%${q}%` : null, tag ? `%${tag}%` : null, boundedLimit],
    );
    const skills = result.rows.map((row) => {
      let value = {};
      try { value = JSON.parse(row.value); } catch { value = { skill_name: row.key, steps: [], expected_outcome: row.value }; }
      return { id: row.id, agent_id: row.agent_id, ...value, created_at: row.created_at, updated_at: row.updated_at };
    });
    res.json({ skills, count: skills.length });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 3: OUTCOME TRACKING / RECOMMENDATION LOG ───────────────────────────

// Log a recommendation with confidence and outcome window
router.post('/recommendations', async (req, res, next) => {
  try {
    const { company_id, agent_id, recommendation, confidence, outcome_window_hours = 24, context = {} } = req.body;
    if (!recommendation || confidence == null) return res.status(400).json({ error: 'recommendation and confidence required' });
    if ((company_id && company_id !== AIMOS_COMPANY_ID) || (agent_id && agent_id !== req.agentId)) {
      return res.status(403).json({ error: 'recommendation_actor_scope_mismatch' });
    }
    const due = new Date(Date.now() + outcome_window_hours * 3600000).toISOString();
    const id = randomUUID();
    const authority = verifiedRequestAuthorityFromReq(req);
    const receipt = await logEvent(AIMOS_COMPANY_ID, req.agentId, 'recommendation_committed', id, {
      schema: 'hom.aimos.recommendation/v1',
      recommendation_id: id,
      agent_id: req.agentId,
      recommendation: String(recommendation).slice(0, 2000),
      confidence_at_time: Number(confidence),
      outcome_window_hours: Number(outcome_window_hours),
      outcome_due_at: due,
      context: context || {},
      reasoning: 'The verified actor retained one recommendation projection for later outcome scoring.',
    }, authority.requestAdmissionEventId, { authority, returnReceipt: true });
    res.json({ logged: true, recommendation: { id, recommendation, confidence_at_time: Number(confidence), outcome_due_at: due }, event_id: receipt.event_id });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Score a recommendation outcome
router.put('/recommendations/:id/score', async (req, res, next) => {
  try {
    const { actual_outcome, outcome_score } = req.body;
    if (!actual_outcome || outcome_score == null) return res.status(400).json({ error: 'actual_outcome and outcome_score required' });
    const authority = verifiedRequestAuthorityFromReq(req);
    const result = await withTransaction(async (client) => {
      const source = await client.query(
        `SELECT id FROM aimos_events
          WHERE company_id = $1 AND agent_id = $2 AND operation = 'recommendation_committed'
            AND key = $3 AND ledger_version = 1 LIMIT 1`,
        [AIMOS_COMPANY_ID, req.agentId, req.params.id],
      );
      if (!source.rows[0]) return null;
      const recommendationEvent = await readVerifiedEventById(source.rows[0].id, AIMOS_COMPANY_ID, { client });
      const metadata = typeof recommendationEvent.metadata === 'string'
        ? JSON.parse(recommendationEvent.metadata)
        : recommendationEvent.metadata;
      const scoreReceipt = await logEvent(AIMOS_COMPANY_ID, req.agentId, 'recommendation_scored', req.params.id, {
        schema: 'hom.aimos.recommendation-score/v1',
        recommendation_id: req.params.id,
        recommendation_event_id: recommendationEvent.id,
        actual_outcome,
        outcome_score: Number(outcome_score),
        reasoning: 'The verified actor retained one outcome successor for the exact recommendation event.',
      }, recommendationEvent.id, { client, authority, exclusiveOperationKey: true, returnReceipt: true });
      const skillIds = metadata?.context?.skill_ids || metadata?.context?.skillIds || [];
      const skillReceipts = [];
      for (const skillId of skillIds.slice(0, 50)) {
        skillReceipts.push(await logEvent(AIMOS_COMPANY_ID, req.agentId, 'procedural_skill_outcome', String(skillId), {
          schema: 'hom.aimos.procedural-skill-outcome/v1',
          memory_id: String(skillId),
          outcome: Number(outcome_score) >= 0.5 ? 'success' : 'failure',
          recommendation_score_event_id: scoreReceipt.event_id,
          reasoning: 'The recommendation outcome was attributed to one explicitly named procedural memory.',
        }, scoreReceipt.event_id, { client, authority, returnReceipt: true }));
      }
      return { metadata, scoreReceipt, skillReceipts };
    }, { restricted: true, client_id: AIMOS_COMPANY_ID, agent_id: req.agentId });
    if (!result) return res.status(404).json({ error: 'Recommendation not found' });
    res.json({
      scored: true,
      recommendation: { ...result.metadata, actual_outcome, outcome_score: Number(outcome_score) },
      skillFeedback: { skills_updated: result.skillReceipts.length, direction: Number(outcome_score) >= 0.5 ? 'success' : 'fail' },
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Get recommendations (with optional filter for unscored/due)
router.get('/recommendations', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id, unscored, limit = 20 } = req.query;
    let sql = `SELECT * FROM recommendation_log WHERE company_id = $1`;
    const params = [company_id];
    if (agent_id) { params.push(agent_id); sql += ` AND agent_id = $${params.length}`; }
    if (unscored === 'true') sql += ` AND actual_outcome IS NULL`;
    sql += ` ORDER BY created_at DESC LIMIT ${parseInt(limit, 10)}`;
    const result = await query(sql, params);
    res.json({ recommendations: result.rows, count: result.rows.length });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Get calibration stats (average delta between confidence and outcome)
router.get('/recommendations/calibration', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id } = req.query;
    let sql = `SELECT agent_id, COUNT(*) as total,
       AVG(outcome_score) as avg_outcome, AVG(confidence_at_time) as avg_confidence,
       AVG(ABS(outcome_score - confidence_at_time)) as avg_delta
       FROM recommendation_log WHERE company_id = $1 AND outcome_score IS NOT NULL`;
    const params = [company_id];
    if (agent_id) { params.push(agent_id); sql += ` AND agent_id = $${params.length}`; }
    sql += ` GROUP BY agent_id`;
    const result = await query(sql, params);
    res.json({ calibration: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 5: CROSS-SESSION REASONING CONTINUITY ──────────────────────────────

// Save reasoning state (hypotheses, evidence, open questions) for an agent
router.post('/reasoning-state', async (req, res, next) => {
  try {
    const { company_id, agent_id, hypotheses = [], evidence = [], open_questions = [], chain = [] } = req.body;
    const verifiedAgentId = req.agentId || req.identityCert?.agent_id || null;
    if (!verifiedAgentId) return res.status(401).json({ success: false, error: 'verified_agent_required' });
    if (agent_id && agent_id !== verifiedAgentId) {
      return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
    }
    const verifiedCompanyId = req.executionContext?.companyId;
    if (!verifiedCompanyId || (company_id && company_id !== verifiedCompanyId)) {
      return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
    }
    const normalizedAgentId = normalizeOperatorAgentId(verifiedAgentId);
    const key = `reasoning_state:${normalizedAgentId}`;
    const value = JSON.stringify({ hypotheses, evidence, open_questions, chain, saved_at: new Date().toISOString() });
    const saved = await executeCanonicalSave({
      company_id: verifiedCompanyId,
      agent_id: normalizedAgentId,
      key,
      value,
      scope: 'system',
      clearance_level: 3,
      memory_type: 'reasoning_state',
      mutation_authority: verifiedRequestAuthorityFromReq(req)
    });
    if (saved?.rejected) {
      return res.status(422).json({ saved: false, reason: saved.reason });
    }
    res.json({ saved: true, key, memory_id: saved?.id });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Recall reasoning state for an agent (used on boot)
router.get('/reasoning-state', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id = getOperatorAgentId() } = req.query;
    const normalizedAgentId = normalizeOperatorAgentId(agent_id);
    const result = await query(
      `SELECT key, value, updated_at FROM aimos_memories
       WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'reasoning_state'
       ORDER BY updated_at DESC LIMIT 1`,
      [company_id, normalizedAgentId]
    );
    if (!result.rows.length) return res.json({ state: null });
    const row = result.rows[0];
    const parsed = typeof row.value === 'string' ? JSON.parse(row.value) : row.value;
    res.json({ state: parsed, updated_at: row.updated_at });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 4: INTERVENTION COST MATRIX ────────────────────────────────────────

// Get cost matrix
router.get('/cost-matrix', async (req, res, next) => {
  try {
    const { company_id = 'hom' } = req.query;
    const result = await query(`SELECT * FROM intervention_cost_matrix WHERE company_id = $1 ORDER BY action_type`, [company_id]);
    res.json({ matrix: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Upsert cost matrix entry
router.post('/cost-matrix', async (req, res, next) => {
  void req; void next;
  res.status(410).json({ saved: false, error: 'legacy_cost_matrix_mutation_retired' });
});

// ─── GAP 7: FRAGILITY LABELS ────────────────────────────────────────────────

router.get('/fragility', async (req, res, next) => {
  try {
    const { company_id = 'hom' } = req.query;
    const result = await query(`SELECT * FROM fragility_labels WHERE company_id = $1 ORDER BY fragility, component`, [company_id]);
    res.json({ labels: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.post('/fragility', async (req, res, next) => {
  void req; void next;
  res.status(410).json({ saved: false, error: 'legacy_fragility_mutation_retired' });
});
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// MCP ENDPOINT — Model Context Protocol (Anthropic standard)
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/mcp/tools/list', (req, res) => {
  res.json({
    tools: [
      {
        name: 'aimos_recall',
        description: 'Retrieve memories from HOM Aimos by semantic search',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
            company_id: { type: 'string', default: 'hom' },
            limit: { type: 'integer', default: 5 }
          },
          required: ['query']
        }
      },
      {
        name: 'aimos_save',
        description: 'Save a memory to HOM Aimos',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string' },
            value: { type: 'string' },
            company_id: { type: 'string', default: 'hom' },
            agent_id: { type: 'string', default: 'external' },
            memory_type: { type: 'string', default: 'declarative' },
            scope: { type: 'string', default: 'global' }
          },
          required: ['key', 'value']
        }
      }
    ]
  });
});

router.post('/mcp/tools/call', async (req, res, next) => {
  const { name, arguments: args = {} } = req.body;
  try {
    if (name === 'aimos_recall') {
      const requestAuthority = {
        kind: 'verified_request',
        body: req.body,
        agentId: req.executionContext?.actorAgentId,
        validFromIso: req.executionContext?.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        identityTier: req.identityTier,
        claimedPrev: req.prevChainHash || null,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        signedClaims: req.identitySignedClaims,
        requestReceiptId: req.executionContext?.requestReceiptId || null,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash || null,
      };
      const result = await executeCanonicalRecall({
        req,
        rawCommand: args,
        executionContext: req.executionContext,
        requestAuthority,
        transportBinding: { transport: 'legacy_mcp' },
      });
      return res.status(result.status).json({
        content: [{ type: 'text', text: JSON.stringify(result.body) }],
        recall: result.body,
      });
    }

    if (name === 'aimos_save') {
      // Legacy MCP transport delegates to the same canonical SAVE owner as REST.
      const { key, value, company_id, agent_id, memory_type = 'declarative', scope = 'global', clearance_level = 1, source } = args;
      if (!key || !value) return res.status(400).json({ error: 'key and value required' });
      const actor = req.executionContext?.actorAgentId;
      const company = req.executionContext?.companyId;
      if (!actor || !company || req.identityAuthenticatedBy !== 'envelope') {
        return res.status(403).json({ error: 'verified envelope authority is required for MCP save' });
      }
      if ((company_id && company_id !== company) || (agent_id && agent_id !== actor)) {
        return res.status(403).json({ error: 'signed MCP save actor or company mismatch' });
      }
      const requestAuthority = {
        kind: 'verified_request',
        body: req.body,
        agentId: actor,
        validFromIso: req.executionContext.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        identityTier: req.identityTier,
        claimedPrev: req.prevChainHash || null,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        signedClaims: req.identitySignedClaims,
        requestReceiptId: req.executionContext?.requestReceiptId || null,
        requestReceiptMutationHash: req.executionContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: req.executionContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: req.executionContext?.requestAdmissionMutationHash || null,
        companyId: company,
      };
      const saved = await executeCanonicalSave({
        company_id: company,
        agent_id: actor,
        key,
        value,
        scope,
        clearance_level,
        memory_type,
        source,
        mutation_authority: requestAuthority,
      });
      if (saved?.rejected) {
        return res.status(Number(saved.http_status || 422)).json({
          error: saved.reason,
          terminal_event_id: saved.terminal_receipt?.event_id || null,
          stage_root_sha256: saved.canonical_save_trace?.stage_root_sha256 || null,
          content: [{ type: 'text', text: `Rejected: ${saved.reason}` }]
        });
      }
      return res.json({
        content: [{ type: 'text', text: `Saved: ${saved?.id}` }],
        memory_id: saved?.id || null,
        content_hash: saved?.live_content_hash?.toString('hex') || null,
        save_mutation_hash: saved?.ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: saved?.binding_commit?.mutationHash?.toString('hex') || null,
        occurrence_reasserted: saved?.occurrence_reasserted === true,
        occurrence_event_id: saved?.save_feedback?.occurrence_event_id || null,
        occurrence_commitment: saved?.save_feedback?.occurrence_commitment || null,
        retrieval_vote_added: saved?.occurrence_reasserted === true ? false : null,
        epistemic_label: saved?.epistemic_label || 'unverified',
        epistemic_confidence_milli: Number(saved?.epistemic_confidence_milli || 0),
        epistemic_classification_event_id: saved?.epistemic_classification_event_id || null,
        epistemic_classification_hash: saved?.epistemic_classification_hash || null,
        quarantined: saved?.quarantined === true,
        security_decision_event_id: saved?.security_decision_event_id || null,
        terminal_event_id: saved?.terminal_receipt?.event_id || null,
        terminal_mutation_hash: saved?.terminal_receipt?.mutation_hash || null,
        stage_root_sha256: saved?.canonical_save_trace?.stage_root_sha256 || null,
      });
    }

    return res.status(400).json({ error: `Unknown tool: ${name}` });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// QMD — Query Memory Database
// Structured graph query language for Aimos's memory brain.
// ═══════════════════════════════════════════════════════════════════════════════
import { parseQMD, QMDSyntaxError }  from '../services/retrieval/qmd-parser.js';
import { executeQMD, buildQueryPlan } from '../services/retrieval/qmd-planner.js';

/**
 * POST /aimos/qmd
 * Body: { query: string, company_id?, agent_id?, clearance_level? }
 * Response: { results, query_plan, ast, execution_time_ms }
 *
 * Examples:
 *   { "query": "FIND type:framework WHERE contains('positioning') HOPS 2 LIMIT 10" }
 *   { "query": "TRAVERSE FROM key:\"F1*\" FOLLOW cross_refs,entity_edges HOPS 3" }
 *   { "query": "COUNT type:event_log WHERE created > 24h GROUP BY agent_id" }
 */
router.post('/qmd', async (req, res, next) => {
  const {
    query: rawQuery,
    company_id,
    agent_id,
    clearance_level
  } = req.body || {};

  if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) {
    return res.status(400).json({ error: 'Missing required field: query (string)' });
  }

  const company        = (company_id   || AIMOS_COMPANY_ID).trim();
  const requestingAgent = normalizeOperatorAgentId(agent_id);
  const clearance      = Number(clearance_level || 5);

  const t0 = Date.now();

  let ast;
  try {
    ast = parseQMD(rawQuery.trim());
  } catch (err) {
    if (err instanceof QMDSyntaxError || err.name === 'QMDSyntaxError') {
      err.statusCode = 400;
      return next(err);
    }
    err.statusCode = 400;
    next(err);
  }

  try {
    const outcome = await executeQMD(ast, { company, clearance, requestingAgent });

    const execution_time_ms = Date.now() - t0;

    // Log event for observability (non-fatal)
    logEvent(company, requestingAgent, 'qmd_query', rawQuery.slice(0, 120), {
      reasoning: `QMD query executed by '${requestingAgent}': natural language query parsed to AST, translated to SQL with same ACL as recall. QMD is the structured query interface — when recall's semantic search isn't precise enough.`,
      source_knowledge: 'aimos.js QMD parser — recursive descent parser with 6 verbs (Feature from cybersec session)'
    }).catch(() => {});

    return res.json({
      results:          outcome.results,
      meta:             outcome.meta,
      query_plan:       outcome.query_plan,
      ast,
      execution_time_ms
    });
  } catch (err) {
    console.error('[qmd] execution error:', err.message);
    return res.status(500).json({
      error:     err.message,
      ast,
      query:     rawQuery,
      execution_time_ms: Date.now() - t0
    });
  }
});

/**
 * GET /aimos/qmd/explain
 * Query param: q=FIND type:framework...
 * Returns the parsed AST, query plan, and estimated cost — WITHOUT executing.
 */
router.get('/qmd/explain', (req, res, next) => {
  const rawQuery = (req.query.q || '').trim();

  if (!rawQuery) {
    return res.status(400).json({ error: 'Missing query param: q' });
  }

  let ast;
  try {
    ast = parseQMD(rawQuery);
  } catch (err) {
    if (err instanceof QMDSyntaxError || err.name === 'QMDSyntaxError') {
      err.statusCode = 400;
      return next(err);
    }
    err.statusCode = 400;
    next(err);
  }

  const query_plan = buildQueryPlan(ast);

  // Build a human-readable SQL preview (parameterized, not executable as-is)
  const sql_preview = buildSQLPreview(ast);

  return res.json({ ast, query_plan, sql_preview, estimated_cost: query_plan.estimated_cost });
});

/** Produce a non-executable, human-readable SQL sketch for /explain */
function buildSQLPreview(ast) {
  switch (ast.verb) {
    case 'FIND': {
      const typeF  = ast.filters?.find(f => f.field === 'type')?.value;
      const keyF   = ast.filters?.find(f => f.field === 'key')?.value;
      const contains = ast.where?.find(w => w.type === 'contains')?.value;
      return [
        `SELECT id, key, value, memory_type, memory_tier, ...`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        typeF    ? `  AND memory_type = '${typeF}'` : null,
        keyF     ? `  AND key ILIKE '${keyF.replace(/\*/g, '%')}'` : null,
        contains ? `  AND (key ILIKE '%${contains}%' OR value ILIKE '%${contains}%')` : null,
        `  -- vector: ORDER BY embedding <=> :query_vector`,
        `LIMIT ${ast.limit || 10};`,
        ast.hops > 1 ? `-- then: WITH RECURSIVE graph_walk ... (${ast.hops} hops)` : null,
      ].filter(Boolean).join('\n');
    }
    case 'TRAVERSE': {
      const follow = ast.follow?.join(', ');
      return [
        `-- anchor resolution:`,
        `SELECT id FROM aimos_memories WHERE company_id = :company AND ${ast.from?.field} ILIKE '${ast.from?.value}'`,
        ``,
        `-- recursive traversal (${ast.hops} hops) via: ${follow}`,
        `WITH RECURSIVE graph_walk AS (`,
        `  SELECT target_memory_id, similarity, 1 AS hop FROM memory_cross_refs WHERE source_memory_id = ANY(:anchor_ids)`,
        `  UNION ALL`,
        `  SELECT cr.target_memory_id, cr.similarity, gw.hop + 1 FROM graph_walk gw JOIN memory_cross_refs cr ON ...`,
        `  WHERE gw.hop < ${ast.hops}`,
        `)`,
        `SELECT ... FROM graph_walk JOIN aimos_memories ... LIMIT ${ast.limit || 50};`,
      ].join('\n');
    }
    case 'MATCH': {
      return [
        `SELECT id, key, value, memory_type, memory_tier, ...`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        ...( ast.filters?.map(f => `  AND ${f.field} = '${f.value}'`) || [] ),
        `  -- plus WHERE conditions from parsed clauses`,
        `ORDER BY memory_tier_rank ASC, created_at DESC`,
        `LIMIT ${ast.limit || 20};`,
      ].join('\n');
    }
    case 'GRAPH': {
      return [
        `-- center: ${ast.center?.field}=${ast.center?.value}`,
        `WITH RECURSIVE graph_walk AS (`,
        `  SELECT target_memory_id AS mem_id, similarity, 1 AS hop`,
        `  FROM memory_cross_refs WHERE source_memory_id = :center_id`,
        `  UNION ALL`,
        `  SELECT cr.target_memory_id, cr.similarity, gw.hop + 1`,
        `  FROM graph_walk gw JOIN memory_cross_refs cr ON ...`,
        `  WHERE gw.hop < ${ast.hops}`,
        `)`,
        `SELECT ... FROM graph_walk JOIN aimos_memories ... LIMIT ${ast.limit || 50};`,
        `-- RETURN format: ${ast.return || 'default'}`,
      ].join('\n');
    }
    case 'PATH': {
      return [
        `-- from: ${ast.from?.field}=${ast.from?.value}`,
        `-- to:   ${ast.to?.field}=${ast.to?.value}`,
        `WITH RECURSIVE path_walk AS (`,
        `  SELECT source_memory_id AS current_id, target_memory_id AS next_id, 1 AS depth, ARRAY[source_memory_id] AS visited, ...`,
        `  FROM memory_cross_refs WHERE source_memory_id = ANY(:from_ids)`,
        `  UNION ALL`,
        `  SELECT pw.next_id, cr.target_memory_id, pw.depth + 1, pw.visited || pw.next_id, ...`,
        `  FROM path_walk pw JOIN memory_cross_refs cr ON ... WHERE pw.depth < ${ast.max_depth}`,
        `)`,
        `SELECT path_ids, depth FROM path_walk WHERE next_id = ANY(:to_ids) ORDER BY depth ASC LIMIT ${ast.limit || 20};`,
      ].join('\n');
    }
    case 'COUNT': {
      const typeF = ast.filters?.find(f => f.field === 'type')?.value;
      const grp   = ast.group_by;
      return [
        `SELECT ${grp ? `${grp}, ` : ''}COUNT(*) AS count`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        typeF ? `  AND memory_type = '${typeF}'` : null,
        `  -- plus WHERE conditions from parsed clauses`,
        grp ? `GROUP BY ${grp}` : null,
        `ORDER BY count DESC;`,
      ].filter(Boolean).join('\n');
    }
    default:
      return '-- unknown verb';
  }
}
// ─────────────────────────────────────────────────────────────────────────────

// The unsigned demo disclosure path is retired. Screen-safe recall is a
// terminal projection of the same signed, provenance-admitted POST pipeline.
router.all('/recall/demo', (_req, res) => res.status(410).json({
  success: false,
  error: 'demo_recall_moved_to_signed_post',
  endpoint: '/aimos/recall',
  method: 'POST',
  projection: 'demo_redacted',
}));

// ─── MEDALLION: Time-travel query ─────────────────────────────────────────────
// Returns the state of a memory key at time T by walking the supersession chain
router.get('/time-travel', async (req, res, next) => {
  const { key, as_of, agent_id, company_id } = req.query;
  const company = company_id || AIMOS_COMPANY_ID;
  const agentId = normalizeOperatorAgentId(agent_id);

  if (!key || !as_of) {
    return res.status(400).json({ error: 'key and as_of (ISO timestamp) required' });
  }

  const asOfDate = new Date(as_of);
  if (isNaN(asOfDate.getTime())) {
    return res.status(400).json({ error: 'as_of must be a valid ISO timestamp' });
  }

  try {
    await ensureMedallionColumn();
    // Walk supersession chain: find the memory that was active at as_of
    // A memory was "active" at time T if created_at <= T AND (superseded by something with created_at > T, or never superseded)
    const result = await query(
      `WITH RECURSIVE chain AS (
        -- Start: the most recent memory for this key created before as_of
        SELECT m.id, m.key, m.value, m.created_at, m.supersedes_id, m.memory_type, m.medallion_layer, m.agent_id, 0 AS depth
        FROM aimos_memories m
        WHERE m.key = $1 AND m.company_id = $2 AND m.agent_id = $3
          AND m.created_at <= $4
        ORDER BY m.created_at DESC
        LIMIT 1
      )
      SELECT * FROM chain ORDER BY created_at DESC LIMIT 1`,
      [key, company, agentId, asOfDate.toISOString()]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: 'No memory found for that key at the specified time',
        key, as_of, agent_id: agentId
      });
    }

    const mem = result.rows[0];
    return res.json({
      key: mem.key,
      value: mem.value,
      memory_type: mem.memory_type,
      medallion_layer: mem.medallion_layer,
      agent_id: mem.agent_id,
      created_at: mem.created_at,
      as_of: as_of,
      snapshot: true
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/medallion-stats', async (req, res, next) => {
  const { company_id } = req.query;
  const company = company_id || AIMOS_COMPANY_ID;
  try {
    await ensureMedallionColumn();
    const result = await query(
      `SELECT medallion_layer, COUNT(*) as count,
              AVG(decay_weight) as avg_weight,
              MAX(created_at) as latest
       FROM aimos_memories
       WHERE company_id = $1
       GROUP BY medallion_layer`,
      [company]
    );
    const stats = {};
    for (const row of result.rows) {
      stats[row.medallion_layer || 'bronze'] = {
        count: parseInt(row.count),
        avg_weight: parseFloat(row.avg_weight || 1),
        latest: row.latest
      };
    }
    return res.json({ company_id: company, layers: stats });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /aimos/embed — Generate embeddings locally ─────────────────────────
// Returns 768-dimension embedding vector using all-mpnet-base-v2.
// PAPER CONTEXT: Zero external API calls after initial model download (~80MB).
router.post('/embed', async (req, res) => {
  const { text } = req.body;

  if (!text || typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({
      error: 'Missing required field: text (string)',
      embedding: null,
      dimensions: 768,
      model: 'all-mpnet-base-v2'
    });
  }

  try {
    const embedding = await getEmbedding(text);

    if (!embedding) {
      return res.status(500).json({
        error: 'Failed to generate embedding',
        embedding: null,
        dimensions: 768,
        model: 'all-mpnet-base-v2'
      });
    }

    return res.json({
      embedding,
      dimensions: embedding.length,
      model: 'Xenova/all-mpnet-base-v2',
      stats: getEmbeddingHealth()
    });
  } catch (err) {
    return res.status(500).json({
      error: err.message,
      embedding: null,
      dimensions: 768,
      model: 'all-mpnet-base-v2'
    });
  }
});

// ─── GET /aimos/embed/stats — Embedding health status ──────────────────────────
router.get('/embed/stats', (_req, res) => {
  res.json({
    model: 'Xenova/all-mpnet-base-v2',
    dimensions: 768,
    ...getEmbeddingHealth()
  });
});


export default router;
