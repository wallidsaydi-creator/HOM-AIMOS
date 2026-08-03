/**
 * V1 API Router — ASMR-enhanced memory endpoints
 *
 * Wires the full ASMR pipeline (ingestion + retrieval + ensemble) into live
 * HTTP endpoints, preserving all existing /aimos/* routes untouched.
 *
 * Endpoints:
 *   POST /v1/ingest  — ASMR-enhanced ingestion (3 observer agents)
 *   POST /v1/recall  — signed native retrieval + ASMR answer synthesis
 *   GET  /v1/health  — Pipeline health check
 *
 * Mode semantics for POST /v1/recall (`answer_mode`):
 *   fast      — 1 variant (precise only), no ensemble aggregation
 *   standard  — 3 variants (default)
 *   thorough  — 8 variants (precise×3 + temporal×3 + contextual×2 weighted copies)
 *
 * Auth: Cryptographic envelope (inherited from server.js auth-tier middleware).
 *
 * @module routes/v1-api
 */


import express from 'express';
import {
  asmrAnswerFromEvidence,
  asmrIngest,
  finalizeAsmrAnswer,
} from '../services/retrieval/asmr-pipeline.js';
import { VARIANTS } from '../services/answering/prompt-variants.js';
import { query } from '../db/connection.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import { resolveNativeRecallAuthority } from '../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../services/retrieval/native-recall-pipeline.js';

const router = express.Router();

/**
 * Build the expanded variant list for 'thorough' mode (8 variants).
 * Duplicates each base variant with adjusted weights so the ensemble
 * runs more parallel queries and surfaces minority-agreement signals.
 *
 * @returns {Array<{id, system, weight}>}
 */
function buildThoroughVariants() {
  const base = Object.values(VARIANTS);
  // 3 copies of precise (highest confidence signal), 3 temporal, 2 contextual = 8
  return [
    { ...base[0], id: 'precise-1',    weight: 1.00 },
    { ...base[0], id: 'precise-2',    weight: 0.95 },
    { ...base[0], id: 'precise-3',    weight: 0.90 },
    { ...base[1], id: 'temporal-1',   weight: 0.90 },
    { ...base[1], id: 'temporal-2',   weight: 0.85 },
    { ...base[1], id: 'temporal-3',   weight: 0.80 },
    { ...base[2], id: 'contextual-1', weight: 0.80 },
    { ...base[2], id: 'contextual-2', weight: 0.75 }
  ];
}

/**
 * Resolve variant list from mode string.
 *
 * @param {'fast'|'standard'|'thorough'} mode
 * @returns {Array|undefined}  undefined means use the default VARIANTS (3 total)
 */
function resolveVariants(mode) {
  switch (String(mode || 'standard').toLowerCase()) {
    case 'fast':
      // Single variant: precise only — no ensemble overhead
      return [{ ...Object.values(VARIANTS)[0], id: 'precise' }];
    case 'thorough':
      return buildThoroughVariants();
    case 'standard':
    default:
      return undefined; // ensemble-engine defaults to all 3 VARIANTS
  }
}

// ─── Structured error helper ───────────────────────────────────────────────────

function apiError(res, status, code, message, detail = null) {
  const body = { error: { code, message } };
  if (detail) body.error.detail = detail;
  return res.status(status).json(body);
}

// ─── POST /v1/ingest ──────────────────────────────────────────────────────────

/**
 * ASMR-enhanced ingestion.
 *
 * Body: { content, source, client_id, session_id, metadata }
 *
 * Runs the 3 observer agents (entity-extractor, relationship-mapper,
 * temporal-marker) in parallel, then saves the structured facets back to
 * Aimos as declarative + episodic memories.
 *
 * Returns: { success, facets, latencyMs }
 */
router.post('/ingest', async (req, res, next) => {
  const start = Date.now();

  const {
    content,
    source,
    session_id,
    metadata,
    clearance_level
  } = req.body || {};

  // Validate required field
  if (!content || typeof content !== 'string' || !content.trim()) {
    return apiError(res, 400, 'MISSING_CONTENT', 'content is required and must be a non-empty string');
  }

  // Trim to a reasonable limit (avoid massive LLM prompts)
  const truncatedContent = content.slice(0, 8000);

  try {
    const result = await asmrIngest(truncatedContent, {
      source:       source     || 'v1-api',
      sessionId:    session_id || null,
      metadata:     metadata   || {},
      clearanceLevel: clearance_level ?? 1,
      executionContext: req.executionContext,
      saveToAimos: true,
    });

    const latencyMs = Date.now() - start;

    return res.status(200).json({
      success: true,
      facets: {
        entities:        result.entities,
        relationships:   result.relationships,
        temporalMarkers: result.temporalMarkers,
        supersessions:   result.supersessions
      },
      ingestionMeta: {
        observerResults: result.observerResults,
        confidence:      result.confidence,
        saved:           result.saved,
        errors:          result.errors,
        sourceProvenance: result.sourceProvenance
      },
      relationshipPersistence: result.relationshipPersistence,
      savedMemoryIds: result.savedMemoryIds,
      savedProofs: result.savedProofs,
      ingestionActionStartReceipt: result.ingestionActionStartReceipt,
      ingestionActionReceipt: result.ingestionActionReceipt,
      latencyMs
    });
  } catch (err) {
    console.error('[v1/ingest] Pipeline error:', err.message);
    err.statusCode = 500;
    return next(err);
  }
});

// ─── POST /v1/recall ──────────────────────────────────────────────────────────

/**
 * ASMR-enhanced retrieval + ensemble answering.
 *
 * Signed body: { query, session_id?, limit?, answer_mode? }
 * Native recall performs grant, clearance, provenance, calibration, and Merkle
 * admission first. ASMR may synthesize only over that admitted evidence set.
 *
 * Returns: { answer, confidence, evidence, latencyMs, mode, retrieval }
 */
router.get('/recall', (_req, res) => res.status(405).json({
  error: { code: 'SIGNED_POST_REQUIRED', message: 'Use signed POST /v1/recall.' },
}));

router.post('/recall', async (req, res, next) => {
  const start = Date.now();
  const query = req.body?.query ?? req.body?.q;

  if (!query || !String(query).trim()) {
    return apiError(res, 400, 'MISSING_QUERY', 'query is required');
  }

  const modeStr = String(req.body?.answer_mode || 'standard').toLowerCase();
  if (!['fast', 'standard', 'thorough'].includes(modeStr)) {
    return apiError(res, 400, 'ANSWER_MODE_INVALID', 'answer_mode must be fast, standard, or thorough');
  }
  const variants = resolveVariants(modeStr);
  const ensembleMode = modeStr === 'fast' ? 'any-correct' : 'majority-vote';

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
    };
    const recallAuthority = await resolveNativeRecallAuthority({
      rawCommand: req.body,
      executionContext: req.executionContext,
      requestAuthority,
      transportBinding: { transport: 'v1' },
    });
    const nativeRecall = await executeNativeRecall(req, recallAuthority);
    if (nativeRecall.status !== 200) {
      return res.status(nativeRecall.status).json(nativeRecall.body);
    }
    const result = await asmrAnswerFromEvidence(
      String(query).trim(),
      nativeRecall.body.memories || [],
      { variants, mode: ensembleMode },
    );
    const answerReceipt = await finalizeAsmrAnswer({
      query: String(query).trim(),
      answerResult: result,
      recallReceipt: nativeRecall.body.recall_receipt,
      variants,
      executionContext: req.executionContext,
    });

    const latencyMs = Date.now() - start;
    const evidence = (result.evidence || []).map(e => ({
      id:          e.id,
      key:         e.key,
      value:       e.value,
      confidence:  e.confidence,
      source:      e.source,
      source_agent: e.source_agent,
      created_at:  e.created_at,
      version_status: e.version_status,
      calibrated_recall_score: e.calibrated_recall_score,
      provenance_proof: e.provenance_proof,
    }));

    return res.status(200).json({
      answer:     result.answer,
      confidence: result.confidence,
      evidence,
      latencyMs,
      mode:       modeStr,
      retrieval: result.retrieval,
      recallReceipt: nativeRecall.body.recall_receipt,
      answerReceipt,
      ensemble: {
        mode:          result.mode,
        validCount:    result.validCount,
        totalVariants: result.totalVariants,
        variantResults: result.variantResults
      },
      stages: result.stages
    });
  } catch (err) {
    console.error('[v1/recall] Pipeline error:', err.message);
    err.statusCode = 500;
    return next(err);
  }
});

// ─── GET /v1/health ───────────────────────────────────────────────────────────

/**
 * System health check — probes Aimos and verifies pipeline module readiness.
 *
 * Returns: { status, aimos: { connected, memories }, asmr: { ... } }
 */
router.get('/health', async (req, res, next) => {
  // Native DB probe — no loopback HTTP. Same query the /aimos/status handler uses.
  let aimosConnected = false;
  let totalMemories   = 0;

  try {
    const result = await query(
      'SELECT COUNT(*)::int AS total FROM aimos_memories WHERE company_id = $1',
      [AIMOS_COMPANY_ID]
    );
    aimosConnected = true;
    totalMemories   = result.rows[0]?.total || 0;
  } catch (err) {
    next(err);
    return;
  }

  // Verify pipeline modules loaded (they are ESM imports — if we got here they loaded)
  const ingestionReady  = typeof asmrIngest  === 'function';
  const retrievalReady  = typeof asmrAnswerFromEvidence === 'function';
  const ensembleReady   = Object.keys(VARIANTS).length >= 3;

  const allHealthy = aimosConnected && ingestionReady && retrievalReady && ensembleReady;

  return res.status(allHealthy ? 200 : 503).json({
    status:    allHealthy ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    aimos: {
      connected: aimosConnected,
      memories:  totalMemories
    },
    asmr: {
      ingestionReady,
      retrievalReady,
      ensembleReady,
      variants: Object.keys(VARIANTS)
    }
  });
});

export default router;
