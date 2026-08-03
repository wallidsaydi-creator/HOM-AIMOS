/**
 * agent-learning.js — reflection, learning, health, and messaging routes.
 *
 * Mounts under the /agents prefix (via agents.js main router).
 * Routes:
 *   POST /:id/reflect
 *   GET  /:id/capability-gap
 *   GET  /:id/skill-library
 *   GET  /:id/learning-metrics
 *   POST /:id/advise
 *   GET  /:id/inbox
 *   POST /:id/message
 *   POST /messages/:key/read
 *   GET  /health/all
 *   GET  /:id/health
 */

import express from 'express';
import {
  getAgentHealthScore,
  getAllAgentHealthScores,
  getAgentLearningMetrics,
  getAgentCapabilityGap,
  getAgentSkillLibrary,
  selfReflect,
  computeForwardTransfer,
  computeBackwardTransfer,
  computePerformanceMaintenance
} from '../services/learning/agent-learning.js';
import {
  sendAgentMessage,
  getAgentInbox,
  markMessageRead,
  postAdvisory
} from '../services/orchestration/agent-runner.js';

const router = express.Router();

// ─── Health ───────────────────────────────────────────────────────────────────

router.get('/health/all', async (req, res, next) => {
  try {
    const scores = await getAllAgentHealthScores();
    res.json({ success: true, scores });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/:id/health', async (req, res, next) => {
  try {
    const score = await getAgentHealthScore(req.params.id);
    res.json({ success: true, ...score });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── Learning & metrics ───────────────────────────────────────────────────────

router.get('/:id/learning-metrics', async (req, res, next) => {
  try {
    const metrics = await getAgentLearningMetrics(req.params.id);
    res.json({ success: true, ...metrics });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/:id/capability-gap', async (req, res, next) => {
  try {
    const gap = await getAgentCapabilityGap(req.params.id);
    res.json({ success: true, ...gap });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/:id/skill-library', async (req, res, next) => {
  try {
    const library = await getAgentSkillLibrary(req.params.id);
    res.json({ success: true, ...library });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── SENGE #1: Personal Mastery — trigger self-reflection ────────────────────
router.post('/:id/reflect', async (req, res, next) => {
  try {
    const reflection = await selfReflect(req.params.id);
    res.json({ success: true, reflection });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── ADVISABILITY: Post a correction/advisory to a running agent ──────────────
// POST /agents/:agentId/advise — human or agent posts advice that the target
// agent picks up before its next LLM call via checkAdvisability()
router.post('/:agentId/advise', async (req, res, next) => {
  try {
    const { agentId } = req.params;
    const { advice } = req.body;
    if (!advice) return res.status(400).json({ error: 'advice is required' });
    const result = await postAdvisory(agentId, advice, req.agentId);
    res.json({ ok: true, ...result });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── Messaging ────────────────────────────────────────────────────────────────

router.post('/:id/message', async (req, res, next) => {
  try {
    if (req.params.id !== req.agentId) {
      return res.status(403).json({ error: 'verified_message_sender_mismatch' });
    }
    const { to, message, messageType } = req.body || {};
    if (!to || !message) return res.status(400).json({ error: 'to and message required' });
    const result = await sendAgentMessage(req.agentId, to, message, { messageType: messageType || 'directive' });
    if (result.blocked) return res.status(403).json(result);
    res.json({ success: true, ...result });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/:id/inbox', async (req, res, next) => {
  try {
    if (req.params.id !== req.agentId) {
      return res.status(403).json({ error: 'verified_inbox_recipient_mismatch' });
    }
    const limit = parseInt(req.query.limit, 10) || 10;
    const messages = await getAgentInbox(req.agentId, limit);
    res.json({ success: true, count: messages.length, messages });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.post('/messages/:key/read', async (req, res, next) => {
  try {
    const result = await markMessageRead(req.params.key, req.agentId || req.identityCert?.agent_id, {
      actorAgentId: req.agentId || req.identityCert?.agent_id,
      actorValidFromIso: req.identityValidFromIso,
      certString: req.identityCertString,
      signedTs: req.identitySignedTs,
      nonce: req.identityNonce,
      sigBytes: req.identitySigBytes,
      requestSigForm: req.identityRequestSigForm,
      signedMethod: req.identitySignedMethod,
      signedPath: req.identitySignedPath,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    if (err.code === 'AIMOS_MESSAGE_NOT_FOUND') err.statusCode = 404;
    else if (/required$/.test(err.message)) err.statusCode = 400;
    else err.statusCode = 500;
    next(err);
  }
});

// ─── L2M: Learning-to-Measure aggregate endpoint ────────────────────────────

router.get('/:id/l2m', async (req, res, next) => {
  try {
    const agentId = req.params.id;
    const [ft, bt, pm] = await Promise.all([
      computeForwardTransfer(agentId),
      computeBackwardTransfer(agentId),
      computePerformanceMaintenance(agentId)
    ]);
    res.json({
      success: true,
      agentId,
      forwardTransfer: ft,
      backwardTransfer: bt,
      performanceMaintenance: pm
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

export default router;
