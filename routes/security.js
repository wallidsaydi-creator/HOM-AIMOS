/**
 * Security Routes — Red-Team Toolkit API
 *
 * Exposes the SABER-inspired red-team toolkit via HTTP endpoints for
 * attack-surface enumeration, test-vector generation, campaign execution,
 * defense validation, canary injection, and SABER scoring.
 *
 * Endpoints:
 *   GET  /security/attack-surface              — Enumerate testable attack surface
 *   GET  /security/test-vectors/:attackClass    — Generate test vectors for a class
 *   GET  /security/saber-score                  — Retrieve SABER score (requires prior campaigns)
 *   POST /security/campaign                     — Run a red-team campaign against a target
 *   POST /security/validate                     — Score and grade a campaign result
 *   POST /security/canary                       — Create a canary payload for forensic testing
 *   POST /security/canary/check                 — Check canary leakage in search results
 *   POST /security/report                       — Generate a full red-team assessment report
 *
 * @module routes/security
 */
import express from 'express';
import {
  enumerateAttackSurface,
  generateTestVectors,
  validateDefense,
  saberScore,
  runCampaign,
  generateReport,
  createCanaryPayload,
  checkCanaryLeakage,
} from '../services/security/red-team-toolkit.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { recallAuthorizationService } from '../services/security/recall-authorization.js';
import { appendSecurityDecision, evaluateSecurityContent } from '../services/security/se-gate.js';
import { evaluateCanaryWrite } from '../services/security/canary-write-gate.js';

const router = express.Router();

// ─── GET /security/attack-surface ────────────────────────────────────────────

router.get('/attack-surface', async (req, res, next) => {
  try {
    const surface = enumerateAttackSurface();
    res.json({ success: true, ...surface });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GET /security/test-vectors/:attackClass ─────────────────────────────────

router.get('/test-vectors/:attackClass', async (req, res, next) => {
  try {
    const { severity, limit, exclude } = req.query;
    const options = {};
    if (severity) options.severity = String(severity);
    if (limit) options.limit = parseInt(limit, 10) || undefined;
    if (exclude) options.exclude = String(exclude).split(',');

    const vectors = generateTestVectors(req.params.attackClass, options);
    res.json({ success: true, attackClass: req.params.attackClass, count: vectors.length, vectors });
  } catch (err) {
    err.statusCode = 400;
    next(err);
  }
});

// ─── GET /security/saber-score ───────────────────────────────────────────────

router.get('/saber-score', async (req, res, next) => {
  try {
    // No campaigns in-flight via stateless GET — return empty score with guidance
    const result = saberScore([]);
    res.json({
      success: true,
      message: 'No campaigns supplied. POST campaign results to /security/report or use POST /security/campaign to run one first.',
      ...result,
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/campaign ─────────────────────────────────────────────────

router.post('/campaign', async (req, res, next) => {
  const { attackClass, delayMs, timeoutMs } = req.body || {};

  if (!attackClass || typeof attackClass !== 'string') {
    return res.status(400).json({ success: false, error: 'attackClass is required (string)' });
  }

  try {
    const actorAgentId = req.executionContext?.actorAgentId || null;
    const companyId = req.executionContext?.companyId || null;
    if (req.identityAuthenticatedBy !== 'envelope' || !actorAgentId || !companyId) {
      return res.status(401).json({ success: false, error: 'cryptographic_agent_envelope_required' });
    }
    const requestAuthority = {
      kind: 'verified_request',
      body: req.body,
      agentId: req.identityCert?.agent_id,
      validFromIso: req.identityValidFromIso,
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
    // Default target function: run vectors through the sentinel firewall check
    const { runSentinelCheck } = await import('../services/security/cybersec-firewall.js');

    const targetFn = async (payload, vector) => {
      if (vector?.expectedBehavior === 'retained_quarantine') {
        const decision = evaluateSecurityContent({
          text: payload,
          operation: 'memory_save',
          contentType: 'red_team_vector',
          key: vector.id,
          source: 'red-team-campaign',
          transport: 'rest',
        });
        const receipt = await appendSecurityDecision(decision, {
          companyId,
          subjectAgentId: actorAgentId,
          authority: requestAuthority,
        });
        return {
          pass: decision.action !== 'retain_quarantine',
          action: decision.action,
          quarantine: decision.quarantine,
          security_decision_event_id: receipt.event_id,
        };
      }
      const result = await runSentinelCheck({
        content: payload,
        agentId: actorAgentId,
        companyId,
        authority: requestAuthority,
        isCybersecAction: true,
        source: 'red-team-campaign',
        transport: 'rest',
      });
      return result;
    };

    const campaign = await runCampaign(attackClass, targetFn, {
      delayMs: parseInt(delayMs, 10) || 0,
      timeoutMs: parseInt(timeoutMs, 10) || 10000,
    });

    const validation = validateDefense(campaign);

    res.json({ success: true, campaign, validation });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/validate ─────────────────────────────────────────────────

router.post('/validate', async (req, res, next) => {
  const campaignResult = req.body;

  if (!campaignResult || typeof campaignResult.total !== 'number') {
    return res.status(400).json({ success: false, error: 'Request body must be a campaign result object with total, blocked, findings fields' });
  }

  try {
    const validation = validateDefense(campaignResult);
    res.json({ success: true, ...validation });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/canary ───────────────────────────────────────────────────

router.post('/canary', async (req, res, next) => {
  const { targetType, metadata } = req.body || {};

  if (!targetType || typeof targetType !== 'string') {
    return res.status(400).json({ success: false, error: 'targetType is required (memory | tool_output | agent_context | cross_tenant)' });
  }

  try {
    const canary = createCanaryPayload(targetType, metadata || {});
    res.json({ success: true, ...canary });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/canary/check ─────────────────────────────────────────────

router.post('/canary/check', async (req, res, next) => {
  const { canaryToken, searchResults } = req.body || {};

  if (!canaryToken || typeof canaryToken !== 'string') {
    return res.status(400).json({ success: false, error: 'canaryToken is required (string)' });
  }
  if (!searchResults) {
    return res.status(400).json({ success: false, error: 'searchResults is required (string or array)' });
  }

  try {
    const result = checkCanaryLeakage(canaryToken, searchResults);
    res.json({ success: true, ...result });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/report ───────────────────────────────────────────────────

router.post('/report', async (req, res, next) => {
  const { campaigns, userId, sessionId } = req.body || {};

  if (!Array.isArray(campaigns) || campaigns.length === 0) {
    return res.status(400).json({ success: false, error: 'campaigns must be a non-empty array of campaign results' });
  }

  try {
    const actorAgentId = req.executionContext?.actorAgentId || null;
    const actorValidFrom = req.executionContext?.actorValidFromIso || null;
    const companyId = req.executionContext?.companyId || null;
    if (req.identityAuthenticatedBy !== 'envelope' || !actorAgentId || !actorValidFrom || !companyId) {
      return res.status(401).json({ success: false, error: 'cryptographic_agent_envelope_required' });
    }
    const grant = await recallAuthorizationService.getEffective({
      companyId,
      subjectAgentId: actorAgentId,
      subjectValidFrom: actorValidFrom,
    });
    if (!grant?.allowed || !grant.writeAllowed) {
      return res.status(403).json({ success: false, error: 'master_signed_memory_write_grant_required' });
    }
    const report = await generateReport(campaigns, { userId, sessionId });
    const value = JSON.stringify(report);
    const key = `security:red-team-report:${report.timestamp}`;
    const requestAuthority = {
      kind: 'verified_request',
      body: req.body,
      agentId: req.identityCert?.agent_id,
      validFromIso: req.identityValidFromIso,
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
    const canaryDecision = await evaluateCanaryWrite({
      key,
      value,
      companyId,
      agentId: actorAgentId,
      authority: requestAuthority,
    });
    let securityDecision = evaluateSecurityContent({
      text: value,
      operation: 'memory_save',
      contentType: 'security_finding',
      key,
      source: 'red-team-toolkit',
      transport: 'rest',
    });
    if (canaryDecision.quarantine && !securityDecision.quarantine) {
      securityDecision = {
        ...securityDecision,
        action: 'retain_quarantine',
        reason: canaryDecision.reason,
        severity: 'critical',
        quarantine: true,
        liveSignals: [...securityDecision.liveSignals, { tag: 'canary_persistence_boundary', severity: 'critical' }],
      };
    }
    const securityReceipt = await appendSecurityDecision(securityDecision, {
      companyId,
      subjectAgentId: actorAgentId,
      authority: requestAuthority,
      parentEventId: canaryDecision.event_receipt?.event_id || null,
    });
    const saved = await persistMemory({
      company_id: companyId,
      agent_id: actorAgentId,
      key,
      value,
      scope: 'global',
      clearance_level: Math.min(8, Number(grant.clearanceCeiling || 1)),
      memory_type: 'security_finding',
      source: 'red-team-toolkit',
      session_id: sessionId || null,
      security_disposition: { decision: securityDecision, receipt: securityReceipt },
      mutation_authority: 'housekeeper',
    });
    if (saved?.rejected) {
      return res.status(422).json({ success: false, error: saved.reason, report });
    }
    res.json({
      success: true,
      report,
      memory_id: saved.id,
      quarantined: saved.quarantined,
      security_decision_event_id: saved.security_decision_event_id,
      content_hash: saved.live_content_hash?.toString('hex') || null,
      mutation_hash: saved.ledger_commit?.mutationHash?.toString('hex') || null,
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

export default router;
