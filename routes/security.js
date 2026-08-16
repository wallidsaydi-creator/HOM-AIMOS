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
import { createHash } from 'node:crypto';
import {
  buildCampaignEvidence,
  buildCampaignManifest,
  campaignFromEvidence,
  enumerateAttackSurface,
  generateTestVectors,
  validateDefense,
  saberScore,
  runCampaign,
  generateReport,
  createCanaryPayload,
  checkCanaryLeakage,
  verifyCampaignEvidence,
  verifyCampaignReceiptBindings,
} from '../services/security/red-team-toolkit.js';
import {
  logEvent,
  readVerifiedEventById,
} from '../services/observe/event-ledger.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { recallAuthorizationService } from '../services/security/recall-authorization.js';
import { appendSecurityDecision, evaluateSecurityContent } from '../services/security/se-gate.js';
import { evaluateCanaryWrite } from '../services/security/canary-write-gate.js';

const router = express.Router();

function verifiedRequestAuthority(req) {
  return {
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
}

function parseEventMetadata(row) {
  if (row?.metadata && typeof row.metadata === 'object') return row.metadata;
  if (typeof row?.metadata === 'string') return JSON.parse(row.metadata);
  throw new Error('red_team_campaign_event_metadata_missing');
}

function sha256Text(value) {
  return createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

async function readVerifiedCampaign(campaignEventId, companyId) {
  const row = await readVerifiedEventById(campaignEventId, companyId);
  if (row.operation !== 'red_team_campaign_terminal') {
    throw new Error('red_team_campaign_terminal_event_required');
  }
  const metadata = parseEventMetadata(row);
  const evidence = metadata.evidence;
  const portable = verifyCampaignEvidence(evidence);
  if (!portable.valid || metadata.campaign_sha256 !== evidence?.campaign_sha256) {
    throw new Error(portable.reason || 'red_team_campaign_terminal_binding_invalid');
  }
  if (String(row.parent_event_id || '') !== String(evidence.start_event_id || '')) {
    throw new Error('red_team_campaign_start_terminal_link_invalid');
  }
  const receiptProof = await verifyCampaignReceiptBindings(
    evidence,
    (eventId) => readVerifiedEventById(eventId, companyId),
  );
  if (!receiptProof.valid) throw new Error(receiptProof.reason);
  return { row, evidence, portable, receiptProof };
}

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
    const companyId = req.executionContext?.companyId || null;
    const ids = String(req.query.campaign_event_id || '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (!companyId || ids.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'verified_campaign_event_id_required',
      });
    }
    const verified = [];
    for (const eventId of ids) {
      verified.push(await readVerifiedCampaign(eventId, companyId));
    }
    const result = saberScore(verified.map(({ evidence }) => campaignFromEvidence(evidence)));
    res.json({
      success: true,
      verified_campaign_event_ids: verified.map(({ row }) => row.id),
      campaign_sha256: verified.map(({ evidence }) => evidence.campaign_sha256),
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
  let campaignContext = null;

  if (!attackClass || typeof attackClass !== 'string') {
    return res.status(400).json({ success: false, error: 'attackClass is required (string)' });
  }

  try {
    const actorAgentId = req.executionContext?.actorAgentId || null;
    const companyId = req.executionContext?.companyId || null;
    if (req.identityAuthenticatedBy !== 'envelope' || !actorAgentId || !companyId) {
      return res.status(401).json({ success: false, error: 'cryptographic_agent_envelope_required' });
    }
    const requestAuthority = verifiedRequestAuthority(req);
    const manifest = buildCampaignManifest(attackClass);
    const campaignKey = `red-team:${attackClass}:${manifest.manifest_sha256.slice(0, 24)}`;
    const startReceipt = await logEvent(
      companyId,
      actorAgentId,
      'red_team_campaign_start',
      campaignKey,
      {
        manifest,
        reasoning: `Authorized native ${attackClass} red-team campaign started from its fixed case manifest.`,
        source_knowledge: 'red-team-toolkit.js SBR-2 signed campaign evidence',
        runtime_authority: false,
      },
      null,
      { authority: requestAuthority, returnReceipt: true },
    );
    campaignContext = {
      actorAgentId,
      companyId,
      requestAuthority,
      campaignKey,
      startEventId: startReceipt.event_id,
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
          parentEventId: startReceipt.event_id,
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
        parentEventId: startReceipt.event_id,
      });
      return result;
    };

    const campaign = await runCampaign(attackClass, targetFn, {
      delayMs: parseInt(delayMs, 10) || 0,
      timeoutMs: parseInt(timeoutMs, 10) || 10000,
    });

    const validation = validateDefense(campaign);
    const evidence = buildCampaignEvidence(campaign, {
      manifest,
      startEventId: startReceipt.event_id,
      requireNativeReceipts: true,
    });
    const portable = verifyCampaignEvidence(evidence);
    if (!portable.valid) throw new Error(portable.reason);
    const terminalReceipt = await logEvent(
      companyId,
      actorAgentId,
      'red_team_campaign_terminal',
      campaignKey,
      {
        campaign_sha256: evidence.campaign_sha256,
        evidence,
        reasoning: `Native ${attackClass} red-team campaign completed and its ordered cases and aggregate were committed.`,
        source_knowledge: 'red-team-toolkit.js SBR-2 signed campaign evidence',
        runtime_authority: false,
      },
      startReceipt.event_id,
      { authority: requestAuthority, returnReceipt: true },
    );

    res.json({
      success: true,
      campaign,
      validation,
      evidence,
      verification: portable,
      campaign_start_event_id: startReceipt.event_id,
      campaign_terminal_event_id: terminalReceipt.event_id,
      terminal_mutation_hash: terminalReceipt.mutation_hash,
    });
  } catch (err) {
    if (campaignContext) {
      try {
        await logEvent(
          campaignContext.companyId,
          campaignContext.actorAgentId,
          'red_team_campaign_failed',
          campaignContext.campaignKey,
          {
            error_name: String(err?.name || 'Error').slice(0, 120),
            error_message_sha256: sha256Text(err?.message),
            reasoning: 'The authorized native red-team campaign did not reach its terminal evidence commitment.',
            source_knowledge: 'red-team-toolkit.js SBR-2 signed campaign evidence',
            runtime_authority: false,
          },
          campaignContext.startEventId,
          { authority: campaignContext.requestAuthority, returnReceipt: true },
        );
      } catch {
        err.failureReceiptStatus = 'red_team_campaign_failed_receipt_append_failed';
      }
    }
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /security/validate ─────────────────────────────────────────────────

router.post('/validate', async (req, res, next) => {
  const { campaignEventId } = req.body || {};
  const companyId = req.executionContext?.companyId || null;
  if (!campaignEventId || typeof campaignEventId !== 'string' || !companyId) {
    return res.status(400).json({ success: false, error: 'verified_campaign_event_id_required' });
  }

  try {
    const verified = await readVerifiedCampaign(campaignEventId, companyId);
    const campaign = campaignFromEvidence(verified.evidence);
    const validation = validateDefense(campaign);
    res.json({
      success: true,
      campaign_event_id: verified.row.id,
      campaign_sha256: verified.evidence.campaign_sha256,
      verification: verified.receiptProof,
      ...validation,
    });
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
  const { campaignEventIds, userId, sessionId } = req.body || {};

  if (!Array.isArray(campaignEventIds) || campaignEventIds.length === 0) {
    return res.status(400).json({ success: false, error: 'verified_campaign_event_ids_required' });
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
    const verifiedCampaigns = [];
    for (const eventId of campaignEventIds) {
      verifiedCampaigns.push(await readVerifiedCampaign(eventId, companyId));
    }
    const campaigns = verifiedCampaigns.map(({ evidence }) => campaignFromEvidence(evidence));
    const report = await generateReport(campaigns, { userId, sessionId });
    report.evidence = {
      campaign_event_ids: verifiedCampaigns.map(({ row }) => row.id),
      campaign_sha256: verifiedCampaigns.map(({ evidence }) => evidence.campaign_sha256),
      receipt_bindings_verified: true,
    };
    const value = JSON.stringify(report);
    const key = `security:red-team-report:${report.timestamp}`;
    const requestAuthority = verifiedRequestAuthority(req);
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
