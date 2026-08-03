import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import express from 'express';
import {
  ensureGovernanceReady,
  resolveExecutionContext,
  getGovernanceStats,
  hydrateAgentStoreFromGovernance
} from '../services/orchestration/governance-resolver.js';
import { getHomBrainOperatingProfile } from '../services/core/brain-contract.js';

const router = express.Router();
const COMPANY = AIMOS_COMPANY_ID;

router.post('/resolve', async (req, res, next) => {
  const {
    agentId = req.agentId,
    prompt = '',
    sessionKey,
    channel,
    peerId,
    requestedModel,
    intent
  } = req.body || {};

  if (!agentId || agentId !== req.agentId) {
    return res.status(403).json({ success: false, error: 'verified_governance_actor_mismatch' });
  }

  try {
    await ensureGovernanceReady(COMPANY);
    await hydrateAgentStoreFromGovernance(COMPANY);

    const resolution = await resolveExecutionContext({
      companyId: COMPANY,
      agentId,
      prompt,
      sessionKey,
      channel,
      peerId,
      requestedModel,
      intent
    });

    res.json({
      success: true,
      resolution,
      dryRun: true
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/stats', async (_req, res, next) => {
  try {
    const stats = await getGovernanceStats(COMPANY);
    res.json({ success: true, ...stats });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/brain', async (req, res, next) => {
  const samplePrompt = String(req.body?.samplePrompt || 'Architect the agent operating system governance layer').trim();
  const sampleIntent = String(req.body?.sampleIntent || 'architecture').trim();

  try {
    await ensureGovernanceReady(COMPANY);
    await hydrateAgentStoreFromGovernance(COMPANY);
    const profile = getHomBrainOperatingProfile(COMPANY);

    const sampleResolution = await resolveExecutionContext({
      companyId: COMPANY,
      agentId: req.agentId,
      prompt: samplePrompt,
      intent: sampleIntent,
      disableDelegation: false
    });

    res.json({
      success: true,
      profile,
      linked: sampleResolution?.brainLink || null,
      sampleResolution: {
        sourceAgentId: sampleResolution.sourceAgentId,
        resolvedAgentId: sampleResolution.resolvedAgentId,
        matchedRule: sampleResolution.delegationPolicy?.matchedRuleReason || null
      }
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

export default router;
