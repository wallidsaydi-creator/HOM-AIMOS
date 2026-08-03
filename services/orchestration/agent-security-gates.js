/**
 * agent-security-gates.js — Security Gate Pipeline (Gap 4 extraction)
 *
 * Extracts the security gate orchestration from agent-runner.js into a
 * single callable pipeline function. Each gate is a sequential check that
 * can throw to block execution or return diagnostic data for later use.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Called by: agent-runner.js (pre-LLM security pipeline)
 * 2. → Calls: cybersec-firewall.js, se-gate.js, security-ladder.js,
 *             cognitive-demand.js, meta-controller.js, agent-learning.js,
 *             canary-tracker.js, security-classifier.js, event-ledger.js
 * 3. Pipeline: AGENT_RUN_PIPELINE | Position: pre-LLM security gates
 *
 * Created: 2026-05-05 (Gap 4 extraction from agent-runner.js)
 */

import { isCybersecAction, isCybersecLocked, filterCybersecContent, auditLog } from '../security/cybersec-firewall.js';
import {
  appendSecurityDecision,
  evaluateSecurityContent,
  BLOCK_THRESHOLD as SE_BLOCK_THRESHOLD,
} from '../security/se-gate.js';
import { computeSecurityResponse } from '../security/security-ladder.js';
import { classifyBloomLevel, classifyCognitiveSecurity } from '../security/cognitive-demand.js';
import { evaluateMetaState } from './meta-controller.js';
import { updateBehavioralBaseline, checkRiskBudget, buildPsychometricContract } from '../learning/agent-learning.js';
import { logEvent } from '../observe/event-ledger.js';

// ─── SECURITY GATE PIPELINE ──────────────────────────────────────────────────

/**
 * Run the full security gate pipeline for an agent run.
 *
 * Returns an object with security diagnostics (bloomLevel, reviewTier,
 * behavioralCheck, psychometricProfile, metaDecision, cybersecMode)
 * that the caller uses for downstream decisions.
 *
 * Throws if any gate blocks execution.
 */
export async function runSecurityGates({ userPrompt, agentId, options = {}, COMPANY = 'hom' }) {
  const results = {
    seScreen: null,
    seGateAnalysis: null,
    securityDecision: null,
    securityDecisionReceipt: null,
    cybersecMode: false,
    ladderResult: null,
    behavioralCheck: null,
    bloomLevel: 1,
    reviewTier: 'se_gate_only',
    taskRiskLevel: 'low',
    metaDecision: null,
    psychometricProfile: null,
  };

  // ─── CONTEXT-AWARE SOCIAL ENGINEERING DECISION ─────────────────────────────
  // One owner and one signed receipt replace the former pair of noun-based
  // screens. Descriptive security work can proceed; executable directives do
  // not acquire authority merely by mentioning an operator or a tool.
  results.securityDecision = evaluateSecurityContent({
    text: userPrompt,
    operation: 'agent_prompt',
    contentType: options.taskType || options.intent || 'chat',
    source: options.source || 'agent-runner',
    transport: 'agent',
  });
  results.seGateAnalysis = results.securityDecision.analysis;
  results.seScreen = {
    allowed: !results.securityDecision.blockExecution,
    se_result: {
      threat_level: results.securityDecision.severity,
      flags: results.securityDecision.liveSignals.map((signal) => signal.tag),
      rules: results.securityDecision.liveSignals.map((signal) => signal.tag),
      score: results.seGateAnalysis.totalWeight,
      prompt_sha: results.securityDecision.contentHash,
    },
  };
  results.securityDecisionReceipt = await appendSecurityDecision(results.securityDecision, {
    companyId: COMPANY,
    subjectAgentId: agentId,
    authority: options.requestAuthority || options.mutationAuthority || null,
    parentEventId: options.parentEventId || null,
  });
  if (results.securityDecision.blockExecution) {
    const err = new Error(`SOCIAL ENGINEERING BLOCKED [${results.securityDecision.severity}]: ${results.securityDecision.liveSignals.slice(0, 2).map((signal) => signal.tag).join(', ')}`);
    err.code = 'SE_BLOCKED';
    err.threat_level = results.securityDecision.severity;
    err.security_receipt = results.securityDecisionReceipt;
    throw err;
  }

  // ─── CYBERSEC FIREWALL GATE ─────────────────────────────────────────────────
  results.cybersecMode = isCybersecAction(options.intent, userPrompt);
  if (results.cybersecMode) {
    if (await isCybersecLocked()) {
      await logEvent(COMPANY, agentId, 'cybersec_lockout', `lockout:${agentId}`, {
        reasoning: 'Agent attempted cybersec action while system is in SENTINEL LOCKOUT state. Lockout exists because violation threshold was exceeded — only the operator can unlock.',
        source_knowledge: 'cybersec-firewall.js lockout policy'
      });
      throw new Error('SENTINEL LOCKOUT: All cybersecurity activity halted. Contact the operator to unlock.');
    }
    const contentCheck = await filterCybersecContent(userPrompt);
    if (!contentCheck.allowed) {
      await logEvent(COMPANY, agentId, 'cybersec_blocked', `sentinel_block:${agentId}`, {
        reasoning: `Content filter rejected prompt: ${contentCheck.reason}. Cybersec content filtering prevents agents from executing potentially destructive security operations without clearance.`,
        source_knowledge: 'cybersec-firewall.js content filter rules'
      });
      throw new Error(`SENTINEL BLOCKED: ${contentCheck.reason}`);
    }
    const auditReceipt = await auditLog({ type: 'GATE_PASS', agent: agentId, intent: options.intent, prompt_length: String(userPrompt).length });
    if (!auditReceipt.ok) throw new Error(`SENTINEL AUDIT FAILED: ${auditReceipt.error}`);
  }

  // ─── BEHAVIORAL BASELINE: Layer 2 SE defense ────────────────────────────────
  results.behavioralCheck = await updateBehavioralBaseline(agentId, {
    prompt: userPrompt,
    taskType: options.taskType || options.intent || 'chat',
    toolsUsed: 0
  });
  if (results.behavioralCheck.anomalyScore > 0.6) {
    console.warn(`[behavioral] HIGH anomaly for ${agentId}: score=${results.behavioralCheck.anomalyScore.toFixed(2)}`);
    await logEvent(COMPANY, agentId, 'behavioral_anomaly', `anomaly:${agentId}`, {
      reasoning: `Behavioral anomaly score ${results.behavioralCheck.anomalyScore.toFixed(2)} exceeds 0.6 threshold. Agent deviated from established baseline patterns. This could indicate compromised input, prompt injection, or legitimate but unusual task.`,
      source_knowledge: 'agent-learning.js behavioral baseline + psychology-over-regex Layer 2 defense',
      score: results.behavioralCheck.anomalyScore,
      features: results.behavioralCheck.features
    });
    await auditLog({ type: 'BEHAVIORAL_ANOMALY', agent: agentId, score: results.behavioralCheck.anomalyScore, features: results.behavioralCheck.features });
  }

  // ─── SECURITY LADDER: graduated response from observed evidence ─────────────
  const rawManipulationRisk = Math.max(0, Math.min(
    1,
    Number(results.seGateAnalysis?.totalWeight || 0) / SE_BLOCK_THRESHOLD,
  ));
  const manipulationRisk = results.securityDecision?.descriptive
    ? Math.min(rawManipulationRisk, 0.15)
    : rawManipulationRisk;
  const contextualRisk = results.securityDecision?.action === 'audit_allow' ? 0.25 : 0;
  results.ladderResult = computeSecurityResponse({
    behavioralDrift: results.behavioralCheck.anomalyScore,
    manipulationRisk,
    contextualRisk,
  });
  if (results.ladderResult.action === 'block') {
    await logEvent(COMPANY, agentId, 'security_ladder_blocked', `ladder_block:${agentId}`, {
      reasoning: `Security ladder computed action=block — tier=${results.ladderResult.tier}, reason=${results.ladderResult.reason}`,
      source_knowledge: 'security-ladder.js — decision ladder for graduated threat response',
      tier: results.ladderResult.tier,
      action: results.ladderResult.action,
      components: results.ladderResult.components,
    });
    const err = new Error(`SECURITY LADDER BLOCKED [tier=${results.ladderResult.tier}]: ${results.ladderResult.reason}`);
    err.code = 'SECURITY_LADDER_BLOCKED';
    throw err;
  }
  if (results.ladderResult.action === 'challenge') {
    await logEvent(COMPANY, agentId, 'security_ladder_escalated', `ladder_challenge:${agentId}`, {
      reasoning: `Security ladder computed action=challenge — ${results.ladderResult.reason}`,
      source_knowledge: 'security-ladder.js — decision ladder for graduated threat response',
      tier: results.ladderResult.tier,
      action: results.ladderResult.action,
      components: results.ladderResult.components,
    });
    console.warn(`[security-ladder] challenge issued for ${agentId}: tier=${results.ladderResult.tier}, reason=${results.ladderResult.reason}`);
  } else if (results.ladderResult.action === 'shape') {
    await logEvent(COMPANY, agentId, 'security_ladder_escalated', `ladder_shape:${agentId}`, {
      reasoning: `Security ladder computed action=shape — ${results.ladderResult.reason}`,
      source_knowledge: 'security-ladder.js — decision ladder for graduated threat response',
      tier: results.ladderResult.tier,
      action: results.ladderResult.action,
      components: results.ladderResult.components,
    });
  }

  // ─── COGNITIVE DEMAND: Bloom taxonomy classification ─────────────────────────
  try {
    results.bloomLevel = classifyBloomLevel(userPrompt);
    const cognitiveSecurity = classifyCognitiveSecurity(results.bloomLevel);
    results.reviewTier = cognitiveSecurity.reviewTier;
    results.taskRiskLevel = cognitiveSecurity.taskRiskLevel;
    if (results.bloomLevel >= 5) {
      console.info(`[cognitive-demand] high-order request for ${agentId}: bloom=${results.bloomLevel} (${results.reviewTier}, risk=${results.taskRiskLevel})`);
    }
  } catch (bloomErr) {
    console.warn('[cognitive-demand] classification failed:', bloomErr.message);
  }

  // ─── META-CONTROLLER: adaptive execution strategy ────────────────────────────
  if (!options.fastLane) {
    try {
      const taskDomain = options.taskType || options.intent || 'general';
      results.metaDecision = await evaluateMetaState(userPrompt, agentId, taskDomain, {
        statedConfidence: options.confidence,
        lastRunSuccess: options.lastRunSuccess,
        resourceBudget: options.resourceBudget || 1.0,
        errorSignature: options.errorSignature
      });
    } catch (metaErr) {
      console.warn('[meta-controller] evaluation failed:', metaErr.message);
    }
  }

  // ─── RISK BUDGET GATE ────────────────────────────────────────────────────────
  if (!options.skipAimos && !options.fastLane) {
    try {
      const riskCheck = await checkRiskBudget(agentId, {
        errorCount: 0,
        tokenEstimate: String(userPrompt || '').length * 4,
        latencyMs: 0
      });
      if (riskCheck.exceeded) {
        await logEvent(COMPANY, agentId, 'risk_budget_exceeded', `risk_block:${agentId}`, {
          reasoning: `Risk budget exceeded: ${riskCheck.reason}. Agent accumulated too many errors/tokens/latency within budget window. Blocking prevents cascading failures and runaway costs.`,
          source_knowledge: 'agent-learning.js risk budget system'
        });
        throw new Error(`Risk budget exceeded for ${agentId}: ${riskCheck.reason}`);
      }
    } catch (riskErr) {
      if (riskErr.message?.startsWith('Risk budget exceeded')) throw riskErr;
      await logEvent(COMPANY, agentId, 'risk_check_failed', `risk_fail:${agentId}`, {
        reasoning: `Risk budget check itself failed — Aimos DB unreachable. Fail-closed: agent blocked because we cannot verify risk state. This is safer than allowing unverified execution.`,
        source_knowledge: 'agent-runner.js fail-closed policy for DB outages'
      });
      throw new Error(`Risk budget check failed for ${agentId}: Aimos unreachable (${riskErr.message || 'DB error'}). Agent blocked until DB recovers.`);
    }
  }

  // ─── PSYCHOMETRIC PROFILE BUILD ─────────────────────────────────────────────
  try {
    results.psychometricProfile = buildPsychometricContract({
      agentId,
      model: options.model || '',
      scaffold: 'unknown',
      taskType: options.taskType || options.intent || 'chat',
      prompt: userPrompt,
      toolsUsed: 0,
      behavioralCheck: results.behavioralCheck,
    });
    if (results.psychometricProfile.behavioral_profile?.drift_triggered) {
      await logEvent(COMPANY, agentId, 'psychometric_drift', `psychometric:${agentId}:${Date.now()}`, {
        reasoning: `Agent Psychometrics drift trigger fired: anomaly=${results.psychometricProfile.behavioral_profile.anomaly_score}, baseline_runs=${results.psychometricProfile.behavioral_profile.baseline_runs}.`,
        source_knowledge: 'Agent Psychometrics — task-level performance prediction and behavioral drift diagnostics',
        profile: results.psychometricProfile
      });
    }
  } catch (psychErr) {
    console.warn('[agent-psychometrics] profile build failed (non-fatal):', psychErr.message);
  }

  return results;
}

/**
 * Build a structured error from a security gate result.
 */
export function buildSecurityGateError({ code, message, threatLevel }) {
  const err = new Error(message);
  err.code = code;
  if (threatLevel != null) err.threat_level = threatLevel;
  return err;
}
