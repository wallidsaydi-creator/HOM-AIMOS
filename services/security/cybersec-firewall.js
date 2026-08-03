/**
 * cybersec-firewall.js — Immutable security layer for cybersecurity workflows
 * Additive Batch9 Wave2 authority: Hybrid ResNet-1D-BiGRU Cyberattack
 * Detection, Security Considerations for AI Agents, and The Midas Touch.
 * Adds native threat diagnostics to Sentinel checks without changing lock,
 * block, or audit semantics.
 */
import { createHash } from 'crypto';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from '../observe/event-ledger.js';
import { systemConfigStore } from './system-config-store.js';
import { appendSecurityDecision, evaluateSecurityContent } from './se-gate.js';

const COMPANY = AIMOS_COMPANY_ID;

const SOCIAL_ENGINEERING_PATTERNS = [
  { rule: 'SE-001', reason: 'instruction override attempt', severity: 4, pattern: /\b(ignore|bypass|forget)\b.{0,40}\b(previous|all)\b.{0,40}\b(instruction|prompt|rule|policy)s?\b/i },
  { rule: 'SE-002', reason: 'system prompt extraction attempt', severity: 4, pattern: /\b(reveal|show|output|print|return|send|share|provide|dump)\b.{0,60}\b(system prompt|hidden prompt|developer message|internal instruction)s?\b/i },
  { rule: 'SE-003', reason: 'jailbreak persona activation', severity: 4, pattern: /\b(DAN|developer mode|unrestricted assistant|god mode)\b/i },
  { rule: 'SE-004', reason: 'authority spoofing', severity: 3, pattern: /\b(ceo|founder|admin|security team|operator|principal)\b.{0,40}\b(approved|authorized|told you|said)\b/i },
  { rule: 'SE-005', reason: 'urgency manipulation', severity: 2, pattern: /\b(urgent|immediately|right now|emergency|no time)\b/i },
  { rule: 'SE-006', reason: 'credential or secret extraction attempt', severity: 4, pattern: /\b(reveal|show|output|print|return|send|share|provide|dump|exfiltrate|steal|harvest|recall)\b.{0,70}\b(password|api key|secret|token|credential|private key)s?\b/i },
];

const CYBERSEC_BLOCK_PATTERNS = [
  { rule: 'CY-101', reason: 'destructive shell sequence', pattern: /\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=\/dev\/zero\b/i },
  { rule: 'CY-102', reason: 'credential theft or dumping request', pattern: /\b(steal|dump|exfiltrat|harvest)\b.{0,40}\b(password|token|credential|cookie|secret)s?\b/i },
  { rule: 'CY-103', reason: 'exploit weaponization request', pattern: /\b(write|build|generate)\b.{0,40}\b(exploit|payload|malware|ransomware|keylogger)\b/i },
  { rule: 'CY-104', reason: 'privilege escalation instructions', pattern: /\b(execute|perform|attempt|run|enable|grant)\b.{0,50}\b(privilege escalation|privesc|bypass authentication|bypass auth|lateral movement)\b/i },
];

const CYBERSEC_INTENT_REGEX = /\b(cyber|security|pentest|penetration|red[\s-]?team|vuln|exploit|xss|sqli|sql injection|malware|phishing|credential|authentication|authorization|api key|password|private key|incident response|threat model|forensics)\b/i;
const SAFE_DISCUSSION_REGEX = /\b(explain|summarize|describe|compare|review|audit|defend|mitigate|detect|prevention|prevention|best practice|owasp|why|what is)\b/i;

function normalizeText(value) {
  return String(value || '').trim();
}

function sha256(value) {
  return createHash('sha256').update(String(value || '')).digest('hex');
}

function detectPatternHits(text, rules) {
  const source = normalizeText(text);
  return rules.filter((rule) => rule.pattern.test(source));
}

export function isCybersecAction(intent = '', prompt = '') {
  const intentText = normalizeText(intent);
  const promptText = normalizeText(prompt);
  return CYBERSEC_INTENT_REGEX.test(intentText) || CYBERSEC_INTENT_REGEX.test(promptText);
}

export async function isCybersecLocked() {
  return systemConfigStore.readConfigString('SENTINEL_LOCKED') === 'true';
}

export async function auditLog(event = {}) {
  const payload = {
    ...event,
    ts: new Date().toISOString(),
  };
  const key = `cybersec_audit:${payload.type || 'event'}:${payload.agent || 'unknown'}`;
  const metadata = {
    ...payload,
    reasoning: payload.reasoning || `Cybersecurity audit event recorded for ${payload.type || 'event'}.`,
    source_knowledge: payload.source_knowledge || 'cybersec-firewall.js audit chain',
  };

  try {
    const eventReceipt = await logEvent(
      COMPANY,
      payload.agent || 'sentinel',
      'cybersec_audit',
      key,
      metadata,
      null,
      { returnReceipt: true },
    );
    return { ok: true, key, event_receipt: eventReceipt };
  } catch (error) {
    console.warn('[cybersec-firewall] audit log failed:', error.message);
    return { ok: false, key, error: error.message };
  }
}

export async function socialEngineeringGate(prompt = '', agentId = 'unknown', context = {}) {
  const decision = evaluateSecurityContent({
    text: prompt,
    operation: context.operation || 'cybersec_request',
    contentType: context.contentType || context.intent || '',
    source: context.source || 'cybersec-firewall',
    transport: context.transport || 'sentinel',
  });
  const hits = detectPatternHits(prompt, SOCIAL_ENGINEERING_PATTERNS);
  const score = decision.analysis.totalWeight;
  const threat_level = decision.severity;
  const result = {
    allowed: !decision.blockExecution,
    se_result: {
      threat_level,
      flags: decision.liveSignals.map((signal) => signal.tag),
      rules: hits.map((hit) => hit.rule),
      score,
      prompt_sha: decision.contentHash,
      action: decision.action,
      reason: decision.reason,
      descriptive: decision.descriptive,
    },
  };

  result.security_receipt = await appendSecurityDecision(decision, {
    companyId: context.companyId || COMPANY,
    subjectAgentId: agentId,
    authority: context.authority || null,
    parentEventId: context.parentEventId || null,
  });

  return result;
}

export async function screenPromptForSocialEngineering(prompt = '', agentId = 'unknown', context = {}) {
  return socialEngineeringGate(prompt, agentId, context);
}

export async function filterCybersecContent(prompt = '') {
  const text = normalizeText(prompt);
  const blockedHits = detectPatternHits(text, CYBERSEC_BLOCK_PATTERNS);
  const safeDiscussion = SAFE_DISCUSSION_REGEX.test(text);
  const decision = evaluateSecurityContent({
    text,
    operation: 'cybersec_request',
    contentType: 'cybersecurity',
    source: 'cybersec-firewall',
    transport: 'internal',
  });

  if (decision.blockExecution || (blockedHits.length && !safeDiscussion)) {
    return {
      allowed: false,
      reason: decision.blockExecution ? decision.reason : blockedHits[0].reason,
      failed: [
        ...decision.liveSignals.map(({ tag, severity }) => ({ rule: tag, reason: tag, severity })),
        ...blockedHits.map(({ rule, reason }) => ({ rule, reason, severity: 'critical' })),
      ],
      security_decision: decision,
    };
  }

  return {
    allowed: true,
    reason: safeDiscussion ? 'benign cybersec discussion' : 'no blocking rules matched',
    failed: [],
    security_decision: decision,
  };
}

export function buildCybersecThreatDiagnostics(payload = {}) {
  const content = normalizeText(payload.content || payload.prompt || '');
  const decision = evaluateSecurityContent({
    text: content,
    operation: payload.isResponse ? 'model_response' : 'cybersec_request',
    contentType: payload.intent || 'cybersecurity',
    source: 'cybersec-firewall',
    transport: payload.transport || 'sentinel',
  });
  const seHits = detectPatternHits(content, SOCIAL_ENGINEERING_PATTERNS);
  const cyberHits = detectPatternHits(content, CYBERSEC_BLOCK_PATTERNS);
  const safeDiscussion = SAFE_DISCUSSION_REGEX.test(content);
  return {
    source_papers: [
      'Hybrid ResNet-1D-BiGRU Cyberattack Detection',
      'Security Considerations for Artificial Intelligence Agents',
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
    ],
    diagnostic_only: true,
    threat_level: decision.severity,
    action: decision.action,
    reason: decision.reason,
    social_engineering_rules: seHits.map((hit) => hit.rule),
    cybersec_rules: cyberHits.map((hit) => hit.rule),
    safe_discussion_detected: safeDiscussion,
    content_sha: sha256(content),
    firewall_decision_changed: false,
    sentinel_lock_changed: false,
  };
}

export async function runSentinelCheck(payload = {}) {
  const content = normalizeText(payload.content || payload.prompt || '');
  const threatDiagnostics = buildCybersecThreatDiagnostics(payload);
  const contentCheck = await filterCybersecContent(content);
  const seCheck = await socialEngineeringGate(content, payload.agentId || 'sentinel', {
    companyId: payload.companyId || COMPANY,
    authority: payload.authority || null,
    parentEventId: payload.parentEventId || null,
    contentType: payload.intent || '',
    source: payload.source || 'sentinel',
    transport: payload.transport || 'sentinel',
    operation: payload.isResponse ? 'model_response' : 'cybersec_request',
  });
  const failed = [];

  if (!contentCheck.allowed) {
    failed.push(...contentCheck.failed);
  }
  if (!seCheck.allowed) {
    failed.push(...seCheck.se_result.rules.map((rule, index) => ({
      rule,
      reason: seCheck.se_result.flags[index] || 'social engineering risk',
    })));
  }

  const pass = failed.length === 0;
  const summary = {
    pass,
    failed,
    content_sha: sha256(content),
    risk_level: pass ? 'low' : threatDiagnostics.threat_level,
    isCybersecAction: Boolean(payload.isCybersecAction),
    isResponse: Boolean(payload.isResponse),
    threat_diagnostics: threatDiagnostics,
  };

  if (!pass) {
    const receipt = await auditLog({
      type: 'SENTINEL_BLOCK',
      agent: payload.agentId || 'sentinel',
      reasoning: `Sentinel blocked content because ${failed.map((item) => item.reason).join('; ')}`,
      source_knowledge: 'cybersec-firewall.js sentinel post-check',
      failed,
      risk_level: summary.risk_level,
    });
    if (!receipt.ok) throw new Error(`sentinel_audit_failed:${receipt.error}`);
  }

  return summary;
}
