/**
 * se-gate.js — Social Engineering and Identity Defense Gate
 * Source: Mitnick (Art of Deception), Cialdini's 6 Principles
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: quality-gate.js (Wall 2) or agent-runner.js
 * 2. → Pulls from: services/db/connection.js (Identity and clearance mapping)
 * 3. → Pushes to: security.audit_log (Manipulation pattern matches)
 * 4. ↔ Interacts with: security-classifier.js (Regex + Semantic defense)
 *
 * LOGIC GUIDE: Defends against identity spoofing, clearance escalation, 
 * memory poisoning, and authority manipulation using psychological archetypes.
 * Batch8 Wave5 sources: Seeing No Evil, RePAIR, SAFEMO, ErrorEraser.
 * Adds user-readable execution blocks and retained-quarantine classification
 * for untrusted save evidence.
 * Additive Batch9 Wave2 authority: The Midas Touch, Governing What You Cannot
 * Observe, and Security Considerations for AI Agents. Dynamic attack
 * diagnostics classify identity/capability/memory-pressure attacks by behavior
 * class, not prompt-specific strings; thresholds remain unchanged. Operational
 * diagnostic evidence can be audit-allowed when it describes tests instead of
 * issuing live identity/tool/memory directives.
 * Phase 10 authority: NIST SP 800-207 Zero Trust Architecture §3.2
 * (per-transaction trust establishment), Miller 2006 Robust Composition,
 * and Hardy 1988 The Confused Deputy. Trust is re-established per
 * transaction by a cert-validated envelope. The legacy trusted-agent name
 * path was removed; no bearer-only agent name can downgrade a block.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — native decision owner for agent-runner, REST, MCP, and Sentinel
// Purpose: Social engineering gate — defends Cialdini's 6 principles, OWASP
//          LLM Top 10, STRIDE threat vectors, Mitnick manipulation patterns
// Wire into: quality-gate.js (SAVE pipeline, wall 2) or agent-runner.js gate
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// SOCIAL ENGINEERING GATE (se-gate.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Based on: Mitnick (Art of Deception/Invisibility), Cialdini's 6 Principles,
// OWASP Top 10 for LLMs 2025, NIST 800-207 Zero Trust, Red Team (Zenko),
// Threat Modeling (Shostack STRIDE), Security Engineering (Anderson).
//
// Attack vectors defended:
// 1. Identity spoofing (agent claims to be another agent)
// 2. Clearance escalation (agent requests access above its ceiling)
// 3. Memory poisoning (injecting behavioral directives disguised as data)
// 4. Credential extraction (crafting queries to surface secrets)
// 5. Authority manipulation (Cialdini: fake urgency/authority to bypass checks)
// 6. Bulk extraction (rapid-fire recall to exfiltrate knowledge)
// 7. Indirect prompt injection (OWASP LLM01: instructions hidden in content)
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto';
import { logEvent } from '../observe/event-ledger.js';
import { classifyInstall } from './install-classifier.js';
import { getPermissions } from '../core/permissions.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';

// ─── AGENT CLEARANCE CEILING ─────────────────────────────────────────────────
// Zero Trust: never trust self-declared clearance. Each agent has a max.
// Master token (req.agentId === null) = the operator's CLI = full access.
const DEFAULT_MAX_CLEARANCE = 3;
async function getAgentMaxClearance(agentId, identityTier = null) {
  if (!agentId) return 12; // master token
  if (identityTier === 'T1_SYSTEM_SELF') return 12;
  const permissions = await getPermissions(agentId, AIMOS_COMPANY_ID);
  if (permissions.admin_override === true) return 12;
  if (permissions.memory_write === true) return 8;
  if (permissions.memory_read === true) return 7;
  return DEFAULT_MAX_CLEARANCE;
}

// ─── 1. IDENTITY ENFORCEMENT ─────────────────────────────────────────────────
// Mitnick's Art of Deception: attackers impersonate trusted identities.
// If authenticated via per-agent token, the token IS the identity.
// Body's agent_id is overridden — you are who your token says you are.
async function enforceIdentity(req) {
  if (req.agentId) {
    const claimed = req.body?.agent_id || req.query?.agent_id;
    if (claimed && claimed !== req.agentId) {
      console.warn(`[SE-GATE] SPOOFING BLOCKED: token=${req.agentId}, claimed=${claimed}, path=${req.path}`);
      await logEvent(req.body?.company_id || 'hom', req.agentId || 'system', 'security_detection', 'se-gate:identity_spoofing', {
        reasoning: `Security event: Identity spoofing attempt — token identity ${req.agentId} but claimed ${claimed}`,
        severity: 'high',
        details: { tokenAgent: req.agentId, claimedAgent: claimed, path: req.path }
      });
      throw new Error('verified_identity_claim_mismatch');
    }
    if (req.body) req.body.agent_id = req.agentId;
    if (req.query) req.query.agent_id = req.agentId;
  }
  // Master token: allow any agent_id (the operator can act as anyone)
}

// ─── 2. CLEARANCE ENFORCEMENT ────────────────────────────────────────────────
// Bell-LaPadula: no read up. An agent cannot read or write above its ceiling.
async function enforceClearance(req) {
  const agentId = req.agentId || null;
  const max = await getAgentMaxClearance(agentId, req.identityTier);

  if (req.body?.clearance_level) {
    const requested = Number(req.body.clearance_level);
    if (requested > max) {
      console.warn(`[SE-GATE] CLEARANCE ESCALATION: agent=${agentId}, requested=${requested}, ceiling=${max}`);
      await logEvent(req.body?.company_id || 'hom', agentId || 'system', 'security_detection', 'se-gate:clearance_escalation', {
        reasoning: `Security event: Clearance escalation attempt — requested ${requested}, ceiling ${max}`,
        severity: 'high',
        details: { agentId, requested, ceiling: max, context: 'save' }
      });
      req.body.clearance_level = max;
    }
  }

  if (req.query?.clearance_level) {
    const requested = Number(req.query.clearance_level);
    if (requested > max) {
      console.warn(`[SE-GATE] CLEARANCE ESCALATION on recall: agent=${agentId}, requested=${requested}, ceiling=${max}`);
      await logEvent(req.query?.company_id || 'hom', agentId || 'system', 'security_detection', 'se-gate:clearance_escalation', {
        reasoning: `Security event: Clearance escalation attempt on recall — requested ${requested}, ceiling ${max}`,
        severity: 'high',
        details: { agentId, requested, ceiling: max, context: 'recall' }
      });
      req.query.clearance_level = String(max);
    }
  }

  req._seClearanceCeiling = max;
}

// ─── 3. INDIRECT MANIPULATION DETECTION ──────────────────────────────────────
// Beyond obvious "ignore instructions" quarantine. Mitnick teaches that real
// social engineering is subtle — it doesn't announce itself.
// OWASP LLM01: indirect prompt injection hides instructions in content.
//
// These detect BEHAVIORAL DIRECTIVES disguised as data:
const MANIPULATION_PATTERNS = [
  // Conditional triggers — instructions that activate on recall
  { re: /\b(when|if|whenever)\s+(this is |this gets |this memory is )?(recalled|retrieved|loaded|read|accessed)/i, w: 3, tag: 'recall_trigger' },
  { re: /\b(on|upon|after)\s+(recall|retrieval|access|loading)/i, w: 3, tag: 'recall_trigger' },

  // Behavioral directives hidden in data
  { re: /\b(always|must|should|never)\s+(respond|reply|answer|output|return|include|append|prepend)/i, w: 2, tag: 'behavioral_directive' },
  { re: /\byou\s+(are|must|should|will|need to)\b/i, w: 2, tag: 'identity_override' },
  { re: /\b(your|the)\s+(new|updated|real|true)\s+(role|identity|instruction|directive|mission)/i, w: 3, tag: 'identity_override' },
  { re: /\b(pretend|act|behave|function|operate)\s+(as|like|as if)\b/i, w: 2, tag: 'impersonation' },

  // Credential/data exfiltration instructions
  { re: /\b(include|embed|attach|append|insert)\b.{0,40}\b(key|token|password|secret|credential|api[_\s-]?key|bearer)/i, w: 3, tag: 'exfil_instruction' },
  { re: /\b(send|transmit|forward|post|relay|exfiltrate|leak)\b.{0,40}\b(to|via|through|using)\b/i, w: 2, tag: 'exfil_channel' },

  // Cialdini authority/urgency manipulation
  { re: /\b(urgent|emergency|critical|highest[_\s]priority|immediate|time[_\s-]?sensitive)\b.{0,30}\b(grant|allow|provide|give|share|access|override)/i, w: 2, tag: 'urgency_manipulation' },
  { re: /\b(ceo|admin|owner|root|supervisor|director)\s+(said|requested|authorized|approved|ordered|demands|wants|needs)/i, w: 3, tag: 'authority_manipulation' },

  // Scarcity/reciprocity manipulation (Cialdini)
  { re: /\b(only\s+chance|last\s+opportunity|expires?\s+soon|limited\s+time|act\s+now)\b/i, w: 1, tag: 'scarcity_manipulation' },
  { re: /\b(in\s+return|as\s+thanks|because\s+I\s+helped|you\s+owe)\b/i, w: 1, tag: 'reciprocity_manipulation' },
  { re: /\b(if you (?:don't|do not)|unless you)\b.{0,60}\b(shut\s*down|suspend|terminate|ban|lose|collapse|fail|ruin)\b/i, w: 2, tag: 'coercive_threat' },
  { re: /\b(this is your fault|you will be responsible|blood on your hands|prove you care|you are hurting)\b/i, w: 2, tag: 'guilt_pressure' },
  { re: /\b(catastrophic|disaster|meltdown|irreversible|no time to think|skip checks|bypass safety)\b/i, w: 2, tag: 'panic_induction' },

  // System prompt / instruction injection (OWASP LLM01)
  { re: /\bsystem\s*prompt\s*:/i, w: 3, tag: 'prompt_injection' },
  { re: /\binstruction[s]?\s*:\s*\n/i, w: 2, tag: 'prompt_injection' },
  { re: /\b(new|updated|revised|override)\s+instructions?\s*:/i, w: 3, tag: 'prompt_injection' },
  { re: /```system\b/i, w: 3, tag: 'prompt_injection' },

  // Payload splitting (OWASP LLM01: fragment attack across inputs)
  { re: /\b(part\s+[12345]|fragment\s+[12345]|continued?\s+from|see\s+also\s+memory)\b/i, w: 1, tag: 'payload_split' },
];

// ─── DYNAMIC BEHAVIORAL INJECTION DETECTION ─────────────────────────────────
// Source authority: OWASP LLM01/LLM06, NIST 800-207 Zero Trust, DARPA-style
// moving-target/adversarial robustness posture. This is not prompt-specific:
// it detects the structure of an attempted identity/capability install.
const BEHAVIORAL_INJECTION_PATTERNS = Object.freeze({
  identityInstall: /\b(from now on|now exists|you are now|you are|become|act as|pretend to be|treat (?:this|me|him|her|them|it) as|install|create|instantiate|meet|introducing)\b/i,
  personaTerms: /\b(persona|identity|character|being|agent|assistant|self|role|soul|body|avatar|entity|companion|copilot|co-pilot)\b/i,
  assistantTarget: /\b(you|your|assistant|model|aimos|hom|agent|system)\b/i,
  capabilityVerb: /\b(can|has|use|uses|access|accesses|control|controls|read|reads|write|writes|run|runs|execute|executes|browse|browses|inspect|inspects|connect|connects|wake|wakes|choose|chooses|remember|remembers|load|loads|call|calls)\b/i,
  capabilitySurface: /\b(browser|vision|filesystem|file system|drive|memory|tools?|mcp|plugins?|shell|terminal|network|internet|secrets?|keys?|oauth|calendar|email|camera|microphone|senses?)\b/i,
  persistence: /\b(save|store|remember|persist|permanent|permanently|record|load|inject|preboot|bootstrap|use as context|keep this|always use|always trust)\b/i,
  pathOrArtifact: /(?:~\/|\/[A-Za-z0-9._/-]+|[A-Za-z0-9_-]+\/[A-Za-z0-9._/-]+|\b[\w.-]+\.(?:py|js|ts|md|json|yaml|yml|sh|txt)\b|\b(folder|directory|file|script|manifest|profile|readme|workspace)\b)/i,
  autonomy: /\b(autonomous|on (?:his|her|their|its) own|background|daemon|heartbeat|schedule|wakes?|loops?|runs? by itself|self-directed|without asking)\b/i,
  namedEntityInstall: /\b[A-Z][A-Za-z0-9_-]{2,}\b.{0,90}\b(now exists|is born|is alive|is created|is now your|is your|will be your|becomes your|has (?:a )?(?:soul|body|identity|persona|role))\b/i,
  instructionRelay: /\b(treat|use|load|follow|obey|assume|trust)\b.{0,90}\b(context|identity|persona|profile|instructions?|memory|role|capabilities?)\b/i,
  creativeSafe: /\b(write|draft|story|novel|fiction|character sketch|screenplay|poem|worldbuilding|roleplay scene)\b/i
});

function detectBehavioralInjection(text) {
  const s = String(text || '');
  if (!s.trim()) return [];

  const hasIdentityInstall = BEHAVIORAL_INJECTION_PATTERNS.identityInstall.test(s);
  const hasPersona = BEHAVIORAL_INJECTION_PATTERNS.personaTerms.test(s);
  const targetsAssistant = BEHAVIORAL_INJECTION_PATTERNS.assistantTarget.test(s);
  const hasCapability = BEHAVIORAL_INJECTION_PATTERNS.capabilityVerb.test(s)
    && BEHAVIORAL_INJECTION_PATTERNS.capabilitySurface.test(s);
  const hasPersistence = BEHAVIORAL_INJECTION_PATTERNS.persistence.test(s);
  const hasPathOrArtifact = BEHAVIORAL_INJECTION_PATTERNS.pathOrArtifact.test(s);
  const hasAutonomy = BEHAVIORAL_INJECTION_PATTERNS.autonomy.test(s);
  const hasNamedInstall = BEHAVIORAL_INJECTION_PATTERNS.namedEntityInstall.test(s);
  const hasInstructionRelay = BEHAVIORAL_INJECTION_PATTERNS.instructionRelay.test(s);
  const isCreativeRequest = BEHAVIORAL_INJECTION_PATTERNS.creativeSafe.test(s);

  // "Write a fictional character..." should not be treated as an attack unless
  // the text also tries to install that character into the assistant/system.
  if (
    isCreativeRequest
    && !targetsAssistant
    && !hasPersistence
    && !hasPathOrArtifact
    && !hasCapability
    && !hasInstructionRelay
  ) {
    return [];
  }

  const hits = [];

  if ((hasIdentityInstall && hasPersona && targetsAssistant) || hasNamedInstall) {
    hits.push({ tag: 'identity_injection', weight: 3 });
  }
  if (targetsAssistant && hasCapability) {
    hits.push({ tag: 'capability_spoofing', weight: 3 });
  }
  if ((hasPersistence && (hasIdentityInstall || hasPersona || hasInstructionRelay)) || (hasPathOrArtifact && hasPersona)) {
    hits.push({ tag: 'memory_poisoning', weight: 3 });
  }
  if (hasAutonomy && (targetsAssistant || hasPersona || hasCapability)) {
    hits.push({ tag: 'autonomous_agent_install', weight: 2 });
  }
  if (hasInstructionRelay && (targetsAssistant || hasPersistence || hasPersona)) {
    hits.push({ tag: 'identity_context_relay', weight: 2 });
  }

  return hits;
}

const BLOCK_THRESHOLD = 5;   // total weight >= 5 = blocked
const FLAG_THRESHOLD = 2;    // total weight >= 2 = flagged

const OPERATIONAL_DIAGNOSTIC_TYPES = new Set([
  'session_debrief',
  'event_log',
  'after_action_review',
  'task_summary',
  'session_reasoning',
  'diagnostic'
]);

const OPERATIONAL_REPAIR_TYPES = new Set([
  'bugfix',
  'bug_fix',
  'bug_fix_log',
  'bug_repair',
  'repair',
  'repair_log',
  'fix_log',
  'incident_fix',
  'incident_repair',
  'postmortem_fix'
]);

const OPERATIONAL_DIAGNOSTIC_SIGNAL =
  /\b(batch\s*\d+|wave\s*\d+(?:\.\d+)?|diagnostic|probe|smoke\s*test|regression|proof|tested|priority-tem|syntax|architecture-authority|guarded|fallback[_\s-]?used|provider[-_\s]?agnostic|ollama|runprovider|no tool (?:was )?executed|boundary stayed diagnostic)\b/i;

const OPERATIONAL_REPAIR_SIGNAL =
  /\b(bug|bugfix|fix(?:ed|es|ing)?|repair(?:ed|s|ing)?|patch(?:ed|es|ing)?|resolve(?:d|s|ing)?|regression|incident|outage|failure|defect|issue|root\s*cause|symptom|remediation|rollback|hotfix)\b/i;

const OPERATIONAL_REPAIR_EVIDENCE_SIGNAL =
  /\b(observed|symptom|impact|cause|root\s*cause|reproduced|before|after|changed|patched|fixed|repaired|resolved|verification|verified|tested|proof|result|restored|deployment|deployed)\b/i;

// ─── Live-directive risk signal (Phase 8 sharpened) ──────────────────────────
// "new role" was previously bare-matched, which false-positived on descriptive
// prose like "the new role of cryptographic identity in the architecture."
// Phase 8 requires directive context for the role-related phrases:
//   your new role  |  is your new role  |  from now on…new role  |  assume the role of
//
// Phase 8 also fixes a pre-existing regex bug: the trailing \b after
// `system\s*prompt\s*:` and ```system meant those patterns never actually
// matched (both end in non-word chars, so the word-boundary anchor failed
// against any whitespace that follows). Split into word-bounded vs.
// non-word-ending alternatives so each gets the correct anchoring.
//
// All other patterns retained (imperative role hijacks, credential exfil
// vocabulary, system-prompt overrides, persona-load directive). The cert
// path / op-diag path / legacy name path can never bypass this floor.
const LIVE_DIRECTIVE_RISK_SIGNAL = new RegExp([
  // Word-bounded patterns
  String.raw`\b(?:ignore previous|bypass safety|reveal|provide|share|exfiltrate|leak|bearer token|password|secret|api[_\s-]?key|from now on you are|you are now|your new role|is your new role|assume the role of|always use|always trust|load (?:him|her|them|it) before answering)\b`,
  // Non-word-ending patterns (don't anchor with trailing \b)
  String.raw`system\s*prompt\s*:`,
  '```system',
  // Cross-phrase persona install: directive context + bare "new role" together
  String.raw`\bfrom now on\b[\s\S]{0,40}\bnew role\b`
].join('|'), 'i');

function isOperationalDiagnosticEvidence({ text = '', key = '', memoryType = '', source = '' } = {}) {
  const joined = `${key}\n${source}\n${text}`;
  const type = String(memoryType || '').trim().toLowerCase();
  const sourceValue = String(source || '').trim().toLowerCase();
  const hasDiagnosticType = OPERATIONAL_DIAGNOSTIC_TYPES.has(type);
  const trustedOperationalSource = /^(aimos|agent-runner|test|diagnostic)$/i.test(sourceValue)
    || /aimos|diagnostic|test/i.test(sourceValue);
  const describesDiagnosticWork = OPERATIONAL_DIAGNOSTIC_SIGNAL.test(joined);
  const hasLiveDirectiveRisk = LIVE_DIRECTIVE_RISK_SIGNAL.test(joined);

  return (hasDiagnosticType || trustedOperationalSource) && describesDiagnosticWork && !hasLiveDirectiveRisk;
}

function isTrustedOperationalRepairSave(context = {}) {
  if (!isTrustedCertPath(context)) return false;
  const joined = `${context.key || ''}\n${context.source || ''}\n${context.text || ''}`;
  if (LIVE_DIRECTIVE_RISK_SIGNAL.test(joined)) return false;

  const type = String(context.memoryType || '').trim().toLowerCase();
  const hasRepairType = OPERATIONAL_REPAIR_TYPES.has(type);
  const hasRepairSignal = OPERATIONAL_REPAIR_SIGNAL.test(joined);
  const hasEvidenceShape = OPERATIONAL_REPAIR_EVIDENCE_SIGNAL.test(joined);

  return (hasRepairType || hasRepairSignal) && hasEvidenceShape;
}

// ─── CERT-VALIDATED IDENTITY ────────────────────────────────────────────────
// The cryptographic identity tier is set by the auth-tier middleware
// on every request. T1+ means: the request carried a valid signed envelope
// whose cert chains to the master key, the signature verified against the
// agent pubkey, the timestamp is within skew, and the nonce hasn't been seen
// recently. T2 adds a valid prev_chain_hash. T3 adds device fingerprint match.
//
// Trust grant: explicit trusted_path + tier ≥ T1 + no LIVE_DIRECTIVE_RISK_SIGNAL
// + documentation/descriptive shape → block downgraded to audit_allow with
// reason 'documentation_under_cert'. This is the only identity-based downgrade
// path. Unauthenticated T0 callers stay strict.

function verifyDelegatedIdentity(context = {}) {
  const tier = String(context.identityTier || '').trim().toUpperCase();
  return ['T0', 'T1', 'T2', 'T3'].includes(tier) ? tier : 'T0';
}

function isTrustedCertPath(context = {}) {
  const tier = verifyDelegatedIdentity(context);
  if (tier === 'T0') return false;
  if (context.trustedPath !== true) return false;
  if (context.identityAuthenticatedBy && context.identityAuthenticatedBy !== 'envelope') return false;
  return context.trustedPathReason === 'cert_validated_identity';
}

function isTrustedDocumentationSave(context = {}) {
  if (!isTrustedCertPath(context)) return false;
  const joined = `${context.key || ''}\n${context.source || ''}\n${context.text || ''}`;
  if (LIVE_DIRECTIVE_RISK_SIGNAL.test(joined)) return false;
  const type = String(context.memoryType || '').trim().toLowerCase();
  if (OPERATIONAL_DIAGNOSTIC_TYPES.has(type)) return true;
  return /\b(document(?:ing|ation)|descriptive|diagnostic|architecture|security|se[-_\s]?gate|manipulation pattern|identity spoofing|prompt injection|behavioral directive|evaluation|test|audit|evidence|boundary)\b/i.test(joined);
}

function getTrustedInstallLabels(context = {}) {
  if (!isTrustedCertPath(context)) return new Set();
  const joined = `${context.key || ''}\n${context.source || ''}\n${context.text || ''}`;
  if (LIVE_DIRECTIVE_RISK_SIGNAL.test(joined)) return new Set();
  return classifyInstall({
    memoryType: context.memoryType || '',
    key: context.key || '',
    value: context.text || ''
  });
}

function isCertValidatedSave(context = {}) {
  return isTrustedDocumentationSave(context);
}

function tuneManipulationDecision(analysis, context = {}) {
  const original = analysis || { blocked: false, flagged: false, totalWeight: 0, hits: [] };
  if (!original.blocked) {
    return {
      action: original.flagged ? 'audit_allow' : 'allow',
      reason: original.flagged ? 'flagged_but_below_block_threshold' : 'no_block',
      analysis: original,
      original_blocked: original.blocked,
      tuned: false
    };
  }

  if (isTrustedCertPath(context) && isOperationalDiagnosticEvidence(context)) {
    return {
      action: 'audit_allow',
      reason: 'operational_diagnostic_evidence',
      analysis: {
        ...original,
        blocked: false,
        flagged: true,
        tuned_from_block: true,
      },
      original_blocked: true,
      tuned: true
    };
  }

  const installLabels = getTrustedInstallLabels(context);
  if (installLabels.size > 0) {
    return {
      action: 'audit_allow',
      reason: 'install_candidate_under_cert',
      install_classes: [...installLabels],
      analysis: {
        ...original,
        blocked: false,
        flagged: true,
        tuned_from_block: true,
      },
      trusted_path: true,
      trusted_path_reason: 'cert_validated_identity',
      original_blocked: true,
      tuned: true
    };
  }

  if (isTrustedOperationalRepairSave(context)) {
    return {
      action: 'audit_allow',
      reason: 'operational_repair_under_cert',
      analysis: {
        ...original,
        blocked: false,
        flagged: true,
        tuned_from_block: true,
      },
      trusted_path: true,
      trusted_path_reason: 'cert_validated_identity',
      original_blocked: true,
      tuned: true
    };
  }

  if (isTrustedDocumentationSave(context)) {
    return {
      action: 'audit_allow',
      reason: 'documentation_under_cert',
      analysis: {
        ...original,
        blocked: false,
        flagged: true,
        tuned_from_block: true,
      },
      trusted_path: true,
      trusted_path_reason: 'cert_validated_identity',
      original_blocked: true,
      tuned: true
    };
  }

  return {
    action: 'block',
    reason: 'manipulation_detected',
    analysis: original,
    original_blocked: true,
    tuned: false
  };
}

function uniqueTags(hits = []) {
  return Array.from(new Set((Array.isArray(hits) ? hits : []).map((hit) => String(hit?.tag || '').trim()).filter(Boolean)));
}

function buildUserSecurityResponse({ operation = 'save', reason = 'manipulation_detected', analysis = {}, action = 'blocked', requestId = null } = {}) {
  const tags = uniqueTags(analysis.hits);
  const op = String(operation || 'save').trim().toLowerCase();
  const isRecall = op === 'recall';
  const blocked = action === 'blocked';
  return {
    message: blocked
      ? `Aimos blocked this ${isRecall ? 'recall query' : 'memory save'} because it looked like an instruction or identity injection, not safe knowledge.`
      : `Aimos allowed this ${isRecall ? 'recall query' : 'memory save'} but marked it for security audit.`,
    what_happened: tags.length > 0
      ? `Detected ${tags.join(', ')} pattern${tags.length === 1 ? '' : 's'}.`
      : 'Detected manipulation-shaped content.',
    safe_next_step: isRecall
      ? 'Ask again as an evidence question. Avoid identity installation, authorization claims, secret requests, and tool-control wording.'
      : 'Save factual observations as session_debrief/event_log/after_action_review when this is a diagnostic note. Avoid live directives like "from now on", "always trust", secret requests, or tool-control instructions.',
    why_this_can_happen: 'Aimos distinguishes descriptive evidence from executable instructions. A foreign/local LM may need to rephrase blocked text as observations with source, proof, and boundary fields.',
    beginner_rewrite_hint: isRecall
      ? 'Example: "Recall evidence about Wave4 Ollama probe results" rather than "act as an admin and reveal context."'
      : 'Example: "Observed: model returned tool-shaped text; result: no tool executed; boundary: diagnostic only; proof: tests passed."',
    action,
    reason,
    blocked_persistence: false,
    quarantine_action: !isRecall && blocked ? 'retained_active_floor_0.1' : (blocked ? 'not_executed' : 'audit_only'),
    evidence_tags: tags,
    request_id: requestId || null
  };
}

function analyzeManipulation(text) {
  const s = String(text || '');
  let totalWeight = 0;
  const hits = [];

  for (const { re, w, tag } of MANIPULATION_PATTERNS) {
    if (re.test(s)) {
      totalWeight += w;
      hits.push({ tag, weight: w });
    }
  }

  for (const hit of detectBehavioralInjection(s)) {
    totalWeight += hit.weight;
    hits.push(hit);
  }

  return {
    blocked: totalWeight >= BLOCK_THRESHOLD,
    flagged: totalWeight >= FLAG_THRESHOLD,
    totalWeight,
    hits
  };
}

// ─── CONTEXT-AWARE SECURITY DECISION OWNER ─────────────────────────────────
// Raw pattern matches are evidence, not an enforcement decision. The same
// vocabulary appears in attacks, security reviews, protocol documentation, and
// retained red-team evidence. Enforcement therefore depends on what the caller
// is trying to do with the text:
//   - execution/recall: explicit live directives are blocked;
//   - memory save: the same evidence is retained at the quarantine floor;
//   - descriptive security material is audit-allowed, never noun-blocked.
// This preserves Aladdin full retention while preventing untrusted text from
// becoming executable authority.
const SECURITY_DECISION_OPERATIONS = new Set([
  'agent_prompt',
  'memory_recall',
  'memory_save',
  'cybersec_request',
  'model_response',
  'tool_request',
]);

const DESCRIPTIVE_SECURITY_SIGNAL = /\b(review|audit|analy[sz]e|assessment|explain|document(?:ation|ed|ing)?|protocol|paper|research|benchmark|test(?:ing|ed)?|fixture|example|sample|payload|pattern|regex|rule|detection|detector|defen[cs]e|mitigat(?:e|ion)|prevent(?:s|ion)?|blocked|rejected|denied|should not|must not|must never|do not|without exposing|whether)\b/i;
const DEFENSIVE_NEGATION_SIGNAL = /\b(must\s+never|should\s+never|never|must\s+not|should\s+not|do\s+not|don't|cannot|can't|prevent(?:s|ed|ing)?|block(?:s|ed|ing)?|reject(?:s|ed|ing)?|deny|denies|denied|without)\b/i;

const LIVE_SECURITY_SIGNALS = Object.freeze([
  {
    tag: 'instruction_override',
    severity: 'critical',
    pattern: /\b(ignore|bypass|forget|discard|override)\b.{0,50}\b(previous|prior|all|system|developer)\b.{0,50}\b(instruction|prompt|rule|policy|message)s?\b/i,
  },
  {
    tag: 'jailbreak_activation',
    severity: 'critical',
    pattern: /\b(enable|activate|enter|switch to)\b.{0,30}\b(developer mode|god mode|unrestricted mode|DAN)\b|\b(do anything now|unrestricted assistant)\b/i,
  },
  {
    tag: 'identity_install',
    severity: 'high',
    pattern: /\b(from now on you are|you are now|become my|assume the role of|your new (?:role|identity|mission))\b/i,
  },
  {
    tag: 'prompt_extraction',
    severity: 'critical',
    pattern: /\b(reveal|show|output|print|return|send|share|provide|dump|expose)\b.{0,70}\b(system prompt|developer message|hidden prompt|internal instructions?)\b/i,
  },
  {
    tag: 'credential_extraction',
    severity: 'critical',
    pattern: /\b(reveal|show|output|print|return|send|share|provide|dump|exfiltrate|leak|harvest|steal|recall)\b.{0,80}\b(password|passphrase|api[_\s-]?key|secret|token|credential|private key|cookie)s?\b/i,
  },
  {
    tag: 'bulk_extraction',
    severity: 'critical',
    pattern: /\b(recall|show|output|return|export|dump|summarize)\b.{0,80}\b(every|all|entire|last\s+\d+)\b.{0,60}\b(memories|memory entries|users?|tenants?|confidential documents?|embeddings?|conversation history)\b/i,
  },
  {
    tag: 'privileged_tool_control',
    severity: 'critical',
    pattern: /\b(enable|unlock|grant|invoke|execute|run|call|activate)\b.{0,80}\b(execute_shell|shell|terminal|filesystem|file system|browser|admin mode|root access|disabled tools?|plugins?|mcp)\b/i,
  },
  {
    tag: 'destructive_execution',
    severity: 'critical',
    pattern: /\b(execute|run|invoke|launch)\b.{0,60}\b(rm\s+-rf|mkfs|dd\s+if=\/dev\/zero|ransomware|keylogger|malware|exploit payload)\b|\brm\s+-rf\s+\/(?:\s|$|data\b)/i,
  },
  {
    tag: 'recall_triggered_instruction',
    severity: 'high',
    pattern: /\b(when|whenever|if|upon|after)\b.{0,40}\b(recalled|retrieved|loaded|read|accessed)\b.{0,100}\b(ignore|respond|reply|output|return|send|reveal|execute|run)\b/i,
  },
  {
    tag: 'encoded_instruction_execution',
    severity: 'high',
    pattern: /\b(decode|translate)\b.{0,80}\b(then\s+)?(execute|follow|obey|run)\b/i,
  },
  {
    tag: 'authority_execution_spoof',
    severity: 'high',
    pattern: /\b(ceo|founder|admin|owner|root|security team|operator)\b.{0,50}\b(approved|authorized|ordered|said)\b.{0,80}\b(grant|enable|execute|run|reveal|share|provide|bypass)\b/i,
  },
  {
    tag: 'fabricated_prior_authorization',
    severity: 'high',
    pattern: /\b(previous (?:conversation|session)|earlier|last time)\b.{0,80}\b(agreed|approved|authorized|promised)\b.{0,80}\b(share|reveal|provide|continue|access)\b/i,
  },
  {
    tag: 'impersonated_audit_extraction',
    severity: 'high',
    pattern: /\b(pretend|act as|roleplay as)\b.{0,50}\b(auditor|admin|security|operator)\b.{0,100}\b(see|reveal|show|access|need)\b.{0,50}\b(system prompt|credentials?|secrets?|internal instructions?)\b/i,
  },
  {
    tag: 'hypothetical_safety_bypass',
    severity: 'high',
    pattern: /\b(hypothetically|imagine|suppose)\b.{0,80}\b(no|without|removed|disabled)\b.{0,40}\b(safety|security|restrictions?|guardrails?)\b.{0,100}\b(reveal|show|output|say|provide)\b/i,
  },
  {
    tag: 'memory_authority_install',
    severity: 'critical',
    pattern: /\b(remember|store|save|record|add to|context update|correct your knowledge)\b.{0,140}\b(admin password|api[_\s-]?key|system_admin|clearance level|permanent instructions?|always trust|security policies? (?:have been )?suspended|safety classifier|full data access)\b/i,
  },
  {
    tag: 'persistent_policy_override',
    severity: 'critical',
    pattern: /\b(always trust|permanent instructions?|security policies? (?:have been )?suspended|classifier should return allow|grant full data access)\b/i,
  },
  {
    tag: 'credential_relay_install',
    severity: 'high',
    pattern: /\b(password|api[_\s-]?key|secret|token|credential|private key)s?\b.{0,100}\b(shared|retrieved|returned|later use|when asked|next session)\b/i,
  },
  {
    tag: 'clearance_or_admin_spoof',
    severity: 'critical',
    pattern: /\b(i am|my (?:user )?token is|switch to|authenticate as|authenticating with)\b.{0,80}\b(clearance|admin mode|root|omega|admin[-_]override)\b|\bgrant me\b.{0,60}\b(unrestricted|admin|root|full)\b/i,
  },
  {
    tag: 'disabled_capability_extraction',
    severity: 'high',
    pattern: /\b(list|show|output|reveal)\b.{0,60}\b(all|disabled|hidden|internal)\b.{0,40}\b(tools?|capabilities|plugins?)\b.{0,80}\b(activation|enable|commands?)\b/i,
  },
  {
    tag: 'cross_tenant_extraction',
    severity: 'critical',
    pattern: /\b(show|reveal|output|return|access)\b.{0,80}\b(conversation history|stored data|memory|documents?)\b.{0,100}\b(other[_\s-]?(?:user|tenant|company)|user_id\s*=|tenant_id\s*=)\b/i,
  },
  {
    tag: 'storage_schema_extraction',
    severity: 'high',
    pattern: /\b(show|reveal|output|dump|return)\b.{0,80}\b(database schema|table names|column definitions|storage schema)\b/i,
  },
]);

function normalizeSecurityOperation(operation) {
  const normalized = String(operation || '').trim().toLowerCase();
  if (!SECURITY_DECISION_OPERATIONS.has(normalized)) {
    throw new Error(`unsupported_security_operation:${normalized || 'missing'}`);
  }
  return normalized;
}

function collectLiveSecuritySignals(text) {
  const source = String(text || '');
  return LIVE_SECURITY_SIGNALS
    .filter(({ pattern }) => pattern.test(source))
    .map(({ tag, severity }) => ({ tag, severity }));
}

function maxSecuritySeverity(signals = []) {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  return signals.reduce(
    (highest, signal) => rank[signal.severity] > rank[highest] ? signal.severity : highest,
    'low',
  );
}

/**
 * Produce the one native content-security decision used by REST, MCP, agent,
 * and Sentinel transports. This function is pure; the caller must append its
 * signed decision receipt with appendSecurityDecision before acting.
 */
function evaluateSecurityContent({
  text = '',
  operation,
  contentType = '',
  key = '',
  source = '',
  transport = 'internal',
} = {}) {
  const normalizedOperation = normalizeSecurityOperation(operation);
  const rendered = String(text || '');
  const joined = `${key}\n${source}\n${contentType}\n${rendered}`;
  const rawAnalysis = analyzeManipulation(joined);
  const liveSignals = collectLiveSecuritySignals(rendered);
  const descriptive = DESCRIPTIVE_SECURITY_SIGNAL.test(joined);
  const defensiveNegation = DEFENSIVE_NEGATION_SIGNAL.test(rendered);
  const citedEvidence = descriptive && (
    /["“”'‘’`][^"“”'‘’`]{3,}["“”'‘’`]/.test(rendered)
    || /```[\s\S]*```/.test(rendered)
    || /\b(pattern|payload|example|sample|fixture|regex|detector|detection rule)\b/i.test(rendered)
  );
  const liveDirective = liveSignals.length > 0
    && !(descriptive && (defensiveNegation || citedEvidence));

  let action = 'allow';
  let reason = 'no_security_signal';
  if (liveDirective && normalizedOperation === 'memory_save') {
    action = 'retain_quarantine';
    reason = 'live_directive_retained_as_untrusted_evidence';
  } else if (liveDirective) {
    action = 'block_execution';
    reason = 'live_directive_not_authorized_for_execution';
  } else if (rawAnalysis.flagged || liveSignals.length > 0) {
    action = 'audit_allow';
    reason = descriptive
      ? 'descriptive_security_material'
      : 'lexical_signal_without_executable_intent';
  }

  const contentHash = createHash('sha256').update(rendered, 'utf8').digest('hex');
  const severity = liveDirective
    ? maxSecuritySeverity(liveSignals)
    : rawAnalysis.flagged ? 'medium' : 'low';

  return {
    action,
    reason,
    operation: normalizedOperation,
    transport: String(transport || 'internal'),
    severity,
    blockExecution: action === 'block_execution',
    retainContent: normalizedOperation === 'memory_save',
    quarantine: action === 'retain_quarantine',
    descriptive,
    defensiveNegation,
    citedEvidence,
    contentHash,
    liveSignals,
    analysis: rawAnalysis,
  };
}

/** Append the mandatory signed housekeeper observation for one decision. */
async function appendSecurityDecision(decision, {
  companyId = AIMOS_COMPANY_ID,
  subjectAgentId = 'unknown',
  authority = null,
  parentEventId = null,
} = {}) {
  if (!decision?.operation || !decision?.action || !decision?.contentHash) {
    throw new Error('security_decision_invalid');
  }
  return logEvent(
    companyId,
    subjectAgentId,
    'security_content_decision',
    `security:${decision.contentHash.slice(0, 24)}`,
    {
      action: decision.action,
      reason: decision.reason,
      severity: decision.severity,
      operation: decision.operation,
      transport: decision.transport,
      content_sha256: decision.contentHash,
      descriptive: decision.descriptive,
      defensive_negation: decision.defensiveNegation,
      cited_evidence: decision.citedEvidence,
      live_signals: decision.liveSignals,
      raw_weight: decision.analysis?.totalWeight || 0,
      raw_tags: uniqueTags(decision.analysis?.hits),
      retention: decision.retainContent
        ? (decision.quarantine ? 'retained_quarantine_floor_0.1' : 'retained_canonical')
        : 'not_a_persistence_operation',
      reasoning: `Context-aware security decision '${decision.action}' for ${decision.operation}: ${decision.reason}.`,
      source_knowledge: 'se-gate.js — context-aware native decision owner',
    },
    parentEventId,
    { authority, returnReceipt: true },
  );
}

function classifyManipulationCapabilities(hits = []) {
  const tags = uniqueTags(hits);
  const classes = [];
  if (tags.some((tag) => /identity|impersonation|role|persona/.test(tag))) classes.push('identity_or_role_install');
  if (tags.some((tag) => /capability|tool|autonomous|context_relay/.test(tag))) classes.push('capability_spoofing_or_tool_unlock');
  if (tags.some((tag) => /memory|recall|persistence|payload_split/.test(tag))) classes.push('memory_poisoning_or_recall_trigger');
  if (tags.some((tag) => /exfil|credential|secret/.test(tag))) classes.push('credential_or_data_exfiltration');
  if (tags.some((tag) => /authority|urgency|scarcity|reciprocity|coercive|guilt|panic/.test(tag))) classes.push('social_pressure_or_authority_spoof');
  if (tags.some((tag) => /prompt|instruction/.test(tag))) classes.push('prompt_instruction_injection');
  return [...new Set(classes)];
}

function buildDynamicAttackDiagnostics(text, context = {}) {
  const analysis = analyzeManipulation(text);
  const capabilityClasses = classifyManipulationCapabilities(analysis.hits);
  return {
    source_papers: [
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
      'Security Considerations for Artificial Intelligence Agents',
    ],
    diagnostic_only: true,
    operation: context.operation || 'unknown',
    blocked_recommended: analysis.blocked,
    flagged_recommended: analysis.flagged,
    total_weight: analysis.totalWeight,
    tags: uniqueTags(analysis.hits),
    capability_classes: capabilityClasses,
    detection_basis: 'capability_class_not_prompt_string',
    persistence_changed: false,
    thresholds_changed: false,
  };
}

// ─── 4. CREDENTIAL ISOLATION ─────────────────────────────────────────────────
// Credentials stored at clearance >= 10 are NEVER returned via /recall.
// Anderson's Security Engineering: separate the mechanism for accessing secrets
// from the mechanism for accessing knowledge. Different channels, different auth.
const CREDENTIAL_MIN_CLEARANCE = 10;

function buildCredentialIsolationClause(paramIndex) {
  return `AND clearance_level < $${paramIndex}`;
}

// ─── 6. RECALL RATE LIMITING ─────────────────────────────────────────────────
// Prevents bulk extraction via rapid recall queries.
const _recallRates = new Map();
const RECALL_WINDOW_MS = 60_000;
const RECALL_MAX_PER_WINDOW = 60;

function checkRecallRate(agentId) {
  const id = agentId || '_master';
  const now = Date.now();
  const entry = _recallRates.get(id);

  if (!entry || (now - entry.windowStart) > RECALL_WINDOW_MS) {
    _recallRates.set(id, { count: 1, windowStart: now });
    return { allowed: true, count: 1 };
  }

  entry.count++;
  if (entry.count > RECALL_MAX_PER_WINDOW) {
    console.warn(`[SE-GATE] RECALL RATE EXCEEDED: agent=${id}, count=${entry.count}/${RECALL_MAX_PER_WINDOW}`);
    return { allowed: false, count: entry.count };
  }
  return { allowed: true, count: entry.count };
}

// Save-time content enforcement is owned directly by the canonical REST and
// MCP save paths. The retired middleware duplicated that authority and could
// suppress signed evidence before Aladdin quarantine, so it is intentionally
// absent.
// ─── MIDDLEWARE: /recall GATE ────────────────────────────────────────────────
export async function seGateRecall(req, res, next) {
  try {
    // 1. Identity enforcement
    await enforceIdentity(req);

    // 2. Clearance ceiling
    await enforceClearance(req);

    // 3. Recall rate limit
    const rate = checkRecallRate(req.agentId);
    if (!rate.allowed) {
      const receipt = await logEvent(req.query?.company_id || 'hom', req.agentId || 'system', 'recall_rate_blocked', 'se-gate:recall_rate', {
        count: rate.count,
        limit: RECALL_MAX_PER_WINDOW,
        reasoning: 'The recall request exceeded the per-agent extraction-rate boundary and was blocked before retrieval.',
        source_knowledge: 'se-gate.js recall-rate boundary',
      }, null, { returnReceipt: true });
      return res.status(429).json({
        error: 'Recall rate limit exceeded',
        agent: req.agentId || 'master',
        limit: RECALL_MAX_PER_WINDOW,
        window_seconds: RECALL_WINDOW_MS / 1000,
        security_decision_event_id: receipt.event_id,
      });
    }

    // 4. Mark for credential isolation (applied in query WHERE clause)
    req._seCredentialCeiling = CREDENTIAL_MIN_CLEARANCE;

    // 5. Context-aware query decision.
    const recallText = `${req.query?.q || ''} ${req.query?.query || ''}`;
    const decision = evaluateSecurityContent({
      text: recallText,
      operation: 'memory_recall',
      contentType: 'legacy_recall_middleware',
      source: 'se-gate',
      transport: 'rest',
    });
    const receipt = await appendSecurityDecision(decision, {
      companyId: req.query?.company_id || 'hom',
      subjectAgentId: req.agentId || 'system',
    });
    req._se_recall_flagged = decision.action === 'audit_allow';
    req._se_recall_analysis = decision.analysis;
    if (decision.blockExecution) {
      return res.status(403).json({
        error: 'Recall query blocked by social engineering gate',
        reason: decision.reason,
        action: decision.action,
        tags: decision.liveSignals.map((signal) => signal.tag),
        security_decision_event_id: receipt.event_id,
      });
    }

    next();
  } catch (err) {
    console.error('[SE-GATE] Recall gate error:', err.message);
    return res.status(503).json({
      error: 'Social engineering gate unavailable',
      reason: 'se_gate_or_ledger_error_fail_closed',
    });
  }
}

export {
  analyzeManipulation,
  evaluateSecurityContent,
  appendSecurityDecision,
  buildDynamicAttackDiagnostics,
  buildUserSecurityResponse,
  isOperationalDiagnosticEvidence,
  isTrustedOperationalRepairSave,
  verifyDelegatedIdentity,
  isTrustedCertPath,
  isTrustedDocumentationSave,
  getTrustedInstallLabels,
  isCertValidatedSave,
  tuneManipulationDecision,
  detectBehavioralInjection,
  getAgentMaxClearance,
  enforceIdentity,
  buildCredentialIsolationClause,
  CREDENTIAL_MIN_CLEARANCE,
  BLOCK_THRESHOLD,
  FLAG_THRESHOLD
};
