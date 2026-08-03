import { systemConfigStore } from '../security/system-config-store.js';

/**
 * brain-contract.js — Social Laws and System Integrity Contract
 * Source: Wooldridge (Multi-Agent Systems)
 * Additive TEM authority: Persistent Identity in AI Agents: A Multi-Anchor
 * Architecture for Resilient Memory and Continuity
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (post-run step 24)
 * 2. → Pulls from: directives.json (Law 1-3 definitions)
 * 3. → Pushes to: security.security_audit_log (Strategic routing violations)
 * 4. ↔ Interacts with: services/security/knowledge-gate.js (Autonomy thresholds)
 *
 * LOGIC GUIDE: Enforces Law of Strategic Routing, Law of Escalation, and Law of Formal Handoffs.
 * Prevents "Shadow Routing" and ensures high-impact actions are escalated to the operator-designated agent.
 * Persistent Identity alignment: operating-contract memories become distinct
 * boot anchors. Behavioral KL drift and identity hash checks remain guarded.
 * Additive Batch9 Wave5 authority: Rhizome OS-1, Ontology-Aware Design
 * Patterns, and HGP-Mamba. Aimos exposes a provider-agnostic representation
 * bridge contract only; unsupported image/video/audio production claims remain
 * blocked until native backend paths and tests exist.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (post-run step 24)
// → Calls: (pure contract validation — no downstream service call)
// Pipeline: AGENT_RUN_PIPELINE
// Position: social law check
// ─────────────────────────────────────────────────────────────────────────────

const AIMOS_OPERATOR_BRAIN_AGENT_ID = String(systemConfigStore.readConfigString('AIMOS_OPERATOR_BRAIN_AGENT_ID') || '').trim();
const AIMOS_OPERATOR_BRAIN_IDENTITY = String(systemConfigStore.readConfigString('AIMOS_OPERATOR_BRAIN_IDENTITY') || 'reviewer').trim();
const AIMOS_OPERATOR_BRAIN_RUNTIME = String(systemConfigStore.readConfigString('AIMOS_OPERATOR_BRAIN_RUNTIME') || 'aimos_operator_runtime').trim();
const WAVE5_REPRESENTATION_BRIDGE_AUTHORITIES = [
  'Rhizome OS-1: Rhizome Semi-Autonomous Operating System for Small Molecule Drug Discovery',
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'HGP-Mamba: Integrating Histology and Generated Protein Features for Mamba-based Multimodal Survival Risk Prediction',
];

const STRATEGIC_BRAIN_PATTERNS = [
  /\barchitecture\b/i,
  /\boperating system\b/i,
  /\bagent os\b/i,
  /\bautonomous system\b/i,
  /\bcontextual reasoning\b/i,
  /\bthird wave\b/i,
  /\bdarpa\b/i,
  /\baladdin\b/i,
  /\bwooldridge\b/i,
  /\bbdi\b/i,
  /\bcontract net\b/i,
  /\bcnp\b/i,
  /\bsocial law/i,
  /\bfipa\b/i,
  /\bacl\b/i,
  /\btrust(?:worthiness)?\b/i,
  /\bassurance\b/i,
  /\bpredictab/i,
  /\bmulti-agent\b/i,
  /\bself-repair\b/i,
  /\bnightly dream\b/i
];

const HIGH_IMPACT_INTENTS = new Set([
  'deploy',
  'trade',
  'delete',
  'infra',
  'security',
  'architecture',
  'governance'
]);

const SOCIAL_LAWS = [
  {
    id: 'law_strategic_prompts_route_to_aimos_operator_brain',
    statement: 'Strategic architecture and governance prompts must be linked to the Aimos operator brain runtime.',
    enforcement: 'routing'
  },
  {
    id: 'law_high_impact_low_confidence_escalates',
    statement: 'Low-confidence high-impact actions must escalate to human review.',
    enforcement: 'runtime'
  },
  {
    id: 'law_formal_messages_for_handoffs',
    statement: 'Inter-agent handoffs must use structured performatives (ACL) rather than implicit context.',
    enforcement: 'coordination'
  }
];

export function requiresAimosOperatorBrain(prompt = '', intent = '') {
  const text = `${String(intent || '')}\n${String(prompt || '')}`;
  return STRATEGIC_BRAIN_PATTERNS.some((pattern) => pattern.test(text));
}

export function enforceAimosOperatorBrainLink({
  sourceAgentId,
  resolvedAgentId,
  prompt = '',
  intent = '',
  allowDelegation = true
} = {}) {
  const strategic = requiresAimosOperatorBrain(prompt, intent);
  const hasExplicitBrainAgent = AIMOS_OPERATOR_BRAIN_AGENT_ID.length > 0;
  const alreadyLinked =
    hasExplicitBrainAgent &&
    (String(sourceAgentId || '') === AIMOS_OPERATOR_BRAIN_AGENT_ID ||
      String(resolvedAgentId || '') === AIMOS_OPERATOR_BRAIN_AGENT_ID);

  if (!strategic) {
    return {
      strategic: false,
      forced: false,
      targetAgentId: String(resolvedAgentId || sourceAgentId || ''),
      reason: null
    };
  }

  if (!hasExplicitBrainAgent || alreadyLinked || !allowDelegation) {
    return {
      strategic: true,
      forced: false,
      targetAgentId: String(resolvedAgentId || sourceAgentId || ''),
      reason: !hasExplicitBrainAgent ? 'channel_link_only' : (!allowDelegation ? 'delegation_disabled' : null)
    };
  }

  return {
    strategic: true,
    forced: true,
    targetAgentId: AIMOS_OPERATOR_BRAIN_AGENT_ID,
    reason: 'strategic_reasoning_requires_aimos_operator_brain'
  };
}

export function evaluateSocialLawViolations({
  sourceAgentId,
  runtimeAgentId,
  prompt = '',
  intent = '',
  confidence = 1
} = {}) {
  const violations = [];
  const intentKey = String(intent || '').toLowerCase().trim();
  const strategic = requiresAimosOperatorBrain(prompt, intent);
  const lowConfidence = Number(confidence) < 0.6;
  const highImpact = HIGH_IMPACT_INTENTS.has(intentKey);

  if (strategic && String(runtimeAgentId || '') !== AIMOS_OPERATOR_BRAIN_AGENT_ID) {
    if (AIMOS_OPERATOR_BRAIN_AGENT_ID) {
      violations.push({
        lawId: 'law_strategic_prompts_route_to_aimos_operator_brain',
        detail: `Runtime agent '${runtimeAgentId}' handled a strategic prompt outside Aimos operator brain '${AIMOS_OPERATOR_BRAIN_AGENT_ID}'.`
      });
    } else {
      violations.push({
        lawId: 'law_strategic_prompts_route_to_aimos_operator_brain',
        detail: `Strategic prompt was handled without explicit Aimos operator runtime confirmation (identity: ${AIMOS_OPERATOR_BRAIN_IDENTITY}).`
      });
    }
  }

  if (lowConfidence && highImpact) {
    violations.push({
      lawId: 'law_high_impact_low_confidence_escalates',
      detail: `Intent '${intentKey}' ran at confidence ${Number(confidence).toFixed(2)} (< 0.60).`
    });
  }

  if (
    (strategic || highImpact) &&
    String(sourceAgentId || '') &&
    String(runtimeAgentId || '') &&
    String(sourceAgentId) !== String(runtimeAgentId)
  ) {
    // Delegation happened. Coordination should remain explicit.
    violations.push({
      lawId: 'law_formal_messages_for_handoffs',
      detail: 'Delegated runs should emit ACL messages for explicit handoff traceability.'
    });
  }

  return {
    mustEscalate: violations.some((v) => v.lawId === 'law_high_impact_low_confidence_escalates'),
    violations
  };
}

export function buildBrainOperatingMemories() {
  return [
    {
      key: 'os:hom:aimos_operator_brain_contract',
      value: `HOM is an autonomous agent operating system. Strategic architecture and governance reasoning is linked to the Aimos operator runtime (identity: ${AIMOS_OPERATOR_BRAIN_IDENTITY}). Identity labels do not equal execution ownership.`,
      clearanceLevel: 8,
      memoryType: 'infrastructure'
    },
    {
      key: 'os:hom:third_wave_capabilities',
      value: 'Third-Wave capabilities in HOM: contextual reasoning over retrieval, explainable decisions, collaborative human-AI operation, trustworthiness controls (robustness, assurance, predictability), and continual adaptation.',
      clearanceLevel: 7,
      memoryType: 'infrastructure'
    },
    {
      key: 'os:hom:coordination_stack',
      value: 'Formal multi-agent coordination stack: BDI state (beliefs/desires/intentions), ACL performatives (ASSERT, QUERY, REQUEST, INFORM, PROPOSE, CONFIRM, REJECT), Contract-Net auction fallback, and social-law enforcement.',
      clearanceLevel: 7,
      memoryType: 'infrastructure'
    },
    {
      key: 'os:hom:self_repair_loop',
      value: 'Nightly dream provides retained self-repair evidence: consolidate patterns, calibrate confidence, and preserve lifelong learning without deleting or suppressing canonical memory.',
      clearanceLevel: 7,
      memoryType: 'infrastructure'
    }
  ];
}

export function getHomBrainOperatingProfile(companyId = 'hom') {
  return {
    companyId,
    mode: 'autonomous-agent-operating-system',
    aimosOperatorBrain: {
      agentId: AIMOS_OPERATOR_BRAIN_AGENT_ID || null,
      identity: AIMOS_OPERATOR_BRAIN_IDENTITY,
      runtime: AIMOS_OPERATOR_BRAIN_RUNTIME,
      role: 'primary_strategic_reasoning_brain'
    },
    capabilities: [
      'contextual_reasoning',
      'formal_multi_agent_coordination',
      'lifelong_learning',
      'trustworthy_execution',
      'self_repair'
    ],
    coordination: {
      protocols: ['BDI', 'FIPA_ACL', 'Contract_Net'],
      socialLaws: SOCIAL_LAWS
    },
    assurances: {
      trustGates: true,
      autonomyThresholds: true,
      escalationOnLowConfidence: true
    }
  };
}

export function buildRepresentationBridgeContract({
  requestedModalities = [],
  backendPathExists = false,
  testsExist = false,
} = {}) {
  const modalities = Array.isArray(requestedModalities)
    ? requestedModalities.map((modality) => String(modality).toLowerCase()).filter(Boolean)
    : [];
  return {
    contract_type: 'aimos_representation_bridge',
    source_papers: WAVE5_REPRESENTATION_BRIDGE_AUTHORITIES,
    status: 'diagnostic_contract',
    provider_agnostic: true,
    diagnostic_only: true,
    requested_modalities: modalities,
    active_capabilities: {
      text: true,
      image: false,
      video: false,
      audio: false,
      multimodal_fusion: false,
    },
    production_claim_allowed: false,
    activation_requirements: {
      native_backend_path: Boolean(backendPathExists),
      targeted_tests: Boolean(testsExist),
      explicit_operator_approval: false,
    },
    guardrails: {
      fake_ui_allowed: false,
      fake_tool_allowed: false,
      raw_media_payload_exposed: false,
      hidden_tool_execution: false,
      canonical_memory_changed: false,
    },
  };
}

export { AIMOS_OPERATOR_BRAIN_AGENT_ID, AIMOS_OPERATOR_BRAIN_IDENTITY, AIMOS_OPERATOR_BRAIN_RUNTIME, SOCIAL_LAWS };
