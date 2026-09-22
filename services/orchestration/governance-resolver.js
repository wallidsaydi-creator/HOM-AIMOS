/**
 * governance-resolver.js — Multi-Agent Coordination and Routing
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
import { query } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { agents } from './agent-store.js';
import { getAgentCert, pubkeyFingerprint } from '../security/agent-identity.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { getPermissions } from '../core/permissions.js';
import { getEmbedding } from '../core/embeddings.js';
import { getProviderRegistry } from '../core/providers.js';
import { createHash } from 'crypto';
import { normalizeOperatorAgentId } from '../security/system-config-store.js';
import { enforceAimosOperatorBrainLink } from '../core/brain-contract.js';
import { designTaskGraph } from './graph-designer.js';
import { resolveFallback, isOrchestrationExhausted, getExhaustionReason } from './fallback-resolver.js';
import { createRoutingCounter, incrementRouting, shouldTriggerFallback } from '../observe/routing-monitor.js';
import { routeTask as trustRouteTask } from './trust-router.js';
import { estimateStateUpdateDepth, observeCapabilityGate } from './capability-probe.js';
import { confidenceWeightedVote, triggerDebate } from './decentralized-consensus.js';
import { runInvestigationLoop } from './explore-exploit-loop.js';
import { observeHVRDiagnostic } from './hypothesis-verifier.js';
import { logAIDecision } from '../observe/architecture-registry.js';
import { generateExplanation } from '../observe/explainer.js';
import { getModelPreference, getModelPreferences } from './model-preferences.js';

const COMPANY = AIMOS_COMPANY_ID;
const SEMANTIC_ROUTING_MIN_PROMPT_CHARS = 24;
const SEMANTIC_ROUTING_MAX_DISTANCE = 0.42;

const ROLE_SLOT_KEYWORDS = {
  security: ['security', 'vulnerability', 'threat', 'auth', 'exploit', 'hardening'],
  legal: ['legal', 'contract', 'terms', 'policy', 'compliance', 'gdpr'],
  finance: ['finance', 'pricing', 'revenue', 'cost', 'budget', 'invoice', 'cashflow'],
  growth: ['growth', 'retention', 'activation', 'funnel', 'acquisition', 'conversion'],
  marketing: ['marketing', 'campaign', 'positioning', 'brand', 'launch', 'content'],
  research: ['research', 'analyze', 'investigate', 'brief', 'market', 'competitive'],
  backend: ['backend', 'api', 'server', 'endpoint', 'microservice'],
  frontend: ['frontend', 'ui', 'ux', 'design', 'css', 'layout'],
  mobile: ['mobile', 'ios', 'android', 'swift', 'react native'],
  devops: ['devops', 'deploy', 'infra', 'kubernetes', 'ci', 'cd'],
  database: ['database', 'sql', 'postgres', 'query', 'migration', 'schema'],
  quality: ['test', 'qa', 'checker', 'verification', 'validation']
};

function inferRoleSlotFromAgentId(agentId = '') {
  const id = String(agentId || '').trim().toLowerCase();
  if (!id) return 'general';
  if (id.includes('security')) return 'security';
  if (id.includes('legal')) return 'legal';
  if (id.includes('finance')) return 'finance';
  if (id.includes('growth')) return 'growth';
  if (id.includes('market') || id.includes('research')) return 'research';
  if (id.includes('marketing') || id.includes('seo')) return 'marketing';
  if (id.includes('frontend') || id.includes('design')) return 'frontend';
  if (id.includes('mobile') || id.includes('ios') || id.includes('android')) return 'mobile';
  if (id.includes('backend') || id.includes('api')) return 'backend';
  if (id.includes('devops') || id.includes('infra')) return 'devops';
  if (id.includes('database') || id.includes('db')) return 'database';
  if (id.includes('checker') || id.includes('qa')) return 'quality';
  return 'general';
}

function inferRoleSlotFromPrompt(prompt = '', intent = '') {
  const text = `${String(prompt || '')} ${String(intent || '')}`.toLowerCase();
  if (!text.trim()) return 'general';
  let bestSlot = 'general';
  let bestScore = 0;
  for (const [slot, keywords] of Object.entries(ROLE_SLOT_KEYWORDS)) {
    const score = keywords.reduce((acc, keyword) => {
      return acc + (text.includes(keyword) ? 1 : 0);
    }, 0);
    if (score > bestScore) {
      bestSlot = slot;
      bestScore = score;
    }
  }
  return bestSlot;
}

function resolveProfileRoleSlot(profile = {}) {
  const slot = String(profile?.role_slot || '').trim().toLowerCase();
  if (slot && slot !== 'general') return slot;
  return inferRoleSlotFromAgentId(profile?.agent_id || '');
}

function resolveTadResistanceScore(profile = {}) {
  const score = Number(profile?.tad_resistance_score);
  if (!Number.isFinite(score)) return 0.5;
  return Math.min(Math.max(score, 0), 1);
}

function buildAuthorizationChainHash(trajectory = []) {
  try {
    return createHash('sha256')
      .update(JSON.stringify(Array.isArray(trajectory) ? trajectory : []))
      .digest('hex');
  } catch {
    return null;
  }
}

const EXEC_MANDATORY_DELEGATION_RULES = [
  {
    target: 'email-manager',
    patterns: [
      /\b(last|latest|recent|exact|subject|inbox|unread)\b.*\b(email|gmail)\b/i,
      /\b(email|gmail)\b.*\b(last|latest|recent|exact|subject|inbox|unread)\b/i
    ]
  },
  {
    target: 'calendar-mgr',
    patterns: [
      /\b(calendar|event|events|meeting|meetings|schedule)\b.*\b(today|tomorrow|week|date|time|availability|plan)\b/i,
      /\b(today|tomorrow|week|date|time|availability|plan)\b.*\b(calendar|event|events|meeting|meetings|schedule)\b/i
    ]
  }
];

let readyPromise = null;

function vectorLiteral(embedding) {
  if (!Array.isArray(embedding) || !embedding.length) return null;
  return `[${embedding.join(',')}]`;
}

function canonicalModelId(value) {
  let model = String(value || '').trim().toLowerCase();
  if (!model) return '';
  // Strip any known provider prefix dynamically from registry.
  const providers = Object.keys(getProviderRegistry());
  for (const p of providers) {
    const re = new RegExp(`^${p}[:/]`);
    model = model.replace(re, '');
  }
  return model;
}

function modelsEquivalent(a, b) {
  const left = canonicalModelId(a);
  const right = canonicalModelId(b);
  return left.length > 0 && left === right;
}

function findRequestedModelCandidate(candidates, requestedModel) {
  const requestedCanonical = canonicalModelId(requestedModel);
  if (!requestedCanonical) return null;
  return candidates.find((candidate) => canonicalModelId(candidate) === requestedCanonical) || null;
}

export async function ensureGovernanceSchema() {
  const requiredRelations = [
    'agent_profiles',
    'agent_routing_policy',
    'session_lanes',
    'directive_claims',
    'agent_runs',
    'run_idempotency',
    'procedural_skills',
  ];
  const result = await query(
    `SELECT name
       FROM unnest($1::text[]) AS required(name)
      WHERE to_regclass(current_schema() || '.' || name) IS NULL
      ORDER BY name`,
    [requiredRelations]
  );
  if (result.rows.length) {
    throw new Error(`governance_schema_missing:${result.rows.map((row) => row.name).join(',')}`);
  }
}

export async function hydrateAgentStoreFromGovernance(companyId = COMPANY) {
  if (companyId !== COMPANY) throw new Error('governance_company_mismatch');
  // Enrollment is authoritative. Profiles are optional presentation/routing
  // data, not a second identity registry or an enrollment prerequisite.
  const identities = await query(
    `SELECT DISTINCT identity.agent_id FROM agent_identity identity
      WHERE identity.valid_from <= NOW() AND identity.valid_until > NOW()
        AND NOT EXISTS (SELECT 1 FROM aimos_agent_revocation_events revocation
          WHERE revocation.agent_id = identity.agent_id
            AND revocation.agent_valid_from = identity.valid_from)
      ORDER BY identity.agent_id`
  );
  const selected = getModelPreference('chat');
  const selectedModel = selected.authority === 'signed_task_preference'
    ? `${selected.provider}:${selected.model}` : null;
  const hydrated = [];
  for (const identity of identities.rows) {
    const row = await getProfile(companyId, identity.agent_id);
    if (!row) continue;
    const previous = agents.get(row.agent_id);
    const agent = {
      id: row.agent_id, name: row.name, tier: row.tier, model: selectedModel,
      tools: [row.tool_profile], toolDeltas: row.tool_deltas,
      persona: row.persona, personaVersion: row.persona_version,
      clearanceLevel: row.clearance_level, enrollment: row.enrollment,
      modelSelectionState: selectedModel ? 'selected' : 'unconfigured',
      isActive: previous?.isActive === true, lastSeen: previous?.lastSeen || null,
    };
    hydrated.push(agent);
  }
  // Replace only this ephemeral projection after every identity/grant verifies.
  // This does not remove a profile, enrollment, event or retained memory.
  agents.clear();
  for (const agent of hydrated) agents.set(agent.id, agent);
  return hydrated;
}

export async function getAgentModelCandidates(companyId, agentId) {
  if (String(companyId || '') !== COMPANY || !String(agentId || '').trim()) return [];
  return [...new Set(Object.values(getModelPreferences())
    .filter((preference) => preference.authority === 'signed_task_preference' && preference.model)
    .map((preference) => `${preference.provider}:${preference.model}`))];
}

async function getProfile(companyId, agentId) {
  if (companyId !== COMPANY) throw new Error('governance_company_mismatch');
  const active = await query(
    `SELECT valid_from FROM agent_identity identity WHERE agent_id = $1
      AND valid_from <= NOW() AND valid_until > NOW()
      AND NOT EXISTS (SELECT 1 FROM aimos_agent_revocation_events revocation
        WHERE revocation.agent_id = identity.agent_id AND revocation.agent_valid_from = identity.valid_from)
      ORDER BY valid_from DESC LIMIT 1`, [agentId]);
  if (!active.rows.length) return null;
  const cert = await getAgentCert(agentId);
  const subject = JSON.parse(Buffer.from(cert, 'base64url').toString('utf8')).body;
  const validFrom = new Date(Number(subject.valid_from) * 1000).toISOString();
  if (subject.agent_id !== agentId || validFrom !== new Date(active.rows[0].valid_from).toISOString()) {
    throw new Error('governance_identity_epoch_mismatch');
  }
  const grant = await recallAuthorizationService.getEffective({ companyId, subjectAgentId: agentId, subjectValidFrom: validFrom });
  if (!grant?.allowed) return null;
  const permissions = await getPermissions(agentId, companyId);
  const result = await query(`SELECT * FROM agent_profiles WHERE company_id = $1 AND agent_id = $2`, [companyId, agentId]);
  const profile = result.rows[0];
  const clearance = profile ? Number(profile.clearance_level) : grant.clearanceCeiling;
  if (!Number.isInteger(clearance) || clearance < 0 || clearance > 12) throw new Error('governance_profile_clearance_invalid');
  return {
    ...(profile || {}), company_id: companyId, agent_id: agentId,
    name: profile?.name ?? agentId, persona: profile?.persona ?? '',
    tier: profile?.tier ?? null, persona_version: profile?.persona_version ?? null,
    clearance_level: Math.min(clearance, grant.clearanceCeiling),
    tool_profile: profile?.tool_profile ?? 'full',
    tool_deltas: profile?.tool_deltas ?? { allow: [], deny: [] },
    allow_delegation: profile?.allow_delegation === true && permissions.delegate === true,
    enrollment: {
      agent_id: agentId, valid_from: validFrom, pubkey_fingerprint: pubkeyFingerprint(subject.pubkey),
      cert_sha256: createHash('sha256').update(cert).digest('hex'),
      recall_grant_event_id: grant.eventId, recall_grant_mutation_sha256: grant.mutationHash.toString('hex'),
    },
  };
}

async function getRoutingRules(companyId, sourceAgentId) {
  const result = await query(`SELECT * FROM agent_routing_policy WHERE company_id = $1 AND source_agent_id = $2 AND enabled = true ORDER BY priority ASC`, [companyId, sourceAgentId]);
  return result.rows;
}

async function getSemanticRouteCandidates(companyId, sourceAgentId) {
  const routed = await query(`SELECT DISTINCT target_agent_id FROM agent_routing_policy WHERE company_id = $1 AND source_agent_id = $2 AND enabled = true`, [companyId, sourceAgentId]);
  const fromRules = routed.rows.map((row) => String(row.target_agent_id || '').trim()).filter(Boolean);
  if (fromRules.length) return fromRules;
  const fallback = await query(`SELECT agent_id FROM agent_profiles WHERE company_id = $1 AND agent_id <> $2`, [companyId, sourceAgentId]);
  return fallback.rows.map((row) => String(row.agent_id || '').trim()).filter(Boolean);
}

async function resolveSemanticDelegation({ companyId, sourceAgentId, prompt }) {
  const text = String(prompt || '').trim();
  if (text.length < SEMANTIC_ROUTING_MIN_PROMPT_CHARS) return null;
  const candidateIds = await getSemanticRouteCandidates(companyId, sourceAgentId);
  if (!candidateIds.length) return null;
  const promptEmbedding = await getEmbedding(text);
  const promptVector = vectorLiteral(promptEmbedding);
  if (!promptVector) return null;
  const result = await query(
    `SELECT agent_id, (persona_embedding <=> $3::vector) AS distance
     FROM agent_profiles
     WHERE company_id = $1 AND agent_id = ANY($2::text[]) AND persona_embedding IS NOT NULL
     ORDER BY persona_embedding <=> $3::vector ASC LIMIT 1`,
    [companyId, candidateIds, promptVector]
  );
  const winner = result.rows[0];
  if (!winner || Number(winner.distance) > SEMANTIC_ROUTING_MAX_DISTANCE) return null;
  return { targetAgentId: winner.agent_id, distance: Number(winner.distance), similarity: 1 - Number(winner.distance) };
}

function matchRule(rule, prompt, intent) {
  if (rule.match_type === 'intent') return intent && String(rule.intent).toLowerCase() === String(intent).toLowerCase();
  return (rule.keywords || []).some(k => new RegExp(`\\b${k}\\b`, 'i').test(String(prompt)));
}

export async function resolveExecutionContext({
  companyId = COMPANY, agentId, prompt, sessionKey, channel, peerId, requestedModel, intent, disableDelegation = false
}) {
  await ensureGovernanceReady(companyId);
  const sourceAgentId = normalizeOperatorAgentId(agentId);
  const sourceProfile = await getProfile(companyId, sourceAgentId);
  if (!sourceProfile) throw new Error(`No profile for ${sourceAgentId}`);

  let resolvedAgentId = sourceAgentId;
  const delegationAllowed = !disableDelegation && !!sourceProfile.allow_delegation;

  if (delegationAllowed) {
    const rules = await getRoutingRules(companyId, sourceAgentId);
    for (const rule of rules) {
      if (matchRule(rule, prompt, intent)) {
        resolvedAgentId = rule.target_agent_id;
        break;
      }
    }
    if (resolvedAgentId === sourceAgentId) {
      const semantic = await resolveSemanticDelegation({ companyId, sourceAgentId, prompt });
      if (semantic) resolvedAgentId = semantic.targetAgentId;
    }
  }

  const targetProfile = await getProfile(companyId, resolvedAgentId);
  if (!targetProfile) {
    const error = new Error(`No enrolled authorized agent for ${resolvedAgentId}`);
    error.statusCode = 403;
    throw error;
  }
  const modelCandidates = await getAgentModelCandidates(companyId, resolvedAgentId);
  let primaryModel = findRequestedModelCandidate(modelCandidates, requestedModel) || requestedModel || modelCandidates[0];
  if (!primaryModel || !modelCandidates.some((candidate) => modelsEquivalent(candidate, primaryModel))) {
    const error = new Error(`model_policy_unavailable:${resolvedAgentId}`);
    error.code = 'MODEL_POLICY_UNAVAILABLE';
    error.statusCode = 503;
    throw error;
  }

  let capabilityProbe = null;
  try {
    const taskHorizon = estimateStateUpdateDepth(prompt);
    capabilityProbe = await observeCapabilityGate({
      companyId,
      agentId: resolvedAgentId,
      taskPrompt: prompt,
      taskHorizon,
      source: 'governance-resolver',
    });
  } catch (err) {
    console.warn('[governance] capability probe failed (non-fatal):', err.message);
  }

  let hvrDiagnostic = null;
  try {
    hvrDiagnostic = await observeHVRDiagnostic({
      companyId,
      agentId: resolvedAgentId,
      taskId: sessionKey || `governance:${sourceAgentId}`,
      taskPrompt: prompt,
      phase: 'hypothesize',
      source: 'governance-resolver',
    });
  } catch (err) {
    console.warn('[governance] HVR diagnostic failed (non-fatal):', err.message);
  }

  return {
    companyId, sourceAgentId, resolvedAgentId, sessionKey: sessionKey || `agent:${sourceAgentId}`,
    channel: channel || 'chat', primaryModel, persona: targetProfile.persona,
    personaVersion: Number(targetProfile.persona_version || 1),
    clearanceLevel: Number(targetProfile.clearance_level || 1),
    roleSlot: resolveProfileRoleSlot(targetProfile),
    capabilityProbe,
    hvrDiagnostic
  };
}

export async function getGovernanceStats(companyId = COMPANY) {
  const [p, r] = await Promise.all([
    query(`SELECT COUNT(*)::int AS total FROM agent_profiles WHERE company_id = $1`, [companyId]),
    query(`SELECT COUNT(*)::int AS total FROM agent_routing_policy WHERE company_id = $1 AND enabled = true`, [companyId])
  ]);
  const modelPolicyCount = Object.values(getModelPreferences())
    .filter((preference) => preference.authority === 'signed_task_preference').length;
  return {
    companyId,
    profileCount: p.rows[0].total,
    modelPolicyCount,
    modelPolicyAuthority: 'master_signed_system_config',
    routingRuleCount: r.rows[0].total,
  };
}

export async function ensureGovernanceReady(companyId = COMPANY, opts = {}) {
  if (opts.force) readyPromise = null;
  if (!readyPromise) {
    readyPromise = (async () => {
      await ensureGovernanceSchema();
      return getGovernanceStats(companyId);
    })();
  }
  return readyPromise;
}

export function shieldGovernanceMemories(memories = [], agentClearanceLevel = 1) {
  const clearance = Number(agentClearanceLevel || 1);
  if (clearance >= 7) return memories;
  return memories.filter(m => !/\[INTERNAL\]/i.test(String(m?.value || m?.content)));
}
