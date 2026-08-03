/**
 * governance-resolver.js — Multi-Agent Coordination and Routing
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
import { query } from '../../db/connection.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { ensureAgent, agents } from './agent-store.js';
import { getEmbedding } from '../core/embeddings.js';
import { getProviderRegistry } from '../core/providers.js';
import { createHash } from 'crypto';
import { normalizeOperatorAgentId } from '../security/system-config-store.js';
import { enforceAimosOperatorBrainLink } from '../core/brain-contract.js';
import { designTaskGraph } from './graph-designer.js';
import { resolveFallback, isOrchestrationExhausted, getExhaustionReason } from './fallback-resolver.js';
import { createRoutingCounter, incrementRouting, shouldTriggerFallback } from '../observe/routing-monitor.js';
import { routeTask as trustRouteTask, recordSuccess as trustRecordSuccess, recordFailure as trustRecordFailure } from './trust-router.js';
import { estimateStateUpdateDepth, observeCapabilityGate } from './capability-probe.js';
import { confidenceWeightedVote, triggerDebate } from './decentralized-consensus.js';
import { runInvestigationLoop } from './explore-exploit-loop.js';
import { observeHVRDiagnostic } from './hypothesis-verifier.js';
import { logAIDecision } from '../observe/architecture-registry.js';
import { generateExplanation } from '../observe/explainer.js';

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
    'agent_model_policy',
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

async function getPrimaryModels(companyId) {
  const result = await query(
    `SELECT DISTINCT ON (agent_id) agent_id, model_id
     FROM agent_model_policy
     WHERE company_id = $1 AND enabled = true
     ORDER BY agent_id, is_primary DESC, priority ASC`,
    [companyId]
  );
  const map = new Map();
  for (const row of result.rows) map.set(row.agent_id, row.model_id);
  return map;
}

export async function hydrateAgentStoreFromGovernance(companyId = COMPANY) {
  const [profilesRes, primaryModelMap] = await Promise.all([
    query(`SELECT * FROM agent_profiles WHERE company_id = $1`, [companyId]),
    getPrimaryModels(companyId)
  ]);
  const hydrated = [];
  for (const row of profilesRes.rows) {
    const modelId = primaryModelMap.get(row.agent_id) || '';
    if (!modelId) continue;
    const agent = ensureAgent(row.agent_id, {
      name: row.name, tier: row.tier, model: modelId,
      tools: [row.tool_profile || 'full'], persona: row.persona, clearanceLevel: row.clearance_level
    });
    agent.isActive = true;
    agents.set(agent.id, agent);
    hydrated.push(agent);
  }
  return hydrated;
}

export async function getAgentModelCandidates(companyId, agentId) {
  const res = await query(
    `SELECT model_id FROM agent_model_policy
     WHERE company_id = $1 AND agent_id = $2 AND enabled = true
     ORDER BY is_primary DESC, priority ASC, model_id ASC`,
    [companyId, agentId]
  );
  const dbCandidates = res.rows.map((row) => row.model_id);
  return dbCandidates;
}

async function getProfile(companyId, agentId) {
  const result = await query(`SELECT * FROM agent_profiles WHERE company_id = $1 AND agent_id = $2`, [companyId, agentId]);
  return result.rows[0] || null;
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

  const modelCandidates = await getAgentModelCandidates(companyId, resolvedAgentId);
  let primaryModel = findRequestedModelCandidate(modelCandidates, requestedModel) || requestedModel || modelCandidates[0];
  if (!primaryModel || !modelCandidates.some((candidate) => modelsEquivalent(candidate, primaryModel))) {
    throw new Error(`model_policy_unavailable:${resolvedAgentId}`);
  }

  const targetProfile = await getProfile(companyId, resolvedAgentId);
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
  const [p, m, r] = await Promise.all([
    query(`SELECT COUNT(*)::int AS total FROM agent_profiles WHERE company_id = $1`, [companyId]),
    query(`SELECT COUNT(*)::int AS total FROM agent_model_policy WHERE company_id = $1 AND enabled = true`, [companyId]),
    query(`SELECT COUNT(*)::int AS total FROM agent_routing_policy WHERE company_id = $1 AND enabled = true`, [companyId])
  ]);
  return { companyId, profileCount: p.rows[0].total, modelPolicyCount: m.rows[0].total, routingRuleCount: r.rows[0].total };
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
