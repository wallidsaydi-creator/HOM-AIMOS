/**
 * epistemic-vigilance.js — Track Skill Source Reliability
 * Source: Sperber et al. (Cognitive Science)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-learning.js or dual-skill-bank.js
 * 2. → Pulls from: services/db/connection.js (Deposit/Validation history)
 * 3. → Pushes to: agent_trust_scores (Historical reliability updates)
 * 4. ↔ Interacts with: agent-runner.js (Skill deposit gate)
 *
 * LOGIC GUIDE: Tracks the reliability of skill sources using high/medium/low trust tiers.
 * Prevents unreliable sources from directly populating the skill registry.
 *
 * Wave 3 source: Epistemic Blinding — An Inference-Time Protocol for
 * Auditing Prior Contamination in LLM-Assisted Analysis. The blinding helpers
 * below apply prompt-level string replacement only for data-driven
 * ranking/scoring/prioritization decisions; they do not claim accuracy gains.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';

const COMPANY = AIMOS_COMPANY_ID;
const EPISTEMIC_BLINDING_SOURCE = 'Epistemic Blinding: An Inference-Time Protocol for Auditing Prior Contamination in LLM-Assisted Analysis';
const RANKING_DECISION_RE = /\b(rank|ranking|score|scoring|prioriti[sz]e|select|top\s+\d+|best|candidate|screen|evaluate|recommend)\b/i;
const DATA_SIGNAL_RE = /\b(dataset|table|csv|rows?|columns?|features?|metrics?|values?|score|rank|top|portfolio|genes?|company|companies|candidate)\b/i;

function escapeRegExp(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stableUnique(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const normalized = String(value || '')
      .replace(/^(rank|score|evaluate|select|prioriti[sz]e|recommend|screen)\s+/i, '')
      .trim();
    const key = normalized.toLowerCase();
    if (!normalized || seen.has(key)) continue;
    seen.add(key);
    out.push(normalized);
  }
  return out;
}

function extractCandidateEntities(text = '') {
  const source = String(text || '');
  const explicit = [];

  // Quoted names, ticker-like symbols, and title-case multi-word names cover
  // the paper's entity-identifier use case without bringing in a heavy NER pass.
  for (const match of source.matchAll(/["'`]([^"'`]{2,80})["'`]/g)) {
    explicit.push(match[1]);
  }
  for (const match of source.matchAll(/\b[A-Z]{2,6}\b/g)) {
    explicit.push(match[0]);
  }
  for (const match of source.matchAll(/\b(?:[A-Z][a-z0-9]+(?:\s+|[-])){1,4}[A-Z][a-z0-9]+\b/g)) {
    explicit.push(match[0]);
  }

  return stableUnique(explicit)
    .filter((entity) => !/^(HOM|LLM|API|JSON|SQL|HTTP|TEM|MCP|URL|ID|DB)$/i.test(entity))
    .slice(0, 100);
}

export function buildEpistemicBlindMap(entities = [], { prefix = 'Entity' } = {}) {
  return stableUnique(entities).map((entity, index) => ({
    original: entity,
    blind: `${prefix}_${String(index + 1).padStart(3, '0')}`,
  }));
}

export function applyEpistemicBlinding(text = '', blindMap = []) {
  let blinded = String(text || '');
  for (const pair of [...blindMap].sort((a, b) => b.original.length - a.original.length)) {
    const pattern = new RegExp(`\\b${escapeRegExp(pair.original)}\\b`, 'g');
    blinded = blinded.replace(pattern, pair.blind);
  }
  return blinded;
}

export function deblindText(text = '', blindMap = []) {
  let restored = String(text || '');
  for (const pair of blindMap) {
    const pattern = new RegExp(`\\b${escapeRegExp(pair.blind)}\\b`, 'g');
    restored = restored.replace(pattern, pair.original);
  }
  return restored;
}

export function buildEpistemicBlindingGate({
  prompt = '',
  entities = null,
  decisionType = '',
  prefix = 'Entity',
  force = false,
} = {}) {
  const sourcePrompt = String(prompt || '');
  const candidateEntities = Array.isArray(entities) && entities.length
    ? stableUnique(entities)
    : extractCandidateEntities(sourcePrompt);
  const isRankingDecision = RANKING_DECISION_RE.test(`${decisionType} ${sourcePrompt}`);
  const hasDataSignal = DATA_SIGNAL_RE.test(sourcePrompt) || candidateEntities.length >= 3;
  const shouldBlind = force === true || (isRankingDecision && hasDataSignal && candidateEntities.length >= 2);
  const blindMap = shouldBlind ? buildEpistemicBlindMap(candidateEntities, { prefix }) : [];
  const blindedPrompt = shouldBlind ? applyEpistemicBlinding(sourcePrompt, blindMap) : sourcePrompt;

  return {
    status: shouldBlind ? 'applied' : 'not_required',
    source_paper: EPISTEMIC_BLINDING_SOURCE,
    should_blind: shouldBlind,
    entity_count: candidateEntities.length,
    blinded_prompt: blindedPrompt,
    blind_map: blindMap,
    leak_sources_to_review: shouldBlind
      ? ['entity identifiers', 'structurally identifying feature combinations', 'semantically meaningful names']
      : [],
    decision_conditions: {
      data_contains_decision_signal: hasDataSignal,
      uneven_training_representation_possible: candidateEntities.length >= 2,
      action_may_follow_output: isRankingDecision,
    },
    audit_contract: {
      mapping_kept_out_of_model_prompt: shouldBlind,
      deblind_after_response: shouldBlind,
      fresh_context_recommended: shouldBlind,
      accuracy_claimed: false,
      auditability_claimed: true,
    },
    guarded_math: {
      jaccard_rank_shift_comparison: false,
      kendall_tau_analysis: false,
      fame_bias_statistics: false,
    },
  };
}

export function buildEpistemicBlindingStatus() {
  const sample = buildEpistemicBlindingGate({
    prompt: 'Rank Apple, CTRA, ELV, and CI using the supplied company feature table.',
    decisionType: 'ranking',
    prefix: 'Company',
  });
  return {
    success: true,
    status: 'wired',
    source_paper: EPISTEMIC_BLINDING_SOURCE,
    sample,
    contract: {
      inference_time_string_replacement: true,
      model_modification_required: false,
      use_when: 'data-driven ranking/scoring/prioritization over named entities',
      avoid_when: 'knowledge synthesis or tasks where entity names carry legitimate functional signal',
    },
  };
}

/**
 * Get source trust profile
 *
 * @param {string} sourceId - Source identifier
 * @param {string} companyId - Company ID
 * @returns {Promise<{trust: number, totalDeposits: number, validatedCount: number, failedCount: number}>}
 */
export async function getSourceTrust(sourceId, companyId = COMPANY) {
  try {
    const res = await query(
      `SELECT value FROM aimos_memories
       WHERE company_id = $1 AND key = $2 AND memory_type = 'skill_source_trust'
       ORDER BY updated_at DESC LIMIT 1`,
      [companyId, `skill_source:${sourceId}`]
    );

    if (res.rows.length > 0) {
      try {
        const trust = JSON.parse(res.rows[0].value);
        return trust;
      } catch {
        // If corrupt data, return defaults
      }
    }

    // First time seeing this source: neutral trust
    return {
      sourceId,
      trust: 0.5,
      totalDeposits: 0,
      validatedCount: 0,
      failedCount: 0,
      createdAt: new Date().toISOString()
    };
  } catch (err) {
    console.warn(`[EPISTEMIC] Could not fetch source trust for ${sourceId}: ${err.message}`);
    return {
      sourceId,
      trust: 0.5,
      totalDeposits: 0,
      validatedCount: 0,
      failedCount: 0
    };
  }
}

/**
 * Record a skill deposit from a source
 *
 * @param {string} sourceId - Source identifier
 * @param {string} skillId - Skill being deposited
 * @param {string} companyId - Company ID
 * @returns {Promise<{recorded: boolean}>}
 */
export async function recordDeposit(sourceId, skillId, companyId = COMPANY) {
  try {
    const trust = await getSourceTrust(sourceId, companyId);

    // Increment total deposits
    trust.totalDeposits = (trust.totalDeposits || 0) + 1;
    trust.lastDeposit = new Date().toISOString();

    // Persist via canonical write gate
    await persistMemory({
      company_id: companyId,
      agent_id: 'epistemic',
      mutation_authority: 'housekeeper',
      key: `skill_source:${sourceId}`,
      value: JSON.stringify(trust),
      scope: 'system',
      memory_type: 'skill_source_trust',
      memory_tier: 'long-term',
      clearance_level: 8,
    });

    return { recorded: true };
  } catch (err) {
    console.error(`[EPISTEMIC] Failed to record deposit: ${err.message}`);
    return { recorded: false };
  }
}

/**
 * Record validation outcome for a skill from a source
 *
 * @param {string} sourceId - Source identifier
 * @param {string} skillId - Skill identifier
 * @param {boolean} success - Whether validation passed
 * @param {string} companyId - Company ID
 * @returns {Promise<{updated: boolean, newTrust: number}>}
 */
export async function recordValidation(sourceId, skillId, success, companyId = COMPANY) {
  try {
    const trust = await getSourceTrust(sourceId, companyId);

    if (success) {
      trust.validatedCount = (trust.validatedCount || 0) + 1;
    } else {
      trust.failedCount = (trust.failedCount || 0) + 1;
    }

    // Recalculate trust score
    trust.trust = calculateTrustScore(
      trust.totalDeposits,
      trust.validatedCount,
      trust.failedCount
    );

    trust.lastValidation = new Date().toISOString();

    await persistMemory({
      company_id: companyId,
      agent_id: 'epistemic',
      mutation_authority: 'housekeeper',
      key: `skill_source:${sourceId}`,
      value: JSON.stringify(trust),
      scope: 'system',
      memory_type: 'skill_source_trust',
      memory_tier: 'long-term',
      clearance_level: 8,
      source: 'epistemic-vigilance',
    });

    return { updated: true, newTrust: trust.trust };
  } catch (err) {
    console.error(`[EPISTEMIC] Failed to record validation: ${err.message}`);
    return { updated: false, newTrust: 0.5 };
  }
}

/**
 * Calculate trust score from validation history
 *
 * @param {number} totalDeposits - Total deposits from source
 * @param {number} validatedCount - Successful validations
 * @param {number} failedCount - Failed validations
 * @returns {number} Trust score 0-1
 */
function calculateTrustScore(totalDeposits = 0, validatedCount = 0, failedCount = 0) {
  if (totalDeposits === 0) {
    return 0.5;  // Neutral for new sources
  }

  const validated = validatedCount || 0;
  const failed = failedCount || 0;
  const total = validated + failed;

  if (total === 0) {
    return 0.5;  // No validations yet
  }

  // Success ratio (0-1)
  const successRatio = validated / total;

  // Confidence bonus: more validations = higher confidence
  // But cap confidence bonus so single success doesn't give full trust
  const confidence = Math.min(1, total / 10);

  // Trust = success ratio * confidence factor
  const trust = successRatio * (0.7 + 0.3 * confidence);

  return Math.min(1, Math.max(0, trust));
}

/**
 * Get deposit mode for source based on trust level
 *
 * @param {number} sourceTrust - Trust score (0-1)
 * @returns {'direct'|'provisional'|'normal'}
 */
export function getDepositMode(sourceTrust) {
  if (sourceTrust > 0.7) {
    return 'direct';        // Direct deposit, no verification
  } else if (sourceTrust < 0.3) {
    return 'provisional';   // Provisional, requires verification
  } else {
    return 'normal';        // Standard deposit
  }
}

/**
 * Check if source requires verification
 *
 * @param {number} sourceTrust - Trust score (0-1)
 * @returns {boolean}
 */
export function requiresVerification(sourceTrust) {
  return sourceTrust < 0.5;
}

/**
 * Get source recommendation
 *
 * @param {number} sourceTrust - Trust score (0-1)
 * @returns {object}
 */
export function getSourceRecommendation(sourceTrust) {
  const mode = getDepositMode(sourceTrust);

  const recommendations = {
    direct: {
      mode: 'direct',
      trustLevel: 'high',
      action: 'Accept deposits immediately',
      riskLevel: 'low',
      requiresApproval: false,
      skipVerification: true
    },
    provisional: {
      mode: 'provisional',
      trustLevel: 'low',
      action: 'Accept but mark as provisional, verify before using',
      riskLevel: 'high',
      requiresApproval: true,
      skipVerification: false
    },
    normal: {
      mode: 'normal',
      trustLevel: 'medium',
      action: 'Accept normally, standard verification',
      riskLevel: 'medium',
      requiresApproval: false,
      skipVerification: false
    }
  };

  return recommendations[mode];
}

/**
 * Get source reputation profile
 *
 * @param {string} sourceId - Source identifier
 * @param {string} companyId - Company ID
 * @returns {Promise<object>}
 */
export async function getSourceReputation(sourceId, companyId = COMPANY) {
  const trust = await getSourceTrust(sourceId, companyId);
  const mode = getDepositMode(trust.trust);
  const recommendation = getSourceRecommendation(trust.trust);

  return {
    sourceId,
    trust: trust.trust,
    mode,
    recommendation,
    statistics: {
      totalDeposits: trust.totalDeposits,
      validatedCount: trust.validatedCount,
      failedCount: trust.failedCount,
      successRate: trust.totalDeposits > 0
        ? (trust.validatedCount / (trust.validatedCount + trust.failedCount)).toFixed(2)
        : 'N/A'
    },
    timeline: {
      createdAt: trust.createdAt,
      lastDeposit: trust.lastDeposit,
      lastValidation: trust.lastValidation
    }
  };
}

/**
 * Batch check multiple sources
 *
 * @param {Array<string>} sourceIds - List of source IDs
 * @param {string} companyId - Company ID
 * @returns {Promise<object>}
 */
export async function batchCheckSources(sourceIds, companyId = COMPANY) {
  const results = {};

  for (const sourceId of sourceIds) {
    try {
      results[sourceId] = await getSourceReputation(sourceId, companyId);
    } catch (err) {
      console.warn(`[EPISTEMIC] Failed to check source ${sourceId}: ${err.message}`);
      results[sourceId] = { sourceId, error: err.message };
    }
  }

  return results;
}

/**
 * Rank sources by trustworthiness
 *
 * @param {Array<string>} sourceIds - List of source IDs
 * @param {string} companyId - Company ID
 * @returns {Promise<Array<{sourceId: string, trust: number}>>}
 */
export async function rankSourcesByTrust(sourceIds, companyId = COMPANY) {
  const reputable = [];

  for (const sourceId of sourceIds) {
    const trust = await getSourceTrust(sourceId, companyId);
    reputable.push({ sourceId, trust: trust.trust });
  }

  reputable.sort((a, b) => b.trust - a.trust);
  return reputable;
}

/**
 * Get deposit priority for source list
 * Returns sources ordered by trust, suitable for ordered processing.
 *
 * @param {Array<string>} sourceIds - List of source IDs
 * @param {string} companyId - Company ID
 * @returns {Promise<Array<{sourceId: string, mode: string, priority: number}>>}
 */
export async function getDepositPriority(sourceIds, companyId = COMPANY) {
  const ranked = await rankSourcesByTrust(sourceIds, companyId);

  return ranked.map((item, index) => ({
    sourceId: item.sourceId,
    mode: getDepositMode(item.trust),
    priority: index + 1,
    trustScore: item.trust
  }));
}

/**
 * Flag source for review (trust below threshold)
 *
 * @param {string} sourceId - Source identifier
 * @param {number} threshold - Trust threshold (default 0.3)
 * @param {string} companyId - Company ID
 * @returns {Promise<{flagged: boolean, reason?: string}>}
 */
export async function flagSourceForReview(sourceId, threshold = 0.3, companyId = COMPANY) {
  const trust = await getSourceTrust(sourceId, companyId);

  if (trust.trust < threshold) {
    // Record flag in audit via canonical write gate
    await persistMemory({
      company_id: companyId,
      agent_id: 'epistemic',
      mutation_authority: 'housekeeper',
      key: `source_flag:${sourceId}`,
      value: JSON.stringify({
        sourceId,
        trust: trust.trust,
        threshold,
        flaggedAt: new Date().toISOString()
      }),
      scope: 'system',
      memory_type: 'source_review_flag',
      memory_tier: 'long-term',
      clearance_level: 8,
    });

    return { flagged: true, reason: `Trust ${trust.trust.toFixed(2)} below threshold ${threshold}` };
  }

  return { flagged: false };
}
