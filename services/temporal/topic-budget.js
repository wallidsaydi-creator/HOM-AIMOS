// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into DREAM topic-coverage analysis and audit
// Purpose: Allocates memory budgets across topics via blended local/global
//          distribution; detects distribution shifts; rebalances retention
// Called by: jobs/nightly-dream.js Stage 16
// Calls: observe/event-ledger.js, db/connection.js
// Pipeline: DREAM
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// TOPIC BUDGET (topic-budget.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-6: Allocates memory budgets across topics using blended local/global
// distribution. Detects distribution shifts and rebalances retention.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { createHash } from 'node:crypto';

import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

function hashMutationSet(mutatedMemories = []) {
  const ordered = [...mutatedMemories]
    .sort((a, b) => String(a.id).localeCompare(String(b.id)))
    .map((row) => ({
      id: row.id,
      key: row.key,
      topic: row.topic,
      previous_next_review_at: row.previous_next_review_at,
      next_review_at: row.next_review_at
    }));
  return createHash('sha256').update(JSON.stringify(ordered), 'utf8').digest('hex');
}

/**
 * Get frequency distribution of topics/concepts in the company's memory base.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<Object>} - {topic: frequency, ...}
 */
export async function getTopicDistribution(companyId) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT unnest(memory_tags) as topic, COUNT(*) as frequency
       FROM aimos_memories
       WHERE company_id = $1
       GROUP BY 1`,
      [cid]
    );

    const distribution = {};
    const total = result.rows.reduce((sum, row) => sum + parseInt(row.frequency, 10), 0);

    for (const row of result.rows) {
      const freq = parseInt(row.frequency, 10);
      distribution[row.topic] = total > 0 ? freq / total : 0;
    }

    return distribution;
  } catch (err) {
    console.error('[topic-budget] getTopicDistribution error:', err.message);
    return {};
  }
}

/**
 * Compute per-topic budget allocation using blended local and global distribution.
 *
 * Formula: budget_i = Norm((1-a)*local_i + a*global_i) * total_budget
 * where a = 0.4 (blend weight), Norm() is L1 normalization
 *
 * @param {string} companyId - Company ID
 * @param {number} totalBudget - Total budget to allocate (e.g., 1000)
 * @param {number} blendWeight - Weight of global distribution (default: 0.4)
 * @returns {Promise<Object>} - {topic: budget_amount, ...}
 */
export async function computeTopicBudgets(companyId, totalBudget, blendWeight = 0.4) {
  const cid = companyId || COMPANY;

  try {
    const localDist = await getTopicDistribution(cid);

    // Global distribution: uniform for now (could be learned from industry standards)
    const topics = Object.keys(localDist);
    const globalDist = {};
    const uniformProb = 1 / Math.max(1, topics.length);
    for (const topic of topics) {
      globalDist[topic] = uniformProb;
    }

    // Blend distributions
    const blended = {};
    for (const topic of topics) {
      const local = localDist[topic] || 0;
      const global = globalDist[topic] || 0;
      blended[topic] = (1 - blendWeight) * local + blendWeight * global;
    }

    // L1 normalization
    const sum = Object.values(blended).reduce((a, b) => a + b, 0);
    const budgets = {};
    for (const topic of topics) {
      budgets[topic] = (blended[topic] / Math.max(1, sum)) * totalBudget;
    }

    return budgets;
  } catch (err) {
    console.error('[topic-budget] computeTopicBudgets error:', err.message);
    return {};
  }
}

/**
 * Compute KL divergence between two distributions.
 * Measures information loss when using one distribution to approximate another.
 *
 * @param {Object} oldDist - Original distribution
 * @param {Object} newDist - New distribution
 * @returns {number} - KL divergence (0 = identical)
 */
function klDivergence(oldDist, newDist) {
  let kl = 0;
  const allTopics = new Set([...Object.keys(oldDist), ...Object.keys(newDist)]);

  for (const topic of allTopics) {
    const p = oldDist[topic] || 0.001; // Smoothing
    const q = newDist[topic] || 0.001;
    kl += p * Math.log(p / q);
  }

  return kl;
}

/**
 * Detect distribution shift between old and new topic distributions.
 * Alerts if KL divergence exceeds threshold.
 *
 * @param {Object} oldDist - Previous distribution
 * @param {Object} newDist - Current distribution
 * @param {number} threshold - KL divergence threshold (default: 0.1)
 * @returns {{detected: boolean, kl_divergence: number, alert: boolean}}
 */
export function detectDistributionShift(oldDist, newDist, threshold = 0.1) {
  const kl = klDivergence(oldDist, newDist);
  return {
    detected: kl > threshold,
    kl_divergence: kl,
    alert: kl > threshold
  };
}

/**
 * Analyze underrepresented topics without changing memory or review eligibility.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<{recommended: number, reason: string}>}
 */
export async function analyzeTopicCoverage(companyId) {
  const cid = companyId || COMPANY;

  try {
    // Get current distribution
    const dist = await getTopicDistribution(cid);
    const topics = Object.keys(dist);
    const avgFreq = Object.values(dist).reduce((a, b) => a + b, 0) / Math.max(1, topics.length);

    // Find underrepresented topics (< 50% of average)
    const underrep = topics.filter(t => dist[t] < avgFreq * 0.5);

    if (underrep.length === 0) {
      return {
        recommended: 0,
        reason: 'all_topics_well_represented',
        underrepresented_topics: [],
        memory_schedule_mutated: false,
        recommended_memories: [],
        recommendation_set_hash: hashMutationSet([])
      };
    }

    const recommendedMemories = [];
    for (const topic of underrep) {
      const result = await query(
        `SELECT id, key
           FROM aimos_memories
          WHERE company_id = $1
            AND $2 = ANY(memory_tags)
          ORDER BY created_at DESC`,
        [cid, topic]
      );
      for (const row of result.rows) {
        recommendedMemories.push({
          topic,
          id: row.id,
          key: row.key,
        });
      }
    }
    const recommendationSetHash = hashMutationSet(recommendedMemories);

    return {
      recommended: recommendedMemories.length,
      reason: `Identified ${underrep.length} underrepresented topics for recall evaluation`,
      underrepresented_topics: underrep,
      memory_schedule_mutated: false,
      recommended_memories: recommendedMemories,
      recommendation_set_hash: recommendationSetHash
    };
  } catch (err) {
    console.error('[topic-budget] analyzeTopicCoverage error:', err.message);
    return {
      recommended: 0,
      reason: `error: ${err.message}`,
      underrepresented_topics: [],
      memory_schedule_mutated: false,
      recommended_memories: [],
      recommendation_set_hash: hashMutationSet([])
    };
  }
}

export async function runTopicBudgetAudit({
  companyId = COMPANY,
  totalBudget = 1000,
  blendWeight = 0.4,
  previousDistribution = null,
  shiftThreshold = 0.1,
  rebalanceResult = null,
} = {}) {
  const cid = companyId || COMPANY;
  const boundedBudget = Math.max(1, Number(totalBudget) || 1000);
  const boundedBlend = Math.max(0, Math.min(1, Number(blendWeight) || 0.4));
  const distribution = await getTopicDistribution(cid);
  const budgets = await computeTopicBudgets(cid, boundedBudget, boundedBlend);
  const topics = Object.keys(distribution);
  const shift = previousDistribution
    ? detectDistributionShift(previousDistribution, distribution, shiftThreshold)
    : {
        detected: false,
        kl_divergence: 0,
        alert: false,
        reason: 'previous_distribution_not_supplied'
      };

  const topTopics = Object.entries(distribution)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([topic, share]) => ({ topic, share }));
  const topBudgets = Object.entries(budgets)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([topic, budget]) => ({ topic, budget }));
  const memoryScheduleMutated = Boolean(rebalanceResult?.memory_schedule_mutated);
  const mutatedMemories = Array.isArray(rebalanceResult?.mutated_memories)
    ? rebalanceResult.mutated_memories
    : [];
  const mutationSetHash = rebalanceResult?.mutation_set_hash || hashMutationSet(mutatedMemories);

  const summary = {
    topic_count: topics.length,
    total_budget: boundedBudget,
    blend_weight: boundedBlend,
    budgeted_topics: Object.keys(budgets).length,
    shift,
    rebalance: rebalanceResult,
    memory_schedule_mutated: memoryScheduleMutated,
    mutated_memory_count: mutatedMemories.length,
    mutation_set_hash: mutationSetHash,
    memory_content_changed: false,
    canonical_memory_deleted: false
  };

  const eventId = await logEvent(cid, 'topic-budget', 'topic_budget_audit', `topic_budget:${Date.now()}`, {
    reasoning: `Topic budget audited ${topics.length} topic(s), applied blended local/global allocation with alpha=${boundedBlend}, and recorded the Stage 16 retention rebalance result.`,
    source_knowledge: 'P2-B3-6 topic budget: budget_i = Norm((1-a)*local_i + a*global_i) * total_budget; KL divergence distribution shift detection',
    summary,
    topTopics,
    topBudgets,
    mutatedMemories,
    mutation_set_hash: mutationSetHash,
    diagnostic_only: false,
    retention_rebalance_live: true,
    memory_schedule_mutated: memoryScheduleMutated,
    mutated_memory_count: mutatedMemories.length,
    memory_content_changed: false,
    canonical_memory_deleted: false,
  });

  return {
    ...summary,
    topTopics,
    topBudgets,
    mutatedMemories,
    mutation_set_hash: mutationSetHash,
    eventId,
  };
}
