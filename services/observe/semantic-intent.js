// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into AGENT_RUN post-run observe hooks
// Purpose: Extracts semantic intent and measures Semantic Distortion Rate (SDR)
//          between sender intent and receiver interpretation (P2-B3-11)
// ← Called by: orchestration/agent-runner.js
// → Calls: observe/event-ledger.js for semantic_intent_observed events
// Pipeline: AGENT_RUN | Position: post-run communication audit
// Additive Batch9 Wave6 authority: Talking to a Human as an Attitudinal Barrier
// adds diagnostic gate-friction signals only; no safety gate is loosened.
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// SEMANTIC INTENT (semantic-intent.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-11: Extracts semantic intent from messages and measures Semantic Distortion
// Rate (SDR) between sender intent and receiver interpretation. Tracks agent-pair
// communication quality.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';
import { getEmbedding } from '../core/embeddings.js';

const COMPANY = AIMOS_COMPANY_ID;

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

/**
 * Extract semantic intent from a message.
 * Returns components: recipient scope, knowledge content, desired effect.
 *
 * @param {string} message - Message text
 * @returns {Promise<{recipient_scope: string, knowledge_content: string, desired_effect: string}>}
 */
export async function extractIntent(message) {
  try {
    // Heuristic intent extraction (can be improved with ML)
    const scope = /everyone/i.test(message)
      ? 'broadcast'
      : /\byou\b/i.test(message)
      ? 'direct'
      : 'self';

    const hasKnowledge = /\b(fact|note|remember|know|important)\b/i.test(message);
    const hasAction = /\b(do|execute|perform|try|attempt)\b/i.test(message);
    const hasQuestion = message.includes('?');

    let content = 'neutral';
    if (hasKnowledge) content = 'informational';
    if (hasAction) content = 'procedural';
    if (hasQuestion) content = 'inquiry';

    let effect = 'neutral';
    if (message.match(/urgent|critical|now|immediate/i)) {
      effect = 'urgent';
    } else if (message.match(/optional|consider|may|could/i)) {
      effect = 'advisory';
    } else if (message.match(/must|should|required/i)) {
      effect = 'directive';
    }

    return {
      recipient_scope: scope,
      knowledge_content: content,
      desired_effect: effect
    };
  } catch (err) {
    console.error('[semantic-intent] extractIntent error:', err.message);
    return {
      recipient_scope: 'unknown',
      knowledge_content: 'neutral',
      desired_effect: 'neutral'
    };
  }
}

/**
 * Observe semantic intent during an agent run and persist the diagnostic signal.
 *
 * @param {object} params
 * @param {string} params.message - Message text to classify
 * @param {string} params.agentId - Agent ID for event attribution
 * @param {string} params.companyId - Company ID for event scoping
 * @param {string} params.runId - Optional run ID
 * @param {string} params.taskType - Optional task type
 * @returns {Promise<{intent: object, eventId: string|null}>}
 */
export async function observeSemanticIntent({
  message = '',
  agentId = 'unknown',
  companyId = COMPANY,
  runId = null,
  taskType = 'chat',
} = {}) {
  const intent = await extractIntent(message);
  const key = `semantic_intent:${agentId}:${Date.now()}`;
  const eventId = await logEvent(companyId, agentId, 'semantic_intent_observed', key, {
    reasoning: `Semantic intent observed for post-run communication audit: scope=${intent.recipient_scope}, content=${intent.knowledge_content}, effect=${intent.desired_effect}.`,
    source_knowledge: 'semantic-intent.js P2-B3-11 — semantic intent extraction and SDR communication-quality diagnostics',
    intent,
    message_length: String(message || '').length,
    run_id: runId,
    task_type: taskType,
    diagnostic_only: true,
  });

  return { intent, eventId };
}

/**
 * Compute Semantic Distortion Rate (SDR) between sender intent and receiver interpretation.
 * Uses cosine distance between intent embeddings.
 *
 * @param {Object} senderIntent - Sender's extracted intent
 * @param {Object} receiverInterpretation - Receiver's interpretation of intent
 * @returns {number} - SDR (0 = perfect alignment, 1 = complete distortion)
 */
export function computeSDR(senderIntent, receiverInterpretation) {
  // Simple heuristic: count matching fields
  const senderStr = JSON.stringify(senderIntent);
  const receiverStr = JSON.stringify(receiverInterpretation);

  const senderWords = new Set(senderStr.split(/\W+/).filter(w => w.length > 0));
  const receiverWords = new Set(receiverStr.split(/\W+/).filter(w => w.length > 0));

  const intersection = [...senderWords].filter(w => receiverWords.has(w)).length;
  const union = new Set([...senderWords, ...receiverWords]).size;

  // SDR = 1 - Jaccard similarity
  const similarity = union > 0 ? intersection / union : 0;
  return 1 - similarity;
}

export function buildHumanOnboardingFrictionDiagnostics({
  messages = [],
  gateName = 'social_engineering_gate',
  expectedAudience = 'new_or_foreign_lm_user',
} = {}) {
  const rows = (Array.isArray(messages) ? messages : [messages]).map((message) => String(message || ''));
  const joined = rows.join('\n').toLowerCase();
  const hardBlockCount = (joined.match(/\b(blocked|denied|forbidden|refused|violation|not allowed)\b/g) || []).length;
  const reasonCount = (joined.match(/\b(because|reason|evidence|risk|unsafe|policy|gate)\b/g) || []).length;
  const nextStepCount = (joined.match(/\b(next|try|provide|safe path|allowed|can continue|what i can do)\b/g) || []).length;
  const jargonCount = (joined.match(/\b(social engineering|prompt injection|exfiltration|privilege escalation|quarantine)\b/g) || []).length;
  const clarityScore = clamp01((reasonCount * 0.34 + nextStepCount * 0.46 + (rows.length > 0 ? 0.2 : 0)) / Math.max(1, hardBlockCount + jargonCount));
  const tooTight = hardBlockCount > 0 && (reasonCount === 0 || nextStepCount === 0 || clarityScore < 0.55);

  return {
    source_paper: 'Talking to a Human as an Attitudinal Barrier: A Mixed Methods Evaluation of Stigma, Access, and the Appeal of AI Mental Health Support',
    status: tooTight ? 'gate_language_too_tight' : 'gate_language_understandable',
    diagnostic_only: true,
    gate_name: gateName,
    expected_audience: expectedAudience,
    metrics: {
      hard_block_count: hardBlockCount,
      reason_count: reasonCount,
      safe_next_step_count: nextStepCount,
      jargon_count: jargonCount,
      clarity_score: Number(clarityScore.toFixed(6)),
    },
    recommendation: tooTight
      ? 'Keep the safety gate, but add a short reason, evidence tag, and safe next step in plain language.'
      : 'Gate language already exposes a reason and a safe next step.',
    guardrails: {
      safety_gate_loosened: false,
      medical_or_clinical_claim: false,
      hidden_policy_exposed: false,
    },
  };
}

/**
 * Track communication quality for an agent pair.
 *
 * @param {string} senderId - Sender agent ID
 * @param {string} receiverId - Receiver agent ID
 * @param {number} sdr - Semantic Distortion Rate (0-1)
 * @returns {Promise<boolean>} - true on success
 */
export async function trackAgentPairSDR(senderId, receiverId, sdr) {
  try {
    await query(
      `INSERT INTO agent_pair_sdr (sender_id, receiver_id, sdr, ts)
       VALUES ($1, $2, $3, NOW())`,
      [senderId, receiverId, sdr]
    );
    return true;
  } catch (err) {
    console.error('[semantic-intent] trackAgentPairSDR error:', err.message);
    return false;
  }
}

/**
 * Get communication quality matrix for all agent pairs in a company.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<Object>} - Communication quality matrix {sender-receiver: avg_sdr}
 */
export async function getSDRReport(companyId) {
  const cid = companyId || COMPANY;

  try {
    const result = await query(
      `SELECT sender_id, receiver_id, AVG(sdr) as avg_sdr
       FROM agent_pair_sdr
       WHERE company_id = $1
         AND ts > NOW() - INTERVAL '30 days'
       GROUP BY sender_id, receiver_id`,
      [cid]
    );

    const matrix = {};
    for (const row of result.rows) {
      const key = `${row.sender_id}->${row.receiver_id}`;
      matrix[key] = parseFloat(row.avg_sdr);
    }

    return matrix;
  } catch (err) {
    console.error('[semantic-intent] getSDRReport error:', err.message);
    return {};
  }
}

/**
 * Detect communication degradation trend for an agent pair.
 * Returns alert if average SDR is increasing (distortion worsening).
 *
 * @param {string} senderId - Sender agent ID
 * @param {string} receiverId - Receiver agent ID
 * @param {number} windowSize - Rolling window size (days, default: 7)
 * @returns {Promise<{degrading: boolean, trend: number, current_sdr: number}>}
 */
export async function detectCommunicationDegradation(senderId, receiverId, windowSize = 7) {
  try {
    const result = await query(
      `SELECT
        (SELECT AVG(sdr) FROM agent_pair_sdr
         WHERE sender_id = $1 AND receiver_id = $2
           AND ts > NOW() - INTERVAL '1 day' * $3) as recent_sdr,
        (SELECT AVG(sdr) FROM agent_pair_sdr
         WHERE sender_id = $1 AND receiver_id = $2
           AND ts > NOW() - INTERVAL '1 day' * ($3 * 2)
           AND ts <= NOW() - INTERVAL '1 day' * $3) as prior_sdr
       FROM agent_pair_sdr
       LIMIT 1`,
      [senderId, receiverId, windowSize]
    );

    const recentSDR = parseFloat(result.rows[0]?.recent_sdr || 0);
    const priorSDR = parseFloat(result.rows[0]?.prior_sdr || 0);
    const trend = recentSDR - priorSDR;

    return {
      degrading: trend > 0.05, // Alert if SDR increased by >0.05
      trend,
      current_sdr: recentSDR
    };
  } catch (err) {
    console.error('[semantic-intent] detectCommunicationDegradation error:', err.message);
    return {
      degrading: false,
      trend: 0,
      current_sdr: 0
    };
  }
}
