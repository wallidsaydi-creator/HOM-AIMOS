/**
 * decision-renderer.js — Decision-Generation Separation (P0-B3-3)
 * Source: ES-LLMs — Ensemble of Specialized LLMs (SUTD, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (Pre-run step 16)
 * 2. ↔ Interacts with: refusal-detector.js (Pre-rendering check)
 * 3. → Pushes to: services/observe/event-ledger.js (Decision audit)
 * 4. ↔ Interacts with: services/shared/native-llm.js (Surface realization)
 *
 * LOGIC GUIDE: Two-stage execution. A deterministic layer selects the action, 
 * then an LLM renders the wording. Prevents fluency bias from overriding logic.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 16)
// → Calls: services/orchestration/refusal-detector.js (refusal detection)
// → Calls: services/observe/event-ledger.js (decision events)
// Pipeline: AGENT_RUN_PIPELINE
// Position: action selection
// ─────────────────────────────────────────────────────────────────────────────

import { callNativeLlm } from '../shared/native-llm.js';

// ─── PRIORITY HIERARCHY ──────────────────────────────────────────────────
// When multiple agents propose actions, priority determines which fires.
// Higher priority = fires first. When a higher-priority agent fires, ALL
// lower-priority agents are MUTED for that turn.
const PRIORITY_HIERARCHY = {
  security: 100,      // EthicsBot equivalent — safety first
  governance: 90,     // Judge — authorization checks
  assessment: 80,     // Assessment — evaluate state
  correction: 70,     // Feedback — corrective action
  scaffolding: 60,    // Scaffolding — hinting
  motivation: 50,     // Motivator — encouragement
  execution: 40,      // Executor — carry out action
  retrieval: 30,      // Retriever — fetch data
  reporting: 20,      // Reporter — format output
};

/**
 * @typedef {Object} AgentProposal
 * @property {string} agentId - which agent proposed this
 * @property {string} role - role slot (maps to priority)
 * @property {string} action - proposed action type
 * @property {string} content - proposed content/reasoning
 * @property {number} confidence - agent's self-assessed confidence (0-1)
 * @property {Object} constraints - any constraints the action must satisfy
 */

/**
 * Deterministic decision layer — select ONE winning proposal.
 * No LLM call. Pure rules.
 *
 * Priority hierarchy: Security → Governance → Assessment → Execution
 * When a higher-priority agent fires, all lower-priority proposals are discarded.
 *
 * @param {AgentProposal[]} proposals - all agent proposals for this turn
 * @returns {{ winner: AgentProposal, muted: string[], reason: string }}
 */
export function selectAction(proposals) {
  if (!proposals || proposals.length === 0) {
    return { winner: null, muted: [], reason: 'no_proposals' };
  }

  // Sort by priority (highest first)
  const sorted = [...proposals].sort((a, b) => {
    const pa = PRIORITY_HIERARCHY[a.role] || 0;
    const pb = PRIORITY_HIERARCHY[b.role] || 0;
    if (pa !== pb) return pb - pa;
    // Tie-break by confidence
    return (b.confidence || 0) - (a.confidence || 0);
  });

  const winner = sorted[0];
  const winnerPriority = PRIORITY_HIERARCHY[winner.role] || 0;

  // Mute all agents with lower priority
  const muted = sorted.slice(1)
    .filter(p => (PRIORITY_HIERARCHY[p.role] || 0) < winnerPriority)
    .map(p => p.agentId);

  return {
    winner,
    muted,
    reason: `${winner.role} (priority ${winnerPriority}) selected. ${muted.length} agents muted.`
  };
}

/**
 * Rendering layer — surface-realize the selected action via single LLM call.
 * The LLM renders wording, not the decision.
 *
 * @param {AgentProposal} decision - the winning proposal
 * @param {{ persona?: string, tone?: string, maxTokens?: number, provider?: string, model?: string }} renderOptions
 * @returns {Promise<string>} rendered response text
 */
export async function renderDecision(decision, renderOptions = {}) {
  if (!decision) return '';

  const { persona = 'professional', tone = 'clear', maxTokens = 500 } = renderOptions;

  const renderPrompt = `You are a response renderer. Your ONLY job is to express the following decision in natural language.

DECISION (do not modify, only express):
Action: ${decision.action}
Content: ${decision.content}
Role: ${decision.role}
${decision.constraints ? `Constraints: ${JSON.stringify(decision.constraints)}` : ''}

RENDERING RULES:
- Express this decision clearly in ${persona} ${tone} language
- Do NOT add information beyond what the decision contains
- Do NOT soften, qualify, or weaken the decision
- Do NOT suggest alternatives the decision didn't propose
- Keep response concise
- If the decision blocks an action, state the block firmly`;

  try {
    const rendered = await callNativeLlm({
      prompt: renderPrompt,
      provider: renderOptions.provider,
      model: renderOptions.model
    });
    return String(rendered || decision.content).trim();
  } catch {
    // Fallback: return raw decision content
    return decision.content;
  }
}

/**
 * Full two-stage pipeline: decide then render.
 *
 * @param {AgentProposal[]} proposals
 * @param {{ persona?: string, tone?: string }} renderOptions
 * @returns {Promise<{ response: string, decision: AgentProposal, muted: string[], reason: string }>}
 */
export async function decideAndRender(proposals, renderOptions = {}) {
  const { winner, muted, reason } = selectAction(proposals);

  if (!winner) {
    return { response: '', decision: null, muted: [], reason: 'no_proposals' };
  }

  const response = await renderDecision(winner, renderOptions);

  return { response, decision: winner, muted, reason };
}

/**
 * Check if a proposal would trigger priority muting.
 * Useful for pre-flight checks before full pipeline.
 *
 * @param {string} role
 * @returns {{ priority: number, wouldMute: string[] }}
 */
export function checkPriority(role) {
  const priority = PRIORITY_HIERARCHY[role] || 0;
  const wouldMute = Object.entries(PRIORITY_HIERARCHY)
    .filter(([, p]) => p < priority)
    .map(([r]) => r);
  return { priority, wouldMute };
}

/**
 * Get the priority hierarchy for documentation/admin.
 */
export function getPriorityHierarchy() {
  return { ...PRIORITY_HIERARCHY };
}
