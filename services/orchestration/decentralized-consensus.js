// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Available — not yet wired into a live pipeline
// Purpose: MediHive self-evolving roles + typed debate protocol for multi-agent
//          consensus (proposeRoles → refineRoles → debate → converge) (P1-B3-13)
// Wire into: agent-runner.js (agent-run pipeline, multi-agent coordination step)
// Additive Batch9 Wave6 authority: Casevo and Maximum Heterogeneity add
// simulation-readiness diagnostics only. Live consensus uses provider-agnostic
// runProvider; diagnostics do not trigger hidden model/tool calls.
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// DECENTRALIZED CONSENSUS (decentralized-consensus.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-13: MediHive Self-Evolving Roles + Typed Debate
//
// Multi-agent consensus protocol:
//   1. proposeRoles(agents, task)      → each agent generates role proposal
//   2. refineRoles(proposals)          → self-reflection pass for clarity/alignment
//   3. triggerDebate(agents, answers)  → typed debate if agreement < threshold (0.8)
//   4. classifyContribution(text)      → 'rebuttal' | 'defense' | 'proposal'
//   5. confidenceWeightedVote(answers) → S(a) = Σ c_i for agents choosing a
//   6. checkConvergence(rounds)        → true if agreement >= threshold x2 rounds
//
// Debate types: rebuttal (challenge existing), defense (support existing),
// proposal (new position). Convergence requires threshold agreement for 2
// consecutive rounds to prevent premature lock-in.
//
// Theoretical basis: MediHive (Sun et al.), typed deliberation protocols,
// confidence-weighted social choice, liquid democracy.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { runProvider } from '../core/providers.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// Default convergence threshold (80% agreement)
const DEFAULT_THRESHOLD = 0.8;

// Maximum debate rounds before forced conclusion
const MAX_DEBATE_ROUNDS = 5;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Normalise a string to a comparable form for agreement checking.
 *
 * @param {string} text
 * @returns {string}
 */
function normaliseAnswer(text) {
  return String(text || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Compute the fraction of agents that agree on the plurality answer.
 *
 * @param {string[]} answers
 * @returns {number} Agreement rate in [0, 1]
 */
function agreementRate(answers) {
  if (!answers || answers.length === 0) return 0;
  const counts = new Map();
  for (const a of answers) {
    const key = normaliseAnswer(a);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const max = Math.max(...counts.values());
  return max / answers.length;
}

async function runConsensusModel(prompt, options = {}) {
  return runProvider({
    prompt,
    model: options.model,
    provider: options.provider,
  });
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Have each agent generate a role proposal for a task.
 * Each agent proposes its own role, responsibilities, and scope.
 *
 * @param {Array<{agentId: string, context?: string}>} agents
 * @param {string} taskDescription
 * @returns {Promise<Array<{agentId: string, role: string, responsibilities: string[], scope: string}>>}
 */
export async function proposeRoles(agents, taskDescription) {
  if (!Array.isArray(agents) || agents.length === 0) {
    throw new Error('[decentralized-consensus] proposeRoles: agents must be a non-empty array');
  }

  const proposals = await Promise.all(
    agents.map(async (agent) => {
      const contextNote = agent.context ? `\nAgent context: ${agent.context}` : '';
      const prompt =
        `You are agent "${agent.agentId}". Given the following task, propose a specific role for yourself.${contextNote}\n\nTask: ${taskDescription}\n\nRespond in JSON: {"role": "...", "responsibilities": ["...", "..."], "scope": "..."}`;

      let parsed = { role: 'general', responsibilities: ['assist'], scope: 'full task' };
      try {
        const response = await runConsensusModel(prompt, { maxTokens: 256 });
        const jsonMatch = String(response || '').match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsed = JSON.parse(jsonMatch[0]);
        }
      } catch (err) {
        console.warn(`[decentralized-consensus] proposeRoles error for ${agent.agentId}:`, err.message);
      }

      return {
        agentId: agent.agentId,
        role: String(parsed.role || 'general'),
        responsibilities: Array.isArray(parsed.responsibilities) ? parsed.responsibilities : ['assist'],
        scope: String(parsed.scope || 'full task'),
      };
    })
  );

  return proposals;
}

/**
 * Refine role proposals through a self-reflection pass.
 * Each proposal is evaluated for: clarity, differentiation, and task alignment.
 * Overlapping or vague roles are sharpened.
 *
 * @param {Array<{agentId: string, role: string, responsibilities: string[], scope: string}>} proposals
 * @returns {Promise<Array<{agentId: string, role: string, responsibilities: string[], scope: string, refinementNote: string}>>}
 */
export async function refineRoles(proposals) {
  if (!Array.isArray(proposals) || proposals.length === 0) return [];

  const proposalSummary = proposals
    .map((p) => `- ${p.agentId}: ${p.role} (scope: ${p.scope})`)
    .join('\n');

  const refined = await Promise.all(
    proposals.map(async (proposal) => {
      const prompt =
        `You are reviewing role assignments for a multi-agent team. Refine the following role for clarity, differentiation from others, and alignment.\n\nAll roles:\n${proposalSummary}\n\nYour role to refine:\nAgent: ${proposal.agentId}\nRole: ${proposal.role}\nResponsibilities: ${proposal.responsibilities.join(', ')}\nScope: ${proposal.scope}\n\nRespond in JSON: {"role": "...", "responsibilities": ["..."], "scope": "...", "refinementNote": "..."}`;

      let refined = { ...proposal, refinementNote: 'no change' };
      try {
        const response = await runConsensusModel(prompt, { maxTokens: 256 });
        const jsonMatch = String(response || '').match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          refined = {
            agentId: proposal.agentId,
            role: String(parsed.role || proposal.role),
            responsibilities: Array.isArray(parsed.responsibilities) ? parsed.responsibilities : proposal.responsibilities,
            scope: String(parsed.scope || proposal.scope),
            refinementNote: String(parsed.refinementNote || 'no change'),
          };
        }
      } catch (err) {
        console.warn(`[decentralized-consensus] refineRoles error for ${proposal.agentId}:`, err.message);
      }

      return refined;
    })
  );

  return refined;
}

/**
 * Classify a debate contribution as rebuttal, defense, or proposal.
 *
 * @param {string} text - Contribution text
 * @returns {Promise<'rebuttal' | 'defense' | 'proposal'>}
 */
export async function classifyContribution(text) {
  if (!text || typeof text !== 'string') return 'proposal';

  const prompt =
    `Classify the following debate contribution as exactly one of: rebuttal, defense, proposal.\n- rebuttal: challenges or contradicts an existing position\n- defense: supports or justifies an existing position\n- proposal: introduces a new position or approach\n\nContribution: ${text.trim().slice(0, 500)}\n\nRespond with only one word: rebuttal, defense, or proposal.`;

  try {
    const response = await runConsensusModel(prompt, { maxTokens: 10 });
    const normalized = String(response || '').trim().toLowerCase();
    if (['rebuttal', 'defense', 'proposal'].includes(normalized)) {
      return normalized;
    }
  } catch (err) {
    console.warn('[decentralized-consensus] classifyContribution error:', err.message);
  }

  // Keyword heuristic fallback
  const lower = text.toLowerCase();
  if (/however|disagree|incorrect|wrong|challenge|contradict/.test(lower)) return 'rebuttal';
  if (/agree|support|correct|confirm|valid|defend/.test(lower)) return 'defense';
  return 'proposal';
}

/**
 * Compute confidence-weighted vote across agent answers.
 * S(a) = Σ c_i for all agents i choosing answer a.
 * Returns the answer with highest S score.
 *
 * @param {Array<{agentId: string, answer: string, confidence: number}>} agentAnswers
 * @returns {{winner: string, scores: Record<string, number>, totalWeight: number}}
 */
export function confidenceWeightedVote(agentAnswers) {
  if (!Array.isArray(agentAnswers) || agentAnswers.length === 0) {
    return { winner: '', scores: {}, totalWeight: 0 };
  }

  const scores = {};
  let totalWeight = 0;

  for (const entry of agentAnswers) {
    const key = normaliseAnswer(entry.answer);
    const confidence = Math.max(0, Math.min(1, Number(entry.confidence) || 0.5));
    scores[key] = (scores[key] || 0) + confidence;
    totalWeight += confidence;
  }

  const winner = Object.entries(scores).sort((a, b) => b[1] - a[1])[0]?.[0] || '';

  return { winner, scores, totalWeight };
}

/**
 * Trigger a typed debate among agents if their agreement is below threshold.
 * Agents exchange rebuttal/defense/proposal contributions up to MAX_DEBATE_ROUNDS.
 *
 * @param {Array<{agentId: string, context?: string}>} agents
 * @param {string[]} answers - Current answers from each agent
 * @param {number} [threshold=0.8] - Agreement threshold to skip debate
 * @returns {Promise<{debated: boolean, rounds: number, finalAnswers: string[], agreement: number}>}
 */
export async function triggerDebate(agents, answers, threshold = DEFAULT_THRESHOLD) {
  const th = Math.max(0, Math.min(1, Number(threshold) || DEFAULT_THRESHOLD));

  if (!Array.isArray(answers) || answers.length === 0) {
    return { debated: false, rounds: 0, finalAnswers: answers, agreement: 0 };
  }

  let currentAnswers = [...answers];
  const initialAgreement = agreementRate(currentAnswers);

  if (initialAgreement >= th) {
    return { debated: false, rounds: 0, finalAnswers: currentAnswers, agreement: initialAgreement };
  }

  let rounds = 0;
  let consecutiveConvergence = 0;

  while (rounds < MAX_DEBATE_ROUNDS && consecutiveConvergence < 2) {
    rounds++;

    const roundPromises = agents.map(async (agent, idx) => {
      const ownAnswer = currentAnswers[idx] || '';
      const othersAnswers = currentAnswers
        .filter((_, i) => i !== idx)
        .map((a, i) => `Agent ${agents[i]?.agentId || i}: "${a}"`)
        .join('\n');

      const prompt =
        `You are agent "${agent.agentId}" in a debate. Review other agents' answers and update your position if warranted.\n\nOther agents:\n${othersAnswers}\n\nYour current answer: "${ownAnswer}"\n\nProvide your updated answer (respond with just the answer):`;

      try {
        const response = await runConsensusModel(prompt, { maxTokens: 128 });
        return String(response || ownAnswer).trim();
      } catch (err) {
        console.warn(`[decentralized-consensus] debate round ${rounds} error for ${agent.agentId}:`, err.message);
        return ownAnswer;
      }
    });

    currentAnswers = await Promise.all(roundPromises);

    const roundAgreement = agreementRate(currentAnswers);
    if (roundAgreement >= th) {
      consecutiveConvergence++;
    } else {
      consecutiveConvergence = 0;
    }
  }

  const finalAgreement = agreementRate(currentAnswers);

  await logEvent(COMPANY, 'debate_completed', {
    rounds,
    initialAgreement,
    finalAgreement,
    converged: consecutiveConvergence >= 2,
  }).catch(() => {});

  return {
    debated: true,
    rounds,
    finalAnswers: currentAnswers,
    agreement: finalAgreement,
  };
}

/**
 * Check if consensus has converged (threshold agreement for 2 consecutive rounds).
 *
 * @param {Array<{round: number, answers: string[]}>} rounds - History of debate rounds
 * @param {number} [threshold=0.8] - Required agreement rate
 * @returns {boolean}
 */
export function checkConvergence(rounds, threshold = DEFAULT_THRESHOLD) {
  const th = Math.max(0, Math.min(1, Number(threshold) || DEFAULT_THRESHOLD));

  if (!Array.isArray(rounds) || rounds.length < 2) return false;

  let consecutiveAbove = 0;
  for (const round of rounds) {
    const rate = agreementRate(round.answers || []);
    if (rate >= th) {
      consecutiveAbove++;
      if (consecutiveAbove >= 2) return true;
    } else {
      consecutiveAbove = 0;
    }
  }

  return false;
}

export function buildCasevoConsensusSimulationDiagnostics({
  agents = [],
  scenarios = [],
  heterogeneitySignals = [],
} = {}) {
  const agentRows = Array.isArray(agents) ? agents : [];
  const scenarioRows = Array.isArray(scenarios) ? scenarios : [];
  const roleTypes = new Set(agentRows.map((agent) => String(agent.role || agent.type || agent.agentId || '').toLowerCase()).filter(Boolean));
  const heterogeneity = agentRows.length ? roleTypes.size / Math.max(1, agentRows.length) : 0;

  return {
    source_papers: [
      'Casevo: A Cognitive Agents and Social Evolution Simulator',
      'The Principle of Maximum Heterogeneity Optimises Productivity in Distributed Production Systems Across Biology, Economics, and Computing',
    ],
    status: agentRows.length >= 2 && scenarioRows.length >= 1
      ? 'simulation_ready'
      : 'needs_more_agents_or_scenarios',
    diagnostic_only: true,
    simulation_only: true,
    agent_count: agentRows.length,
    scenario_count: scenarioRows.length,
    heterogeneity_proxy: Number(heterogeneity.toFixed(6)),
    scenario_ids: scenarioRows.map((scenario) => scenario.id || scenario.name).filter(Boolean),
    heterogeneity_signals: Array.isArray(heterogeneitySignals) ? heterogeneitySignals : [],
    guardrails: {
      hidden_model_call_executed: false,
      debate_triggered: false,
      tool_execution_enabled: false,
      production_policy_changed: false,
      canonical_memory_changed: false,
    },
  };
}
