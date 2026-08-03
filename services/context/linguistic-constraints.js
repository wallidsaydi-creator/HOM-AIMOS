// ═══════════════════════════════════════════════════════════════════════════════
// LINGUISTIC CONSTRAINTS (linguistic-constraints.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-7: Applies linguistic constraints (No-Have, E-Prime) to system prompts
// and creates orthogonal constraint assignments for diverse agent teams.
// ═══════════════════════════════════════════════════════════════════════════════
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: STANDALONE (barrel-only, not wired into live request path)
// Exposed via: services/context/index.js
// → Calls: db (connection.js), event-ledger.js
// Available for: Agent team diversification, prompt constraint injection
// Additive Batch9 Wave6 authority: Talking to a Human as an Attitudinal Barrier
// adds supportive gate-language diagnostics only; safety gates remain intact.
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

const NO_HAVE_RULE = `
LINGUISTIC CONSTRAINT: NO-HAVE RULE
You must avoid using the structure "have/has" in your responses.
Instead, use possession or attribute verbs:
- Instead of "I have an idea", say "An idea arises" or "I notice an idea"
- Instead of "it has properties", say "it exhibits properties" or "its properties include"
- Instead of "they have issues", say "they face issues" or "issues affect them"
This constraint forces more precise and dynamic language.
`;

const E_PRIME_RULE = `
LINGUISTIC CONSTRAINT: E-PRIME RULE
Avoid all forms of "to be" (is, are, was, were, be, being, been, am, are).
Instead, describe relationships, functions, and processes:
- Instead of "That is wrong", say "That contradicts the evidence" or "That leads to errors"
- Instead of "This is important", say "This matters because" or "This affects the outcome"
- Instead of "We are ready", say "We have prepared" or "Conditions support beginning"
This constraint forces more precise, action-oriented language without abstract identity claims.
`;

/**
 * Apply the No-Have linguistic constraint to a system prompt.
 *
 * @param {string} systemPrompt - Original system prompt
 * @returns {string} - Prompt with No-Have rule appended
 */
export function applyNoHaveConstraint(systemPrompt) {
  return `${systemPrompt}\n\n${NO_HAVE_RULE}`;
}

/**
 * Apply the E-Prime linguistic constraint to a system prompt.
 *
 * @param {string} systemPrompt - Original system prompt
 * @returns {string} - Prompt with E-Prime rule appended
 */
export function applyEPrimeConstraint(systemPrompt) {
  return `${systemPrompt}\n\n${E_PRIME_RULE}`;
}

/**
 * Get the appropriate linguistic constraint for a role slot.
 *
 * @param {string} roleSlot - Role identifier (e.g., 'analyst', 'curator', 'executor')
 * @returns {string} - Constraint name ('no-have', 'e-prime', or 'none')
 */
export function getConstraintForRole(roleSlot) {
  const constraintMap = {
    'analyst': 'e-prime',      // Force precise, dynamic analysis
    'curator': 'no-have',      // Force active description of relationships
    'executor': 'none',        // Executors need standard language for reliability
    'challenger': 'e-prime',   // Challenge framing benefits from process language
    'synthesizer': 'no-have',  // Synthesis benefits from precise possession language
    'validator': 'e-prime'     // Validation benefits from condition/process language
  };

  return constraintMap[roleSlot] || 'none';
}

/**
 * Build a linguistically diverse team with orthogonal constraints.
 * Assigns complementary constraints to prevent linguistic homogeneity.
 *
 * @param {Array<string>} agentIds - List of agent IDs
 * @param {string} taskDescription - Description of the task
 * @returns {{agentId: string, constraint: string, reasoning: string}[]}
 */
export function buildLinguisticallyDiverseTeam(agentIds, taskDescription) {
  const constraints = ['e-prime', 'no-have', 'none'];
  const assignments = [];

  for (let i = 0; i < agentIds.length; i++) {
    const constraint = constraints[i % constraints.length];
    let reasoning = '';

    switch (constraint) {
      case 'e-prime':
        reasoning = 'Focuses on processes and conditions; avoids abstract identity claims';
        break;
      case 'no-have':
        reasoning = 'Forces active relationship language; emphasizes dynamics over static possession';
        break;
      case 'none':
        reasoning = 'Maintains standard language as control or flexibility anchor';
        break;
    }

    assignments.push({
      agentId: agentIds[i],
      constraint,
      reasoning
    });
  }

  return assignments;
}

/**
 * Measure conciseness: estimate word count reduction from applying constraints.
 * Constraints often force more direct expression, reducing verbosity.
 *
 * @param {string} text - Original text
 * @returns {{original_words: number, constraint_estimate: number, reduction_percent: number}}
 */
export function measureConciseness(text) {
  const originalWords = text.split(/\s+/).length;

  // Heuristic: constraints typically reduce verbosity by 10-15%
  // ("I have an idea" → "An idea arises" saves ~20% but adds clarity)
  const estimatedReduction = originalWords * 0.12;
  const constrainedWords = Math.round(originalWords - estimatedReduction);

  return {
    original_words: originalWords,
    constraint_estimate: constrainedWords,
    reduction_percent: Math.round((estimatedReduction / originalWords) * 100)
  };
}

export function buildSupportiveGateLanguageDiagnostics({
  message = '',
  gateName = 'security_gate',
  blocked = true,
} = {}) {
  const text = String(message || '');
  const lower = text.toLowerCase();
  const hasPlainReason = /\b(because|reason|risk|evidence|this protects|blocked due to)\b/.test(lower);
  const hasSafeNextStep = /\b(next|try|provide|share|safe path|what i can do|you can)\b/.test(lower);
  const hasEvidenceTag = /\b(evidence|signal|matched|trigger|category|tag)\b/.test(lower);
  const hasOpaqueBlock = blocked && /\b(blocked|denied|forbidden|refused)\b/.test(lower) && (!hasPlainReason || !hasSafeNextStep);
  const readabilityScore = clamp01(
    (hasPlainReason ? 0.34 : 0)
    + (hasSafeNextStep ? 0.42 : 0)
    + (hasEvidenceTag ? 0.16 : 0)
    + (text.split(/\s+/).filter(Boolean).length <= 90 ? 0.08 : 0)
  );

  return {
    source_paper: 'Talking to a Human as an Attitudinal Barrier: A Mixed Methods Evaluation of Stigma, Access, and the Appeal of AI Mental Health Support',
    status: hasOpaqueBlock || readabilityScore < 0.5
      ? 'needs_supportive_rewrite'
      : 'supportive_gate_language_ready',
    diagnostic_only: true,
    gate_name: gateName,
    readability_score: Number(readabilityScore.toFixed(6)),
    checks: {
      has_plain_reason: hasPlainReason,
      has_safe_next_step: hasSafeNextStep,
      has_evidence_tag: hasEvidenceTag,
      opaque_block_detected: hasOpaqueBlock,
    },
    suggested_shape: [
      'Name the gate in plain language.',
      'Give one sentence explaining the risk/evidence.',
      'Offer a safe next step that preserves the boundary.',
    ],
    guardrails: {
      safety_gate_loosened: false,
      medical_or_clinical_advice: false,
      hidden_policy_exposed: false,
    },
  };
}
