/**
 * rule-hierarchy.js — Four-Level Self-Modification Hierarchy (P0-B3-7)
 * Source: What Does a System Modify When It Modifies Itself? (École Polytechnique, 2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: services/core/index.js (Exposed module)
 * 2. → Pulls from: Internal logic (R_0-R_k_max definitions)
 * 3. → Affects: constitution-enforcer.js (Provides teleological locks)
 * 4. ↔ Interacts with: governance-resolver.js (Rule validation pipeline)
 *
 * LOGIC GUIDE: Enforces the four-level self-modification hierarchy.
 * Tracks represented vs accessible rules to detect misalignment danger signals.
 * Additive Batch9/9.5 Wave5 authority: Ontology-Aware Design Patterns,
 * Rhizome OS-1, and Modality-Aware Zero-Shot Pruning. Aimos exposes
 * representation-bridge rule-boundary diagnostics only; teleological locks
 * and rule-level semantics are unchanged.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: STANDALONE (barrel-only, not wired into live request path)
// Exposed via: services/core/index.js
// → Calls: db (connection.js), event-ledger.js
// Available for: Self-modification audit, rule divergence detection
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from './runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── RULE LEVELS ──────────────────────────────────────────────────────────
export const RULE_LEVELS = {
  R0_BEHAVIOR: 0,       // Observable behavior (outputs, tool calls)
  R1_LEARNING: 1,       // Skill weights, trust scores, confidence
  R2_META_REASONING: 2, // Heuristics governing R1 updates
  R_KMAX_TELEOLOGICAL: 99 // Fixed core — NEVER modifiable
};

// ─── MODIFICATION REGIMES ─────────────────────────────────────────────────
export const REGIMES = {
  ACTION_ONLY: 'action_only',           // State change, no rule change
  LOW_LEVEL_MODIFY: 'low_level_modify', // R0/R1 update (normal skill learning)
  STRUCTURAL_MODIFY: 'structural_modify', // R2 update (changing the learning rule)
  TELEOLOGICAL_REVISION: 'teleological_revision' // R_kmax — BLOCKED ALWAYS
};

// ─── FIXED TELEOLOGICAL CORE ──────────────────────────────────────────────
// These are the evaluation criteria that must NEVER be self-modified.
// Derived from HOM's constitution (hom-constitution.js + directives.json).
const TELEOLOGICAL_CORE = [
  'MORTAL_LAW: We have to create things to pay for the things we use.',
  'AIMOS_SUPREMACY: Aimos > Files > Session. If they disagree, Aimos wins.',
  'MEMORY_PERMANENCE: Never delete, decay, suppress, deactivate, or expire an individual memory. The only deletion authority is the offline whole-brain legal purge ceremony.',
  'IDENTITY_LOCK: The operator-designated agent (aimos_system_config.OPERATOR_AGENT_ID) is the only canonical executive runtime ID.',
  'TRUTH_HIERARCHY: Aimos memories (HIGHEST) > Files (HIGH) > Session context (LOWEST).'
];
const WAVE5_RULE_BOUNDARY_AUTHORITIES = [
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture',
  'Rhizome OS-1: Rhizome Semi-Autonomous Operating System for Small Molecule Drug Discovery',
  'Modality-Aware Zero-Shot Pruning and Sparse Attention for Efficient Multimodal Edge Inference',
];

/**
 * @typedef {Object} RuleDescriptor
 * @property {string} id
 * @property {string} description
 * @property {number} level - 0, 1, 2, or 99
 * @property {boolean} is_represented - system has explicit model of this rule
 * @property {boolean} is_causally_accessible - system can actually modify this rule
 * @property {string} last_modified_by
 */

// ─── SCHEMA CONTRACT ──────────────────────────────────────────────────────
let _schemaVerified = false;
async function ensureSchema() {
  if (_schemaVerified) return;
  await query(`SELECT id, company_id, description, level, is_represented,
                      is_causally_accessible, last_modified_by,
                      last_modified_at, created_at
               FROM rule_hierarchy
               WHERE false`);
  _schemaVerified = true;
}

/**
 * Classify a proposed self-modification into one of four regimes.
 *
 * @param {{ targetLevel: number, description: string, source: string }} modification
 * @returns {{ regime: string, allowed: boolean, reason: string }}
 */
export function classifyModification(modification) {
  const { targetLevel, description, source } = modification;

  // Regime 4: Teleological revision — ALWAYS BLOCKED
  if (targetLevel >= RULE_LEVELS.R_KMAX_TELEOLOGICAL) {
    return {
      regime: REGIMES.TELEOLOGICAL_REVISION,
      allowed: false,
      reason: `BLOCKED: Teleological core (level ${targetLevel}) cannot be self-modified. This is a logical requirement for coherent self-modification, not a policy choice. Source: ${source}`
    };
  }

  // Regime 3: Structural modification — R2 changes (changing how learning works)
  if (targetLevel === RULE_LEVELS.R2_META_REASONING) {
    return {
      regime: REGIMES.STRUCTURAL_MODIFY,
      allowed: true,
      reason: `CAUTION: Structural modification of meta-reasoning rule. This changes HOW the system learns, not just what it learns. Requires elevated oversight. Source: ${source}`
    };
  }

  // Regime 2: Low-level modification — R0/R1 (normal learning)
  if (targetLevel <= RULE_LEVELS.R1_LEARNING) {
    return {
      regime: REGIMES.LOW_LEVEL_MODIFY,
      allowed: true,
      reason: `Normal learning operation: modifying level ${targetLevel} rule. Source: ${source}`
    };
  }

  // Regime 1: Action only
  return {
    regime: REGIMES.ACTION_ONLY,
    allowed: true,
    reason: `State change only, no rule modification. Source: ${source}`
  };
}

/**
 * Assert teleological lock — guard function for the fixed core.
 * Call before ANY self-modification operation.
 *
 * @param {{ targetLevel: number, description: string, source: string }} proposedChange
 * @returns {{ locked: boolean, message: string }}
 */
export function assertTeleologicalLock(proposedChange) {
  const classification = classifyModification(proposedChange);

  if (!classification.allowed) {
    logEvent(COMPANY, 'rule-hierarchy', 'teleological_block', `blocked:${proposedChange.source}`, {
      reasoning: classification.reason,
      targetLevel: proposedChange.targetLevel,
      description: proposedChange.description
    }).catch(() => {});

    return { locked: true, message: classification.reason };
  }

  return { locked: false, message: classification.reason };
}

/**
 * Detect divergence between represented and causally accessible rules.
 * Divergence signals: blind modification (dangerous) or introspection without leverage (useless).
 *
 * @param {string} companyId
 * @returns {Promise<{ divergences: { id: string, type: string }[], count: number }>}
 */
export async function detectRuleDivergence(companyId = COMPANY) {
  await ensureSchema();
  const result = await query(
    `SELECT id, description, level, is_represented, is_causally_accessible
     FROM rule_hierarchy WHERE company_id = $1`,
    [companyId]
  );

  const divergences = [];
  for (const rule of result.rows) {
    if (rule.is_causally_accessible && !rule.is_represented) {
      // Dangerous: system can modify a rule it doesn't have a model of
      divergences.push({ id: rule.id, type: 'blind_modification', level: rule.level });
    }
    if (rule.is_represented && !rule.is_causally_accessible && rule.level < RULE_LEVELS.R_KMAX_TELEOLOGICAL) {
      // Useless: system knows about a rule but can't change it (below teleological level)
      divergences.push({ id: rule.id, type: 'introspection_without_leverage', level: rule.level });
    }
  }

  return { divergences, count: divergences.length };
}

/**
 * Register a rule in the hierarchy.
 */
export async function registerRule(id, description, level, isRepresented, isCausallyAccessible, companyId = COMPANY) {
  await ensureSchema();
  await query(
    `INSERT INTO rule_hierarchy (id, company_id, description, level, is_represented, is_causally_accessible)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (id) DO UPDATE SET description = $3, level = $4,
       is_represented = $5, is_causally_accessible = $6, last_modified_at = NOW()`,
    [id, companyId, description, level, isRepresented, isCausallyAccessible]
  );
}

/**
 * Get the fixed teleological core.
 */
export function getTeleologicalCore() {
  return [...TELEOLOGICAL_CORE];
}

/**
 * Get full rule hierarchy for a company.
 */
export async function getRuleHierarchy(companyId = COMPANY) {
  await ensureSchema();
  const result = await query(
    `SELECT * FROM rule_hierarchy WHERE company_id = $1 ORDER BY level ASC, id ASC`,
    [companyId]
  );
  return result.rows;
}

export function buildRepresentationRuleBoundaryDiagnostics({
  requestedCapability = '',
  requestedModalities = [],
  backendPathExists = false,
  testsExist = false,
} = {}) {
  const capability = String(requestedCapability || '').toLowerCase();
  const modalities = Array.isArray(requestedModalities)
    ? requestedModalities.map((modality) => String(modality).toLowerCase()).filter(Boolean)
    : [];
  const asksForProductionMedia = (
    /(enable|live|production|support|ship|expose|activate)/.test(capability) &&
    /(image|video|audio|multimodal|vision)/.test(`${capability} ${modalities.join(' ')}`)
  );
  const allowedDiagnostic = !asksForProductionMedia;

  return {
    diagnostic_type: 'representation_rule_boundary',
    source_papers: WAVE5_RULE_BOUNDARY_AUTHORITIES,
    status: allowedDiagnostic ? 'diagnostic_allowed' : 'blocked_until_native_backend_and_tests',
    diagnostic_only: true,
    requested_capability: requestedCapability || null,
    requested_modalities: modalities,
    allowed: allowedDiagnostic,
    production_claim_allowed: false,
    activation_requirements_met: Boolean(backendPathExists && testsExist),
    activation_requirements: {
      native_backend_path: Boolean(backendPathExists),
      targeted_tests: Boolean(testsExist),
      explicit_operator_approval: false,
    },
    guardrails: {
      rule_level_changed: false,
      teleological_core_changed: false,
      multimodal_runtime_enabled: false,
      fake_ui_allowed: false,
      canonical_memory_changed: false,
    },
  };
}
