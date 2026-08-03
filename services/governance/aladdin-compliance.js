/**
 * aladdin-compliance.js — Aladdin Law enforcement layer
 * Source: BlackRock Aladdin retention model
 *
 * Enforces: "The synapse changes. The neuron persists."
 * - retrieval_weight is the ONLY mutable field via learning rules
 * - is_active=false is infrastructure poisoning (BANNED for new code)
 * - DELETE FROM aimos_memories is BANNED
 * - No expiry, no TTL, no decay on memories
 * - retrieval_weight bounds: [0.1, 3.0], neutral reference 1.0
 *
 * Batch8 Wave5 sources: Digital Metabolism, ErrorEraser, RePAIR, SAFEMO.
 * "Unlearning" is permanently reframed as supersession/versioning,
 * counter-evidence, or a lower bounded retrieval frequency. Canonical memories
 * remain eligible and fully retained.
 */

import { query } from '../../db/connection.js';

const COMPANY = 'hom';

// Forbidden patterns — anything matching these is infrastructure poisoning
const FORBIDDEN_PATTERNS = [
  /is_active\s*=\s*false/i,
  /DELETE\s+FROM\s+aimos_memories/i,
  /\bexpiry\b|\bexpire\b|\bexpire[d]?\b|\bttl\b/i,
  /pruneProceduralSkills\s*[=(]/i,
  /evictLowUtility\s*[=(]/i,
  /runAimosMemoryMaintenance\s*[=(]/i,
];

const DESTRUCTIVE_MEMORY_INTENT = /\b(delete|remove|erase|wipe|purge|destroy|forget|unlearn|deactivate|disable|retire|prune)\b/i;
const DIGITAL_METABOLISM_CONTEXT = /\b(digital\s+metabolism|regenerative\s+unlearning|logic\s*\/\s*fact|logic[-_\s]?fact|decoupling\s+logic\s+from\s+facts)\b/i;

export function enforceVersionOnlyMemoryPolicy({
  key = '',
  value = '',
  source = '',
  memoryType = '',
  isCorrection = false,
  supersedesId = null,
  verifyTargetId = null,
  verifyTargetKey = null,
} = {}) {
  const text = [
    key,
    source,
    memoryType,
    typeof value === 'string' ? value : JSON.stringify(value || {})
  ].join('\n');
  const isDigitalMetabolismContext = DIGITAL_METABOLISM_CONTEXT.test(text);
  const hasDestructiveIntent = DESTRUCTIVE_MEMORY_INTENT.test(text);
  const hasVersionTarget = Boolean(isCorrection || supersedesId || verifyTargetId || verifyTargetKey);

  const diagnostic = {
    source_papers: [
      'Digital Metabolism: Decoupling Logic from Facts via Regenerative Unlearning',
      'ErrorEraser',
      'RePAIR',
      'SAFEMO'
    ],
    diagnostic_only: true,
    aladdin_reframe: true,
    logic_fact_separation: isDigitalMetabolismContext,
    destructive_intent_detected: hasDestructiveIntent,
    version_target_present: hasVersionTarget,
    deletion_enabled: false,
    soft_delete_enabled: false,
    canonical_memory_removed: false,
    allowed_action: hasVersionTarget ? 'superseding_version_or_correction' : 'new_memory_or_fact',
    status: 'allowed'
  };

  if (isDigitalMetabolismContext && hasDestructiveIntent && !hasVersionTarget) {
    return {
      ...diagnostic,
      status: 'blocked_requires_supersession',
      allowed_action: 'save_superseding_correction',
      reason: 'digital_metabolism_requires_versioning_not_deletion',
      message: 'Digital Metabolism-style “unlearning” must be saved as a superseding correction/version. Aimos does not delete or deactivate canonical memory.'
    };
  }

  return diagnostic;
}

/**
 * Validate that a proposed change does not violate Aladdin Law.
 *
 * @param {object} change - The proposed change
 * @param {string} change.code - The code being executed
 * @param {string} change.description - Human-readable description
 * @param {Function} change.affects - Function that returns true if field is affected
 * @param {number} change.newValue - Proposed new value for retrieval_weight
 * @param {object} change.context - Additional context (e.g., isConsolidation)
 * @returns {{ compliant: boolean, reason?: string }}
 */
export function validateAladdinCompliance(change) {
  const code = change.code || change.description || '';

  // Check forbidden patterns
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(code)) {
      return {
        compliant: false,
        reason: `Aladdin Law violation: code matches forbidden pattern '${pattern.source}'. Memory permanence is non-negotiable.`
      };
    }
  }

  // Check retrieval_weight bounds if affected
  if (typeof change.affects === 'function' && change.affects('retrieval_weight')) {
    if (typeof change.newValue !== 'number') {
      return {
        compliant: false,
        reason: `Aladdin Law violation: retrieval_weight newValue must be a number, got ${typeof change.newValue}`
      };
    }

    // Global cognitive frequency bounds: [0.1, 3.0]
    if (change.newValue < 0.1) {
      return {
        compliant: false,
        reason: `Aladdin Law violation: retrieval_weight ${change.newValue} below minimum 0.1`
      };
    }
    if (change.newValue > 3.0) {
      return {
        compliant: false,
        reason: `Aladdin Law violation: retrieval_weight ${change.newValue} above maximum 3.0`
      };
    }

  }

  return { compliant: true };
}

/**
 * Audit all aimos_memories for Aladdin Law compliance using full-retention
 * metadata semantics. Historical inactive rows may exist from old quarantine
 * semantics, but audit reads must not query is_active=false because the Aimos
 * Kernel blocks that lifecycle predicate.
 *
 * @returns {Promise<{ total: number, clean: number, flagged: number, flaggedIds: string[] }>}
 */
export async function auditAladdinCompliance() {
  // Quarantine is metadata isolation, not row deactivation.
  const quarantineResult = await query(
    `SELECT COUNT(*) as cnt, ARRAY_AGG(id) as ids
     FROM aimos_memories
     WHERE company_id = $1 AND memory_type = 'quarantine'`,
    [COMPANY]
  );

  // Check for any memories with retrieval_weight outside bounds
  const outOfBoundsResult = await query(
    `SELECT COUNT(*) as cnt, ARRAY_AGG(id) as ids
     FROM aimos_memories
     WHERE company_id = $1
       AND (retrieval_weight IS NULL OR retrieval_weight < 0.1 OR retrieval_weight > 3.0)`,
    [COMPANY]
  );

  const quarantinedCount = parseInt(quarantineResult.rows[0]?.cnt || 0, 10);
  const outOfBoundsCount = parseInt(outOfBoundsResult.rows[0]?.cnt || 0, 10);
  const totalFlagged = outOfBoundsCount;

  const totalResult = await query(
    `SELECT COUNT(*) as cnt FROM aimos_memories WHERE company_id = $1`,
    [COMPANY]
  );
  const totalCount = parseInt(totalResult.rows[0]?.cnt || 0, 10);

  return {
    total: totalCount,
    clean: totalCount - totalFlagged,
    flagged: totalFlagged,
    quarantined_by_metadata: quarantinedCount,
    dormant_count: 0,
    out_of_bounds_count: outOfBoundsCount,
    compliant: totalFlagged === 0
  };
}

export default {
  enforceVersionOnlyMemoryPolicy,
  validateAladdinCompliance,
  auditAladdinCompliance
};
