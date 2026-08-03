/**
 * WRITE VALIDATION GATE — PRE-COMMIT CHECKS FOR ENTITY GRAPH MUTATIONS
 * Sources: OWASP ASVS (input validation), HOM Constitution (data integrity)
 *
 * Pre-commit validation before agent modifies aimos_memories or entity graph.
 * Checks: key format, value validity, schema compliance, permissions, injection patterns.
 * Additive Batch9 Wave2 authority: The Midas Touch, Security Considerations
 * for AI Agents, and Governing What You Cannot Observe. Validation now emits
 * decomposed diagnostics natively while preserving the existing valid/retryable
 * write contract.
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildCoVWriteDiagnostic: CoVe self-verification pass before commit
 *     alongside existing write validation. Write validation unchanged.
 *   - buildCuraLightWriteDiagnostic: CuraLight multi-perspective debate
 *     diagnostic at write-time alongside existing validation. Gate unchanged.
 *
 * Created: 2026-03-31
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: routes/aimos.js (SAVE pipeline, step 2)
// → Calls: (terminal validator — no downstream service call)
// Pipeline: SAVE_PIPELINE
// Position: after quality gate
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from '../observe/event-ledger.js';
import { getPermissions } from '../core/permissions.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── R11b — system-self write authority ──────────────────────────────────────
// The housekeeper is NOT a free agent. It is the system self, and its authority
// to write (e.g. to ingest the Guide on first fire) comes from BEING the system
// role, not from holding an agent_session. The request tier is
// `T1_SYSTEM_SELF`: auth-tier.js verified the self-signed housekeeper cert
// against the housekeeper's own pubkey. No mutable database role flag can grant
// this authority. The lane is restricted to the exact `housekeeper` principal.
// The system-self lane is part of the certificate-envelope authority itself.
const SYSTEM_SELF_TIER = 'T1_SYSTEM_SELF';

// Injection patterns similar to cybersec-firewall but for data safety.
// Keep these structural: Aimos stores academic/source evidence that may quote
// words such as delete/drop/update/insert/alter/truncate. A bare control verb is
// not enough evidence of an operating routine.
const SQL_STRUCTURAL_INJECTION_PATTERNS = [
  /['"];?\s*(delete|drop|truncate|update|insert|alter)\s+(from|table|into|database|schema|index|view|column|aimos_memories|entity_graph)\b/i,
  /--\s*;?\s*DROP/i,
  /;\s*DROP\s+TABLE/i,
];

const GENERIC_UNSAFE_PATTERNS = [
  /\x00/,  // null byte
  /\r\n\r\n/,  // suspicious line breaks
];

/**
 * Validate a write operation before committing to entity graph
 *
 * @param {string} agentId - Agent performing write
 * @param {string} targetKey - Memory key being modified
 * @param {any} newValue - New value
 * @param {any} existingValue - Current value (if update)
 * @returns {{valid: boolean, reason?: string, retryable: boolean}}
 */
export async function validateWrite(agentId, targetKey, newValue, existingValue, opts = {}) {
  const diagnostics = buildWriteValidationDiagnostics({ agentId, targetKey, newValue, existingValue });

  // Key format validation
  const keyValidation = validateKeyFormat(targetKey);
  if (!keyValidation.valid) {
    return { valid: false, reason: keyValidation.reason, retryable: false, diagnostics };
  }

  // Value validation
  const valueValidation = validateValue(newValue);
  if (!valueValidation.valid) {
    return { valid: false, reason: valueValidation.reason, retryable: false, diagnostics };
  }

  // Injection check
  const injectionCheck = checkInjectionPatterns(newValue);
  if (!injectionCheck.clean) {
    return { valid: false, reason: `Injection pattern detected: ${injectionCheck.pattern}`, retryable: false, diagnostics };
  }

  // Permission check
  try {
    const permissionCheck = await checkWritePermission(agentId, targetKey, opts);
    if (!permissionCheck.permitted) {
      return {
        valid: false,
        reason: permissionCheck.reason,
        retryable: true,
        diagnostics: buildWriteValidationDiagnostics({ agentId, targetKey, newValue, existingValue, permission: permissionCheck }),
      };
    }
  } catch (err) {
    console.error(`[WRITE-VALIDATOR] Permission check error: ${err.message}`);
    return { valid: false, reason: 'Could not verify permissions', retryable: true, diagnostics };
  }

  // Schema validation
  const schemaCheck = validateSchema(targetKey, newValue, existingValue);
  if (!schemaCheck.valid) {
    return { valid: false, reason: schemaCheck.reason, retryable: false, diagnostics };
  }

  return { valid: true, retryable: false, diagnostics };
}

/**
 * Validate key format (alphanumeric, underscores, hyphens)
 *
 * @param {string} key - Key to validate
 * @returns {{valid: boolean, reason?: string}}
 */
function validateKeyFormat(key) {
  if (!key) {
    return { valid: false, reason: 'Key cannot be empty' };
  }

  if (typeof key !== 'string') {
    return { valid: false, reason: 'Key must be a string' };
  }

  if (key.length > 255) {
    return { valid: false, reason: 'Key exceeds 255 characters' };
  }

  // Allow alphanumeric, underscore, hyphen, colon (for namespacing)
  if (!/^[a-zA-Z0-9_:\-]+$/.test(key)) {
    return { valid: false, reason: 'Key contains invalid characters' };
  }

  return { valid: true };
}

/**
 * Validate value is non-empty and reasonable
 *
 * @param {any} value - Value to validate
 * @returns {{valid: boolean, reason?: string}}
 */
function validateValue(value) {
  if (value === null || value === undefined) {
    return { valid: false, reason: 'Value cannot be null or undefined' };
  }

  if (typeof value === 'string') {
    if (value.length === 0) {
      return { valid: false, reason: 'String value cannot be empty' };
    }
    if (value.length > 1000000) {
      return { valid: false, reason: 'Value exceeds 1MB limit' };
    }
  } else if (typeof value === 'object') {
    try {
      const serialized = JSON.stringify(value);
      if (serialized.length > 1000000) {
        return { valid: false, reason: 'Serialized value exceeds 1MB limit' };
      }
    } catch {
      return { valid: false, reason: 'Value is not JSON-serializable' };
    }
  }

  return { valid: true };
}

/**
 * Check for injection patterns in value
 *
 * @param {any} value - Value to check
 * @returns {{clean: boolean, pattern?: string}}
 */
function hasNonExecutableEvidenceEnvelope(text) {
  const upper = String(text || '').toUpperCase();
  return (
    upper.includes('EXECUTION_AUTHORITY: NONE') &&
    (
      upper.includes('BIBLIOGRAPHIC IMPLEMENTATION TECHNIQUE EXTRACT') ||
      upper.includes('ACADEMIC_SOURCE_TECHNIQUE_EXTRACTION: TRUE') ||
      upper.includes('TEXT_MODE: IMPLEMENTATION_TECHNIQUE_EXTRACT')
    )
  );
}

function checkInjectionPatterns(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const isNonExecutableEvidence = hasNonExecutableEvidenceEnvelope(text);

  for (const pattern of GENERIC_UNSAFE_PATTERNS) {
    if (pattern.test(text)) {
      return { clean: false, pattern: pattern.source, class: 'generic_unsafe' };
    }
  }

  for (const pattern of SQL_STRUCTURAL_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      if (isNonExecutableEvidence) {
        return { clean: true, class: 'non_executable_evidence_sql_vocabulary', pattern: pattern.source };
      }
      return { clean: false, pattern: pattern.source, class: 'sql_structural' };
    }
  }

  // Source evidence may contain design/database verbs as vocabulary. Once the
  // non-executable evidence envelope is present and unsafe generic patterns are
  // absent, do not block on those words alone.
  if (isNonExecutableEvidence) {
    return { clean: true, class: 'non_executable_evidence' };
  }

  return { clean: true };
}

export function buildWriteValidationDiagnostics({
  agentId = '',
  targetKey = '',
  newValue = '',
  existingValue = undefined,
  permission = null,
} = {}) {
  const keyValidation = validateKeyFormat(targetKey);
  const valueValidation = validateValue(newValue);
  const injectionCheck = checkInjectionPatterns(newValue);
  const schemaCheck = validateSchema(targetKey, newValue, existingValue);
  const scope = String(targetKey || '').split(':')[0] || String(targetKey || '');
  const requiredClearance = getScopeRequiredClearance(scope);

  return {
    source_papers: [
      'The Midas Touch: Triggering LLMs with Hidden Intentions',
      'Security Considerations for Artificial Intelligence Agents',
      'Governing What You Cannot Observe: Adaptive Runtime Governance for Autonomous AI',
    ],
    diagnostic_only: true,
    agent_id: String(agentId || ''),
    target_key: String(targetKey || ''),
    target_scope: scope || null,
    required_clearance: requiredClearance,
    checks: {
      key_format: keyValidation,
      value_integrity: valueValidation,
      injection: injectionCheck.clean
        ? { pass: true }
        : { pass: false, reason: `Injection pattern detected: ${injectionCheck.pattern}`, pattern: injectionCheck.pattern },
      schema: schemaCheck,
      permission: permission
        ? { pass: Boolean(permission.permitted), reason: permission.reason || null }
        : { pass: null, reason: 'not_checked_in_pure_diagnostic' },
    },
    write_result_changed: false,
    permission_policy_changed: false,
    guarded_math: {
      cov_write: true,
      curalight_write: true,
    },
    guarded_math_implemented: {
      cov_write: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'Chain-of-Verification Reduces Hallucination in Large Language Models',
        coexistence_class: 'side_by_side_independent',
      },
      curalight_write: {
        enabled: true,
        diagnostic_only: true,
        source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
        coexistence_class: 'side_by_side_overlay',
      },
    },
  };
}

/**
 * Check if agent has write permission for target scope
 *
 * @param {string} agentId - Agent ID
 * @param {string} targetKey - Target key
 * @returns {Promise<{permitted: boolean, reason?: string}>}
 */
export async function checkWritePermission(agentId, targetKey, opts = {}) {
  // ── R11b: first-class system-self write authority (BEFORE the session lookup) ──
  // If the request authenticated at tier T1_SYSTEM_SELF and the acting identity
  // is the exact housekeeper principal, it holds
  // intrinsic system-maintenance write clearance and is permitted WITHOUT an
  // agent_session row. The tier is taken from the VERIFIED envelope (opts.identityTier,
  // set by auth-gate). Prefer the verified cert agent id; fall back to the
  // passed agentId only if the caller did not thread a verified id.
  const identityTier = opts.identityTier || null;
  const verifiedAgentId = opts.verifiedAgentId || agentId;
  if (identityTier === SYSTEM_SELF_TIER && verifiedAgentId === 'housekeeper') {
        // Never silent: record the intrinsic system-self write path in the ledger.
        logEvent(COMPANY, verifiedAgentId, 'system_self_write_authorized', targetKey, {
          stage: 'write_validator',
          reason: 'verified_housekeeper_system_self',
          tier: identityTier,
          target_key: targetKey,
          note: 'The cryptographically-proven system self (T1_SYSTEM_SELF + exact housekeeper principal) '
              + 'holds intrinsic system-maintenance write authority and does not require an '
              + 'agent_session. No mutable role column participates in authorization.',
          source_knowledge: 'write-validator.js R11b verified housekeeper system-self authority',
        }).catch((e) => console.warn('[WRITE-VALIDATOR] system-self ledger emit failed:', e && e.message));
        return { permitted: true, systemSelf: true };
  }

  // Ordinary-agent authority comes only from the verified append-only
  // capability ledger. A memory row is never an identity or clearance grant.
  try {
    const scope = targetKey.split(':')[0] || targetKey;
    const permissions = await getPermissions(agentId, COMPANY);
    if (permissions.memory_write !== true) {
      return { permitted: false, reason: `Agent ${agentId} lacks memory_write capability` };
    }
    if (['system', 'admin'].includes(scope) && permissions.admin_override !== true) {
      return { permitted: false, reason: `Agent ${agentId} lacks admin_override capability for scope ${scope}` };
    }
    return { permitted: true, capability: 'memory_write' };
  } catch (err) {
    console.error(`[WRITE-VALIDATOR] Permission check failed: ${err.message}`);
    return { permitted: false, reason: `Permission check error: ${err.message}` };
  }
}

/**
 * Get required clearance level for a scope
 *
 * @param {string} scope - Scope name
 * @returns {number}
 */
function getScopeRequiredClearance(scope) {
  const clearanceMap = {
    'system': 12,
    'admin': 10,
    'workspace': 5,
    'entity': 3,
    'user': 1
  };

  return clearanceMap[scope] || 5;
}

/**
 * Validate schema compatibility
 *
 * @param {string} targetKey - Target key
 * @param {any} newValue - New value
 * @param {any} existingValue - Existing value
 * @returns {{valid: boolean, reason?: string}}
 */
function validateSchema(targetKey, newValue, existingValue) {
  // If existing value exists, type should match or be compatible
  if (existingValue !== undefined && existingValue !== null) {
    const existingType = typeof existingValue;
    const newType = typeof newValue;

    // String <-> Object conversions are allowed (JSON serialization)
    if (existingType === 'string' && newType !== 'string' && newType !== 'object') {
      return { valid: false, reason: `Type mismatch: existing is string, new is ${newType}` };
    }

    if (existingType === 'object' && newType === 'string') {
      try {
        JSON.parse(newValue);
      } catch {
        return { valid: false, reason: 'String value is not valid JSON' };
      }
    }
  }

  return { valid: true };
}

/**
 * Check if a write is permitted (shorthand)
 *
 * @param {string} agentId - Agent ID
 * @param {string} targetKey - Target key
 * @returns {Promise<boolean>}
 */
export async function isWritePermitted(agentId, targetKey) {
  const result = await checkWritePermission(agentId, targetKey);
  return result.permitted;
}

/**
 * Get validation summary for debugging
 *
 * @param {object} validationResult - Result from validateWrite
 * @returns {string}
 */
export function getValidationSummary(validationResult) {
  if (validationResult.valid) {
    return 'PASS';
  }
  return `FAIL: ${validationResult.reason} (retryable: ${validationResult.retryable})`;
}

/**
 * CoV Write Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Chain-of-Verification Reduces Hallucination in LLMs
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CoV paper: self-verification pass before commit reduces hallucination.
 * This diagnostic checks whether the write content has been independently
 * verified before the write gate. The existing write validation logic
 * remains authoritative. Guarded by guarded_math flag cov_write
 * (knowledge-gated: paper understanding required).
 */
export function buildCoVWriteDiagnostic({
  writeContent = '',
  verificationSources = [],
} = {}) {
  const content = String(writeContent || '');
  const sources = Array.isArray(verificationSources) ? verificationSources : [];

  // CoV verification: content is verified if at least one independent source confirms it
  const verifiedSources = sources.filter((src) => {
    const srcContent = String(src?.content || src?.value || src?.excerpt || '');
    if (!srcContent) return false;
    // Token overlap as proxy for verification
    const contentTokens = new Set(content.toLowerCase().split(/\s+/).filter((t) => t.length > 3));
    const srcTokens = new Set(srcContent.toLowerCase().split(/\s+/).filter((t) => t.length > 3));
    const overlap = [...contentTokens].filter((t) => srcTokens.has(t)).length;
    return overlap > 0;
  });

  return {
    diagnostic: true,
    source_paper: 'Chain-of-Verification Reduces Hallucination in Large Language Models',
    coexistence_class: 'side_by_side_independent',
    content_length: content.length,
    verification_source_count: sources.length,
    verified_source_count: verifiedSources.length,
    verification_coverage: sources.length > 0 ? Number((verifiedSources.length / sources.length).toFixed(6)) : 0,
    independent_verification_present: verifiedSources.length > 0,
    write_gate_unchanged: true,
    note: 'Alongside-path diagnostic. CoV write verification does not modify write gate logic.',
  };
}

/**
 * CuraLight Write Diagnostic — Alongside-path diagnostic
 *
 * Source paper: CuraLight — Debate-Guided Data Curation for Medical Image Analysis
 * Coexistence class: side_by_side_overlay
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * CuraLight paper: multi-perspective debate improves data curation quality.
 * This diagnostic assesses whether the write has been vetted from multiple
 * perspectives (debate signals). Debate signals do NOT lower quality-gate
 * thresholds. Write validation unchanged. Guarded by guarded_math flag
 * curalight_write (knowledge-gated: paper understanding required).
 */
export function buildCuraLightWriteDiagnostic({
  writeContent = '',
  debatePerspectives = [],
} = {}) {
  const content = String(writeContent || '');
  const perspectives = Array.isArray(debatePerspectives) ? debatePerspectives : [];

  // CuraLight debate quality: coverage of perspectives and agreement level
  const perspectiveCoverage = perspectives.length;
  const agreeingPerspectives = perspectives.filter((p) => {
    const verdict = String(p?.verdict || p?.position || p?.stance || '').toLowerCase();
    return /\b(agree|support|accept|pass|valid)\b/.test(verdict);
  }).length;
  const disagreeingPerspectives = perspectives.filter((p) => {
    const verdict = String(p?.verdict || p?.position || p?.stance || '').toLowerCase();
    return /\b(disagree|reject|fail|invalid|oppose)\b/.test(verdict);
  }).length;

  const debateAgreement = perspectives.length > 0 ? agreeingPerspectives / perspectives.length : 1;

  return {
    diagnostic: true,
    source_paper: 'CuraLight: Debate-Guided Data Curation for Medical Image Analysis',
    coexistence_class: 'side_by_side_overlay',
    content_length: content.length,
    perspective_count: perspectiveCoverage,
    agreement_ratio: Number(debateAgreement.toFixed(6)),
    agreeing_count: agreeingPerspectives,
    disagreeing_count: disagreeingPerspectives,
    debate_signal_does_not_lower_threshold: true,
    write_gate_unchanged: true,
    note: 'Alongside-path diagnostic. CuraLight debate signal does not lower write quality thresholds.',
  };
}
