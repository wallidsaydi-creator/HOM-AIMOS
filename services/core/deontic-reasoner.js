/**
 * deontic-reasoner.js — CODORD formal deontic logic engine
 * Source: DARPA CODORD program
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (Intent processing phase)
 * 2. → Pulls from: directives.json (Normative core)
 * 3. → Pushes to: aimos_events (Conflict and violation logs)
 * 4. ↔ Interacts with: services/orchestration/symbolic-reasoner.js (Symbolic traces)
 *
 * LOGIC GUIDE: Implements formal deontic operators (O/P/F/D) with NL-to-logic translation
 * AND structured schema path for JSON-structured rules. Handles normative closure,
 * CTD (Contrary-to-Duty), negation scope, and conflict detection.
 *
 * Phase 3 fix (2026-05-01):
 * - Added parseStructuredRule() for JSON-structured deontic rules
 *   Paper: CODORD (DARPA) — structured schema path for programmatic norm registration
 * - registerNorm() now accepts string OR object
 * - Reordered NL_PATTERNS: Forbidden before CTD (prevents CTD shadowing Forbidden)
 *   Paper: Deontic Logic (von Wright 1951) — F(φ) takes precedence over D(ψ,φ) evaluation
 * - Added negation scope detection (NEGATION_SCOPES)
 *   Paper: Deontic Logic negation semantics — ¬O(φ) ≠ O(¬φ), maps to P(¬φ)
 * - Changed silent fallback from OBLIGATORY to UNKNOWN (priority 0)
 *   Paper: Open World Assumption — unrecognised text should not default to obligation
 * - Improved _normMatchesAction with exact-match priority tier
 *   Paper: Normative Closure (Alchourrón & Bulygin) — specificity ordering in norm application
 * - Added loadSocialLaws() boot-time loader for directives.json
 *   Paper: CODORD (DARPA) — social laws as structured norms, not NL interpretation
 */
import { readFileSync } from 'fs';

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────

// ← Called by: symbolic-reasoner.js, boot-integrity.js
// Pipeline: AGENT_RUN | Position: Post-run deontic logic (via symbolic-reasoner)
// ─────────────────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DEONTIC_CONSTANTS = Object.freeze({
  OBLIGATORY: 'O',
  PERMITTED:  'P',
  FORBIDDEN:  'F',
  CTD:        'D',
  UNKNOWN:    'UNKNOWN',  // Phase 3: explicit unknown operator (was silent OBLIGATORY)
});

// ---------------------------------------------------------------------------
// Internal norm base (module-level state, cleared via clearNorms())
// ---------------------------------------------------------------------------

/** @type {Map<string, { id: string, norm: ReturnType<typeof parseDeonticRule>, priority: number }>} */
const _normBase = new Map();

// ---------------------------------------------------------------------------
// Negation scope detection (Phase 3 fix)
// Patterns that indicate a negated obligation → should be PERMITTED, not OBLIGATORY
// ---------------------------------------------------------------------------

const NEGATION_SCOPES = [
  /is\s+not\s+(?:required|obliged|obligated)\s+to/i,
  /does\s+not\s+(?:need|have)\s+to/i,
  /need\s+not/i,
  /not\s+(?:required|obligatory|mandatory)\s+to/i,
  /is\s+not\s+obligated/i,
  /no\s+(?:obligation|requirement|need)\s+to/i,
];

// ---------------------------------------------------------------------------
// NL keyword patterns (order matters — more specific patterns first)
// Phase 3 fix: CTD moved AFTER Forbidden to prevent "must not" shadowing
// ---------------------------------------------------------------------------

/**
 * Each entry: { pattern: RegExp, operator: string, formulaGroup: number }
 * formulaGroup points to the capture group that carries the action/formula text.
 */
const NL_PATTERNS = [
  // Forbidden — compound keywords first (most specific)
  {
    pattern: /(?:must\s+not|must\s+never|shall\s+not|shall\s+never|is\s+not\s+allowed\s+to|is\s+prohibited\s+from|is\s+forbidden\s+(?:from|to)?)\s+(.+)/i,
    operator: DEONTIC_CONSTANTS.FORBIDDEN,
    formulaGroup: 1,
  },
  {
    pattern: /(?:^|\baction\s+is\s+)(?:forbidden|prohibited)\b[:\s]+(.+)/i,
    operator: DEONTIC_CONSTANTS.FORBIDDEN,
    formulaGroup: 1,
  },

  // CTD: "if [something] is violated, [subject] must ..."
  // Phase 3: moved AFTER Forbidden patterns so "must not" doesn't get caught
  {
    pattern: /if\s+(?:the\s+)?(.+?)\s+(?:obligation\s+)?(?:is\s+)?violated[,;]?\s+(?:then\s+)?(?:\S+\s+)*(?:must|shall|is\s+required\s+to)\s+(.+)/i,
    operator: DEONTIC_CONSTANTS.CTD,
    formulaGroup: 2,
    ctdViolatedGroup: 1,
  },

  // Obligatory (after Forbidden and CTD so they don't get shadowed)
  {
    pattern: /(?:must|shall|is\s+required\s+to|is\s+obliged\s+to|is\s+obligated\s+to|has\s+to)\s+(.+)/i,
    operator: DEONTIC_CONSTANTS.OBLIGATORY,
    formulaGroup: 1,
  },

  // Permitted — least specific
  {
    pattern: /(?:may|is\s+allowed\s+to|is\s+permitted\s+to|can|is\s+authorized\s+to)\s+(.+)/i,
    operator: DEONTIC_CONSTANTS.PERMITTED,
    formulaGroup: 1,
  },
  {
    pattern: /(?:^|\baction\s+is\s+)(?:permitted|allowed|permissible)\b[:\s]+(.+)/i,
    operator: DEONTIC_CONSTANTS.PERMITTED,
    formulaGroup: 1,
  },
];

// ---------------------------------------------------------------------------
// parseDeonticRule (NL path)
// ---------------------------------------------------------------------------

/**
 * Parse a natural-language normative statement into a deontic logic form.
 *
 * Phase 3 fixes:
 * - CTD pattern no longer shadows Forbidden patterns (pattern order fixed)
 * - Negation scope detection: "is not required to" → PERMITTED, not OBLIGATORY
 * - Silent fallback is now UNKNOWN (priority 0) instead of OBLIGATORY (priority 1)
 *
 * @param {string} text  Raw NL rule text.
 * @returns {{ operator: string, formula: string, raw: string, priority: number,
 *             ctd_violated?: string, parse_path: string }}
 */
export function parseDeonticRule(text) {
  if (typeof text !== 'string' || !text.trim()) {
    throw new TypeError('parseDeonticRule: text must be a non-empty string');
  }

  const trimmed = text.trim();

  // Phase 3: Check negation scope before pattern matching
  for (const negPattern of NEGATION_SCOPES) {
    if (negPattern.test(trimmed)) {
      return {
        operator: DEONTIC_CONSTANTS.PERMITTED,
        formula: _normalizeFormula(trimmed),
        raw: trimmed,
        priority: 1,
        parse_path: 'negation_scope',
      };
    }
  }

  for (const entry of NL_PATTERNS) {
    const match = trimmed.match(entry.pattern);
    if (match) {
      const formula = _normalizeFormula(match[entry.formulaGroup] || '');
      const result = {
        operator: entry.operator,
        formula,
        raw: trimmed,
        priority: 1,
        parse_path: 'nl_pattern',
      };
      if (entry.operator === DEONTIC_CONSTANTS.CTD && entry.ctdViolatedGroup) {
        result.ctd_violated = _normalizeFormula(match[entry.ctdViolatedGroup] || '');
      }
      return result;
    }
  }

  // Phase 3: Changed from silent OBLIGATORY to explicit UNKNOWN with priority 0
  return {
    operator: DEONTIC_CONSTANTS.UNKNOWN,
    formula: _normalizeFormula(trimmed),
    raw: trimmed,
    priority: 0,
    parse_path: 'fallback',
  };
}

// ---------------------------------------------------------------------------
// parseStructuredRule (Phase 3: structured schema path)
// ---------------------------------------------------------------------------

/**
 * Parse a JSON-structured deontic rule into the same shape as parseDeonticRule.
 *
 * Accepts an object with explicit operator, formula, and optional fields.
 * This path is used by directives.json and programmatic callers who know the
 * operator and formula exactly — no NL pattern matching needed.
 *
 * @param {{ operator: string, formula: string, priority?: number, ctd_violated?: string }} rule
 * @returns {{ operator: string, formula: string, raw: string, priority: number,
 *             ctd_violated?: string, parse_path: string }}
 */
export function parseStructuredRule(rule) {
  if (!rule || typeof rule !== 'object') {
    throw new TypeError('parseStructuredRule: rule must be a non-empty object');
  }

  const validOperators = Object.values(DEONTIC_CONSTANTS);
  if (!validOperators.includes(rule.operator)) {
    throw new TypeError(`parseStructuredRule: operator must be one of ${validOperators.join(', ')}, got "${rule.operator}"`);
  }

  if (typeof rule.formula !== 'string' || !rule.formula.trim()) {
    throw new TypeError('parseStructuredRule: formula must be a non-empty string');
  }

  const result = {
    operator: rule.operator,
    formula: _normalizeFormula(rule.formula),
    raw: rule.formula,
    priority: typeof rule.priority === 'number' ? rule.priority : 1,
    parse_path: 'structured',
  };

  if (rule.operator === DEONTIC_CONSTANTS.CTD && rule.ctd_violated) {
    result.ctd_violated = _normalizeFormula(rule.ctd_violated);
  }

  return result;
}

// ---------------------------------------------------------------------------
// registerNorm / clearNorms
// ---------------------------------------------------------------------------

/**
 * Add a norm to the norm base.
 *
 * Phase 3: Now accepts either a string (NL path) or an object (structured path).
 *
 * @param {string} id       Unique norm identifier.
 * @param {string|object} textOrRule  NL rule text OR structured rule object.
 * @param {number} priority Higher number = higher priority (default 1).
 * @returns {{ id: string, norm: ReturnType<typeof parseDeonticRule> }}
 */
export function registerNorm(id, textOrRule, priority = 1) {
  if (typeof id !== 'string' || !id.trim()) {
    throw new TypeError('registerNorm: id must be a non-empty string');
  }
  const norm = typeof textOrRule === 'object'
    ? parseStructuredRule(textOrRule)
    : parseDeonticRule(textOrRule);
  norm.priority = typeof priority === 'number' ? priority : 1;
  _normBase.set(id, { id, norm });
  return { id, norm };
}

/**
 * Clear all registered norms (useful for testing).
 */
export function clearNorms() {
  _normBase.clear();
}

// ---------------------------------------------------------------------------
// evaluatePermission
// ---------------------------------------------------------------------------

/**
 * Evaluate whether an action is permitted under the current norm base.
 *
 * Evaluation order:
 *   1. Collect applicable norms (those whose formula matches the action).
 *   2. Sort by priority descending — highest priority wins.
 *   3. First matching norm determines the verdict.
 *   4. If no norm matches → normative closure → default-forbidden.
 *   5. Phase 3: UNKNOWN operator (unmatched NL text) → also default-forbidden.
 *
 * @param {string} action   Action string to evaluate.
 * @param {object} [context]  Optional context (reserved for future use).
 * @returns {{
 *   permitted: boolean,
 *   operator: string,
 *   norm_id: string|null,
 *   reason: string,
 *   derivation: string[]
 * }}
 */
export function evaluatePermission(action, context = {}) {
  if (typeof action !== 'string' || !action.trim()) {
    throw new TypeError('evaluatePermission: action must be a non-empty string');
  }

  const normalizedAction = _normalizeFormula(action);
  const derivation = [`evaluatePermission("${normalizedAction}")`];

  // Collect applicable norms sorted by priority (highest first)
  const applicable = _getSortedApplicableNorms(normalizedAction, context, derivation);

  if (applicable.length === 0) {
    derivation.push('No applicable norm found — applying normative closure.');
    derivation.push('Result: default-forbidden');
    return {
      permitted: false,
      operator: 'default-forbidden',
      norm_id: null,
      reason: 'Normative closure: no norm explicitly covers this action.',
      derivation,
    };
  }

  // First match wins (already sorted by priority)
  const { id, norm } = applicable[0];

  derivation.push(`Matched norm [${id}] (priority=${norm.priority}): ${_fmtNorm(norm)}`);

  switch (norm.operator) {
    case DEONTIC_CONSTANTS.PERMITTED:
      derivation.push(`P(${norm.formula}) — action is explicitly permitted.`);
      return {
        permitted: true,
        operator: DEONTIC_CONSTANTS.PERMITTED,
        norm_id: id,
        reason: `Explicitly permitted by norm [${id}]: "${norm.raw}"`,
        derivation,
      };

    case DEONTIC_CONSTANTS.OBLIGATORY:
      derivation.push(`O(${norm.formula}) — action is obligatory, hence also permitted.`);
      return {
        permitted: true,
        operator: DEONTIC_CONSTANTS.OBLIGATORY,
        norm_id: id,
        reason: `Obligatory (and therefore permitted) by norm [${id}]: "${norm.raw}"`,
        derivation,
      };

    case DEONTIC_CONSTANTS.FORBIDDEN:
      derivation.push(`F(${norm.formula}) — action is forbidden.`);
      return {
        permitted: false,
        operator: DEONTIC_CONSTANTS.FORBIDDEN,
        norm_id: id,
        reason: `Forbidden by norm [${id}]: "${norm.raw}"`,
        derivation,
      };

    case DEONTIC_CONSTANTS.CTD: {
      // CTD obligation: violated primary duty — the fallback obligation is itself obligatory
      derivation.push(
        `D(${norm.ctd_violated || '?'}, ${norm.formula}) — contrary-to-duty obligation applies.`
      );
      return {
        permitted: true,
        operator: DEONTIC_CONSTANTS.CTD,
        norm_id: id,
        reason: `CTD fallback obligation by norm [${id}]: "${norm.raw}"`,
        derivation,
      };
    }

    case DEONTIC_CONSTANTS.UNKNOWN:
      derivation.push(`UNKNOWN(${norm.formula}) — unrecognised text treated as default-forbidden.`);
      return {
        permitted: false,
        operator: DEONTIC_CONSTANTS.UNKNOWN,
        norm_id: id,
        reason: `Unrecognised text (no NL pattern matched) by norm [${id}]: "${norm.raw}"`,
        derivation,
      };

    default:
      derivation.push(`Unknown operator "${norm.operator}" — defaulting to forbidden.`);
      return {
        permitted: false,
        operator: 'default-forbidden',
        norm_id: id,
        reason: `Unrecognised deontic operator in norm [${id}].`,
        derivation,
      };
  }
}

// ---------------------------------------------------------------------------
// detectConflicts
// ---------------------------------------------------------------------------

/**
 * Detect normative conflicts in the current norm base.
 *
 * Detects:
 *   - obligation_forbidden: same formula appears under both O and F.
 *   - ctd_loop: a CTD rule's target formula is the same as its own formula
 *               (A is obligatory because A is violated — circular).
 *
 * @returns {Array<{
 *   norm1_id: string,
 *   norm2_id: string,
 *   conflict_type: 'obligation_forbidden'|'ctd_loop',
 *   formula: string
 * }>}
 */
export function detectConflicts() {
  const conflicts = [];

  // Group norms by normalised formula
  /** @type {Map<string, Array<{id: string, norm: object}>>} */
  const byFormula = new Map();

  for (const [id, entry] of _normBase) {
    const key = entry.norm.formula;
    if (!byFormula.has(key)) byFormula.set(key, []);
    byFormula.get(key).push({ id, norm: entry.norm });
  }

  // obligation_forbidden: O(φ) ∧ F(φ)
  for (const [formula, entries] of byFormula) {
    const obligations = entries.filter(e => e.norm.operator === DEONTIC_CONSTANTS.OBLIGATORY);
    const prohibitions = entries.filter(e => e.norm.operator === DEONTIC_CONSTANTS.FORBIDDEN);

    for (const o of obligations) {
      for (const f of prohibitions) {
        conflicts.push({
          norm1_id: o.id,
          norm2_id: f.id,
          conflict_type: 'obligation_forbidden',
          formula,
        });
      }
    }
  }

  // ctd_loop: D(φ, φ) — the CTD norm's violated formula equals its own formula
  for (const [id, entry] of _normBase) {
    const { norm } = entry;
    if (norm.operator === DEONTIC_CONSTANTS.CTD) {
      if (norm.ctd_violated && norm.ctd_violated === norm.formula) {
        conflicts.push({
          norm1_id: id,
          norm2_id: id,
          conflict_type: 'ctd_loop',
          formula: norm.formula,
        });
      }
    }
  }

  return conflicts;
}

// ---------------------------------------------------------------------------
// getApplicableNorms
// ---------------------------------------------------------------------------

/**
 * Return all norms and indicate which ones apply to the given action.
 *
 * @param {string} action
 * @param {object} [context]
 * @returns {Array<{ id: string, norm: object, matches: boolean, operator: string }>}
 */
export function getApplicableNorms(action, context = {}) {
  if (typeof action !== 'string' || !action.trim()) {
    throw new TypeError('getApplicableNorms: action must be a non-empty string');
  }

  const normalizedAction = _normalizeFormula(action);

  return Array.from(_normBase.values()).map(({ id, norm }) => ({
    id,
    norm,
    matches: _normMatchesAction(norm, normalizedAction, context),
    operator: norm.operator,
  }));
}

// ---------------------------------------------------------------------------
// buildDeonticSummary
// ---------------------------------------------------------------------------

/**
 * Return a summary of the current norm base and any detected conflicts.
 *
 * @returns {{
 *   total_norms: number,
 *   obligations: number,
 *   permissions: number,
 *   prohibitions: number,
 *   ctd_rules: number,
 *   unknowns: number,
 *   conflicts: ReturnType<typeof detectConflicts>
 * }}
 */
export function buildDeonticSummary() {
  let obligations = 0;
  let permissions = 0;
  let prohibitions = 0;
  let ctd_rules = 0;
  let unknowns = 0;

  for (const { norm } of _normBase.values()) {
    switch (norm.operator) {
      case DEONTIC_CONSTANTS.OBLIGATORY: obligations++;  break;
      case DEONTIC_CONSTANTS.PERMITTED:  permissions++;  break;
      case DEONTIC_CONSTANTS.FORBIDDEN:  prohibitions++; break;
      case DEONTIC_CONSTANTS.CTD:        ctd_rules++;    break;
      case DEONTIC_CONSTANTS.UNKNOWN:    unknowns++;     break;
    }
  }

  return {
    total_norms:  _normBase.size,
    obligations,
    permissions,
    prohibitions,
    ctd_rules,
    unknowns,
    conflicts: detectConflicts(),
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Normalise a formula/action string for comparison:
 * lowercase, collapse whitespace, strip trailing punctuation.
 *
 * @param {string} text
 * @returns {string}
 */
function _normalizeFormula(text) {
  return text
    .toLowerCase()
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/[.;,!?]+$/, '');
}

/**
 * Determine whether a norm applies to a normalised action string.
 *
 * Phase 3 fix: Added exact-match priority tier.
 * Matching strategy (in order of precedence):
 *   1. Exact match between norm formula and action (highest priority tier)
 *   2. Action contains the norm formula as a substring
 *   3. Norm formula contains the action as a substring (lowest priority)
 *
 * Returns a match quality: 'exact', 'contains', 'substring', or false.
 *
 * CTD norms match on the CTD consequent formula (norm.formula), not the
 * violated precondition, because we are evaluating whether the reparative
 * action is applicable.
 *
 * @param {object} norm
 * @param {string} normalizedAction
 * @param {object} _context  (reserved)
 * @returns {string|boolean} Match quality string or false
 */
function _normMatchesAction(norm, normalizedAction, _context) {
  const nf = norm.formula; // already stored normalised via parseDeonticRule
  if (!nf) return false;

  // Phase 3: Exact match is a stronger signal than substring containment
  if (nf === normalizedAction) return 'exact';
  if (normalizedAction.includes(nf)) return 'contains';
  if (nf.includes(normalizedAction)) return 'substring';

  return false;
}

/**
 * Return norms applicable to normalizedAction, sorted by priority descending.
 * Phase 3: Priority tie-breaking now considers match quality (exact > contains > substring).
 * Logs derivation steps.
 *
 * @param {string} normalizedAction
 * @param {object} context
 * @param {string[]} derivation  Mutated in place.
 * @returns {Array<{ id: string, norm: object, match_quality: string }>}
 */
function _getSortedApplicableNorms(normalizedAction, context, derivation) {
  derivation.push(`Scanning ${_normBase.size} registered norm(s)...`);

  const applicable = [];

  for (const [id, { norm }] of _normBase) {
    const matchQuality = _normMatchesAction(norm, normalizedAction, context);
    if (matchQuality) {
      applicable.push({ id, norm, match_quality: matchQuality });
      derivation.push(
        `  [${id}] ${_fmtNorm(norm)} — MATCHES ${matchQuality} (priority=${norm.priority})`
      );
    } else {
      derivation.push(
        `  [${id}] ${_fmtNorm(norm)} — no match`
      );
    }
  }

  // Sort: highest priority first; within same priority, exact > contains > substring
  const qualityRank = { exact: 3, contains: 2, substring: 1 };
  applicable.sort((a, b) => {
    const priorityDiff = b.norm.priority - a.norm.priority;
    if (priorityDiff !== 0) return priorityDiff;
    return (qualityRank[b.match_quality] || 0) - (qualityRank[a.match_quality] || 0);
  });

  return applicable;
}

/**
 * Format a norm for human-readable derivation output.
 *
 * @param {object} norm
 * @returns {string}
 */
function _fmtNorm(norm) {
  if (norm.operator === DEONTIC_CONSTANTS.CTD) {
    return `D(${norm.ctd_violated || '?'}, ${norm.formula})`;
  }
  return `${norm.operator}(${norm.formula})`;
}

// ---------------------------------------------------------------------------
// loadSocialLaws (Phase 3: boot-time loader for directives.json)
// ---------------------------------------------------------------------------

/**
 * Load social_laws from directives.json and register them as structured norms.
 * Each social_law entry has { id, statement } and is mapped to OBLIGATORY with
 * priority 2 (higher than default NL-parsed norms).
 *
 * @param {string} [directivesPath] - Path to directives.json (default: auto-resolve)
 * @returns {{ loaded: number, laws: Array<{ id: string, norm: object }> }}
 */
export function loadSocialLaws(directivesPath) {
  const path = directivesPath || new URL('../../directives.json', import.meta.url).pathname;
  let raw;
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return { loaded: 0, laws: [] };
  }

  const laws = Array.isArray(raw.social_laws) ? raw.social_laws : [];
  const results = [];

  for (const law of laws) {
    if (!law.id || !law.statement) continue;
    const result = registerNorm(law.id, {
      operator: DEONTIC_CONSTANTS.OBLIGATORY,
      formula: law.statement,
    }, 2);
    results.push(result);
  }

  return { loaded: results.length, laws: results };
}