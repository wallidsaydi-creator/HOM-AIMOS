/**
 * constitution-enforcer.js — Compile constitution rules into executable checks
 * Source: ContextCov (2026)
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: agent-runner.js (pre-run step 18 & post-run step 23)
 * 2. → Pulls from: directives.json + architecture-authority.json
 * 3. → Pushes to: security.active_proofs (Constitutional compliance status)
 * 4. ↔ Interacts with: services/security/knowledge-gate.js (Enforces rule acquisition)
 *
 * LOGIC GUIDE: Parses JSON rules into runtime-enforceable constraints. 
 * Replaces passive prompts with "Self-Constraint" logic blocks.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (pre-run step 2, post-run step 23)
// → Calls: directives.json + architecture-authority.json (file reads)
// Pipeline: AGENT_RUN_PIPELINE
// Position: constitution load + enforcement
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync } from 'fs';
import { persistMemory } from '../write/persist-memory.js';
import { assertTeleologicalLock, classifyModification, RULE_LEVELS } from './rule-hierarchy.js';
import { AIMOS_COMPANY_ID } from './runtime-config.js';

const COMPANY = AIMOS_COMPANY_ID;

export const ENFORCEMENT_DOMAINS = {
  PROCESS: 'process',
  SOURCE: 'source',
  ARCH_DET: 'arch_det',
  ARCH_SEM: 'arch_sem'
};

const BLOCKED_COMMANDS = [
  /rm\s+-rf\s+\//,
  /DROP\s+TABLE/i,
  /DELETE\s+FROM\s+aimos_memories\s+WHERE/i,
  /git\s+push\s+--force\s+(origin\s+)?(main|master)/,
  /git\s+reset\s+--hard/,
];

const STALE_PATH_PATTERNS = new Map();

export function loadConstitutionRules(authorityPath) {
  if (!existsSync(authorityPath)) return { rules: [], errors: ['authority file not found'] };

  const authority = JSON.parse(readFileSync(authorityPath, 'utf-8'));
  const rules = [];

  const staleAliases = authority.path_authority?.stale_aliases || [];
  if (Array.isArray(staleAliases)) {
    for (const { alias: stale, canonical } of staleAliases) {
      if (!stale || !canonical) continue;
      STALE_PATH_PATTERNS.set(stale, canonical);
      rules.push({
        id: `stale_path:${stale}`,
        domain: ENFORCEMENT_DOMAINS.ARCH_DET,
        check: (toolCall) => {
          const path = extractPath(toolCall);
          if (path && path.includes(stale)) {
            return { pass: false, message: `Stale path "${stale}" — use "${canonical}" instead` };
          }
          return { pass: true };
        }
      });
    }
  }

  const DENIED_FILES = ['memory.md', 'style.md', 'working-memory.md', 'session-memory.md'];
  rules.push({
    id: 'memory_file_denylist',
    domain: ENFORCEMENT_DOMAINS.PROCESS,
    check: (toolCall) => {
      if (['Write', 'Edit', 'MultiEdit'].includes(toolCall.tool_name)) {
        const path = toolCall.file_path || '';
        if (DENIED_FILES.some(f => path.endsWith(f))) {
          return { pass: false, message: `Cannot write to memory file: ${path}` };
        }
      }
      return { pass: true };
    }
  });

  rules.push({
    id: 'destructive_command_block',
    domain: ENFORCEMENT_DOMAINS.PROCESS,
    check: (toolCall) => {
      if (toolCall.tool_name === 'Bash') {
        const cmd = toolCall.command || '';
        for (const pattern of BLOCKED_COMMANDS) {
          if (pattern.test(cmd)) {
            return { pass: false, message: `Blocked destructive command: ${pattern.source}` };
          }
        }
      }
      return { pass: true };
    }
  });

  rules.push({
    id: 'clearance_enforcement',
    domain: ENFORCEMENT_DOMAINS.ARCH_DET,
    check: (toolCall, context) => {
      if (toolCall.tool_name === 'aimos_save' && toolCall.clearance_level > (context?.agentClearance || 3)) {
        return { pass: false, message: `Agent clearance ${context.agentClearance} cannot write clearance ${toolCall.clearance_level} memory` };
      }
      return { pass: true };
    }
  });

  rules.push({
    id: 'max_delegation_depth',
    domain: ENFORCEMENT_DOMAINS.ARCH_DET,
    check: (toolCall, context) => {
      if (toolCall.tool_name === 'delegate_to_agent' && (context?.delegationDepth || 0) >= 2) {
        return { pass: false, message: 'Max delegation depth (2) exceeded' };
      }
      return { pass: true };
    }
  });

  return { rules, errors: [] };
}

export function enforceRules(rules, toolCall, context = {}) {
  const violations = [];
  for (const rule of rules) {
    try {
      const result = rule.check(toolCall, context);
      if (!result.pass) {
        violations.push({ rule_id: rule.id, domain: rule.domain, message: result.message });
      }
    } catch (e) {
      violations.push({ rule_id: rule.id, domain: rule.domain, message: `Check error: ${e.message}`, fail_closed: true });
    }
  }

  // ─── Kmax hierarchy check: guard against self-modification violations ──────
  // Any toolCall that proposes a modification is verified against the 4-level
  // rule hierarchy. Teleological-core (level 99) modifications are always blocked.
  try {
    const targetLevel = Number(toolCall?.target_rule_level ?? toolCall?.ruleLevel ?? -1);
    if (targetLevel >= 0) {
      const source = toolCall?.tool_name || toolCall?.source || 'unknown';
      const description = toolCall?.description || toolCall?.command || JSON.stringify(toolCall).slice(0, 120);
      const lockResult = assertTeleologicalLock({ targetLevel, description, source });
      if (lockResult.locked) {
        violations.push({
          rule_id: 'rule-hierarchy:teleological-lock',
          domain: ENFORCEMENT_DOMAINS.ARCH_SEM,
          message: lockResult.message,
        });
      } else if (targetLevel === RULE_LEVELS.R2_META_REASONING) {
        const classification = classifyModification({ targetLevel, description, source });
        if (classification.regime === 'structural_modify') {
          // Log caution but do not block R2 modifications — just annotate context
          context._ruleHierarchyWarning = classification.reason;
        }
      }
    }
  } catch (_hierarchyErr) {
    // Rule-hierarchy check is non-fatal — level metadata may not be present
  }

  return { allowed: violations.length === 0, violations };
}

function extractPath(toolCall) {
  return toolCall.file_path || toolCall.path ||
    (toolCall.command && toolCall.command.match(/(?:\/Users\/\S+|backend\/\S+)/)?.[0]) || '';
}

export { BLOCKED_COMMANDS };

// ─── ContextCov Extraction Pipeline (2026) ───────────────────────────────────

/**
 * parseMarkdownAST
 * Parse markdown text into a flat AST array.
 * Each node: { level, heading, content, path }
 *   level   — heading depth 1-6
 *   heading — heading text (stripped of leading #s)
 *   content — array of non-heading lines that follow this heading
 *   path    — slash-joined heading stack, e.g. "Constitution/Ground Truth Files"
 */
export function parseMarkdownAST(mdText) {
  const lines = mdText.split('\n');
  const ast = [];
  const stack = []; // { level, heading }
  let current = null;

  for (const line of lines) {
    const match = line.match(/^(#{1,6})\s+(.+)/);
    if (match) {
      // Flush pending node
      if (current) ast.push(current);

      const level = match[1].length;
      const heading = match[2].trim();

      // Trim stack to parent levels
      while (stack.length && stack[stack.length - 1].level >= level) {
        stack.pop();
      }
      stack.push({ level, heading });

      const path = stack.map(s => s.heading).join('/');
      current = { level, heading, content: [], path };
    } else if (current) {
      current.content.push(line);
    }
  }

  if (current) ast.push(current);
  return ast;
}

/**
 * sliceConstraints
 * Extract constraint sentences from AST nodes.
 * targetPath: optional filter — only process nodes whose path starts with targetPath.
 * Returns: [{ path, constraint, raw_line, confidence }]
 * A "constraint" line contains at least one of: must/shall/never/forbidden/required/only/always/not allowed
 */
const CONSTRAINT_KEYWORDS = /\b(must|shall|never|forbidden|required|only|always|not allowed)\b/gi;

export function sliceConstraints(ast, targetPath = null) {
  const results = [];

  for (const node of ast) {
    if (targetPath && !node.path.startsWith(targetPath)) continue;

    for (const line of node.content) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const matches = trimmed.match(CONSTRAINT_KEYWORDS);
      if (!matches) continue;

      const uniqueMatches = new Set(matches.map(m => m.toLowerCase()));
      const confidence = uniqueMatches.size >= 2 ? 0.9 : 0.7;

      results.push({
        path: node.path,
        constraint: trimmed,
        raw_line: line,
        confidence,
      });
    }
  }

  return results;
}

/**
 * buildRefinementPrompt
 * Build an LLM prompt that asks the model to convert raw constraint sentences
 * into machine-checkable JSON check objects.
 * Returns: string
 */
export function buildRefinementPrompt(constraints) {
  const constraintList = constraints
    .map((c, i) => `${i + 1}. [${c.path}] (confidence: ${c.confidence})\n   "${c.constraint}"`)
    .join('\n\n');

  return `You are a constitution compiler. Convert each raw constraint sentence below into a structured JSON check object.

Output format for each check:
{
  "rule_id": "<short_snake_case_identifier>",
  "check_type": "denylist" | "allowlist" | "pattern" | "threshold" | "existence",
  "condition": "<what triggers this check — tool name, field, value, etc.>",
  "action": "block" | "warn" | "log"
}

Rules:
- Use the heading path as a namespace hint for rule_id.
- Prefer "block" for "never" / "forbidden" constraints, "warn" for "should" / "only", "log" for "always".
- Be precise and machine-executable — avoid vague conditions.
- Return a valid JSON array only, no prose.

Constraints to refine:

${constraintList}

Respond with a JSON array of check objects.`;
}

/**
 * storeChecks
 * Persist an array of extracted checks to Aimos DB (aimos_memories table).
 * Each check: { path, constraint, raw_line, confidence }
 * Stored as memory_type='constitution_check', key='constitution_check:<hash>'
 * Returns: { stored: number, errors: string[] }
 */
export async function storeChecks(checks, company = COMPANY) {
  const stored = [];
  const errors = [];

  for (const check of checks) {
    try {
      // Stable 8-char hash derived from the constraint text
      const hash = btoa(check.constraint).replace(/[^a-zA-Z0-9]/g, '').slice(0, 8);
      const key = `constitution_check:${hash}`;

      await persistMemory({
        company_id: company,
        agent_id: 'system',
        mutation_authority: 'housekeeper',
        scope: 'system',
        memory_type: 'constitution_check',
        key,
        value: JSON.stringify({
          path: check.path,
          constraint: check.constraint,
          raw_line: check.raw_line,
          confidence: check.confidence,
        }),
        clearance_level: 5,
      });

      stored.push(key);
    } catch (e) {
      errors.push(`Failed to store check "${check.constraint.slice(0, 60)}…": ${e.message}`);
    }
  }

  return { stored: stored.length, errors };
}

/**
 * extractAndStoreFromFile
 * Full ContextCov pipeline: read file → parseMarkdownAST → sliceConstraints → storeChecks
 * Returns: { path: filePath, checks_found: number, checks_stored: number, errors: string[] }
 */
export async function extractAndStoreFromFile(filePath, company = COMPANY) {
  const errors = [];

  if (!existsSync(filePath)) {
    return { path: filePath, checks_found: 0, checks_stored: 0, errors: [`File not found: ${filePath}`] };
  }

  let mdText;
  try {
    mdText = readFileSync(filePath, 'utf-8');
  } catch (e) {
    return { path: filePath, checks_found: 0, checks_stored: 0, errors: [`Read error: ${e.message}`] };
  }

  const ast = parseMarkdownAST(mdText);
  const constraints = sliceConstraints(ast);

  const { stored, errors: storeErrors } = await storeChecks(constraints, company);
  errors.push(...storeErrors);

  return {
    path: filePath,
    checks_found: constraints.length,
    checks_stored: stored,
    errors,
  };
}
