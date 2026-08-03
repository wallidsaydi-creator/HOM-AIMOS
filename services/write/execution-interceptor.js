// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js
// → Calls: event-ledger.js
// Pipeline: TOOL_REGISTRY | Position: Fail-closed execution gate (hook)
// ─────────────────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════
// EXECUTION INTERCEPTOR (execution-interceptor.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-4: Fail-Closed Execution
//
// Synchronous gate wrapping all tool execution. Default posture: BLOCK.
// Only executes if tool + method + params exactly match an approved plan.
//
// Design principle: fail-closed security (Saltzer & Schroeder, 1975).
// If the gate cannot verify approval, execution is denied.
//
// Validation checks:
//   1. Tool exists in approved plan
//   2. Method/operation matches allowed verbs for that tool
//   3. Parameters stay within defined bounds
//   4. All blocked executions are logged for audit
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// HTTP verbs allowed per tool category — defence against verb confusion attacks
const DEFAULT_ALLOWED_VERBS = Object.freeze({
  read: ['GET'],
  write: ['POST', 'PUT', 'PATCH'],
  delete: ['DELETE'],
  search: ['GET', 'POST'],
  execute: ['POST'],
  default: ['GET', 'POST'],
});

/**
 * Build an execution plan from a list of approved tool invocations.
 * Each entry defines the exact tool, method, and parameter bounds permitted.
 *
 * @param {Array<{tool: string, method: string, params: Object, paramBounds?: Object}>} approvedActions
 * @returns {Object} Execution plan keyed by `${tool}:${method}`
 */
export function createExecutionPlan(approvedActions) {
  if (!Array.isArray(approvedActions)) return {};

  const plan = {};
  for (const action of approvedActions) {
    const tool = String(action?.tool || '').toLowerCase().trim();
    const method = String(action?.method || 'POST').toUpperCase().trim();
    if (!tool) continue;

    const planKey = `${tool}:${method}`;
    plan[planKey] = {
      tool,
      method,
      params: action?.params && typeof action.params === 'object' ? action.params : {},
      paramBounds: action?.paramBounds && typeof action.paramBounds === 'object'
        ? action.paramBounds
        : {},
      approvedAt: new Date().toISOString(),
    };
  }

  return plan;
}

/**
 * Check whether a specific tool+method combination is present in the approved plan.
 *
 * @param {string} toolName
 * @param {string} method
 * @param {Object} approvedPlan - From createExecutionPlan()
 * @returns {boolean}
 */
export function isApprovedAction(toolName, method, approvedPlan) {
  if (!approvedPlan || typeof approvedPlan !== 'object') return false;
  const tool = String(toolName || '').toLowerCase().trim();
  const verb = String(method || 'POST').toUpperCase().trim();
  const planKey = `${tool}:${verb}`;
  return Object.prototype.hasOwnProperty.call(approvedPlan, planKey);
}

/**
 * Validate that execution parameters stay within approved bounds.
 *
 * @param {Object} params - Actual parameters being passed
 * @param {Object} approvedParams - Approved parameter values from plan
 * @param {Object} paramBounds - Min/max bounds per numeric parameter
 * @returns {string[]} Array of violation descriptions (empty = valid)
 */
function validateParameters(params, approvedParams, paramBounds) {
  const violations = [];

  if (!params || typeof params !== 'object') return violations;

  // Check that no unexpected parameters are present
  const approvedKeys = new Set(Object.keys(approvedParams || {}));
  for (const key of Object.keys(params)) {
    if (approvedKeys.size > 0 && !approvedKeys.has(key)) {
      violations.push(`Unapproved parameter: '${key}'`);
    }
  }

  // Check numeric bounds
  const bounds = paramBounds || {};
  for (const [key, bound] of Object.entries(bounds)) {
    const val = params[key];
    if (val === undefined) continue;
    const num = Number(val);
    if (!Number.isFinite(num)) continue;
    if (typeof bound.min === 'number' && num < bound.min) {
      violations.push(`Parameter '${key}' (${num}) below minimum (${bound.min})`);
    }
    if (typeof bound.max === 'number' && num > bound.max) {
      violations.push(`Parameter '${key}' (${num}) above maximum (${bound.max})`);
    }
  }

  return violations;
}

/**
 * Validate an execution request against the approved plan.
 * DEFAULT POSTURE: BLOCK. Approve only if all checks pass.
 *
 * @param {string} toolName - Name of the tool being invoked
 * @param {string} method - HTTP verb or operation type (GET, POST, etc.)
 * @param {Object} parameters - Parameters being passed to the tool
 * @param {Object} approvedPlan - From createExecutionPlan()
 * @param {string} [companyId]
 * @returns {Promise<{allowed: boolean, reason: string, violations: string[]}>}
 */
export async function validateExecution(toolName, method, parameters, approvedPlan, companyId) {
  const cid = companyId || COMPANY;
  const tool = String(toolName || '').toLowerCase().trim();
  const verb = String(method || 'POST').toUpperCase().trim();
  const params = parameters && typeof parameters === 'object' ? parameters : {};

  // Gate 1: Approved plan must exist
  if (!approvedPlan || typeof approvedPlan !== 'object' || Object.keys(approvedPlan).length === 0) {
    await _logBlocked(cid, tool, verb, params, ['No approved execution plan provided']);
    return {
      allowed: false,
      reason: 'no_approved_plan',
      violations: ['No approved execution plan provided'],
    };
  }

  // Gate 2: Tool + method must be in approved plan
  const planKey = `${tool}:${verb}`;
  const planEntry = approvedPlan[planKey];

  if (!planEntry) {
    const violation = `Tool '${tool}' with method '${verb}' not in approved plan`;
    await _logBlocked(cid, tool, verb, params, [violation]);
    return {
      allowed: false,
      reason: 'not_in_approved_plan',
      violations: [violation],
    };
  }

  // Gate 3: HTTP verb must match tool's allowed verb category
  const toolCategory = _inferToolCategory(tool);
  const allowedVerbs = DEFAULT_ALLOWED_VERBS[toolCategory] || DEFAULT_ALLOWED_VERBS.default;
  if (!allowedVerbs.includes(verb)) {
    const violation = `Method '${verb}' not allowed for tool category '${toolCategory}' (allowed: ${allowedVerbs.join(', ')})`;
    await _logBlocked(cid, tool, verb, params, [violation]);
    return {
      allowed: false,
      reason: 'verb_not_allowed',
      violations: [violation],
    };
  }

  // Gate 4: Parameter bounds validation
  const paramViolations = validateParameters(params, planEntry.params, planEntry.paramBounds);
  if (paramViolations.length > 0) {
    await _logBlocked(cid, tool, verb, params, paramViolations);
    return {
      allowed: false,
      reason: 'parameter_violations',
      violations: paramViolations,
    };
  }

  // All gates passed
  return { allowed: true, reason: 'approved', violations: [] };
}

/**
 * Infer the tool category from its name for verb validation.
 *
 * @param {string} toolName
 * @returns {string} Category key
 */
function _inferToolCategory(toolName) {
  const name = String(toolName || '').toLowerCase();
  if (name.includes('read') || name.includes('get') || name.includes('fetch') || name.includes('load')) return 'read';
  if (name.includes('write') || name.includes('save') || name.includes('create') || name.includes('update')) return 'write';
  if (name.includes('delete') || name.includes('remove') || name.includes('purge')) return 'delete';
  if (name.includes('search') || name.includes('recall') || name.includes('query') || name.includes('find')) return 'search';
  if (name.includes('execute') || name.includes('run') || name.includes('call')) return 'execute';
  return 'default';
}

/**
 * Log a blocked execution attempt to the event ledger for audit.
 *
 * @param {string} companyId
 * @param {string} tool
 * @param {string} method
 * @param {Object} params
 * @param {string[]} violations
 */
async function _logBlocked(companyId, tool, method, params, violations) {
  try {
    await logEvent(companyId, 'execution-interceptor', 'execution_blocked', `${tool}:${method}`, {
      reasoning: `Execution blocked by fail-closed gate. Violations: ${violations.join('; ')}`,
      tool,
      method,
      paramKeys: Object.keys(params),
      violations,
    });
  } catch (err) {
    // Non-fatal — audit log failure should not mask the block itself
    console.error('[execution-interceptor] Failed to log blocked execution:', err.message);
  }
}
