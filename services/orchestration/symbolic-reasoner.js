/**
 * symbolic-reasoner.js
 * Source: Neuro-symbolic AI (NeSy), Allen's Interval Algebra, Pearl's SCM
 *
 * Neuro-symbolic reasoning engine: constraint propagation, symbolic
 * explanation traces, lightweight causal reasoning (SCM), and temporal
 * constraints (Allen intervals).
 *
 * Sits BELOW the decision layer -- it informs, never vetoes.
 * Complements deontic-reasoner.js, meta-controller.js, and
 * decision-renderer.js.
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (post-run step 30)
// → Calls: services/core/embeddings.js (symbolic constraint embedding)
// Pipeline: AGENT_RUN_PIPELINE
// Position: symbolic post-check
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { getEmbedding } from '../core/embeddings.js';
import { evaluatePermission } from '../core/deontic-reasoner.js';

const COMPANY = AIMOS_COMPANY_ID;

// ---------------------------------------------------------------------------
// 1. Constraint Satisfaction (CSP)
// ---------------------------------------------------------------------------

/**
 * Create an empty CSP instance.
 */
export function createCSP() {
  return {
    variables: new Map(),   // name -> { domain: [...] }
    constraints: [],        // { variables: [name], predicate: fn, label: string }
    solutions: [],
  };
}

/**
 * Register a variable with its finite domain.
 */
export function addVariable(csp, name, domain) {
  csp.variables.set(name, { domain: [...domain] });
}

/**
 * Register a constraint over one or more variables.
 * @param {string[]} variables  names of the variables involved
 * @param {Function} predicateFn  (assignment: Record<string, any>) => boolean
 * @param {string} label  human-readable description
 */
export function addConstraint(csp, variables, predicateFn, label) {
  csp.constraints.push({ variables, predicate: predicateFn, label });
}

/**
 * AC-3 arc-consistency preprocessing.  Mutates the domains in `domains` map.
 * Returns false if a domain is wiped out (inconsistency detected).
 */
function ac3(domains, constraints) {
  // Build work-queue of (variable, constraint) pairs
  const queue = [];
  for (const c of constraints) {
    for (const v of c.variables) {
      queue.push({ variable: v, constraint: c });
    }
  }

  while (queue.length > 0) {
    const { variable, constraint } = queue.shift();
    const domainBefore = domains.get(variable).length;

    // For unary / binary / n-ary: keep only values that have at least one
    // supporting tuple among the other variables' current domains.
    const others = constraint.variables.filter(v => v !== variable);
    if (others.length === 0) {
      // Unary constraint
      domains.set(
        variable,
        domains.get(variable).filter(val => {
          const assignment = { [variable]: val };
          return constraint.predicate(assignment);
        }),
      );
    } else {
      domains.set(
        variable,
        domains.get(variable).filter(val => {
          return hasSupport(val, variable, others, domains, constraint);
        }),
      );
    }

    if (domains.get(variable).length === 0) return false;

    if (domains.get(variable).length < domainBefore) {
      // Re-enqueue neighbours
      for (const c2 of constraints) {
        if (c2 === constraint) continue;
        for (const v2 of c2.variables) {
          if (v2 !== variable) {
            queue.push({ variable: v2, constraint: c2 });
          }
        }
      }
    }
  }
  return true;
}

/**
 * Check if `val` for `variable` has at least one consistent assignment
 * among `others` given their current domains and the constraint.
 */
function hasSupport(val, variable, others, domains, constraint) {
  function check(idx, partial) {
    if (idx === others.length) {
      return constraint.predicate(partial);
    }
    const other = others[idx];
    for (const v of domains.get(other)) {
      partial[other] = v;
      if (check(idx + 1, partial)) return true;
    }
    delete partial[other];
    return false;
  }
  return check(0, { [variable]: val });
}

/**
 * Backtracking search with MRV heuristic and AC-3 preprocessing.
 * Returns up to `maxSolutions` valid complete assignments.
 */
export function solveCSP(csp, maxSolutions = 5) {
  csp.solutions = [];

  // Clone domains so AC-3 doesn't mutate the original CSP
  const domains = new Map();
  for (const [name, v] of csp.variables) {
    domains.set(name, [...v.domain]);
  }

  // Arc-consistency pass
  if (!ac3(domains, csp.constraints)) return csp.solutions;

  const varNames = [...csp.variables.keys()];

  function selectUnassigned(assignment) {
    // MRV: pick the unassigned variable with the smallest remaining domain
    let best = null;
    let bestSize = Infinity;
    for (const name of varNames) {
      if (name in assignment) continue;
      const size = domains.get(name).length;
      if (size < bestSize) {
        bestSize = size;
        best = name;
      }
    }
    return best;
  }

  function isConsistent(assignment) {
    for (const c of csp.constraints) {
      // Only check if all variables of this constraint are assigned
      if (c.variables.every(v => v in assignment)) {
        if (!c.predicate(assignment)) return false;
      }
    }
    return true;
  }

  function backtrack(assignment) {
    if (csp.solutions.length >= maxSolutions) return;

    if (Object.keys(assignment).length === varNames.length) {
      csp.solutions.push({ ...assignment });
      return;
    }

    const variable = selectUnassigned(assignment);
    if (!variable) return;

    for (const value of domains.get(variable)) {
      assignment[variable] = value;
      if (isConsistent(assignment)) {
        backtrack(assignment);
        if (csp.solutions.length >= maxSolutions) return;
      }
      delete assignment[variable];
    }
  }

  backtrack({});
  return csp.solutions;
}

// ---------------------------------------------------------------------------
// 2. Symbolic Derivation / Explanation Traces
// ---------------------------------------------------------------------------

/**
 * Create an empty derivation trace.
 */
export function createDerivation() {
  return { steps: [], conclusion: null };
}

/**
 * Append a reasoning step.
 */
export function addStep(derivation, rule, inputs, output, confidence) {
  derivation.steps.push({
    rule,
    inputs,
    output,
    confidence,
    timestamp: Date.now(),
  });
}

/**
 * Set the final conclusion.
 */
export function conclude(derivation, conclusion, confidence) {
  derivation.conclusion = { conclusion, confidence, timestamp: Date.now() };
}

/**
 * Render a derivation to a human-readable string.
 */
export function explainDerivation(derivation) {
  const lines = derivation.steps.map((s, i) => {
    const inputStr = Array.isArray(s.inputs) ? s.inputs.join(', ') : String(s.inputs);
    return `Step ${i + 1}: [${s.rule}] applied to [${inputStr}] \u2192 ${s.output} (conf: ${s.confidence})`;
  });

  if (derivation.conclusion) {
    lines.push(
      `Conclusion: ${derivation.conclusion.conclusion} (conf: ${derivation.conclusion.confidence})`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// 3. Causal Reasoning (Lightweight Structural Causal Model)
// ---------------------------------------------------------------------------

/**
 * Create an empty causal model.
 */
export function createCausalModel() {
  return {
    variables: new Map(),   // name -> { value: any, intervened: bool }
    edges: [],              // { cause, effect, strength }
    observations: new Map(),
  };
}

/**
 * Add a directed causal edge.
 * @param {number} strength  how strongly cause influences effect (0..1)
 */
export function addCausalEdge(model, cause, effect, strength) {
  if (!model.variables.has(cause)) {
    model.variables.set(cause, { value: null, intervened: false });
  }
  if (!model.variables.has(effect)) {
    model.variables.set(effect, { value: null, intervened: false });
  }
  model.edges.push({ cause, effect, strength });
}

/**
 * Pearl's do-operator: set `variable` to `value` and sever all incoming edges.
 */
export function intervene(model, variable, value) {
  if (!model.variables.has(variable)) {
    model.variables.set(variable, { value: null, intervened: false });
  }
  model.variables.get(variable).value = value;
  model.variables.get(variable).intervened = true;

  // Remove incoming edges (cut off causal parents)
  model.edges = model.edges.filter(e => e.effect !== variable);
}

/**
 * Topological sort of the causal DAG.  Returns ordered variable names.
 */
function topoSort(model) {
  const inDeg = new Map();
  for (const [v] of model.variables) inDeg.set(v, 0);
  for (const e of model.edges) {
    inDeg.set(e.effect, (inDeg.get(e.effect) || 0) + 1);
  }

  const queue = [];
  for (const [v, d] of inDeg) {
    if (d === 0) queue.push(v);
  }

  const order = [];
  while (queue.length > 0) {
    const v = queue.shift();
    order.push(v);
    for (const e of model.edges) {
      if (e.cause === v) {
        inDeg.set(e.effect, inDeg.get(e.effect) - 1);
        if (inDeg.get(e.effect) === 0) queue.push(e.effect);
      }
    }
  }
  return order;
}

/**
 * Forward propagation through the causal graph.
 * For root / observed / intervened nodes, uses their current value.
 * For others, computes a weighted sum of parent contributions.
 *
 * @param {Map} observations  variable -> observed numeric value
 * @returns {Map} variable -> estimated value
 */
export function propagate(model, observations) {
  const result = new Map();

  // Set observations
  for (const [v, val] of observations) {
    if (model.variables.has(v)) {
      model.variables.get(v).value = val;
    }
    model.observations.set(v, val);
  }

  const order = topoSort(model);

  for (const v of order) {
    const info = model.variables.get(v);

    // Intervened or observed nodes keep their value
    if (info.intervened || observations.has(v)) {
      result.set(v, info.value);
      continue;
    }

    // Compute from parents
    const incoming = model.edges.filter(e => e.effect === v);
    if (incoming.length === 0) {
      // Root node with no observation -- default to current value or 0
      result.set(v, info.value ?? 0);
      continue;
    }

    let sum = 0;
    for (const e of incoming) {
      const parentVal = result.get(e.cause) ?? 0;
      sum += parentVal * e.strength;
    }
    info.value = sum;
    result.set(v, sum);
  }

  return result;
}

/**
 * Counterfactual reasoning (Pearl's 3-step):
 *   1. Abduction   -- set factual observations
 *   2. Intervention -- apply do(intervention)
 *   3. Prediction   -- propagate and read query variable
 *
 * @param {Map|Object} factualObs  variable -> observed value
 * @param {{ variable: string, value: any }} intervention
 * @param {string} queryVar  which variable to read
 * @returns {{ queryVariable: string, factualValue: any, counterfactualValue: any }}
 */
export function counterfactual(model, factualObs, intervention, queryVar) {
  // Normalise factualObs to a Map
  const obsMap = factualObs instanceof Map
    ? new Map(factualObs)
    : new Map(Object.entries(factualObs));

  // --- Step 1: Abduction (observe the factual world) ---
  const factualResult = propagate(cloneModel(model), obsMap);
  const factualValue = factualResult.get(queryVar) ?? null;

  // --- Step 2 + 3: Intervention then Prediction ---
  const cfModel = cloneModel(model);

  // Apply abducted observations first (for exogenous nodes)
  for (const [v, val] of obsMap) {
    if (cfModel.variables.has(v)) {
      cfModel.variables.get(v).value = val;
    }
  }

  // Apply intervention (do-operator)
  intervene(cfModel, intervention.variable, intervention.value);

  // Propagate with remaining observations (excluding the intervened variable)
  const cfObs = new Map(obsMap);
  cfObs.delete(intervention.variable);
  const cfResult = propagate(cfModel, cfObs);
  const counterfactualValue = cfResult.get(queryVar) ?? null;

  return { queryVariable: queryVar, factualValue, counterfactualValue };
}

/**
 * Deep-clone a causal model so mutations don't affect the original.
 */
function cloneModel(model) {
  const m = createCausalModel();
  for (const [v, info] of model.variables) {
    m.variables.set(v, { value: info.value, intervened: info.intervened });
  }
  m.edges = model.edges.map(e => ({ ...e }));
  for (const [k, v] of model.observations) m.observations.set(k, v);
  return m;
}

// ---------------------------------------------------------------------------
// 4. Integration with Meta-Controller
// ---------------------------------------------------------------------------

/**
 * Called BEFORE meta-controller's Propose step.
 *
 * Checks the current metaState for constraint violations and matches the
 * task prompt against known causal patterns (via embedding similarity).
 *
 * @returns {{ constraintsSatisfied: boolean, violations: string[], causalHints: string[], confidence: number }}
 */
export async function symbolicPreCheck(taskPrompt, metaState) {
  const violations = [];
  const causalHints = [];
  let confidence = 1.0;

  // --- Constraint check against metaState ---
  if (metaState) {
    // Build a lightweight CSP from metaState properties
    const csp = createCSP();

    if (metaState.resources) {
      for (const [name, info] of Object.entries(metaState.resources)) {
        if (info.domain) {
          addVariable(csp, name, info.domain);
        }
      }
    }

    if (metaState.constraints && Array.isArray(metaState.constraints)) {
      for (const c of metaState.constraints) {
        addConstraint(csp, c.variables, c.predicate, c.label);
      }

      // Quick validation: try to solve; if no solution, report violations
      if (csp.variables.size > 0) {
        const solutions = solveCSP(csp, 1);
        if (solutions.length === 0) {
          for (const c of csp.constraints) {
            violations.push(`Constraint "${c.label}" cannot be satisfied`);
          }
          confidence *= 0.5;
        }
      }
    }
  }

  // --- Causal hint lookup via embeddings ---
  try {
    const embedding = await getEmbedding(taskPrompt);
    const rows = await query(
      `SELECT pattern, hint, similarity
       FROM causal_patterns
       WHERE company = $1
       ORDER BY embedding <-> $2::vector
       LIMIT 3`,
      [COMPANY, JSON.stringify(embedding)],
    );

    for (const row of rows) {
      causalHints.push(`Pattern "${row.pattern}": ${row.hint}`);
    }
  } catch (_) {
    // Causal-pattern lookup is best-effort; failures are non-fatal
  }

  return {
    constraintsSatisfied: violations.length === 0,
    violations,
    causalHints,
    confidence,
  };
}

/**
 * Called AFTER execution to validate the result against known constraints.
 *
 * @returns {{ valid: boolean, explanation: string }}
 */
export async function symbolicPostCheck(action, result) {
  const derivation = createDerivation();
  let valid = true;

  // Basic structural checks
  if (result === undefined || result === null) {
    addStep(derivation, 'null-check', [action], 'result is null/undefined', 0.9);
    valid = false;
  } else if (typeof result === 'object' && result.error) {
    addStep(derivation, 'error-check', [action, result.error], 'result contains error', 0.95);
    valid = false;
  }

  // If the action carried embedded constraints, verify them
  if (action && action.constraints && Array.isArray(action.constraints)) {
    for (const c of action.constraints) {
      try {
        const satisfied = typeof c.check === 'function' ? c.check(result) : true;
        addStep(
          derivation,
          `constraint:${c.label || 'unnamed'}`,
          [result],
          satisfied ? 'satisfied' : 'violated',
          satisfied ? 1.0 : 0.0,
        );
        if (!satisfied) valid = false;
      } catch (err) {
        addStep(derivation, `constraint:${c.label || 'unnamed'}`, [err.message], 'error during check', 0.0);
        valid = false;
      }
    }
  }

  // ─── Deontic validation: evaluate the action against registered norms ────
  try {
    const actionLabel = typeof action === 'string' ? action : (action?.label || action?.tool_name || JSON.stringify(action));
    const deonticResult = evaluatePermission(actionLabel);
    addStep(
      derivation,
      'deontic-check',
      [actionLabel],
      `${deonticResult.operator}(${actionLabel}) — ${deonticResult.reason}`,
      deonticResult.permitted ? 1.0 : 0.0,
    );
    if (!deonticResult.permitted) {
      valid = false;
    }
  } catch (_deonticErr) {
    // Deontic check is non-fatal — norm base may be empty at startup
  }

  conclude(derivation, valid ? 'Result valid' : 'Result invalid', valid ? 1.0 : 0.3);

  return {
    valid,
    explanation: explainDerivation(derivation),
  };
}

// ---------------------------------------------------------------------------
// 5. Temporal Constraints (Allen Interval Algebra)
// ---------------------------------------------------------------------------

/**
 * Determine the Allen relation between two intervals.
 * Each interval: { start: number, end: number }
 *
 * Returns one of: 'before', 'after', 'meets', 'met-by',
 *   'overlaps', 'overlapped-by', 'during', 'contains',
 *   'starts', 'started-by', 'finishes', 'finished-by', 'equals'
 */
export function allenRelation(intervalA, intervalB) {
  const a = intervalA;
  const b = intervalB;

  if (a.end < b.start) return 'before';
  if (b.end < a.start) return 'after';
  if (a.end === b.start) return 'meets';
  if (b.end === a.start) return 'met-by';

  if (a.start < b.start && a.end > b.start && a.end < b.end) return 'overlaps';
  if (b.start < a.start && b.end > a.start && b.end < a.end) return 'overlapped-by';

  if (a.start === b.start && a.end < b.end) return 'starts';
  if (a.start === b.start && a.end > b.end) return 'started-by';

  if (a.end === b.end && a.start > b.start) return 'finishes';
  if (a.end === b.end && a.start < b.start) return 'finished-by';

  if (a.start > b.start && a.end < b.end) return 'during';
  if (a.start < b.start && a.end > b.end) return 'contains';

  if (a.start === b.start && a.end === b.end) return 'equals';

  // Fallback (should not reach here for well-formed intervals)
  return 'unknown';
}

/**
 * Check whether a temporal constraint holds between two events.
 *
 * @param {Object} events  Map or object: eventId -> { start, end }
 * @param {{ a: string, relation: string, b: string }} constraint
 * @returns {{ satisfied: boolean, actual: string }}
 */
export function checkTemporalConstraint(events, constraint) {
  const evMap = events instanceof Map ? events : new Map(Object.entries(events));
  const intervalA = evMap.get(constraint.a);
  const intervalB = evMap.get(constraint.b);

  if (!intervalA || !intervalB) {
    return { satisfied: false, actual: 'missing-event' };
  }

  const actual = allenRelation(intervalA, intervalB);
  return {
    satisfied: actual === constraint.relation,
    actual,
  };
}
