/**
 * interaction-graph-healer.js — Dynamic Interaction Graph Healing Engine
 *
 * Source: "DIG to Heal — Scaling Agent Collaboration via Explainable Dynamic
 * Decision Paths" (2026, CMU / Zoom / Salesforce / Amazon)
 *
 * Core idea: multi-agent collaboration produces a time-evolving bipartite
 * causal DAG (the Dynamic Interaction Graph — DIG). The graph contains two
 * node types (Activation = agent invocation, Event = message / artifact) and
 * two edge types (generation: agent→event, delivery: event→agent). Five
 * rewrite operators mutate the graph at runtime:
 *
 *   RESPOND  — agent processes an event and emits new events
 *   WAIT     — agent defers until a predicate is satisfied
 *   REROUTE  — redirect an event to a different agent
 *   DISCARD  — drop an event with an auditable justification
 *   SUBMIT   — mark an event as final output of the session
 *
 * A 7-pattern structural failure taxonomy drives automatic healing:
 *   FATAL:   Early Termination, Missing Completion, Orphaned Event, Deadlock
 *   WARNING: Excessive Rerouting, Cross-lineage Aggregation, Repeated Subproblem
 *
 * The healing engine blocks events at delivery time, checks for failure
 * patterns, and applies structure-level interventions (inject_info,
 * inject_and_reroute, create_system_event) — it never modifies agent
 * internals. All observable reasoning reduces to DIG analysis (topological
 * inference).
 */

// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (post-run step 40)
// → Calls: services/db/connection.js (DIG state read/write)
// Pipeline: AGENT_RUN_PIPELINE
// Position: DIG auto-healing
// ─────────────────────────────────────────────────────────────────────────────

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from '../observe/event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

// ─── CONSTANTS ──────────────────────────────────────────────────────────────

const NODE_TYPE_ACTIVATION = 'activation';
const NODE_TYPE_EVENT = 'event';

const EDGE_TYPE_GENERATION = 'generation'; // activation → event
const EDGE_TYPE_DELIVERY = 'delivery';     // event → activation

const OPERATORS = Object.freeze({
  RESPOND: 'RESPOND',
  WAIT: 'WAIT',
  REROUTE: 'REROUTE',
  DISCARD: 'DISCARD',
  SUBMIT: 'SUBMIT',
});

const FAILURE_SEVERITY = Object.freeze({
  FATAL: 'FATAL',
  WARNING: 'WARNING',
});

const FAILURE_PATTERNS = Object.freeze({
  EARLY_TERMINATION: { id: 'early_termination', severity: FAILURE_SEVERITY.FATAL },
  MISSING_COMPLETION: { id: 'missing_completion', severity: FAILURE_SEVERITY.FATAL },
  ORPHANED_EVENT: { id: 'orphaned_event', severity: FAILURE_SEVERITY.FATAL },
  DEADLOCK: { id: 'deadlock', severity: FAILURE_SEVERITY.FATAL },
  EXCESSIVE_REROUTING: { id: 'excessive_rerouting', severity: FAILURE_SEVERITY.WARNING },
  CROSS_LINEAGE_AGGREGATION: { id: 'cross_lineage_aggregation', severity: FAILURE_SEVERITY.WARNING },
  REPEATED_SUBPROBLEM: { id: 'repeated_subproblem', severity: FAILURE_SEVERITY.WARNING },
});

const INTERVENTION_TYPES = Object.freeze({
  INJECT_INFO: 'inject_info',
  INJECT_AND_REROUTE: 'inject_and_reroute',
  CREATE_SYSTEM_EVENT: 'create_system_event',
});

// Thresholds
const MAX_REROUTE_COUNT = 5;
const DEADLOCK_WAIT_MS = 30_000;
const MAX_REPEATED_CONTENT_SIMILARITY = 0.85;
const MAX_GRAPH_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// ─── IN-MEMORY GRAPH STORE ──────────────────────────────────────────────────
// Production: persisted to Aimos; in-memory map serves as hot cache.

/** @type {Map<string, DIGState>} */
const graphStore = new Map();

/**
 * @typedef {Object} DIGNode
 * @property {string} id
 * @property {'activation'|'event'} type
 * @property {string} [agentId]       — only for activation nodes
 * @property {string} [eventType]     — only for event nodes
 * @property {*}      [content]       — only for event nodes
 * @property {string} [sourceActivation] — activation that generated this event
 * @property {number} logicalTs       — Lamport-style logical timestamp
 * @property {string} status          — 'active' | 'waiting' | 'completed' | 'discarded' | 'submitted'
 * @property {string} createdAt       — ISO timestamp
 * @property {Object} [waitCondition] — condition predicate for WAIT operator
 */

/**
 * @typedef {Object} DIGEdge
 * @property {string} id
 * @property {string} from
 * @property {string} to
 * @property {'generation'|'delivery'} edgeType
 * @property {number} logicalTs
 * @property {string} createdAt
 */

/**
 * @typedef {Object} AuditEntry
 * @property {string} operator
 * @property {string} nodeId
 * @property {Object} params
 * @property {string} timestamp
 * @property {string} [interventionType]
 * @property {string} [reason]
 */

/**
 * @typedef {Object} DIGState
 * @property {string} graphId
 * @property {string} sessionId
 * @property {Map<string, DIGNode>} nodes
 * @property {Map<string, DIGEdge>} edges
 * @property {Map<string, Set<string>>} adjOut    — adjacency list: nodeId → set of edge ids (outgoing)
 * @property {Map<string, Set<string>>} adjIn     — adjacency list: nodeId → set of edge ids (incoming)
 * @property {AuditEntry[]} auditTrail
 * @property {number} logicalClock
 * @property {string} createdAt
 * @property {string} updatedAt
 */

// ─── ID GENERATION ──────────────────────────────────────────────────────────

let _seq = 0;

function nextId(prefix) {
  _seq += 1;
  return `${prefix}_${Date.now().toString(36)}_${_seq.toString(36)}`;
}

// ─── GRAPH LIFECYCLE ────────────────────────────────────────────────────────

/**
 * Initialise a new Dynamic Interaction Graph for a session.
 *
 * @param {string} sessionId — the session this graph tracks
 * @returns {Promise<{ graphId: string }>}
 */
export async function createGraph(sessionId) {
  if (!sessionId) throw new Error('sessionId is required');

  const graphId = nextId('dig');
  const now = new Date().toISOString();

  /** @type {DIGState} */
  const state = {
    graphId,
    sessionId,
    nodes: new Map(),
    edges: new Map(),
    adjOut: new Map(),
    adjIn: new Map(),
    auditTrail: [],
    logicalClock: 0,
    createdAt: now,
    updatedAt: now,
  };

  graphStore.set(graphId, state);

  // Persist to Aimos
  await _persistGraphMeta(graphId, sessionId, now);

  await logEvent(COMPANY, 'interaction-graph-healer', 'graph_created', graphId, {
    reasoning: 'New DIG initialised for session to track agent collaboration topology',
    sessionId,
  });

  return { graphId };
}

/**
 * Add an Activation node (agent invocation) to the graph.
 *
 * @param {string} graphId
 * @param {string} agentId — which agent was invoked
 * @param {number} [timestamp] — optional logical timestamp override
 * @returns {Promise<{ nodeId: string, logicalTs: number }>}
 */
export async function addActivation(graphId, agentId, timestamp) {
  const g = _requireGraph(graphId);
  const ts = _advanceClock(g, timestamp);
  const nodeId = nextId('act');
  const now = new Date().toISOString();

  /** @type {DIGNode} */
  const node = {
    id: nodeId,
    type: NODE_TYPE_ACTIVATION,
    agentId,
    logicalTs: ts,
    status: 'active',
    createdAt: now,
  };

  g.nodes.set(nodeId, node);
  g.adjOut.set(nodeId, new Set());
  g.adjIn.set(nodeId, new Set());
  g.updatedAt = now;

  await _persistNode(graphId, node);

  _audit(g, 'add_activation', nodeId, { agentId, logicalTs: ts });

  return { nodeId, logicalTs: ts };
}

/**
 * Add an Event node (message / artifact) to the graph.
 *
 * @param {string} graphId
 * @param {string} eventType — e.g. 'message', 'artifact', 'tool_result'
 * @param {*} content — the payload
 * @param {string} [sourceActivation] — activation node that generated this event
 * @returns {Promise<{ nodeId: string, logicalTs: number }>}
 */
export async function addEvent(graphId, eventType, content, sourceActivation) {
  const g = _requireGraph(graphId);
  const ts = _advanceClock(g);
  const nodeId = nextId('evt');
  const now = new Date().toISOString();

  /** @type {DIGNode} */
  const node = {
    id: nodeId,
    type: NODE_TYPE_EVENT,
    eventType,
    content,
    sourceActivation: sourceActivation || null,
    logicalTs: ts,
    status: 'active',
    createdAt: now,
  };

  g.nodes.set(nodeId, node);
  g.adjOut.set(nodeId, new Set());
  g.adjIn.set(nodeId, new Set());
  g.updatedAt = now;

  // Auto-create generation edge if sourceActivation exists
  if (sourceActivation && g.nodes.has(sourceActivation)) {
    await addEdge(graphId, sourceActivation, nodeId, EDGE_TYPE_GENERATION);
  }

  await _persistNode(graphId, node);

  _audit(g, 'add_event', nodeId, { eventType, sourceActivation, logicalTs: ts });

  return { nodeId, logicalTs: ts };
}

/**
 * Add a typed edge between two nodes.
 *
 * @param {string} graphId
 * @param {string} fromId
 * @param {string} toId
 * @param {'generation'|'delivery'} edgeType
 * @returns {Promise<{ edgeId: string }>}
 */
export async function addEdge(graphId, fromId, toId, edgeType) {
  const g = _requireGraph(graphId);

  if (!g.nodes.has(fromId)) throw new Error(`Source node ${fromId} not found in graph ${graphId}`);
  if (!g.nodes.has(toId)) throw new Error(`Target node ${toId} not found in graph ${graphId}`);

  // Validate bipartite constraint
  const fromNode = g.nodes.get(fromId);
  const toNode = g.nodes.get(toId);

  if (edgeType === EDGE_TYPE_GENERATION) {
    if (fromNode.type !== NODE_TYPE_ACTIVATION || toNode.type !== NODE_TYPE_EVENT) {
      throw new Error('Generation edges must go from activation → event');
    }
  } else if (edgeType === EDGE_TYPE_DELIVERY) {
    if (fromNode.type !== NODE_TYPE_EVENT || toNode.type !== NODE_TYPE_ACTIVATION) {
      throw new Error('Delivery edges must go from event → activation');
    }
  } else {
    throw new Error(`Unknown edge type: ${edgeType}`);
  }

  // Check for duplicate
  const existingOut = g.adjOut.get(fromId) || new Set();
  for (const eid of existingOut) {
    const e = g.edges.get(eid);
    if (e && e.to === toId && e.edgeType === edgeType) {
      return { edgeId: eid }; // idempotent
    }
  }

  const ts = _advanceClock(g);
  const edgeId = nextId('edg');
  const now = new Date().toISOString();

  /** @type {DIGEdge} */
  const edge = {
    id: edgeId,
    from: fromId,
    to: toId,
    edgeType,
    logicalTs: ts,
    createdAt: now,
  };

  g.edges.set(edgeId, edge);
  _ensureAdj(g, fromId).adjOut.add(edgeId);
  _ensureAdj(g, toId).adjIn.add(edgeId);
  g.updatedAt = now;

  await _persistEdge(graphId, edge);

  return { edgeId };
}

// ─── REWRITE OPERATORS ──────────────────────────────────────────────────────

/**
 * Apply a graph rewrite operator to a node.
 *
 * @param {string} graphId
 * @param {'RESPOND'|'WAIT'|'REROUTE'|'DISCARD'|'SUBMIT'} operator
 * @param {string} nodeId
 * @param {Object} [params]
 * @param {string}   [params.targetAgentId]  — for REROUTE
 * @param {Object}   [params.waitCondition]  — for WAIT
 * @param {string}   [params.reason]         — for DISCARD
 * @param {string[]} [params.generatedEventIds] — for RESPOND
 * @returns {Promise<{ success: boolean, details: Object }>}
 */
export async function applyOperator(graphId, operator, nodeId, params = {}) {
  const g = _requireGraph(graphId);
  const node = g.nodes.get(nodeId);
  if (!node) throw new Error(`Node ${nodeId} not found in graph ${graphId}`);

  const op = String(operator).toUpperCase();
  if (!OPERATORS[op]) throw new Error(`Unknown operator: ${operator}. Valid: ${Object.keys(OPERATORS).join(', ')}`);

  let details;

  switch (op) {
    case OPERATORS.RESPOND:
      details = await _applyRespond(g, node, params);
      break;
    case OPERATORS.WAIT:
      details = await _applyWait(g, node, params);
      break;
    case OPERATORS.REROUTE:
      details = await _applyReroute(g, node, params);
      break;
    case OPERATORS.DISCARD:
      details = await _applyDiscard(g, node, params);
      break;
    case OPERATORS.SUBMIT:
      details = await _applySubmit(g, node, params);
      break;
    default:
      throw new Error(`Unhandled operator: ${op}`);
  }

  _audit(g, op, nodeId, { ...params, ...details });
  g.updatedAt = new Date().toISOString();

  await logEvent(COMPANY, 'interaction-graph-healer', `operator_${op.toLowerCase()}`, graphId, {
    reasoning: `Applied ${op} operator to node ${nodeId} — graph rewrite per DIG protocol`,
    nodeId,
    operator: op,
    details,
  });

  return { success: true, details };
}

/**
 * RESPOND — agent processes an event and generates new events.
 * Marks the activation as completed, links generated events.
 */
async function _applyRespond(g, node, params) {
  if (node.type !== NODE_TYPE_ACTIVATION) {
    throw new Error('RESPOND can only be applied to activation nodes');
  }

  node.status = 'completed';

  const generatedIds = params.generatedEventIds || [];
  const linkedEvents = [];

  for (const evtId of generatedIds) {
    if (g.nodes.has(evtId)) {
      const evtNode = g.nodes.get(evtId);
      if (evtNode.type === NODE_TYPE_EVENT) {
        // Ensure generation edge exists
        await addEdge(g.graphId, node.id, evtId, EDGE_TYPE_GENERATION);
        linkedEvents.push(evtId);
      }
    }
  }

  return { linkedEvents, status: 'completed' };
}

/**
 * WAIT — agent defers processing until a condition is met.
 * Stores the wait condition on the node for later evaluation.
 */
async function _applyWait(g, node, params) {
  if (node.type !== NODE_TYPE_ACTIVATION) {
    throw new Error('WAIT can only be applied to activation nodes');
  }

  const condition = params.waitCondition || { type: 'manual' };
  node.status = 'waiting';
  node.waitCondition = {
    ...condition,
    waitingSince: Date.now(),
    timeoutMs: condition.timeoutMs || DEADLOCK_WAIT_MS,
  };

  return { status: 'waiting', condition: node.waitCondition };
}

/**
 * REROUTE — redirect an event to a different agent.
 * Removes existing delivery edges from the event and creates a new one.
 */
async function _applyReroute(g, node, params) {
  if (node.type !== NODE_TYPE_EVENT) {
    throw new Error('REROUTE can only be applied to event nodes');
  }

  const targetAgentId = params.targetAgentId;
  if (!targetAgentId) throw new Error('REROUTE requires params.targetAgentId');

  // Count existing reroutes for this event
  const rerouteCount = _countReroutes(g, node.id);

  // Remove existing delivery edges from this event
  const outEdges = g.adjOut.get(node.id) || new Set();
  const removedDeliveries = [];
  for (const eid of [...outEdges]) {
    const edge = g.edges.get(eid);
    if (edge && edge.edgeType === EDGE_TYPE_DELIVERY) {
      removedDeliveries.push({ edgeId: eid, toNode: edge.to });
      _removeEdge(g, eid);
    }
  }

  // Find or create activation for target agent
  let targetActivation = _findActiveActivation(g, targetAgentId);
  if (!targetActivation) {
    const { nodeId } = await addActivation(g.graphId, targetAgentId);
    targetActivation = g.nodes.get(nodeId);
  }

  // Create delivery edge to the new target
  await addEdge(g.graphId, node.id, targetActivation.id, EDGE_TYPE_DELIVERY);

  return {
    removedDeliveries,
    newTarget: targetActivation.id,
    targetAgentId,
    rerouteCount: rerouteCount + 1,
  };
}

/**
 * DISCARD — drop an event with an auditable justification.
 * The event is marked as discarded but NOT removed (audit trail).
 */
async function _applyDiscard(g, node, params) {
  if (node.type !== NODE_TYPE_EVENT) {
    throw new Error('DISCARD can only be applied to event nodes');
  }

  const reason = params.reason || 'No reason provided';
  node.status = 'discarded';
  node.discardReason = reason;
  node.discardedAt = new Date().toISOString();

  return { status: 'discarded', reason };
}

/**
 * SUBMIT — mark an event as the final output of this collaboration.
 */
async function _applySubmit(g, node, params) {
  if (node.type !== NODE_TYPE_EVENT) {
    throw new Error('SUBMIT can only be applied to event nodes');
  }

  node.status = 'submitted';
  node.submittedAt = new Date().toISOString();

  return { status: 'submitted', eventType: node.eventType };
}

// ─── FAILURE DETECTION ──────────────────────────────────────────────────────

/**
 * Scan the graph for all 7 structural failure patterns.
 *
 * @param {string} graphId
 * @returns {Promise<Array<{ pattern: string, severity: string, nodes: string[], description: string }>>}
 */
export async function detectFailures(graphId) {
  const g = _requireGraph(graphId);
  const failures = [];

  // 1. FATAL: Early Termination
  //    An activation node completed but produced no generation edges (no output)
  //    while other activations are still waiting for its output.
  const earlyTerminations = _detectEarlyTermination(g);
  failures.push(...earlyTerminations);

  // 2. FATAL: Missing Completion
  //    An activation has been active for too long without completing.
  //    Indicates an agent that started but never finished.
  const missingCompletions = _detectMissingCompletion(g);
  failures.push(...missingCompletions);

  // 3. FATAL: Orphaned Event
  //    An event node with no outgoing delivery edges and not submitted/discarded.
  //    It was generated but never consumed by any agent.
  const orphanedEvents = _detectOrphanedEvents(g);
  failures.push(...orphanedEvents);

  // 4. FATAL: Deadlock
  //    A cycle of activations all in 'waiting' status, each waiting for
  //    events that can only be produced by another waiting activation.
  const deadlocks = _detectDeadlocks(g);
  failures.push(...deadlocks);

  // 5. WARNING: Excessive Rerouting
  //    An event has been rerouted more than MAX_REROUTE_COUNT times.
  const excessiveReroutes = _detectExcessiveRerouting(g);
  failures.push(...excessiveReroutes);

  // 6. WARNING: Cross-lineage Aggregation
  //    An activation receives events from multiple independent causal lineages
  //    without any prior merge point. Can cause incoherent reasoning.
  const crossLineage = _detectCrossLineageAggregation(g);
  failures.push(...crossLineage);

  // 7. WARNING: Repeated Subproblem
  //    Multiple activations of the same agent type process events with
  //    highly similar content, wasting compute.
  const repeatedSubs = _detectRepeatedSubproblem(g);
  failures.push(...repeatedSubs);

  await logEvent(COMPANY, 'interaction-graph-healer', 'failure_detection', graphId, {
    reasoning: `Scanned graph for 7 failure patterns — found ${failures.length} issue(s)`,
    failureCount: failures.length,
    fatal: failures.filter(f => f.severity === FAILURE_SEVERITY.FATAL).length,
    warning: failures.filter(f => f.severity === FAILURE_SEVERITY.WARNING).length,
  });

  return failures;
}

/**
 * Detect Early Termination: activation completed with no output events,
 * while downstream activations depend on it.
 */
function _detectEarlyTermination(g) {
  const failures = [];

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_ACTIVATION || node.status !== 'completed') continue;

    // Check if this activation generated any events
    const outEdges = g.adjOut.get(nodeId) || new Set();
    let hasGeneration = false;
    for (const eid of outEdges) {
      const edge = g.edges.get(eid);
      if (edge && edge.edgeType === EDGE_TYPE_GENERATION) {
        hasGeneration = true;
        break;
      }
    }

    if (hasGeneration) continue;

    // Check if any other activation was expecting events from this one
    // by looking for delivery edges that fed INTO this activation
    const inEdges = g.adjIn.get(nodeId) || new Set();
    const hasIncoming = inEdges.size > 0;

    // An activation that completed with no output and had incoming events
    // means it consumed but produced nothing — early termination
    if (hasIncoming) {
      failures.push({
        pattern: FAILURE_PATTERNS.EARLY_TERMINATION.id,
        severity: FAILURE_PATTERNS.EARLY_TERMINATION.severity,
        nodes: [nodeId],
        description: `Activation ${nodeId} (agent: ${node.agentId}) completed without generating any events despite receiving input`,
      });
    }
  }

  return failures;
}

/**
 * Detect Missing Completion: activations stuck in 'active' status for too long.
 */
function _detectMissingCompletion(g) {
  const failures = [];
  const now = Date.now();
  const staleCutoff = now - DEADLOCK_WAIT_MS;

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_ACTIVATION) continue;
    if (node.status !== 'active') continue;

    const createdMs = new Date(node.createdAt).getTime();
    if (createdMs < staleCutoff) {
      const staleDuration = Math.round((now - createdMs) / 1000);
      failures.push({
        pattern: FAILURE_PATTERNS.MISSING_COMPLETION.id,
        severity: FAILURE_PATTERNS.MISSING_COMPLETION.severity,
        nodes: [nodeId],
        description: `Activation ${nodeId} (agent: ${node.agentId}) has been active for ${staleDuration}s without completing`,
      });
    }
  }

  return failures;
}

/**
 * Detect Orphaned Events: event nodes with no outgoing delivery edges
 * and not in a terminal status.
 */
function _detectOrphanedEvents(g) {
  const failures = [];

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_EVENT) continue;
    if (node.status === 'discarded' || node.status === 'submitted') continue;

    const outEdges = g.adjOut.get(nodeId) || new Set();
    let hasDelivery = false;
    for (const eid of outEdges) {
      const edge = g.edges.get(eid);
      if (edge && edge.edgeType === EDGE_TYPE_DELIVERY) {
        hasDelivery = true;
        break;
      }
    }

    if (!hasDelivery) {
      // Allow a grace period — very new events may not yet have deliveries
      const ageMs = Date.now() - new Date(node.createdAt).getTime();
      if (ageMs > 5000) {
        failures.push({
          pattern: FAILURE_PATTERNS.ORPHANED_EVENT.id,
          severity: FAILURE_PATTERNS.ORPHANED_EVENT.severity,
          nodes: [nodeId],
          description: `Event ${nodeId} (type: ${node.eventType}) has no delivery edges and is not submitted/discarded`,
        });
      }
    }
  }

  return failures;
}

/**
 * Detect Deadlocks: cycles of activations all in 'waiting' status.
 * Uses DFS-based cycle detection on the dependency subgraph.
 */
function _detectDeadlocks(g) {
  const failures = [];

  // Build a dependency graph: waiting activation A depends on waiting activation B
  // if A is waiting for an event that can only come from B.
  const waitingActivations = new Map();
  for (const [nodeId, node] of g.nodes) {
    if (node.type === NODE_TYPE_ACTIVATION && node.status === 'waiting') {
      waitingActivations.set(nodeId, node);
    }
  }

  if (waitingActivations.size < 2) {
    // Check for single-activation timeouts
    const now = Date.now();
    for (const [actId, node] of waitingActivations) {
      if (!node.waitCondition) continue;
      const waitStart = node.waitCondition.waitingSince || new Date(node.createdAt).getTime();
      const timeout = node.waitCondition.timeoutMs || DEADLOCK_WAIT_MS;
      if (now - waitStart > timeout) {
        failures.push({
          pattern: FAILURE_PATTERNS.DEADLOCK.id,
          severity: FAILURE_PATTERNS.DEADLOCK.severity,
          nodes: [actId],
          description: `Activation ${actId} (agent: ${node.agentId}) exceeded wait timeout of ${timeout}ms`,
        });
      }
    }
    return failures;
  }

  // Build dependency adjacency: A → B means A waits on something B should produce
  const deps = new Map();
  for (const [actId] of waitingActivations) {
    deps.set(actId, new Set());
  }

  // For each waiting activation, find what events it's waiting for.
  // An activation is "waiting for" events from other activations that have
  // delivery edges pointing to it but haven't been generated yet.
  for (const [actId] of waitingActivations) {
    // Find events delivered to this activation
    const inEdges = g.adjIn.get(actId) || new Set();
    for (const eid of inEdges) {
      const edge = g.edges.get(eid);
      if (!edge || edge.edgeType !== EDGE_TYPE_DELIVERY) continue;

      const eventNode = g.nodes.get(edge.from);
      if (!eventNode || eventNode.status === 'discarded') continue;

      // Find the activation that should generate events for this waiting one
      // by looking at what agents haven't completed
      if (eventNode.sourceActivation && waitingActivations.has(eventNode.sourceActivation)) {
        deps.get(actId).add(eventNode.sourceActivation);
      }
    }

    // Also check: the activation's wait condition may reference specific agents
    const node = waitingActivations.get(actId);
    if (node.waitCondition && node.waitCondition.dependsOn) {
      const depAgents = Array.isArray(node.waitCondition.dependsOn)
        ? node.waitCondition.dependsOn
        : [node.waitCondition.dependsOn];

      for (const depAgentId of depAgents) {
        for (const [otherId, otherNode] of waitingActivations) {
          if (otherId !== actId && otherNode.agentId === depAgentId) {
            deps.get(actId).add(otherId);
          }
        }
      }
    }
  }

  // DFS cycle detection
  const visited = new Set();
  const inStack = new Set();
  const cycles = [];

  function dfs(nodeId, path) {
    if (inStack.has(nodeId)) {
      const cycleStart = path.indexOf(nodeId);
      if (cycleStart >= 0) {
        cycles.push(path.slice(cycleStart));
      }
      return;
    }
    if (visited.has(nodeId)) return;

    visited.add(nodeId);
    inStack.add(nodeId);
    path.push(nodeId);

    const neighbours = deps.get(nodeId) || new Set();
    for (const nbr of neighbours) {
      dfs(nbr, [...path]);
    }

    inStack.delete(nodeId);
  }

  for (const [actId] of waitingActivations) {
    if (!visited.has(actId)) {
      dfs(actId, []);
    }
  }

  // Deduplicate cycles (same set of nodes)
  const seen = new Set();
  for (const cycle of cycles) {
    const key = [...cycle].sort().join(',');
    if (seen.has(key)) continue;
    seen.add(key);

    const agents = cycle.map(id => waitingActivations.get(id)?.agentId || id).join(' → ');
    failures.push({
      pattern: FAILURE_PATTERNS.DEADLOCK.id,
      severity: FAILURE_PATTERNS.DEADLOCK.severity,
      nodes: cycle,
      description: `Deadlock detected: waiting cycle among activations: ${agents}`,
    });
  }

  // Also detect timeout-based deadlocks: individual activations waiting too long
  const now = Date.now();
  for (const [actId, node] of waitingActivations) {
    if (!node.waitCondition) continue;
    const waitStart = node.waitCondition.waitingSince || new Date(node.createdAt).getTime();
    const timeout = node.waitCondition.timeoutMs || DEADLOCK_WAIT_MS;
    if (now - waitStart > timeout) {
      failures.push({
        pattern: FAILURE_PATTERNS.DEADLOCK.id,
        severity: FAILURE_PATTERNS.DEADLOCK.severity,
        nodes: [actId],
        description: `Activation ${actId} (agent: ${node.agentId}) exceeded wait timeout of ${timeout}ms`,
      });
    }
  }

  return failures;
}

/**
 * Detect Excessive Rerouting: events rerouted more than MAX_REROUTE_COUNT times.
 */
function _detectExcessiveRerouting(g) {
  const failures = [];

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_EVENT) continue;

    const count = _countReroutes(g, nodeId);
    if (count > MAX_REROUTE_COUNT) {
      failures.push({
        pattern: FAILURE_PATTERNS.EXCESSIVE_REROUTING.id,
        severity: FAILURE_PATTERNS.EXCESSIVE_REROUTING.severity,
        nodes: [nodeId],
        description: `Event ${nodeId} has been rerouted ${count} times (threshold: ${MAX_REROUTE_COUNT})`,
      });
    }
  }

  return failures;
}

/**
 * Detect Cross-lineage Aggregation: an activation receives events from
 * multiple independent causal lineages without a shared ancestor.
 */
function _detectCrossLineageAggregation(g) {
  const failures = [];

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_ACTIVATION) continue;

    // Gather all events delivered to this activation
    const inEdges = g.adjIn.get(nodeId) || new Set();
    const incomingEvents = [];
    for (const eid of inEdges) {
      const edge = g.edges.get(eid);
      if (edge && edge.edgeType === EDGE_TYPE_DELIVERY) {
        incomingEvents.push(edge.from);
      }
    }

    if (incomingEvents.length < 2) continue;

    // For each incoming event, trace back its causal lineage (root ancestors)
    const lineageRoots = new Map();
    for (const evtId of incomingEvents) {
      const roots = _traceLineageRoots(g, evtId);
      lineageRoots.set(evtId, roots);
    }

    // Check if lineages share any common root
    const allRoots = [...lineageRoots.values()];
    let hasSharedRoot = false;

    if (allRoots.length >= 2) {
      const firstRoots = allRoots[0];
      for (let i = 1; i < allRoots.length; i++) {
        for (const root of allRoots[i]) {
          if (firstRoots.has(root)) {
            hasSharedRoot = true;
            break;
          }
        }
        if (hasSharedRoot) break;
      }
    }

    if (!hasSharedRoot && incomingEvents.length >= 2) {
      failures.push({
        pattern: FAILURE_PATTERNS.CROSS_LINEAGE_AGGREGATION.id,
        severity: FAILURE_PATTERNS.CROSS_LINEAGE_AGGREGATION.severity,
        nodes: [nodeId, ...incomingEvents],
        description: `Activation ${nodeId} (agent: ${node.agentId}) aggregates events from ${incomingEvents.length} independent lineages`,
      });
    }
  }

  return failures;
}

/**
 * Detect Repeated Subproblem: same agent type processing highly similar events.
 */
function _detectRepeatedSubproblem(g) {
  const failures = [];

  // Group activations by agentId
  const byAgent = new Map();
  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_ACTIVATION) continue;
    if (!byAgent.has(node.agentId)) byAgent.set(node.agentId, []);
    byAgent.get(node.agentId).push(node);
  }

  for (const [agentId, activations] of byAgent) {
    if (activations.length < 2) continue;

    // Collect event content delivered to each activation
    const activationContents = [];
    for (const act of activations) {
      const inEdges = g.adjIn.get(act.id) || new Set();
      const contents = [];
      for (const eid of inEdges) {
        const edge = g.edges.get(eid);
        if (!edge || edge.edgeType !== EDGE_TYPE_DELIVERY) continue;
        const evtNode = g.nodes.get(edge.from);
        if (evtNode && evtNode.content) {
          contents.push(_contentFingerprint(evtNode.content));
        }
      }
      if (contents.length > 0) {
        activationContents.push({ act, fingerprint: contents.join('|') });
      }
    }

    // Compare fingerprints pairwise
    for (let i = 0; i < activationContents.length; i++) {
      for (let j = i + 1; j < activationContents.length; j++) {
        const sim = _stringSimilarity(
          activationContents[i].fingerprint,
          activationContents[j].fingerprint
        );
        if (sim > MAX_REPEATED_CONTENT_SIMILARITY) {
          failures.push({
            pattern: FAILURE_PATTERNS.REPEATED_SUBPROBLEM.id,
            severity: FAILURE_PATTERNS.REPEATED_SUBPROBLEM.severity,
            nodes: [activationContents[i].act.id, activationContents[j].act.id],
            description: `Agent ${agentId} processes highly similar content (similarity: ${(sim * 100).toFixed(1)}%) in activations ${activationContents[i].act.id} and ${activationContents[j].act.id}`,
          });
        }
      }
    }
  }

  return failures;
}

// ─── HEALING ENGINE ─────────────────────────────────────────────────────────

/**
 * Apply structure-level interventions for detected failures.
 * Never modifies agent internals — only graph structure.
 *
 * @param {string} graphId
 * @param {Array<{ pattern: string, severity: string, nodes: string[], description: string }>} failures
 * @returns {Promise<Array<{ failure: string, intervention: string, details: Object }>>}
 */
export async function healGraph(graphId, failures) {
  const g = _requireGraph(graphId);
  const interventions = [];

  if (!failures || failures.length === 0) return interventions;

  for (const failure of failures) {
    let result;

    switch (failure.pattern) {
      case FAILURE_PATTERNS.EARLY_TERMINATION.id:
        result = await _healEarlyTermination(g, failure);
        break;
      case FAILURE_PATTERNS.MISSING_COMPLETION.id:
        result = await _healMissingCompletion(g, failure);
        break;
      case FAILURE_PATTERNS.ORPHANED_EVENT.id:
        result = await _healOrphanedEvent(g, failure);
        break;
      case FAILURE_PATTERNS.DEADLOCK.id:
        result = await _healDeadlock(g, failure);
        break;
      case FAILURE_PATTERNS.EXCESSIVE_REROUTING.id:
        result = await _healExcessiveRerouting(g, failure);
        break;
      case FAILURE_PATTERNS.CROSS_LINEAGE_AGGREGATION.id:
        result = await _healCrossLineageAggregation(g, failure);
        break;
      case FAILURE_PATTERNS.REPEATED_SUBPROBLEM.id:
        result = await _healRepeatedSubproblem(g, failure);
        break;
      default:
        result = { intervention: 'none', details: { reason: `No healer for pattern: ${failure.pattern}` } };
    }

    interventions.push({
      failure: failure.pattern,
      intervention: result.intervention,
      details: result.details,
    });

    _audit(g, 'heal', failure.nodes[0] || graphId, {
      pattern: failure.pattern,
      intervention: result.intervention,
      ...result.details,
    });
  }

  g.updatedAt = new Date().toISOString();

  await logEvent(COMPANY, 'interaction-graph-healer', 'graph_healed', graphId, {
    reasoning: `Applied ${interventions.length} intervention(s) to heal structural failures in DIG`,
    interventions: interventions.map(i => ({ failure: i.failure, intervention: i.intervention })),
  });

  return interventions;
}

/**
 * Heal Early Termination: inject a system event that re-activates the
 * terminated agent with context about what output was expected.
 */
async function _healEarlyTermination(g, failure) {
  const actId = failure.nodes[0];
  const actNode = g.nodes.get(actId);
  if (!actNode) return { intervention: 'skip', details: { reason: 'Node no longer exists' } };

  // Create a system event prompting the agent to complete its task
  const { nodeId: sysEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'early_termination_recovery',
    message: `Agent ${actNode.agentId} completed without producing output. Re-invoking with original context.`,
    originalActivation: actId,
  });

  // Re-create an activation for the same agent
  const { nodeId: newActId } = await addActivation(g.graphId, actNode.agentId);

  // Deliver the system event to the new activation
  await addEdge(g.graphId, sysEvtId, newActId, EDGE_TYPE_DELIVERY);

  // Also forward original incoming events to the new activation
  const inEdges = g.adjIn.get(actId) || new Set();
  for (const eid of inEdges) {
    const edge = g.edges.get(eid);
    if (edge && edge.edgeType === EDGE_TYPE_DELIVERY) {
      await addEdge(g.graphId, edge.from, newActId, EDGE_TYPE_DELIVERY);
    }
  }

  return {
    intervention: INTERVENTION_TYPES.CREATE_SYSTEM_EVENT,
    details: {
      systemEventId: sysEvtId,
      newActivationId: newActId,
      originalActivation: actId,
      agentId: actNode.agentId,
    },
  };
}

/**
 * Heal Missing Completion: inject an info event prompting the stale
 * activation to either complete or yield.
 */
async function _healMissingCompletion(g, failure) {
  const actId = failure.nodes[0];
  const actNode = g.nodes.get(actId);
  if (!actNode) return { intervention: 'skip', details: { reason: 'Node no longer exists' } };

  const staleMs = Date.now() - new Date(actNode.createdAt).getTime();

  // Inject an info event to the stale activation
  const { nodeId: infoEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'completion_nudge',
    message: `Activation ${actId} has been active for ${Math.round(staleMs / 1000)}s without completing. Please complete or yield.`,
    staleDurationMs: staleMs,
  });

  await addEdge(g.graphId, infoEvtId, actId, EDGE_TYPE_DELIVERY);

  return {
    intervention: INTERVENTION_TYPES.INJECT_INFO,
    details: {
      infoEventId: infoEvtId,
      activationId: actId,
      agentId: actNode.agentId,
      staleDurationMs: staleMs,
    },
  };
}

/**
 * Heal Orphaned Event: find the best available agent to route the event to.
 * Uses topological inference to select an appropriate recipient.
 */
async function _healOrphanedEvent(g, failure) {
  const evtId = failure.nodes[0];
  const evtNode = g.nodes.get(evtId);
  if (!evtNode) return { intervention: 'skip', details: { reason: 'Node no longer exists' } };

  // Find the best agent to handle this event via topological analysis:
  // prefer agents that have handled similar event types before
  const agentScores = new Map();

  for (const [nodeId, node] of g.nodes) {
    if (node.type !== NODE_TYPE_ACTIVATION || node.status === 'discarded') continue;

    // Score: count how many events of the same type this agent has processed
    const inEdges = g.adjIn.get(nodeId) || new Set();
    let score = 0;
    for (const eid of inEdges) {
      const edge = g.edges.get(eid);
      if (!edge || edge.edgeType !== EDGE_TYPE_DELIVERY) continue;
      const srcEvt = g.nodes.get(edge.from);
      if (srcEvt && srcEvt.eventType === evtNode.eventType) {
        score += 1;
      }
    }

    // Prefer active agents over completed ones
    if (node.status === 'active') score += 2;

    if (score > 0) {
      const existing = agentScores.get(node.agentId) || { score: 0, nodeId };
      if (score > existing.score) {
        agentScores.set(node.agentId, { score, nodeId });
      }
    }
  }

  if (agentScores.size === 0) {
    // No suitable agent found — create a system event flagging this for the orchestrator
    const { nodeId: sysEvtId } = await addEvent(g.graphId, 'system_heal', {
      type: 'orphan_escalation',
      message: `Event ${evtId} (type: ${evtNode.eventType}) is orphaned and no suitable agent was found`,
      orphanedEventId: evtId,
    });

    return {
      intervention: INTERVENTION_TYPES.CREATE_SYSTEM_EVENT,
      details: {
        systemEventId: sysEvtId,
        orphanedEventId: evtId,
        outcome: 'escalated_to_orchestrator',
      },
    };
  }

  // Route to best-scoring agent
  const best = [...agentScores.entries()].sort((a, b) => b[1].score - a[1].score)[0];
  const [targetAgentId, { nodeId: targetNodeId }] = best;

  let targetActivation = g.nodes.get(targetNodeId);

  // If the target activation is completed, create a new one
  if (targetActivation.status === 'completed') {
    const { nodeId: newActId } = await addActivation(g.graphId, targetAgentId);
    targetActivation = g.nodes.get(newActId);
  }

  await addEdge(g.graphId, evtId, targetActivation.id, EDGE_TYPE_DELIVERY);

  return {
    intervention: INTERVENTION_TYPES.INJECT_AND_REROUTE,
    details: {
      orphanedEventId: evtId,
      routedTo: targetActivation.id,
      targetAgentId,
    },
  };
}

/**
 * Heal Deadlock: break the cycle by injecting a system event that
 * releases one of the waiting activations.
 */
async function _healDeadlock(g, failure) {
  const nodeIds = failure.nodes;

  if (nodeIds.length === 1) {
    // Single activation timeout — force-complete it
    const actNode = g.nodes.get(nodeIds[0]);
    if (actNode) {
      actNode.status = 'completed';
      actNode.waitCondition = null;

      const { nodeId: sysEvtId } = await addEvent(g.graphId, 'system_heal', {
        type: 'wait_timeout_release',
        message: `Activation ${nodeIds[0]} (agent: ${actNode.agentId}) was released due to wait timeout`,
        releasedActivation: nodeIds[0],
      });

      return {
        intervention: INTERVENTION_TYPES.CREATE_SYSTEM_EVENT,
        details: {
          systemEventId: sysEvtId,
          releasedActivation: nodeIds[0],
          agentId: actNode.agentId,
          strategy: 'timeout_release',
        },
      };
    }
  }

  // Cycle deadlock — pick the activation with the lowest logical timestamp
  // (the one that's been waiting longest) and release it with injected context
  const cycleNodes = nodeIds
    .map(id => g.nodes.get(id))
    .filter(Boolean)
    .sort((a, b) => a.logicalTs - b.logicalTs);

  if (cycleNodes.length === 0) {
    return { intervention: 'skip', details: { reason: 'Cycle nodes no longer exist' } };
  }

  const victim = cycleNodes[0];
  victim.status = 'active';
  victim.waitCondition = null;

  // Inject a system event explaining the deadlock break
  const { nodeId: sysEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'deadlock_break',
    message: `Deadlock detected among ${nodeIds.length} activations. Releasing ${victim.id} (agent: ${victim.agentId}) to break cycle.`,
    cycleParticipants: nodeIds,
    releasedActivation: victim.id,
  });

  await addEdge(g.graphId, sysEvtId, victim.id, EDGE_TYPE_DELIVERY);

  return {
    intervention: INTERVENTION_TYPES.CREATE_SYSTEM_EVENT,
    details: {
      systemEventId: sysEvtId,
      releasedActivation: victim.id,
      agentId: victim.agentId,
      cycleSize: nodeIds.length,
      strategy: 'cycle_break_oldest',
    },
  };
}

/**
 * Heal Excessive Rerouting: inject info about the reroute cap and force
 * delivery to the current target rather than allowing infinite reroutes.
 */
async function _healExcessiveRerouting(g, failure) {
  const evtId = failure.nodes[0];
  const evtNode = g.nodes.get(evtId);
  if (!evtNode) return { intervention: 'skip', details: { reason: 'Node no longer exists' } };

  const rerouteCount = _countReroutes(g, evtId);

  // Inject info event explaining the reroute cap
  const { nodeId: infoEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'reroute_cap',
    message: `Event ${evtId} has been rerouted ${rerouteCount} times (max: ${MAX_REROUTE_COUNT}). Forcing delivery to current target.`,
    originalEventId: evtId,
    rerouteCount,
  });

  // Find current delivery target and inject the info event there too
  const outEdges = g.adjOut.get(evtId) || new Set();
  for (const eid of outEdges) {
    const edge = g.edges.get(eid);
    if (edge && edge.edgeType === EDGE_TYPE_DELIVERY) {
      await addEdge(g.graphId, infoEvtId, edge.to, EDGE_TYPE_DELIVERY);
      break; // deliver info to the current target only
    }
  }

  return {
    intervention: INTERVENTION_TYPES.INJECT_INFO,
    details: {
      infoEventId: infoEvtId,
      originalEventId: evtId,
      rerouteCount,
      action: 'capped_rerouting',
    },
  };
}

/**
 * Heal Cross-lineage Aggregation: inject a merge context event that
 * explains the lineage divergence to the aggregating agent.
 */
async function _healCrossLineageAggregation(g, failure) {
  const actId = failure.nodes[0];
  const eventIds = failure.nodes.slice(1);
  const actNode = g.nodes.get(actId);
  if (!actNode) return { intervention: 'skip', details: { reason: 'Node no longer exists' } };

  // Build lineage summaries for each incoming event
  const lineageSummaries = [];
  for (const evtId of eventIds) {
    const roots = _traceLineageRoots(g, evtId);
    const rootAgents = [...roots]
      .map(id => g.nodes.get(id)?.agentId || 'unknown')
      .filter(Boolean);
    lineageSummaries.push({
      eventId: evtId,
      rootAgents,
      eventType: g.nodes.get(evtId)?.eventType || 'unknown',
    });
  }

  // Inject a context-setting event so the agent knows about divergent lineages
  const { nodeId: ctxEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'lineage_context',
    message: `This activation receives events from ${eventIds.length} independent lineages. Summaries attached for coherent reasoning.`,
    lineageSummaries,
    aggregatingActivation: actId,
  });

  await addEdge(g.graphId, ctxEvtId, actId, EDGE_TYPE_DELIVERY);

  return {
    intervention: INTERVENTION_TYPES.INJECT_INFO,
    details: {
      contextEventId: ctxEvtId,
      activationId: actId,
      agentId: actNode.agentId,
      lineageCount: eventIds.length,
      lineageSummaries,
    },
  };
}

/**
 * Heal Repeated Subproblem: discard the duplicate activation and reroute
 * downstream consumers to the original activation's output.
 */
async function _healRepeatedSubproblem(g, failure) {
  const [firstActId, duplicateActId] = failure.nodes;
  const firstAct = g.nodes.get(firstActId);
  const dupAct = g.nodes.get(duplicateActId);

  if (!firstAct || !dupAct) {
    return { intervention: 'skip', details: { reason: 'One or both nodes no longer exist' } };
  }

  // Keep the first activation (lower logical timestamp), discard the duplicate
  const [keeper, discard] = firstAct.logicalTs <= dupAct.logicalTs
    ? [firstAct, dupAct]
    : [dupAct, firstAct];

  // Mark the duplicate as completed (not discarded, since its events may be useful)
  discard.status = 'completed';

  // If the keeper has produced events, route them to anyone waiting on the duplicate
  const keeperOutEdges = g.adjOut.get(keeper.id) || new Set();
  const keeperEvents = [];
  for (const eid of keeperOutEdges) {
    const edge = g.edges.get(eid);
    if (edge && edge.edgeType === EDGE_TYPE_GENERATION) {
      keeperEvents.push(edge.to);
    }
  }

  // Find activations that receive events from the duplicate
  const discardOutEdges = g.adjOut.get(discard.id) || new Set();
  const redirected = [];
  for (const eid of discardOutEdges) {
    const edge = g.edges.get(eid);
    if (!edge || edge.edgeType !== EDGE_TYPE_GENERATION) continue;
    const discardEvt = edge.to;

    // Find who this event is delivered to
    const evtOutEdges = g.adjOut.get(discardEvt) || new Set();
    for (const evtEid of evtOutEdges) {
      const delEdge = g.edges.get(evtEid);
      if (!delEdge || delEdge.edgeType !== EDGE_TYPE_DELIVERY) continue;

      // Redirect: deliver keeper's events to the downstream activation
      for (const keeperEvtId of keeperEvents) {
        await addEdge(g.graphId, keeperEvtId, delEdge.to, EDGE_TYPE_DELIVERY);
        redirected.push({ from: discardEvt, to: keeperEvtId, downstream: delEdge.to });
      }
    }
  }

  // Inject info about the deduplication
  const { nodeId: infoEvtId } = await addEvent(g.graphId, 'system_heal', {
    type: 'subproblem_dedup',
    message: `Duplicate activation ${discard.id} (agent: ${discard.agentId}) merged with ${keeper.id}`,
    keeperActivation: keeper.id,
    discardedActivation: discard.id,
  });

  return {
    intervention: INTERVENTION_TYPES.INJECT_AND_REROUTE,
    details: {
      infoEventId: infoEvtId,
      keeperActivation: keeper.id,
      discardedActivation: discard.id,
      agentId: keeper.agentId,
      redirectedEdges: redirected.length,
    },
  };
}

// ─── GRAPH QUERY ────────────────────────────────────────────────────────────

/**
 * Retrieve the full graph state for visualization / topological inference.
 *
 * @param {string} graphId
 * @returns {Promise<Object>}
 */
export async function getGraphState(graphId) {
  const g = _requireGraph(graphId);

  const nodes = [];
  for (const [, node] of g.nodes) {
    nodes.push({ ...node });
  }

  const edges = [];
  for (const [, edge] of g.edges) {
    edges.push({ ...edge });
  }

  // Compute graph statistics
  const activations = nodes.filter(n => n.type === NODE_TYPE_ACTIVATION);
  const events = nodes.filter(n => n.type === NODE_TYPE_EVENT);

  const stats = {
    totalNodes: nodes.length,
    activationCount: activations.length,
    eventCount: events.length,
    edgeCount: edges.length,
    generationEdges: edges.filter(e => e.edgeType === EDGE_TYPE_GENERATION).length,
    deliveryEdges: edges.filter(e => e.edgeType === EDGE_TYPE_DELIVERY).length,
    statusCounts: _countByField(nodes, 'status'),
    agentCounts: _countByField(activations, 'agentId'),
    eventTypeCounts: _countByField(events, 'eventType'),
    logicalClock: g.logicalClock,
  };

  // Topological sort for causal ordering
  const causalOrder = _topologicalSort(g);

  return {
    graphId: g.graphId,
    sessionId: g.sessionId,
    nodes,
    edges,
    stats,
    causalOrder,
    createdAt: g.createdAt,
    updatedAt: g.updatedAt,
  };
}

/**
 * Get the full audit trail of operations and interventions for a graph.
 *
 * @param {string} graphId
 * @returns {Promise<AuditEntry[]>}
 */
export async function getAuditTrail(graphId) {
  const g = _requireGraph(graphId);
  return [...g.auditTrail];
}

/**
 * Prune nodes and edges created before a given timestamp.
 * Preserves audit trail entries. Only removes nodes in terminal states.
 *
 * @param {string} graphId
 * @param {number} beforeTimestamp — epoch millis
 * @returns {Promise<{ prunedNodes: number, prunedEdges: number }>}
 */
export async function pruneGraph(graphId, beforeTimestamp) {
  const g = _requireGraph(graphId);

  if (!beforeTimestamp || typeof beforeTimestamp !== 'number') {
    throw new Error('beforeTimestamp must be a numeric epoch millis value');
  }

  const cutoff = new Date(beforeTimestamp).getTime();
  let prunedNodes = 0;
  let prunedEdges = 0;

  // Identify prunable nodes: terminal status and created before cutoff
  const terminalStatuses = new Set(['completed', 'discarded', 'submitted']);
  const prunableNodeIds = new Set();

  for (const [nodeId, node] of g.nodes) {
    const createdMs = new Date(node.createdAt).getTime();
    if (createdMs < cutoff && terminalStatuses.has(node.status)) {
      prunableNodeIds.add(nodeId);
    }
  }

  // First remove edges connected to prunable nodes
  for (const nodeId of prunableNodeIds) {
    const outEdges = g.adjOut.get(nodeId) || new Set();
    for (const eid of [...outEdges]) {
      const edge = g.edges.get(eid);
      if (edge) {
        // Only prune edge if both endpoints are prunable
        if (prunableNodeIds.has(edge.to)) {
          _removeEdge(g, eid);
          prunedEdges++;
        }
      }
    }

    const inEdges = g.adjIn.get(nodeId) || new Set();
    for (const eid of [...inEdges]) {
      const edge = g.edges.get(eid);
      if (edge) {
        if (prunableNodeIds.has(edge.from)) {
          _removeEdge(g, eid);
          prunedEdges++;
        }
      }
    }
  }

  // Now remove nodes that have no remaining edges to non-prunable nodes
  for (const nodeId of prunableNodeIds) {
    const remainingOut = g.adjOut.get(nodeId) || new Set();
    const remainingIn = g.adjIn.get(nodeId) || new Set();

    // Check if any remaining edges connect to non-prunable nodes
    let hasLiveConnection = false;
    for (const eid of remainingOut) {
      const edge = g.edges.get(eid);
      if (edge && !prunableNodeIds.has(edge.to)) {
        hasLiveConnection = true;
        break;
      }
    }
    if (!hasLiveConnection) {
      for (const eid of remainingIn) {
        const edge = g.edges.get(eid);
        if (edge && !prunableNodeIds.has(edge.from)) {
          hasLiveConnection = true;
          break;
        }
      }
    }

    if (!hasLiveConnection) {
      // Safe to remove — clean up any remaining edges
      for (const eid of [...remainingOut]) {
        _removeEdge(g, eid);
        prunedEdges++;
      }
      for (const eid of [...remainingIn]) {
        _removeEdge(g, eid);
        prunedEdges++;
      }

      g.nodes.delete(nodeId);
      g.adjOut.delete(nodeId);
      g.adjIn.delete(nodeId);
      prunedNodes++;
    }
  }

  g.updatedAt = new Date().toISOString();

  _audit(g, 'prune', graphId, { beforeTimestamp, prunedNodes, prunedEdges });

  await _persistPrune(graphId, beforeTimestamp, prunedNodes, prunedEdges);

  await logEvent(COMPANY, 'interaction-graph-healer', 'graph_pruned', graphId, {
    reasoning: `Pruned ${prunedNodes} terminal nodes and ${prunedEdges} edges older than ${new Date(beforeTimestamp).toISOString()}`,
    prunedNodes,
    prunedEdges,
  });

  return { prunedNodes, prunedEdges };
}

// ─── PHASE 4: AUTO-DETECT FAILURES AT DELIVERY TIME ─────────────────────────

/**
 * Deliver an event to a target activation, then auto-detect and heal
 * structural failures. This is the Phase 4 "delivery-time interception"
 * entry-point: every delivery edge triggers an immediate failure scan
 * so problems are caught and healed before they propagate.
 *
 * @param {string} graphId
 * @param {string} eventNodeId — the event node to deliver
 * @param {string} targetActivationId — the activation to deliver to
 * @returns {Promise<{ delivered: boolean, edgeId: string, failuresDetected: number, healed: boolean, healingResults: Array }>}
 */
export async function deliverEvent(graphId, eventNodeId, targetActivationId) {
  // 1. Create the delivery edge (event → activation)
  const { edgeId } = await addEdge(graphId, eventNodeId, targetActivationId, EDGE_TYPE_DELIVERY);

  // 2. Immediately scan for structural failures
  const failures = await detectFailures(graphId);

  // 3. Auto-heal if failures were found
  let healed = false;
  let healingResults = [];

  if (failures.length > 0) {
    healingResults = await healGraph(graphId, failures);
    healed = healingResults.length > 0;
  }

  // 4. Log the auto-detection with reasoning
  const fatalCount = failures.filter(f => f.severity === FAILURE_SEVERITY.FATAL).length;
  const warningCount = failures.filter(f => f.severity === FAILURE_SEVERITY.WARNING).length;

  await logEvent(COMPANY, 'interaction-graph-healer', 'delivery_auto_detect', graphId, {
    reasoning: failures.length === 0
      ? `Delivery edge ${edgeId} created (event ${eventNodeId} → activation ${targetActivationId}). Auto-detection found no structural failures.`
      : `Delivery edge ${edgeId} created (event ${eventNodeId} → activation ${targetActivationId}). Auto-detection found ${failures.length} failure(s) (${fatalCount} fatal, ${warningCount} warning) and applied ${healingResults.length} intervention(s).`,
    edgeId,
    eventNodeId,
    targetActivationId,
    failuresDetected: failures.length,
    fatalCount,
    warningCount,
    healed,
    interventionCount: healingResults.length,
  });

  // 5. Return structured result
  return {
    delivered: true,
    edgeId,
    failuresDetected: failures.length,
    healed,
    healingResults,
  };
}

/**
 * Convenience function that chains event creation and delivery in one call.
 * Creates an event node, finds or creates an activation for the target agent,
 * and delivers the event — with full auto-detection at delivery time.
 *
 * @param {string} graphId
 * @param {string} sourceActivationId — the activation that generated this event
 * @param {string} eventType — e.g. 'message', 'artifact', 'tool_result'
 * @param {*} content — the event payload
 * @param {string} targetAgentId — the agent that should receive this event
 * @returns {Promise<{ eventNodeId: string, targetActivationId: string, delivered: boolean, edgeId: string, failuresDetected: number, healed: boolean, healingResults: Array }>}
 */
export async function deliverAndChain(graphId, sourceActivationId, eventType, content, targetAgentId) {
  const g = _requireGraph(graphId);

  // 1. Create the event node (auto-creates generation edge if sourceActivation exists)
  const { nodeId: eventNodeId } = await addEvent(graphId, eventType, content, sourceActivationId);

  // 2. Find an existing active activation for the target agent, or create one
  let targetActivation = _findActiveActivation(g, targetAgentId);
  if (!targetActivation) {
    const { nodeId: newActId } = await addActivation(graphId, targetAgentId);
    targetActivation = g.nodes.get(newActId);
  }

  // 3. Deliver the event with auto-detection
  const deliveryResult = await deliverEvent(graphId, eventNodeId, targetActivation.id);

  // 4. Return combined result
  return {
    eventNodeId,
    targetActivationId: targetActivation.id,
    ...deliveryResult,
  };
}

// ─── TOPOLOGICAL INFERENCE ──────────────────────────────────────────────────

/**
 * Compute a topological sort of the graph for causal ordering.
 * Uses Kahn's algorithm. Returns node IDs in causal order.
 *
 * @param {DIGState} g
 * @returns {string[]}
 */
function _topologicalSort(g) {
  const inDegree = new Map();
  for (const [nodeId] of g.nodes) {
    inDegree.set(nodeId, 0);
  }

  for (const [, edge] of g.edges) {
    inDegree.set(edge.to, (inDegree.get(edge.to) || 0) + 1);
  }

  // Queue starts with zero in-degree nodes, sorted by logical timestamp
  const queue = [];
  for (const [nodeId, deg] of inDegree) {
    if (deg === 0) queue.push(nodeId);
  }
  queue.sort((a, b) => {
    const na = g.nodes.get(a);
    const nb = g.nodes.get(b);
    return (na?.logicalTs || 0) - (nb?.logicalTs || 0);
  });

  const order = [];
  const visited = new Set();

  while (queue.length > 0) {
    const nodeId = queue.shift();
    if (visited.has(nodeId)) continue;
    visited.add(nodeId);
    order.push(nodeId);

    const outEdges = g.adjOut.get(nodeId) || new Set();
    const neighbours = [];
    for (const eid of outEdges) {
      const edge = g.edges.get(eid);
      if (edge) {
        const newDeg = (inDegree.get(edge.to) || 1) - 1;
        inDegree.set(edge.to, newDeg);
        if (newDeg <= 0 && !visited.has(edge.to)) {
          neighbours.push(edge.to);
        }
      }
    }

    // Sort neighbours by logical timestamp for deterministic ordering
    neighbours.sort((a, b) => {
      const na = g.nodes.get(a);
      const nb = g.nodes.get(b);
      return (na?.logicalTs || 0) - (nb?.logicalTs || 0);
    });

    queue.push(...neighbours);
  }

  return order;
}

/**
 * Trace the causal lineage of a node back to its root ancestors.
 * Returns the set of root node IDs (nodes with no incoming edges).
 *
 * @param {DIGState} g
 * @param {string} nodeId
 * @returns {Set<string>}
 */
function _traceLineageRoots(g, nodeId) {
  const roots = new Set();
  const visited = new Set();
  const stack = [nodeId];

  while (stack.length > 0) {
    const current = stack.pop();
    if (visited.has(current)) continue;
    visited.add(current);

    const inEdges = g.adjIn.get(current) || new Set();
    if (inEdges.size === 0) {
      roots.add(current);
      continue;
    }

    for (const eid of inEdges) {
      const edge = g.edges.get(eid);
      if (edge && !visited.has(edge.from)) {
        stack.push(edge.from);
      }
    }
  }

  return roots;
}

// ─── INTERNAL HELPERS ───────────────────────────────────────────────────────

/**
 * Retrieve a graph or throw.
 * @param {string} graphId
 * @returns {DIGState}
 */
function _requireGraph(graphId) {
  const g = graphStore.get(graphId);
  if (!g) throw new Error(`Graph ${graphId} not found. Create one with createGraph() first.`);
  return g;
}

/**
 * Advance the Lamport logical clock.
 * @param {DIGState} g
 * @param {number} [externalTs] — optional external timestamp to merge
 * @returns {number} new logical timestamp
 */
function _advanceClock(g, externalTs) {
  if (typeof externalTs === 'number' && externalTs > g.logicalClock) {
    g.logicalClock = externalTs + 1;
  } else {
    g.logicalClock += 1;
  }
  return g.logicalClock;
}

/**
 * Ensure adjacency sets exist for a node.
 * @returns {{ adjOut: Set, adjIn: Set }}
 */
function _ensureAdj(g, nodeId) {
  if (!g.adjOut.has(nodeId)) g.adjOut.set(nodeId, new Set());
  if (!g.adjIn.has(nodeId)) g.adjIn.set(nodeId, new Set());
  return { adjOut: g.adjOut.get(nodeId), adjIn: g.adjIn.get(nodeId) };
}

/**
 * Remove an edge from the graph (both maps and adjacency lists).
 */
function _removeEdge(g, edgeId) {
  const edge = g.edges.get(edgeId);
  if (!edge) return;

  const fromAdj = g.adjOut.get(edge.from);
  if (fromAdj) fromAdj.delete(edgeId);

  const toAdj = g.adjIn.get(edge.to);
  if (toAdj) toAdj.delete(edgeId);

  g.edges.delete(edgeId);
}

/**
 * Find an active activation for a specific agent in the graph.
 * @returns {DIGNode|null}
 */
function _findActiveActivation(g, agentId) {
  for (const [, node] of g.nodes) {
    if (node.type === NODE_TYPE_ACTIVATION && node.agentId === agentId && node.status === 'active') {
      return node;
    }
  }
  return null;
}

/**
 * Count how many times an event has been rerouted by examining the audit trail.
 */
function _countReroutes(g, eventId) {
  let count = 0;
  for (const entry of g.auditTrail) {
    if (entry.operator === OPERATORS.REROUTE && entry.nodeId === eventId) {
      count++;
    }
  }
  return count;
}

/**
 * Append an entry to the audit trail.
 */
function _audit(g, operator, nodeId, params) {
  g.auditTrail.push({
    operator,
    nodeId,
    params,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Create a content fingerprint for similarity comparison.
 * Normalises content to a comparable string.
 */
function _contentFingerprint(content) {
  if (typeof content === 'string') {
    return content.toLowerCase().replace(/\s+/g, ' ').trim().slice(0, 500);
  }
  try {
    return JSON.stringify(content).toLowerCase().slice(0, 500);
  } catch {
    return String(content).slice(0, 500);
  }
}

/**
 * Compute Jaccard-style string similarity between two fingerprints.
 * Uses trigram overlap for speed.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} similarity in [0, 1]
 */
function _stringSimilarity(a, b) {
  if (a === b) return 1;
  if (!a || !b) return 0;

  const trigramsA = _trigrams(a);
  const trigramsB = _trigrams(b);

  if (trigramsA.size === 0 && trigramsB.size === 0) return 1;
  if (trigramsA.size === 0 || trigramsB.size === 0) return 0;

  let intersection = 0;
  for (const t of trigramsA) {
    if (trigramsB.has(t)) intersection++;
  }

  const union = trigramsA.size + trigramsB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Extract character trigrams from a string.
 * @returns {Set<string>}
 */
function _trigrams(str) {
  const set = new Set();
  for (let i = 0; i <= str.length - 3; i++) {
    set.add(str.slice(i, i + 3));
  }
  return set;
}

/**
 * Count occurrences of a field value across an array of objects.
 * @returns {Object<string, number>}
 */
function _countByField(items, field) {
  const counts = {};
  for (const item of items) {
    const val = item[field] || 'unknown';
    counts[val] = (counts[val] || 0) + 1;
  }
  return counts;
}

// ─── AIMOS PERSISTENCE ─────────────────────────────────────────────────────

async function _persistGraphMeta(graphId, sessionId, createdAt) {
  try {
    await query(
      `INSERT INTO interaction_graphs (company_id, graph_id, session_id, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $4)
       ON CONFLICT (company_id, graph_id) DO UPDATE SET updated_at = $4`,
      [COMPANY, graphId, sessionId, createdAt]
    );
  } catch (err) {
    console.error('[interaction-graph-healer] Failed to persist graph meta:', err.message);
  }
}

async function _persistNode(graphId, node) {
  try {
    await query(
      `INSERT INTO interaction_graph_nodes (company_id, graph_id, node_id, node_type, agent_id, event_type, status, logical_ts, content, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (company_id, graph_id, node_id) DO UPDATE
       SET status = $7, logical_ts = $8, content = $9`,
      [
        COMPANY,
        graphId,
        node.id,
        node.type,
        node.agentId || null,
        node.eventType || null,
        node.status,
        node.logicalTs,
        node.content ? JSON.stringify(node.content) : null,
        node.createdAt,
      ]
    );
  } catch (err) {
    console.error('[interaction-graph-healer] Failed to persist node:', err.message);
  }
}

async function _persistEdge(graphId, edge) {
  try {
    await query(
      `INSERT INTO interaction_graph_edges (company_id, graph_id, edge_id, from_node, to_node, edge_type, logical_ts, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (company_id, graph_id, edge_id) DO NOTHING`,
      [COMPANY, graphId, edge.id, edge.from, edge.to, edge.edgeType, edge.logicalTs, edge.createdAt]
    );
  } catch (err) {
    console.error('[interaction-graph-healer] Failed to persist edge:', err.message);
  }
}

async function _persistPrune(graphId, beforeTimestamp, prunedNodes, prunedEdges) {
  try {
    await query(
      `UPDATE interaction_graphs SET updated_at = NOW(), metadata = jsonb_set(
         COALESCE(metadata, '{}'::jsonb),
         '{last_prune}',
         $3::jsonb
       ) WHERE company_id = $1 AND graph_id = $2`,
      [COMPANY, graphId, JSON.stringify({ beforeTimestamp, prunedNodes, prunedEdges, at: new Date().toISOString() })]
    );
  } catch (err) {
    console.error('[interaction-graph-healer] Failed to persist prune metadata:', err.message);
  }
}
