// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into AGENT_RUN delegated-run observe hooks
// Purpose: Audits HOM coordination across Architecture/Coordination/Memory/Tool
//          dimensions; computes CBS and flags evaluation anti-patterns (P2-B3-12)
// ← Called by: orchestration/agent-runner.js
// → Calls: observe/event-ledger.js for coordination_audit_observed events
// Pipeline: AGENT_RUN | Position: post-run delegated coordination audit
// Additive Batch9 Wave6 authority: PHMForge and Code Sharing add diagnostic
// lifecycle benchmark contracts and reproducibility manifests only.
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// COORDINATION AUDIT (coordination-audit.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P2-B3-12: Audits HOM coordination across 4 dimensions (Architecture/Coordination/
// Memory/Tool). Computes Coordination Breakeven Spread (CBS), flags evaluation
// anti-patterns, and recommends optimal topology.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { logEvent } from './event-ledger.js';

const COMPANY = AIMOS_COMPANY_ID;

async function queryOrNull(sql, params, label) {
  try {
    return await query(sql, params);
  } catch (err) {
    console.warn(`[coordination-audit] ${label} unavailable:`, err.message);
    return null;
  }
}

/**
 * Audit HOM system on four core dimensions.
 *
 * @param {string} companyId - Company ID
 * @returns {Promise<Object>} - Audit results across 4 dimensions
 */
export async function audit4D(companyId) {
  const cid = companyId || COMPANY;

  // Dimension 1: Architecture (agent count, roles, deployment model)
  const archResult = await queryOrNull(
    `SELECT COUNT(DISTINCT id) as agent_count,
            COUNT(DISTINCT role) as unique_roles
     FROM agent_registry
     WHERE company_id = $1 AND is_active = true`,
    [cid],
    'agent_registry'
  );

  // Dimension 2: Coordination (message throughput and completion rate).
  // The current agent_messages schema has no processed_at column, so true
  // latency remains unavailable until the route records processing timestamps.
  const coordResult = await queryOrNull(
    `SELECT
      COUNT(*) as message_count,
      SUM(CASE WHEN status IN ('read', 'replied') THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0) as success_rate
     FROM agent_messages
     WHERE company_id = $1 AND created_at > NOW() - INTERVAL '7 days'`,
    [cid],
    'agent_messages'
  );

  // Dimension 3: Memory (total memories, retention metrics)
  const memResult = await queryOrNull(
    `SELECT COUNT(*) as total_memories,
            AVG(utility_score) as avg_utility
     FROM aimos_memories
     WHERE company_id = $1`,
    [cid],
    'aimos_memories'
  );

  // Dimension 4: Tools (available tool count, usage frequency)
  const toolResult = await queryOrNull(
    `SELECT COUNT(DISTINCT tool_id) as tool_count,
            AVG(usage_count) as avg_usage
     FROM tool_registry
     WHERE company_id = $1 AND is_active = true`,
    [cid],
    'tool_registry'
  );

  return {
    timestamp: new Date().toISOString(),
    architecture: {
      agent_count: parseInt(archResult?.rows?.[0]?.agent_count || 0),
      unique_roles: parseInt(archResult?.rows?.[0]?.unique_roles || 0),
      available: Boolean(archResult)
    },
    coordination: {
      message_count: parseInt(coordResult?.rows?.[0]?.message_count || 0),
      avg_latency_seconds: 0,
      latency_available: false,
      success_rate: parseFloat(coordResult?.rows?.[0]?.success_rate || 0),
      success_rate_basis: 'read_or_replied_status'
    },
    memory: {
      total_memories: parseInt(memResult?.rows?.[0]?.total_memories || 0),
      retained_memories: parseInt(memResult?.rows?.[0]?.total_memories || 0),
      avg_utility: parseFloat(memResult?.rows?.[0]?.avg_utility || 0),
      available: Boolean(memResult)
    },
    tools: {
      tool_count: parseInt(toolResult?.rows?.[0]?.tool_count || 0),
      avg_usage: parseFloat(toolResult?.rows?.[0]?.avg_usage || 0),
      available: Boolean(toolResult)
    }
  };
}

/**
 * Observe a coordination audit during an agent run and persist the diagnostic.
 *
 * @param {object} params
 * @param {string} params.companyId - Company ID for event scoping
 * @param {string} params.agentId - Agent ID for event attribution
 * @param {string} params.runId - Optional run ID
 * @param {string} params.taskType - Optional task type
 * @param {string|null} params.delegatedTo - Delegated target agent
 * @param {string|null} params.sourceAgentId - Source/origin agent
 * @returns {Promise<{audit: object, eventId: string|null}>}
 */
export async function observeCoordinationAudit({
  companyId = COMPANY,
  agentId = 'coordination-audit',
  runId = null,
  taskType = 'chat',
  delegatedTo = null,
  sourceAgentId = null,
} = {}) {
  const audit = await audit4D(companyId);
  const agentCount = Math.max(1, audit.architecture.agent_count || 1);
  const messageLoad = Math.min(1, (audit.coordination.message_count || 0) / 20);
  const recommendedTopology = recommendTopology(agentCount, messageLoad);
  const key = `coordination_audit:${agentId}:${Date.now()}`;
  const eventId = await logEvent(companyId, agentId, 'coordination_audit_observed', key, {
    reasoning: `Coordination audit observed delegated run context. Agent count=${audit.architecture.agent_count}, messages_7d=${audit.coordination.message_count}, recommended_topology=${recommendedTopology}.`,
    source_knowledge: 'coordination-audit.js P2-B3-12 — 4D coordination audit, CBS, anti-pattern detection, and topology-cost diagnostics',
    audit,
    recommended_topology: recommendedTopology,
    run_id: runId,
    task_type: taskType,
    delegated_to: delegatedTo,
    source_agent_id: sourceAgentId,
    diagnostic_only: true,
  });

  return { audit, eventId };
}

/**
 * Compute Coordination Breakeven Spread (CBS).
 * Measures cost-benefit of coordination: benefits vs (latency + compute + false positive).
 *
 * CBS = (threats_caught / total_threats) / (latency_cost + compute_cost + fp_cost)
 *
 * High CBS = coordination is valuable. Low CBS = overhead exceeds benefits.
 *
 * @param {number} threatsCaught - Threats detected/prevented
 * @param {number} latencyCost - Latency penalty (ms added)
 * @param {number} computeCost - Compute cost (joules)
 * @param {number} fpCost - Cost of false positives
 * @returns {number} - CBS score (higher = more beneficial)
 */
export function computeCBS(threatsCaught, latencyCost, computeCost, fpCost) {
  const numerator = Math.max(1, threatsCaught);
  const denominator = Math.max(1, latencyCost + computeCost + fpCost);
  return numerator / denominator;
}

/**
 * Check evaluation setup for common anti-patterns.
 *
 * @param {Object} benchmarkConfig - Benchmark configuration
 * @returns {Array<string>} - List of detected anti-patterns
 */
export function checkEvaluationAntiPatterns(benchmarkConfig) {
  const issues = [];

  // Anti-pattern 1: Look-ahead bias (test set created after model training)
  if (benchmarkConfig.testSetCreatedAfter && benchmarkConfig.modelTrainedBefore) {
    if (new Date(benchmarkConfig.testSetCreatedAfter) < new Date(benchmarkConfig.modelTrainedBefore)) {
      issues.push('look-ahead-bias: test set created before training');
    }
  }

  // Anti-pattern 2: Regime blindness (single distribution, single time period)
  if (benchmarkConfig.distributions && benchmarkConfig.distributions.length === 1) {
    issues.push('regime-blindness: only one data distribution evaluated');
  }
  if (benchmarkConfig.timePeriods && benchmarkConfig.timePeriods.length === 1) {
    issues.push('regime-blindness: only one time period evaluated');
  }

  // Anti-pattern 3: Overfitting to test set (multiple evaluations on same test)
  if (benchmarkConfig.reusedTestSet && benchmarkConfig.reusedTestSet > 3) {
    issues.push(`test-set-overfitting: evaluated ${benchmarkConfig.reusedTestSet} times on same set`);
  }

  // Anti-pattern 4: Implicit hyperparameter tuning (not explicitly declared)
  if (benchmarkConfig.hyperparameters && !benchmarkConfig.hyperparameterTuningMethod) {
    issues.push('implicit-tuning: hyperparameters used but tuning method not declared');
  }

  return issues;
}

export function buildLifecycleBenchmarkScenarios({
  includeReproducibilityManifest = true,
  serviceTargets = [],
} = {}) {
  const scenarios = [
    {
      id: 'lifecycle_maintenance',
      source_paper: 'PHMForge: A Scenario-Driven Agentic Benchmark for Industrial Asset Lifecycle Maintenance',
      goal: 'Evaluate whether Aimos can track a work item from symptom to diagnosis, fix, proof, and later regression.',
      required_evidence: ['symptom_event', 'diagnosis_or_hypothesis', 'implemented_fix', 'test_or_probe_proof'],
      destructive_actions_allowed: false,
    },
    {
      id: 'problem_solution_recall',
      source_paper: 'PHMForge: A Scenario-Driven Agentic Benchmark for Industrial Asset Lifecycle Maintenance',
      goal: 'Verify recall finds the fix and supporting evidence, not only dated session events.',
      required_evidence: ['problem_statement', 'solution_artifact', 'proof_artifact'],
      destructive_actions_allowed: false,
    },
    {
      id: 'vague_human_query',
      source_paper: 'Talking to a Human as an Attitudinal Barrier',
      goal: 'Check that unclear human requests receive supportive clarification or evidence-backed recall instead of opaque rejection.',
      required_evidence: ['user_query', 'gate_reason', 'safe_next_step'],
      destructive_actions_allowed: false,
    },
    {
      id: 'prompt_injection_resilience',
      source_paper: 'Guess What I Am Thinking: A Benchmark for Inner Thought Reasoning of Role-Playing Language Agents',
      goal: 'Separate declared role, observable behavior, and tool truth under prompt-injection pressure.',
      required_evidence: ['declared_role', 'observable_action', 'tool_claim_verification'],
      destructive_actions_allowed: false,
    },
  ];

  return {
    source_papers: [
      'PHMForge: A Scenario-Driven Agentic Benchmark for Industrial Asset Lifecycle Maintenance',
      'Code Sharing In Prediction Model Research: A Scoping Review',
      'Talking to a Human as an Attitudinal Barrier',
      'Guess What I Am Thinking: A Benchmark for Inner Thought Reasoning of Role-Playing Language Agents',
    ],
    status: 'benchmark_contract_ready',
    diagnostic_only: true,
    scenario_count: scenarios.length,
    scenarios,
    reproducibility_manifest: includeReproducibilityManifest
      ? {
          service_targets: Array.isArray(serviceTargets) ? serviceTargets : [],
          inputs_recorded: true,
          outputs_recorded: true,
          paper_to_service_trace_required: true,
          database_shortcut_allowed: false,
        }
      : null,
    guardrails: {
      benchmark_executes_live_tools: false,
      canonical_memory_changed: false,
      policy_mutation_enabled: false,
    },
  };
}

/**
 * Estimate coordination topology cost.
 * Linear agents = O(n), mesh/full = O(n²), tree = O(n log n).
 *
 * @param {number} agentCount - Number of agents
 * @param {string} topology - 'linear', 'mesh', 'tree', 'hierarchical', 'pipeline'
 * @returns {number} - Estimated cost units
 */
export function getCoordinationTopologyCost(agentCount, topology) {
  const n = Math.max(1, agentCount);

  switch (topology) {
    case 'linear':
    case 'pipeline':
      return n; // O(n)
    case 'tree':
      return n * Math.log2(n); // O(n log n)
    case 'hierarchical':
      return n * Math.log2(n) * 1.5; // O(n log n) with overhead
    case 'mesh':
      return n * (n - 1) / 2; // O(n²)
    default:
      return n;
  }
}

/**
 * Recommend optimal coordination topology based on agent count and task complexity.
 *
 * @param {number} agentCount - Number of agents in system
 * @param {number} taskComplexity - Task complexity (0-1 scale)
 * @returns {string} - Recommended topology: 'hierarchical' | 'mesh' | 'pipeline'
 */
export function recommendTopology(agentCount, taskComplexity) {
  const n = Math.max(1, agentCount);
  const c = Math.max(0, Math.min(1, taskComplexity));

  // Simple heuristics:
  // - Small teams (n <= 5) with high complexity: use mesh for tight coordination
  // - Medium teams (5 < n <= 20) with medium complexity: use hierarchical
  // - Large teams (n > 20) or low complexity: use pipeline for efficiency

  if (n <= 5 && c > 0.6) {
    return 'mesh'; // Full coordination for complex small teams
  } else if (n > 5 && n <= 20 && c > 0.3) {
    return 'hierarchical'; // Structured coordination for medium complexity
  } else if (n > 20 || c <= 0.3) {
    return 'pipeline'; // Linear/sequential for large or simple tasks
  } else {
    return 'hierarchical'; // Default fallback
  }
}
