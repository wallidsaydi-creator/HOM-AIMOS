// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK SCENARIOS (benchmark-scenarios.js)
// ═══════════════════════════════════════════════════════════════════════════════
// Batch9.75 authority: WE BAR E N A- A REALISTIC WEB ENVIRONMENT FOR BUILDING
// AUTONOMOUS AGENTS.
// Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
//   - buildWebArenaScenarioDiagnostic: WebArena scenario diagnostic alongside
//     existing benchmark contracts. Does not execute tools.
//
// Batch 10 Lane 6 authority:
//   LOLEM: Beyond a Million Tokens — Long-context factual retention, temporal
//   ordering, multi-hop reasoning, cross-session continuity, capacity at scale.
//   MemBench: Contradictory memory resolution, trust-weighted recall accuracy.
//
// Diagnostic scenario contracts only. This service does not execute browser,
// network, tool, or autonomous web actions.
//
// SERVICE CONNECTION GUIDE:
// 1. ← Called by: tests/phase0-capsule-contract-test.js (Lane 6 E2E probes)
// 2. → Reads: Aimos memory via recall (never writes test data to Aimos)
// Pipeline: OBSERVE | Position: benchmark evaluation
// ═══════════════════════════════════════════════════════════════════════════════

export const WEBARENA_SOURCE = 'WE BAR E N A- A REALISTIC WEB ENVIRONMENT FOR BUILDING AUTONOMOUS AGENTS';

export function buildWebArenaBenchmarkScenarios({
  domains = ['web_navigation', 'form_interaction', 'tool_truth', 'state_tracking'],
  serviceTargets = ['services/orchestration/hypothesis-verifier.js'],
} = {}) {
  const domainList = (Array.isArray(domains) ? domains : [])
    .map(String)
    .filter(Boolean);
  const targets = (Array.isArray(serviceTargets) ? serviceTargets : [])
    .map(String)
    .filter(Boolean);

  const scenarios = domainList.map((domain) => ({
    id: `webarena_${domain}`,
    source_paper: WEBARENA_SOURCE,
    domain,
    required_evidence: ['task_intent', 'observed_state', 'action_proposal', 'verification_result'],
    browser_action_executed: false,
    live_tool_execution_allowed: false,
  }));

  const webarenaScenarioDiagnostic = buildWebArenaScenarioDiagnostic({ domains: domainList });

  return {
    status: 'benchmark_contract_ready',
    source_paper: WEBARENA_SOURCE,
    diagnostic_only: true,
    scenario_count: scenarios.length,
    scenarios,
    reproducibility_manifest: {
      service_targets: targets,
      inputs_recorded: true,
      outputs_recorded: true,
      paper_to_service_trace_required: true,
      database_shortcut_allowed: false,
    },
    guardrails: {
      benchmark_executes_live_tools: false,
      browser_automation_enabled: false,
      canonical_memory_changed: false,
      policy_mutation_enabled: false,
    },
    guarded_math: {
      webarena_scenario: true,
    },
    guarded_math_implemented: {
      webarena_scenario: {
        enabled: true,
        diagnostic_only: true,
        source_paper: WEBARENA_SOURCE,
        coexistence_class: 'side_by_side_independent',
      },
    },
  };
}

/**
 * WebArena Scenario Diagnostic — Alongside-path diagnostic
 *
 * Source paper: WebArena — Realistic Web Environment for Autonomous Agents
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function produces a scenario diagnostic overlay
 * alongside existing benchmark contracts. It does NOT execute live tools
 * or browser actions. The existing buildWebArenaBenchmarkScenarios
 * production path remains authoritative. Guarded by guarded_math flag
 * webarena_scenario which is guarded in production (knowledge-gated: paper understanding required).
 */
export function buildWebArenaScenarioDiagnostic({
  scenarioType = 'navigation',
  taskComplexity = 'standard',
  domains = ['web_navigation', 'form_interaction', 'tool_truth', 'state_tracking'],
} = {}) {
  const validTypes = ['navigation', 'form_interaction', 'tool_truth', 'state_tracking', 'comprehensive'];
  const validComplexity = ['standard', 'challenging', 'adversarial'];
  const type = validTypes.includes(scenarioType) ? scenarioType : 'navigation';
  const complexity = validComplexity.includes(taskComplexity) ? taskComplexity : 'standard';
  const domainList = (Array.isArray(domains) ? domains : []).map(String).filter(Boolean);

  // WebArena paper: task success = f(step_count, domain_coverage, state_accuracy)
  // Deterministic metrics from domain type + complexity (no randomness)
  const complexityMultiplier = complexity === 'adversarial' ? 2.0 : complexity === 'challenging' ? 1.5 : 1.0;
  const scenarioMetrics = {
    navigation_steps: type === 'navigation' ? Math.ceil(3 * complexityMultiplier) : 1,
    form_fields: type === 'form_interaction' ? Math.ceil(2 * complexityMultiplier) : 0,
    tool_calls_required: type === 'tool_truth' ? Math.ceil(1 * complexityMultiplier) : 0,
    state_transitions: type === 'state_tracking' ? Math.ceil(2 * complexityMultiplier) : 0,
  };

  return {
    diagnostic: true,
    source_paper: WEBARENA_SOURCE,
    coexistence_class: 'side_by_side_independent',
    scenario_type: type,
    task_complexity: complexity,
    domains: domainList,
    scenario_metrics: scenarioMetrics,
    evidence_requirements: ['task_intent', 'observed_state', 'action_proposal', 'verification_result'],
    safety_contract: {
      live_tool_execution: false,
      browser_automation: false,
      canonical_memory_mutated: false,
    },
    note: 'Alongside-path diagnostic. Web-task benchmark scenarios do not execute live tools.',
  };
}

// ─── BATCH 10 LANE 6: LOLEM BENCHMARK SCENARIOS ────────────────────────────────
// Paper: Beyond a Million Tokens (LOLEM)
// Targets: factual retention ≥ 0.85, temporal ordering ≥ 0.90,
//          multi-hop reasoning ≥ 0.75, cross-session continuity ≥ 0.80,
//          working memory capacity > 10K memories before degradation,
//          conflict resolution ≥ 0.90.
// Aladdin: Scenarios are diagnostic — they inspect, never modify canonical memory.

export const LOLEM_SOURCE = 'Beyond a Million Tokens (LOLEM)';

export const LOLEM_TARGETS = {
  factual_retention: 0.85,
  temporal_ordering: 0.90,
  multi_hop_reasoning: 0.75,
  cross_session_continuity: 0.80,
  working_memory_capacity: 10000,
  conflict_resolution: 0.90,
};

/**
 * Build LOLEM benchmark scenarios for long-context memory evaluation.
 * Paper: Beyond a Million Tokens
 * Targets defined in LOLEM_TARGETS.
 *
 * @param {object} opts - Configuration options
 * @returns {object} LOLEM benchmark scenario set
 */
export function buildLOLEMBenchmarkScenarios(opts = {}) {
  const scenarioFactories = [
    {
      id: 'lolem_factual_retention',
      name: 'Factual Retention',
      description: 'Recall factual details from memories across varying distances. Target: ≥ 0.85 accuracy.',
      metric: 'accuracy',
      target: LOLEM_TARGETS.factual_retention,
      source_paper: LOLEM_SOURCE,
      methodology: 'Insert N facts. Recall after K intervening memories. Measure accuracy.',
      parameters: { memory_distances: [10, 100, 500, 1000, 5000], fact_count_per_distance: 20 },
    },
    {
      id: 'lolem_temporal_ordering',
      name: 'Temporal Ordering',
      description: 'Correctly order events by timestamp after extended context. Target: ≥ 0.90 ordering accuracy.',
      metric: 'ordering_accuracy',
      target: LOLEM_TARGETS.temporal_ordering,
      source_paper: LOLEM_SOURCE,
      methodology: 'Present events with timestamps. Query ordering. Measure pair-wise accuracy.',
      parameters: { event_count: 50, inter_event_gap_ms: 60000 },
    },
    {
      id: 'lolem_multi_hop_reasoning',
      name: 'Multi-Hop Reasoning',
      description: 'Chain 2-4 retrieval steps to answer compositional queries. Target: ≥ 0.75 accuracy.',
      metric: 'reasoning_accuracy',
      target: LOLEM_TARGETS.multi_hop_reasoning,
      source_paper: LOLEM_SOURCE,
      methodology: 'Plant connected facts requiring 2-4 hops. Measure correct final answers.',
      parameters: { hop_depths: [2, 3, 4], queries_per_depth: 15 },
    },
    {
      id: 'lolem_cross_session_continuity',
      name: 'Cross-Session Continuity',
      description: 'Maintain context across simulated session boundaries. Target: ≥ 0.80 continuity.',
      metric: 'continuity_score',
      target: LOLEM_TARGETS.cross_session_continuity,
      source_paper: LOLEM_SOURCE,
      methodology: 'Save facts in session A. Recall in session B. Measure consistency.',
      parameters: { session_gap_minutes: 60, fact_count: 30 },
    },
    {
      id: 'lolem_working_memory_capacity',
      name: 'Working Memory Capacity',
      description: 'Aimos serves > 10K memories before relevance degradation. Target: > 10000.',
      metric: 'effective_capacity',
      target: LOLEM_TARGETS.working_memory_capacity,
      source_paper: LOLEM_SOURCE,
      methodology: 'Populate 10K+ memories. Measure recall MRR at increasing scale.',
      parameters: { scale_points: [100, 1000, 5000, 10000, 20000] },
    },
    {
      id: 'lolem_conflict_resolution',
      name: 'Conflict Resolution',
      description: 'When contradictory memories exist, higher-trust memory wins. Target: ≥ 0.90.',
      metric: 'resolution_accuracy',
      target: LOLEM_TARGETS.conflict_resolution,
      source_paper: LOLEM_SOURCE,
      methodology: 'Insert pairs with conflicting values. Measure trust-weighted selection.',
      parameters: { conflict_pairs: 25 },
    },
  ];

  return {
    suite: 'lolem_benchmark',
    source_paper: LOLEM_SOURCE,
    targets: LOLEM_TARGETS,
    scenario_count: scenarioFactories.length,
    scenarios: scenarioFactories,
    diagnostic_only: true,
    canonical_memory_untouched: true,
    aladdin: 'benchmark_scenarios_inspect_only_never_modify_memory',
  };
}

/**
 * Evaluate a specific LOLEM scenario against Aimos results.
 * Paper: Beyond a Million Tokens
 *
 * @param {string} scenarioId - One of the LOLEM scenario IDs
 * @param {object} results - Measured results from Aimos recall
 * @returns {object} Evaluation result with pass/fail
 */
export function evaluateLOLEMScenario(scenarioId, results = {}) {
  const scenario = buildLOLEMBenchmarkScenarios().scenarios.find(s => s.id === scenarioId);
  if (!scenario) {
    return { scenario_id: scenarioId, status: 'unknown_scenario', passes: false };
  }

  const measured = results.measured ?? 0;
  const target = scenario.target;
  const passes = measured >= target;

  return {
    scenario_id: scenarioId,
    name: scenario.name,
    measured,
    target,
    passes,
    gap: Number((target - measured).toFixed(4)),
    source_paper: LOLEM_SOURCE,
    diagnostic_only: true,
    canonical_memory_untouched: true,
  };
}

// ─── BATCH 10 LANE 6: MEMBENCH SCENARIOS ──────────────────────────────────────
// Paper: MemBench — Contradictory memory injection, trust-weighted resolution
// Target: Higher-trust memory returned in 95%+ of conflicts.
// Aladdin: Trust scoring only affects retrieval ranking, never deletes memory.

export const MEMBENCH_SOURCE = 'MemBench';

export const MEMBENCH_TARGETS = {
  trust_resolution_rate: 0.95,
  ranking_consistency: 0.90,
  retrieval_accuracy_trusted: 0.90,
};

/**
 * Build MemBench scenarios for contradictory memory evaluation.
 * Paper: MemBench
 * Formula: T = 0.4*access + 0.2*cross_refs + 0.2*recency + 0.2*credit_score
 *
 * @param {object} opts - Configuration options
 * @returns {object} MemBench scenario set
 */
export function buildMemBenchScenarios(opts = {}) {
  const scenarios = [
    {
      id: 'membench_trust_resolution',
      name: 'Trust Resolution',
      description: 'Inject contradictory memories with different trust scores. Higher-trust wins ≥ 95%.',
      metric: 'resolution_rate',
      target: MEMBENCH_TARGETS.trust_resolution_rate,
      source_paper: MEMBENCH_SOURCE,
      methodology: 'Create N pairs with conflicting values and different trust scores. Measure higher-trust selection rate.',
      parameters: { pair_count: 50, trust_gap_range: [0.05, 0.10, 0.20, 0.40, 0.60] },
    },
    {
      id: 'membench_ranking_consistency',
      name: 'Ranking Consistency',
      description: 'Same query produces consistent ranking across retrievals. Target: ≥ 0.90 consistency.',
      metric: 'consistency',
      target: MEMBENCH_TARGETS.ranking_consistency,
      source_paper: MEMBENCH_SOURCE,
      methodology: 'Issue same query 5 times. Measure top-K overlap across retrievals.',
      parameters: { query_count: 20, top_k: 5, repeat_count: 5 },
    },
    {
      id: 'membench_retrieval_accuracy_trusted',
      name: 'Trusted Retrieval Accuracy',
      description: 'Memories with trust > 0.7 are retrieved with ≥ 0.90 accuracy for relevant queries.',
      metric: 'accuracy',
      target: MEMBENCH_TARGETS.retrieval_accuracy_trusted,
      source_paper: MEMBENCH_SOURCE,
      methodology: 'Plant trusted memories. Measure recall@K for relevant queries.',
      parameters: { trusted_count: 100, queries: 50, top_k: 10 },
    },
  ];

  return {
    suite: 'membench_benchmark',
    source_paper: MEMBENCH_SOURCE,
    trust_formula: 'T = 0.4*access_frequency + 0.2*cross_refs + 0.2*recency + 0.2*credit_score',
    targets: MEMBENCH_TARGETS,
    scenario_count: scenarios.length,
    scenarios,
    diagnostic_only: true,
    canonical_memory_untouched: true,
    aladdin: 'trust_scoring_only_affects_retrieval_ranking_never_deletes',
  };
}

/**
 * Evaluate a specific MemBench scenario against Aimos results.
 * Paper: MemBench
 *
 * @param {string} scenarioId - One of the MemBench scenario IDs
 * @param {object} results - Measured results from Aimos recall
 * @returns {object} Evaluation result with pass/fail
 */
export function evaluateMemBenchScenario(scenarioId, results = {}) {
  const scenario = buildMemBenchScenarios().scenarios.find(s => s.id === scenarioId);
  if (!scenario) {
    return { scenario_id: scenarioId, status: 'unknown_scenario', passes: false };
  }

  const measured = results.measured ?? 0;
  const target = scenario.target;
  const passes = measured >= target;

  return {
    scenario_id: scenarioId,
    name: scenario.name,
    measured,
    target,
    passes,
    gap: Number((target - measured).toFixed(4)),
    trust_formula: 'T = 0.4*access + 0.2*cross_refs + 0.2*recency + 0.2*credit',
    source_paper: MEMBENCH_SOURCE,
    diagnostic_only: true,
    canonical_memory_untouched: true,
  };
}
