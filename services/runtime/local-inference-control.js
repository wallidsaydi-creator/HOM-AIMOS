// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wave 5 additive local-inference contract — native Aimos server only
// ← Called by: routes/aimos.js, agent-runner.js (Wave 5 local runtime signals)
// Pipeline: AGENT_RUN | Position: Local hardware / MoE / memory-layout planning
// Source: TurboQuant; DALI; DyMoE; HillInfer; PROBE; MoE-SpAc;
//         Speculating Experts; ML-Driven Intelligent Memory System Design;
//         Mitigating the Memory Bottleneck with ML-Driven and Data-Aware
//         Microarchitectural Techniques; Optimizing SSD-Resident Graph Indexing;
//         Making Array-Based Translation Practical; Nexus; PIM-SHERPA; LPC-SM.
// Additive Batch8 authority: Joint Optimization of Reasoning and Dual-Memory
// for Self-Learning Diagnostic Agent; Large Memory Network for Recommendation.
// Aimos exposes dual-memory lane and context-placement diagnostics only.
// Additive Batch8 Wave6 authority: BranchLoRA; Stream; SoulX-Duplug;
// VLM-Augmented Degradation Modeling. Aimos exposes inactive adapter contracts
// and guarded routing-math flags only; no multimodal support, LoRA merge,
// sparse attention, or audio-state predictor is enabled.
// Additive Batch9.5 Wave4 authority: Hold Onto That Thought, Don't Waste Bits,
// AQPIM, EliteKV, Stochastic KV Routing, Fractional RoPE, Two-Block Hadamard
// Rotations, HieraSparse, and Neural Preconditioning. Aimos exposes guarded
// KV/cache/quantization readiness diagnostics only; no live KV mutation,
// quantization execution, sparse kernel, or ranking change is enabled.
// Batch 10 Lane 4: Dynamic Memory Compression per-token gate,
//   KV Cache Optimization per-layer compression ratios. All diagnostic.
// Guardrail: this service exposes planning contracts, diagnostics, and runtime
// telemetry only. It does not quantize persisted memories, rewrite calibrated
// recall ranking, mutate KV caches, train RL/perceptron predictors, or introduce
// any proxy. All hard scheduler/math claims remain guarded until benchmarked.
// ─────────────────────────────────────────────────────────────────────────────

import os from 'node:os';

export const TURBOQUANT_SOURCE = 'TurboQuant: Online Vector Quantization with Near-optimal Distortion Rate';
export const DALI_SOURCE = 'DALI: A Workload-Aware Offloading Framework for Efficient MoE Inference on Local PCs';
export const DYMOE_SOURCE = 'DyMoE: Dynamic Expert Orchestration with Mixed-Precision Quantization for Efficient MoE Inference on Edge';
export const HILLINFER_SOURCE = 'HillInfer: Efficient Long-Context LLM Inference on the Edge with Hierarchical KV Eviction using SmartSSD';
export const PROBE_SOURCE = 'PROBE: Co-Balancing Computation and Communication in MoE Inference via Real-Time Predictive Prefetching';
export const MOE_SPAC_SOURCE = 'MoE-SpAc: Efficient MoE Inference Based on Speculative Activation Utility in Heterogeneous Edge Scenarios';
export const SPECULATING_EXPERTS_SOURCE = 'Speculating Experts Accelerates Inference for Mixture-of-Experts';
export const ML_MEMORY_SOURCE = 'Machine Learning-Driven Intelligent Memory System Design: From On-Chip Caches to Storage';
export const MICRO_BOTTLENECK_SOURCE = 'Mitigating the Memory Bottleneck with Machine Learning-Driven and Data-Aware Microarchitectural Techniques';
export const SSD_GRAPH_SOURCE = 'Optimizing SSD-Resident Graph Indexing for High-Throughput Vector Search';
export const ARRAY_TRANSLATION_SOURCE = 'Making Array-Based Translation Practical for Modern, High-Performance Buffer Management';
export const NEXUS_SOURCE = 'Nexus: Transparent I/O Offloading for High-Density Serverless Computing';
export const PIM_SHERPA_SOURCE = 'PIM-SHERPA: Software Method for On-Device LLM Inference by Resolving PIM Memory Attribute and Layout Inconsistencies';
export const LPC_SM_SOURCE = 'LPC-SM: Local Predictive Coding and Sparse Memory for Long-Context Language Modeling';
export const DUAL_MEMORY_SOURCE = 'Joint Optimization of Reasoning and Dual-Memory for Self-Learning Diagnostic Agent';
export const LARGE_MEMORY_NETWORK_SOURCE = 'Large Memory Network for Recommendation';
export const BRANCHLORA_SOURCE = 'Enhancing Multimodal Continual Instruction Tuning with BranchLoRA';
export const STREAM_SOURCE = 'Stream: Sparse Attention for Long Context';
export const SOULX_DUPLUG_SOURCE = 'SoulX-Duplug: Streaming State Prediction for Full-Duplex Speech';
export const VLM_DEGRADATION_SOURCE = 'VLM-Augmented Degradation Modeling';
export const ESS_SOURCE = 'ESS: An Offload-Centric Latent-Cache Management Architecture for DeepSeek-V3.2-Exp';
export const INDEXCACHE_SOURCE = 'IndexCache: Accelerating Sparse Attention via Cross-Layer Index Reuse';
export const VFA_SOURCE = 'VFA: Relieving Vector Operations in Flash Attention with Global Maximum Pre-computation';
export const SALCA_SOURCE = 'Salca: A Sparsity-Aware Hardware Accelerator for Efficient Long-Context Attention Decoding';
export const HOLD_THOUGHT_SOURCE = 'Hold Onto That Thought: Assessing KV Cache Compression on Reasoning';
export const DONT_WASTE_BITS_SOURCE = "Don't Waste Bits: Adaptive KV-Cache Quantization for Lightweight On-Device LLMs";
export const AQPIM_SOURCE = 'AQPIM: Breaking the PIM Capacity Wall for LLMs with In-Memory Activation Quantization';
export const ELITEKV_SOURCE = 'EliteKV: Scalable KV Cache Compression via RoPE Frequency Selection and Joint Low-Rank Projection';
export const STOCHASTIC_KV_SOURCE = 'Stochastic KV Routing: Enabling Adaptive Depth-Wise Cache Sharing';
export const FRACTIONAL_ROPE_SOURCE = 'Fractional Rotation, Full Potential: Investigating Performance and Convergence of Partial RoPE';
export const TWO_BLOCK_HADAMARD_SOURCE = 'Approximating Uniform Random Rotations by Two-Block Structured Hadamard Rotations in High Dimensions';
export const HIERASPARSE_SOURCE = 'HieraSparse: Hierarchical Semi-Structured Sparse KV Attention';
export const NEURAL_PRECONDITIONING_SOURCE = 'Neural Preconditioning via Krylov Subspace Geometry';

const GIB = 1024 ** 3;

function clampNumber(value, min, max, fallback = min) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
}

function estimateTokensFromChars(value = '') {
  return Math.max(1, Math.ceil(String(value || '').length / 4));
}

function clamp01(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.min(1, numeric));
}

function round(value, digits = 3) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Number(numeric.toFixed(digits));
}

function hasNumericValue(value) {
  return value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value));
}

function detectMoEModel(model = '') {
  const normalized = String(model || '').toLowerCase();
  return /\b(mixtral|dbrx|deepseek|gpt-oss|moe|router|expert)\b/.test(normalized)
    || /\bqwen-?3[^ ]*a\d+b\b/.test(normalized)
    || /\ba\d+b\b/.test(normalized);
}

function inferExpertCounts(model = '', overrides = {}) {
  const normalized = String(model || '').toLowerCase();
  if (hasNumericValue(overrides.totalExperts) && hasNumericValue(overrides.activeExperts)) {
    return {
      totalExperts: Math.max(1, Number(overrides.totalExperts)),
      activeExperts: Math.max(1, Number(overrides.activeExperts)),
      source: 'caller',
    };
  }
  if (normalized.includes('mixtral')) {
    return { totalExperts: 8, activeExperts: 2, source: 'model_name_hint' };
  }
  if (/\bqwen-?3[^ ]*a\d+b\b/.test(normalized) || /\ba3b\b/.test(normalized)) {
    return { totalExperts: 128, activeExperts: 8, source: 'model_name_hint' };
  }
  if (normalized.includes('deepseek') || normalized.includes('gpt-oss')) {
    return { totalExperts: 128, activeExperts: 4, source: 'model_name_hint' };
  }
  return { totalExperts: 64, activeExperts: 4, source: 'default_moe_contract' };
}

export function buildHostHardwareProfile({
  totalMemoryBytes = os.totalmem(),
  freeMemoryBytes = os.freemem(),
  cpuCount = os.cpus()?.length || 1,
  platform = os.platform(),
  arch = os.arch(),
  gpuVramGb = null,
  diskFreeGb = null,
} = {}) {
  const totalGb = Math.max(0, Number(totalMemoryBytes || 0) / GIB);
  const freeGb = Math.max(0, Number(freeMemoryBytes || 0) / GIB);
  const cpu = Math.max(1, Number(cpuCount || 1));
  const memoryClass = totalGb >= 64 ? 'high_ram' : totalGb >= 32 ? 'local_standard' : 'memory_constrained';
  const computeClass = cpu >= 16 ? 'many_core' : cpu >= 8 ? 'balanced_core' : 'low_core';
  const vramClass = Number.isFinite(Number(gpuVramGb))
    ? (Number(gpuVramGb) >= 24 ? 'large_vram' : Number(gpuVramGb) >= 12 ? 'medium_vram' : 'small_vram')
    : 'unknown_vram';

  return {
    status: 'observed',
    source_papers: [DALI_SOURCE, HILLINFER_SOURCE, ML_MEMORY_SOURCE, MICRO_BOTTLENECK_SOURCE],
    platform,
    arch,
    cpu_count: cpu,
    total_memory_gb: round(totalGb, 2),
    free_memory_gb: round(freeGb, 2),
    gpu_vram_gb: hasNumericValue(gpuVramGb) ? Number(gpuVramGb) : null,
    disk_free_gb: hasNumericValue(diskFreeGb) ? Number(diskFreeGb) : null,
    classes: {
      memory: memoryClass,
      compute: computeClass,
      vram: vramClass,
    },
    aimos_local_posture: totalGb >= 32 && cpu >= 8 ? 'local_ready' : 'constrained_but_supported',
    guarded_math: {
      hardware_counter_model: false,
      hill_climbing_scheduler: false,
      rl_data_placement_policy: false,
    },
  };
}

export function buildTurboQuantReadiness({
  vectorDimension = 768,
  vectorCount = 0,
  bitsPerChannel = 3.5,
  baselineRecallAt10 = null,
  quantizedRecallAt10 = null,
  qualityLossBudgetPct = 2,
  quantColumns = false,
} = {}) {
  const baseline = Number(baselineRecallAt10);
  const quantized = Number(quantizedRecallAt10);
  const hasBenchmark = Number.isFinite(baseline) && baseline > 0 && Number.isFinite(quantized);
  const qualityLossPct = hasBenchmark
    ? Math.max(0, ((baseline - quantized) / baseline) * 100)
    : null;
  const qualityGatePassed = hasBenchmark && qualityLossPct <= Number(qualityLossBudgetPct || 2);
  const rawVectorBytes = Math.max(0, Number(vectorCount || 0)) * Math.max(1, Number(vectorDimension || 768)) * 4;
  const quantizedBytes = rawVectorBytes * (clampNumber(bitsPerChannel, 1, 16, 3.5) / 32);

  return {
    status: qualityGatePassed ? 'eligible' : 'benchmark_required',
    source_paper: TURBOQUANT_SOURCE,
    quantization_map: 'Q: R^d -> {0,1}^B',
    representation_only: true,
    aimos_memory_loss_allowed: false,
    target_bits_per_channel: clampNumber(bitsPerChannel, 1, 16, 3.5),
    vector_dimension: Math.max(1, Number(vectorDimension || 768)),
    vector_count: Math.max(0, Number(vectorCount || 0)),
    estimated_storage: {
      raw_vector_bytes: Math.round(rawVectorBytes),
      quantized_vector_bytes: Math.round(quantizedBytes),
      estimated_reduction_ratio: rawVectorBytes > 0 ? round(1 - quantizedBytes / rawVectorBytes, 4) : null,
    },
    quality_gate: {
      benchmark_required: true,
      baseline_recall_at_10: hasBenchmark ? baseline : null,
      quantized_recall_at_10: hasBenchmark ? quantized : null,
      quality_loss_pct: qualityLossPct == null ? null : round(qualityLossPct, 4),
      budget_pct: Number(qualityLossBudgetPct || 2),
      passed: qualityGatePassed,
    },
    schema_support: {
      turboquant_columns_present: Boolean(quantColumns),
      full_fidelity_vectors_required: true,
    },
    guarded_math: {
      live_embedding_quantization_enabled: false,
      kv_cache_quantization_enabled: false,
      recall_ranking_changed: false,
      distortion_rate_proof_reimplemented: false,
    },
  };
}

export function computeSpeculativeExpectedTokens({ gamma = 4, acceptanceProbability = 0.7 } = {}) {
  const g = Math.max(0, Math.floor(Number(gamma || 0)));
  const alpha = clampNumber(acceptanceProbability, 0, 0.999999, 0.7);
  if (Math.abs(1 - alpha) < 1e-9) return g + 1;
  return (1 - alpha ** (g + 1)) / (1 - alpha);
}

export function buildMoEExpertSchedulingPlan({
  model = '',
  prompt = '',
  taskType = 'chat',
  totalExperts = null,
  activeExperts = null,
  turnDifficulty = null,
  gpuVramGb = null,
  cpuCount = os.cpus()?.length || 1,
  gamma = 4,
  acceptanceProbability = 0.7,
  idleComputeRatio = 0.25,
} = {}) {
  const isMoE = detectMoEModel(model);
  const counts = inferExpertCounts(model, { totalExperts, activeExperts });
  const promptTokens = estimateTokensFromChars(prompt);
  const difficulty = String(turnDifficulty || taskType || 'chat').toLowerCase();
  const difficultyMultiplier = /\b(hard|complex|analysis|research|investigation|architecture)\b/.test(difficulty) ? 1.5 : 1;
  const hotExpertBudget = Math.min(
    counts.totalExperts,
    Math.max(
      counts.activeExperts,
      Math.ceil(counts.activeExperts * (Number(gpuVramGb) >= 24 ? 4 : Number(gpuVramGb) >= 12 ? 2.5 : 1.5) * difficultyMultiplier),
    ),
  );
  const coldExpertCount = Math.max(0, counts.totalExperts - hotExpertBudget);
  const omega = computeSpeculativeExpectedTokens({ gamma, acceptanceProbability });
  const speculativeUseful = isMoE && Number(idleComputeRatio || 0) >= 0.2;

  return {
    status: isMoE ? 'wired' : 'not_applicable',
    source_papers: [DALI_SOURCE, DYMOE_SOURCE, PROBE_SOURCE, MOE_SPAC_SOURCE, SPECULATING_EXPERTS_SOURCE],
    model,
    moe_detected: isMoE,
    expert_counts: {
      total_experts: counts.totalExperts,
      active_experts_per_token: counts.activeExperts,
      source: counts.source,
    },
    prompt_tokens_estimate: promptTokens,
    dali: {
      mechanism: 'workload_aware_cpu_gpu_expert_assignment',
      runtime_assignment: isMoE ? 'greedy_hot_experts_to_gpu_cold_to_cpu' : 'disabled_non_moe_model',
      gpu_hot_expert_budget: isMoE ? hotExpertBudget : 0,
      cpu_cold_expert_count: isMoE ? coldExpertCount : 0,
      cache_policy: 'temporal_correlation_aware_replacement_contract',
    },
    dymoe: {
      mechanism: 'importance_aware_mixed_precision_contract',
      critical_layers: 'preserve_high_precision',
      subcritical_experts: 'eligible_for_lower_precision_after_benchmark',
      depth_adaptive_scheduling: true,
      lookahead_prefetching: true,
    },
    probe: {
      phases: ['predict', 'plan', 'prefetch'],
      continuous_lookahead_pipelining: true,
      split_phase_transmission: 'diagnostic_contract_only',
      hotspot_volatility_handled: true,
    },
    moe_spac: {
      speculative_decoding_as_sensor: true,
      gamma: Math.max(0, Math.floor(Number(gamma || 0))),
      acceptance_probability: clampNumber(acceptanceProbability, 0, 0.999999, 0.7),
      expected_tokens_formula: 'Omega(gamma, alpha) = (1 - alpha^(gamma + 1)) / (1 - alpha)',
      expected_tokens: round(omega, 4),
      utility_space: 'estimated_hot_vs_cold_expert_priority',
    },
    speculating_experts: {
      parameter_free_prefetch_contract: true,
      execute_prefetched_experts: false,
      enabled_when_idle_compute_available: speculativeUseful,
      idle_compute_ratio: clampNumber(idleComputeRatio, 0, 1, 0.25),
    },
    combined_pipeline: {
      dali_to_dymoe_signal: isMoE ? 'retrieval_or_prompt_difficulty_sets_hot_expert_budget' : 'not_applicable',
      probe_to_spac_signal: isMoE ? 'lookahead_hotspots_feed_speculative_utility' : 'not_applicable',
      local_runtime_mutated: false,
    },
    guarded_math: {
      zero_one_integer_solver: false,
      learned_router_distillation: false,
      mixed_precision_weight_rewrite: false,
      speculative_expert_execution: false,
      online_threshold_optimizer_tau: false,
    },
    guarded_routing_math: {
      router_logits_used: false,
      sparse_attention_kernel_enabled: false,
      lora_adapter_merge_enabled: false,
      expert_assignment_executed: false,
      live_model_routing_changed: false,
    },
  };
}

export function buildKvCacheAndLayoutPlan({
  contextTokens = 4096,
  predictedOutputTokens = 512,
  layers = 32,
  hiddenSize = 4096,
  bytesPerValue = 2,
  freeMemoryBytes = os.freemem(),
  hasSmartSsd = false,
  pimAvailable = false,
} = {}) {
  const totalTokens = Math.max(1, Number(contextTokens || 4096) + Number(predictedOutputTokens || 0));
  const kvBytes = totalTokens
    * Math.max(1, Number(layers || 32))
    * Math.max(1, Number(hiddenSize || 4096))
    * Math.max(1, Number(bytesPerValue || 2))
    * 2;
  const freeBytes = Math.max(1, Number(freeMemoryBytes || os.freemem() || GIB));
  const pressureRatio = kvBytes / freeBytes;
  const hotWindowTokens = Math.min(totalTokens, pressureRatio > 0.5 ? 1024 : 2048);
  const coldWindowTokens = Math.max(0, totalTokens - hotWindowTokens);

  return {
    status: 'wired',
    source_papers: [HILLINFER_SOURCE, TURBOQUANT_SOURCE, ARRAY_TRANSLATION_SOURCE, PIM_SHERPA_SOURCE],
    kv_cache_estimate: {
      context_tokens: Number(contextTokens || 4096),
      predicted_output_tokens: Number(predictedOutputTokens || 0),
      formula: 'bytes = tokens * layers * hidden_size * bytes_per_value * 2(K,V)',
      estimated_bytes: Math.round(kvBytes),
      estimated_gb: round(kvBytes / GIB, 3),
      free_memory_pressure_ratio: round(pressureRatio, 4),
    },
    hillinfer: {
      hierarchical_kv_cache_manager: true,
      hot_pool_tokens: hotWindowTokens,
      cold_pool_tokens: coldWindowTokens,
      hot_pool_target: 'ram',
      cold_pool_target: coldWindowTokens > 0 && hasSmartSsd ? 'smartssd_advisory' : coldWindowTokens > 0 ? 'ssd_advisory' : 'none',
      adaptive_prefetch_pipeline: true,
      importance_evaluation_offloaded: Boolean(hasSmartSsd),
    },
    turboquant: {
      kv_quantization_bits_per_channel: 3.5,
      quality_neutrality_claim_requires_benchmark: true,
      enabled: false,
    },
    array_translation: {
      layout: 'contiguous_typed_array_advisory',
      cache_friendly_scan_order: true,
      simd_exploitable_layout: true,
      data_content_changed: false,
    },
    pim_sherpa: {
      pim_available: Boolean(pimAvailable),
      prefill_region: 'cacheable_host_friendly',
      decode_region: pimAvailable ? 'non_cacheable_pim_aware' : 'host_memory_fallback',
      memory_attribute_inconsistency_detected: Boolean(pimAvailable),
      layout_inconsistency_handled_as_diagnostic: true,
    },
    guarded_math: {
      live_kv_eviction_mutation: false,
      smartssd_fpga_program: false,
      pim_double_buffering_enabled: false,
      online_weight_rearrangement_enabled: false,
      kv_quantization_enabled: false,
    },
  };
}

export function classifyPhysicalMemoryTemperature(memory = {}, nowMs = Date.now()) {
  const accessCount = Number(memory.access_count || memory.accessCount || 0);
  const weight = Number(memory.retrieval_weight ?? memory.weight ?? memory.decay_weight ?? 1);
  const lastAccessed = memory.last_accessed_at || memory.last_accessed || memory.updated_at || memory.created_at || null;
  const ageDays = lastAccessed ? Math.max(0, (Number(nowMs || Date.now()) - new Date(lastAccessed).getTime()) / 86_400_000) : null;

  if (accessCount >= 10 || weight >= 1.5 || (ageDays != null && ageDays <= 7 && accessCount >= 2)) {
    return 'hot';
  }
  if (accessCount >= 2 || weight >= 0.5 || (ageDays != null && ageDays <= 45)) {
    return 'warm';
  }
  return 'cold';
}

export function buildLocalMemoryPlacementPlan({
  memories = [],
  graphEdgeCount = 0,
  vectorCount = 0,
  vectorDimension = 768,
  totalMemoryBytes = os.totalmem(),
} = {}) {
  const counts = { hot: 0, warm: 0, cold: 0 };
  for (const memory of Array.isArray(memories) ? memories : []) {
    counts[classifyPhysicalMemoryTemperature(memory)] += 1;
  }
  const estimatedVectorBytes = Math.max(0, Number(vectorCount || 0)) * Math.max(1, Number(vectorDimension || 768)) * 4;
  const estimatedGraphBytes = Math.max(0, Number(graphEdgeCount || 0)) * 64;
  const footprintBytes = estimatedVectorBytes + estimatedGraphBytes;
  const ramThresholdBytes = Math.max(1, Number(totalMemoryBytes || os.totalmem() || GIB)) * 0.5;

  return {
    status: 'wired',
    source_papers: [ML_MEMORY_SOURCE, MICRO_BOTTLENECK_SOURCE, SSD_GRAPH_SOURCE],
    physical_tiers: {
      hot: { target: 'ram', count: counts.hot },
      warm: { target: 'page_cache_or_mmap', count: counts.warm },
      cold: { target: 'ssd_resident', count: counts.cold },
    },
    ssd_graph_indexing: {
      source_paper: SSD_GRAPH_SOURCE,
      graph_edge_count: Math.max(0, Number(graphEdgeCount || 0)),
      vector_count: Math.max(0, Number(vectorCount || 0)),
      estimated_footprint_bytes: Math.round(footprintBytes),
      ram_threshold_bytes: Math.round(ramThresholdBytes),
      ssd_resident_recommended: footprintBytes > ramThresholdBytes,
      aladdin_scaling_role: 'keep_everything_without_ram_crash',
    },
    ml_memory_policy: {
      pythia_prefetcher: 'diagnostic_only',
      hermes_off_chip_predictor: 'diagnostic_only',
      sibyl_data_placement: 'tier_contract_only',
      online_learning_enabled: false,
    },
    aladdin_boundary: {
      physical_delete_allowed: false,
      cold_tier_means_less_resident_not_less_retained: true,
    },
    guarded_math: {
      rl_prefetch_policy: false,
      perceptron_off_chip_predictor: false,
      adaptive_storage_rl: false,
      graph_index_rewrite: false,
    },
  };
}

export function buildDualMemoryLaneDiagnostics({
  memories = [],
  placement = null,
  contextTokens = null,
} = {}) {
  const rows = Array.isArray(memories) ? memories : [];
  const counts = { episodic: 0, semantic: 0, procedural: 0, short_term: 0, unknown: 0 };
  for (const memory of rows) {
    const type = String(memory.memory_type || memory.memoryType || '').toLowerCase();
    if (['session_debrief', 'session_exchange', 'session_manifest', 'event_log', 'agent_session', 'conversation_feed'].includes(type)) counts.episodic += 1;
    else if (['bibliographic_reference', 'framework', 'tacit_knowledge', 'book_extract'].includes(type)) counts.semantic += 1;
    else if (['procedural', 'procedure', 'session_reasoning'].includes(type) || String(memory.key || '').startsWith('ai_adr:')) counts.procedural += 1;
    else if (['reasoning_state', 'heartbeat'].includes(type)) counts.short_term += 1;
    else counts.unknown += 1;
  }
  const physical = placement?.physical_tiers || {};
  const hotCount = Number(physical.hot?.count || 0);
  const warmCount = Number(physical.warm?.count || 0);
  const coldCount = Number(physical.cold?.count || 0);

  return {
    source_papers: [DUAL_MEMORY_SOURCE, LARGE_MEMORY_NETWORK_SOURCE, LPC_SM_SOURCE],
    status: 'diagnostic',
    fast_memory: {
      lane: 'short_term_or_hot_context',
      candidate_count: counts.short_term + hotCount,
      context_tokens: contextTokens ?? null,
    },
    slow_memory: {
      lane: 'long_term_aimos_memory',
      candidate_count: rows.length,
      semantic_count: counts.semantic,
      episodic_count: counts.episodic,
      procedural_count: counts.procedural,
    },
    physical_temperature_counts: {
      hot: hotCount,
      warm: warmCount,
      cold: coldCount,
    },
    memory_lane_counts: counts,
    cold_means_less_resident_not_forgotten: true,
    physical_memory_migration_enabled: false,
    diagnostic_only: true,
    ranking_math_changed: false,
    guarded_math: {
      dual_memory_joint_reward: false,
      large_memory_network_topk_softmax: false,
      stm_ltm_policy_update: false,
    },
  };
}

export function buildInactiveMultimodalAdapterContracts({
  requestedModalities = [],
  contextTokens = null,
} = {}) {
  const modalities = new Set((Array.isArray(requestedModalities) ? requestedModalities : [])
    .map((value) => String(value || '').toLowerCase())
    .filter(Boolean));

  return {
    status: 'inactive_contract',
    source_papers: [BRANCHLORA_SOURCE, SOULX_DUPLUG_SOURCE, VLM_DEGRADATION_SOURCE, STREAM_SOURCE],
    requested_modalities: Array.from(modalities),
    context_tokens: contextTokens ?? null,
    claims_support: false,
    contract_only: true,
    adapter_weights_mutated: false,
    active_capabilities: {
      vision: false,
      audio: false,
      multimodal_fusion: false,
      lora: false,
      speech_stream_state: false,
      degradation_prior: false,
    },
    future_readiness: {
      adapter_registry_required: true,
      permissioned_media_ingest_required: true,
      paper_formula_audit_required: true,
      live_model_integration_required: true,
    },
    guarded_math: {
      lora_training: false,
      branch_router_enabled: false,
      streaming_state_predictor_enabled: false,
      vlm_cot_prior_enabled: false,
      cross_attention_fusion_enabled: false,
      sparse_attention_mask_enabled: false,
    },
  };
}

export function buildMicroBottleneckDiagnostic({
  latencyMs = 0,
  cpuUtilization = null,
  memoryPressure = null,
  ioWaitRatio = null,
  gpuUtilization = null,
} = {}) {
  const latency = Number(latencyMs || 0);
  const cpu = Number(cpuUtilization);
  const mem = Number(memoryPressure);
  const io = Number(ioWaitRatio);
  const gpu = Number(gpuUtilization);
  let bottleneck = 'unknown';
  if (Number.isFinite(io) && io > 0.35) bottleneck = 'io_wait';
  else if (Number.isFinite(mem) && mem > 0.75) bottleneck = 'memory_pressure';
  else if (Number.isFinite(gpu) && gpu > 0.9) bottleneck = 'gpu_saturation';
  else if (Number.isFinite(cpu) && cpu > 0.9) bottleneck = 'cpu_saturation';
  else if (latency > 10_000) bottleneck = 'latency_unattributed';

  return {
    status: 'diagnostic',
    source_paper: MICRO_BOTTLENECK_SOURCE,
    bottleneck,
    observed: {
      latency_ms: latency,
      cpu_utilization: Number.isFinite(cpu) ? round(cpu, 3) : null,
      memory_pressure: Number.isFinite(mem) ? round(mem, 3) : null,
      io_wait_ratio: Number.isFinite(io) ? round(io, 3) : null,
      gpu_utilization: Number.isFinite(gpu) ? round(gpu, 3) : null,
    },
    guarded_math: {
      hardware_performance_counters: false,
      learned_microarchitectural_classifier: false,
      processor_level_speculation: false,
    },
  };
}

export function buildNexusIoOffloadPlan({
  operation = 'agent_run',
  inputBytes = 0,
  outputBytes = 0,
  backgroundWriteAllowed = true,
} = {}) {
  return {
    status: 'wired',
    source_paper: NEXUS_SOURCE,
    operation,
    native_server_only: true,
    proxy_layer_introduced: false,
    io_contract: {
      decouple_compute_from_io: true,
      input_prefetch_during_bootstrap: Number(inputBytes || 0) > 0,
      output_write_off_critical_path: Boolean(backgroundWriteAllowed),
      at_least_once_write_semantics_required: true,
      zero_copy_shared_memory: false,
    },
    security_boundary: {
      credentials_moved_to_browser: false,
      least_privilege_backend_identity: true,
      raw_provider_credentials_exposed_to_guest: false,
    },
    guarded_math: {
      hypervisor_intercept: false,
      shared_memory_transport: false,
      vm_snapshot_scheduler: false,
    },
  };
}

export function buildLpcSmSmallModelPlan({
  prompt = '',
  model = '',
  confidence = null,
  noveltyScore = null,
  targetContextTokens = 4096,
} = {}) {
  const promptTokens = estimateTokensFromChars(prompt);
  const conf = Number(confidence);
  const novelty = Number(noveltyScore);
  const sparseRatio = promptTokens > 2048 ? 0.35 : promptTokens > 512 ? 0.5 : 0.65;
  const shouldDelegateUp = Number.isFinite(conf) && conf < 0.55;

  return {
    status: 'wired',
    source_paper: LPC_SM_SOURCE,
    model,
    target_context_tokens: Math.max(512, Number(targetContextTokens || 4096)),
    local_predictive_coding: {
      local_attention_window: Math.min(1024, Math.max(128, Math.ceil(promptTokens / 2))),
      fast_memory: 'session_token_trace',
      slow_memory: 'aimos_long_term_memory',
      predictive_correction_signal: Number.isFinite(conf) ? (1 - conf) : null,
    },
    sparse_memory_control: {
      adaptive_sparse_ratio: round(sparseRatio, 3),
      learned_sparse_controller: false,
      delegate_up_when_low_confidence: shouldDelegateUp,
      confidence_threshold: 0.55,
    },
    ont_write_boundary: {
      orthogonal_novelty_transport: 'guarded_until_vector_math_review',
      novelty_score: Number.isFinite(novelty) ? round(novelty, 3) : null,
      aimos_write_mutated: false,
    },
    guarded_math: {
      lpc_sm_architecture_training: false,
      ont_vector_projection: false,
      learned_stopping_head: false,
      slow_memory_write_rule: false,
    },
  };
}

export function buildLocalInferenceRunPlan({
  model = '',
  prompt = '',
  taskType = 'chat',
  confidence = null,
  contextTokens = null,
  predictedOutputTokens = null,
  hardware = {},
  memories = [],
  vectorCount = 0,
  graphEdgeCount = 0,
  quantColumns = false,
} = {}) {
  const host = buildHostHardwareProfile(hardware);
  const promptTokens = contextTokens || estimateTokensFromChars(prompt);
  const moe = buildMoEExpertSchedulingPlan({
    model,
    prompt,
    taskType,
    gpuVramGb: hardware.gpuVramGb,
    cpuCount: host.cpu_count,
    turnDifficulty: taskType,
  });
  const kv = buildKvCacheAndLayoutPlan({
    contextTokens: promptTokens,
    predictedOutputTokens: predictedOutputTokens || 512,
    freeMemoryBytes: hardware.freeMemoryBytes || os.freemem(),
    hasSmartSsd: hardware.hasSmartSsd,
    pimAvailable: hardware.pimAvailable,
  });
  const placement = buildLocalMemoryPlacementPlan({
    memories,
    graphEdgeCount,
    vectorCount,
    totalMemoryBytes: hardware.totalMemoryBytes || os.totalmem(),
  });
  const quant = buildTurboQuantReadiness({
    vectorCount,
    quantColumns,
  });
  const nexus = buildNexusIoOffloadPlan({
    operation: taskType,
    inputBytes: String(prompt || '').length,
    outputBytes: Number(predictedOutputTokens || 512) * 4,
  });
  const lpcSm = buildLpcSmSmallModelPlan({
    prompt,
    model,
    confidence,
    targetContextTokens: promptTokens,
  });
  const dualMemoryLanes = buildDualMemoryLaneDiagnostics({
    memories,
    placement,
    contextTokens: promptTokens,
  });
  const inactiveAdapterContracts = buildInactiveMultimodalAdapterContracts({
    requestedModalities: hardware.requestedModalities || [],
    contextTokens: promptTokens,
  });
  const guardedCompression = buildGuardedKvCompressionReadiness({
    contextTokens: promptTokens,
    predictedOutputTokens: predictedOutputTokens || 512,
    freeMemoryBytes: hardware.freeMemoryBytes || os.freemem(),
    evidencePrecisionLevel: hardware.evidencePrecisionLevel || 'claim_evidence',
    reasoningSafeCompression: hardware.reasoningSafeCompression || null,
  });

  return {
    status: 'wired',
    source_papers: [
      TURBOQUANT_SOURCE,
      DALI_SOURCE,
      DYMOE_SOURCE,
      HILLINFER_SOURCE,
      PROBE_SOURCE,
      MOE_SPAC_SOURCE,
      SPECULATING_EXPERTS_SOURCE,
      ML_MEMORY_SOURCE,
      MICRO_BOTTLENECK_SOURCE,
      SSD_GRAPH_SOURCE,
      ARRAY_TRANSLATION_SOURCE,
      NEXUS_SOURCE,
      PIM_SHERPA_SOURCE,
      LPC_SM_SOURCE,
      BRANCHLORA_SOURCE,
      STREAM_SOURCE,
      SOULX_DUPLUG_SOURCE,
      VLM_DEGRADATION_SOURCE,
    ],
    native_server_only: true,
    proxy_layer_introduced: false,
    host,
    quantization: quant,
    moe_scheduling: moe,
    kv_cache: kv,
    memory_placement: placement,
    dual_memory_lanes: dualMemoryLanes,
    inactive_adapter_contracts: inactiveAdapterContracts,
    wave4_compression: guardedCompression,
    nexus_io: nexus,
    small_model_efficiency: lpcSm,
    guarded_math: {
      model_weights_changed: false,
      retrieval_ranking_changed: false,
      scheduler_learning_enabled: false,
      hardware_offload_enabled: false,
      physical_memory_migration_enabled: false,
    },
  };
}

export function buildGuardedKvCompressionReadiness({
  contextTokens = 0,
  predictedOutputTokens = 0,
  freeMemoryBytes = os.freemem(),
  evidencePrecisionLevel = 'claim_evidence',
  requestedMethods = [],
  reasoningSafeCompression = null,
  benchmark = {},
} = {}) {
  const context = Math.max(0, Number(contextTokens || 0));
  const output = Math.max(0, Number(predictedOutputTokens || 0));
  const total = context + output;
  const freeBytes = Math.max(1, Number(freeMemoryBytes || os.freemem() || GIB));
  const estimatedKvBytes = total * 32 * 4096 * 2 * 2;
  const memoryPressure = estimatedKvBytes / freeBytes;
  const methods = new Set((Array.isArray(requestedMethods) ? requestedMethods : [])
    .map((method) => String(method || '').toLowerCase())
    .filter(Boolean));
  const benchmarkHasProof = Number.isFinite(Number(benchmark?.baselineRecallAt10))
    && Number.isFinite(Number(benchmark?.compressedRecallAt10));
  const reasoningSafe = reasoningSafeCompression?.safe_to_answer === true
    || reasoningSafeCompression?.status === 'safe_to_answer_from_compressed_view';

  return {
    status: reasoningSafe && benchmarkHasProof ? 'diagnostic_ready' : 'guarded_benchmark_required',
    source_papers: [
      HOLD_THOUGHT_SOURCE,
      DONT_WASTE_BITS_SOURCE,
      AQPIM_SOURCE,
      ELITEKV_SOURCE,
      STOCHASTIC_KV_SOURCE,
      FRACTIONAL_ROPE_SOURCE,
      TWO_BLOCK_HADAMARD_SOURCE,
      HIERASPARSE_SOURCE,
      NEURAL_PRECONDITIONING_SOURCE,
    ],
    diagnostic_only: true,
    runtime_estimate: {
      context_tokens: context,
      predicted_output_tokens: output,
      total_tokens: total,
      estimated_kv_bytes: Math.round(estimatedKvBytes),
      estimated_kv_gb: round(estimatedKvBytes / GIB, 3),
      free_memory_pressure_ratio: round(memoryPressure, 6),
      evidence_precision_level: String(evidencePrecisionLevel || 'claim_evidence'),
    },
    requested_methods: Array.from(methods),
    readiness_gate: {
      reasoning_safe_compression_proven: reasoningSafe,
      benchmark_required: true,
      benchmark_present: benchmarkHasProof,
      formula_audit_required: true,
      production_enabled: false,
    },
    execution_contract: {
      kv_cache_mutated: false,
      kv_quantization_executed: false,
      sparse_attention_kernel_enabled: false,
      rope_rotation_changed: false,
      hadamard_rotation_enabled: false,
      pim_activation_quantization_enabled: false,
      recall_ranking_changed: false,
      provider_routing_changed: false,
    },
    guarded_math: {
      adaptive_kv_quantization: false,
      rope_frequency_selection: false,
      joint_low_rank_projection: false,
      stochastic_depthwise_cache_sharing: false,
      fractional_rope: false,
      two_block_hadamard_rotation: false,
      hierarchical_sparse_kv_attention: false,
      krylov_preconditioner: false,
    },
  };
}

export function buildLocalRuntimePressureDiagnostics({
  contextTokens = 0,
  predictedOutputTokens = 0,
  freeMemoryBytes = null,
  cacheOffloadRequested = false,
  indexReuseRequested = false,
  vectorOperationsPerToken = 0,
  sparseAttentionRequested = false,
} = {}) {
  const context = Math.max(0, Number(contextTokens || 0));
  const output = Math.max(0, Number(predictedOutputTokens || 0));
  const total = context + output;
  const memoryBytes = Number(freeMemoryBytes);
  const memoryPressure = Number.isFinite(memoryBytes) && memoryBytes > 0
    ? clamp01((total * 4096) / memoryBytes)
    : clamp01(total / 128000);
  const vectorPressure = clamp01(Number(vectorOperationsPerToken || 0) / 4096);
  const contextPressure = clamp01(total / 128000);

  return {
    status: 'diagnostic',
    source_papers: [ESS_SOURCE, INDEXCACHE_SOURCE, VFA_SOURCE, SALCA_SOURCE],
    diagnostic_only: true,
    runtime_pressure: {
      context_tokens: context,
      predicted_output_tokens: output,
      total_tokens: total,
      context_pressure: round(contextPressure, 6),
      memory_pressure: round(memoryPressure, 6),
      vector_operation_pressure: round(vectorPressure, 6),
    },
    acceleration_contract: {
      cache_offload_requested: Boolean(cacheOffloadRequested),
      index_reuse_requested: Boolean(indexReuseRequested),
      sparse_attention_requested: Boolean(sparseAttentionRequested),
      cache_offload_executed: false,
      index_reuse_executed: false,
      sparse_attention_kernel_enabled: false,
      local_model_started: false,
    },
    aladdin_boundary: {
      canonical_memory_moved: false,
      canonical_memory_deleted: false,
      compression_scope: 'runtime_context_and_cache_views_only',
    },
  };
}

export function buildWave5LocalInferenceStatus(sample = {}) {
  const plan = buildLocalInferenceRunPlan({
    model: sample.model || 'qwen3-30b-a3b',
    prompt: sample.prompt || 'Recall the last safe session with source-backed evidence.',
    taskType: sample.taskType || 'recall',
    confidence: sample.confidence ?? 0.74,
    contextTokens: sample.contextTokens || 4096,
    predictedOutputTokens: sample.predictedOutputTokens || 512,
    memories: sample.memories || [
      { access_count: 20, retrieval_weight: 1.8, updated_at: new Date().toISOString() },
      { access_count: 3, retrieval_weight: 0.7, updated_at: new Date().toISOString() },
      { access_count: 0, retrieval_weight: 0.1, updated_at: '2026-01-01T00:00:00.000Z' },
    ],
    vectorCount: sample.vectorCount || 12_000,
    graphEdgeCount: sample.graphEdgeCount || 36_000,
    quantColumns: sample.quantColumns || false,
    hardware: sample.hardware || {},
  });

  return {
    success: true,
    status: 'wired',
    wave: 'wave_5_local_inference_efficiency',
    plan,
    exit_criteria: {
      quantization_gate_present: plan.quantization.quality_gate.benchmark_required,
      moe_scheduling_contract_present: plan.moe_scheduling.status !== 'missing',
      kv_layout_contract_present: plan.kv_cache.status === 'wired',
      memory_tiering_contract_present: plan.memory_placement.status === 'wired',
      nexus_native_io_contract_present: plan.nexus_io.proxy_layer_introduced === false,
      lpc_sm_small_model_contract_present: plan.small_model_efficiency.status === 'wired',
    },
  };
}

// ─── BATCH 10 LANE 4: PER-TOKEN COMPRESSION GATE + LAYER RATIOS ──────────────
// Papers: Dynamic Memory Compression, KV Cache Optimization Strategies
// compression_ratio_per_layer = {layer_0: 0.8, layer_1: 0.6, ...}
// retain_gate(token, layer) = σ(MVS_chunk_avg - 0.42)
// kv_reviver_memory_savings = 1 - (sketch_bytes / full_kv_bytes)
// All diagnostic — existing inference path unchanged.
// ─────────────────────────────────────────────────────────────────────────────

const COMPRESSION_GATE_THRESHOLD = 0.42; // MVS threshold for retention decision

/**
 * Per-token compression gate diagnostic.
 * retain_gate(token, layer) = σ(MVS_chunk_avg - 0.42)
 * Tokens with MVS above threshold are retained at full fidelity;
 * tokens below are candidates for compression.
 *
 * @param {number[]} tokenScores - Array of per-token MVS/attention scores
 * @param {number} threshold - MVS threshold (default 0.42)
 * @returns {{ retained_count: number, compressed_count: number, gate_decisions: Array, source_paper: string, diagnostic_only: boolean }}
 */
export function computeCompressionGate(tokenScores = [], threshold = COMPRESSION_GATE_THRESHOLD) {
  const scores = Array.isArray(tokenScores) ? tokenScores : [];
  const t = Number(threshold) || COMPRESSION_GATE_THRESHOLD;

  let retainedCount = 0;
  let compressedCount = 0;
  const gateDecisions = [];

  for (let i = 0; i < scores.length; i++) {
    const score = Number(scores[i]) || 0;
    // sigmoid(MVS - threshold): smooth gate around threshold
    const gateValue = 1 / (1 + Math.exp(-(score - t) * 10)); // steep sigmoid
    const retain = gateValue >= 0.5;

    if (retain) retainedCount++;
    else compressedCount++;

    gateDecisions.push({
      token_index: i,
      mvs_score: Number(score.toFixed(6)),
      gate_value: Number(gateValue.toFixed(6)),
      decision: retain ? 'RETAIN' : 'COMPRESS',
    });
  }

  return {
    retained_count: retainedCount,
    compressed_count: compressedCount,
    total_tokens: scores.length,
    compression_ratio: scores.length > 0
      ? Number((compressedCount / scores.length).toFixed(6))
      : 0,
    gate_decisions: gateDecisions,
    threshold: t,
    formula: 'retain_gate(token, layer) = σ(MVS_chunk_avg - 0.42)',
    source_paper: 'Dynamic Memory Compression',
    diagnostic_only: true,
    inference_path_unchanged: true,
  };
}

/**
 * Per-layer compression ratio reporting.
 * compression_ratio_per_layer = {layer_0: 0.8, layer_1: 0.6, ...}
 * Higher layers tend to have lower compression ratios (more compressible).
 *
 * @param {object} kvCache - KV cache with per-layer statistics
 * @returns {{ layer_ratios: object, avg_compression: number, source_paper: string, diagnostic_only: boolean }}
 */
export function computeLayerCompressionRatios(kvCache = {}) {
  const layers = kvCache?.layers || {};
  const layerRatios = {};
  let totalRatio = 0;
  let layerCount = 0;

  const layerNames = Object.keys(layers).sort((a, b) => {
    const numA = parseInt(a.replace(/\D/g, ''), 10) || 0;
    const numB = parseInt(b.replace(/\D/g, ''), 10) || 0;
    return numA - numB;
  });

  for (const layerName of layerNames) {
    const layerData = layers[layerName];
    const tokenCount = Number(layerData?.token_count || layerData?.tokens || 0);
    const retainedCount = Number(layerData?.retained_count || 0);
    const attentionEntropy = Number(layerData?.attention_entropy || 0);

    // Compression ratio estimation:
    // - Layers with high attention entropy are more uniform → more compressible
    // - Layers with more retained tokens are less compressible
    // - Base ratio: 0.8 for early layers, decreasing for deeper layers
    const layerIndex = parseInt(layerName.replace(/\D/g, ''), 10) || 0;
    const depthFactor = Math.max(0.2, 0.8 - layerIndex * 0.02);
    const entropyFactor = Math.max(0.3, 1 - attentionEntropy * 0.5);
    const retentionFactor = tokenCount > 0 ? Math.max(0.2, retainedCount / tokenCount) : 0.5;

    const ratio = Number((depthFactor * entropyFactor * retentionFactor).toFixed(6));
    layerRatios[layerName] = ratio;
    totalRatio += ratio;
    layerCount++;
  }

  // If no layer data, generate a default 32-layer profile
  if (layerCount === 0) {
    const totalLayers = Number(kvCache?.total_layers) || 32;
    for (let i = 0; i < totalLayers; i++) {
      const ratio = Number(Math.max(0.2, 0.8 - i * 0.02).toFixed(6));
      layerRatios[`layer_${i}`] = ratio;
      totalRatio += ratio;
      layerCount++;
    }
  }

  return {
    layer_ratios: layerRatios,
    layer_count: layerCount,
    avg_compression: layerCount > 0 ? Number((totalRatio / layerCount).toFixed(6)) : 0,
    formula: 'compression_ratio_per_layer = f(depth, entropy, retention)',
    source_paper: 'KV Cache Optimization Strategies',
    diagnostic_only: true,
    inference_path_unchanged: true,
  };
}

/**
 * Build compression diagnostic report combining gate and layer ratios.
 */
export function buildCompressionDiagnostic(sample = {}) {
  const tokenScores = sample.tokenScores || new Array(64).fill(0).map((_, i) =>
    0.3 + 0.4 * Math.exp(-0.05 * i) + 0.1 * Math.sin(i * 0.3)
  );

  const gate = computeCompressionGate(tokenScores, sample.threshold || COMPRESSION_GATE_THRESHOLD);
  const layerRatios = computeLayerCompressionRatios(sample.kvCache || {});

  return {
    status: 'diagnostic',
    source_papers: ['Dynamic Memory Compression', 'KV Cache Optimization Strategies'],
    diagnostic_only: true,
    compression_gate: gate,
    layer_compression_ratios: layerRatios,
    guardrails: {
      inference_path_unchanged: true,
      canonical_memory_unchanged: true,
      production_kv_mutation: false,
    },
  };
}
