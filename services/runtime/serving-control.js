// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wave 4 additive serving contract — native Aimos server only
// ← Called by: routes/aimos.js, agent-runner.js (Wave 4 runtime diagnostics)
// Pipeline: AGENT_RUN | Position: Serving QoS / stream / budget planning layer
// Source: Niyama — Breaking the Silos of LLM Inference Serving.
//         Low-Latency Stateful Stream Processing through Timely and Accurate
//         Prefetching; TokenScale; Robust Length Prediction; AGSC.
// Additive Batch8 authority: Fast Heterogeneous Serving; Stream; SoulX-Duplug.
// Aimos exposes passive model-allocation, sparse-context, and streaming-state
// diagnostics only; live routing, sparse attention, and speech predictors remain
// guarded.
// Additive Batch9.5 Wave4 authority: Hold Onto That Thought, Don't Waste Bits,
// EliteKV, Stochastic KV Routing, and HieraSparse. Aimos exposes serving-side
// evidence I/O and compression-readiness diagnostics only; no KV compression,
// sparse attention, or production routing mutation is enabled.
// Batch 10 Lane 4: ChunkKV chunk-level KV budget with attention-weighted pooling,
//   Predictive Multi-Tier Memory (HBM→DRAM→SSD). All diagnostic.
// Guardrail: this service exposes contracts and diagnostics first. It does not
// create a proxy, reject requests, mutate calibrated recall math, or train
// schedulers/predictors without the paper-backed validation set.
// ─────────────────────────────────────────────────────────────────────────────

export const NIYAMA_SOURCE = 'Niyama: Breaking the Silos of LLM Inference Serving';
export const KEYED_PREFETCH_SOURCE = 'Low-Latency Stateful Stream Processing through Timely and Accurate Prefetching';
export const TOKENSCALE_SOURCE = 'TokenScale: Timely and Accurate Autoscaling for Disaggregated LLM Serving with Token Velocity';
export const ROBUST_LENGTH_SOURCE = 'Robust Length Prediction: A Perspective from Heavy-Tailed Prompt-Conditioned Distributions';
export const AGSC_SOURCE = 'AGSC: Adaptive Granularity and Semantic Clustering for Uncertainty Quantification in Long-text Generation';
export const FAST_HETEROGENEOUS_SERVING_SOURCE = 'Fast Heterogeneous Serving: Mixed-Scale LLM Allocation for SLO-Constrained Inference';
export const STREAM_SOURCE = 'Stream: Sparse Attention for Long Context';
export const SOULX_DUPLUG_SOURCE = 'SoulX-Duplug: Streaming State Prediction for Full-Duplex Speech';
export const AGENTICCACHE_SOURCE = 'AGENTICCACHE: Cache-Driven Asynchronous Planning for Embodied AI Agents';
export const FSM_STREAMING_SOURCE = 'Boosting AI Reliability with an FSM-Driven Streaming Inference Pipeline';
export const AGENTPULSE_SOURCE = 'AgentPulse: A Continuous Multi-Signal Framework for Evaluating AI Agents in Deployment';
export const THERMAL_COMFORT_SOURCE = 'Agentic AI-Enabled Framework for Thermal Comfort and Building Energy Assessment';
export const COOPERATIVE_DRIVING_SOURCE = 'Towards Interactive and Learnable Cooperative Driving Automation';
export const SNAPSTREAM_SOURCE = 'SnapStream: Efficient Long Sequence Decoding on Dataflow Accelerators';
export const ESS_SOURCE = 'ESS: An Offload-Centric Latent-Cache Management Architecture for DeepSeek-V3.2-Exp';
export const INDEXCACHE_SOURCE = 'IndexCache: Accelerating Sparse Attention via Cross-Layer Index Reuse';
export const DEEPSEEK_V32_SOURCE = 'DeepSeek-V3.2: Pushing the Frontier of Open Large Language Models';
export const VFA_SOURCE = 'VFA: Relieving Vector Operations in Flash Attention with Global Maximum Pre-computation';
export const SALCA_SOURCE = 'Salca: A Sparsity-Aware Hardware Accelerator for Efficient Long-Context Attention Decoding';
export const HOLD_THOUGHT_SOURCE = 'Hold Onto That Thought: Assessing KV Cache Compression on Reasoning';
export const DONT_WASTE_BITS_SOURCE = "Don't Waste Bits: Adaptive KV-Cache Quantization for Lightweight On-Device LLMs";
export const ELITEKV_SOURCE = 'EliteKV: Scalable KV Cache Compression via RoPE Frequency Selection and Joint Low-Rank Projection';
export const STOCHASTIC_KV_SOURCE = 'Stochastic KV Routing: Enabling Adaptive Depth-Wise Cache Sharing';
export const HIERASPARSE_SOURCE = 'HieraSparse: Hierarchical Semi-Structured Sparse KV Attention';

export const FSM_STREAM_STATES = Object.freeze({
  INITIALIZED: 'initialized',
  PROVIDER_CONNECTED: 'provider_connected',
  TOOL_PENDING: 'tool_pending',
  STREAMING: 'streaming',
  BACKPRESSURE: 'backpressure',
  RECOVERED: 'recovered',
  FAILED_SAFE: 'failed_safe',
});

export const QOS_TIERS = Object.freeze({
  interactive: Object.freeze({
    tier: 'interactive',
    ttft_slo_ms: 2000,
    tbt_slo_ms: 120,
    ttlt_slo_ms: 30000,
    queue_soft_limit: 8,
  }),
  batch: Object.freeze({
    tier: 'batch',
    ttft_slo_ms: 10000,
    tbt_slo_ms: 350,
    ttlt_slo_ms: 30000,
    queue_soft_limit: 20,
  }),
  background: Object.freeze({
    tier: 'background',
    ttft_slo_ms: null,
    tbt_slo_ms: null,
    ttlt_slo_ms: 300000,
    queue_soft_limit: 60,
  }),
});

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

function redactProtocolFrame(value = '') {
  const text = String(value || '');
  if (!text) return '';
  if (/\b(HOM_TOOL|FunctionCall|tool_call|<\/?tool|args\s*=>|\"tool\"\s*:)/i.test(text)) {
    return '[redacted runtime protocol frame]';
  }
  return text.slice(0, 240);
}

export function normalizeFsmStreamState(state = '') {
  const normalized = String(state || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return Object.values(FSM_STREAM_STATES).includes(normalized)
    ? normalized
    : FSM_STREAM_STATES.INITIALIZED;
}

export function buildFsmStreamStateDiagnostics({
  providerConnected = false,
  toolPending = false,
  streaming = false,
  backpressure = false,
  recovered = false,
  failed = false,
  failureReason = '',
  rawFramePreview = '',
  partialToolFrameVisible = false,
  previousState = FSM_STREAM_STATES.INITIALIZED,
} = {}) {
  const protocolLeak = Boolean(partialToolFrameVisible)
    || /\b(HOM_TOOL|FunctionCall|tool_call|<\/?tool|args\s*=>|\"tool\"\s*:)/i.test(String(rawFramePreview || ''));
  let state = normalizeFsmStreamState(previousState);
  if (failed || protocolLeak) state = FSM_STREAM_STATES.FAILED_SAFE;
  else if (recovered) state = FSM_STREAM_STATES.RECOVERED;
  else if (backpressure) state = FSM_STREAM_STATES.BACKPRESSURE;
  else if (toolPending) state = FSM_STREAM_STATES.TOOL_PENDING;
  else if (streaming) state = FSM_STREAM_STATES.STREAMING;
  else if (providerConnected) state = FSM_STREAM_STATES.PROVIDER_CONNECTED;

  return {
    status: 'wired',
    source_paper: FSM_STREAMING_SOURCE,
    diagnostic_only: true,
    stream_state: state,
    previous_state: normalizeFsmStreamState(previousState),
    transition: `${normalizeFsmStreamState(previousState)}->${state}`,
    protocol_frame: {
      user_visible_protocol_allowed: false,
      partial_tool_frame_visible: protocolLeak,
      preview: redactProtocolFrame(rawFramePreview),
    },
    recovery: {
      required: state === FSM_STREAM_STATES.FAILED_SAFE || state === FSM_STREAM_STATES.BACKPRESSURE,
      reason: protocolLeak
        ? 'runtime_protocol_frame_must_not_be_user_visible'
        : failed
          ? String(failureReason || 'provider_or_tool_failure')
          : backpressure
            ? 'stream_backpressure_detected'
            : null,
      safe_user_status: state === FSM_STREAM_STATES.FAILED_SAFE
        ? 'The runtime hit a safe-stop and needs a typed recovery path.'
        : state === FSM_STREAM_STATES.BACKPRESSURE
          ? 'The runtime is slowing the stream to protect output integrity.'
          : 'Runtime state is stable.',
    },
    guarded_math: {
      learned_fsm_policy: false,
      provider_stream_rewrite: false,
      hidden_tool_execution: false,
      raw_protocol_passthrough: false,
    },
  };
}

export function buildRuntimeReliabilityPulse({
  latencyMs = 0,
  recallConfidence = 0,
  toolTruthStatus = 'unknown',
  safetyIntercepts = 0,
  driftScore = 0,
  evidenceCount = 0,
  contextPressure = 0,
  streamState = FSM_STREAM_STATES.INITIALIZED,
} = {}) {
  const latencyPressure = clamp01(Number(latencyMs || 0) / 30000);
  const recall = clamp01(recallConfidence, 0);
  const drift = clamp01(driftScore, 0);
  const pressure = clamp01(contextPressure, 0);
  const safety = Math.min(1, Math.max(0, Number(safetyIntercepts || 0)) / 3);
  const evidence = Math.min(1, Math.max(0, Number(evidenceCount || 0)) / 5);
  const toolPenalty = ['needs_intercept', 'failed', 'unavailable', 'unknown'].includes(String(toolTruthStatus || '').toLowerCase())
    ? 0.18
    : 0;
  const fsmPenalty = normalizeFsmStreamState(streamState) === FSM_STREAM_STATES.FAILED_SAFE
    ? 0.25
    : normalizeFsmStreamState(streamState) === FSM_STREAM_STATES.BACKPRESSURE
      ? 0.08
      : 0;
  const score = clamp01(
    (0.26 * (1 - latencyPressure))
    + (0.22 * recall)
    + (0.18 * evidence)
    + (0.14 * (1 - pressure))
    + (0.12 * (1 - drift))
    + (0.08 * (1 - safety))
    - toolPenalty
    - fsmPenalty
  );
  const state = score >= 0.72
    ? 'healthy'
    : score >= 0.45
      ? 'watch'
      : 'degraded';

  return {
    status: 'wired',
    source_paper: AGENTPULSE_SOURCE,
    diagnostic_only: true,
    health_state: state,
    health_score: Number(score.toFixed(6)),
    signals: {
      latency_ms: Math.max(0, Number(latencyMs || 0)),
      latency_pressure: Number(latencyPressure.toFixed(6)),
      recall_confidence: recall,
      tool_truth_status: String(toolTruthStatus || 'unknown'),
      safety_intercepts: Math.max(0, Number(safetyIntercepts || 0)),
      drift_score: drift,
      evidence_count: Math.max(0, Number(evidenceCount || 0)),
      context_pressure: pressure,
      stream_state: normalizeFsmStreamState(streamState),
    },
    action_contract: {
      policy_mutated_automatically: false,
      routing_changed: false,
      user_escalation_recommended: state === 'degraded',
    },
  };
}

export function buildEphemeralPlanCacheDiagnostics({
  prompt = '',
  nextActions = [],
  entries = [],
  maxEntries = 6,
  nowMs = Date.now(),
} = {}) {
  const boundedMax = Math.max(1, Math.min(16, Number(maxEntries || 6)));
  const promptKey = normalizePrefetchKey(prompt);
  const actionRows = (Array.isArray(nextActions) ? nextActions : [])
    .map((action, index) => ({
      key: normalizePrefetchKey(typeof action === 'string' ? action : action?.key || action?.label || ''),
      source: action?.source || 'predicted_next_action',
      rank: index + 1,
    }))
    .filter((row) => row.key);
  const retained = rankTimestampAwareCacheEntries([
    ...(Array.isArray(entries) ? entries : []),
    ...actionRows.map((row) => ({
      key: row.key,
      expected_access_at_ms: Number(nowMs || Date.now()) + row.rank * 250,
      entry_type: row.source,
    })),
    promptKey ? {
      key: promptKey,
      expected_access_at_ms: Number(nowMs || Date.now()) + 100,
      entry_type: 'current_prompt',
    } : null,
  ].filter(Boolean), { nowMs, limit: boundedMax });

  return {
    status: retained.length ? 'ready' : 'idle',
    source_paper: AGENTICCACHE_SOURCE,
    diagnostic_only: true,
    cache_scope: 'ephemeral_runtime_only',
    retained_entries: retained,
    canonical_memory_eviction: false,
    canonical_memory_deleted: false,
    cache_eviction_scope: 'runtime_artifacts_only',
    asynchronous_planning: {
      likely_next_actions: actionRows.slice(0, boundedMax),
      writes_on_critical_path: false,
      plan_cache_persisted_to_aimos_memory: false,
    },
    guarded_math: {
      learned_cache_policy: false,
      plan_reuse_executor: false,
      canonical_memory_eviction: false,
    },
  };
}

export function buildRuntimeAccelerationDiagnostics({
  provider = '',
  model = '',
  promptTokens = 0,
  outputTokens = 0,
  kvPressure = 0,
  indexReuseAvailable = false,
  cacheOffloadAvailable = false,
  vectorPressure = 0,
  sparseAttentionRequested = false,
} = {}) {
  const totalTokens = Math.max(0, Number(promptTokens || 0)) + Math.max(0, Number(outputTokens || 0));
  const contextPressure = clamp01(totalTokens / 128000);
  const kv = clamp01(kvPressure, contextPressure);
  const vector = clamp01(vectorPressure, 0);
  const longSequence = totalTokens >= 32000 || kv >= 0.6;

  return {
    status: 'diagnostic',
    source_papers: [
      SNAPSTREAM_SOURCE,
      ESS_SOURCE,
      INDEXCACHE_SOURCE,
      DEEPSEEK_V32_SOURCE,
      VFA_SOURCE,
      SALCA_SOURCE,
    ],
    provider: provider || null,
    model: model || null,
    diagnostic_only: true,
    long_sequence_detected: longSequence,
    runtime_pressure: {
      prompt_tokens: Math.max(0, Number(promptTokens || 0)),
      output_tokens: Math.max(0, Number(outputTokens || 0)),
      total_tokens: totalTokens,
      context_pressure: Number(contextPressure.toFixed(6)),
      kv_pressure: Number(kv.toFixed(6)),
      vector_pressure: Number(vector.toFixed(6)),
    },
    acceleration_readiness: {
      index_reuse_available: Boolean(indexReuseAvailable),
      cache_offload_available: Boolean(cacheOffloadAvailable),
      sparse_attention_requested: Boolean(sparseAttentionRequested),
      accelerator_required: false,
      production_path_changed: false,
    },
    guarded_math: {
      cache_offload_execution: false,
      cross_layer_index_reuse_execution: false,
      flash_attention_vector_precompute: false,
      sparsity_aware_hardware_scheduler: false,
      snapstream_dataflow_kernel: false,
      provider_kernel_assumption: false,
    },
  };
}

export function buildWave3RuntimeReliabilityDiagnostics({
  prompt = '',
  provider = '',
  model = '',
  stream = {},
  pulse = {},
  cache = {},
  acceleration = {},
} = {}) {
  const streamDiagnostics = buildFsmStreamStateDiagnostics(stream);
  const healthPulse = buildRuntimeReliabilityPulse({
    ...pulse,
    streamState: pulse.streamState || streamDiagnostics.stream_state,
  });
  const planCache = buildEphemeralPlanCacheDiagnostics({
    prompt,
    ...cache,
  });
  const runtimeAcceleration = buildRuntimeAccelerationDiagnostics({
    provider,
    model,
    ...acceleration,
  });

  return {
    status: 'wired',
    diagnostic_only: true,
    source_papers: [
      AGENTICCACHE_SOURCE,
      FSM_STREAMING_SOURCE,
      AGENTPULSE_SOURCE,
      THERMAL_COMFORT_SOURCE,
      COOPERATIVE_DRIVING_SOURCE,
      SNAPSTREAM_SOURCE,
      ESS_SOURCE,
      INDEXCACHE_SOURCE,
      DEEPSEEK_V32_SOURCE,
      VFA_SOURCE,
      SALCA_SOURCE,
    ],
    stream_state: streamDiagnostics,
    agent_pulse: healthPulse,
    ephemeral_plan_cache: planCache,
    runtime_acceleration: runtimeAcceleration,
    safety_contract: {
      raw_tool_protocol_user_visible: false,
      failed_path_returns_typed_state: true,
      automatic_model_switching_enabled: false,
      canonical_memory_mutated: false,
      canonical_memory_deleted: false,
    },
  };
}

export function buildWave4ServingCompressionDiagnostics({
  prompt = '',
  evidencePack = {},
  contextPressure = null,
  precisionLevel = 'claim_evidence',
  requestedKvCompression = false,
  requestedSparseAttention = false,
} = {}) {
  const promptTokens = estimateTokensFromChars(prompt);
  const cards = Array.isArray(evidencePack?.cards) ? evidencePack.cards : [];
  const openHandleCount = cards.filter((card) => card?.open_memory_handle).length;
  const pressureRatio = contextPressure == null
    ? clamp01(promptTokens / 128000)
    : clamp01(contextPressure);

  return {
    status: 'diagnostic',
    source_papers: [
      HOLD_THOUGHT_SOURCE,
      DONT_WASTE_BITS_SOURCE,
      ELITEKV_SOURCE,
      STOCHASTIC_KV_SOURCE,
      HIERASPARSE_SOURCE,
      AGSC_SOURCE,
      TOKENSCALE_SOURCE,
    ],
    diagnostic_only: true,
    serving_context_pressure: {
      prompt_tokens_estimate: promptTokens,
      context_pressure: Number(pressureRatio.toFixed(6)),
      precision_level: String(precisionLevel || 'claim_evidence'),
      evidence_card_count: cards.length,
      open_memory_handle_count: openHandleCount,
      omitted_raw_memory_count: Number(evidencePack?.omitted_raw_memory_count || 0),
    },
    evidence_io_contract: {
      claim_evidence_cards_supported: true,
      raw_open_handles_supported: true,
      inspectable_evidence_required: true,
      raw_tool_protocol_user_visible: false,
      canonical_memory_compressed: false,
      raw_memory_deleted: false,
    },
    runtime_execution: {
      kv_compression_requested: Boolean(requestedKvCompression),
      sparse_attention_requested: Boolean(requestedSparseAttention),
      kv_compression_executed: false,
      sparse_attention_kernel_enabled: false,
      production_routing_changed: false,
    },
    guarded_math: {
      kv_cache_quantization_enabled: false,
      rope_frequency_selection_enabled: false,
      stochastic_kv_routing_enabled: false,
      hierarchical_sparse_attention_enabled: false,
      agsc_uncertainty_formula_changed: false,
    },
  };
}

export function classifyServingQosTier({
  taskType = 'chat',
  intent = '',
  stream = false,
  background = false,
} = {}) {
  const normalized = `${taskType || ''} ${intent || ''}`.toLowerCase();
  if (background || /\b(dream|nightly|ingest|bootstrap|reflection|maintenance|heartbeat)\b/.test(normalized)) {
    return QOS_TIERS.background;
  }
  if (stream || /\b(chat|recall|status|inspect|question|ask)\b/.test(normalized)) {
    return QOS_TIERS.interactive;
  }
  return QOS_TIERS.batch;
}

export function buildNiyamaQosContract({
  prompt = '',
  taskType = 'chat',
  intent = '',
  stream = false,
  background = false,
  requestImportance = 'standard',
  queueDepth = 0,
  nowMs = Date.now(),
  modelAllocationDiagnostics = null,
} = {}) {
  const tier = classifyServingQosTier({ taskType, intent, stream, background });
  const promptTokens = estimateTokensFromChars(prompt);
  const queueDepthValue = Math.max(0, Number(queueDepth || 0));
  const arrivalMs = Number(nowMs || Date.now());
  const prefillRemainingMs = Math.ceil(promptTokens * 1.6);
  const decodeRemainingMs = Math.ceil(Math.max(64, promptTokens * 0.55) * 18);
  const alpha = tier.tier === 'interactive' ? 0.35 : tier.tier === 'batch' ? 0.65 : 1.0;
  const firstTokenDeadlineMs = tier.ttft_slo_ms == null ? null : arrivalMs + tier.ttft_slo_ms;
  const totalDeadlineMs = arrivalMs + tier.ttlt_slo_ms;
  const priorityDeadline = firstTokenDeadlineMs || totalDeadlineMs;
  const priorityValue = priorityDeadline + alpha * (
    tier.tier === 'interactive'
      ? prefillRemainingMs
      : prefillRemainingMs + decodeRemainingMs
  );
  const overloadRatio = tier.queue_soft_limit > 0
    ? queueDepthValue / tier.queue_soft_limit
    : 0;
  const isLowImportance = ['free', 'low', 'background'].includes(String(requestImportance || '').toLowerCase());
  const shouldRelegate = tier.tier === 'background'
    || (overloadRatio > 1 && isLowImportance);

  return {
    status: 'wired',
    source_paper: NIYAMA_SOURCE,
    qos_tier: tier.tier,
    native_server_only: true,
    prompt_tokens_estimate: promptTokens,
    queue_depth: queueDepthValue,
    deadlines: {
      arrival_ms: arrivalMs,
      ttft_slo_ms: tier.ttft_slo_ms,
      tbt_slo_ms: tier.tbt_slo_ms,
      ttlt_slo_ms: tier.ttlt_slo_ms,
      first_token_deadline_ms: firstTokenDeadlineMs,
      total_deadline_ms: totalDeadlineMs,
      formulas: {
        first_token: 'D_first = t_arrival + SLO_TTFT',
        nth_token: 'D_n = t_arrival + SLO_TTFT + (n - 1) * SLO_TBT',
        total: 'D_total = t_arrival + SLO_TTLT',
      },
    },
    hybrid_priority: {
      alpha,
      priority_value: Number(priorityValue.toFixed(3)),
      lower_is_higher_priority: true,
      formula: tier.tier === 'interactive'
        ? 'P_i = t_arrival_i + SLO_TTFT_i + alpha * Prefill_remaining_i'
        : 'P_i = t_arrival_i + SLO_TTLT_i + alpha * (Prefill_remaining_i + Decode_remaining_i)',
      estimated_prefill_remaining_ms: prefillRemainingMs,
      estimated_decode_remaining_ms: decodeRemainingMs,
    },
    relegation: {
      policy: 'eager_relegation_diagnostic',
      should_relegate: shouldRelegate,
      reason: shouldRelegate
        ? 'background_or_low_importance_under_overload'
        : 'within_qos_contract',
      queue_soft_limit: tier.queue_soft_limit,
      overload_ratio: Number(clampNumber(overloadRatio, 0, 10, 0).toFixed(3)),
      permanent_rejection: false,
    },
    guarded_math: {
      gpu_dynamic_chunk_scheduler: false,
      prefill_decode_coscheduling: false,
      learned_overload_relegation: false,
      request_rejection: false,
    },
    diagnostics: {
      source_papers: [FAST_HETEROGENEOUS_SERVING_SOURCE, STREAM_SOURCE, SOULX_DUPLUG_SOURCE],
      model_allocation_diagnostics: modelAllocationDiagnostics || null,
      sparse_context_ready: true,
      streaming_state_diagnostic_only: true,
      speech_bridge_active: false,
      routing_changed: false,
      guarded_math: {
        mixed_scale_allocator_enabled: false,
        sparse_attention_mask_enabled: false,
        streaming_state_predictor_enabled: false,
        automatic_model_switching_enabled: false,
      },
    },
  };
}

export function buildNiyamaServingStatus(sample = {}) {
  return {
    success: true,
    status: 'wired',
    source_paper: NIYAMA_SOURCE,
    contract: buildNiyamaQosContract({
      prompt: sample.prompt || 'Recall the last safe session and stream the answer.',
      taskType: sample.taskType || 'recall',
      intent: sample.intent || 'chat',
      stream: sample.stream ?? true,
      requestImportance: sample.requestImportance || 'standard',
      queueDepth: sample.queueDepth || 0,
    }),
  };
}

function normalizePrefetchKey(value = '') {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 96);
}

export function rankTimestampAwareCacheEntries(entries = [], { nowMs = Date.now(), limit = 8 } = {}) {
  const rows = (Array.isArray(entries) ? entries : [])
    .map((entry) => {
      const expected = Number(entry?.expected_access_at_ms ?? entry?.event_time_ms ?? 0);
      const last = Number(entry?.last_accessed_at_ms ?? 0);
      const timestamp = Math.max(expected, last, 0);
      const freshnessMs = Math.max(0, Number(nowMs || Date.now()) - timestamp);
      return {
        key: normalizePrefetchKey(entry?.key || entry?.state_key || ''),
        entry_type: entry?.entry_type || (expected > last ? 'prefetched' : 'accessed'),
        timestamp_order_ms: timestamp,
        freshness_ms: freshnessMs,
        priority: Number((1 / (1 + freshnessMs / 1000)).toFixed(6)),
      };
    })
    .filter((entry) => entry.key);

  return rows
    .sort((a, b) => b.timestamp_order_ms - a.timestamp_order_ms || b.priority - a.priority)
    .slice(0, Math.max(1, Number(limit || 8)));
}

export function buildKeyedPrefetchPlan({
  prompt = '',
  prefetchQueries = [],
  sessionKey = 'session',
  hotKeys = [],
  cacheEntries = [],
  nowMs = Date.now(),
  maxHints = 5,
} = {}) {
  const hot = new Set((Array.isArray(hotKeys) ? hotKeys : []).map(normalizePrefetchKey).filter(Boolean));
  const candidates = [
    ...((Array.isArray(prefetchQueries) ? prefetchQueries : []).map((value) => ({ value, source: 'lookahead_query' }))),
    { value: prompt, source: 'current_prompt' },
  ];
  const hints = [];
  for (const candidate of candidates) {
    const key = normalizePrefetchKey(candidate.value);
    if (!key || hot.has(key)) continue;
    if (hints.some((hint) => hint.key === key)) continue;
    hints.push({
      key,
      t: Number(nowMs || Date.now()) + (hints.length + 1) * 250,
      source: candidate.source,
      omitted_as_hot_key: false,
    });
    if (hints.length >= Math.max(1, Number(maxHints || 5))) break;
  }

  const rankedCache = rankTimestampAwareCacheEntries([
    ...cacheEntries,
    ...hints.map((hint) => ({
      key: hint.key,
      expected_access_at_ms: hint.t,
      entry_type: 'prefetched',
    })),
  ], { nowMs, limit: Math.max(1, Number(maxHints || 5)) });

  return {
    status: hints.length ? 'ready' : 'idle',
    source_paper: KEYED_PREFETCH_SOURCE,
    session_key: String(sessionKey || 'session'),
    mechanism: 'keyed_prefetching_with_timestamp_aware_cache',
    prefetch_hints: hints.map((hint) => ({
      h_t: { k: hint.key, t: hint.t },
      source: hint.source,
    })),
    cache_policy: {
      name: 'timestamp_aware_cache',
      single_ordering_signal: 'max(expected_access_at_ms, last_accessed_at_ms)',
      retained_entries: rankedCache,
    },
    data_path: {
      state_io_decoupled_from_data_path: true,
      writes_on_critical_path: false,
      aimos_memory_mutated: false,
      cache_scope: 'ephemeral_session',
    },
    guarded_math: {
      count_min_sketch_hot_key_filter: false,
      adaptive_lookahead_switching: false,
      zero_prefetch_miss_threshold_enforced: false,
      persistent_prefetch_index: false,
    },
  };
}

export function buildKeyedPrefetchStatus(sample = {}) {
  return {
    success: true,
    status: 'wired',
    source_paper: KEYED_PREFETCH_SOURCE,
    contract: buildKeyedPrefetchPlan({
      prompt: sample.prompt || 'What changed in Aimos after the Wave 4 serving pass?',
      prefetchQueries: sample.prefetchQueries || [
        'Wave 4 serving status',
        'Aimos stream cadence diagnostics',
      ],
      sessionKey: sample.sessionKey || 'status:wave4',
      hotKeys: sample.hotKeys || ['aimos'],
      nowMs: sample.nowMs || Date.now(),
    }),
  };
}

export function computeTokenVelocityPressure({
  inputTokensPerSecond = 0,
  predictedOutputTokensPerSecond = 0,
  prefillVelocity = 1200,
  networkVelocity = 8000,
  decodeVelocity = 180,
} = {}) {
  const inRate = Math.max(0, Number(inputTokensPerSecond || 0));
  const outRate = Math.max(0, Number(predictedOutputTokensPerSecond || 0));
  const vp = Math.max(1, Number(prefillVelocity || 1200));
  const vn = Math.max(1, Number(networkVelocity || 8000));
  const vd = Math.max(1, Number(decodeVelocity || 180));
  const ratios = {
    prefill: inRate / vp,
    network: (inRate + outRate) / vn,
    decode: outRate / vd,
  };
  const bottleneckStage = Object.entries(ratios)
    .sort((a, b) => b[1] - a[1])[0]?.[0] || 'prefill';

  return {
    source_paper: TOKENSCALE_SOURCE,
    formula: 'required_instances_stage = ceil(token_arrival_rate_stage / token_velocity_stage)',
    token_rates_per_second: {
      input: Number(inRate.toFixed(3)),
      predicted_output: Number(outRate.toFixed(3)),
    },
    velocities_tokens_per_second: {
      prefill: vp,
      network: vn,
      decode: vd,
    },
    pressure_ratios: Object.fromEntries(
      Object.entries(ratios).map(([key, value]) => [key, Number(value.toFixed(6))])
    ),
    required_instances: {
      prefill: Math.max(1, Math.ceil(ratios.prefill)),
      network: Math.max(1, Math.ceil(ratios.network)),
      decode: Math.max(1, Math.ceil(ratios.decode)),
    },
    bottleneck_stage: bottleneckStage,
    backpressure_state: ratios[bottleneckStage] > 1 ? 'pressure' : 'stable',
    guarded_math: {
      autoscaler_execution: false,
      convertible_decoder_routing: false,
      gpu_instance_scaling: false,
      kv_cache_transfer_scheduler: false,
    },
  };
}

export function buildTokenScaleRuntimeSignal({
  promptChars = 0,
  responseChars = 0,
  latencyMs = 1,
  predictedOutputTokens = null,
  stream = false,
} = {}) {
  const promptTokens = estimateTokensFromChars('x'.repeat(Math.max(0, Number(promptChars || 0))));
  const responseTokens = estimateTokensFromChars('x'.repeat(Math.max(0, Number(responseChars || 0))));
  const elapsedSeconds = Math.max(0.001, Number(latencyMs || 1) / 1000);
  const predictedTokens = Math.max(1, Number(predictedOutputTokens || responseTokens || 1));
  const pressure = computeTokenVelocityPressure({
    inputTokensPerSecond: promptTokens / elapsedSeconds,
    predictedOutputTokensPerSecond: predictedTokens / elapsedSeconds,
  });
  const tpotMs = responseTokens > 0 ? Number((Number(latencyMs || 0) / responseTokens).toFixed(3)) : null;
  const targetTpotMs = stream ? 120 : 350;

  return {
    status: 'wired',
    source_paper: TOKENSCALE_SOURCE,
    prompt_tokens_estimate: promptTokens,
    response_tokens_estimate: responseTokens,
    predicted_output_tokens: predictedTokens,
    latency_ms: Number(latencyMs || 0),
    token_velocity: pressure,
    cadence: {
      stream,
      tpot_ms: tpotMs,
      target_tpot_ms: targetTpotMs,
      degraded: tpotMs != null ? tpotMs > targetTpotMs : false,
      adaptive_buffering: true,
    },
  };
}

export function selectTokenScaleChunkSize({
  qosTier = 'interactive',
  predictedOutputTokens = 256,
  degraded = false,
} = {}) {
  const tier = String(qosTier || 'interactive').toLowerCase();
  const predicted = Math.max(1, Number(predictedOutputTokens || 256));
  if (degraded) return 48;
  if (tier === 'interactive') return predicted > 512 ? 36 : 28;
  if (tier === 'batch') return 64;
  return 96;
}

export function buildTokenScaleStatus(sample = {}) {
  return {
    success: true,
    status: 'wired',
    source_paper: TOKENSCALE_SOURCE,
    contract: buildTokenScaleRuntimeSignal({
      promptChars: sample.promptChars || 2400,
      responseChars: sample.responseChars || 1800,
      latencyMs: sample.latencyMs || 4200,
      predictedOutputTokens: sample.predictedOutputTokens || 500,
      stream: sample.stream ?? true,
    }),
  };
}

function median(values = []) {
  const nums = values.map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (!nums.length) return null;
  const mid = Math.floor(nums.length / 2);
  return nums.length % 2 ? nums[mid] : (nums[mid - 1] + nums[mid]) / 2;
}

export function buildRobustLengthPrediction({
  prompt = '',
  taskType = 'chat',
  repeatedLengthSamples = [],
  fallbackBudgetTokens = null,
} = {}) {
  const promptTokens = estimateTokensFromChars(prompt);
  const task = String(taskType || 'chat').toLowerCase();
  const multiplier = /\b(research|analysis|investigation|architecture|coding|code)\b/.test(task)
    ? 1.8
    : /\b(recall|status|inspect)\b/.test(task)
      ? 0.75
      : 1.1;
  const heuristic = Math.max(64, Math.ceil(promptTokens * multiplier));
  const sampleMedian = median(repeatedLengthSamples);
  const prediction = Math.max(1, Math.ceil(sampleMedian ?? Number(fallbackBudgetTokens || heuristic)));
  const sampleValues = repeatedLengthSamples.map(Number).filter(Number.isFinite);
  const deviations = sampleMedian == null
    ? []
    : sampleValues.map((value) => Math.abs(value - sampleMedian));
  const noiseRadius = deviations.length ? median(deviations) : null;
  const maxValue = sampleValues.length ? Math.max(...sampleValues) : null;
  const maxToMedian = sampleMedian && maxValue ? maxValue / sampleMedian : null;

  return {
    status: 'wired',
    source_paper: ROBUST_LENGTH_SOURCE,
    prediction_tokens: prediction,
    target_functional: 'conditional_median_under_mae',
    formulas: {
      conditional_mae: 'R_pt(a | phi(x)) = E[|L_i - a| | phi(x_i)]',
      bayes_target: 'argmin_a R_pt(a | phi(x_i)) is a conditional median',
      prod_m_label: 'L_bar_i = median(L_i,1 ... L_i,r)',
    },
    evidence: {
      prompt_tokens: promptTokens,
      repeated_sample_count: sampleValues.length,
      sample_median: sampleMedian,
      median_absolute_deviation_tokens: noiseRadius,
      max_to_median_ratio: maxToMedian == null ? null : Number(maxToMedian.toFixed(3)),
      heuristic_used: sampleMedian == null,
    },
    heavy_tail_guard: {
      state: maxToMedian != null && maxToMedian >= 2 ? 'heavy_tail_observed' : 'not_established',
      scheduling_note: 'use median-like budget; do not trust a single sampled length as ground truth',
    },
    guarded_math: {
      prod_m_training: false,
      prod_d_distributional_training: false,
      hidden_state_probe_training: false,
      repeated_generation_collection: false,
    },
  };
}

export function buildRobustLengthStatus(sample = {}) {
  return {
    success: true,
    status: 'wired',
    source_paper: ROBUST_LENGTH_SOURCE,
    contract: buildRobustLengthPrediction({
      prompt: sample.prompt || 'Analyze the serving stream and explain the implementation plan.',
      taskType: sample.taskType || 'analysis',
      repeatedLengthSamples: sample.repeatedLengthSamples || [380, 410, 430, 920, 390],
    }),
  };
}

function splitTextUnits(text = '') {
  return String(text || '')
    .split(/(?<=[.!?])\s+|\n+/)
    .map((unit) => unit.replace(/\s+/g, ' ').trim())
    .filter((unit) => unit.length > 0);
}

function classifyAgscTheme(unit = '') {
  const text = String(unit || '').toLowerCase();
  if (/\b(evidence|source|confidence|inspection|metadata|retrieved|recall)\b/.test(text)) return 'evidence';
  if (/\b(decision|why|because|therefore|tradeoff|chosen|reason)\b/.test(text)) return 'reasoning';
  if (/\b(risk|guard|caveat|stale|sparse|uncertain|insufficient)\b/.test(text)) return 'risk';
  if (/\b(implemented|wired|patched|test|endpoint|service|route)\b/.test(text)) return 'implementation';
  return 'summary';
}

export function buildAgscOutputContract({
  text = '',
  taskType = 'chat',
  maxPrimaryUnits = 8,
} = {}) {
  const units = splitTextUnits(text);
  const themeCounts = new Map();
  const annotatedUnits = units.slice(0, Math.max(1, Number(maxPrimaryUnits || 8))).map((unit, index) => {
    const theme = classifyAgscTheme(unit);
    themeCounts.set(theme, (themeCounts.get(theme) || 0) + 1);
    const shouldDecompose = unit.length > 260 || /\b(and|because|therefore|while|however)\b/i.test(unit);
    return {
      unit_id: `unit_${index + 1}`,
      theme,
      granularity: shouldDecompose ? 'candidate_atomic_fact_split' : 'sentence',
      excerpt: unit.slice(0, 220),
      inspectable: true,
    };
  });
  const total = annotatedUnits.length || 1;
  const clusterWeights = Array.from(themeCounts.entries())
    .map(([theme, count]) => ({
      theme,
      weight: Number((count / total).toFixed(6)),
      count,
    }))
    .sort((a, b) => b.weight - a.weight || a.theme.localeCompare(b.theme));
  const task = String(taskType || 'chat').toLowerCase();

  return {
    status: 'wired',
    source_paper: AGSC_SOURCE,
    policy: 'adaptive_granularity_diagnostic',
    output_contract: {
      task_type: task,
      preferred_shape: /\b(recall|status|inspect)\b/.test(task)
        ? 'concise_source_backed_answer'
        : /\b(dream|debrief|strategy)\b/.test(task)
          ? 'structured_narrative_with_evidence'
          : 'audited_summary_with_inspectable_evidence',
      inspectable_evidence_required: true,
      truncate_evidence: false,
      hide_minor_themes: false,
    },
    units: annotatedUnits,
    semantic_clusters: {
      method: 'theme_proxy_until_gmm_enabled',
      cluster_weights: clusterWeights,
      formula_guarded: 'U_final = sum_k w_k * U_k remains guarded until NLI/GMM stack is validated',
    },
    adaptive_granularity: {
      neutral_probability_trigger_enabled: false,
      proxy_decomposition_candidates: annotatedUnits.filter((unit) => unit.granularity === 'candidate_atomic_fact_split').length,
    },
    guarded_math: {
      nli_neutral_probability_trigger: false,
      umap_embedding_projection: false,
      gmm_soft_clustering: false,
      uncertainty_aggregation: false,
      factuality_correlation_claim: false,
    },
  };
}

export function buildAgscStatus(sample = {}) {
  return {
    success: true,
    status: 'wired',
    source_paper: AGSC_SOURCE,
    contract: buildAgscOutputContract({
      text: sample.text || 'Implemented the native serving contract. Evidence remains inspectable. Risk: GMM and NLI uncertainty math are still guarded.',
      taskType: sample.taskType || 'analysis',
    }),
  };
}

// ─── BATCH 10 LANE 4: CHUNK-LEVEL KV BUDGET + PREDICTIVE TIERING ───────────
// Papers: ChunkKV, Predictive Multi-Tier Memory
// CHUNK_SIZE_KV = 64 tokens
// kv_compressed = AttentionWeightedPool(KV[chunk_start:chunk_end])
// memory_savings = 1 - (compressed_bytes / full_kv_bytes)
// tier_predictor(hit_rate, latency_slo) → {tier: HBM|DRAM|SSD, prefetch: bool}
// All diagnostic — existing QoS tiers unchanged.
// ─────────────────────────────────────────────────────────────────────────────

const CHUNK_SIZE_KV = 64; // tokens per KV chunk

/**
 * Compute chunk-level KV budget with attention-weighted pooling.
 * kv_compressed = AttentionWeightedPool(KV[chunk_start:chunk_end])
 * memory_savings = 1 - (compressed_bytes / full_kv_bytes)
 *
 * @param {object} kvCache - KV cache object with layers containing attention weights
 * @param {number} chunkSize - Chunk size in tokens (default 64)
 * @returns {{ chunks: Array, total_chunks: number, memory_savings: number, source_paper: string, diagnostic_only: boolean }}
 */
export function computeChunkBudget(kvCache = {}, chunkSize = CHUNK_SIZE_KV) {
  const cs = Math.max(1, Number(chunkSize) || CHUNK_SIZE_KV);
  const layers = kvCache?.layers || {};
  const layerEntries = Object.entries(layers);

  if (layerEntries.length === 0) {
    return {
      chunks: [],
      total_chunks: 0,
      full_kv_bytes: 0,
      compressed_kv_bytes: 0,
      memory_savings: 0,
      chunk_size: cs,
      source_paper: 'ChunkKV',
      diagnostic_only: true,
    };
  }

  const chunks = [];
  let fullKvBytes = 0;
  let compressedKvBytes = 0;

  for (const [layerName, layerData] of layerEntries) {
    const attentionWeights = Array.isArray(layerData?.attention_weights)
      ? layerData.attention_weights
      : [];
    const tokenCount = attentionWeights.length || 0;
    const bytesPerToken = Math.max(1, Number(layerData?.bytes_per_token) || 2 * 4096);
    const layerFullBytes = tokenCount * bytesPerToken;
    fullKvBytes += layerFullBytes;

    // Divide into chunks and compute attention-weighted pool per chunk
    for (let i = 0; i < tokenCount; i += cs) {
      const end = Math.min(i + cs, tokenCount);
      const chunkWeights = attentionWeights.slice(i, end);

      // AttentionWeightedPool: average of weights in chunk
      const poolSum = chunkWeights.reduce((s, w) => s + Math.max(0, Number(w) || 0), 0);
      const poolAvg = chunkWeights.length > 0 ? poolSum / chunkWeights.length : 0;

      // Compression: retain only 128 dimensions per chunk instead of full hidden
      const chunkFullBytes = chunkWeights.length * bytesPerToken;
      const chunkCompressedBytes = Math.round(128 * 2 * 2); // 128d × fp16 × K+V
      compressedKvBytes += chunkCompressedBytes;

      chunks.push({
        layer: layerName,
        chunk_index: Math.floor(i / cs),
        token_start: i,
        token_end: end - 1,
        token_count: chunkWeights.length,
        attention_pool_avg: Number(poolAvg.toFixed(6)),
        full_bytes: chunkFullBytes,
        compressed_bytes: chunkCompressedBytes,
        compression_ratio: Number((1 - chunkCompressedBytes / Math.max(1, chunkFullBytes)).toFixed(6)),
      });
    }
  }

  const memorySavings = fullKvBytes > 0 ? 1 - compressedKvBytes / fullKvBytes : 0;

  return {
    chunks,
    total_chunks: chunks.length,
    full_kv_bytes: Math.round(fullKvBytes),
    compressed_kv_bytes: Math.round(compressedKvBytes),
    memory_savings: Number(memorySavings.toFixed(6)),
    chunk_size: cs,
    formula: 'kv_compressed = AttentionWeightedPool(KV[chunk_start:chunk_end])',
    source_paper: 'ChunkKV',
    diagnostic_only: true,
    qos_tiers_unchanged: true,
  };
}

/**
 * Predict memory tier based on hit rate and latency SLO.
 * tier_predictor(hit_rate, latency_slo) → {tier: HBM|DRAM|SSD, prefetch: bool}
 *
 * @param {number} hitRate - Cache hit rate [0, 1]
 * @param {number} latencySLO - Latency SLO in milliseconds
 * @returns {{ tier: string, prefetch: boolean, confidence: number, source_paper: string, diagnostic_only: boolean }}
 */
export function predictMemoryTier(hitRate, latencySLO) {
  const hr = clamp01(Number(hitRate) || 0);
  const slo = Math.max(0, Number(latencySLO) || 0);

  // Tier prediction heuristics:
  // HBM: high hit rate + tight SLO (< 100ms)
  // DRAM: moderate hit rate + moderate SLO (100-500ms)
  // SSD: low hit rate or loose SLO (> 500ms)
  let tier = 'DRAM';
  let prefetch = false;
  let confidence = 0.5;

  if (hr > 0.8 && slo > 0 && slo <= 100) {
    tier = 'HBM';
    prefetch = true;
    confidence = Number((0.7 + hr * 0.25).toFixed(3));
  } else if (hr > 0.5 && slo > 0 && slo <= 500) {
    tier = 'DRAM';
    prefetch = hr > 0.6;
    confidence = Number((0.5 + hr * 0.3).toFixed(3));
  } else if (hr <= 0.3 || slo > 500) {
    tier = 'SSD';
    prefetch = false;
    confidence = Number((0.3 + (1 - hr) * 0.3).toFixed(3));
  }

  return {
    tier,
    prefetch,
    confidence: Math.min(0.95, confidence),
    hit_rate: hr,
    latency_slo_ms: slo,
    formula: 'tier_predictor(hit_rate, latency_slo) → {tier, prefetch}',
    source_paper: 'Predictive Multi-Tier Memory',
    diagnostic_only: true,
    qos_tiers_unchanged: true,
    production_routing_changed: false,
  };
}

/**
 * Build ChunkKV diagnostic report.
 */
export function buildChunkKVDiagnostic(sample = {}) {
  const kvCache = sample.kvCache || {
    layers: {
      layer_0: {
        attention_weights: new Array(128).fill(0).map((_, i) =>
          Math.exp(-0.01 * i) * (0.5 + 0.5 * Math.sin(i * 0.1))
        ),
        bytes_per_token: 8192,
      },
      layer_15: {
        attention_weights: new Array(128).fill(0).map((_, i) =>
          Math.exp(-0.02 * i) * (0.3 + 0.7 * Math.cos(i * 0.05))
        ),
        bytes_per_token: 8192,
      },
    },
  };

  const chunkBudget = computeChunkBudget(kvCache, sample.chunkSize || CHUNK_SIZE_KV);
  const tierPrediction = predictMemoryTier(
    sample.hitRate ?? 0.72,
    sample.latencySLO ?? 200,
  );

  return {
    status: 'diagnostic',
    source_papers: ['ChunkKV', 'Predictive Multi-Tier Memory'],
    diagnostic_only: true,
    chunk_budget: chunkBudget,
    tier_prediction: tierPrediction,
    guardrails: {
      qos_tiers_unchanged: true,
      production_routing_changed: false,
      canonical_memory_unchanged: true,
    },
  };
}

// ─── G1: CACHE DEMOTION (Aladdin adaptation of memory eviction) ────────────────
// Original: evict(key) → DELETE FROM cache WHERE key = LRU_key
// Aladdin adaptation: demote(key) → UPDATE cache SET tier = 'cold', priority *= 0.5
// Memory remains accessible at higher retrieval cost. Full retention, frequency-modulated recall.
// Scale adaptation: demotion_threshold = max(0.01, min(0.1, 0.05 * (14000/N)^0.5))
// At 14K: threshold=0.05. At 100K: threshold≈0.019.

export function computeDemotionThreshold(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(0.01, Math.min(0.1, 0.05 * Math.pow(14000 / N, 0.5)));
}

export function demoteCacheEntry(entry, demotionFactor = 0.5) {
  // Aladdin-compliant demotion: reduce priority, move to cold tier, NEVER delete
  return {
    ...entry,
    tier: 'cold',
    access_priority: Math.max(0.001, (entry.access_priority || 1) * demotionFactor),
    demoted_at: new Date().toISOString(),
    aladdin_compliant: true, // Never deleted, only frequency-modulated
  };
}

export function buildCacheDemotionDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: ['Cache demotion (Aladdin adaptation of memory eviction)'],
    demotion_threshold: computeDemotionThreshold(N),
    demotion_formula: 'threshold = max(0.01, min(0.1, 0.05 * (14000/N)^0.5))',
    aladdin_law: {
      original_operation: 'DELETE FROM cache WHERE key = LRU_key',
      adapted_operation: "UPDATE cache SET tier = 'cold', access_priority *= 0.5",
      retention_guaranteed: true,
      content_never_deleted: true,
      frequency_modulated_recall: true,
    },
    diagnostic_only: true,
    guarded_math: {
      canonical_memory_eviction: false, // Original eviction: disabled
      cache_demotion: true, // Aladdin-adapted: enabled
    },
  };
}
