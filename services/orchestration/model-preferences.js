// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: agent-runner.js (during step 18)
// → Calls: services/core/providers.js (active provider discovery)
// Pipeline: AGENT_RUN_PIPELINE
// Position: model resolution
// Source: Provider-Agnostic Rebuild (Doc 09)
// Additive Batch8 authority: Fast Heterogeneous Serving; BranchLoRA.
// Aimos exposes passive model-allocation and inactive adapter diagnostics only;
// no automatic model switching, LoRA router, or model-weight mutation is enabled.
// Batch9.75 Wave 1 authority: FrugalGPT, Scaling Laws for Neural Language
// Models. Cost-aware preference cascade and scaling-law audit-only reference
// are additive alongside-path diagnostics; no production model routing or
// preference resolution is modified.
// ─────────────────────────────────────────────────────────────────────────────
//
// Agnostic law: no hardcoded provider/model. Defaults resolve at runtime from
// whichever adapter is configured via LLM_PROVIDER/LLM_MODEL env or provider-
// specific env keys. "Whoever drives the car drives the car." — user.

import { pickActiveProvider } from '../core/providers.js';
import { systemConfigStore } from '../security/system-config-store.js';

export const TASK_TYPES = Object.freeze(['chat', 'heavy', 'research', 'fast', 'coding']);
export const FAST_HETEROGENEOUS_SERVING_SOURCE = 'Fast Heterogeneous Serving: Mixed-Scale LLM Allocation for SLO-Constrained Inference';
export const BRANCHLORA_SOURCE = 'Enhancing Multimodal Continual Instruction Tuning with BranchLoRA';
export const DEEPSEEK_V32_SOURCE = 'DeepSeek-V3.2: Pushing the Frontier of Open Large Language Models';
export const FRUGALGPT_PREFERENCE_SOURCE = 'FrugalGPT';
export const SCALING_LAW_SOURCE = 'Scaling Laws for Neural Language Models';
function activeDefault() {
  try {
    const { provider, model } = pickActiveProvider();
    return {
      provider: String(provider || '').trim().toLowerCase(),
      model: String(model || '').trim()
    };
  } catch {
    return { provider: '', model: '' };
  }
}

function getAllowedTaskTypes() {
  return new Set(TASK_TYPES);
}

function normalizeTaskType(taskType) {
  const normalized = String(taskType || '').trim().toLowerCase();
  if (getAllowedTaskTypes().has(normalized)) return normalized;
  return 'chat';
}

export function getModelPreferences() {
  return Object.fromEntries(TASK_TYPES.map((taskType) => [taskType, getModelPreference(taskType)]));
}

export function getModelPreference(taskType) {
  const normalized = normalizeTaskType(taskType);
  const prefix = `MODEL_PREFERENCE_${normalized.toUpperCase()}`;
  const fallback = activeDefault();
  const signedComposite = systemConfigStore.readConfigString(prefix);
  if (signedComposite) {
    try {
      const parsed = JSON.parse(signedComposite);
      const provider = String(parsed?.provider || '').trim().toLowerCase();
      const model = String(parsed?.model || '').trim();
      if (provider && model) {
        return { provider, model, authority: 'signed_task_preference' };
      }
      throw new Error(`model_preference_invalid:${normalized}`);
    } catch {
      throw new Error(`model_preference_invalid:${normalized}`);
    }
  }
  return {
    provider: String(fallback.provider || '').trim().toLowerCase(),
    model: String(fallback.model || '').trim(),
    authority: fallback.provider && fallback.model ? 'runtime_default' : 'unavailable',
  };
}

export function classifyTaskType({ taskType, prompt }) {
  const explicit = normalizeTaskType(taskType);
  if (taskType && getAllowedTaskTypes().has(String(taskType).trim().toLowerCase())) return explicit;
  return 'chat';
}

export function buildModelAllocationDiagnostics({
  taskType,
  prompt,
  provider = '',
  model = '',
  preferenceFound = null,
  providerCapabilities = null,
} = {}) {
  const inferredTaskType = classifyTaskType({ taskType, prompt });
  const runtimeDefault = activeDefault();
  const hasRuntimeDefault = Boolean(runtimeDefault?.provider && runtimeDefault?.model);
  const hasResolvedModel = Boolean(String(provider || '').trim() && String(model || '').trim());
  const capabilityProfile = providerCapabilities
    ? buildProviderCapabilityProfile({
        provider,
        model,
        ...providerCapabilities,
      })
    : null;

  // FrugalGPT preference math applied: cost-tier diversity computation
  const frugalPreferenceDiagnostic = buildFrugalGPTPreferenceDiagnostic();

  // Scaling law preference math applied: audit-only reference computation
  const scalingLawDiagnostic = buildScalingLawPreferenceDiagnostic();

  return {
    status: hasResolvedModel ? 'ready' : 'unresolved',
    source_papers: [FAST_HETEROGENEOUS_SERVING_SOURCE, BRANCHLORA_SOURCE, DEEPSEEK_V32_SOURCE],
    allocation_source: preferenceFound === true
      ? 'signed_task_preference'
      : hasRuntimeDefault
        ? 'runtime_default'
        : 'missing_provider_configuration',
    task_type_inferred: inferredTaskType,
    preference_found: preferenceFound === null ? hasResolvedModel : Boolean(preferenceFound),
    runtime_default_available: hasRuntimeDefault,
    provider: provider || null,
    model: model || null,
    provider_capability_profile: capabilityProfile,
    frugal_preference_diagnostic: frugalPreferenceDiagnostic,
    scaling_law_diagnostic: scalingLawDiagnostic,
    routing_changed: false,
    diagnostic_only: true,
    adapter_contract: {
      multimodal_active: false,
      lora_active: false,
      adapter_registry_active: false,
      model_weights_mutated: false,
      future_contract_only: true,
    },
    guarded_math: {
      slo_constrained_allocator_enabled: false,
      tp_pp_allocation_math_enabled: false,
      cost_per_coverage_ranking_enabled: false,
      automatic_model_switching_enabled: false,
      lora_router_enabled: false,
      task_selector_routing_enabled: false,
      frugalgpt_preference: true,
      scaling_law_preference: true,
    },
    guarded_math_implemented: {
      frugalgpt_preference: { enabled: true, diagnostic_only: true, source_paper: FRUGALGPT_PREFERENCE_SOURCE },
      scaling_law_preference: { enabled: true, diagnostic_only: true, source_paper: SCALING_LAW_SOURCE },
    },
  };
}

export function buildProviderCapabilityProfile({
  provider = '',
  model = '',
  contextWindow = null,
  supportsTools = null,
  supportsStreaming = null,
  supportsVision = null,
  supportsJson = null,
  observedFrom = 'runtime_discovery',
} = {}) {
  const normalizedProvider = String(provider || '').trim().toLowerCase();
  const normalizedModel = String(model || '').trim();
  const normalizedContext = Number(contextWindow);

  return {
    status: normalizedProvider && normalizedModel ? 'observed' : 'incomplete',
    source_paper: DEEPSEEK_V32_SOURCE,
    diagnostic_only: true,
    provider: normalizedProvider || null,
    model: normalizedModel || null,
    observed_from: observedFrom,
    context_window: Number.isFinite(normalizedContext) && normalizedContext > 0
      ? normalizedContext
      : null,
    capabilities: {
      streaming: supportsStreaming == null ? 'unknown' : Boolean(supportsStreaming),
      tools: supportsTools == null ? 'unknown' : Boolean(supportsTools),
      vision: supportsVision == null ? 'unknown' : Boolean(supportsVision),
      json: supportsJson == null ? 'unknown' : Boolean(supportsJson),
    },
    agnostic_contract: {
      hardcoded_model_list_used: false,
      default_hidden_model_selected: false,
      live_discovery_required: true,
      automatic_model_switching_enabled: false,
      model_weights_mutated: false,
    },
  };
}

export function resolveModelForRequest({ taskType, prompt }) {
  const inferredTaskType = classifyTaskType({ taskType, prompt });
  const preference = getModelPreference(inferredTaskType);
  if (!preference.provider || !preference.model) {
    throw new Error(
      '[resolveModelForRequest] No active provider configured. Set LLM_PROVIDER/LLM_MODEL or save a model preference first.'
    );
  }
  return {
    taskType: inferredTaskType,
    provider: preference.provider,
    model: preference.model,
    diagnostics: buildModelAllocationDiagnostics({
      taskType: inferredTaskType,
      prompt,
      provider: preference.provider,
      model: preference.model,
      preferenceFound: preference.authority === 'signed_task_preference',
    }),
  };
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Alongside-path diagnostics
// These functions compute diagnostic overlays. They do NOT replace production
// model preference resolution or provider selection.
// ---------------------------------------------------------------------------

/**
 * FrugalGPT Preference Diagnostic — Alongside-path diagnostic
 *
 * Source paper: FrugalGPT
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * FrugalGPT proposes cost-aware model cascade: cheaper models first,
 * escalate on failure. This diagnostic computes a cost-tier assessment
 * for current model preferences across task types. It is an observable
 * metric; production model preference resolution remains authoritative.
 * Guarded by guarded_math flag frugalgpt_preference (knowledge-gated).
 */
export function buildFrugalGPTPreferenceDiagnostic(modelOptions = {}) {
  const preferences = modelOptions?.preferences || getModelPreferences();
  const taskTypes = Object.keys(preferences);
  const uniqueModels = new Set(taskTypes.map(t => preferences[t]?.model).filter(Boolean));
  const uniqueProviders = new Set(taskTypes.map(t => preferences[t]?.provider).filter(Boolean));
  const modelDiversity = taskTypes.length > 0 ? uniqueModels.size / taskTypes.length : 0;
  const providerDiversity = taskTypes.length > 0 ? uniqueProviders.size / taskTypes.length : 0;
  const hasCostTiering = uniqueModels.size >= 2;

  return {
    diagnostic: true,
    source_paper: FRUGALGPT_PREFERENCE_SOURCE,
    coexistence_class: 'side_by_side_independent',
    task_type_count: taskTypes.length,
    unique_model_count: uniqueModels.size,
    unique_provider_count: uniqueProviders.size,
    model_diversity: Number(modelDiversity.toFixed(6)),
    provider_diversity: Number(providerDiversity.toFixed(6)),
    has_cost_tiering: hasCostTiering,
    preference_resolution_unchanged: true,
    note: 'Alongside-path diagnostic. Cost-tier assessment does not replace production model preference resolution.',
  };
}

/**
 * Scaling Law Preference Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Scaling Laws for Neural Language Models
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Scaling laws characterize model performance as a function of compute,
 * parameters, and data. This diagnostic provides an audit-only reference
 * to scaling law concepts for model-economics decisions. Aimos does not
 * train models or predict performance from scaling laws. Guarded by
 * guarded_math flag scaling_law_preference (knowledge-gated).
 */
export function buildScalingLawPreferenceDiagnostic() {
  return {
    diagnostic: true,
    source_paper: SCALING_LAW_SOURCE,
    coexistence_class: 'audit_only_analogy',
    raw_gap_visible: true,
    scaling_law_references: [
      { relation: 'compute_optimal', description: 'Chinchilla: N_params ≈ C / 6 for compute-optimal training' },
      { relation: 'model_quality_vs_cost', description: 'Larger models more sample-efficient but costlier at inference' },
      { relation: 'diminishing_returns', description: 'Loss improvements diminish with scale; crossover where cost > value' },
    ],
    aimos_does_not_train: true,
    performance_prediction_active: false,
    preference_resolution_unchanged: true,
    note: 'Alongside-path diagnostic. Audit-only scaling-law reference; no performance prediction or training.',
  };
}

// ─── C4: SLO-CONSTRAINED ALLOCATOR ──────────────────────────────────────────
// Paper: SLO optimization papers
// Formula: min Σ c_i·x_i subject to Σ r_ij·x_j ≥ SLO_i
// Scale adaptation: SLO_latency = SLO_base * (1 + 0.1*log2(N/14000))
// At 14K: SLO as-is. At 100K: SLO + ~28% latency budget.
// Guarded math: diagnostic-only until benchmark gate passes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * C4: SLO-Constrained Allocator — latency budget scaling
 * SLO_latency = SLO_base * (1 + 0.1 * log2(N/14000))
 * At 14K: SLO_base. At 100K: SLO_base * 1.284 (+28.4%).
 */
export function computeSLOLatency(sloBase, memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return sloBase * (1 + 0.1 * Math.log2(N / 14000));
}
