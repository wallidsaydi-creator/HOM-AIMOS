// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Live — wired into AGENT_RUN XAI/RAD-AI decision logging
// Purpose: RAD-AI documentation system — model registry, AI-ADR decision log,
//          and AI debt register for auditable AI layer ledger (P1-B3-16)
// Called by: orchestration/agent-xai-explanation.js (post-run capture)
// Calls: write/persist-memory.js, observe/event-ledger.js
// Pipeline: AGENT_RUN
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// ARCHITECTURE REGISTRY (architecture-registry.js)
// ═══════════════════════════════════════════════════════════════════════════════
// P1-B3-16: RAD-AI Documentation
//
// Implements the RAD-AI (Records of Architecture Decisions — AI) documentation
// system. Every AI model, component boundary, decision, and technical debt item
// is registered here, providing an auditable, queryable ledger of the AI layer.
//
// Three primary registries:
//
//   1. MODEL REGISTRY — tracks live AI models with their evaluation thresholds,
//      deployment status, and framework metadata. Replaces informal model
//      catalogs with a structured, version-aware registry.
//
//   2. DECISION LOG (AI-ADR) — extends conventional Architecture Decision
//      Records with 7 AI-specific extra fields capturing uncertainty, drift
//      potential, blast radius, and governance approvals.
//
//   3. AI DEBT REGISTER — structured technical debt tracking specific to AI
//      components: data drift risk, evaluation gaps, dependency entanglement,
//      interpretability gaps, etc. Each entry carries severity, blast_radius,
//      remediation_effort, and owner.
//
// Boundary contracts are stored in aimos_memories under the key
//   'component_boundary:{componentId}' for retrieval by the execution layer.
//
// DB tables: model_registry, ai_debt_register
// Aimos memories: component_boundary:{componentId}, ai_adr:{decision_id}
//
// Theoretical basis:
//   Nygard (2011) Documenting Architecture Decisions
//   Sculley et al. (2015) Hidden Technical Debt in ML Systems
//   Klaise et al. (2022) Alibi: Algorithms for Monitoring and Explaining ML
//   TEM additive authority: Learning Hierarchical Procedural Memory for LLM
//   Agents through Bayesian Selection and Contrastive Refinement (MACLA)
//   MACLA scope: AI-ADR records are recallable as procedural reasoning
//   artifacts. Bayesian procedure scoring is not implemented here.
//   Batch 6/7 additive authority: Ontology-Aware Design Patterns for Clinical
//   AI Systems: Translating Reification Theory into Software Architecture
//   (Stummer, 2026). Aimos exposes the seven-pattern vocabulary as a live
//   architecture contract. Fidelity scoring, drift thresholds, and compliance
//   verdict math remain guarded until implemented from the paper formulas and
//   Aimos's existing service math.
//   Batch9.75 Wave 1 authority: The Bitter Lesson, Scaling Laws for Neural
//   Language Models, Qwen-Audio, The Pile. Audit-only architecture notes and
//   dataset provenance references; no production architecture changes.
//   Batch9/9.5 Wave5 additive authority: HGP-Mamba, Modality-Aware Zero-Shot
//   Pruning, One Token per Highly Selective Frame, Sink-Token-Aware Pruning,
//   and Long-Horizon Streaming Video Generation. Aimos exposes inactive
//   multimodal representation contracts only; no unsupported media capability
//   is claimed.
// ═══════════════════════════════════════════════════════════════════════════════

import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { query } from '../../db/connection.js';
import { persistMemory } from '../write/persist-memory.js';
import { logEvent } from './event-ledger.js';
import { buildInactiveAudioUnderstandingContract, QWEN_AUDIO_SOURCE } from './multimodal-contract.js';

const COMPANY = AIMOS_COMPANY_ID;

export const BITTER_LESSON_SOURCE = 'The Bitter Lesson';
export const SCALING_LAW_REGISTRY_SOURCE = 'Scaling Laws for Neural Language Models';
export const DATASET_PROVENANCE_SOURCE = 'The Pile — 800GB Dataset';

// ─── E5: SEMANTIC FINGERPRINT VECTOR ──────────────────────────────────────────
// Source: Architecture drift detection
// Formula: fingerprint(x) = hash(Σ w_i·φ_i(x) mod p)
// Scale adaptation: dim = max(64, min(512, floor(128 * (N/14000)^0.3)))
// At 14K: dim=128. At 100K: dim≈231.
// Fingerprinting is detection only. Aladdin SAFE.

export function computeFingerprintDimension(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return Math.max(64, Math.min(512, Math.floor(128 * Math.pow(N / 14000, 0.3))));
}

export function computeSemanticFingerprint(weights, features, prime = 2147483647) {
  if (!Array.isArray(weights) || !Array.isArray(features)) return 0;
  const dim = Math.min(weights.length, features.length);
  let sum = 0;
  for (let i = 0; i < dim; i++) {
    sum += Number(weights[i] || 0) * Number(features[i] || 0);
  }
  return ((sum % prime) + prime) % prime;
}

// ─── E6: JS DIVERGENCE THRESHOLDS ─────────────────────────────────────────────
// Source: Jensen-Shannon divergence for distribution drift
// Formula: JS(P||Q) = (1/2)·KL(P||M) + (1/2)·KL(Q||M), M = (P+Q)/2
// Scale adaptation: threshold = 0.1 * max(0.5, (14000/N)^0.3)
// At 14K: threshold=0.1. At 100K: threshold≈0.055 (stricter at scale).
// Divergence is detection only. Aladdin SAFE.

export function computeJSDivergenceThreshold(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return 0.1 * Math.max(0.5, Math.pow(14000 / N, 0.3));
}

export function computeJSDivergence(P, Q) {
  if (!Array.isArray(P) || !Array.isArray(Q)) return 0;
  const len = Math.min(P.length, Q.length);
  if (len === 0) return 0;
  let jsDiv = 0;
  for (let i = 0; i < len; i++) {
    const p = Number(P[i]) || 0;
    const q = Number(Q[i]) || 0;
    const m = (p + q) / 2;
    if (p > 0 && m > 0) jsDiv += 0.5 * p * Math.log2(p / m);
    if (q > 0 && m > 0) jsDiv += 0.5 * q * Math.log2(q / m);
  }
  return Math.max(0, jsDiv);
}

export function buildArchitectureDriftDiagnostics(memoryCount = 14000) {
  const N = Math.max(1, memoryCount);
  return {
    source_papers: ['Architecture drift detection', 'Jensen-Shannon divergence'],
    fingerprint: {
      dimension: computeFingerprintDimension(N),
      formula: 'fingerprint(x) = hash(Σ w_i·φ_i(x) mod p)',
    },
    js_divergence: {
      threshold: computeJSDivergenceThreshold(N),
      formula: 'JS(P||Q) = (1/2)·KL(P||M) + (1/2)·KL(Q||M), M = (P+Q)/2',
    },
    diagnostic_only: true,
    guarded_math: {
      semantic_fingerprint_vector: true,
      js_divergence_thresholds: true,
    },
  };
}

// Valid model deployment statuses
const VALID_STATUSES = ['active', 'shadow', 'deprecated', 'experimental', 'retired'];

// Valid AI debt categories (Sculley et al. taxonomy + extensions)
const VALID_DEBT_CATEGORIES = [
  'data-dependency',
  'evaluation-gap',
  'model-entanglement',
  'pipeline-glue',
  'configuration-debt',
  'drift-risk',
  'interpretability-gap',
  'boundary-erosion',
  'governance-gap',
  'undeclared-consumer',
];

// Valid severity levels
const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

const ONTOLOGY_PATTERN_SOURCE_PAPER =
  'Ontology-Aware Design Patterns for Clinical AI Systems: Translating Reification Theory into Software Architecture';
const WAVE5_MULTIMODAL_CONTRACT_AUTHORITIES = [
  'HGP-Mamba: Integrating Histology and Generated Protein Features for Mamba-based Multimodal Survival Risk Prediction',
  'Modality-Aware Zero-Shot Pruning and Sparse Attention for Efficient Multimodal Edge Inference',
  'One Token per Highly Selective Frame- Towards Extreme Compression for Long Video Understanding',
  'Sink-Token-Aware Pruning for Fine-Grained Video Understanding in Efficient Video LLMs',
  'Long-Horizon Streaming Video Generation via Hybrid Attention with Decoupled Distillation',
  QWEN_AUDIO_SOURCE,
];

const ONTOLOGY_AWARE_PATTERNS = Object.freeze([
  {
    id: 'P1',
    slug: 'ontological_checkpoint',
    name: 'Ontological Checkpoint',
    also_known_as: ['Coding Fidelity Gate', 'Ingestion Validator'],
    paper_problem: 'Data can pass syntax checks while still carrying documentary or administrative distortion.',
    aimos_contract: 'Annotate incoming memories/evidence with fidelity and verification metadata instead of treating all valid records as equal truth.',
    target_services: [
      'services/write/quality-gate.js',
      'services/write/write-validator.js',
      'services/temporal/freshness-metadata.js',
      'services/governance/knowledge-gate-enforcer.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      coding_fidelity_score: false,
      demographic_prevalence_reference_model: false,
      co_occurrence_contradiction_model: false,
    },
  },
  {
    id: 'P2',
    slug: 'dormancy_aware_pipeline',
    name: 'Dormancy-Aware Pipeline',
    also_known_as: ['Long-Tail Preserver', 'Signal Hibernation Layer'],
    paper_problem: 'Rare but important signals are often pruned as noise even when they matter for safety and continuity.',
    aimos_contract: 'Route rare or low-frequency signals to dormancy-aware retention instead of physical deletion or silent pruning.',
    target_services: [
      'services/temporal/dormancy-manager.js',
      'services/context/mnemonic-encoder.js',
      'services/learning/spaced-repetition.js',
      'services/write/persist-memory.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      activation_condition_calibration: false,
      dormant_feature_frequency_threshold: false,
    },
  },
  {
    id: 'P3',
    slug: 'drift_sentinel',
    name: 'Drift Sentinel',
    also_known_as: ['Semantic Drift Monitor', 'Ontological Shift Detector'],
    paper_problem: 'Meaning shifts over time, and statistical drift alone cannot tell whether the cause is real, administrative, or terminological.',
    aimos_contract: 'Classify architecture and retrieval drift as semantic/temporal/governance evidence before any downstream policy action.',
    target_services: [
      'services/observe/retrieval-drift-monitor.js',
      'services/observe/routing-monitor.js',
      'services/temporal/memory-t1-learning-loop.js',
      'services/observe/architecture-registry.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      semantic_fingerprint_vector: false,
      js_divergence_thresholds: false,
      drift_cause_classifier: false,
    },
  },
  {
    id: 'P4',
    slug: 'dual_ontology_layer',
    name: 'Dual-Ontology Layer',
    also_known_as: ['Clinical-Administrative Parallel Store', 'Twin Representation Layer'],
    paper_problem: 'A single representation hides divergence between operational reality and the representation used for storage or governance.',
    aimos_contract: 'Keep raw/source evidence and interpreted Aimos evidence separately visible, with divergence represented as evidence rather than erased.',
    target_services: [
      'services/core/concept-graph.js',
      'services/retrieval/magma-lineage-retriever.js',
      'services/retrieval/chronos-temporal-retriever.js',
      'services/retrieval/recall-diagnostics.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      cross_layer_divergence_score: false,
      probabilistic_layer_population: false,
    },
  },
  {
    id: 'P5',
    slug: 'reification_circuit_breaker',
    name: 'Reification Circuit Breaker',
    also_known_as: ['Feedback Loop Interrupter', 'Recursive Amplification Guard'],
    paper_problem: 'AI outputs can feed back into the next training or memory cycle and recursively amplify their own distortions.',
    aimos_contract: 'Tag AI-influenced artifacts and expose feedback-loop diagnostics before dream, learning, or architecture promotion.',
    target_services: [
      'services/observe/event-ledger.js',
      'services/observe/explainer.js',
      'services/observe/architecture-registry.js',
      'services/dream/dream-feedback.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      ai_influence_ratio_threshold: false,
      retraining_pause_policy: false,
    },
  },
  {
    id: 'P6',
    slug: 'terminology_version_gate',
    name: 'Terminology Version Gate',
    also_known_as: ['Schema Migration Guard', 'Version-Aware Data Layer'],
    paper_problem: 'Terminology/schema changes can silently alter meaning across time and corrupt cross-version reasoning.',
    aimos_contract: 'Treat architecture vocabulary, memory type, and service-map changes as versioned semantic migrations with explicit compatibility metadata.',
    target_services: [
      'services/observe/architecture-registry.js',
      'services/core/authority-paths.js',
      'services/pipeline-manifest.js',
      'services/retrieval/recall-mode-planner.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      cross_version_mapping_completeness: false,
      unmappable_code_quarantine_policy: false,
    },
  },
  {
    id: 'P7',
    slug: 'regulatory_compliance_adapter',
    name: 'Regulatory Compliance Adapter',
    also_known_as: ['Jurisdiction Plug-in', 'Compliance Wrapper'],
    paper_problem: 'Compliance logic becomes brittle when hard-coded into core pipelines instead of isolated behind auditable adapters.',
    aimos_contract: 'Expose compliance checks as auditable wrappers around architecture, retrieval, and memory decisions without replacing core service math.',
    target_services: [
      'services/governance/aladdin-compliance.js',
      'services/governance/knowledge-gate-enforcer.js',
      'services/core/constitution-enforcer.js',
      'services/security/knowledge-gate.js',
    ],
    live_status: 'partially_wired',
    guarded_math: {
      legal_verdict_engine: false,
      jurisdiction_adapter_composition: false,
    },
  },
]);

const ONTOLOGY_PATTERN_INTERACTIONS = Object.freeze([
  {
    from: 'ontological_checkpoint',
    to: 'dual_ontology_layer',
    relation: 'feeds_fidelity_annotations',
  },
  {
    from: 'ontological_checkpoint',
    to: 'drift_sentinel',
    relation: 'supplies_fidelity_distribution_for_monitoring',
  },
  {
    from: 'dormancy_aware_pipeline',
    to: 'drift_sentinel',
    relation: 'reactivation_signals_are_monitored_for_shift',
  },
  {
    from: 'drift_sentinel',
    to: 'reification_circuit_breaker',
    relation: 'type_b_or_feedback_drift_can_trigger_loop_diagnostics',
  },
  {
    from: 'terminology_version_gate',
    to: 'dual_ontology_layer',
    relation: 'versions_both_representational_layers',
  },
  {
    from: 'regulatory_compliance_adapter',
    to: 'all_patterns',
    relation: 'wraps_external_facing_data_operations',
  },
]);

// ─── Schema ──────────────────────────────────────────────────────────────────

/**
 * Verify migration-owned registry contracts without mutating schema.
 *
 * @returns {Promise<void>}
 */
let architectureRegistrySchemaVerified = false;
async function ensureArchitectureRegistrySchema() {
  if (architectureRegistrySchemaVerified) return;
  await query(
    `SELECT id, company_id, model_id, version, framework, eval_metric,
            threshold, status, metadata, registered_at, updated_at
     FROM model_registry
     WHERE false`
  );

  await query(
    `SELECT id, company_id, category, severity, blast_radius,
            remediation_effort, owner, status, description, metadata,
            created_at, updated_at
     FROM ai_debt_register
     WHERE false`
  );
  architectureRegistrySchemaVerified = true;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Generate a compact timestamp-based ID prefix.
 *
 * @param {string} prefix
 * @returns {string}
 */
function generateId(prefix) {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// ─── Ontology-Aware Architecture Pattern Map ────────────────────────────────

/**
 * Return Aimos's live mapping of Stummer's seven ontology-aware design
 * patterns onto existing services. This is an additive architecture contract:
 * it makes the pattern obligations inspectable without changing admission,
 * ranking, calibration, drift, or compliance math.
 *
 * @param {{ servicePath?: string, slug?: string }} [options]
 * @returns {{
 *   source_paper: string,
 *   status: string,
 *   patterns: Array<object>,
 *   interactions: Array<object>,
 *   guardrails: object
 * }}
 */
export function buildOntologyAwarePatternMap(options = {}) {
  const servicePath = options.servicePath ? String(options.servicePath) : '';
  const slug = options.slug ? String(options.slug) : '';
  const patterns = ONTOLOGY_AWARE_PATTERNS
    .filter((pattern) => {
      if (slug && pattern.slug !== slug) return false;
      if (servicePath && !pattern.target_services.includes(servicePath)) return false;
      return true;
    })
    .map((pattern) => ({
      ...pattern,
      source_paper: ONTOLOGY_PATTERN_SOURCE_PAPER,
      empirical_validation_claimed: false,
      formula_implemented: false,
      ranking_math_changed: false,
    }));

  return {
    source_paper: ONTOLOGY_PATTERN_SOURCE_PAPER,
    status: 'live_architecture_contract',
    scope: 'ontology-aware pattern mapping',
    patterns,
    interactions: [...ONTOLOGY_PATTERN_INTERACTIONS],
    guardrails: {
      additive_contract_only: true,
      ranking_math_changed: false,
      trust_score_math_changed: false,
      drift_threshold_math_changed: false,
      compliance_verdict_math_changed: false,
      no_physical_delete: true,
    },
  };
}

export function buildInactiveMultimodalRepresentationContracts({
  requestedModalities = ['image', 'video', 'audio'],
  backendPaths = {},
  tests = {},
} = {}) {
  const requested = Array.isArray(requestedModalities) ? requestedModalities : ['image', 'video', 'audio'];
  const modalities = [...new Set(requested.map((modality) => String(modality || '').toLowerCase()).filter(Boolean))];
  const contracts = Object.fromEntries(modalities.map((modality) => {
    const backendPathPresent = Boolean(backendPaths[modality]);
    const testsPresent = Boolean(tests[modality]);
    return [modality, {
      modality,
      status: 'inactive_diagnostic_contract',
      active: false,
      backend_path_present: backendPathPresent,
      tests_present: testsPresent,
      production_claim_allowed: false,
      activation_requirements: [
        'native_backend_path',
        'targeted_tests',
        'operator_approval',
        'architecture_authority_update',
      ],
    }];
  }));

  return {
    contract_type: 'inactive_multimodal_representation_bridge',
    source_papers: WAVE5_MULTIMODAL_CONTRACT_AUTHORITIES,
    status: 'inactive_contract',
    diagnostic_only: true,
    contract_only: true,
    claims_support: false,
    active_capabilities: Object.fromEntries(modalities.map((modality) => [modality, false])),
    contracts,
    batch9_75_audio_contract: modalities.includes('audio')
      ? buildInactiveAudioUnderstandingContract({
          backendPathPresent: Boolean(backendPaths.audio),
          testsPresent: Boolean(tests.audio),
        })
      : null,
    guardrails: {
      image_support_claimed: false,
      video_support_claimed: false,
      audio_support_claimed: false,
      multimodal_fusion_enabled: false,
      backend_stub_allowed: false,
      fake_ui_allowed: false,
      ranking_math_changed: false,
      canonical_memory_changed: false,
    },
  };
}

// ─── Model Registry ──────────────────────────────────────────────────────────

/**
 * Register a new AI model in the model registry.
 * Uses UPSERT on (company_id, model_id, version) — re-registering an existing
 * version updates its metadata and status.
 *
 * @param {{
 *   model_id: string,
 *   version: string,
 *   framework: string,
 *   eval_metric: string,
 *   threshold: number,
 *   status?: string,
 *   metadata?: object
 * }} modelSpec
 * @param {string} [companyId]
 * @returns {Promise<{registered: boolean, model_id: string, version: string}>}
 */
export async function registerModel(modelSpec, companyId) {
  const cid = companyId || COMPANY;
  await ensureArchitectureRegistrySchema();

  if (!modelSpec?.model_id || !modelSpec?.version) {
    throw new Error('[architecture-registry] registerModel: model_id and version are required');
  }

  const status = VALID_STATUSES.includes(modelSpec.status) ? modelSpec.status : 'experimental';
  const threshold = Number(modelSpec.threshold) || 0;
  const metadata = modelSpec.metadata && typeof modelSpec.metadata === 'object'
    ? modelSpec.metadata
    : {};

  try {
    await query(
      `INSERT INTO model_registry
         (company_id, model_id, version, framework, eval_metric, threshold, status, metadata, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())
       ON CONFLICT (company_id, model_id, version)
       DO UPDATE SET
         framework   = $4,
         eval_metric = $5,
         threshold   = $6,
         status      = $7,
         metadata    = $8::jsonb,
         updated_at  = NOW()`,
      [
        cid,
        String(modelSpec.model_id),
        String(modelSpec.version),
        String(modelSpec.framework || 'unknown'),
        String(modelSpec.eval_metric || 'accuracy'),
        threshold,
        status,
        JSON.stringify(metadata),
      ]
    );

    await logEvent(cid, 'architecture-registry', 'model_registered', modelSpec.model_id, {
      reasoning: `Model '${modelSpec.model_id}@${modelSpec.version}' registered with status '${status}', eval_metric='${modelSpec.eval_metric}', threshold=${threshold}`,
      version: modelSpec.version,
      framework: modelSpec.framework,
      status,
    }).catch(() => {});

    return { registered: true, model_id: modelSpec.model_id, version: modelSpec.version };
  } catch (err) {
    console.error('[architecture-registry] registerModel DB error:', err.message);
    return { registered: false, model_id: modelSpec.model_id, version: modelSpec.version };
  }
}

/**
 * Retrieve all registered AI models for a company.
 * Returns models ordered by registration date descending.
 *
 * @param {string} [companyId]
 * @returns {Promise<Array<{
 *   id: number,
 *   model_id: string,
 *   version: string,
 *   framework: string,
 *   eval_metric: string,
 *   threshold: number,
 *   status: string,
 *   metadata: object,
 *   registered_at: string
 * }>>}
 */
export async function getModelRegistry(companyId) {
  const cid = companyId || COMPANY;
  await ensureArchitectureRegistrySchema();

  try {
    const result = await query(
      `SELECT id, model_id, version, framework, eval_metric, threshold,
              status, metadata, registered_at, updated_at
       FROM model_registry
       WHERE company_id = $1
       ORDER BY registered_at DESC`,
      [cid]
    );

    return result.rows.map((row) => ({
      id: row.id,
      model_id: row.model_id,
      version: row.version,
      framework: row.framework,
      eval_metric: row.eval_metric,
      threshold: parseFloat(row.threshold) || 0,
      status: row.status,
      metadata: row.metadata || {},
      registered_at: row.registered_at,
      updated_at: row.updated_at,
    }));
  } catch (err) {
    console.error('[architecture-registry] getModelRegistry DB error:', err.message);
    return [];
  }
}

// ─── Boundary Contracts ───────────────────────────────────────────────────────

/**
 * Register a component boundary contract in Aimos.
 * Contracts define the output type, confidence specification, update frequency,
 * and fallback behaviour — the interface contract between AI components.
 *
 * Stored under key 'component_boundary:{componentId}' in aimos_memories.
 *
 * @param {string} componentId - Unique component identifier
 * @param {{
 *   output_type: string,
 *   confidence_spec: string,
 *   update_frequency: string,
 *   fallback_behavior: string,
 *   [key: string]: any
 * }} contract
 * @param {string} [companyId]
 * @returns {Promise<{registered: boolean, componentId: string, key: string}>}
 */
export async function registerBoundary(componentId, contract, companyId) {
  const cid = companyId || COMPANY;
  await ensureArchitectureRegistrySchema();

  if (!componentId || typeof componentId !== 'string') {
    throw new Error('[architecture-registry] registerBoundary: componentId must be a non-empty string');
  }
  if (!contract || typeof contract !== 'object') {
    throw new Error('[architecture-registry] registerBoundary: contract must be an object');
  }

  const boundaryKey = `component_boundary:${componentId}`;
  const boundaryValue = JSON.stringify({
    component_id: componentId,
    output_type: String(contract.output_type || 'unknown'),
    confidence_spec: String(contract.confidence_spec || ''),
    update_frequency: String(contract.update_frequency || ''),
    fallback_behavior: String(contract.fallback_behavior || 'error'),
    ...contract,
    registered_at: new Date().toISOString(),
  });

  try {
    await persistMemory({
      company_id: cid,
      agent_id: 'architecture-registry',
      key: boundaryKey,
      value: boundaryValue,
      scope: 'global',
      memory_type: 'declarative',
      clearance_level: 5,
      mutation_authority: 'housekeeper',
    });

    await logEvent(cid, 'architecture-registry', 'boundary_registered', componentId, {
      reasoning: `Component boundary contract registered for '${componentId}': output_type='${contract.output_type}', fallback='${contract.fallback_behavior}'`,
      outputType: contract.output_type,
      fallbackBehavior: contract.fallback_behavior,
    }).catch(() => {});

    return { registered: true, componentId, key: boundaryKey };
  } catch (err) {
    console.error('[architecture-registry] registerBoundary save error:', err.message);
    return { registered: false, componentId, key: boundaryKey };
  }
}

// ─── AI Decision Log (AI-ADR) ────────────────────────────────────────────────

/**
 * Log an AI Architecture Decision Record (AI-ADR).
 * Extends the conventional ADR format with 7 AI-specific fields.
 *
 * Standard ADR fields: title, context, decision, consequences, status
 * AI-specific extra fields:
 *   1. uncertainty_estimate    — confidence interval or qualitative uncertainty level
 *   2. drift_potential         — likelihood that this decision degrades over time
 *   3. blast_radius            — systems/users affected if this decision proves wrong
 *   4. reversibility           — 'reversible' | 'costly' | 'irreversible'
 *   5. evaluation_criteria     — how correctness of this decision will be measured
 *   6. human_oversight_level   — 'full' | 'partial' | 'automated'
 *   7. governance_approved_by  — identity of approver (human or governance process)
 *
 * Stored in aimos_memories under key 'ai_adr:{decision_id}'.
 *
 * @param {{
 *   title: string,
 *   context: string,
 *   decision: string,
 *   consequences: string,
 *   status?: string,
 *   uncertainty_estimate?: string,
 *   drift_potential?: string,
 *   blast_radius?: string,
 *   reversibility?: string,
 *   evaluation_criteria?: string,
 *   human_oversight_level?: string,
 *   governance_approved_by?: string,
 *   [key: string]: any
 * }} decisionRecord
 * @param {string} [companyId]
 * @returns {Promise<{logged: boolean, decisionId: string, key: string}>}
 */
export async function logAIDecision(decisionRecord, companyId) {
  const cid = companyId || COMPANY;
  await ensureArchitectureRegistrySchema();

  if (!decisionRecord?.title || !decisionRecord?.decision) {
    throw new Error('[architecture-registry] logAIDecision: title and decision fields are required');
  }

  const decisionId = generateId('adr');
  const adrKey = `ai_adr:${decisionId}`;

  const adr = {
    // Standard ADR fields
    decision_id: decisionId,
    title: String(decisionRecord.title),
    context: String(decisionRecord.context || ''),
    decision: String(decisionRecord.decision),
    consequences: String(decisionRecord.consequences || ''),
    status: String(decisionRecord.status || 'proposed'),

    // AI-specific extra fields (7)
    uncertainty_estimate: String(decisionRecord.uncertainty_estimate || 'not-assessed'),
    drift_potential: String(decisionRecord.drift_potential || 'unknown'),
    blast_radius: String(decisionRecord.blast_radius || 'unknown'),
    reversibility: String(decisionRecord.reversibility || 'unknown'),
    evaluation_criteria: String(decisionRecord.evaluation_criteria || ''),
    human_oversight_level: String(decisionRecord.human_oversight_level || 'partial'),
    governance_approved_by: String(decisionRecord.governance_approved_by || 'pending'),

    // Provenance
    company_id: cid,
    logged_at: new Date().toISOString(),
  };

  // Merge any additional fields from the record
  const extraFields = Object.fromEntries(
    Object.entries(decisionRecord).filter(
      ([k]) => !Object.prototype.hasOwnProperty.call(adr, k)
    )
  );
  Object.assign(adr, extraFields);

  try {
    await persistMemory({
      company_id: cid,
      agent_id: 'architecture-registry',
      key: adrKey,
      value: JSON.stringify(adr),
      scope: 'global',
      memory_type: 'declarative',
      clearance_level: 5,
      mutation_authority: 'housekeeper',
    });

    await logEvent(cid, 'architecture-registry', 'ai_decision_logged', adrKey, {
      reasoning: `AI-ADR logged: '${adr.title}'. Decision: '${adr.decision.slice(0, 120)}'. Reversibility: ${adr.reversibility}. Oversight: ${adr.human_oversight_level}`,
      decisionId,
      status: adr.status,
      reversibility: adr.reversibility,
      blastRadius: adr.blast_radius,
      humanOversightLevel: adr.human_oversight_level,
    }).catch(() => {});

    return { logged: true, decisionId, key: adrKey };
  } catch (err) {
    console.error('[architecture-registry] logAIDecision save error:', err.message);
    return { logged: false, decisionId, key: adrKey };
  }
}

// ─── AI Debt Register ─────────────────────────────────────────────────────────

/**
 * Track an AI technical debt entry.
 * Uses Sculley et al. (2015) taxonomy extended with AI governance gaps.
 *
 * @param {{
 *   category: string,
 *   severity?: string,
 *   blast_radius?: string,
 *   remediation_effort?: string,
 *   owner?: string,
 *   status?: string,
 *   description?: string,
 *   metadata?: object
 * }} entry
 * @param {string} [companyId]
 * @returns {Promise<{tracked: boolean, debtId: number|null, category: string}>}
 */
export async function trackAIDebt(entry, companyId) {
  const cid = companyId || COMPANY;
  await ensureArchitectureRegistrySchema();

  if (!entry?.category) {
    throw new Error('[architecture-registry] trackAIDebt: category is required');
  }

  const category = VALID_DEBT_CATEGORIES.includes(entry.category)
    ? entry.category
    : entry.category; // Accept unknown categories — warn only

  if (!VALID_DEBT_CATEGORIES.includes(entry.category)) {
    console.warn(`[architecture-registry] trackAIDebt: unknown category '${entry.category}'. Valid: ${VALID_DEBT_CATEGORIES.join(', ')}`);
  }

  const severity = VALID_SEVERITIES.includes(entry.severity) ? entry.severity : 'medium';
  const status = entry.status || 'open';
  const metadata = entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : {};

  try {
    const result = await query(
      `INSERT INTO ai_debt_register
         (company_id, category, severity, blast_radius, remediation_effort,
          owner, status, description, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
       RETURNING id`,
      [
        cid,
        category,
        severity,
        String(entry.blast_radius || 'unknown'),
        String(entry.remediation_effort || 'unknown'),
        String(entry.owner || 'unassigned'),
        status,
        String(entry.description || ''),
        JSON.stringify(metadata),
      ]
    );

    const debtId = result.rows[0]?.id ?? null;

    await logEvent(cid, 'architecture-registry', 'ai_debt_tracked', `debt:${debtId}`, {
      reasoning: `AI technical debt item tracked: category='${category}', severity='${severity}', blast_radius='${entry.blast_radius}', owner='${entry.owner}'`,
      category,
      severity,
      blastRadius: entry.blast_radius,
      remediationEffort: entry.remediation_effort,
      owner: entry.owner,
    }).catch(() => {});

    return { tracked: true, debtId, category };
  } catch (err) {
    console.error('[architecture-registry] trackAIDebt DB error:', err.message);
    return { tracked: false, debtId: null, category };
  }
}

// ---------------------------------------------------------------------------
// Batch9.75 Wave 1: Audit-only architecture notes
// These functions return audit-only references. They do NOT modify production
// architecture, model registry, or AI debt register state.
// ---------------------------------------------------------------------------

/**
 * Bitter Lesson Note — Audit-only architecture analogy
 *
 * Source paper: The Bitter Lesson (Sutton, 2019)
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Sutton's thesis: general methods that leverage computation scale
 * ultimately outperform domain-specific human engineering. This note
 * provides an audit-only architectural analogy; Aimos does not
 * automatically replace heuristic services with scaled computation.
 */
export function buildBitterLessonNote() {
  return {
    analogy: true,
    source_paper: BITTER_LESSON_SOURCE,
    coexistence_class: 'audit_only_analogy',
    thesis: 'General methods that leverage computation ultimately outperform domain-specific human engineering.',
    implications: [
      'Scaling compute and data tends to dominate hand-crafted features over time',
      'Search and learning are the two general methods that scale with compute',
      'Domain knowledge is most valuable when it improves the learning or search process itself',
    ],
    aimos_contract: {
      heuristic_services_unchanged: true,
      compute_scaling_preferred: false,
      auto_replacement_enabled: false,
    },
    note: 'Audit-only analogy. Aimos does not automatically replace heuristic services with scaled computation.',
  };
}

/**
 * Scaling Law Architecture Diagnostic — Audit-only reference
 *
 * Source paper: Scaling Laws for Neural Language Models (Kaplan et al., 2020)
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Scaling laws characterize model performance as a function of compute,
 * parameters, and data. This diagnostic provides an audit-only reference
 * to scaling law concepts for architecture-economics decisions. Aimos
 * does not train models or predict performance from scaling laws.
 */
export function buildScalingLawDiagnostic() {
  return {
    diagnostic: true,
    source_paper: SCALING_LAW_REGISTRY_SOURCE,
    coexistence_class: 'audit_only_analogy',
    raw_gap_visible: true,
    scaling_law_references: [
      { relation: 'compute_optimal', description: 'Chinchilla: N_params ≈ C / 6 for compute-optimal training' },
      { relation: 'model_quality_vs_cost', description: 'Larger models more sample-efficient but costlier at inference' },
      { relation: 'diminishing_returns', description: 'Loss improvements diminish with scale; crossover where cost > value' },
    ],
    aimos_does_not_train: true,
    performance_prediction_active: false,
    architecture_registry_unchanged: true,
    note: 'Audit-only scaling-law reference; no performance prediction or model training.',
  };
}

/**
 * Audio Architecture Diagnostic — Audit-only audio architecture note
 *
 * Source paper: Qwen-Audio — Universal Audio Understanding via Unified
 * Large-Scale Audio-Language Models
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Provides an audit-only reference for audio architecture concepts.
 * Aimos has no active audio modality; the audio contract is inactive.
 */
export function buildAudioArchitectureDiagnostic() {
  return {
    diagnostic: true,
    source_paper: QWEN_AUDIO_SOURCE,
    coexistence_class: 'audit_only_analogy',
    audio_modality: 'inactive',
    audio_contract_status: 'inactive_diagnostic_contract',
    inactive_audio_contract: buildInactiveAudioUnderstandingContract({
      backendPathPresent: false,
      testsPresent: false,
    }),
    architecture_implications: [
      'Audio modality requires dedicated encoder and alignment layer',
      'Cross-modal alignment between audio and text is research-stage',
      'No production audio capability exists in Aimos',
    ],
    audio_production_claim: false,
    note: 'Audit-only audio architecture reference. No active audio modality in Aimos.',
  };
}

/**
 * Dataset Provenance Note — Audit-only dataset provenance reference
 *
 * Source paper: The Pile — 800GB Dataset (Gao et al., 2020)
 * Coexistence class: audit_only_analogy
 * Authority: Batch9.75 Wave 1 coexistence map
 *
 * Provides an audit-only reference for dataset provenance and
 * documentation practices. Aimos does not ingest The Pile or
 * any specific external dataset.
 */
export function buildDatasetProvenanceNote() {
  return {
    diagnostic: true,
    source_paper: DATASET_PROVENANCE_SOURCE,
    coexistence_class: 'audit_only_analogy',
    dataset_documentation_principles: [
      'Datasets should carry structured provenance metadata (source, license, curation method)',
      'Data composition affects model behaviour — provenance is an architecture concern',
      'Training data transparency enables reproducibility and accountability',
    ],
    aimos_dataset_contract: {
      external_dataset_ingested: false,
      provenance_metadata_required: true,
      data_composition_visible: true,
    },
    architecture_registry_unchanged: true,
    note: 'Audit-only dataset provenance reference. Aimos does not ingest external datasets.',
  };
}
