// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Infrastructure — imported by the command-center validation surface
// Purpose: Canonical source of truth for critical pipeline connections across
//          runtime pipelines; validated at boot via node -e "import(...)"
// Note: This file governs pipeline wiring. The complete live service inventory
//       lives in architecture-authority.json + hom-architecture-manifest.json.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from './security/protocol/canonical-json.js';

const SOURCE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVICES_ROOT = path.join(SOURCE_ROOT, 'services');

export const EXECUTABLE_DISPOSITIONS = Object.freeze([
  'ACTIVE',
  'CONDITIONAL',
  'DIAGNOSTIC',
  'DORMANT',
  'SUPERSEDED',
  'ALTERNATE_PIPELINE',
  'ORPHAN',
]);

export const EXECUTABLE_DISPOSITION_DEFINITIONS = Object.freeze({
  ACTIVE: 'The owning entry invokes this connection on every admitted execution of the relevant stage.',
  CONDITIONAL: 'The owning entry has a real call site gated by request shape, signed policy, corpus state, schedule, or failure branch.',
  DIAGNOSTIC: 'The owning entry executes the connection for bounded observation only; it has no independent rank, disclosure, retention, or mutation authority.',
  DORMANT: 'Deliberately absent from the owning executable call graph pending an explicit promotion gate.',
  SUPERSEDED: 'Replaced by a named current owner and absent from the owning executable call graph; retained source is non-authoritative pending physical retirement.',
  ALTERNATE_PIPELINE: 'Executable from a different named product pipeline, not from this owning entry.',
  ORPHAN: 'No executable owner is established; removal or explicit ownership is required.',
});

const NON_EXECUTABLE_DISPOSITIONS = Object.freeze({
  'save:./core/directive-claims.js': ['ALTERNATE_PIPELINE', 'directive and agent-execution routes own directive claims'],
  'save:./retrieval/similarity-stats.js': ['ALTERNATE_PIPELINE', 'canonical RECALL owns the executable similarity-statistics caller; the Dream import is unused'],
  'save:./governance/knowledge-gate-enforcer.js': ['ORPHAN', 'registry metadata and manifest declaration provide no executable caller'],
  'save:./retrieval/pipeline-instrumentation.js': ['ORPHAN', 'native signed stage events and doctor telemetry replaced predecessor instrumentation'],
  'recall:./temporal/retrieval-pheromone.js': ['DORMANT', 'online recall mutation lacks a signed atomic database-local owner'],
  'recall:./retrieval/hmem-hierarchical-reasoning.js': ['DORMANT', 'unpromoted research kernel'],
  'recall:./retrieval/hage-hybrid-agent-graph.js': ['DORMANT', 'unpromoted non-equivalent research adaptation'],
  'recall:./retrieval/hindsight-memory-graph.js': ['DORMANT', 'retained research kernel outside the canonical graph family'],
  'recall:./retrieval/hingemem-boundary-hypergraph.js': ['DORMANT', 'retained research kernel outside the canonical graph family'],
  'recall:./retrieval/reconstructed-graph-memory.js': ['SUPERSEDED', 'active source-bound reconstructed-graph native candidate owns the production role'],
  'recall:./retrieval/mnemis-dual-route-graph.js': ['DORMANT', 'retained research kernel outside the canonical graph family'],
  'recall:./retrieval/pipeline-instrumentation.js': ['ORPHAN', 'native signed stage events and doctor telemetry replaced predecessor instrumentation'],
  'recall:./ingestion/ingestion-orchestrator.js': ['ALTERNATE_PIPELINE', 'the signed v1 ASMR ingestion route owns this service'],
  'recall:./ingestion/entity-extractor.js': ['ALTERNATE_PIPELINE', 'the signed v1 ASMR ingestion route owns this service'],
  'recall:./ingestion/relationship-mapper.js': ['ALTERNATE_PIPELINE', 'the signed v1 ASMR ingestion route owns this service'],
  'recall:./ingestion/temporal-marker.js': ['ALTERNATE_PIPELINE', 'the signed v1 ASMR ingestion route owns this service'],
  'dream:./retrieval/similarity-stats.js': ['ALTERNATE_PIPELINE', 'canonical RECALL owns the executable similarity-statistics caller; the Dream import is unused'],
  'governance:./core/brain-contract.js': ['ALTERNATE_PIPELINE', 'agent-run and persistent identity bootstrap own the executable brain-contract callers; the Governance import is unused'],
  'governance:./observe/routing-monitor.js': ['ALTERNATE_PIPELINE', 'agent-run owns the executable routing-monitor caller; the Governance import is unused'],
  'governance:./orchestration/graph-designer.js': ['ORPHAN', 'the only production import is unused and no executable caller is established'],
  'governance:./orchestration/fallback-resolver.js': ['ORPHAN', 'the only production import is unused and no executable caller is established'],
  'governance:./orchestration/trust-router.js': ['ORPHAN', 'the only production import is unused and no executable caller is established'],
});

const DIAGNOSTIC_CONNECTIONS = new Set([
  'agent_run:./observe/coordination-audit.js',
  'agent_run:./observe/agent-trace.js',
  'agent_run:./observe/explainer.js',
  'agent_run:./observe/architecture-registry.js',
  'dream:./observe/retrieval-drift-monitor.js',
  'dream:./observe/mastery-paradox-detector.js',
  'dream:./observe/entanglement-monitor.js',
  'dream:./observe/svdd-anomaly.js',
  'dream:./temporal/temporal-fingerprinter.js',
  'dream:./temporal/topic-budget.js',
  'dream:./retrieval/embedding-stability.js',
]);

const ALWAYS_ACTIVE_CONNECTIONS = new Set([
  'save:./write/canonical-save-owner.js',
  'save:./write/canonical-save-contract.js',
  'save:./write/quality-gate.js',
  'save:./write/write-validator.js',
  'save:./core/embeddings.js',
  'save:./observe/event-ledger.js',
  'save:./security/memory-epistemic-classifier.js',
  'save:./dream/curator.js',
  'save:./governance/aladdin-compliance.js',
  'recall:./retrieval/native-recall-pipeline.js',
  'recall:./retrieval/native-recall.js',
  'recall:./retrieval/native-retrieval-fusion.js',
  'recall:./security/recall-authorization.js',
  'recall:./security/memory-provenance.js',
  'recall:./retrieval/epistemic-trust-retrieval.js',
  'recall:./core/embeddings.js',
  'recall:./learning/trust-score.js',
  'recall:./retrieval/query-entity-anchors.js',
  'recall:./retrieval/recall-calibrator.js',
  'recall:./observe/event-ledger.js',
  'heartbeat:./observe/event-ledger.js',
]);

const PIPELINE_EXECUTION_CONTRACTS = Object.freeze({
  save: Object.freeze({
    authority: 'verified_agent_certificate_envelope_or_housekeeper_system_principal',
    input_schema: 'hom.aimos.canonical-save-request/runtime-versioned',
    output_schema: 'hom.aimos.canonical-save-trace/v1',
    terminal_evidence: 'canonical_save_terminal',
  }),
  recall: Object.freeze({
    authority: 'verified_agent_certificate_envelope_and_effective_recall_grant',
    input_schema: 'hom.aimos.native-recall-command/runtime-versioned',
    output_schema: 'hom.aimos.recall-return-projection/v1',
    terminal_evidence: 'recall_receipt',
  }),
  agent_run: Object.freeze({
    authority: 'verified_agent_identity_capability_and_model_policy',
    input_schema: 'hom.aimos.agent-run-request/runtime-versioned',
    output_schema: 'hom.aimos.agent-run-terminal/runtime-versioned',
    terminal_evidence: 'agent_run_terminal_or_failure',
  }),
  dream: Object.freeze({
    authority: 'housekeeper_scheduler_and_signed_governor_heads',
    input_schema: 'hom.aimos.nightly-dream-job/runtime-versioned',
    output_schema: 'hom.aimos.nightly-dream-terminal/runtime-versioned',
    terminal_evidence: 'nightly_dream_terminal_or_subowner_terminals',
  }),
  heartbeat: Object.freeze({
    authority: 'housekeeper_scheduler',
    input_schema: 'hom.aimos.heartbeat-job/runtime-versioned',
    output_schema: 'hom.aimos.heartbeat-observation/runtime-versioned',
    terminal_evidence: 'heartbeat',
  }),
  governance: Object.freeze({
    authority: 'verified_agent_identity_and_governance_policy',
    input_schema: 'hom.aimos.governance-resolution-request/runtime-versioned',
    output_schema: 'hom.aimos.governance-resolution/runtime-versioned',
    terminal_evidence: 'governance_resolution_or_agent_run_terminal',
  }),
});

/**
 * PIPELINE WIRING MANIFEST — Single source of truth
 *
 * Every critical pipeline. Every declared connection.
 * If a connection is not in this manifest, it is not governed as part of the
 * six canonical runtime pipelines.
 * If it fails validation, the system doesn't start.
 *
 * Paths are relative to this file: services/pipeline-manifest.js
 * i.e., relative to the `services/` directory.
 */

export const PIPELINES = {
  // ─── SAVE ────────────────────────────────────────────────────────────────────
  save: {
    description: 'One canonical SAVE owner: AUTH → RECEIPT → CANARY → SE → ALADDIN → VALIDATOR → QUALITY → SECRET_BOUNDARY → EMBEDDING → PERSISTENCE → PROVENANCE → LINEAGE → GRAPH → EPISTEMIC → TERMINAL',
    entry: 'services/write/canonical-save-owner.js',
    services: [
      {
        path: './write/canonical-save-owner.js',
        exports: [
          'executeCanonicalSave',
          'executeHousekeeperCanonicalSave',
          'createHousekeeperCanonicalSaveOwner',
        ],
      },
      {
        path: './write/canonical-save-contract.js',
        exports: ['CANONICAL_SAVE_STAGE_ORDER', 'verifyCanonicalSaveTrace'],
      },
      {
        path: './write/quality-gate.js',
        exports: ['assessQuality', 'wall1_form', 'wall2_filter', 'wall3_substance'],
      },
      {
        path: './write/write-validator.js',
        exports: ['validateWrite'],
      },
      {
        path: './write/rpe-gate.js',
        exports: ['computeRPE'],
      },
      {
        path: './core/embeddings.js',
        exports: ['getEmbedding'],
      },
      {
        path: './observe/event-ledger.js',
        exports: ['logEvent'],
      },
      {
        path: './security/memory-epistemic-classifier.js',
        exports: ['classifyRetainedMemoryEpistemics', 'classifyAndCommitRetainedMemoryGroup'],
      },
      {
        path: './dream/curator.js',
        exports: ['checkConflict'],
      },
      {
        path: './core/directive-claims.js',
        exports: ['claimDirective', 'completeDirectiveClaim'],
      },
      {
        path: './retrieval/similarity-stats.js',
        exports: ['recordSimilarityObservation', 'computeSurprise', 'getAnisotropyStats'],
      },
      {
        path: './context/mnemonic-encoder.js',
        exports: ['detectEncodingStyle', 'rankByStyleMatch'],
      },
      // ─── PHASE 1-2 SPEED OPTIMIZATIONS ──────────────────────────────────────
      {
        path: './governance/knowledge-gate-enforcer.js',
        exports: ['buildSourceEvidenceRequirements', 'buildCuraLightGateDiagnostic', 'buildRewardHackingGateDiagnostic'],
      },
      {
        path: './governance/aladdin-compliance.js',
        exports: ['validateAladdinCompliance'],
      },
      {
        path: './retrieval/pipeline-instrumentation.js',
        exports: ['instrumentedStage', 'getBaselineReport'],
      },
    ],
  },

  // ─── RECALL ──────────────────────────────────────────────────────────────────
  recall: {
    description: 'One canonical RECALL owner: signed authority + actor/grant lock → one restricted repeatable-read snapshot → per-lane provenance admission before influence → native dense/sparse/temporal/entity/QuIM/QMD/HyDE/concept gears → one bounded Reconstructed-Graph G2 family channel → central RRF fusion → signed epistemic and Canary/Aladdin closure → decision-bound output receipt; MAGMA remains retained dormant research with no pipeline edge',
    entry: 'services/retrieval/native-recall-pipeline.js',
    services: [
      {
        path: './retrieval/native-recall-pipeline.js',
        exports: ['executeCanonicalRecall', 'executeNativeRecall'],
      },
      {
        path: './retrieval/native-recall.js',
        exports: [
          'openNativeRecallRequestSession',
          'admitNativeRecallCandidatesInVerifiedSession',
          'finalizeNativeRecall',
        ],
      },
      {
        path: './retrieval/native-retrieval-fusion.js',
        exports: ['NATIVE_RETRIEVAL_FUSION_CONTRACT', 'fuseNativeRetrievalGears'],
      },
      {
        path: './retrieval/reconstructed-graph-native-candidate.js',
        exports: ['RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT', 'composeReconstructedGraphNativeCandidate'],
      },
      {
        path: './security/recall-authorization.js',
        exports: ['recallAuthorizationService'],
      },
      {
        path: './security/memory-provenance.js',
        exports: ['memoryProvenanceLedger', 'verifyRecallEvidenceRow'],
      },
      {
        path: './retrieval/epistemic-trust-retrieval.js',
        exports: ['calibrateEpistemicRecall'],
      },
      {
        path: './security/system-config-store.js',
        exports: ['systemConfigStore'],
      },
      {
        path: './security/system-config-ledger.js',
        exports: [
          'validateTwinPrimeRetrievalPolicy',
          'validateMagmaRetrievalCalibration',
          'validateQuimRetrievalPolicy',
          'validateConceptPprRetrievalPolicy',
        ],
      },
      {
        path: './retrieval/twin-prime-arithmetic.js',
        exports: ['computeB2Distance', 'computeTwinPrimeDistance', 'gaussianTwinIndicator'],
      },
      {
        path: './core/embeddings.js',
        exports: ['getEmbedding'],
      },
      {
        path: './retrieval/similarity-stats.js',
        exports: ['recordSimilarityObservation', 'computeSurprise', 'getAnisotropyStats'],
      },
      {
        path: './learning/trust-score.js',
        exports: ['rankByTrust'],
      },
      {
        path: './retrieval/quim-index.js',
        exports: ['quimLookup', 'buildQuimIndex'],
      },
      {
        path: './retrieval/query-entity-anchors.js',
        exports: ['extractQueryEntityAnchors', 'normalizeEntityAnchor'],
      },
      {
        path: './retrieval/concept-ppr-native.js',
        exports: ['conceptPprLookup', 'buildConceptPprGraph'],
      },
      {
        path: './retrieval/recall-calibrator.js',
        exports: ['getVerifiedCalibrationSnapshot', 'applyCalibrationSnapshot', 'runCalibrationUpdate'],
      },
      {
        path: './temporal/dormancy-manager.js',
        exports: ['evaluateDormancy'],
      },
      {
        path: './context/mnemonic-encoder.js',
        exports: ['detectEncodingStyle', 'rankByStyleMatch'],
      },
      {
        path: './observe/event-ledger.js',
        exports: ['logEvent'],
      },
      {
        path: './temporal/retrieval-pheromone.js',
        exports: ['reinforceRetrievedPheromones', 'depositPheromone', 'getPheromoneStrength'],
      },
      // ─── NATIVE PAPER-BACKED RECALL OPERATORS ─────────────────────────────
      {
        path: './retrieval/hmem-hierarchical-reasoning.js',
        exports: ['buildHierarchicalMemory', 'recursiveTopK', 'hmemScores'],
      },
      {
        path: './retrieval/hage-hybrid-agent-graph.js',
        exports: ['buildHageGraph', 'hageTraversalScores', 'hageScores'],
      },
      {
        path: './retrieval/hindsight-memory-graph.js',
        exports: ['partitionMemoryUnit', 'reciprocalRankFusion', 'hindsightMemoryGraphScores'],
      },
      {
        path: './retrieval/hingemem-boundary-hypergraph.js',
        exports: ['buildBoundaryHypergraph', 'fieldAwareJaccard', 'hingeMemScores'],
      },
      {
        path: './retrieval/reconstructed-graph-memory.js',
        exports: ['buildCueTagContentGraph', 'reconstructMemoryState', 'reconstructedGraphMemoryScores'],
      },
      {
        path: './retrieval/mnemis-dual-route-graph.js',
        exports: ['buildMnemisBaseGraph', 'reciprocalRankFusionMnemis', 'mnemisScores'],
      },
      // ─── PHASE 1-2 SPEED OPTIMIZATIONS ──────────────────────────────────────
      {
        path: './caching/semantic-cache.js',
        exports: ['semanticCache', 'SemanticCache'],
      },
      {
        path: './retrieval/adaptive-early-exit.js',
        exports: ['shouldEarlyExit', 'generateEarlyExitMetadata'],
      },
      {
        path: './retrieval/pipeline-instrumentation.js',
        exports: ['instrumentedStage', 'getBaselineReport'],
      },
      // ─── SAVE pipeline: async post-save enrichment (ingestion) ──────────────
      {
        path: './ingestion/ingestion-orchestrator.js',
        exports: ['runIngestion'],
      },
      {
        path: './ingestion/entity-extractor.js',
        exports: ['extractEntities', 'resolveAliases', 'attachEvidence'],
      },
      {
        path: './ingestion/relationship-mapper.js',
        exports: ['extractRelationships', 'validateDAG'],
      },
      {
        path: './ingestion/temporal-marker.js',
        exports: ['extractTemporalMarkers'],
      },
    ],
  },

  // ─── AGENT RUN ───────────────────────────────────────────────────────────────
  agent_run: {
    description: 'Agent execution: prompt → constitution → governance → schema-mapper → LLM → STDP → reasoning extraction',
    entry: 'services/orchestration/agent-runner.js',
    services: [
      {
        path: './orchestration/agent-store.js',
        exports: ['agents', 'ensureAgent'],
      },
      {
        path: './orchestration/tool-registry.js',
        exports: ['getToolsForAgent', 'executeTool'],
      },
      {
        path: './core/embeddings.js',
        exports: ['getEmbedding'],
      },
      {
        path: './orchestration/session-runner.js',
        exports: ['getConversationHistory', 'addConversationTurn'],
      },
      {
        path: './orchestration/model-preferences.js',
        exports: ['resolveModelForRequest'],
      },
      {
        path: './security/cybersec-firewall.js',
        exports: [
          'runSentinelCheck',
          'filterCybersecContent',
          'isCybersecAction',
          'isCybersecLocked',
          'auditLog',
          'screenPromptForSocialEngineering',
        ],
      },
      {
        path: './security/cognitive-demand.js',
        exports: [
          'classifyBloomLevel',
          'mapBloomToSecurityTier',
          'computeAlignmentGap',
          'detectEnactedLevel',
          'assessSecurityImplications',
        ],
      },
      {
        path: './learning/agent-learning.js',
        exports: [
          'recordAgentRun',
          'checkRiskBudget',
          'selfReflect',
          'getSharedFailures',
          'recordRecommendation',
          'afterActionReview',
          'updateBehavioralBaseline',
        ],
      },
      {
        path: './write/quality-gate.js',
        exports: ['assessQuality'],
      },
      {
        path: './core/brain-contract.js',
        exports: ['evaluateSocialLawViolations'],
      },
      {
        path: './observe/event-ledger.js',
        exports: ['logEvent'],
      },
      {
        path: './observe/semantic-intent.js',
        exports: [
          'extractIntent',
          'observeSemanticIntent',
          'computeSDR',
          'buildHumanOnboardingFrictionDiagnostics',
        ],
      },
      {
        path: './observe/coordination-audit.js',
        exports: [
          'audit4D',
          'observeCoordinationAudit',
          'computeCBS',
          'checkEvaluationAntiPatterns',
          'recommendTopology',
        ],
      },
      {
        path: './security/knowledge-gate.js',
        exports: [
          'createKnowledgeGateState',
          'recordKnowledgeToolEvent',
          'shouldBlockCompletionForMissingKnowledge',
        ],
      },
      {
        path: './core/hom-constitution.js',
        exports: ['evaluateDelegatedDirectiveAgainstConstitution'],
      },
      {
        path: './orchestration/meta-controller.js',
        exports: ['evaluateMetaState', 'META_ACTIONS'],
      },
      {
        path: './security/security-classifier.js',
        exports: ['runSecurityPipeline'],
      },
      {
        path: './shared/schema-mapper.js',
        exports: ['getToolSchema', 'mapFactsToToolCalls', 'extractStructuredFacts'],
      },
      {
        path: './orchestration/escalation-resolver.js',
        exports: ['resolveEscalation'],
      },
      {
        path: './orchestration/decision-renderer.js',
        exports: ['selectAction', 'renderDecision'],
      },
      {
        path: './context/context-renewal.js',
        exports: ['shouldRenew', 'checkpointProgress', 'loadCheckpoint', 'incrementRenewalCount'],
      },
      {
        path: './write/channel-separator.js',
        exports: ['buildSeparatedPrompt', 'validateChannelSeparation', 'sanitizeMemoryValue'],
      },
      {
        path: './context/workspace-partitions.js',
        exports: ['createWorkspace', 'setPartition', 'getPartition', 'serializeWorkspace'],
      },
      {
        path: './core/scheming-monitor.js',
        exports: ['auditTrajectory', 'getWarningSignsForEvents'],
      },
      {
        path: './core/constitution-enforcer.js',
        exports: ['loadConstitutionRules', 'enforceRules'],
      },
      {
        path: './learning/stdp-kernel.js',
        exports: ['applyRewardSignal'],
      },
      {
        path: './orchestration/interaction-graph-healer.js',
        exports: ['deliverAndChain'],
      },
      {
        path: './observe/agent-trace.js',
        exports: ['logTracedEvent'],
      },
      {
        path: './observe/explainer.js',
        exports: [
          'EXPLANATION_LEVEL',
          'COT_EXPLANATION_SOURCE',
          'buildTransparencyReport',
          'buildInterpretabilityReport',
          'buildContrastiveExplanation',
          'generateExplanation',
          'formatForUser',
          'scoreExplanationQuality',
          'buildEvidencePathExplanation',
          'buildCoTExplanationDiagnostic',
        ],
      },
      {
        path: './observe/architecture-registry.js',
        exports: [
          'computeFingerprintDimension',
          'computeSemanticFingerprint',
          'computeJSDivergenceThreshold',
          'computeJSDivergence',
          'buildArchitectureDriftDiagnostics',
          'buildOntologyAwarePatternMap',
          'buildInactiveMultimodalRepresentationContracts',
          'registerModel',
          'getModelRegistry',
          'registerBoundary',
          'logAIDecision',
          'trackAIDebt',
          'buildBitterLessonNote',
          'buildScalingLawDiagnostic',
          'buildAudioArchitectureDiagnostic',
          'buildDatasetProvenanceNote',
        ],
      },
      {
        path: './orchestration/symbolic-reasoner.js',
        exports: ['symbolicPostCheck'],
      },
      {
        path: './orchestration/agent-prompts.js',
        exports: [
          'redactSecrets',
          'isInternalMemoryText',
          'compactText',
          'buildEmptyContextPack',
          'loadRecentAimosContext',
          'loadProceduralSkills',
          'buildPromptPressure',
          'updateLatestPromptPressureTelemetry',
          'getPromptPressureTelemetry',
          'normalizeConversationSessionKey',
          'buildConversationMessages',
          'trimConversationMessagesForBudget',
          'buildFastLaneSystemPrompt',
          'buildSystemPrompt',
          'TEAM_TOPOLOGY',
        ],
      },
      {
        path: './orchestration/agent-tools.js',
        exports: [
          'isToolApprovalRequired',
          'createToolApprovalError',
          'loopExhaustedResult',
          'emitTextChunks',
          'runAgentWithFallback',
          'isModelCircuitBroken',
          'pruneModelFailureHistory',
          'recordModelFailure',
          'resetModelCircuitBreaker',
          'runByModel',
        ],
      },
      // ─── AGENT_RUN pipeline: state matrix (Zhang et al. ICLR 2026) ──────────
      // Aladdin compliance: state matrices are ephemeral operational overlays.
      // Original reasoning traces are always persisted to Aimos via
      // memory_type: reasoning_step. State matrices are reconstructed from Aimos
      // on session resume — never a source of truth, always a cache.
      // Replay mode 'bottom_20_percent_deprioritize' does NOT delete or suppress
      // any memory; it deprioritizes low-deviation steps for active replay only.
      {
        path: './context/scoped-state.js',
        exports: [
          'createReasoningStateMatrix',
          'compressReasoningStep',
          'detectStepDeviation',
          'selectiveReplayCandidates',
          'serializeStateMatrix',
          'deserializeStateMatrix',
          'getStateMatrixSummary',
        ],
      },
    ],
  },

  // ─── DREAM ───────────────────────────────────────────────────────────────────
  dream: {
    description: 'Nightly consolidation: events → dedup → hierarchical summarization → SPICED → failure-replay → skill-consolidation → delta-writer → spaced-repetition',
    entry: 'jobs/nightly-dream.js',
    services: [
      {
        path: './core/embeddings.js',
        exports: ['getEmbedding'],
      },
      {
        path: './observe/event-ledger.js',
        exports: ['logEvent'],
      },
      {
        path: './dream/spiced-consolidator.js',
        exports: ['runDreamConsolidation'],
      },
      {
        path: './dream/hebbian-consensus.js',
        exports: ['buildVerifiedHebbianAssociationSnapshot', 'runHebbianConsensusBatch'],
      },
      {
        path: './learning/neuroplasticity-stability-control.js',
        exports: ['controlCertifiedMutationProposal'],
      },
      {
        path: './learning/agent-learning.js',
        exports: [
          'scoreDueRecommendations',
          'curateSkillsFromSuccesses',
          'computeForwardTransfer',
          'computeBackwardTransfer',
          'computePerformanceMaintenance',
        ],
      },
      {
        path: './core/providers.js',
        exports: ['runProvider'],
      },
      {
        path: './observe/retrieval-drift-monitor.js',
        exports: ['formatRetrievalDriftSummary', 'recordRetrievalDriftSnapshot'],
      },
      {
        path: './retrieval/similarity-stats.js',
        exports: ['computeSurprise', 'getAnisotropyStats'],
      },
      {
        path: './temporal/temporal-resolver.js',
        exports: ['auditSupersessionChains'],
      },
      {
        path: './learning/failure-replay.js',
        exports: ['replayFailuresBatch', 'generateAntiSkill'],
      },
      {
        path: './learning/error-normalizer.js',
        exports: ['normalizeErrorBatch', 'runErrorNormalizationCycle', 'updateSkillRunningStats'],
      },
      {
        path: './learning/skill-consolidation.js',
        exports: [
          'clusterSimilarSkills',
          'extractAbstraction',
          'promoteProvisionalSkill',
          'flagRedundantSkills',
        ],
      },
      {
        path: './dream/delta-writer.js',
        exports: ['runDeltaPipeline'],
      },
      {
        path: './dream/dream-feedback.js',
        exports: ['loadDreamConstraints'],
      },
      {
        path: './learning/spaced-repetition.js',
        exports: ['getNextReviewBatch', 'scheduleRepetition'],
      },
      {
        path: './observe/mastery-paradox-detector.js',
        exports: ['detectMasteryParadox'],
      },
      {
        path: './observe/entanglement-monitor.js',
        exports: [
          'computeCoV',
          'classifyBehavior',
          'runEntanglementAutonomyAudit',
          'detectBotFarming',
          'computeEchoDecay',
          'computeInfluenceScore',
          'triangulateSignals',
          'buildInspiralEntanglementDiagnostics',
        ],
      },
      {
        path: './observe/svdd-anomaly.js',
        exports: [
          'initializeCenter',
          'updateCenter',
          'scoreAnomaly',
          'buildOpenSetNoveltyDiagnostics',
          'runSVDDMemoryIntegrityCheck',
          'EMA_ALPHA',
          'EPSILON',
        ],
      },
      {
        path: './temporal/temporal-fingerprinter.js',
        exports: ['fingerprintAgent', 'fingerprintAllAgents', 'runTemporalFingerprintAudit'],
      },
      {
        path: './temporal/topic-budget.js',
        exports: [
          'getTopicDistribution',
          'computeTopicBudgets',
          'detectDistributionShift',
          'analyzeTopicCoverage',
          'runTopicBudgetAudit',
        ],
      },
      {
        path: './retrieval/embedding-stability.js',
        exports: [
          'initProjectionMatrix',
          'projectEmbedding',
          'getProjectionMatrix',
          'crossVersionCompare',
          'runEmbeddingStabilityAudit',
        ],
      },
    ],
  },

  // ─── HEARTBEAT ───────────────────────────────────────────────────────────────
  heartbeat: {
    description: 'System health check: DB → memory counts → event flow → process health + background nudge',
    entry: 'jobs/heartbeat.js',
    services: [
      {
        path: './observe/event-ledger.js',
        exports: ['logEvent'],
      },
    ],
  },

  // ─── GOVERNANCE ──────────────────────────────────────────────────────────────
  governance: {
    description: 'Agent governance: profiles → policies → rules → trust routing',
    entry: 'services/orchestration/governance-resolver.js',
    services: [
      {
        path: './orchestration/agent-store.js',
        exports: ['ensureAgent', 'listAgents', 'agents'],
      },
      {
        path: './core/embeddings.js',
        exports: ['getEmbedding'],
      },
      {
        path: './core/providers.js',
        exports: ['providerStatus'],
      },
      {
        path: './core/brain-contract.js',
        exports: ['buildBrainOperatingMemories', 'enforceAimosOperatorBrainLink'],
      },
      {
        path: './orchestration/graph-designer.js',
        exports: ['designTaskGraph'],
      },
      {
        path: './orchestration/capability-probe.js',
        exports: [
          'estimateStateUpdateDepth',
          'observeCapabilityGate',
          'buildCapabilityGateDecision',
          'runWMFProbe',
          'shouldExcludeAgent',
        ],
      },
      {
        path: './orchestration/hypothesis-verifier.js',
        exports: [
          'runHVRLoop',
          'observeHVRDiagnostic',
          'buildSchemaVerificationDiagnostics',
          'buildRuntimeVerificationStateDiagnostics',
          'buildGuessVerifyRefineDiagnostics',
        ],
      },
      {
        path: './orchestration/fallback-resolver.js',
        exports: ['resolveFallback', 'isOrchestrationExhausted', 'getExhaustionReason'],
      },
      {
        path: './observe/routing-monitor.js',
        exports: ['createRoutingCounter', 'incrementRouting', 'shouldTriggerFallback'],
      },
      {
        path: './orchestration/trust-router.js',
        exports: ['routeTask', 'recordSuccess', 'recordFailure'],
      },
    ],
  },
};

function sourceRelative(filePath) {
  return path.relative(SOURCE_ROOT, filePath).split(path.sep).join('/');
}

function lineNumberAt(source, index) {
  return source.slice(0, index).split('\n').length;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function resolveLocalModule(importerPath, specifier) {
  if (!specifier.startsWith('.')) return null;
  const base = path.resolve(path.dirname(importerPath), specifier);
  const candidates = path.extname(base)
    ? [base]
    : [base, `${base}.js`, path.join(base, 'index.js')];
  for (const candidate of candidates) {
    const relative = path.relative(SOURCE_ROOT, candidate);
    if (relative.startsWith('..') || path.isAbsolute(relative)) continue;
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function parseImportBindings(clause) {
  const bindings = [];
  const trimmed = String(clause || '').trim();
  if (!trimmed) return bindings;
  const namespace = trimmed.match(/\*\s+as\s+([A-Za-z_$][\w$]*)/);
  if (namespace) bindings.push({ imported: '*', local: namespace[1] });
  const named = trimmed.match(/\{([\s\S]*?)\}/);
  if (named) {
    for (const item of named[1].split(',')) {
      const match = item.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
      if (match) bindings.push({ imported: match[1], local: match[2] || match[1] });
    }
  }
  const defaultPart = trimmed.split(',')[0].trim();
  if (/^[A-Za-z_$][\w$]*$/.test(defaultPart)) {
    bindings.push({ imported: 'default', local: defaultPart });
  }
  return bindings;
}

function findBindingUsages(source, record) {
  if (!record.bindings.length) return [];
  const masked = `${source.slice(0, record.start)}${' '.repeat(record.end - record.start)}${source.slice(record.end)}`;
  const usages = [];
  for (const binding of record.bindings) {
    const escaped = escapeRegExp(binding.local);
    const callPattern = new RegExp(`\\b${escaped}\\s*(?:\\?\\.)?\\s*\\(`, 'g');
    const constructPattern = new RegExp(`\\bnew\\s+${escaped}\\s*\\(`, 'g');
    const referencePattern = new RegExp(`\\b${escaped}\\b`, 'g');
    let match = constructPattern.exec(masked);
    let kind = 'CONSTRUCT';
    if (!match) {
      match = callPattern.exec(masked);
      kind = 'CALL';
    }
    if (!match) {
      match = referencePattern.exec(masked);
      kind = 'REFERENCE';
    }
    if (match) {
      usages.push({
        imported: binding.imported,
        local: binding.local,
        kind,
        line: lineNumberAt(masked, match.index),
      });
    }
  }
  return usages.sort((left, right) => left.line - right.line || left.local.localeCompare(right.local));
}

function parseLiteralModuleEdges(importerPath) {
  const source = fs.readFileSync(importerPath, 'utf8');
  const records = [];
  const patterns = [
    {
      kind: 'IMPORT',
      regex: /\bimport\s+([\s\S]*?)\s+from\s+(['"])([^'"]+)\2\s*;?/g,
      clause: 1,
      specifier: 3,
    },
    {
      kind: 'REEXPORT',
      regex: /\bexport\s+([\s\S]*?)\s+from\s+(['"])([^'"]+)\2\s*;?/g,
      clause: null,
      specifier: 3,
    },
    {
      kind: 'SIDE_EFFECT_IMPORT',
      regex: /\bimport\s+(['"])([^'"]+)\1\s*;?/g,
      clause: null,
      specifier: 2,
    },
    {
      kind: 'DYNAMIC_IMPORT',
      regex: /\bimport\s*\(\s*(['"])([^'"]+)\1\s*\)/g,
      clause: null,
      specifier: 2,
    },
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.regex.exec(source)) !== null) {
      const targetPath = resolveLocalModule(importerPath, match[pattern.specifier]);
      if (!targetPath) continue;
      const record = {
        importer: sourceRelative(importerPath),
        target: sourceRelative(targetPath),
        kind: pattern.kind,
        import_line: lineNumberAt(source, match.index),
        start: match.index,
        end: match.index + match[0].length,
        bindings: pattern.clause ? parseImportBindings(match[pattern.clause]) : [],
      };
      record.usages = findBindingUsages(source, record);
      record.executable_reference = record.kind === 'SIDE_EFFECT_IMPORT'
        || record.kind === 'DYNAMIC_IMPORT'
        || record.usages.length > 0;
      records.push(record);
    }
  }
  return records.sort((left, right) => left.import_line - right.import_line || left.target.localeCompare(right.target));
}

function buildLiteralImportGraph(entry) {
  const entryPath = path.resolve(SOURCE_ROOT, entry);
  if (!fs.existsSync(entryPath)) throw new Error(`pipeline_entry_missing:${entry}`);
  const queue = [entryPath];
  const visited = new Set();
  const edges = [];
  while (queue.length > 0) {
    const current = queue.shift();
    const relative = sourceRelative(current);
    if (visited.has(relative)) continue;
    visited.add(relative);
    const currentEdges = parseLiteralModuleEdges(current);
    for (const edge of currentEdges) {
      edges.push(edge);
      if (!visited.has(edge.target)) queue.push(path.resolve(SOURCE_ROOT, edge.target));
    }
  }
  return {
    entry,
    literal_closure: [...visited].sort(),
    edges,
  };
}

function buildExecutableClosure(graph) {
  const reached = new Set([graph.entry]);
  const queue = [graph.entry];
  while (queue.length > 0) {
    const importer = queue.shift();
    for (const edge of graph.edges) {
      if (edge.importer !== importer || !edge.executable_reference || reached.has(edge.target)) continue;
      reached.add(edge.target);
      queue.push(edge.target);
    }
  }
  return [...reached].sort();
}

function findExecutablePath(graph, executableSet, target) {
  if (target === graph.entry) return [{ caller: graph.entry, target, kind: 'ENTRY', line: 1, bindings: [] }];
  const queue = [{ node: graph.entry, path: [] }];
  const visited = new Set([graph.entry]);
  while (queue.length > 0) {
    const current = queue.shift();
    for (const edge of graph.edges) {
      if (edge.importer !== current.node || !edge.executable_reference || !executableSet.has(edge.target)) continue;
      const step = {
        caller: edge.importer,
        target: edge.target,
        kind: edge.kind,
        line: edge.import_line,
        bindings: edge.usages,
      };
      const nextPath = [...current.path, step];
      if (edge.target === target) return nextPath;
      if (!visited.has(edge.target)) {
        visited.add(edge.target);
        queue.push({ node: edge.target, path: nextPath });
      }
    }
  }
  return [];
}

function manifestSourcePath(servicePath) {
  return `services/${servicePath.replace(/^\.\//, '')}`;
}

function dispositionFor(pipelineName, servicePath, executable) {
  const key = `${pipelineName}:${servicePath}`;
  if (NON_EXECUTABLE_DISPOSITIONS[key]) return NON_EXECUTABLE_DISPOSITIONS[key];
  if (!executable) return [null, 'unreachable declaration has no explicit disposition'];
  if (DIAGNOSTIC_CONNECTIONS.has(key)) {
    return ['DIAGNOSTIC', 'bounded observation is invoked by the owning pipeline without independent product authority'];
  }
  if (ALWAYS_ACTIVE_CONNECTIONS.has(key)) {
    return ['ACTIVE', 'the owning pipeline invokes this connection on every admitted execution of its relevant stage'];
  }
  return ['CONDITIONAL', 'a real source call site is gated by runtime input, signed policy, state, schedule, or failure branch'];
}

export function buildExecutableTopology() {
  const pipelines = {};
  const records = [];
  const declaredKeys = new Set();
  for (const [pipelineName, pipeline] of Object.entries(PIPELINES)) {
    const graph = buildLiteralImportGraph(pipeline.entry);
    const executableClosure = buildExecutableClosure(graph);
    const executableSet = new Set(executableClosure);
    const declaredPaths = new Set(pipeline.services.map((service) => manifestSourcePath(service.path)));
    for (const service of pipeline.services) {
      const serviceSourcePath = manifestSourcePath(service.path);
      const key = `${pipelineName}:${service.path}`;
      if (declaredKeys.has(key)) throw new Error(`pipeline_service_duplicate:${key}`);
      declaredKeys.add(key);
      const executable = executableSet.has(serviceSourcePath);
      const [disposition, reason] = dispositionFor(pipelineName, service.path, executable);
      const executionPath = executable ? findExecutablePath(graph, executableSet, serviceSourcePath) : [];
      records.push({
        pipeline: pipelineName,
        service: service.path,
        source_path: serviceSourcePath,
        declared_exports: [...service.exports].sort(),
        disposition,
        disposition_reason: reason,
        executable_from_owning_entry: executable,
        execution_path: executionPath,
        activation_predicate: disposition === 'ACTIVE'
          ? 'every admitted execution of the relevant owning stage'
          : disposition === 'CONDITIONAL'
            ? 'runtime input, signed policy, retained state, schedule, or failure branch'
            : disposition === 'DIAGNOSTIC'
              ? 'bounded owning-pipeline observation stage'
              : 'none in the owning pipeline',
        authority: PIPELINE_EXECUTION_CONTRACTS[pipelineName].authority,
        input_schema: PIPELINE_EXECUTION_CONTRACTS[pipelineName].input_schema,
        output_schema: PIPELINE_EXECUTION_CONTRACTS[pipelineName].output_schema,
        terminal_evidence: PIPELINE_EXECUTION_CONTRACTS[pipelineName].terminal_evidence,
      });
    }
    const reachableDeclared = [...declaredPaths].filter((servicePath) => executableSet.has(servicePath)).sort();
    pipelines[pipelineName] = {
      entry: pipeline.entry,
      description: pipeline.description,
      declared: pipeline.services.length,
      executable_declared: reachableDeclared.length,
      non_executable_declared: pipeline.services.length - reachableDeclared.length,
      literal_closure_count: graph.literal_closure.length,
      executable_closure_count: executableClosure.length,
      executable_declared_paths: reachableDeclared,
      non_executable_declared_paths: [...declaredPaths].filter((servicePath) => !executableSet.has(servicePath)).sort(),
      executable_undeclared_paths: executableClosure.filter((servicePath) => servicePath.startsWith('services/') && !declaredPaths.has(servicePath)).sort(),
    };
  }
  records.sort((left, right) => left.pipeline.localeCompare(right.pipeline) || left.service.localeCompare(right.service));
  const dispositionCounts = Object.fromEntries(EXECUTABLE_DISPOSITIONS.map((name) => [name, 0]));
  const dispositionMembers = Object.fromEntries(EXECUTABLE_DISPOSITIONS.map((name) => [name, []]));
  for (const record of records) {
    if (!record.disposition || !Object.hasOwn(dispositionCounts, record.disposition)) continue;
    dispositionCounts[record.disposition] += 1;
    dispositionMembers[record.disposition].push(`${record.pipeline}:${record.service}`);
  }
  const rootBody = {
    schema: 'hom.aimos.executable-topology/v1',
    dispositions: EXECUTABLE_DISPOSITION_DEFINITIONS,
    pipeline_contracts: PIPELINE_EXECUTION_CONTRACTS,
    pipelines,
    records,
  };
  return {
    ...rootBody,
    declared_total: records.length,
    disposition_counts: dispositionCounts,
    disposition_members: dispositionMembers,
    topology_root_sha256: createHash('sha256').update(canonicalJson(rootBody), 'utf8').digest('hex'),
  };
}

export function validateExecutableTopology(topology = buildExecutableTopology()) {
  const failures = [];
  const expectedTotal = Object.values(PIPELINES).reduce((sum, pipeline) => sum + pipeline.services.length, 0);
  if (topology.records.length !== expectedTotal) failures.push('executable_topology_record_count_invalid');
  const seen = new Set();
  for (const record of topology.records) {
    const key = `${record.pipeline}:${record.service}`;
    if (seen.has(key)) failures.push(`executable_topology_duplicate:${key}`);
    seen.add(key);
    if (!EXECUTABLE_DISPOSITIONS.includes(record.disposition)) {
      failures.push(`executable_topology_disposition_invalid:${key}`);
      continue;
    }
    const executableDisposition = ['ACTIVE', 'CONDITIONAL', 'DIAGNOSTIC'].includes(record.disposition);
    if (executableDisposition && (!record.executable_from_owning_entry || record.execution_path.length === 0)) {
      failures.push(`executable_topology_false_executable:${key}`);
    }
    if (!executableDisposition && record.executable_from_owning_entry) {
      failures.push(`executable_topology_false_non_executable:${key}`);
    }
  }
  const counted = Object.values(topology.disposition_counts).reduce((sum, count) => sum + count, 0);
  if (counted !== expectedTotal) failures.push('executable_topology_disposition_partition_invalid');
  if (!/^[0-9a-f]{64}$/.test(topology.topology_root_sha256)) failures.push('executable_topology_root_invalid');
  return {
    valid: failures.length === 0,
    failures,
    expected_total: expectedTotal,
    classified_total: counted,
    topology_root_sha256: topology.topology_root_sha256,
  };
}

/**
 * Validate module availability and the source-derived executable topology.
 * A module that merely imports successfully is not reported as executable.
 */
export async function validatePipelines() {
  const results = [];
  for (const [name, pipeline] of Object.entries(PIPELINES)) {
    for (const svc of pipeline.services) {
      try {
        const mod = await import(svc.path);
        const missing = svc.exports.filter((exportName) => mod[exportName] === undefined);
        results.push(missing.length > 0
          ? { pipeline: name, service: svc.path, status: 'BROKEN', missing }
          : { pipeline: name, service: svc.path, status: 'OK', exports: svc.exports.length });
      } catch (error) {
        results.push({
          pipeline: name,
          service: svc.path,
          status: 'MISSING',
          error: error.message.slice(0, 100),
        });
      }
    }
  }
  const topology = buildExecutableTopology();
  const topologyValidation = validateExecutableTopology(topology);
  const availabilityValid = results.every((result) => result.status === 'OK');
  return {
    valid: availabilityValid && topologyValidation.valid,
    total: results.length,
    ok: results.filter((result) => result.status === 'OK').length,
    results,
    topology,
    topology_validation: topologyValidation,
  };
}
