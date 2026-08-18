// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Infrastructure — imported by the command-center validation surface
// Purpose: Canonical source of truth for critical pipeline connections across
//          runtime pipelines; validated at boot via node -e "import(...)"
// Note: This file governs pipeline wiring. The complete live service inventory
//       lives in architecture-authority.json + hom-architecture-manifest.json.
// ─────────────────────────────────────────────────────────────────────────────

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
    description: 'Memory persistence: request → quality gate → write-validator → rpe-gate → mnemonic-encoder → embedding → DB insert → signed retained-memory epistemic label',
    entry: 'routes/aimos.js',
    services: [
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
    description: 'Memory retrieval: query → native dense/sparse/temporal/entity/QuIM/QMD/HyDE/concept gears → request-bound Canary/quarantine graph admission → one bounded Reconstructed-Graph G2 family channel → central RRF fusion → trust and signed epistemic projection → pre-disclosure Canary/Aladdin closure → decision-bound output receipt; MAGMA remains retained dormant research with no pipeline edge',
    entry: 'services/retrieval/native-recall-pipeline.js',
    services: [
      {
        path: './retrieval/native-recall-pipeline.js',
        exports: ['executeNativeRecall'],
      },
      {
        path: './retrieval/native-recall.js',
        exports: ['resolveNativeRecallAuthority', 'admitNativeRecallCandidates', 'finalizeNativeRecall'],
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
        path: './temporal/timex-normalizer.js',
        exports: ['normalizeTemporalExpressions', 'temporalWindowFromTimex'],
      },
      {
        path: './temporal/temporal-knowledge-base.js',
        exports: ['normalizeTemporalKbFact', 'temporalFactState', 'classifyTemporalRelationArity'],
      },
      {
        path: './temporal/temporal-kg-reasoning.js',
        exports: ['classifyTemporalQuestion', 'makeNaryTemporalFact', 'buildAnswerGraph'],
      },
      {
        path: './temporal/temporal-graph-fusion.js',
        exports: ['createTemporalGraph', 'intervalRelation'],
      },
      {
        path: './temporal/multi-view-timeline.js',
        exports: ['createTimelineState', 'pairwiseTimeScoring', 'transitiveTimelineClosure'],
      },
      {
        path: './temporal/recurrent-event-network.js',
        exports: ['makeTemporalEvent', 'recurrentEventEncode', 'empiricalMarginals'],
      },
      {
        path: './retrieval/interval-algebra-rag.js',
        exports: ['createIntervalEventUnit', 'intervalAwareRetrieve', 'queryTemporalWindow'],
      },
      {
        path: './retrieval/rag-ranking-verification.js',
        exports: ['rankRagPipeline', 'ragvueEvaluate', 'reasonAndVerifyPipeline'],
      },
      {
        path: './temporal/right-time-rag.js',
        exports: ['buildTimeAlignedRuleGraph', 'personalizedTemporalPageRank', 'rightTimeEvidenceScores'],
      },
      {
        path: './retrieval/situated-qa-context.js',
        exports: ['parseSituatedContext', 'situatedContextScore', 'situatedQaEvaluate'],
      },
      {
        path: './temporal/streaming-qa-horizon.js',
        exports: ['streamingQuestionPeriod', 'buildStreamingQaModel', 'streamingHorizonScores'],
      },
      {
        path: './retrieval/step-back-abstraction.js',
        exports: ['deriveStepBackQuestion', 'extractAbstractionPrinciples', 'stepBackRetrieveSignals'],
      },
      {
        path: './temporal/tcomplex-tntcomplex.js',
        exports: ['tcomplexScore', 'tntcomplexScore', 'scoreTemporalKgFacts'],
      },
      {
        path: './temporal/tempcourt-normalization.js',
        exports: ['normalizeCourtDateExpression', 'bioTagTemporalTokens', 'tempCourtEvidenceScores'],
      },
      {
        path: './temporal/tempeval-merge-closure.js',
        exports: ['mergeTempEvalSystemOutputs', 'temporalClosure', 'tempEvalEvidenceScores'],
      },
      {
        path: './temporal/tempquestions-intervals.js',
        exports: ['coarsenAllenRelation', 'detectTemporalQuestion', 'tempQuestionsEvidenceScores'],
      },
      {
        path: './retrieval/time-aware-representation.js',
        exports: ['timeAwareRepresentationScores', 'tcScore', 'totalTimeAwareLoss'],
      },
      {
        path: './temporal/time-aware-lm-kb.js',
        exports: ['temporalPrefixInput', 'routeTemporalExpert', 'timeAwareLmKbScores'],
      },
      {
        path: './retrieval/temporal-abstention-reward.js',
        exports: ['answerReward', 'grpoObjective', 'temporalAbstentionEvidenceScores'],
      },
      {
        path: './temporal/xerte-temporal-kg-explain.js',
        exports: ['buildXerteInferenceGraph', 'segmentSoftmax', 'xerteEvidenceScores'],
      },
      {
        path: './temporal/decoder-only-time-series-forecast.js',
        exports: ['patchSeries', 'msMape', 'timeSeriesForecastScores'],
      },
      {
        path: './retrieval/conversational-event-memory-baseline.js',
        exports: ['buildEventMemoryGraph', 'personalizedPageRank', 'eventMemoryScores'],
      },
      {
        path: './retrieval/aeon-atlas-memory.js',
        exports: ['symmetricInt8Quantize', 'dequantizedSimilarity', 'aeonAtlasScores'],
      },
      {
        path: './retrieval/artificial-hippocampus-memory.js',
        exports: ['ahnGdnUpdate', 'maskedScaledDotProductAttention', 'ahnRecallScores'],
      },
      {
        path: './learning/bayesian-continual-memory.js',
        exports: ['combineGaussianPosterior', 'mesuMeanUpdate', 'bayesianContinualScores'],
      },
      {
        path: './temporal/temporal-semantic-memory.js',
        exports: ['constructDurativeMemories', 'semanticScore', 'temporalSemanticMemoryScores'],
      },
      {
        path: './retrieval/xmemory-beyond-rag.js',
        exports: ['groupingObjective', 'fanoBound', 'xmemoryScores'],
      },
      {
        path: './retrieval/ember-retention-memory.js',
        exports: ['budgetedRetentionSelect', 'f1Score', 'emberRetentionScores'],
      },
      {
        path: './retrieval/contextual-intent-memory.js',
        exports: ['contextualIntentTuple', 'queryIntentFilter', 'contextualIntentScores'],
      },
      {
        path: './retrieval/hmem-hierarchical-reasoning.js',
        exports: ['buildHierarchicalMemory', 'recursiveTopK', 'hmemScores'],
      },
      {
        path: './retrieval/hage-hybrid-agent-graph.js',
        exports: ['buildHageGraph', 'hageTraversalScores', 'hageScores'],
      },
      {
        path: './learning/hebbian-orthogonal-projection.js',
        exports: ['projectionMatrixRls', 'lifStep', 'hebbianProjectionScores'],
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
        path: './retrieval/longmemeval-v2-context-gathering.js',
        exports: ['buildKnowledgePools', 'topMPerQuery', 'longMemEvalV2Scores'],
      },
      {
        path: './retrieval/memaudit-package-audit.js',
        exports: ['semanticCoverageValue', 'branchAndBoundPackageOpt', 'memAuditScores'],
      },
      {
        path: './retrieval/memmachine-retrieval-agent.js',
        exports: ['routeQueryStructure', 'contextualizedEpisodeClusters', 'memMachineScores'],
      },
      {
        path: './retrieval/reconstructed-graph-memory.js',
        exports: ['buildCueTagContentGraph', 'reconstructMemoryState', 'reconstructedGraphMemoryScores'],
      },
      {
        path: './retrieval/mnemis-dual-route-graph.js',
        exports: ['buildMnemisBaseGraph', 'reciprocalRankFusionMnemis', 'mnemisScores'],
      },
      {
        path: './learning/neuroplasticity-stability-control.js',
        exports: ['bernoulliMask', 'dropoutActivation', 'neuroplasticityScores'],
      },
      {
        path: './learning/neurogenesis-catastrophic-forgetting.js',
        exports: ['bmuDistance', 'buildNeurogenesisState', 'neurogenesisScores'],
      },
      {
        path: './retrieval/prism-typed-path-retrieval.js',
        exports: ['buildPrismGraph', 'prismPathCost', 'prismScores'],
      },
      {
        path: './learning/serena-self-regulated-neurogenesis.js',
        exports: ['erkAllocation', 'recencyWeightedEnsemble', 'serenaScores'],
      },
      {
        path: './retrieval/swiftmem-query-aware-index.js',
        exports: ['buildSwiftMemTemporalIndex', 'buildSwiftMemDagTagIndex', 'swiftMemScores'],
      },
      {
        path: './learning/tacos-neuromodulated-consolidation.js',
        exports: ['lifMembraneUpdate', 'tacosWeightUpdate', 'tacosScores'],
      },
      {
        path: './retrieval/ai-hippocampus-memory-system.js',
        exports: ['classifyMemoryParadigm', 'buildHippocampalIndex', 'aiHippocampusScores'],
      },
      {
        path: './learning/synaptic-consolidation-plasticity.js',
        exports: ['hopfieldConnectivityMatrix', 'ewcSurrogateLoss', 'synapticConsolidationScores'],
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

/**
 * Validate every pipeline connection at startup.
 * Dynamically imports every service and checks every named export.
 *
 * NOTE: paths in the manifest are relative to services/pipeline-manifest.js,
 * which is inside the `services/` directory. Dynamic import() resolves relative
 * to the calling module, so paths like './write/quality-gate.js' resolve correctly.
 *
 * Returns { valid: boolean, total: number, ok: number, results: Array }
 */
export async function validatePipelines() {
  const results = [];

  for (const [name, pipeline] of Object.entries(PIPELINES)) {
    for (const svc of pipeline.services) {
      try {
        const mod = await import(svc.path);
        const missing = svc.exports.filter((e) => {
          const val = mod[e];
          // Accept functions, classes, constants (Map, Set, plain objects, strings, etc.)
          return val === undefined;
        });
        if (missing.length > 0) {
          results.push({
            pipeline: name,
            service: svc.path,
            status: 'BROKEN',
            missing,
          });
        } else {
          results.push({
            pipeline: name,
            service: svc.path,
            status: 'OK',
            exports: svc.exports.length,
          });
        }
      } catch (err) {
        results.push({
          pipeline: name,
          service: svc.path,
          status: 'MISSING',
          error: err.message.slice(0, 100),
        });
      }
    }
  }

  const valid = results.every((r) => r.status === 'OK');
  return {
    valid,
    total: results.length,
    ok: results.filter((r) => r.status === 'OK').length,
    results,
  };
}
