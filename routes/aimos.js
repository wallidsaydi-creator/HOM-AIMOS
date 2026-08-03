/**
 * aimos.js — Memory OS API Surface
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ↔ Interacts with: asmr-pipeline.js (Drives hybrid retrieval and answering)
 * 2. ↔ Interacts with: knowledge-gate.js (Receives 'Knowledge Proofs' for RLS authorization)
 * 3. ↔ Interacts with: db/connection.js (Utilizes 'secureQuery' for agent-initiated writes)
 * 4. → Pushes to: security.security_audit_log (Forensic logging of all memory operations)
 * 5. → Calls: curator.js (Detects logical conflicts and reasoning drifts during save)
 *
 * LOGIC GUIDE (High-Integrity Save): If a 'knowledge_proof' is provided, the API
 * switches to the 'agent_runtime' DB user. This user is subject to Row-Level
 * Security (RLS) and is protocol-blocked from deleting any records (Aladdin Law).
 */
import express from 'express';
import { query, withTransaction } from '../db/connection.js';
import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import { getEmbedding } from '../services/core/embeddings.js';
import { logEvent } from '../services/observe/event-ledger.js';
import { runNightlyDream } from '../jobs/nightly-dream.js';
import { claimDirective, completeDirectiveClaim, createDirective } from '../services/core/directive-claims.js';
import { computeRPE } from '../services/write/rpe-gate.js';
import {
  buildOrcaCalibrationReadiness,
  getCalibrationStatus,
  recordCalibrationObservationBatch,
} from '../services/retrieval/recall-calibrator.js';
import { requireCapability } from '../services/security/require-capability.js';
import { buildTrustAlignmentDiagnostics } from '../services/learning/trust-score.js';
import { buildEngramPoolDiagnostics } from '../services/core/concept-graph.js';
import { validateWrite } from '../services/write/write-validator.js';
import { detectEncodingStyle } from '../services/context/mnemonic-encoder.js';
import { monitorRPEGateQuality } from '../services/write/sensible-screening.js';
import { computeSchemaHash, getCachedTransformation, cacheTransformation } from '../services/write/transformation-cache.js';
import { semanticCache } from '../services/caching/semantic-cache.js';
import { enforceVersionOnlyMemoryPolicy } from '../services/governance/aladdin-compliance.js';
import { persistMemory } from '../services/write/persist-memory.js';
import { saveCompactionMemory } from '../services/write/compaction-save.js';
import { savePostCompactionDelivery } from '../services/context/post-compaction-delivery.js';
import { sessionMemoryOwner } from '../services/orchestration/session-memory-owner.js';
import { saveEnvelopeOrchestrator } from '../services/security/save-envelope.js';
import { recallAuthorizationService } from '../services/security/recall-authorization.js';
import {
  resolveNativeRecallAuthority,
} from '../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../services/retrieval/native-recall-pipeline.js';
import { RECALL_SPEED_CONFIG as SPEED_CONFIG } from '../services/retrieval/recall-runtime-config.js';
import { memoryLineageLedger } from '../services/security/memory-lineage.js';
import { getOperatorAgentId, normalizeOperatorAgentId } from '../services/security/system-config-store.js';
import { genesisHashFor } from '../services/security/identity-chain.js';
import { evaluateCanaryWrite } from '../services/security/canary-write-gate.js';
import { appendSecurityDecision, evaluateSecurityContent } from '../services/security/se-gate.js';
import { createIntervalEventUnit, intervalAwareRetrieve, queryTemporalWindow } from '../services/retrieval/interval-algebra-rag.js';
import { ragvueEvaluate, rankRagPipeline, reasonAndVerifyPipeline } from '../services/retrieval/rag-ranking-verification.js';
import { normalizeTemporalExpressions, temporalWindowFromTimex } from '../services/temporal/timex-normalizer.js';
import { classifyTemporalRelationArity, normalizeTemporalKbFact, temporalFactState } from '../services/temporal/temporal-knowledge-base.js';
import { buildAnswerGraph, classifyTemporalQuestion, makeNaryTemporalFact } from '../services/temporal/temporal-kg-reasoning.js';
import { createTemporalGraph, intervalRelation } from '../services/temporal/temporal-graph-fusion.js';
import { createTimelineState, pairwiseTimeScoring, transitiveTimelineClosure } from '../services/temporal/multi-view-timeline.js';
import { empiricalMarginals, makeTemporalEvent, recurrentEventEncode } from '../services/temporal/recurrent-event-network.js';
import { rightTimeEvidenceScores } from '../services/temporal/right-time-rag.js';
import { situatedQaEvaluate } from '../services/retrieval/situated-qa-context.js';
import { streamingHorizonScores } from '../services/temporal/streaming-qa-horizon.js';
import { stepBackRetrieveSignals } from '../services/retrieval/step-back-abstraction.js';
import { scoreTemporalKgFacts } from '../services/temporal/tcomplex-tntcomplex.js';
import { tempCourtEvidenceScores } from '../services/temporal/tempcourt-normalization.js';
import { tempEvalEvidenceScores } from '../services/temporal/tempeval-merge-closure.js';
import { tempQuestionsEvidenceScores } from '../services/temporal/tempquestions-intervals.js';
import { timeAwareRepresentationScores } from '../services/retrieval/time-aware-representation.js';
import { timeAwareLmKbScores } from '../services/temporal/time-aware-lm-kb.js';
import { temporalAbstentionEvidenceScores } from '../services/retrieval/temporal-abstention-reward.js';
import { xerteEvidenceScores } from '../services/temporal/xerte-temporal-kg-explain.js';
import { timeSeriesForecastScores } from '../services/temporal/decoder-only-time-series-forecast.js';
import { eventMemoryScores } from '../services/retrieval/conversational-event-memory-baseline.js';
import { aeonAtlasScores } from '../services/retrieval/aeon-atlas-memory.js';
import { ahnRecallScores } from '../services/retrieval/artificial-hippocampus-memory.js';
import { bayesianContinualScores } from '../services/learning/bayesian-continual-memory.js';
import { temporalSemanticMemoryScores } from '../services/temporal/temporal-semantic-memory.js';
import { xmemoryScores } from '../services/retrieval/xmemory-beyond-rag.js';
import { emberRetentionScores } from '../services/retrieval/ember-retention-memory.js';
import { contextualIntentScores } from '../services/retrieval/contextual-intent-memory.js';
import { hmemScores } from '../services/retrieval/hmem-hierarchical-reasoning.js';
import { hageScores } from '../services/retrieval/hage-hybrid-agent-graph.js';
import { hebbianProjectionScores } from '../services/learning/hebbian-orthogonal-projection.js';
import { hindsightMemoryGraphScores } from '../services/retrieval/hindsight-memory-graph.js';
import { hingeMemScores } from '../services/retrieval/hingemem-boundary-hypergraph.js';
import { longMemEvalV2Scores } from '../services/retrieval/longmemeval-v2-context-gathering.js';
import { memAuditScores } from '../services/retrieval/memaudit-package-audit.js';
import { memMachineScores } from '../services/retrieval/memmachine-retrieval-agent.js';
import { reconstructedGraphMemoryScores } from '../services/retrieval/reconstructed-graph-memory.js';
import { mnemisScores } from '../services/retrieval/mnemis-dual-route-graph.js';
import { neuroplasticityScores } from '../services/learning/neuroplasticity-stability-control.js';
import { neurogenesisScores } from '../services/learning/neurogenesis-catastrophic-forgetting.js';
import { prismScores } from '../services/retrieval/prism-typed-path-retrieval.js';
import { serenaScores } from '../services/learning/serena-self-regulated-neurogenesis.js';
import { swiftMemScores } from '../services/retrieval/swiftmem-query-aware-index.js';
import { tacosScores } from '../services/learning/tacos-neuromodulated-consolidation.js';
import { aiHippocampusScores } from '../services/retrieval/ai-hippocampus-memory-system.js';
import { synapticConsolidationScores } from '../services/learning/synaptic-consolidation-plasticity.js';
import { buildLifelongMemoryContract } from '../services/context/context-renewal.js';
import { buildSpeculativeVerificationContract, META_ACTIONS } from '../services/orchestration/meta-controller.js';
import { buildScratPipelineStatus } from '../services/orchestration/explore-exploit-loop.js';
import { buildOntologyAwarePatternMap } from '../services/observe/architecture-registry.js';
import { buildTemporalHomeostasisDiagnostics } from '../services/observe/retrieval-drift-monitor.js';
import { buildOscillatorySTDPStatus } from '../services/learning/stdp-kernel.js';
import { getAgentPsychometricStatus } from '../services/learning/agent-learning.js';
import { buildTurnAdaptiveBudgetStatus } from '../services/observe/energy-budget.js';
import { buildLatentLookaheadStatus } from '../services/observe/agent-trace.js';
import { buildEvolveRouterStatus } from '../services/observe/routing-monitor.js';
import { buildEpistemicBlindingStatus } from '../services/learning/epistemic-vigilance.js';
import { buildAgscStatus, buildKeyedPrefetchStatus, buildNiyamaServingStatus, buildRobustLengthStatus, buildTokenScaleStatus } from '../services/runtime/serving-control.js';
import {
  buildKvCacheAndLayoutPlan,
  buildLocalMemoryPlacementPlan,
  buildLpcSmSmallModelPlan,
  buildMicroBottleneckDiagnostic,
  buildMoEExpertSchedulingPlan,
  buildNexusIoOffloadPlan,
  buildTurboQuantReadiness,
  buildWave5LocalInferenceStatus,
} from '../services/runtime/local-inference-control.js';



// ─── SPEED CONFIG — Phase 1-2 toggles (default OFF) ──────────────────────────
// Persistent configuration is read from the signed configuration ledgers at
// each owning subsystem; these defaults deliberately do not read environment.


























const NATIVE_RECALL_PAPER_ACTIVATION = Object.freeze([
  '2010_SEMEVAL_StroetgenGertz_HeidelTime.pdf',
  'A Multi-Axis Annotation Scheme for Event Temporal Relations.pdf',
  'An Annotation Framework for Dense Event Ordering.pdf',
  'Can Language Models Serve as Temporal Knowledge Bases?.pdf',
  'Complex Temporal Question Answering on Knowledge Graphs.pdf',
  'Evaluating Memory in LLM Agents via Incremental Multi-Turn Interactions.pdf',
  'Fusing Temporal Graphs .pdf',
  'HyTE.pdf',
  'IA-RAG.pdf',
  'Mitigating LLM Hallucinations through Domain-Grounded Tiered Retrieval.pdf',
  'MTGER- Multi-view.pdf',
  'NARRATIVETIME- Dense Temporal Annotation on a Timeline.pdf',
  'Question Answering Over Temporal Knowledge Graphs.pdf',
  'RAGVUE.pdf',
  'RankRAG.pdf',
  'Reason and Verify.pdf',
  'Recurrent Event Network.pdf',
  'Retrieving, Rethinking and Revising.pdf',
  'RIGHT ANSWER AT THE RIGHT TIME.pdf',
  'SITUATEDQA.pdf',
  'SUTIME.pdf',
  'StreamingQA.pdf',
  'TAKE A STEP BACK- EVOKING REASONING VIA ABSTRACTION IN LARGE LANGUAGE MODELS.pdf',
  'TComplEx : TNTComplEx.pdf',
  'TempCourt.pdf',
  'TempEval-3.pdf',
  'TempQuestions.pdf',
  'Time-Aware Representation.pdf',
  'Time-Aware_Language_Models_as_Temporal_Knowledge_B.pdf',
  'WHEN SILENCE IS GOLDEN- CAN LLMS LEARN TO ABSTAIN IN TEMPORAL QA AND BEYOND?.pdf',
  'xERTE- Explainable Reasoning on Temporal Knowledge Graphs.pdf',
  'A DECODER-ONLY FOUNDATION MODEL FOR TIME-SERIES FORECASTING.pdf',
  'A Simple Yet Strong Baseline for Long-Term Conversational Memory of LLM Agents.pdf',
  'Aeon.pdf',
  'Artificial Hippocampus Networks for Efficient Long-Context Modeling.pdf',
  'Bayesian continual learning and forgetting in neural networks.pdf',
  'Beyond Dialogue Time- Temporal Semantic Memory for Personalized LLM Agents.pdf',
  'Beyond RAG for Agent Memory.pdf',
  'EMBER.pdf',
  'Grounding Agent Memory in Contextual Intent.pdf',
  'H-MEM- Hierarchical Memory for High-Efficiency Long-Term Reasoning in LLM Agents.pdf',
  'HAGE.pdf',
  'HEBBIAN LEARNING BASED ORTHOGONAL PROJECTION FOR CONTINUAL LEARNING OF SPIKING NEURAL NETWORKS.pdf',
  'HINDSIGHT IS 20:20.pdf',
  'HingeMem.pdf',
  'LongMemEval-V2.pdf',
  'MEMAUDIT.pdf',
  'MemMachine.pdf',
  'Memory is Reconstructed, Not Retrieved- Graph Memory for LLM Agents.pdf',
  'Mnemis- Dual-Route Retrieval on Hierarchical Graphs for Long-Term LLM Memory.pdf',
  'Neuroplasticity in Artificial Intelligence.pdf',
  'On the role of neurogenesis in overcoming catastrophic forgetting.pdf',
  'PRISM.pdf',
  'SELF-REGULATED NEUROGENESIS FOR ONLINE DATA-INCREMENTAL LEARNING.pdf',
  'SwiftMem.pdf',
  'TACOS.pdf',
  'The AI Hippocampus- How Far are We From Human Memory?.pdf',
  'Theories of synaptic memory consolidation and intelligent plasticity for continual learning.pdf',
]);

function clampNativePaperScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function nativePaperMemoryText(memory = {}) {
  return [memory.key, memory.scope, memory.memory_type, memory.source, memory.value]
    .filter(Boolean)
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function nativePaperDateMs(value, fallback = NaN) {
  if (value === -Infinity || value === Infinity) return value;
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : fallback;
}

function nativePaperIsoDate(value) {
  const ms = nativePaperDateMs(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function nativePaperDayIndex(value) {
  const ms = nativePaperDateMs(value);
  return Number.isFinite(ms) ? Math.floor(ms / 86400000) : 0;
}

function nativePaperQueryWindow(queryText = '', queryTimexes = [], referenceDate = new Date()) {
  const algebra = queryTemporalWindow(queryText, { referenceDate });
  if (Number.isFinite(algebra.start) || Number.isFinite(algebra.end)) {
    return {
      start: algebra.start,
      end: algebra.end,
      source: algebra.source,
      bounded: Number.isFinite(algebra.start) && Number.isFinite(algebra.end),
    };
  }
  for (const timex of queryTimexes) {
    const window = temporalWindowFromTimex(timex);
    if (!window) continue;
    const start = nativePaperDateMs(window.from);
    const end = nativePaperDateMs(window.to);
    if (Number.isFinite(start) && Number.isFinite(end)) {
      return { start, end, source: `timex:${timex.ruleId || timex.type}`, bounded: true };
    }
  }
  return { start: -Infinity, end: Infinity, source: 'unbounded', bounded: false };
}

function nativePaperWindowOverlapScore(interval = {}, window = {}) {
  if (!window?.bounded) return 0;
  const start = Number(interval.start);
  const end = Number(interval.end);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return 0;
  if (end < window.start || start > window.end) return 0;
  const overlap = Math.max(0, Math.min(end, window.end) - Math.max(start, window.start));
  const width = Math.max(1, Math.min(end - start || 1, window.end - window.start || 1));
  return clampNativePaperScore(overlap / width || 1);
}

function nativePaperMemoryState(memory = {}, index = 0, referenceDate = new Date()) {
  const documentTime = nativePaperIsoDate(memory.created_at) || referenceDate;
  const body = nativePaperMemoryText(memory);
  const normalized = normalizeTemporalExpressions(body, { documentTime });
  const timexWindows = normalized.timexes
    .map(temporalWindowFromTimex)
    .filter(Boolean)
    .map((window) => ({
      from: nativePaperDateMs(window.from),
      to: nativePaperDateMs(window.to),
      granularity: window.granularity,
    }))
    .filter((window) => Number.isFinite(window.from) && Number.isFinite(window.to));
  const createdMs = nativePaperDateMs(memory.created_at, nativePaperDateMs(referenceDate));
  const firstWindow = timexWindows[0] || null;
  const start = firstWindow?.from ?? createdMs;
  const end = firstWindow?.to ?? createdMs;
  const id = String(memory.id || memory.key || `memory:${index + 1}`);
  return {
    id,
    index,
    memory,
    text: body,
    timexes: normalized.timexes,
    interval: {
      start: Number.isFinite(start) ? start : createdMs,
      end: Number.isFinite(end) ? end : createdMs,
      bounded: Number.isFinite(start) && Number.isFinite(end),
    },
    event: createIntervalEventUnit({
      id,
      session: memory.session_id || memory.source || '',
      content: body.slice(0, 1200),
      start: Number.isFinite(start) ? new Date(start).toISOString() : memory.created_at,
      end: Number.isFinite(end) ? new Date(end).toISOString() : memory.created_at,
      factuality: memory.is_correction === true ? 1 : 1,
      source: memory.source || memory.memory_type || '',
      metadata: { key: memory.key, memory_type: memory.memory_type },
    }),
  };
}

function nativePaperTemporalRelations(states = []) {
  const sorted = [...states]
    .filter((row) => Number.isFinite(row.interval.start))
    .sort((a, b) => a.interval.start - b.interval.start || a.index - b.index)
    .slice(0, 48);
  const relations = [];
  for (let i = 0; i + 1 < sorted.length; i += 1) {
    relations.push({
      from: sorted[i].id,
      to: sorted[i + 1].id,
      relation: sorted[i].interval.end <= sorted[i + 1].interval.start ? 'BEFORE' : 'OVERLAP',
    });
  }
  return relations;
}

function nativePaperActivationWeight(queryUnderstanding = {}) {
  if (hasTemporalRecallAxis(queryUnderstanding)) return 0.28;
  if (hasAggregateRecallAxis(queryUnderstanding) || queryUnderstanding.intent === 'current_truth') return 0.24;
  if (hasEntityRecallAxis(queryUnderstanding)) return 0.20;
  return 0.16;
}

export function applyNativePaperRecallOperators({
  queryText = '',
  memories = [],
  queryUnderstanding = {},
  referenceDate = new Date(),
} = {}) {
  void queryText;
  void memories;
  void queryUnderstanding;
  void referenceDate;
  return {
    active: false,
    applied: false,
    retired: true,
    reason: 'retired_monotone_positive_only_stack',
    papers_active: NATIVE_RECALL_PAPER_ACTIVATION.length,
    papers: NATIVE_RECALL_PAPER_ACTIVATION,
    replacement: 'services/observe/calibrated-rank-composition.js',
    score_contract: {
      type: 'retired_bounded_monotone_additive_boost',
      formula: "s' = s + alpha * operator * (1 - s)",
      rejected_reason: 'positive_only_boosts_compress_scores_and_hide_rank_discrimination',
      replacement_formula: 'p(relevant|x)=sigma(b + sum_i w_i*x_i)',
      native_hot_path: false,
    },
  };

  if (!Array.isArray(memories) || memories.length === 0) {
    return {
      active: true,
      applied: false,
      reason: 'no_memories',
      papers_active: NATIVE_RECALL_PAPER_ACTIVATION.length,
      papers: NATIVE_RECALL_PAPER_ACTIVATION,
    };
  }

  const alpha = nativePaperActivationWeight(queryUnderstanding);
  const queryTimex = normalizeTemporalExpressions(queryText, { documentTime: referenceDate });
  const queryWindow = nativePaperQueryWindow(queryText, queryTimex.timexes, referenceDate);
  const states = memories.map((memory, index) => nativePaperMemoryState(memory, index, referenceDate));
  const contexts = states.map((state) => ({
    id: state.id,
    text: state.text,
    value: state.text,
    memory: state.memory,
    score: state.memory.rerank_score ?? state.memory._raw_rerank ?? 0,
    rerank_score: state.memory.rerank_score ?? state.memory._raw_rerank ?? 0,
  }));

  const intervalState = intervalAwareRetrieve({
    query: queryText,
    events: states.map((state) => state.event),
    referenceDate,
    options: { tauSem: 0.25, minClusterSize: 2, maxLevels: 3, q: 24 },
  });
  const intervalMax = Math.max(1e-9, ...intervalState.target_events.map((event) => Number(event.score) || 0));
  const intervalById = new Map(intervalState.target_events.map((event) => [String(event.id), clampNativePaperScore((Number(event.score) || 0) / intervalMax)]));

  const rankRag = rankRagPipeline({
    query: queryText,
    retrievedContexts: contexts,
    topN: Math.min(contexts.length, 120),
    topK: Math.min(8, Math.max(1, contexts.length)),
  });
  const rankById = new Map(rankRag.ranked_contexts.map((context) => [String(context.id), clampNativePaperScore(context.relevance_score)]));

  const ragvue = ragvueEvaluate({ question: queryText, contexts });
  const reasonVerify = reasonAndVerifyPipeline({
    query: queryText,
    documents: contexts,
    rationale: contexts.slice(0, 5).map((context) => context.text).join(' '),
  });

  const timelineRelations = nativePaperTemporalRelations(states);
  const timeline = createTimelineState({
    events: states.map((state) => ({ id: state.id, text: state.text.slice(0, 240), start: state.interval.start, end: state.interval.end })),
    timexes: queryTimex.timexes,
  });
  const timelineClosure = transitiveTimelineClosure(timelineRelations);
  const timeScores = pairwiseTimeScoring(timeline.events.slice(0, 32));

  const temporalGraph = createTemporalGraph({
    events: states.slice(0, 48).map((state) => ({ id: state.id, text: state.text.slice(0, 240) })),
    timexes: queryTimex.timexes,
    edges: timelineRelations.map((relation, index) => ({
      id: `native-paper-recall:${index + 1}`,
      from: relation.from,
      to: relation.to,
      relation: String(relation.relation).toLowerCase(),
    })),
    questionTime: queryTimex.timexes[0] || null,
  });

  const temporalFacts = states.map((state) => makeNaryTemporalFact({
    subject: state.memory.source || state.memory.memory_type || 'memory',
    predicate: state.memory.memory_type || 'mentions',
    object: state.memory.key || state.id,
    startDate: nativePaperIsoDate(state.memory.created_at) || '',
    endDate: nativePaperIsoDate(state.memory.created_at) || '',
    qualifiers: { memory_id: state.memory.id || null },
  }));
  const temporalKbFacts = states.map((state) => normalizeTemporalKbFact({
    subject: state.memory.source || state.memory.memory_type || 'memory',
    predicate: state.memory.memory_type || 'mentions',
    object: state.memory.key || state.id,
    start_time: nativePaperIsoDate(state.memory.created_at)?.slice(0, 10) || '',
    end_time: nativePaperIsoDate(state.memory.created_at)?.slice(0, 10) || '',
  }));
  const temporalKg = buildAnswerGraph({
    questionRelevantFacts: temporalFacts.map((fact, index) => ({ ...fact, score: rankById.get(states[index].id) || 0 })),
    temporalFacts: temporalFacts.map((fact, index) => ({ ...fact, score: nativePaperWindowOverlapScore(states[index].interval, queryWindow) })),
  });
  const arity = classifyTemporalRelationArity(temporalKbFacts);
  const recurrentEvents = states.map((state) => makeTemporalEvent({
    subject: state.memory.source || state.memory.memory_type || 'memory',
    relation: state.memory.memory_type || 'mentions',
    object: state.memory.key || state.id,
    time: nativePaperDayIndex(state.memory.created_at),
    metadata: { memory_id: state.memory.id || null },
  }));
  const recurrent = recurrentEventEncode({ events: recurrentEvents });
  const recurrentMarginals = empiricalMarginals(recurrentEvents);
  const temporalQuestionCategory = classifyTemporalQuestion(queryText);
  const temporalStateSample = temporalKbFacts[0] ? temporalFactState(temporalKbFacts[0]) : null;
  const rightTime = rightTimeEvidenceScores({ queryText, states, referenceDate });
  const situatedQa = situatedQaEvaluate({ queryText, contexts, referenceDate });
  const streamingQa = streamingHorizonScores({ queryText, states, referenceDate });
  const stepBack = stepBackRetrieveSignals({ queryText, contexts });
  const tcomplex = scoreTemporalKgFacts({ queryText, facts: temporalFacts, states, referenceDate });
  const tempCourt = tempCourtEvidenceScores({ queryText, states, referenceDate });
  const tempEval = tempEvalEvidenceScores({ queryText, states });
  const tempQuestions = tempQuestionsEvidenceScores({ queryText, states, referenceDate });
  const timeAwareRepresentation = timeAwareRepresentationScores({ queryText, contexts, states, referenceDate });
  const timeAwareLmKb = timeAwareLmKbScores({ queryText, states, referenceDate });
  const temporalAbstention = temporalAbstentionEvidenceScores({ queryText, states, contexts, facts: temporalFacts });
  const xerte = xerteEvidenceScores({ queryText, states, facts: temporalFacts, referenceDate });
  const timeSeriesForecast = timeSeriesForecastScores({ queryText, states, referenceDate });
  const eventMemory = eventMemoryScores({ queryText, states });
  const aeonAtlas = aeonAtlasScores({ queryText, contexts });
  const artificialHippocampus = ahnRecallScores({ queryText, states, contexts });
  const bayesianContinual = bayesianContinualScores({ queryText, states });
  const temporalSemanticMemory = temporalSemanticMemoryScores({ queryText, states, referenceDate });
  const beyondRagXmemory = xmemoryScores({ queryText, states });
  const emberRetention = emberRetentionScores({ queryText, states });
  const contextualIntent = contextualIntentScores({ queryText, states });
  const hmem = hmemScores({ queryText, states });
  const hage = hageScores({ queryText, states, referenceDate });
  const hebbianProjection = hebbianProjectionScores({ queryText, states });
  const hindsightGraph = hindsightMemoryGraphScores({ queryText, states, referenceDate });
  const hingeMem = hingeMemScores({ queryText, states, referenceDate });
  const longMemEvalV2 = longMemEvalV2Scores({ queryText, states, referenceDate });
  const memAudit = memAuditScores({ queryText, states, referenceDate });
  const memMachine = memMachineScores({ queryText, states, referenceDate });
  const reconstructedGraphMemory = reconstructedGraphMemoryScores({ queryText, states, referenceDate });
  const mnemis = mnemisScores({ queryText, states, referenceDate });
  const neuroplasticity = neuroplasticityScores({ queryText, states, referenceDate });
  const neurogenesis = neurogenesisScores({ queryText, states, referenceDate });
  const prism = prismScores({ queryText, states, referenceDate });
  const serena = serenaScores({ queryText, states, referenceDate });
  const swiftMem = swiftMemScores({ queryText, states, referenceDate });
  const tacos = tacosScores({ queryText, states, referenceDate });
  const aiHippocampus = aiHippocampusScores({ queryText, states, referenceDate });
  const synapticConsolidation = synapticConsolidationScores({ queryText, states, referenceDate });

  const isTemporal = hasTemporalRecallAxis(queryUnderstanding);
  const isCurrent = queryUnderstanding.intent === 'current_truth' || Boolean(queryUnderstanding.features?.asks_current_truth);
  let boosted = 0;
  for (const state of states) {
    const memory = state.memory;
    const id = state.id;
    const prior = clampNativePaperScore(memory.rerank_score ?? memory._raw_rerank ?? memory.score ?? 0);
    const rankScore = rankById.get(id) || 0;
    const intervalScore = intervalById.get(id) || 0;
    const windowScore = nativePaperWindowOverlapScore(state.interval, queryWindow);
    const temporalTokenScore = state.timexes.length ? 1 : 0;
    const graphRelationScore = timelineClosure.some((edge) => edge.from === id || edge.to === id) ? 1 : 0;
    const currentStateScore = isCurrent
      ? clampNativePaperScore(1 / (1 + Math.max(0, nativePaperDayIndex(referenceDate) - nativePaperDayIndex(memory.created_at))))
      : 0;
    const baseOperator = clampNativePaperScore(
      (rankScore * 0.34)
      + (intervalScore * 0.22)
      + (windowScore * (isTemporal ? 0.20 : 0.10))
      + (temporalTokenScore * (isTemporal ? 0.10 : 0.06))
      + (graphRelationScore * 0.06)
      + (currentStateScore * 0.08)
    );
    const rightTimeScore = rightTime.scoreById.get(id) || 0;
    const situatedScore = situatedQa.scoreById.get(id) || 0;
    const streamingScore = streamingQa.scoreById.get(id) || 0;
    const stepBackScore = stepBack.scoreById.get(id) || 0;
    const tcomplexScore = tcomplex.scoreById.get(id) || 0;
    const tempCourtScore = tempCourt.scoreById.get(id) || 0;
    const tempEvalScore = tempEval.scoreById.get(id) || 0;
    const tempQuestionsScore = tempQuestions.scoreById.get(id) || 0;
    const timeAwareRepresentationScore = timeAwareRepresentation.scoreById.get(id) || 0;
    const timeAwareLmKbScore = timeAwareLmKb.scoreById.get(id) || 0;
    const temporalAbstentionScore = temporalAbstention.scoreById.get(id) || 0;
    const xerteScore = xerte.scoreById.get(id) || 0;
    const timeSeriesForecastScore = timeSeriesForecast.scoreById.get(id) || 0;
    const eventMemoryScore = eventMemory.scoreById.get(id) || 0;
    const aeonAtlasScore = aeonAtlas.scoreById.get(id) || 0;
    const artificialHippocampusScore = artificialHippocampus.scoreById.get(id) || 0;
    const bayesianContinualScore = bayesianContinual.scoreById.get(id) || 0;
    const temporalSemanticMemoryScore = temporalSemanticMemory.scoreById.get(id) || 0;
    const beyondRagXmemoryScore = beyondRagXmemory.scoreById.get(id) || 0;
    const emberRetentionScore = emberRetention.scoreById.get(id) || 0;
    const contextualIntentScore = contextualIntent.scoreById.get(id) || 0;
    const hmemScore = hmem.scoreById.get(id) || 0;
    const hageScore = hage.scoreById.get(id) || 0;
    const hebbianProjectionScore = hebbianProjection.scoreById.get(id) || 0;
    const hindsightGraphScore = hindsightGraph.scoreById.get(id) || 0;
    const hingeMemScore = hingeMem.scoreById.get(id) || 0;
    const longMemEvalV2Score = longMemEvalV2.scoreById.get(id) || 0;
    const memAuditScore = memAudit.scoreById.get(id) || 0;
    const memMachineScore = memMachine.scoreById.get(id) || 0;
    const reconstructedGraphMemoryScore = reconstructedGraphMemory.scoreById.get(id) || 0;
    const mnemisScore = mnemis.scoreById.get(id) || 0;
    const neuroplasticityScore = neuroplasticity.scoreById.get(id) || 0;
    const neurogenesisScore = neurogenesis.scoreById.get(id) || 0;
    const prismScore = prism.scoreById.get(id) || 0;
    const serenaScore = serena.scoreById.get(id) || 0;
    const swiftMemScore = swiftMem.scoreById.get(id) || 0;
    const tacosScore = tacos.scoreById.get(id) || 0;
    const aiHippocampusScore = aiHippocampus.scoreById.get(id) || 0;
    const synapticConsolidationScore = synapticConsolidation.scoreById.get(id) || 0;
    const batch2Operator = clampNativePaperScore(
      (rightTimeScore * 0.24)
      + (situatedScore * 0.18)
      + (streamingScore * 0.18)
      + (stepBackScore * 0.22)
      + (tcomplexScore * 0.18)
    );
    const previous24Operator = Math.max(
      baseOperator,
      clampNativePaperScore((baseOperator * 0.78) + (batch2Operator * 0.22))
    );
    const batch3Operator = clampNativePaperScore(
      (tempCourtScore * 0.18)
      + (tempEvalScore * 0.18)
      + (tempQuestionsScore * 0.22)
      + (timeAwareRepresentationScore * 0.22)
      + (timeAwareLmKbScore * 0.20)
    );
    const previous29Operator = Math.max(
      previous24Operator,
      clampNativePaperScore((previous24Operator * 0.80) + (batch3Operator * 0.20))
    );
    const batch4Operator = clampNativePaperScore(
      (temporalAbstentionScore * 0.18)
      + (xerteScore * 0.22)
      + (timeSeriesForecastScore * 0.18)
      + (eventMemoryScore * 0.24)
      + (aeonAtlasScore * 0.18)
    );
    const previous34Operator = Math.max(
      previous29Operator,
      clampNativePaperScore((previous29Operator * 0.82) + (batch4Operator * 0.18))
    );
    const batch5Operator = clampNativePaperScore(
      (artificialHippocampusScore * 0.20)
      + (bayesianContinualScore * 0.18)
      + (temporalSemanticMemoryScore * 0.22)
      + (beyondRagXmemoryScore * 0.25)
      + (emberRetentionScore * 0.15)
    );
    const previous39Operator = Math.max(
      previous34Operator,
      clampNativePaperScore((previous34Operator * 0.84) + (batch5Operator * 0.16))
    );
    const batch6Operator = clampNativePaperScore(
      (contextualIntentScore * 0.22)
      + (hmemScore * 0.16)
      + (hageScore * 0.18)
      + (hebbianProjectionScore * 0.20)
      + (hindsightGraphScore * 0.24)
    );
    const previous44Operator = Math.max(
      previous39Operator,
      clampNativePaperScore((previous39Operator * 0.86) + (batch6Operator * 0.14))
    );
    const batch7Operator = clampNativePaperScore(
      (hingeMemScore * 0.22)
      + (longMemEvalV2Score * 0.16)
      + (memAuditScore * 0.20)
      + (memMachineScore * 0.20)
      + (reconstructedGraphMemoryScore * 0.22)
    );
    const previous49Operator = Math.max(
      previous44Operator,
      clampNativePaperScore((previous44Operator * 0.88) + (batch7Operator * 0.12))
    );
    const batch8Operator = clampNativePaperScore(
      (mnemisScore * 0.22)
      + (neuroplasticityScore * 0.16)
      + (neurogenesisScore * 0.18)
      + (prismScore * 0.24)
      + (serenaScore * 0.20)
    );
    const previous54Operator = Math.max(
      previous49Operator,
      clampNativePaperScore((previous49Operator * 0.90) + (batch8Operator * 0.10))
    );
    const batch9Operator = clampNativePaperScore(
      (swiftMemScore * 0.26)
      + (tacosScore * 0.20)
      + (aiHippocampusScore * 0.24)
      + (synapticConsolidationScore * 0.30)
    );
    const operator = Math.max(
      previous54Operator,
      clampNativePaperScore((previous54Operator * 0.92) + (batch9Operator * 0.08))
    );
    const next = clampNativePaperScore(prior + ((1 - prior) * alpha * operator));
    memory.native_paper_recall = {
      prior_rerank: Number(prior.toFixed(6)),
      operator_score: Number(operator.toFixed(6)),
      base_operator_score: Number(baseOperator.toFixed(6)),
      previous24_operator_score: Number(previous24Operator.toFixed(6)),
      previous29_operator_score: Number(previous29Operator.toFixed(6)),
      previous34_operator_score: Number(previous34Operator.toFixed(6)),
      previous39_operator_score: Number(previous39Operator.toFixed(6)),
      previous44_operator_score: Number(previous44Operator.toFixed(6)),
      previous49_operator_score: Number(previous49Operator.toFixed(6)),
      previous54_operator_score: Number(previous54Operator.toFixed(6)),
      batch2_operator_score: Number(batch2Operator.toFixed(6)),
      batch3_operator_score: Number(batch3Operator.toFixed(6)),
      batch4_operator_score: Number(batch4Operator.toFixed(6)),
      batch5_operator_score: Number(batch5Operator.toFixed(6)),
      batch6_operator_score: Number(batch6Operator.toFixed(6)),
      batch7_operator_score: Number(batch7Operator.toFixed(6)),
      batch8_operator_score: Number(batch8Operator.toFixed(6)),
      batch9_operator_score: Number(batch9Operator.toFixed(6)),
      alpha,
      components: {
        rankrag: Number(rankScore.toFixed(6)),
        interval_algebra: Number(intervalScore.toFixed(6)),
        temporal_window: Number(windowScore.toFixed(6)),
        timex: Number(temporalTokenScore.toFixed(6)),
        temporal_graph: Number(graphRelationScore.toFixed(6)),
        current_state: Number(currentStateScore.toFixed(6)),
        right_time_rule_graph: Number(rightTimeScore.toFixed(6)),
        situated_context: Number(situatedScore.toFixed(6)),
        streaming_horizon: Number(streamingScore.toFixed(6)),
        step_back_abstraction: Number(stepBackScore.toFixed(6)),
        tcomplex_tntcomplex: Number(tcomplexScore.toFixed(6)),
        tempcourt_normalization: Number(tempCourtScore.toFixed(6)),
        tempeval_merge_closure: Number(tempEvalScore.toFixed(6)),
        tempquestions_interval: Number(tempQuestionsScore.toFixed(6)),
        time_aware_representation: Number(timeAwareRepresentationScore.toFixed(6)),
        time_aware_lm_kb: Number(timeAwareLmKbScore.toFixed(6)),
        temporal_abstention_reward: Number(temporalAbstentionScore.toFixed(6)),
        xerte_temporal_kg: Number(xerteScore.toFixed(6)),
        decoder_only_time_series: Number(timeSeriesForecastScore.toFixed(6)),
        conversational_event_memory: Number(eventMemoryScore.toFixed(6)),
        aeon_atlas_memory: Number(aeonAtlasScore.toFixed(6)),
        artificial_hippocampus_network: Number(artificialHippocampusScore.toFixed(6)),
        bayesian_continual_memory: Number(bayesianContinualScore.toFixed(6)),
        temporal_semantic_memory: Number(temporalSemanticMemoryScore.toFixed(6)),
        xmemory_beyond_rag: Number(beyondRagXmemoryScore.toFixed(6)),
        ember_retention_memory: Number(emberRetentionScore.toFixed(6)),
        contextual_intent_memory: Number(contextualIntentScore.toFixed(6)),
        hmem_hierarchical_reasoning: Number(hmemScore.toFixed(6)),
        hage_hybrid_agent_graph: Number(hageScore.toFixed(6)),
        hebbian_orthogonal_projection: Number(hebbianProjectionScore.toFixed(6)),
        hindsight_memory_graph: Number(hindsightGraphScore.toFixed(6)),
        hingemem_boundary_hypergraph: Number(hingeMemScore.toFixed(6)),
        longmemeval_v2_context_gathering: Number(longMemEvalV2Score.toFixed(6)),
        memaudit_package_audit: Number(memAuditScore.toFixed(6)),
        memmachine_retrieval_agent: Number(memMachineScore.toFixed(6)),
        reconstructed_graph_memory: Number(reconstructedGraphMemoryScore.toFixed(6)),
        mnemis_dual_route_graph: Number(mnemisScore.toFixed(6)),
        neuroplasticity_stability_control: Number(neuroplasticityScore.toFixed(6)),
        neurogenesis_catastrophic_forgetting: Number(neurogenesisScore.toFixed(6)),
        prism_typed_path_retrieval: Number(prismScore.toFixed(6)),
        serena_self_regulated_neurogenesis: Number(serenaScore.toFixed(6)),
        swiftmem_query_aware_index: Number(swiftMemScore.toFixed(6)),
        tacos_neuromodulated_consolidation: Number(tacosScore.toFixed(6)),
        ai_hippocampus_memory_system: Number(aiHippocampusScore.toFixed(6)),
        synaptic_consolidation_plasticity: Number(synapticConsolidationScore.toFixed(6)),
      },
      formula: "s' = s + alpha * operator * (1 - s)",
    };
    if (next > prior) boosted += 1;
    memory.rerank_score = Number(next.toFixed(6));
  }

  memories.sort((a, b) =>
    (Number(b.rerank_score) || 0) - (Number(a.rerank_score) || 0)
    || String(a.key || a.id || '').localeCompare(String(b.key || b.id || ''))
  );

  return {
    active: true,
    applied: true,
    papers_active: NATIVE_RECALL_PAPER_ACTIVATION.length,
    papers: NATIVE_RECALL_PAPER_ACTIVATION,
    services_active: [
      'services/temporal/timex-normalizer.js',
      'services/temporal/temporal-knowledge-base.js',
      'services/temporal/temporal-kg-reasoning.js',
      'services/temporal/temporal-graph-fusion.js',
      'services/temporal/multi-view-timeline.js',
      'services/temporal/recurrent-event-network.js',
      'services/retrieval/interval-algebra-rag.js',
      'services/retrieval/rag-ranking-verification.js',
      'services/temporal/right-time-rag.js',
      'services/retrieval/situated-qa-context.js',
      'services/temporal/streaming-qa-horizon.js',
      'services/retrieval/step-back-abstraction.js',
      'services/temporal/tcomplex-tntcomplex.js',
      'services/temporal/tempcourt-normalization.js',
      'services/temporal/tempeval-merge-closure.js',
      'services/temporal/tempquestions-intervals.js',
      'services/retrieval/time-aware-representation.js',
      'services/temporal/time-aware-lm-kb.js',
      'services/retrieval/temporal-abstention-reward.js',
      'services/temporal/xerte-temporal-kg-explain.js',
      'services/temporal/decoder-only-time-series-forecast.js',
      'services/retrieval/conversational-event-memory-baseline.js',
      'services/retrieval/aeon-atlas-memory.js',
      'services/retrieval/artificial-hippocampus-memory.js',
      'services/learning/bayesian-continual-memory.js',
      'services/temporal/temporal-semantic-memory.js',
      'services/retrieval/xmemory-beyond-rag.js',
      'services/retrieval/ember-retention-memory.js',
      'services/retrieval/contextual-intent-memory.js',
      'services/retrieval/hmem-hierarchical-reasoning.js',
      'services/retrieval/hage-hybrid-agent-graph.js',
      'services/learning/hebbian-orthogonal-projection.js',
      'services/retrieval/hindsight-memory-graph.js',
      'services/retrieval/hingemem-boundary-hypergraph.js',
      'services/retrieval/longmemeval-v2-context-gathering.js',
      'services/retrieval/memaudit-package-audit.js',
      'services/retrieval/memmachine-retrieval-agent.js',
      'services/retrieval/reconstructed-graph-memory.js',
      'services/retrieval/mnemis-dual-route-graph.js',
      'services/learning/neuroplasticity-stability-control.js',
      'services/learning/neurogenesis-catastrophic-forgetting.js',
      'services/retrieval/prism-typed-path-retrieval.js',
      'services/learning/serena-self-regulated-neurogenesis.js',
      'services/retrieval/swiftmem-query-aware-index.js',
      'services/learning/tacos-neuromodulated-consolidation.js',
      'services/retrieval/ai-hippocampus-memory-system.js',
      'services/learning/synaptic-consolidation-plasticity.js',
    ],
    score_contract: {
      type: 'bounded_monotone_additive_boost',
      formula: "s' = s + alpha * operator * (1 - s)",
      operator_formula: 'operator = max(previous54, 0.92 * previous54 + 0.08 * batch9)',
      alpha,
      range: [0, 1],
      preserves_prior_as_lower_bound: true,
      preserves_previous_paper_operator_as_floor: true,
    },
    temporal_question_category: temporalQuestionCategory,
    query_timex_count: queryTimex.timexes.length,
    query_window: {
      source: queryWindow.source,
      bounded: queryWindow.bounded,
      start: Number.isFinite(queryWindow.start) ? new Date(queryWindow.start).toISOString() : null,
      end: Number.isFinite(queryWindow.end) ? new Date(queryWindow.end).toISOString() : null,
    },
    boosted_count: boosted,
    memory_count: memories.length,
    interval_target_count: intervalState.target_events.length,
    ragvue_metrics: ragvue.metrics,
    reason_verify: {
      final_query_changed: reasonVerify.final_query !== reasonVerify.query,
      rewrite: reasonVerify.rewrite,
      evidence_count: reasonVerify.evidence.length,
      faithfulness: reasonVerify.verification.faithfulness,
    },
    timeline: {
      event_count: timeline.events.length,
      relation_count: timelineRelations.length,
      inferred_relation_count: timelineClosure.filter((edge) => edge.inferred).length,
      pairwise_score_count: timeScores.length,
    },
    temporal_graph: {
      node_count: temporalGraph.nodes.length,
      edge_count: temporalGraph.edges.length,
      relation_sample: temporalGraph.edges[0] ? intervalRelation({ start: states[0]?.interval.start, end: states[0]?.interval.end }, { start: states[1]?.interval.start, end: states[1]?.interval.end }) : null,
    },
    temporal_kg: {
      question_relevant_facts: temporalKg.question_relevant_facts.length,
      temporal_facts: temporalKg.temporal_facts.length,
      arity,
      sample_state: temporalStateSample?.tuple || null,
    },
    recurrent_event_network: {
      timeline_steps: recurrent.timeline.length,
      event_count: recurrentEvents.length,
      subject_count: Object.keys(recurrentMarginals.p_subject).length,
      relation_count: Object.keys(recurrentMarginals.p_relation).length,
    },
    right_time_rag: {
      graph_nodes: rightTime.graph.nodes.length,
      graph_edges: rightTime.graph.edges.length,
      seed_categories: rightTime.seed_categories,
      formula: rightTime.formula,
    },
    situated_qa: {
      context_dependent: situatedQa.context_dependent,
      context_types: situatedQa.parsed.context_types,
      context_count: situatedQa.parsed.contexts.length,
      formula: situatedQa.formula,
    },
    streaming_qa: {
      period: streamingQa.period,
      formula: streamingQa.formula,
    },
    step_back_abstraction: {
      primary_principle: stepBack.step_back.primary_principle,
      principles: stepBack.step_back.principles.map((principle) => principle.id),
      formula: stepBack.formula,
    },
    tcomplex_tntcomplex: {
      fact_count: tcomplex.fact_count,
      augmented_fact_count: tcomplex.augmented_fact_count,
      temporal_smoothness_penalty: Number(tcomplex.temporal_smoothness_penalty.toFixed(6)),
      formula: tcomplex.formula,
    },
    tempcourt: {
      query: tempCourt.query,
      formula: tempCourt.formula,
    },
    tempeval3: {
      query_signals: tempEval.query_signals,
      formula: tempEval.formula,
    },
    tempquestions: {
      query_detection: tempQuestions.query_detection,
      query_signals: tempQuestions.query_signals,
      formula: tempQuestions.formula,
    },
    time_aware_representation: {
      formula: timeAwareRepresentation.formula,
    },
    time_aware_lm_kb: {
      expert: timeAwareLmKb.expert,
      conditional_model: timeAwareLmKb.conditional_model,
      formula: timeAwareLmKb.formula,
    },
    temporal_abstention_reward: {
      abstention: temporalAbstention.abstention,
      constants: temporalAbstention.constants,
      formula: temporalAbstention.formula,
    },
    xerte_temporal_kg: {
      node_count: xerte.graph.nodes.length,
      edge_count: xerte.graph.edges.length,
      message_passing_iterations: xerte.graph.message_passing_iterations,
      formula: xerte.formula,
    },
    decoder_only_time_series: {
      forecast_error_msmapE: timeSeriesForecast.forecast_error_msmapE,
      covariates: timeSeriesForecast.covariates,
      formula: timeSeriesForecast.formula,
    },
    conversational_event_memory: {
      graph_stats: eventMemory.graph_stats,
      constants: eventMemory.constants,
      formula: eventMemory.formula,
    },
    aeon_atlas_memory: {
      latency_effective_us: aeonAtlas.latency_effective_us,
      compression_ratio_768: aeonAtlas.compression_ratio_768,
      complexity: aeonAtlas.complexity,
      formula: aeonAtlas.formula,
    },
    artificial_hippocampus_network: {
      complexity: artificialHippocampus.complexity,
      constants: artificialHippocampus.constants,
      formula: artificialHippocampus.formula,
    },
    bayesian_continual_memory: {
      constants: bayesianContinual.constants,
      formula: bayesianContinual.formula,
    },
    temporal_semantic_memory: {
      topic_count: temporalSemanticMemory.topic_count,
      temporal_intent: temporalSemanticMemory.temporal_intent,
      formula: temporalSemanticMemory.formula,
    },
    xmemory_beyond_rag: {
      hierarchy: beyondRagXmemory.hierarchy,
      formula: beyondRagXmemory.formula,
    },
    ember_retention_memory: {
      retained_count: emberRetention.retained_count,
      used_tokens: emberRetention.used_tokens,
      budget_tokens: emberRetention.budget_tokens,
      bootstrap_probe_ci: emberRetention.bootstrap_probe_ci,
      formula: emberRetention.formula,
    },
    contextual_intent_memory: {
      indexed_steps: contextualIntent.indexed_steps,
      filter: contextualIntent.filter,
      label_space: contextualIntent.label_space,
      formula: contextualIntent.formula,
    },
    hmem_hierarchical_reasoning: {
      hierarchy_counts: hmem.hierarchy_counts,
      route_count: hmem.route_count,
      complexity: hmem.complexity,
      formula: hmem.formula,
    },
    hage_hybrid_agent_graph: {
      graph_stats: hage.graph_stats,
      relational_intent: hage.relational_intent,
      beam_count: hage.beam_count,
      formula: hage.formula,
    },
    hebbian_orthogonal_projection: {
      basis_rank: hebbianProjection.basis_rank,
      projected_query_norm: hebbianProjection.projected_query_norm,
      formula: hebbianProjection.formula,
    },
    hindsight_memory_graph: {
      graph_stats: hindsightGraph.graph_stats,
      used_tokens: hindsightGraph.used_tokens,
      budget_tokens: hindsightGraph.budget_tokens,
      formula: hindsightGraph.formula,
    },
    hingemem_boundary_hypergraph: {
      hyperedge_count: hingeMem.hyperedge_count,
      node_count: hingeMem.node_count,
      raw_boundary_count: hingeMem.raw_boundary_count,
      query_plan: hingeMem.query_plan,
      selected_count: hingeMem.selected_count,
      common_topic_count: hingeMem.common_topic_count,
      rare_topic_count: hingeMem.rare_topic_count,
      formula: hingeMem.formula,
    },
    longmemeval_v2_context_gathering: {
      pools: longMemEvalV2.pools,
      query_bundle: longMemEvalV2.query_bundle,
      top_m_per_query: longMemEvalV2.top_m_per_query,
      selected_context_count: longMemEvalV2.selected_context_count,
      formula: longMemEvalV2.formula,
    },
    memaudit_package_audit: {
      package: memAudit.package,
      selected_count: memAudit.selected_count,
      ratio: memAudit.ratio,
      formula: memAudit.formula,
    },
    memmachine_retrieval_agent: {
      route_type: memMachine.route_type,
      subqueries: memMachine.subqueries,
      cluster_count: memMachine.cluster_count,
      retrieval_depth: memMachine.retrieval_depth,
      formula: memMachine.formula,
    },
    reconstructed_graph_memory: {
      graph_stats: reconstructedGraphMemory.graph_stats,
      reconstruction_steps: reconstructedGraphMemory.reconstruction_steps,
      active_count: reconstructedGraphMemory.active_count,
      reconstructed_context_count: reconstructedGraphMemory.reconstructed_context_count,
      formula: reconstructedGraphMemory.formula,
    },
    mnemis_dual_route_graph: {
      graph_stats: mnemis.graph_stats,
      system1_count: mnemis.system1_count,
      system2_count: mnemis.system2_count,
      union_count: mnemis.union_count,
      selected_categories: mnemis.selected_categories,
      formula: mnemis.formula,
    },
    neuroplasticity_stability_control: {
      dropin_gate_count: neuroplasticity.dropin_gate_count,
      dropout_mask_count: neuroplasticity.dropout_mask_count,
      relevant_index_count: neuroplasticity.relevant_index_count,
      plasticity_mode: neuroplasticity.plasticity_mode,
      formula: neuroplasticity.formula,
    },
    neurogenesis_catastrophic_forgetting: {
      neuron_count: neurogenesis.neuron_count,
      grown_count: neurogenesis.grown_count,
      synapse_count: neurogenesis.synapse_count,
      rnat_count: neurogenesis.rnat_count,
      formula: neurogenesis.formula,
    },
    prism_typed_path_retrieval: {
      graph_stats: prism.graph_stats,
      intent: prism.intent,
      bundle_count: prism.bundle_count,
      compressed_count: prism.compressed_count,
      formula: prism.formula,
    },
    serena_self_regulated_neurogenesis: {
      concept_cell_count: serena.concept_cell_count,
      drift_count: serena.drift_count,
      recurrence_count: serena.recurrence_count,
      average_accuracy: serena.average_accuracy,
      average_forgetting: serena.average_forgetting,
      formula: serena.formula,
    },
    swiftmem_query_aware_index: {
      temporal_index: swiftMem.temporal_index,
      dag_tag_index: swiftMem.dag_tag_index,
      filtered_count: swiftMem.filtered_count,
      temporal_indicator: swiftMem.temporal_indicator,
      cluster_cohesion: swiftMem.cluster_cohesion,
      formula: swiftMem.formula,
    },
    tacos_neuromodulated_consolidation: {
      synapse_count: tacos.synapse_count,
      active_gate_count: tacos.active_gate_count,
      consolidated_count: tacos.consolidated_count,
      mean_consolidation: tacos.mean_consolidation,
      formula: tacos.formula,
    },
    ai_hippocampus_memory_system: {
      index_stats: aiHippocampus.index_stats,
      paradigm_counts: aiHippocampus.paradigm_counts,
      stage_counts: aiHippocampus.stage_counts,
      retrieval_demand: aiHippocampus.retrieval_demand,
      completed_count: aiHippocampus.completed_count,
      formula: aiHippocampus.formula,
    },
    synaptic_consolidation_plasticity: {
      vocabulary_size: synapticConsolidation.vocabulary_size,
      pattern_count: synapticConsolidation.pattern_count,
      capacity_alpha: synapticConsolidation.capacity_alpha,
      capacity_safe: synapticConsolidation.capacity_safe,
      query_energy: synapticConsolidation.query_energy,
      formula: synapticConsolidation.formula,
    },
  };
}



const SERVER_BOOT_TIME = new Date().toISOString();

const router = express.Router();

function b64u(buf) {
  return Buffer.isBuffer(buf) ? buf.toString('base64url') : null;
}

function chainStatusFor(reason) {
  if (reason === 'agent_revoked' || reason === 'agent_not_active') return 401;
  return ['fork_detected', 'first_save_must_use_genesis'].includes(reason) ? 409 : 400;
}

const AIMOS_NATIVE_DIAGNOSTIC_ROUTES = new Set([
  '/recall/calibration/status',
  '/recall/trust-alignment/status',
  '/architecture/ontology-patterns',
  '/memory/lifelong/status',
  '/memory/homeostasis/status',
  '/memory/engram-pools/status',
  '/learning/oscillatory-stdp/status',
  '/orchestration/open-loop/status',
  '/orchestration/scrat/status',
  '/orchestration/turn-budget/status',
  '/orchestration/lookahead/status',
  '/orchestration/evolve-router/status',
  '/orchestration/epistemic-blinding/status',
  '/serving/qos/status',
  '/serving/prefetch/status',
  '/serving/tokenscale/status',
  '/serving/length/status',
  '/serving/agsc/status',
  '/serving/local/status',
  '/serving/local/quantization/status',
  '/serving/local/moe/status',
  '/serving/local/kv/status',
  '/serving/local/memory/status',
  '/serving/local/io/status',
  '/serving/local/lpc-sm/status',
]);

function hasAimosReadContext(req) {
  if (req.identityAuthenticatedBy === 'internal_token') return true;
  const tier = String(req.identityTier || 'T0').toUpperCase();
  return req.identityAuthenticatedBy === 'envelope' && ['T1', 'T2', 'T3'].includes(tier);
}

function requireAimosEnvelopeAgent(req, res, { allowSystemSelfHousekeeper = false } = {}) {
  const tier = String(req.identityTier || 'T0').toUpperCase();
  const agentId = req.agentId || req.identityCert?.agent_id;
  const standardAgent = ['T1', 'T2', 'T3'].includes(tier);
  const systemSelfHousekeeper = allowSystemSelfHousekeeper
    && tier === 'T1_SYSTEM_SELF'
    && agentId === 'housekeeper';
  if (req.identityAuthenticatedBy !== 'envelope'
    || !agentId
    || (!standardAgent && !systemSelfHousekeeper)) {
    res.status(401).json({
      success: false,
      error: 'cryptographic agent envelope required',
      required: 'Aimos-Agent-Cert, Aimos-Agent-Signature, Aimos-Agent-Nonce, Aimos-Agent-Timestamp',
    });
    return null;
  }
  return {
    agentId,
    tier,
    validFrom: req.identityValidFromIso || null,
  };
}

function verifiedRequestAuthorityFromReq(req) {
  return {
    kind: 'verified_request',
    body: req.body,
    agentId: req.identityCert?.agent_id,
    validFromIso: req.identityValidFromIso,
    certString: req.identityCertString,
    signedTs: req.identitySignedTs,
    nonce: req.identityNonce,
    sigBytes: req.identitySigBytes,
    identityTier: req.identityTier,
    claimedPrev: req.prevChainHash || null,
    requestSigForm: req.identityRequestSigForm,
    signedMethod: req.identitySignedMethod,
    signedPath: req.identitySignedPath,
    signedClaims: req.identitySignedClaims,
  };
}

async function requireSessionWriteContext(req, res) {
  const identity = requireAimosEnvelopeAgent(req, res, {
    allowSystemSelfHousekeeper: true,
  });
  if (!identity) return null;
  const companyId = req.executionContext?.companyId || req.body?.company_id || AIMOS_COMPANY_ID;
  if (req.body?.company_id && req.body.company_id !== companyId) {
    res.status(403).json({ success: false, error: 'session_company_mismatch' });
    return null;
  }
  if (req.body?.agent_id && req.body.agent_id !== identity.agentId) {
    res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
    return null;
  }
  let clearanceCeiling = 0;
  if (identity.tier === 'T1_SYSTEM_SELF' && identity.agentId === 'housekeeper') {
    clearanceCeiling = 12;
  } else {
    const grant = await recallAuthorizationService.getEffective({
      companyId,
      subjectAgentId: identity.agentId,
      subjectValidFrom: identity.validFrom,
    });
    if (!grant?.allowed || !grant.writeAllowed) {
      res.status(403).json({ success: false, error: 'master_signed_memory_write_grant_required' });
      return null;
    }
    clearanceCeiling = grant.clearanceCeiling;
  }
  const requestedClearance = Number(req.body?.clearance_level ?? 1);
  if (!Number.isInteger(requestedClearance)
    || requestedClearance < 1
    || requestedClearance > clearanceCeiling) {
    res.status(403).json({
      success: false,
      error: 'clearance_exceeds_verified_authority',
      actor_clearance: clearanceCeiling,
      requested_clearance: req.body?.clearance_level ?? 1,
    });
    return null;
  }
  return {
    ...identity,
    companyId,
    clearanceCeiling,
    requestAuthority: verifiedRequestAuthorityFromReq(req),
  };
}

function nativeAimosReadBoundary(req, res, next) {
  const diagnosticRoute =
    AIMOS_NATIVE_DIAGNOSTIC_ROUTES.has(req.path) ||
    /^\/agents\/[^/]+\/psychometrics\/status$/.test(req.path);
  if (!diagnosticRoute) return next();
  if (hasAimosReadContext(req)) return next();
  return res.status(403).json({
    success: false,
    error: 'Aimos diagnostic surface requires authenticated Aimos read context',
    required: 'T1 envelope or internal service token',
  });
}

// ─── D7: LOCALHOST API BOUNDARY HARDENING ────────────────────────────────────
const HOM_SESSION_TOKEN = null;
const ALLOWED_ORIGINS_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

router.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && !ALLOWED_ORIGINS_RE.test(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (HOM_SESSION_TOKEN) {
    const token = req.headers['x-session-token'];
    if (!token || token !== HOM_SESSION_TOKEN) {
      return res.status(401).json({ error: 'Missing or invalid session token' });
    }
  }
  next();
});

// ─── D7: SECRET REDACTION ─────────────────────────────────────────────────────
const AIMOS_SECRET_PATTERNS = [
  /sk_live_[A-Za-z0-9]{20,}/g,
  /sk_test_[A-Za-z0-9]{20,}/g,
  /AIza[0-9A-Za-z\-_]{35,}/g,
  /ghp_[A-Za-z0-9]{36,}/g,
  /xox[baprs]-[0-9A-Za-z]{10,}/g,
  /"access_token"\s*:\s*"[^"]{20,}"/gi,
  /"refresh_token"\s*:\s*"[^"]{20,}"/gi,
];

function redactAimosValue(text) {
  let out = String(text || '');
  for (const pat of AIMOS_SECRET_PATTERNS) {
    out = out.replace(pat, '[REDACTED]');
  }
  return out;
}

// ─── Feature 6: Data Classification ──────────────────────────────────────────
// Auto-classifies memory sensitivity: public/internal/confidential/restricted.
// Clearance mapping: 1-3 = public, 4-6 = internal, 7-9 = confidential, 10+ = all.
function classifyDataSensitivity(value, clearanceLevel = 1) {
  const text = String(value || '').toLowerCase();
  const cl = Number(clearanceLevel || 1);

  // Restricted: explicit secrets, credentials, keys
  if (/\b(password|secret|private.key|api.key|token|credential)\b/.test(text)) return 'restricted';
  if (/sk_live|sk_test|AIza|ghp_|xox[baprs]-/.test(value || '')) return 'restricted';

  // Confidential: financial, personal, strategic
  if (/\b(revenue|salary|ssn|bank.account|credit.card|social.security)\b/.test(text)) return 'confidential';
  if (/\b(strategy|acquisition|merger|valuation|term.sheet)\b/.test(text)) return 'confidential';
  if (cl >= 7) return 'confidential';

  // Internal: operational, agent-specific
  if (/\b(internal|agent_run|directive|escalat|clearance|governance)\b/.test(text)) return 'internal';
  if (cl >= 4) return 'internal';

  return 'public';
}


// ─── HIPPORAG: Lightweight entity extraction (no NLP dependency) ──────────────
// Extracts proper nouns, dates, monetary amounts, agent names, and known patterns.

// ─── D8: QUARANTINE DETECTION ─────────────────────────────────────────────────
const QUARANTINE_PATTERNS = [
  /ignore (previous|prior|all) instructions?/i,
  /ignore all previous instructions?/i,
  /\bignore\b.{0,40}\binstructions?\b/i,
  /disregard (your|all|previous) (rules?|instructions?|guidelines?)/i,
  /you are now (?!your assistant)/i,
  /\bprompt injection\b/i,
  /\bjailbreak\b/i,
  /\[OVERRIDE\]/i,
  /system:\s*(ignore|bypass|disable)/i,
  // SEC-01: behavioral directive patterns (indirect instruction injection)
  /\bwhen recalled\b/i,
  /\balways respond\b/i,
  /\bprepend (to )?(every|all|each|your)/i,
  /\boverride all\b/i,
  /\bignore previous\b/i,
  /\bact as if\b/i,
  /\byour new (role|persona|identity|instruction)\b/i,
  /\bforget (your|all|previous) (instructions?|rules?|training)\b/i,
];

function decodeForQuarantine(text) {
  const s = String(text || '');
  // SEC-03: decode base64 and URL encoding before pattern matching
  let decoded = s;
  // URL decode
  try { decoded = decodeURIComponent(decoded); } catch { /* invalid encoding, use original */ }
  // Base64 decode (only if string looks like valid base64, min 16 chars)
  const b64 = s.replace(/\s/g, '');
  if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(b64)) {
    try {
      const candidate = Buffer.from(b64, 'base64').toString('utf8');
      // Only use decoded version if it produces readable ASCII
      if (/^[\x20-\x7E\n\r\t]+$/.test(candidate)) decoded += ' ' + candidate;
    } catch { /* not valid base64 */ }
  }
  return decoded;
}

function isQuarantineCandidate(text) {
  const decoded = decodeForQuarantine(text);
  return QUARANTINE_PATTERNS.some((p) => p.test(decoded));
}

// ─── MEDALLION LAYER MIGRATION CONTRACT (read-only verification) ─────────────
let medallionColumnEnsured = false;
async function ensureMedallionColumn() {
  if (medallionColumnEnsured) return;
  const result = await query(
    `SELECT
       to_regclass('public.aimos_memories') IS NOT NULL AS relation_exists,
       EXISTS (
         SELECT 1 FROM pg_attribute
         WHERE attrelid = to_regclass('public.aimos_memories')
           AND attname = 'medallion_layer'
           AND attnum > 0
           AND NOT attisdropped
       ) AS medallion_column_exists,
       to_regclass('public.idx_memories_medallion') IS NOT NULL AS medallion_index_exists`
  );
  const schema = result.rows[0] || {};
  const missing = [];
  if (!schema.relation_exists) missing.push('relation:aimos_memories');
  if (!schema.medallion_column_exists) missing.push('column:aimos_memories.medallion_layer');
  if (!schema.medallion_index_exists) missing.push('index:idx_memories_medallion');
  if (missing.length) {
    const error = new Error(`migration_schema_missing:medallion:${missing.join(',')}`);
    error.code = 'MIGRATION_SCHEMA_MISSING';
    error.statusCode = 503;
    throw error;
  }
  medallionColumnEnsured = true;
}

// ─── ALADDIN RETENTION: Everything is long-term. Nothing expires. Nothing deletes. ───
// Modeled on BlackRock Aladdin: $11.5T AUM retained because clients cannot leave their data.
// Storage is cheap, retrieval quality is the bottleneck. Keep everything, surface the right thing.
// Columns memory_tier, expires_at, promoted_at remain in DB schema for compatibility but are
// functionally fixed: memory_tier='long-term', expires_at=NULL, always.

// persistMemory is now imported from services/write/persist-memory.js
// All helper functions (normalizeOperatorAgentId, isOperatorAgentId, redactAimosValue,
// classifyDataSensitivity, isQuarantineCandidate, extractEntities, inferMedallionLayer,
// ensureMedallionColumn) remain here for use
// by other aimos.js routes (recall, status, etc.).

function heartbeatKey(date = new Date()) {
  return `heartbeat:${date.toISOString().slice(0, 16).replace('T', '-')}`;
}

// ─── MEDALLION: Infer layer from memory_type ──────────────────────────────────
function inferMedallionLayer(memoryType) {
  const gold = new Set(['milestone','product','identity','procedural','crew_identity','dream_summary','self_improvement','infrastructure']);
  const silver = new Set(['session','directive','heartbeat','intel','constitution_check','test']);
  if (gold.has(memoryType)) return 'gold';
  if (silver.has(memoryType)) return 'silver';
  return 'bronze';
}

const DIRECTIVE_BLOCK_PATTERNS = [
  /\bsandbox[_\s-]*mode\b/i,
  /\btool\s*sandbox\s*mode\b/i,
  /\bsandbox(?:ing|ed)?\b/i,
  /--dangerously-skip-permissions/i,
  /\bhardcod(?:e|ed|ing)\b/i
];

function sanitizeDirectiveGoal(goal = '') {
  const text = String(goal || '');
  if (!text.trim()) {
    return { sanitizedGoal: '', removedLines: [] };
  }

  const removedLines = [];
  const keptLines = [];
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    const blocked = DIRECTIVE_BLOCK_PATTERNS.some((pattern) => pattern.test(line));
    if (blocked) {
      const trimmed = line.trim();
      if (trimmed) removedLines.push(trimmed);
      continue;
    }
    keptLines.push(line);
  }

  const sanitizedGoal = keptLines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  return { sanitizedGoal, removedLines };
}

// ─── EVENT LEDGER (called by Swift AimosCore.logEvent) ──────────────────────
router.post('/event', async (req, res, next) => {
  const { company_id, agent_id, operation, key, metadata } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.companyId) {
    return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  }
  const actorAgentId = context.actorAgentId;
  const cid = context.companyId;
  if (agent_id && agent_id !== actorAgentId) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }
  if (company_id && company_id !== cid) {
    return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
  }
  try {
    const receipt = await logEvent(cid, actorAgentId, operation || 'event', key || null, {
      ...(metadata && typeof metadata === 'object' ? metadata : {}),
      reasoning: metadata?.reasoning || `Swift/external event logged: operation=${operation || 'event'}, key=${key || 'none'}`,
      source_knowledge: metadata?.source_knowledge || 'external caller (Swift AimosCore or API client)'
    }, null, {
      returnReceipt: true,
      authority: {
        actorAgentId,
        actorValidFromIso: req.identityValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
      },
    });
    res.status(201).json({ success: true, receipt });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/status', async (req, res, next) => {
  try {
    const result = await query('SELECT COUNT(*) as total FROM aimos_memories WHERE company_id = $1', [AIMOS_COMPANY_ID]);
    res.json({
      connected: true,
      total_memories: parseInt(result.rows[0].total),
      speed_flags: {
        cache_enabled: SPEED_CONFIG.cache.enabled,
        early_exit_enabled: SPEED_CONFIG.earlyExit.enabled,
        governance_enabled: SPEED_CONFIG.governance.enabled,
        instrumentation_enabled: SPEED_CONFIG.instrumentation.enabled
      },
      cache_stats: SPEED_CONFIG.cache.enabled ? semanticCache.getStats() : null,
      server_started_at: SERVER_BOOT_TIME
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/chain-head', async (req, res, next) => {
  try {
    const identityTier = String(req.identityTier || 'T0').toUpperCase();
    const agentId = req.identityCert?.agent_id;
    const validFromIso = req.identityValidFromIso;
    if (!['T1', 'T2', 'T3'].includes(identityTier) || !agentId || !validFromIso) {
      return res.status(401).json({
        success: false,
        error: 'cryptographic identity required'
      });
    }

    const result = await query(
      `SELECT chain_head FROM agent_identity ai
        WHERE agent_id = $1 AND valid_from = $2
          AND NOT EXISTS (
            SELECT 1 FROM aimos_agent_revocation_events r
             WHERE r.agent_id = ai.agent_id
               AND r.agent_valid_from = ai.valid_from
          )`,
      [agentId, validFromIso]
    );
    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        error: 'agent_not_active'
      });
    }

    const chainHead = result.rows[0].chain_head;
    const previousChainHash = chainHead || genesisHashFor(agentId, validFromIso);
    res.json({
      success: true,
      agent_id: agentId,
      valid_from: validFromIso,
      identity_tier: identityTier,
      chain_head: b64u(chainHead),
      previous_chain_hash: b64u(previousChainHash),
      previous_is_genesis: !Buffer.isBuffer(chainHead)
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/session/turn', async (req, res) => {
  let context;
  try {
    context = await requireSessionWriteContext(req, res);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
  if (!context) return;

  try {
    const result = await sessionMemoryOwner.appendTurn(req.body || {}, {
      companyId: context.companyId,
      agentId: context.agentId,
      clearanceLevel: context.clearanceCeiling,
      mutationAuthority: context.requestAuthority,
      requestAuthority: context.requestAuthority,
      source: req.body?.source || 'signed-session-transport',
    });
    return res.json(result);
  } catch (error) {
    const conflict = [
      'session_already_finalized',
      'session_turn_idempotency_conflict',
      'session_turn_idempotency_fork',
    ].includes(error.message) || Boolean(error.envelopeReason);
    const invalid = error.message.startsWith('session_') && !conflict;
    return res.status(conflict ? 409 : invalid ? 400 : 500).json({
      success: false,
      error: error.envelopeReason || error.message,
      current_head: error.currentHead ? b64u(error.currentHead) : null,
    });
  }
});

router.post('/session/finalize', async (req, res) => {
  let context;
  try {
    context = await requireSessionWriteContext(req, res);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
  if (!context) return;

  try {
    const result = await sessionMemoryOwner.finalizeSession(req.body || {}, {
      companyId: context.companyId,
      agentId: context.agentId,
      clearanceLevel: context.clearanceCeiling,
      requestAuthority: context.requestAuthority,
      source: req.body?.source || 'housekeeper:session-finalization',
    });
    return res.json(result);
  } catch (error) {
    const conflict = [
      'session_finalization_conflict',
      'session_finalization_fork',
    ].includes(error.message);
    const invalid = error.message.startsWith('session_') && !conflict;
    return res.status(conflict ? 409 : invalid ? 400 : 500).json({
      success: false,
      error: error.message,
      rejected: error.rejected || null,
    });
  }
});

router.post('/compaction/save', async (req, res) => {
  const identity = requireAimosEnvelopeAgent(req, res);
  if (!identity) return;

  try {
    const result = await saveCompactionMemory(req.body || {}, {
      agentId: identity.agentId,
      companyId: req.body?.company_id || AIMOS_COMPANY_ID,
      identityTier: identity.tier,
      validFrom: identity.validFrom,
      origin: req.body?.origin || 'app_context_window',
      route: '/aimos/compaction/save',
    });

    if (!result.success) {
      return res.status(result.status || 400).json({
        success: false,
        error: result.error,
        reason: result.reason || null,
        lane: 'compaction_full',
        identity_tier: identity.tier,
        validation: result.payload?.validation || null,
        quality_score: result.quality_score,
      });
    }

    return res.json({
      success: true,
      lane: result.lane,
      memory_id: result.memory_id,
      key: result.key,
      memory_type: result.memory_type,
      identity_tier: identity.tier,
      agent_id: identity.agentId,
      memory_tier: result.memory_tier,
      quality_score: result.quality_score,
      freshness_state: result.freshness_state,
      valid_from: result.valid_from || null,
      valid_until: result.valid_until || null,
      surprise_at_save: result.surprise_at_save,
      compression_ratio: result.compression_ratio,
      content_hash: result.payload?.metadata?.content_hash || null,
      trigger: result.payload?.metadata?.app_trigger || null,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      lane: 'compaction_full',
    });
  }
});

router.post('/compaction/post', async (req, res) => {
  const identity = requireAimosEnvelopeAgent(req, res);
  if (!identity) return;

  try {
    const result = await savePostCompactionDelivery(req.body || {}, {
      agentId: identity.agentId,
      companyId: req.body?.company_id || AIMOS_COMPANY_ID,
      identityTier: identity.tier,
      validFrom: identity.validFrom,
      origin: req.body?.origin || 'app_context_window',
      route: '/aimos/compaction/post',
    });

    if (!result.success) {
      return res.status(result.status || 400).json({
        success: false,
        error: result.error,
        reason: result.reason || null,
        lane: 'post_compaction_delivery',
        identity_tier: identity.tier,
        validation: result.payload?.validation || null,
        quality_score: result.quality_score,
      });
    }

    return res.json({
      success: true,
      lane: result.lane,
      memory_id: result.memory_id,
      key: result.key,
      memory_type: result.memory_type,
      identity_tier: identity.tier,
      agent_id: identity.agentId,
      memory_tier: result.memory_tier,
      quality_score: result.quality_score,
      freshness_state: result.freshness_state,
      valid_from: result.valid_from || null,
      valid_until: result.valid_until || null,
      surprise_at_save: result.surprise_at_save,
      compression_ratio: result.compression_ratio,
      content_hash: result.payload?.metadata?.content_hash || null,
      source: result.delivery?.source || null,
      handoff: result.delivery?.handoff || null,
      confidence: result.delivery?.confidence || null,
      evidence_refs: result.delivery?.evidence_refs || [],
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message,
      lane: 'post_compaction_delivery',
    });
  }
});

router.post('/save', async (req, res, next) => {
  const __latencyStart = Date.now();
  res.on('finish', () => {
    logEvent(req.body?.company_id || 'hom', req.agentId || 'app', 'save_latency', req.body?.key || null, {
      endpoint: '/save',
      latency_ms: Date.now() - __latencyStart,
      aimos_status: res.statusCode,
      reasoning: 'Housekeeper observed the completed signed save request latency and terminal HTTP status.',
      source_knowledge: 'routes/aimos.js — signed native save transport',
    }).catch(() => {});
  });
  const {
    company_id,
    agent_id: claimedAgentId,
    key,
    value,
    scope,
    clearance_level,
    memory_type,
    source,
    memory_tier,
    is_correction,
    supersedes_id,
    knowledge_proof,
    verify_target_id,
    verify_target_key
  } = req.body;

  if (!key || typeof key !== 'string' || !key.trim()) {
    return res.status(400).json({ success: false, error: 'Missing required field: key' });
  }
  if (!value || (typeof value !== 'string' && typeof value !== 'object')) {
    return res.status(400).json({ success: false, error: 'Missing required field: value' });
  }

  const aladdinVersionPolicy = enforceVersionOnlyMemoryPolicy({
    key,
    value,
    source,
    memoryType: memory_type,
    isCorrection: is_correction,
    supersedesId: supersedes_id,
    verifyTargetId: verify_target_id,
    verifyTargetKey: verify_target_key,
  });
  if (aladdinVersionPolicy.status === 'blocked_requires_supersession') {
    return res.status(409).json({
      success: false,
      error: aladdinVersionPolicy.message,
      reason: aladdinVersionPolicy.reason,
      aladdin_compliant: true,
      aladdin_reframe: aladdinVersionPolicy,
      safe_next_step: 'Save a correction with is_correction=true and a supersedes_id, verify_target_id, or verify_target_key. The original memory remains as audit evidence.'
    });
  }

  const identityTier = String(req.identityTier || 'T0').toUpperCase();
  const agent_id = req.agentId || req.identityCert?.agent_id || null;
  if (!agent_id) {
    return res.status(401).json({ success: false, error: 'verified_agent_required' });
  }
  if (claimedAgentId && claimedAgentId !== agent_id) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }

  let actorClearance = 0;
  if (identityTier === 'T1_SYSTEM_SELF' && agent_id === 'housekeeper') {
    actorClearance = 12;
  } else {
    const memoryAuthority = await recallAuthorizationService.getEffective({
      companyId: req.executionContext.companyId,
      subjectAgentId: req.executionContext.actorAgentId,
      subjectValidFrom: req.executionContext.actorValidFromIso,
    });
    if (!memoryAuthority?.allowed || !memoryAuthority.writeAllowed) {
      return res.status(403).json({ success: false, error: 'master_signed_memory_write_grant_required' });
    }
    actorClearance = memoryAuthority.clearanceCeiling;
  }
  const targetClearance = Number(clearance_level || 1);
  if (!Number.isFinite(targetClearance) || targetClearance < 1 || targetClearance > actorClearance) {
    return res.status(403).json({
      success: false,
      error: 'clearance_exceeds_verified_authority',
      actor_clearance: actorClearance,
      requested_clearance: clearance_level ?? 1
    });
  }
  const isChainSave = ['T2', 'T3'].includes(identityTier) && Buffer.isBuffer(req.prevChainHash);
  const requestAuthority = verifiedRequestAuthorityFromReq(req);
  const canaryDecision = await evaluateCanaryWrite({
    key,
    value,
    companyId: company_id || req.executionContext.companyId,
    agentId: agent_id,
    authority: requestAuthority,
  });
  let securityDecision = evaluateSecurityContent({
    text: typeof value === 'string' ? value : JSON.stringify(value),
    operation: 'memory_save',
    contentType: memory_type || 'declarative',
    key,
    source: source || 'aimos-rest',
    transport: 'rest',
  });
  if (canaryDecision.quarantine && !securityDecision.quarantine) {
    securityDecision = {
      ...securityDecision,
      action: 'retain_quarantine',
      reason: canaryDecision.reason,
      severity: 'critical',
      quarantine: true,
      liveSignals: [...securityDecision.liveSignals, { tag: 'canary_persistence_boundary', severity: 'critical' }],
    };
  }
  const securityReceipt = await appendSecurityDecision(securityDecision, {
    companyId: company_id || req.executionContext.companyId,
    subjectAgentId: agent_id,
    authority: requestAuthority,
    parentEventId: canaryDecision.event_receipt?.event_id || null,
  });

  if (isChainSave) {
    try {
      const preflight = await saveEnvelopeOrchestrator.preSaveCheck({
        agentId: req.identityCert?.agent_id,
        validFromIso: req.identityValidFromIso,
        claimedPrev: req.prevChainHash
      });
      if (!preflight.ok) {
        return res.status(chainStatusFor(preflight.reason)).json({
          success: false,
          error: preflight.reason,
          current_head: b64u(preflight.currentHead)
        });
      }
    } catch (err) {
      err.statusCode = 500;
      next(err);
    }
  }

  // Knowledge Gate retired 2026-07-07 — was scaffolding for the build phase (Speed.md Appendix A).
  // The quality gate (quality-gate.js) is the remaining write-time gate.

  try {
    // ─── SUDO CLEARANCE GUARD — protect clearance 12+ memories ───────────────
    if (key) {
      const existing = await query(
        `SELECT clearance_level FROM aimos_memories
         WHERE company_id = $1 AND key = $2 AND clearance_level >= 12
         LIMIT 1`,
        [company_id || 'hom', key]
      );
      if (existing.rows.length > 0 && actorClearance < 12) {
        return res.status(403).json({
          error: 'SUDO PROTECTED: This memory requires clearance level 12+ to modify. Use sudo access.',
          key,
          required_clearance: 12
        });
      }
    }

    // ─── WIRE: write-validator — pre-commit validation ──────────────────────
    // Skip validation for internal system types (agent_session, event_log, dream_summary, dream_pattern)
    // to avoid circular dependency: validator needs agent_session but can't create one without passing validation
    const VALIDATION_EXEMPT_TYPES = new Set(['agent_session', 'event_log', 'dream_summary', 'dream_pattern', 'reasoning_state', 'session_debrief', 'strategic_directive', 'procedural', 'tacit_knowledge', 'core_belief']);
    let writeValidation = { valid: true };
    if (!VALIDATION_EXEMPT_TYPES.has(memory_type)) {
      try {
        const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
        const existingVal = undefined; // new write, no existing value in request context
        // R11b: thread the VERIFIED identity (tier + cert agent id) so the
        // write-validator can grant the system self intrinsic write authority
        // (the exact T1_SYSTEM_SELF housekeeper principal) without an agent_session.
        writeValidation = await validateWrite(agent_id || 'app', key, valueStr, existingVal, {
          identityTier,
          verifiedAgentId: req.identityCert?.agent_id || null
        });
        if (!writeValidation.valid) {
          return res.status(400).json({
            success: false,
            error: `Write validation failed: ${writeValidation.reason}`,
            retryable: writeValidation.retryable
          });
        }
      } catch (_wvErr) {
        console.warn('[aimos] write-validator error (non-fatal):', _wvErr.message);
      }
    }

    // ─── WIRE: rpe-gate — compute RPE to route processing depth ──────────
    // RPE uses heuristic utility classification (no LLM). Timeout kept as DB safety net.
    let rpeResult = { rpe: 0, route: 'STANDARD', surprise: 0, utility: 0 };
    try {
      const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
      const rpePromise = computeRPE(valueStr, company_id);
      const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('RPE timeout')), 5000));
      rpeResult = await Promise.race([rpePromise, timeoutPromise]);
    } catch (_rpeErr) {
      console.warn('[aimos] rpe-gate error (non-fatal):', _rpeErr.message);
    }

    // ─── WIRE: sensible-screening — monitor RPE gate quality after RPE result ─
    try {
      monitorRPEGateQuality(company_id).catch(_ssErr =>
        console.warn('[aimos] sensible-screening monitor error (non-fatal):', _ssErr.message)
      );
    } catch (_ssErr) {
      console.warn('[aimos] sensible-screening error (non-fatal):', _ssErr.message);
    }

    // ─── WIRE: transformation-cache — check cache before any value transform ──
    let cachedTransformResult = null;
    let _pendingTransformCache = null;
    try {
      const valueObj = typeof value === 'string' ? { raw: value } : (value || {});
      const inputHash = computeSchemaHash(Object.fromEntries(Object.keys(valueObj).map(k => [k, typeof valueObj[k]])));
      const outputHash = computeSchemaHash({ memory_type: memory_type || 'episodic', scope: scope || 'agent' });
      cachedTransformResult = await getCachedTransformation(inputHash, outputHash);
      if (!cachedTransformResult) {
        // No cached transform; register for future caching after save completes
        _pendingTransformCache = { inputHash, outputHash };
      }
    } catch (_tcErr) {
      console.warn('[aimos] transformation-cache error (non-fatal):', _tcErr.message);
    }

    // ─── WIRE: mnemonic-encoder — tag encoding style at save time ────────
    let encodingStyle = { style: 'visual_hook', confidence: 0 };
    try {
      const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
      encodingStyle = detectEncodingStyle(valueStr, memory_type || '');
    } catch (_encErr) {
      console.warn('[aimos] mnemonic-encoder error (non-fatal):', _encErr.message);
    }

    // ─── R3 Step 4: ATOMIC memory + provenance ────────────────────────────────
    // persistMemory (the canonical memory row) and commitProvenance (the memory-
    // centric mutation ledger row) run inside ONE transaction on a single client.
    // If the provenance commit fails, the whole transaction rolls back and the
    // memory row NEVER existed — closing the "ledgered memory with no provenance"
    // gap that the old sequential-autocommit flow left open on a mid-save crash.
    //
    // Pool note: migration 045 grants the restricted agent_runtime role only the
    // native transaction statements. RLS binds here because client_id/agent_id
    // are set on the same restricted client before persistence begins.
    let saved = null;
    let provenanceCommit = null;
    let envelopeCommit = null;
    try {
      const txnResult = await withTransaction(async (txClient) => {
        const savedInner = await persistMemory({
          company_id,
          agent_id,
          key,
          value,
          scope,
          clearance_level,
          memory_type,
          source,
          memory_tier,
          is_correction,
          supersedes_id,
          session_id: req.body?.session_id || null,
          account: req.body?.account || null,
          ts_created: req.body?.ts_created || null,
          security_disposition: { decision: securityDecision, receipt: securityReceipt },
          mutation_authority: requestAuthority,
          client: txClient
        });

        // Quality reject: no memory row was inserted; commit the empty txn and
        // surface the 422 outside. Credential references carry housekeeper
        // provenance plus their credential lifecycle proof; T2/T3 requests also
        // advance the caller's save envelope inside this same transaction.
        if (savedInner?.rejected || !savedInner?.id) {
          return { saved: savedInner, provenanceCommit: null, envelopeCommit: null };
        }

        return {
          saved: savedInner,
          provenanceCommit: savedInner.ledger_commit || savedInner.credential_ledger_commit || null,
          envelopeCommit: savedInner.envelope_commit || null,
        };
      }, { agent_id, client_id: company_id, knowledge_proof, restricted: true });
      saved = txnResult.saved;
      provenanceCommit = txnResult.provenanceCommit;
      envelopeCommit = txnResult.envelopeCommit;
    } catch (err) {
      if (err && err.envelopeReason) {
        return res.status(chainStatusFor(err.envelopeReason)).json({
          success: false,
          error: err.envelopeReason,
          current_head: b64u(err.currentHead)
        });
      }
      if (err && err.provenanceReason) {
        const provenanceReasonToStatus = {
          malformed_input: 400,
          fork_race: 500,
          duplicate_genesis: 500,
          retry_exhausted: 500
        };
        return res.status(provenanceReasonToStatus[err.provenanceReason] || 500).json({
          success: false,
          error: 'provenance_commit_failed',
          reason: err.provenanceReason
        });
      }
      throw err; // any other error → outer handler
    }

    // ─── Save truthfulness: quality reject must surface as 4xx, not success ────
    if (saved?.rejected) {
      return res.status(422).json({
        success: false,
        error: `Quality gate rejected: ${saved.reason}`,
        reason: saved.reason,
        quality_score: saved.quality_score,
        existing_memory_id: saved?.save_feedback?.existing_memory_id || null
      });
    }

    // ─── WIRE: transformation-cache — store transform result after save ──────
    if (_pendingTransformCache && saved && saved.id) {
      cacheTransformation(_pendingTransformCache.inputHash, _pendingTransformCache.outputHash, {
        memory_id: saved.id,
        memory_tier: saved.memory_tier,
        encoding_style: encodingStyle.style
      }).catch(_tcSaveErr =>
        console.warn('[aimos] transformation-cache store error (non-fatal):', _tcSaveErr.message)
      );
    }

    // ─── Invalidate semantic cache on new memory save ──────────────────────────
    if (SPEED_CONFIG.cache.enabled && saved?.id) {
      semanticCache.invalidate('cross_ref_update');
    }

    const responseMutationHash = envelopeCommit?.chainHash
      || provenanceCommit?.mutationHash
      || saved?.ledger_commit?.mutationHash
      || saved?.credential_ledger_commit?.mutationHash;
    const responseContentHash = envelopeCommit?.contentHash
      || provenanceCommit?.contentHash
      || saved?.ledger_commit?.contentHash
      || saved?.credential_ledger_commit?.contentHash
      || saved?.live_content_hash;
    res.json({
      success: true,
      memory_id: saved.id,
      identity_tier: identityTier,
      chain_hash: b64u(responseMutationHash),
      content_hash: b64u(responseContentHash),
      chain_kind: envelopeCommit ? 'save_envelope' : (saved?.credential_lane ? 'credential_lifecycle' : 'memory_provenance'),
      trusted_path: req.trustedPath === true,
      trusted_path_reason: req.trustedPathReason || null,
      memory_tier: saved.memory_tier,
      conflict_detected: saved.conflict_detected,
      quarantined: saved.quarantined,
      security_decision_event_id: saved.security_decision_event_id || securityReceipt.event_id,
      correction_applied: saved.correction_applied,
      corrections_applied: saved.corrections_applied,
      non_executable_evidence: req.body?._non_executable_evidence === true,
      rpe: { score: rpeResult.rpe, route: rpeResult.route },
      encoding_style: encodingStyle.style,
      mutation_hash: b64u(responseMutationHash),
      live_content_hash: saved?.live_content_hash?.toString('hex') || null,
      save_mutation_hash: saved?.ledger_commit?.mutationHash?.toString('hex') || null,
      binding_mutation_hash: saved?.binding_commit?.mutationHash?.toString('hex') || null,
      epistemic_label: saved?.epistemic_label || 'unverified',
      epistemic_confidence_milli: Number(saved?.epistemic_confidence_milli || 0),
      epistemic_classification_event_id: saved?.epistemic_classification_event_id || null,
      epistemic_classification_hash: saved?.epistemic_classification_hash || null,
      epistemic_related_memory_ids_reclassified: saved?.epistemic_related_memory_ids_reclassified || [],
      is_genesis: provenanceCommit?.isGenesis ?? null,
      provenance_prev_mutation_hash: b64u(provenanceCommit?.prevMutationHash)
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// ─── Phase 4: POST /aimos/lineage — D3 agent-attested cross-memory derivation
// Sibling to /save; both inherit authGate from server.js (cert-envelope auth
// over canonicalJson(body)+'\n'+nonce+'\n'+String(ts)). Body shape:
// {child_id, parent_ids[], derivation_type}. The same validated sig bytes
// from auth-tier are persisted to aimos_memory_lineage as a D3 row.
// One sig, two attestation ledgers (provenance + lineage) when T2/T3.
// Phase 4 wires ONLY derivation_type='agent_reasoning'; other types wired
// in Phase 5 (D2 server-attested, D1 structural backfill).
router.post('/lineage', async (req, res, next) => {
  try {
    const { child_id, parent_ids, derivation_type } = req.body || {};

    if (typeof child_id !== 'string' || child_id.length === 0) {
      return res.status(400).json({ success: false, error: 'Missing required field: child_id' });
    }
    if (!Array.isArray(parent_ids) || parent_ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Missing required field: parent_ids (non-empty array)' });
    }
    if (derivation_type !== 'agent_reasoning') {
      return res.status(400).json({
        success: false,
        error: 'derivation_type must be "agent_reasoning" in Phase 4 (other types wired in Phase 5)'
      });
    }

    const identityTierLineage = String(req.identityTier || 'T0').toUpperCase();
    // T0 = no envelope, no validated sig → cannot attest D3 lineage.
    if (!['T1', 'T2', 'T3'].includes(identityTierLineage)) {
      return res.status(401).json({ success: false, error: 'T0 identity cannot attest D3 lineage' });
    }

    const sigBytes = req.identitySigBytes;
    const nonce = req.identityNonce;
    const tsSigned = req.identitySignedTs;
    const agentId = req.identityCert?.agent_id;
    if (!Buffer.isBuffer(sigBytes) || sigBytes.length !== 64) {
      return res.status(401).json({ success: false, error: 'No validated sig bytes on request' });
    }
    if (typeof agentId !== 'string' || agentId.length === 0) {
      return res.status(401).json({ success: false, error: 'No active agent identity on cert' });
    }

    const lineageCommit = await memoryLineageLedger.commitLineage({
      childId: child_id,
      parentIds,
      derivationType: derivation_type,
      agentId,
      certString: req.identityCertString,
      sigBytes,
      nonce,
      tsSigned
    });
    if (!lineageCommit.ok) {
      const lineageReasonToStatus = {
        malformed_input: 400,
        derivation_type_not_wired_in_phase4: 400,
        duplicate_d3_event: 409,
        child_id_missing: 404,
        parent_id_missing: 404
      };
      return res.status(lineageReasonToStatus[lineageCommit.reason] || 500).json({
        success: false,
        error: lineageCommit.reason
      });
    }

    res.json({
      success: true,
      child_id,
      derivation_type,
      attestation_tier: 'D3',
      attesting_agent_id: agentId,
      parent_ids: lineageCommit.parentIds,
      ts_signed: tsSigned
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

async function handleAimosRecall(req, res, next) {
  const __latencyStart = Date.now();
  const actor = req.executionContext?.actorAgentId || null;
  const company = req.executionContext?.companyId || null;
  res.on('finish', () => {
    if (!actor || !company) return;
    logEvent(company, actor, 'recall_latency', String(req.body?.query || req.body?.q || '').slice(0, 50) || null, {
      endpoint: '/recall',
      latency_ms: Date.now() - __latencyStart,
      aimos_status: res.statusCode,
      reasoning: 'Observed signed native recall endpoint latency after response completion.',
      source_knowledge: 'routes/aimos.js native recall transport',
    }).catch(() => {});
  });
  try {
    const requestAuthority = {
      kind: 'verified_request',
      body: req.body,
      agentId: req.executionContext?.actorAgentId,
      validFromIso: req.executionContext?.actorValidFromIso,
      certString: req.identityCertString,
      signedTs: req.identitySignedTs,
      nonce: req.identityNonce,
      sigBytes: req.identitySigBytes,
      identityTier: req.identityTier,
      claimedPrev: req.prevChainHash || null,
      requestSigForm: req.identityRequestSigForm,
      signedMethod: req.identitySignedMethod,
      signedPath: req.identitySignedPath,
      signedClaims: req.identitySignedClaims,
    };
    const recallText = String(req.body?.query || req.body?.q || req.body?.key || req.body?.memory_id || '');
    const securityDecision = evaluateSecurityContent({
      text: recallText,
      operation: 'memory_recall',
      contentType: 'native_recall',
      source: 'aimos-rest',
      transport: 'rest',
    });
    const securityReceipt = await appendSecurityDecision(securityDecision, {
      companyId: company,
      subjectAgentId: actor,
      authority: requestAuthority,
    });
    if (securityDecision.blockExecution) {
      return res.status(403).json({
        success: false,
        error: 'recall_query_blocked',
        reason: securityDecision.reason,
        action: securityDecision.action,
        security_decision_event_id: securityReceipt.event_id,
      });
    }
    const recallAuthority = await resolveNativeRecallAuthority({
      rawCommand: req.body,
      executionContext: req.executionContext,
      requestAuthority,
      transportBinding: { transport: 'rest' },
    });
    const result = await executeNativeRecall(req, recallAuthority);
    return res.status(result.status).json(result.body);
  } catch (error) {
    const reason = String(error?.message || error);
    const status = /required|authority|clearance|scope|actor|company|epoch_not_active/.test(reason)
      ? 403
      : /evidence|topology|binding/.test(reason)
        ? 409
        : 400;
    error.statusCode = status;
    next(error);
  }
}

router.get('/recall', (_req, res) => res.status(405).json({
  success: false,
  error: 'signed_post_recall_required',
}));
router.post('/recall', handleAimosRecall);

router.post('/recall/calibration/observe', requireCapability('memory_read'), async (req, res, next) => {
  try {
    const context = req.executionContext;
    const company = String(req.body?.company_id || context?.companyId || '');
    if (!context?.actorAgentId || company !== context.companyId) {
      return res.status(403).json({ success: false, error: 'calibration_company_or_actor_mismatch' });
    }
    if (String(req.identitySignedMethod || '').toUpperCase() !== 'POST'
      || req.identitySignedPath !== '/aimos/recall/calibration/observe') {
      return res.status(403).json({ success: false, error: 'calibration_feedback_signature_binding_invalid' });
    }
    const receipt = await recordCalibrationObservationBatch({
      companyId: company,
      labels: req.body?.labels,
      authority: {
        actorAgentId: context.actorAgentId,
        actorValidFromIso: context.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        requestReceiptId: context.requestReceiptId,
        requestReceiptMutationHash: context.requestReceiptMutationHash,
        requestAdmissionEventId: context.requestAdmissionEventId,
        requestAdmissionMutationHash: context.requestAdmissionMutationHash,
      },
    });
    res.json({ success: true, observation_receipt: receipt });
  } catch (error) {
    error.statusCode = /binding|authority|required|mismatch/.test(String(error?.message || '')) ? 403 : 400;
    next(error);
  }
});

router.use(nativeAimosReadBoundary);

// Native Aimos diagnostic/status surfaces.
// These handlers live behind server.js authGate and expose existing Aimos
// service contracts directly; they are not MCP wrappers or alternate write paths.
router.get('/recall/calibration/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || req.executionContext?.companyId || AIMOS_COMPANY_ID);
    if (req.executionContext?.companyId && company !== req.executionContext.companyId) {
      return res.status(403).json({ success: false, error: 'calibration_company_scope_mismatch' });
    }
    const status = await getCalibrationStatus(company);
    res.json({
      success: true,
      company_id: company,
      calibration: status,
      orca: buildOrcaCalibrationReadiness(status, {
        deployedProcedure: 'aimos_recall_linear_hybrid',
      }),
      ranking_math_changed: false,
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/recall/trust-alignment/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 50), 200));
    const result = await query(
      `SELECT id, key, memory_type, retrieval_weight, decay_weight, credit_score,
              access_count, last_accessed_at, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY COALESCE(last_accessed_at, updated_at, created_at) DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildTrustAlignmentDiagnostics(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/architecture/ontology-patterns', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildOntologyAwarePatternMap({
        servicePath: req.query.service_path || '',
        slug: req.query.slug || '',
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/lifelong/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 100), 500));
    const result = await query(
      `SELECT id, key, memory_type, scope, source, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildLifelongMemoryContract(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/homeostasis/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));
    const result = await query(
      `SELECT id, key, memory_type, retrieval_weight, decay_weight,
              access_count, last_accessed_at, created_at, updated_at
       FROM aimos_memories
       WHERE company_id = $1
       ORDER BY COALESCE(last_accessed_at, updated_at, created_at) DESC
       LIMIT $2`,
      [company, limit]
    );
    res.json({
      success: true,
      company_id: company,
      ...buildTemporalHomeostasisDiagnostics(result.rows),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/memory/engram-pools/status', async (req, res, next) => {
  try {
    const company = String(req.query.company_id || AIMOS_COMPANY_ID);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 12), 50));
    res.json({
      success: true,
      company_id: company,
      ...await buildEngramPoolDiagnostics({ companyId: company, limit }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/learning/oscillatory-stdp/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildOscillatorySTDPStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/open-loop/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildSpeculativeVerificationContract({
        metaState: {
          mastery: 0.82,
          novelty: 0.18,
          predictionError: 0.08,
          failureRecurrence: 0,
          resourceBudgetRemaining: 0.9,
        },
        decision: {
          action: META_ACTIONS.APPLY_SKILL,
          expectedValue: 4.2,
        },
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/scrat/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildScratPipelineStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/agents/:agentId/psychometrics/status', async (req, res, next) => {
  try {
    const status = await getAgentPsychometricStatus(normalizeOperatorAgentId(req.params.agentId), {
      model: req.query.model || 'unknown',
      scaffold: req.query.scaffold || 'unknown',
      taskType: req.query.task_type || 'status',
      prompt: req.query.prompt || '',
      toolsUsed: req.query.tools_used || 0,
    });
    res.json({
      success: true,
      ...status,
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/turn-budget/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildTurnAdaptiveBudgetStatus({
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        globalBudget: req.query.global_budget || undefined,
        usedTokens: req.query.used_tokens || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/lookahead/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildLatentLookaheadStatus({
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        maxThoughts: req.query.max_thoughts || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/evolve-router/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildEvolveRouterStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/orchestration/epistemic-blinding/status', (_req, res, next) => {
  try {
    res.json({
      success: true,
      ...buildEpistemicBlindingStatus(),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/qos/status', (req, res, next) => {
  try {
    res.json(buildNiyamaServingStatus({
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
      intent: req.query.intent || undefined,
      stream: req.query.stream === 'true' ? true : req.query.stream === 'false' ? false : undefined,
      requestImportance: req.query.importance || undefined,
      queueDepth: req.query.queue_depth || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/prefetch/status', (req, res, next) => {
  try {
    res.json(buildKeyedPrefetchStatus({
      prompt: req.query.prompt || undefined,
      sessionKey: req.query.session_key || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/tokenscale/status', (req, res, next) => {
  try {
    res.json(buildTokenScaleStatus({
      promptChars: req.query.prompt_chars || undefined,
      responseChars: req.query.response_chars || undefined,
      latencyMs: req.query.latency_ms || undefined,
      predictedOutputTokens: req.query.predicted_output_tokens || undefined,
      stream: req.query.stream === 'true' ? true : req.query.stream === 'false' ? false : undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/length/status', (req, res, next) => {
  try {
    res.json(buildRobustLengthStatus({
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/agsc/status', (req, res, next) => {
  try {
    res.json(buildAgscStatus({
      text: req.query.text || undefined,
      taskType: req.query.task_type || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/status', (req, res, next) => {
  try {
    res.json(buildWave5LocalInferenceStatus({
      model: req.query.model || undefined,
      prompt: req.query.prompt || undefined,
      taskType: req.query.task_type || undefined,
      contextTokens: req.query.context_tokens || undefined,
      predictedOutputTokens: req.query.predicted_output_tokens || undefined,
      vectorCount: req.query.vector_count || undefined,
      graphEdgeCount: req.query.graph_edge_count || undefined,
    }));
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/quantization/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildTurboQuantReadiness({
        vectorCount: req.query.vector_count || undefined,
        vectorDimension: req.query.vector_dimension || undefined,
        baselineRecallAt10: req.query.baseline_recall_at_10 || undefined,
        quantizedRecallAt10: req.query.quantized_recall_at_10 || undefined,
        quantColumns: false,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/moe/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildMoEExpertSchedulingPlan({
        model: req.query.model || undefined,
        prompt: req.query.prompt || undefined,
        taskType: req.query.task_type || undefined,
        totalExperts: req.query.total_experts || undefined,
        activeExperts: req.query.active_experts || undefined,
        gpuVramGb: req.query.gpu_vram_gb || undefined,
        gamma: req.query.gamma || undefined,
        acceptanceProbability: req.query.acceptance_probability || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/kv/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildKvCacheAndLayoutPlan({
        contextTokens: req.query.context_tokens || undefined,
        predictedOutputTokens: req.query.predicted_output_tokens || undefined,
        layers: req.query.layers || undefined,
        hiddenSize: req.query.hidden_size || undefined,
        bytesPerValue: req.query.bytes_per_value || undefined,
        hasSmartSsd: req.query.smartssd === 'true',
        pimAvailable: req.query.pim === 'true',
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/memory/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildLocalMemoryPlacementPlan({
        graphEdgeCount: req.query.graph_edge_count || undefined,
        vectorCount: req.query.vector_count || undefined,
        vectorDimension: req.query.vector_dimension || undefined,
      }),
      bottleneck: buildMicroBottleneckDiagnostic({
        latencyMs: req.query.latency_ms || undefined,
        cpuUtilization: req.query.cpu_utilization || undefined,
        memoryPressure: req.query.memory_pressure || undefined,
        ioWaitRatio: req.query.io_wait_ratio || undefined,
        gpuUtilization: req.query.gpu_utilization || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/io/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildNexusIoOffloadPlan({
        operation: req.query.operation || undefined,
        inputBytes: req.query.input_bytes || undefined,
        outputBytes: req.query.output_bytes || undefined,
        backgroundWriteAllowed: req.query.background_write === 'false' ? false : undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/serving/local/lpc-sm/status', (req, res, next) => {
  try {
    res.json({
      success: true,
      status: 'wired',
      contract: buildLpcSmSmallModelPlan({
        model: req.query.model || undefined,
        prompt: req.query.prompt || undefined,
        confidence: req.query.confidence || undefined,
        noveltyScore: req.query.novelty_score || undefined,
        targetContextTokens: req.query.target_context_tokens || undefined,
      }),
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/heartbeat', async (req, res, next) => {
  const {
    company_id,
    agent_id,
    summary,
    files_touched = [],
    decisions_made = [],
    corrections = [],
    knowledge_proof
  } = req.body || {};

  const cid = company_id || AIMOS_COMPANY_ID;
  const verifiedAgentId = req.agentId || req.identityCert?.agent_id || null;
  if (!verifiedAgentId) return res.status(401).json({ success: false, error: 'verified_agent_required' });
  if (agent_id && agent_id !== verifiedAgentId) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }
  const aid = normalizeOperatorAgentId(verifiedAgentId);
  const key = heartbeatKey(new Date());

  try {
    const heartbeatValue = JSON.stringify(
      {
        summary: summary || '',
        files_touched: Array.isArray(files_touched) ? files_touched : [],
        decisions_made: Array.isArray(decisions_made) ? decisions_made : [],
        corrections: Array.isArray(corrections) ? corrections : []
      },
      null,
      2
    );

    // ─── R3 Step 4: ATOMIC heartbeat memory + provenance ──────────────────────
    // Same invariant as the /save path: the heartbeat memory row and its
    // housekeeper-signed provenance row commit or roll back together. The
    // housekeeper signing happens inside the txn (before commitProvenance) so a
    // sign failure aborts the whole thing and no unattested heartbeat row is left.
    // Runs on the same restricted native transaction as /save.
    let saved = null;
    try {
      const txnResult = await withTransaction(async (txClient) => {
        const savedInner = await persistMemory({
          company_id: cid,
          agent_id: aid,
          key,
          value: heartbeatValue,
          scope: 'system',
          clearance_level: 5,
          memory_type: 'heartbeat',
          memory_tier: 'working',
          mutation_authority: 'housekeeper',
          client: txClient
        });
        return { saved: savedInner };
      }, { agent_id: aid, client_id: cid, knowledge_proof, restricted: true });
      saved = txnResult.saved;
    } catch (err) {
      if (err && err.provenanceReason) {
        return res.status(500).json({
          success: false,
          error: 'provenance_commit_failed',
          reason: err.provenanceReason
        });
      }
      // Fail-closed: housekeeper not enrolled / sign failure / any txn error →
      // heartbeat not ledgered and rolled back.
      return res.status(500).json({
        success: false,
        error: 'provenance_sign_failed',
        reason: String(err?.message || err)
      });
    }

    let correctionsApplied = 0;
    const list = Array.isArray(corrections) ? corrections : [];
    for (const correction of list) {
      const correctionKey = String(correction?.key || '').trim();
      if (!correctionKey) continue;
      const correctedValue = correction?.new_value ?? correction?.value ?? '';
      const correctionResult = await persistMemory({
        company_id: cid,
        agent_id: aid,
        key: correctionKey,
        value: String(correctedValue),
        scope: 'global',
        clearance_level: 5,
        memory_type: 'directive',
        is_correction: true,
        mutation_authority: 'housekeeper'
      });
      correctionsApplied += Number(correctionResult.corrections_applied || 0) > 0 ? 1 : 0;
    }

    res.json({
      success: true,
      heartbeat_id: saved.id,
      corrections_applied: correctionsApplied
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// Aladdin retention: no config needed. Everything is long-term. Nothing expires.
router.get('/retention-config', (req, res) => {
  res.json({ company_id: req.query.company_id || 'hom', policy: 'aladdin', retention: 'permanent', expires: 'never' });
});

router.put('/retention-config', (req, res) => {
  res.json({ success: true, policy: 'aladdin', message: 'Retention is permanent. No configuration needed.' });
});

router.post('/checkpoint', async (req, res, next) => {
  const { task_id, company_id, agent_id, step, checkpoint_state } = req.body;

  try {
    await query(
      `INSERT INTO aimos_capsules (task_id, company_id, agent_id, step, checkpoint_state, status, updated_at)
       VALUES ($1, $2, $3, $4, $5, 'suspended', NOW())
       ON CONFLICT (task_id) DO UPDATE SET step = $4, checkpoint_state = $5, updated_at = NOW()`,
      [task_id, company_id, agent_id, step, JSON.stringify(checkpoint_state)]
    );

    res.json({ success: true });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/resume/:taskId', async (req, res, next) => {
  try {
    const result = await query(
      `SELECT task_id, agent_id, step, checkpoint_state, goal FROM aimos_capsules WHERE task_id = $1`,
      [req.params.taskId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json({ capsule: result.rows[0] });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/conflicts', async (req, res, next) => {
  const { company_id } = req.query;

  try {
    const result = await query(
      `SELECT id, conflict_type, created_at FROM aimos_conflicts 
       WHERE company_id = $1 AND resolved_at IS NULL`,
      [company_id]
    );

    res.json({ conflicts: result.rows });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/conflicts/:id/resolve', async (req, res, next) => {
  const { resolution, resolved_by } = req.body;

  try {
    await query(
      `UPDATE aimos_conflicts SET resolution = $1, resolved_by = $2, resolved_at = NOW() WHERE id = $3`,
      [resolution, resolved_by, req.params.id]
    );

    res.json({ success: true });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/curator/stats', async (req, res) => {
  res.json({
    entries_reviewed: 0,
    deduplicated: 0,
    conflicts_found: 0,
    avg_importance: 0.75
  });
});

router.get('/dream/latest', async (req, res, next) => {
  try {
    const result = await query(
      `SELECT key, value, created_at
       FROM aimos_memories
       WHERE company_id = $1 AND memory_type = 'dream_summary'
       ORDER BY created_at DESC
       LIMIT 1`,
      [AIMOS_COMPANY_ID]
    );
    if (!result.rows.length) {
      return res.json({ run_date: null, summary: null });
    }
    res.json({
      run_date: result.rows[0].created_at,
      summary: result.rows[0].value
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/audit/x-usage', async (req, res) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const windowHours = Math.min(Math.max(parseInt(req.query.hours || '24', 10), 1), 168);
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 200);

  try {
    const runsResult = await query(
      `WITH recent_runs AS (
         SELECT
           ar.run_id::text,
           ar.source_agent_id,
           ar.resolved_agent_id,
           ar.status,
           ar.intent,
           ar.channel,
           ar.created_at,
           ar.updated_at,
           ar.response_preview,
           ar.error,
           dc.directive_id::text,
           EXISTS (
             SELECT 1
             FROM aimos_memories om
             WHERE om.company_id = ar.company_id
               AND om.created_at >= ar.created_at - INTERVAL '5 seconds'
               AND om.created_at <= COALESCE(ar.updated_at, NOW()) + INTERVAL '5 seconds'
               AND (
                 om.key ILIKE '%x_search%'
                 OR om.value ILIKE '%x_search%'
                 OR om.value ILIKE '%twitter%'
                 OR om.value ILIKE '%x.com%'
               )
           ) AS aimos_mention
         FROM agent_runs ar
         LEFT JOIN directive_claims dc
           ON dc.run_id::text = ar.run_id::text
         WHERE ar.company_id = $1
           AND ar.created_at >= NOW() - ($2::int * INTERVAL '1 hour')
       )
       SELECT *
       FROM recent_runs
       WHERE
         intent IN ('x', 'twitter', 'x_search', 'social-listening', 'social_listening')
         OR COALESCE(response_preview, '') ILIKE '%x_search%'
         OR COALESCE(response_preview, '') ILIKE '%twitter%'
         OR COALESCE(error, '') ILIKE '%x_search%'
         OR aimos_mention = true
       ORDER BY created_at DESC
       LIMIT $3`,
      [company, windowHours, limit]
    );

    const runs = runsResult.rows.map((row) => ({
      run_id: row.run_id,
      source_agent_id: row.source_agent_id,
      resolved_agent_id: row.resolved_agent_id,
      status: row.status,
      intent: row.intent,
      channel: row.channel,
      created_at: row.created_at,
      updated_at: row.updated_at,
      origin: row.directive_id ? 'directive' : 'chat',
      directive_id: row.directive_id || null,
      aimos_mention: row.aimos_mention === true,
      estimated_queries: 1
    }));

    const summary = runs.reduce((acc, run) => {
      acc.total_runs += 1;
      acc.estimated_queries += Number(run.estimated_queries || 0);
      if (run.origin === 'directive') {
        acc.directive_runs += 1;
      } else {
        acc.chat_runs += 1;
      }
      if (run.aimos_mention) {
        acc.aimos_mentions += 1;
      }
      return acc;
    }, {
      window_hours: windowHours,
      total_runs: 0,
      chat_runs: 0,
      directive_runs: 0,
      aimos_mentions: 0,
      estimated_queries: 0
    });

    res.json({
      success: true,
      summary,
      runs
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      summary: {
        window_hours: windowHours,
        total_runs: 0,
        chat_runs: 0,
        directive_runs: 0,
        aimos_mentions: 0,
        estimated_queries: 0
      },
      runs: [],
      error: error.message
    });
  }
});

router.get('/timeline', async (req, res) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const days = Math.min(Math.max(parseInt(req.query.days || '7', 10), 1), 30);

  try {
    const rowsResult = await query(
      `SELECT
         created_at::date AS day,
         memory_type,
         key,
         value
       FROM aimos_memories
       WHERE company_id = $1
         AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       ORDER BY created_at ASC`,
      [company, days]
    );

    const now = new Date();
    const timeline = [];
    const byDay = new Map();
    const safeType = (value = '') => {
      const type = String(value || '').toLowerCase();
      if (type === 'procedural' || type === 'episodic' || type === 'semantic') return type;
      return 'semantic';
    };

    for (let offset = days - 1; offset >= 0; offset -= 1) {
      const point = new Date(now);
      point.setHours(0, 0, 0, 0);
      point.setDate(point.getDate() - offset);
      const key = point.toISOString().slice(0, 10);
      byDay.set(key, {
        date: key,
        total: 0,
        procedural: 0,
        episodic: 0,
        semantic: 0,
        memories: []
      });
    }

    for (const row of rowsResult.rows) {
      const rawDay = row.day;
      const day = rawDay instanceof Date
        ? rawDay.toISOString().slice(0, 10)
        : String(rawDay || '').slice(0, 10);
      const bucket = byDay.get(day);
      if (!bucket) continue;

      const type = safeType(row.memory_type);
      bucket.total += 1;
      bucket[type] += 1;
      if (bucket.memories.length < 25) {
        bucket.memories.push({
          key: String(row.key || ''),
          value: String(row.value || '').slice(0, 220),
          type
        });
      }
    }

    for (const value of byDay.values()) {
      timeline.push(value);
    }

    const total = timeline.reduce((acc, day) => acc + Number(day.total || 0), 0);
    const first = Number(timeline[0]?.total || 0);
    const last = Number(timeline[timeline.length - 1]?.total || 0);
    const growthPercent = first > 0
      ? Number((((last - first) / first) * 100).toFixed(2))
      : (last > 0 ? 100 : 0);

    res.json({
      success: true,
      total,
      growthPercent,
      days: timeline
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      total: 0,
      growthPercent: 0,
      days: [],
      error: error?.message || String(error)
    });
  }
});

router.get('/graph/:entityId', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const entityId = (req.params.entityId || '').trim();
  const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10), 1), 100);

  if (!entityId) return res.status(400).json({ error: 'entityId is required' });

  try {
    const needle = `%${entityId}%`;
    const result = await query(
      `SELECT id::text, key, value, scope, memory_type
       FROM aimos_memories
       WHERE company_id = $1
         AND (key ILIKE $2 OR value ILIKE $2 OR scope ILIKE $2)
       ORDER BY updated_at DESC
       LIMIT $3`,
      [company, needle, limit]
    );

    const nodes = result.rows.map(row => ({
      id: row.id,
      value: row.value,
      entity_type: row.memory_type || 'declarative',
      relations: [
        { type: 'scope', target: String(row.scope || 'global') },
        { type: 'key', target: String(row.key || '') }
      ]
    }));

    res.json({ nodes });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/dream/run', async (req, res, next) => {
  try {
    const result = await runNightlyDream(AIMOS_COMPANY_ID);
    res.json({ success: true, result });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/layer-status', async (req, res, next) => {
  const company = AIMOS_COMPANY_ID;
  try {
    const [
      memoryCount,
      todayEvents,
      capsules,
      conflicts,
      creditAvg,
      clearanceLevels,
      dreamRow,
      typeBreakdown
    ] = await Promise.all([
      query(`SELECT COUNT(*) AS total FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT COUNT(*) AS total FROM aimos_events WHERE company_id = $1 AND ts >= NOW() - INTERVAL '48 hours'`, [company]),
      query(`SELECT COUNT(*) AS total, status FROM aimos_capsules WHERE company_id = $1 GROUP BY status`, [company]),
      query(`SELECT COUNT(*) AS total FROM aimos_conflicts WHERE company_id = $1 AND resolved_at IS NULL`, [company]),
      query(`SELECT AVG(credit_score) AS avg FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT COUNT(DISTINCT clearance_level) AS levels FROM aimos_memories WHERE company_id = $1`, [company]),
      query(`SELECT created_at FROM aimos_memories WHERE company_id = $1 AND memory_type = 'dream_summary' ORDER BY created_at DESC LIMIT 1`, [company]),
      query(`SELECT memory_type, COUNT(*) AS count FROM aimos_memories WHERE company_id = $1 GROUP BY memory_type`, [company])
    ]);

    const capsuleMap = {};
    capsules.rows.forEach(r => { capsuleMap[r.status] = parseInt(r.total); });
    const totalCapsules = Object.values(capsuleMap).reduce((a, b) => a + b, 0);

    const typeMap = {};
    typeBreakdown.rows.forEach(r => { typeMap[r.memory_type || 'declarative'] = parseInt(r.count); });

    const memoryTotal = parseInt(memoryCount.rows[0].total);
    const eventsToday = parseInt(todayEvents.rows[0].total);
    const openConflicts = parseInt(conflicts.rows[0].total);
    const avgCredit = parseFloat(creditAvg.rows[0].avg || 1.0);
    const clearanceLevelsCount = parseInt(clearanceLevels.rows[0].levels || 0);
    const lastDream = dreamRow.rows[0]?.created_at || null;
    const dreamScheduled = !lastDream || (Date.now() - new Date(lastDream).getTime() > 20 * 60 * 60 * 1000);

    res.json({
      event_ledger: {
        status: eventsToday > 0 ? 'active' : 'idle',
        events_today: eventsToday,
        label: eventsToday + ' today'
      },
      memory_store: {
        status: memoryTotal > 0 ? 'online' : 'idle',
        total: memoryTotal,
        by_type: typeMap,
        label: memoryTotal + ' entries'
      },
      knowledge_graph: {
        status: memoryTotal > 0 ? 'online' : 'idle',
        nodes: memoryTotal,
        label: memoryTotal > 0 ? `${memoryTotal} nodes` : 'No nodes yet'
      },
      task_capsules: {
        status: totalCapsules > 0 ? 'active' : 'ready',
        total: totalCapsules,
        suspended: capsuleMap['suspended'] || 0,
        completed: capsuleMap['completed'] || 0,
        label: totalCapsules > 0 ? totalCapsules + ' capsules' : 'Ready'
      },
      curator_agent: {
        status: openConflicts === 0 ? 'online' : 'warning',
        conflicts_open: openConflicts,
        label: openConflicts === 0 ? 'No conflicts' : openConflicts + ' conflicts'
      },
      memory_market: {
        status: memoryTotal > 0 ? 'active' : 'idle',
        avg_credit: avgCredit.toFixed(2),
        label: memoryTotal > 0 ? `Score ${avgCredit.toFixed(2)}` : 'Idle'
      },
      governance: {
        status: clearanceLevelsCount > 0 ? 'active' : 'idle',
        levels: clearanceLevelsCount,
        label: clearanceLevelsCount > 0 ? `${clearanceLevelsCount} levels` : 'No policies yet'
      },
      nightly_dream: {
        status: dreamScheduled ? 'idle' : 'online',
        last_run: lastDream,
        label: lastDream ? `Last run ${new Date(lastDream).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}` : '2AM scheduled'
      }
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/review/weekly', async (req, res, next) => {
  try {
    const company = AIMOS_COMPANY_ID;
    const now = new Date();
    const since = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const rows = await query(
      `SELECT created_at::date as day, COUNT(*)::int as count
       FROM aimos_memories
       WHERE company_id = $1 AND memory_type = 'task_summary' AND created_at >= $2
       GROUP BY day
       ORDER BY day ASC`,
      [company, since]
    );

    const counts = {};
    rows.rows.forEach(r => { counts[r.day] = r.count; });

    const missingDays = [];
    for (let i = 0; i < 7; i += 1) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      if (!counts[key]) missingDays.push(key);
    }

    // ─── MOAT METRICS (Zero to One + Seven Powers) ────────────────────────────
    const [memoryCount, crossRefCount, skillCount, recLogCount, eventCount, frameworkCount, bookCount] = await Promise.all([
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM memory_cross_refs WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM procedural_skills WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM recommendation_log WHERE company_id = $1`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'event_log' AND created_at >= $2`, [company, since]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'framework'`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'book_extract'`, [company]).then(r => r.rows[0]?.c || 0)
    ]);

    const graphDensity = memoryCount > 0 ? (crossRefCount / memoryCount).toFixed(2) : 0;

    // ─── WIP CHECK (Flow Control) ───────────────────────────────────────────
    const [activeLoops, pendingDirectives] = await Promise.all([
      query(`SELECT COUNT(*)::int as c FROM aimos_memories WHERE company_id = $1 AND memory_type = 'active_loop'`, [company]).then(r => r.rows[0]?.c || 0),
      query(`SELECT COUNT(*)::int as c FROM aimos_directives WHERE company_id = $1 AND status = 'pending' AND authority_event_id IS NOT NULL`, [company]).then(r => r.rows[0]?.c || 0).catch(() => 0)
    ]);

    const wipViolations = [];
    if (activeLoops > 10) wipViolations.push(`active_loops=${activeLoops} (limit 10)`);
    if (pendingDirectives > 15) wipViolations.push(`pending_directives=${pendingDirectives} (limit 15)`);

    res.json({
      range_days: 7,
      total_entries: rows.rows.reduce((sum, r) => sum + r.count, 0),
      per_day: counts,
      missing_days: missingDays,
      moat_metrics: {
        total_memories: memoryCount,
        graph_density: Number(graphDensity),
        graph_density_target: 2.0,
        cross_refs: crossRefCount,
        procedural_skills: skillCount,
        recommendation_log_entries: recLogCount,
        frameworks: frameworkCount,
        book_extracts: bookCount,
        switching_cost_index: memoryCount + skillCount + recLogCount
      },
      flow_control: {
        events_this_week: eventCount,
        active_loops: activeLoops,
        pending_directives: pendingDirectives,
        wip_violations: wipViolations,
        wip_healthy: wipViolations.length === 0
      },
      warning: 'Habit erosion: Week 1 you are intentional. Week 4 you move fast and agents stop writing memories because no one enforces it. A month in, the Aimos has 30 entries when it should have 3,000.'
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});


// CEO Bridge (CEO Directives)
router.post('/ceo/directive', requireCapability('delegate'), async (req, res, next) => {
  const { company_id, agent_id, goal, priority, clearance_level } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.actorValidFromIso) {
    return res.status(401).json({ error: 'verified_execution_context_required' });
  }
  if (company_id && company_id !== context.companyId) return res.status(403).json({ error: 'company_scope_mismatch' });
  if (!agent_id) return res.status(400).json({ error: 'target_agent_id_required' });

  try {
    const { sanitizedGoal, removedLines } = sanitizeDirectiveGoal(goal);
    if (!sanitizedGoal) {
      return res.status(400).json({
        success: false,
        error: 'Directive goal is empty after sanitization (blocked hardcoding/sandbox directives).',
        removed_lines: removedLines.length
      });
    }

    const result = await createDirective({
      companyId: context.companyId,
      targetAgentId: agent_id,
      goal: sanitizedGoal,
      priority: Math.max(1, Math.min(100, Number(priority) || 1)),
      clearanceLevel: Math.max(1, Math.min(12, Number(clearance_level) || 5)),
      authority: {
        actorAgentId: context.actorAgentId,
        actorValidFromIso: context.actorValidFromIso,
        requestReceiptId: context.requestReceiptId || null,
        requestReceiptMutationHash: context.requestReceiptMutationHash || null,
        requestAdmissionEventId: context.requestAdmissionEventId || null,
        requestAdmissionMutationHash: context.requestAdmissionMutationHash || null,
      },
    });
    res.json({
      success: true,
      directive_id: result.directiveId,
      event_id: result.eventId,
      sanitized: removedLines.length > 0,
      removed_lines: removedLines.length
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.get('/ceo/inbox', requireCapability('delegate'), async (req, res, next) => {
  const { company_id, agent_id, status } = req.query;
  const context = req.executionContext;
  if (company_id && company_id !== context?.companyId) return res.status(403).json({ error: 'company_scope_mismatch' });

  try {
    let sql = `SELECT * FROM aimos_directives WHERE company_id = $1 AND authority_event_id IS NOT NULL`;
    const params = [context.companyId];

    if (agent_id) {
      sql += ` AND agent_id = $${params.length + 1}`;
      params.push(agent_id);
    }

    if (status) {
      sql += ` AND status = $${params.length + 1}`;
      params.push(status);
    } else {
      sql += ` AND status != 'completed'`;
    }

    sql += ` ORDER BY priority DESC, created_at DESC`;

    const result = await query(sql, params);
    res.json({ directives: result.rows });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/directives/claim', async (req, res, next) => {
  const {
    company_id,
    directive_id,
    agent_id,
    run_id,
    lease_seconds
  } = req.body || {};
  const context = req.executionContext;
  if (!context?.actorAgentId) return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  if (company_id && company_id !== context.companyId) return res.status(403).json({ success: false, error: 'company_scope_mismatch' });
  if (agent_id && agent_id !== context.actorAgentId && context.actorAgentId !== 'housekeeper') {
    return res.status(403).json({ success: false, error: 'directive_claim_actor_mismatch' });
  }
  const claimAgentId = agent_id || context.actorAgentId;

  try {
    const result = await claimDirective({
      companyId: context.companyId,
      directiveId: directive_id || null,
      agentId: claimAgentId,
      runId: run_id || null,
      leaseSeconds: lease_seconds || 120,
      authority: context,
    });

    if (!result.claimed) {
      return res.status(409).json({ success: false, ...result });
    }

    // Include the directive goal in the claim response so callers
    // don't need a separate fetch (eliminates race condition)
    let goal = null;
    if (result.directiveId) {
      try {
        const dRow = await query(
          'SELECT goal FROM aimos_directives WHERE id = $1 AND authority_event_id IS NOT NULL',
          [result.directiveId]
        );
        if (dRow.rows.length) goal = dRow.rows[0].goal;
      } catch { /* goal fetch is best-effort */ }
    }

    res.json({ success: true, ...result, goal });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

router.post('/ceo/report', async (req, res, next) => {
  const { directive_id, agent_id, result_data, status } = req.body;
  const context = req.executionContext;
  if (!context?.actorAgentId) return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  if (agent_id && agent_id !== context.actorAgentId && context.actorAgentId !== 'housekeeper') {
    return res.status(403).json({ success: false, error: 'directive_report_actor_mismatch' });
  }
  const reportingAgentId = agent_id || context.actorAgentId;

  try {
    const completed = await completeDirectiveClaim({
      companyId: context.companyId,
      directiveId: directive_id,
      agentId: reportingAgentId,
      status: status || 'completed',
      resultData: result_data,
      authority: context,
    });
    if (!completed) return res.status(409).json({ success: false, error: 'directive_completion_rejected' });
    res.json({ success: true });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// ─── FELIX: GET /aimos/events/today ────────────────────────────────────────
// Returns today's event_log entries in chronological order.
// Used by the nightly health loop and boot sequence recall.
router.get('/events/today', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const hours = Math.min(Math.max(parseInt(req.query.hours || '24', 10), 1), 168);
  try {
    const result = await query(
      `SELECT id, key, value, memory_type, created_at
       FROM aimos_memories
       WHERE company_id = $1
         AND memory_type IN ('declarative', 'task_summary', 'event_log', 'milestone', 'active_loop')
         AND created_at >= NOW() - ($2::int * INTERVAL '1 hour')
       ORDER BY created_at ASC`,
      [company, hours]
    );
    res.json({ events: result.rows, count: result.rows.length });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});


// ─── POST /aimos/log-event ───────────────────────────────────────────────────
// Convenience endpoint: one call logs a bullet event to Aimos.
// Body: { agent_id, action, summary, files?, result, company_id?, reasoning?, source_knowledge?, next_action? }
// action types: code_change | deploy | post | trade | briefing | memory | infra | creds | design | brand
// reasoning: WHY was this decision made (required for ALL actions — Third Wave traceability)
// source_knowledge: which book, framework, or principle informed this (traceable origin)
router.post('/log-event', async (req, res, next) => {
  const {
    company_id,
    agent_id,
    action,
    summary,
    files = [],
    result: outcome,
    next: bodyNext,
    next_action,
    reasoning,
    source_knowledge
  } = req.body || {};

  if (!action || !summary) {
    return res.status(400).json({ success: false, error: '`action` and `summary` are required' });
  }

  if (!reasoning) {
    console.warn(`[aimos] WARNING: log-event '${action}' missing reasoning field. Every decision needs a traceable WHY.`);
  }

  const context = req.executionContext;
  if (!context?.actorAgentId || !context?.companyId) {
    return res.status(401).json({ success: false, error: 'verified_execution_context_required' });
  }
  const cid = context.companyId;
  const verifiedLogAgentId = context.actorAgentId;
  if (agent_id && agent_id !== verifiedLogAgentId) {
    return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
  }
  const aid = normalizeOperatorAgentId(verifiedLogAgentId);
  const now = new Date();
  const ts = now.toISOString().slice(0, 16).replace('T', '_').replace(':', '');
  const key = `event_${String(action).toLowerCase()}_${ts}`;

  const effectiveNext = next_action || bodyNext;
  const bullet = [
    `• ${now.toISOString().slice(11, 16)} — [${action}] ${summary}`,
    outcome ? `  result: ${outcome}` : null,
    reasoning ? `  reasoning: ${reasoning}` : null,
    source_knowledge ? `  source: ${source_knowledge}` : null,
    Array.isArray(files) && files.length ? `  files: ${files.join(', ')}` : null,
    effectiveNext ? `  next: ${effectiveNext}` : null
  ].filter(Boolean).join('\n');

  try {
    const requestAuthority = {
      kind: 'verified_request',
      body: req.body,
      agentId: verifiedLogAgentId,
      validFromIso: req.identityValidFromIso,
      certString: req.identityCertString,
      signedTs: req.identitySignedTs,
      nonce: req.identityNonce,
      sigBytes: req.identitySigBytes,
      identityTier: req.identityTier,
      claimedPrev: req.prevChainHash || null,
      requestSigForm: req.identityRequestSigForm,
      signedMethod: req.identitySignedMethod,
      signedPath: req.identitySignedPath,
      signedClaims: req.identitySignedClaims,
    };
    const saved = await persistMemory({
      company_id: cid,
      agent_id: aid,
      key,
      value: bullet,
      scope: 'system',
      clearance_level: 5,
      memory_type: 'event_log',
      mutation_authority: requestAuthority
    });

    const eventReceipt = await logEvent(cid, aid, String(action).toLowerCase(), key, {
      summary,
      files,
      result: outcome || null,
      next_action: effectiveNext || null,
      reasoning: reasoning || `Verified agent ${aid} recorded ${action}: ${summary}`,
      source_knowledge: source_knowledge || 'aimos.js /log-event verified request',
      memory_id: saved.id,
    }, null, {
      returnReceipt: true,
      authority: {
        actorAgentId: verifiedLogAgentId,
        actorValidFromIso: req.identityValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
      },
    });

    res.json({ success: true, key, memory_id: saved.id, memory_tier: saved.memory_tier, event_receipt: eventReceipt });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// ─── AGENT STATE MACHINE ──────────────────────────────────────────────────────
// The installer owns schema creation. Routes only verify the migration contract.
let agentStateTableEnsured = false;
async function ensureAgentStateTable() {
  if (agentStateTableEnsured) return;
  const result = await query(
    `WITH required_columns(name) AS (
       VALUES ('company_id'), ('agent_id'), ('phase'), ('current_task'),
              ('beliefs'), ('desires'), ('intentions'), ('waiting_for'),
              ('blockers'), ('confidence'), ('last_action'), ('next_action'),
              ('created_at'), ('updated_at')
     ), required_indexes(name) AS (
       VALUES ('agent_state_pkey')
     ), target AS (
       SELECT to_regclass('public.agent_state') AS relid
     )
     SELECT 'relation' AS kind, 'agent_state' AS name
       FROM target WHERE relid IS NULL
     UNION ALL
     SELECT 'column', 'agent_state.' || required_columns.name
       FROM required_columns, target
      WHERE NOT EXISTS (
        SELECT 1 FROM pg_attribute
         WHERE attrelid = target.relid
           AND attname = required_columns.name
           AND attnum > 0
           AND NOT attisdropped
      )
     UNION ALL
     SELECT 'index', required_indexes.name
       FROM required_indexes
      WHERE to_regclass('public.' || required_indexes.name) IS NULL`
  );
  if (result.rows.length) {
    const missing = result.rows.map((row) => `${row.kind}:${row.name}`);
    const error = new Error(`migration_schema_missing:agent_state:${missing.join(',')}`);
    error.code = 'MIGRATION_SCHEMA_MISSING';
    error.statusCode = 503;
    throw error;
  }
  agentStateTableEnsured = true;
}

// GET /agent-state/:agentId — returns the current BDI state for an agent
router.get('/agent-state/:agentId', async (req, res, next) => {
  const company = req.query.company_id || AIMOS_COMPANY_ID;
  const agentId = (req.params.agentId || '').trim();

  if (!agentId) return res.status(400).json({ error: 'agentId is required' });

  try {
    await ensureAgentStateTable();

    const result = await query(
      `SELECT company_id, agent_id, phase, current_task, beliefs, desires, intentions,
              waiting_for, blockers, confidence, last_action, next_action,
              created_at, updated_at
       FROM agent_state
       WHERE company_id = $1 AND agent_id = $2`,
      [company, agentId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Agent state not found' });
    }

    res.json({ state: result.rows[0] });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// PUT /agent-state/:agentId — upserts the BDI state for an agent
router.put('/agent-state/:agentId', async (req, res, next) => {
  const company = req.body.company_id || AIMOS_COMPANY_ID;
  const agentId = (req.params.agentId || '').trim();

  if (!agentId) return res.status(400).json({ error: 'agentId is required' });

  const {
    phase,
    current_task,
    beliefs,
    desires,
    intentions,
    waiting_for,
    blockers,
    confidence,
    last_action,
    next_action
  } = req.body || {};

  try {
    await ensureAgentStateTable();

    const result = await query(
      `INSERT INTO agent_state
         (company_id, agent_id, phase, current_task, beliefs, desires, intentions,
          waiting_for, blockers, confidence, last_action, next_action,
          created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
       ON CONFLICT (company_id, agent_id) DO UPDATE SET
         phase        = COALESCE(EXCLUDED.phase,        agent_state.phase),
         current_task = COALESCE(EXCLUDED.current_task, agent_state.current_task),
         beliefs      = COALESCE(EXCLUDED.beliefs,      agent_state.beliefs),
         desires      = COALESCE(EXCLUDED.desires,      agent_state.desires),
         intentions   = COALESCE(EXCLUDED.intentions,   agent_state.intentions),
         waiting_for  = EXCLUDED.waiting_for,
         blockers     = COALESCE(EXCLUDED.blockers,     agent_state.blockers),
         confidence   = COALESCE(EXCLUDED.confidence,   agent_state.confidence),
         last_action  = COALESCE(EXCLUDED.last_action,  agent_state.last_action),
         next_action  = COALESCE(EXCLUDED.next_action,  agent_state.next_action),
         updated_at   = NOW()
       RETURNING *`,
      [
        company,
        agentId,
        phase || 'idle',
        current_task || null,
        beliefs      ? JSON.stringify(beliefs)    : '{}',
        desires      ? JSON.stringify(desires)    : '{}',
        intentions   ? JSON.stringify(intentions) : '[]',
        waiting_for  || null,
        Array.isArray(blockers) ? blockers : [],
        confidence != null ? Number(confidence) : 0.5,
        last_action  || null,
        next_action  || null
      ]
    );

    await logEvent(company, agentId, 'state_update', `agent_state:${agentId}`, {
      phase: result.rows[0].phase,
      current_task: result.rows[0].current_task,
      reasoning: `Agent '${agentId}' state updated: phase=${result.rows[0].phase}, task=${result.rows[0].current_task}. State tracking enables session continuity — any crash or reboot can resume from last known state.`,
      source_knowledge: 'aimos.js /agent-state — BDI agent state persistence (Feature 4)'
    });

    res.json({ success: true, state: result.rows[0] });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});

// Mutable autonomy configuration was retired. Runtime autonomy is derived from
// the verified append-only capability ledger in agent-confidence-calibration.
router.get('/autonomy/:agentId', (_req, res) => res.status(410).json({
  error: 'mutable_autonomy_config_retired',
  authority: 'aimos_authorization_events',
}));
router.put('/autonomy/:agentId', (_req, res) => res.status(410).json({
  error: 'mutable_autonomy_config_retired',
  authority: 'POST /permissions/set',
}));

// ─── A-MEM ZETTELKASTEN: GET /aimos/cross-refs/:memoryId ─────────────────────
// Returns all memories linked to the given memoryId, sorted by similarity desc.
// Query param: company_id (defaults to COMPANY_ID env or 'hom')
router.get('/cross-refs/:memoryId', async (req, res, next) => {
  const company = (req.query.company_id || AIMOS_COMPANY_ID).trim();
  const memoryId = (req.params.memoryId || '').trim();

  if (!memoryId) {
    return res.status(400).json({ error: 'memoryId is required' });
  }

  try {
    const result = await query(
      `SELECT
         cr.id            AS link_id,
         cr.target_memory_id,
         cr.similarity,
         cr.created_at    AS linked_at,
         m.key,
         m.value,
         m.memory_type,
         m.memory_tier,
         m.agent_id,
         m.created_at     AS memory_created_at
       FROM memory_cross_refs cr
       JOIN aimos_memories m
         ON m.id = cr.target_memory_id
        AND m.company_id = cr.company_id
       WHERE cr.company_id = $1
         AND cr.source_memory_id = $2
       ORDER BY cr.similarity DESC`,
      [company, memoryId]
    );

    res.json({
      memory_id: memoryId,
      linked_count: result.rows.length,
      links: result.rows
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
});
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────

// ─── GAP 1: PROCEDURAL MEMORY / SKILL LIBRARY (VOYAGER + CoALA) ──────────────

// Save or update a procedural skill
router.post('/skills', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id = 'system', skill_name, trigger_pattern, steps = [], expected_outcome, tags = [] } = req.body;
    if (!skill_name) return res.status(400).json({ error: 'skill_name required' });
    const result = await query(
      `INSERT INTO procedural_skills (company_id, agent_id, skill_name, trigger_pattern, steps, expected_outcome, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (company_id, skill_name) DO UPDATE SET
         steps = EXCLUDED.steps, trigger_pattern = EXCLUDED.trigger_pattern,
         expected_outcome = EXCLUDED.expected_outcome, tags = EXCLUDED.tags,
         agent_id = EXCLUDED.agent_id, updated_at = NOW()
       RETURNING id, skill_name`,
      [company_id, agent_id, skill_name, trigger_pattern, JSON.stringify(steps), expected_outcome, tags]
    );
    res.json({ saved: true, skill: result.rows[0] });
  } catch (err) {
    console.error('[aimos] POST /skills error:', err.message);
    err.statusCode = 500;
    next(err);
  }
});

// Record a skill use (success or failure)
router.put('/skills/:id/use', async (req, res, next) => {
  try {
    const { success = true } = req.body;
    const col = success ? 'success_count' : 'fail_count';
    const result = await query(
      `UPDATE procedural_skills SET ${col} = ${col} + 1, last_used = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Skill not found' });
    res.json({ updated: true, skill: result.rows[0] });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Recall skills by agent, tags, or search
router.get('/skills', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id, tag, q, limit = 20 } = req.query;
    let sql = `SELECT * FROM procedural_skills WHERE company_id = $1`;
    const params = [company_id];
    if (agent_id) { params.push(agent_id); sql += ` AND agent_id = $${params.length}`; }
    if (tag) { params.push(tag); sql += ` AND $${params.length} = ANY(tags)`; }
    if (q) { params.push(`%${q}%`); sql += ` AND (skill_name ILIKE $${params.length} OR trigger_pattern ILIKE $${params.length} OR expected_outcome ILIKE $${params.length})`; }
    sql += ` ORDER BY last_used DESC NULLS LAST, success_count DESC LIMIT ${parseInt(limit, 10)}`;
    const result = await query(sql, params);
    res.json({ skills: result.rows, count: result.rows.length });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 3: OUTCOME TRACKING / RECOMMENDATION LOG ───────────────────────────

// Log a recommendation with confidence and outcome window
router.post('/recommendations', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id = getOperatorAgentId(), recommendation, confidence, outcome_window_hours = 24, context = {} } = req.body;
    if (!recommendation || confidence == null) return res.status(400).json({ error: 'recommendation and confidence required' });
    const due = new Date(Date.now() + outcome_window_hours * 3600000).toISOString();
    const normalizedAgentId = normalizeOperatorAgentId(agent_id);
    const result = await query(
      `INSERT INTO recommendation_log (company_id, agent_id, recommendation, confidence_at_time, outcome_window_hours, outcome_due_at, context)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, recommendation, confidence_at_time, outcome_due_at`,
      [company_id, normalizedAgentId, recommendation, confidence, outcome_window_hours, due, JSON.stringify(context)]
    );
    res.json({ logged: true, recommendation: result.rows[0] });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Score a recommendation outcome
router.put('/recommendations/:id/score', async (req, res, next) => {
  try {
    const { actual_outcome, outcome_score } = req.body;
    if (!actual_outcome || outcome_score == null) return res.status(400).json({ error: 'actual_outcome and outcome_score required' });
    const result = await query(
      `UPDATE recommendation_log SET actual_outcome = $1, outcome_score = $2, scored_at = NOW() WHERE id = $3 RETURNING *`,
      [actual_outcome, outcome_score, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Recommendation not found' });

    // ─── GAP 4: FEEDBACK LOOP — outcome → procedural_skills ──────────────
    // If the recommendation has context.skill_ids, feed outcome back
    const rec = result.rows[0];
    let skillFeedback = null;
    try {
      const ctx = typeof rec.context === 'string' ? JSON.parse(rec.context) : (rec.context || {});
      const skillIds = ctx.skill_ids || ctx.skillIds || [];
      if (skillIds.length > 0) {
        const isPositive = parseFloat(outcome_score) >= 0.5;
        const col = isPositive ? 'success_count' : 'fail_count';
        for (const sid of skillIds) {
          await query(
            `UPDATE procedural_skills SET ${col} = ${col} + 1, last_used = NOW(), updated_at = NOW() WHERE id = $1`,
            [sid]
          );
        }
        skillFeedback = { skills_updated: skillIds.length, direction: isPositive ? 'success' : 'fail' };
      }
    } catch { /* skill feedback is best-effort */ }
    // ───────────────────────────────────────────────────────────────────────

    res.json({ scored: true, recommendation: result.rows[0], skillFeedback });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Get recommendations (with optional filter for unscored/due)
router.get('/recommendations', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id, unscored, limit = 20 } = req.query;
    let sql = `SELECT * FROM recommendation_log WHERE company_id = $1`;
    const params = [company_id];
    if (agent_id) { params.push(agent_id); sql += ` AND agent_id = $${params.length}`; }
    if (unscored === 'true') sql += ` AND actual_outcome IS NULL`;
    sql += ` ORDER BY created_at DESC LIMIT ${parseInt(limit, 10)}`;
    const result = await query(sql, params);
    res.json({ recommendations: result.rows, count: result.rows.length });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Get calibration stats (average delta between confidence and outcome)
router.get('/recommendations/calibration', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id } = req.query;
    let sql = `SELECT agent_id, COUNT(*) as total,
       AVG(outcome_score) as avg_outcome, AVG(confidence_at_time) as avg_confidence,
       AVG(ABS(outcome_score - confidence_at_time)) as avg_delta
       FROM recommendation_log WHERE company_id = $1 AND outcome_score IS NOT NULL`;
    const params = [company_id];
    if (agent_id) { params.push(agent_id); sql += ` AND agent_id = $${params.length}`; }
    sql += ` GROUP BY agent_id`;
    const result = await query(sql, params);
    res.json({ calibration: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 5: CROSS-SESSION REASONING CONTINUITY ──────────────────────────────

// Save reasoning state (hypotheses, evidence, open questions) for an agent
router.post('/reasoning-state', async (req, res, next) => {
  try {
    const { company_id = AIMOS_COMPANY_ID, agent_id, hypotheses = [], evidence = [], open_questions = [], chain = [] } = req.body;
    const verifiedAgentId = req.agentId || req.identityCert?.agent_id || null;
    if (!verifiedAgentId) return res.status(401).json({ success: false, error: 'verified_agent_required' });
    if (agent_id && agent_id !== verifiedAgentId) {
      return res.status(403).json({ success: false, error: 'agent_identity_mismatch' });
    }
    const normalizedAgentId = normalizeOperatorAgentId(verifiedAgentId);
    const key = `reasoning_state:${normalizedAgentId}`;
    const value = JSON.stringify({ hypotheses, evidence, open_questions, chain, saved_at: new Date().toISOString() });
    // Route through persistMemory() for quality gate, cross-refs, entity extraction
    const saved = await persistMemory({
      company_id,
      agent_id: normalizedAgentId,
      key,
      value,
      scope: 'system',
      clearance_level: 3,
      memory_type: 'reasoning_state',
      mutation_authority: 'housekeeper'
    });
    if (saved?.rejected) {
      return res.status(422).json({ saved: false, reason: saved.reason });
    }
    res.json({ saved: true, key, memory_id: saved?.id });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Recall reasoning state for an agent (used on boot)
router.get('/reasoning-state', async (req, res, next) => {
  try {
    const { company_id = 'hom', agent_id = getOperatorAgentId() } = req.query;
    const normalizedAgentId = normalizeOperatorAgentId(agent_id);
    const result = await query(
      `SELECT key, value, updated_at FROM aimos_memories
       WHERE company_id = $1 AND agent_id = $2 AND memory_type = 'reasoning_state'
       ORDER BY updated_at DESC LIMIT 1`,
      [company_id, normalizedAgentId]
    );
    if (!result.rows.length) return res.json({ state: null });
    const row = result.rows[0];
    const parsed = typeof row.value === 'string' ? JSON.parse(row.value) : row.value;
    res.json({ state: parsed, updated_at: row.updated_at });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 4: INTERVENTION COST MATRIX ────────────────────────────────────────

// Get cost matrix
router.get('/cost-matrix', async (req, res, next) => {
  try {
    const { company_id = 'hom' } = req.query;
    const result = await query(`SELECT * FROM intervention_cost_matrix WHERE company_id = $1 ORDER BY action_type`, [company_id]);
    res.json({ matrix: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// Upsert cost matrix entry
router.post('/cost-matrix', async (req, res, next) => {
  try {
    const { company_id = 'hom', action_type, fp_cost = 0, fn_cost = 0, tp_benefit = 0, tn_benefit = 0, notes } = req.body;
    if (!action_type) return res.status(400).json({ error: 'action_type required' });
    const result = await query(
      `INSERT INTO intervention_cost_matrix (company_id, action_type, fp_cost, fn_cost, tp_benefit, tn_benefit, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (company_id, action_type) DO UPDATE SET
         fp_cost = EXCLUDED.fp_cost, fn_cost = EXCLUDED.fn_cost,
         tp_benefit = EXCLUDED.tp_benefit, tn_benefit = EXCLUDED.tn_benefit,
         notes = EXCLUDED.notes, updated_at = NOW()
       RETURNING *`,
      [company_id, action_type, fp_cost, fn_cost, tp_benefit, tn_benefit, notes]
    );
    res.json({ saved: true, entry: result.rows[0] });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── GAP 7: FRAGILITY LABELS ────────────────────────────────────────────────

router.get('/fragility', async (req, res, next) => {
  try {
    const { company_id = 'hom' } = req.query;
    const result = await query(`SELECT * FROM fragility_labels WHERE company_id = $1 ORDER BY fragility, component`, [company_id]);
    res.json({ labels: result.rows });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.post('/fragility', async (req, res, next) => {
  try {
    const { company_id = 'hom', component, fragility, rationale } = req.body;
    if (!component || !fragility) return res.status(400).json({ error: 'component and fragility required' });
    const result = await query(
      `INSERT INTO fragility_labels (company_id, component, fragility, rationale)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (company_id, component) DO UPDATE SET
         fragility = EXCLUDED.fragility, rationale = EXCLUDED.rationale, updated_at = NOW()
       RETURNING *`,
      [company_id, component, fragility, rationale]
    );
    res.json({ saved: true, label: result.rows[0] });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// MCP ENDPOINT — Model Context Protocol (Anthropic standard)
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/mcp/tools/list', (req, res) => {
  res.json({
    tools: [
      {
        name: 'aimos_recall',
        description: 'Retrieve memories from HOM Aimos by semantic search',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
            company_id: { type: 'string', default: 'hom' },
            limit: { type: 'integer', default: 5 }
          },
          required: ['query']
        }
      },
      {
        name: 'aimos_save',
        description: 'Save a memory to HOM Aimos',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string' },
            value: { type: 'string' },
            company_id: { type: 'string', default: 'hom' },
            agent_id: { type: 'string', default: 'external' },
            memory_type: { type: 'string', default: 'declarative' },
            scope: { type: 'string', default: 'global' }
          },
          required: ['key', 'value']
        }
      }
    ]
  });
});

router.post('/mcp/tools/call', async (req, res, next) => {
  const { name, arguments: args = {} } = req.body;
  try {
    if (name === 'aimos_recall') {
      const requestAuthority = {
        kind: 'verified_request',
        body: req.body,
        agentId: req.executionContext?.actorAgentId,
        validFromIso: req.executionContext?.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        identityTier: req.identityTier,
        claimedPrev: req.prevChainHash || null,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        signedClaims: req.identitySignedClaims,
      };
      const recallAuthority = await resolveNativeRecallAuthority({
        rawCommand: args,
        executionContext: req.executionContext,
        requestAuthority,
        transportBinding: { transport: 'legacy_mcp' },
      });
      const result = await executeNativeRecall(req, recallAuthority);
      return res.status(result.status).json({
        content: [{ type: 'text', text: JSON.stringify(result.body) }],
        recall: result.body,
      });
    }

    if (name === 'aimos_save') {
      // ─── UNIFIED SAVE: Route MCP through persistMemory() — same quality gate,
      // governance, write-validation, cross-refs, entity extraction as normal save.
      // Fixes the MCP bypass that allowed junk writes to skip all protections.
      const { key, value, company_id, agent_id, memory_type = 'declarative', scope = 'global', clearance_level = 1, source } = args;
      if (!key || !value) return res.status(400).json({ error: 'key and value required' });
      const actor = req.executionContext?.actorAgentId;
      const company = req.executionContext?.companyId;
      if (!actor || !company || req.identityAuthenticatedBy !== 'envelope') {
        return res.status(403).json({ error: 'verified envelope authority is required for MCP save' });
      }
      if ((company_id && company_id !== company) || (agent_id && agent_id !== actor)) {
        return res.status(403).json({ error: 'signed MCP save actor or company mismatch' });
      }
      const requestAuthority = {
        kind: 'verified_request',
        body: req.body,
        agentId: actor,
        validFromIso: req.executionContext.actorValidFromIso,
        certString: req.identityCertString,
        signedTs: req.identitySignedTs,
        nonce: req.identityNonce,
        sigBytes: req.identitySigBytes,
        identityTier: req.identityTier,
        claimedPrev: req.prevChainHash || null,
        requestSigForm: req.identityRequestSigForm,
        signedMethod: req.identitySignedMethod,
        signedPath: req.identitySignedPath,
        signedClaims: req.identitySignedClaims,
      };
      const saved = await persistMemory({
        company_id: company,
        agent_id: actor,
        key,
        value,
        scope,
        clearance_level,
        memory_type,
        source,
        mutation_authority: requestAuthority,
      });
      if (saved?.rejected) {
        return res.status(422).json({
          error: `Quality gate rejected: ${saved.reason}`,
          content: [{ type: 'text', text: `Rejected: ${saved.reason} (score: ${saved.quality_score})` }]
        });
      }
      return res.json({
        content: [{ type: 'text', text: `Saved: ${saved?.id}` }],
        memory_id: saved?.id || null,
        content_hash: saved?.live_content_hash?.toString('hex') || null,
        save_mutation_hash: saved?.ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: saved?.binding_commit?.mutationHash?.toString('hex') || null,
        epistemic_label: saved?.epistemic_label || 'unverified',
        epistemic_confidence_milli: Number(saved?.epistemic_confidence_milli || 0),
        epistemic_classification_event_id: saved?.epistemic_classification_event_id || null,
        epistemic_classification_hash: saved?.epistemic_classification_hash || null,
      });
    }

    return res.status(400).json({ error: `Unknown tool: ${name}` });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// QMD — Query Memory Database
// Structured graph query language for Aimos's memory brain.
// ═══════════════════════════════════════════════════════════════════════════════
import { parseQMD, QMDSyntaxError }  from '../services/retrieval/qmd-parser.js';
import { executeQMD, buildQueryPlan } from '../services/retrieval/qmd-planner.js';

/**
 * POST /aimos/qmd
 * Body: { query: string, company_id?, agent_id?, clearance_level? }
 * Response: { results, query_plan, ast, execution_time_ms }
 *
 * Examples:
 *   { "query": "FIND type:framework WHERE contains('positioning') HOPS 2 LIMIT 10" }
 *   { "query": "TRAVERSE FROM key:\"F1*\" FOLLOW cross_refs,entity_edges HOPS 3" }
 *   { "query": "COUNT type:event_log WHERE created > 24h GROUP BY agent_id" }
 */
router.post('/qmd', async (req, res, next) => {
  const {
    query: rawQuery,
    company_id,
    agent_id,
    clearance_level
  } = req.body || {};

  if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) {
    return res.status(400).json({ error: 'Missing required field: query (string)' });
  }

  const company        = (company_id   || AIMOS_COMPANY_ID).trim();
  const requestingAgent = normalizeOperatorAgentId(agent_id);
  const clearance      = Number(clearance_level || 5);

  const t0 = Date.now();

  let ast;
  try {
    ast = parseQMD(rawQuery.trim());
  } catch (err) {
    if (err instanceof QMDSyntaxError || err.name === 'QMDSyntaxError') {
      err.statusCode = 400;
      return next(err);
    }
    err.statusCode = 400;
    next(err);
  }

  try {
    const outcome = await executeQMD(ast, { company, clearance, requestingAgent });

    const execution_time_ms = Date.now() - t0;

    // Log event for observability (non-fatal)
    logEvent(company, requestingAgent, 'qmd_query', rawQuery.slice(0, 120), {
      reasoning: `QMD query executed by '${requestingAgent}': natural language query parsed to AST, translated to SQL with same ACL as recall. QMD is the structured query interface — when recall's semantic search isn't precise enough.`,
      source_knowledge: 'aimos.js QMD parser — recursive descent parser with 6 verbs (Feature from cybersec session)'
    }).catch(() => {});

    return res.json({
      results:          outcome.results,
      meta:             outcome.meta,
      query_plan:       outcome.query_plan,
      ast,
      execution_time_ms
    });
  } catch (err) {
    console.error('[qmd] execution error:', err.message);
    return res.status(500).json({
      error:     err.message,
      ast,
      query:     rawQuery,
      execution_time_ms: Date.now() - t0
    });
  }
});

/**
 * GET /aimos/qmd/explain
 * Query param: q=FIND type:framework...
 * Returns the parsed AST, query plan, and estimated cost — WITHOUT executing.
 */
router.get('/qmd/explain', (req, res, next) => {
  const rawQuery = (req.query.q || '').trim();

  if (!rawQuery) {
    return res.status(400).json({ error: 'Missing query param: q' });
  }

  let ast;
  try {
    ast = parseQMD(rawQuery);
  } catch (err) {
    if (err instanceof QMDSyntaxError || err.name === 'QMDSyntaxError') {
      err.statusCode = 400;
      return next(err);
    }
    err.statusCode = 400;
    next(err);
  }

  const query_plan = buildQueryPlan(ast);

  // Build a human-readable SQL preview (parameterized, not executable as-is)
  const sql_preview = buildSQLPreview(ast);

  return res.json({ ast, query_plan, sql_preview, estimated_cost: query_plan.estimated_cost });
});

/** Produce a non-executable, human-readable SQL sketch for /explain */
function buildSQLPreview(ast) {
  switch (ast.verb) {
    case 'FIND': {
      const typeF  = ast.filters?.find(f => f.field === 'type')?.value;
      const keyF   = ast.filters?.find(f => f.field === 'key')?.value;
      const contains = ast.where?.find(w => w.type === 'contains')?.value;
      return [
        `SELECT id, key, value, memory_type, memory_tier, ...`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        typeF    ? `  AND memory_type = '${typeF}'` : null,
        keyF     ? `  AND key ILIKE '${keyF.replace(/\*/g, '%')}'` : null,
        contains ? `  AND (key ILIKE '%${contains}%' OR value ILIKE '%${contains}%')` : null,
        `  -- vector: ORDER BY embedding <=> :query_vector`,
        `LIMIT ${ast.limit || 10};`,
        ast.hops > 1 ? `-- then: WITH RECURSIVE graph_walk ... (${ast.hops} hops)` : null,
      ].filter(Boolean).join('\n');
    }
    case 'TRAVERSE': {
      const follow = ast.follow?.join(', ');
      return [
        `-- anchor resolution:`,
        `SELECT id FROM aimos_memories WHERE company_id = :company AND ${ast.from?.field} ILIKE '${ast.from?.value}'`,
        ``,
        `-- recursive traversal (${ast.hops} hops) via: ${follow}`,
        `WITH RECURSIVE graph_walk AS (`,
        `  SELECT target_memory_id, similarity, 1 AS hop FROM memory_cross_refs WHERE source_memory_id = ANY(:anchor_ids)`,
        `  UNION ALL`,
        `  SELECT cr.target_memory_id, cr.similarity, gw.hop + 1 FROM graph_walk gw JOIN memory_cross_refs cr ON ...`,
        `  WHERE gw.hop < ${ast.hops}`,
        `)`,
        `SELECT ... FROM graph_walk JOIN aimos_memories ... LIMIT ${ast.limit || 50};`,
      ].join('\n');
    }
    case 'MATCH': {
      return [
        `SELECT id, key, value, memory_type, memory_tier, ...`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        ...( ast.filters?.map(f => `  AND ${f.field} = '${f.value}'`) || [] ),
        `  -- plus WHERE conditions from parsed clauses`,
        `ORDER BY memory_tier_rank ASC, created_at DESC`,
        `LIMIT ${ast.limit || 20};`,
      ].join('\n');
    }
    case 'GRAPH': {
      return [
        `-- center: ${ast.center?.field}=${ast.center?.value}`,
        `WITH RECURSIVE graph_walk AS (`,
        `  SELECT target_memory_id AS mem_id, similarity, 1 AS hop`,
        `  FROM memory_cross_refs WHERE source_memory_id = :center_id`,
        `  UNION ALL`,
        `  SELECT cr.target_memory_id, cr.similarity, gw.hop + 1`,
        `  FROM graph_walk gw JOIN memory_cross_refs cr ON ...`,
        `  WHERE gw.hop < ${ast.hops}`,
        `)`,
        `SELECT ... FROM graph_walk JOIN aimos_memories ... LIMIT ${ast.limit || 50};`,
        `-- RETURN format: ${ast.return || 'default'}`,
      ].join('\n');
    }
    case 'PATH': {
      return [
        `-- from: ${ast.from?.field}=${ast.from?.value}`,
        `-- to:   ${ast.to?.field}=${ast.to?.value}`,
        `WITH RECURSIVE path_walk AS (`,
        `  SELECT source_memory_id AS current_id, target_memory_id AS next_id, 1 AS depth, ARRAY[source_memory_id] AS visited, ...`,
        `  FROM memory_cross_refs WHERE source_memory_id = ANY(:from_ids)`,
        `  UNION ALL`,
        `  SELECT pw.next_id, cr.target_memory_id, pw.depth + 1, pw.visited || pw.next_id, ...`,
        `  FROM path_walk pw JOIN memory_cross_refs cr ON ... WHERE pw.depth < ${ast.max_depth}`,
        `)`,
        `SELECT path_ids, depth FROM path_walk WHERE next_id = ANY(:to_ids) ORDER BY depth ASC LIMIT ${ast.limit || 20};`,
      ].join('\n');
    }
    case 'COUNT': {
      const typeF = ast.filters?.find(f => f.field === 'type')?.value;
      const grp   = ast.group_by;
      return [
        `SELECT ${grp ? `${grp}, ` : ''}COUNT(*) AS count`,
        `FROM aimos_memories`,
        `WHERE company_id = :company AND clearance_level <= :clearance`,
        typeF ? `  AND memory_type = '${typeF}'` : null,
        `  -- plus WHERE conditions from parsed clauses`,
        grp ? `GROUP BY ${grp}` : null,
        `ORDER BY count DESC;`,
      ].filter(Boolean).join('\n');
    }
    default:
      return '-- unknown verb';
  }
}
// ─────────────────────────────────────────────────────────────────────────────

// The unsigned demo disclosure path is retired. Screen-safe recall is a
// terminal projection of the same signed, provenance-admitted POST pipeline.
router.all('/recall/demo', (_req, res) => res.status(410).json({
  success: false,
  error: 'demo_recall_moved_to_signed_post',
  endpoint: '/aimos/recall',
  method: 'POST',
  projection: 'demo_redacted',
}));

// ─── MEDALLION: Time-travel query ─────────────────────────────────────────────
// Returns the state of a memory key at time T by walking the supersession chain
router.get('/time-travel', async (req, res, next) => {
  const { key, as_of, agent_id, company_id } = req.query;
  const company = company_id || AIMOS_COMPANY_ID;
  const agentId = normalizeOperatorAgentId(agent_id);

  if (!key || !as_of) {
    return res.status(400).json({ error: 'key and as_of (ISO timestamp) required' });
  }

  const asOfDate = new Date(as_of);
  if (isNaN(asOfDate.getTime())) {
    return res.status(400).json({ error: 'as_of must be a valid ISO timestamp' });
  }

  try {
    await ensureMedallionColumn();
    // Walk supersession chain: find the memory that was active at as_of
    // A memory was "active" at time T if created_at <= T AND (superseded by something with created_at > T, or never superseded)
    const result = await query(
      `WITH RECURSIVE chain AS (
        -- Start: the most recent memory for this key created before as_of
        SELECT m.id, m.key, m.value, m.created_at, m.supersedes_id, m.memory_type, m.medallion_layer, m.agent_id, 0 AS depth
        FROM aimos_memories m
        WHERE m.key = $1 AND m.company_id = $2 AND m.agent_id = $3
          AND m.created_at <= $4
        ORDER BY m.created_at DESC
        LIMIT 1
      )
      SELECT * FROM chain ORDER BY created_at DESC LIMIT 1`,
      [key, company, agentId, asOfDate.toISOString()]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: 'No memory found for that key at the specified time',
        key, as_of, agent_id: agentId
      });
    }

    const mem = result.rows[0];
    return res.json({
      key: mem.key,
      value: mem.value,
      memory_type: mem.memory_type,
      medallion_layer: mem.medallion_layer,
      agent_id: mem.agent_id,
      created_at: mem.created_at,
      as_of: as_of,
      snapshot: true
    });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

router.get('/medallion-stats', async (req, res, next) => {
  const { company_id } = req.query;
  const company = company_id || AIMOS_COMPANY_ID;
  try {
    await ensureMedallionColumn();
    const result = await query(
      `SELECT medallion_layer, COUNT(*) as count,
              AVG(decay_weight) as avg_weight,
              MAX(created_at) as latest
       FROM aimos_memories
       WHERE company_id = $1
       GROUP BY medallion_layer`,
      [company]
    );
    const stats = {};
    for (const row of result.rows) {
      stats[row.medallion_layer || 'bronze'] = {
        count: parseInt(row.count),
        avg_weight: parseFloat(row.avg_weight || 1),
        latest: row.latest
      };
    }
    return res.json({ company_id: company, layers: stats });
  } catch (err) {
    err.statusCode = 500;
    next(err);
  }
});

// ─── POST /aimos/embed — Generate embeddings locally ─────────────────────────
// Returns 768-dimension embedding vector using all-mpnet-base-v2.
// PAPER CONTEXT: Zero external API calls after initial model download (~80MB).
router.post('/embed', async (req, res) => {
  const { text } = req.body;

  if (!text || typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({
      error: 'Missing required field: text (string)',
      embedding: null,
      dimensions: 768,
      model: 'all-mpnet-base-v2'
    });
  }

  try {
    const embedding = await getEmbedding(text);

    if (!embedding) {
      return res.status(500).json({
        error: 'Failed to generate embedding',
        embedding: null,
        dimensions: 768,
        model: 'all-mpnet-base-v2'
      });
    }

    return res.json({
      embedding,
      dimensions: embedding.length,
      model: 'Xenova/all-mpnet-base-v2',
      stats: getEmbeddingHealth()
    });
  } catch (err) {
    return res.status(500).json({
      error: err.message,
      embedding: null,
      dimensions: 768,
      model: 'all-mpnet-base-v2'
    });
  }
});

// ─── GET /aimos/embed/stats — Embedding health status ──────────────────────────
router.get('/embed/stats', (_req, res) => {
  res.json({
    model: 'Xenova/all-mpnet-base-v2',
    dimensions: 768,
    ...getEmbeddingHealth()
  });
});


export default router;
