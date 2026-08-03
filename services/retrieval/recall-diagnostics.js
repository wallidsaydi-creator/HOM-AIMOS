/**
 * recall-diagnostics.js — Phase 1A retrieval evaluation envelope
 * Sources: RAGChecker: A Fine-grained Framework for Diagnosing
 * Retrieval-Augmented Generation (2024); BRIGHT: A Realistic and Challenging
 * Benchmark for Reasoning-Intensive Retrieval (2024);
 * ReAlign: Reasoning-Guided Fine-Grained Alignment (Batch 7);
 * Additive Batch8 authority: Reasoning Graphs: Self-Improving,
 * Deterministic RAG through Evidence-Centric Feedback
 * Additive Batch8 Wave 3 authority: MERIT and VerifAI. Aimos exposes
 * interpretable evidence-trail and claim-verification diagnostics only; no
 * retrieval ranking, NLI, or knowledge-tracing model is trained here.
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js for every recall response shape
 * 2. → Emits: diagnostic-only recall evaluation metadata
 * 3. ↔ Interacts with: recall-mode-planner.js, Chronos, MAGMA, procedural recall
 *
 * LOGIC GUIDE:
 * This service does not score, rank, rerank, calibrate, or change retrieval
 * outcomes. It packages evidence counts, source coverage, fallback posture, and
 * reasoning-intensity markers so Aimos can explain retrieval quality without
 * touching Sortify/MVS/calibration math.
 *
 * ReAlign guardrail: Aimos exposes evidence-localization diagnostics inspired
 * by reasoning-guided alignment, but does not implement the visual retriever KL
 * objective or alter ranking distributions in this service.
 */

const THIN_EVIDENCE_LIMIT = 2;

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function countBy(items, selector) {
  const counts = {};
  for (const item of asArray(items)) {
    const key = String(selector(item) || 'unknown').trim() || 'unknown';
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function uniqueSorted(values) {
  return Array.from(new Set(values.filter(Boolean).map(String))).sort();
}

function inferSourceTables(memories, recallMeta = {}) {
  const fromMemories = asArray(memories).map((memory) => memory.evidence_table || memory.source);
  const chronosTables = asArray(recallMeta?.chronos?.diagnostics?.source_tables);
  return uniqueSorted([...fromMemories, ...chronosTables]);
}

function inferFallback(recallMeta = {}) {
  const chronos = recallMeta.chronos?.diagnostics || {};
  const magma = recallMeta.magma?.diagnostics || {};
  const procedural = recallMeta.procedural_reasoning?.diagnostics || {};
  return {
    used: Boolean(chronos.fallback_used || magma.fallback_used || procedural.fallback_used),
    reason: chronos.fallback_reason || magma.fallback_reason || procedural.fallback_reason || null,
    semantic_fallback: Boolean(chronos.semantic_fallback || magma.semantic_fallback || procedural.semantic_fallback),
  };
}

function inferStatus({ totalResults, insufficientEvidence, fallback }) {
  if (insufficientEvidence || totalResults === 0) {
    return 'insufficient_evidence';
  }
  if (totalResults < THIN_EVIDENCE_LIMIT) {
    return 'thin_evidence';
  }
  if (fallback.used) {
    return 'sufficient_with_labeled_fallback';
  }
  return 'sufficient_evidence';
}

function isReasoningIntensive(planner = {}) {
  return ['reasoning_trace', 'lineage_navigation', 'temporal', 'corpus_analytics'].includes(planner.mode);
}

export function buildReasoningGuidedAlignmentDiagnostics({
  queryText = '',
  memories = [],
  recallMeta = {},
} = {}) {
  const queryTokens = new Set(
    String(queryText || '')
      .toLowerCase()
      .split(/[^a-z0-9_:-]+/)
      .filter((token) => token.length >= 4)
  );
  const evidenceDescriptions = asArray(memories).slice(0, 8).map((memory) => {
    const text = `${memory.key || ''} ${memory.value || ''}`.toLowerCase();
    const matchedTokens = [...queryTokens].filter((token) => text.includes(token));
    return {
      key: memory.key || memory.id || null,
      memory_type: memory.memory_type || null,
      source: memory.source || memory.evidence_table || null,
      localized_evidence_available: matchedTokens.length > 0 || Boolean(memory.identifier_match?.exact),
      matched_query_tokens: matchedTokens.slice(0, 6),
      excerpt: String(memory.value || '').slice(0, 220),
    };
  });

  const localizedCount = evidenceDescriptions.filter((entry) => entry.localized_evidence_available).length;
  const lineagePathCount = Array.isArray(recallMeta?.magma?.paths) ? recallMeta.magma.paths.length : 0;
  const temporalEvidenceCount = Number(recallMeta?.chronos?.diagnostics?.structured_event_count || 0) +
    Number(recallMeta?.chronos?.diagnostics?.raw_turn_count || 0);

  return {
    source_paper: 'ReAlign: Optimizing the Visual Document Retriever with Reasoning-Guided Fine-Grained Alignment',
    diagnostic_only: true,
    query_focused_evidence_count: localizedCount,
    evidence_description_count: evidenceDescriptions.length,
    lineage_path_count: lineagePathCount,
    temporal_evidence_count: temporalEvidenceCount,
    evidence_descriptions: evidenceDescriptions,
    guarded_math: {
      kl_distribution_alignment: false,
      contrastive_retraining: false,
      visual_region_attention: false,
    },
    ranking_math_changed: false,
  };
}

export function buildRecallEvaluation({
  queryText = '',
  planner = {},
  memories = [],
  directMode = null,
  recallMeta = {},
  insufficientEvidence = false,
  insufficiencyReason = null,
} = {}) {
  const resultCount = asArray(memories).length;
  const fallback = inferFallback(recallMeta);
  const status = inferStatus({
    totalResults: resultCount,
    insufficientEvidence,
    fallback,
  });
  const memoryTypes = countBy(memories, (memory) => memory.memory_type || memory.memoryType);
  const freshnessStates = countBy(memories, (memory) => memory.freshness_state || memory.freshness?.freshness_state);
  const chronosDiagnostics = recallMeta?.chronos?.diagnostics || null;
  const magmaDiagnostics = recallMeta?.magma?.diagnostics || null;
  const proceduralDiagnostics = recallMeta?.procedural_reasoning?.diagnostics || null;
  const reasoningGraph = recallMeta?.synthesis?.evidence_graph || null;
  const evidenceTrail = recallMeta?.synthesis?.evidence_trail || null;

  return {
    diagnostic_only: true,
    source_papers: ['RAGChecker', 'BRIGHT', 'ReAlign', 'MERIT', 'VerifAI'],
    mode: planner.mode || directMode || 'unknown',
    direct_mode: directMode,
    supported: planner.supported ?? null,
    status,
    query: String(queryText || '').slice(0, 240),
    evidence: {
      total_results: resultCount,
      source_tables: inferSourceTables(memories, recallMeta),
      memory_types: memoryTypes,
      freshness_states: freshnessStates,
      structured_event_count: chronosDiagnostics?.structured_event_count ?? null,
      raw_turn_count: chronosDiagnostics?.raw_turn_count ?? null,
      lineage_path_count: Array.isArray(recallMeta?.magma?.paths) ? recallMeta.magma.paths.length : null,
      reasoning_artifact_count: proceduralDiagnostics?.reasoning_artifact_count ?? null,
      procedure_candidate_count: proceduralDiagnostics?.procedure_candidate_count ?? null,
      reasoning_graph: reasoningGraph
        ? {
            graph_type: reasoningGraph.graph_type || null,
            status: reasoningGraph.status || null,
            source_paper: reasoningGraph.source_paper || null,
            diagnostic_only: reasoningGraph.diagnostic_only === true,
            node_count: reasoningGraph.node_count ?? null,
            edge_count: reasoningGraph.edge_count ?? null,
            guardrails: reasoningGraph.guardrails || null,
        }
        : null,
      interpretable_evidence_trail: evidenceTrail
        ? {
            diagnostic_only: evidenceTrail.diagnostic_only === true,
            source_papers: evidenceTrail.source_papers || [],
            trail_count: evidenceTrail.trail_count ?? 0,
            trail: Array.isArray(evidenceTrail.trail) ? evidenceTrail.trail.slice(0, 8) : [],
            ranking_math_changed: evidenceTrail.ranking_math_changed === true,
            hidden_chain_of_thought_exposed: evidenceTrail.hidden_chain_of_thought_exposed === true,
          }
        : null,
      reasoning_guided_alignment: buildReasoningGuidedAlignmentDiagnostics({
        queryText,
        memories,
        recallMeta,
      }),
    },
    fallback,
    failure: status === 'insufficient_evidence'
      ? {
          reason: insufficiencyReason || recallMeta?.insufficiency_reason || fallback.reason || 'no_evidence_returned',
          attempted_mode: planner.mode || directMode || 'unknown',
        }
      : null,
    reasoning_intensive: isReasoningIntensive(planner),
    guardrails: {
      ranking_math_changed: false,
      calibration_math_changed: false,
      diagnostic_envelope_only: true,
    },
  };
}
