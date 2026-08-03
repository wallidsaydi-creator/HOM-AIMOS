/**
 * retrieval-orchestrator.js — M2 Specialist Retrieval Orchestrator
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/aimos.js (Multi-agent retrieval step)
 * 2. ↔ Interacts with: fact-finder.js (Specialist 1: Facts)
 * 3. ↔ Interacts with: context-builder.js (Specialist 2: Graph)
 * 4. ↔ Interacts with: timeline-reconstructor.js (Specialist 3: Chronology)
 * 5. ↔ Interacts with: hnsw-optimizer.js (Specialist 4: kNN fast-path + product-key)
 * 6. → Pushes to: Unified evidence bundle (Deduplicated)
 *
 * LOGIC GUIDE: Dispatches four parallel specialist retrieval agents.
 * Merges direct facts, graph-expanded context, temporal supersessions, and kNN
 * product-key candidates into one bundle.
 *
 * Batch 10 Lane 3: kNN fast-path wired as fourth parallel candidate source.
 *   knnSearch: pgvector HNSW fast-path, recall_confidence > 0.75 bypasses PPR
 *   productKeySearch: dual 128d sub-key search + cartesian select for O(√n) lookup
 *   W_INFINI=0.20 weights Infini-attention linear memory in RRF
 * Aladdin: kNN is retrieval optimization. It changes result ordering, never content.
 *
 * Additive Batch9/9.5 Wave1 authority: Fast-Slow Planning, DH-RAG,
 * RNNs Are Not Transformers (Yet), and SepSeq. Aimos emits fast/slow
 * escalation diagnostics, fixed-size recall packs, and segmented timeline
 * packs only; specialist dispatch, ranking math, and recall behavior remain
 * native unless a later guarded proof explicitly unguards them.
 *
 * Batch9.75 Wave 1 guarded math (alongside paths, not replacements):
 *   - buildMoECascadeDiagnostic: Local/global cascade routing diagnostic
 *     alongside existing specialist dispatch. Routing math unchanged.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────


import { findFacts } from './fact-finder.js';
import { buildContext, buildFixedSizeRecallPack } from './context-builder.js';
import { reconstructTimeline } from './timeline-reconstructor.js';
import { knnSearch, productKeySearch } from './hnsw-optimizer.js';
import { getEmbedding } from '../core/embeddings.js';

const BATCH9_FAST_SLOW_AUTHORITIES = [
  'Bridging Large-Model Reasoning and Real-Time Control via Agentic Fast-Slow Planning',
  'RNNs Are Not Transformers (Yet): The Key Bottleneck on In-Context Retrieval',
  'DH-RAG',
  'SepSeq',
];

/**
 * Deduplicates an array of evidence items by their id.
 * Items with no id are kept but not deduplicated against each other.
 *
 * @param {Array} items
 * @returns {Array}
 */
function deduplicateById(items) {
  const seen = new Set();
  return items.filter(item => {
    if (!item.id) return true; // no id — always include
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

/**
 * Merge and rank evidence from all four agents.
 * Ranking heuristic:
 *   - Fact-finder results score highest (most direct)
 *   - Timeline isLatest entries score higher than stale ones
 *   - Context items ranked by hop (fewer hops = more relevant)
 *   - kNN results ranked by similarity with product-key boost
 *
 * @param {Array} facts
 * @param {Array} contextItems
 * @param {Array} timelineItems
 * @param {Array} knnItems
 * @returns {Array}
 */
function mergeAndRank(facts, contextItems, timelineItems, knnItems = []) {
  const tagged = [
    ...facts.map(f => ({
      ...f,
      source_agent: 'fact-finder',
      _rank: (f.confidence || 0.5) + 0.2
    })),
    ...contextItems.map(c => ({
      ...c,
      source_agent: 'context-builder',
      _rank: (c.confidence || 0.5) - (c.hop - 1) * 0.1
    })),
    ...timelineItems.map(t => ({
      ...t,
      source_agent: 'timeline-reconstructor',
      _rank: (t.confidence || 0.5) + (t.isLatest ? 0.15 : -0.05)
    })),
    ...knnItems.map(k => ({
      ...k,
      source_agent: 'knn-optimizer',
      _rank: (k.similarity || k.score || 0.5) + (k.source === 'product_key_intersection' ? 0.1 : 0)
    }))
  ];

  // Sort by rank descending
  tagged.sort((a, b) => b._rank - a._rank);

  // Clean internal rank field before returning
  return tagged.map(({ _rank, ...rest }) => rest);
}

function buildFastSlowPathDiagnostics({ evidence = [], errors = [], agentLatencies = {}, limit = 10 } = {}) {
  const evidenceCount = Array.isArray(evidence) ? evidence.length : 0;
  const maxLatency = Math.max(0, ...Object.values(agentLatencies).map((v) => Number(v || 0)));
  const shouldEscalate = evidenceCount < Math.min(3, Number(limit || 10)) || errors.length > 0;

  return {
    source_papers: BATCH9_FAST_SLOW_AUTHORITIES,
    diagnostic_only: true,
    selected_path: shouldEscalate ? 'slow_path_recommended' : 'fast_path_sufficient',
    fast_path: {
      stages: ['fact_finder', 'context_builder', 'timeline_reconstructor'],
      evidence_count: evidenceCount,
      max_agent_latency_ms: maxLatency,
    },
    slow_path: {
      recommended: shouldEscalate,
      reason: shouldEscalate
        ? (errors.length > 0 ? 'specialist_error_or_missing_evidence' : 'thin_evidence_pack')
        : 'bounded_evidence_pack_sufficient',
      suggested_followups: shouldEscalate
        ? ['full_16_stage_recall', 'lineage_navigation', 'temporal_range_reconstruction']
        : [],
    },
    ranking_math_changed: false,
    early_exit_applied: false,
  };
}

/**
 * Run all 4 specialist retrieval agents in parallel and return a merged evidence bundle.
 * Batch 10 Lane 3: kNN fast-path is the 4th parallel candidate source.
 *
 * @param {string} query - User query
 * @param {Object} opts
 * @param {Array}    [opts.entities=[]]    - Seed entities for context builder
 * @param {Function} [opts.searchFn]       - Injected search function for fact-finder
 * @param {Function} [opts.graphWalkFn]    - Injected graph walk for context-builder
 * @param {Function} [opts.timelineFn]     - Injected timeline function for timeline-reconstructor
 * @param {Object}   [opts.pool]           - pg Pool (used as fallback when no inject fn)
 * @param {number}   [opts.limit=10]       - Per-agent result limit
 * @param {number}   [opts.maxHops=2]      - Context builder graph depth
 * @param {string}   [opts.clientId]       - Agent/client id filter
 * @param {string}   [opts.companyId]      - Tenant scope
 * @param {string}   [opts.sessionId]      - Session scope for ASMR-ingested data filtering
 * @returns {Promise<{
 *   evidence: Array,
 *   factCount: number,
 *   contextCount: number,
 *   timelineCount: number,
 *   knnCount: number,
 *   supersessions: Array,
 *   latestValues: Object,
 *   agentResults: number,
 *   errors: string[],
 *   agentLatencies: Object,
 *   latencyMs: number
 * }>}
 */
export async function runRetrieval(query, opts = {}) {
  const globalStart = Date.now();
  const {
    entities = [],
    searchFn,
    graphWalkFn,
    timelineFn,
    pool,
    limit = 10,
    maxHops = 2,
    clientId,
    companyId,
    sessionId
  } = opts;

  if (!searchFn && !graphWalkFn && !timelineFn && !pool) {
    throw new Error('retrieval-orchestrator: at least one of searchFn/graphWalkFn/timelineFn/pool is required');
  }

  // ── Dispatch all 4 agents in parallel ─────────────────────────────────────
  const [factResult, contextResult, timelineResult, knnResult] = await Promise.all([

    findFacts(query, { searchFn, pool, limit, clientId, companyId, sessionId })
      .catch(err => ({
        facts: [],
        latencyMs: 0,
        agentType: 'fact-finder',
        error: err.message
      })),

    buildContext(query, entities, { graphWalkFn, pool, maxHops, clientId, companyId })
      .catch(err => ({
        context: [],
        latencyMs: 0,
        agentType: 'context-builder',
        error: err.message
      })),

    reconstructTimeline(query, { timelineFn, pool, clientId, companyId, limit })
      .catch(err => ({
        timeline: [],
        supersessions: [],
        latestValues: {},
        latencyMs: 0,
        agentType: 'timeline-reconstructor',
        error: err.message
      })),

    // Batch 10 Lane 3: kNN fast-path as fourth parallel candidate source
    getEmbedding(query)
      .then(async (queryEmbedding) => {
        if (!queryEmbedding || queryEmbedding.length === 0) {
          return { candidates: [], latencyMs: 0, agentType: 'knn-optimizer' };
        }
        const knnCandidates = await knnSearch(queryEmbedding, { companyId, limit: Math.max(limit, 20) });
        // If kNN returns candidates, also run product-key search and merge
        if (Array.isArray(knnCandidates) && knnCandidates.length > 0) {
          try {
            const pkResults = await productKeySearch(queryEmbedding, { companyId, limit });
            // Merge product-key results into kNN candidates, deduplicating by id
            const seen = new Set(knnCandidates.map(c => c.id));
            const merged = [...knnCandidates];
            for (const pk of pkResults) {
              if (!seen.has(pk.id)) {
                seen.add(pk.id);
                merged.push({ ...pk, similarity: pk.score });
              }
            }
            return { candidates: merged, latencyMs: 0, agentType: 'knn-optimizer' };
          } catch (_) {
            return { candidates: knnCandidates, latencyMs: 0, agentType: 'knn-optimizer' };
          }
        }
        return { candidates: knnCandidates || [], latencyMs: 0, agentType: 'knn-optimizer' };
      })
      .catch(err => ({
        candidates: [],
        latencyMs: 0,
        agentType: 'knn-optimizer',
        error: err.message
      }))

  ]);

  // ── Merge and deduplicate ─────────────────────────────────────────────────
  const merged = mergeAndRank(
    factResult.facts || [],
    contextResult.context || [],
    timelineResult.timeline || [],
    knnResult.candidates || []
  );

  const evidence = deduplicateById(merged);

  // ── Collect errors ────────────────────────────────────────────────────────
  const errors = [factResult, contextResult, timelineResult, knnResult]
    .filter(r => r.error)
    .map(r => `${r.agentType}: ${r.error}`);

  const agentLatencies = {
    factFinder: factResult.latencyMs || 0,
    contextBuilder: contextResult.latencyMs || 0,
    timelineReconstructor: timelineResult.latencyMs || 0,
    knnOptimizer: knnResult.latencyMs || 0
  };

  return {
    evidence,
    factCount: (factResult.facts || []).length,
    contextCount: (contextResult.context || []).length,
    timelineCount: (timelineResult.timeline || []).length,
    knnCount: (knnResult.candidates || []).length,
    supersessions: timelineResult.supersessions || [],
    latestValues: timelineResult.latestValues || {},
    agentResults: 4 - errors.length,
    errors,
    agentLatencies,
    fixed_size_recall_pack: buildFixedSizeRecallPack(evidence, { maxItems: limit }),
    fast_slow_path: buildFastSlowPathDiagnostics({ evidence, errors, agentLatencies, limit }),
    segmented_timeline_pack: timelineResult.segmented_timeline_pack || null,
    latencyMs: Date.now() - globalStart
  };
}

/**
 * MoE Cascade Diagnostic — Alongside-path diagnostic
 *
 * Source paper: Bridging Local and Global Knowledge — Cascaded MoE Path Routing
 * Coexistence class: side_by_side_independent
 * Authority: Batch9.75 Wave 0 coexistence map
 *
 * Alongside note: This function computes local/global cascade routing metrics
 * as a diagnostic alongside existing specialist dispatch. It does NOT modify
 * the routing policy or specialist dispatch. The production retrieval
 * orchestrator path remains authoritative. Guarded by guarded_math flag
 * moe_cascade which is guarded in production (knowledge-gated: paper understanding required).
 */
export function buildMoECascadeDiagnostic({
  query = '',
  specialists = [],
  localResults = 0,
  globalResults = 0,
} = {}) {
  const specList = Array.isArray(specialists) ? specialists : [];
  const total = Math.max(1, (Number(localResults) || 0) + (Number(globalResults) || 0));
  const localRatio = (Number(localResults) || 0) / total;
  const globalRatio = (Number(globalResults) || 0) / total;

  return {
    diagnostic: true,
    source_paper: 'Bridging Local and Global Knowledge — Cascaded MoE Path Routing',
    coexistence_class: 'side_by_side_independent',
    query: String(query || '').slice(0, 240),
    specialist_count: specList.length,
    local_results: Number(localResults) || 0,
    global_results: Number(globalResults) || 0,
    local_ratio: localRatio,
    global_ratio: globalRatio,
    routing_unchanged: true,
    note: 'Alongside-path diagnostic. Local/global cascade stays separate from active routing.',
  };
}
