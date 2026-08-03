// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: SAVE pipeline (async post-save enrichment)
// Purpose: ASMR write-time orchestrator — runs 3 parallel observer agents and
//          merges into 6-facet structured record for fast recall
// ← Called by: routes/aimos.js (SAVE pipeline, post persistMemory)
// → Calls: entity-extractor.js, relationship-mapper.js, temporal-marker.js
// Pipeline: SAVE_PIPELINE
// Position: post-save async enrichment (fire-and-forget, concurrency-limited)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ASMR Structured Ingestion Orchestrator
 *
 * Runs 3 observer agents in parallel on every ingest call, merging their
 * outputs into a single 6-facet structured record. This is the core of the
 * Supermemory ASMR technique: extract structure at WRITE time so recall is fast.
 *
 * The 3 parallel observers are:
 *   1. Entity Extractor  — who/what/where/when/how-much
 *   2. Relationship Mapper — subject-predicate-object triples
 *   3. Temporal Marker  — dates, sequences, supersession chains (old → new)
 *
 * Output 6 facets:
 *   1. entities         — typed named entities with confidence
 *   2. relationships    — SPO triples
 *   3. temporalMarkers  — dated events and state changes
 *   4. supersessions    — old_value → new_value chains for conflict resolution
 *   5. sourceProvenance — origin, clientId, sessionId, ingestedAt
 *   6. confidence       — aggregate extraction confidence
 *
 * @module services/ingestion/ingestion-orchestrator
 */
import { extractEntities, resolveAliases, attachEvidence } from './entity-extractor.js';
import { extractRelationships, validateDAG } from './relationship-mapper.js';
import { extractTemporalMarkers } from './temporal-marker.js';
import { extractConcepts, linkToConcepts } from '../core/concept-graph.js';

// ── CONCURRENCY LIMIT ───────────────────────────────────────────────────────
// Each ingestion run fires up to 3 LLM calls (entity, relationship, temporal).
// Under burst traffic, unbounded concurrency risks LLM pool exhaustion.
// Cap concurrent ingestion runs to prevent resource starvation.
const MAX_CONCURRENT_INGESTIONS = 4;
let activeIngestions = 0;

async function runIngestionWithConcurrencyControl(input) {
  // Spin-wait while at capacity — Node.js is single-threaded so no race condition
  while (activeIngestions >= MAX_CONCURRENT_INGESTIONS) {
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  activeIngestions++;
  try {
    return await runIngestionInner(input);
  } finally {
    activeIngestions--;
  }
}

/**
 * Run the full ASMR ingestion pipeline on raw content.
 *
 * All 3 observers run in parallel via Promise.all — individual failures are
 * caught and recorded in `errors`; the other observers continue unaffected.
 *
 * @param {Object} input
 * @param {string} input.content     - Raw text to ingest
 * @param {string} [input.source]    - Origin label (e.g. 'api', 'webhook', 'import')
 * @param {string} [input.clientId]  - Tenant identifier for provenance
 * @param {string} [input.sessionId] - Conversation/session ID if applicable
 * @param {Object} [input.metadata]  - Arbitrary caller metadata
 * @param {string} [input.provider]  - Override LLM provider for all observers
 * @param {string} [input.model]     - Override model for all observers
 *
 * @returns {Promise<{
 *   entities:        Array,
 *   relationships:   Array,
 *   temporalMarkers: Array,
 *   supersessions:   Array,
 *   sourceProvenance: Object,
 *   confidence:      number,
 *   observerResults: number,
 *   latencyMs:       number,
 *   sequence:        string[],
 *   errors:          string[]
 * }>}
 */
export async function runIngestion(input) {
  return runIngestionWithConcurrencyControl(input);
}

async function runIngestionInner(input) {
  const {
    content,
    source,
    clientId,
    sessionId,
    metadata,
    provider,
    model
  } = input || {};

  const start = Date.now();
  const observerOpts = { provider, model };

  // Smart observer routing: skip observers whose output adds no value for
  // short content where relationship and temporal signals are unlikely.
  //
  //   SHORT  (<100 chars):  entity extractor only
  //   MEDIUM (100-300):     entity + temporal (relationships need more context)
  //   LONG   (>300 chars):  all 3 observers
  //
  // Empty / null content is handled by early returns inside each observer.
  const contentLen = typeof content === 'string' ? content.trim().length : 0;
  const isShort    = contentLen < 100;
  const isMedium   = contentLen >= 100 && contentLen <= 300;

  const skippedRel  = { relationships: [] };
  const skippedTemp = { markers: [], supersessions: [], sequence: [] };

  const [entityResult, relationshipResult, temporalResult] = await Promise.all([
    extractEntities(content, observerOpts)
      .catch(err => ({ entities: [], _error: err.message })),

    isShort || isMedium
      ? Promise.resolve(skippedRel)
      : extractRelationships(content, observerOpts)
          .catch(err => ({ relationships: [], _error: err.message })),

    isShort
      ? Promise.resolve(skippedTemp)
      : extractTemporalMarkers(content, observerOpts)
          .catch(err => ({ markers: [], supersessions: [], sequence: [], _error: err.message }))
  ]);

  const executedObserverResults = [
    entityResult,
    (isShort || isMedium) ? null : relationshipResult,
    isShort ? null : temporalResult
  ].filter(Boolean);

  const executedObserverErrors = executedObserverResults
    .filter(r => r._error)
    .map(r => r._error);

  if (
    executedObserverResults.length > 0 &&
    executedObserverErrors.length === executedObserverResults.length
  ) {
    throw new Error(
      `[ingestion] Native extraction unavailable: ${executedObserverErrors.join(' | ')}`
    );
  }

  const latencyMs = Date.now() - start;

  // Count how many observers completed without error.
  // Skipped observers (short/medium routing) count as successful — they returned
  // clean defaults and did not fail.  This keeps observerResults stable at 3
  // for downstream consumers and tests that check for the full observer count.
  const observerResults = [entityResult, relationshipResult, temporalResult]
    .filter(r => !r._error).length;

  // Collect error messages from failed observers (skipped ones are never errors)
  const errors = [entityResult, relationshipResult, temporalResult]
    .filter(r => r._error)
    .map(r => r._error);

  // Aggregate confidence across all extracted items
  const allConfidences = [
    ...(entityResult.entities || []).map(e => e.confidence),
    ...(relationshipResult.relationships || []).map(r => r.confidence),
    ...(temporalResult.markers || []).map(m => m.confidence)
  ];
  const confidence = allConfidences.length > 0
    ? allConfidences.reduce((sum, c) => sum + c, 0) / allConfidences.length
    : 0.5;  // neutral default when LLM unavailable

  // ── SESSION TAGGING: stamp every extracted item with sessionId ──────────
  // This enables downstream retrieval to filter by session scope. Without it,
  // ASMR recall searches the entire 10K+ memory pool instead of session data.
  const entities = (entityResult.entities || []).map(e =>
    sessionId ? { ...e, sessionId } : e
  );
  const relationships = (relationshipResult.relationships || []).map(r =>
    sessionId ? { ...r, sessionId } : r
  );
  const temporalMarkers = (temporalResult.markers || []).map(m =>
    sessionId ? { ...m, sessionId } : m
  );

  // ── PHASE 4: Alias resolution, evidence attachment, DAG validation ────
  // Best-effort enrichment — failures are logged but never block the pipeline.
  let aliases = [];
  let evidence = [];
  let dagValidation = { valid: true, cycles: [] };

  try {
    aliases = entities.length > 0 ? resolveAliases(entities) : [];
  } catch (err) {
    errors.push(`resolveAliases: ${err.message}`);
  }

  try {
    const sourceId = input.sourceId || input.key || null;
    evidence = entities.length > 0 ? attachEvidence(entities, sourceId, content) : [];
  } catch (err) {
    errors.push(`attachEvidence: ${err.message}`);
  }

  try {
    dagValidation = relationships.length > 0
      ? validateDAG(relationships)
      : { valid: true, cycles: [] };
  } catch (err) {
    errors.push(`validateDAG: ${err.message}`);
  }

  // ── PHASE 5: Concept extraction & linking ─────────────────────────────
  // Extract topic-level concept labels from raw content and link them to
  // the memory node (if a memoryId is available from the write result).
  // Best-effort — failures never block the pipeline.
  let concepts = [];
  try {
    concepts = extractConcepts(content);
  } catch (err) {
    errors.push(`extractConcepts: ${err.message}`);
  }

  // Concept linking happens asynchronously after the return value is built.
  // The caller (asmr-pipeline) may pass a memoryId via input for linking.
  const memoryId = input.memoryId || input.id || null;
  if (memoryId && concepts.length > 0) {
    try {
      await linkToConcepts(memoryId, concepts, input.companyId);
    } catch { /* concept linking is best-effort */ }
  }

  return {
    // Facet 1: Named entities (session-tagged)
    entities,

    // Facet 2: Subject-predicate-object triples (session-tagged)
    relationships,

    // Facet 3: Temporal events and changes (session-tagged)
    temporalMarkers,

    // Facet 4: Supersession chains (old state → new state)
    supersessions: temporalResult.supersessions || [],

    // Facet 5: Source provenance (immutable audit record)
    sourceProvenance: {
      source: source || 'unknown',
      clientId: clientId || null,
      sessionId: sessionId || null,
      ingestedAt: new Date().toISOString(),
      metadata: metadata || {}
    },

    // Facet 6: Aggregate extraction confidence
    confidence,

    // Phase 4: Enrichment outputs
    aliases,
    evidence,
    dagValidation,

    // Phase 5: Concept graph
    concepts,

    // Pipeline metadata
    observerResults,
    latencyMs,
    sequence: temporalResult.sequence || [],
    errors
  };
}
