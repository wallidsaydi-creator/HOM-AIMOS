/**
 * asmr-pipeline.js — ASMR ingestion and admitted-evidence answer synthesis
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ← Triggered by: routes/v1-api.js (Primary external entry)
 * 2. ↔ Interacts with: ingestion-orchestrator.js (Faceting and extraction)
 * 3. ← Receives: provenance-admitted memories from native-recall-pipeline.js
 * 4. ↔ Interacts with: ensemble-engine.js (Response generation)
 * 5. → Pushes to: persist-memory.js via signed derived-action authority
 *
 * LOGIC GUIDE: Retrieval authority remains exclusively native-recall. ASMR
 * performs observer ingestion and answer synthesis without opening a raw SQL,
 * graph, temporal, or HNSW disclosure path.
 */
// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: v1-api.js
// → Calls: ingestion-orchestrator.js, ensemble-engine.js, persist-memory.js,
//           tool-action-ledger.js
// Pipeline: ASMR | Position: Top-level entry point
// ─────────────────────────────────────────────────────────────────────────────


import { createHash } from 'node:crypto';

import { runIngestion } from '../ingestion/ingestion-orchestrator.js';
import { runEnsemble } from '../answering/ensemble-engine.js';
import { persistMemory } from '../write/persist-memory.js';
import { canonicalJson } from '../security/agent-identity.js';
import { logEvent } from '../observe/event-ledger.js';
import { beginToolAction, finishToolAction } from '../orchestration/tool-action-ledger.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { sessionKeyPrefix } from '../shared/session-scope.js';

function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value ?? null), 'utf8').digest('hex');
}

// ─── ASMR answer synthesis over admitted evidence ────────────────────────────

/**
 * Synthesize an answer from the canonical recall owner's admitted evidence.
 *
 * @param {string} query
 * @param {Array} admittedEvidence - Memories already admitted by native recall.
 * @param {Object} [opts]
 * @param {string}   [opts.mode]        - Ensemble mode: 'any-correct' | 'majority-vote'
 * @param {string}   [opts.model]       - LLM model override
 * @param {string}   [opts.provider]    - LLM provider override
 * @param {Function} [opts.llmFn]       - Injected LLM mock for testing
 *
 * @returns {Promise<{
 *   query: string,
 *   answer: string,
 *   confidence: number,
 *   mode: string,
 *   variantResults: Array,
 *   validCount: number,
 *   totalVariants: number,
 *   evidence: Array,
 *   retrieval: {
 *     factCount: number,
 *     contextCount: number,
 *     timelineCount: number,
 *     supersessions: Array,
 *     latestValues: Object,
 *     agentResults: number,
 *     errors: string[],
 *     latencyMs: number
 *   },
 *   latencyMs: number,
 *   stages: { retrievalMs: number, ensembleMs: number }
 * }>}
 */
export async function asmrAnswerFromEvidence(query, admittedEvidence, opts = {}) {
  const pipelineStart = Date.now();
  if (!Array.isArray(admittedEvidence)) throw new Error('asmr_admitted_evidence_required');
  const evidence = admittedEvidence;

  const ensembleStart = Date.now();
  const ensembleResult = await runEnsemble(query, evidence, {
    mode:     opts.mode     || 'any-correct',
    model:    opts.model,
    provider: opts.provider,
    llmFn:    opts.llmFn,
    variants: opts.variants
  });
  const ensembleMs = Date.now() - ensembleStart;

  return {
    query,
    answer:         ensembleResult.answer,
    confidence:     ensembleResult.confidence,
    mode:           ensembleResult.mode,
    variantResults: ensembleResult.variantResults,
    validCount:     ensembleResult.validCount,
    totalVariants:  ensembleResult.totalVariants,
    evidence,
    retrieval: {
      source: 'native_recall_admitted_evidence',
      admittedCount: evidence.length,
      provenanceVerified: evidence.every((item) => Boolean(item?.provenance_proof)),
    },
    latencyMs: Date.now() - pipelineStart,
    stages: { retrievalMs: 0, ensembleMs }
  };
}

export async function finalizeAsmrAnswer({ query, answerResult, recallReceipt, variants, executionContext }) {
  if (!recallReceipt?.merkle_root || !recallReceipt?.event_receipt?.event_id) {
    throw new Error('asmr_recall_receipt_required');
  }
  const variantConfigHash = sha256Canonical(variants || 'default');
  const outputHash = sha256Canonical({
    schema: 'hom.aimos.asmr-answer/v1',
    answer: answerResult?.answer || '',
    confidence: answerResult?.confidence ?? null,
    mode: answerResult?.mode || null,
    valid_count: answerResult?.validCount ?? null,
    total_variants: answerResult?.totalVariants ?? null,
    variant_results: answerResult?.variantResults || [],
    retrieval: answerResult?.retrieval || null,
    evidence: answerResult?.evidence || [],
    stages: answerResult?.stages || null,
  });
  const receipt = await logEvent(
    executionContext.companyId,
    executionContext.actorAgentId,
    'asmr_answer_receipt',
    sha256Canonical(String(query || '')),
    {
      recall_event_id: recallReceipt.event_receipt.event_id,
      recall_merkle_root: recallReceipt.merkle_root,
      variant_config_sha256: variantConfigHash,
      output_sha256: outputHash,
      evidence_count: answerResult?.evidence?.length || 0,
      output_schema: 'hom.aimos.asmr-answer/v1',
      reasoning: 'ASMR answer synthesis consumed only provenance-admitted native recall evidence and signed the exact recall root, variants, evidence, retrieval metadata, stages, and semantic output. Top-level wall-clock latency remains diagnostic telemetry.',
      source_knowledge: 'Chronos structured temporal retrieval; RRF rank-only fusion; RFC 6962 evidence binding',
    },
    recallReceipt.event_receipt.event_id,
    { authority: executionContext, returnReceipt: true },
  );
  return {
    output_schema: 'hom.aimos.asmr-answer/v1',
    variant_config_sha256: variantConfigHash,
    output_sha256: outputHash,
    event_receipt: receipt,
  };
}

// ─── asmrIngest ───────────────────────────────────────────────────────────────

/**
 * Run the full Ingestion pipeline on raw content, optionally persisting
 * the extracted facets back to Aimos.
 *
 * @param {string} content
 * @param {Object} [opts]
 * @param {string}  [opts.source]     - Origin label
 * @param {string}  [opts.clientId]   - Tenant identifier
 * @param {string}  [opts.sessionId]  - Session/conversation ID
 * @param {Object}  [opts.metadata]   - Arbitrary caller metadata
 * @param {string}  [opts.provider]   - LLM provider for observers
 * @param {string}  [opts.model]      - LLM model for observers
 * @param {boolean} [opts.saveToAimos=false] - Persist facets through the native signed write spine
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
 *   errors:          string[],
 *   saved:           number
 * }>}
 */
async function persistDerivedFacet(spec, { executionContext, parentEventId }) {
  const action = await beginToolAction({
    tool: 'aimos_save_commit',
    args: spec,
    runtimeAgentId: 'housekeeper',
    executionContext,
    parentEventId,
  });
  try {
    const saved = await persistMemory({
      ...spec,
      mutation_authority: action.authority,
    });
    if (saved?.rejected || !saved?.id) {
      throw new Error(saved?.reason || 'asmr_facet_persistence_failed');
    }
    await finishToolAction({ action, executionContext, succeeded: true, result: { memory_id: saved.id } });
    return saved;
  } catch (error) {
    try {
      await finishToolAction({ action, executionContext, succeeded: false, error: error?.message || error });
    } catch (ledgerError) {
      error.toolActionLedgerError = ledgerError?.message || String(ledgerError);
    }
    throw error;
  }
}

export async function asmrIngest(content, opts = {}) {
  const executionContext = opts.executionContext || null;
  let clearanceLevel = null;
  let ingestionAction = null;
  let ingestionOutcomeReceipt = null;

  if (opts.saveToAimos) {
    if (!executionContext?.actorAgentId || !executionContext?.actorValidFromIso || !executionContext?.companyId) {
      throw new Error('verified_asmr_ingestion_context_required');
    }
    const isHousekeeper = executionContext.actorAgentId === 'housekeeper'
      && ['T1', 'T1_SYSTEM_SELF'].includes(executionContext.identityTier);
    const grant = isHousekeeper ? {
      allowed: true,
      writeAllowed: true,
      clearanceCeiling: 12,
    } : await recallAuthorizationService.getEffective({
      companyId: executionContext.companyId,
      subjectAgentId: executionContext.actorAgentId,
      subjectValidFrom: executionContext.actorValidFromIso,
    });
    if (!grant?.allowed || !grant.writeAllowed) {
      throw new Error('master_signed_memory_write_grant_required');
    }
    clearanceLevel = Number(opts.clearanceLevel ?? 1);
    if (!Number.isInteger(clearanceLevel) || clearanceLevel < 1 || clearanceLevel > grant.clearanceCeiling) {
      throw new Error('clearance_exceeds_verified_authority');
    }
    ingestionAction = await beginToolAction({
      tool: 'asmr_ingest',
      args: {
        content,
        source: opts.source || 'asmr-pipeline',
        session_id: opts.sessionId || null,
        metadata: opts.metadata || {},
      },
      runtimeAgentId: 'housekeeper',
      executionContext,
    });
  }

  try {
    const result = await runIngestion({
      content,
      source: opts.source || 'asmr-pipeline',
      clientId: executionContext?.actorAgentId || opts.clientId,
      sessionId: opts.sessionId,
      metadata: opts.metadata || {},
      provider: opts.provider,
      model: opts.model,
    });

    const savedMemories = [];
    if (opts.saveToAimos) {
      const sessPrefix = opts.sessionId ? sessionKeyPrefix(opts.sessionId) : '';
      const source = result.sourceProvenance?.source || opts.source || 'asmr-pipeline';
      const specs = [];
      for (const entity of result.entities || []) {
        specs.push({
          company_id: executionContext.companyId,
          agent_id: executionContext.actorAgentId,
          key: `${sessPrefix}entity:${entity.type || 'unknown'}:${entity.value}`,
          value: entity.context || `${entity.value} is a ${entity.type || 'entity'} mentioned in: ${content.slice(0, 300)}`,
          memory_type: 'declarative',
          source,
          scope: 'private',
          clearance_level: clearanceLevel,
          session_id: opts.sessionId || null,
        });
      }
      for (const marker of result.temporalMarkers || []) {
        specs.push({
          company_id: executionContext.companyId,
          agent_id: executionContext.actorAgentId,
          key: `${sessPrefix}event:${marker.entity || 'unknown'}:${marker.date || 'undated'}`,
          value: marker.description || marker.value || JSON.stringify(marker),
          memory_type: 'episodic',
          source,
          scope: 'private',
          clearance_level: clearanceLevel,
          session_id: opts.sessionId || null,
        });
      }
      for (const spec of specs) {
        savedMemories.push(await persistDerivedFacet(spec, {
          executionContext,
          parentEventId: ingestionAction.receipt.event_id,
        }));
      }
      const savedProofs = savedMemories.map((memory) => ({
        memory_id: memory.id,
        content_hash: memory.live_content_hash?.toString('hex') || null,
        save_mutation_hash: memory.ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: memory.binding_commit?.mutationHash?.toString('hex') || null,
      }));
      ingestionOutcomeReceipt = await finishToolAction({
        action: ingestionAction,
        executionContext,
        succeeded: true,
        result: {
          schema: 'hom.aimos.asmr-ingestion-outcome/v1',
          saved: savedMemories.length,
          saved_memory_ids: savedMemories.map((memory) => memory.id),
          saved_proofs_sha256: sha256Canonical(savedProofs),
          entities_sha256: sha256Canonical(result.entities || []),
          relationships_sha256: sha256Canonical(result.relationships || []),
          temporal_markers_sha256: sha256Canonical(result.temporalMarkers || []),
          supersessions_sha256: sha256Canonical(result.supersessions || []),
          source_provenance_sha256: sha256Canonical(result.sourceProvenance || null),
          observer_errors_sha256: sha256Canonical(result.errors || []),
          relationships_persisted: 0,
        },
      });
    }

    return {
      ...result,
      saved: savedMemories.length,
      savedMemoryIds: savedMemories.map((memory) => memory.id),
      savedProofs: savedMemories.map((memory) => ({
        memory_id: memory.id,
        content_hash: memory.live_content_hash?.toString('hex') || null,
        save_mutation_hash: memory.ledger_commit?.mutationHash?.toString('hex') || null,
        binding_mutation_hash: memory.binding_commit?.mutationHash?.toString('hex') || null,
      })),
      relationshipPersistence: 'extraction_only',
      ingestionActionStartReceipt: ingestionAction?.receipt || null,
      ingestionActionReceipt: ingestionOutcomeReceipt || null,
    };
  } catch (error) {
    if (ingestionAction) {
      try {
        await finishToolAction({
          action: ingestionAction,
          executionContext,
          succeeded: false,
          error: error?.message || error,
        });
      } catch (ledgerError) {
        error.toolActionLedgerError = ledgerError?.message || String(ledgerError);
      }
    }
    throw error;
  }
}
