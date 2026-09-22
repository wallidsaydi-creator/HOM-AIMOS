/**
 * compaction-save.js — Native Aimos compaction save lane
 *
 * Builds a full-detail, dream-readable session_debrief for app-owned
 * context-window compaction, then persists through the canonical
 * executeCanonicalSave() spine, with the original verified request authority.
 *
 * Sources: docs/compaction-post-compaction-corpus.md
 * Formula anchors: TiMem L2 session memory, Chronos event/raw-turn split,
 * RPE surprise metadata, LSM/WiscKey persistence shape, Aladdin retention.
 */

import { executeCanonicalSave } from './canonical-save-owner.js';
import { logEvent } from '../observe/event-ledger.js';
import { buildCompactionSavePayload } from '../security/protocol/compaction-record.js';
export { buildCompactionSavePayload, __private__ } from '../security/protocol/compaction-record.js';

export function createCompactionSaveService(deps = {}) {
  const saveFn = deps.executeCanonicalSave || executeCanonicalSave;
  const logEventFn = deps.logEvent || logEvent;

  return async function saveCompactionMemory(input = {}, context = {}) {
    const agentId = context.agentId || input.agent_id;
    const companyId = context.companyId || input.company_id || 'hom';
    if (!context.requestAuthority || (input.company_id && input.company_id !== companyId)
      || (input.agent_id && input.agent_id !== agentId)) throw new Error('compaction_authority_mismatch');
    const scope=input.scope || 'global';
    if (!['global','executive','system','agent','private',agentId].includes(scope)) throw new Error('compaction_scope_unsupported');
    const effectiveInput = {
      ...input,
      agent_id: agentId,
      origin: input.origin || context.origin || 'app_context_window',
    };
    const payload = buildCompactionSavePayload(effectiveInput);

    if (!payload.validation.ok) {
      await logEventFn(companyId, agentId || 'unknown', 'compaction_full_rejected', payload.key || null, {
        lane: 'compaction_full',
        origin: effectiveInput.origin,
        project_id: effectiveInput.project_id || null,
        session_id: effectiveInput.session_id || null,
        route: context.route || '/aimos/compaction/save',
        status: 'rejected',
        validation: payload.validation,
        reasoning: `Compaction save rejected before persistence for session '${effectiveInput.session_id || 'unknown'}'.`,
        source_knowledge: 'compaction-save.js — native compaction lane validation',
      },context.requestAuthority.requestAdmissionEventId,{authority:context.requestAuthority});
      return {
        success: false,
        status: 400,
        error: 'compaction_validation_failed',
        payload,
      };
    }

    const saved = await saveFn({
      company_id: companyId,
      agent_id: agentId,
      key: payload.key,
      value: payload.value,
      scope,
      clearance_level: effectiveInput.clearance_level || 5,
      memory_type: payload.memory_type,
      source: 'aimos-compaction:full',
      session_id: effectiveInput.session_id,
      source_memory_ids: effectiveInput.source_memory_ids,
      valid_from: effectiveInput.valid_from,
      valid_until: effectiveInput.valid_until,
      mutation_authority: context.requestAuthority,
      freshness_state: 'fresh',
      verified_by: agentId,
      verification_basis: 'app_context_window_compaction',
      semantic_triples: payload.metadata.chronos.structured_event_candidates,
      surprise_at_save: payload.metadata.rpe.surprise_at_save,
      compression_ratio: payload.metadata.compression_policy.ratio,
    });

    if (saved?.rejected) {
      await logEventFn(companyId, agentId, 'compaction_full_rejected', payload.key, {
        lane: 'compaction_full',
        origin: effectiveInput.origin,
        project_id: effectiveInput.project_id,
        session_id: effectiveInput.session_id,
        route: context.route || '/aimos/compaction/save',
        status: 'rejected',
        error_code: saved.reason,
        quality_score: saved.quality_score,
        reasoning: `Compaction full save was rejected by the canonical SAVE owner: ${saved.reason}.`,
        source_knowledge: 'persist-memory.js + compaction-save.js',
      },saved.terminal_receipt?.event_id || context.requestAuthority.requestAdmissionEventId,{authority:context.requestAuthority});
      return {
        success: false,
        status: 422,
        error: 'compaction_persist_rejected',
        reason: saved.reason,
        quality_score: saved.quality_score,
        payload,
      };
    }

    await logEventFn(companyId, agentId, 'compaction_full_saved', payload.key, {
      lane: 'compaction_full',
      origin: effectiveInput.origin,
      project_id: effectiveInput.project_id,
      session_id: effectiveInput.session_id,
      route: context.route || '/aimos/compaction/save',
      status: 'saved',
      memory_id: saved.id,
      canonical_terminal_event_id: saved.terminal_receipt?.event_id,
      memory_type: payload.memory_type,
      trigger: payload.metadata.app_trigger,
      content_hash: payload.metadata.content_hash,
      reasoning: `Full context-window compaction saved as session_debrief '${payload.key}'.`,
      source_knowledge: 'compaction-save.js — TiMem L2 + Chronos + RPE metadata',
    },saved.terminal_receipt?.event_id,{authority:context.requestAuthority});

    return {
      success: true,
      lane: 'compaction_full',
      key: payload.key,
      memory_type: payload.memory_type,
      memory_id: saved.id,
      payload,
      terminal_event_id: saved.terminal_receipt?.event_id,
      save_feedback: saved.save_feedback || null,
      quality_score: saved.quality_score,
      freshness_state: saved.freshness_state,
      valid_from: saved.valid_from || payload.metadata.compaction_record.time_window.valid_from,
      valid_until: saved.valid_until || payload.metadata.compaction_record.time_window.valid_until,
      surprise_at_save: saved.surprise_at_save,
      compression_ratio: saved.compression_ratio,
      memory_tier: saved.memory_tier,
    };
  };
}

export const saveCompactionMemory = createCompactionSaveService();
