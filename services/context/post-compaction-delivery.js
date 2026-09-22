/**
 * post-compaction-delivery.js — Native Aimos post-compaction lane
 *
 * Builds a concise continuity handoff from a saved compaction record, then
 * persists the handoff artifact through executeCanonicalSave() when the app asks
 * Aimos to record post-compaction state.
 *
 * Sources: docs/compaction-post-compaction-corpus.md
 * Formula anchors: MemGPT/CoALA context renewal, source-attributed synthesis,
 * TiMem L2 session continuity, Chronos time window, Aladdin retention.
 */

import { withTransaction } from '../../db/connection.js';
import { executeCanonicalSave } from '../write/canonical-save-owner.js';
import { logEvent } from '../observe/event-ledger.js';
import { buildPostCompactionSummaryPayload, postCompactionInputFromMemory } from '../security/protocol/post-compaction-record.js';
import { memoryProvenanceLedger } from '../security/memory-provenance.js';
import { recallAuthorizationService } from '../security/recall-authorization.js';
import { isNativeRecallProofAllowed } from '../retrieval/native-recall.js';
export { buildPostCompactionDelivery, buildPostCompactionSummaryPayload } from '../security/protocol/post-compaction-record.js';

async function loadCompactionMemory(input, context) {
  if (!input.compaction_memory_id && !input.compaction_key) throw new Error('post_compaction_retained_source_required');
  const authority = context.requestAuthority;
  return withTransaction(async client => {
    const grant = authority.agentId === 'housekeeper' && ['T1','T1_SYSTEM_SELF'].includes(authority.identityTier)
      ? { allowed:true, clearanceCeiling:12, dataClassCeiling:'restricted' }
      : await recallAuthorizationService.getEffective({ companyId:context.companyId,
        subjectAgentId:context.agentId, subjectValidFrom:authority.validFromIso, client });
    const rows = (await client.query(
      `SELECT m.id AS memory_id,m.key,m.value,m.memory_type,m.source,m.content_hash,m.agent_id,m.scope,
              m.clearance_level,m.data_class
         FROM aimos_memories m WHERE m.company_id=$1
          AND (($2::uuid IS NOT NULL AND m.id=$2) OR ($2::uuid IS NULL AND m.key=$3
            AND NOT EXISTS(SELECT 1 FROM aimos_memories s WHERE s.company_id=m.company_id
              AND s.key=m.key AND s.supersedes_id=m.id))) LIMIT 2`,
      [context.companyId,input.compaction_memory_id || null,input.compaction_key || null])).rows;
    if (rows.length !== 1) throw new Error('post_compaction_retained_source_missing_or_ambiguous');
    const row = rows[0], classes=['public','internal','confidential','restricted'];
    if (!grant?.allowed || row.clearance_level>grant.clearanceCeiling
      || classes.indexOf(row.data_class)>classes.indexOf(grant.dataClassCeiling)
      || (row.scope==='private' && row.agent_id!==context.agentId)) throw new Error('post_compaction_source_not_authorized');
    const verified = await memoryProvenanceLedger.verifyRecallEvidence({ memoryIds:[row.memory_id],client });
    if (verified.rejected.length || !verified.verified.has(row.memory_id)) throw new Error('post_compaction_source_evidence_invalid');
    if (!isNativeRecallProofAllowed(verified.proofs.get(row.memory_id),{
      companyId:context.companyId,actorAgentId:context.agentId,clearanceCeiling:grant.clearanceCeiling,
      dataClassCeiling:grant.dataClassCeiling,isHousekeeper:context.agentId==='housekeeper',command:{},
    })) throw new Error('post_compaction_source_not_authorized');
    return { memory_id:row.memory_id,key:row.key,value:row.value,memory_type:row.memory_type,
      clearance_level:row.clearance_level,
      metadata:{content_hash:Buffer.from(row.content_hash).toString('hex')} };
  }, {restricted:true,client_id:context.companyId,agent_id:context.agentId});
}

export function createPostCompactionDeliveryService(deps = {}) {
  const saveFn = deps.executeCanonicalSave || executeCanonicalSave;
  const logEventFn = deps.logEvent || logEvent;

  return async function savePostCompactionDelivery(input = {}, context = {}) {
    const agentId = context.agentId || input.agent_id;
    const companyId = context.companyId || input.company_id || 'hom';
    if (!context.requestAuthority || (input.company_id && input.company_id!==companyId)
      || (input.agent_id && input.agent_id!==agentId)) throw new Error('compaction_authority_mismatch');
    const scope=input.scope || 'global';
    if (!['global','executive','system','agent','private',agentId].includes(scope)) throw new Error('compaction_scope_unsupported');
    const loaded = await loadCompactionMemory(input,{...context,companyId,agentId});
    const effectiveInput = postCompactionInputFromMemory(input,loaded,agentId);

    const payload = buildPostCompactionSummaryPayload(effectiveInput);
    if (!payload.validation.ok) {
      await logEventFn(companyId, agentId || 'unknown', 'post_compaction_rejected', payload.key || null, {
        lane: 'post_compaction_delivery',
        origin: effectiveInput.origin || 'app_context_window',
        project_id: effectiveInput.project_id || payload.delivery?.source?.project_id || null,
        session_id: effectiveInput.session_id || payload.delivery?.source?.session_id || null,
        route: context.route || '/aimos/compaction/post',
        status: 'rejected',
        validation: payload.validation,
        reasoning: 'Post-compaction delivery rejected before persistence.',
        source_knowledge: 'post-compaction-delivery.js — native post-compaction lane validation',
      },context.requestAuthority.requestAdmissionEventId,{authority:context.requestAuthority});
      return {
        success: false,
        status: 400,
        error: 'post_compaction_validation_failed',
        payload,
      };
    }

    const saved = await saveFn({
      company_id: companyId,
      agent_id: agentId,
      key: payload.key,
      value: payload.value,
      scope,
      clearance_level: effectiveInput.clearance_level ?? loaded.clearance_level,
      memory_type: payload.memory_type,
      source: 'aimos-compaction:post',
      session_id: payload.metadata.compaction_record.session_id,
      source_memory_ids: effectiveInput.source_memory_ids,
      valid_from: payload.metadata.compaction_record.time_window.valid_from,
      valid_until: payload.metadata.compaction_record.time_window.valid_until,
      mutation_authority: context.requestAuthority,
      freshness_state: 'fresh',
      verified_by: agentId,
      verification_basis: 'post_compaction_delivery',
      semantic_triples: payload.metadata.chronos.structured_event_candidates,
      surprise_at_save: payload.metadata.rpe.surprise_at_save,
      compression_ratio: payload.metadata.compression_policy.ratio,
    });

    if (saved?.rejected) {
      await logEventFn(companyId, agentId, 'post_compaction_rejected', payload.key, {
        lane: 'post_compaction_delivery',
        origin: effectiveInput.origin || 'app_context_window',
        project_id: payload.delivery.source.project_id,
        session_id: payload.delivery.source.session_id,
        route: context.route || '/aimos/compaction/post',
        status: 'rejected',
        error_code: saved.reason,
        quality_score: saved.quality_score,
        reasoning: `Post-compaction delivery was rejected by the canonical SAVE owner: ${saved.reason}.`,
        source_knowledge: 'persist-memory.js + post-compaction-delivery.js',
      },saved.terminal_receipt?.event_id || context.requestAuthority.requestAdmissionEventId,{authority:context.requestAuthority});
      return {
        success: false,
        status: 422,
        error: 'post_compaction_persist_rejected',
        reason: saved.reason,
        quality_score: saved.quality_score,
        payload,
      };
    }

    await logEventFn(companyId, agentId, 'post_compaction_saved', payload.key, {
      lane: 'post_compaction_delivery',
      origin: effectiveInput.origin || 'app_context_window',
      project_id: payload.delivery.source.project_id,
      session_id: payload.delivery.source.session_id,
      route: context.route || '/aimos/compaction/post',
      status: 'saved',
      memory_id: saved.id,
      canonical_terminal_event_id: saved.terminal_receipt?.event_id,
      source_memory_id: payload.metadata.compaction_record.source.memory_id,
      memory_type: payload.memory_type,
      content_hash: payload.metadata.content_hash,
      reasoning: `Post-compaction handoff saved as session_debrief '${payload.key}'.`,
      source_knowledge: 'post-compaction-delivery.js — context renewal + source-attributed handoff',
    },saved.terminal_receipt?.event_id,{authority:context.requestAuthority});

    return {
      success: true,
      lane: 'post_compaction_delivery',
      key: payload.key,
      memory_type: payload.memory_type,
      memory_id: saved.id,
      payload,
      terminal_event_id: saved.terminal_receipt?.event_id,
      delivery: payload.delivery,
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

export const savePostCompactionDelivery = createPostCompactionDeliveryService();
