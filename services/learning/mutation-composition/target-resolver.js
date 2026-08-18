/**
 * target-resolver.js — database-facing principal-state mutation target owner
 *
 * Reuses the same provenance and signed epistemic admission owners as recall,
 * then delegates deterministic grouping to the authority-free R7-M kernel.
 */

import { memoryProvenanceLedger } from '../../security/memory-provenance.js';
import { createRequestScopedContentStateAdmission } from '../../retrieval/content-state-occurrence/request-admission.js';
import { createRequestEpistemicEvidenceScope } from '../../retrieval/content-state-occurrence/evidence-scope.js';
import { projectPrincipalStateMutationTargets } from './principal-state.js';

export async function resolvePrincipalStateMutationTargets({
  memoryIds,
  companyId,
  client,
  maximumIds = 500,
} = {}) {
  const ids = [...new Set((Array.isArray(memoryIds) ? memoryIds : [])
    .map((id) => String(id || '').toLowerCase())
    .filter(Boolean))];
  if (!client || typeof client.query !== 'function' || !companyId
      || ids.length > maximumIds) {
    throw new Error('principal_state_target_resolution_input_invalid');
  }
  if (!ids.length) return Object.freeze({ targets: Object.freeze([]), projection: null });
  const rows = await client.query(
    `SELECT id::text,key,value,scope,memory_type,clearance_level,
            data_class,source,agent_id,retrieval_weight
       FROM aimos_memories
      WHERE company_id=$1 AND id=ANY($2::uuid[])
      ORDER BY id`,
    [companyId, ids],
  );
  if (rows.rowCount !== ids.length) throw new Error('principal_state_target_memory_missing');
  const evidence = await memoryProvenanceLedger.verifyRecallEvidence({
    memoryIds: ids,
    client,
  });
  if (evidence.rejected.length || evidence.verified.size !== ids.length) {
    throw new Error('principal_state_target_provenance_invalid');
  }
  const admittedRows = rows.rows.map((row) => ({
    ...row,
    provenance_proof: evidence.proofs.get(String(row.id)),
  }));
  const epistemic = createRequestEpistemicEvidenceScope({
    queryFn: (sql, params = []) => client.query(sql, params),
  });
  const admission = createRequestScopedContentStateAdmission({
    authority: { companyId, actorAgentId: 'housekeeper' },
    admitBatch: async (memories) => ({ memories, rejected: [] }),
    evidenceScopeOwner: epistemic,
  });
  await admission.admit(admittedRows);
  const projection = admission.internalProjection();
  const targets = projectPrincipalStateMutationTargets(
    projection.occurrence_view
      .filter((occurrence) => occurrence.rank_eligible === true)
      .map((occurrence) => ({
        company_id: occurrence.company_id,
        memory_id: occurrence.memory_id,
        live_content_hash: occurrence.live_content_hash,
        principal_agent_id: occurrence.principal.agent_id,
        occurrence_ref: occurrence.occurrence_ref,
        signed_time_ms: occurrence.lineage.signed_time_ms,
        security_eligible: true,
      })),
  );
  return Object.freeze({ targets, projection, evidence_scope: epistemic.finalize(projection) });
}
