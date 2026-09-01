import { randomUUID } from 'node:crypto';

import { AIMOS_COMPANY_ID } from '../../../services/core/runtime-config.js';
import { signAsHousekeeper } from '../../../services/security/housekeeper-signer.js';
import { resolveNativeRecallAuthority } from '../../../services/retrieval/native-recall.js';
import { executeNativeRecall } from '../../../services/retrieval/native-recall-pipeline.js';

export async function createMutationOutcomeEvidence(memoryId) {
  const body = {
    company_id: AIMOS_COMPANY_ID,
    agent_id: 'housekeeper',
    memory_id: memoryId,
    limit: 1,
    clearance_level: 12,
    cache: false,
    semantic_cache: false,
  };
  const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/recall' });
  const requestAuthority = Object.freeze({
    kind: 'verified_request',
    body: signed.body,
    agentId: signed.agentId,
    validFromIso: signed.validFromIso,
    certString: signed.certString,
    signedTs: signed.signedTs,
    nonce: signed.nonce,
    sigBytes: signed.sigBytes,
    identityTier: signed.identityTier,
    requestSigForm: signed.sigForm,
    signedMethod: signed.signedMethod,
    signedPath: signed.signedPath,
    signedClaims: signed.signedClaims,
  });
  const executionContext = Object.freeze({
    actorAgentId: signed.agentId,
    actorValidFromIso: signed.validFromIso,
    companyId: AIMOS_COMPANY_ID,
    identityTier: signed.identityTier,
  });
  const authority = await resolveNativeRecallAuthority({
    rawCommand: signed.body,
    executionContext,
    requestAuthority,
    transportBinding: { transport: 'rest' },
  });
  const recalled = await executeNativeRecall(
    { ip: '127.0.0.1', headers: {}, originalUrl: '/aimos/recall' },
    authority,
  );
  if (recalled.status !== 200 || recalled.body?.memories?.length !== 1) {
    throw new Error('mutation_outcome_fixture_recall_failed');
  }
  const receipt = recalled.body.recall_receipt;
  const evidence = receipt?.evidence?.[0];
  if (!evidence?.occurrence_ref || !receipt?.canary_final_security_closure_sha256
      || !receipt?.event_receipt?.event_id || !receipt?.event_receipt?.mutation_hash) {
    throw new Error('mutation_outcome_fixture_receipt_incomplete');
  }
  return Object.freeze({
    schema: 'hom.aimos.mutation-outcome-evidence/v2',
    company_id: AIMOS_COMPANY_ID,
    memory_id: String(evidence.memory_id),
    live_content_hash: String(evidence.live_content_hash),
    occurrence_ref: String(evidence.occurrence_ref),
    target_scope: 'principal_state',
    recall_event_id: String(receipt.event_receipt.event_id),
    recall_event_mutation_hash: String(receipt.event_receipt.mutation_hash),
    recall_merkle_root: String(receipt.merkle_root),
    security_closure_sha256: String(receipt.canary_final_security_closure_sha256),
    outcome_id: randomUUID(),
  });
}

export function successorOutcomeEvidence(evidence) {
  return Object.freeze({ ...evidence, outcome_id: randomUUID() });
}
