/**
 * outcome-authority.js — verify and retain causal mutation evidence
 *
 * A weight transition cannot be authorized by a naked memory ID. This owner
 * verifies the signed recall receipt that disclosed the exact occurrence, then
 * appends one housekeeper-signed outcome-evidence event in the same transaction.
 */

import { readVerifiedEventById, logEvent } from '../../observe/event-ledger.js';
import {
  occurrenceReferenceForProvenanceRow,
  orderProvenanceRowsByOccurrenceTopology,
} from '../../security/memory-provenance.js';
import { readVerifiedRequestReceiptByMutationHash } from '../../security/request-receipt-ledger.js';
import { validateOutcomeMutationEvidence } from './principal-state.js';

function parseObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value !== 'string') return null;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export async function verifyOutcomeMutationEvidence(evidence, { client } = {}) {
  if (!client || typeof client.query !== 'function') {
    throw new Error('mutation_outcome_transaction_client_required');
  }
  const normalized = validateOutcomeMutationEvidence(evidence);
  const receipt = await readVerifiedEventById(
    normalized.recall_event_id,
    normalized.company_id,
    { client },
  );
  if (receipt.operation !== 'recall_receipt'
      || Buffer.from(receipt.mutation_hash || []).toString('hex')
        !== normalized.recall_event_mutation_hash) {
    throw new Error('mutation_outcome_recall_receipt_invalid');
  }
  const metadata = parseObject(receipt.metadata);
  const recalled = Array.isArray(metadata?.evidence) ? metadata.evidence : [];
  const exact = recalled.filter((entry) => (
    String(entry?.memory_id || '').toLowerCase() === normalized.memory_id
    && String(entry?.live_content_hash || '').toLowerCase() === normalized.live_content_hash
    && String(entry?.occurrence_ref || '').toLowerCase() === normalized.occurrence_ref
  ));
  if (metadata?.merkle_root !== normalized.recall_merkle_root
      || metadata?.canary_final_security_closure_sha256 !== normalized.security_closure_sha256
      || exact.length !== 1) {
    throw new Error('mutation_outcome_disclosure_binding_invalid');
  }

  const memory = await client.query(
    `SELECT id::text, company_id, agent_id, encode(content_hash,'hex') AS live_content_hash
       FROM aimos_memories
      WHERE company_id=$1 AND id=$2::uuid`,
    [normalized.company_id, normalized.memory_id],
  );
  if (memory.rowCount !== 1
      || memory.rows[0].live_content_hash !== normalized.live_content_hash) {
    throw new Error('mutation_outcome_live_state_invalid');
  }
  const provenance = await client.query(
    `SELECT provenance_id, memory_id, agent_id,
            agent_id AS provenance_agent_id, agent_valid_from,
            cert_fingerprint, mutation_hash, prev_mutation_hash,
            event_type, sig_form_version, body_json
       FROM aimos_memory_provenance
      WHERE memory_id=$1::uuid`,
    [normalized.memory_id],
  );
  const ordered = orderProvenanceRowsByOccurrenceTopology(
    provenance.rows,
    normalized.company_id,
  );
  const retainedOccurrence = ordered.find(
    (row) => occurrenceReferenceForProvenanceRow(row, normalized.company_id)
      === normalized.occurrence_ref,
  );
  if (!retainedOccurrence) {
    throw new Error('mutation_outcome_occurrence_not_retained');
  }
  let principalAgentId = String(retainedOccurrence.provenance_agent_id || retainedOccurrence.agent_id || '');
  if (Number(retainedOccurrence.sig_form_version || 1) === 3) {
    const body = parseObject(retainedOccurrence.body_json);
    if (Number(body?.request_receipt_present) === 1) {
      const requestAuthority = await readVerifiedRequestReceiptByMutationHash({
        companyId: normalized.company_id,
        requestReceiptMutationHash: body.request_receipt_mutation_hash_hex,
        client,
      });
      principalAgentId = requestAuthority.actorAgentId;
    }
  }
  if (!principalAgentId) throw new Error('mutation_outcome_principal_missing');
  return Object.freeze({
    ...normalized,
    principal_agent_id: principalAgentId,
    recall_actor_agent_id: String(receipt.agent_id || ''),
    recall_actor_valid_from: receipt.signed_body?.actor_valid_from || null,
  });
}

export async function appendMutationOutcomeEvidenceEvent({
  verifiedEvidence,
  rewardSign,
  client,
} = {}) {
  if (!client || typeof client.query !== 'function'
      || !verifiedEvidence || (rewardSign !== 1 && rewardSign !== -1)) {
    throw new Error('mutation_outcome_event_input_invalid');
  }
  return logEvent(
    verifiedEvidence.company_id,
    verifiedEvidence.principal_agent_id,
    'mutation_outcome_evidence_v2',
    verifiedEvidence.outcome_id,
    {
      schema: 'hom.aimos.mutation-outcome-authority/v2',
      target_scope: verifiedEvidence.target_scope,
      memory_id: verifiedEvidence.memory_id,
      live_content_hash: verifiedEvidence.live_content_hash,
      occurrence_ref: verifiedEvidence.occurrence_ref,
      reward_sign: rewardSign,
      recall_event_id: verifiedEvidence.recall_event_id,
      recall_event_mutation_hash: verifiedEvidence.recall_event_mutation_hash,
      recall_merkle_root: verifiedEvidence.recall_merkle_root,
      security_closure_sha256: verifiedEvidence.security_closure_sha256,
      recall_actor_agent_id: verifiedEvidence.recall_actor_agent_id,
      recall_actor_valid_from: verifiedEvidence.recall_actor_valid_from,
      content_state_mutation_authorized: false,
      classification_changed: false,
      eligibility_changed: false,
      reasoning: 'The housekeeper verified that this exact signed occurrence was disclosed by the retained recall receipt before admitting the outcome as mutation evidence.',
      source_knowledge: 'R7-M occurrence-attributed principal-state mutation contract',
    },
    verifiedEvidence.recall_event_id,
    { client, returnReceipt: true, exclusiveOperationKey: true },
  );
}
