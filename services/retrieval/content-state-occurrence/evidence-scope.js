/**
 * evidence-scope.js — R6 request-local signed epistemic scope projection
 *
 * Reads only the migration-092 chain verifier and the already signed current
 * classification event. It does not classify, relabel, mutate, delete, or
 * grant disclosure. The resulting occurrence/content eligibility is consumed
 * by the R4 state projection before any retrieval gear can vote.
 */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../security/protocol/canonical-json.js';

export const REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT = Object.freeze({
  schema: 'hom-aimos/request-epistemic-evidence-scope/v1',
  source: 'migration_092_verified_classification_chain_and_signed_event',
  content_blocking_labels: Object.freeze(['poison_likely', 'poison_confirmed']),
  occurrence_blocking_labels: Object.freeze(['disputed', 'poison_suspect']),
  eligible_labels: Object.freeze(['unverified', 'supported', 'poison_refuted']),
  quarantine_scope: 'occurrence_blocked_content_retained',
  exoneration_rule: 'one_content_blocking_occurrence_blocks_the_complete_content_state',
  time_complexity: 'O(unique_request_occurrences_plus_verified_chain_rows)',
  space_complexity: 'O(unique_request_occurrences)',
  classification_authority: false,
  mutation_authority: false,
  disclosure_authority: false,
  deletion_authority: false,
  environment_authority: false,
});

const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTENT_BLOCKING = new Set(REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT.content_blocking_labels);
const OCCURRENCE_BLOCKING = new Set(REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT.occurrence_blocking_labels);
const ELIGIBLE = new Set(REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT.eligible_labels);
const TYPED_EVIDENCE_REQUIRED = new Set(['supported', 'disputed', 'poison_confirmed', 'poison_refuted']);

function fail(code) {
  throw new Error(`request_epistemic_evidence_scope:${code}`);
}

function sha256(value) {
  return createHash('sha256')
    .update(Buffer.from(canonicalJson(value), 'utf8'))
    .digest('hex');
}

function eventMetadata(value) {
  if (value && typeof value === 'object') return value;
  try { return JSON.parse(value || '{}'); } catch { fail('classification_event_metadata_invalid'); }
}

function normalizeVerifiedRow(row) {
  const memoryId = String(row?.memory_id || '').toLowerCase();
  const liveContentHash = String(row?.live_content_hash || '').toLowerCase();
  const label = String(row?.current_label || '').trim().toLowerCase();
  const confidenceMilli = Number(row?.current_confidence_milli);
  const chainLength = Number(row?.chain_length);
  const headHash = row?.classification_head_hash == null
    ? null
    : String(row.classification_head_hash).toLowerCase();
  if (!UUID.test(memoryId) || !HEX64.test(liveContentHash)
      || !Number.isSafeInteger(confidenceMilli) || confidenceMilli < 0 || confidenceMilli > 1000
      || !Number.isSafeInteger(chainLength) || chainLength < 0
      || (headHash != null && !HEX64.test(headHash))) {
    fail('verified_row_invalid');
  }
  if (row.ok !== true || row.reason != null) fail(`classification_chain_invalid:${row.reason || 'unknown'}`);
  if (!ELIGIBLE.has(label) && !CONTENT_BLOCKING.has(label) && !OCCURRENCE_BLOCKING.has(label)) {
    fail('classification_label_invalid');
  }
  if (chainLength === 0 && (label !== 'unverified' || headHash != null)) {
    fail('unverified_chain_projection_invalid');
  }
  if (chainLength > 0 && headHash == null) fail('classification_head_missing');

  const metadata = eventMetadata(row.classification_event_metadata);
  const evidenceBinding = metadata?.evidence_assertion_binding || null;
  const evidenceRoot = evidenceBinding?.evidence_root_sha256 == null
    ? null
    : String(evidenceBinding.evidence_root_sha256).toLowerCase();
  if (evidenceRoot != null && !HEX64.test(evidenceRoot)) fail('typed_evidence_root_invalid');
  if (TYPED_EVIDENCE_REQUIRED.has(label) && !evidenceRoot) fail('typed_evidence_root_required');
  const classificationEventMutationHash = row.classification_event_mutation_hash == null
    ? null : String(row.classification_event_mutation_hash).toLowerCase();
  if (chainLength > 0 && !HEX64.test(classificationEventMutationHash || '')) {
    fail('classification_event_mutation_hash_invalid');
  }

  const retainedQuarantine = row.scope === 'quarantine' || row.memory_type === 'quarantine';
  const contentBlocked = CONTENT_BLOCKING.has(label);
  const occurrenceBlocked = contentBlocked || OCCURRENCE_BLOCKING.has(label) || retainedQuarantine;
  const dispositionBody = {
    schema: 'hom-aimos/request-epistemic-occurrence-disposition/v1',
    memory_id: memoryId,
    live_content_hash: liveContentHash,
    label,
    confidence_milli: confidenceMilli,
    classification_chain_length: chainLength,
    classification_head_hash: headHash,
    classification_event_mutation_hash: classificationEventMutationHash,
    evidence_root_sha256: evidenceRoot,
    independent_supporting_source_count:
      Number(evidenceBinding?.independent_supporting_source_count || 0),
    independent_refuting_source_count:
      Number(evidenceBinding?.independent_refuting_source_count || 0),
    retained_quarantine: retainedQuarantine,
    occurrence_eligible: !occurrenceBlocked,
    content_eligible: !contentBlocked,
    canonical_memory_mutated: false,
    classification_changed: false,
    retention_changed: false,
  };
  const dispositionSha256 = sha256(dispositionBody);
  return Object.freeze({
    ...dispositionBody,
    disposition_sha256: dispositionSha256,
    occurrence_decision_ref: occurrenceBlocked ? dispositionSha256 : null,
    content_decision_ref: contentBlocked ? dispositionSha256 : null,
  });
}

export function createRequestEpistemicEvidenceScope({ queryFn } = {}) {
  if (typeof queryFn !== 'function') fail('query_owner_required');
  const decisionsByMemoryId = new Map();

  const resolve = async (memories = [], companyId) => {
    const proposedIds = [...new Set((Array.isArray(memories) ? memories : [])
      .map((memory) => String(memory?.id || memory?.memory_id || '').toLowerCase())
      .filter((id) => UUID.test(id)))];
    if (proposedIds.length !== (Array.isArray(memories) ? new Set(memories.map(
      (memory) => String(memory?.id || memory?.memory_id || '').toLowerCase(),
    )).size : 0)) fail('memory_identity_invalid');
    const missingIds = proposedIds.filter((id) => !decisionsByMemoryId.has(id));
    if (missingIds.length) {
      const result = await queryFn(
        `WITH requested AS (
           SELECT memory_id, ordinal
             FROM unnest($2::uuid[]) WITH ORDINALITY AS input(memory_id, ordinal)
         )
         SELECT requested.memory_id::text,
                encode(memory.content_hash, 'hex') AS live_content_hash,
                memory.scope, memory.memory_type,
                verified.ok, verified.chain_length, verified.current_label,
                verified.current_confidence_milli,
                encode(verified.head_hash, 'hex') AS classification_head_hash,
                verified.reason,
                event.metadata AS classification_event_metadata,
                encode(event.mutation_hash, 'hex') AS classification_event_mutation_hash
           FROM requested
           JOIN public.aimos_memories memory
             ON memory.id = requested.memory_id
            AND memory.company_id = $1
           CROSS JOIN LATERAL public.verify_memory_epistemic_classification_chain(memory.id) verified
           LEFT JOIN public.aimos_events event
             ON event.id = memory.current_epistemic_event_id
            AND event.company_id = memory.company_id
            AND event.operation = 'memory_epistemic_classified'
          ORDER BY requested.ordinal`,
        [companyId, missingIds],
      );
      if ((result.rows || []).length !== missingIds.length) fail('classification_projection_missing');
      for (const row of result.rows) {
        const decision = normalizeVerifiedRow(row);
        if (decisionsByMemoryId.has(decision.memory_id)) fail('classification_projection_duplicate');
        decisionsByMemoryId.set(decision.memory_id, decision);
      }
    }
    return new Map(proposedIds.map((id) => [id, decisionsByMemoryId.get(id)]));
  };

  const finalize = (projection) => {
    if (!projection?.decision || !Array.isArray(projection.state_view)
        || !Array.isArray(projection.occurrence_view)) fail('content_state_projection_invalid');
    const projectionOccurrenceByMemoryId = new Map(projection.occurrence_view.map(
      (occurrence) => [String(occurrence.memory_id), occurrence],
    ));
    const records = Object.freeze([...decisionsByMemoryId.values()]
      .map((record) => {
        const occurrence = projectionOccurrenceByMemoryId.get(record.memory_id);
        if (!occurrence) fail('projection_occurrence_mapping_missing');
        return Object.freeze({
          ...record,
          projection_rank_eligible: occurrence.rank_eligible === true,
          projection_ineligibility_reason: occurrence.ineligibility_reason || null,
        });
      })
      .sort((left, right) => left.memory_id.localeCompare(right.memory_id)));
    const blockedRecords = Object.freeze(records.filter(
      (record) => record.projection_rank_eligible !== true,
    ));
    const body = {
      schema: REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT.schema,
      content_state_projection_decision_sha256: projection.decision.decision_sha256,
      state_view_root_sha256: projection.decision.state_view_root_sha256,
      occurrence_view_root_sha256: projection.decision.occurrence_view_root_sha256,
      authorized_class_commitment_sha256: projection.decision.state_view_root_sha256,
      input_occurrence_count: projection.decision.input_occurrence_count,
      unique_state_count: projection.decision.unique_state_count,
      rank_eligible_state_count: projection.decision.rank_eligible_state_count,
      content_blocked_state_count: projection.decision.content_blocked_state_count,
      occurrence_blocked_count: projection.decision.occurrence_blocked_count,
      verified_classification_count: records.length,
      blocked_record_count: blockedRecords.length,
      records,
      records_root_sha256: sha256(records),
      blocked_records: blockedRecords,
      retained_blocked_decision_set_sha256: sha256(blockedRecords),
      evidence_root_sha256s: Object.freeze([...new Set(records
        .map((record) => record.evidence_root_sha256)
        .filter(Boolean))].sort()),
      eligibility_exhaustion_reason: projection.decision.input_occurrence_count === 0
        ? 'no_admitted_occurrences'
        : projection.decision.rank_eligible_state_count === 0
          ? 'all_admitted_states_evidence_blocked'
          : null,
      no_exoneration: true,
      label_history_changed: false,
      canonical_memory_mutated: false,
      retention_changed: false,
      deletion_performed: false,
    };
    return Object.freeze({ ...body, decision_sha256: sha256(body) });
  };

  return Object.freeze({ resolve, finalize });
}
