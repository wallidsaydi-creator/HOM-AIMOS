/**
 * request-admission.js — one request-scoped R4 admission/projection owner
 *
 * The database/provenance owner is dependency-injected. This owner accumulates
 * only already admitted occurrences, derives legacy occurrence references,
 * and maintains the R2 state/occurrence views. R4 records the view but does not
 * yet replace per-gear candidate populations; that integration belongs to R5.
 */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../security/protocol/canonical-json.js';
import {
  canonicalizeLiveContentState,
  projectContentStateOccurrenceViews,
} from './kernel.js';
import { computeVerifiedLegacyOccurrenceReference } from './legacy-occurrence-reference.js';

export const REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT = Object.freeze({
  schema: 'hom.aimos.request-scoped-content-state-admission/v1',
  occurrence_reference: 'hom.aimos.memory-occurrence-reference/versioned-v1-v3',
  occurrence_reference_versions: Object.freeze([
    'hom.aimos.memory-occurrence-ref/legacy-v1',
    'hom.aimos.memory-occurrence/v3',
  ]),
  evidence_scope_status: 'active_verified_signed_epistemic_scope',
  changes_gear_inputs: true,
  disclosure_authority: false,
  mutation_authority: false,
  classification_authority: false,
  deletion_authority: false,
});

const HEX32 = /^[0-9a-f]{64}$/;

function fail(code) {
  throw new Error(`request_scoped_occurrence_admission:${code}`);
}

function occurrenceFromAdmittedMemory(memory, authority, evidenceScope) {
  const proof = memory?.provenance_proof;
  if (!proof || String(proof.company_id) !== String(authority.companyId)) {
    fail('verified_proof_required');
  }
  const memoryId = String(memory.id || memory.memory_id || '').toLowerCase();
  const liveContentHash = String(proof.live_content_hash || '').toLowerCase();
  const provenanceId = String(proof.occurrence_provenance_id || '').toLowerCase();
  const mutationHash = String(proof.occurrence_mutation_hash || '').toLowerCase();
  const signerAgentId = String(proof.occurrence_signer_agent_id || '');
  const signerValidFrom = new Date(proof.occurrence_signer_valid_from || '');
  const certFingerprint = String(proof.occurrence_cert_fingerprint || '').toLowerCase();
  const eventType = String(proof.occurrence_event_type || '').toUpperCase();
  const sigFormVersion = Number(proof.occurrence_sig_form_version);
  const signedSeconds = Number(proof.occurrence_ts_signed);
  const actorAgentId = String(proof.occurrence_actor_agent_id || signerAgentId);
  const actorValidFrom = new Date(proof.occurrence_actor_valid_from || proof.occurrence_signer_valid_from || '');
  const actorCertFingerprint = String(proof.occurrence_actor_cert_fingerprint || certFingerprint).toLowerCase();
  if (!memoryId || !HEX32.test(liveContentHash) || !provenanceId || !HEX32.test(mutationHash)
      || !signerAgentId || Number.isNaN(signerValidFrom.getTime())
      || !HEX32.test(certFingerprint) || !eventType || !Number.isInteger(sigFormVersion)
      || !Number.isSafeInteger(signedSeconds) || !actorAgentId || Number.isNaN(actorValidFrom.getTime())
      || !HEX32.test(actorCertFingerprint)) {
    fail('verified_occurrence_fields_required');
  }
  const content = {
    key: proof.key ?? memory.key,
    value: memory.value,
    scope: proof.scope ?? memory.scope,
    memory_type: proof.memory_type ?? memory.memory_type,
    clearance_level: proof.clearance_level ?? memory.clearance_level,
    data_class: proof.data_class ?? memory.data_class,
    source: proof.source ?? memory.source,
  };
  const recomputed = canonicalizeLiveContentState(content);
  if (recomputed.live_content_hash !== liveContentHash) fail('live_content_hash_mismatch');
  const occurrenceRef = sigFormVersion === 3
    ? mutationHash
    : computeVerifiedLegacyOccurrenceReference({
        company_id: authority.companyId,
        memory_id: memoryId,
        provenance_id: provenanceId,
        mutation_hash_hex: mutationHash,
        agent_id: signerAgentId,
        signer_valid_from_unix_ms: signerValidFrom.getTime(),
        cert_fingerprint_hex: certFingerprint,
        event_type: eventType,
        sig_form_version: sigFormVersion,
      });
  return {
    company_id: authority.companyId,
    memory_id: memoryId,
    occurrence_ref: occurrenceRef,
    live_content_hash: liveContentHash,
    content,
    principal: {
      agent_id: actorAgentId,
      valid_from: actorValidFrom.toISOString(),
      cert_fingerprint: actorCertFingerprint,
    },
    lineage: {
      lineage_id: String(proof.lineage_mutation_hash || `verified-memory:${memoryId}`),
      is_current_head: proof.version_status === 'current',
      signed_time_ms: signedSeconds * 1000,
    },
    admission: {
      principal_scope_admitted: true,
      provenance_verified: true,
      topology_verified: true,
    },
    evidence: {
      occurrence_eligible: evidenceScope?.occurrence_eligible === true,
      content_eligible: evidenceScope?.content_eligible === true,
      occurrence_decision_ref: evidenceScope?.occurrence_decision_ref || null,
      content_decision_ref: evidenceScope?.content_decision_ref || null,
    },
    gear_scores: {},
  };
}

function withoutInternalOccurrenceProof(memory, occurrence = null) {
  const proof = memory?.provenance_proof;
  if (!proof || typeof proof !== 'object') return memory;
  const {
    occurrence_provenance_id: _occurrenceProvenanceId,
    occurrence_mutation_hash: _occurrenceMutationHash,
    occurrence_signer_agent_id: _occurrenceSignerAgentId,
    occurrence_signer_valid_from: _occurrenceSignerValidFrom,
    occurrence_cert_fingerprint: _occurrenceCertFingerprint,
    occurrence_event_type: _occurrenceEventType,
    occurrence_sig_form_version: _occurrenceSigFormVersion,
    occurrence_ts_signed: _occurrenceTsSigned,
    occurrence_actor_agent_id: _occurrenceActorAgentId,
    occurrence_actor_valid_from: _occurrenceActorValidFrom,
    occurrence_actor_cert_fingerprint: _occurrenceActorCertFingerprint,
    ...publicProof
  } = proof;
  return {
    ...memory,
    provenance_proof: {
      ...publicProof,
      disclosure_occurrence_ref: occurrence?.occurrence_ref || null,
      disclosure_occurrence_signed_time_ms: occurrence?.lineage?.signed_time_ms || null,
    },
  };
}

export function createRequestScopedContentStateAdmission({
  authority,
  admitBatch,
  evidenceScopeOwner,
} = {}) {
  if (!authority?.companyId || !authority?.actorAgentId || typeof admitBatch !== 'function'
      || typeof evidenceScopeOwner?.resolve !== 'function'
      || typeof evidenceScopeOwner?.finalize !== 'function') {
    fail('owner_inputs_invalid');
  }
  const occurrenceByRef = new Map();
  let projection = projectContentStateOccurrenceViews({ occurrences: [] });
  let batchCount = 0;
  let proposedCount = 0;
  let admittedSubmissionCount = 0;
  let filteredCount = 0;
  let duplicateSubmissionCount = 0;
  let evidenceCacheStats = null;

  const selectCandidateStateRepresentatives = (
    memories,
    { retainIneligibleForSecurityBoundary = false } = {},
  ) => {
    const candidates = Array.isArray(memories) ? memories : [];
    const candidateById = new Map();
    for (const memory of candidates) {
      const id = String(memory?.id || memory?.memory_id || '').toLowerCase();
      if (!id || candidateById.has(id)) continue;
      candidateById.set(id, memory);
    }
    const occurrenceByRef = new Map(projection.occurrence_view.map((occurrence) => [
      occurrence.occurrence_ref,
      occurrence,
    ]));
    const occurrenceByMemoryId = new Map();
    for (const occurrence of projection.occurrence_view) {
      if (!occurrenceByMemoryId.has(occurrence.memory_id)) occurrenceByMemoryId.set(occurrence.memory_id, []);
      occurrenceByMemoryId.get(occurrence.memory_id).push(occurrence);
    }
    const stateByKey = new Map(projection.state_view.map((state) => [
      `${state.company_id}\0${state.live_content_hash}`,
      state,
    ]));
    const selected = [];
    const seenStates = new Set();
    for (const memory of candidateById.values()) {
      const id = String(memory.id || memory.memory_id).toLowerCase();
      const occurrences = occurrenceByMemoryId.get(id) || [];
      if (!occurrences.length) fail('candidate_state_mapping_missing');
      const stateKey = `${occurrences[0].company_id}\0${occurrences[0].live_content_hash}`;
      if (occurrences.some((occurrence) => `${occurrence.company_id}\0${occurrence.live_content_hash}` !== stateKey)) {
        fail('candidate_state_mapping_invalid');
      }
      if (seenStates.has(stateKey)) continue;
      seenStates.add(stateKey);
      const state = stateByKey.get(stateKey);
      if (!state) fail('candidate_state_mapping_missing');
      if (!state.rank_eligible && retainIneligibleForSecurityBoundary !== true) continue;
      const preferred = occurrenceByRef.get(state.disclosure_witness_occurrence_ref);
      let representativeId = preferred && candidateById.has(preferred.memory_id)
        ? preferred.memory_id
        : null;
      if (!representativeId) {
        const eligibleMembers = (
          state.rank_eligible
            ? state.eligible_occurrence_refs
            : state.occurrence_refs
        )
          .map((ref) => occurrenceByRef.get(ref))
          .filter((occurrence) => occurrence && candidateById.has(occurrence.memory_id))
          .sort((left, right) => (
            Number(right.lineage?.is_current_head) - Number(left.lineage?.is_current_head)
            || Number(right.lineage?.signed_time_ms || 0) - Number(left.lineage?.signed_time_ms || 0)
            || left.occurrence_ref.localeCompare(right.occurrence_ref)
          ));
        representativeId = eligibleMembers[0]?.memory_id || null;
      }
      if (!representativeId) fail('candidate_state_representative_missing');
      selected.push(candidateById.get(representativeId));
    }
    const decisionBody = {
      schema: 'hom.aimos.identifier-content-state-selection/v1',
      projection_decision_sha256: projection.decision.decision_sha256,
      input_count: candidates.length,
      unique_candidate_count: candidateById.size,
      selected_state_count: selected.length,
      collapsed_occurrence_count: candidateById.size - selected.length,
      explicit_memory_id_non_substitutable: true,
      security_boundary_population_retained: retainIneligibleForSecurityBoundary === true,
      retained_ineligible_state_count: retainIneligibleForSecurityBoundary === true
        ? selected.filter((memory) => {
            const id = String(memory.id || memory.memory_id).toLowerCase();
            const occurrence = (occurrenceByMemoryId.get(id) || [])[0];
            return occurrence
              ? stateByKey.get(`${occurrence.company_id}\0${occurrence.live_content_hash}`)
                ?.rank_eligible !== true
              : false;
          }).length
        : 0,
      rank_eligibility_bypassed: false,
      distinct_content_states_preserved: true,
      canonical_memory_mutated: false,
      retention_changed: false,
      authority_changed: false,
    };
    return Object.freeze({
      memories: Object.freeze(selected),
      decision: Object.freeze({
        ...decisionBody,
        decision_sha256: createHash('sha256')
          .update(Buffer.from(canonicalJson(decisionBody), 'utf8'))
          .digest('hex'),
      }),
    });
  };

  return Object.freeze({
    admit: async (memories) => {
      const proposed = Array.isArray(memories) ? memories : [];
      batchCount += 1;
      proposedCount += proposed.length;
      const admitted = await admitBatch(proposed);
      const rows = Array.isArray(admitted?.memories) ? admitted.memories : [];
      const evidenceScopeByMemoryId = await evidenceScopeOwner.resolve(
        rows,
        authority.companyId,
      );
      admittedSubmissionCount += rows.length;
      if (admitted?.evidence_cache?.schema === 'hom-aimos/request-local-recall-evidence-cache/v1') {
        evidenceCacheStats = Object.freeze({ ...admitted.evidence_cache });
      }
      filteredCount += Math.max(0, proposed.length - rows.length);
      for (const memory of rows) {
        const evidenceScope = evidenceScopeByMemoryId.get(
          String(memory.id || memory.memory_id || '').toLowerCase(),
        );
        if (!evidenceScope) fail('verified_evidence_scope_required');
        const occurrence = occurrenceFromAdmittedMemory(memory, authority, evidenceScope);
        const existing = occurrenceByRef.get(occurrence.occurrence_ref);
        if (existing) {
          if (canonicalJson(existing) !== canonicalJson(occurrence)) {
            fail('occurrence_replay_mismatch');
          }
          duplicateSubmissionCount += 1;
          continue;
        }
        occurrenceByRef.set(occurrence.occurrence_ref, occurrence);
      }
      projection = projectContentStateOccurrenceViews({
        occurrences: [...occurrenceByRef.values()],
      });
      const admittedOccurrenceByMemoryId = new Map();
      for (const occurrence of occurrenceByRef.values()) {
        if (!admittedOccurrenceByMemoryId.has(occurrence.memory_id)) {
          admittedOccurrenceByMemoryId.set(occurrence.memory_id, occurrence);
        }
      }
      return Object.freeze({
        ...admitted,
        memories: Object.freeze(rows.map((memory) => {
          const memoryId = String(memory.id || memory.memory_id || '').toLowerCase();
          const occurrence = admittedOccurrenceByMemoryId.get(memoryId) || null;
          return withoutInternalOccurrenceProof(memory, occurrence);
        })),
        occurrence_admission_decision_sha256: projection.decision.decision_sha256,
      });
    },
    metadata: () => Object.freeze({
      schema: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.schema,
      occurrence_reference: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.occurrence_reference,
      occurrence_reference_versions: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.occurrence_reference_versions,
      evidence_scope_status: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.evidence_scope_status,
      batch_count: batchCount,
      proposed_count: proposedCount,
      admitted_submission_count: admittedSubmissionCount,
      filtered_count: filteredCount,
      unique_occurrence_count: projection.decision.input_occurrence_count,
      duplicate_occurrence_submission_count: duplicateSubmissionCount,
      unique_state_count: projection.decision.unique_state_count,
      collapsed_occurrence_count: projection.decision.collapsed_occurrence_count,
      state_view_root_sha256: projection.decision.state_view_root_sha256,
      occurrence_view_root_sha256: projection.decision.occurrence_view_root_sha256,
      decision_sha256: projection.decision.decision_sha256,
      content_blocked_state_count: projection.decision.content_blocked_state_count,
      occurrence_blocked_count: projection.decision.occurrence_blocked_count,
      changes_gear_inputs: true,
      principal_scoped: true,
      canonical_memory_mutated: false,
      retention_changed: false,
      authority_changed: false,
      request_local_evidence_cache: evidenceCacheStats,
    }),
    publicMetadata: () => Object.freeze({
      schema: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.schema,
      occurrence_reference: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.occurrence_reference,
      occurrence_reference_versions: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.occurrence_reference_versions,
      evidence_scope_status: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.evidence_scope_status,
      unique_occurrence_count: projection.decision.input_occurrence_count,
      duplicate_occurrence_submission_count: duplicateSubmissionCount,
      unique_state_count: projection.decision.unique_state_count,
      collapsed_occurrence_count: projection.decision.collapsed_occurrence_count,
      state_view_root_sha256: projection.decision.state_view_root_sha256,
      occurrence_view_root_sha256: projection.decision.occurrence_view_root_sha256,
      decision_sha256: projection.decision.decision_sha256,
      content_blocked_state_count: projection.decision.content_blocked_state_count,
      occurrence_blocked_count: projection.decision.occurrence_blocked_count,
      changes_gear_inputs: true,
      principal_scoped: true,
      canonical_memory_mutated: false,
      retention_changed: false,
      authority_changed: false,
      request_local_evidence_cache: evidenceCacheStats,
    }),
    finalizeEvidenceScope: () => evidenceScopeOwner.finalize(projection),
    selectCandidateStateRepresentatives,
    internalProjection: () => projection,
  });
}
