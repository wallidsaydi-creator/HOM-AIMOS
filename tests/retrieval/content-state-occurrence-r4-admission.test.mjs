import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { computeLegacyOccurrenceReference } from '../../eval/mutmem-v2/content-state-occurrence-crypto.mjs';
import { canonicalizeLiveContentState } from '../../services/retrieval/content-state-occurrence/kernel.js';
import { computeVerifiedLegacyOccurrenceReference } from '../../services/retrieval/content-state-occurrence/legacy-occurrence-reference.js';
import { calibrateNativeRecallResponse } from '../../services/retrieval/recall-output-calibrator.js';
import {
  REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT,
  createRequestScopedContentStateAdmission,
} from '../../services/retrieval/content-state-occurrence/request-admission.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const AUTHORITY = Object.freeze({ companyId: 'hom', actorAgentId: 'codex-auditor' });
const UUIDS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
  '44444444-4444-4444-8444-444444444444',
];

function memory(index, { value = 'same content', hidden = false } = {}) {
  const content = {
    key: 'r4:test',
    value,
    scope: 'global',
    memory_type: 'fact',
    clearance_level: 5,
    data_class: 'confidential',
    source: 'r4-fixture',
  };
  const liveHash = canonicalizeLiveContentState(content).live_content_hash;
  return {
    id: UUIDS[index],
    ...content,
    hidden,
    provenance_proof: {
      company_id: 'hom',
      subject_agent_id: 'fixture-subject',
      key: content.key,
      scope: content.scope,
      cube_scope: 'shared',
      memory_type: content.memory_type,
      clearance_level: content.clearance_level,
      data_class: content.data_class,
      source: content.source,
      live_content_hash: liveHash,
      save_mutation_hash: (index + 5).toString(16).repeat(64).slice(0, 64),
      binding_mutation_hash: (index + 9).toString(16).repeat(64).slice(0, 64),
      occurrence_provenance_id: UUIDS[(index + 1) % UUIDS.length],
      occurrence_mutation_hash: (index + 1).toString(16).repeat(64).slice(0, 64),
      occurrence_signer_agent_id: `writer-${index}`,
      occurrence_signer_valid_from: '2026-08-17T00:00:00.000Z',
      occurrence_cert_fingerprint: 'a'.repeat(64),
      occurrence_event_type: 'SAVE',
      occurrence_sig_form_version: 1,
      occurrence_ts_signed: 1_786_200_000 + index,
      lineage_mutation_hash: null,
      version_status: 'current',
    },
  };
}

function passthroughAdmission() {
  return async (rows) => ({
    memories: rows.filter((row) => !row.hidden),
    rejected: [],
  });
}

function eligibleEvidenceScopeOwner() {
  return {
    async resolve(rows) {
      return new Map(rows.map((row) => [String(row.id), {
        occurrence_eligible: true,
        content_eligible: true,
        occurrence_decision_ref: null,
        content_decision_ref: null,
      }]));
    },
    finalize(projection) {
      return {
        decision_sha256: projection.decision.decision_sha256,
        authorized_class_commitment_sha256: projection.decision.state_view_root_sha256,
        retained_blocked_decision_set_sha256: '0'.repeat(64),
      };
    },
  };
}

test('R4 request owner incrementally accumulates admitted occurrences and exact states', async () => {
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  const a1 = memory(0);
  const a2 = memory(1);
  const b1 = memory(2, { value: 'different content' });
  const first = await owner.admit([a1, a2]);
  const second = await owner.admit([a2, b1]);
  const metadata = owner.metadata();
  const projection = owner.internalProjection();

  assert.deepEqual(first.memories.map((row) => row.id), [a1.id, a2.id]);
  assert.deepEqual(second.memories.map((row) => row.id), [a2.id, b1.id]);
  assert.equal(first.memories.every((row) => row.provenance_proof.occurrence_provenance_id === undefined), true);
  assert.equal(metadata.batch_count, 2);
  assert.equal(metadata.proposed_count, 4);
  assert.equal(metadata.admitted_submission_count, 4);
  assert.equal(metadata.unique_occurrence_count, 3);
  assert.equal(metadata.duplicate_occurrence_submission_count, 1);
  assert.equal(metadata.unique_state_count, 2);
  assert.equal(metadata.collapsed_occurrence_count, 1);
  assert.equal(projection.occurrence_view.length, 3);
  assert.equal(projection.state_view.length, 2);
  assert.equal(metadata.changes_gear_inputs, true);
});

test('production legacy reference has exact R3 parity for an admitted proof', async () => {
  const row = memory(0);
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  await owner.admit([row]);
  const occurrence = owner.internalProjection().occurrence_view[0];
  const input = {
    company_id: 'hom',
    memory_id: row.id,
    provenance_id: row.provenance_proof.occurrence_provenance_id,
    mutation_hash_hex: row.provenance_proof.occurrence_mutation_hash,
    agent_id: row.provenance_proof.occurrence_signer_agent_id,
    signer_valid_from_unix_ms: Date.parse(row.provenance_proof.occurrence_signer_valid_from),
    cert_fingerprint_hex: row.provenance_proof.occurrence_cert_fingerprint,
    event_type: row.provenance_proof.occurrence_event_type,
    sig_form_version: row.provenance_proof.occurrence_sig_form_version,
  };
  assert.equal(occurrence.occurrence_ref, computeVerifiedLegacyOccurrenceReference(input));
  assert.equal(occurrence.occurrence_ref, computeLegacyOccurrenceReference(input));
});

test('filtered principal-scope proposals affect only aggregate counters and leak no identity', async () => {
  const visible = memory(0);
  const hidden = memory(1, { hidden: true });
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  await owner.admit([visible, hidden]);
  const serialized = JSON.stringify(owner.metadata());
  const publicSerialized = JSON.stringify(owner.publicMetadata());
  assert.equal(owner.metadata().filtered_count, 1);
  assert.equal(owner.metadata().unique_occurrence_count, 1);
  assert.equal(serialized.includes(hidden.id), false);
  assert.equal(serialized.includes(hidden.provenance_proof.occurrence_provenance_id), false);
  assert.equal(serialized.includes(hidden.provenance_proof.occurrence_signer_agent_id), false);
  assert.equal(publicSerialized.includes('filtered_count'), false);
  assert.equal(publicSerialized.includes('proposed_count'), false);
  assert.equal(publicSerialized.includes(hidden.id), false);
});

test('same occurrence reference replayed with different content fails closed', async () => {
  const original = memory(0);
  const tampered = memory(0, { value: 'tampered content' });
  tampered.provenance_proof.occurrence_provenance_id = original.provenance_proof.occurrence_provenance_id;
  tampered.provenance_proof.occurrence_mutation_hash = original.provenance_proof.occurrence_mutation_hash;
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  await owner.admit([original]);
  await assert.rejects(owner.admit([tampered]), /occurrence_replay_mismatch/);
});

test('R4 owner requires verified occurrence proof fields and never defaults them', async () => {
  const incomplete = memory(0);
  delete incomplete.provenance_proof.occurrence_signer_valid_from;
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  await assert.rejects(owner.admit([incomplete]), /verified_occurrence_fields_required/);
});

test('R5B exact identifier keeps distinct states and collapses only byte-identical occurrences', async () => {
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  const a1 = memory(0);
  const a2 = memory(1);
  const b1 = memory(2, { value: 'different retained state' });
  const admitted = await owner.admit([a1, a2, b1]);
  const selected = owner.selectCandidateStateRepresentatives(admitted.memories);
  assert.equal(selected.decision.input_count, 3);
  assert.equal(selected.decision.selected_state_count, 2);
  assert.equal(selected.decision.collapsed_occurrence_count, 1);
  assert.equal(selected.decision.explicit_memory_id_non_substitutable, true);
  assert.deepEqual(
    new Set(selected.memories.map((row) => row.provenance_proof.live_content_hash)),
    new Set([
      a1.provenance_proof.live_content_hash,
      b1.provenance_proof.live_content_hash,
    ]),
  );
});

test('R5B explicit memory identifier remains the exact admitted row', async () => {
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: eligibleEvidenceScopeOwner(),
  });
  const exact = memory(0);
  const admitted = await owner.admit([exact]);
  const selected = owner.selectCandidateStateRepresentatives(admitted.memories);
  assert.equal(selected.memories.length, 1);
  assert.equal(selected.memories[0].id, exact.id);
  assert.equal(selected.decision.collapsed_occurrence_count, 0);
});

test('R5B exact identifier retains blocked state for the signed security boundary only', async () => {
  const blockedEvidenceScopeOwner = {
    async resolve(rows) {
      return new Map(rows.map((row) => [String(row.id), {
        occurrence_eligible: true,
        content_eligible: false,
        occurrence_decision_ref: null,
        content_decision_ref: 'b'.repeat(64),
      }]));
    },
    finalize: eligibleEvidenceScopeOwner().finalize,
  };
  const owner = createRequestScopedContentStateAdmission({
    authority: AUTHORITY,
    admitBatch: passthroughAdmission(),
    evidenceScopeOwner: blockedEvidenceScopeOwner,
  });
  const exact = memory(0);
  const admitted = await owner.admit([exact]);
  const rankSelection = owner.selectCandidateStateRepresentatives(admitted.memories);
  const securitySelection = owner.selectCandidateStateRepresentatives(
    admitted.memories,
    { retainIneligibleForSecurityBoundary: true },
  );
  assert.equal(rankSelection.memories.length, 0);
  assert.equal(securitySelection.memories.length, 1);
  assert.equal(securitySelection.memories[0].id, exact.id);
  assert.equal(securitySelection.decision.security_boundary_population_retained, true);
  assert.equal(securitySelection.decision.retained_ineligible_state_count, 1);
  assert.equal(securitySelection.decision.rank_eligibility_bypassed, false);
  assert.equal(owner.internalProjection().state_view[0].rank_eligible, false);
});

test('R4 source uses one request-scoped session across every production candidate lane', () => {
  const source = fs.readFileSync(path.join(ROOT, 'services/retrieval/native-recall-pipeline.js'), 'utf8');
  assert.match(source, /openNativeRecallAdmissionSession/);
  assert.match(source, /createRequestScopedContentStateAdmission/);
  assert.doesNotMatch(source, /admitNativeRecallCandidates\(/);
  assert.equal((source.match(/contentStateOccurrenceAdmission\.admit\(/g) || []).length, 8);
  assert.match(source, /admitEvidenceFn: contentStateOccurrenceAdmission\.admit/);
  assert.match(source, /contentStateOccurrenceAdmission\.selectCandidateStateRepresentatives/);
  assert.match(source, /const siblingAdmission = siblingCandidates\.length/);
  assert.match(source, /await contentStateOccurrenceAdmission\.admit\(siblingCandidates\)/);
  assert.match(source, /content_state_selection: handoffStateSelection\.decision/);
  assert.equal((source.match(/contentStateProjection: contentStateOccurrenceAdmission\.internalProjection\(\)/g) || []).length, 4);
  assert.equal((source.match(/contentStateGears: NATIVE_RETRIEVAL_FUSION_CONTRACT\.content_state_first_gear_set/g) || []).length, 3);
  assert.match(source, /verifiedAdmissionSession\.close\(\{ commit: false \}\)/);
  assert.ok((source.match(/content_state_occurrence_admission:/g) || []).length >= 4);
  const siblingStart = source.indexOf('const siblingCandidates = []');
  const siblingAdmission = source.indexOf('await contentStateOccurrenceAdmission.admit(siblingCandidates)', siblingStart);
  const siblingPush = source.indexOf('memories.push(memory)', siblingAdmission);
  const reranking = source.indexOf('// ─── REFINEMENT 2: Re-ranking', siblingPush);
  assert.ok(siblingStart >= 0);
  assert.ok(siblingAdmission > siblingStart);
  assert.ok(siblingPush > siblingAdmission);
  assert.ok(reranking > siblingPush);
  const entityCandidates = source.indexOf('entityCandidates = entResult.rows.map');
  const entityAdmission = source.indexOf('await contentStateOccurrenceAdmission.admit(entityCandidates)', entityCandidates);
  const entityMerge = source.indexOf('const entityMemoryById = new Map', entityAdmission);
  assert.ok(entityCandidates >= 0);
  assert.ok(entityAdmission > entityCandidates);
  assert.ok(entityMerge > entityAdmission);
  assert.ok(reranking > entityMerge);
  assert.match(source, /existing\.entity_hits = Math\.max\(/);
  assert.match(source, /entityAdmission\.occurrence_admission_decision_sha256/);
  assert.match(source, /ORDER BY entity_hits DESC, e\.memory_id ASC/);
  const qmdProposals = source.indexOf('const qmdProposals =');
  const qmdAdmission = source.indexOf('await contentStateOccurrenceAdmission.admit(qmdProposals)', qmdProposals);
  const qmdMerge = source.indexOf('const rescueMemoryById = new Map', qmdAdmission);
  const hydeCall = source.indexOf('const hydeResults = await multiStageRecall', qmdMerge);
  const hydeOwner = source.indexOf('admitEvidenceFn: contentStateOccurrenceAdmission.admit', hydeCall);
  assert.ok(qmdProposals >= 0);
  assert.ok(qmdAdmission > qmdProposals);
  assert.ok(qmdMerge > qmdAdmission);
  assert.ok(hydeCall > qmdMerge);
  assert.ok(hydeOwner > hydeCall);
  assert.ok(reranking < qmdProposals);
  assert.match(source, /existing\.qmd_score = Math\.max\(/);
  assert.match(source, /existing\.hyde_score = Math\.max\(/);
  assert.match(source, /getAuthorizedRescueDataClasses/);
  assert.doesNotMatch(source, /metadata->>'source'/);
  assert.match(source, /LOWER\(COALESCE\(source,''\)\)/);
  const conceptStage = source.indexOf("markStage('concept_graph_ppr')");
  const conceptSelection = source.indexOf('const conceptPprStateSelection =', conceptStage);
  const conceptLookup = source.indexOf('await conceptPprLookup(', conceptSelection);
  const postGraphAdmission = source.indexOf('const postGraphAdmission = await contentStateOccurrenceAdmission.admit', conceptLookup);
  assert.ok(conceptStage >= 0);
  assert.ok(conceptSelection > conceptStage);
  assert.ok(conceptLookup > conceptSelection);
  assert.ok(postGraphAdmission > conceptLookup);
  assert.match(source.slice(conceptLookup, postGraphAdmission), /admittedStates: conceptPprStateMemories\.map/);
  assert.match(source.slice(conceptLookup, postGraphAdmission), /live_content_hash: memory\.provenance_proof\?\.live_content_hash/);
  assert.doesNotMatch(source.slice(conceptStage, postGraphAdmission), /pprOnlyIds|PPR passage hydration/);
  assert.match(source, /max_hops !== undefined && max_hops !== null/);
});

test('R4 owner is native, internal-only, and has no database or environment authority', () => {
  const source = fs.readFileSync(path.join(
    ROOT,
    'services/retrieval/content-state-occurrence/request-admission.js',
  ), 'utf8');
  assert.doesNotMatch(source, /db\/connection|process\.env|routes\/|server\.js|persist-memory|migrations\//);
  assert.equal(REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.changes_gear_inputs, true);
  assert.equal(REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.disclosure_authority, false);
  assert.equal(REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.mutation_authority, false);
  assert.equal(REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.deletion_authority, false);
});

test('caller-safe R4 admission metadata survives output calibration unchanged', () => {
  const metadata = {
    schema: REQUEST_SCOPED_OCCURRENCE_ADMISSION_CONTRACT.schema,
    occurrence_reference: 'hom.aimos.memory-occurrence-reference/versioned-v1-v3',
    occurrence_reference_versions: [
      'hom.aimos.memory-occurrence-ref/legacy-v1',
      'hom.aimos.memory-occurrence/v3',
    ],
    unique_occurrence_count: 2,
    duplicate_occurrence_submission_count: 1,
    unique_state_count: 1,
    collapsed_occurrence_count: 1,
    state_view_root_sha256: 'a'.repeat(64),
    occurrence_view_root_sha256: 'b'.repeat(64),
    decision_sha256: 'c'.repeat(64),
    principal_scoped: true,
    changes_gear_inputs: false,
  };
  const calibrated = calibrateNativeRecallResponse({
    query: 'R4 metadata parity',
    recallResponse: {
      success: true,
      memories: [],
      recall_meta: { content_state_occurrence_admission: metadata },
    },
  });
  assert.deepEqual(calibrated.recall_meta.content_state_occurrence_admission, metadata);
});

test('R5B identifier state-selection evidence survives output calibration', () => {
  const identifierRecall = {
    status: 'exact_match',
    candidate_count: 3,
    content_state_selection: {
      schema: 'hom.aimos.identifier-content-state-selection/v1',
      selected_state_count: 2,
      collapsed_occurrence_count: 1,
      decision_sha256: 'd'.repeat(64),
    },
  };
  const calibrated = calibrateNativeRecallResponse({
    query: 'key:exact-fixture',
    recallResponse: { success: true, memories: [], recall_meta: { identifier_recall: identifierRecall } },
  });
  assert.deepEqual(calibrated.recall_meta.identifier_recall, identifierRecall);
});

test('R5C handoff state-selection evidence survives output calibration', () => {
  const handoff = {
    source: 'native_compaction_lane',
    content_state_selection: {
      schema: 'hom.aimos.identifier-content-state-selection/v1',
      input_count: 3,
      selected_state_count: 2,
      collapsed_occurrence_count: 1,
      decision_sha256: 'e'.repeat(64),
    },
  };
  const calibrated = calibrateNativeRecallResponse({
    query: 'resume post compaction handoff',
    recallResponse: { success: true, memories: [], recall_meta: { compaction_handoff_recall: handoff } },
  });
  assert.deepEqual(calibrated.recall_meta.compaction_handoff_recall, handoff);
});
