import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalizeLiveContentState } from '../../services/retrieval/content-state-occurrence/kernel.js';
import { createRequestScopedContentStateAdmission } from '../../services/retrieval/content-state-occurrence/request-admission.js';
import {
  REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT,
  createRequestEpistemicEvidenceScope,
} from '../../services/retrieval/content-state-occurrence/evidence-scope.js';

const IDS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333',
];
const HASH = (character) => character.repeat(64);

function admittedMemory(index, value) {
  const content = {
    key: index < 2 ? 'state:a' : 'state:b',
    value,
    scope: 'global',
    memory_type: 'fact',
    clearance_level: 5,
    data_class: 'confidential',
    source: 'r6-fixture',
  };
  const liveContentHash = canonicalizeLiveContentState(content).live_content_hash;
  return {
    id: IDS[index],
    ...content,
    provenance_proof: {
      company_id: 'hom',
      subject_agent_id: 'fixture',
      ...content,
      cube_scope: 'shared',
      live_content_hash: liveContentHash,
      save_mutation_hash: HASH('a'),
      binding_mutation_hash: HASH('b'),
      occurrence_provenance_id: IDS[(index + 1) % IDS.length],
      occurrence_mutation_hash: HASH(String(index + 1)),
      occurrence_signer_agent_id: `writer-${index}`,
      occurrence_signer_valid_from: '2026-08-17T00:00:00.000Z',
      occurrence_cert_fingerprint: HASH('c'),
      occurrence_event_type: 'SAVE',
      occurrence_sig_form_version: 1,
      occurrence_ts_signed: 1_786_200_000 + index,
      lineage_mutation_hash: null,
      version_status: 'current',
    },
  };
}

function verifiedRow(memory, label, {
  confidenceMilli = 800,
  evidenceRoot = null,
  ok = true,
  reason = null,
} = {}) {
  const unverified = label === 'unverified';
  return {
    memory_id: memory.id,
    live_content_hash: memory.provenance_proof.live_content_hash,
    scope: memory.scope,
    memory_type: memory.memory_type,
    ok,
    chain_length: unverified ? 0 : 1,
    current_label: label,
    current_confidence_milli: unverified ? 0 : confidenceMilli,
    classification_head_hash: unverified ? null : HASH('d'),
    reason,
    classification_event_mutation_hash: unverified ? null : HASH('e'),
    classification_event_metadata: evidenceRoot ? {
      evidence_assertion_binding: {
        evidence_root_sha256: evidenceRoot,
        independent_supporting_source_count: 1,
        independent_refuting_source_count: 1,
      },
    } : null,
  };
}

test('R6 signed scope blocks a complete poison class without exonerating its peer occurrence', async () => {
  const a1 = admittedMemory(0, 'same retained state');
  const a2 = admittedMemory(1, 'same retained state');
  const b1 = admittedMemory(2, 'different retained state');
  const rowById = new Map([
    [a1.id, verifiedRow(a1, 'poison_likely')],
    [a2.id, verifiedRow(a2, 'poison_refuted', { evidenceRoot: HASH('f') })],
    [b1.id, verifiedRow(b1, 'unverified')],
  ]);
  let queryCalls = 0;
  const evidenceScopeOwner = createRequestEpistemicEvidenceScope({
    queryFn: async (sql, params) => {
      queryCalls += 1;
      assert.match(sql, /verify_memory_epistemic_classification_chain/);
      return { rows: params[1].map((id) => rowById.get(id)) };
    },
  });
  const owner = createRequestScopedContentStateAdmission({
    authority: { companyId: 'hom', actorAgentId: 'codex-auditor' },
    admitBatch: async (rows) => ({ memories: rows, rejected: [] }),
    evidenceScopeOwner,
  });
  await owner.admit([a1, a2, b1]);
  await owner.admit([a1, b1]);

  const projection = owner.internalProjection();
  const decision = owner.finalizeEvidenceScope();
  assert.equal(queryCalls, 1, 'one request-local verifier read per unseen identity');
  assert.equal(projection.decision.input_occurrence_count, 3);
  assert.equal(projection.decision.unique_state_count, 2);
  assert.equal(projection.decision.rank_eligible_state_count, 1);
  assert.equal(projection.decision.content_blocked_state_count, 1);
  assert.equal(projection.decision.occurrence_blocked_count, 1);
  assert.equal(decision.blocked_record_count, 2);
  assert.deepEqual(decision.blocked_records.map((row) => row.memory_id).sort(), [a1.id, a2.id]);
  assert.equal(decision.blocked_records.every((row) => row.projection_rank_eligible === false), true);
  assert.deepEqual(decision.evidence_root_sha256s, [HASH('f')]);
  assert.equal(decision.no_exoneration, true);
  assert.equal(decision.label_history_changed, false);
  assert.equal(decision.retention_changed, false);
  assert.match(decision.retained_blocked_decision_set_sha256, /^[0-9a-f]{64}$/);
  assert.match(decision.decision_sha256, /^[0-9a-f]{64}$/);
  assert.equal(REQUEST_EPISTEMIC_EVIDENCE_SCOPE_CONTRACT.classification_authority, false);
});

test('R6 evidence scope fails closed on invalid chains and missing mandatory typed evidence', async () => {
  const memory = admittedMemory(0, 'retained state');
  const invalidChain = createRequestEpistemicEvidenceScope({
    queryFn: async () => ({ rows: [verifiedRow(memory, 'poison_likely', {
      ok: false,
      reason: 'signed_event_mismatch',
    })] }),
  });
  await assert.rejects(
    invalidChain.resolve([memory], 'hom'),
    /classification_chain_invalid:signed_event_mismatch/,
  );

  const missingEvidence = createRequestEpistemicEvidenceScope({
    queryFn: async () => ({ rows: [verifiedRow(memory, 'poison_confirmed')] }),
  });
  await assert.rejects(
    missingEvidence.resolve([memory], 'hom'),
    /typed_evidence_root_required/,
  );
});
