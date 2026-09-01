import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

import {
  cognitiveProjectionHash,
  cognitiveTransitionHash,
} from '../../services/security/protocol/mutmem-protocol.js';
import {
  createMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const UUID = {
  memory: '11111111-1111-4111-8111-111111111111',
  recall: '22222222-2222-4222-8222-222222222222',
  outcome: '33333333-3333-4333-8333-333333333333',
  outcomeEvent: '44444444-4444-4444-8444-444444444444',
  terminalEvent: '55555555-5555-4555-8555-555555555555',
};
const HASH = {
  recallMutation: sha('recall-event'),
  merkle: sha('recall-merkle'),
  security: sha('security-closure'),
  content: sha('live-content'),
  occurrence: sha('occurrence'),
  outcomeEvent: sha('outcome-event'),
  valence: sha('valence-row'),
  provenance: sha('reweight-provenance'),
  previousProjection: sha('previous-projection'),
};
const SIGNATURE = Buffer.alloc(64, 9).toString('base64url');

function common(targetScope = 'principal_state') {
  const outcome = {
    schema: 'hom.aimos.mutation-outcome-evidence/v2',
    company_id: 'hom',
    memory_id: UUID.memory,
    live_content_hash: HASH.content,
    occurrence_ref: HASH.occurrence,
    target_scope: targetScope,
    recall_event_id: UUID.recall,
    recall_event_mutation_hash: HASH.recallMutation,
    recall_merkle_root: HASH.merkle,
    security_closure_sha256: HASH.security,
    outcome_id: UUID.outcome,
  };
  const recall = {
    event_id: UUID.recall,
    mutation_hash: HASH.recallMutation,
    merkle_root: HASH.merkle,
    security_closure_sha256: HASH.security,
    evidence: {
      memory_id: UUID.memory,
      live_content_hash: HASH.content,
      occurrence_ref: HASH.occurrence,
    },
  };
  const outcomeEvent = {
    event_id: UUID.outcomeEvent,
    mutation_hash: HASH.outcomeEvent,
    operation: 'mutation_outcome_evidence_v2',
    parent_event_id: UUID.recall,
    metadata: {
      target_scope: targetScope,
      memory_id: UUID.memory,
      live_content_hash: HASH.content,
      occurrence_ref: HASH.occurrence,
    },
  };
  const valenceBody = {
    evidence_schema: 'hom.aimos.mutation-outcome-evidence/v2',
    target_scope: targetScope,
    memory_id: UUID.memory,
    target_live_content_hash: HASH.content,
    target_occurrence_ref: HASH.occurrence,
    recall_event_id: UUID.recall,
    recall_event_mutation_hash: HASH.recallMutation,
    recall_merkle_root: HASH.merkle,
    security_closure_sha256: HASH.security,
    outcome_id: UUID.outcome,
    outcome_event_id: UUID.outcomeEvent,
    outcome_event_mutation_hash: HASH.outcomeEvent,
  };
  return {
    outcome,
    recall,
    outcomeEvent,
    valence: { row_hash: HASH.valence, reward_sign: 1, body_json: valenceBody },
  };
}

function transitionInput() {
  const base = common('principal_state');
  const oldWeightMilli = 1000;
  const newWeightMilli = 1100;
  const projectionHash = cognitiveProjectionHash({
    memoryId: UUID.memory,
    oldWeightMilli,
    newWeightMilli,
    provenanceMutationHash: Buffer.from(HASH.provenance, 'hex'),
    previousHash: Buffer.from(HASH.previousProjection, 'hex'),
  }).toString('hex');
  const transitionHash = cognitiveTransitionHash({
    companyId: 'hom',
    memoryId: UUID.memory,
    oldWeight: oldWeightMilli / 1000,
    newWeight: newWeightMilli / 1000,
    provenanceMutationHash: Buffer.from(HASH.provenance, 'hex'),
  }).toString('hex');
  return {
    ...base,
    terminal: {
      kind: 'authorized_transition',
      reweight_provenance: {
        memory_id: UUID.memory,
        event_type: 'REWEIGHT',
        mutation_hash: HASH.provenance,
        body_json: { valence_row_hash: HASH.valence },
      },
    },
    projection: {
      memory_id: UUID.memory,
      provenance_mutation_hash: HASH.provenance,
      old_weight_milli: oldWeightMilli,
      new_weight_milli: newWeightMilli,
      prev_projection_hash: HASH.previousProjection,
      projection_hash: projectionHash,
      transition_hash: transitionHash,
      transition_signature_b64u: SIGNATURE,
    },
  };
}

function noopInput() {
  const base = common('principal_state');
  return {
    ...base,
    terminal: {
      kind: 'signed_noop',
      event: {
        event_id: UUID.terminalEvent,
        operation: 'cognitive_weight_unchanged',
        parent_event_id: null,
        metadata: { valence_row_hash: HASH.valence, projection_appended: false },
      },
    },
    projection: null,
  };
}

function observationInput() {
  const base = common('occurrence_observation');
  return {
    ...base,
    terminal: {
      kind: 'occurrence_observation',
      event: {
        event_id: UUID.terminalEvent,
        operation: 'mutation_occurrence_observation_retained',
        parent_event_id: UUID.outcomeEvent,
        metadata: {
          outcome_id: UUID.outcome,
          occurrence_ref: HASH.occurrence,
          projection_appended: false,
        },
      },
    },
    projection: null,
  };
}

function bundle(input, id) {
  return createMutMemPortableMutationBundleV2({
    bundleId: id,
    companyId: 'hom',
    recallEvidenceSha256: sha(Buffer.from(canonicalJson(input.recall), 'utf8')),
    outcomeEvidence: input.outcome,
    recallReceipt: input.recall,
    outcomeEvent: input.outcomeEvent,
    valenceEvidence: input.valence,
    terminal: input.terminal,
    cognitiveProjection: input.projection,
  });
}

const negative = [
  ['MUTATION_OUTCOME_SCHEMA_INVALID', (x) => { x.outcome.schema = 'wrong'; }],
  ['MUTATION_RECALL_BINDING_INVALID', (x) => { x.recall.merkle_root = sha('wrong'); }],
  ['MUTATION_OUTCOME_EVENT_INVALID', (x) => { x.outcomeEvent.parent_event_id = UUID.outcome; }],
  ['MUTATION_VALENCE_BINDING_INVALID', (x) => { x.valence.body_json.outcome_id = UUID.recall; }],
  ['MUTATION_TERMINAL_KIND_INVALID', (x) => { x.terminal.kind = 'unknown'; }],
  ['MUTATION_OBSERVATION_TERMINAL_INVALID', (x) => { x.terminal.event.parent_event_id = UUID.recall; }, observationInput],
  ['MUTATION_NOOP_TERMINAL_INVALID', (x) => { x.terminal.event.metadata.projection_appended = true; }, noopInput],
  ['MUTATION_TRANSITION_PROVENANCE_INVALID', (x) => { x.terminal.reweight_provenance.body_json.valence_row_hash = sha('wrong'); }],
  ['MUTATION_PROJECTION_BINDING_INVALID', (x) => { x.projection.old_weight_milli = 99; }],
  ['MUTATION_PROJECTION_HASH_INVALID', (x) => { x.projection.projection_hash = sha('wrong'); }],
  ['MUTATION_TRANSITION_HASH_INVALID', (x) => { x.projection.transition_hash = sha('wrong'); }],
];

export function createMutMemPortableMutationVectorsV2() {
  const vectors = [
    { id: 'P1-MUT-CV-VALID-TRANSITION', expected: 'valid', reason: null, bundle: bundle(transitionInput(), 'P1-MUT-CV-VALID-TRANSITION') },
    { id: 'P1-MUT-CV-VALID-NOOP', expected: 'valid', reason: null, bundle: bundle(noopInput(), 'P1-MUT-CV-VALID-NOOP') },
    { id: 'P1-MUT-CV-VALID-OBSERVATION', expected: 'valid', reason: null, bundle: bundle(observationInput(), 'P1-MUT-CV-VALID-OBSERVATION') },
    ...negative.map(([reason, mutate, factory = transitionInput], index) => {
      const input = factory();
      mutate(input);
      return {
        id: `P1-MUT-CV-${String(index + 1).padStart(3, '0')}`,
        expected: 'invalid',
        reason,
        bundle: bundle(input, `P1-MUT-CV-${String(index + 1).padStart(3, '0')}`),
      };
    }),
  ];
  const tampered = structuredClone(vectors[0].bundle);
  tampered.bundle_sha256 = sha('tampered');
  vectors.push({
    id: 'P1-MUT-CV-BUNDLE-COMMITMENT',
    expected: 'invalid',
    reason: 'MUTATION_BUNDLE_COMMITMENT_INVALID',
    bundle: tampered,
  });
  return Object.freeze(vectors.map((vector) => Object.freeze(vector)));
}
