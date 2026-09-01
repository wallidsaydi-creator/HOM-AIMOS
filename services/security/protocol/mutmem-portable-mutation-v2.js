// Authority-free portable mutation-outcome/cognitive-projection profile.

import { createHash } from 'node:crypto';

import { canonicalJson } from './canonical-json.js';
import {
  cognitiveProjectionHash,
  cognitiveTransitionHash,
} from './mutmem-protocol.js';

export const MUTMEM_PORTABLE_MUTATION_V2 = Object.freeze({
  schema: 'hom.aimos.mutmem-portable-mutation-evidence/v2',
  version: 2,
  native_outcome_schema: 'hom.aimos.mutation-outcome-evidence/v2',
  domain: Buffer.from('hom.aimos.mutmem-portable-mutation-evidence/v2\0', 'utf8'),
  terminal_kinds: Object.freeze([
    'authorized_transition',
    'signed_noop',
    'occurrence_observation',
  ]),
});

export const MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2 = Object.freeze([
  'MUTATION_BUNDLE_COMMITMENT_INVALID',
  'MUTATION_OUTCOME_SCHEMA_INVALID',
  'MUTATION_RECALL_BINDING_INVALID',
  'MUTATION_OUTCOME_EVENT_INVALID',
  'MUTATION_VALENCE_BINDING_INVALID',
  'MUTATION_TERMINAL_KIND_INVALID',
  'MUTATION_OBSERVATION_TERMINAL_INVALID',
  'MUTATION_NOOP_TERMINAL_INVALID',
  'MUTATION_TRANSITION_PROVENANCE_INVALID',
  'MUTATION_PROJECTION_BINDING_INVALID',
  'MUTATION_PROJECTION_HASH_INVALID',
  'MUTATION_TRANSITION_HASH_INVALID',
]);

const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function fail(code) {
  if (!MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2.includes(code)) {
    throw new Error('mutmem_portable_mutation_v2:UNDECLARED_FAILURE_CODE');
  }
  throw new Error(`mutmem_portable_mutation_v2:${code}`);
}

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalClone(value) {
  return JSON.parse(canonicalJson(value));
}

function exactHash(value, code) {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) fail(code);
  return normalized;
}

export function mutMemPortableMutationHashV2(body) {
  return sha(Buffer.concat([
    MUTMEM_PORTABLE_MUTATION_V2.domain,
    Buffer.from(canonicalJson(body), 'utf8'),
  ]));
}

export function createMutMemPortableMutationBundleV2(input = {}) {
  const body = canonicalClone({
    format: {
      schema: MUTMEM_PORTABLE_MUTATION_V2.schema,
      version: MUTMEM_PORTABLE_MUTATION_V2.version,
      native_outcome_schema: MUTMEM_PORTABLE_MUTATION_V2.native_outcome_schema,
      canonicalization: 'hom-aimos/canonical-json/v1',
      hash: 'sha256',
      signature: 'ed25519',
    },
    bundle_id: input.bundleId,
    company_id: input.companyId,
    recall_evidence_sha256: input.recallEvidenceSha256,
    outcome_evidence: input.outcomeEvidence,
    recall_receipt: input.recallReceipt,
    outcome_event: input.outcomeEvent,
    valence_evidence: input.valenceEvidence,
    terminal: input.terminal,
    cognitive_projection: input.cognitiveProjection ?? null,
  });
  if (!body.bundle_id || !body.company_id) fail('MUTATION_BUNDLE_COMMITMENT_INVALID');
  return Object.freeze({
    ...body,
    bundle_sha256: mutMemPortableMutationHashV2(body),
  });
}

function validateOutcome(bundle) {
  const outcome = bundle.outcome_evidence;
  const recall = bundle.recall_receipt;
  if (outcome?.schema !== MUTMEM_PORTABLE_MUTATION_V2.native_outcome_schema
      || outcome.company_id !== bundle.company_id
      || !UUID.test(String(outcome.memory_id || ''))
      || !HEX32.test(String(outcome.live_content_hash || ''))
      || !HEX32.test(String(outcome.occurrence_ref || ''))
      || !['principal_state', 'occurrence_observation'].includes(outcome.target_scope)
      || !UUID.test(String(outcome.recall_event_id || ''))
      || !HEX32.test(String(outcome.recall_event_mutation_hash || ''))
      || !HEX32.test(String(outcome.recall_merkle_root || ''))
      || !HEX32.test(String(outcome.security_closure_sha256 || ''))
      || !UUID.test(String(outcome.outcome_id || ''))) {
    fail('MUTATION_OUTCOME_SCHEMA_INVALID');
  }
  if (recall.event_id !== outcome.recall_event_id
      || recall.mutation_hash !== outcome.recall_event_mutation_hash
      || recall.merkle_root !== outcome.recall_merkle_root
      || recall.security_closure_sha256 !== outcome.security_closure_sha256
      || recall.evidence?.memory_id !== outcome.memory_id
      || recall.evidence?.live_content_hash !== outcome.live_content_hash
      || recall.evidence?.occurrence_ref !== outcome.occurrence_ref) {
    fail('MUTATION_RECALL_BINDING_INVALID');
  }
  return outcome;
}

function validateOutcomeEvent(bundle, outcome) {
  const event = bundle.outcome_event;
  if (!UUID.test(String(event?.event_id || ''))
      || !HEX32.test(String(event?.mutation_hash || ''))
      || event.operation !== 'mutation_outcome_evidence_v2'
      || event.parent_event_id !== outcome.recall_event_id
      || event.metadata?.target_scope !== outcome.target_scope
      || event.metadata?.memory_id !== outcome.memory_id
      || event.metadata?.live_content_hash !== outcome.live_content_hash
      || event.metadata?.occurrence_ref !== outcome.occurrence_ref) {
    fail('MUTATION_OUTCOME_EVENT_INVALID');
  }
  return event;
}

function validateValence(bundle, outcome, outcomeEvent) {
  const valence = bundle.valence_evidence;
  const body = valence?.body_json;
  if (!HEX32.test(String(valence?.row_hash || ''))
      || ![-1, 1].includes(Number(valence?.reward_sign))
      || body?.evidence_schema !== MUTMEM_PORTABLE_MUTATION_V2.native_outcome_schema
      || body.target_scope !== outcome.target_scope
      || body.memory_id !== outcome.memory_id
      || body.target_live_content_hash !== outcome.live_content_hash
      || body.target_occurrence_ref !== outcome.occurrence_ref
      || body.recall_event_id !== outcome.recall_event_id
      || body.recall_event_mutation_hash !== outcome.recall_event_mutation_hash
      || body.recall_merkle_root !== outcome.recall_merkle_root
      || body.security_closure_sha256 !== outcome.security_closure_sha256
      || body.outcome_id !== outcome.outcome_id
      || body.outcome_event_id !== outcomeEvent.event_id
      || body.outcome_event_mutation_hash !== outcomeEvent.mutation_hash) {
    fail('MUTATION_VALENCE_BINDING_INVALID');
  }
  return valence;
}

function validateTerminal(bundle, outcome, outcomeEvent, valence) {
  const terminal = bundle.terminal;
  if (!MUTMEM_PORTABLE_MUTATION_V2.terminal_kinds.includes(terminal?.kind)) {
    fail('MUTATION_TERMINAL_KIND_INVALID');
  }
  if (terminal.kind === 'occurrence_observation') {
    if (outcome.target_scope !== 'occurrence_observation'
        || bundle.cognitive_projection !== null
        || terminal.event?.operation !== 'mutation_occurrence_observation_retained'
        || terminal.event?.parent_event_id !== outcomeEvent.event_id
        || terminal.event?.metadata?.outcome_id !== outcome.outcome_id
        || terminal.event?.metadata?.occurrence_ref !== outcome.occurrence_ref
        || terminal.event?.metadata?.projection_appended !== false) {
      fail('MUTATION_OBSERVATION_TERMINAL_INVALID');
    }
    return;
  }
  if (terminal.kind === 'signed_noop') {
    if (outcome.target_scope !== 'principal_state'
        || bundle.cognitive_projection !== null
        || terminal.event?.operation !== 'cognitive_weight_unchanged'
        || terminal.event?.metadata?.valence_row_hash !== valence.row_hash
        || terminal.event?.metadata?.projection_appended !== false) {
      fail('MUTATION_NOOP_TERMINAL_INVALID');
    }
    return;
  }
  const provenance = terminal.reweight_provenance;
  const projection = bundle.cognitive_projection;
  if (outcome.target_scope !== 'principal_state'
      || provenance?.event_type !== 'REWEIGHT'
      || provenance.memory_id !== outcome.memory_id
      || provenance.body_json?.valence_row_hash !== valence.row_hash
      || !HEX32.test(String(provenance.mutation_hash || ''))) {
    fail('MUTATION_TRANSITION_PROVENANCE_INVALID');
  }
  if (!projection || projection.memory_id !== outcome.memory_id
      || projection.provenance_mutation_hash !== provenance.mutation_hash
      || !Number.isInteger(projection.old_weight_milli)
      || !Number.isInteger(projection.new_weight_milli)
      || projection.old_weight_milli === projection.new_weight_milli
      || projection.old_weight_milli < 100 || projection.old_weight_milli > 3000
      || projection.new_weight_milli < 100 || projection.new_weight_milli > 3000
      || !HEX32.test(String(projection.projection_hash || ''))
      || !HEX32.test(String(projection.transition_hash || ''))
      || Buffer.from(String(projection.transition_signature_b64u || ''), 'base64url').length !== 64) {
    fail('MUTATION_PROJECTION_BINDING_INVALID');
  }
  const expectedProjection = cognitiveProjectionHash({
    memoryId: outcome.memory_id,
    oldWeightMilli: projection.old_weight_milli,
    newWeightMilli: projection.new_weight_milli,
    provenanceMutationHash: Buffer.from(provenance.mutation_hash, 'hex'),
    previousHash: projection.prev_projection_hash
      ? Buffer.from(projection.prev_projection_hash, 'hex') : null,
  }).toString('hex');
  if (projection.projection_hash !== expectedProjection) {
    fail('MUTATION_PROJECTION_HASH_INVALID');
  }
  const expectedTransition = cognitiveTransitionHash({
    companyId: bundle.company_id,
    memoryId: outcome.memory_id,
    oldWeight: projection.old_weight_milli / 1000,
    newWeight: projection.new_weight_milli / 1000,
    provenanceMutationHash: Buffer.from(provenance.mutation_hash, 'hex'),
  }).toString('hex');
  if (projection.transition_hash !== expectedTransition) {
    fail('MUTATION_TRANSITION_HASH_INVALID');
  }
}

export function evaluateMutMemPortableMutationBundleV2(bundle) {
  const { bundle_sha256: claimedHash, ...body } = bundle || {};
  if (bundle?.format?.schema !== MUTMEM_PORTABLE_MUTATION_V2.schema
      || claimedHash !== mutMemPortableMutationHashV2(body)) {
    fail('MUTATION_BUNDLE_COMMITMENT_INVALID');
  }
  if (exactHash(bundle.recall_evidence_sha256, 'MUTATION_RECALL_BINDING_INVALID')
      !== sha(Buffer.from(canonicalJson(bundle.recall_receipt), 'utf8'))) {
    fail('MUTATION_RECALL_BINDING_INVALID');
  }
  const outcome = validateOutcome(bundle);
  const outcomeEvent = validateOutcomeEvent(bundle, outcome);
  const valence = validateValence(bundle, outcome, outcomeEvent);
  validateTerminal(bundle, outcome, outcomeEvent, valence);
  return Object.freeze({
    schema: 'hom.aimos.mutmem-portable-mutation-result/v2',
    valid: true,
    bundle_sha256: claimedHash,
    terminal_kind: bundle.terminal.kind,
    native_outcome_schema_preserved: true,
    cryptographic_signatures_verified: false,
    next_required_owner: 'P2_INDEPENDENT_CRYPTOGRAPHIC_VERIFIER',
  });
}

export default {
  MUTMEM_PORTABLE_MUTATION_V2,
  MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
  createMutMemPortableMutationBundleV2,
  evaluateMutMemPortableMutationBundleV2,
};
