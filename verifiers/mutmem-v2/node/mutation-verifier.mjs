// Independent MutMem V2 mutation-outcome structural and cryptographic verifier.

import {
  canonicalBytes,
  canonicalJson,
  exactBase64url,
  exactHashBytes,
  framedUtf8,
  i64,
  sha256Hex,
  uuidBytes,
  verifyEd25519,
  verifyPayloadSignature,
} from './crypto-kernel.mjs';
import { verifyRecallEnvelope } from './recall-verifier.mjs';

export const MUTATION_FAILURE_CODES = Object.freeze([
  'MUTATION_BUNDLE_COMMITMENT_INVALID', 'MUTATION_OUTCOME_SCHEMA_INVALID',
  'MUTATION_RECALL_BINDING_INVALID', 'MUTATION_OUTCOME_EVENT_INVALID',
  'MUTATION_VALENCE_BINDING_INVALID', 'MUTATION_TERMINAL_KIND_INVALID',
  'MUTATION_OBSERVATION_TERMINAL_INVALID', 'MUTATION_NOOP_TERMINAL_INVALID',
  'MUTATION_TRANSITION_PROVENANCE_INVALID', 'MUTATION_PROJECTION_BINDING_INVALID',
  'MUTATION_PROJECTION_HASH_INVALID', 'MUTATION_TRANSITION_HASH_INVALID',
]);

export const MUTATION_WITNESS_FAILURE_CODES = Object.freeze([
  'MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED',
  'MUTATION_CRYPTOGRAPHIC_WITNESS_COMMITMENT_INVALID',
  'MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID',
  'MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID',
  'MUTATION_VALENCE_SIGNATURE_INVALID',
  'MUTATION_TERMINAL_SIGNATURE_INVALID',
  'MUTATION_PROVENANCE_SIGNATURE_INVALID',
  'MUTATION_TRANSITION_SIGNATURE_INVALID',
]);

const DOMAIN = Buffer.from('hom.aimos.mutmem-portable-mutation-evidence/v2\0', 'utf8');
const TRANSITION_DOMAIN = Buffer.from('aimos.cognitive-transition/v2\0', 'utf8');
const PROJECTION_DOMAIN = Buffer.from('aimos.cwc/v1\0', 'utf8');
const WITNESS_DOMAIN = Buffer.from('hom.aimos.mutmem-portable-mutation-witness/v1\0', 'utf8');
const EVENT_LINK_DOMAIN = Buffer.from('AIMOS-EVENT-LINK-v1\0', 'utf8');
const HEX32 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TERMINALS = Object.freeze(['authorized_transition', 'signed_noop', 'occurrence_observation']);

export class MutMemMutationVerificationError extends Error {
  constructor(reason) {
    super(`mutmem_v2_mutation:${reason}`);
    this.name = 'MutMemMutationVerificationError';
    this.reason = reason;
  }
}
function fail(reason) {
  if (!MUTATION_FAILURE_CODES.includes(reason) && !MUTATION_WITNESS_FAILURE_CODES.includes(reason)) {
    throw new MutMemMutationVerificationError('UNDECLARED_FAILURE_CODE');
  }
  throw new MutMemMutationVerificationError(reason);
}
function hash(value, reason) {
  const normalized = String(value || '').toLowerCase();
  if (!HEX32.test(normalized)) fail(reason);
  return normalized;
}

export function mutationBundleHash(body) {
  return sha256Hex(Buffer.concat([DOMAIN, canonicalBytes(body)]));
}

function projectionHash(projection) {
  return sha256Hex(Buffer.concat([
    PROJECTION_DOMAIN,
    uuidBytes(projection.memory_id),
    i64(projection.old_weight_milli),
    i64(projection.new_weight_milli),
    exactHashBytes(projection.provenance_mutation_hash),
    projection.prev_projection_hash
      ? exactHashBytes(projection.prev_projection_hash) : Buffer.alloc(32),
  ]));
}

function transitionHash(companyId, projection) {
  return sha256Hex(Buffer.concat([
    TRANSITION_DOMAIN,
    framedUtf8(companyId),
    uuidBytes(projection.memory_id),
    i64(projection.old_weight_milli),
    i64(projection.new_weight_milli),
    exactHashBytes(projection.provenance_mutation_hash),
  ]));
}

function eventMutationHash(previous, content, nonce, signedTs) {
  return sha256Hex(Buffer.concat([
    EVENT_LINK_DOMAIN,
    exactHashBytes(previous),
    exactHashBytes(content),
    Buffer.from(String(nonce), 'utf8'),
    Buffer.from(String(signedTs), 'utf8'),
  ]));
}

function witnessHash(body) {
  return sha256Hex(Buffer.concat([WITNESS_DOMAIN, canonicalBytes(body)]));
}

function sameIdentity(proof, housekeeper) {
  return proof.signer_agent_id === 'housekeeper'
    && new Date(proof.signer_valid_from).toISOString()
      === new Date(housekeeper.valid_from).toISOString()
    && proof.cert_fingerprint === housekeeper.cert_fingerprint
    && proof.signer_public_key_b64u === housekeeper.public_key_b64u
    && proof.signer_certificate === housekeeper.certificate;
}

function verifyFullEvent(proof, summary, housekeeper) {
  const summaryId = summary.event_id || summary.id;
  if (!proof || proof.event_id !== summaryId || proof.operation !== summary.operation
      || proof.parent_event_id !== (summary.parent_event_id ?? null)
      || proof.mutation_hash !== summary.mutation_hash
      || canonicalJson(proof.metadata) !== canonicalJson(summary.metadata)
      || proof.proof_required !== true || proof.ledger_version !== 1
      || !sameIdentity(proof, housekeeper)) return false;
  const body = proof.signed_body;
  if (!body || body.event_id !== proof.event_id || body.company_id !== proof.company_id
      || body.subject_agent_id !== proof.subject_agent_id
      || body.signer_agent_id !== proof.signer_agent_id
      || new Date(body.signer_valid_from).toISOString()
        !== new Date(proof.signer_valid_from).toISOString()
      || body.cert_fingerprint !== proof.cert_fingerprint
      || body.identity_tier !== proof.identity_tier
      || body.authority_kind !== proof.authority_kind || body.operation !== proof.operation
      || body.key !== proof.key || canonicalJson(body.metadata) !== canonicalJson(proof.metadata)
      || body.parent_event_id !== (proof.parent_event_id ?? null)
      || Number(body.ledger_seq) !== Number(proof.ledger_seq)
      || body.prev_mutation_hash !== proof.prev_mutation_hash
      || Number(body.ts_signed) !== Number(proof.ts_signed)
      || new Date(proof.timestamp).getTime() !== Number(proof.ts_signed) * 1000) return false;
  const contentHash = sha256Hex(canonicalBytes(body));
  if (proof.content_hash !== contentHash
      || proof.mutation_hash !== eventMutationHash(
        proof.prev_mutation_hash, contentHash, proof.nonce, proof.ts_signed,
      )) return false;
  return verifyPayloadSignature({
    publicKey: housekeeper.public_key_b64u,
    body,
    nonce: proof.nonce,
    signedTs: Number(proof.ts_signed),
    signature: proof.signature_b64u,
  });
}

function verifyValenceProof(proof, summary, bundle, housekeeper) {
  if (!proof || proof.proof_required !== true || !sameIdentity(proof, housekeeper)
      || proof.row_hash !== summary.row_hash || proof.reward_sign !== summary.reward_sign
      || canonicalJson(proof.body_json) !== canonicalJson(summary.body_json)
      || proof.memory_id !== bundle.outcome_evidence.memory_id
      || proof.company_id !== bundle.company_id) return false;
  const contentHash = sha256Hex(canonicalBytes(proof.body_json));
  const rowHash = sha256Hex(Buffer.concat([
    Buffer.from(contentHash, 'hex'),
    ...(proof.prev_hash ? [Buffer.from(proof.prev_hash, 'hex')] : []),
    Buffer.from(String(proof.nonce), 'utf8'),
    Buffer.from(String(proof.ts_signed), 'utf8'),
  ]));
  if (proof.content_hash !== contentHash || proof.row_hash !== rowHash
      || proof.body_json.ts_signed !== proof.ts_signed
      || proof.body_json.cert_fingerprint !== proof.cert_fingerprint
      || proof.body_json.signer_agent_id !== proof.signer_agent_id
      || new Date(proof.body_json.signer_valid_from).toISOString()
        !== new Date(proof.signer_valid_from).toISOString()) return false;
  return verifyPayloadSignature({
    publicKey: housekeeper.public_key_b64u,
    body: proof.body_json,
    nonce: proof.nonce,
    signedTs: Number(proof.ts_signed),
    signature: proof.signature_b64u,
  });
}

function verifyProvenanceProof(proof, summary, housekeeper) {
  if (!proof || proof.provenance_id !== summary.provenance_id
      || proof.memory_id !== summary.memory_id || proof.event_type !== summary.event_type
      || proof.mutation_hash !== summary.mutation_hash
      || canonicalJson(proof.body_json) !== canonicalJson(summary.body_json)
      || proof.event_type !== 'REWEIGHT' || proof.body_json.event_type !== 'REWEIGHT'
      || proof.backfilled !== false || !sameIdentity({
        ...proof,
        signer_agent_id: proof.agent_id,
        signer_valid_from: proof.agent_valid_from,
      }, housekeeper)) return false;
  const contentHash = sha256Hex(canonicalBytes(proof.body_json));
  const pieces = [
    Buffer.from(contentHash, 'hex'),
    ...(proof.prev_mutation_hash ? [Buffer.from(proof.prev_mutation_hash, 'hex')] : []),
    Buffer.from(String(proof.nonce), 'utf8'),
    Buffer.from(String(proof.ts_signed), 'utf8'),
  ];
  if (proof.sig_form_version === 2) {
    pieces.push(Buffer.from(String(Math.floor(new Date(proof.memory_originated_at).getTime() / 1000))));
  }
  if (proof.content_hash !== contentHash || proof.mutation_hash !== sha256Hex(Buffer.concat(pieces))) {
    return false;
  }
  if (proof.sig_form_version !== 1 || proof.request_sig_form !== 1) return false;
  return verifyPayloadSignature({
    publicKey: housekeeper.public_key_b64u,
    body: proof.body_json,
    nonce: proof.nonce,
    signedTs: Number(proof.ts_signed),
    signature: proof.signature_b64u,
  });
}

function verifyWitness(bundle, witness, trustContext, expectedMasterFingerprint) {
  if (!witness || !trustContext) fail('MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED');
  const { witness_sha256: claimed, ...body } = witness;
  if (witness.format?.schema !== 'hom.aimos.mutmem-portable-mutation-witness/v1'
      || witness.format.version !== 1
      || witness.format.canonicalization !== 'hom-aimos/canonical-json/v1'
      || witness.format.hash !== 'sha256' || witness.format.signature !== 'ed25519'
      || claimed !== witnessHash(body)) fail('MUTATION_CRYPTOGRAPHIC_WITNESS_COMMITMENT_INVALID');
  const trustResult = verifyRecallEnvelope(trustContext, {
    expectedMasterFingerprint,
    verifyCryptography: true,
  });
  const housekeeper = trustContext.objects.find(
    (object) => object.kind === 'housekeeper_identity_epoch',
  )?.body;
  if (witness.mutation_bundle_sha256 !== bundle.bundle_sha256
      || witness.trust_context_bundle_sha256 !== trustResult.bundle_sha256
      || witness.expected_master_fingerprint !== expectedMasterFingerprint
      || !housekeeper) fail('MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID');
  if (!verifyFullEvent(witness.outcome_event, bundle.outcome_event, housekeeper)) {
    fail('MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID');
  }
  if (!verifyValenceProof(
    witness.valence_evidence,
    bundle.valence_evidence,
    bundle,
    housekeeper,
  )) fail('MUTATION_VALENCE_SIGNATURE_INVALID');
  let signatureCount = 2;
  if (bundle.terminal.kind === 'authorized_transition') {
    if (witness.terminal_proof?.kind !== 'reweight_provenance'
        || !verifyProvenanceProof(
          witness.terminal_proof.provenance,
          bundle.terminal.reweight_provenance,
          housekeeper,
        )) fail('MUTATION_PROVENANCE_SIGNATURE_INVALID');
    if (!verifyEd25519(
      housekeeper.public_key_b64u,
      Buffer.from(bundle.cognitive_projection.transition_hash, 'hex'),
      bundle.cognitive_projection.transition_signature_b64u,
    )) fail('MUTATION_TRANSITION_SIGNATURE_INVALID');
    signatureCount += 2;
  } else {
    if (witness.terminal_proof?.kind !== 'terminal_event'
        || !verifyFullEvent(
          witness.terminal_proof.event,
          bundle.terminal.event,
          housekeeper,
        )) fail('MUTATION_TERMINAL_SIGNATURE_INVALID');
    signatureCount += 1;
  }
  return { signatureCount, trustResult };
}

function validateOutcome(bundle) {
  const outcome = bundle.outcome_evidence;
  const recall = bundle.recall_receipt;
  if (outcome?.schema !== 'hom.aimos.mutation-outcome-evidence/v2'
      || outcome.company_id !== bundle.company_id || !UUID.test(String(outcome.memory_id || ''))
      || !HEX32.test(String(outcome.live_content_hash || ''))
      || !HEX32.test(String(outcome.occurrence_ref || ''))
      || !['principal_state', 'occurrence_observation'].includes(outcome.target_scope)
      || !UUID.test(String(outcome.recall_event_id || ''))
      || !HEX32.test(String(outcome.recall_event_mutation_hash || ''))
      || !HEX32.test(String(outcome.recall_merkle_root || ''))
      || !HEX32.test(String(outcome.security_closure_sha256 || ''))
      || !UUID.test(String(outcome.outcome_id || ''))) fail('MUTATION_OUTCOME_SCHEMA_INVALID');
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
  if (!UUID.test(String(event?.event_id || '')) || !HEX32.test(String(event?.mutation_hash || ''))
      || event.operation !== 'mutation_outcome_evidence_v2'
      || event.parent_event_id !== outcome.recall_event_id
      || event.metadata?.target_scope !== outcome.target_scope
      || event.metadata?.memory_id !== outcome.memory_id
      || event.metadata?.live_content_hash !== outcome.live_content_hash
      || event.metadata?.occurrence_ref !== outcome.occurrence_ref) fail('MUTATION_OUTCOME_EVENT_INVALID');
  return event;
}

function validateValence(bundle, outcome, outcomeEvent) {
  const valence = bundle.valence_evidence;
  const body = valence?.body_json;
  if (!HEX32.test(String(valence?.row_hash || '')) || ![-1, 1].includes(Number(valence?.reward_sign))
      || body?.evidence_schema !== 'hom.aimos.mutation-outcome-evidence/v2'
      || body.target_scope !== outcome.target_scope || body.memory_id !== outcome.memory_id
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
  if (!TERMINALS.includes(terminal?.kind)) fail('MUTATION_TERMINAL_KIND_INVALID');
  if (terminal.kind === 'occurrence_observation') {
    if (outcome.target_scope !== 'occurrence_observation' || bundle.cognitive_projection !== null
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
    if (outcome.target_scope !== 'principal_state' || bundle.cognitive_projection !== null
        || terminal.event?.operation !== 'cognitive_weight_unchanged'
        || terminal.event?.metadata?.valence_row_hash !== valence.row_hash
        || terminal.event?.metadata?.projection_appended !== false) {
      fail('MUTATION_NOOP_TERMINAL_INVALID');
    }
    return;
  }
  const provenance = terminal.reweight_provenance;
  const projection = bundle.cognitive_projection;
  if (outcome.target_scope !== 'principal_state' || provenance?.event_type !== 'REWEIGHT'
      || provenance.memory_id !== outcome.memory_id
      || provenance.body_json?.valence_row_hash !== valence.row_hash
      || !HEX32.test(String(provenance.mutation_hash || ''))) {
    fail('MUTATION_TRANSITION_PROVENANCE_INVALID');
  }
  let signatureBytes;
  try { signatureBytes = exactBase64url(projection?.transition_signature_b64u); } catch { signatureBytes = null; }
  if (!projection || projection.memory_id !== outcome.memory_id
      || projection.provenance_mutation_hash !== provenance.mutation_hash
      || !Number.isInteger(projection.old_weight_milli)
      || !Number.isInteger(projection.new_weight_milli)
      || projection.old_weight_milli === projection.new_weight_milli
      || projection.old_weight_milli < 100 || projection.old_weight_milli > 3000
      || projection.new_weight_milli < 100 || projection.new_weight_milli > 3000
      || !HEX32.test(String(projection.projection_hash || ''))
      || !HEX32.test(String(projection.transition_hash || ''))
      || signatureBytes?.length !== 64) fail('MUTATION_PROJECTION_BINDING_INVALID');
  if (projection.projection_hash !== projectionHash(projection)) fail('MUTATION_PROJECTION_HASH_INVALID');
  if (projection.transition_hash !== transitionHash(bundle.company_id, projection)) {
    fail('MUTATION_TRANSITION_HASH_INVALID');
  }
}

export function verifyMutationBundle(bundle, {
  witness = null,
  trustContext = null,
  expectedMasterFingerprint = null,
  verifyCryptography = false,
} = {}) {
  const { bundle_sha256: claimed, ...body } = bundle || {};
  if (bundle?.format?.schema !== 'hom.aimos.mutmem-portable-mutation-evidence/v2'
      || bundle.format.version !== 2
      || bundle.format.native_outcome_schema !== 'hom.aimos.mutation-outcome-evidence/v2'
      || bundle.format.canonicalization !== 'hom-aimos/canonical-json/v1'
      || bundle.format.hash !== 'sha256' || bundle.format.signature !== 'ed25519'
      || claimed !== mutationBundleHash(body)) fail('MUTATION_BUNDLE_COMMITMENT_INVALID');
  if (hash(bundle.recall_evidence_sha256, 'MUTATION_RECALL_BINDING_INVALID')
      !== sha256Hex(canonicalBytes(bundle.recall_receipt))) fail('MUTATION_RECALL_BINDING_INVALID');
  const outcome = validateOutcome(bundle);
  const outcomeEvent = validateOutcomeEvent(bundle, outcome);
  const valence = validateValence(bundle, outcome, outcomeEvent);
  validateTerminal(bundle, outcome, outcomeEvent, valence);
  const crypto = verifyCryptography
    ? verifyWitness(bundle, witness, trustContext, expectedMasterFingerprint)
    : null;
  return Object.freeze({
    schema: 'hom.aimos.mutmem-independent-mutation-result/v2',
    valid: true,
    bundle_sha256: claimed,
    terminal_kind: bundle.terminal.kind,
    native_outcome_schema_preserved: true,
    cryptographic_signatures_verified: Boolean(crypto),
    external_trust_established: Boolean(crypto),
    verified_signature_count: crypto?.signatureCount || 0,
    witness_required: true,
  });
}

export const mutationInternals = Object.freeze({ projectionHash, transitionHash });

export default { verifyMutationBundle };
