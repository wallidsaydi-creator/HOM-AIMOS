// Deterministic test-only cryptographic vectors for the independent P2 verifiers.
// The fixed seeds below are public fixture material, never production secrets.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  cognitiveProjectionHash,
  cognitiveTransitionHash,
  eventMutationHash,
  recallMerkleRoot,
} from '../../services/security/protocol/mutmem-protocol.js';
import {
  computeOccurrenceCommitmentV3,
  occurrenceSignatureMessageV3,
} from '../../services/security/protocol/content-state-occurrence-v3.js';
import {
  createMutMemPortableEvidenceEnvelopeV2,
  createMutMemPortableObjectV2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  recallAuthorizationMutationHashV1,
  requestReceiptMutationHashV1,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import { mutMemPortableMutationHashV2 }
  from '../../services/security/protocol/mutmem-portable-mutation-v2.js';
import { baseMutMemPortablePredicateBodies }
  from './mutmem-portable-predicate-fixture-factory.mjs';
import { createMutMemPortableMutationVectorsV2 }
  from './mutmem-portable-mutation-fixture-factory.mjs';

const sha = (value) => createHash('sha256').update(value).digest();
const shaHex = (value) => sha(value).toString('hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const INVALID_SIGNATURE = Buffer.alloc(64, 0xa5).toString('base64url');
const WITNESS_DOMAIN = Buffer.from('hom.aimos.mutmem-portable-mutation-witness/v1\0', 'utf8');
const SINGLETONS = [
  'trust_anchor', 'actor_identity_epoch', 'actor_revocation_state',
  'housekeeper_identity_epoch', 'housekeeper_revocation_state',
  'effective_recall_grant', 'request_envelope', 'request_receipt',
  'content_state_projection', 'epistemic_recall_decision',
  'final_security_closure', 'return_projection', 'native_recall_receipt',
];
const RESULTS = [
  'memory_state', 'provenance_chain', 'occurrence',
  'epistemic_projection', 'receipt_evidence',
];

function testKey(label) {
  const seed = sha(Buffer.from(`HOM-AIMOS-P2-PUBLIC-TEST-KEY:${label}`, 'utf8'));
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return Object.freeze({
    privateKey,
    publicKeyB64u: publicDer.toString('base64url'),
    fingerprint: shaHex(publicDer),
  });
}

const KEYS = Object.freeze({
  master: testKey('master'),
  actor: testKey('actor'),
  housekeeper: testKey('housekeeper'),
});

function payloadMessage(body, nonce, signedTs) {
  return Buffer.from(`${canonicalJson(body)}\n${nonce}\n${signedTs}`, 'utf8');
}
function contextMessage(body, method, signedPath, nonce, signedTs) {
  return Buffer.from(
    `${canonicalJson(body)}\n${String(method).toUpperCase()}\n${String(signedPath).split('?')[0]}`
      + `\n${nonce}\n${signedTs}`,
    'utf8',
  );
}
function signPayload(key, body, nonce, signedTs) {
  return sign(null, payloadMessage(body, nonce, signedTs), key.privateKey).toString('base64url');
}
function signContext(key, body, method, signedPath, nonce, signedTs) {
  return sign(
    null,
    contextMessage(body, method, signedPath, nonce, signedTs),
    key.privateKey,
  ).toString('base64url');
}
function issueCertificate(key, agentId, validFrom, validUntil) {
  const body = {
    v: 1,
    agent_id: agentId,
    pubkey: key.publicKeyB64u,
    device_fp: `p2-public-test-device-${agentId}`,
    valid_from: validFrom,
    valid_until: validUntil,
    issuer: 'aimos-master',
    issued_at: validFrom,
  };
  const envelope = {
    body,
    sig: sign(null, Buffer.from(canonicalJson(body)), KEYS.master.privateKey).toString('base64url'),
  };
  return Buffer.from(canonicalJson(envelope)).toString('base64url');
}
function corruptCertificate(certificate) {
  const envelope = JSON.parse(Buffer.from(certificate, 'base64url').toString('utf8'));
  envelope.sig = INVALID_SIGNATURE;
  return Buffer.from(canonicalJson(envelope)).toString('base64url');
}

function rebuildEnvelope(bodies, bundleId = 'P2-CRYPTO-RECALL-VALID') {
  const memoryId = bodies.memory_state.memory_id;
  const objects = [
    ...SINGLETONS.map((kind) => createMutMemPortableObjectV2({
      kind,
      schema: bodies[kind].schema,
      body: bodies[kind],
    })),
    ...RESULTS.map((kind) => createMutMemPortableObjectV2({
      kind,
      schema: bodies[kind].schema,
      subjectId: memoryId,
      resultOrdinal: 0,
      body: bodies[kind],
    })),
  ];
  return createMutMemPortableEvidenceEnvelopeV2({
    bundleId,
    companyId: 'hom',
    expectedMasterFingerprint: KEYS.master.fingerprint,
    resultCount: 1,
    objects,
  });
}

function refreshEvent(bodies) {
  const event = bodies.native_recall_receipt.event_receipt;
  event.signed_body.cert_fingerprint = bodies.housekeeper_identity_epoch.cert_fingerprint;
  event.signed_body.metadata = {
    ...event.signed_body.metadata,
    command_hash: bodies.native_recall_receipt.command_hash,
    outer_request_hash: bodies.native_recall_receipt.outer_request_hash,
    authority_mutation_hash: bodies.native_recall_receipt.authority_mutation_hash,
    request_receipt_id: bodies.native_recall_receipt.request_receipt_id,
    request_receipt_mutation_hash: bodies.native_recall_receipt.request_receipt_mutation_hash,
    merkle_root: bodies.native_recall_receipt.merkle_root,
    result_count: bodies.native_recall_receipt.result_count,
    evidence: bodies.native_recall_receipt.evidence,
    return_projection: bodies.native_recall_receipt.return_projection,
  };
  event.signer_certificate = bodies.housekeeper_identity_epoch.certificate;
  event.content_hash = shaHex(Buffer.from(canonicalJson(event.signed_body)));
  event.mutation_hash = eventMutationHash(
    Buffer.from(event.prev_mutation_hash, 'hex'),
    Buffer.from(event.content_hash, 'hex'),
    event.nonce,
    event.ts_signed,
  ).toString('hex');
  event.signature_b64u = signPayload(
    KEYS.housekeeper,
    event.signed_body,
    event.nonce,
    event.ts_signed,
  );
  bodies.actor_revocation_state.source_event_mutation_hash = event.mutation_hash;
  bodies.housekeeper_revocation_state.source_event_mutation_hash = event.mutation_hash;
}

function refreshOccurrence(bodies) {
  const occurrence = bodies.occurrence;
  occurrence.native_body.cert_fingerprint_hex = bodies.housekeeper_identity_epoch.cert_fingerprint;
  delete occurrence.native_body.occurrence_commitment;
  const commitment = computeOccurrenceCommitmentV3(occurrence.native_body);
  occurrence.native_body.occurrence_commitment = commitment;
  occurrence.occurrence_ref = commitment;
  occurrence.signer_certificate = bodies.housekeeper_identity_epoch.certificate;
  occurrence.signature_b64u = sign(
    null,
    occurrenceSignatureMessageV3(commitment),
    KEYS.housekeeper.privateKey,
  ).toString('base64url');
  bodies.receipt_evidence.occurrence_ref = commitment;
  bodies.content_state_projection.selected_occurrence_refs = [commitment];
  bodies.native_recall_receipt.evidence[0].occurrence_ref = commitment;
  bodies.native_recall_receipt.merkle_entries = [
    { entry_type: 'epistemic_decision', decision_sha256: bodies.epistemic_recall_decision.decision_sha256 },
    { entry_type: 'canary_final_security_closure', decision_sha256: bodies.final_security_closure.decision_sha256 },
    bodies.native_recall_receipt.evidence[0],
  ];
  bodies.native_recall_receipt.merkle_root = recallMerkleRoot(
    bodies.native_recall_receipt.merkle_entries,
  ).toString('hex');
}

function upgradeRecallBodies() {
  const bodies = structuredClone(baseMutMemPortablePredicateBodies());
  const validFrom = Math.floor(new Date(bodies.actor_identity_epoch.valid_from).getTime() / 1000);
  const actorUntil = Math.floor(new Date(bodies.actor_identity_epoch.valid_until).getTime() / 1000);
  const hkUntil = Math.floor(new Date(bodies.housekeeper_identity_epoch.valid_until).getTime() / 1000);
  const actorCertificate = issueCertificate(KEYS.actor, 'codex-auditor', validFrom, actorUntil);
  const hkCertificate = issueCertificate(KEYS.housekeeper, 'housekeeper', validFrom, hkUntil);
  Object.assign(bodies.trust_anchor, {
    master_fingerprint: KEYS.master.fingerprint,
    master_public_key_b64u: KEYS.master.publicKeyB64u,
  });
  Object.assign(bodies.actor_identity_epoch, {
    certificate: actorCertificate,
    public_key_b64u: KEYS.actor.publicKeyB64u,
    cert_fingerprint: shaHex(Buffer.from(actorCertificate)),
  });
  Object.assign(bodies.housekeeper_identity_epoch, {
    certificate: hkCertificate,
    public_key_b64u: KEYS.housekeeper.publicKeyB64u,
    cert_fingerprint: shaHex(Buffer.from(hkCertificate)),
  });
  const grant = bodies.effective_recall_grant;
  grant.master_fingerprint = KEYS.master.fingerprint;
  grant.signed_body.master_fingerprint = KEYS.master.fingerprint;
  grant.content_hash = shaHex(Buffer.from(canonicalJson(grant.signed_body)));
  grant.mutation_hash = recallAuthorizationMutationHashV1({
    previousMutationHash: grant.prev_mutation_hash,
    contentHash: grant.content_hash,
    nonce: grant.nonce,
    signedTs: grant.ts_signed,
  });
  grant.signature_b64u = signPayload(
    KEYS.master,
    grant.signed_body,
    grant.nonce,
    grant.ts_signed,
  );
  const request = bodies.request_envelope;
  request.cert_fingerprint = bodies.actor_identity_epoch.cert_fingerprint;
  request.signature_b64u = signContext(
    KEYS.actor,
    request.request_body,
    request.signed_method,
    request.signed_path,
    request.nonce,
    request.ts_signed,
  );
  const receipt = bodies.request_receipt;
  receipt.cert_fingerprint = request.cert_fingerprint;
  receipt.signature_b64u = request.signature_b64u;
  receipt.mutation_hash = requestReceiptMutationHashV1({
    previousMutationHash: receipt.prev_mutation_hash,
    requestHash: receipt.request_hash,
    claimsHash: receipt.signed_claims_hash,
    signature: receipt.signature_b64u,
    method: receipt.signed_method,
    path: receipt.signed_path,
    nonce: receipt.nonce,
    signedTs: receipt.ts_signed,
  });
  bodies.native_recall_receipt.authority_mutation_hash = grant.mutation_hash;
  bodies.native_recall_receipt.request_receipt_mutation_hash = receipt.mutation_hash;
  refreshOccurrence(bodies);
  refreshEvent(bodies);
  return bodies;
}

function rehashRequestSignatureAttack(bodies) {
  bodies.request_envelope.signature_b64u = INVALID_SIGNATURE;
  bodies.request_receipt.signature_b64u = INVALID_SIGNATURE;
  const receipt = bodies.request_receipt;
  receipt.mutation_hash = requestReceiptMutationHashV1({
    previousMutationHash: receipt.prev_mutation_hash,
    requestHash: receipt.request_hash,
    claimsHash: receipt.signed_claims_hash,
    signature: receipt.signature_b64u,
    method: receipt.signed_method,
    path: receipt.signed_path,
    nonce: receipt.nonce,
    signedTs: receipt.ts_signed,
  });
  bodies.native_recall_receipt.request_receipt_mutation_hash = receipt.mutation_hash;
  refreshEvent(bodies);
}

export function createP2RecallCryptographicVectors() {
  const validBodies = upgradeRecallBodies();
  const definitions = [
    ['EXPECTED_TRUST_ANCHOR_REQUIRED', (b) => b, shaHex('wrong-master')],
    ['ACTOR_CERTIFICATE_SIGNATURE_INVALID', (b) => {
      const cert = corruptCertificate(b.actor_identity_epoch.certificate);
      const fingerprint = shaHex(Buffer.from(cert));
      b.actor_identity_epoch.certificate = cert;
      b.actor_identity_epoch.cert_fingerprint = fingerprint;
      b.request_envelope.cert_fingerprint = fingerprint;
      b.request_receipt.cert_fingerprint = fingerprint;
    }],
    ['MASTER_GRANT_SIGNATURE_INVALID', (b) => { b.effective_recall_grant.signature_b64u = INVALID_SIGNATURE; }],
    ['ACTOR_REQUEST_SIGNATURE_INVALID', rehashRequestSignatureAttack],
    ['HOUSEKEEPER_CERTIFICATE_SIGNATURE_INVALID', (b) => {
      const cert = corruptCertificate(b.housekeeper_identity_epoch.certificate);
      b.housekeeper_identity_epoch.certificate = cert;
      b.housekeeper_identity_epoch.cert_fingerprint = shaHex(Buffer.from(cert));
      refreshOccurrence(b);
      refreshEvent(b);
    }],
    ['HOUSEKEEPER_EVENT_SIGNATURE_INVALID', (b) => {
      b.native_recall_receipt.event_receipt.signature_b64u = INVALID_SIGNATURE;
    }],
    ['HOUSEKEEPER_OCCURRENCE_SIGNATURE_INVALID', (b) => { b.occurrence.signature_b64u = INVALID_SIGNATURE; }],
  ];
  const vectors = [{
    id: 'P2-CRYPTO-RECALL-VALID',
    expected: 'valid',
    reason: null,
    expected_master_fingerprint: KEYS.master.fingerprint,
    bundle: rebuildEnvelope(structuredClone(validBodies)),
  }];
  definitions.forEach(([reason, mutate, expected = KEYS.master.fingerprint], index) => {
    const bodies = structuredClone(validBodies);
    mutate(bodies);
    vectors.push({
      id: `P2-CRYPTO-RECALL-${String(index + 1).padStart(3, '0')}`,
      expected: 'invalid',
      reason,
      expected_master_fingerprint: expected,
      bundle: rebuildEnvelope(bodies, `P2-CRYPTO-RECALL-${String(index + 1).padStart(3, '0')}`),
    });
  });
  return Object.freeze(vectors);
}

export const P2_TEST_KEYS = Object.freeze({
  master_fingerprint: KEYS.master.fingerprint,
  master_public_key_b64u: KEYS.master.publicKeyB64u,
  housekeeper_public_key_b64u: KEYS.housekeeper.publicKeyB64u,
});

function deterministicUuid(label) {
  const bytes = sha(Buffer.from(`HOM-AIMOS-P2-UUID:${label}`));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function fullEventProof(summary, { label, ledgerSeq, tsSigned, memoryId }) {
  const eventId = summary.event_id || summary.id || deterministicUuid(`${label}:event`);
  summary.event_id = eventId;
  const previous = shaHex(Buffer.from(`${label}:previous-event`));
  const hk = upgradeRecallBodies().housekeeper_identity_epoch;
  const signedBody = {
    event_id: eventId,
    company_id: 'hom',
    subject_agent_id: 'housekeeper',
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    cert_fingerprint: hk.cert_fingerprint,
    identity_tier: 'T1',
    authority_kind: 'housekeeper_system_principal',
    operation: summary.operation,
    key: memoryId,
    metadata: summary.metadata,
    parent_event_id: summary.parent_event_id ?? null,
    ledger_seq: ledgerSeq,
    prev_mutation_hash: previous,
    ts_signed: tsSigned,
  };
  const contentHash = shaHex(Buffer.from(canonicalJson(signedBody)));
  const mutationHash = eventMutationHash(
    Buffer.from(previous, 'hex'),
    Buffer.from(contentHash, 'hex'),
    `${label}-nonce`,
    tsSigned,
  ).toString('hex');
  summary.mutation_hash = mutationHash;
  return {
    event_id: eventId,
    timestamp: new Date(tsSigned * 1000).toISOString(),
    company_id: 'hom',
    subject_agent_id: 'housekeeper',
    operation: summary.operation,
    key: memoryId,
    metadata: summary.metadata,
    parent_event_id: summary.parent_event_id ?? null,
    proof_required: true,
    ledger_version: 1,
    ledger_seq: ledgerSeq,
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    signer_valid_until: hk.valid_until,
    cert_fingerprint: hk.cert_fingerprint,
    identity_tier: 'T1',
    authority_kind: 'housekeeper_system_principal',
    signed_body: signedBody,
    content_hash: contentHash,
    mutation_hash: mutationHash,
    prev_mutation_hash: previous,
    ts_signed: tsSigned,
    nonce: `${label}-nonce`,
    signature_b64u: signPayload(KEYS.housekeeper, signedBody, `${label}-nonce`, tsSigned),
    signer_public_key_b64u: hk.public_key_b64u,
    signer_certificate: hk.certificate,
  };
}

function fullValenceProof(bundle, label, tsSigned) {
  const hk = upgradeRecallBodies().housekeeper_identity_epoch;
  const body = {
    ...bundle.valence_evidence.body_json,
    event_type: 'VALENCE',
    company_id: 'hom',
    reward_sign: bundle.valence_evidence.reward_sign,
    context_hash: null,
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    cert_fingerprint: hk.cert_fingerprint,
    identity_tier: 'T1',
    ts_signed: tsSigned,
  };
  bundle.valence_evidence.body_json = body;
  const contentHash = shaHex(Buffer.from(canonicalJson(body)));
  const nonce = `${label}-valence-nonce`;
  const rowHash = shaHex(Buffer.concat([
    Buffer.from(contentHash, 'hex'),
    Buffer.from(nonce),
    Buffer.from(String(tsSigned)),
  ]));
  Object.assign(bundle.valence_evidence, {
    row_hash: rowHash,
    signature_b64u: signPayload(KEYS.housekeeper, body, nonce, tsSigned),
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    cert_fingerprint: hk.cert_fingerprint,
  });
  return {
    row_id: String(tsSigned),
    memory_id: bundle.outcome_evidence.memory_id,
    company_id: 'hom',
    reward_sign: bundle.valence_evidence.reward_sign,
    context_hash: null,
    body_json: body,
    content_hash: contentHash,
    prev_hash: null,
    row_hash: rowHash,
    ts_signed: tsSigned,
    nonce,
    signature_b64u: bundle.valence_evidence.signature_b64u,
    proof_required: true,
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    signer_valid_until: hk.valid_until,
    cert_fingerprint: hk.cert_fingerprint,
    identity_tier: 'T1',
    signer_public_key_b64u: hk.public_key_b64u,
    signer_certificate: hk.certificate,
  };
}

function fullProvenanceProof(bundle, label, tsSigned) {
  const hk = upgradeRecallBodies().housekeeper_identity_epoch;
  const summary = bundle.terminal.reweight_provenance;
  summary.provenance_id = deterministicUuid(`${label}:provenance`);
  summary.body_json = {
    ...summary.body_json,
    valence_row_hash: bundle.valence_evidence.row_hash,
    event_type: 'REWEIGHT',
    company_id: 'hom',
    memory_id: summary.memory_id,
    signer_agent_id: 'housekeeper',
    signer_valid_from: hk.valid_from,
    cert_fingerprint: hk.cert_fingerprint,
  };
  const contentHash = shaHex(Buffer.from(canonicalJson(summary.body_json)));
  const previous = shaHex(Buffer.from(`${label}:previous-provenance`));
  const nonce = `${label}-provenance-nonce`;
  const mutationHash = shaHex(Buffer.concat([
    Buffer.from(contentHash, 'hex'), Buffer.from(previous, 'hex'),
    Buffer.from(nonce), Buffer.from(String(tsSigned)),
  ]));
  summary.mutation_hash = mutationHash;
  const projection = bundle.cognitive_projection;
  projection.provenance_mutation_hash = mutationHash;
  projection.projection_hash = cognitiveProjectionHash({
    memoryId: projection.memory_id,
    oldWeightMilli: projection.old_weight_milli,
    newWeightMilli: projection.new_weight_milli,
    provenanceMutationHash: Buffer.from(mutationHash, 'hex'),
    previousHash: projection.prev_projection_hash
      ? Buffer.from(projection.prev_projection_hash, 'hex') : null,
  }).toString('hex');
  projection.transition_hash = cognitiveTransitionHash({
    companyId: 'hom',
    memoryId: projection.memory_id,
    oldWeight: projection.old_weight_milli / 1000,
    newWeight: projection.new_weight_milli / 1000,
    provenanceMutationHash: Buffer.from(mutationHash, 'hex'),
  }).toString('hex');
  projection.transition_signature_b64u = sign(
    null,
    Buffer.from(projection.transition_hash, 'hex'),
    KEYS.housekeeper.privateKey,
  ).toString('base64url');
  return {
    provenance_id: summary.provenance_id,
    memory_id: summary.memory_id,
    agent_id: 'housekeeper',
    agent_valid_from: hk.valid_from,
    agent_valid_until: hk.valid_until,
    cert_fingerprint: hk.cert_fingerprint,
    content_hash: contentHash,
    mutation_hash: mutationHash,
    prev_mutation_hash: previous,
    ts_signed: tsSigned,
    nonce,
    signature_b64u: signPayload(KEYS.housekeeper, summary.body_json, nonce, tsSigned),
    identity_tier: 'T1',
    is_genesis: false,
    backfilled: false,
    memory_originated_at: null,
    event_type: 'REWEIGHT',
    body_json: summary.body_json,
    sig_form_version: 1,
    request_sig_form: 1,
    signed_method: null,
    signed_path: null,
    signed_claims: null,
    signer_public_key_b64u: hk.public_key_b64u,
    signer_certificate: hk.certificate,
  };
}

function mutationWitnessHash(body) {
  return shaHex(Buffer.concat([WITNESS_DOMAIN, Buffer.from(canonicalJson(body))]));
}
function refreshMutationBundleHash(bundle) {
  const { bundle_sha256: _, ...body } = bundle;
  bundle.bundle_sha256 = mutMemPortableMutationHashV2(body);
}

function buildMutationCryptoEntry(source, ordinal, trustContext) {
  const bundle = structuredClone(source.bundle);
  const label = `p2-${bundle.terminal.kind}`;
  const baseTs = 1_788_100_000 + ordinal * 100;
  const outcomeEvent = fullEventProof(bundle.outcome_event, {
    label: `${label}-outcome`, ledgerSeq: 100 + ordinal * 3,
    tsSigned: baseTs, memoryId: bundle.outcome_evidence.memory_id,
  });
  bundle.valence_evidence.body_json.outcome_event_mutation_hash = outcomeEvent.mutation_hash;
  const valence = fullValenceProof(bundle, label, baseTs + 1);
  if (bundle.terminal.kind === 'signed_noop') {
    bundle.terminal.event.metadata.valence_row_hash = bundle.valence_evidence.row_hash;
  }
  let terminalProof;
  if (bundle.terminal.kind === 'authorized_transition') {
    terminalProof = {
      kind: 'reweight_provenance',
      provenance: fullProvenanceProof(bundle, label, baseTs + 2),
    };
  } else {
    const terminalEvent = fullEventProof(bundle.terminal.event, {
      label: `${label}-terminal`, ledgerSeq: 102 + ordinal * 3,
      tsSigned: baseTs + 2, memoryId: bundle.outcome_evidence.memory_id,
    });
    terminalProof = { kind: 'terminal_event', event: terminalEvent };
  }
  refreshMutationBundleHash(bundle);
  const body = {
    format: {
      schema: 'hom.aimos.mutmem-portable-mutation-witness/v1',
      version: 1,
      canonicalization: 'hom-aimos/canonical-json/v1',
      hash: 'sha256',
      signature: 'ed25519',
    },
    mutation_bundle_sha256: bundle.bundle_sha256,
    trust_context_bundle_sha256: trustContext.bundle_sha256,
    expected_master_fingerprint: KEYS.master.fingerprint,
    outcome_event: outcomeEvent,
    valence_evidence: valence,
    terminal_proof: terminalProof,
  };
  return {
    bundle,
    witness: { ...body, witness_sha256: mutationWitnessHash(body) },
    trust_context: trustContext,
    expected_master_fingerprint: KEYS.master.fingerprint,
  };
}

function rehashWitness(witness) {
  const { witness_sha256: _, ...body } = witness;
  witness.witness_sha256 = mutationWitnessHash(body);
}

export function createP2MutationCryptographicVectors() {
  const trustContext = createP2RecallCryptographicVectors()[0].bundle;
  const sources = createMutMemPortableMutationVectorsV2().filter((vector) => vector.expected === 'valid');
  const valid = sources.map((source, ordinal) => buildMutationCryptoEntry(source, ordinal, trustContext));
  const vectors = valid.map((entry) => ({
    id: `P2-CRYPTO-MUTATION-VALID-${entry.bundle.terminal.kind}`,
    expected: 'valid', reason: null, ...entry,
  }));
  const attacks = [
    ['MUTATION_CRYPTOGRAPHIC_WITNESS_COMMITMENT_INVALID', 0, (entry) => {
      entry.witness.witness_sha256 = shaHex('wrong-witness');
    }],
    ['MUTATION_CRYPTOGRAPHIC_WITNESS_SCOPE_INVALID', 0, (entry) => {
      entry.witness.mutation_bundle_sha256 = shaHex('wrong-scope'); rehashWitness(entry.witness);
    }],
    ['MUTATION_OUTCOME_EVENT_SIGNATURE_INVALID', 0, (entry) => {
      entry.witness.outcome_event.signature_b64u = INVALID_SIGNATURE; rehashWitness(entry.witness);
    }],
    ['MUTATION_VALENCE_SIGNATURE_INVALID', 0, (entry) => {
      entry.witness.valence_evidence.signature_b64u = INVALID_SIGNATURE; rehashWitness(entry.witness);
    }],
    ['MUTATION_PROVENANCE_SIGNATURE_INVALID', 0, (entry) => {
      entry.witness.terminal_proof.provenance.signature_b64u = INVALID_SIGNATURE;
      rehashWitness(entry.witness);
    }],
    ['MUTATION_TRANSITION_SIGNATURE_INVALID', 0, (entry) => {
      entry.bundle.cognitive_projection.transition_signature_b64u = INVALID_SIGNATURE;
      refreshMutationBundleHash(entry.bundle);
      entry.witness.mutation_bundle_sha256 = entry.bundle.bundle_sha256;
      rehashWitness(entry.witness);
    }],
    ['MUTATION_TERMINAL_SIGNATURE_INVALID', 1, (entry) => {
      entry.witness.terminal_proof.event.signature_b64u = INVALID_SIGNATURE; rehashWitness(entry.witness);
    }],
  ];
  attacks.forEach(([reason, sourceIndex, mutate], index) => {
    const entry = structuredClone(valid[sourceIndex]);
    mutate(entry);
    vectors.push({
      id: `P2-CRYPTO-MUTATION-${String(index + 1).padStart(3, '0')}`,
      expected: 'invalid', reason, ...entry,
    });
  });
  return Object.freeze(vectors);
}
