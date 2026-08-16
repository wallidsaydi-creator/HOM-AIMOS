// Synthetic fixture producer for the MutMem V2-S4 clean-room verifier.
//
// This is producer-side test support, not part of the independent verifier.
// Keys are generated in memory, are purpose-bound to conformance tests, and
// are never written to an artifact. No live AIMOS identity is read or used.

import {
  createHash,
  randomUUID,
} from 'node:crypto';

import {
  canonicalJson,
  createAgentRevocationProof,
  generateKeypair,
  issueCert,
  pubkeyFingerprint,
  signPayload,
  signRaw,
} from '../../services/security/agent-identity.js';
import {
  createCognitiveWeightEvidenceBundle,
  verifyCognitiveWeightEvidenceBundle,
} from '../../services/security/protocol/cognitive-weight-evidence.js';
import {
  cognitiveBaselineHash,
  cognitiveProjectionHash,
  cognitiveTransitionHash,
  eventGenesisHash,
  eventMutationHash,
} from '../../services/security/protocol/mutmem-protocol.js';

const COMPANY = 'hom';
const VALID_FROM = 1_786_447_260;
const VALID_UNTIL = 253_402_300_799;
const SIGNED_AT = VALID_FROM + 60;
const DEVICE = 'mutmem-v2-s4-synthetic-device';

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function clone(value) {
  return structuredClone(value);
}

function flipHexByte(value) {
  const first = value.slice(0, 2) === '00' ? '01' : '00';
  return first + value.slice(2);
}

function float4Hex(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatBE(Number(value));
  return bytes.toString('hex');
}

function makeAuthority({
  issuer = 'aimos-master',
  selfSigned = false,
  validUntil = VALID_UNTIL,
} = {}) {
  const master = generateKeypair();
  const signer = generateKeypair();
  const masterFingerprint = pubkeyFingerprint(master.pubkey);
  const certificateIssuer = issuer === 'legacy-master-fingerprint'
    ? masterFingerprint
    : issuer;
  const cert = issueCert(selfSigned ? signer.privkey : master.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: DEVICE,
    valid_from: VALID_FROM,
    valid_until: validUntil,
    issuer: certificateIssuer,
    issued_at: VALID_FROM,
  });
  return {
    master,
    signer,
    masterFingerprint,
    cert,
    certFingerprint: sha256(Buffer.from(cert, 'utf8')).toString('hex'),
    identityTier: selfSigned ? 'T1_SYSTEM_SELF' : 'T1',
    validUntil,
  };
}

function sqlRecord(memoryId, {
  ok = true,
  status = 'certified_chain',
  chainLength = 1,
  signatures = chainLength,
  reason = null,
} = {}) {
  return {
    memory_id: memoryId,
    certification_status: status,
    ok,
    chain_length: chainLength,
    sigs_verified: signatures,
    reason,
  };
}

export function createDefaultBundle() {
  const authority = makeAuthority();
  const memoryId = '11111111-1111-4111-8111-111111111111';
  return createCognitiveWeightEvidenceBundle({
    companyId: COMPANY,
    masterIdentity: {
      master_pubkey: authority.master.pubkey,
      master_fingerprint: authority.masterFingerprint,
    },
    memories: [{
      id: memoryId,
      company_id: COMPANY,
      content_hash: Buffer.alloc(32, 7),
      retrieval_weight: 1,
    }],
    sqlRows: [sqlRecord(memoryId, {
      status: 'default_empty_chain',
      chainLength: 0,
      signatures: 0,
    })],
  });
}

export function createEventBundle(issuer, { selfSigned = false } = {}) {
  const authority = makeAuthority({ issuer, selfSigned });
  const validFromIso = new Date(VALID_FROM * 1000).toISOString();
  const previous = eventGenesisHash(COMPANY, 'housekeeper', validFromIso);
  const eventId = randomUUID();
  const nonce = 'mutmem-v2-s4-event';
  const body = {
    event_id: eventId,
    company_id: COMPANY,
    subject_agent_id: 'housekeeper',
    signer_agent_id: 'housekeeper',
    signer_valid_from: validFromIso,
    cert_fingerprint: authority.certFingerprint,
    identity_tier: authority.identityTier,
    authority_kind: 'system',
    operation: 'mutmem_v2_s4_conformance',
    key: 'mutmem:v2:s4',
    metadata: {},
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: previous.toString('hex'),
    ts_signed: SIGNED_AT,
  };
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = eventMutationHash(previous, contentHash, nonce, SIGNED_AT);
  return createCognitiveWeightEvidenceBundle({
    companyId: COMPANY,
    masterIdentity: {
      master_pubkey: authority.master.pubkey,
      master_fingerprint: authority.masterFingerprint,
    },
    events: [{
      id: eventId,
      company_id: COMPANY,
      agent_id: 'housekeeper',
      signer_agent_id: 'housekeeper',
      signer_valid_from: validFromIso,
      cert_fingerprint: authority.certFingerprint,
      identity_tier: authority.identityTier,
      authority_kind: body.authority_kind,
      operation: body.operation,
      key: body.key,
      metadata: body.metadata,
      parent_event_id: null,
      ledger_seq: 1,
      prev_mutation_hash: previous,
      content_hash: contentHash,
      mutation_hash: mutationHash,
      ts_signed: SIGNED_AT,
      nonce,
      sig: Buffer.from(
        signPayload(authority.signer.privkey, body, nonce, SIGNED_AT),
        'base64url',
      ),
      proof_required: true,
      ledger_version: 1,
      signed_body: body,
      pubkey: authority.signer.pubkey,
      cert: authority.cert,
      device_fp: DEVICE,
      valid_until: new Date(VALID_UNTIL * 1000).toISOString(),
    }],
  });
}

export function createSignedBaselineBundle() {
  const authority = makeAuthority();
  const memoryId = '22222222-2222-4222-8222-222222222222';
  const eventId = '22222222-2222-4222-8222-222222222223';
  const baselineId = '22222222-2222-4222-8222-222222222224';
  const validFromIso = new Date(VALID_FROM * 1000).toISOString();
  const previous = eventGenesisHash(COMPANY, 'housekeeper', validFromIso);
  const nonce = 'mutmem-v2-s4-signed-baseline-event';
  const observedWeight = Math.fround(1.234);
  const observedWeightMilli = 1234;
  const liveContentHash = Buffer.alloc(32, 2);
  const body = {
    event_id: eventId,
    company_id: COMPANY,
    subject_agent_id: 'housekeeper',
    signer_agent_id: 'housekeeper',
    signer_valid_from: validFromIso,
    cert_fingerprint: authority.certFingerprint,
    identity_tier: authority.identityTier,
    authority_kind: 'system',
    operation: 'cognitive_initial_weight_attested',
    key: memoryId,
    metadata: {
      schema: 'hom.aimos.cognitive-initial-weight/v1',
      observed_weight_float4: float4Hex(observedWeight),
      weight_milli: observedWeightMilli,
      observed_ts: SIGNED_AT,
      memory_content_hash: liveContentHash.toString('hex'),
      historical_origin_claimed: false,
      canonical_memory_mutation: false,
    },
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: previous.toString('hex'),
    ts_signed: SIGNED_AT,
  };
  const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = eventMutationHash(previous, contentHash, nonce, SIGNED_AT);
  const baselineHash = cognitiveBaselineHash({
    companyId: COMPANY,
    memoryId,
    eventId,
    eventMutationHash: mutationHash,
    liveContentHash,
    observedWeight,
    weightMilli: observedWeightMilli,
    observedTs: SIGNED_AT,
    signerValidFromIso: validFromIso,
    certFingerprint: authority.certFingerprint,
  });
  const identityFields = {
    agent_id: 'housekeeper',
    pubkey: authority.signer.pubkey,
    cert: authority.cert,
    device_fp: DEVICE,
    valid_from: validFromIso,
    valid_until: new Date(VALID_UNTIL * 1000).toISOString(),
  };
  return createCognitiveWeightEvidenceBundle({
    companyId: COMPANY,
    masterIdentity: {
      master_pubkey: authority.master.pubkey,
      master_fingerprint: authority.masterFingerprint,
    },
    memories: [{
      id: memoryId,
      company_id: COMPANY,
      content_hash: liveContentHash,
      retrieval_weight: observedWeight,
    }],
    baselines: [{
      baseline_id: baselineId,
      company_id: COMPANY,
      memory_id: memoryId,
      event_id: eventId,
      event_mutation_hash: mutationHash,
      live_content_hash: liveContentHash,
      observed_weight: observedWeight,
      retrieval_weight_milli: observedWeightMilli,
      observed_weight_float4: Buffer.from(float4Hex(observedWeight), 'hex'),
      observed_ts: SIGNED_AT,
      attestation_reason: 'retained_nondefault_weight_baseline',
      historical_origin_claimed: false,
      signer_agent_id: 'housekeeper',
      signer_valid_from: validFromIso,
      cert_fingerprint: authority.certFingerprint,
      baseline_hash: baselineHash,
      baseline_sig: signRaw(authority.signer.privkey, baselineHash),
      ...identityFields,
    }],
    events: [{
      id: eventId,
      company_id: COMPANY,
      agent_id: 'housekeeper',
      signer_agent_id: 'housekeeper',
      signer_valid_from: validFromIso,
      cert_fingerprint: authority.certFingerprint,
      identity_tier: authority.identityTier,
      authority_kind: body.authority_kind,
      operation: body.operation,
      key: body.key,
      metadata: body.metadata,
      parent_event_id: null,
      ledger_seq: 1,
      prev_mutation_hash: previous,
      content_hash: contentHash,
      mutation_hash: mutationHash,
      ts_signed: SIGNED_AT,
      nonce,
      sig: Buffer.from(
        signPayload(authority.signer.privkey, body, nonce, SIGNED_AT),
        'base64url',
      ),
      proof_required: true,
      ledger_version: 1,
      signed_body: body,
      ...identityFields,
    }],
    sqlRows: [sqlRecord(memoryId, {
      status: 'signed_initial_weight',
      chainLength: 0,
      signatures: 0,
    })],
  });
}

export function createTransitionBundle(weights = [1, 1.3], {
  revokedAt = null,
  signerValidUntil = VALID_UNTIL,
} = {}) {
  if (!Array.isArray(weights) || weights.length < 2) {
    throw new Error('mutmem_v2_s4_weight_sequence_invalid');
  }
  const authority = makeAuthority({ validUntil: signerValidUntil });
  const memoryId = '33333333-3333-4333-8333-333333333333';
  const rows = [];
  let previousMutation = null;
  let previousProjection = null;
  for (let index = 0; index < weights.length - 1; index += 1) {
    const oldWeight = weights[index];
    const newWeight = weights[index + 1];
    const signedAt = SIGNED_AT + index;
    const nonce = `mutmem-v2-s4-transition-${index}`;
    const body = {
      event_type: 'REWEIGHT',
      company_id: COMPANY,
      memory_id: memoryId,
      old_weight: oldWeight,
      new_weight: newWeight,
      judge_valence: newWeight >= oldWeight ? 0.75 : -0.75,
      governor_flag: 'S4_CONFORMANCE',
      reason: newWeight >= oldWeight ? 'signed_upward_transition' : 'signed_downward_transition',
      ts_signed: signedAt,
    };
    const contentHash = sha256(Buffer.from(canonicalJson(body), 'utf8'));
    const mutationParts = [contentHash];
    if (previousMutation) mutationParts.push(previousMutation);
    mutationParts.push(Buffer.from(nonce), Buffer.from(String(signedAt)));
    const mutationHash = sha256(Buffer.concat(mutationParts));
    const projectionHash = cognitiveProjectionHash({
      memoryId,
      oldWeightMilli: Math.round(oldWeight * 1000),
      newWeightMilli: Math.round(newWeight * 1000),
      provenanceMutationHash: mutationHash,
      previousHash: previousProjection,
    });
    const transitionHash = cognitiveTransitionHash({
      companyId: COMPANY,
      memoryId,
      oldWeight,
      newWeight,
      provenanceMutationHash: mutationHash,
    });
    rows.push({
      projection_id: `${String(index + 1).padStart(8, '0')}-0000-4000-8000-000000000003`,
      company_id: COMPANY,
      memory_id: memoryId,
      old_weight: oldWeight,
      new_weight: newWeight,
      old_weight_milli: Math.round(oldWeight * 1000),
      new_weight_milli: Math.round(newWeight * 1000),
      provenance_mutation_hash: mutationHash,
      prev_projection_hash: previousProjection,
      projection_hash: projectionHash,
      transition_hash: transitionHash,
      transition_sig: signRaw(authority.signer.privkey, transitionHash),
      provenance_id: `${String(index + 1).padStart(8, '0')}-0000-4000-8000-000000000004`,
      body_json: body,
      prov_content_hash: contentHash,
      mutation_hash: mutationHash,
      prev_mutation_hash: previousMutation,
      ts_signed: signedAt,
      nonce,
      sig: Buffer.from(
        signPayload(authority.signer.privkey, body, nonce, signedAt),
        'base64url',
      ),
      event_type: 'REWEIGHT',
      binding_schema_version: 2,
      provenance_agent_id: 'housekeeper',
      agent_valid_from: new Date(VALID_FROM * 1000),
      cert_fingerprint: authority.certFingerprint,
      identity_tier: authority.identityTier,
      sig_form_version: 1,
      request_sig_form: 1,
      signed_method: null,
      signed_path: null,
      signed_claims: null,
      is_genesis: index === 0,
      backfilled: false,
      memory_originated_at: null,
      signer_pubkey: authority.signer.pubkey,
      signer_cert: authority.cert,
      signer_valid_until: new Date(authority.validUntil * 1000),
      signer_device_fp: DEVICE,
      master_pubkey: authority.master.pubkey,
      master_fingerprint: authority.masterFingerprint,
    });
    previousMutation = mutationHash;
    previousProjection = projectionHash;
  }
  const bundle = createCognitiveWeightEvidenceBundle({
    companyId: COMPANY,
    masterIdentity: {
      master_pubkey: authority.master.pubkey,
      master_fingerprint: authority.masterFingerprint,
    },
    memories: [{
      id: memoryId,
      company_id: COMPANY,
      content_hash: Buffer.alloc(32, 3),
      retrieval_weight: weights.at(-1),
    }],
    projections: rows,
    sqlRows: [sqlRecord(memoryId, {
      chainLength: rows.length,
      signatures: rows.length,
    })],
  });
  if (revokedAt != null) {
    const validFromIso = new Date(VALID_FROM * 1000).toISOString();
    const proof = createAgentRevocationProof(authority.master.privkey, {
      agentId: 'housekeeper',
      agentValidFrom: validFromIso,
      targetCert: authority.cert,
      masterFingerprint: authority.masterFingerprint,
      reasonCode: 'mutmem_v2_conformance_revocation',
    }, {
      nowFn: () => Number(revokedAt),
      nonceFn: () => 'mutmem-v2-s5-revocation',
    });
    const revocation = {
      agent_id: 'housekeeper',
      agent_valid_from: VALID_FROM,
      master_fingerprint: authority.masterFingerprint,
      target_cert_hash: proof.targetCertHash.toString('hex'),
      prior_identity_hash: proof.priorIdentityHash.toString('hex'),
      signed_body: proof.body,
      content_hash: proof.contentHash.toString('hex'),
      mutation_hash: proof.mutationHash.toString('hex'),
      ts_signed: proof.signedTs,
      nonce: proof.nonce,
      signature: proof.sigBytes.toString('hex'),
    };
    for (const memory of bundle.memories) {
      for (const projection of memory.projections) {
        projection.provenance.identity.revocation = revocation;
      }
    }
  }
  return bundle;
}

function alignSql(bundle, { reason, chainLength = 0, signatures = 0 } = {}) {
  const record = bundle.sql_records[0];
  record.ok = false;
  record.chain_length = chainLength;
  record.signatures_verified = signatures;
  record.reason = reason;
  return bundle;
}

export function createFocusedVectors() {
  const defaultGenesis = createDefaultBundle();
  const upward = createTransitionBundle([1, 1.3]);
  const downward = createTransitionBundle([1, 1.3, 0.9]);
  const reversible = createTransitionBundle([1, 1.3, 0.9, 1.2]);

  const transitionTamper = clone(upward);
  transitionTamper.memories[0].projections[0].transition_signature = flipHexByte(
    transitionTamper.memories[0].projections[0].transition_signature,
  );
  alignSql(transitionTamper, { reason: 'transition_signature_invalid' });

  const provenanceTamper = clone(upward);
  provenanceTamper.memories[0].projections[0].provenance.content_hash = flipHexByte(
    provenanceTamper.memories[0].projections[0].provenance.content_hash,
  );
  alignSql(provenanceTamper, { reason: 'provenance_signed_body_content_hash_mismatch' });

  const terminalDivergence = clone(upward);
  terminalDivergence.memories[0].retrieval_weight_milli = 1200;
  terminalDivergence.memories[0].retrieval_weight_float4 = '3f99999a';
  alignSql(terminalDivergence, {
    reason: 'terminal_weight_mismatch',
    chainLength: 1,
    signatures: 1,
  });

  const continuity = clone(downward);
  continuity.memories[0].projections[1].old_weight_milli = 1200;
  continuity.memories[0].projections[1].old_weight_float4 = '3f99999a';
  alignSql(continuity, { reason: 'continuity_break', chainLength: 1, signatures: 1 });

  const duplicateGenesis = clone(downward);
  duplicateGenesis.memories[0].projections[1].previous_projection_hash = null;
  alignSql(duplicateGenesis, { reason: 'cognitive_projection_genesis_invalid' });

  const fork = clone(reversible);
  fork.memories[0].projections[2].previous_projection_hash =
    fork.memories[0].projections[0].projection_hash;
  alignSql(fork, { reason: 'cognitive_projection_fork' });

  const disconnected = clone(downward);
  disconnected.memories[0].projections[1].previous_projection_hash = 'ab'.repeat(32);
  alignSql(disconnected, { reason: 'cognitive_projection_disconnected' });

  const schema = clone(defaultGenesis);
  schema.format.version = 2;

  const unknownField = clone(defaultGenesis);
  unknownField.critical_extension = true;

  const masterMismatch = createEventBundle('aimos-master');
  masterMismatch.master_identity.fingerprint = '00'.repeat(32);

  return [
    { id: 'S4-CV-001', expected: 'valid', reason: null, bundle: defaultGenesis },
    { id: 'S4-CV-002', expected: 'valid', reason: null, bundle: createEventBundle('housekeeper', { selfSigned: true }) },
    { id: 'S4-CV-003', expected: 'valid', reason: null, bundle: createEventBundle('aimos-master') },
    { id: 'S4-CV-004', expected: 'valid', reason: null, bundle: createEventBundle('legacy-master-fingerprint') },
    { id: 'S4-CV-005', expected: 'valid', reason: null, bundle: upward },
    { id: 'S4-CV-006', expected: 'valid', reason: null, bundle: downward },
    { id: 'S4-CV-007', expected: 'valid', reason: null, bundle: reversible },
    { id: 'S4-CV-008', expected: 'invalid', reason: 'transition_signature_invalid', bundle: transitionTamper },
    { id: 'S4-CV-009', expected: 'invalid', reason: 'provenance_signed_body_content_hash_mismatch', bundle: provenanceTamper },
    { id: 'S4-CV-010', expected: 'invalid', reason: 'terminal_weight_mismatch', bundle: terminalDivergence },
    { id: 'S4-CV-011', expected: 'invalid', reason: 'continuity_break', bundle: continuity },
    { id: 'S4-CV-012', expected: 'invalid', reason: 'cognitive_projection_genesis_invalid', bundle: duplicateGenesis },
    { id: 'S4-CV-013', expected: 'invalid', reason: 'cognitive_projection_fork', bundle: fork },
    { id: 'S4-CV-014', expected: 'invalid', reason: 'cognitive_projection_disconnected', bundle: disconnected },
    { id: 'S4-CV-015', expected: 'invalid', reason: 'cognitive_evidence_bundle_schema_invalid', bundle: schema },
    { id: 'S4-CV-016', expected: 'invalid', reason: 'cognitive_evidence_bundle_schema_invalid', bundle: unknownField },
    { id: 'S4-CV-017', expected: 'invalid', reason: 'cognitive_evidence_master_fingerprint_mismatch', bundle: masterMismatch },
    { id: 'S4-CV-018', expected: 'invalid', reason: 'cognitive_evidence_event_identity_epoch_invalid', bundle: createEventBundle('unexpected-root') },
  ];
}

export function nodeVerdict(bundle) {
  try {
    const proof = verifyCognitiveWeightEvidenceBundle(bundle);
    const valid = proof.parity
      && proof.records.every((record) => record.ok)
      && proof.eventStreamResults.every((stream) => stream.valid);
    const reason = !proof.eventStreamResults.every((stream) => stream.valid)
      ? proof.eventStreamResults.find((stream) => !stream.valid)?.reason
      : !proof.records.every((record) => record.ok)
        ? proof.records.find((record) => !record.ok)?.reason
        : !proof.parity
          ? 'sql_portable_parity_mismatch'
          : null;
    return { verdict: valid ? 'valid' : 'invalid', reason, proof };
  } catch (error) {
    return {
      verdict: 'invalid',
      reason: error instanceof Error ? error.message : 'verifier_internal_failure',
      proof: null,
    };
  }
}

export const MUTMEM_V2_S4_FIXTURE_CONSTANTS = Object.freeze({
  COMPANY,
  VALID_FROM,
  VALID_UNTIL,
  SIGNED_AT,
  DEVICE,
});
