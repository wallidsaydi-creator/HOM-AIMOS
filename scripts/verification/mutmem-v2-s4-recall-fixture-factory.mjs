// Test-only producer for V2-S4B signed recall/corpus conformance evidence.
// Production and released verifiers never import this file or retain its keys.

import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  eventMutationHash,
  recallCorpusRoot,
  recallMerkleRoot,
} from '../../services/security/protocol/mutmem-protocol.js';

const RECALL_SCHEMA = 'hom.aimos.mutmem-recall-evidence/v1';
const CORPUS_SCHEMA = 'hom.aimos.mutmem-recall-corpus/v1';

function sha(value) {
  return createHash('sha256').update(value).digest();
}

function b64u(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function keys() {
  const pair = generateKeyPairSync('ed25519');
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    pubkey: b64u(pair.publicKey.export({ format: 'der', type: 'spki' })),
  };
}

function rawSign(privateKey, message) {
  return b64u(sign(null, Buffer.from(message), privateKey));
}

function certificate(privateKey, body) {
  return b64u(Buffer.from(canonicalJson({
    body,
    sig: rawSign(privateKey, canonicalJson(body)),
  }), 'utf8'));
}

function command(raw = {}) {
  const query = String(raw.query ?? raw.q ?? '').trim();
  return {
    ...raw,
    query,
    q: query,
    key: raw.key == null ? null : String(raw.key).trim(),
    memory_id: raw.memory_id == null ? null : String(raw.memory_id).trim(),
    company_id: raw.company_id == null ? 'hom' : String(raw.company_id),
    agent_id: raw.agent_id == null ? null : String(raw.agent_id),
    limit: raw.limit == null ? 10 : Number(raw.limit),
    clearance_level: raw.clearance_level == null ? null : Number(raw.clearance_level),
    max_hops: raw.max_hops == null ? null : Number(raw.max_hops),
  };
}

function clone(value) {
  return structuredClone(value);
}

export function makeRecallBundle({
  id = 'S4B-R-001',
  epistemic = false,
  memoryCount = 2,
} = {}) {
  if (!Number.isSafeInteger(memoryCount) || memoryCount < 1 || memoryCount > 16) {
    throw new Error('mutmem_v2_recall_fixture_memory_count_invalid');
  }
  const master = keys();
  const requestSigner = keys();
  const eventSigner = keys();
  const ts = 1_786_500_000;
  const requestCertBody = {
    v: 1, agent_id: 'reviewer-fixture', pubkey: requestSigner.pubkey,
    device_fp: 'synthetic-reviewer-device', valid_from: ts - 10_000,
    valid_until: ts + 10_000, issuer: 'aimos-master', issued_at: ts - 10_000,
  };
  const eventCertBody = {
    v: 1, agent_id: 'housekeeper', pubkey: eventSigner.pubkey,
    device_fp: 'synthetic-housekeeper-device', valid_from: ts - 10_000,
    valid_until: ts + 10_000, issuer: 'housekeeper', issued_at: ts - 10_000,
  };
  const requestCert = certificate(master.privateKey, requestCertBody);
  const eventCert = certificate(eventSigner.privateKey, eventCertBody);
  const masterFingerprint = sha(Buffer.from(master.pubkey, 'base64url')).toString('hex');
  const requestBody = {
    company_id: 'hom', agent_id: 'reviewer-fixture',
    q: `portable recall proof ${id}`, source_filter: `fixture:${id}`,
    memory_type_filter: 'session_exchange', limit: memoryCount, clearance_level: 10,
    cache: false, answer_shape: 'full_detail', ts_signed: ts,
  };
  const requestNonce = `request-${id}`;
  const requestSignature = rawSign(
    requestSigner.privateKey,
    `${canonicalJson(requestBody)}\nPOST\n/aimos/recall\n${requestNonce}\n${ts}`,
  );
  const memories = Array.from({ length: memoryCount }, (_, ordinal) => {
    const memoryId = ordinal === 0
      ? '11111111-1111-4111-8111-111111111111'
      : ordinal === 1
        ? '22222222-2222-4222-8222-222222222222'
        : `00000000-0000-4000-8000-${String(ordinal + 1).padStart(12, '0')}`;
    return {
      id: memoryId,
      source: requestBody.source_filter,
      memory_type: requestBody.memory_type_filter,
      provenance_proof: {
        live_content_hash: sha(`live:${id}:${ordinal}`).toString('hex'),
        save_mutation_hash: sha(`save:${id}:${ordinal}`).toString('hex'),
        binding_mutation_hash: sha(`binding:${id}:${ordinal}`).toString('hex'),
      },
    };
  });
  const evidence = memories.map((memory, ordinal) => ({
    ordinal,
    memory_id: memory.id,
    live_content_hash: memory.provenance_proof.live_content_hash,
    save_mutation_hash: memory.provenance_proof.save_mutation_hash,
    binding_mutation_hash: memory.provenance_proof.binding_mutation_hash,
    truth_state: 'current',
    raw_calibration_score: 0.75 - ordinal * 0.1,
    calibrated_score: 0.75 - ordinal * 0.1,
    calibration_event_id: null,
    calibration_mutation_hash: null,
    calibration_formula_version: null,
  }));
  const epistemicHash = sha(`epistemic:${id}`).toString('hex');
  const merkleEntries = epistemic
    ? [{ entry_type: 'epistemic_decision', decision_sha256: epistemicHash }, ...evidence]
    : evidence;
  const commandHash = sha(Buffer.from(canonicalJson(command(requestBody)), 'utf8')).toString('hex');
  const outerHash = sha(Buffer.from(canonicalJson(requestBody), 'utf8')).toString('hex');
  const merkleRoot = recallMerkleRoot(merkleEntries).toString('hex');
  const authorityMutation = sha(`authority:${id}`).toString('hex');
  const requestMutation = sha(`request-receipt:${id}`).toString('hex');
  const eventTs = ts + 1;
  const eventNonce = `event-${id}`;
  const eventPrev = sha(`event-prev:${id}`);
  const eventCertHash = sha(Buffer.from(eventCert, 'utf8')).toString('hex');
  const eventBody = {
    ledger_version: 1,
    event_id: randomUUID(),
    company_id: 'hom',
    subject_agent_id: 'reviewer-fixture',
    actor_agent_id: 'reviewer-fixture',
    actor_valid_from: new Date(requestCertBody.valid_from * 1000).toISOString(),
    signer_agent_id: 'housekeeper',
    signer_valid_from: new Date(eventCertBody.valid_from * 1000).toISOString(),
    cert_fingerprint: eventCertHash,
    identity_tier: 'T1',
    authority_kind: 'housekeeper_observation_of_verified_request',
    request_envelope_digest: sha(`request-envelope:${id}`).toString('hex'),
    operation: 'recall_receipt',
    key: commandHash,
    metadata: {
      command_hash: commandHash,
      outer_request_hash: outerHash,
      authority_mutation_hash: authorityMutation,
      request_receipt_id: randomUUID(),
      request_receipt_mutation_hash: requestMutation,
      authorization_event_id: randomUUID(),
      transport: 'rest',
      derived_tool_action_event_id: null,
      rpc_id: null,
      batch_index: null,
      result_count: evidence.length,
      merkle_root: merkleRoot,
      evidence,
      ...(epistemic ? {
        merkle_schema: 'hom-aimos/recall-merkle/v2-epistemic-decision',
        epistemic_decision_sha256: epistemicHash,
        merkle_entries: merkleEntries,
      } : {}),
      reasoning: `Housekeeper observed ${evidence.length} fail-closed provenance-verified recall result(s).`,
      source_knowledge: 'RFC 6962 domain-separated Merkle receipt; native-recall.js',
    },
    parent_event_id: null,
    ledger_seq: 1,
    prev_mutation_hash: eventPrev.toString('hex'),
    ts_signed: eventTs,
  };
  const eventContent = sha(Buffer.from(canonicalJson(eventBody), 'utf8'));
  const eventMutation = eventMutationHash(eventPrev, eventContent, eventNonce, eventTs);
  const receipt = {
    command_hash: commandHash,
    outer_request_hash: outerHash,
    authority_mutation_hash: authorityMutation,
    request_receipt_id: eventBody.metadata.request_receipt_id,
    request_receipt_mutation_hash: requestMutation,
    merkle_root: merkleRoot,
    evidence,
    ...(epistemic ? {
      merkle_schema: 'hom-aimos/recall-merkle/v2-epistemic-decision',
      epistemic_decision_sha256: epistemicHash,
      merkle_entries: merkleEntries,
    } : {}),
    event_receipt: {
      event_id: eventBody.event_id,
      proof_required: true,
      ledger_version: 1,
      ledger_seq: 1,
      signed_body: eventBody,
      content_hash: eventContent.toString('hex'),
      mutation_hash: eventMutation.toString('hex'),
      prev_mutation_hash: eventPrev.toString('hex'),
      signer_agent_id: 'housekeeper',
      signer_valid_from: eventBody.signer_valid_from,
      cert_fingerprint: eventCertHash,
      signer_certificate: eventCert,
      identity_tier: 'T1',
      ts_signed: eventTs,
      nonce: eventNonce,
      signature: rawSign(eventSigner.privateKey, `${canonicalJson(eventBody)}\n${eventNonce}\n${eventTs}`),
    },
  };
  return {
    format: {
      schema: RECALL_SCHEMA, version: 1, authority: 'descriptive_only',
      canonicalization: 'hom-aimos/canonical-json/v1', hash: 'sha256', signature: 'ed25519',
    },
    bundle_id: id,
    company_id: 'hom',
    trust_anchors: {
      master: { public_key_b64u: master.pubkey, fingerprint: masterFingerprint },
      certificates: [{
        certificate_sha256: sha(Buffer.from(eventCert, 'utf8')).toString('hex'),
        public_key_b64u: eventSigner.pubkey,
      }],
    },
    request: {
      body: requestBody, method: 'POST', path: '/aimos/recall', nonce: requestNonce,
      ts_signed: ts, signature: requestSignature, certificate: requestCert,
    },
    memories,
    recall_receipt: receipt,
  };
}

export function makeRecallCorpus(bundles) {
  const members = bundles.map((bundle, ordinal) => ({
    ordinal,
    bundle_id: bundle.bundle_id,
    bundle_sha256: sha(Buffer.from(canonicalJson(bundle), 'utf8')).toString('hex'),
    bundle,
  }));
  const summaries = members.map(({ ordinal, bundle_id, bundle_sha256 }) => ({
    ordinal, bundle_id, bundle_sha256,
  }));
  return {
    format: { schema: CORPUS_SCHEMA, version: 1, authority: 'descriptive_only' },
    intended_n: members.length,
    members,
    corpus_root: recallCorpusRoot({ intendedN: members.length, members: summaries }).toString('hex'),
  };
}

function resignEvent(bundle) {
  // This helper is intentionally unavailable: tamper fixtures must remain
  // invalid rather than possessing producer authority to rewrite evidence.
  return bundle;
}

export function createRecallVectors() {
  const basic = makeRecallBundle();
  const epistemic = makeRecallBundle({ id: 'S4B-R-002', epistemic: true });
  const vectors = [
    { id: 'S4B-CV-001', expected: 'valid', reason: null, bundle: basic },
    { id: 'S4B-CV-002', expected: 'valid', reason: null, bundle: epistemic },
  ];
  const tamper = (id, reason, mutator, source = basic, expected = 'invalid') => {
    const bundle = clone(source);
    mutator(bundle);
    vectors.push({ id, expected, reason, bundle: resignEvent(bundle) });
  };
  tamper('S4B-CV-003', 'recall_receipt_memory_binding_invalid:0', (b) => {
    b.recall_receipt.evidence[0].live_content_hash = '00'.repeat(32);
  });
  tamper('S4B-CV-004', 'recall_receipt_memory_binding_invalid:0', (b) => {
    b.recall_receipt.evidence.reverse();
  });
  tamper('S4B-CV-005', 'recall_receipt_cryptographic_binding_invalid', (b) => {
    b.recall_receipt.merkle_root = '00'.repeat(32);
  });
  tamper('S4B-CV-006', 'recall_request_signature_invalid', (b) => {
    b.request.signature = Buffer.alloc(64).toString('base64url');
  });
  tamper('S4B-CV-007', 'recall_event_signature_invalid', (b) => {
    b.recall_receipt.event_receipt.signature = Buffer.alloc(64).toString('base64url');
  });
  tamper('S4B-CV-008', 'recall_event_binding_invalid', (b) => {
    b.recall_receipt.event_receipt.mutation_hash = '00'.repeat(32);
  });
  tamper('S4B-CV-009', 'recall_receipt_memory_binding_invalid:0', (b) => {
    b.memories[0].source = 'fixture:wrong';
  });
  tamper('S4B-CV-010', 'recall_mandatory_evidence_missing', (b) => {
    delete b.recall_receipt.event_receipt;
  }, basic, 'indeterminate');
  tamper('S4B-CV-011', 'recall_receipt_epistemic_binding_invalid', (b) => {
    b.recall_receipt.merkle_entries[0].decision_sha256 = '00'.repeat(32);
  }, epistemic);
  return vectors;
}

export function createCorpusVectors() {
  const one = makeRecallBundle({ id: 'S4B-CORPUS-001' });
  const two = makeRecallBundle({ id: 'S4B-CORPUS-002', epistemic: true });
  const valid = makeRecallCorpus([one, two]);
  const vectors = [{ id: 'S4B-CV-012', expected: 'valid', reason: null, corpus: valid }];
  const tamper = (id, reason, mutator) => {
    const corpus = clone(valid);
    mutator(corpus);
    vectors.push({ id, expected: 'invalid', reason, corpus });
  };
  tamper('S4B-CV-013', 'recall_corpus_intended_n_invalid', (c) => { c.members.pop(); });
  tamper('S4B-CV-014', 'recall_corpus_member_invalid', (c) => { c.members.reverse(); });
  tamper('S4B-CV-015', 'recall_corpus_member_invalid', (c) => {
    c.members[1].bundle_id = c.members[0].bundle_id;
    c.members[1].bundle.bundle_id = c.members[0].bundle_id;
  });
  tamper('S4B-CV-016', 'recall_corpus_root_mismatch', (c) => { c.corpus_root = '00'.repeat(32); });
  tamper('S4B-CV-017', 'recall_corpus_intended_n_invalid', (c) => { c.intended_n = 3; });
  return vectors;
}
