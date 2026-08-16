import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import {
  canonicalJson,
  generateKeypair,
  signPayload,
} from '../../services/security/agent-identity.js';
import { eventMutationHash } from '../../services/security/protocol/mutmem-protocol.js';
import {
  CONCEPT_EDGE_OPERATION,
  CONCEPT_EDGE_PROVENANCE_SCHEMA,
  conceptEdgeEventMetadata,
  conceptEdgeIdentityHash,
  normalizeConceptEdge,
  verifyConceptEdgeReceipt,
} from '../../services/security/concept-edge-provenance.js';

const edge = Object.freeze({
  company_id: 'hom',
  source_id: '10000000-0000-4000-8000-000000000001',
  target_id: '20000000-0000-4000-8000-000000000002',
  edge_type: 'HAS_CONCEPT',
  weight: 1,
});

function signedReceipt(boundEdge = edge) {
  const { pubkey, privkey } = generateKeypair();
  const normalized = normalizeConceptEdge(boundEdge);
  const identity = conceptEdgeIdentityHash(normalized);
  const nonce = randomBytes(16).toString('base64url');
  const tsSigned = 1_786_350_000;
  const previous = createHash('sha256').update('previous').digest();
  const body = {
    ledger_version: 1,
    event_id: randomUUID(),
    company_id: normalized.company_id,
    subject_agent_id: 'concept-graph',
    signer_agent_id: 'housekeeper',
    operation: CONCEPT_EDGE_OPERATION,
    key: identity,
    metadata: conceptEdgeEventMetadata(normalized),
    ledger_seq: 9,
    prev_mutation_hash: previous.toString('hex'),
    ts_signed: tsSigned,
  };
  const contentHash = createHash('sha256').update(canonicalJson(body)).digest();
  const mutationHash = eventMutationHash(previous, contentHash, nonce, tsSigned);
  return {
    pubkey,
    receipt: {
      proof_required: true,
      ledger_version: 1,
      signed_body: body,
      content_hash: contentHash.toString('hex'),
      mutation_hash: mutationHash.toString('hex'),
      prev_mutation_hash: previous.toString('hex'),
      ts_signed: tsSigned,
      nonce,
      signature: signPayload(privkey, body, nonce, tsSigned),
    },
  };
}

test('concept edge identity is deterministic, directional, typed, and weight-bound', () => {
  const normalized = normalizeConceptEdge(edge);
  assert.equal(normalized.schema, CONCEPT_EDGE_PROVENANCE_SCHEMA);
  assert.equal(normalized.weight_q9, '1.000000000');
  assert.equal(conceptEdgeIdentityHash(edge), conceptEdgeIdentityHash({ ...edge }));
  assert.notEqual(
    conceptEdgeIdentityHash(edge),
    conceptEdgeIdentityHash({ ...edge, source_id: edge.target_id, target_id: edge.source_id }),
  );
  assert.notEqual(conceptEdgeIdentityHash(edge), conceptEdgeIdentityHash({ ...edge, weight: 0.5 }));
});

test('concept edge normalization fails closed on malformed projections', () => {
  assert.throws(() => normalizeConceptEdge({ ...edge, source_id: 'not-a-uuid' }), /source_uuid_invalid/);
  assert.throws(() => normalizeConceptEdge({ ...edge, target_id: edge.source_id }), /self_edge_forbidden/);
  assert.throws(() => normalizeConceptEdge({ ...edge, edge_type: 'LIKES' }), /type_invalid/);
  assert.throws(() => normalizeConceptEdge({ ...edge, weight: Number.NaN }), /weight_invalid/);
  assert.throws(() => normalizeConceptEdge({ ...edge, weight: 0 }), /weight_invalid/);
});

test('portable verifier binds edge identity, event hash chain, and Ed25519 signature', () => {
  const proof = signedReceipt();
  assert.deepEqual(
    verifyConceptEdgeReceipt(edge, proof.receipt, proof.pubkey),
    {
      valid: true,
      reason: null,
      edge_identity_sha256: conceptEdgeIdentityHash(edge),
    },
  );
  assert.equal(
    verifyConceptEdgeReceipt({ ...edge, weight: 0.5 }, proof.receipt, proof.pubkey).reason,
    'concept_edge_receipt_binding',
  );
  assert.equal(
    verifyConceptEdgeReceipt(
      edge,
      { ...proof.receipt, mutation_hash: '00'.repeat(32) },
      proof.pubkey,
    ).reason,
    'concept_edge_receipt_mutation_hash',
  );
});
