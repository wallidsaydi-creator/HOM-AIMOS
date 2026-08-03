import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  canonicalJson,
  generateKeypair,
  signPayloadWithContext,
} from '../../services/security/agent-identity.js';
import {
  requestReceiptMutationHash,
  verifyRequestReceiptChain,
  verifyRequestReceiptProof,
} from '../../services/security/request-receipt-ledger.js';

function makeRow({ signer, body, previous = null, nonce, signedTs, id }) {
  const method = 'POST';
  const path = '/aimos/recall';
  const sig = Buffer.from(
    signPayloadWithContext(signer.privkey, body, method, path, nonce, signedTs),
    'base64url',
  );
  const requestHash = createHash('sha256').update(Buffer.from(canonicalJson(body), 'utf8')).digest();
  const mutationHash = requestReceiptMutationHash({
    previousMutationHash: previous,
    requestHash,
    signature: sig,
    method,
    path,
    nonce,
    signedTs,
  });
  return {
    request_receipt_id: id,
    company_id: 'hom',
    actor_agent_id: 'receipt-agent',
    actor_valid_from: '2026-07-11T00:00:00.000Z',
    request_sig_form: 3,
    signed_method: method,
    signed_path: path,
    signed_claims: null,
    signed_claims_hash: null,
    request_hash: requestHash,
    prev_mutation_hash: previous,
    mutation_hash: mutationHash,
    ts_signed: signedTs,
    nonce,
    sig,
    is_genesis: previous === null,
  };
}

test('durable request receipt proves the signed request and complete nonce chain', () => {
  const signer = generateKeypair();
  const firstBody = { query: 'first retained memory', limit: 2 };
  const first = makeRow({ signer, body: firstBody, nonce: 'receipt-1', signedTs: 1_783_764_000, id: 'r1' });
  const secondBody = { query: 'second retained memory', limit: 3 };
  const second = makeRow({
    signer,
    body: secondBody,
    previous: first.mutation_hash,
    nonce: 'receipt-2',
    signedTs: 1_783_764_001,
    id: 'r2',
  });

  assert.deepEqual(verifyRequestReceiptProof(first, { body: firstBody, pubkey: signer.pubkey }), { valid: true, reason: null });
  assert.equal(verifyRequestReceiptChain([first, second]).rowCount, 2);
  assert.equal(verifyRequestReceiptProof({ ...first, sig: Buffer.alloc(64) }, { body: firstBody, pubkey: signer.pubkey }).valid, false);
  assert.equal(verifyRequestReceiptProof(first, { body: { ...firstBody, limit: 99 }, pubkey: signer.pubkey }).valid, false);
  assert.throws(() => verifyRequestReceiptChain([second]), /request_receipt_chain_link_invalid/);
});
