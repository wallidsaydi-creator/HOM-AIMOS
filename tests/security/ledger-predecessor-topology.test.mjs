import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  orderCredentialLifecycleRows,
} from '../../services/security/credential-ledger.js';
import {
  orderRequestReceiptRows,
  requestReceiptMutationHash,
  verifyRequestReceiptChain,
} from '../../services/security/request-receipt-ledger.js';

function hash(byte) {
  return Buffer.alloc(32, byte);
}

test('credential lifecycle chronology follows predecessor topology, not clock or UUID order', () => {
  const genesis = {
    provenance_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    mutation_hash: hash(1),
    prev_mutation_hash: null,
    created_at: '2030-01-01T00:00:00.000Z',
  };
  const middle = {
    provenance_id: '88888888-8888-4888-8888-888888888888',
    mutation_hash: hash(2),
    prev_mutation_hash: genesis.mutation_hash,
    created_at: '2020-01-01T00:00:00.000Z',
  };
  const head = {
    provenance_id: '00000000-0000-4000-8000-000000000000',
    mutation_hash: hash(3),
    prev_mutation_hash: middle.mutation_hash,
    created_at: '2010-01-01T00:00:00.000Z',
  };

  assert.deepEqual(orderCredentialLifecycleRows([head, genesis, middle]), [genesis, middle, head]);
});

test('credential lifecycle fails closed on forks, missing predecessors, and root ambiguity', () => {
  const genesis = { mutation_hash: hash(1), prev_mutation_hash: null };
  assert.throws(
    () => orderCredentialLifecycleRows([
      genesis,
      { mutation_hash: hash(2), prev_mutation_hash: genesis.mutation_hash },
      { mutation_hash: hash(3), prev_mutation_hash: genesis.mutation_hash },
    ]),
    /credential_chain_fork_detected/,
  );
  assert.throws(
    () => orderCredentialLifecycleRows([
      genesis,
      { mutation_hash: hash(2), prev_mutation_hash: hash(9) },
    ]),
    /credential_chain_disconnected_predecessor/,
  );
  assert.throws(
    () => orderCredentialLifecycleRows([
      genesis,
      { mutation_hash: hash(2), prev_mutation_hash: null },
    ]),
    /credential_chain_multiple_genesis/,
  );
});

function receiptRow({ previous = null, requestByte, nonce, signedTs }) {
  const requestHash = hash(requestByte);
  const signature = Buffer.alloc(64, requestByte);
  const mutationHash = requestReceiptMutationHash({
    previousMutationHash: previous,
    requestHash,
    signature,
    method: 'POST',
    path: '/aimos/save',
    nonce,
    signedTs,
  });
  return {
    request_receipt_id: `${requestByte}`.padStart(32, '0'),
    company_id: 'hom',
    actor_agent_id: 'topology-agent',
    actor_valid_from: '2026-07-11T00:00:00.000Z',
    request_sig_form: 3,
    signed_method: 'POST',
    signed_path: '/aimos/save',
    signed_claims: null,
    signed_claims_hash: null,
    request_hash: requestHash,
    prev_mutation_hash: previous,
    mutation_hash: mutationHash,
    ts_signed: signedTs,
    nonce,
    sig: signature,
    is_genesis: previous === null,
  };
}

test('request receipt verification reconstructs shuffled rows from predecessor hashes', () => {
  const genesis = receiptRow({ requestByte: 1, nonce: 'topology-1', signedTs: 100 });
  const middle = receiptRow({
    previous: genesis.mutation_hash,
    requestByte: 2,
    nonce: 'topology-2',
    signedTs: 99,
  });
  const head = receiptRow({
    previous: middle.mutation_hash,
    requestByte: 3,
    nonce: 'topology-3',
    signedTs: 98,
  });

  assert.deepEqual(orderRequestReceiptRows([head, genesis, middle]), [genesis, middle, head]);
  const proof = verifyRequestReceiptChain([head, genesis, middle]);
  assert.equal(proof.rowCount, 3);
  assert.deepEqual(proof.mutationHash, head.mutation_hash);
});

test('request receipt topology fails closed on forks and disconnected rows', () => {
  const genesis = { mutation_hash: hash(1), prev_mutation_hash: null };
  assert.throws(
    () => orderRequestReceiptRows([
      genesis,
      { mutation_hash: hash(2), prev_mutation_hash: genesis.mutation_hash },
      { mutation_hash: hash(3), prev_mutation_hash: genesis.mutation_hash },
    ]),
    /request_receipt_fork_detected/,
  );
  assert.throws(
    () => orderRequestReceiptRows([
      genesis,
      { mutation_hash: hash(2), prev_mutation_hash: hash(8) },
    ]),
    /request_receipt_chain_link_invalid:disconnected_predecessor/,
  );
});

test('native ledger readers do not use created_at or UUIDs as predecessor authority', () => {
  const credentialSource = readFileSync(
    new URL('../../services/security/credential-ledger.js', import.meta.url),
    'utf8',
  );
  const receiptSource = readFileSync(
    new URL('../../services/security/request-receipt-ledger.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(credentialSource, /ORDER BY lifecycle\.created_at|ORDER BY lifecycle\.provenance_id/);
  assert.doesNotMatch(receiptSource, /ORDER BY created_at|ORDER BY request_receipt_id/);
  assert.match(credentialSource, /orderCredentialLifecycleRows/);
  assert.match(receiptSource, /verifyRequestReceiptChain\(stream\.rows \|\| \[\]\)/);
});

test('migration 076 enforces retained same-stream predecessor existence', () => {
  const sql = readFileSync(
    new URL('../../migrations/076-ledger-predecessor-topology.sql', import.meta.url),
    'utf8',
  );
  assert.match(sql, /aimos_credential_lifecycle_predecessor_fk/);
  assert.match(sql, /FOREIGN KEY \(slot_id, prev_mutation_hash\)/);
  assert.match(sql, /aimos_request_receipts_predecessor_fk/);
  assert.match(sql, /FOREIGN KEY \(company_id, actor_agent_id, actor_valid_from, prev_mutation_hash\)/);
  assert.match(sql, /ON DELETE RESTRICT/);
  assert.doesNotMatch(sql, /\bUPDATE\b|\bDELETE FROM\b|\bTRUNCATE\b/i);
});
