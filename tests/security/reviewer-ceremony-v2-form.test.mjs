// reviewer-ceremony-v2-form.test.mjs — the crypto the reviewer ceremony rests on.
//
// The ceremony's whole claim is that the memory's ORIGIN TIME is bound into the
// signature and into the hash chain — not merely stored as metadata. These tests
// pin that: change the origin time and BOTH the signature and the mutation_hash
// must break. If either survives, the ceremony proves nothing.
//
// No DB required — this is the canonical form, not the transport.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { generateKeypair, signPayloadV2, verifyPayloadSigV2 } from '../../services/security/agent-identity.js';
import { computeMutationHashV2 } from '../../services/security/memory-provenance.js';
import { computeBuildId, METHODS_FREEZE_FILES } from '../../scripts/ceremony/ledger-fingerprints.mjs';

const BODY = {
  event_type: 'RETAINED_ATTEST',
  ceremony: 'reviewer_origin_time_notarization',
  memory_id: '00000000-0000-4000-8000-00000000beef',
  claim: 'notarization_at_T_not_authorship_at_origin',
};
const NONCE = 'Zm9vYmFyYmF6cXV4';
const TS = 1783932650;
const ORIGIN = 1783248817; // months earlier than TS — the whole point of v2

test('v2 signature binds the origin time: re-dating the memory breaks the signature', () => {
  const kp = generateKeypair();
  const sig = signPayloadV2(kp.privkey, BODY, NONCE, TS, ORIGIN);

  const honest = verifyPayloadSigV2(kp.pubkey, BODY, NONCE, TS, ORIGIN, sig, { nowFn: () => TS });
  assert.equal(honest.valid, true, 'the honest claim must verify');

  // The attack the ceremony exists to stop: backdate/forward-date the memory's
  // origin while leaving body, nonce and ts_signed untouched.
  const tampered = verifyPayloadSigV2(kp.pubkey, BODY, NONCE, TS, ORIGIN + 1, sig, { nowFn: () => TS });
  assert.equal(tampered.valid, false, 'a re-dated origin MUST invalidate the v2 signature');
});

test('v2 mutation_hash binds the origin time into the chain, not just the sig', () => {
  const contentHash = createHash('sha256').update('memory-body').digest();
  const prev = createHash('sha256').update('predecessor').digest();

  const h1 = computeMutationHashV2(contentHash, prev, NONCE, TS, ORIGIN);
  const h2 = computeMutationHashV2(contentHash, prev, NONCE, TS, ORIGIN + 1);
  assert.notEqual(h1.toString('hex'), h2.toString('hex'), 'origin time must change the chain hash');

  // Determinism: the same inputs must always yield the same link.
  const again = computeMutationHashV2(contentHash, prev, NONCE, TS, ORIGIN);
  assert.equal(h1.toString('hex'), again.toString('hex'), 'the chain hash must be deterministic');

  // Genesis form drops the predecessor and must differ from the linked form.
  const genesis = computeMutationHashV2(contentHash, null, NONCE, TS, ORIGIN);
  assert.notEqual(genesis.toString('hex'), h1.toString('hex'), 'genesis and linked forms must differ');
  assert.equal(genesis.length, 32, 'sha256 → 32 bytes');
});

test('v2 mutation_hash rejects a non-integer origin time instead of hashing garbage', () => {
  const contentHash = createHash('sha256').update('x').digest();
  assert.throws(
    () => computeMutationHashV2(contentHash, null, NONCE, TS, '1783248817'),
    /integer unix seconds/,
    'a string origin time must be refused, not silently coerced'
  );
});

test('build_id is deterministic and covers the methods-freeze set', () => {
  const a = computeBuildId();
  const b = computeBuildId();
  assert.equal(a, b, 'build_id must be reproducible — this is the reproducibility fix');
  assert.match(a, /^[0-9a-f]{64}$/, 'build_id is a sha256 hex digest');

  assert.ok(METHODS_FREEZE_FILES.length >= 10, 'the freeze set must cover the crypto surface');
  assert.ok(
    METHODS_FREEZE_FILES.includes('services/security/canary-write-gate.js'),
    'the new canary gate is part of the measured surface and must be frozen with it'
  );

  // Order matters: the digest is over concatenated bytes in declared order, so a
  // reordered list is a different build. Pin that, or the freeze is not a freeze.
  const reordered = [...METHODS_FREEZE_FILES].reverse();
  assert.notEqual(computeBuildId(undefined, reordered), a, 'file order must affect build_id');
});
