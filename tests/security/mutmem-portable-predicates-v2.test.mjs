import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { recallAuthorizationMutationHash as nativeRecallAuthorizationMutationHash }
  from '../../services/security/recall-authorization.js';
import { requestReceiptMutationHash as nativeRequestReceiptMutationHash }
  from '../../services/security/request-receipt-ledger.js';
import {
  MUTMEM_PORTABLE_PREDICATE_CODES_V2,
  evaluateMutMemPortablePredicatesV2,
  recallAuthorizationMutationHashV1,
  requestReceiptMutationHashV1,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import {
  baseMutMemPortablePredicateBodies,
  createMutMemPortablePredicateVectorsV2,
} from '../../scripts/verification/mutmem-portable-predicate-fixture-factory.mjs';

const vectors = createMutMemPortablePredicateVectorsV2();
const sha = (value) => createHash('sha256').update(value).digest('hex');

test('P1 static-source vectors cover both authority profiles and every declared failure', () => {
  assert.equal(vectors.length, MUTMEM_PORTABLE_PREDICATE_CODES_V2.length + 2);
  assert.equal(vectors.filter((vector) => vector.expected === 'valid').length, 2);
  const reasons = vectors.filter((vector) => vector.expected === 'invalid')
    .map((vector) => vector.reason);
  assert.deepEqual([...reasons].sort(), [...MUTMEM_PORTABLE_PREDICATE_CODES_V2].sort());
});

test('P1 committed static package is self-hashed and exactly regenerable', async () => {
  const file = new URL('../../verifiers/mutmem-conformance/v2/vectors.json', import.meta.url);
  const [bytes, hashLine] = await Promise.all([
    readFile(file),
    readFile(new URL(`${file.href}.sha256`), 'utf8'),
  ]);
  const manifest = JSON.parse(bytes.toString('utf8'));
  const [expectedFileHash, filename] = hashLine.trim().split(/\s+/);
  assert.equal(filename, 'vectors.json');
  assert.equal(sha(bytes), expectedFileHash);
  const { manifest_sha256: manifestHash, ...unsigned } = manifest;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), manifestHash);
  assert.equal(manifest.intended_n, vectors.length);
  assert.equal(manifest.valid_n, 2);
  assert.equal(manifest.invalid_n, MUTMEM_PORTABLE_PREDICATE_CODES_V2.length);
  assert.deepEqual(manifest.failure_codes, MUTMEM_PORTABLE_PREDICATE_CODES_V2);
  assert.deepEqual(manifest.vectors, vectors);
});

for (const vector of vectors) {
  test(`P1 predicate vector ${vector.id} has exact terminal ${vector.expected}`, () => {
    if (vector.expected === 'valid') {
      const result = evaluateMutMemPortablePredicatesV2(vector.bundle);
      assert.equal(result.valid, true);
      assert.equal(result.predicate_count, MUTMEM_PORTABLE_PREDICATE_CODES_V2.length);
      assert.equal(result.cryptographic_signatures_verified, false);
      assert.equal(result.external_trust_established, false);
      assert.equal(result.next_required_owner, 'P2_INDEPENDENT_CRYPTOGRAPHIC_VERIFIER');
      return;
    }
    assert.throws(
      () => evaluateMutMemPortablePredicatesV2(vector.bundle),
      new RegExp(`mutmem_portable_predicates_v2:${vector.reason}$`),
    );
  });
}

test('P1 Housekeeper vector contains intrinsic authority and no fabricated grant', () => {
  const vector = vectors.find((entry) => entry.id === 'P1-PRED-CV-VALID-HOUSEKEEPER');
  const grant = vector.bundle.objects.find(
    (object) => object.kind === 'effective_recall_grant',
  ).body;
  assert.equal(grant.authority_kind, 'housekeeper_system_principal');
  assert.equal(grant.subject_agent_id, 'housekeeper');
  assert.equal(grant.clearance_ceiling, 12);
  assert.equal(grant.data_class_ceiling, 'restricted');
  assert.equal(Object.hasOwn(grant, 'signed_body'), false);
  assert.equal(Object.hasOwn(grant, 'signature_b64u'), false);
});

test('P1 grant and request-receipt reference bytes have exact native parity', () => {
  const bodies = baseMutMemPortablePredicateBodies();
  const grant = bodies.effective_recall_grant;
  assert.equal(
    recallAuthorizationMutationHashV1({
      previousMutationHash: grant.prev_mutation_hash,
      contentHash: grant.content_hash,
      nonce: grant.nonce,
      signedTs: grant.ts_signed,
    }),
    nativeRecallAuthorizationMutationHash(
      null,
      Buffer.from(grant.content_hash, 'hex'),
      grant.nonce,
      grant.ts_signed,
    ).toString('hex'),
  );
  const receipt = bodies.request_receipt;
  assert.equal(
    requestReceiptMutationHashV1({
      previousMutationHash: receipt.prev_mutation_hash,
      requestHash: receipt.request_hash,
      claimsHash: receipt.signed_claims_hash,
      signature: receipt.signature_b64u,
      method: receipt.signed_method,
      path: receipt.signed_path,
      nonce: receipt.nonce,
      signedTs: receipt.ts_signed,
    }),
    nativeRequestReceiptMutationHash({
      previousMutationHash: Buffer.from(receipt.prev_mutation_hash, 'hex'),
      requestHash: Buffer.from(receipt.request_hash, 'hex'),
      claimsHash: null,
      signature: Buffer.from(receipt.signature_b64u, 'base64url'),
      method: receipt.signed_method,
      path: receipt.signed_path,
      nonce: receipt.nonce,
      signedTs: receipt.ts_signed,
    }).toString('hex'),
  );
});

test('P1 predicate and fixture owners have no runtime, signer, database, network, or policy authority', async () => {
  const [owner, fixtures] = await Promise.all([
    readFile(new URL(
      '../../services/security/protocol/mutmem-portable-predicates-v2.js',
      import.meta.url,
    ), 'utf8'),
    readFile(new URL(
      '../../scripts/verification/mutmem-portable-predicate-fixture-factory.mjs',
      import.meta.url,
    ), 'utf8'),
  ]);
  assert.deepEqual(
    [...owner.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]),
    ['node:crypto', './canonical-json.js', './mutmem-protocol.js', './mutmem-portable-evidence-v2.js'],
  );
  assert.doesNotMatch(`${owner}\n${fixtures}`,
    /process\.env|fetch\(|writeFile\(|query\(|pool\.|\bsign\(|createPrivateKey|routes\/|jobs\//);
});
