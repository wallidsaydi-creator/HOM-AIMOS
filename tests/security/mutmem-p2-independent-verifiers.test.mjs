import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { recallAuthorizationMutationHash as nativeRecallAuthorizationMutationHash }
  from '../../services/security/recall-authorization.js';
import { requestReceiptMutationHash as nativeRequestReceiptMutationHash }
  from '../../services/security/request-receipt-ledger.js';
import {
  createP2MutationCryptographicVectors,
  createP2RecallCryptographicVectors,
}
  from '../../scripts/verification/mutmem-p2-crypto-vector-factory.mjs';

import {
  MutMemMutationVerificationError,
  MUTATION_WITNESS_FAILURE_CODES,
  verifyMutationBundle,
} from '../../verifiers/mutmem-v2/node/mutation-verifier.mjs';
import { CRYPTOGRAPHIC_FAILURE_CODES, verifyRecallEnvelope }
  from '../../verifiers/mutmem-v2/node/recall-verifier.mjs';
import { recallByteParity }
  from '../../verifiers/mutmem-v2/node/recall-verifier.mjs';

const PYTHON = process.env.MUTMEM_P2_PYTHON || 'python3';
const PYTHON_CLI = new URL(
  '../../verifiers/mutmem-v2/python/verifier_cli.py',
  import.meta.url,
).pathname;
const RECALL_VECTORS = new URL(
  '../../verifiers/mutmem-conformance/v2/vectors.json',
  import.meta.url,
);
const MUTATION_VECTORS = new URL(
  '../../verifiers/mutmem-conformance/v2/mutation-vectors.json',
  import.meta.url,
);
const LIVE_RECALL = new URL(
  '../../artifacts/security/mutmem-v2/p1-live-projection/10217fc3-2c04-418c-8f8f-61346e29a88b.json',
  import.meta.url,
);
const LIVE_MUTATION = new URL(
  '../../artifacts/security/mutmem-v2/p1-live-mutation/64e723e3cae6c1bbdcdb7b0d.json',
  import.meta.url,
);
const LIVE_WITNESS = new URL(
  '../../artifacts/security/mutmem-v2/p2-mutation-witness/3860653fb82805e87b76ef7c.json',
  import.meta.url,
);
const CRYPTO_VECTORS = new URL(
  '../../verifiers/mutmem-conformance/v2/p2-crypto-vectors.json',
  import.meta.url,
);
const RESOURCE_MEASUREMENT = new URL(
  '../../verifiers/mutmem-conformance/v2/p2-resource-measurement.json',
  import.meta.url,
);
const sha = (value) => createHash('sha256').update(value).digest('hex');

async function json(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

function python(request) {
  const run = spawnSync(PYTHON, [PYTHON_CLI], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
  return JSON.parse(run.stdout);
}

test('P2 independent Node and Python recall verifiers reproduce all 39 P1 structural terminals', async () => {
  const vectors = (await json(RECALL_VECTORS)).vectors;
  const nodeTerminals = vectors.map((vector) => {
    try {
      verifyRecallEnvelope(vector.bundle, { verifyCryptography: false });
      return { id: vector.id, valid: true, reason: null };
    } catch (error) {
      return { id: vector.id, valid: false, reason: error.reason };
    }
  });
  const pythonTerminals = python({
    operation: 'batch',
    profile: 'recall',
    items: vectors.map((vector) => ({
      id: vector.id,
      bundle: vector.bundle,
      verify_cryptography: false,
    })),
  }).terminals.map(({ id, valid, reason }) => ({ id, valid, reason }));
  const expected = vectors.map((vector) => ({
    id: vector.id,
    valid: vector.expected === 'valid',
    reason: vector.reason,
  }));
  assert.deepEqual(nodeTerminals, expected);
  assert.deepEqual(pythonTerminals, expected);
});

test('P2 independent Node and Python mutation verifiers reproduce all 15 P1 structural terminals', async () => {
  const vectors = (await json(MUTATION_VECTORS)).vectors;
  const nodeTerminals = vectors.map((vector) => {
    try {
      verifyMutationBundle(vector.bundle);
      return { id: vector.id, valid: true, reason: null };
    } catch (error) {
      return { id: vector.id, valid: false, reason: error.reason };
    }
  });
  const pythonTerminals = python({
    operation: 'batch',
    profile: 'mutation',
    items: vectors.map((vector) => ({
      id: vector.id,
      bundle: vector.bundle,
      verify_cryptography: false,
    })),
  }).terminals.map(({ id, valid, reason }) => ({ id, valid, reason }));
  const expected = vectors.map((vector) => ({
    id: vector.id,
    valid: vector.expected === 'valid',
    reason: vector.reason,
  }));
  assert.deepEqual(nodeTerminals, expected);
  assert.deepEqual(pythonTerminals, expected);
});

test('P2 deterministic recall cryptographic vectors have exact Node/Python failure parity', () => {
  const vectors = createP2RecallCryptographicVectors();
  const nodeTerminals = vectors.map((vector) => {
    try {
      verifyRecallEnvelope(vector.bundle, {
        expectedMasterFingerprint: vector.expected_master_fingerprint,
      });
      return { id: vector.id, valid: true, reason: null };
    } catch (error) {
      return { id: vector.id, valid: false, reason: error.reason };
    }
  });
  const pythonTerminals = python({
    operation: 'batch',
    profile: 'recall',
    items: vectors.map((vector) => ({
      id: vector.id,
      bundle: vector.bundle,
      expected_master_fingerprint: vector.expected_master_fingerprint,
      verify_cryptography: true,
    })),
  }).terminals.map(({ id, valid, reason }) => ({ id, valid, reason }));
  const expected = vectors.map((vector) => ({
    id: vector.id,
    valid: vector.expected === 'valid',
    reason: vector.reason,
  }));
  assert.deepEqual(nodeTerminals, expected);
  assert.deepEqual(pythonTerminals, expected);
});

test('P2 deterministic mutation-witness cryptographic vectors have exact Node/Python failure parity', () => {
  const vectors = createP2MutationCryptographicVectors();
  const nodeTerminals = vectors.map((vector) => {
    try {
      verifyMutationBundle(vector.bundle, {
        witness: vector.witness,
        trustContext: vector.trust_context,
        expectedMasterFingerprint: vector.expected_master_fingerprint,
        verifyCryptography: true,
      });
      return { id: vector.id, valid: true, reason: null };
    } catch (error) {
      return { id: vector.id, valid: false, reason: error.reason };
    }
  });
  const pythonTerminals = python({
    operation: 'batch',
    profile: 'mutation',
    items: vectors.map((vector) => ({
      id: vector.id,
      bundle: vector.bundle,
      witness: vector.witness,
      trust_context: vector.trust_context,
      expected_master_fingerprint: vector.expected_master_fingerprint,
      verify_cryptography: true,
    })),
  }).terminals.map(({ id, valid, reason }) => ({ id, valid, reason }));
  const expected = vectors.map((vector) => ({
    id: vector.id,
    valid: vector.expected === 'valid',
    reason: vector.reason,
  }));
  assert.deepEqual(nodeTerminals, expected);
  assert.deepEqual(pythonTerminals, expected);
});

test('P2 committed cryptographic vectors are deterministic, self-hashed, and failure-complete', async () => {
  const [bytes, hashLine] = await Promise.all([
    readFile(CRYPTO_VECTORS),
    readFile(new URL(`${CRYPTO_VECTORS.href}.sha256`), 'utf8'),
  ]);
  const artifact = JSON.parse(bytes.toString('utf8'));
  const [fileHash, filename] = hashLine.trim().split(/\s+/);
  assert.equal(filename, 'p2-crypto-vectors.json');
  assert.equal(sha(bytes), fileHash);
  const { manifest_sha256: manifestHash, ...unsigned } = artifact;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), manifestHash);
  assert.deepEqual(artifact.recall.vectors, createP2RecallCryptographicVectors());
  assert.deepEqual(artifact.mutation.vectors, createP2MutationCryptographicVectors());
  assert.deepEqual(
    artifact.recall.vectors.filter((vector) => vector.expected === 'invalid')
      .map((vector) => vector.reason).sort(),
    [...CRYPTOGRAPHIC_FAILURE_CODES].sort(),
  );
  assert.deepEqual(
    [
      ...artifact.mutation.vectors.filter((vector) => vector.expected === 'invalid')
        .map((vector) => vector.reason),
      'MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED',
    ].sort(),
    [...MUTATION_WITNESS_FAILURE_CODES].sort(),
  );
});

test('P2 committed 100,000-leaf resource measurement is self-hashed and within fixed gates', async () => {
  const measurement = await json(RESOURCE_MEASUREMENT);
  const { measurement_sha256: root, ...unsigned } = measurement;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), root);
  assert.equal(measurement.intended_n, 100_000);
  assert.equal(measurement.exact_root_parity, true);
  assert.equal(measurement.node.root_sha256, measurement.python.root_sha256);
  assert.equal(measurement.node.time_complexity, 'O(n)');
  assert.equal(measurement.python.time_complexity, 'O(n)');
  assert.ok(measurement.node.elapsed_ms
    <= measurement.thresholds.maximum_elapsed_ms_per_implementation);
  assert.ok(measurement.python.elapsed_ms
    <= measurement.thresholds.maximum_elapsed_ms_per_implementation);
  assert.ok(measurement.node.peak_rss_bytes
    <= measurement.thresholds.maximum_peak_rss_bytes_per_implementation);
  assert.ok(measurement.python.peak_rss_bytes
    <= measurement.thresholds.maximum_peak_rss_bytes_per_implementation);
  assert.equal(measurement.passed, true);
});

test('P2 mutation verification fails explicitly without its cryptographic witness', async () => {
  const vector = (await json(MUTATION_VECTORS)).vectors.find(
    (entry) => entry.expected === 'valid',
  );
  assert.throws(
    () => verifyMutationBundle(vector.bundle, { verifyCryptography: true }),
    (error) => error instanceof MutMemMutationVerificationError
      && error.reason === 'MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED',
  );
  const terminal = python({
    profile: 'mutation',
    bundle: vector.bundle,
    verify_cryptography: true,
  });
  assert.equal(terminal.valid, false);
  assert.equal(terminal.reason, 'MUTATION_CRYPTOGRAPHIC_WITNESS_REQUIRED');
});

test('P2 exact legacy unframed nonce/timestamp hashes have native, Node, and Python parity', async () => {
  const valid = (await json(RECALL_VECTORS)).vectors.find(
    (entry) => entry.id === 'P1-PRED-CV-VALID-ORDINARY',
  ).bundle;
  const byKind = Object.fromEntries(valid.objects.map((object) => [object.kind, object.body]));
  const grant = byKind.effective_recall_grant;
  const receipt = byKind.request_receipt;
  const recallInput = {
    previousMutationHash: grant.prev_mutation_hash,
    contentHash: grant.content_hash,
    nonce: grant.nonce,
    signedTs: grant.ts_signed,
  };
  const receiptInput = {
    previousMutationHash: receipt.prev_mutation_hash,
    requestHash: receipt.request_hash,
    claimsHash: receipt.signed_claims_hash,
    signature: receipt.signature_b64u,
    method: receipt.signed_method,
    path: receipt.signed_path,
    nonce: receipt.nonce,
    signedTs: receipt.ts_signed,
  };
  const nativeRecall = nativeRecallAuthorizationMutationHash(
    null,
    Buffer.from(grant.content_hash, 'hex'),
    grant.nonce,
    grant.ts_signed,
  ).toString('hex');
  const nativeReceipt = nativeRequestReceiptMutationHash({
    previousMutationHash: Buffer.from(receipt.prev_mutation_hash, 'hex'),
    requestHash: Buffer.from(receipt.request_hash, 'hex'),
    claimsHash: null,
    signature: Buffer.from(receipt.signature_b64u, 'base64url'),
    method: receipt.signed_method,
    path: receipt.signed_path,
    nonce: receipt.nonce,
    signedTs: receipt.ts_signed,
  }).toString('hex');
  assert.equal(recallByteParity.recallAuthorizationMutationHash(recallInput), nativeRecall);
  assert.equal(recallByteParity.requestReceiptMutationHash(receiptInput), nativeReceipt);
  const result = python({
    operation: 'byte_parity',
    recall_authorization: {
      previous_mutation_hash: recallInput.previousMutationHash,
      content_hash: recallInput.contentHash,
      nonce: recallInput.nonce,
      signed_ts: recallInput.signedTs,
    },
    request_receipt: {
      previous_mutation_hash: receiptInput.previousMutationHash,
      request_hash: receiptInput.requestHash,
      claims_hash: receiptInput.claimsHash,
      signature: receiptInput.signature,
      method: receiptInput.method,
      path: receiptInput.path,
      nonce: receiptInput.nonce,
      signed_ts: receiptInput.signedTs,
    },
  });
  assert.equal(result.recall_authorization_mutation_hash, nativeRecall);
  assert.equal(result.request_receipt_mutation_hash, nativeReceipt);
});

test('P2 recall verifiers fail before traversing oversized cardinality, body, and depth inputs', async () => {
  const valid = (await json(RECALL_VECTORS)).vectors.find(
    (entry) => entry.expected === 'valid',
  ).bundle;
  const oversizedCardinality = structuredClone(valid);
  oversizedCardinality.objects.push(structuredClone(valid.objects.at(-1)));
  const oversizedBody = structuredClone(valid);
  oversizedBody.objects[0].body.padding = 'x'.repeat(1024 * 1024 + 1);
  const excessiveDepth = structuredClone(valid);
  let cursor = excessiveDepth.objects[0].body;
  for (let depth = 0; depth < 34; depth += 1) {
    cursor.nested = {};
    cursor = cursor.nested;
  }
  const cases = [oversizedCardinality, oversizedBody, excessiveDepth];
  for (const bundle of cases) {
    assert.throws(
      () => verifyRecallEnvelope(bundle, { verifyCryptography: false }),
      (error) => error.reason === 'ENVELOPE_COMMITMENT_INVALID',
    );
  }
  const terminals = python({
    operation: 'batch',
    profile: 'recall',
    items: cases.map((bundle, index) => ({
      id: `bound-${index}`,
      bundle,
      verify_cryptography: false,
    })),
  }).terminals;
  assert.deepEqual(terminals.map((entry) => entry.reason), [
    'ENVELOPE_COMMITMENT_INVALID',
    'ENVELOPE_COMMITMENT_INVALID',
    'ENVELOPE_COMMITMENT_INVALID',
  ]);
});

test('P2 independent verifiers behaviorally verify the promoted live recall and three mutation terminals', async (context) => {
  try {
    await Promise.all([access(LIVE_RECALL), access(LIVE_MUTATION), access(LIVE_WITNESS)]);
  } catch {
    context.skip('private promoted artifacts are not distributed');
    return;
  }
  const [recallArtifact, mutationArtifact, witnessSet] = await Promise.all([
    json(LIVE_RECALL), json(LIVE_MUTATION), json(LIVE_WITNESS),
  ]);
  const trust = recallArtifact.bundle;
  const expectedMasterFingerprint = trust.expected_master_fingerprint;
  const nodeRecall = verifyRecallEnvelope(trust, { expectedMasterFingerprint });
  const pythonRecall = python({
    profile: 'recall',
    bundle: trust,
    expected_master_fingerprint: expectedMasterFingerprint,
    verify_cryptography: true,
  });
  assert.equal(nodeRecall.verified_signature_count, 6);
  assert.equal(pythonRecall.valid, true);
  assert.deepEqual(pythonRecall.result, nodeRecall);
  for (const entry of mutationArtifact.projections) {
    const witness = witnessSet.witnesses.find(
      (candidate) => candidate.mutation_bundle_sha256 === entry.bundle.bundle_sha256,
    );
    const nodeResult = verifyMutationBundle(entry.bundle, {
      witness,
      trustContext: trust,
      expectedMasterFingerprint,
      verifyCryptography: true,
    });
    const pythonResult = python({
      profile: 'mutation',
      bundle: entry.bundle,
      witness,
      trust_context: trust,
      expected_master_fingerprint: expectedMasterFingerprint,
      verify_cryptography: true,
    });
    assert.equal(pythonResult.valid, true);
    assert.deepEqual(pythonResult.result, nodeResult);
  }
});

test('P2 independent verifier modules import no HOM-AIMOS runtime, database, route, or signer', async () => {
  const sources = await Promise.all([
    '../../verifiers/mutmem-v2/node/recall-verifier.mjs',
    '../../verifiers/mutmem-v2/node/mutation-verifier.mjs',
    '../../verifiers/mutmem-v2/python/recall_verifier.py',
    '../../verifiers/mutmem-v2/python/mutation_verifier.py',
  ].map((relative) => readFile(new URL(relative, import.meta.url), 'utf8')));
  const joined = sources.join('\n');
  assert.doesNotMatch(joined,
    /db\/|routes\/|services\/|jobs\/|fetch\(|psycopg|requests\.|urllib|createPrivateKey|signPayload|cryptoSign/);
});
