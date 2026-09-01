import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { canonicalJson as nativeCanonicalJson }
  from '../../services/security/protocol/canonical-json.js';
import { recallMerkleRoot as nativeRecallMerkleRoot }
  from '../../services/security/protocol/mutmem-protocol.js';
import {
  canonicalJson,
  occurrenceCommitmentV3,
  recallMerkleRoot,
  verifyCertificate,
  verifyEd25519,
  verifyOccurrenceSignatureV3,
} from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';

const PYTHON = process.env.MUTMEM_P2_PYTHON || 'python3';
const PYTHON_CLI = new URL(
  '../../verifiers/mutmem-v2/python/kernel_cli.py',
  import.meta.url,
).pathname;
const PUBLIC_CRYPTO_VECTORS = new URL(
  '../../verifiers/mutmem-conformance/v2/p2-crypto-vectors.json',
  import.meta.url,
);

function python(request) {
  const run = spawnSync(PYTHON, [PYTHON_CLI], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
  return JSON.parse(run.stdout);
}

test('P2 Node and Python kernels reproduce canonical JSON bytes independently', () => {
  const values = [
    null,
    true,
    false,
    0,
    -0,
    1e-7,
    1e-6,
    1e15,
    333333333.33333329,
    { numbers: [333333333.33333329, 1e-30, 4.50, 2e-3, 1e-27] },
    { '\u20ac': 'Euro', '\r': 'CR', '\ufb33': 'Hebrew', '1': 'one', '\ud83d\ude00': 'emoji' },
    { text: 'control\b\t\n\f\r"\\', nested: [{ z: 1, a: 2 }] },
  ];
  for (const value of values) {
    const expected = nativeCanonicalJson(value);
    assert.equal(canonicalJson(value), expected);
    assert.equal(python({ operation: 'canonical_json', value }).canonical_json, expected);
  }
});

test('P2 iterative RFC 6962 roots match native roots for empty and non-power-of-two lists', () => {
  const entries = Array.from({ length: 17 }, (_, ordinal) => ({
    ordinal,
    value: `entry-${ordinal}`,
  }));
  for (let count = 0; count <= entries.length; count += 1) {
    const selected = entries.slice(0, count);
    const expected = nativeRecallMerkleRoot(selected).toString('hex');
    assert.equal(recallMerkleRoot(selected).toString('hex'), expected);
    assert.equal(
      python({ operation: 'recall_merkle_root', entries: selected }).root_sha256,
      expected,
    );
  }
});

test('P2 kernels verify RFC 8032 Ed25519 test vector 1 and reject its mutation', () => {
  const rawPublicKey = Buffer.from(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'hex',
  );
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    rawPublicKey,
  ]).toString('base64url');
  const signature = Buffer.from(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
      + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    'hex',
  ).toString('base64url');
  assert.equal(verifyEd25519(spki, Buffer.alloc(0), signature), true);
  assert.equal(verifyEd25519(spki, Buffer.from([0]), signature), false);
  assert.equal(python({
    operation: 'verify_ed25519',
    public_key: spki,
    message_hex: '',
    signature,
  }).valid, true);
  assert.equal(python({
    operation: 'verify_ed25519',
    public_key: spki,
    message_hex: '00',
    signature,
  }).valid, false);
});

test('P2 kernels behaviorally verify public deterministic certificate and occurrence bytes', async () => {
  const vectors = JSON.parse(await readFile(PUBLIC_CRYPTO_VECTORS, 'utf8'));
  const artifact = vectors.recall.vectors.find(
    (vector) => vector.id === 'P2-CRYPTO-RECALL-VALID',
  );
  assert.ok(artifact?.bundle);
  const byKind = Object.fromEntries(
    artifact.bundle.objects.map((object) => [object.kind, object.body]),
  );
  const trust = byKind.trust_anchor;
  const actor = byKind.actor_identity_epoch;
  const housekeeper = byKind.housekeeper_identity_epoch;
  const requestTs = byKind.request_envelope.ts_signed;
  for (const identity of [actor, housekeeper]) {
    const input = {
      certificate: identity.certificate,
      authorityPublicKey: trust.master_public_key_b64u,
      expectedAgentId: identity.agent_id,
      expectedSubjectPublicKey: identity.public_key_b64u,
      atUnixSeconds: requestTs,
    };
    assert.equal(verifyCertificate(input).valid, true);
    assert.equal(python({
      operation: 'verify_certificate',
      certificate: input.certificate,
      authority_public_key: input.authorityPublicKey,
      expected_agent_id: input.expectedAgentId,
      expected_subject_public_key: input.expectedSubjectPublicKey,
      at_unix_seconds: input.atUnixSeconds,
    }).valid, true);
  }
  const occurrence = artifact.bundle.objects.find(
    (object) => object.kind === 'occurrence',
  ).body;
  assert.equal(
    occurrenceCommitmentV3(occurrence.native_body),
    occurrence.occurrence_ref,
  );
  assert.equal(verifyOccurrenceSignatureV3(
    occurrence.native_body,
    occurrence.signature_b64u,
    housekeeper.public_key_b64u,
  ), true);
  const pythonOccurrence = python({
    operation: 'occurrence',
    record: occurrence.native_body,
    signature: occurrence.signature_b64u,
    public_key: housekeeper.public_key_b64u,
  });
  assert.equal(pythonOccurrence.commitment_sha256, occurrence.occurrence_ref);
  assert.equal(pythonOccurrence.signature_valid, true);
});

test('P2 kernels have no HOM-AIMOS runtime or I/O authority imports', async () => {
  const [nodeSource, pythonSource] = await Promise.all([
    readFile(new URL(
      '../../verifiers/mutmem-v2/node/crypto-kernel.mjs',
      import.meta.url,
    ), 'utf8'),
    readFile(new URL(
      '../../verifiers/mutmem-v2/python/crypto_kernel.py',
      import.meta.url,
    ), 'utf8'),
  ]);
  assert.deepEqual(
    [...nodeSource.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]),
    ['node:crypto'],
  );
  assert.doesNotMatch(`${nodeSource}\n${pythonSource}`,
    /db\/|routes\/|services\/|jobs\/|fetch\(|requests\.|urllib|psycopg|child_process|subprocess/);
});
