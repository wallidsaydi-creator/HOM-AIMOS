import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  createCorpusVectors,
  createRecallVectors,
} from '../../scripts/verification/mutmem-v2-s4-recall-fixture-factory.mjs';
import {
  recallCorpusRoot as productionRecallCorpusRoot,
  recallMerkleRoot as productionRecallMerkleRoot,
} from '../../services/security/protocol/mutmem-protocol.js';
import {
  normalizeNativeRecallCommand,
} from '../../services/retrieval/native-recall.js';
import {
  canonicalJson as independentCanonicalJson,
  normalizeRecallCommand as independentNormalizeRecallCommand,
  recallCorpusRoot as independentRecallCorpusRoot,
  recallMerkleRoot as independentRecallMerkleRoot,
  verifyRecallBundle as verifyNodeRecall,
  verifyRecallCorpus as verifyNodeCorpus,
} from '../../verifiers/mutmem-node/recall-verifier.mjs';

const VERIFY = new URL('../../verifiers/mutmem-python/verify.py', import.meta.url);
const NODE_OWNER = new URL('../../verifiers/mutmem-node/recall-verifier.mjs', import.meta.url);
const PYTHON_OWNER = new URL('../../verifiers/mutmem-python/recall_verifier.py', import.meta.url);

function runPython(value, operation) {
  const child = spawnSync('python3', [VERIFY.pathname, operation, '-'], {
    input: JSON.stringify(value),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  assert.notEqual(child.status, null, child.error?.message || 'Python verifier did not terminate');
  return { status: child.status, output: JSON.parse(child.stdout), stderr: child.stderr };
}

test('V2-S4B recall vectors have exact independent Node/Python terminal parity', () => {
  for (const vector of createRecallVectors()) {
    const node = verifyNodeRecall(vector.bundle);
    const python = runPython(vector.bundle, 'verify-recall');
    assert.equal(node.verdict, vector.expected, `${vector.id}: Node verdict`);
    assert.equal(node.primary_reason, vector.reason, `${vector.id}: Node reason`);
    assert.equal(python.output.verdict, vector.expected, `${vector.id}: Python verdict`);
    assert.equal(python.output.primary_reason, vector.reason, `${vector.id}: Python reason`);
    assert.equal(python.status, vector.expected === 'valid' ? 0 : vector.expected === 'indeterminate' ? 2 : 1);
    if (vector.expected === 'valid') {
      assert.equal(python.output.bundle_sha256, node.bundle_sha256, `${vector.id}: bundle hash`);
      assert.equal(python.output.command_hash, node.command_hash, `${vector.id}: command hash`);
      assert.equal(python.output.outer_request_hash, node.outer_request_hash, `${vector.id}: request hash`);
      assert.equal(python.output.merkle_root, node.merkle_root, `${vector.id}: Merkle root`);
      assert.deepEqual(python.output.counts, node.counts, `${vector.id}: counts`);
    }
  }
});

test('V2-S4B production command and Merkle protocol have exact independent parity', () => {
  for (const vector of createRecallVectors().filter((entry) => entry.expected === 'valid')) {
    const body = vector.bundle.request.body;
    assert.equal(
      independentCanonicalJson(independentNormalizeRecallCommand(body)),
      independentCanonicalJson(normalizeNativeRecallCommand(body)),
      `${vector.id}: production command normalization`,
    );
    const receipt = vector.bundle.recall_receipt;
    const entries = receipt.merkle_entries || receipt.evidence;
    assert.equal(
      independentRecallMerkleRoot(entries).toString('hex'),
      productionRecallMerkleRoot(entries).toString('hex'),
      `${vector.id}: production Merkle root`,
    );
  }
});

test('V2-S4B intended-N corpus vectors have exact independent Node/Python parity', () => {
  for (const vector of createCorpusVectors()) {
    const node = verifyNodeCorpus(vector.corpus);
    const python = runPython(vector.corpus, 'verify-corpus');
    assert.equal(node.verdict, vector.expected, `${vector.id}: Node verdict`);
    assert.equal(node.primary_reason, vector.reason, `${vector.id}: Node reason`);
    assert.equal(python.output.verdict, vector.expected, `${vector.id}: Python verdict`);
    assert.equal(python.output.primary_reason, vector.reason, `${vector.id}: Python reason`);
    assert.equal(python.status, vector.expected === 'valid' ? 0 : 1);
    if (vector.expected === 'valid') {
      assert.equal(python.output.corpus_root, node.corpus_root);
      assert.equal(python.output.intended_n, node.intended_n);
      assert.equal(python.output.observed_n, node.observed_n);
      assert.deepEqual(python.output.members, node.members);
      const summaries = vector.corpus.members.map(({ ordinal, bundle_id, bundle_sha256 }) => ({
        ordinal, bundle_id, bundle_sha256,
      }));
      assert.equal(
        independentRecallCorpusRoot(vector.corpus.intended_n, summaries).toString('hex'),
        productionRecallCorpusRoot({ intendedN: vector.corpus.intended_n, members: summaries }).toString('hex'),
      );
    }
  }
});

test('V2-S4B independent verifiers contain no runtime or authority dependencies', async () => {
  const [node, python] = await Promise.all([
    readFile(NODE_OWNER, 'utf8'),
    readFile(PYTHON_OWNER, 'utf8'),
  ]);
  assert.deepEqual([...node.matchAll(/^import\s+.*?from\s+['"]([^'"]+)/gm)].map((match) => match[1]), [
    'node:crypto',
  ]);
  assert.doesNotMatch(
    `${node}\n${python}`,
    /process\.env|os\.environ|subprocess|socket|requests|urllib|services\/|routes\/|db\/|Keychain|private[_ -]?key/i,
  );
  assert.doesNotMatch(`${node}\n${python}`, /createPrivateKey|generateKeyPair|cryptoSign|\bsign\(/);
});

test('V2-S4B unknown critical fields and duplicate JSON keys fail closed', () => {
  const bundle = structuredClone(createRecallVectors()[0].bundle);
  bundle.critical_extension = true;
  const node = verifyNodeRecall(bundle);
  assert.equal(node.verdict, 'invalid');
  assert.equal(node.primary_reason, 'recall_bundle_schema_invalid');

  const nested = structuredClone(createRecallVectors()[0].bundle);
  nested.recall_receipt.evidence[0].critical_extension = true;
  const nestedNode = verifyNodeRecall(nested);
  const nestedPython = runPython(nested, 'verify-recall');
  assert.equal(nestedNode.verdict, 'invalid');
  assert.equal(nestedNode.primary_reason, 'recall_receipt_memory_binding_invalid:0');
  assert.equal(nestedPython.status, 1);
  assert.equal(nestedPython.output.primary_reason, nestedNode.primary_reason);

  const anchor = structuredClone(createRecallVectors()[0].bundle);
  anchor.trust_anchors.certificates[0].critical_extension = true;
  const anchorNode = verifyNodeRecall(anchor);
  const anchorPython = runPython(anchor, 'verify-recall');
  assert.equal(anchorNode.verdict, 'invalid');
  assert.equal(anchorNode.primary_reason, 'recall_trust_anchor_schema_invalid');
  assert.equal(anchorPython.status, 1);
  assert.equal(anchorPython.output.primary_reason, anchorNode.primary_reason);

  const noncanonical = structuredClone(createRecallVectors()[0].bundle);
  const decodedCertificate = JSON.parse(Buffer.from(noncanonical.request.certificate, 'base64url').toString('utf8'));
  noncanonical.request.certificate = Buffer.from(JSON.stringify(decodedCertificate, null, 2)).toString('base64url');
  const certificateNode = verifyNodeRecall(noncanonical);
  const certificatePython = runPython(noncanonical, 'verify-recall');
  assert.equal(certificateNode.verdict, 'invalid');
  assert.equal(certificateNode.primary_reason, 'cert_schema');
  assert.equal(certificatePython.status, 1);
  assert.equal(certificatePython.output.primary_reason, certificateNode.primary_reason);

  const duplicate = spawnSync('python3', [VERIFY.pathname, 'verify-recall', '-'], {
    input: '{"format":{},"format":{}}', encoding: 'utf8',
  });
  assert.equal(duplicate.status, 1);
  assert.equal(JSON.parse(duplicate.stdout).primary_reason, 'json_duplicate_key');
});
