#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  verifyCognitiveWeightEvidenceBundle,
} from '../../services/security/protocol/cognitive-weight-evidence.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURES = path.join(ROOT, 'verifiers/mutmem-python/fixtures');
const VERIFY = path.join(ROOT, 'verifiers/mutmem-python/verify.py');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function nodeVerdict(bundle) {
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

async function main() {
  const manifestBytes = await readFile(path.join(FIXTURES, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.schema, 'hom.aimos.mutmem-v2-s4-focused-fixture-manifest/v1');
  assert.equal(manifest.vector_count, manifest.vectors.length);
  assert.equal(manifest.synthetic_keys, true);
  assert.equal(manifest.private_keys_retained, false);
  assert.equal(manifest.live_aimos_data_included, false);
  const files = (await readdir(FIXTURES)).sort();
  const expectedFiles = [
    ...manifest.vectors.map((vector) => vector.filename),
    'manifest.json',
    'manifest.json.sha256',
  ].sort();
  assert.deepEqual(files, expectedFiles);

  const results = [];
  for (const vector of manifest.vectors) {
    const raw = await readFile(path.join(FIXTURES, vector.filename));
    assert.equal(sha256(raw), vector.fixture_sha256, `${vector.vector_id}: fixture hash`);
    const bundle = JSON.parse(raw);
    const node = nodeVerdict(bundle);
    const child = spawnSync('python3', [VERIFY, 'verify-bundle', '-'], {
      input: raw,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    if (child.error) throw child.error;
    const python = JSON.parse(child.stdout);
    assert.equal(node.verdict, vector.expected_verdict, `${vector.vector_id}: Node verdict`);
    assert.equal(node.reason, vector.expected_primary_reason, `${vector.vector_id}: Node reason`);
    assert.equal(python.verdict, vector.expected_verdict, `${vector.vector_id}: Python verdict`);
    assert.equal(python.primary_reason, vector.expected_primary_reason, `${vector.vector_id}: Python reason`);
    assert.equal(child.status, vector.expected_verdict === 'valid' ? 0 : 1);
    if (node.proof) {
      assert.deepEqual(python.records, node.proof.records);
      assert.deepEqual(python.sql_rows, node.proof.sqlRows);
      assert.equal(python.parity, node.proof.parity);
      assert.equal(python.proof_root, node.proof.proofRoot.toString('hex'));
      assert.equal(python.bundle_sha256, node.proof.bundleSha256.toString('hex'));
      assert.deepEqual(python.event_stream_results, node.proof.eventStreamResults);
    }
    results.push({
      vector_id: vector.vector_id,
      verdict: python.verdict,
      primary_reason: python.primary_reason,
      node_python_exact_parity: true,
    });
  }
  process.stdout.write(`${JSON.stringify({
    success: true,
    manifest_sha256: sha256(manifestBytes),
    vector_count: results.length,
    valid_vectors: results.filter((result) => result.verdict === 'valid').length,
    invalid_vectors: results.filter((result) => result.verdict === 'invalid').length,
    exact_parity: true,
    results,
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.stack || error}`);
  process.exitCode = 1;
});
