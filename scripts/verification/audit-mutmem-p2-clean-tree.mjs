#!/usr/bin/env node

// Database-free, runtime-free P2 verifier audit suitable for `git archive`.

import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyMutationBundle } from '../../verifiers/mutmem-v2/node/mutation-verifier.mjs';
import { verifyRecallEnvelope } from '../../verifiers/mutmem-v2/node/recall-verifier.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PYTHON = process.argv.find((value) => value.startsWith('--python='))?.slice(9) || 'python3';
const readJson = async (relative) => JSON.parse(await readFile(path.join(ROOT, relative), 'utf8'));
const [recallStructural, mutationStructural, crypto] = await Promise.all([
  readJson('verifiers/mutmem-conformance/v2/vectors.json'),
  readJson('verifiers/mutmem-conformance/v2/mutation-vectors.json'),
  readJson('verifiers/mutmem-conformance/v2/p2-crypto-vectors.json'),
]);

function nodeTerminal(profile, vector, cryptoMode) {
  try {
    if (profile === 'recall') {
      verifyRecallEnvelope(vector.bundle, {
        expectedMasterFingerprint: vector.expected_master_fingerprint,
        verifyCryptography: cryptoMode,
      });
    } else {
      verifyMutationBundle(vector.bundle, {
        witness: vector.witness,
        trustContext: vector.trust_context,
        expectedMasterFingerprint: vector.expected_master_fingerprint,
        verifyCryptography: cryptoMode,
      });
    }
    return { id: vector.id, valid: true, reason: null };
  } catch (error) {
    return { id: vector.id, valid: false, reason: error.reason || error.message };
  }
}

function expected(vectors) {
  return vectors.map((vector) => ({
    id: vector.id,
    valid: vector.expected === 'valid',
    reason: vector.reason,
  }));
}

function pythonBatch(profile, vectors, cryptoMode) {
  const child = spawnSync(PYTHON, [path.join(
    ROOT,
    'verifiers/mutmem-v2/python/verifier_cli.py',
  )], {
    input: JSON.stringify({
      operation: 'batch',
      profile,
      items: vectors.map((vector) => ({ ...vector, verify_cryptography: cryptoMode })),
    }),
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  if (child.status !== 0) throw new Error(`p2_clean_python_failed:${child.stderr}:${child.stdout}`);
  return JSON.parse(child.stdout).terminals.map(({ id, valid, reason }) => ({ id, valid, reason }));
}

export function auditMutMemP2CleanTree() {
  const lanes = [
    ['recall_structural', 'recall', recallStructural.vectors, false],
    ['mutation_structural', 'mutation', mutationStructural.vectors, false],
    ['recall_cryptographic', 'recall', crypto.recall.vectors, true],
    ['mutation_cryptographic', 'mutation', crypto.mutation.vectors, true],
  ].map(([name, profile, vectors, cryptoMode]) => {
    const expectedTerminals = expected(vectors);
    const node = vectors.map((vector) => nodeTerminal(profile, vector, cryptoMode));
    const python = pythonBatch(profile, vectors, cryptoMode);
    return {
      name,
      intended_n: vectors.length,
      node_exact: JSON.stringify(node) === JSON.stringify(expectedTerminals),
      python_exact: JSON.stringify(python) === JSON.stringify(expectedTerminals),
      cross_language_exact: JSON.stringify(node) === JSON.stringify(python),
    };
  });
  return {
    schema: 'hom.aimos.mutmem-p2-clean-tree-audit/v1',
    lanes,
    intended_n: lanes.reduce((sum, lane) => sum + lane.intended_n, 0),
    passed: lanes.every((lane) => lane.node_exact && lane.python_exact && lane.cross_language_exact),
    database_access: false,
    network_access: false,
    runtime_imports: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = auditMutMemP2CleanTree();
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) process.exitCode = 1;
}
