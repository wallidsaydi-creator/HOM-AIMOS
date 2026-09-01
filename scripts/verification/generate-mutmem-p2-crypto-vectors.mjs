#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  createP2MutationCryptographicVectors,
  createP2RecallCryptographicVectors,
} from './mutmem-p2-crypto-vector-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/mutmem-conformance/v2/p2-crypto-vectors.json');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const recall = createP2RecallCryptographicVectors();
const mutation = createP2MutationCryptographicVectors();
const unsigned = {
  schema: 'hom.aimos.mutmem-p2-cryptographic-vectors/v1',
  version: 1,
  authority: 'deterministic_public_test_keys_only',
  canonicalization: 'hom-aimos/canonical-json/v1',
  hash: 'sha256',
  signature: 'ed25519',
  recall: {
    intended_n: recall.length,
    valid_n: recall.filter((vector) => vector.expected === 'valid').length,
    invalid_n: recall.filter((vector) => vector.expected === 'invalid').length,
    vectors: recall,
  },
  mutation: {
    intended_n: mutation.length,
    valid_n: mutation.filter((vector) => vector.expected === 'valid').length,
    invalid_n: mutation.filter((vector) => vector.expected === 'invalid').length,
    vectors: mutation,
  },
  production_private_keys: false,
  database_state: false,
  live_identity_material: false,
};
const artifact = {
  ...unsigned,
  manifest_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
};
const bytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
await writeFile(OUTPUT, bytes, { mode: 0o644 });
await writeFile(`${OUTPUT}.sha256`, `${sha(bytes)}  ${path.basename(OUTPUT)}\n`, { mode: 0o644 });
console.log(JSON.stringify({
  output: OUTPUT,
  file_sha256: sha(bytes),
  manifest_sha256: artifact.manifest_sha256,
  recall_intended_n: recall.length,
  mutation_intended_n: mutation.length,
}, null, 2));
