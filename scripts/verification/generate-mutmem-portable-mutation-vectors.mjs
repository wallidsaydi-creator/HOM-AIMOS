#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
  evaluateMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';
import {
  createMutMemPortableMutationVectorsV2,
} from './mutmem-portable-mutation-fixture-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/mutmem-conformance/v2');
const FILE = path.join(OUTPUT, 'mutation-vectors.json');
const sha = (value) => createHash('sha256').update(value).digest('hex');

function terminal(vector) {
  try {
    evaluateMutMemPortableMutationBundleV2(vector.bundle);
    return { verdict: 'valid', reason: null };
  } catch (error) {
    return {
      verdict: 'invalid',
      reason: String(error.message).replace('mutmem_portable_mutation_v2:', ''),
    };
  }
}

async function main() {
  const vectors = createMutMemPortableMutationVectorsV2();
  for (const vector of vectors) {
    const actual = terminal(vector);
    if (actual.verdict !== vector.expected || actual.reason !== vector.reason) {
      throw new Error(`mutation_vector_terminal_mismatch:${vector.id}`);
    }
  }
  const summaries = vectors.map((vector, ordinal) => ({
    ordinal,
    id: vector.id,
    expected: vector.expected,
    reason: vector.reason,
    bundle_sha256: sha(Buffer.from(canonicalJson(vector.bundle), 'utf8')),
  }));
  const unsigned = {
    schema: 'hom.aimos.mutmem-portable-mutation-vectors/v2',
    version: 2,
    authority: 'descriptive_conformance_only',
    canonicalization: 'hom-aimos/canonical-json/v1',
    intended_n: vectors.length,
    valid_n: 3,
    invalid_n: MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2.length,
    terminal_kinds: ['authorized_transition', 'signed_noop', 'occurrence_observation'],
    failure_codes: MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
    vectors_root_sha256: sha(Buffer.from(canonicalJson(summaries), 'utf8')),
    summaries,
    vectors,
  };
  const manifest = {
    ...unsigned,
    manifest_sha256: sha(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const fileHash = sha(bytes);
  await mkdir(OUTPUT, { recursive: true });
  const temp = `${FILE}.tmp-${process.pid}`;
  const hashFile = `${FILE}.sha256`;
  const hashTemp = `${hashFile}.tmp-${process.pid}`;
  await writeFile(temp, bytes, { mode: 0o644 });
  await writeFile(hashTemp, `${fileHash}  mutation-vectors.json\n`, { mode: 0o644 });
  await rename(temp, FILE);
  await rename(hashTemp, hashFile);
  console.log(JSON.stringify({
    success: true,
    intended_n: manifest.intended_n,
    valid_n: manifest.valid_n,
    invalid_n: manifest.invalid_n,
    vectors_root_sha256: manifest.vectors_root_sha256,
    manifest_sha256: manifest.manifest_sha256,
    file_sha256: fileHash,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
});
