#!/usr/bin/env node

// Deterministic offline generator for P1 portable predicate vectors.

import { createHash } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  MUTMEM_PORTABLE_PREDICATE_CODES_V2,
  evaluateMutMemPortablePredicatesV2,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import {
  createMutMemPortablePredicateVectorsV2,
} from './mutmem-portable-predicate-fixture-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/mutmem-conformance/v2');
const JSON_FILE = path.join(OUTPUT, 'vectors.json');
const HASH_FILE = `${JSON_FILE}.sha256`;

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function exactTerminal(vector) {
  try {
    const result = evaluateMutMemPortablePredicatesV2(vector.bundle);
    return { verdict: result.valid ? 'valid' : 'invalid', reason: null };
  } catch (error) {
    const prefix = 'mutmem_portable_predicates_v2:';
    const message = String(error?.message || error);
    return {
      verdict: 'invalid',
      reason: message.startsWith(prefix) ? message.slice(prefix.length) : 'INTERNAL_FAILURE',
    };
  }
}

async function main() {
  const vectors = createMutMemPortablePredicateVectorsV2();
  for (const vector of vectors) {
    const actual = exactTerminal(vector);
    if (actual.verdict !== vector.expected || actual.reason !== vector.reason) {
      throw new Error(`p1_vector_terminal_mismatch:${vector.id}:${actual.verdict}:${actual.reason}`);
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
    schema: 'hom.aimos.mutmem-portable-predicate-vectors/v2',
    version: 2,
    authority: 'descriptive_conformance_only',
    canonicalization: 'hom-aimos/canonical-json/v1',
    hash: 'sha256',
    intended_n: vectors.length,
    valid_n: vectors.filter((vector) => vector.expected === 'valid').length,
    invalid_n: vectors.filter((vector) => vector.expected === 'invalid').length,
    authority_profiles: ['master_signed_recall_grant', 'housekeeper_system_principal'],
    failure_codes: MUTMEM_PORTABLE_PREDICATE_CODES_V2,
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
  const jsonTmp = `${JSON_FILE}.tmp-${process.pid}`;
  const hashTmp = `${HASH_FILE}.tmp-${process.pid}`;
  await writeFile(jsonTmp, bytes, { mode: 0o644 });
  await writeFile(hashTmp, `${fileHash}  vectors.json\n`, { mode: 0o644 });
  await rename(jsonTmp, JSON_FILE);
  await rename(hashTmp, HASH_FILE);
  console.log(JSON.stringify({
    success: true,
    file: JSON_FILE,
    file_sha256: fileHash,
    manifest_sha256: manifest.manifest_sha256,
    vectors_root_sha256: manifest.vectors_root_sha256,
    intended_n: manifest.intended_n,
    valid_n: manifest.valid_n,
    invalid_n: manifest.invalid_n,
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
});
