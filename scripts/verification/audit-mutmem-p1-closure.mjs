#!/usr/bin/env node

// Independent P1 closure audit. Uses Node built-ins only and does not import
// the P1 protocol owners whose output it audits.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const V2 = path.join(ROOT, 'verifiers/mutmem-conformance/v2');
const MANIFEST_FILE = path.join(V2, 'protocol-manifest.json');
const VECTOR_FILE = path.join(V2, 'vectors.json');
const LIVE_FILE = path.join(V2, 'live-projection.json');
const MUTATION_VECTOR_FILE = path.join(V2, 'mutation-vectors.json');
const LIVE_MUTATION_FILE = path.join(V2, 'live-mutation-projections.json');
const RETIRED = [
  'scripts/ceremony/cognitive-roundtrip.mjs',
  'scripts/ceremony/authorize-mutmem-v2-s7-pre-outcome-repair.mjs',
];

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonical(value, depth = 0) {
  if (depth > 32) throw new Error('p1_audit_canonical_depth');
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new Error('p1_audit_canonical_number');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonical(entry, depth + 1)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`,
    ).join(',')}}`;
  }
  throw new Error('p1_audit_canonical_type');
}

function json(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function verifyGenerated(file) {
  const bytes = readFileSync(file);
  const [expected, name] = readFileSync(`${file}.sha256`, 'utf8').trim().split(/\s+/);
  assert.equal(name, path.basename(file));
  assert.equal(sha(bytes), expected);
  return { value: JSON.parse(bytes.toString('utf8')), file_sha256: expected };
}

function walk(directory, output = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute, output);
    else if (entry.isFile() && /\.(?:m?js)$/.test(entry.name)) output.push(absolute);
  }
  return output;
}

function productionImporters() {
  const files = [path.join(ROOT, 'server.js')];
  for (const directory of ['routes', 'jobs', 'services']) files.push(...walk(path.join(ROOT, directory)));
  return files.filter((file) => {
    const relative = path.relative(ROOT, file);
    if (relative.startsWith('services/security/protocol/')) return false;
    return /mutmem-portable-(?:evidence|predicates)-v2\.js/.test(readFileSync(file, 'utf8'));
  }).map((file) => path.relative(ROOT, file));
}

async function main() {
  const [manifestRecord, vectorRecord, liveRecord, mutationVectorRecord,
    liveMutationRecord] = [
    verifyGenerated(MANIFEST_FILE),
    verifyGenerated(VECTOR_FILE),
    verifyGenerated(LIVE_FILE),
    verifyGenerated(MUTATION_VECTOR_FILE),
    verifyGenerated(LIVE_MUTATION_FILE),
  ];
  const manifest = manifestRecord.value;
  const vectors = vectorRecord.value;
  const live = liveRecord.value;
  const mutationVectors = mutationVectorRecord.value;
  const liveMutation = liveMutationRecord.value;
  const { protocol_root_sha256: protocolRoot, ...protocolUnsigned } = manifest;
  assert.equal(sha(Buffer.from(canonical(protocolUnsigned), 'utf8')), protocolRoot);
  const { manifest_sha256: vectorManifestHash, ...vectorUnsigned } = vectors;
  assert.equal(sha(Buffer.from(canonical(vectorUnsigned), 'utf8')), vectorManifestHash);
  const { manifest_sha256: liveManifestHash, ...liveUnsigned } = live;
  assert.equal(sha(Buffer.from(canonical(liveUnsigned), 'utf8')), liveManifestHash);

  assert.equal(manifest.status, 'p1_protocol_versioned');
  assert.equal(Object.keys(manifest.schemas).length, 18);
  assert.equal(new Set(Object.values(manifest.schemas)).size, 18);
  assert.equal(manifest.singleton_order.length, 13);
  assert.equal(manifest.result_object_order.length, 5);
  assert.equal(manifest.failure_codes.length, 37);
  assert.equal(new Set(manifest.failure_codes).size, 37);
  assert.equal(vectors.intended_n, 39);
  assert.equal(vectors.valid_n, 2);
  assert.equal(vectors.invalid_n, 37);
  assert.deepEqual(
    [...vectors.vectors.filter((vector) => vector.expected === 'invalid')
      .map((vector) => vector.reason).sort()],
    [...manifest.failure_codes].sort(),
  );
  assert.equal(vectorRecord.file_sha256, manifest.vectors.file_sha256);
  assert.equal(vectors.vectors_root_sha256, manifest.vectors.vectors_root_sha256);

  assert.equal(live.event_id, manifest.live_projection.event_id);
  assert.equal(live.bundle_sha256, manifest.live_projection.bundle_sha256);
  assert.equal(live.object_root_sha256, manifest.live_projection.object_root_sha256);
  assert.equal(live.occurrence_form, 'v3');
  assert.equal(live.object_count, 18);
  assert.equal(live.reference_predicates_valid, true);
  assert.equal(live.private_artifact_distributed, false);
  assert.equal(live.memory_write, false);
  assert.equal(live.domain_database_mutation, false);

  assert.equal(manifest.mutation_profile.native_outcome_schema,
    'hom.aimos.mutation-outcome-evidence/v2');
  assert.equal(manifest.mutation_profile.failure_codes.length, 12);
  assert.equal(mutationVectors.intended_n, 15);
  assert.equal(mutationVectors.valid_n, 3);
  assert.equal(mutationVectors.invalid_n, 12);
  assert.deepEqual(
    mutationVectors.vectors.filter((vector) => vector.expected === 'invalid')
      .map((vector) => vector.reason).sort(),
    [...manifest.mutation_profile.failure_codes].sort(),
  );
  assert.deepEqual([...liveMutation.terminal_kinds].sort(),
    ['authorized_transition', 'occurrence_observation', 'signed_noop']);
  assert.equal(liveMutation.bundle_sha256s.length, 3);
  assert.equal(liveMutation.private_artifact_distributed, false);
  assert.equal(liveMutation.memory_write, false);
  assert.equal(liveMutation.domain_database_mutation, false);

  const sources = manifest.source_files.map((entry) => {
    const bytes = readFileSync(path.join(ROOT, entry.path));
    assert.equal(sha(bytes), entry.sha256, entry.path);
    return entry;
  });
  assert.equal(sha(Buffer.from(canonical(sources), 'utf8')), manifest.source_root_sha256);
  assert.deepEqual(productionImporters(), []);
  for (const relative of RETIRED) assert.equal(existsSync(path.join(ROOT, relative)), false);
  const benchmark = readFileSync(path.join(ROOT, 'scripts/benchmark/run-isolated.mjs'), 'utf8');
  assert.doesNotMatch(benchmark,
    /mutmem-v2-s7|MUTMEM_V2_S7|successor_corpus|bound-clone|database_clone/i);
  assert.equal(statSync(MANIFEST_FILE).isFile(), true);

  const health = await fetch('http://127.0.0.1:9100/health', {
    signal: AbortSignal.timeout(5000),
  }).then((response) => response.json());
  assert.equal(health.ready, true);
  assert.equal(health.runtime?.tenant_dependency ?? health.readiness?.scheduler?.tenant_dependency, false);

  const exitCriteria = {
    versioned_schemas_unique: true,
    domain_bytes_bound: true,
    authority_profiles_bound: true,
    failure_vectors_complete: true,
    live_native_v3_projection_valid: true,
    mutation_outcome_schema_preserved: true,
    mutation_terminal_classes_complete: true,
    retired_clone_and_mutation_paths_absent: true,
    production_runtime_unchanged: true,
    source_identity_bound: true,
  };
  console.log(JSON.stringify({
    success: true,
    status: 'P1_EXIT_CRITERIA_PASS',
    protocol_root_sha256: protocolRoot,
    protocol_manifest_file_sha256: manifestRecord.file_sha256,
    source_root_sha256: manifest.source_root_sha256,
    vectors_root_sha256: vectors.vectors_root_sha256,
    live_bundle_sha256: live.bundle_sha256,
    exit_criteria: exitCriteria,
    exit_criteria_passed: Object.values(exitCriteria).every(Boolean),
  }, null, 2));
}

main().catch((error) => {
  console.error(`[FATAL] ${error.message}`);
  process.exitCode = 1;
});
