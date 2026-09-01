import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  MUTMEM_RECALL_RESULT_KINDS_V2,
  MUTMEM_RECALL_SINGLETON_KINDS_V2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import {
  MUTMEM_PORTABLE_DOMAIN_HEX_V2,
  MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2,
  MUTMEM_PORTABLE_PREDICATE_CODES_V2,
  evaluateMutMemPortablePredicatesV2,
} from '../../services/security/protocol/mutmem-portable-predicates-v2.js';
import {
  MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2,
  MUTMEM_PORTABLE_MUTATION_V2,
  evaluateMutMemPortableMutationBundleV2,
} from '../../services/security/protocol/mutmem-portable-mutation-v2.js';

const ROOT = path.resolve(new URL('../..', import.meta.url).pathname);
const MANIFEST = new URL('../../verifiers/mutmem-conformance/v2/protocol-manifest.json', import.meta.url);
const LIVE = new URL('../../verifiers/mutmem-conformance/v2/live-projection.json', import.meta.url);
const VECTORS = new URL('../../verifiers/mutmem-conformance/v2/vectors.json', import.meta.url);
const MUTATION_VECTORS = new URL(
  '../../verifiers/mutmem-conformance/v2/mutation-vectors.json',
  import.meta.url,
);
const LIVE_MUTATION = new URL(
  '../../verifiers/mutmem-conformance/v2/live-mutation-projections.json',
  import.meta.url,
);
const sha = (value) => createHash('sha256').update(value).digest('hex');

async function verifiedGeneratedFile(file) {
  const bytes = await readFile(file);
  const hashLine = await readFile(new URL(`${file.href}.sha256`), 'utf8');
  const [expected, name] = hashLine.trim().split(/\s+/);
  assert.equal(name, path.basename(file.pathname));
  assert.equal(sha(bytes), expected);
  return { bytes, value: JSON.parse(bytes.toString('utf8')) };
}

test('P1 protocol manifest is self-hashed and binds exact schemas, domains, and ordering', async () => {
  const { value: manifest } = await verifiedGeneratedFile(MANIFEST);
  const { protocol_root_sha256: root, ...unsigned } = manifest;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), root);
  assert.equal(manifest.status, 'p1_protocol_versioned');
  assert.deepEqual(manifest.schemas, MUTMEM_PORTABLE_OBJECT_SCHEMAS_V2);
  assert.equal(new Set(Object.values(manifest.schemas)).size, Object.keys(manifest.schemas).length);
  assert.deepEqual(manifest.domain_hex, MUTMEM_PORTABLE_DOMAIN_HEX_V2);
  assert.deepEqual(manifest.singleton_order, MUTMEM_RECALL_SINGLETON_KINDS_V2);
  assert.deepEqual(manifest.result_object_order, MUTMEM_RECALL_RESULT_KINDS_V2);
  assert.deepEqual(manifest.failure_codes, MUTMEM_PORTABLE_PREDICATE_CODES_V2);
  assert.equal(manifest.object_count_formula, '13 + 5 * result_count');
  assert.equal(manifest.production_runtime_importers, 0);
  assert.equal(manifest.mutation_profile.schema, MUTMEM_PORTABLE_MUTATION_V2.schema);
  assert.equal(manifest.mutation_profile.native_outcome_schema,
    'hom.aimos.mutation-outcome-evidence/v2');
  assert.deepEqual(manifest.mutation_profile.failure_codes,
    MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2);
});

test('P1 mutation vectors preserve the native outcome and cover every terminal/failure', async () => {
  const [{ value: manifest }, { bytes, value: vectors }] = await Promise.all([
    verifiedGeneratedFile(MANIFEST), verifiedGeneratedFile(MUTATION_VECTORS),
  ]);
  assert.equal(sha(bytes), manifest.mutation_profile.vectors.file_sha256);
  assert.equal(vectors.intended_n, 15);
  assert.equal(vectors.valid_n, 3);
  assert.equal(vectors.invalid_n, 12);
  assert.deepEqual(vectors.failure_codes, MUTMEM_PORTABLE_MUTATION_FAILURE_CODES_V2);
  for (const vector of vectors.vectors) {
    try {
      const result = evaluateMutMemPortableMutationBundleV2(vector.bundle);
      assert.equal(vector.expected, 'valid', vector.id);
      assert.equal(result.valid, true, vector.id);
      assert.equal(result.native_outcome_schema_preserved, true, vector.id);
    } catch (error) {
      assert.equal(vector.expected, 'invalid', vector.id);
      assert.equal(
        String(error.message).replace('mutmem_portable_mutation_v2:', ''),
        vector.reason,
        vector.id,
      );
    }
  }
});

test('P1 live mutation record covers transition, no-op, and observation without mutation', async () => {
  const [{ value: manifest }, { bytes, value: live }] = await Promise.all([
    verifiedGeneratedFile(MANIFEST), verifiedGeneratedFile(LIVE_MUTATION),
  ]);
  const { manifest_sha256: liveRoot, ...unsigned } = live;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), liveRoot);
  assert.equal(sha(bytes), manifest.mutation_profile.live_projection.file_sha256);
  assert.deepEqual([...live.terminal_kinds].sort(),
    ['authorized_transition', 'occurrence_observation', 'signed_noop']);
  assert.equal(live.bundle_sha256s.length, 3);
  assert.equal(live.private_artifact_distributed, false);
  assert.equal(live.memory_write, false);
  assert.equal(live.domain_database_mutation, false);
});

test('P1 protocol manifest binds every source file and the exact source root', async () => {
  const { value: manifest } = await verifiedGeneratedFile(MANIFEST);
  const actual = [];
  for (const entry of manifest.source_files) {
    const bytes = await readFile(path.join(ROOT, entry.path));
    assert.equal(sha(bytes), entry.sha256, entry.path);
    actual.push({ path: entry.path, sha256: entry.sha256 });
  }
  assert.equal(sha(Buffer.from(canonicalJson(actual), 'utf8')), manifest.source_root_sha256);
});

test('P1 static vectors are denominator-complete and reconstruct every declared terminal', async () => {
  const [{ value: manifest }, { bytes, value: vectors }] = await Promise.all([
    verifiedGeneratedFile(MANIFEST), verifiedGeneratedFile(VECTORS),
  ]);
  assert.equal(sha(bytes), manifest.vectors.file_sha256);
  assert.equal(vectors.intended_n, 39);
  assert.equal(vectors.valid_n, 2);
  assert.equal(vectors.invalid_n, MUTMEM_PORTABLE_PREDICATE_CODES_V2.length);
  assert.equal(vectors.vectors_root_sha256, manifest.vectors.vectors_root_sha256);
  for (const vector of vectors.vectors) {
    try {
      const result = evaluateMutMemPortablePredicatesV2(vector.bundle);
      assert.equal(vector.expected, 'valid', vector.id);
      assert.equal(result.valid, true, vector.id);
    } catch (error) {
      assert.equal(vector.expected, 'invalid', vector.id);
      assert.equal(
        String(error.message).replace('mutmem_portable_predicates_v2:', ''),
        vector.reason,
        vector.id,
      );
    }
  }
});

test('P1 live projection public record binds the private proof without distributing it', async () => {
  const [{ value: manifest }, { bytes, value: live }] = await Promise.all([
    verifiedGeneratedFile(MANIFEST), verifiedGeneratedFile(LIVE),
  ]);
  const { manifest_sha256: liveRoot, ...unsigned } = live;
  assert.equal(sha(Buffer.from(canonicalJson(unsigned), 'utf8')), liveRoot);
  assert.equal(sha(bytes), manifest.live_projection.file_sha256);
  assert.equal(live.event_id, manifest.live_projection.event_id);
  assert.equal(live.bundle_sha256, manifest.live_projection.bundle_sha256);
  assert.equal(live.object_root_sha256, manifest.live_projection.object_root_sha256);
  assert.equal(live.occurrence_form, 'v3');
  assert.equal(live.private_artifact_distributed, false);
  assert.equal(live.memory_write, false);
  assert.equal(live.domain_database_mutation, false);
  assert.doesNotMatch(JSON.stringify(live), /\/Users\/|private.*path|memory_value/i);
});

test('P1 retired executable files and clone authority remain absent', async () => {
  for (const relative of [
    'scripts/ceremony/cognitive-roundtrip.mjs',
    'scripts/ceremony/authorize-mutmem-v2-s7-pre-outcome-repair.mjs',
  ]) {
    await assert.rejects(access(path.join(ROOT, relative)));
  }
  const runner = await readFile(path.join(ROOT, 'scripts/benchmark/run-isolated.mjs'), 'utf8');
  assert.doesNotMatch(runner,
    /mutmem-v2-s7|MUTMEM_V2_S7|successor_corpus|bound-clone|database_clone/i);
});
