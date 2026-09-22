import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/origin-binding/v1');
const GENERATED = Object.freeze([
  'family-profile.json',
  'vectors.json',
  'source-census.json',
  'source-manifest.json',
  'protocol-manifest.json',
]);

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function json(name) {
  return JSON.parse(await readFile(path.join(OUTPUT, name), 'utf8'));
}

test('OB-1 frozen manifest preserves the non-runtime authority boundary', async () => {
  const manifest = await json('protocol-manifest.json');
  assert.equal(manifest.schema, 'hom.aimos.origin-binding-protocol-manifest/v1');
  assert.equal(manifest.status, 'ob1_protocol_frozen');
  assert.equal(manifest.ob1_closed, true);
  assert.equal(manifest.family_profile.family_count, 30);
  assert.equal(manifest.vectors.valid_n, 6);
  assert(manifest.vectors.invalid_n >= 16);
  assert.deepEqual(manifest.production_runtime_importers, []);
  assert.equal(manifest.database_mutation, false);
  assert.equal(manifest.runtime_activation, false);
  assert.equal(manifest.memory_write, false);
  assert.equal(manifest.next_required_owner, 'OB-2_ATOMIC_ORIGIN_FAMILY_LEDGER');
});

test('OB-1 frozen census retains every enumerated direct production memory read at freeze time', async () => {
  const census = await json('source-census.json');
  assert.equal(census.schema, 'hom.aimos.origin-binding-source-census/v1');
  assert.equal(census.direct_memory_read_file_count, 77);
  assert.equal(census.direct_memory_read_site_count, 243);
  assert(census.model_or_action_influencing_site_count >= 40);
  assert.equal(census.direct_memory_read_sites.length, census.direct_memory_read_site_count);
  assert(census.direct_memory_read_sites.every((site) => site.classification && site.closure_owner));
  assert(census.direct_memory_read_sites.some((site) => (
    site.file === 'services/orchestration/agent-prompts.js'
      && site.classification === 'MODEL_VISIBLE_DIRECT_READ'
      && site.closure_owner === 'OB-4'
  )));
  assert(census.direct_memory_read_sites.some((site) => (
    site.file === 'services/orchestration/agent-runner.js'
      && site.classification === 'MODEL_AND_ACTION_INFLUENCING_DIRECT_READ'
      && site.closure_owner === 'OB-4/OB-5'
  )));
});

test('OB-1 Python verifier independently reproduces the frozen protocol artifacts', () => {
  const result = spawnSync(
    'python3',
    ['verifiers/origin-binding/v1/verify.py', '--artifacts-only'],
    { cwd: ROOT, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.success, true);
  assert.equal(output.status, 'OB1_INDEPENDENT_FROZEN_PROTOCOL_VERIFIED');
  assert(output.vectors_verified >= 22);
  assert.equal(output.direct_memory_read_sites_verified, 243);
});

test('OB-1 artifact checksum sidecars bind exact files', async () => {
  for (const name of GENERATED) {
    const bytes = await readFile(path.join(OUTPUT, name));
    const sidecar = (await readFile(path.join(OUTPUT, `${name}.sha256`), 'utf8')).trim();
    assert.equal(sidecar, `${sha(bytes)}  ${name}`);
  }
});
