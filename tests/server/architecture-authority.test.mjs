import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { collectServiceCensus } from '../../scripts/architecture/sync-service-inventory.mjs';
import { PIPELINES } from '../../services/pipeline-manifest.js';
import { verifyGenesisManifest } from '../../scripts/verify-genesis-manifest.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const template = JSON.parse(fs.readFileSync(path.join(root, 'architecture-authority.template.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'hom-architecture-manifest.json'), 'utf8'));

test('service manifest is exact set-equality with the live 295-service census', () => {
  const census = collectServiceCensus(root);
  const manifestFiles = Object.entries(manifest.service_inventory.groups)
    .flatMap(([group, entry]) => entry.files.map((file) => `services/${group}/${file}`))
    .sort();

  assert.equal(census.groupCount, 17);
  assert.equal(census.serviceCount, 295);
  assert.equal(census.digest, 'a001876ec9e5f503247b55479ec9ad7d4a8bab65f01582fd3060321bdb3ded4c');
  assert.deepEqual(manifestFiles, census.files);
  assert.equal(manifest.total_services, census.serviceCount);
  assert.equal(manifest.service_inventory.counted_service_files, census.serviceCount);
  assert.equal(manifest.service_inventory.census_sha256, census.digest);
  assert.equal(template.service_inventory.counted_service_files, census.serviceCount);
  assert.equal(template.service_inventory.census_sha256, census.digest);
});

test('current public architecture accounting matches the live service and pipeline manifests', () => {
  const census = collectServiceCensus(root);
  const pipelineCount = Object.keys(PIPELINES).length;
  const connectionCount = Object.values(PIPELINES)
    .reduce((total, pipeline) => total + pipeline.services.length, 0);
  const architectureMap = fs.readFileSync(path.join(root, 'ARCHITECTURE-MAP.md'), 'utf8');
  const pipelineSource = fs.readFileSync(path.join(root, 'services', 'pipeline-manifest.js'), 'utf8');

  assert.match(architectureMap, new RegExp(`Service census: ${census.serviceCount} JavaScript services across ${census.groupCount} groups`));
  assert.match(architectureMap, new RegExp(`\\| integrations \\| ${census.groups.integrations.length} \\|`));
  assert.match(architectureMap, new RegExp(`declares ${connectionCount} service connections across ${pipelineCount} pipelines`));
  assert.equal(manifest.architecture.pipeline_manifest.validated_connections, connectionCount);
  assert.equal(manifest.architecture.pipeline_manifest.pipelines, pipelineCount);

  // The installed Guide is a signed, versioned corpus, not a mutable service
  // counter. Current code is checked above; Guide byte integrity is checked
  // independently so adding a service cannot force an unadmitted corpus edit.
  const guide = verifyGenesisManifest({ brainRoot: root });
  assert.equal(guide.version, template.genesis_corpus.version);
  assert.equal(guide.corpusRoot, template.genesis_corpus.corpus_root);
  assert.match(pipelineSource, new RegExp(`\\b${pipelineCount === 6 ? 'six' : pipelineCount} canonical runtime pipelines\\b`));
});

test('portable authority contains no stale predecessor/private file-memory declarations', () => {
  const source = JSON.stringify(template);
  assert.doesNotMatch(source, /\.claude\/settings|directives\.json|session-journals|daily-ledgers|deep-memory|hom-cloud|hom-cli/);
  assert.equal(template.governance.environment_configuration_authoritative, false);
  assert.equal(template.governance.legacy_runtime_authoritative, false);
  assert.deepEqual(template.path_authority.stale_aliases, []);
  assert.deepEqual(template.path_authority.runtime_created_path_keys, ['meta_improvement_root']);
  assert.ok(!template.path_authority.required_static_path_keys.includes('meta_improvement_root'));
});

test('authority dry run binds current static authority, Genesis root, and service census', () => {
  const output = execFileSync(process.execPath, [
    path.join(root, 'scripts/identity/init-architecture-authority.js'),
    '--dry-run',
  ], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const runtime = JSON.parse(output);
  assert.equal(runtime.runtime_mode, 'runtime');
  assert.equal(runtime.genesis_corpus.verified_during_generation, true);
  assert.equal(runtime.service_inventory.verified_during_generation, true);
  assert.equal(runtime.service_inventory.counted_service_files, 295);
});
