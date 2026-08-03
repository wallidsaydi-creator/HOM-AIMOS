import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { collectServiceCensus } from '../../scripts/architecture/sync-service-inventory.mjs';
import { PIPELINES } from '../../services/pipeline-manifest.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const template = JSON.parse(fs.readFileSync(path.join(root, 'architecture-authority.template.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'hom-architecture-manifest.json'), 'utf8'));

test('service manifest is exact set-equality with the live 275-service census', () => {
  const census = collectServiceCensus(root);
  const manifestFiles = Object.entries(manifest.service_inventory.groups)
    .flatMap(([group, entry]) => entry.files.map((file) => `services/${group}/${file}`))
    .sort();

  assert.equal(census.groupCount, 17);
  assert.equal(census.serviceCount, 275);
  assert.equal(census.digest, '9ae9e86daec8b420da768ab523e13cbfe2072c812a8d34d564ea8c315ce10095');
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
  const tier4 = fs.readFileSync(path.join(root, 'Guide', 'aimos-guide-tier4-debug.md'), 'utf8');
  const llmGuide = fs.readFileSync(path.join(root, 'Guide', 'aimos-llm-guide.md'), 'utf8');
  const pipelineSource = fs.readFileSync(path.join(root, 'services', 'pipeline-manifest.js'), 'utf8');

  assert.match(architectureMap, new RegExp(`Service census: ${census.serviceCount} JavaScript services across ${census.groupCount} groups`));
  assert.match(architectureMap, new RegExp(`\\| integrations \\| ${census.groups.integrations.length} \\|`));
  assert.match(architectureMap, new RegExp(`declares ${connectionCount} service connections across ${pipelineCount} pipelines`));

  for (const guide of [tier4, llmGuide]) {
    assert.match(guide, new RegExp(`binds ${census.serviceCount} service files`));
    assert.match(guide, new RegExp(`${connectionCount} declared service connections across ${pipelineCount} pipelines`));
    assert.doesNotMatch(guide, /runWeeklyReflection|weekly-reflection/);
  }
  assert.match(pipelineSource, new RegExp(`\\b${pipelineCount === 6 ? 'six' : pipelineCount} canonical runtime pipelines\\b`));
});

test('portable authority contains no stale Oracle/private file-memory declarations', () => {
  const source = JSON.stringify(template);
  assert.doesNotMatch(source, /\.claude\/settings|directives\.json|session-journals|daily-ledgers|deep-memory|hom-cloud|hom-cli/);
  assert.equal(template.governance.environment_configuration_authoritative, false);
  assert.equal(template.governance.oracle_runtime_authoritative, false);
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
  assert.equal(runtime.service_inventory.counted_service_files, 275);
});
