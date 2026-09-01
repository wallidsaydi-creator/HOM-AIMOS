import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  AIMOS_USER_SERVICE_LABEL,
  AIMOS_USER_SERVICE_SCHEMA,
  buildUserServiceDefinition,
  buildUserServiceManifest,
  validateUserServiceManifest,
} from '../../scripts/service/manage-user-service.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE_HOME = '/test-home';

test('macOS user service owns one native process without secret authority', () => {
  const definition = buildUserServiceDefinition({
    sourceRoot: ROOT,
    nodePath: process.execPath,
    platform: 'darwin',
    homeDirectory: FIXTURE_HOME,
  });
  assert.equal(definition.schema, AIMOS_USER_SERVICE_SCHEMA);
  assert.equal(definition.label, AIMOS_USER_SERVICE_LABEL);
  assert.equal(definition.secrets_in_service_definition, false);
  assert.equal(definition.log_rotation_max_bytes, 10 * 1024 * 1024);
  assert.equal(definition.log_rotation_generations, 3);
  assert.match(definition.unit_path, /Library\/LaunchAgents\/com\.hom\.aimos\.plist$/);
  assert.match(definition.unit_body, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(definition.unit_body, /<key>SuccessfulExit<\/key><false\/>/);
  assert.match(definition.unit_body, /<key>ThrottleInterval<\/key><integer>10<\/integer>/);
  assert.doesNotMatch(definition.unit_body, /<key>ProcessType<\/key>/);
  assert.match(definition.unit_body, new RegExp(process.execPath.replaceAll('/', '\\/')));
  assert.match(definition.unit_body, /--aimos-db/);
  assert.match(definition.unit_body, /--aimos-port/);
  assert.doesNotMatch(definition.unit_body, /passphrase|private.?key|keychain|process\.env|EnvironmentVariables/i);
});

test('service owner waits for complete unload and cleans failed readiness', async () => {
  const source = await import('node:fs').then(({ readFileSync }) => readFileSync(
    new URL('../../scripts/service/manage-user-service.mjs', import.meta.url),
    'utf8',
  ));
  assert.match(source, /waitForLaunchdUnloaded\(definition\)/);
  assert.match(source, /aimos_user_service_unload_timeout/);
  assert.ok((source.match(/catch \(error\) \{\n\s+stopDefinition\(definition\);/g) || []).length >= 3);
});

test('Linux user service implements the same on-failure lifecycle contract', () => {
  const definition = buildUserServiceDefinition({
    sourceRoot: ROOT,
    nodePath: process.execPath,
    platform: 'linux',
    homeDirectory: FIXTURE_HOME,
  });
  assert.match(definition.unit_path, /\.config\/systemd\/user\/hom-aimos\.service$/);
  assert.match(definition.unit_body, /Restart=on-failure/);
  assert.match(definition.unit_body, /RestartSec=10/);
  assert.match(definition.unit_body, /WantedBy=default\.target/);
  assert.match(definition.unit_body, /server\.js/);
  assert.doesNotMatch(definition.unit_body, /Environment=|passphrase|private.?key|keychain/i);
});

test('named installation service is disjoint while canonical defaults stay unchanged', () => {
  const definition = buildUserServiceDefinition({
    sourceRoot: ROOT,
    nodePath: process.execPath,
    platform: 'darwin',
    homeDirectory: FIXTURE_HOME,
    database: 'aimos_p3_repro',
    port: 9303,
    instance: 'p3_repro',
    postgresPort: 55432,
  });
  assert.equal(definition.label, 'com.hom.aimos.p3_repro');
  assert.equal(definition.state_root, '/test-home/.aimos/instances/p3_repro/service');
  assert.equal(definition.log_root, '/test-home/.aimos/instances/p3_repro/logs');
  assert.match(definition.unit_path, /com\.hom\.aimos\.p3_repro\.plist$/);
  assert.match(definition.unit_body, /--aimos-instance/);
  assert.match(definition.unit_body, /p3_repro/);
  assert.match(definition.unit_body, /--aimos-postgres-port/);
  assert.match(definition.unit_body, /55432/);
  const manifest = buildUserServiceManifest(definition);
  const rebuilt = validateUserServiceManifest(manifest, { homeDirectory: FIXTURE_HOME });
  assert.equal(rebuilt.installation_context_sha256, definition.installation_context_sha256);
  assert.equal(rebuilt.postgres_port, 55432);
  assert.equal(rebuilt.unit_path, definition.unit_path);
});

test('service definition rejects unsafe database, port and unsupported platform', () => {
  const common = { sourceRoot: ROOT, nodePath: process.execPath, homeDirectory: os.homedir() };
  assert.throws(() => buildUserServiceDefinition({ ...common, database: 'oracle' }), /database_invalid/);
  assert.throws(() => buildUserServiceDefinition({ ...common, port: 9000 }), /port_invalid/);
  assert.throws(() => buildUserServiceDefinition({ ...common, platform: 'aix' }), /platform_unsupported/);
});
