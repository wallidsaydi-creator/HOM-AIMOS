import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  AIMOS_USER_SERVICE_LABEL,
  AIMOS_USER_SERVICE_SCHEMA,
  buildUserServiceDefinition,
  buildUserServiceManifest,
  installUserService,
  serviceReadinessMatches,
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

test('service owner waits for complete unload before replacing a unit', async () => {
  const source = await import('node:fs').then(({ readFileSync }) => readFileSync(
    new URL('../../scripts/service/manage-user-service.mjs', import.meta.url),
    'utf8',
  ));
  assert.match(source, /waitForLaunchdUnloaded\(definition\)/);
  assert.match(source, /aimos_user_service_unload_timeout/);
});

test('readiness requires the configured PostgreSQL port', () => {
  const definition = buildUserServiceDefinition({
    sourceRoot: ROOT, nodePath: process.execPath, platform: 'darwin',
    homeDirectory: FIXTURE_HOME, postgresPort: 55432, postgresBin: '/test-pg/bin',
  });
  const health = { ready: true, runtime: {
    database_name: 'aimos', server_port: 9100, postgres_port: 5432,
  } };
  assert.equal(serviceReadinessMatches(definition, health), false);
  health.runtime.postgres_port = 55432;
  assert.equal(serviceReadinessMatches(definition, health), true);
});

test('failed private-port install restores and restarts the previous canonical unit', async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'aimos-service-rollback-'));
  try {
    const common = { sourceRoot: ROOT, nodePath: process.execPath,
      platform: 'darwin', homeDirectory: home };
    const oldDefinition = buildUserServiceDefinition(common);
    const oldManifest = `${JSON.stringify(buildUserServiceManifest(oldDefinition), null, 2)}\n`;
    mkdirSync(path.dirname(oldDefinition.unit_path), { recursive: true, mode: 0o700 });
    mkdirSync(path.dirname(oldDefinition.manifest_path), { recursive: true, mode: 0o700 });
    writeFileSync(oldDefinition.unit_path, oldDefinition.unit_body, { mode: 0o600 });
    writeFileSync(oldDefinition.manifest_path, oldManifest, { mode: 0o600 });
    const stops = [];
    const starts = [];
    await assert.rejects(installUserService({ ...common,
      postgresPort: 55432, postgresBin: '/test-pg/bin',
    }, {
      isRunning: () => true,
      stop: (definition) => stops.push(definition.postgres_port),
      start: (definition) => starts.push(definition.postgres_port),
      waitReady: async (definition) => {
        if (definition.postgres_port === 55432) throw new Error('private_target_unready');
        return { ready: true };
      },
    }), /private_target_unready/);
    assert.deepEqual(stops, [55432, 55432]);
    assert.deepEqual(starts, [55432, 5432]);
    assert.equal(readFileSync(oldDefinition.unit_path, 'utf8'), oldDefinition.unit_body);
    assert.equal(readFileSync(oldDefinition.manifest_path, 'utf8'), oldManifest);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('failed first install removes its unit and manifest', async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'aimos-service-first-failure-'));
  try {
    const options = { sourceRoot: ROOT, nodePath: process.execPath,
      platform: 'darwin', homeDirectory: home,
      postgresPort: 55432, postgresBin: '/test-pg/bin' };
    const definition = buildUserServiceDefinition(options);
    await assert.rejects(installUserService(options, {
      stop: () => {}, start: () => {},
      waitReady: async () => { throw new Error('first_install_unready'); },
    }), /first_install_unready/);
    assert.equal(existsSync(definition.unit_path), false);
    assert.equal(existsSync(definition.manifest_path), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('failed stop during rollback still restores the prior unit files', async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'aimos-service-stop-failure-'));
  try {
    const common = { sourceRoot: ROOT, nodePath: process.execPath,
      platform: 'darwin', homeDirectory: home };
    const oldDefinition = buildUserServiceDefinition(common);
    const oldManifest = `${JSON.stringify(buildUserServiceManifest(oldDefinition), null, 2)}\n`;
    mkdirSync(path.dirname(oldDefinition.unit_path), { recursive: true, mode: 0o700 });
    mkdirSync(path.dirname(oldDefinition.manifest_path), { recursive: true, mode: 0o700 });
    writeFileSync(oldDefinition.unit_path, oldDefinition.unit_body, { mode: 0o600 });
    writeFileSync(oldDefinition.manifest_path, oldManifest, { mode: 0o600 });
    let stops = 0;
    await assert.rejects(installUserService({ ...common,
      postgresPort: 55432, postgresBin: '/test-pg/bin',
    }, {
      isRunning: () => true,
      stop: () => { if (++stops === 2) throw new Error('replacement_stop_failed'); },
      start: () => {},
      waitReady: async () => { throw new Error('private_target_unready'); },
    }), /aimos_service_install_and_rollback_failed/);
    assert.equal(readFileSync(oldDefinition.unit_path, 'utf8'), oldDefinition.unit_body);
    assert.equal(readFileSync(oldDefinition.manifest_path, 'utf8'), oldManifest);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
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
    postgresBin: '/test-pg/bin',
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

test('canonical service retains a private PostgreSQL port across manifest reload', () => {
  const definition = buildUserServiceDefinition({
    sourceRoot: ROOT,
    nodePath: process.execPath,
    platform: 'darwin',
    homeDirectory: FIXTURE_HOME,
    postgresPort: 55432,
    postgresBin: '/test-pg/bin',
  });
  const manifest = buildUserServiceManifest(definition);
  assert.equal(manifest.postgres_port, 55432);
  const rebuilt = validateUserServiceManifest(manifest, { homeDirectory: FIXTURE_HOME });
  assert.equal(rebuilt.postgres_port, 55432);
  assert.match(rebuilt.unit_body, /--aimos-postgres-port/);
  assert.match(rebuilt.unit_body, /55432/);
});

test('service definition rejects unsafe database, port and unsupported platform', () => {
  const common = { sourceRoot: ROOT, nodePath: process.execPath, homeDirectory: os.homedir() };
  assert.throws(() => buildUserServiceDefinition({ ...common, database: 'oracle' }), /database_invalid/);
  assert.throws(() => buildUserServiceDefinition({ ...common, port: 9000 }), /port_invalid/);
  assert.throws(() => buildUserServiceDefinition({ ...common, platform: 'aix' }), /platform_unsupported/);
});
