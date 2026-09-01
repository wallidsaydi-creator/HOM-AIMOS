#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  CANONICAL_USER_SERVICE_LABEL,
  resolveAimosInstallationContext,
} from '../../services/installation-context.js';

export const AIMOS_USER_SERVICE_SCHEMA = 'hom.aimos.user-service/v1';
export const AIMOS_USER_SERVICE_LABEL = CANONICAL_USER_SERVICE_LABEL;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PROTECTED_DATABASES = new Set(['oracle', 'aimos_dev', 'postgres', 'template0', 'template1']);

function fail(code) {
  throw new Error(code);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function cliValue(argv, name) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function requireRegularFile(target, code) {
  const resolved = realpathSync(path.resolve(target));
  if (!lstatSync(resolved).isFile()) fail(code);
  return resolved;
}

function requireSourceRoot(target) {
  const resolved = realpathSync(path.resolve(target));
  if (!lstatSync(resolved).isDirectory()) fail('aimos_service_source_root_invalid');
  requireRegularFile(path.join(resolved, 'server.js'), 'aimos_service_server_missing');
  return resolved;
}

function normalizeDatabase(value) {
  const database = String(value || 'aimos').trim();
  if (!/^[a-z][a-z0-9_]*$/.test(database) || PROTECTED_DATABASES.has(database)) {
    fail('aimos_service_database_invalid');
  }
  return database;
}

function normalizePort(value) {
  const port = Number(value ?? 9100);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || [9000, 9001].includes(port)) {
    fail('aimos_service_port_invalid');
  }
  return port;
}

function xml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function systemdQuote(value) {
  const text = String(value);
  if (/[^\x20-\x7e]/.test(text)) fail('aimos_service_systemd_argument_invalid');
  return `"${text.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

export function buildUserServiceDefinition({
  sourceRoot = ROOT,
  nodePath = process.execPath,
  database = 'aimos',
  port = 9100,
  platform = process.platform,
  homeDirectory = os.homedir(),
  instance = 'canonical',
  postgresPort = 5432,
} = {}) {
  const source = requireSourceRoot(sourceRoot);
  const node = requireRegularFile(nodePath, 'aimos_service_node_invalid');
  const db = normalizeDatabase(database);
  const serverPort = normalizePort(port);
  const home = path.resolve(String(homeDirectory || ''));
  if (!path.isAbsolute(home) || home === path.parse(home).root) fail('aimos_service_home_invalid');
  const context = resolveAimosInstallationContext([
    '--aimos-instance', String(instance),
    '--aimos-postgres-port', String(postgresPort),
  ], { homeDirectory: home });
  const stateRoot = context.service_state_root;
  const logRoot = context.service_log_root;
  const runtimeArguments = [
    '--aimos-db', db,
    '--aimos-port', String(serverPort),
    ...(context.canonical ? [] : ['--aimos-instance', context.instance]),
    ...(context.postgres_port === 5432
      ? [] : ['--aimos-postgres-port', String(context.postgres_port)]),
  ];
  const common = {
    schema: AIMOS_USER_SERVICE_SCHEMA,
    label: context.user_service_label,
    instance: context.instance,
    installation_context_sha256: context.context_sha256,
    postgres_port: context.postgres_port,
    platform,
    source_root: source,
    node_path: node,
    server_path: path.join(source, 'server.js'),
    database: db,
    port: serverPort,
    state_root: stateRoot,
    log_root: logRoot,
    stdout_path: path.join(logRoot, 'server.stdout.log'),
    stderr_path: path.join(logRoot, 'server.stderr.log'),
    manifest_path: path.join(stateRoot, 'service.json'),
    restart_policy: 'on_failure',
    restart_delay_seconds: 10,
    log_rotation_max_bytes: 10 * 1024 * 1024,
    log_rotation_generations: 3,
    secrets_in_service_definition: false,
  };

  if (platform === 'darwin') {
    const unitPath = path.join(home, 'Library', 'LaunchAgents', `${context.user_service_label}.plist`);
    const argumentXml = runtimeArguments.map((value) => `<string>${xml(value)}</string>`).join('');
    const unit = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${xml(context.user_service_label)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xml(node)}</string>
    <string>${xml(common.server_path)}</string>
    ${argumentXml}
  </array>
  <key>WorkingDirectory</key><string>${xml(source)}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>${xml(common.stdout_path)}</string>
  <key>StandardErrorPath</key><string>${xml(common.stderr_path)}</string>
</dict>
</plist>
`;
    return Object.freeze({ ...common, unit_path: unitPath, unit_body: unit });
  }

  if (platform === 'linux') {
    const unitName = context.canonical ? 'hom-aimos.service' : `hom-aimos-${context.instance}.service`;
    const unitPath = path.join(home, '.config', 'systemd', 'user', unitName);
    const command = [node, common.server_path, ...runtimeArguments]
      .map(systemdQuote).join(' ');
    const unit = `[Unit]
Description=HOM-AIMOS native memory service
After=network.target

[Service]
Type=simple
WorkingDirectory=${systemdQuote(source)}
ExecStart=${command}
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=append:${common.stdout_path}
StandardError=append:${common.stderr_path}

[Install]
WantedBy=default.target
`;
    return Object.freeze({ ...common, unit_path: unitPath, unit_body: unit });
  }

  fail(`aimos_user_service_platform_unsupported:${platform}`);
}

function definitionManifest(definition) {
  const body = {
    schema: definition.schema,
    label: definition.label,
    ...(definition.instance === 'canonical' ? {} : {
      instance: definition.instance,
      installation_context_sha256: definition.installation_context_sha256,
      postgres_port: definition.postgres_port,
    }),
    platform: definition.platform,
    source_root: definition.source_root,
    node_path: definition.node_path,
    server_path: definition.server_path,
    database: definition.database,
    port: definition.port,
    unit_path: definition.unit_path,
    stdout_path: definition.stdout_path,
    stderr_path: definition.stderr_path,
    restart_policy: definition.restart_policy,
    restart_delay_seconds: definition.restart_delay_seconds,
    log_rotation_max_bytes: definition.log_rotation_max_bytes,
    log_rotation_generations: definition.log_rotation_generations,
    secrets_in_service_definition: false,
  };
  return { ...body, configuration_sha256: sha256(Buffer.from(canonicalJson(body), 'utf8')) };
}

export function validateUserServiceManifest(manifest, {
  homeDirectory = os.homedir(),
} = {}) {
  const rebuilt = buildUserServiceDefinition({
    sourceRoot: manifest.source_root,
    nodePath: manifest.node_path,
    database: manifest.database,
    port: manifest.port,
    instance: manifest.instance,
    postgresPort: manifest.postgres_port,
    platform: manifest.platform,
    homeDirectory,
  });
  const expected = definitionManifest(rebuilt);
  if (expected.configuration_sha256 !== manifest.configuration_sha256
      || canonicalJson(expected) !== canonicalJson(manifest)) {
    fail('aimos_user_service_manifest_invalid');
  }
  return rebuilt;
}

export function buildUserServiceManifest(definition) {
  return definitionManifest(definition);
}

function writeAtomic(file, value, mode) {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, value, { mode });
  chmodSync(temporary, mode);
  renameSync(temporary, file);
}

function run(command, args, { allowFailure = false } = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    const detail = String(result.stderr || result.stdout || '').trim().slice(0, 500);
    fail(`aimos_service_command_failed:${command}:${result.status}:${detail}`);
  }
  return result;
}

function launchdDomain() {
  return `gui/${process.getuid()}`;
}

function launchdLoaded(definition) {
  return run('/bin/launchctl', [
    'print', `${launchdDomain()}/${definition.label}`,
  ], { allowFailure: true }).status === 0;
}

function waitForLaunchdUnloaded(definition, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  while (Date.now() < deadline) {
    if (!launchdLoaded(definition)) return;
    Atomics.wait(waiter, 0, 0, 100);
  }
  fail('aimos_user_service_unload_timeout');
}

function rotateLog(file, maxBytes, generations) {
  if (!existsSync(file) || statSync(file).size <= maxBytes) return;
  const oldest = `${file}.${generations}`;
  if (existsSync(oldest)) unlinkSync(oldest);
  for (let generation = generations - 1; generation >= 1; generation -= 1) {
    const source = `${file}.${generation}`;
    if (existsSync(source)) renameSync(source, `${file}.${generation + 1}`);
  }
  renameSync(file, `${file}.1`);
}

function rotateServiceLogs(definition) {
  rotateLog(
    definition.stdout_path,
    definition.log_rotation_max_bytes,
    definition.log_rotation_generations,
  );
  rotateLog(
    definition.stderr_path,
    definition.log_rotation_max_bytes,
    definition.log_rotation_generations,
  );
}

function stopDefinition(definition) {
  if (definition.platform === 'darwin') {
    run('/bin/launchctl', ['bootout', `${launchdDomain()}/${definition.label}`], { allowFailure: true });
    waitForLaunchdUnloaded(definition);
    return;
  }
  run('/usr/bin/systemctl', ['--user', 'disable', '--now', path.basename(definition.unit_path)], { allowFailure: true });
}

function startDefinition(definition) {
  rotateServiceLogs(definition);
  if (definition.platform === 'darwin') {
    if (!launchdLoaded(definition)) {
      run('/bin/launchctl', ['bootstrap', launchdDomain(), definition.unit_path]);
      run('/bin/launchctl', ['enable', `${launchdDomain()}/${definition.label}`]);
    }
    run('/bin/launchctl', ['kickstart', `${launchdDomain()}/${definition.label}`]);
    return;
  }
  run('/usr/bin/systemctl', ['--user', 'daemon-reload']);
  run('/usr/bin/systemctl', ['--user', 'enable', '--now', path.basename(definition.unit_path)]);
}

async function waitForReadiness(definition, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${definition.port}/health`);
      const body = await response.json();
      if (response.ok && body?.ready === true
          && body?.runtime?.database_name === definition.database
          && Number(body?.runtime?.server_port) === definition.port) return body;
    } catch { /* bounded poll */ }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  fail('aimos_user_service_readiness_timeout');
}

export function readInstalledUserServiceDefinition(instance = 'canonical') {
  const context = resolveAimosInstallationContext([
    '--aimos-instance', String(instance),
  ]);
  const manifestPath = path.join(context.service_state_root, 'service.json');
  if (!existsSync(manifestPath)) fail('aimos_user_service_not_installed');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  return validateUserServiceManifest(manifest, { homeDirectory: os.homedir() });
}

export async function installUserService(options = {}) {
  const definition = buildUserServiceDefinition(options);
  mkdirSync(definition.state_root, { recursive: true, mode: 0o700 });
  mkdirSync(definition.log_root, { recursive: true, mode: 0o700 });
  stopDefinition(definition);
  writeAtomic(definition.unit_path, definition.unit_body, 0o600);
  writeAtomic(definition.manifest_path, `${JSON.stringify(definitionManifest(definition), null, 2)}\n`, 0o600);
  startDefinition(definition);
  try {
    const health = await waitForReadiness(definition);
    return { success: true, action: 'install', definition: definitionManifest(definition), health };
  } catch (error) {
    stopDefinition(definition);
    throw error;
  }
}

export async function manageInstalledUserService(action, { instance = 'canonical' } = {}) {
  const definition = readInstalledUserServiceDefinition(instance);
  if (action === 'stop') {
    stopDefinition(definition);
    return { success: true, action, definition: definitionManifest(definition) };
  }
  if (action === 'start') {
    startDefinition(definition);
    try {
      return { success: true, action, definition: definitionManifest(definition), health: await waitForReadiness(definition) };
    } catch (error) {
      stopDefinition(definition);
      throw error;
    }
  }
  if (action === 'restart') {
    stopDefinition(definition);
    startDefinition(definition);
    try {
      return { success: true, action, definition: definitionManifest(definition), health: await waitForReadiness(definition) };
    } catch (error) {
      stopDefinition(definition);
      throw error;
    }
  }
  if (action === 'status') {
    let supervisor;
    if (definition.platform === 'darwin') {
      const result = run('/bin/launchctl', ['print', `${launchdDomain()}/${definition.label}`], { allowFailure: true });
      supervisor = { loaded: result.status === 0, detail: String(result.stdout || '').slice(0, 2_000) };
    } else {
    const result = run('/usr/bin/systemctl', ['--user', 'is-active', path.basename(definition.unit_path)], { allowFailure: true });
      supervisor = { loaded: result.status === 0, detail: String(result.stdout || '').trim() };
    }
    let health = null;
    try {
      const response = await fetch(`http://127.0.0.1:${definition.port}/health`);
      health = await response.json();
    } catch { /* status reports unavailable */ }
    return { success: supervisor.loaded && health?.ready === true, action, definition: definitionManifest(definition), supervisor, health };
  }
  if (action === 'uninstall') {
    stopDefinition(definition);
    if (existsSync(definition.unit_path)) unlinkSync(definition.unit_path);
    if (existsSync(definition.manifest_path)) unlinkSync(definition.manifest_path);
    if (definition.platform === 'linux') run('/usr/bin/systemctl', ['--user', 'daemon-reload']);
    return { success: true, action, unit_removed: true, manifest_removed: true };
  }
  fail('aimos_user_service_action_invalid');
}

function usage() {
  process.stderr.write('Usage: node scripts/service/manage-user-service.mjs install|start|stop|restart|status|uninstall [--source-root PATH --node PATH --database NAME --port PORT --instance NAME --postgres-port PORT]\n');
}

async function main() {
  const argv = process.argv.slice(2);
  const action = String(argv[0] || '');
  if (!['install', 'start', 'stop', 'restart', 'status', 'uninstall'].includes(action)) {
    usage();
    process.exitCode = 64;
    return;
  }
  const result = action === 'install'
    ? await installUserService({
        sourceRoot: cliValue(argv, '--source-root') || ROOT,
        nodePath: cliValue(argv, '--node') || process.execPath,
        database: cliValue(argv, '--database') || 'aimos',
        port: cliValue(argv, '--port') || 9100,
        instance: cliValue(argv, '--instance') || 'canonical',
        postgresPort: cliValue(argv, '--postgres-port') || 5432,
      })
    : await manageInstalledUserService(action, {
        instance: cliValue(argv, '--instance') || 'canonical',
      });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (action === 'status' && !result.success) process.exitCode = 1;
}

if (process.argv[1] && existsSync(process.argv[1])
    && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${String(error?.message || error)}\n`);
    process.exitCode = 1;
  });
}
