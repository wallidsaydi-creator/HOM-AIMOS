// Pure explicit installation namespace for same-user HOM-AIMOS isolation.
//
// This module derives deployment paths and names only from validated CLI facts
// plus the invoking user's real home directory. It never reads environment
// variables, databases, Keychain contents, source manifests, or mutable policy.

import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export const CANONICAL_AIMOS_INSTANCE = 'canonical';
export const CANONICAL_RUNTIME_CREDENTIAL_SERVICE = 'agent_runtime_db_password';
export const CANONICAL_USER_SERVICE_LABEL = 'com.hom.aimos';
export const CANONICAL_POSTGRES_PORT = 5432;

function cliValue(name, argv) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function normalizeInstance(value) {
  const instance = String(value == null ? CANONICAL_AIMOS_INSTANCE : value).trim().toLowerCase();
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(instance)) {
    throw new Error(`Invalid --aimos-instance value: ${value}`);
  }
  return instance;
}

function normalizePostgresPort(value) {
  if (value == null) return CANONICAL_POSTGRES_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || [9000, 9001, 9100].includes(port)) {
    throw new Error(`Invalid --aimos-postgres-port value: ${value}`);
  }
  return port;
}

function contextCommitment(body) {
  const canonical = JSON.stringify(body, Object.keys(body).sort());
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function resolveAimosInstallationContext(
  argv = process.argv.slice(2),
  { homeDirectory = os.homedir() } = {},
) {
  const instance = normalizeInstance(cliValue('--aimos-instance', argv));
  const canonical = instance === CANONICAL_AIMOS_INSTANCE;
  const home = path.resolve(String(homeDirectory || ''));
  if (!path.isAbsolute(home) || home === path.parse(home).root) {
    throw new Error('AIMOS installation home directory is invalid');
  }
  const stateRoot = canonical
    ? path.join(home, '.aimos')
    : path.join(home, '.aimos', 'instances', instance);
  const postgresPort = normalizePostgresPort(cliValue('--aimos-postgres-port', argv));
  const body = Object.freeze({
    schema: 'hom.aimos.installation-context/v1',
    instance,
    canonical,
    state_root: stateRoot,
    agent_key_root: path.join(stateRoot, 'agents'),
    runtime_credential_service: canonical
      ? CANONICAL_RUNTIME_CREDENTIAL_SERVICE
      : `${CANONICAL_RUNTIME_CREDENTIAL_SERVICE}-${instance}`,
    user_service_label: canonical
      ? CANONICAL_USER_SERVICE_LABEL
      : `${CANONICAL_USER_SERVICE_LABEL}.${instance}`,
    service_state_root: path.join(stateRoot, 'service'),
    service_log_root: path.join(stateRoot, 'logs'),
    generated_authority_path: path.join(stateRoot, 'architecture-authority.json'),
    postgres_port: postgresPort,
    runtime_role: 'agent_runtime',
  });
  return Object.freeze({
    ...body,
    context_sha256: contextCommitment(body),
  });
}

export default { resolveAimosInstallationContext };
