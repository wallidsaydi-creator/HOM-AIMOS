// AIMOS bootstrap/runtime constants.
//
// Environment variables are deliberately not a configuration source. Before
// the database exists, the installer may only use deterministic local bootstrap
// facts or explicit non-secret CLI arguments. After genesis, mutable settings
// belong in the signed system-config / credential ledgers.

import os from 'node:os';

export const AIMOS_COMPANY_ID = 'hom';
export const AIMOS_RUNTIME_ROLE = 'agent_runtime';
export const AIMOS_RUNTIME_CREDENTIAL_SERVICE = 'agent_runtime_db_password';
export const ORACLE_RESERVED_PORTS = Object.freeze([9000, 9001]);

function cliValue(name, argv = process.argv.slice(2)) {
  const prefix = `${name}=`;
  const inline = argv.find((arg) => arg.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function resolveAimosServerPort(argv = process.argv.slice(2)) {
  const raw = cliValue('--aimos-port', argv);
  if (raw == null) return 9100;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`Invalid --aimos-port value: ${raw}`);
  }
  if (ORACLE_RESERVED_PORTS.includes(port)) {
    throw new Error(`Refusing AIMOS port ${port}: reserved for HOM Oracle`);
  }
  return port;
}

export const AIMOS_SERVER_PORT = resolveAimosServerPort();
export const AIMOS_HTTP_ORIGIN = `http://127.0.0.1:${AIMOS_SERVER_PORT}`;
export const AIMOS_API_BASE_URL = `${AIMOS_HTTP_ORIGIN}/aimos`;

/**
 * Validate a signed HTTP-origin configuration value used by AIMOS transports.
 * Paths, credentials, query strings, and fragments are forbidden so callers
 * cannot disagree about whether a configured value is an origin or endpoint.
 * Oracle ports are rejected regardless of hostname: this fork must never be
 * configured back onto Oracle's runtime surface.
 */
export function validateAimosHttpOrigin(value, configKey = 'AIMOS_HTTP_ORIGIN') {
  const raw = String(value ?? '').trim();
  if (!raw) return { ok: false, reason: 'empty_value' };

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid_absolute_url' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, reason: 'invalid_protocol' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'embedded_credentials_forbidden' };
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    return { ok: false, reason: 'origin_only_required' };
  }

  const effectivePort = parsed.port
    ? Number(parsed.port)
    : (parsed.protocol === 'https:' ? 443 : 80);
  if (ORACLE_RESERVED_PORTS.includes(effectivePort)) {
    return { ok: false, reason: 'oracle_port_reserved' };
  }

  return {
    ok: true,
    value: parsed.origin,
    configKey,
  };
}

export function resolveAimosHttpOrigin(configuredValue = null, {
  fallback = AIMOS_HTTP_ORIGIN,
  configKey = 'AIMOS_HTTP_ORIGIN',
} = {}) {
  const selected = String(configuredValue ?? '').trim() || fallback;
  const validated = validateAimosHttpOrigin(selected, configKey);
  if (!validated.ok) {
    throw new Error(`${configKey}: ${validated.reason}`);
  }
  return validated.value;
}

export function resolveAimosDatabaseName(argv = process.argv.slice(2)) {
  const name = cliValue('--aimos-db', argv) || 'aimos';
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(name)) {
    throw new Error(`Invalid --aimos-db value: ${name}`);
  }
  if (name === 'oracle' || name === 'aimos_dev') {
    throw new Error(`Refusing protected database name: ${name}`);
  }
  return name;
}

export function resolveAimosDatabaseUrl(argv = process.argv.slice(2)) {
  const username = encodeURIComponent(os.userInfo().username);
  return `postgresql://${username}@localhost:5432/${resolveAimosDatabaseName(argv)}`;
}
