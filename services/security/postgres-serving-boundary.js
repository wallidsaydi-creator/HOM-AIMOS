// Pre-listen admission for the private AIMOS PostgreSQL cluster. A correct
// Keychain password alone does not prove HBA is enforcing authentication, so
// an intentionally wrong password must be rejected for each serving role.

import { randomBytes } from 'node:crypto';
import pg from 'pg';

import {
  AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE,
  AIMOS_RUNTIME_CREDENTIAL_SERVICE,
  AIMOS_RUNTIME_ROLE,
  AIMOS_SERVICE_READER_CREDENTIAL_SERVICE,
  resolveAimosDatabaseName,
  resolveAimosIdentityWriterDatabaseConfig,
  resolveAimosServiceReaderDatabaseConfig,
} from '../core/runtime-config.js';
import { readCredentialSync } from './credential-store.js';

const { Client } = pg;

const ROLES = Object.freeze([
  ['aimos_service_reader', AIMOS_SERVICE_READER_CREDENTIAL_SERVICE,
    resolveAimosServiceReaderDatabaseConfig, 'aimos_memories'],
  ['aimos_identity_writer', AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE,
    resolveAimosIdentityWriterDatabaseConfig, 'aimos_events'],
  [AIMOS_RUNTIME_ROLE, AIMOS_RUNTIME_CREDENTIAL_SERVICE,
    (argv) => ({ ...resolveAimosServiceReaderDatabaseConfig(argv), user: AIMOS_RUNTIME_ROLE }),
    'aimos_memories'],
]);

async function withClient(config, fn) {
  const client = new Client({ ...config, ssl: false, connectionTimeoutMillis: 5000 });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    await client.end().catch(() => {});
  }
}

export async function assertPrivatePostgresServingBoundary({
  argv = process.argv.slice(2),
  credentialReader = readCredentialSync,
  connect = withClient,
} = {}) {
  const results = [];
  for (const [role, service, resolveConfig, rlsTable] of ROLES) {
    const credential = credentialReader(service);
    if (!credential?.value) throw new Error(`postgres_serving_credential_unavailable:${role}`);
    const config = resolveConfig(argv);
    if (config.database !== resolveAimosDatabaseName(argv)
        || !Number.isInteger(config.port) || config.port === 5432) {
      throw new Error('postgres_serving_target_invalid');
    }
    for (const host of ['127.0.0.1', '::1']) {
      const target = { ...config, host };
      const wrongPassword = `invalid-${randomBytes(24).toString('base64url')}`;
      let rejected = false;
      try {
        await connect({ ...target, password: wrongPassword }, async () => {});
      } catch (error) {
        rejected = error.code === '28P01'
          || /password must be a string|SASL.*password/i.test(error.message || '');
        if (!rejected) throw error;
      }
      if (!rejected) throw new Error(`postgres_passwordless_or_wrong_password_accepted:${role}:${host}`);
    }
    const facts = await connect({ ...config, host: '127.0.0.1', password: credential.value },
      async (client) => (await client.query(`
        SELECT current_user, current_setting('app.current_client_id', true) AS company_id,
               (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
               (SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user) AS bypass_rls,
               row_security_active($1::regclass) AS rls_active`, [`public.${rlsTable}`])).rows[0]);
    if (facts?.current_user !== role
        || (role !== AIMOS_RUNTIME_ROLE && facts.company_id !== 'hom')
        || facts.superuser !== false
        || facts.bypass_rls !== false || facts.rls_active !== true) {
      throw new Error(`postgres_serving_role_postcondition_invalid:${role}`);
    }
    results.push({ role, authenticated: true, rlsTable });
  }
  return Object.freeze(results);
}
