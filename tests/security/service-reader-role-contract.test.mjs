import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createLazyIdentityWriterPool, createLazyServiceReaderPool } from '../../db/connection.js';
import {
  AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE,
  AIMOS_IDENTITY_WRITER_ROLE,
  AIMOS_SERVICE_READER_CREDENTIAL_SERVICE,
  AIMOS_SERVICE_READER_ROLE,
  resolveAimosIdentityWriterCredentialService,
  resolveAimosIdentityWriterDatabaseConfig,
  resolveAimosServiceReaderDatabaseConfig,
  resolveAimosServiceReaderCredentialService,
} from '../../services/core/runtime-config.js';

test('service reader target is explicit and carries no credential or maintenance user', () => {
  const target = resolveAimosServiceReaderDatabaseConfig([
    '--aimos-db', 'aimos_reader_test',
    '--aimos-postgres-port', '5549',
    '--aimos-instance', 'reader_test',
  ]);
  assert.deepEqual(target, {
    host: 'localhost',
    port: 5549,
    database: 'aimos_reader_test',
    user: AIMOS_SERVICE_READER_ROLE,
  });
  assert.equal(Object.isFrozen(target), true);
  assert.equal(Object.hasOwn(target, 'password'), false);
  assert.equal(Object.hasOwn(target, 'connectionString'), false);
  assert.equal(resolveAimosServiceReaderCredentialService(['--aimos-instance', 'canonical']),
    'aimos_service_reader_db_password');
  assert.equal(resolveAimosServiceReaderCredentialService(['--aimos-instance', 'reader_test']),
    'aimos_service_reader_db_password-reader_test');
  assert.equal(resolveAimosIdentityWriterCredentialService(['--aimos-instance', 'canonical']),
    'aimos_identity_writer_db_password');
  assert.equal(resolveAimosIdentityWriterCredentialService(['--aimos-instance', 'reader_test']),
    'aimos_identity_writer_db_password-reader_test');
  assert.notEqual(AIMOS_SERVICE_READER_CREDENTIAL_SERVICE, AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE);
  const writerTarget = resolveAimosIdentityWriterDatabaseConfig([
    '--aimos-db', 'aimos_reader_test', '--aimos-postgres-port', '5549',
  ]);
  assert.equal(writerTarget.user, AIMOS_IDENTITY_WRITER_ROLE);
  assert.equal(Object.hasOwn(writerTarget, 'password'), false);
  assert.equal(Object.hasOwn(writerTarget, 'connectionString'), false);
});

test('service reader fails before pool construction when Keychain evidence is absent', () => {
  let constructions = 0;
  const reader = createLazyServiceReaderPool({
    credentialReader: () => null,
    poolFactory: () => { constructions++; throw new Error('unexpected_pool_construction'); },
  });
  assert.throws(() => reader.query('SELECT 1'), /service_reader_credential_unavailable/);
  assert.equal(constructions, 0);
});

test('service reader does not expose credential-reader errors or fall back to primary', () => {
  let constructions = 0;
  const reader = createLazyServiceReaderPool({
    credentialReader: () => { throw new Error('private_backend_diagnostic'); },
    poolFactory: () => { constructions++; throw new Error('unexpected_pool_construction'); },
  });
  assert.throws(() => reader.connect(), (error) => {
    assert.equal(error.message, 'service_reader_credential_unavailable');
    return true;
  });
  assert.equal(constructions, 0);
});

test('service reader passes the secret only as a private driver field', async () => {
  const secret = randomBytes(32).toString('base64url');
  let serviceName = null;
  let captured = null;
  let constructions = 0;
  const fakePool = {
    query: async () => ({ rows: [{ current_user: AIMOS_SERVICE_READER_ROLE }] }),
    connect: async () => ({ release() {} }),
    end: async () => {},
    totalCount: 1,
    idleCount: 1,
    waitingCount: 0,
  };
  const reader = createLazyServiceReaderPool({
    credentialReader: (name) => { serviceName = name; return { value: secret }; },
    poolFactory: (config) => { constructions++; captured = config; return fakePool; },
  });
  assert.equal(constructions, 0);
  assert.equal((await reader.query('SELECT current_user')).rows[0].current_user, AIMOS_SERVICE_READER_ROLE);
  assert.equal(serviceName, AIMOS_SERVICE_READER_CREDENTIAL_SERVICE);
  assert.equal(constructions, 1);
  assert.equal(captured.user, AIMOS_SERVICE_READER_ROLE);
  assert.equal(captured.password, secret);
  assert.equal(captured.application_name, 'aimos_service_reader');
  assert.equal(Object.hasOwn(captured, 'connectionString'), false);
  assert.equal(Object.hasOwn(resolveAimosServiceReaderDatabaseConfig(), 'password'), false);
  await reader.query('SELECT current_user');
  assert.equal(constructions, 1);
  await reader.end();
});

test('identity writer requires its own credential and never selects the primary pool', async () => {
  let constructions = 0;
  const missing = createLazyIdentityWriterPool({
    credentialReader: () => null,
    poolFactory: () => { constructions++; throw new Error('unexpected_pool_construction'); },
  });
  assert.throws(() => missing.connect(), /identity_writer_credential_unavailable/);
  assert.equal(constructions, 0);

  const secret = randomBytes(32).toString('base64url');
  let captured = null;
  let serviceName = null;
  const writer = createLazyIdentityWriterPool({
    credentialReader: (name) => { serviceName = name; return { value: secret }; },
    poolFactory: (config) => {
      captured = config;
      return { connect: async () => ({ release() {} }), query: async () => ({ rows: [] }),
        end: async () => {}, totalCount: 0, idleCount: 0, waitingCount: 0 };
    },
  });
  assert.equal(captured, null);
  const client = await writer.connect();
  client.release();
  assert.equal(serviceName, AIMOS_IDENTITY_WRITER_CREDENTIAL_SERVICE);
  assert.equal(captured.user, AIMOS_IDENTITY_WRITER_ROLE);
  assert.equal(captured.password, secret);
  assert.equal(captured.application_name, AIMOS_IDENTITY_WRITER_ROLE);
  assert.equal(Object.hasOwn(captured, 'connectionString'), false);
  await writer.end();
});

test('forward migration stages NOLOGIN with only boot-reader table grants', () => {
  const source = readFileSync(new URL('../../migrations/116-service-reader-role-acl.sql', import.meta.url), 'utf8');
  assert.match(source, /CREATE ROLE aimos_service_reader\s+NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION\s+NOBYPASSRLS NOINHERIT/);
  assert.match(source, /service_reader_role_membership_forbidden/);
  assert.match(source, /service_reader_write_privilege_forbidden/);
  assert.match(source, /service_reader_unscoped_select_forbidden/);
  assert.match(source, /AS RESTRICTIVE FOR SELECT TO aimos_service_reader/);
  assert.match(source, /service_reader_existing_company_policy_invalid/);
  for (const relation of [
    'aimos_action_origin_verdicts', 'aimos_cognitive_weight_baselines',
    'aimos_cognitive_weight_projections', 'aimos_events', 'aimos_memories',
    'aimos_memory_epistemic_classifications', 'aimos_memory_origin_bindings',
    'aimos_origin_elevations', 'aimos_origin_ledger_entries',
    'aimos_request_receipts', 'dream_summary_layers', 'entity_memory_edges',
    'integration_tokens', 'procedural_skills', 'recommendation_log',
    'retrieval_pheromones', 'scheduled_tasks',
  ]) {
    assert.match(source, new RegExp(`'${relation}'`));
  }
  assert.match(source, /service_reader_rls_policy_invalid/);
  for (const relation of [
    'aimos_master_identity', 'agent_identity',
    'aimos_agent_revocation_events', 'aimos_system_config',
  ]) {
    assert.match(source, new RegExp(`ON public\\.${relation} TO aimos_service_reader`));
  }
  assert.doesNotMatch(source, /GRANT\s+(?:ALL|INSERT|UPDATE|DELETE|TRUNCATE|EXECUTE)\b/i);
  assert.doesNotMatch(source, /GRANT\s+SELECT\s+ON\s+ALL\s+TABLES/i);
  assert.doesNotMatch(source, /\bPASSWORD\s+'/i);
});

test('serving ACL migration keeps the identity writer narrow and both roles staged', () => {
  const source = readFileSync(new URL('../../migrations/118-serving-reader-and-identity-writer-acl.sql', import.meta.url), 'utf8');
  assert.match(source, /CREATE ROLE aimos_identity_writer\s+NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION\s+NOBYPASSRLS NOINHERIT/);
  assert.match(source, /GRANT INSERT \(agent_id, pubkey, cert, device_fp, valid_from, valid_until\)\s+ON public\.agent_identity TO aimos_identity_writer/);
  assert.match(source, /signed_body_bytes\s*\) ON public\.aimos_events TO aimos_identity_writer/);
  assert.match(source, /AS RESTRICTIVE FOR ALL TO aimos_identity_writer/);
  assert.match(source, /identity_writer_write_surface_invalid/);
  assert.match(source, /service_reader_select_surface_invalid/);
  assert.match(source, /ALTER ROLE aimos_service_reader IN DATABASE %I SET app\.current_client_id/);
  assert.match(source, /ALTER ROLE aimos_identity_writer IN DATABASE %I SET app\.current_client_id/);
  assert.doesNotMatch(source, /GRANT\s+ALL\b/i);
  assert.doesNotMatch(source, /GRANT\s+INSERT\s+ON\s+ALL\s+TABLES/i);
  assert.doesNotMatch(source, /\bPASSWORD\s+'/i);
});

test('signed enrollment master verification needs only the writer read grant', () => {
  const source = readFileSync(new URL('../../scripts/identity/db.js', import.meta.url), 'utf8');
  const commit = source.slice(source.indexOf('export async function commitAgentEnrollment'),
    source.indexOf('export async function markAgentEnrollmentIndeterminate'));
  assert.match(commit,
    /SELECT master_pubkey, fingerprint FROM aimos_master_identity WHERE id = 1'/);
  assert.doesNotMatch(commit, /aimos_master_identity[^']*FOR (?:UPDATE|NO KEY UPDATE|SHARE|KEY SHARE)/);
});
