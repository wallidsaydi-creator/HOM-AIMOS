import test from 'node:test';
import assert from 'node:assert/strict';

import { assertPrivatePostgresServingBoundary } from '../../services/security/postgres-serving-boundary.js';

const argv = ['--aimos-db', 'aimos', '--aimos-postgres-port', '55432'];
const credentialReader = () => ({ value: 'test-only-secret' });

function connection({ acceptWrong = false, superuser = false } = {}) {
  const attempts = [];
  const connect = async (config, fn) => {
    attempts.push({ role: config.user, host: config.host,
      invalidPassword: config.password.startsWith('invalid-') });
    if (config.password.startsWith('invalid-') && !acceptWrong) {
      const error = new Error('password authentication failed');
      error.code = '28P01';
      throw error;
    }
    return fn({ query: async () => ({ rows: [{
      current_user: config.user,
      company_id: config.user === 'agent_runtime' ? '' : 'hom',
      socket_directories: '', superuser, bypass_rls: false, rls_active: true,
    }] }) });
  };
  return { connect, attempts };
}

test('private serving admission requires three distinct SCRAM roles on both loopback families', async () => {
  const fixture = connection();
  const roles = await assertPrivatePostgresServingBoundary({
    argv, credentialReader, connect: fixture.connect,
  });
  assert.deepEqual(roles.map((row) => row.role), [
    'aimos_service_reader', 'aimos_identity_writer', 'agent_runtime',
  ]);
  assert.equal(fixture.attempts.filter((attempt) => attempt.invalidPassword).length, 6);
  assert.deepEqual(new Set(fixture.attempts.map((attempt) => attempt.host)),
    new Set(['127.0.0.1', '::1']));
});

test('private serving admission rejects trust before any correct-password role query', async () => {
  const fixture = connection({ acceptWrong: true });
  await assert.rejects(assertPrivatePostgresServingBoundary({
    argv, credentialReader, connect: fixture.connect,
  }), /wrong_password_accepted/);
  assert.equal(fixture.attempts.length, 1);
  assert.equal(fixture.attempts[0].invalidPassword, true);
});

test('private serving admission rejects a superuser even with valid SCRAM', async () => {
  const fixture = connection({ superuser: true });
  await assert.rejects(assertPrivatePostgresServingBoundary({
    argv, credentialReader, connect: fixture.connect,
  }), /role_postcondition_invalid/);
});
