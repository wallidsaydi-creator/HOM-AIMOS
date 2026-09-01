import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  resolveAimosInstallationContext,
} from '../../services/installation-context.js';

const FIXTURE_HOME = '/test-home';

test('canonical installation context preserves every existing deployment default', () => {
  const context = resolveAimosInstallationContext([], { homeDirectory: FIXTURE_HOME });
  assert.equal(context.instance, 'canonical');
  assert.equal(context.canonical, true);
  assert.equal(context.state_root, '/test-home/.aimos');
  assert.equal(context.agent_key_root, '/test-home/.aimos/agents');
  assert.equal(context.runtime_credential_service, 'agent_runtime_db_password');
  assert.equal(context.user_service_label, 'com.hom.aimos');
  assert.equal(context.service_state_root, '/test-home/.aimos/service');
  assert.equal(context.service_log_root, '/test-home/.aimos/logs');
  assert.equal(context.postgres_port, 5432);
  assert.equal(context.runtime_role, 'agent_runtime');
  assert.match(context.context_sha256, /^[0-9a-f]{64}$/);
});

test('named installation context derives disjoint same-user application ownership', () => {
  const context = resolveAimosInstallationContext([
    '--aimos-instance', 'p3_repro',
    '--aimos-postgres-port=55432',
  ], { homeDirectory: FIXTURE_HOME });
  assert.equal(context.canonical, false);
  assert.equal(context.state_root, '/test-home/.aimos/instances/p3_repro');
  assert.equal(context.agent_key_root, `${context.state_root}/agents`);
  assert.equal(context.runtime_credential_service, 'agent_runtime_db_password-p3_repro');
  assert.equal(context.user_service_label, 'com.hom.aimos.p3_repro');
  assert.equal(context.service_state_root, `${context.state_root}/service`);
  assert.equal(context.service_log_root, `${context.state_root}/logs`);
  assert.equal(context.generated_authority_path, `${context.state_root}/architecture-authority.json`);
  assert.equal(context.postgres_port, 55432);
  assert.equal(context.runtime_role, 'agent_runtime');
});

test('installation context rejects ambiguous namespace and PostgreSQL ports', () => {
  for (const value of ['', '../x', 'Canonical!', 'a'.repeat(33)]) {
    assert.throws(
      () => resolveAimosInstallationContext([`--aimos-instance=${value}`]),
      /Invalid --aimos-instance/,
    );
  }
  for (const port of ['abc', '543', '9000', '9001', '9100', '70000']) {
    assert.throws(
      () => resolveAimosInstallationContext([`--aimos-postgres-port=${port}`]),
      /Invalid --aimos-postgres-port/,
    );
  }
});

test('installation context has no environment, database, Keychain, or network authority', async () => {
  const source = await readFile(new URL(
    '../../services/installation-context.js',
    import.meta.url,
  ), 'utf8');
  assert.doesNotMatch(source,
    /process\.env|db\/|pg\b|keychain|security\s|fetch\(|http:|https:|child_process/);
});
