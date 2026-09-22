import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { acceptedMigrationSecurityTransition } from '../../migrations/run.js';

const ROOT = new URL('../../', import.meta.url);

test('migration 029 password-free successor retains its exact canonical checksum', async () => {
  const bytes = await readFile(new URL('migrations/029-rename-runtime-role.sql', ROOT));
  const source = bytes.toString('utf8');
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    '774d12cd80f44e7dd9425f7ac1d879e165514be70a7d1f3e5fd192d4d4c252fc',
  );
  assert.doesNotMatch(source, /ALTER\s+ROLE\s+agent_runtime\s+WITH\s+PASSWORD/i);
});

test('v1.0.4 migration 029 advances only through the exact security transition', () => {
  const predecessor = 'd8cb32a188e7280ea9ca0ed5f07f00c2b5153e7db81f0f5a3e290ae175bed91a';
  const successor = '774d12cd80f44e7dd9425f7ac1d879e165514be70a7d1f3e5fd192d4d4c252fc';
  assert.equal(acceptedMigrationSecurityTransition(
    '029-rename-runtime-role.sql', predecessor, successor,
  ), true);
  assert.equal(acceptedMigrationSecurityTransition(
    '029-rename-runtime-role.sql', '0'.repeat(64), successor,
  ), false);
  assert.equal(acceptedMigrationSecurityTransition(
    '029-rename-runtime-role.sql', predecessor, 'f'.repeat(64),
  ), false);
  assert.equal(acceptedMigrationSecurityTransition(
    '030-agent-envelope.sql', predecessor, successor,
  ), false);
});

test('Genesis restores the Keychain runtime credential before loading runtime pools', async () => {
  const source = await readFile(new URL('scripts/genesis-install.mjs', ROOT), 'utf8');
  const migration = source.indexOf('await phaseA3SchemaMigrations()');
  const synchronization = source.indexOf('await phaseA3_1RuntimeCredentialSync()');
  const runtimePoolLoad = source.indexOf("await import('../db/connection.js')");

  assert.ok(migration >= 0);
  assert.ok(synchronization > migration);
  assert.ok(runtimePoolLoad > synchronization);
  assert.match(source, /synchronizeRuntimeRoleCredential/);
});
