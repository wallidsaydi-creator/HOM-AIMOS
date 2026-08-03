import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('applied migration 029 retains its canonical checksum', async () => {
  const bytes = await readFile(new URL('migrations/029-rename-runtime-role.sql', ROOT));
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    'd8cb32a188e7280ea9ca0ed5f07f00c2b5153e7db81f0f5a3e290ae175bed91a',
  );
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
