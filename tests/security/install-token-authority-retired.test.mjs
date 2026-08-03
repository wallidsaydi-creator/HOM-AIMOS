import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('token-only install authorization is absent from the live save route', async () => {
  const route = await readFile(new URL('routes/aimos.js', ROOT), 'utf8');
  assert.doesNotMatch(route, /install_token_confirmed|installGateOrchestrator|SECURITY_ENFORCE_INSTALL_GATE/);
  assert.doesNotMatch(route, /router\.post\('\/install\/(?:confirm|finalize)'/);
  await assert.rejects(access(new URL('services/security/install-gate.js', ROOT)));
});

test('historical install confirmation rows are retained but non-authoritative', async () => {
  const migration = await readFile(new URL('migrations/071-retire-token-install-authority.sql', ROOT), 'utf8');
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE/);
  assert.match(migration, /RETIRED retained historical token state/);
  assert.doesNotMatch(migration, /DROP TABLE|DELETE FROM|TRUNCATE TABLE/i);
});
