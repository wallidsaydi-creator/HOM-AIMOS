import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('revocation and replay rejection have no mutable kill switch', async () => {
  const auth = await readFile(new URL('services/security/auth-tier.js', ROOT), 'utf8');
  assert.doesNotMatch(auth, /SECURITY_KILLSWITCH|readFlag/);
  assert.match(auth, /return t0\('agent_revoked'\)/);
  assert.match(auth, /return t0\('replay_detected'\)/);
  await assert.rejects(access(new URL('services/security/security-flag-store.js', ROOT)));
  await assert.rejects(access(new URL('services/security/envelope-reader.js', ROOT)));
});

test('historical mutable flag rows are retained and non-authoritative', async () => {
  const migration = await readFile(new URL('migrations/072-retire-mutable-security-flags.sql', ROOT), 'utf8');
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE/);
  assert.match(migration, /Never admission or authorization authority/);
  assert.doesNotMatch(migration, /DROP TABLE|DELETE FROM|TRUNCATE TABLE/i);
});
