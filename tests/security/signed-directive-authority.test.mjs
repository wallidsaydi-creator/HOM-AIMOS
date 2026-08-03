import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('directive lifecycle is owned by atomic signed transitions', async () => {
  const [owner, route, migration] = await Promise.all([
    readFile(new URL('services/core/directive-claims.js', ROOT), 'utf8'),
    readFile(new URL('routes/aimos.js', ROOT), 'utf8'),
    readFile(new URL('migrations/073-signed-directive-projection.sql', ROOT), 'utf8'),
  ]);

  assert.match(owner, /logEvent\(companyId, targetAgentId, 'directive_created'/);
  assert.match(owner, /logEvent\(companyId, agentId, 'directive_claim_reserved'/);
  assert.match(owner, /logEvent\(companyId, agentId, 'directive_terminal'/);
  assert.match(owner, /\{ client, authority \}/);
  assert.match(owner, /authority_event_id, last_event_id/);
  assert.doesNotMatch(route, /clearance_level \|\| 0\) < 5/);
  assert.match(route, /router\.post\('\/ceo\/directive', requireCapability\('delegate'\)/);
  assert.doesNotMatch(route, /UPDATE aimos_directives/);
  assert.match(migration, /ON DELETE RESTRICT/);
  assert.match(migration, /REVOKE DELETE, TRUNCATE/);
});
