import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('unsigned trigger executor and mutable CRUD are absent', async () => {
  const [route, writer, runner] = await Promise.all([
    readFile(new URL('routes/aimos.js', ROOT), 'utf8'),
    readFile(new URL('services/write/persist-memory.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/agent-runner.js', ROOT), 'utf8'),
  ]);
  for (const source of [route, writer, runner]) assert.doesNotMatch(source, /evaluateTriggers|trigger-evaluator/);
  assert.doesNotMatch(route, /router\.(?:post|get|put|delete)\('\/triggers/);
  await assert.rejects(access(new URL('services/orchestration/trigger-evaluator.js', ROOT)));
});

test('historical trigger rows are retained but non-authoritative', async () => {
  const migration = await readFile(new URL('migrations/074-retire-unsigned-trigger-authority.sql', ROOT), 'utf8');
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE/);
  assert.match(migration, /housekeeper signed scheduler events are canonical/);
  assert.doesNotMatch(migration, /DROP TABLE|DELETE FROM|TRUNCATE TABLE/i);
});
