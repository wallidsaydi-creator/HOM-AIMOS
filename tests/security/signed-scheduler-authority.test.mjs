import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('canonical scheduler derives authority from retained signed events', async () => {
  const source = await readFile(new URL('services/orchestration/scheduler.js', ROOT), 'utf8');

  assert.match(source, /readVerifiedEventHistory\(COMPANY, \{ client \}\)/);
  assert.match(source, /authority\?\.kind !== 'verified_request'/);
  assert.match(source, /authority\.requestReceiptMutationHash/);
  assert.match(source, /'schedule_created'/);
  assert.match(source, /'schedule_run_reserved'/);
  assert.match(source, /'schedule_run_completed'/);
  assert.match(source, /'schedule_run_failed'/);
  assert.doesNotMatch(source, /getOperatorAgentId/);
  assert.doesNotMatch(source, /DELETE FROM scheduled_tasks|TRUNCATE scheduled_tasks/);
});

test('housekeeper dispatches delegated schedules with canonical memory enabled', async () => {
  const source = await readFile(new URL('services/orchestration/scheduler.js', ROOT), 'utf8');

  assert.match(source, /skipAimos: false,[\s\S]{0,80}autonomous: true/);
  assert.match(source, /schedule_projection_proof_mismatch/);
  assert.match(source, /schedule_creation_proof_missing/);
  assert.match(source, /scheduler_lock_authority_unavailable/);
});

test('scheduler projection ACL forbids runtime deletion and deactivation', async () => {
  const migration = await readFile(new URL('migrations/065-signed-scheduler-authority.sql', ROOT), 'utf8');

  assert.match(migration, /ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /FORCE ROW LEVEL SECURITY/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public\.scheduled_tasks FROM agent_runtime/);
  assert.doesNotMatch(migration, /GRANT UPDATE \([^)]*is_active/s);
  assert.doesNotMatch(migration, /GRANT DELETE|GRANT TRUNCATE/);
});
