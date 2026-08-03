import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

test('ephemeral natural-language scheduler and placeholder executor are absent', async () => {
  const root = new URL('../../', import.meta.url);
  await assert.rejects(access(new URL('services/orchestration/scheduler-nl.js', root)));
  await assert.rejects(access(new URL('routes/scheduler.js', root)));
  const server = await readFile(new URL('server.js', root), 'utf8');
  assert.doesNotMatch(server, /startNaturalScheduler|stopNaturalScheduler|routes\/scheduler\.js/);
});

test('canonical scheduler never executes when overlap authority is unavailable', async () => {
  const scheduler = await readFile(new URL('../../services/orchestration/scheduler.js', import.meta.url), 'utf8');
  assert.match(scheduler, /agentPool\.connect\(\)/);
  assert.match(scheduler, /reason: 'scheduler_lock_authority_unavailable'/);
  assert.doesNotMatch(scheduler, /advisory-lock connect failed, running unguarded/);
});
