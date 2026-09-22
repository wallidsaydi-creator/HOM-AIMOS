// Actual scheduler owner, existing Housekeeper, real PostgreSQL and signed
// events. Explicit opt-in; no model or listener and no canonical memory writes.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { executeSystemJob, getSchedulerWorkState, drainScheduler } from '../../services/orchestration/scheduler.js';
import { pool, agentPool, schedulerLockPool, withTransaction } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { getServingWorkState } from '../../services/runtime/serving-control.js';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const prefix = `aud011:${randomUUID()}`;
const work = [], began = [];
let releaseWork;
const held = new Promise(resolve => { releaseWork = resolve; });
const read = () => withTransaction(async c => (await c.query('SELECT current_database() AS database, current_user AS role')).rows[0],
  { restricted: true, client_id: 'hom', agent_id: 'housekeeper', readOnly: true });
try {
  for (let i = 0; i < 12; i++) work.push(executeSystemJob({
    jobId: `${prefix}:${i}`, cronExpression: '* * * * *',
    runFn: async () => { began.push(i); await held; return read(); },
  }).then(value => ({ value }), error => ({ error })));
  const waitUntil = performance.now() + 10000;
  while (began.length < 2 && performance.now() < waitUntil) await new Promise(r => setTimeout(r, 20));
  assert.equal(began.length, 2);
  const during = getSchedulerWorkState();
  assert.equal(during.activeJobs, 2); assert.equal(during.lockPool.total, 2);
  assert.equal((await read()).role, 'agent_runtime');
  const duplicate = await executeSystemJob({ jobId: `${prefix}:0`, cronExpression: '* * * * *', runFn: read });
  assert.equal(duplicate.reason, 'scheduler_job_in_flight');
  releaseWork();
  const results = await Promise.all(work);
  for (const r of results) assert(!r.error, r.error?.stack);
  const completed = results.filter(r => r.value.skipped === false).map(r => r.value);
  assert.equal(completed.length, 2);
  assert.equal(results.filter(r => r.value.reason === 'scheduler_capacity_busy').length, 10);
  for (const r of results.filter(r => r.value.skipped)) {
    const deferred = await readVerifiedEventById(r.value.admissionEventId, 'hom');
    assert.equal(deferred.metadata.dispatched, false);
    assert.equal(deferred.metadata.reason_code, 'scheduler_capacity_busy');
  }
  for (const r of completed) {
    const start = await readVerifiedEventById(r.start.event_id, 'hom');
    const terminal = await readVerifiedEventById(r.terminal.event_id, 'hom');
    assert.equal(terminal.parent_event_id, start.id);
    assert.equal(terminal.metadata.disposition, 'SUCCEEDED');
  }
  assert.equal(getSchedulerWorkState().activeJobs, 0);
  assert.equal(getServingWorkState().active, 0);
  console.log(JSON.stringify({ at: new Date().toISOString(), prefix, passed: true,
    submitted: 12, completed: 2, explicit_capacity_deferrals: 10, duplicate: duplicate.reason,
    during, after: getSchedulerWorkState(),
    events: completed.map(r => ({ start: r.start.event_id, terminal: r.terminal.event_id })),
    deferral_events: results.filter(r => r.value.skipped).map(r => r.value.admissionEventId),
    scope: 'native_scheduler_owner_no_cron_registration_no_model_no_listener', canonical_memory_write: false }, null, 2));
} finally {
  releaseWork(); await Promise.allSettled(work); await drainScheduler();
  await schedulerLockPool.end(); await agentPool.end(); await pool.end();
}
