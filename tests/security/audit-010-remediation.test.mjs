// Explicit canonical qualification: actual session owner, real signed lifecycle
// events and restricted PostgreSQL reads. No model, new identity or listener.
// Not registered in the source suite; --live-fire is required.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { withSessionLane, getSessionRunnerStats, stopConversationSessionCleanup } from '../../services/orchestration/session-runner.js';
import { pool, agentPool, withTransaction } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { getServingWorkState } from '../../services/runtime/serving-control.js';

assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const prefix = `aud010:${randomUUID()}`;
const order = [], runs = [], pending = [];
let releaseHead, headStarted;
const held = new Promise(resolve => { releaseHead = resolve; });
const started = new Promise(resolve => { headStarted = resolve; });
const read = () => withTransaction(async client => {
  const row = (await client.query('SELECT current_database() AS database, current_user AS role')).rows[0];
  assert.equal(row.database, 'aimos'); assert.equal(row.role, 'agent_runtime');
  return row;
}, { restricted: true, client_id: 'hom', agent_id: 'codex-auditor', readOnly: true });
const submit = (session, fn, options = {}) => {
  const runId = randomUUID(); runs.push(runId);
  const promise = withSessionLane({ companyId: 'hom', agentId: 'codex-auditor',
    sessionKey: `${prefix}:${session}`, runId, ...options }, fn)
    .then(value => ({ value }), error => ({ error }));
  pending.push(promise); return promise;
};
try {
  const head = submit('backlog', async () => { await read(); order.push('head'); headStarted(); await held; });
  await started;
  const controllers = Array.from({ length: 5 }, () => new AbortController());
  const backlog = controllers.map((c, i) => submit('backlog', async () => { await read(); order.push(i); }, { signal: c.signal }));
  const expiring = submit('backlog', async () => { throw Error('expired_callback_executed'); }, { deadlineAt: performance.now() + 80 });
  const excess = submit('backlog', async () => { throw Error('overloaded_callback_executed'); });
  const before = await getSessionRunnerStats();
  assert.equal(before.activeGlobalRuns, 1); assert.equal(before.waitingGlobalRuns, 6);
  const other = submit('independent', async () => { await read(); order.push('independent'); });
  const otherResult = await other;
  assert(!otherResult.error); assert.deepEqual(order, ['head', 'independent']);
  controllers[1].abort(); controllers[3].abort();
  assert.equal((await excess).error?.code, 'session_queue_overloaded');
  assert.equal((await expiring).error?.code, 'session_queue_timed_out');
  releaseHead(); await head; await Promise.all(backlog);
  assert.deepEqual(order, ['head', 'independent', 0, 2, 4]);
  const after = await getSessionRunnerStats();
  assert.equal(after.activeGlobalRuns, 0); assert.equal(after.waitingGlobalRuns, 0);
  assert.equal(after.trackedSessionLanes, 0);
  const eventIds = await withTransaction(async client => (await client.query(
    "SELECT id FROM aimos_events WHERE company_id='hom' AND operation IN ('session_lane_started','session_lane_terminal','session_lane_admission_denied') AND metadata->>'run_id'=ANY($1::text[]) ORDER BY ts,id", [runs])).rows.map(r => r.id),
  { restricted: true, client_id: 'hom', agent_id: 'housekeeper', readOnly: true });
  const events = [];
  for (const id of eventIds) events.push(await readVerifiedEventById(id, 'hom'));
  const counts = Object.fromEntries(['session_lane_started', 'session_lane_terminal', 'session_lane_admission_denied'].map(op => [op, events.filter(e => e.operation === op).length]));
  assert.deepEqual(counts, { session_lane_started: 5, session_lane_terminal: 5, session_lane_admission_denied: 4 });
  assert.equal(getServingWorkState().active, 0);
  console.log(JSON.stringify({ at: new Date().toISOString(), prefix, scope: 'native_session_owner_not_HTTP_model_run',
    passed: true, order, counts, event_ids: eventIds, before, after, canonical_memory_write: false }, null, 2));
} finally {
  releaseHead(); await Promise.allSettled(pending);
  stopConversationSessionCleanup(); await agentPool.end(); await pool.end();
}
