// Operator-authorized canonical route qualification. Real signed requests,
// existing agent/provider, retained native events; no alternate listener.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { pool, agentPool } from '../../db/connection.js';

assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const base = 'http://127.0.0.1:9100', actor = 'codex-auditor';
const target = '/agents/codex-auditor/run';
const session = `r6-route-queue:${randomUUID()}`, otherSession = `${session}:independent`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const requests = [], snapshots = [];
const startedAt = new Date().toISOString();

async function signed(path, body, signal, method = 'POST') {
  return fetch(base + path, { method, headers: {
    ...await buildEnvelopeHeaders(actor, method, path, body), 'Content-Type': 'application/json',
  }, ...(method === 'POST' ? { body: JSON.stringify(body) } : {}), signal });
}
async function stats() {
  const response = await signed('/status/model-suite', {}, AbortSignal.timeout(15000), 'GET');
  assert.equal(response.status, 200);
  const { runtime } = await response.json();
  assert(runtime && runtime.maxConcurrency === 6);
  assert(runtime.activeGlobalRuns >= 0 && runtime.activeGlobalRuns <= runtime.maxConcurrency);
  assert(runtime.waitingGlobalRuns >= 0 && runtime.waitingGlobalRuns <= runtime.maxQueuedRuns);
  return runtime;
}
async function until(fn, timeout, label) {
  const deadline = performance.now() + timeout;
  while (performance.now() < deadline) {
    const result = await fn();
    if (result) return result;
    await sleep(500);
  }
  throw new Error(label);
}
function send(label, sessionKey, prompt) {
  const controller = new AbortController();
  const entry = { label, sessionKey, controller, body: {
    prompt, sessionKey, idempotencyKey: randomUUID(), taskType: 'chat', disableDelegation: true,
  } };
  entry.promise = signed(target, entry.body, AbortSignal.any([controller.signal, AbortSignal.timeout(600000)]))
    .then(async response => ({ status: response.status, body: await response.json() }))
    .catch(error => ({ transportError: error.name }));
  requests.push(entry);
  return entry;
}
async function laneEvents(key) {
  return (await pool.query("SELECT id,operation,metadata FROM aimos_events WHERE company_id='hom' AND metadata->>'session_key'=$1 AND operation IN ('session_lane_started','session_lane_terminal','session_lane_admission_denied') ORDER BY ledger_seq", [key])).rows;
}

try {
  const initial = await stats();
  assert.equal(initial.activeGlobalRuns, 0, 'preexisting_active_runs');
  assert.equal(initial.waitingGlobalRuns, 0, 'preexisting_queued_runs');
  snapshots.push({ stage: 'initial', ...initial });
  console.log(JSON.stringify({ stage: 'started', at: startedAt, session, otherSession }));
  const head = send('head', session, 'Explain the difference between waiting queue capacity and running capacity for HOM-AIMOS in one short paragraph.');
  const headStart = await until(async () => (await laneEvents(session)).find(e => e.operation === 'session_lane_started'), 45000, 'native_head_not_started');
  const queued = Array.from({ length: 6 }, (_, i) => send(`queued-${i}`, session,
    'Describe why cancelled queued work must not execute later. This is a queued session-admission check.'));
  const full = await until(async () => { const s = await stats(); return s.activeGlobalRuns === 1 && s.waitingGlobalRuns === 6 ? s : null; }, 20000, 'six_waiters_not_observed');
  snapshots.push({ stage: 'one_active_six_waiting', ...full });
  const overflow = send('overflow', session, 'Explain what an explicit queue-overload response means.');
  const overflowResult = await overflow.promise;
  assert.equal(overflowResult.status, 429, JSON.stringify(overflowResult));
  assert.equal(overflowResult.body.code, 'session_queue_overloaded');
  const independent = send('independent', otherSession,
    'Explain why an unrelated session should make progress while one session has a backlog, in one short paragraph.');
  const progressed = await until(async () => { const s = await stats(); return s.activeGlobalRuns === 2 && s.waitingGlobalRuns === 6 ? s : null; }, 15000, 'independent_session_did_not_progress');
  snapshots.push({ stage: 'independent_progress_with_full_backlog', ...progressed });
  queued[1].controller.abort(); queued[4].controller.abort();
  const cancelled = await until(async () => { const s = await stats(); return s.activeGlobalRuns === 2 && s.waitingGlobalRuns === 4 ? s : null; }, 10000, 'queued_abort_did_not_release_waiters');
  snapshots.push({ stage: 'two_cancelled', ...cancelled });
  const queuedResults = await Promise.all(queued.map(q => q.promise));
  assert.equal(queuedResults.filter(r => r.transportError === 'AbortError').length, 2);
  assert.equal(queuedResults.filter(r => r.status === 408 && r.body.code === 'session_queue_timed_out').length, 4, JSON.stringify(queuedResults));
  const events = await until(async () => { const rows = await laneEvents(session); return rows.filter(e => e.operation === 'session_lane_admission_denied').length === 7 ? rows : null; }, 15000, 'denials_not_retained');
  assert.equal(events.filter(e => e.operation === 'session_lane_started').length, 1);
  const denials = events.filter(e => e.operation === 'session_lane_admission_denied');
  const counts = {};
  for (const denial of denials) {
    const verified = await readVerifiedEventById(denial.id, 'hom');
    assert.equal(verified.metadata.execution_started, false);
    counts[verified.metadata.disposition] = (counts[verified.metadata.disposition] || 0) + 1;
    const starts = await pool.query("SELECT count(*)::int AS n FROM aimos_events WHERE company_id='hom' AND metadata->>'run_id'=$1 AND operation IN ('agent_run_started','tool_context_prepared')", [verified.metadata.run_id]);
    assert.equal(starts.rows[0].n, 0);
  }
  assert.deepEqual(counts, { session_queue_overloaded: 1, session_queue_cancelled: 2, session_queue_timed_out: 4 });
  console.log(JSON.stringify({ stage: 'queue_boundaries_passed', at: new Date().toISOString(), counts, snapshots }));
  const completions = await Promise.all([head.promise, independent.promise]);
  for (const result of completions) assert.equal(result.status, 200, JSON.stringify({ status: result.status, error: result.body?.error, transportError: result.transportError }));
  const final = await until(async () => { const s = await stats(); return s.activeGlobalRuns === 0 && s.waitingGlobalRuns === 0 ? s : null; }, 15000, 'queue_counters_not_idle');
  snapshots.push({ stage: 'final', ...final });
  const terminals = [];
  for (const key of [session, otherSession]) {
    const rows = await laneEvents(key);
    const starts = rows.filter(e => e.operation === 'session_lane_started'), ends = rows.filter(e => e.operation === 'session_lane_terminal');
    assert.equal(starts.length, 1); assert.equal(ends.length, 1);
    const start = await readVerifiedEventById(starts[0].id, 'hom'), end = await readVerifiedEventById(ends[0].id, 'hom');
    assert.equal(end.metadata.start_event_id, start.id); assert.equal(end.metadata.disposition, 'COMPLETED');
    terminals.push({ session: key, run_id: start.metadata.run_id, start: start.id, terminal: end.id, verified: true });
  }
  console.log(JSON.stringify({ schema: 'hom.aimos.r6-live-route-queue/v1', at: new Date().toISOString(), started_at: startedAt,
    passed: true, session, otherSession, counts, snapshots, terminals,
    denial_event_ids: denials.map(e => e.id), completed_http_statuses: completions.map(r => r.status),
    head_start: headStart.id, no_cancelled_or_expired_callback_started: true,
    scope: 'Real canonical HTTP same-session backlog isolation, independent progress, overload, queued disconnect and expiry; not queued-success FIFO or streaming/shutdown qualification' }, null, 2));
} finally {
  // Stop this client's outstanding queued submissions; admitted native work
  // retains its own lifetime and signed terminal ownership after disconnect.
  for (const entry of requests) entry.controller.abort();
  await Promise.allSettled(requests.map(entry => entry.promise));
  await pool.end(); await agentPool.end();
}
