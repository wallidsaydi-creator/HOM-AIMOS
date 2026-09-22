// Close only this process's own dedicated lock connection. Exercise the native
// retained-start guard from a fresh process, without another HTTP listener.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { executeSystemJob, getSchedulerWorkState, cancelSchedulerWork, drainScheduler } from '../../services/orchestration/scheduler.js';
import { pool, agentPool, schedulerLockPool, withTransaction } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const jobId = `aud011:loss:${randomUUID()}`;
const read = () => withTransaction(async c => (await c.query('SELECT current_database() AS database')).rows[0],
  { restricted: true, client_id: 'hom', agent_id: 'housekeeper', readOnly: true });
const wait = () => { let release; const promise = new Promise(r => { release = r; }); return { promise, release }; };
const gate = wait(), began = wait();
let work;
try {
  const ownConnection = await schedulerLockPool.connect();
  const backendPid = (await ownConnection.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  ownConnection.release();
  work = executeSystemJob({ jobId, cronExpression: '* * * * *',
    runFn: async () => { await read(); began.release(); await gate.promise; return read(); },
  }).then(value => ({ value }), error => ({ error }));
  await began.promise;
  await ownConnection.end();
  const script = `import {executeSystemJob,drainScheduler} from './services/orchestration/scheduler.js';
    import {pool,agentPool,schedulerLockPool} from './db/connection.js';
    try { const r=await executeSystemJob({jobId:process.argv[1],cronExpression:'* * * * *',runFn:async()=>({database:(await agentPool.query('SELECT current_database() AS name')).rows[0].name})});console.log(JSON.stringify({dispatched:!r.skipped})); }
    catch(e){console.log(JSON.stringify({denied:e.message}));}finally{await drainScheduler();await schedulerLockPool.end();await agentPool.end();await pool.end();}`;
  const peer = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, jobId], { cwd: process.cwd(), stdio: ['ignore','pipe','pipe'] });
    let out = '', err = '';
    child.stdout.on('data', x => { out += x; }); child.stderr.on('data', x => { err += x; });
    child.once('error', reject); child.once('exit', code => code === 0 ? resolve(JSON.parse(out.trim())) : reject(new Error(err)));
  });
  assert.equal(peer.denied, 'scheduler_prior_run_unresolved');
  gate.release(); const result = await work;
  assert(result.error); assert.equal(getSchedulerWorkState().activeJobs, 0);
  const events = (await pool.query("SELECT id,operation FROM aimos_events WHERE company_id='hom' AND metadata->>'job_id'=$1 ORDER BY ts,ledger_seq", [jobId])).rows;
  assert.equal(events.length, 2);
  const terminal = await readVerifiedEventById(events.find(e=>e.operation==='system_job_terminal').id, 'hom');
  assert.equal(terminal.metadata.disposition, 'INDETERMINATE');
  const cancelled = await executeSystemJob({ jobId: jobId+':cancel', cronExpression:'* * * * *',
    runFn: async ({signal}) => { await read(); cancelSchedulerWork(); signal.throwIfAborted(); },
  }).then(value=>({value}),error=>({error}));
  assert.equal(cancelled.error?.message, 'scheduler_work_cancelled');
  const cancellationId=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='system_job_terminal' AND metadata->>'job_id'=$1",[jobId+':cancel'])).rows[0].id;
  assert.equal((await readVerifiedEventById(cancellationId,'hom')).metadata.disposition,'INDETERMINATE');
  console.log(JSON.stringify({at:new Date().toISOString(),passed:true,jobId,owned_backend_closed:backendPid,peer,
    terminal:terminal.id,cancellation_terminal:cancellationId,after:getSchedulerWorkState(),memory_write:false,parallel_listener:false},null,2));
} finally { gate.release(); if(work)await work; await drainScheduler();await schedulerLockPool.end();await agentPool.end();await pool.end(); }
