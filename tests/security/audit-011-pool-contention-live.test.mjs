// Only this process's restricted pool is occupied; canonical server connections
// are untouched. Actual checkout timeout and scheduler/event progress, no mocks.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { executeSystemJob, getSchedulerWorkState, drainScheduler } from '../../services/orchestration/scheduler.js';
import { pool, agentPool, schedulerLockPool, withTransaction } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const prefix=`aud011:contention:${randomUUID()}`,held=[],work=[];
const read=()=>withTransaction(async c=>(await c.query('SELECT current_database() AS database')).rows[0],{restricted:true,client_id:'hom',agent_id:'housekeeper',readOnly:true});
try{
  for(let i=0;i<10;i++)held.push(await agentPool.connect());
  const at=performance.now();let timeout;
  try{const c=await agentPool.connect();c.release();}catch(e){timeout=e;}
  const checkoutMs=performance.now()-at;assert(timeout);assert(checkoutMs>=4500&&checkoutMs<8000);
  for(let i=0;i<12;i++)work.push(executeSystemJob({jobId:prefix+':'+i,cronExpression:'* * * * *',runFn:read})
    .then(value=>({value}),error=>({error})));
  const competing=read();work.push(competing.then(value=>({value}),error=>({error})));
  await new Promise(r=>setTimeout(r,250));const saturated=getSchedulerWorkState();
  assert.equal(saturated.workPool.total,10);assert.equal(saturated.workPool.idle,0);assert(saturated.workPool.waiting>0);
  assert.equal(saturated.activeJobs,2);assert.equal(saturated.lockPool.total,2);
  while(held.length)held.pop().release();
  const results=await Promise.all(work);for(const r of results)assert(!r.error,r.error?.stack);
  const completed=results.filter(r=>r.value.skipped===false);
  assert.equal(completed.length,2);assert.equal(results.filter(r=>r.value.reason==='scheduler_capacity_busy').length,10);
  const ids=[];
  for(const {value} of completed){assert.equal((await readVerifiedEventById(value.terminal.event_id,'hom')).metadata.disposition,'SUCCEEDED');ids.push(value.terminal.event_id);}
  for(const {value} of results.filter(r=>r.value.skipped)){assert.equal((await readVerifiedEventById(value.admissionEventId,'hom')).metadata.dispatched,false);ids.push(value.admissionEventId);}
  assert.equal(getSchedulerWorkState().activeJobs,0);
  console.log(JSON.stringify({at:new Date().toISOString(),passed:true,prefix,checkout_timeout_ms:checkoutMs,scheduling_tolerance_ms:3000,saturated,
    after:getSchedulerWorkState(),event_ids:ids,competing_read_completed:true,canonical_memory_write:false,canonical_server_pool_untouched:true},null,2));
}finally{while(held.length)held.pop().release();await Promise.allSettled(work);await drainScheduler();await schedulerLockPool.end();await agentPool.end();await pool.end();}
