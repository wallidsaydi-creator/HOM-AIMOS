// Bounded native queue qualification with actual signed lifecycle writes and
// restricted SQL. No injected signer, synthetic identity, model or listener.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { withSessionLane, getSessionRunnerStats, stopConversationSessionCleanup } from '../../services/orchestration/session-runner.js';
import { getServingWorkState } from '../../services/runtime/serving-control.js';
import { pool, agentPool, withTransaction } from '../../db/connection.js';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const prefix = `aud010:capacity:${randomUUID()}`;
let release;
const held = new Promise(r=>{release=r;});
const pending=[], controllers=[];let started=0,queuedExecuted=0;
const read = () => withTransaction(async c=>(await c.query('SELECT current_database() AS database')).rows[0],
  {restricted:true,client_id:'hom',agent_id:'codex-auditor',readOnly:true});
const submit=(session,fn,signal)=>{const p=withSessionLane({companyId:'hom',agentId:'codex-auditor',sessionKey:prefix+':'+session,runId:randomUUID(),signal},fn)
  .then(value=>({value}),error=>({error}));pending.push(p);return p;};
try {
  const heads=Array.from({length:6},(_,i)=>submit(i,async()=>{await read();started++;await held;}));
  const until=performance.now()+10000;
  while(started!==6&&performance.now()<until)await new Promise(r=>setTimeout(r,10));
  assert.equal(started,6);
  const queued=[];
  for(let i=0;i<36;i++){const c=new AbortController();controllers.push(c);queued.push(submit(i%6,async()=>{queuedExecuted++;return read();},c.signal));}
  const before=await getSessionRunnerStats();assert.equal(before.activeGlobalRuns,6);assert.equal(before.waitingGlobalRuns,36);
  const excess=await submit('extra',read);assert.equal(excess.error?.code,'session_queue_overloaded');
  for(const c of controllers)c.abort();
  for(const r of await Promise.all(queued))assert.equal(r.error?.code,'session_queue_cancelled');
  release();await Promise.all(heads);assert.equal(queuedExecuted,0);
  const pre=new AbortController();pre.abort();assert.equal((await submit('pre',read,pre.signal)).error?.code,'session_queue_cancelled');
  const post=new AbortController();let ran=false;
  const reserved=submit('reserved',async()=>{ran=true;return read();},post.signal);post.abort();
  assert.equal((await reserved).error?.code,'session_queue_cancelled');assert.equal(ran,false);
  const failure=await submit('sql_failure',()=>withTransaction(c=>c.query('SELECT 1/0'),{restricted:true,client_id:'hom',agent_id:'codex-auditor'}));
  assert.equal(failure.error?.code,'22012');
  const after=await getSessionRunnerStats();assert.equal(after.activeGlobalRuns,0);assert.equal(after.waitingGlobalRuns,0);assert.equal(after.trackedSessionLanes,0);assert.equal(getServingWorkState().active,0);
  console.log(JSON.stringify({at:new Date().toISOString(),passed:true,prefix,before,after,queued_callbacks_executed:queuedExecuted,
    cancellation_after_slot_reservation:true,real_sql_callback_failure:failure.error.code,scope:'native_owner_not_HTTP_model_run',memory_write:false},null,2));
}finally{release();for(const c of controllers)c.abort();await Promise.allSettled(pending);stopConversationSessionCleanup();await agentPool.end();await pool.end();}
