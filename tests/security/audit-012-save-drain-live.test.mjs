// One canonical managed service. Hold only this new SAVE's exact native
// advisory key, signal the real server, release during drain, verify retention,
// then restore the same managed service. No test hook, installer or second DB.
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { pool, agentPool } from '../../db/connection.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { getAgentCert, canonicalJson } from '../../services/security/agent-identity.js';
import { extractValidFromIso } from '../../services/security/housekeeper-signer.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { manageInstalledUserService } from '../../scripts/service/manage-user-service.mjs';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const base='http://127.0.0.1:9100',agent='codex-auditor',operationId=randomUUID();
const memoryKey=`audit:r6:drain:${operationId}`;
const body={save_operation_id:operationId,key:memoryKey,
  value:'R6 managed shutdown qualification is in progress on the canonical HOM-AIMOS service. Fair session admission now separates queued work from running capacity. Scheduler lock connections are separate from its database work capacity. This retained procedural note exercises the existing signed SAVE path during a controlled drain; R6 is not yet independently closed.',
  memory_type:'procedural',scope:'system',clearance_level:5,data_class:'internal',source:'r6-native-qualification',
  session_id:'08fd5e8d-ddec-4c7c-84f9-fabf04bde253'};
const epoch=extractValidFromIso(await getAgentCert(agent));
const key='canonical-save:'+createHash('sha256').update(canonicalJson({schema:'hom.aimos.canonical-save-operation/v1',company_id:'hom',actor_agent_id:agent,actor_valid_from:epoch,operation_id:operationId})).digest('hex');
const lock=await agentPool.connect();let locked=false,signalled=false,pid,savePending,streamReader;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let evidence, failure;
try {
  const status=await manageInstalledUserService('status');assert(status.success);assert.equal(status.definition.port,9100);assert.equal(status.definition.database,'aimos');assert.equal(status.definition.source_root,process.cwd());
  pid=Number(status.supervisor.detail.match(/\bpid = (\d+)/)?.[1]);assert(Number.isInteger(pid)&&pid>1&&pid!==process.pid);
  const ownPid=(await lock.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  await lock.query('SELECT pg_advisory_lock(hashtextextended($1,0))',[key]);locked=true;
  const headers=await buildEnvelopeHeaders(agent,'POST','/aimos/save',body);
  savePending=fetch(base+'/aimos/save',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(45000)})
    .then(async response=>({status:response.status,body:await response.json()})).catch(error=>({error}));
  let blocked;
  const until=performance.now()+15000;
  while(performance.now()<until){
    blocked=(await pool.query("SELECT pid,wait_event,query FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))",[ownPid])).rows.find(r=>r.query.includes('pg_advisory_xact_lock'));
    if(blocked)break;await sleep(25);
  }
  assert(blocked,'owned_save_precommit_wait_not_observed');
  assert.equal(Number((await pool.query('SELECT count(*) AS n FROM aimos_memories WHERE company_id=$1 AND key=$2',['hom',memoryKey])).rows[0].n),0);
  const streamPath='/mcp?sessionId='+randomUUID();
  const stream=await fetch(base+streamPath,{headers:await buildEnvelopeHeaders(agent,'GET',streamPath,{}),signal:AbortSignal.timeout(45000)});
  assert.equal(stream.status,200);streamReader=stream.body.getReader();await streamReader.read();
  const afterHeaders=await buildEnvelopeHeaders(agent,'GET','/aimos/status',{});
  const afterNonce=new Headers(afterHeaders).get('aimos-agent-nonce');
  const preHealth=await (await fetch(base+'/health')).json();assert(preHealth.runtime.lifecycle.counts.canonical_save>=1);
  process.kill(pid,'SIGTERM');signalled=true;await sleep(30);process.kill(pid,'SIGINT');
  await sleep(400);
  let postDrain;try{postDrain=(await fetch(base+'/aimos/status',{headers:afterHeaders,signal:AbortSignal.timeout(2000)})).status;}catch{postDrain='CONNECTION_CLOSED';}
  assert(postDrain===503||postDrain==='CONNECTION_CLOSED');
  await lock.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[key]);locked=false;
  const saved=await savePending;assert(!saved.error,saved.error?.message);assert.equal(saved.status,200,JSON.stringify(saved.body));
  const saveTerminal=await readVerifiedEventById(saved.body.terminal_event_id,'hom');assert.equal(saveTerminal.id,saved.body.terminal_event_id);
  let streamDone=false;while(!streamDone){streamDone=(await streamReader.read()).done;}streamReader.releaseLock();streamReader=null;
  const exitUntil=performance.now()+30000;let exited=false;
  while(performance.now()<exitUntil){try{process.kill(pid,0);}catch{exited=true;break;}await sleep(25);}assert(exited,'managed_pid_did_not_exit');
  const shutdown=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='runtime_shutdown_terminal' AND metadata->>'pid'=$1",[String(pid)])).rows;
  assert.equal(shutdown.length,1);const terminal=await readVerifiedEventById(shutdown[0].id,'hom');assert.equal(terminal.metadata.disposition,'DRAINED');
  const afterReceipt=Number((await pool.query('SELECT count(*) AS n FROM aimos_request_receipts WHERE company_id=$1 AND nonce=$2',['hom',afterNonce])).rows[0].n);assert.equal(afterReceipt,0);
  evidence={at:new Date().toISOString(),passed:true,pre_pid:pid,operation_id:operationId,memory_id:saved.body.memory_id,
    memory_key:memoryKey,precommit_wait_observed:true,precommit_memory_count:0,post_drain_admission:postDrain,post_drain_receipts:afterReceipt,
    save_http_status:saved.status,save_terminal:saveTerminal.id,stage_count:saved.body.stage_count,
    shutdown_terminal:terminal.id,shutdown_disposition:terminal.metadata.disposition,duplicate_signal_terminal_count:shutdown.length,mcp_stream_closed:true,
    scope:'real_managed_SIGTERM_during_native_SAVE_precommit_and_MCP_SSE'};
}catch(error){failure=error;}
finally{
  if(locked)await lock.query('SELECT pg_advisory_unlock(hashtextextended($1,0))',[key]);lock.release();
  if(streamReader){try{await streamReader.cancel();}catch{}streamReader.releaseLock();}
  if(savePending)await savePending;
  if(signalled){const resumed=await manageInstalledUserService('restart');assert(resumed.health.ready);if(evidence)evidence.restart={ready:true,scheduler_jobs:resumed.health.readiness.scheduler.registered_required_jobs,database:resumed.health.runtime.database_name,port:resumed.health.runtime.server_port};}
  if(evidence){const row=(await pool.query('SELECT id,encode(content_hash,\'hex\') AS content_hash FROM aimos_memories WHERE id=$1',[evidence.memory_id])).rows[0];assert(row);evidence.retained_after_restart=true;evidence.content_hash=row.content_hash;console.log(JSON.stringify(evidence,null,2));}
  await agentPool.end();await pool.end();
}
if(failure)throw failure;
