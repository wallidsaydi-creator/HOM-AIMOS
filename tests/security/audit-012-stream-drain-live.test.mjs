// Real streamed agent on the one canonical managed service. Observe an exact
// native tool or provider use before signalling; no test hooks or fake server.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { pool, agentPool } from '../../db/connection.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { credentialLedger } from '../../services/security/credential-ledger.js';
import { manageInstalledUserService } from '../../scripts/service/manage-user-service.mjs';
assert(process.argv.includes('--live-fire'));
const mode = process.argv.includes('--provider') ? 'provider' : 'tool';
const session = `r6-stream-drain:${randomUUID()}`, path = '/agents/codex-auditor/stream';
const base = 'http://127.0.0.1:9100';
const body = { prompt: 'Use the native aimos_recall tool to find retained evidence about HOM-AIMOS queue admission and summarize the evidence in one paragraph. Do not change configuration or perform external actions.',
  sessionKey: session, idempotencyKey: randomUUID(), disableDelegation: true, taskType: 'chat' };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, ms, reason) {
  const end=performance.now()+ms;
  while(performance.now()<end){
    try { const v=await fn();if(v)return v; }
    catch(error){
      if(!['ECONNRESET','ECONNREFUSED'].includes(error?.cause?.code))throw error;
      console.log(JSON.stringify({stage:'observation_transport_retry',code:error.cause.code}));
    }
    await sleep(1000);
  }
  throw new Error(reason);
}
let pid, signalled=false, reader, reading, receiptId, runId, boundary, shutdown, evidence, error;
let streamBytes=0, streamClosed=false, streamError=null;
try {
  const state=await manageInstalledUserService('status');assert.equal(state.definition.port,9100);assert.equal(state.definition.database,'aimos');assert.equal(state.definition.source_root,process.cwd());assert(state.health.ready);
  pid=Number(state.supervisor.detail.match(/\bpid = (\d+)/)?.[1]);assert(Number.isInteger(pid)&&pid>1&&pid!==process.pid);
  const headers=await buildEnvelopeHeaders('codex-auditor','POST',path,body),nonce=new Headers(headers).get('aimos-agent-nonce');
  const response=await fetch(base+path,{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(420000)});
  assert.equal(response.status,200);assert(response.headers.get('content-type')?.includes('text/event-stream'));
  reader=response.body.getReader();
  reading=(async()=>{try{while(true){const n=await reader.read();if(n.done){streamClosed=true;break;}streamBytes+=n.value.length;}}catch(e){streamClosed=true;streamError=e.name;}finally{reader.releaseLock();reader=null;}})();
  receiptId=await until(async()=> (await pool.query('SELECT request_receipt_id FROM aimos_request_receipts WHERE nonce=$1',[nonce])).rows[0]?.request_receipt_id,10000,'receipt_missing');
  runId=await until(async()=> (await pool.query("SELECT metadata->>'run_id' AS id FROM aimos_events WHERE company_id='hom' AND operation='agent_run_started' AND metadata->>'session_key'=$1",[session])).rows[0]?.id,30000,'run_not_started');
  console.log(JSON.stringify({stage:'accepted_stream',mode,session,runId,pid,receiptId}));
  boundary=await until(async()=>{
    let health = null;
    if(mode==='tool') {
      const response = await fetch(base+'/health');
      if (response.status === 429) return null;
      assert(response.ok, 'health_observation_failed');
      health = await response.json();
      if(!(health.runtime.lifecycle.counts.native_tool>0&&health.runtime.lifecycle.counts.canonical_recall>0))return null;
      const rows=(await pool.query("SELECT s.id FROM aimos_events s WHERE s.company_id='hom' AND s.operation='tool_execution_started' AND s.metadata->>'request_receipt_id'=$1 AND s.metadata->>'tool'='aimos_recall' AND s.metadata->>'dispatch_allowed'='true' AND NOT EXISTS (SELECT 1 FROM aimos_events t WHERE t.company_id=s.company_id AND t.operation='tool_execution_terminal' AND t.key=s.id::text) ORDER BY s.ledger_seq DESC",[receiptId])).rows;
      return rows[0]?{tool_start:rows[0].id,work:health.runtime.lifecycle}:null;
    }
    const context=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='tool_context_prepared' AND metadata->>'run_id'=$1",[runId])).rows[0];
    if(!context)return null;
    const use=(await pool.query("SELECT r.provenance_id FROM aimos_credential_lifecycle r WHERE r.service_name='oauth_codex_access_token' AND r.event_type='USE_RESERVED' AND r.body_json->>'operation'='codex.responses.create' AND r.body_json->>'request_receipt_id'=$1 AND NOT EXISTS (SELECT 1 FROM aimos_credential_lifecycle t WHERE t.event_type IN ('USE_COMPLETED','USE_FAILED') AND t.body_json->>'reservation_provenance_id'=r.provenance_id::text) ORDER BY r.created_at DESC",[receiptId])).rows[0];
    // The exact unmatched credential reservation is the provider-work proof.
    // Do not poll HTTP liveness at high frequency or confuse rate-limit JSON
    // with a lifecycle snapshot. No production limiter is changed.
    return use?{context_start:context.id,use_start:String(use.provenance_id),work_observation:'exact_unterminated_provider_reservation'}:null;
  },300000,'active_boundary_not_observed');
  const after=await buildEnvelopeHeaders('codex-auditor','GET','/aimos/status',{}),afterNonce=new Headers(after).get('aimos-agent-nonce');
  process.kill(pid,'SIGTERM');signalled=true;await sleep(30);try{process.kill(pid,'SIGINT');}catch(e){if(e.code!=='ESRCH')throw e;}
  let admission;try{admission=(await fetch(base+'/aimos/status',{headers:after,signal:AbortSignal.timeout(2000)})).status;}catch{admission='CONNECTION_CLOSED';}assert(admission===503||admission==='CONNECTION_CLOSED');
  await until(()=>{try{process.kill(pid,0);return false;}catch{return true;}},35000,'server_exit_timeout');
  await reading;assert(streamClosed);
  const rows=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='runtime_shutdown_terminal' AND metadata->>'pid'=$1",[String(pid)])).rows;assert.equal(rows.length,1);
  shutdown=await readVerifiedEventById(rows[0].id,'hom');assert(['DRAINED','INDETERMINATE'].includes(shutdown.metadata.disposition));
  assert.equal(Number((await pool.query('SELECT count(*) AS n FROM aimos_request_receipts WHERE nonce=$1',[afterNonce])).rows[0].n),0);
  evidence={at:new Date().toISOString(),mode,session,runId,receiptId,pid,boundary,streamBytes,streamClosed,streamError,post_drain_admission:admission,post_drain_receipts:0,shutdown_terminal:shutdown.id,shutdown_disposition:shutdown.metadata.disposition};
}catch(e){error=e;}
finally{
  if(signalled){const r=await manageInstalledUserService('restart');assert(r.health.ready);if(evidence)evidence.restart={ready:true,jobs:r.health.readiness.scheduler.registered_required_jobs,port:r.health.runtime.server_port,database:r.health.runtime.database_name};}
  if(reader){await reader.cancel();await reading;}
}
try {
  if(evidence){
    const ids=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND metadata->>'run_id'=$1 AND operation IN ('agent_run_terminal','session_lane_terminal')",[runId])).rows;assert.equal(ids.length,2);
    evidence.run_terminals=[];for(const r of ids){const v=await readVerifiedEventById(r.id,'hom');evidence.run_terminals.push({id:v.id,operation:v.operation,status:v.metadata.status,disposition:v.metadata.disposition,verified:true});}
    if(boundary.tool_start){
      const ids=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='tool_execution_terminal' AND key=$1",[boundary.tool_start])).rows;assert.equal(ids.length,1);
      const t=await readVerifiedEventById(ids[0].id,'hom');evidence.tool_terminal={id:t.id,disposition:t.metadata.disposition,verified:true};
      const start=await readVerifiedEventById(shutdown.metadata.start_event_id,'hom');
      assert(BigInt(t.ledger_seq)>BigInt(start.ledger_seq),'tool_settled_before_shutdown_start');
    }
    if(boundary.use_start){
      const ids=(await pool.query("SELECT provenance_id FROM aimos_credential_lifecycle WHERE event_type IN ('USE_COMPLETED','USE_FAILED') AND body_json->>'reservation_provenance_id'=$1",[boundary.use_start])).rows;assert.equal(ids.length,1);
      const t=await credentialLedger.getLifecycleRow(ids[0].provenance_id);evidence.use_terminal={id:String(t.provenance_id),event_type:t.event_type,disposition:t.body_json.disposition,verified:true};
      const contexts=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation IN ('model_context_completed','model_context_terminal') AND key=$1",[boundary.context_start])).rows;assert.equal(contexts.length,1);const c=await readVerifiedEventById(contexts[0].id,'hom');evidence.context_terminal={id:c.id,operation:c.operation,verified:true};
    }
    evidence.passed=true;console.log(JSON.stringify(evidence,null,2));
  }
  if(error)throw error;
}finally{await pool.end();await agentPool.end();}
