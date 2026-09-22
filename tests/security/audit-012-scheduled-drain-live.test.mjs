// Observe the existing real cron; do not register, accelerate or invent a job.
import assert from 'node:assert/strict';
import { pool, agentPool } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { manageInstalledUserService } from '../../scripts/service/manage-user-service.mjs';
assert(process.argv.includes('--live-fire'));
const base='http://127.0.0.1:9100',sleep=ms=>new Promise(r=>setTimeout(r,ms));
const from=Math.floor(Date.now()/1000);let pid,signalled=false,evidence,error;
try{
  const status=await manageInstalledUserService('status');assert(status.health.ready);assert.equal(status.definition.port,9100);assert.equal(status.definition.database,'aimos');assert.equal(status.definition.source_root,process.cwd());
  pid=Number(status.supervisor.detail.match(/\bpid = (\d+)/)?.[1]);assert(pid>1&&pid!==process.pid);
  const headers=await buildEnvelopeHeaders('codex-auditor','GET','/aimos/status',{});
  const end=performance.now()+31*60000;let active;
  console.log(JSON.stringify({stage:'waiting_existing_cron',pid,from}));
  while(performance.now()<end){
    active=(await pool.query("SELECT s.id,s.key,s.metadata->>'job_id' AS job_id FROM aimos_events s WHERE s.company_id='hom' AND s.operation='system_job_started' AND s.ts_signed>=$1 AND NOT EXISTS (SELECT 1 FROM aimos_events t WHERE t.company_id=s.company_id AND t.operation='system_job_terminal' AND t.key=s.key) ORDER BY s.ledger_seq",[from])).rows;
    if(active.length)break;
    const minute=new Date().getUTCMinutes(),second=new Date().getUTCSeconds();
    await sleep(minute%30===0||minute%30===29&&second>55?25:1000);
  }
  assert(active?.length,'no_existing_due_job_observed');
  process.kill(pid,'SIGTERM');signalled=true;await sleep(30);try{process.kill(pid,'SIGINT');}catch(e){if(e.code!=='ESRCH')throw e;}
  let admission;try{admission=(await fetch(base+'/aimos/status',{headers,signal:AbortSignal.timeout(2000)})).status;}catch{admission='CONNECTION_CLOSED';}assert(admission===503||admission==='CONNECTION_CLOSED');
  const exit=performance.now()+35000;let stopped=false;while(performance.now()<exit){try{process.kill(pid,0);}catch{stopped=true;break;}await sleep(25);}assert(stopped);
  const rows=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='runtime_shutdown_terminal' AND metadata->>'pid'=$1",[String(pid)])).rows;assert.equal(rows.length,1);
  const terminal=await readVerifiedEventById(rows[0].id,'hom'),start=await readVerifiedEventById(terminal.metadata.start_event_id,'hom');
  assert(['DRAINED','INDETERMINATE'].includes(terminal.metadata.disposition));
  evidence={at:new Date().toISOString(),pid,observed_jobs:active,shutdown_start:start.id,shutdown_start_seq:String(start.ledger_seq),shutdown_terminal:terminal.id,shutdown_disposition:terminal.metadata.disposition,post_drain_admission:admission};
}catch(e){error=e;}finally{
  if(signalled){const r=await manageInstalledUserService('restart');assert(r.health.ready);if(evidence)evidence.restart={ready:true,jobs:r.health.readiness.scheduler.registered_required_jobs,port:r.health.runtime.server_port,database:r.health.runtime.database_name};}
}
try{
 if(evidence){let crossed=0;evidence.job_terminals=[];
  for(const job of evidence.observed_jobs){const start=await readVerifiedEventById(job.id,'hom');const rows=(await pool.query("SELECT id FROM aimos_events WHERE company_id='hom' AND operation='system_job_terminal' AND key=$1",[job.key])).rows;assert.equal(rows.length,1);const t=await readVerifiedEventById(rows[0].id,'hom');assert.equal(t.metadata.start_event_id,start.id);const during=BigInt(t.ledger_seq)>BigInt(evidence.shutdown_start_seq);if(during)crossed++;evidence.job_terminals.push({id:t.id,job:job.job_id,disposition:t.metadata.disposition,crossed_shutdown_start:during,verified:true});}
  assert(crossed>0,'all_jobs_finished_before_shutdown_started');evidence.passed=true;console.log(JSON.stringify(evidence,null,2));
 }
 if(error)throw error;
}finally{await pool.end();await agentPool.end();}
