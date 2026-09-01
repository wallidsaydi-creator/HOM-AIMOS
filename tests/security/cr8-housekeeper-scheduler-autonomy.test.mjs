import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { proveCr8HousekeeperScheduler } from '../../scripts/verification/prove-cr8-housekeeper-scheduler.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('Housekeeper system-job owner proves success, uncertainty, overlap denial and restart no-op', () => {
  const moduleUrl = pathToFileURL(path.join(ROOT, 'services/orchestration/scheduler.js')).href;
  const script = `
    const {executeSystemJob,reconstructSystemJobRuns,reconcileOpenSystemJobs,stopScheduler}=await import(${JSON.stringify(moduleUrl)});
    const rows=[];let seq=0;const log=async(company,agent,operation,key,metadata,parent)=>{if(rows.some(r=>r.operation===operation&&r.key===key))throw new Error('event_operation_key_exists');const id='e'+(++seq);const mutation=String(seq).padStart(64,'0');rows.push({id,event_id:id,company_id:company,agent_id:agent,operation,key,metadata,parent_event_id:parent,mutation_hash:mutation});return {event_id:id,mutation_hash:mutation};};
    const lock=async(_key,fn)=>fn();const ok=await executeSystemJob({jobId:'__test_ok__',cronExpression:'* * * * *',runFn:async()=>({ok:true}),lockFn:lock,logEventFn:log,runIdFn:()=> 'run-ok'});let failed=false;try{await executeSystemJob({jobId:'__test_fail__',cronExpression:'* * * * *',runFn:async()=>{throw new Error('boom')},lockFn:lock,logEventFn:log,runIdFn:()=> 'run-fail'});}catch{failed=true;}const skipped=await executeSystemJob({jobId:'__test_skip__',cronExpression:'* * * * *',runFn:async()=>{throw new Error('must-not-run')},lockFn:async()=>({skipped:true,reason:'overlap'}),logEventFn:log});
    rows.push({id:'orphan',event_id:'orphan',company_id:'hom',agent_id:'housekeeper',operation:'system_job_started',key:'run-orphan',parent_event_id:null,mutation_hash:'a'.repeat(64),metadata:{schema:'hom.aimos.system-job-run/v1',run_id:'run-orphan',job_id:'__orphan__',cron_expression:'* * * * *',actor_agent_id:'housekeeper'}});const first=await reconcileOpenSystemJobs({events:rows,logEventFn:log});const second=await reconcileOpenSystemJobs({events:rows,logEventFn:log});const reconstructed=reconstructSystemJobRuns([...rows].reverse());let fork=false;try{reconstructSystemJobRuns([...rows,structuredClone(rows.find(r=>r.key==='run-ok'&&r.operation==='system_job_terminal'))]);}catch(e){fork=/terminal_fork/.test(e.message);}stopScheduler();process.stdout.write(JSON.stringify({ok:ok.result.ok,failed,skipped,first,second,complete:reconstructed.complete.length,fork,rows}));process.exit(0);
  `;
  const result = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
    cwd: ROOT, encoding: 'utf8', timeout: 10_000,
  }));
  assert.equal(result.ok, true);
  assert.equal(result.failed, true);
  assert.equal(result.skipped.skipped, true);
  assert.equal(result.first.jobsReplayed, 0);
  assert.equal(result.first.remainingOpen, 0);
  assert.equal(result.second.reconciled.length, 0);
  assert.equal(result.fork, true);
  assert.equal(result.rows.every((row) => row.agent_id === 'housekeeper'), true);
});

test('delegated schedule orphan recovery binds the original reservation and never reruns the agent', () => {
  const moduleUrl = pathToFileURL(path.join(ROOT, 'services/orchestration/scheduler.js')).href;
  const script = `
    const {reconstructDelegatedScheduleRuns,reconcileOpenDelegatedSchedules,stopScheduler}=await import(${JSON.stringify(moduleUrl)});const rows=[{id:'reserved',company_id:'hom',agent_id:'housekeeper',operation:'schedule_run_reserved',key:'schedule-1',parent_event_id:null,mutation_hash:'a'.repeat(64),metadata:{schema:'hom.aimos.schedule/v1',schedule_id:'schedule-1',run_id:'run-1',last_status:'running'}}];const schedule={id:'schedule-1',agentId:'codex-auditor',verified:true};let calls=0;const mark=async(_schedule,input)=>{calls++;rows.push({id:'terminal',company_id:'hom',agent_id:'housekeeper',operation:'schedule_run_failed',key:'schedule-1',parent_event_id:input.parentEventId,mutation_hash:'b'.repeat(64),metadata:{schema:'hom.aimos.schedule/v1',schedule_id:'schedule-1',run_id:input.runId,start_event_id:input.parentEventId,start_mutation_hash:input.startMutationHash,last_status:input.status}});return {event_id:'terminal',mutation_hash:'b'.repeat(64)};};const first=await reconcileOpenDelegatedSchedules({schedules:[schedule],events:rows,markStatusFn:mark});const second=await reconcileOpenDelegatedSchedules({schedules:[schedule],events:rows,markStatusFn:mark});const proof=reconstructDelegatedScheduleRuns([...rows].reverse());stopScheduler();process.stdout.write(JSON.stringify({first,second,calls,complete:proof.complete.length}));process.exit(0);
  `;
  const result = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
    cwd: ROOT, encoding: 'utf8', timeout: 10_000,
  }));
  assert.equal(result.calls, 1);
  assert.equal(result.first.jobsReplayed, 0);
  assert.equal(result.first.remainingOpen, 0);
  assert.equal(result.second.reconciled.length, 0);
  assert.equal(result.complete, 1);
});

test('independent CR8 audit proves truthful scheduler authority without local-model or tenant dependency', () => {
  const proof = proveCr8HousekeeperScheduler();
  assert.equal(proof.required_system_jobs, 5);
  assert.equal(proof.autonomous_principal, 'housekeeper');
  assert.equal(proof.signed_start_terminal, true);
  assert.equal(proof.overlap_fail_closed, true);
  assert.equal(proof.scheduler_readiness_gates_server_readiness, true);
  assert.equal(proof.tenant_dependencies, 0);
  assert.equal(proof.local_model_required, false);
  assert.equal(proof.paper_authority.formulas_changed, false);
  assert.equal(proof.live_database_mutated, false);
  assert.match(proof.source_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.audit_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});

test('scheduler startup reuses one verified event snapshot when no jobs are open', () => {
  const source = fs.readFileSync(path.join(ROOT, 'services/orchestration/scheduler.js'), 'utf8');
  const start = source.indexOf('export async function startScheduler');
  const end = source.indexOf('\nexport function stopScheduler', start);
  const owner = source.slice(start, end);
  assert.equal((owner.match(/readVerifiedEventHistory\(/g) || []).length, 1);
  assert.match(owner, /reconstructSystemJobRuns\(recoveryEvents\)/);
  assert.match(owner, /reconstructDelegatedScheduleRuns\(recoveryEvents\)/);
});
