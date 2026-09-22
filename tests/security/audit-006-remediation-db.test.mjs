// R3's owned PostgreSQL fault qualification. No product listener, new identity,
// Keychain write, canonical row copy or canonical fault injection.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import pg from 'pg';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database=process.argv[process.argv.indexOf('--aimos-db')+1];
assert(/^aimos_test_security_audr3_[0-9]+_[a-f0-9]{6}$/.test(database));
const original=new URL(resolveAimosDatabaseUrl());
assert.equal(original.pathname,`/${database}`);
const observer=new pg.Client({connectionString:original.href,connectionTimeoutMillis:3000});
const canonicalUrl=new URL(original.href);canonicalUrl.pathname='/aimos';
const authorityReader=new pg.Client({connectionString:canonicalUrl.href,connectionTimeoutMillis:3000});
const sockets=new Set(), held=new Set();
let fault=null;
let canonicalCommitObserved=null;
const observations=[];
const proxy=net.createServer(front=>{
  const back=net.connect({host:original.hostname,port:Number(original.port||5432)});
  sockets.add(front);sockets.add(back);
  let startup=true, input=Buffer.alloc(0), output=Buffer.alloc(0), intercepted=null;
  let canonicalMemoryTransaction=false;
  let drainCommittedBackend=false;
  const destroy=()=>{front.destroy();if(!held.has(back))back.destroy();};
  for(const socket of [front,back]){socket.on('error',destroy);socket.on('close',()=>sockets.delete(socket));}
  front.on('close',()=>{if(!held.has(back))back.destroy();});
  back.on('close',()=>front.destroy());
  front.on('data',data=>{
    input=Buffer.concat([input,data]);
    while(input.length>=(startup?4:5)){
      const length=input.readInt32BE(startup?0:1)+(startup?0:1);
      assert(length>=4&&length<=1048576,'bounded_postgres_frontend_frame');
      if(input.length<length)return;
      const frame=input.subarray(0,length);input=input.subarray(length);
      const query=!startup&&frame[0]===81?frame.subarray(5,-1).toString():null;
      let parsedQuery=null;
      if(!startup&&frame[0]===80){
        const statementEnd=frame.indexOf(0,5);
        const queryEnd=statementEnd<0?-1:frame.indexOf(0,statementEnd+1);
        if(queryEnd>statementEnd)parsedQuery=frame.subarray(statementEnd+1,queryEnd).toString();
      }
      if(/INSERT\s+INTO\s+(?:public\.)?aimos_memories\b/i.test(parsedQuery||query||'')){
        canonicalMemoryTransaction=true;
      }
      startup=false;
      const canonicalFault=fault==='canonical_committed_ack_lost';
      if(query==='COMMIT'&&fault&&(!canonicalFault||canonicalMemoryTransaction)){
        intercepted=fault;fault=null;
        if(intercepted==='commit_not_delivered'){destroy();return;}
        if(intercepted==='transaction_still_open'){held.add(back);front.destroy();return;}
      }
      back.write(frame);
    }
  });
  back.on('data',data=>{
    output=Buffer.concat([output,data]);
    while(output.length>=5){
      const length=output.readInt32BE(1)+1;
      assert(length>=5&&length<=1048576,'bounded_postgres_backend_frame');
      if(output.length<length)return;
      const frame=output.subarray(0,length);output=output.subarray(length);
      if(['committed_ack_lost','canonical_committed_ack_lost'].includes(intercepted)
          &&frame[0]===67&&frame.subarray(5,-1).toString()==='COMMIT'){
        observations.push('server_COMMIT_command_complete_observed_before_transport_loss');
        canonicalCommitObserved?.();canonicalCommitObserved=null;
        held.add(back);drainCommittedBackend=true;front.destroy();continue;
      }
      if(drainCommittedBackend){
        if(frame[0]===90){held.delete(back);back.end();}
        continue;
      }
      front.write(frame);
    }
  });
});
await new Promise((resolve,reject)=>{proxy.once('error',reject);proxy.listen(0,'127.0.0.1',resolve);});
const routed=new URL(original.href);routed.hostname='127.0.0.1';routed.port=String(proxy.address().port);
process.argv.push('--aimos-postgres-port', routed.port);
const db=await import('../../db/connection.js');
// Both native pools resolve this explicit isolated PostgreSQL port at module
// creation. No production injection option is added to withTransaction.
const result={database,product_listener_started:false,genesis_invoked:false,new_identity:false,
  production_canonical_writes:false,scratch_native_canonical_save:true,
  mechanism:'native_canonical_SAVE_over_real_PostgreSQL_wire'};
const failures=[];
async function check(name,fn){try{await fn();result[name]=true;}catch(e){failures.push({name,error:e.message});}}
async function attempt(id,mode){
  fault=mode;
  try{return {value:await db.withTransaction(async c=>{
    await c.query('INSERT INTO aud006_commit_truth(id) VALUES($1) ON CONFLICT(id) DO NOTHING',[id]);
    return id;
  })};}catch(error){return {error,outcome:db.getTransactionOutcome?.(error)||null};}
}
async function count(id){return (await observer.query('SELECT count(*)::int AS n FROM aud006_commit_truth WHERE id=$1',[id])).rows[0].n;}
async function readbackInFreshProcess(input){
  const marker='AUD006_PROCESS_READBACK:';
  const program=`
    const input=JSON.parse(Buffer.from(process.env.AUD006_INPUT,'base64url').toString('utf8'));
    const db=await import('./db/connection.js');
    const current=(await db.pool.query('SELECT current_database() AS name')).rows[0]?.name;
    if(current!==process.env.AUD006_DATABASE)throw new Error('audit006_child_database_scope_mismatch');
    const {createHousekeeperCanonicalSaveOwner}=await import('./services/write/canonical-save-owner.js');
    const result=await createHousekeeperCanonicalSaveOwner()(input);
    process.stdout.write('${marker}'+JSON.stringify({id:result.id,operation_replayed:result.operation_replayed})+'\\n');
    await Promise.allSettled([db.pool.end(),db.agentPool.end()]);
  `;
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[
      '--input-type=module','-e',program,'audit-006-child','--aimos-db',database,
      '--aimos-postgres-port',String(original.port||5432),
    ],{cwd:process.cwd(),env:{...process.env,AUD006_DATABASE:database,
      AUD006_INPUT:Buffer.from(JSON.stringify(input)).toString('base64url')},
      stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('canonical_process_restart_readback_timeout'));},60_000);
    child.stdout.on('data',chunk=>{stdout+=chunk;});
    child.stderr.on('data',chunk=>{stderr+=chunk;});
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('exit',(code,signal)=>{
      clearTimeout(timer);
      if(code!==0)return reject(new Error(`canonical_process_restart_readback_failed:${code??signal}:${stderr.slice(0,500)}`));
      const line=stdout.split(/\r?\n/).find(entry=>entry.startsWith(marker));
      if(!line)return reject(new Error('canonical_process_restart_readback_result_missing'));
      try{resolve(JSON.parse(line.slice(marker.length)));}catch(error){reject(error);}
    });
  });
}
try{
  await Promise.all([observer.connect(),authorityReader.connect()]);
  assert.equal((await observer.query('SELECT current_database() AS name')).rows[0].name,database);
  const master=(await authorityReader.query(`SELECT id,master_pubkey,fingerprint,created_at,
    revocation_cert_hash,keychain_service,keychain_account FROM aimos_master_identity WHERE id=1`)).rows[0];
  const housekeeper=(await authorityReader.query(`SELECT agent_id,pubkey,cert,device_fp,valid_from,
    valid_until,issued_at,revoked_at,chain_head,is_system_role FROM agent_identity identity
    WHERE agent_id='housekeeper' AND revoked_at IS NULL AND NOT EXISTS (
      SELECT 1 FROM aimos_agent_revocation_events revocation
      WHERE revocation.agent_id=identity.agent_id AND revocation.agent_valid_from=identity.valid_from)
    ORDER BY valid_from DESC LIMIT 1`)).rows[0];
  assert(master&&housekeeper,'canonical public Housekeeper authority required');
  await observer.query(`INSERT INTO aimos_master_identity
    (id,master_pubkey,fingerprint,created_at,revocation_cert_hash,keychain_service,keychain_account)
    VALUES($1,$2,$3,$4,$5,$6,$7)`,Object.values(master));
  await observer.query(`INSERT INTO agent_identity
    (agent_id,pubkey,cert,device_fp,valid_from,valid_until,issued_at,revoked_at,chain_head,is_system_role)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,Object.values(housekeeper));
  const profiles=(await authorityReader.query(`SELECT profile_sha256,schema_id,profile_version,
    body_json,body_bytes,installed_at FROM aimos_origin_family_profiles`)).rows;
  for(const row of profiles)await observer.query(`INSERT INTO aimos_origin_family_profiles
    (profile_sha256,schema_id,profile_version,body_json,body_bytes,installed_at)
    VALUES($1,$2,$3,$4,$5,$6)`,Object.values(row));
  const definitions=(await authorityReader.query(`SELECT profile_sha256,family_id,parent_id,
    confidentiality_floor,action_policy FROM aimos_origin_family_definitions`)).rows;
  for(const row of definitions)await observer.query(`INSERT INTO aimos_origin_family_definitions
    (profile_sha256,family_id,parent_id,confidentiality_floor,action_policy)
    VALUES($1,$2,$3,$4,$5)`,Object.values(row));
  await observer.query('CREATE TABLE aud006_commit_truth(id text PRIMARY KEY)');
  await check('precommit_failure_confirmed_not_committed',async()=>{
    let error;try{await db.withTransaction(async c=>{await c.query("INSERT INTO aud006_commit_truth VALUES('precommit')");throw new Error('owned_precommit_fault');});}catch(e){error=e;}
    assert.equal(await count('precommit'),0);assert.equal(db.getTransactionOutcome?.(error)?.state,'NOT_COMMITTED');
  });
  await check('commit_not_delivered_not_misreported_committed',async()=>{
    const a=await attempt('not-delivered','commit_not_delivered');assert(a.error);
    assert.equal(await count('not-delivered'),0);assert(['NOT_COMMITTED','INDETERMINATE'].includes(a.outcome?.state));
  });
  await check('committed_ack_loss_recognized_without_replaying',async()=>{
    const a=await attempt('committed','committed_ack_lost');assert(a.error);
    assert.equal(await count('committed'),1);assert.equal(a.outcome?.state,'COMMITTED');
    assert(observations.includes('server_COMMIT_command_complete_observed_before_transport_loss'));
  });
  await check('live_original_transaction_remains_indeterminate',async()=>{
    const a=await attempt('open','transaction_still_open');assert(a.error);
    assert.equal(await count('open'),0);assert.equal(a.outcome?.state,'INDETERMINATE');
    assert.equal(a.outcome?.postgresStatus,'in progress');
    for(const back of held)back.destroy();held.clear();
    const retry=await attempt('open',null);assert.equal(retry.value,'open');assert.equal(await count('open'),1);
  });
  await check('swallowed_sql_error_cannot_return_success',async()=>{
    let error;try{await db.withTransaction(async c=>{try{await c.query('SELECT 1/0');}catch{}return 'must-not-return-success';});}catch(e){error=e;}
    assert(error);assert.equal(db.getTransactionOutcome?.(error)?.state,'NOT_COMMITTED');
  });
  await check('subsequent_native_transaction_works',async()=>{assert.equal(await db.withTransaction(async c=>(await c.query('SELECT 42 AS n')).rows[0].n),42);});
  await check('canonical_save_lost_ack_concurrent_retry_and_owner_restart',async()=>{
    const { createHousekeeperCanonicalSaveOwner } = await import('../../services/write/canonical-save-owner.js');
    const operationId='60000000-0000-4000-8000-000000000006';
    const key=`audit:r3:commit-loss:${database}`;
    const input={company_id:'hom',agent_id:'housekeeper',key,
      value:'AUD-006 qualifies the native canonical SAVE owner across a real PostgreSQL transport loss after the server commits. The same signed operation is retried concurrently and after owner reconstruction. Exactly one retained memory, provenance chain, origin binding, and successful terminal may exist; transport uncertainty must never fabricate rollback or repeat a durable effect.',
      scope:'system',clearance_level:12,data_class:'restricted',memory_type:'declarative',
      source:'audit:r3',save_operation_id:operationId};
    let resolveObserved;
    const observed=new Promise(resolve=>{resolveObserved=resolve;});
    canonicalCommitObserved=resolveObserved;
    fault='canonical_committed_ack_lost';
    const first=createHousekeeperCanonicalSaveOwner()(input);
    const boundary=await Promise.race([
      observed.then(()=>({state:'COMMIT_OBSERVED'})),
      first.then(value=>({state:'SAVE_FINISHED_BEFORE_FAULT',value}),
        error=>({state:'SAVE_FAILED_BEFORE_FAULT',error})),
      new Promise(resolve=>setTimeout(()=>resolve({state:'TIMEOUT'}),30_000).unref()),
    ]);
    if(boundary.state!=='COMMIT_OBSERVED'){
      throw new Error(`canonical_commit_not_observed:${boundary.state}:${boundary.error?.message
        ||boundary.value?.reason||boundary.value?.canonical_save_trace?.outcome||'none'}`);
    }
    const concurrent=createHousekeeperCanonicalSaveOwner()(input);
    const settled=await Promise.allSettled([first,concurrent]);
    if(settled.some(entry=>entry.status==='rejected')){
      throw new Error(`canonical_save_retry_failed:${settled.map(entry=>entry.status==='fulfilled'
        ?'fulfilled':`${entry.reason?.message}:${entry.reason?.canonicalSaveOutcome?.state
          ||entry.reason?.canonicalCommitOutcome?.state
          ||db.getTransactionOutcome?.(entry.reason)?.state||'no_state'}:${entry.reason?.canonicalCommitOutcome?.commitIssued?'commit_issued':'commit_not_issued'}:${entry.reason?.canonicalCommitOutcome?.rollbackAcknowledged?'rollback_ack':'no_rollback_ack'}:${entry.reason?.canonicalCommitOutcome?.postgresStatus||'no_pg_status'}:cause=${String(entry.reason?.cause?.stack||'').split('\n').slice(0,6).map(line=>line.trim()).join('>')||'none'}:${String(entry.reason?.stack||'').split('\n').slice(1,6).map(line=>line.trim()).join('>')||'no_stack'}`).join('|')}`);
    }
    const [one,two]=settled.map(entry=>entry.value);
    const restartedOwner=createHousekeeperCanonicalSaveOwner();
    const afterRestart=await restartedOwner(input);
    const processRestart=await readbackInFreshProcess(input);
    assert.equal(one.id,two.id);assert.equal(two.id,afterRestart.id);
    assert.equal(afterRestart.id,processRestart.id);
    assert([one,two].some(value=>value.operation_replayed===true));
    assert.equal(afterRestart.operation_replayed,true);
    assert.equal(processRestart.operation_replayed,true);
    assert.equal((await observer.query('SELECT count(*)::int AS n FROM aimos_memories WHERE company_id=$1 AND key=$2',['hom',key])).rows[0].n,1);
    assert.equal((await observer.query(`SELECT count(*)::int AS n FROM aimos_events
      WHERE operation='canonical_save_terminal' AND metadata->'stages'->14->'evidence'->>'operation_id'=$1`,[operationId])).rows[0].n,1);
    result.canonical_memory_id=one.id;
    result.canonical_operation_id=operationId;
    result.canonical_concurrent_retry_replayed=true;
    result.canonical_owner_restart_readback=true;
    result.canonical_process_restart_readback=true;
  });
  assert.deepEqual(failures,[],'native_transaction_truth_failures');
  console.log(JSON.stringify({...result,observations,observed_at:new Date().toISOString()},null,2));
}finally{
  for(const back of held)back.destroy();held.clear();
  await Promise.allSettled([db.pool.end(),db.agentPool.end(),observer.end(),authorityReader.end()]);
  for(const socket of sockets)socket.destroy();
  await new Promise(resolve=>proxy.close(resolve));
}
