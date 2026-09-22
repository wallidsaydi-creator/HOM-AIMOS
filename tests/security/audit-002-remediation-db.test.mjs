// Owned real HTTP/PostgreSQL qualification. No mocked authentication,
// revocation, admission, transport response, or tool dispatch. No Genesis.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import pg from 'pg';
import { pool, agentPool } from '../../db/connection.js';
import { AIMOS_AGENT_KEY_ROOT, resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { generateKeypair,issueCert,pubkeyFingerprint,signPayloadWithContext,
  createAgentRevocationProof,verifyAgentRevocationProof } from '../../services/security/agent-identity.js';
import { loadHousekeeperPrivkey } from '../../services/security/housekeeper-signer.js';
import { insertMaster,insertAgent,insertRevocationEvent } from '../../scripts/identity/db.js';
import { authGate } from '../../services/security/auth-gate.js';
import { agentRevocationCache } from '../../services/security/agent-revocation-cache.js';
import { readVerifiedEventHistory } from '../../services/observe/event-ledger.js';
import router from '../../routes/aimos-mcp-streamable.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database=process.argv[process.argv.indexOf('--aimos-db')+1];
assert.match(database,/^aimos_test_security_aud002_[0-9]+_[a-f0-9]{6}$/);
assert.equal(new URL(resolveAimosDatabaseUrl()).pathname,`/${database}`);
const canonicalUrl=new URL(resolveAimosDatabaseUrl()); canonicalUrl.pathname='/aimos';
const canonical=new pg.Pool({connectionString:canonicalUrl.href,max:1});
const sha=value=>createHash('sha256').update(value).digest('hex');
const streams=[];const observations=[];let server;let lockClient;
const requestTranscripts=[];
const pending=[];
const protectedFiles=[path.join(AIMOS_AGENT_KEY_ROOT,'housekeeper.key'),
  path.join(AIMOS_AGENT_KEY_ROOT,'housekeeper.cert-cache.json'),new URL('../../architecture-authority.json',import.meta.url).pathname];
const fileState=()=>protectedFiles.map(file=>({file,sha256:existsSync(file)?sha(readFileSync(file)):null}));
const beforeFiles=fileState();
const canonicalIdentityState=async()=>{
  const c=await canonical.connect();
  try {
    await c.query('BEGIN READ ONLY');
    const identities=(await c.query(`SELECT agent_id,valid_from,valid_until,pubkey,cert,revoked_at
      FROM agent_identity ORDER BY agent_id,valid_from`)).rows;
    const masters=(await c.query('SELECT * FROM aimos_master_identity ORDER BY id')).rows;
    const revocations=(await c.query('SELECT agent_id,agent_valid_from,mutation_hash FROM aimos_agent_revocation_events ORDER BY agent_id,agent_valid_from')).rows;
    await c.query('COMMIT');
    return {identities,sha256:sha(JSON.stringify({identities,masters,revocations}))};
  }finally{c.release();}
};
let canonicalBefore;
let base;
function headers(actor,method,url,body={}) {
  assert.notEqual(actor.id,'housekeeper','test_must_not_emit_housekeeper_http_authority');
  const nonce=randomBytes(16).toString('base64url');const ts=Math.floor(Date.now()/1000);
  return {'Aimos-Agent-Cert':actor.cert,'Aimos-Agent-Signature':signPayloadWithContext(actor.privkey,body,method,url.split('?')[0],nonce,ts),
    'Aimos-Agent-Nonce':nonce,'Aimos-Agent-Timestamp':String(ts),'X-Aimos-Sig-Form':'3','Content-Type':'application/json'};
}
async function open(actor,sessionId) {
  const url=`/mcp?sessionId=${encodeURIComponent(sessionId)}`;
  const signedHeaders=headers(actor,'GET',url);
  const transcript={actor:actor.id,method:'GET',url,body:{},headers:signedHeaders,status:null};requestTranscripts.push(transcript);
  return new Promise((resolve,reject)=>{
    const request=http.get(base+url,{headers:{...signedHeaders,accept:'text/event-stream'}});
    request.on('error',reject);
    request.setTimeout(70000,()=>request.destroy(new Error('audit_sse_timeout')));
    request.once('response',response=>{
      transcript.status=response.statusCode;
      let finish;const ended=new Promise(r=>{finish=r;});response.once('end',finish);response.once('close',finish);
      const entry={request,response,text:'',transcript,ended};streams.push(entry);
      response.setEncoding('utf8');response.on('data',text=>{entry.text+=text;});
      resolve(entry);
    });
  });
}
async function call(actor,method,sessionId,body=null) {
  const url=`/mcp?sessionId=${encodeURIComponent(sessionId)}`;
  const signedHeaders=headers(actor,method,url,body||{});
  const transcript={actor:actor.id,method,url,body:body||{},headers:signedHeaders,status:null};requestTranscripts.push(transcript);
  const response=await fetch(base+url,{method,headers:signedHeaders,
    ...(body===null?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(30000)});
  const text=await response.text();transcript.status=response.status;transcript.response=text;
  return {status:response.status,body:text};
}
async function until(fn,timeoutMs=8000) {
  const deadline=Date.now()+timeoutMs;
  while(!await fn()) {if(Date.now()>deadline)throw new Error('audit_002_native_boundary_timeout');await new Promise(r=>setTimeout(r,15));}
}
function sseResponse(stream,id) {
  for(const frame of stream.text.split('\n\n').slice(0,-1)) {
    if(!frame.startsWith('event: response\n'))continue;
    const data=frame.split('\n').find(line=>line.startsWith('data: '));
    const value=JSON.parse(data.slice(6));if(value.id===id)return value;
  }
  return null;
}
function assertHealthResponse(response,id) {
  assert.equal(response.id,id);assert.equal(response.error,undefined);
  const health=response.result?.structuredContent;
  assert.equal(health?.connected,true);assert.equal(health.total_memories,0);assert.equal(health.active_agents,0);
  assert.deepEqual(JSON.parse(response.result.content[0].text),health);
}
function assertDeliveryDenied(response) {
  assert.equal(response.status,403);
  assert.deepEqual(JSON.parse(response.body),{jsonrpc:'2.0',id:null,
    error:{code:-32001,message:'Session delivery authority is no longer valid',data:null}});
}
async function nextKeepalive(stream) {
  const count=()=>stream.text.split('\n\n').filter(frame=>frame===': ping').length;
  const before=count();await until(()=>count()>before,40000);
  return {native_same_stream_keepalive_observed:true,keepalive_number:count()};
}
async function holdNativeHealth(actor,sessionId,{batch=false}={}) {
  lockClient=await pool.connect();await lockClient.query('BEGIN');
  await lockClient.query('LOCK TABLE public.aimos_memories IN ACCESS EXCLUSIVE MODE');
  const id=randomUUID();
  const one={jsonrpc:'2.0',id,method:'tools/call',params:{name:'aimos_system_health',arguments:{}}};
  let settled=false;
  const response=call(actor,'POST',sessionId,batch?[one,{...one,id:`${id}-second`}]:one)
    .then(result=>{settled=true;return result;},error=>{settled=true;throw error;});
  pending.push(response.catch(()=>{}));
  const expectedQueries=batch?4:2;
  await until(async()=>{
    const waiting=(await pool.query(`SELECT count(*)::int AS n FROM pg_stat_activity a
      WHERE a.datname=current_database() AND a.wait_event_type='Lock'
        AND a.query LIKE 'SELECT COUNT(%' AND a.query LIKE '%FROM aimos_memories%'
        AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted
          AND l.relation='public.aimos_memories'::regclass)`)).rows[0].n;
    return waiting>=expectedQueries;
  });
  assert.equal(settled,false,'native_dispatch_not_pending');
  return {id,response,isPending:()=>!settled,blockedQueries:expectedQueries};
}
async function releaseLock(){if(lockClient){await lockClient.query('ROLLBACK');lockClient.release();lockClient=null;}}
async function revoke(actor,master) {
  const proof=createAgentRevocationProof(master.privkey,{agentId:actor.id,agentValidFrom:actor.epoch,
    targetCert:actor.cert,masterFingerprint:pubkeyFingerprint(master.pubkey),reasonCode:'isolated_audit_002_qualification'});
  const row={agent_id:actor.id,agent_valid_from:actor.epoch,master_fingerprint:pubkeyFingerprint(master.pubkey),
    target_cert_hash:proof.targetCertHash,prior_identity_hash:proof.priorIdentityHash,signed_body:proof.body,
    content_hash:proof.contentHash,mutation_hash:proof.mutationHash,ts_signed:proof.signedTs,nonce:proof.nonce,sig:proof.sigBytes};
  assert.equal(verifyAgentRevocationProof(row,master.pubkey,actor.cert).valid,true);
  assert.equal((await insertRevocationEvent(row)).ok,true);
  return proof.mutationHash.toString('hex');
}
try {
  assert.equal((await pool.query('SELECT current_database() AS db')).rows[0].db,database);
  assert.deepEqual((await agentPool.query('SELECT current_database() AS db,current_user AS role')).rows[0],{db:database,role:'agent_runtime'});
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM agent_identity')).rows[0].n,0);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM aimos_memories')).rows[0].n,0);
  canonicalBefore=await canonicalIdentityState();
  const hk=canonicalBefore.identities.filter(i=>i.agent_id==='housekeeper').at(-1);
  assert(hk,'existing_housekeeper_public_identity_missing');
  const now=Math.floor(Date.now()/1000);let hkEpoch=now-300;
  while(canonicalBefore.identities.some(i=>i.agent_id==='housekeeper'&&Date.parse(i.valid_from)===hkEpoch*1000))hkEpoch--;
  assert(!canonicalBefore.identities.some(i=>i.agent_id==='housekeeper'&&Date.parse(i.valid_from)===hkEpoch*1000));
  const device=sha(database);
  const hkCert=issueCert(loadHousekeeperPrivkey(),{v:1,agent_id:'housekeeper',pubkey:hk.pubkey,device_fp:device,
    valid_from:hkEpoch,valid_until:now+3600,issuer:'housekeeper',issued_at:now});
  await insertAgent({agent_id:'housekeeper',pubkey:hk.pubkey,cert:hkCert,device_fp:device,
    valid_from:new Date(hkEpoch*1000).toISOString(),valid_until:new Date((now+3600)*1000).toISOString()});
  const master=generateKeypair();
  // Test trust root only: no claim that a custody/installer ceremony occurred.
  await insertMaster(master.pubkey,pubkeyFingerprint(master.pubkey),null,null);
  async function enroll(id,epochUnix) {
    assert(!canonicalBefore.identities.some(i=>i.agent_id===id));
    const key=generateKeypair();
    const cert=issueCert(master.privkey,{v:1,agent_id:id,pubkey:key.pubkey,device_fp:device,
      valid_from:epochUnix,valid_until:now+3600,issuer:'aimos-master',issued_at:now});
    const actor={id,...key,cert,epoch:new Date(epochUnix*1000).toISOString()};
    await insertAgent({agent_id:id,pubkey:key.pubkey,cert,device_fp:device,valid_from:actor.epoch,
      valid_until:new Date((now+3600)*1000).toISOString()});
    return actor;
  }
  const suffix=randomBytes(4).toString('hex');
  const a=await enroll(`aud002a_${suffix}`,now-240);const b=await enroll(`aud002b_${suffix}`,now-240);
  const app=express();app.use(express.json());app.use(authGate);app.use('/mcp',router);
  server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  base=`http://127.0.0.1:${server.address().port}`;
  const sessionId=randomUUID();const first=await open(a,sessionId);assert.equal(first.response.statusCode,200);
  const held=await holdNativeHealth(a,sessionId);
  const intruder=await open(b,sessionId);assert.equal(intruder.response.statusCode,403);
  await intruder.ended;
  assert.equal((await call(b,'POST',sessionId,{jsonrpc:'2.0',id:10,method:'ping'})).status,403);
  assert.equal((await call(b,'DELETE',sessionId)).status,403);
  const replacement=await open(a,sessionId);assert.equal(replacement.response.statusCode,200);
  first.request.destroy();assert(held.isPending());await releaseLock();
  const heldResponse=await held.response;assert.equal(heldResponse.status,200);
  assertHealthResponse(JSON.parse(heldResponse.body),held.id);
  await until(()=>sseResponse(replacement,held.id));assertHealthResponse(sseResponse(replacement,held.id),held.id);
  assert(!intruder.text.includes(held.id));
  observations.push({case:'signed_in_flight_reconnect',native_queries_blocked:held.blockedQueries,owner_payload:true,foreign_payload:false});

  const reuse=await holdNativeHealth(a,sessionId);
  assert.equal((await call(a,'DELETE',sessionId)).status,204);
  const reused=await open(b,sessionId);assert.equal(reused.response.statusCode,200);
  assert(reuse.isPending());await releaseLock();
  const reusedResponse=await reuse.response;assert.equal(reusedResponse.status,200);assertHealthResponse(JSON.parse(reusedResponse.body),reuse.id);
  const barrier=randomUUID();
  const barrierResponse=await call(b,'POST',sessionId,{jsonrpc:'2.0',id:barrier,method:'tools/call',params:{name:'aimos_system_health',arguments:{}}});
  assert.equal(barrierResponse.status,200);assertHealthResponse(JSON.parse(barrierResponse.body),barrier);
  await until(()=>sseResponse(reused,barrier));assertHealthResponse(sseResponse(reused,barrier),barrier);
  assert(!reused.text.includes(reuse.id));
  assert.equal((await call(b,'DELETE',sessionId)).status,204);
  observations.push({case:'deleted_session_recreated_by_other_actor',prior_payload_delivered_to_replacement:false,same_stream_barrier_id:barrier});

  const revokedSession=randomUUID();const revStream=await open(a,revokedSession);assert.equal(revStream.response.statusCode,200);
  const revPending=await holdNativeHealth(a,revokedSession);const revocation=await revoke(a,master);
  assert(revPending.isPending());await releaseLock();assertDeliveryDenied(await revPending.response);
  // The pending delivery performs the first revocation lookup after the commit.
  assert.deepEqual(await agentRevocationCache.lookup(a.id,a.epoch),{found:true,revoked:true,proofVerified:true});
  const revBarrier=await nextKeepalive(revStream);
  assert(!revStream.text.includes(revPending.id));
  assert.equal((await call(a,'POST',revokedSession,{jsonrpc:'2.0',id:20,method:'ping'})).status,401);
  observations.push({case:'committed_revocation_during_pending_single',revocation_hash:revocation,payload_delivered:false,...revBarrier});

  const rotated=await enroll(a.id,now-60);
  const wrongEpoch=await open(rotated,revokedSession);assert.equal(wrongEpoch.response.statusCode,403);
  const newSession=randomUUID();const newStream=await open(rotated,newSession);assert.equal(newStream.response.statusCode,200);
  assert.equal((await call(rotated,'POST',newSession,{jsonrpc:'2.0',id:21,method:'ping'})).status,200);
  observations.push({case:'new_signed_epoch',old_session_status:403,new_session_status:200});

  const batch=await holdNativeHealth(rotated,newSession,{batch:true});const batchRevocation=await revoke(rotated,master);
  assert(batch.isPending());await releaseLock();assertDeliveryDenied(await batch.response);
  assert.deepEqual(await agentRevocationCache.lookup(rotated.id,rotated.epoch),{found:true,revoked:true,proofVerified:true});
  const batchBarrier=await nextKeepalive(newStream);
  assert(!newStream.text.includes(batch.id));
  observations.push({case:'committed_revocation_during_pending_batch',native_queries_blocked:batch.blockedQueries,
    revocation_hash:batchRevocation,payload_delivered:false,...batchBarrier});

  const events=await readVerifiedEventHistory('hom');
  assert(events.length>0);assert(events.some(e=>e.operation==='request_admission_verified'));
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM aimos_memories')).rows[0].n,0);
  assert.deepEqual(fileState(),beforeFiles);
  assert.equal((await canonicalIdentityState()).sha256,canonicalBefore.sha256);
  const evidenceDirectory=new URL('../../engineering/remediation/2026-09-05-system-audit/AUD-002/',import.meta.url);
  mkdirSync(evidenceDirectory,{recursive:true,mode:0o700});
  const evidenceFile=new URL(`native-http-postgres-${database}.json`,evidenceDirectory);
  const evidence={schema:'hom.aimos.audit-002-native-boundary-evidence/v1',database,observed_at:new Date().toISOString(),
    test_master_pubkey:master.pubkey,test_master_fingerprint:pubkeyFingerprint(master.pubkey),
    observations,request_transcripts:requestTranscripts,
    sse_transcripts:streams.map(s=>({request_nonce:s.transcript.headers['Aimos-Agent-Nonce'],status:s.transcript.status,text:s.text})),
    identities:(await pool.query('SELECT agent_id,valid_from,valid_until,pubkey,cert FROM agent_identity ORDER BY agent_id,valid_from')).rows,
    revocations:(await pool.query('SELECT * FROM aimos_agent_revocation_events ORDER BY created_at')).rows,
    request_receipts:(await pool.query('SELECT * FROM aimos_request_receipts ORDER BY created_at,request_receipt_id')).rows,
    events,canonical_identity_sha256:canonicalBefore.sha256,protected_file_commitments:beforeFiles,
    private_key_material_retained:false,independent_key_custody_claimed:false};
  const evidenceBytes=Buffer.from(JSON.stringify(evidence,null,2)+'\n');
  writeFileSync(evidenceFile,evidenceBytes,{flag:'wx',mode:0o600});
  console.log(JSON.stringify({success:true,observed_at:new Date().toISOString(),node:process.version,database,
    actual_native_authentication:true,actual_native_admission:true,actual_native_sse:true,
    verified_event_count:events.length,verified_event_head:events.at(-1).mutation_hash.toString('hex'),observations,
    canonical_identity_state_unchanged:true,canonical_key_and_cache_files_unchanged:true,
    canonical_role_or_credential_changed:false,new_canonical_identities:0,genesis_invoked:false,
    test_key_custody:'test actor/master keys in process memory; existing Housekeeper signer used read-only for isolated certificate/events',
    evidence_file:evidenceFile.pathname,evidence_sha256:sha(evidenceBytes),
    independent_key_custody_claimed:false,housekeeper_http_requests:0,full_installer_or_custody_enrollment_claimed:false},null,2));
}finally{
  await releaseLock();for(const stream of streams)stream.request.destroy();
  if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
  await Promise.allSettled(pending);
  try {assert.deepEqual(fileState(),beforeFiles);if(canonicalBefore)assert.equal((await canonicalIdentityState()).sha256,canonicalBefore.sha256);}
  finally {await Promise.allSettled([pool.end(),agentPool.end(),canonical.end()]);}
}
