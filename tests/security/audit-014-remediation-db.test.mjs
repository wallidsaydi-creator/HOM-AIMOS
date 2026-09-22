// Operator-authorized R3 credential qualification. Real Keychain + PostgreSQL
// and native signed SAVE/custody owners. Only the unused sentinel audit slot
// may change; the selected database must be the runner's disposable database.
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { pool, agentPool, withTransaction } from '../../db/connection.js';
import { createCanonicalSaveOwner, createHousekeeperCanonicalSaveOwner } from '../../services/write/canonical-save-owner.js';
import { createCredentialCacheOwner } from '../../services/security/credential-cache.js';
import { credentialLedger } from '../../services/security/credential-ledger.js';
import { credentialSlotId, readCredential, computeCredentialHash } from '../../services/security/credential-store.js';
import { signAsHousekeeper } from '../../services/security/housekeeper-signer.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { verifyCanonicalSaveTrace } from '../../services/write/canonical-save-contract.js';

if(!process.argv.includes('--live-fire'))throw new Error('owned_live_fire_required');
const database=process.argv[process.argv.indexOf('--aimos-db')+1];
assert(/^aimos_test_security_audr3_[0-9]+_[a-f0-9]{6}$/.test(database));
const service='sentinel_audit_secret';
const slot=credentialSlotId(service);
let holdUnrelated=false, unrelatedEntered, releaseUnrelated;
const unrelatedBlocked=new Promise(resolve=>{unrelatedEntered=resolve;});
const unrelatedGate=new Promise(resolve=>{releaseUnrelated=resolve;});
const cache=createCredentialCacheOwner({services:[service,'api_key'],
  readCredentialFn:async name=>{
    const entry=await readCredential(name);
    if(name==='api_key'&&holdUnrelated){unrelatedEntered();await unrelatedGate;}
    return entry;
  },
});
const result={database,service,production_database_writes:false,
  actual_keychain:true,provider_call:false,new_identity:false};
let slotTouched=false;
let revoked=false;

function saveOwner(refresh=serviceName=>cache.refresh(serviceName),transaction=withTransaction) {
  return createHousekeeperCanonicalSaveOwner({executeCanonicalSave:createCanonicalSaveOwner({
    refreshCachedCredential:refresh,withTransaction:transaction,
  })});
}
function spec(value) {
  return {company_id:'hom',agent_id:'housekeeper',key:service,value,
    source:'audit:r3:authorized-credential',scope:'system',clearance_level:12,
    data_class:'restricted',memory_type:'procedural',save_operation_id:randomUUID()};
}
async function counts() {
  return (await pool.query(`SELECT
    (SELECT count(*)::int FROM aimos_memories WHERE key=$1) AS memories,
    (SELECT count(*)::int FROM aimos_credential_lifecycle WHERE slot_id=$2) AS lifecycle,
    (SELECT count(*)::int FROM aimos_events WHERE operation='credential_custody_started'
       AND metadata->>'service_name'=$1) AS custody`,[service,slot])).rows[0];
}
async function verifySave(saved,expectedHash) {
  assert.equal(saved.rejected,undefined,`credential_save_rejected:${saved.reason}`);
  assert.equal(saved.credential_lane,true);
  assert.equal(verifyCanonicalSaveTrace(saved.canonical_save_trace).valid,true);
  const terminal=await readVerifiedEventById(saved.terminal_receipt.event_id,'hom');
  assert.equal(terminal.metadata.outcome,'SUCCESS');
  const chain=await credentialLedger.readVerifiedSlotChain(slot);
  assert.equal(chain.effectiveStore.body_json.credential_hash,expectedHash);
  assert.equal((await pool.query('SELECT data_class FROM aimos_memories WHERE id=$1',[saved.id])).rows[0].data_class,'restricted');
  return chain;
}
async function revoke({refresh=true}={}) {
  const current=await readCredential(service);
  if(!current)return;
  const chain=await credentialLedger.readVerifiedSlotChain(slot);
  const custody=await credentialLedger.beginCredentialCustodyMutation({
    serviceName:service,eventType:'REVOKE',subjectAgentId:'housekeeper',reason:'operator_authorized_R3_qualification_terminal',
  });
  const body={event_type:'REVOKE',service,slot_id:slot,credential_hash:current.hash,
    valid_from:chain.effectiveStore?.body_json.valid_from||null,valid_until:Math.floor(Date.now()/1000),
    revoked_provenance_id:chain.effectiveStore?.provenance_id||null,
    reason:'operator_authorized_R3_qualification_terminal',operator:'housekeeper',signer_agent_id:'housekeeper',
    custody_action_id:custody.custodyTrace.actionId,
    custody_start_event_id:custody.custodyTrace.startEventId,
    custody_start_mutation_hash:custody.custodyTrace.startMutationHash,
    custody_readback_event_id:custody.custodyTrace.readbackEventId,
    custody_readback_mutation_hash:custody.custodyTrace.readbackMutationHash,
    custody_version_slot_sha256:custody.custodyTrace.versionSlotSha256};
  const signed=await signAsHousekeeper(body);
  if(chain.rowCount===0) {
    // Custody reached Keychain but the first lifecycle never committed. There
    // is no lifecycle to revoke; retain an indeterminate custody terminal.
    await credentialLedger.markCredentialCustodyIndeterminate(custody.custodyTrace,
      new Error('audit_initial_lifecycle_uncommitted'));
    assert.equal(await readCredential(service),null);
    revoked=true;
    return;
  }
  await withTransaction(async client=>{
    const commit=await credentialLedger.commitCredentialLifecycle({serviceName:service,slotId:slot,
      body:signed.body,bodyJson:signed.body,agentId:signed.agentId,validFromIso:signed.validFromIso,
      certString:signed.certString,signedTs:signed.signedTs,nonce:signed.nonce,sigBytes:signed.sigBytes,
      identityTier:signed.identityTier,eventType:'REVOKE',client});
    assert.equal(commit.ok,true,commit.reason);
    await credentialLedger.commitCredentialCustodyTerminal(custody.custodyTrace,commit,{client});
  },{restricted:true,client_id:'hom',agent_id:'housekeeper'});
  assert.equal(await readCredential(service),null);
  revoked=true;
  if(refresh) {
    await cache.refresh(service);
    assert.equal(cache.state(service).state,'REVOKED');
    assert.equal(cache.checkout(service),null);
  }
}

try {
  for(const connection of [pool,agentPool])assert.equal(
    (await connection.query('SELECT current_database() AS name')).rows[0].name,database);
  assert.equal(await readCredential(service),null,'audit_slot_already_in_use');
  assert.equal((await counts()).lifecycle,0,'scratch_audit_slot_not_empty');
  await cache.load();
  assert.equal(cache.state(service).state,'ABSENT');
  const first=spec(randomBytes(64).toString('base64url'));
  slotTouched=true;
  const saved=await saveOwner()(first);
  await verifySave(saved,computeCredentialHash(first.value));
  assert.equal(saved.save_diagnostics.credential_cache.status,'PUBLISHED_AFTER_COMMIT');
  assert.equal(cache.checkout(service).value,first.value);
  result.native_save_immediate_checkout=true;
  const retained=await counts();
  const replay=await saveOwner()(first);
  assert.equal(replay.operation_replayed,true);
  assert.deepEqual(await counts(),retained);
  result.retry_has_no_duplicate_memory_or_custody=true;

  // Real database permission loss at publication, after durable commit. The
  // test callback selects the failure instant; the cache uses native readers.
  const second=spec(randomBytes(64).toString('base64url'));
  let failed;
  try {
    failed=await saveOwner(async serviceName=>{
      await pool.query('REVOKE SELECT ON aimos_credential_lifecycle FROM agent_runtime');
      return cache.refresh(serviceName);
    })(second);
    assert.equal(failed.save_diagnostics.credential_cache.status,'COMMITTED_PUBLICATION_UNAVAILABLE');
    assert.equal(cache.state(service).state,'UNAVAILABLE');
    assert.throws(()=>cache.checkout(service),/authority_unavailable/);
  } finally {await pool.query('GRANT SELECT ON aimos_credential_lifecycle TO agent_runtime');}
  await verifySave(failed,computeCredentialHash(second.value));
  const postcommit=await counts();
  const retried=await saveOwner()(second);
  assert.equal(retried.operation_replayed,true);
  assert.deepEqual(await counts(),postcommit);
  assert.equal(cache.checkout(service).value,second.value);
  const failures=(await pool.query(`SELECT id FROM aimos_events
    WHERE operation='credential_cache_refresh_failed' AND key=$1`,[second.save_operation_id])).rows;
  assert.equal(failures.length,1);
  assert.equal((await readVerifiedEventById(failures[0].id,'hom')).metadata.durable_save_committed,true);
  result.real_postcommit_read_failure_and_retry=true;

  // PostgreSQL raises a real error after custody/reference writes but before
  // COMMIT. The Keychain version remains retained; it must not become usable.
  const rollback=spec(randomBytes(64).toString('base64url'));
  const beforeRollback=await counts();
  let rollbackError;
  try {await saveOwner(undefined,(fn,options)=>withTransaction(async client=>{
    const value=await fn(client);
    if(value?.saved)await client.query('SELECT 1/0');
    return value;
  },options))(rollback);}catch(error){rollbackError=error;}
  assert(rollbackError,'precommit_fault_not_observed');
  const afterRollback=await counts();
  assert.equal(afterRollback.memories,beforeRollback.memories);
  assert.equal(afterRollback.lifecycle,beforeRollback.lifecycle);
  await assert.rejects(cache.refresh(service),/refresh_unavailable/);
  assert.throws(()=>cache.checkout(service),/authority_unavailable/);
  result.rollback_does_not_publish=true;
  // Append a new authorized recovery operation for the same retained version.
  const recovered=await saveOwner()({...rollback,save_operation_id:randomUUID()});
  await verifySave(recovered,computeCredentialHash(rollback.value));
  const generation=cache.inspect().generation;
  const [one,two]=await Promise.all([cache.reload(),cache.reload()]);
  assert(one.generation>generation && two.generation>one.generation);
  assert.equal(cache.checkout(service).value,rollback.value);
  result.rotation_and_overlapping_real_reloads=true;
  // Hold only the unrelated native Keychain read after obtaining its real
  // result. The selected slot's old READY candidate is already read when a
  // genuine signed REVOKE commits. No simulated lifecycle authority is used.
  holdUnrelated=true;
  const pendingReload=cache.reload();
  await unrelatedBlocked;
  await new Promise(resolve=>setTimeout(resolve,100));
  let immediateRefresh;
  try {
    await revoke({refresh:false});
    immediateRefresh=cache.refresh(service);
    const deadline=Date.now()+5000;
    while(cache.state(service).state!=='REVOKED'&&Date.now()<deadline)
      await new Promise(resolve=>setTimeout(resolve,10));
    assert.equal(cache.state(service).state,'REVOKED');
    assert.equal(cache.checkout(service),null);
  } finally {releaseUnrelated();}
  const [,published]=await Promise.all([pendingReload,immediateRefresh]);
  assert.equal(published.state,'REVOKED');
  assert.equal(published.entry,null);
  assert.equal(cache.checkout(service),null);
  result.real_revocation_fences_blocked_multislot_reload=true;
  result.signed_revocation_denies_checkout=true;
  result.final_state=cache.state(service).state;
  result.encrypted_versions_retained=true;
  result.counts=await counts();
  console.log('R3_CREDENTIAL_RESULT:'+JSON.stringify(result));
} catch(error) {
  console.error('R3_CREDENTIAL_FAILURE:'+JSON.stringify({code:error.code||null,
    message:error.message,stage:error.stage||null,cause:error.cause?.message||null,
    provenanceReason:error.provenanceReason||null,stack:error.stack?.split('\n').slice(0,7)}));
  throw new Error('R3 credential qualification failed; see bounded diagnostic above');
} finally {
  releaseUnrelated();
  try {if(slotTouched&&!revoked)await revoke();}
  finally {await Promise.allSettled([pool.end(),agentPool.end()]);}
}
