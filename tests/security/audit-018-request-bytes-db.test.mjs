// Native request signer -> retained admission owner -> SQL byte verification.
// Existing Codex certificate/key only. No listener, model or production write.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { pool,agentPool } from '../../db/connection.js';
import { resolveAimosDatabaseUrl, AIMOS_AGENT_KEY_ROOT } from '../../services/core/runtime-config.js';
import path from 'node:path';
import { loadAgentPrivkey, signPayloadWithRequestTarget, signPayloadWithContext, signPayloadWithEnvelopeClaims } from '../../services/security/agent-identity.js';
import { buildSignedRequestMessageV5, validateRequestTargetV5 } from '../../services/security/protocol/mutmem-protocol.js';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { reserveVerifiedRequest } from '../../services/security/request-receipt-ledger.js';
import { auditCurrentOriginLedger,currentOriginSourceContract } from '../../scripts/verification/audit-origin-ledger-current.mjs';
if(!process.argv.includes('--live-fire'))throw new Error('owned_live_fire_required');
const database=process.argv[process.argv.indexOf('--aimos-db')+1];
assert(/^aimos_test_security_audr5_[0-9]+_[a-f0-9]{6}$/.test(database));
const sourceUrl=new URL(resolveAimosDatabaseUrl());sourceUrl.pathname='/aimos';
const source=new pg.Client({connectionString:sourceUrl.href,ssl:false});
const c=await pool.connect();
try{
  assert.equal((await c.query('SELECT current_database() name')).rows[0].name,database);
  await source.connect();await source.query('BEGIN READ ONLY');
  const actor=(await source.query("SELECT agent_id,pubkey,cert,device_fp,valid_from,valid_until FROM agent_identity WHERE agent_id='codex-auditor' ORDER BY valid_from DESC LIMIT 1")).rows[0];
  assert(actor && new Date(actor.valid_until)>new Date());await source.query('COMMIT');
  await c.query('INSERT INTO agent_identity(agent_id,pubkey,cert,device_fp,valid_from,valid_until) VALUES($1,$2,$3,$4,$5,$6)',Object.values(actor));
  await c.query('BEGIN');
  await c.query("SET LOCAL pgsodium.enable_event_trigger='on'");
  await c.query(readFileSync(new URL('../../db/request-target.sql',import.meta.url),'utf8'));
  await c.query(readFileSync(new URL('../../db/signed-request-bytes.sql',import.meta.url),'utf8'));
  // This schema belongs only to the runner's empty owned database. Release
  // table-DDL locks before the receipt owner opens its own real transaction.
  await c.query('COMMIT');
  await c.query('BEGIN');
  const cases=[];
  for(const form of [3,4,5]){
    const body={key:'audit:r5:wire-qualification',value:'Native signed byte qualification in the owner-controlled test database; this request is not executed as SAVE.',
      metadata:{'\ue000':{scale:4.5},'\u{10000}':{exponent:1e-7},values:[0.1,5e-324,1e23]}};
    const headers=await buildEnvelopeHeaders('codex-auditor','POST','/aimos/save',body,
      form===4?{prevChainHash:Buffer.alloc(32).toString('base64url')}:{});
    const claims=form===5?{prev_chain_hash:null,device_fp:null}:form===4?{prev_chain_hash:headers['Aimos-Agent-Prev-Chain-Hash'],device_fp:null}:null;
    const target=form===5?'/aimos/save?audit=owned%20qualification&empty=':'/aimos/save';
    if(form===5){
      headers['X-Aimos-Sig-Form']='5';
      headers['Aimos-Agent-Signature']=signPayloadWithRequestTarget(loadAgentPrivkey(path.join(AIMOS_AGENT_KEY_ROOT,'codex-auditor.key')),
        body,'POST',target,claims,headers['Aimos-Agent-Nonce'],Number(headers['Aimos-Agent-Timestamp']));
    }else{
      // Explicit historical-byte compatibility check; never emit these forms
      // through the current public header builder or an HTTP request.
      const legacyKey=loadAgentPrivkey(path.join(AIMOS_AGENT_KEY_ROOT,'codex-auditor.key'));
      headers['X-Aimos-Sig-Form']=String(form);
      headers['Aimos-Agent-Signature']=form===4
        ? signPayloadWithEnvelopeClaims(legacyKey,body,'POST',target,claims,headers['Aimos-Agent-Nonce'],Number(headers['Aimos-Agent-Timestamp']))
        : signPayloadWithContext(legacyKey,body,'POST',target,headers['Aimos-Agent-Nonce'],Number(headers['Aimos-Agent-Timestamp']));
    }
    const receipt=await reserveVerifiedRequest({companyId:'hom',actorAgentId:actor.agent_id,
      actorValidFromIso:new Date(actor.valid_from).toISOString(),certString:headers['Aimos-Agent-Cert'],pubkey:actor.pubkey,
      body,requestSigForm:form,signedMethod:'POST',signedPath:target,signedClaims:claims,
      nonce:headers['Aimos-Agent-Nonce'],signedTs:Number(headers['Aimos-Agent-Timestamp']),
      sigBytes:Buffer.from(headers['Aimos-Agent-Signature'],'base64url')});
    const wire=canonicalJson(body);
    const verified=await c.query('SELECT (public.ob2_verify_signed_request_bytes($1,$2::json)).request_receipt_id AS id',[receipt.request_receipt_id,wire]);
    assert.equal(verified.rows[0].id,receipt.request_receipt_id);
    for(const [name,bytes] of [['same_value_changed_wire',' '+wire],['changed_value',canonicalJson({...body,value:body.value+' altered'})]]){
      await c.query('SAVEPOINT invalid_wire');let reason;
      try{await c.query('SELECT public.ob2_verify_signed_request_bytes($1,$2::json)',[receipt.request_receipt_id,bytes]);}
      catch(error){reason=error.message;await c.query('ROLLBACK TO SAVEPOINT invalid_wire');}
      await c.query('RELEASE SAVEPOINT invalid_wire');assert.equal(reason,'origin_native_request_body_invalid');
      cases.push({form,case:name,denied:true});
    }
    cases.push({form,case:'native_signed_request',verified:true,receipt_id:receipt.request_receipt_id});
    if(form===5){
      const native=buildSignedRequestMessageV5(body,'POST',target,claims,headers['Aimos-Agent-Nonce'],Number(headers['Aimos-Agent-Timestamp']));
      const sql=(await c.query('SELECT public.request_signature_message_v5($1,$2,$3,$4,$5,$6) AS message',
        [Buffer.from(wire),'POST',target,claims,headers['Aimos-Agent-Nonce'],Number(headers['Aimos-Agent-Timestamp'])])).rows[0].message;
      assert(native.equals(sql));cases.push({form,case:'exact_framed_sql_byte_parity',verified:true});
      for(const candidate of ['/aimos/status?a=1&%61=2','/aimos/status?=1&=2','/aimos/status?a+z=1&a%20z=2','/aimos/status?%FF=1','/aimos/status?%00=1','/aimos/status?x=%gg','/aimos/status?x=1&y=2','/aimos/status?x=&y','/aimos/status?x=%2f','/aimos/status?x=%2F']){
        let expected=true;try{validateRequestTargetV5(candidate);}catch{expected=false;}
        const actual=(await c.query('SELECT public.request_target_valid_v5($1) AS valid',[candidate])).rows[0].valid;
        assert.equal(actual,expected,candidate);cases.push({form,case:'target_validation',target:candidate,accepted:actual});
      }
    }
  }
  assert.equal((await c.query("SELECT has_function_privilege('agent_runtime','public.ob2_verify_signed_request_bytes(uuid,json)','EXECUTE') allowed")).rows[0].allowed,false);
  // Compile the dependent native writer replacement in this transaction too.
  await c.query(readFileSync(new URL('../../db/atomic-save-origin.sql',import.meta.url),'utf8'));
  for (let pass=0;pass<2;pass++) for (const file of ['signed-json-bytes.sql','signed-event-bytes.sql','cognitive-ancestry.sql'])
    await c.query(readFileSync(new URL('../../db/'+file,import.meta.url),'utf8'));
  assert.equal((await c.query("SELECT to_regprocedure('public.commit_memory_origin_binding_v2(jsonb,bytea,bytea,uuid,bytea,timestamptz,text,bytea,timestamptz,bytea,jsonb)') old")).rows[0].old,null);
  for(const source of currentOriginSourceContract().sources.filter(s=>s.path.startsWith('migrations/'))){
    await c.query('INSERT INTO schema_migrations(filename,checksum) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [source.path.slice('migrations/'.length),source.sha256]);
  }
  const schemaAudit=await auditCurrentOriginLedger(c);
  await c.query('ROLLBACK');
  console.log(JSON.stringify({database,existing_agent:actor.agent_id,cases,canonical_sql_changed:false,
    request_body_retained:false,save_executed:false,request_schema_installed_in_owned_database:true,
    dependent_ddl_reapplication_rolled_back:true,schema_audit:schemaAudit},null,2));
}finally{c.release();await source.end();await Promise.allSettled([pool.end(),agentPool.end()]);}
