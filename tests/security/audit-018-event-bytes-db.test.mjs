// Real Housekeeper signatures and exact runtime-role INSERT/verification.
// All database effects are confined to the existing runner-owned database.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { spawnSync } from 'node:child_process';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { pool, agentPool } from '../../db/connection.js';
import { logEvent, verifyEventProof, readVerifiedEventsByIds, EVENT_EXACT_PAYLOAD_SCHEMA } from '../../services/observe/event-ledger.js';
import { signedJsonBytesCommitmentV1, eventMutationHash } from '../../services/security/protocol/mutmem-protocol.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { signedJsonBytesCommitmentV1 as independentCommitment, verifyEd25519,
  eventPayloadCommitment, verifyEventPayloadSignature } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { createCognitiveWeightEvidenceBundle, verifyCognitiveWeightEvidenceBundle } from '../../services/security/protocol/cognitive-weight-evidence.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert(/^aimos_test_security_audr5_[0-9]+_[a-f0-9]{6}$/.test(database));
const sourceUrl = new URL(resolveAimosDatabaseUrl()); sourceUrl.pathname = '/aimos';
const source = new pg.Client({ connectionString: sourceUrl.href, ssl: false });
const c = await pool.connect();
try {
  assert.equal((await c.query('SELECT current_database() AS name')).rows[0].name, database);
  await source.connect(); await source.query('BEGIN READ ONLY');
  const master = (await source.query('SELECT id,master_pubkey,fingerprint,created_at,revocation_cert_hash,keychain_service,keychain_account FROM aimos_master_identity WHERE id=1')).rows[0];
  const hk = (await source.query(`SELECT agent_id,pubkey,cert,device_fp,valid_from,valid_until,issued_at,revoked_at,chain_head,is_system_role
    FROM agent_identity WHERE agent_id='housekeeper' AND revoked_at IS NULL ORDER BY valid_from DESC LIMIT 1`)).rows[0];
  assert(master && hk); await source.query('COMMIT');
  await c.query(`INSERT INTO aimos_master_identity(id,master_pubkey,fingerprint,created_at,revocation_cert_hash,keychain_service,keychain_account)
    VALUES($1,$2,$3,$4,$5,$6,$7)`, Object.values(master));
  await c.query(`INSERT INTO agent_identity(agent_id,pubkey,cert,device_fp,valid_from,valid_until,issued_at,revoked_at,chain_head,is_system_role)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, Object.values(hk));
  await c.query('BEGIN');
  await c.query("SET LOCAL pgsodium.enable_event_trigger='on'");
  for (const file of ['signed-json-bytes.sql', 'signed-event-bytes.sql']) await c.query(readFileSync(new URL('../../db/' + file, import.meta.url), 'utf8'));
  await c.query('SET LOCAL ROLE agent_runtime');
  assert.equal((await c.query('SELECT current_user AS role')).rows[0].role, 'agent_runtime');
  const options = { client: c, returnReceipt: true };
  const first = await logEvent('hom','housekeeper','audit018_byte_profile','default_before',
    { reasoning: 'Verify the default native event writer emits exact-byte payloads.' },null,options);
  assert.equal(first.signed_body.payload_schema,EVENT_EXACT_PAYLOAD_SCHEMA);
  await c.query('SAVEPOINT signed_candidate');
  const issue = () => logEvent('hom','housekeeper','audit018_byte_profile','exact',
    { reasoning: 'Qualify exact bytes with real native signing and runtime-role SQL.',
      sample: { '\ue000': 1, '\u{10000}': 2 }, fractional_value: 1e-7,
      wide_numbers:[1e23,1e20,5e-324] },null,{ ...options, payloadSchema: EVENT_EXACT_PAYLOAD_SCHEMA });
  const signed = await issue();
  const row = (await c.query('SELECT * FROM aimos_events WHERE id=$1',[signed.event_id])).rows[0];
  assert.equal(verifyEventProof(row,hk.pubkey).valid,true);
  const hash = independentCommitment(EVENT_EXACT_PAYLOAD_SCHEMA,row.signed_body_bytes);
  assert.equal(verifyEd25519(hk.pubkey,hash,row.sig.toString('base64url')),true);
  const portableEvent = { signed_body: row.signed_body, nonce: row.nonce,
    ts_signed: Number(row.ts_signed), signature_b64u: row.sig.toString('base64url'),
    signed_body_bytes_b64u: row.signed_body_bytes.toString('base64url') };
  const portableCases = [{ id: 'native_exact_event', event: portableEvent, valid: true }];
  for (const variant of ['missing_bytes', 'different_bytes', 'different_projection', 'different_nonce', 'unknown_version', 'null_version', 'noncanonical_base64']) {
    const event = structuredClone(portableEvent);
    if (variant === 'missing_bytes') delete event.signed_body_bytes_b64u;
    if (variant === 'different_bytes') event.signed_body_bytes_b64u = Buffer.concat([row.signed_body_bytes,Buffer.from(' ')]).toString('base64url');
    if (variant === 'different_projection') event.signed_body.metadata.fractional_value = 0.25;
    if (variant === 'different_nonce') event.nonce += 'x';
    if (variant === 'unknown_version') event.signed_body.payload_schema = 'hom.aimos.event/v3';
    if (variant === 'null_version') event.signed_body.payload_schema = null;
    if (variant === 'noncanonical_base64') event.signed_body_bytes_b64u += '=';
    portableCases.push({ id: variant, event, valid: false });
  }
  const wide = await logEvent('hom','housekeeper','audit018_byte_profile','wide_exact',
    { reasoning:'Qualify native finite numeric metadata without reserializing it for independent signature verification.',
      values:[1e23,1e20,5e-324,0.1] },null,{...options,payloadSchema:EVENT_EXACT_PAYLOAD_SCHEMA});
  const wideRow = (await c.query('SELECT * FROM aimos_events WHERE id=$1',[wide.event_id])).rows[0];
  assert.equal(verifyEventProof(wideRow,hk.pubkey).valid,true);
  const widePortable = { nonce:wideRow.nonce,ts_signed:Number(wideRow.ts_signed),
    signature_b64u:wideRow.sig.toString('base64url'),signed_body_bytes_b64u:wideRow.signed_body_bytes.toString('base64url') };
  portableCases.push({id:'native_wide_event_bytes_only',event:widePortable,valid:true},
    {id:'native_wide_event_redundant_projection',event:{...widePortable,signed_body:wideRow.signed_body},valid:true});
  const alteredWide = structuredClone(wideRow.signed_body);alteredWide.metadata.values[0]=1e24;
  portableCases.push({id:'native_wide_event_projection_mismatch',event:{...widePortable,signed_body:alteredWide},valid:false});
  assert.equal(eventPayloadCommitment(portableEvent).toString('hex'),hash.toString('hex'));
  for (const item of portableCases) assert.equal(verifyEventPayloadSignature(item.event,hk.pubkey),item.valid,item.id);
  const pythonPath = new URL('../../verifiers/mutmem-v2/python',import.meta.url).pathname;
  const python = spawnSync('python3',['-c',`import sys,json
sys.path.insert(0,${JSON.stringify(pythonPath)})
from crypto_kernel import signed_json_bytes_commitment_v1,verify_ed25519,verify_event_payload_signature
r=json.load(sys.stdin);h=signed_json_bytes_commitment_v1(r['schema'],bytes.fromhex(r['wire']))
print(json.dumps({'hash':h.hex(),'valid':verify_ed25519(r['public_key'],h,r['signature']),
 'portable':[{'id':c['id'],'valid':verify_event_payload_signature(c['event'],r['public_key'])} for c in r['portable']]}))`],{
    input:JSON.stringify({schema:EVENT_EXACT_PAYLOAD_SCHEMA,wire:row.signed_body_bytes.toString('hex'),public_key:hk.pubkey,signature:row.sig.toString('base64url'),portable:portableCases}),
    encoding:'utf8',timeout:10000});
  assert.equal(python.status,0,python.stderr);assert.deepEqual(JSON.parse(python.stdout),{hash:hash.toString('hex'),valid:true,
    portable:portableCases.map(({id,valid})=>({id,valid}))});
  await c.query('ROLLBACK TO SAVEPOINT signed_candidate');
  const columns = ['id','ts','company_id','agent_id','operation','key','metadata','parent_event_id',
    'ledger_version','ledger_seq','signer_agent_id','signer_valid_from','cert_fingerprint','identity_tier',
    'authority_kind','signed_body','content_hash','mutation_hash','prev_mutation_hash','ts_signed','nonce','sig','signed_body_bytes'];
  const insert = `INSERT INTO aimos_events(${columns.join(',')}) VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')})`;
  const negatives = [];
  for (const variant of ['row_metadata','wire_order','wire_invalid_utf8','unsigned_rehashed_body','nonce',
    'identity_fingerprint','identity_epoch','identity_expiry','predecessor_missing']) {
    const candidate = { ...row, signed_body: structuredClone(row.signed_body), metadata: structuredClone(row.metadata) };
    if (variant === 'row_metadata') candidate.metadata = { altered: true };
    if (variant === 'wire_order') candidate.signed_body_bytes = Buffer.from(JSON.stringify(candidate.signed_body));
    if (variant === 'wire_invalid_utf8') candidate.signed_body_bytes = Buffer.from([0xff]);
    if (variant === 'nonce') candidate.nonce += 'x';
    if (variant === 'identity_fingerprint') candidate.cert_fingerprint = '00'.repeat(32);
    if (variant === 'identity_epoch') candidate.signer_valid_from = new Date(new Date(hk.valid_from).getTime()+1000);
    if (variant === 'identity_expiry') candidate.ts_signed = Math.floor(new Date(hk.valid_until).getTime()/1000);
    if (variant === 'predecessor_missing') candidate.prev_mutation_hash = Buffer.alloc(32);
    if (variant === 'unsigned_rehashed_body') {
      candidate.metadata.fractional_value = 0.5;
      candidate.signed_body.metadata = candidate.metadata;
      candidate.signed_body_bytes = Buffer.from(canonicalJson(candidate.signed_body));
      candidate.content_hash = signedJsonBytesCommitmentV1(EVENT_EXACT_PAYLOAD_SCHEMA,candidate.signed_body_bytes);
      candidate.mutation_hash = eventMutationHash(candidate.prev_mutation_hash,candidate.content_hash,candidate.nonce,Number(candidate.ts_signed));
    }
    await c.query('SAVEPOINT attack'); let reason,sqlState,constraint;
    try { await c.query(insert,columns.map(k=>k==='metadata'||k==='signed_body'?JSON.stringify(candidate[k]):candidate[k])); }
    catch(error) { reason=error.message;sqlState=error.code;constraint=error.constraint;await c.query('ROLLBACK TO SAVEPOINT attack'); }
    assert(reason,variant);
    if (variant === 'identity_epoch') {
      assert.equal(sqlState,'23503');assert.equal(constraint,'aimos_events_signer_epoch_fkey');
    } else assert.match(reason,/origin_signed_event|signed_json_wire_invalid/,variant);
    if (['identity_fingerprint','identity_expiry'].includes(variant)) assert.equal(reason,'origin_signed_event_identity_invalid',variant);
    if (variant === 'predecessor_missing') assert.equal(reason,'origin_signed_event_predecessor_invalid',variant);
    await c.query('RELEASE SAVEPOINT attack'); negatives.push({ variant, reason });
  }
  const exact = await issue();
  const after = await logEvent('hom','housekeeper','audit018_byte_profile','default_after',
    { reasoning: 'Verify a continuous default exact-byte event linkage chain.' },null,options);
  assert.equal(after.signed_body.payload_schema,EVENT_EXACT_PAYLOAD_SCHEMA);
  const ids = [first.event_id,exact.event_id,after.event_id];
  assert.equal((await readVerifiedEventsByIds(ids,'hom',{client:c})).size,3);
  const streamRows = (await c.query('SELECT * FROM aimos_events WHERE id=ANY($1::uuid[]) ORDER BY ledger_seq',[ids])).rows;
  const cognitive = createCognitiveWeightEvidenceBundle({ companyId: 'hom',
    masterIdentity: { master_pubkey: master.master_pubkey, master_fingerprint: master.fingerprint },
    events: streamRows.map(event=>({ ...event, pubkey:hk.pubkey, cert:hk.cert,
      device_fp:hk.device_fp, valid_until:hk.valid_until })) });
  const nativeCognitive = verifyCognitiveWeightEvidenceBundle(cognitive);
  assert.equal(nativeCognitive.eventStreamResults.length,1);
  assert.equal(nativeCognitive.eventStreamResults[0].valid,true,JSON.stringify(nativeCognitive.eventStreamResults));
  assert.equal(cognitive.event_streams[0].events[1].signed_body_bytes_b64u,
    streamRows[1].signed_body_bytes.toString('base64url'));
  assert.equal(Object.hasOwn(cognitive.event_streams[0].events[1],'signed_body'),false);
  assert.equal(Object.hasOwn(cognitive.event_streams[0].events[1],'metadata'),false);
  const cognitivePython = spawnSync('python3',[new URL('../../verifiers/mutmem-python/verify.py',import.meta.url).pathname,'verify-bundle','-'],{
    input:JSON.stringify(cognitive),encoding:'utf8',timeout:10000 });
  assert.equal(cognitivePython.status,0,cognitivePython.stderr+cognitivePython.stdout);
  assert.equal(JSON.parse(cognitivePython.stdout).verdict,'valid');
  // SQL verification helpers are not exposed to the runtime role. The INSERT
  // trigger ran under its constrained definer; owner reads below verify results.
  await c.query('RESET ROLE');
  for(const id of ids) assert.equal((await c.query('SELECT (public.ob2_verify_signed_event($1,$2)).id AS id',[id,'hom'])).rows[0].id,id);
  await c.query('ROLLBACK');
  console.log(JSON.stringify({ database, role:'agent_runtime',native_signer:'existing_housekeeper',
    independent_node_signature_verified:true,independent_python_signature_verified:true,legacy_exact_legacy_chain_verified:true,
    portable_event_cases:portableCases.map(({id,valid})=>({id,valid})),
    native_and_independent_cognitive_event_stream_verified:true,
    cognitive_memory_records:0,full_v2_recall_mutation_bundle_qualified:false,
    sql_insert_guard_enforced:true,negatives,candidate_ddl_and_events_rolled_back:true,
    production_database_changed:false,new_identity_created:false },null,2));
} finally { c.release(); await source.end(); await Promise.allSettled([pool.end(),agentPool.end()]); }
