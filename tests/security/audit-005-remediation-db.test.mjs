// R3 owned qualification: 100k+ genuine Ed25519 event rows in a schema-only
// disposable database, followed by two actual server.js recovery boots.
// Public credential/identity verification evidence is copied for boot only;
// no canonical memory rows, provider call or production identity mutation.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';

import { canonicalJson, generateKeypair, issueCert, signPayload } from '../../services/security/agent-identity.js';
import { eventGenesisHash, eventMutationHash } from '../../services/security/protocol/mutmem-protocol.js';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { verifyEventLedgerChain, verifyEventProof } from '../../services/observe/event-ledger.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert(/^aimos_test_security_audr3_[0-9]+_[a-f0-9]{6}$/.test(database));
const url = new URL(resolveAimosDatabaseUrl());
assert.equal(url.pathname, `/${database}`);
const admin = new pg.Client({ connectionString: url.href, connectionTimeoutMillis: 5_000 });
const COMPANY = 'hom';
const SIGNER = 'housekeeper';
const CHAIN_DOMAIN = Buffer.from('hom.aimos.verified-event-history-chain/v1\0', 'utf8');
const CHECKPOINT_SCHEMA = 'hom.aimos.event-recovery-checkpoint/v1';
const CHECKPOINT_OPERATION = 'event_history_recovery_checkpoint';
const TOTAL_UNRELATED = 1_004;
const TOTAL_COMPLETED = 50_001;

async function copyPublicBootAuthority() {
  // Cache boot verifies the existing Keychain slots against their complete
  // signed public lifecycle. Copy only verification evidence, never secrets
  // or canonical memory rows, and never make a new production identity.
  const sourceUrl = new URL(url); sourceUrl.pathname = '/aimos';
  const source = new pg.Client({ connectionString:sourceUrl.href });
  try {
    await source.connect();
    await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await admin.query('BEGIN');
    for (const table of ['agent_identity','aimos_agent_revocation_events','aimos_credential_lifecycle']) {
      const records = (await source.query(`SELECT to_jsonb(t) AS record FROM public.${table} t`)).rows;
      for (let offset=0; offset<records.length; offset+=500) {
        await admin.query(`INSERT INTO public.${table} SELECT * FROM jsonb_populate_recordset(NULL::public.${table},$1::jsonb) ON CONFLICT DO NOTHING`,
          [JSON.stringify(records.slice(offset,offset+500).map(row=>row.record))]);
      }
    }
    await admin.query('COMMIT');
    await source.query('COMMIT');
  } finally { await source.end(); }
}

async function bootRecoveryTwice() {
  const port=9202;
  const probe=net.createServer();
  await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(port,'127.0.0.1',resolve);});
  await new Promise(resolve=>probe.close(resolve));
  const observations=[];
  for (let boot=0; boot<2; boot+=1) {
    // server.js receives ordinary script argv, with all target facts explicit.
    const child=spawn(process.execPath,['server.js','--aimos-db',database,
      '--aimos-port',String(port),'--aimos-postgres-port',String(url.port||5432)],
    {cwd:process.cwd(),stdio:['ignore','pipe','pipe']});
    let log='';
    const retain=chunk=>{log=(log+chunk.toString()).slice(-16000);};
    child.stdout.on('data',retain); child.stderr.on('data',retain);
    let startupError=null; child.once('error',error=>{startupError=error;});
    try {
      const deadline=Date.now()+240000;
      let health=null;
      while (Date.now()<deadline) {
        if(startupError)throw startupError;
        if(child.exitCode!==null || child.signalCode!==null)throw new Error(`aud005_server_exited:${child.exitCode??child.signalCode}:${log}`);
        try {
          const response=await fetch(`http://127.0.0.1:${port}/health`,{signal:AbortSignal.timeout(1500)});
          const body=await response.json();
          assert.equal(body.runtime?.database_name,database,'isolated_health_database_mismatch');
          assert.equal(body.runtime?.server_port,port,'isolated_health_port_mismatch');
          if(log.includes('[BOOT] CR7 action recovery complete:')) {health=body;break;}
        } catch(error) {if(error.code==='ERR_ASSERTION')throw error;}
        await new Promise(resolve=>setTimeout(resolve,200));
      }
      assert(health,`aud005_actual_boot_recovery_timeout:${log}`);
      observations.push({pid:child.pid,recovery_completed:true,
        database:health.runtime.database_name,port,application_ready:health.ready,
        scope:'actual server.js pre-admission recovery; empty scratch Guide/config is not installer qualification'});
    } finally {
      if(child.exitCode===null && child.signalCode===null) {
        const exited=new Promise(resolve=>child.once('exit',resolve));
        child.kill('SIGTERM');
        const timer=setTimeout(()=>{if(child.exitCode===null && child.signalCode===null)child.kill('SIGKILL');},5000);
        await exited; clearTimeout(timer);
      }
    }
  }
  assert.notEqual(observations[0].pid,observations[1].pid);
  return observations;
}

function sha(value) { return createHash('sha256').update(value).digest(); }
function historyInitial() {
  return sha(Buffer.concat([CHAIN_DOMAIN,
    Buffer.from(canonicalJson({ company_id: COMPANY, signer_agent_id: SIGNER }), 'utf8')]));
}
function historyNext(previous, mutation) {
  return sha(Buffer.concat([CHAIN_DOMAIN, Buffer.from(previous), Buffer.from(mutation)]));
}
function unresolvedRoot(entries) {
  return sha(Buffer.concat([Buffer.from('hom.aimos.event-recovery-unresolved/v1\0', 'utf8'),
    Buffer.from(canonicalJson(entries), 'utf8')])).toString('hex');
}
function epoch(validFromSeconds) {
  const keys = generateKeypair();
  const cert = issueCert(keys.privkey, {
    v: 1, agent_id: SIGNER, pubkey: keys.pubkey, device_fp: `aud005-${validFromSeconds}`,
    valid_from: validFromSeconds, valid_until: 2_000_000_000,
    issuer: SIGNER, issued_at: validFromSeconds,
  });
  return { ...keys, cert, validFrom: new Date(validFromSeconds * 1000).toISOString(), seq: 0,
    previous: eventGenesisHash(COMPANY, SIGNER, new Date(validFromSeconds * 1000).toISOString()) };
}
let history = historyInitial();
let eventOrdinal = 0;
function append(state, operation, key, metadata, parentEventId = null) {
  eventOrdinal += 1;
  state.seq += 1;
  const id = randomUUID();
  const tsSigned = 1_788_600_000 + Math.floor(eventOrdinal / 10_000);
  const nonce = `aud005-${eventOrdinal}`;
  const body = {
    ledger_version: 1, event_id: id, company_id: COMPANY,
    subject_agent_id: SIGNER, actor_agent_id: null, actor_valid_from: null,
    signer_agent_id: SIGNER, signer_valid_from: state.validFrom,
    cert_fingerprint: sha(Buffer.from(state.cert, 'utf8')).toString('hex'),
    identity_tier: 'T1_SYSTEM_SELF', authority_kind: 'housekeeper_autonomous',
    request_envelope_digest: null, operation, key, metadata, parent_event_id: parentEventId,
    ledger_seq: state.seq, prev_mutation_hash: state.previous.toString('hex'), ts_signed: tsSigned,
  };
  const contentHash = sha(Buffer.from(canonicalJson(body), 'utf8'));
  const mutationHash = eventMutationHash(state.previous, contentHash, nonce, tsSigned);
  const row = { id, ts_signed: tsSigned, company_id: COMPANY, agent_id: SIGNER, operation, key,
    metadata, parent_event_id: parentEventId, ledger_seq: state.seq, signer_agent_id: SIGNER,
    signer_valid_from: state.validFrom, cert_fingerprint: body.cert_fingerprint,
    identity_tier: body.identity_tier, authority_kind: body.authority_kind, signed_body: body,
    content_hash: contentHash.toString('hex'), mutation_hash: mutationHash.toString('hex'),
    prev_mutation_hash: state.previous.toString('hex'), nonce,
    sig: Buffer.from(signPayload(state.privkey, body, nonce, tsSigned), 'base64url').toString('hex') };
  if (operation === CHECKPOINT_OPERATION) {
    const localProof = verifyEventProof({ ...row, ts: new Date(tsSigned * 1000), proof_required: true,
      ledger_version: 1, content_hash: Buffer.from(row.content_hash, 'hex'),
      mutation_hash: Buffer.from(row.mutation_hash, 'hex'),
      prev_mutation_hash: Buffer.from(row.prev_mutation_hash, 'hex'), sig: Buffer.from(row.sig, 'hex'),
      cert: state.cert, pubkey: state.pubkey }, state.pubkey);
    assert.deepEqual(localProof, { valid: true, reason: null });
  }
  state.previous = mutationHash;
  history = historyNext(history, mutationHash);
  return row;
}
function checkpoint(state, epochHeads, unresolvedEvents) {
  const unresolved = unresolvedEvents.map((row) => ({ event_id: row.id,
    mutation_sha256: row.mutation_hash, operation: row.operation, key: row.key }))
    .sort((left, right) => left.event_id.localeCompare(right.event_id));
  const body = { schema: CHECKPOINT_SCHEMA, algorithm: 'verified-event-history-chain/v1',
    company_id: COMPANY, signer_agent_id: SIGNER,
    prefix_event_count: epochHeads.reduce((sum, entry) => sum + entry.ledger_seq, 0),
    prefix_history_sha256: history.toString('hex'), prefix_epoch_heads: epochHeads,
    unresolved_count: unresolved.length, unresolved_root_sha256: unresolvedRoot(unresolved),
    unresolved_events: unresolved };
  return append(state, CHECKPOINT_OPERATION,
    sha(Buffer.from(canonicalJson(body), 'utf8')).toString('hex'),
    { ...body, checkpoint_sha256: sha(Buffer.from(canonicalJson(body), 'utf8')).toString('hex'),
      reasoning: 'Disposable AUD-005 checkpoint over a verified retained prefix.' });
}
async function insertRows(rows) {
  for (let index = 0; index < rows.length; index += 250) {
    await admin.query(`INSERT INTO aimos_events
      (id,ts,company_id,agent_id,operation,key,metadata,parent_event_id,proof_required,
       ledger_version,ledger_seq,signer_agent_id,signer_valid_from,cert_fingerprint,
       identity_tier,authority_kind,signed_body,content_hash,mutation_hash,
       prev_mutation_hash,ts_signed,nonce,sig)
      SELECT x.id::uuid,to_timestamp(x.ts_signed),x.company_id,x.agent_id,
       x.operation,x.key,x.metadata,x.parent_event_id::uuid,true,1,x.ledger_seq,
       x.signer_agent_id,x.signer_valid_from::timestamptz,x.cert_fingerprint,x.identity_tier,
       x.authority_kind,x.signed_body,decode(x.content_hash,'hex'),decode(x.mutation_hash,'hex'),
       decode(x.prev_mutation_hash,'hex'),x.ts_signed,x.nonce,decode(x.sig,'hex')
      FROM jsonb_to_recordset($1::jsonb) AS x(id text,ts_signed bigint,company_id text,
       agent_id text,operation text,key text,metadata jsonb,parent_event_id text,ledger_seq bigint,
       signer_agent_id text,signer_valid_from text,cert_fingerprint text,identity_tier text,
       authority_kind text,signed_body jsonb,content_hash text,mutation_hash text,
       prev_mutation_hash text,nonce text,sig text)`, [JSON.stringify(rows.slice(index, index + 250))]);
  }
}

const first = epoch(1_786_000_000);
const second = epoch(1_786_086_400);
const rows = [];
const scheduleId=randomUUID();
const scheduleCreatedAt='2026-08-20T00:00:00.000Z';
let scheduleCreation, scheduleLatest;
const result = { database, total_unrelated: TOTAL_UNRELATED, temporary_recovery_listener: 9202,
  genesis_invoked: false, canonical_memory_row_copy: false, public_boot_authority_copied: true,
  production_memory_write: false };
try {
  await admin.connect();
  for (const state of [first, second]) {
    await admin.query(`INSERT INTO agent_identity
      (agent_id,pubkey,cert,device_fp,valid_from,valid_until,issued_at,is_system_role)
      VALUES($1,$2,$3,$4,$5,$6,$5,true)`, [SIGNER, state.pubkey, state.cert,
      `aud005-${state.validFrom}`, state.validFrom, new Date(2_000_000_000 * 1000).toISOString()]);
  }
  const appendCompletedRange = (state, startIndex, endIndex) => {
    for (let index = startIndex; index < endIndex; index += 1) {
      const sessionKey = `aud005-complete-${index}`;
      const runId = `run-${index}`;
      const key = `${sessionKey}:${runId}`;
      const start = append(state, 'session_lane_started', key, {
        schema: 'hom.aimos.session-lane-transition/v1', session_key: sessionKey, run_id: runId,
        reasoning: 'A retained completed action exercises incremental recovery above the old lifetime cap.' });
      rows.push(start);
      rows.push(append(state, 'session_lane_terminal', key, {
        schema: 'hom.aimos.session-lane-transition/v1', session_key: sessionKey, run_id: runId,
        start_event_id: start.id, start_mutation_hash: start.mutation_hash,
        disposition: 'SUCCEEDED', reasoning: 'The retained action completed exactly once.' }, start.id));
    }
  };
  scheduleCreation=append(first,'schedule_created',scheduleId,{
    schema:'hom.aimos.schedule/v1',schedule_id:scheduleId,company_id:COMPANY,
    label:'AUD005 retained schedule projection',cron_expression:'0 0 1 1 *',
    task_description:'Isolated projection qualification; never dispatched.',agent_id:SIGNER,
    is_active:true,created_at:scheduleCreatedAt,
    reasoning:'A nonempty native schedule projection must remain bounded over retained run history.'});
  rows.push(scheduleCreation);
  for(let index=0;index<1001;index+=1) {
    scheduleLatest=append(first,'schedule_invalid',scheduleId,{
      schema:'hom.aimos.schedule/v1',schedule_id:scheduleId,last_run_at:null,
      last_status:'failed',last_error:'qualification_not_dispatched',
      updated_at:new Date(Date.parse(scheduleCreatedAt)+1000*(index+1)).toISOString(),
      reasoning:'Retained scheduler status readback qualification; no job execution.'},scheduleCreation.id);
    rows.push(scheduleLatest);
  }
  for (let index = 0; index < TOTAL_UNRELATED / 2; index += 1) {
    rows.push(append(first, 'audit_retained_unrelated', `first:${index}`,
      { reasoning: 'Retained unrelated AUD-005 history.' }));
  }
  const split = Math.floor(TOTAL_COMPLETED / 2);
  appendCompletedRange(first, 0, split);
  for (let index = 0; index < TOTAL_UNRELATED / 2; index += 1) {
    rows.push(append(second, 'audit_retained_unrelated', `second:${index}`,
      { reasoning: 'Retained unrelated AUD-005 history.' }));
  }
  appendCompletedRange(second, split, TOTAL_COMPLETED);
  const sessionStart = append(second, 'session_lane_started', 'aud005-session:run-1', {
    schema: 'hom.aimos.session-lane-transition/v1', session_key: 'aud005-session', run_id: 'run-1',
    reasoning: 'Open work crosses the signed recovery checkpoint.' });
  rows.push(sessionStart);
  const firstCheckpoint = checkpoint(second, [
    { valid_from: first.validFrom, ledger_seq: first.seq, mutation_sha256: first.previous.toString('hex') },
    { valid_from: second.validFrom, ledger_seq: second.seq, mutation_sha256: second.previous.toString('hex') },
  ], [sessionStart]);
  rows.push(firstCheckpoint);
  const terminal = append(second, 'session_lane_terminal', 'aud005-session:run-1', {
    schema: 'hom.aimos.session-lane-transition/v1', session_key: 'aud005-session', run_id: 'run-1',
    start_event_id: sessionStart.id, start_mutation_hash: sessionStart.mutation_hash,
    disposition: 'INDETERMINATE_PROCESS_RESTART',
    reasoning: 'The crossing operation receives its exact retained terminal.' }, sessionStart.id);
  rows.push(terminal);
  const generatedHeap = process.memoryUsage().heapUsed;
  await insertRows(rows);
  await admin.query(`INSERT INTO scheduled_tasks
    (id,company_id,label,cron_expression,task_description,agent_id,is_active,
     created_at,updated_at,last_status,last_error)
    VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,'failed','qualification_not_dispatched')`,
    [scheduleId,COMPANY,scheduleCreation.metadata.label,scheduleCreation.metadata.cron_expression,
      scheduleCreation.metadata.task_description,SIGNER,scheduleCreatedAt,scheduleLatest.metadata.updated_at]);
  rows.length = 0;
  const storedCheckpoint = (await admin.query(`SELECT e.*,i.pubkey,i.cert
    FROM aimos_events e JOIN agent_identity i
      ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
    WHERE e.id=$1`, [firstCheckpoint.id])).rows[0];
  const storedProof = verifyEventProof(storedCheckpoint, storedCheckpoint.pubkey);
  assert.deepEqual(storedProof, { valid: true, reason: null }, JSON.stringify({
    body_equal: canonicalJson(storedCheckpoint.signed_body) === canonicalJson(firstCheckpoint.signed_body),
    metadata_equal: canonicalJson(storedCheckpoint.metadata) === canonicalJson(firstCheckpoint.metadata),
    timestamp_ms: new Date(storedCheckpoint.ts).getTime(),
    expected_timestamp_ms: Number(firstCheckpoint.ts_signed) * 1000,
  }));
  const firstEpochRows=(await admin.query(`SELECT e.*,i.pubkey,i.cert
    FROM aimos_events e JOIN agent_identity i
      ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
    WHERE e.signer_valid_from=$1 ORDER BY e.ledger_seq LIMIT 3`,[first.validFrom])).rows;
  assert.equal(verifyEventLedgerChain(firstEpochRows).verified,true);
  assert.throws(()=>verifyEventLedgerChain([firstEpochRows[0],firstEpochRows[2]]),/chain_link_invalid/);
  assert.throws(()=>verifyEventLedgerChain([firstEpochRows[0],firstEpochRows[1],firstEpochRows[1]]),/chain_link_invalid/);
  assert.throws(()=>verifyEventLedgerChain([
    firstEpochRows[0],{...firstEpochRows[1],metadata:{...firstEpochRows[1].metadata,reasoning:'tampered'}},
  ]),/proof_invalid/);
  const secondEpochRow=(await admin.query(`SELECT e.*,i.pubkey,i.cert
    FROM aimos_events e JOIN agent_identity i
      ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
    WHERE e.signer_valid_from=$1 ORDER BY e.ledger_seq LIMIT 1`,[second.validFrom])).rows[0];
  assert.throws(()=>verifyEventLedgerChain([firstEpochRows[0],secondEpochRow]),/chain_link_invalid/);
  result.corrupted_missing_duplicate_and_cross_epoch_segments_denied=true;

  const db = await import('../../db/connection.js');
  const { readVerifiedRecoveryHistory, readVerifiedEventHistory,
    iterateVerifiedEventHistory, createVerifiedOpenEventReducer } = await import('../../services/observe/event-ledger.js');
  const { reconstructSessionLaneTraces, stopConversationSessionCleanup } = await import('../../services/orchestration/session-runner.js');
  const makeReducer = () => createVerifiedOpenEventReducer([{
    name: 'session_lane', startOperations: ['session_lane_started'],
    terminalOperations: ['session_lane_terminal'],
    startId: (event) => `${event.metadata.session_key}:${event.metadata.run_id}`,
    terminalId: (event) => `${event.metadata.session_key}:${event.metadata.run_id}`,
    validate: reconstructSessionLaneTraces,
  }]);

  const {listScheduledTasks,stopScheduler}=await import('../../services/orchestration/scheduler.js');
  const schedules=await listScheduledTasks();
  assert.equal(schedules.length,1);
  assert.equal(schedules[0].verified,true);
  assert.equal(schedules[0].statusMutationHash,scheduleLatest.mutation_hash);
  result.nonempty_schedule_projection={retained_status_events:1001,verified:true,latest_status_exact:true};

  let fullRows = await readVerifiedEventHistory(COMPANY, {
    operations: ['session_lane_started', 'session_lane_terminal'],
  });
  let fullReplay = reconstructSessionLaneTraces(fullRows);
  assert.equal(fullRows.length, TOTAL_COMPLETED * 2 + 2);
  assert.equal(fullReplay.complete.length, TOTAL_COMPLETED + 1);
  assert.equal(fullReplay.open.length, 0);
  const relevantEventRows = fullRows.length;
  const independentFullReplayComplete = fullReplay.complete.length;
  fullRows = null;
  fullReplay = null;
  global.gc?.();
  const streamingReducer = makeReducer();
  const streamingBaselineHeap = process.memoryUsage().heapUsed;
  let streamingPeakHeap = streamingBaselineHeap;
  const heapSampler = setInterval(() => {
    streamingPeakHeap = Math.max(streamingPeakHeap, process.memoryUsage().heapUsed);
  },20);
  let fullStream;
  try { fullStream = await readVerifiedRecoveryHistory(COMPANY, {
    operations:['session_lane_started','session_lane_terminal'], reducer:streamingReducer,
    onOpenGroup:() => { throw new Error('unexpected_open_action'); },
  }); } finally { clearInterval(heapSampler); }
  assert.equal(fullStream.rows.length, 0);
  assert.equal(fullStream.reduction.completedActions, TOTAL_COMPLETED + 1);
  assert.equal(fullStream.reduction.peakOpenActions, 0);
  assert.equal(fullStream.reduction.peakRetainedRows, 2);

  const before = process.memoryUsage().heapUsed;
  const recovered = await readVerifiedRecoveryHistory(COMPANY, {
    operations: ['session_lane_started', 'session_lane_terminal'],
    reducer: makeReducer(),
  });
  const reconstructed = reconstructSessionLaneTraces(recovered.rows);
  assert.equal(recovered.summary.checkpointValidated, true);
  assert(recovered.summary.suffixRowCount >= 1);
  assert.equal(recovered.rows.length, 0);
  assert.equal(reconstructed.complete.length, 0);
  assert.equal(reconstructed.open.length, 0);
  assert.equal(recovered.reduction.completedActions, TOTAL_COMPLETED + 1);
  assert.equal(recovered.reduction.peakRetainedRows, 2);
  assert(recovered.summary.epochCount >= 2);
  result.checkpoint_crossing_complete = true;
  result.signer_rotation_verified = true;
  result.recovery_heap_delta_bytes = process.memoryUsage().heapUsed - before;
  result.generation_heap_bytes = generatedHeap;
  result.relevant_event_rows = relevantEventRows;
  result.independent_full_replay_complete = independentFullReplayComplete;
  result.streaming_completed_actions = fullStream.reduction.completedActions;
  result.streaming_peak_retained_rows = fullStream.reduction.peakRetainedRows;
  result.streaming_peak_heap_bytes = streamingPeakHeap;
  result.streaming_peak_heap_delta_bytes = streamingPeakHeap - streamingBaselineHeap;

  const emptyCheckpoint=checkpoint(second,[
    {valid_from:first.validFrom,ledger_seq:first.seq,mutation_sha256:first.previous.toString('hex')},
    {valid_from:second.validFrom,ledger_seq:second.seq,mutation_sha256:second.previous.toString('hex')},
  ],[]);
  await insertRows([emptyCheckpoint]);
  const fast=await readVerifiedRecoveryHistory(COMPANY,{
    operations:['session_lane_started','session_lane_terminal'],reducer:makeReducer(),
    onOpenGroup:()=>{throw new Error('unexpected_open_after_empty_checkpoint');},
  });
  assert.equal(fast.summary.usedCheckpoint,true);
  assert.equal(fast.summary.fullPrefixVerified,true);
  assert.equal(fast.reduction.acceptedRows,0);
  result.empty_checkpoint_skips_completed_action_replay_not_signature_verification=true;

  // A genuinely large unresolved set stays in PostgreSQL's grouped cursor.
  // The caller receives one trace at a time, not an unbounded final array.
  const openStarts=[];
  for(let index=0;index<10001;index+=1)openStarts.push(append(second,'session_lane_started',`aud005-open-${index}:run`,{
    schema:'hom.aimos.session-lane-transition/v1',session_key:`aud005-open-${index}`,run_id:'run',
    reasoning:'Retained unresolved work qualifies bounded grouped recovery.'}));
  await insertRows(openStarts);
  let openCount=0,openPeakHeap=process.memoryUsage().heapUsed;
  const openBaseline=process.memoryUsage().heapUsed;
  const opens=await readVerifiedRecoveryHistory(COMPANY,{
    operations:['session_lane_started','session_lane_terminal'],reducer:makeReducer(),
    onOpenGroup:async group=>{
      assert.equal(group.length,1);openCount+=1;
      openPeakHeap=Math.max(openPeakHeap,process.memoryUsage().heapUsed);
    },
  });
  assert.equal(openCount,10001);
  assert.equal(opens.rows.length,0);
  assert.equal(opens.reduction.peakRetainedRows,1);
  assert.equal(opens.reduction.peakOpenActions,1);
  result.large_unresolved={count:openCount,retained_rows:opens.rows.length,
    peak_action_rows:opens.reduction.peakRetainedRows,heap_delta_bytes:openPeakHeap-openBaseline};
  await insertRows(openStarts.map(start=>append(second,'session_lane_terminal',start.key,{
    ...start.metadata,start_event_id:start.id,start_mutation_hash:start.mutation_hash,
    disposition:'SUCCEEDED',reasoning:'The qualification retains each exact terminal.'},start.id)));
  openStarts.length=0;

  // Boot the actual native service after the same above-threshold history.
  // A final open lane is signed with the existing Housekeeper and must receive
  // one restart terminal. The second boot must not append another terminal.
  await copyPublicBootAuthority();
  const {logEvent}=await import('../../services/observe/event-ledger.js');
  const bootKey=`aud005-boot-${database}:run-open`;
  const bootStart=await logEvent(COMPANY,SIGNER,'session_lane_started',bootKey,{
    schema:'hom.aimos.session-lane-transition/v1',session_key:`aud005-boot-${database}`,
    run_id:'run-open',reasoning:'An actual native service restart must reconcile this retained open lane.',
  },null,{returnReceipt:true,exclusiveOperationKey:true});
  result.actual_service_boots=await bootRecoveryTwice();
  const bootTerminals=(await admin.query(`SELECT e.*,i.pubkey,i.cert FROM aimos_events e
    JOIN agent_identity i ON i.agent_id=e.signer_agent_id AND i.valid_from=e.signer_valid_from
    WHERE e.operation='session_lane_terminal' AND e.key=$1`,[bootKey])).rows;
  assert.equal(bootTerminals.length,1);
  assert.equal(bootTerminals[0].parent_event_id,bootStart.event_id);
  assert.equal(bootTerminals[0].metadata.disposition,'INDETERMINATE_PROCESS_RESTART');
  assert.equal(verifyEventProof(bootTerminals[0],bootTerminals[0].pubkey).valid,true);
  result.actual_boot_open_lane_reconciled_once=true;

  const malformedTool=append(second,'tool_execution_terminal','aud005-malformed-tool',{
    schema:'aimos.tool-action/v1',reasoning:'A current-schema terminal without its native action ID must be rejected, not omitted.'});
  await insertRows([malformedTool]);
  const {reconstructToolActionTraces}=await import('../../services/orchestration/tool-action-ledger.js');
  assert.throws(()=>reconstructToolActionTraces([malformedTool]),/tool_action_terminal_without_start/);
  await assert.rejects(readVerifiedRecoveryHistory(COMPANY,{
    operations:['tool_execution_started','tool_execution_terminal'],
    reducer:createVerifiedOpenEventReducer([{
      name:'tool_action',startOperations:['tool_execution_started'],terminalOperations:['tool_execution_terminal'],
      startId:row=>row.id,terminalId:row=>row.metadata.tool_action_event_id,
      validate:reconstructToolActionTraces,
    }]),onOpenGroup:()=>{throw new Error('malformed_tool_must_not_authorize_recovery');},
  }),/tool_action_terminal_without_start/);
  result.malformed_current_identity_not_silently_omitted=true;

  // Reuse a completed identity from before the empty checkpoint. Both full
  // native replay and the checkpointed grouped reader must reject the fork.
  const reused=append(second,'session_lane_started','aud005-complete-0:run-0',{
    schema:'hom.aimos.session-lane-transition/v1',session_key:'aud005-complete-0',run_id:'run-0',
    reasoning:'Signed completed identity reuse must not disappear after a checkpoint.'});
  const reusedTerminal=append(second,'session_lane_terminal',reused.key,{
    ...reused.metadata,start_event_id:reused.id,start_mutation_hash:reused.mutation_hash,
    disposition:'SUCCEEDED',reasoning:'A second completed trace remains a fork.'},reused.id);
  await insertRows([reused,reusedTerminal]);
  await assert.rejects(readVerifiedRecoveryHistory(COMPANY,{
    operations:['session_lane_started','session_lane_terminal'],reducer:makeReducer(),
    onOpenGroup:()=>{throw new Error('unexpected_open_in_duplicate_complete_test');},
  }),/start_fork/);
  const duplicateRows=(await admin.query(`SELECT * FROM aimos_events WHERE key=$1 ORDER BY signer_valid_from,ledger_seq`,[reused.key])).rows;
  assert.throws(()=>reconstructSessionLaneTraces(duplicateRows),/start_fork/);
  result.completed_identity_reuse_across_checkpoint_denied=true;

  const omittedStart = append(second, 'session_lane_started', 'aud005-session:run-omitted', {
    schema: 'hom.aimos.session-lane-transition/v1', session_key: 'aud005-session', run_id: 'run-omitted',
    reasoning: 'This start must not be omitted from a checkpoint.' });
  const badCheckpoint = checkpoint(second, [
    { valid_from: first.validFrom, ledger_seq: first.seq, mutation_sha256: first.previous.toString('hex') },
    { valid_from: second.validFrom, ledger_seq: second.seq, mutation_sha256: second.previous.toString('hex') },
  ], []);
  await insertRows([omittedStart, badCheckpoint]);
  await assert.rejects(readVerifiedRecoveryHistory(COMPANY, {
    operations: ['session_lane_started', 'session_lane_terminal'],
    reducer: makeReducer(),
  }), /event_recovery_checkpoint_unresolved_omission/);
  result.unresolved_omission_denied = true;
  const unresolved=[{event_id:omittedStart.id,mutation_sha256:omittedStart.mutation_hash,
    operation:omittedStart.operation,key:omittedStart.key}];
  const wrongPrefixBody={schema:CHECKPOINT_SCHEMA,algorithm:'verified-event-history-chain/v1',
    company_id:COMPANY,signer_agent_id:SIGNER,prefix_event_count:first.seq+second.seq,
    prefix_history_sha256:'01'.repeat(32),prefix_epoch_heads:[
      {valid_from:first.validFrom,ledger_seq:first.seq,mutation_sha256:first.previous.toString('hex')},
      {valid_from:second.validFrom,ledger_seq:second.seq,mutation_sha256:second.previous.toString('hex')},
    ],unresolved_count:1,unresolved_root_sha256:unresolvedRoot(unresolved),unresolved_events:unresolved};
  const wrongPrefixHash=sha(Buffer.from(canonicalJson(wrongPrefixBody),'utf8')).toString('hex');
  await insertRows([append(second,CHECKPOINT_OPERATION,wrongPrefixHash,{
    ...wrongPrefixBody,checkpoint_sha256:wrongPrefixHash,
    reasoning:'An internally consistent signed checkpoint with a false prefix root must be rejected.'})]);
  await assert.rejects(readVerifiedRecoveryHistory(COMPANY,{
    operations:['session_lane_started','session_lane_terminal'],reducer:makeReducer(),
  }),/event_recovery_checkpoint_verified_prefix_mismatch/);
  result.signed_recomputed_false_prefix_root_denied=true;
  const forgedBody={schema:CHECKPOINT_SCHEMA,algorithm:'verified-event-history-chain/v1',
    company_id:COMPANY,signer_agent_id:SIGNER,
    prefix_event_count:first.seq+second.seq,prefix_history_sha256:history.toString('hex'),
    prefix_epoch_heads:[
      {valid_from:first.validFrom,ledger_seq:first.seq,mutation_sha256:first.previous.toString('hex')},
      {valid_from:second.validFrom,ledger_seq:second.seq,mutation_sha256:second.previous.toString('hex')},
    ],unresolved_count:1,unresolved_root_sha256:unresolvedRoot(unresolved),unresolved_events:unresolved};
  const forgedCheckpoint=append(second,CHECKPOINT_OPERATION,
    sha(Buffer.from(canonicalJson(forgedBody),'utf8')).toString('hex'),
    {...forgedBody,checkpoint_sha256:'00'.repeat(32),reasoning:'Signed event with a forged checkpoint commitment must fail closed.'});
  await insertRows([forgedCheckpoint]);
  await assert.rejects(readVerifiedRecoveryHistory(COMPANY, {
    operations: ['session_lane_started', 'session_lane_terminal'], reducer: makeReducer(),
  }), /event_recovery_checkpoint_commitment_invalid/);
  result.forged_checkpoint_commitment_denied=true;
  await insertRows([append(second,'schedule_created',scheduleId,{
    ...scheduleCreation.metadata,reasoning:'Duplicate retained creation must still fail in the streaming projection owner.'})]);
  await assert.rejects(listScheduledTasks(),/schedule_creation_not_unique/);
  result.nonempty_schedule_duplicate_creation_denied=true;
  stopScheduler();
  stopConversationSessionCleanup();
  await Promise.allSettled([db.pool.end(), db.agentPool.end()]);
  console.log(JSON.stringify({ ...result, observed_at: new Date().toISOString() }, null, 2));
} finally {
  await admin.end().catch(() => {});
}
