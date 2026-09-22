// Real database parity edge cases for the same R3 grouped recovery owner.
// Uses the isolated runner's existing Housekeeper verification material.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {pool,agentPool} from '../../db/connection.js';
import {logEvent,iterateVerifiedEventHistory,createVerifiedOpenEventReducer} from '../../services/observe/event-ledger.js';
import {reconstructRunTraces} from '../../services/orchestration/run-metadata.js';

if(!process.argv.includes('--live-fire'))throw new Error('owned_live_fire_required');
const database=process.argv[process.argv.indexOf('--aimos-db')+1];
assert(/^aimos_test_security_audr3_[0-9]+_[a-f0-9]{6}$/.test(database));
const schema='hom.aimos.agent-run-state/v1';
const reducer=()=>createVerifiedOpenEventReducer([{
  name:'agent_run',startOperations:['agent_run_started'],terminalOperations:['agent_run_terminal'],
  relatedOperations:['agent_run_awaiting_approval'],
  startId:row=>row.metadata.schema===schema ? row.metadata.run_id||row.key : null,
  terminalId:row=>row.metadata.schema===schema ? row.metadata.run_id||row.key : null,
  validate:reconstructRunTraces,
}]);
async function verifiedProjection() {
  const client=await agentPool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query("SELECT set_config('app.current_client_id','hom',true),set_config('app.current_agent_id','housekeeper',true)");
    for await(const _row of iterateVerifiedEventHistory('hom',{client})) { /* exhaust verification */ }
    const result=await reducer().reduce(client,'hom','housekeeper');
    await client.query('COMMIT');return result;
  } catch(error) {await client.query('ROLLBACK');throw error;}
  finally {client.release();}
}
try {
  assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name,database);
  const key='aud005-fallback:'+randomUUID();
  const start=await logEvent('hom','housekeeper','agent_run_started',key,{
    schema,run_id:'',reasoning:'Qualify the retained native empty-ID key fallback without dispatching a model.',
  },null,{returnReceipt:true});
  const open=await verifiedProjection();
  assert.equal(open.metrics.openActions,1);
  assert.equal(open.rows[0].key,key);
  await logEvent('hom','housekeeper','agent_run_terminal',key,{
    schema,run_id:'',start_event_id:start.event_id,start_mutation_hash:start.mutation_hash,
    disposition:'INDETERMINATE_PROCESS_RESTART',reasoning:'Close the signed qualification trace without model execution.',
  },start.event_id,{returnReceipt:true});
  assert.equal((await verifiedProjection()).metrics.completedActions,1);
  const orphanKey='aud005-orphan-related:'+randomUUID();
  await logEvent('hom','housekeeper','agent_run_awaiting_approval',orphanKey,{
    schema,run_id:orphanKey,reasoning:'A signed orphan related transition must reach the native validator.',
  },null,{returnReceipt:true});
  await assert.rejects(verifiedProjection(),/agent_run_transition_without_start/);
  console.log(JSON.stringify({database,empty_identity_native_fallback:true,
    exact_terminal_verified:true,orphan_related_transition_denied:true,
    production_effect:false,provider_call:false,temporary_listener:false}));
} finally {await Promise.allSettled([pool.end(),agentPool.end()]);}
