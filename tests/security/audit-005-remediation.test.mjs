import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { createVerifiedOpenEventReducer } from '../../services/observe/event-ledger.js';
import { reconstructSessionLaneTraces,
  stopConversationSessionCleanup } from '../../services/orchestration/session-runner.js';
import { reconstructRunTraces } from '../../services/orchestration/run-metadata.js';

after(() => stopConversationSessionCleanup());

const ROOT = new URL('../../', import.meta.url);
const read = path => readFileSync(new URL(path, ROOT), 'utf8');

test('boot recovery verifies a cursor-paged suffix and authenticates unresolved work across checkpoints', () => {
  const ledger = read('services/observe/event-ledger.js');
  const server = read('server.js');
  const scheduler = read('services/orchestration/scheduler.js');
  assert.match(ledger, /EVENT_HISTORY_PAGE_ROWS = 16/);
  assert.match(ledger, /DECLARE \$\{cursor\} NO SCROLL CURSOR WITHOUT HOLD/);
  assert.match(ledger, /event_recovery_checkpoint_unresolved_omission/);
  assert.match(ledger, /unresolved_events/);
  assert.match(ledger, /readVerifiedEventsByIds/);
  assert.match(ledger, /expectedPreviousMutationHash/);
  assert.match(server, /readVerifiedRecoveryHistory/);
  assert.match(server, /checkpointCr7RecoveryAtBoot/);
  assert.ok(
    server.indexOf('await checkpointCr7RecoveryAtBoot();')
      < server.indexOf('schedulerStatus = await startScheduler'),
    'recovery checkpoint must commit before scheduler admission can advance the event ledger',
  );
  assert.match(scheduler, /readVerifiedRecoveryHistory/);
  assert.doesNotMatch(server.slice(server.indexOf('async function reconcileCr7OpenActionsAtBoot'),
    server.indexOf('async function checkpointCr7RecoveryAtBoot')), /readVerifiedEventHistory/);
});

test('native identity fallback accepts empty run metadata and still rejects a mismatched key', () => {
  const start={id:'native-start',key:'native-run',operation:'agent_run_started',
    mutation_hash:'ab'.repeat(32),metadata:{schema:'hom.aimos.agent-run-state/v1',run_id:''}};
  assert.equal(reconstructRunTraces([start]).open[0].runId,start.key);
  assert.equal(reconstructRunTraces([{...start,metadata:{...start.metadata,run_id:false}}]).open[0].runId,start.key);
  assert.throws(()=>reconstructRunTraces([{...start,metadata:{...start.metadata,run_id:'substituted'}}]),/key_mismatch/);
  assert.match(read('services/observe/event-ledger.js'),/agent_run: 'e.key'/);
});

test('non-recovery lifetime readers retain only their exact operations after complete verification', () => {
  for (const [file, pattern] of [
    ['services/orchestration/tool-approval-store.js', /operations: Object\.values\(OPERATIONS\)/],
    ['services/retrieval/recall-calibrator.js', /operations: \[GENESIS_OPERATION, OBSERVATION_OPERATION, UPDATE_OPERATION\]/],
    ['services/orchestration/scheduler.js', /operations: \['session_lane_started', 'session_lane_terminal'\]/],
  ]) assert.match(read(file), pattern, file);
});

test('grouped recovery uses native fork predicates even after an identity has completed', () => {
  const schema = 'hom.aimos.session-lane-transition/v1';
  const epoch = '2026-09-05T00:00:00.000Z';
  const reducer = createVerifiedOpenEventReducer([{
    name: 'session_lane',
    startOperations: ['session_lane_started'],
    terminalOperations: ['session_lane_terminal'],
    startId: (event) => `${event.metadata.session_key}:${event.metadata.run_id}`,
    terminalId: (event) => `${event.metadata.session_key}:${event.metadata.run_id}`,
    validate: reconstructSessionLaneTraces,
  }]);
  const mutation = 'ab'.repeat(32);
  const rows = [];
  for (let index = 0; index < 2; index += 1) {
    const lane = `session-${index}:run-${index}`;
    const startId = `start-${index}`;
    rows.push({ id:startId, operation:'session_lane_started', key:lane,
      signer_valid_from:epoch, ledger_seq:index * 2 + 1, mutation_hash:mutation,
      metadata:{ schema, session_key:`session-${index}`, run_id:`run-${index}` } });
    rows.push({ id:`terminal-${index}`, operation:'session_lane_terminal', key:lane,
      parent_event_id:startId, signer_valid_from:epoch, ledger_seq:index * 2 + 2,
      mutation_hash:'cd'.repeat(32), metadata:{ schema, session_key:`session-${index}`,
        run_id:`run-${index}`, start_event_id:startId, start_mutation_hash:mutation } });
  }
  assert.equal(typeof reducer.reduce, 'function');
  assert.equal(reconstructSessionLaneTraces(rows).complete.length, 2);
  const reused = { ...rows[0], id:'reused-completed-start', ledger_seq:5 };
  assert.throws(() => reconstructSessionLaneTraces([...rows,reused]), /start_fork/);
});
