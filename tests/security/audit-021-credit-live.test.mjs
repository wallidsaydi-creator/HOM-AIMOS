// Canonical live qualification: real existing memory, enrolled actor, selected
// OAuth provider and native Housekeeper. No fixture server/database/identity.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildEnvelopeHeaders } from '../../services/security/envelope-headers.js';
import { pool, agentPool, schedulerLockPool, withTransaction } from '../../db/connection.js';
import { readVerifiedEventsByIds } from '../../services/observe/event-ledger.js';
import { readMemoryCreditCacheFrontier } from '../../services/retrieval/recall-calibrator.js';
import { MEMORY_CREDIT_POLICY } from '../../services/security/protocol/memory-credit.js';
assert(process.argv.includes('--live-fire'), 'explicit_live_fire_required');
const actor = 'codex-auditor', company = 'hom', base = 'http://127.0.0.1:9100';
const target = '511d7516-c786-4b62-b9b3-f2fd6c2c0ec5';
const session = `r7-credit-native-use:${randomUUID()}`;
async function call(path, body) {
  const headers = await buildEnvelopeHeaders(actor, 'POST', path, body);
  const response = await fetch(base + path, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(600000) });
  return { status: response.status, body: await response.json(), nonce: new Headers(headers).get('aimos-agent-nonce') };
}
try {
  assert.equal((await (await fetch(base + '/healthz')).json()).ready, true);
  const before = await call('/aimos/recall', { company_id: company, memory_id: target,
    query: 'retained R6 normal completion session', limit: 1, cache: false });
  assert.equal(before.status, 200, JSON.stringify(before.body.error));
  const memory = before.body.memories.find(row => row.id === target);
  assert(memory, 'existing_private_memory_not_returned');
  // This first stage collects actual completed-task evidence. Final scorer,
  // response and receipt credit parity are qualified after HK processing.
  console.log(JSON.stringify({ stage: 'native_recall', target, value: memory.value, memory_credit: memory.memory_credit }));
  const run = await call(`/agents/${actor}/run`, { sessionKey: session, idempotencyKey: randomUUID(),
    taskType: 'chat', disableDelegation: true,
    prompt: `Call the registered aimos_recall tool exactly once with memory_id ${target} and limit 1. Then state, in one sentence, only what the returned memory establishes about the R6 runtime-acceptance request. Do not infer a comparison, call another tool, write a file, or save a new fact.` });
  assert.equal(run.status, 200, JSON.stringify(run.body.error || run.body));
  console.log(JSON.stringify({ stage: 'native_completed_response', session, response: run.body }));
  const refs = await withTransaction(async client => {
    const starts = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1 AND operation='agent_run_started'
      AND metadata->>'session_key'=$2`, [company, session]);
    assert.equal(starts.rows.length, 1);
    const startId = starts.rows[0].id;
    const ends = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1 AND operation='agent_run_terminal'
      AND parent_event_id=$2`, [company, startId]);
    assert.equal(ends.rows.length, 1);
    const verified = await readVerifiedEventsByIds([startId, ends.rows[0].id], company, { client });
    const start = verified.get(startId), terminal = verified.get(ends.rows[0].id);
    assert.equal(terminal.metadata.status, 'completed');
    const contexts = await client.query(`SELECT c.id FROM aimos_events c JOIN aimos_events s ON c.parent_event_id=s.id
      WHERE c.company_id=$1 AND c.operation='model_context_completed' AND s.operation='tool_context_prepared'
      AND s.metadata->>'run_id'=$2 ORDER BY c.ledger_seq DESC`, [company, start.metadata.run_id]);
    const models = await readVerifiedEventsByIds(contexts.rows.map(row => row.id), company, { client });
    for (const row of contexts.rows) {
      const model = models.get(row.id), inputs = model.metadata.result_origin?.input_snapshot?.tool_results || [];
      for (const ref of inputs.filter(ref => ref.tool === 'aimos_recall')) {
        const recalls = await client.query(`SELECT id FROM aimos_events WHERE company_id=$1 AND operation='recall_receipt'
          AND metadata->>'derived_tool_action_event_id'=$2`, [company, ref.action_event_id]);
        const receipts = await readVerifiedEventsByIds(recalls.rows.map(row => row.id), company, { client });
        for (const recall of receipts.values()) {
          const evidence = recall.metadata.evidence?.find(item => item.memory_id === target);
          if (evidence) return { run_id: start.metadata.run_id, start: start.id, terminal: terminal.id,
            model: model.id, recall: recall.id, recall_hash: Buffer.from(recall.mutation_hash).toString('hex'), evidence };
        }
      }
    }
    throw new Error('completed_model_did_not_consume_target_recall');
  }, { restricted: true, readOnly: true, client_id: company, agent_id: 'housekeeper' });
  console.log(JSON.stringify({ stage: 'native_evaluation_ready', session, target, ...refs }));

  const label = {
    memory_id: target,
    recall_event_id: refs.recall,
    recall_mutation_hash: refs.recall_hash,
    calibration_mutation_hash: refs.evidence.calibration_mutation_hash,
    raw_score: refs.evidence.raw_calibration_score,
    calibrated_score: refs.evidence.calibrated_score,
    observed_usefulness: 1,
    label_source: 'Operator-authorized R7 live qualification: the completed response exactly restated the retained runtime-acceptance fact.',
    evaluation: { run_terminal_event_id: refs.terminal, model_context_event_id: refs.model },
  };
  const observation = await call('/aimos/recall/calibration/observe', {
    company_id: company, labels: [label],
  });
  assert.equal(observation.status, 200, JSON.stringify(observation.body));
  const replay = await call('/aimos/recall/calibration/observe', {
    company_id: company, labels: [label],
  });
  assert.equal(replay.status, 409, JSON.stringify(replay.body));
  const conflict = await call('/aimos/recall/calibration/observe', {
    company_id: company, labels: [{ ...label, observed_usefulness: 0 }],
  });
  assert.equal(conflict.status, 409, JSON.stringify(conflict.body));

  const dream = await call('/aimos/dream/run', {});
  assert.equal(dream.status, 200, JSON.stringify(dream.body));
  const measured = await call('/aimos/recall', { company_id: company, memory_id: target,
    query: 'retained R6 runtime acceptance request', limit: 1, cache: false });
  assert.equal(measured.status, 200, JSON.stringify(measured.body));
  const measuredMemory = measured.body.memories.find(row => row.id === target);
  assert(measuredMemory, 'measured_private_memory_not_returned');
  assert.equal(measuredMemory.memory_credit.state, 'MEASURED_REPORTED_USEFULNESS');
  assert(measuredMemory.memory_credit.count >= 1);
  assert.equal(measuredMemory.memory_credit.score, 1);
  assert.equal(measuredMemory.credit_score, 1);
  const receiptEvidence = measured.body.recall_receipt.evidence.find(row => row.memory_id === target);
  assert.deepEqual(receiptEvidence.memory_credit, measuredMemory.memory_credit);
  assert.equal(measured.body.recall_meta.return_projection.return_path, 'identifier_exact');

  const projection = await withTransaction(async client => {
    const event = (await readVerifiedEventsByIds([measuredMemory.memory_credit.event_id], company, { client }))
      .get(measuredMemory.memory_credit.event_id);
    assert.equal(event.operation, 'memory_credit_projection');
    assert.equal(event.signer_agent_id, 'housekeeper');
    assert.equal(event.metadata.visibility.subject_agent_id, actor);
    const codexFrontier = await readMemoryCreditCacheFrontier(company, {
      actorAgentId: actor, clearanceCeiling: 12, dataClassCeiling: 'restricted',
    }, client);
    const housekeeperFrontier = await readMemoryCreditCacheFrontier(company, {
      actorAgentId: 'housekeeper', clearanceCeiling: 12, dataClassCeiling: 'restricted',
    }, client);
    assert.equal(codexFrontier, Buffer.from(event.mutation_hash).toString('hex'));
    assert.equal(housekeeperFrontier, MEMORY_CREDIT_POLICY);
    return { event_id: event.id, mutation_hash: codexFrontier,
      count: event.metadata.count, score: event.metadata.score };
  }, { restricted: true, readOnly: true, client_id: company, agent_id: 'housekeeper' });
  console.log(JSON.stringify({ stage: 'native_credit_measured', session, target,
    observation_event_id: observation.body.observation_receipt.event_id,
    replay_status: replay.status, conflict_status: conflict.status,
    projection, response_receipt_parity: true, cache_frontier_subject_scoped: true,
    objective_quality_claimed: measuredMemory.memory_credit.objective_quality_claimed,
    action_authority: measuredMemory.memory_credit.action_authority }));
} finally { await Promise.all([pool.end(), agentPool.end(), schedulerLockPool.end()]); }
