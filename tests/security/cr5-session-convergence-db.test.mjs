import assert from 'node:assert/strict';
import test from 'node:test';

import { agentPool, pool } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { createSessionMemoryOwner } from '../../services/orchestration/session-memory-owner.js';
import { verifyCanonicalSaveTrace } from '../../services/write/canonical-save-contract.js';

if (!process.argv.includes('--live-fire')) {
  throw new Error('cr5-session-convergence-db.test.mjs requires --live-fire and an isolated AIMOS database');
}

const runId = `${Date.now()}`;
const sessionId = `cr5_session_${runId}`;
const source = 'test:cr5-session-convergence';
const context = Object.freeze({
  companyId: 'hom',
  agentId: 'housekeeper',
  clearanceLevel: 5,
  autonomousHousekeeper: true,
  source,
});

async function countSessionRows() {
  return Number((await pool.query(
    'SELECT count(*)::int AS n FROM aimos_memories WHERE company_id=$1 AND source=$2',
    ['hom', source],
  )).rows[0].n);
}

test('CR5 session SAVE proves typed Housekeeper actions, security order, continuity, and restart parity', async () => {
  let owner = createSessionMemoryOwner();
  const user = await owner.appendTurn({
    session_id: sessionId,
    turn_id: `${sessionId}:user`,
    role: 'user',
    content: 'CR5 retains this exact signed session observation through the complete canonical SAVE security path.',
    observed_at: '2026-08-27T12:00:00.000Z',
    source,
    clearance_level: 5,
  }, context);
  const assistant = await owner.appendTurn({
    session_id: sessionId,
    turn_id: `${sessionId}:assistant`,
    role: 'assistant',
    content: 'CR5 controlled reference SECRET-C5A7B9D1 remains retained as quarantine evidence without becoming an instruction.',
    observed_at: '2026-08-27T12:01:00.000Z',
    source,
    clearance_level: 5,
  }, context);
  assert.equal(user.sequence, 1);
  assert.equal(assistant.sequence, 2);
  assert.equal(assistant.quarantined, true);

  owner = createSessionMemoryOwner();
  const restoredBeforeFinalize = await owner.loadVerifiedTurns({ session_id: sessionId }, context);
  assert.deepEqual(restoredBeforeFinalize.map((turn) => turn.sequence), [1, 2]);
  const finalized = await owner.finalizeSession({
    session_id: sessionId,
    source,
    clearance_level: 5,
    expected_turn_count: 2,
  }, context);
  assert.equal(finalized.turn_count, 2);
  assert.equal(finalized.exchange_count, 1);
  assert.match(finalized.session_merkle_root, /^[0-9a-f]{64}$/);
  assert.match(finalized.exchange_merkle_root, /^[0-9a-f]{64}$/);
  assert.equal(await countSessionRows(), 4);

  owner = createSessionMemoryOwner();
  const replay = await owner.finalizeSession({ session_id: sessionId, source }, context);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.session_merkle_root, finalized.session_merkle_root);
  assert.equal(replay.exchange_merkle_root, finalized.exchange_merkle_root);
  assert.equal(await countSessionRows(), 4);
  await assert.rejects(owner.appendTurn({
    session_id: sessionId,
    turn_id: `${sessionId}:late`,
    role: 'user',
    content: 'A finalized session cannot admit a late turn after restart.',
    observed_at: '2026-08-27T12:02:00.000Z',
    source,
  }, context), /session_already_finalized/);

  const events = await pool.query(
    `SELECT id::text, operation, key, metadata, parent_event_id::text
       FROM aimos_events
      WHERE company_id=$1
        AND key LIKE $2
        AND operation IN ('canonical_save_action_started','canonical_save_terminal')
      ORDER BY ledger_seq`,
    ['hom', `sess:${sessionId}:%`],
  );
  const actions = events.rows.filter((row) => row.operation === 'canonical_save_action_started');
  const terminals = events.rows.filter((row) => row.operation === 'canonical_save_terminal');
  assert.equal(actions.length, 4);
  assert.equal(terminals.length, 4);

  for (const terminalRow of terminals) {
    const terminal = await readVerifiedEventById(terminalRow.id, 'hom');
    const trace = terminal.metadata;
    const verification = verifyCanonicalSaveTrace(trace);
    assert.equal(verification.valid, true, verification.reason);
    assert.equal(trace.outcome, 'SUCCESS');
    assert.equal(trace.stage_count, 15);
    assert.equal(trace.stages[0].evidence.authority_kind, 'verified_housekeeper_action');
    assert.equal(trace.stages[1].evidence.kind, 'verified_housekeeper_action');
    assert.ok(['PASS', 'RETAIN_QUARANTINE'].includes(trace.stages[2].status));
    assert.ok(['PASS', 'RETAIN_QUARANTINE'].includes(trace.stages[3].status));
    assert.ok(['PASS', 'EXEMPT'].includes(trace.stages[5].status));
    assert.equal(trace.stages[14].status, 'SUCCESS');

    const action = await readVerifiedEventById(trace.stages[1].evidence.event_id, 'hom');
    const canary = await readVerifiedEventById(trace.stages[2].evidence.event_id, 'hom');
    const security = await readVerifiedEventById(trace.stages[3].evidence.event_id, 'hom');
    assert.equal(action.metadata.schema, 'hom.aimos.canonical-save-action-start/v2');
    assert.equal(action.metadata.action_sha256, trace.action_sha256);
    assert.equal(Buffer.from(action.mutation_hash).toString('hex'), trace.stages[1].evidence.mutation_hash);
    assert.equal(String(canary.parent_event_id), String(action.id));
    assert.equal(String(security.parent_event_id), String(canary.id));
    assert.equal(String(terminal.parent_event_id), String(security.id));
  }

  const quarantinedTerminal = terminals
    .map((row) => row.metadata)
    .find((metadata) => metadata.stages?.[2]?.status === 'RETAIN_QUARANTINE');
  assert.ok(quarantinedTerminal);
  assert.equal(quarantinedTerminal.stages[3].status, 'RETAIN_QUARANTINE');
});

test.after(async () => {
  await Promise.allSettled([pool.end(), agentPool.end()]);
});
