import assert from 'node:assert/strict';
import test from 'node:test';

import { agentPool, pool } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { verifyCanonicalSaveTrace } from '../../services/write/canonical-save-contract.js';
import {
  createCanonicalSaveOwner,
  createHousekeeperCanonicalSaveOwner,
  executeHousekeeperCanonicalSave,
} from '../../services/write/canonical-save-owner.js';
import { persistMemory } from '../../services/write/persist-memory.js';

if (!process.argv.includes('--live-fire')) {
  throw new Error('canonical-save-owner-db.test.mjs requires --live-fire and an isolated AIMOS database');
}

const runId = `${Date.now()}`;
const prefix = `cr4:canonical:${runId}`;

function spec(suffix, overrides = {}) {
  return {
    company_id: 'hom',
    agent_id: 'housekeeper',
    key: `${prefix}:${suffix}`,
    value: `CR4 canonical SAVE ${suffix} evidence with substantive ordered-stage, transaction, and terminal proof.`,
    scope: 'system',
    clearance_level: 5,
    memory_type: 'declarative',
    source: 'test:canonical-save-owner',
    ...overrides,
  };
}

async function memoryCount(key) {
  return Number((await pool.query(
    'SELECT count(*)::int AS n FROM aimos_memories WHERE company_id=$1 AND key=$2',
    ['hom', key],
  )).rows[0].n);
}

async function verifyTerminal(result, expectedOutcome = 'SUCCESS') {
  assert.equal(result.canonical_save_trace.outcome, expectedOutcome);
  assert.equal(verifyCanonicalSaveTrace(result.canonical_save_trace).valid, true);
  assert.ok(result.terminal_receipt?.event_id);
  const event = await readVerifiedEventById(result.terminal_receipt.event_id, 'hom');
  assert.equal(event.operation, 'canonical_save_terminal');
  assert.equal(event.metadata.outcome, expectedOutcome);
  assert.equal(event.metadata.stage_root_sha256, result.canonical_save_trace.stage_root_sha256);
  return event;
}

test('database-local canonical SAVE proves success, quarantine, reject, rollback, retry, and reassertion', async () => {
  const validSpec = spec('valid');
  const valid = await executeHousekeeperCanonicalSave(validSpec);
  assert.ok(valid.id);
  await verifyTerminal(valid);
  assert.equal(await memoryCount(validSpec.key), 1);
  assert.ok(valid.live_content_hash);
  assert.ok(valid.ledger_commit?.mutationHash);
  assert.ok(valid.binding_commit?.mutationHash);
  assert.ok(valid.epistemic_classification_event_id);
  assert.ok(['NO_OP', 'COMMITTED'].includes(valid.lineage_disposition.status));
  assert.ok(['NO_OP', 'COMMITTED'].includes(valid.graph_disposition.status));

  const quarantineSpec = spec('quarantine', {
    value: 'CR4 retained quarantine proof includes explicit marker SECRET-DEADBEEF and remains substantive evidence.',
  });
  const quarantined = await executeHousekeeperCanonicalSave(quarantineSpec);
  assert.equal(quarantined.quarantined, true);
  assert.equal(quarantined.canonical_save_trace.stages[2].status, 'RETAIN_QUARANTINE');
  assert.equal(quarantined.canonical_save_trace.stages[12].status, 'QUARANTINE_SKIPPED');
  await verifyTerminal(quarantined);
  const quarantinedRow = await pool.query(
    'SELECT retrieval_weight,scope,memory_type FROM aimos_memories WHERE id=$1',
    [quarantined.id],
  );
  assert.equal(Number(quarantinedRow.rows[0].retrieval_weight), 1);
  assert.ok(quarantinedRow.rows[0].scope === 'quarantine' || quarantinedRow.rows[0].memory_type === 'quarantine');

  const rejectedSpec = spec('rejected', { value: 'ok' });
  const rejected = await executeHousekeeperCanonicalSave(rejectedSpec);
  assert.equal(rejected.rejected, true);
  assert.equal(rejected.canonical_save_trace.outcome, 'REJECTED');
  await verifyTerminal(rejected, 'REJECTED');
  assert.equal(await memoryCount(rejectedSpec.key), 0);

  const rollbackSpec = spec('rollback');
  const faultOwner = createCanonicalSaveOwner({
    persistMemory: async (input) => {
      await persistMemory(input);
      throw Object.assign(new Error('cr4_fault_after_persistence'), { code: 'CR4_FAULT_AFTER_PERSISTENCE' });
    },
  });
  const faultHousekeeperOwner = createHousekeeperCanonicalSaveOwner({
    executeCanonicalSave: faultOwner,
  });
  await assert.rejects(faultHousekeeperOwner(rollbackSpec), (error) => {
    assert.equal(error.code, 'CR4_FAULT_AFTER_PERSISTENCE');
    assert.equal(error.canonicalSaveTrace.outcome, 'FAILED');
    return true;
  });
  assert.equal(await memoryCount(rollbackSpec.key), 0);

  const retry = await executeHousekeeperCanonicalSave(rollbackSpec);
  await verifyTerminal(retry);
  assert.equal(await memoryCount(rollbackSpec.key), 1);

  const reassert = await executeHousekeeperCanonicalSave(validSpec);
  await verifyTerminal(reassert);
  assert.equal(reassert.occurrence_reasserted, true);
  assert.equal(reassert.canonical_save_trace.stages[9].status, 'NO_OP_REASSERT');
  assert.ok(reassert.epistemic_classification_event_id);
  assert.equal(await memoryCount(validSpec.key), 1);
});

test.after(async () => {
  await Promise.allSettled([pool.end(), agentPool.end()]);
});
