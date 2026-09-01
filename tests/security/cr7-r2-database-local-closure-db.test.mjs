import assert from 'node:assert/strict';
import test from 'node:test';

import { agentPool, pool } from '../../db/connection.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';
import { createCanonicalSaveOwner, createHousekeeperCanonicalSaveOwner, executeHousekeeperCanonicalSave } from '../../services/write/canonical-save-owner.js';
import { buildEntityEdgeProjection, persistMemory } from '../../services/write/persist-memory.js';

if (!process.argv.includes('--live-fire')) {
  throw new Error('cr7-r2-database-local-closure-db.test.mjs requires --live-fire and an isolated AIMOS database');
}

const runId = `${Date.now()}`;
const source = 'test:cr7-r2-database-local-closure';

function spec(suffix) {
  return {
    company_id: 'hom',
    agent_id: 'housekeeper',
    key: `cr7:r2:${runId}:${suffix}`,
    value: `Rome Platform and Codex Memory retain exact CR7 ${suffix} relational evidence with cryptographic traceability.`,
    scope: 'system',
    clearance_level: 5,
    memory_type: 'declarative',
    source,
  };
}

async function verifyEntityProjection(result) {
  assert.equal(result.graph_disposition.status, 'COMMITTED');
  assert.ok(result.graph_disposition.entity_edges_committed > 0);
  assert.ok(result.graph_disposition.entity_edge_authority_event_id);
  assert.match(result.graph_disposition.entity_edge_projection_root_sha256, /^[0-9a-f]{64}$/);
  const rows = (await pool.query(
    `SELECT id, company_id, entity, entity_type, memory_id::text
       FROM entity_memory_edges
      WHERE company_id=$1 AND memory_id=$2::uuid
      ORDER BY id`,
    ['hom', result.id],
  )).rows;
  const projection = buildEntityEdgeProjection(rows);
  assert.equal(projection.projection_root_sha256, result.graph_disposition.entity_edge_projection_root_sha256);
  assert.deepEqual(projection.records.map((record) => record.row_id), result.graph_disposition.entity_edge_row_ids);
  const event = await readVerifiedEventById(result.graph_disposition.entity_edge_authority_event_id, 'hom');
  assert.equal(event.operation, 'memory_entity_edges_committed');
  assert.equal(event.metadata.projection_root_sha256, projection.projection_root_sha256);
  assert.deepEqual(event.metadata.records, projection.records);
  assert.equal(event.metadata.row_count, rows.length);
}

test('R2 entity edges and exact signed projection roll back and commit as one material action', async () => {
  const rollbackSpec = spec('rollback');
  const faultOwner = createCanonicalSaveOwner({
    persistMemory: async (input) => {
      await persistMemory(input);
      throw Object.assign(new Error('cr7_r2_fault_after_entity_projection'), { code: 'CR7_R2_FAULT' });
    },
  });
  const faultHousekeeper = createHousekeeperCanonicalSaveOwner({ executeCanonicalSave: faultOwner });
  await assert.rejects(faultHousekeeper(rollbackSpec), /cr7_r2_fault_after_entity_projection/);
  const rolledBack = await pool.query(
    `SELECT
       (SELECT count(*)::int FROM aimos_memories WHERE company_id=$1 AND key=$2) AS memories,
       (SELECT count(*)::int FROM aimos_events WHERE company_id=$1 AND operation='memory_entity_edges_committed' AND key=$2) AS events`,
    ['hom', rollbackSpec.key],
  );
  assert.deepEqual(rolledBack.rows[0], { memories: 0, events: 0 });

  const committed = await executeHousekeeperCanonicalSave(spec('commit'));
  await verifyEntityProjection(committed);
});

test('restricted runtime role cannot resurrect disabled or offline administrative writers', async () => {
  for (const statement of [
    'INSERT INTO concept_edges DEFAULT VALUES',
    'INSERT INTO aimos_governor_config DEFAULT VALUES',
    'INSERT INTO aimos_system_config DEFAULT VALUES',
    'INSERT INTO aimos_recall_authorization_events DEFAULT VALUES',
  ]) {
    await assert.rejects(agentPool.query(statement), (error) => error?.code === '42501');
  }
});

test.after(async () => {
  await Promise.allSettled([pool.end(), agentPool.end()]);
});
