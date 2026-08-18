import assert from 'node:assert/strict';
import test from 'node:test';

import {
  RECALL_GRAPH_LINK_BATCH_CONTRACT,
  readBatchedRecallGraphLinks,
} from '../../services/retrieval/native-recall-pipeline.js';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

test('R5H-S0 graph-link annotation uses one bounded multi-seed query', async () => {
  const calls = [];
  const result = await readBatchedRecallGraphLinks({
    companyId: 'hom',
    seedMemoryIds: [A, B],
    maxHops: 4,
    queryFn: async (text, params) => {
      calls.push({ text, params });
      return { rows: [
        { root_memory_id: A, memory_id: C, similarity: 0.9, hop: 1 },
        { root_memory_id: B, memory_id: C, similarity: 0.8, hop: 2 },
      ] };
    },
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0].text, /unnest\(\$2::uuid\[\]\)/);
  assert.match(calls[0].text, /CROSS JOIN LATERAL/);
  assert.match(calls[0].text, /NOT edge\.target_memory_id = ANY\(gw\.path_ids\)/);
  assert.match(calls[0].text, /root_rank <= \$5/);
  assert.equal(calls[0].params[2], 2);
  assert.equal(result.decision.database_round_trips, 1);
  assert.equal(result.decision.seed_count, 2);
  assert.equal(result.decision.row_count, 2);
  assert.equal(result.decision.applied_hops, 2);
  assert.deepEqual(result.linksBySeed.get(A), [{ id: C, similarity: 0.9, hop: 1 }]);
  assert.deepEqual(result.linksBySeed.get(B), [{ id: C, similarity: 0.8, hop: 2 }]);
});

test('R5H-S0 graph-link batch fails closed on seed and row bound violations', async () => {
  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom', seedMemoryIds: ['invalid'], maxHops: 1,
      queryFn: async () => ({ rows: [] }),
    }),
    /recall_graph_link_batch_seed_bound_invalid/,
  );
  const tooManyRows = Array.from(
    { length: RECALL_GRAPH_LINK_BATCH_CONTRACT.maximum_links_per_seed + 1 },
    () => ({ root_memory_id: A, memory_id: C, similarity: 1, hop: 1 }),
  );
  await assert.rejects(
    readBatchedRecallGraphLinks({
      companyId: 'hom', seedMemoryIds: [A], maxHops: 1,
      queryFn: async () => ({ rows: tooManyRows }),
    }),
    /recall_graph_link_batch_row_bound_exceeded/,
  );
});
