import assert from 'node:assert/strict';
import test from 'node:test';

import {
  evaluateSalienceFrequencyBatch,
  SALIENCE_FREQUENCY_ALADDIN_CONTRACT,
} from '../../services/temporal/dormancy-manager.js';

const MEMORY = '11111111-1111-4111-8111-111111111111';

test('salience diagnostic consumes only request-scoped verified graph counts', async () => {
  let sql = '';
  const results = await evaluateSalienceFrequencyBatch([MEMORY], 'hom', {
    memoryCount: 10_000,
    nowMs: Date.parse('2026-08-31T12:00:00.000Z'),
    verifiedCrossRefCounts: new Map([[MEMORY, 8]]),
    queryFn: async (text) => {
      sql = text;
      return { rows: [{
        id: MEMORY,
        key: 'verified:graph:test',
        credit_score: 0,
        supersedes_id: null,
        created_at: '2026-08-31T11:00:00.000Z',
        recall_count: 0,
        last_recall_at: null,
      }] };
    },
  });
  assert.doesNotMatch(sql, /memory_cross_refs/);
  assert.equal(
    SALIENCE_FREQUENCY_ALADDIN_CONTRACT.metric_sources.cross_refs,
    'request-scoped cryptographically verified recall graph links',
  );
  assert.equal(results.get(MEMORY).components.cross_refs > 0, true);
  assert.equal(
    results.get(MEMORY).metricSources.active_cross_ref_source,
    'verified_request_graph_link_count',
  );
});
