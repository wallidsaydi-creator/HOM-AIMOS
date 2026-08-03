import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  getScaleAdaptiveRRFWeights,
  reciprocalRankFusion
} from '../../services/retrieval/multi-stage-retrieval.js';
import {
  getEarlyExitThreshold,
  shouldEarlyExit
} from '../../services/retrieval/adaptive-early-exit.js';
import { normalizeConfidence } from '../../services/retrieval/recall-output-calibrator.js';
import { SemanticCache } from '../../services/caching/semantic-cache.js';

test('normalized RRF is live, scale-adaptive, and sparse-rank based', () => {
  for (const n of [100, 10_000, 1_000_000]) {
    const weights = getScaleAdaptiveRRFWeights(n);
    assert.ok(Math.abs(weights.W_VEC + weights.W_TXT + weights.W_INFINI - 1) < 1e-12);
  }

  const rank1 = reciprocalRankFusion(
    [{ id: 'dense-1', dense_rank: 1, similarity: 0.95 }],
    [],
    60,
    [],
    { memoryCount: 10_000 }
  );
  assert.equal(rank1.length, 1);
  assert.ok(rank1[0].rrf_score >= 0.3);
  assert.ok(rank1[0].rrf_raw_score > 0);

  const straggler = reciprocalRankFusion(
    [{ id: 'dense-200', dense_rank: 200, similarity: 0.95 }],
    [],
    60,
    [],
    { memoryCount: 10_000 }
  );
  assert.ok(straggler[0].rrf_score < 0.3);

  const sparseExact = reciprocalRankFusion(
    [],
    [{ id: 'sparse-1', sparse_rank: 1, bm25_score: 0.01 }],
    60,
    [],
    { memoryCount: 10_000 }
  );
  assert.equal(sparseExact.length, 1, 'top-ranked lexical evidence must not be killed by an absolute BM25 floor');
  assert.ok(sparseExact[0].rrf_score >= 0.3);
});

test('early exit uses bounded score-domain thresholds and blocks bronze lock-in', () => {
  assert.equal(shouldEarlyExit([0.83, 0.67, 0.66, 0.65, 0.64], 0.5, { top1_medallion: 'bronze' }), false);
  assert.equal(shouldEarlyExit([0.83, 0.67, 0.66, 0.65, 0.64], 0.5, { top1_medallion: 'silver' }), true);
  assert.equal(shouldEarlyExit([0.90, 0.89, 0.88, 0.87, 0.86], 0.2, { top1_medallion: 'silver' }), false);
  assert.ok(getEarlyExitThreshold(10_000_000) <= 0.98);
});

test('confidence parsing ignores object wrappers and cache namespaces bind ACL', async () => {
  assert.equal(normalizeConfidence({ confidence: { label: 'high' }, recall_confidence: 0.83 }), 0.83);

  const cache = new SemanticCache({ maxSize: 10 });
  const result = { memories: [{ id: 'm1', recall_confidence: 0.8, memory_type: 'declarative' }] };
  const calibrationMutationHash = 'a'.repeat(64);
  cache.set([1, 0], 'same query', result, { companyId: 'a', agentId: 'one', clearanceLevel: 3, calibrationMutationHash });
  cache.set([1, 0], 'same query', result, { companyId: 'a', agentId: 'two', clearanceLevel: 3, calibrationMutationHash });
  assert.equal(cache._cache.size, 2);
  assert.ok([...cache._cache.values()].every((entry) => entry.namespace));
  const lowerClearanceKey = `${cache._namespace({ companyId: 'a', agentId: 'one', clearanceLevel: 2, calibrationMutationHash })}\u0000same query`;
  assert.equal(cache._cache.has(lowerClearanceKey), false);

  const retrievalSource = readFileSync(new URL('../../services/retrieval/multi-stage-retrieval.js', import.meta.url), 'utf8');
  assert.doesNotMatch(retrievalSource, /temporalDecay|TEMPORAL_GAMMA|S_TXT_MIN/);
});
