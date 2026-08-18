import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MULTI_STAGE_RETRIEVAL_CONTRACT,
  getScaleAdaptiveRRFWeights,
  multiStageRecall,
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
  const result = { memories: [{
    id: '11111111-1111-4111-8111-111111111111',
    recall_confidence: 0.8,
    memory_type: 'declarative',
    provenance_proof: {
      live_content_hash: 'b'.repeat(64),
      save_mutation_hash: 'c'.repeat(64),
      binding_mutation_hash: 'd'.repeat(64),
    },
  }] };
  const calibrationMutationHash = 'a'.repeat(64);
  cache.set([1, 0], 'same query', result, { companyId: 'a', agentId: 'one', clearanceLevel: 3, calibrationMutationHash });
  cache.set([1, 0], 'same query', result, { companyId: 'a', agentId: 'two', clearanceLevel: 3, calibrationMutationHash });
  assert.equal(cache._cache.size, 2);
  assert.ok([...cache._cache.values()].every((entry) => entry.namespace));
  assert.ok([...cache._cache.values()].every((entry) => entry.result.state_reference_count === 1));
  assert.ok([...cache._cache.values()].every((entry) => !Object.hasOwn(entry.result, 'memories')));
  const lowerClearanceKey = `${cache._namespace({ companyId: 'a', agentId: 'one', clearanceLevel: 2, calibrationMutationHash })}\u0000same query`;
  assert.equal(cache._cache.has(lowerClearanceKey), false);

  const retrievalSource = readFileSync(new URL('../../services/retrieval/multi-stage-retrieval.js', import.meta.url), 'utf8');
  assert.doesNotMatch(retrievalSource, /temporalDecay|TEMPORAL_GAMMA|S_TXT_MIN|S_VEC_MIN/);
});

test('R5E multi-stage rescue admits before scoring and binds every SQL proposal to request scope', async () => {
  const order = [];
  const rows = [
    { id: 'blocked', key: 'blocked', value: 'blocked evidence', scope: 'global', memory_type: 'fact', clearance_level: 5, data_class: 'confidential', source: 'fixture', retrieval_weight: 1, similarity: 0.99, bm25_score: 1 },
    { id: 'allowed-a', key: 'allowed-a', value: 'alpha evidence', scope: 'global', memory_type: 'fact', clearance_level: 5, data_class: 'confidential', source: 'fixture', retrieval_weight: 1, similarity: 0.98, bm25_score: 0.9 },
    { id: 'allowed-b', key: 'allowed-b', value: 'beta evidence', scope: 'global', memory_type: 'fact', clearance_level: 5, data_class: 'confidential', source: 'fixture', retrieval_weight: 1, similarity: 0.97, bm25_score: 0.8 },
  ];
  const sqlCalls = [];
  const queryFn = async (sql, params) => {
    sqlCalls.push({ sql, params });
    if (sql.includes('SELECT DISTINCT value')) {
      order.push('interaction');
      return { rows: [] };
    }
    if (sql.includes('embedding <=>')) {
      order.push('dense');
      return { rows };
    }
    order.push('sparse');
    return { rows };
  };
  const admitEvidenceFn = async (proposals) => {
    order.push('admit');
    return {
      memories: proposals
        .filter((row) => row.id !== 'blocked')
        .map((row) => ({ ...row, provenance_proof: { version_status: 'current' } })),
    };
  };
  const embeddingPrompts = [];
  const result = await multiStageRecall('alpha beta', {
    limit: 5,
    minConfidence: 0,
    companyId: 'hom',
    clearanceLevel: 10,
    requestingAgent: 'codex-auditor',
    allowedDataClasses: ['public', 'internal', 'confidential'],
    sourceFilter: 'fixture',
    sessionLikePattern: 'sess:fixed:%',
    queryFn,
    admitEvidenceFn,
    embeddingFn: async (text) => {
      embeddingPrompts.push(text);
      return [1, 0];
    },
    memoryCountFn: async () => 10_000,
  });
  assert.equal(result.some((row) => row.id === 'blocked'), false);
  assert.deepEqual(new Set(result.map((row) => row.id)), new Set(['allowed-a', 'allowed-b']));
  assert.deepEqual(order.slice(0, 3), ['dense', 'sparse', 'admit']);
  assert.ok(order.lastIndexOf('admit') < order.indexOf('interaction'));
  assert.equal(embeddingPrompts.length, 2);
  assert.match(embeddingPrompts[1], /^A document that answers this question would say:/);
  assert.equal(MULTI_STAGE_RETRIEVAL_CONTRACT.full_hyde_paper_implementation, false);
  assert.equal(result.every((row) => row.hyde_adaptation === MULTI_STAGE_RETRIEVAL_CONTRACT.hyde_implementation), true);
  assert.equal(result.every((row) => row.hypothetical_expansion_used === true), true);
  for (const call of sqlCalls.filter((entry) => !entry.sql.includes('SELECT DISTINCT value'))) {
    assert.match(call.sql, /agent_id = \$4/);
    assert.match(call.sql, /data_class, 'public'\) = ANY\(\$5::text\[\]\)/);
    assert.match(call.sql, /source = \$6/);
    assert.match(call.sql, /key LIKE \$7 ESCAPE/);
  }
});

test('R5E rank fusion retains bounded dense evidence without a corpus-invalid absolute cosine floor', () => {
  const result = reciprocalRankFusion(
    [{ id: 'relative-top', dense_rank: 1, similarity: 0.31 }],
    [],
    60,
    [],
    { memoryCount: 10_000 },
  );
  assert.equal(result.length, 1);
  assert.equal(result[0].id, 'relative-top');
  assert.ok(result[0].rrf_score > 0);
});
