import assert from 'node:assert/strict';
import test from 'node:test';

import {
  NATIVE_RETRIEVAL_FUSION_CONTRACT,
  fuseNativeRetrievalGears,
} from '../../services/retrieval/native-retrieval-fusion.js';

const proof = Object.freeze({ version_status: 'current' });
const memory = (id, fields = {}) => ({ id, provenance_proof: proof, ...fields });

test('central native RRF treats MAGMA as one peer gear and preserves every admitted baseline', () => {
  const baseline = [
    memory('a', { raw_distance: 0.1, bm25_rank: 0.1, rerank_score: 0.4 }),
    memory('b', { raw_distance: 0.4, bm25_rank: 0.9, rerank_score: 0.8 }),
    memory('c', { raw_distance: 0.2, ppr_score: 0.8, created_at: '2026-01-02T00:00:00Z' }),
  ];
  const magma = {
    ranks: [
      { id: 'd', rank: 1, score: 9 },
      { id: 'c', rank: 2, score: 8 },
      { id: 'a', rank: 3, score: 7 },
    ],
    discovered_memories: [memory('d', { magma_score: 9 })],
  };

  const first = fuseNativeRetrievalGears({
    admittedMemories: baseline,
    magmaGear: magma,
    temporalBias: true,
  });
  const second = fuseNativeRetrievalGears({
    admittedMemories: baseline,
    magmaGear: magma,
    temporalBias: true,
  });

  assert.deepEqual(first, second);
  assert.deepEqual(new Set(first.memories.map((row) => row.id)), new Set(['a', 'b', 'c', 'd']));
  assert.equal(first.decision.baseline_candidate_set_preserved, true);
  assert.equal(first.decision.candidate_set_monotone, true);
  assert.equal(first.decision.magma_discovery_count, 1);
  assert.equal(first.decision.channels.some((channel) => channel.gear === 'magma'), true);
  assert.equal(first.decision.channels.some((channel) => channel.gear === 'temporal'), true);
  assert.equal(first.memories.every((row) => row.provenance_proof === proof), true);
  assert.match(first.decision.decision_sha256, /^[0-9a-f]{64}$/);
});

test('central native RRF rejects unadmitted discoveries and never needs MAGMA activation state', () => {
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('magma'), true);
  assert.equal(NATIVE_RETRIEVAL_FUSION_CONTRACT.gears.includes('temporal'), true);
  assert.equal(Object.hasOwn(NATIVE_RETRIEVAL_FUSION_CONTRACT, 'execution'), false);
  assert.throws(
    () => fuseNativeRetrievalGears({
      admittedMemories: [memory('a', { raw_distance: 0.1 })],
      magmaGear: {
        ranks: [{ id: 'b', rank: 1, score: 1 }],
        discovered_memories: [{ id: 'b' }],
      },
    }),
    /native_retrieval_fusion:unadmitted_magma_discovery/,
  );
});

test('central native RRF closes an empty admitted population deterministically', () => {
  const result = fuseNativeRetrievalGears({ admittedMemories: [] });
  assert.deepEqual(result.memories, []);
  assert.equal(result.decision.baseline_count, 0);
  assert.equal(result.decision.fused_count, 0);
  assert.equal(result.decision.baseline_candidate_set_preserved, true);
});

test('native gear channels do not convert absent or zero evidence into votes', () => {
  const result = fuseNativeRetrievalGears({
    admittedMemories: [
      memory('plain'),
      memory('zero', { bm25_rank: 0, rerank_score: 0, entity_hits: 0, ppr_score: 0 }),
      memory('qmd', { retrieval_source: 'qmd_fts', rerank_score: 0.7 }),
      memory('hyde', { retrieval_source: 'multi_stage_hyde', rerank_score: 0.6 }),
      memory('quim', { retrieval_source: 'quim_lookup', rerank_score: 0.5 }),
    ],
  });
  const channels = Object.fromEntries(result.decision.channels.map((channel) => [channel.gear, channel]));

  assert.equal(channels.bm25, undefined);
  assert.equal(channels.lexical, undefined);
  assert.equal(channels.entity, undefined);
  assert.equal(channels.concept_ppr, undefined);
  assert.equal(channels.qmd.count, 1);
  assert.equal(channels.hyde.count, 1);
  assert.equal(channels.quim.count, 1);
  assert.deepEqual(result.memories.find((row) => row.id === 'plain').native_fusion_gears, []);
  assert.deepEqual(result.memories.find((row) => row.id === 'zero').native_fusion_gears, []);
});
