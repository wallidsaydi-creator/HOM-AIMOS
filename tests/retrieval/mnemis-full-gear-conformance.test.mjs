import assert from 'node:assert/strict';
import test from 'node:test';

import { fuseNativeRetrievalGears } from '../../services/retrieval/native-retrieval-fusion.js';
import { fuseBoundedGraphFamily } from '../../services/retrieval/reconstructed-graph-additive/graph-family-bounded-fusion.js';
import { composeMnemisMarginalGear } from '../../services/retrieval/mnemis-marginal-gear.js';

function hash(value) {
  return String(value).padStart(64, '0').slice(-64);
}

function memory(index, overrides = {}) {
  return {
    id: `memory-${index}`,
    value: `Signed retained evidence ${index} links Project Quasar to Rome security review.`,
    embedding: [1, index / 20, 0],
    raw_distance: index / 100,
    content_hash: hash(index + 1),
    provenance_sha256: hash(index + 101),
    provenance_proof: {
      live_content_hash: hash(index + 1),
      binding_event_mutation_hash: hash(index + 101),
    },
    canary_admitted: true,
    created_at: `2026-08-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`,
    ...overrides,
  };
}

function fullGearPopulation() {
  return [
    memory(0, { bm25_score: 9 }),
    memory(1, { rerank_score: 0.91, retrieval_source: 'lexical_rerank' }),
    memory(2, { rerank_score: 0.92, retrieval_source: 'quim_lookup' }),
    memory(3, { rerank_score: 0.93, retrieval_source: 'qmd_expansion' }),
    memory(4, { rerank_score: 0.94, retrieval_source: 'multi_stage_hyde' }),
    memory(5, { entity_hits: 4 }),
    memory(6, { ppr_score: 0.88 }),
    memory(7),
    memory(8),
    memory(9),
  ];
}

function simpleGear(memories, order) {
  return {
    ranks: order.map((index, rank) => ({
      id: memories[index].id,
      rank: rank + 1,
      score: 1 - (rank / 100),
    })),
    discovered_memories: [],
  };
}

test('Mnemis remains one graph-family subgear alongside every native retrieval channel', () => {
  const memories = fullGearPopulation();
  const magma = simpleGear(memories, [7, 6, 5, 4, 3, 2, 1, 0, 8, 9]);
  const g2 = simpleGear(memories, [5, 4, 3, 2, 1, 0, 6, 7, 8, 9]);
  const m2 = composeMnemisMarginalGear({
    admittedMemories: memories,
    queryText: 'Who linked Project Quasar to the Rome security review?',
    queryEmbedding: [1, 0.2, 0],
  });

  const baselineFamily = fuseBoundedGraphFamily({
    magmaGear: magma,
    candidateGears: [{ name: 'reconstructed_graph', gear: g2 }],
  });
  const candidateFamily = fuseBoundedGraphFamily({
    magmaGear: magma,
    candidateGears: [
      { name: 'reconstructed_graph', gear: g2 },
      { name: 'mnemis', gear: m2 },
    ],
  });
  const baseline = fuseNativeRetrievalGears({
    admittedMemories: memories,
    magmaGear: baselineFamily,
    temporalBias: true,
  });
  const candidate = fuseNativeRetrievalGears({
    admittedMemories: memories,
    magmaGear: candidateFamily,
    temporalBias: true,
  });
  const expectedChannels = [
    'vector',
    'bm25',
    'lexical',
    'quim',
    'qmd',
    'hyde',
    'entity',
    'concept_ppr',
    'graph_family',
    'temporal',
  ].sort();

  assert.deepEqual(
    baseline.decision.channels.map((channel) => channel.gear).sort(),
    expectedChannels,
  );
  assert.deepEqual(
    candidate.decision.channels.map((channel) => channel.gear).sort(),
    expectedChannels,
  );
  assert.deepEqual(
    baseline.decision.channels
      .filter((channel) => channel.gear !== 'graph_family'),
    candidate.decision.channels
      .filter((channel) => channel.gear !== 'graph_family'),
  );
  assert.equal(baselineFamily.decision.outer_channel_count, 1);
  assert.equal(candidateFamily.decision.outer_channel_count, 1);
  assert.equal(candidateFamily.decision.subgear_count, 3);
  assert.deepEqual(
    baseline.memories.map((row) => row.id).sort(),
    candidate.memories.map((row) => row.id).sort(),
  );
  assert.equal(candidate.decision.baseline_candidate_set_preserved, true);
  assert.equal(candidate.decision.candidate_set_monotone, true);
});

test('duplicating Mnemis cannot multiply graph-family voting mass', () => {
  const memories = fullGearPopulation();
  const magma = simpleGear(memories, [7, 6, 5, 4, 3, 2, 1, 0, 8, 9]);
  const g2 = simpleGear(memories, [5, 4, 3, 2, 1, 0, 6, 7, 8, 9]);
  const m2 = composeMnemisMarginalGear({
    admittedMemories: memories,
    queryText: 'Project Quasar Rome security review',
    queryEmbedding: [1, 0.2, 0],
  });
  const once = fuseBoundedGraphFamily({
    magmaGear: magma,
    candidateGears: [
      { name: 'reconstructed_graph', gear: g2 },
      { name: 'mnemis', gear: m2 },
    ],
  });
  const twice = fuseBoundedGraphFamily({
    magmaGear: magma,
    candidateGears: [
      { name: 'reconstructed_graph', gear: g2 },
      { name: 'mnemis_a', gear: m2 },
      { name: 'mnemis_b', gear: m2 },
    ],
  });

  assert.deepEqual(
    once.ranks.map(({ id, score }) => ({ id, score })),
    twice.ranks.map(({ id, score }) => ({ id, score })),
  );
});
