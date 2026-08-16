import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MNEMIS_CONSTANTS,
  MNEMIS_GUARDRAILS,
  bm25ScoresMnemis,
  buildMnemisBaseGraph,
  buildMnemisHierarchy,
  cosineSimilarityMnemis,
  mnemisGlobalSelection,
  mnemisScores,
  mnemisSystem1,
  mnemisSystem1EpisodeEvidence,
  reciprocalRankFusionMnemis,
} from '../../services/retrieval/mnemis-dual-route-graph.js';

function fixtureStates() {
  return [
    {
      id: 'a',
      text: 'Alice joined Project Quasar in Rome after a security review.',
      memory: { created_at: '2026-05-01T00:00:00Z' },
      embedding: [1, 0, 0],
    },
    {
      id: 'b',
      text: 'Alice prefers Alpine skiing and booked a mountain hotel.',
      memory: { created_at: '2026-05-02T00:00:00Z' },
      embedding: [0.8, 0.2, 0],
    },
    {
      id: 'c',
      text: 'Caroline visited Berlin for an art exhibition.',
      memory: { created_at: '2026-05-03T00:00:00Z' },
      embedding: [0, 0, 1],
    },
  ];
}

test('base graph is deterministic, immutable, malformed-safe, and represents all four object classes', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = buildMnemisBaseGraph(states);
  const second = buildMnemisBaseGraph(states);

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.equal(first.episodes.length, 3);
  assert.ok(first.entities.length > 0);
  assert.ok(first.edges.length > 0);
  assert.ok(first.episodic_edges.length > 0);
  assert.ok(first.episodes.every((episode) => episode.valid_at?.startsWith('2026-05-')));
  assert.ok(first.edges.every((edge) => edge.source_entity_id && edge.target_entity_id && Array.isArray(edge.episode_idx)));
  assert.ok(first.episodic_edges.every((edge) => edge.entity_id && edge.episode_id));
  assert.deepEqual(buildMnemisBaseGraph(null), { episodes: [], entities: [], edges: [], episodic_edges: [] });
  assert.equal(buildMnemisBaseGraph([null, {}, { id: '', text: 'bad' }, { id: 'x', text: 'valid' }, { id: 'x', text: 'duplicate' }]).episodes.length, 1);
});

test('base graph caps the admitted transient candidate window', () => {
  const states = Array.from({ length: MNEMIS_CONSTANTS.max_states + 9 }, (_, index) => ({
    id: `state-${index}`,
    text: `Distinct memory candidate ${index}`,
  }));
  assert.equal(buildMnemisBaseGraph(states).episodes.length, MNEMIS_CONSTANTS.max_states);
});

test('cosine is exact over supplied finite vectors and rejects malformed dimensions', () => {
  assert.equal(cosineSimilarityMnemis([1, 0], [1, 0]), 1);
  assert.equal(cosineSimilarityMnemis([1, 0], [0, 1]), 0);
  assert.equal(cosineSimilarityMnemis([1, 0], [-1, 0]), -1);
  assert.equal(cosineSimilarityMnemis([1], [1, 0]), 0);
  assert.equal(cosineSimilarityMnemis(null, [1]), 0);
});

test('BM25 uses corpus document frequency and length normalization', () => {
  const scores = bm25ScoresMnemis('rare', [
    { id: 'rare', text: 'rare rare evidence' },
    { id: 'common-a', text: 'common evidence' },
    { id: 'common-b', text: 'common record' },
  ]);
  assert.ok(scores.get('rare') > 0);
  assert.equal(scores.get('common-a'), 0);
  assert.equal(scores.get('common-b'), 0);
  assert.deepEqual(bm25ScoresMnemis('', [{ id: 'a', text: 'text' }]), new Map());
});

test('RRF implements the rank equation exactly and remains object-class separated in System-1', () => {
  const fused = reciprocalRankFusionMnemis([
    [{ id: 'a' }, { id: 'b' }],
    [{ id: 'b' }, { id: 'a' }],
  ], 60);
  assert.equal(fused[0].score, (1 / 61) + (1 / 62));
  assert.equal(fused[1].score, (1 / 61) + (1 / 62));
  assert.deepEqual(fused.map((row) => row.id), ['a', 'b']);

  const graph = buildMnemisBaseGraph(fixtureStates());
  const system1 = mnemisSystem1(graph, 'Alice Quasar', [1, 0, 0]);
  assert.ok(system1.episode_ranks.every((row) => row.id.startsWith('episode:')));
  assert.ok(system1.entity_ranks.every((row) => row.id.startsWith('entity:')));
  assert.ok(system1.edge_ranks.every((row) => row.id.startsWith('edge:')));
  assert.ok(system1.rank_sources.episodes.embedding > 0);
  assert.ok(system1.rank_sources.episodes.bm25 > 0);

  const episodeEvidence = mnemisSystem1EpisodeEvidence(
    graph,
    'Alice Quasar',
    [1, 0, 0],
  );
  assert.ok(episodeEvidence.ranks.length > 0);
  assert.ok(episodeEvidence.ranks.every((row) => row.id.startsWith('episode:')));
  assert.ok(episodeEvidence.ranks.every((row) => row.normalized_score > 0 && row.normalized_score <= 1));
  assert.equal(
    episodeEvidence.object_rank_count,
    system1.episode_ranks.length + system1.entity_ranks.length + system1.edge_ranks.length,
  );
});

test('hierarchy is multi-level, many-to-many, progressively non-expanding, and edge-complete', () => {
  const hierarchy = buildMnemisHierarchy(buildMnemisBaseGraph(fixtureStates()));
  assert.ok(hierarchy.levels.length >= 3);
  for (let index = 2; index < hierarchy.levels.length; index += 1) {
    assert.ok(hierarchy.levels[index].nodes.length <= hierarchy.levels[index - 1].nodes.length);
  }
  const childIds = new Set(hierarchy.category_edges.map((edge) => edge.child_id));
  assert.ok(hierarchy.categories.every((category) => category.child_ids.every((id) => childIds.has(id))));
  const entityParentCounts = new Map();
  for (const edge of hierarchy.category_edges.filter((row) => row.child_layer === 0)) {
    entityParentCounts.set(edge.child_id, (entityParentCounts.get(edge.child_id) || 0) + 1);
  }
  assert.ok([...entityParentCounts.values()].some((count) => count > 1));
  assert.ok(hierarchy.categories.every((category) => typeof category.standalone === 'boolean'));
});

test('deterministic System-2 rejects zero-relevance branches and returns an unordered set', () => {
  const graph = {
    episodes: [
      { id: 'episode:s', state_id: 's', text: 'encryption credential security', categories: ['security'] },
      { id: 'episode:t', state_id: 't', text: 'airport hotel travel', categories: ['travel'] },
    ],
    entities: [
      { id: 'entity:security', name: 'security', summary: 'encryption credential', tags: ['security'], episode_idx: ['episode:s'] },
      { id: 'entity:travel', name: 'travel', summary: 'airport hotel', tags: ['travel'], episode_idx: ['episode:t'] },
    ],
    edges: [],
    episodic_edges: [],
  };
  const selected = mnemisGlobalSelection(graph, 'credential encryption');
  assert.equal(selected.ordering, 'unordered_set');
  assert.ok(selected.selected_episode_ids.includes('episode:s'));
  assert.ok(!selected.selected_episode_ids.includes('episode:t'));
  assert.ok(selected.selected_categories.every((category) => category.relevance > 0));
  assert.equal(mnemisGlobalSelection(graph, 'completely unrelated').selected_categories.length, 0);
});

test('service output is deterministic, bounded, candidate-window-only, and honest about absent model stages', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = mnemisScores({ queryText: 'Alice Quasar security', queryEmbedding: [1, 0, 0], states });
  const second = mnemisScores({ queryText: 'Alice Quasar security', queryEmbedding: [1, 0, 0], states });

  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.ok([...first.scoreById.values()].every((score) => Number.isFinite(score) && score >= 0 && score <= 1));
  assert.ok([...first.diagnosticsById.values()].every((row) => row.system2_is_unordered === true));
  assert.equal(first.guardrails.candidate_window_only, true);
  assert.equal(first.guardrails.uses_model_policy, false);
  assert.match(first.formula, /System2 remains an unordered selected set/);
  assert.equal(first.unimplemented_paper_components.length, 4);
  assert.equal(mnemisScores({ states: null }).graph_stats.episodes, 0);
});

test('System-2 is not smuggled into the ranked diagnostic and no outside memory can be invented', () => {
  const result = mnemisScores({
    queryText: 'airport travel',
    states: [
      { id: 'inside', text: 'Airport travel record.' },
      { id: 'other', text: 'Unrelated database record.' },
    ],
  });
  assert.deepEqual([...result.scoreById.keys()], ['inside', 'other']);
  assert.equal(result.scoreById.has('outside'), false);
  assert.equal(result.diagnosticsById.get('inside').selected_by_system2, true);
  assert.match(result.formula, /normalized episode-evidence RRF/);
});

test('source contains no database, network, server, persistence, environment, or model authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/mnemis-dual-route-graph.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /Native Mnemis dual-route hierarchical-graph recall operator/);
  assert.equal(MNEMIS_GUARDRAILS.dormant, true);
  assert.equal(MNEMIS_GUARDRAILS.uses_environment_authority, false);
  assert.equal(MNEMIS_GUARDRAILS.accesses_database, false);
  assert.equal(MNEMIS_GUARDRAILS.persists_graph, false);
  assert.equal(MNEMIS_GUARDRAILS.mutates_canonical_memory, false);
});
