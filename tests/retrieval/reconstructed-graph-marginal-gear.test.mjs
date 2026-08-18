import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT,
  fuseBoundedGraphFamily,
} from '../../services/retrieval/reconstructed-graph-additive/graph-family-bounded-fusion.js';
import {
  RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT,
  buildReconstructedGraphMarginalWorkspace,
  composeReconstructedGraphMarginalGear,
  rankReconstructedGraphMarginalWorkspace,
} from '../../services/retrieval/reconstructed-graph-additive/reconstructed-graph-marginal-gear.js';

function digest(char) {
  return char.repeat(64);
}

function admittedStates() {
  return [
    {
      id: 'a', value: 'Alice submitted the Quasar screenplay during spring.',
      content_hash: digest('a'), provenance_proof: { binding_event_mutation_hash: digest('1') }, canary_admitted: true,
    },
    {
      id: 'b', value: 'Quasar received an Orion company review during summer.',
      content_hash: digest('b'), provenance_proof: { binding_event_mutation_hash: digest('2') }, canary_admitted: true,
    },
    {
      id: 'c', value: 'Orion company rejected the screenplay after review.',
      content_hash: digest('c'), provenance_proof: { binding_event_mutation_hash: digest('3') }, canary_admitted: true,
    },
  ];
}

test('marginal gear is deterministic, immutable, and emits only same-set rank evidence', () => {
  const states = admittedStates();
  const before = structuredClone(states);
  const first = composeReconstructedGraphMarginalGear({
    queryText: 'What happened to Alice submission?', admittedMemories: states,
  });
  const second = composeReconstructedGraphMarginalGear({
    queryText: 'What happened to Alice submission?', admittedMemories: states,
  });
  assert.deepEqual(states, before);
  assert.deepEqual(first, second);
  assert.equal(first.discovered_memories.length, 0);
  assert.ok(first.ranks.length > 0);
  assert.ok(first.ranks.every((row) => states.some((state) => state.id === row.id)));
  assert.equal(first.decision.graph_only_discovery_count, 0);
  assert.equal(first.decision.unsupported_edge_ratio, 0);
  assert.equal(first.decision.ungrounded_disclosure_ratio_at_20, 0);
});

test('marginal gear fails closed before graph construction on missing admission evidence', () => {
  const [state] = admittedStates();
  assert.throws(() => composeReconstructedGraphMarginalGear({
    queryText: 'Alice', admittedMemories: [{ ...state, provenance_proof: null }],
  }), /provenance_admission_required/);
  assert.throws(() => composeReconstructedGraphMarginalGear({
    queryText: 'Alice', admittedMemories: [{ ...state, canary_admitted: false }],
  }), /canary_admission_required/);
  assert.throws(() => composeReconstructedGraphMarginalGear({
    queryText: 'Alice', admittedMemories: [{ ...state, content_hash: 'invalid' }],
  }), /content_binding_invalid/);
});

test('marginal workspace and emitted ranks obey scale bounds', () => {
  const states = Array.from({ length: 300 }, (_, index) => ({
    id: `m-${String(index).padStart(3, '0')}`,
    value: `Alice project bridge memory ${index}`,
    content_hash: digest((index % 10).toString()),
    provenance_proof: { binding_event_mutation_hash: digest('a') },
    canary_admitted: true,
  }));
  const result = composeReconstructedGraphMarginalGear({
    queryText: 'Alice project bridge', admittedMemories: states, workspaceLimit: 999, rankLimit: 999,
  });
  assert.equal(result.decision.workspace_population, RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.maximum_workspace_states);
  assert.ok(result.ranks.length <= RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.maximum_emitted_ranks);
  assert.equal(result.diagnostics.workspace_capped, true);
});

test('separate construction and ranking reproduce the composed gear exactly', () => {
  const states = admittedStates();
  const workspace = buildReconstructedGraphMarginalWorkspace({ admittedMemories: states });
  const separated = rankReconstructedGraphMarginalWorkspace({
    queryText: 'What happened to Alice submission?',
    workspace,
  });
  const composed = composeReconstructedGraphMarginalGear({
    queryText: 'What happened to Alice submission?',
    admittedMemories: states,
  });
  assert.deepEqual(separated, composed);
  assert.equal(workspace.decision.canonical_memory_mutated, false);
  assert.equal(workspace.decision.persistence_authority, false);
});

test('one-subgear family reproduces MAGMA rank order exactly', () => {
  const magmaGear = {
    ranks: [
      { id: 'a', rank: 1, score: 0.9 },
      { id: 'b', rank: 2, score: 0.8 },
      { id: 'c', rank: 3, score: 0.7 },
    ],
    discovered_memories: [],
  };
  const family = fuseBoundedGraphFamily({ magmaGear });
  assert.deepEqual(family.ranks.map((row) => row.id), ['a', 'b', 'c']);
  assert.equal(family.decision.outer_channel_count, 1);
  assert.equal(family.decision.subgear_count, 1);
});

test('candidate is an additive subgear but graph family retains one outer vote', () => {
  const magmaGear = { ranks: [{ id: 'a', rank: 1, score: 1 }, { id: 'b', rank: 2, score: 0.9 }] };
  const reconstructed = { ranks: [{ id: 'c', rank: 1, score: 0.8 }, { id: 'b', rank: 2, score: 0.7 }] };
  const family = fuseBoundedGraphFamily({
    magmaGear,
    candidateGears: [{ name: 'reconstructed_graph', gear: reconstructed }],
  });
  assert.equal(family.decision.subgear_count, 2);
  assert.equal(family.decision.outer_channel_count, 1);
  assert.deepEqual(new Set(family.ranks.map((row) => row.id)), new Set(['a', 'b', 'c']));
  assert.equal(family.discovered_memories.length, 0);
});

test('R5F graph-family pooling removes duplicate-state slots before its rank limit', () => {
  const projection = {
    occurrence_view: [
      { company_id: 'hom', memory_id: 'a1', live_content_hash: digest('a') },
      { company_id: 'hom', memory_id: 'a2', live_content_hash: digest('a') },
      { company_id: 'hom', memory_id: 'b1', live_content_hash: digest('b') },
    ],
    decision: { decision_sha256: digest('d') },
  };
  const family = fuseBoundedGraphFamily({
    magmaGear: { ranks: [
      { id: 'a1', rank: 1, score: 1 },
      { id: 'a2', rank: 2, score: 0.9 },
      { id: 'b1', rank: 3, score: 0.8 },
    ] },
    contentStateProjection: projection,
    limit: 2,
  });
  assert.deepEqual(family.ranks.map((row) => row.id), ['a1', 'b1']);
  assert.equal(family.decision.input_occurrence_rank_count, 3);
  assert.equal(family.decision.emitted_state_rank_count, 2);
  assert.equal(family.decision.collapsed_occurrence_rank_count, 1);
  assert.equal(family.decision.content_state_deduplicated, true);
  assert.equal(family.decision.content_state_projection_decision_sha256, digest('d'));
});

test('duplicate graph signal cannot multiply graph-family score', () => {
  const magmaGear = { ranks: [{ id: 'a', rank: 1, score: 1 }, { id: 'b', rank: 2, score: 0.9 }] };
  const reconstructed = { ranks: [{ id: 'c', rank: 1, score: 0.8 }, { id: 'b', rank: 2, score: 0.7 }] };
  const once = fuseBoundedGraphFamily({
    magmaGear,
    candidateGears: [{ name: 'reconstructed_graph', gear: reconstructed }],
  });
  const twice = fuseBoundedGraphFamily({
    magmaGear,
    candidateGears: [
      { name: 'reconstructed_graph_1', gear: reconstructed },
      { name: 'reconstructed_graph_2', gear: reconstructed },
    ],
  });
  assert.deepEqual(
    twice.ranks.map(({ id, score }) => ({ id, score })),
    once.ranks.map(({ id, score }) => ({ id, score })),
  );
  assert.equal(GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.duplicate_signal_idempotent, true);
});

test('candidate cannot smuggle discoveries through the graph-family combiner', () => {
  const candidateMemory = { id: 'x', provenance_proof: { binding_event_mutation_hash: digest('f') } };
  const family = fuseBoundedGraphFamily({
    magmaGear: { ranks: [{ id: 'a', rank: 1, score: 1 }], discovered_memories: [] },
    candidateGears: [{
      name: 'reconstructed_graph',
      gear: { ranks: [{ id: 'x', rank: 1, score: 1 }], discovered_memories: [candidateMemory] },
    }],
  });
  assert.equal(family.discovered_memories.length, 0);
  assert.equal(family.decision.candidate_discovery_count, 0);
});

test('pure reconstructed kernels own no database, network, server, model, ENV, or mutation authority', () => {
  const marginalSource = readFileSync(new URL('../../services/retrieval/reconstructed-graph-additive/reconstructed-graph-marginal-gear.js', import.meta.url), 'utf8');
  const familySource = readFileSync(new URL('../../services/retrieval/reconstructed-graph-additive/graph-family-bounded-fusion.js', import.meta.url), 'utf8');
  for (const source of [marginalSource, familySource]) {
    assert.doesNotMatch(source, /process\.env|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
    assert.doesNotMatch(source, /openai|anthropic|ollama|provider|chatgpt/i);
  }
  assert.equal(RECONSTRUCTED_GRAPH_MARGINAL_GEAR_CONTRACT.runtime_wired, false);
  assert.equal(GRAPH_FAMILY_BOUNDED_FUSION_CONTRACT.runtime_wired, true);
});
