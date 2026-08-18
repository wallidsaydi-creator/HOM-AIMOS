import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT,
  composeNativeGraphFamilyChannel,
  composeReconstructedGraphNativeCandidate,
} from '../../services/retrieval/reconstructed-graph-native-candidate.js';

function digest(character) {
  return character.repeat(64);
}

function admittedMemories() {
  return [
    {
      id: 'a',
      value: 'Alice submitted the Quasar screenplay during spring.',
      content_hash: digest('a'),
      provenance_proof: { binding_event_mutation_hash: digest('1') },
      canary_admitted: true,
    },
    {
      id: 'b',
      value: 'Quasar received an Orion company review during summer.',
      content_hash: digest('b'),
      provenance_proof: { binding_event_mutation_hash: digest('2') },
      canary_admitted: true,
    },
    {
      id: 'c',
      value: 'Orion company rejected the screenplay after review.',
      content_hash: digest('c'),
      provenance_proof: { binding_event_mutation_hash: digest('3') },
      canary_admitted: true,
    },
  ];
}

test('native adapter emits a bounded same-set G2 signal with explicit runtime custody', () => {
  const memories = admittedMemories();
  const before = structuredClone(memories);
  const result = composeReconstructedGraphNativeCandidate({
    admittedMemories: memories,
    queryText: 'What happened to the Quasar screenplay?',
  });

  assert.deepEqual(memories, before);
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.runtime_wired, true);
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.graph_family_outer_channels, 1);
  assert.match(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.fixed_corpus_proof_file_sha256, /^[a-f0-9]{64}$/);
  assert.ok(result.ranks.length > 0);
  assert.ok(result.ranks.every((rank) => memories.some((memory) => memory.id === rank.id)));
  assert.deepEqual(result.decision.selected_memory_ids, result.ranks.map((rank) => rank.id));
  assert.equal(result.decision.edge_commitment_sha256, result.decision.graph_sha256);
  assert.equal(result.discovered_memories.length, 0);
  assert.ok(result.runtime_breakdown_ms.construction >= 0);
  assert.ok(result.runtime_breakdown_ms.ranking >= 0);
  assert.equal(
    result.runtime_breakdown_ms.total,
    Number((result.runtime_breakdown_ms.construction + result.runtime_breakdown_ms.ranking).toFixed(3)),
  );
});

test('native adapter owns the single bounded graph-family runtime channel', () => {
  const magmaGear = {
    ranks: admittedMemories().map((memory, index) => ({ id: memory.id, rank: index + 1, score: 1 - index * 0.1 })),
    discovered_memories: [],
  };
  const reconstructedGraphGear = composeReconstructedGraphNativeCandidate({
    admittedMemories: admittedMemories(),
    queryText: 'What happened to the Quasar screenplay?',
  });
  const family = composeNativeGraphFamilyChannel({ magmaGear, reconstructedGraphGear });

  assert.equal(family.decision.outer_channel_count, 1);
  assert.equal(family.decision.subgear_count, 2);
  assert.equal(family.decision.duplicate_signal_idempotent, true);
  assert.equal(family.decision.candidate_discovery_count, 0);
});

test('R5G native reconstructed workspace binds a pre-cap content-state selection', () => {
  const decision = {
    unique_candidate_count: 3,
    selected_state_count: 2,
    collapsed_occurrence_count: 1,
    decision_sha256: digest('d'),
  };
  const result = composeReconstructedGraphNativeCandidate({
    admittedMemories: admittedMemories().slice(0, 2),
    queryText: 'Quasar screenplay',
    contentStateSelectionDecision: decision,
    requireContentStateSelection: true,
  });
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.one_workspace_node_per_verified_content_state, true);
  assert.equal(result.decision.content_state_selection_decision_sha256, digest('d'));
  assert.equal(result.decision.content_state_input_occurrence_count, 3);
  assert.equal(result.decision.content_state_selected_state_count, 2);
  assert.equal(result.decision.content_state_workspace_count, 2);
  assert.equal(result.decision.content_state_collapsed_occurrence_count, 1);
  assert.equal(result.decision.one_workspace_node_per_verified_content_state, true);
  assert.throws(() => composeReconstructedGraphNativeCandidate({
    admittedMemories: admittedMemories().slice(0, 2),
    queryText: 'Quasar screenplay',
    requireContentStateSelection: true,
  }), /content_state_selection_required/);
});

test('native adapter rejects any candidate that lacks Canary admission', () => {
  const memories = admittedMemories();
  memories[1] = { ...memories[1], canary_admitted: false };
  assert.throws(() => composeReconstructedGraphNativeCandidate({
    admittedMemories: memories,
    queryText: 'Quasar',
  }), /canary_admission_required/);
});

test('native adapter normalizes live Buffer content and provenance bindings', () => {
  const memories = admittedMemories().map((memory) => ({
    ...memory,
    content_hash: Buffer.from(memory.content_hash, 'hex'),
    provenance_sha256: Buffer.from(memory.provenance_proof.binding_event_mutation_hash, 'hex'),
  }));
  const result = composeReconstructedGraphNativeCandidate({
    admittedMemories: memories,
    queryText: 'What happened to the Quasar screenplay?',
  });
  assert.ok(result.ranks.length > 0);
  assert.ok(result.ranks.every((rank) => /^[a-f0-9]{64}$/.test(rank.content_hash)));
});

test('native adapter bounds only its transient workspace to the proven 40-candidate opening', () => {
  const memories = Array.from({ length: 45 }, (_, index) => ({
    id: `memory-${String(index).padStart(2, '0')}`,
    value: `Evidence record ${index} links the retrieval gearbox to signed provenance.`,
    content_hash: index.toString(16).padStart(64, '0'),
    provenance_sha256: (index + 100).toString(16).padStart(64, '0'),
    provenance_proof: { binding_event_mutation_hash: (index + 100).toString(16).padStart(64, '0') },
    canary_admitted: true,
  }));
  const result = composeReconstructedGraphNativeCandidate({
    admittedMemories: memories,
    queryText: 'signed provenance retrieval gearbox',
  });
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.native_workspace_states, 40);
  assert.equal(result.decision.admitted_population, 40);
  assert.equal(result.decision.content_state_workspace_count, 40);
  assert.equal(result.decision.workspace_population, 40);
  assert.equal(result.diagnostics.workspace_capped, true);
});

test('native adapter owns no database, network, model, ENV, persistence, or mutation authority', () => {
  const source = readFileSync(
    new URL('../../services/retrieval/reconstructed-graph-native-candidate.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /process\.env|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /openai|anthropic|ollama|provider|chatgpt/i);
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.persistence_authority, false);
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.mutation_authority, false);
  assert.equal(RECONSTRUCTED_GRAPH_NATIVE_CANDIDATE_CONTRACT.deletion_authority, false);
});
