import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  MNEMIS_MARGINAL_GEAR_CONTRACT,
  buildMnemisMarginalWorkspace,
  composeMnemisMarginalGear,
  rankMnemisMarginalWorkspace,
} from '../../services/retrieval/mnemis-marginal-gear.js';

function digest(value) {
  return String(value).padStart(64, '0').slice(-64);
}

function admittedMemories(count = 4) {
  const values = [
    'Alice joined Project Quasar after a signed security review.',
    'Project Quasar passed the provenance audit in Rome.',
    'The Rome team approved the final Quasar release.',
    'Caroline visited Berlin for an art exhibition.',
  ];
  return Array.from({ length: count }, (_, index) => ({
    id: `memory-${index}`,
    value: values[index % values.length],
    embedding: [index === 3 ? 0 : 1, index === 3 ? 1 : 0, index / Math.max(1, count)],
    content_hash: digest(index + 1),
    provenance_sha256: digest(index + 101),
    provenance_proof: {
      live_content_hash: digest(index + 1),
      binding_event_mutation_hash: digest(index + 101),
    },
    canary_admitted: true,
  }));
}

test('Mnemis marginal gear emits deterministic same-set System-1 ranks only', () => {
  const memories = admittedMemories();
  const before = structuredClone(memories);
  const input = {
    admittedMemories: memories,
    queryText: 'Who approved Project Quasar after the security review?',
    queryEmbedding: [1, 0, 0.25],
  };
  const first = composeMnemisMarginalGear(input);
  const second = composeMnemisMarginalGear(input);

  assert.deepEqual(first, second);
  assert.deepEqual(memories, before);
  assert.ok(first.ranks.length > 0 && first.ranks.length <= memories.length);
  assert.ok(first.ranks.every((rank) => memories.some((memory) => memory.id === rank.id)));
  assert.equal(first.discovered_memories.length, 0);
  assert.equal(first.decision.graph_only_discovery_count, 0);
  assert.equal(first.decision.system2_rank_influence, 0);
  assert.equal(first.diagnostics.unsupported_entities, 0);
  assert.equal(first.diagnostics.unsupported_edges, 0);
});

test('Mnemis accepts the native pgvector text representation without weakening finite checks', () => {
  const memories = admittedMemories(4).map((memory) => ({
    ...memory,
    embedding: `[${memory.embedding.join(',')}]`,
  }));
  const gear = composeMnemisMarginalGear({
    admittedMemories: memories,
    queryText: 'Project Quasar Rome security review',
    queryEmbedding: '[1,0.2,0]',
  });

  assert.equal(gear.ranks.length > 0, true);
  assert.equal(gear.ranks.every((row) => memories.some((memory) => memory.id === row.id)), true);
  assert.throws(
    () => composeMnemisMarginalGear({
      admittedMemories: memories.map((memory, index) => (
        index === 0 ? { ...memory, embedding: '[1,NaN,0]' } : memory
      )),
      queryText: 'Project Quasar Rome security review',
      queryEmbedding: '[1,0.2,0]',
    }),
    /mnemis_marginal_gear:embedding_invalid/,
  );
});

test('workspace has exact scale bounds for all four paper object classes', () => {
  const memories = admittedMemories(40);
  const workspace = buildMnemisMarginalWorkspace({ admittedMemories: memories });
  const result = rankMnemisMarginalWorkspace({
    workspace,
    queryText: 'Quasar provenance security approval',
    queryEmbedding: [1, 0, 0.5],
  });

  assert.equal(workspace.graph.episodes.length, 40);
  assert.ok(workspace.graph.entities.length <= 40 * 12);
  assert.ok(workspace.graph.edges.length <= 40 * 66);
  assert.ok(workspace.graph.episodic_edges.length <= 40 * 12);
  assert.ok(result.ranks.length <= 40);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.maximum_pre_dedup_edges, 2640);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.graph_family_outer_channels, 1);
});

test('workspace caps the validated admitted population and fails closed beyond the scale contract', () => {
  const capped = buildMnemisMarginalWorkspace({ admittedMemories: admittedMemories(41) });
  assert.equal(capped.decision.admitted_population, 41);
  assert.equal(capped.decision.workspace_population, 40);
  assert.equal(capped.decision.workspace_capped, true);

  const base = admittedMemories();
  assert.throws(() => buildMnemisMarginalWorkspace({
    admittedMemories: base.map((memory, index) => index ? memory : { ...memory, provenance_proof: null }),
  }), /provenance_admission_required/);
  assert.throws(() => buildMnemisMarginalWorkspace({
    admittedMemories: base.map((memory, index) => index ? memory : { ...memory, canary_admitted: false }),
  }), /canary_admission_required/);
  assert.throws(() => buildMnemisMarginalWorkspace({
    admittedMemories: base.map((memory, index) => index ? memory : { ...memory, embedding: null }),
  }), /embedding_invalid/);
  assert.throws(() => buildMnemisMarginalWorkspace({
    admittedMemories: [base[0], { ...base[1], id: base[0].id }],
  }), /identity_invalid/);
  assert.throws(
    () => buildMnemisMarginalWorkspace({ admittedMemories: admittedMemories(121) }),
    /admitted_population_limit_exceeded/,
  );
});

test('source owns no database, server, model, ENV, persistence, mutation, or disclosure authority', () => {
  const source = readFileSync(
    new URL('../../services/retrieval/mnemis-marginal-gear.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /process\.env|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+aimos_memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /openai|anthropic|ollama|provider|chatgpt/i);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.runtime_wired, false);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.model_authority, false);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.persistence_authority, false);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.mutation_authority, false);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.deletion_authority, false);
  assert.equal(MNEMIS_MARGINAL_GEAR_CONTRACT.disclosure_authority, false);
});
