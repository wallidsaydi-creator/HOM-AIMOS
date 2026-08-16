import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  HINGEMEM_CONSTANTS,
  HINGEMEM_GUARDRAILS,
  adaptiveStop,
  buildBoundaryHypergraph,
  fieldAwareJaccard,
  hingeMemQueryPlan,
  hingeMemScores,
  recursivelyMergeHyperedges,
  rerankHyperedges,
} from '../../services/retrieval/hingemem-boundary-hypergraph.js';

function fixtureStates() {
  return [
    {
      id: 'h1',
      text: 'Alice met Bob at KFC in May 2026 to discuss Project Quasar.',
      embedding: [1, 0],
      boundary_elements: {
        person: ['Alice', 'Bob'],
        time: ['2026-05'],
        location: ['KFC'],
        topic: ['project quasar'],
      },
      boundary_reasons: ['change_person'],
    },
    {
      id: 'h2',
      text: 'Alice met Bob at KFC in May 2026 and approved Project Quasar.',
      embedding: [0.8, 0.2],
      boundary_elements: {
        person: ['Alice', 'Bob'],
        time: ['2026-05'],
        location: ['KFC'],
        topic: ['project quasar'],
      },
      boundary_reasons: ['topic_shift'],
    },
    {
      id: 'h3',
      text: 'Caroline visited Rome in June 2026 for a museum exhibition.',
      embedding: [0, 1],
      boundary_elements: {
        person: ['Caroline'],
        time: ['2026-06'],
        location: ['Rome'],
        topic: ['museum exhibition'],
      },
      boundary_reasons: ['change_location'],
    },
  ];
}

function row(id, score) {
  return { hyperedge: { id }, xi_hat: score };
}

test('field-aware Jaccard distinguishes element types and preserves bounds', () => {
  assert.equal(fieldAwareJaccard({ person: ['alice'] }, { topic: ['alice'] }), 0);
  assert.equal(fieldAwareJaccard({}, {}), 1);
  assert.equal(fieldAwareJaccard({ person: ['alice'] }, {}), 0);
  const left = { person: ['alice'], topic: ['quasar'] };
  const right = { person: ['alice'], location: ['rome'] };
  assert.equal(fieldAwareJaccard(left, right), 1 / 3);
  assert.equal(fieldAwareJaccard(left, right), fieldAwareJaccard(right, left));
});

test('recursive merge uses the strict J > 0.8 threshold and does not mutate inputs', () => {
  const exactThreshold = [
    { id: 'a', state_ids: ['a'], person: ['a', 'b', 'c', 'd'], time: [], location: [], topic: [], description: 'a' },
    { id: 'b', state_ids: ['b'], person: ['a', 'b', 'c', 'd'], time: [], location: [], topic: ['x'], description: 'b' },
  ];
  const before = structuredClone(exactThreshold);
  assert.equal(fieldAwareJaccard(exactThreshold[0], exactThreshold[1]), 0.8);
  assert.equal(recursivelyMergeHyperedges(exactThreshold).length, 2);
  assert.deepEqual(exactThreshold, before);

  const identical = [exactThreshold[0], { ...structuredClone(exactThreshold[0]), id: 'c', state_ids: ['c'] }];
  const merged = recursivelyMergeHyperedges(identical);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].state_ids, ['a', 'c']);
});

test('boundary construction is deterministic, immutable, malformed-safe, and capped', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const first = buildBoundaryHypergraph(states);
  const second = buildBoundaryHypergraph(states);
  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.equal(first.raw_boundary_count, 3);
  assert.equal(first.H.length, 2);
  assert.ok(first.N.every((node) => node.salience >= 0 && node.salience <= 1));
  assert.ok(first.N.every((node) => Object.values(node.salience_components).every(Number.isFinite)));
  assert.deepEqual(buildBoundaryHypergraph([null, {}, { id: 'valid', text: 'Valid memory.' }, { id: 'valid', text: 'Duplicate.' }]).H.map((edge) => edge.id), ['valid']);

  const oversized = Array.from({ length: HINGEMEM_CONSTANTS.max_hyperedges + 4 }, (_, index) => ({
    id: `edge-${index}`,
    text: `Distinct memory ${index}`,
    boundary_elements: { topic: [`topic-${index}`] },
  }));
  assert.equal(buildBoundaryHypergraph(oversized).raw_boundary_count, HINGEMEM_CONSTANTS.max_hyperedges);
});

test('query plans remain explicit deterministic adaptations', () => {
  assert.equal(hingeMemQueryPlan('List all Alice meetings in Rome').type, 'recall_priority');
  assert.equal(hingeMemQueryPlan('did Alice approve the plan').type, 'judgment');
  assert.equal(hingeMemQueryPlan('Alice project detail').type, 'precision_priority');
  assert.equal(hingeMemQueryPlan('When did Alice visit Rome?').priorities[0], 'time');
  assert.equal(hingeMemQueryPlan('Alice project detail').producer, 'deterministic_aimos_adaptation_not_paper_llm');
});

test('reranking preserves the raw additive Equation 6 terms', () => {
  const hypergraph = {
    N: [
      { id: 'person:alice', salience: 0.6 },
      { id: 'topic:quasar', salience: 0.9 },
    ],
    H: [{
      id: 'edge',
      person: ['alice'],
      time: [],
      location: [],
      topic: ['quasar'],
      description: 'Alice quasar',
      embedding: [1, 0],
      state_ids: ['edge'],
    }],
    C_common: ['routine'],
    C_rare: ['quasar'],
  };
  const plan = {
    type: 'precision_priority',
    targeted_indices: { person: ['alice'], time: [], location: [], topic: ['quasar'] },
    priorities: ['person', 'topic'],
  };
  const [lexical] = rerankHyperedges({ queryText: 'Alice quasar', hypergraph, plan });
  assert.equal(lexical.xi_source, 'lexical_adaptation');
  assert.ok(Math.abs(lexical.xi_hat - (lexical.xi + lexical.omegaS + lexical.omegaT)) < 1e-12);
  assert.ok(lexical.xi_hat > 1, 'additive Equation 6 must not be silently replaced by a convex blend');

  const [dense] = rerankHyperedges({ queryText: 'Alice quasar', queryEmbedding: [1, 0], hypergraph, plan });
  assert.equal(dense.xi_source, 'cosine_embedding');
  assert.equal(dense.xi, 1);
});

test('recall-priority stop uses the disclosed descending-knee resolution', () => {
  const selected = adaptiveStop(
    [row('a', 1), row('b', 0.95), row('c', 0.7), row('d', 0.2)],
    { type: 'recall_priority' },
    0.1,
  );
  assert.deepEqual(selected.map((entry) => entry.hyperedge.id), ['a', 'b']);
  assert.deepEqual(
    adaptiveStop([row('a', 1), row('b', 0.95), row('c', 0.9)], { type: 'recall_priority' }, 0.1).map((entry) => entry.hyperedge.id),
    ['a', 'b', 'c'],
  );
});

test('precision-priority stop applies the strict 80% maximum rule', () => {
  const selected = adaptiveStop(
    [row('a', 1), row('b', 0.81), row('c', 0.8), row('d', 0.2)],
    { type: 'precision_priority' },
  );
  assert.deepEqual(selected.map((entry) => entry.hyperedge.id), ['a', 'b']);
});

test('judgment stop applies stable softmax then the strict 80% relative-maximum rule', () => {
  const selected = adaptiveStop(
    [row('a', 3), row('b', 2), row('c', 0)],
    { type: 'judgment' },
  );
  assert.deepEqual(selected.map((entry) => entry.hyperedge.id), ['a']);
  assert.deepEqual(adaptiveStop([], { type: 'judgment' }), []);
});

test('service output is deterministic, bounded, and selection adds no score boost', () => {
  const states = fixtureStates();
  const before = structuredClone(states);
  const input = { queryText: 'Alice Project Quasar', queryEmbedding: [1, 0], states };
  const first = hingeMemScores(input);
  const second = hingeMemScores(input);
  assert.deepEqual(first, second);
  assert.deepEqual(states, before);
  assert.ok([...first.scoreById.values()].every((score) => Number.isFinite(score) && score >= 0 && score <= 1));
  assert.ok([...first.diagnosticsById.values()].every((diagnostic) => Number.isFinite(diagnostic.xi_hat_raw)));
  assert.equal(Math.max(...first.scoreById.values()), 1);
  assert.equal(first.guardrails.adaptive_stop_is_transient_read_selection_only, true);
  assert.equal(hingeMemScores({ states: null }).hyperedge_count, 0);
});

test('source contains no database, server, network, or ENV authority', () => {
  const source = readFileSync(new URL('../../services/retrieval/hingemem-boundary-hypergraph.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|from ['"].*db\/|fetch\(|listen\(|INSERT\s+INTO|UPDATE\s+memories|DELETE\s+FROM/i);
  assert.doesNotMatch(source, /0\.54\s*\*|selectedBoost|rare_topic_bonus|common_topic_bonus/);
  assert.match(source, /uses_environment_authority:\s*false/);
  assert.equal(HINGEMEM_GUARDRAILS.uses_environment_authority, false);
  assert.equal(HINGEMEM_GUARDRAILS.mutates_canonical_memory, false);
});
