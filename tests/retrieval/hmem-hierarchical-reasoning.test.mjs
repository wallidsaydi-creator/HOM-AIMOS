import test from 'node:test';
import assert from 'node:assert/strict';

import {
  HMEM_GUARDRAILS,
  buildHierarchicalMemory,
  confidenceWeight,
  cosine,
  hashVector,
  hmemScores,
  recursiveTopK,
} from '../../services/retrieval/hmem-hierarchical-reasoning.js';

function fixtureStates() {
  return [
    {
      id: 'm1',
      text: 'Alice prefers Alpine skiing',
      memory: { session_id: 's1', source: 'chat', memory_type: 'preference', key: 'pref:alice:ski' },
    },
    {
      id: 'm2',
      text: 'Alice booked a mountain hotel',
      memory: { session_id: 's1', source: 'chat', memory_type: 'episode', key: 'trip:alice:hotel' },
    },
    {
      id: 'm3',
      text: 'Database encryption protects records',
      memory: { session_id: 's2', source: 'paper', memory_type: 'fact', key: 'security:database' },
    },
  ];
}

test('H-MEM builds bottom-up pointer unions without mutating input', () => {
  const states = fixtureStates();
  const snapshot = structuredClone(states);
  const hierarchy = buildHierarchicalMemory(states);

  assert.deepEqual(states, snapshot);
  assert.deepEqual(
    hierarchy.levels.content.map((node) => node.position_index),
    [[0], [1], [2]],
  );

  for (const node of [...hierarchy.levels.subsub_section, ...hierarchy.levels.subsection, ...hierarchy.levels.section]) {
    const expected = [...new Set(node.children.flatMap((child) => child.position_index))].sort((a, b) => a - b);
    assert.deepEqual(node.position_index, expected);
    assert.equal(node.position_index.length > 0, true);
  }
});

test('H-MEM construction and routing are deterministic and bounded', () => {
  const states = fixtureStates();
  const first = buildHierarchicalMemory(states);
  const second = buildHierarchicalMemory(states);
  assert.deepEqual(first, second);

  const routeA = recursiveTopK('Alice skiing', first.roots, 10);
  const routeB = recursiveTopK('Alice skiing', second.roots, 10);
  assert.deepEqual(routeA, routeB);
  assert.equal(routeA.some((row) => row.node.level === 'content'), true);
  assert.equal(routeA.every((row) => Number.isFinite(row.score) && row.score >= 0 && row.score <= 1), true);
});

test('H-MEM applies top-k within each selected parent before taking the union', () => {
  const roots = [
    {
      id: 'root-a',
      text: 'alpha',
      children: [
        { id: 'a1', text: 'query alpha', children: [] },
        { id: 'a2', text: 'unrelated', children: [] },
      ],
    },
    {
      id: 'root-b',
      text: 'beta',
      children: [
        { id: 'b1', text: 'query beta', children: [] },
        { id: 'b2', text: 'unrelated', children: [] },
      ],
    },
  ];

  const route = recursiveTopK('query', roots, 2);
  assert.deepEqual(route.map((row) => row.node.id), ['root-a', 'root-b', 'a1', 'b1', 'a2', 'b2']);
});

test('H-MEM traversal rejects cyclic revisits and terminates', () => {
  const a = { id: 'a', text: 'alpha', children: [] };
  const b = { id: 'b', text: 'beta', children: [] };
  a.children.push(b);
  b.children.push(a);

  const route = recursiveTopK('alpha', [a], 10);
  assert.deepEqual(route.map((row) => row.path), [['a'], ['a', 'b']]);
  assert.equal(route.every((row) => new Set(row.path).size === row.path.length), true);
});

test('H-MEM malformed inputs fail closed without throwing', () => {
  assert.deepEqual(buildHierarchicalMemory(null).roots, []);
  assert.deepEqual(buildHierarchicalMemory([null, {}, { id: '', text: 'ignored' }]).roots, []);
  assert.deepEqual(recursiveTopK('query', null, 10), []);
  assert.deepEqual(recursiveTopK('query', [null, {}], Number.POSITIVE_INFINITY), []);
  assert.deepEqual(hmemScores({ queryText: 'query', states: [null, {}, { id: '' }] }).scoreById, new Map());
  assert.equal(cosine(null, [1]), 0);
  assert.equal(cosine([1], [1, 0]), 0);
  assert.equal(hashVector('value', Number.POSITIVE_INFINITY).length, 64);
});

test('H-MEM lexical proxy uses the natural cosine range and honest confidence', () => {
  const alpha = hashVector('alpha');
  const beta = hashVector('beta');
  assert.equal(cosine(alpha, alpha), 1);
  assert.equal(cosine(alpha, beta), 0);
  assert.equal(confidenceWeight(0.4, 4, 100), 0.4);
  assert.equal(confidenceWeight(2), 1);
  assert.equal(confidenceWeight(-1), 0);

  const result = hmemScores({ queryText: 'alpha', states: [{ id: 'beta', text: 'beta', memory: {} }] });
  assert.equal(result.diagnosticsById.get('beta').direct_content_similarity, 0);
  assert.match(result.formula, /confidence=selected_similarity_score/);

  const memoryValueOnly = hmemScores({
    queryText: 'alpha',
    states: [
      { id: 'value-only', memory: { value: 'alpha' } },
      { id: 'value-only', memory: { value: 'conflicting duplicate' } },
    ],
  });
  assert.equal(memoryValueOnly.scoreById.size, 1);
  assert.equal(memoryValueOnly.diagnosticsById.get('value-only').direct_content_similarity, 1);
});

test('H-MEM remains a non-mutating, no-decay dormant kernel', () => {
  assert.deepEqual(HMEM_GUARDRAILS, {
    mutates_canonical_memory: false,
    prunes_canonical_memory: false,
    applies_decay: false,
    deletes_memory: false,
    injects_answers: false,
    positional_index_is_pointer_not_similarity_feature: true,
  });
});
