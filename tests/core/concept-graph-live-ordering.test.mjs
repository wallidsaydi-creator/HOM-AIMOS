import assert from 'node:assert/strict';
import test from 'node:test';

import { compareHybridConceptResults } from '../../services/core/concept-graph.js';

test('live Concept/PPR result ordering is deterministic for exact score ties', () => {
  const input = [
    { id: 'c', score: 0.5 },
    { id: 'a', score: 0.5 },
    { id: 'b', score: 0.5 },
  ];
  const before = structuredClone(input);
  const first = [...input].sort(compareHybridConceptResults);
  const second = [...input].sort(compareHybridConceptResults);

  assert.deepEqual(first.map((row) => row.id), ['a', 'b', 'c']);
  assert.deepEqual(second, first);
  assert.deepEqual(input, before);
});

test('live Concept/PPR ordering preserves descending score and fails closed on non-finite scores', () => {
  const ordered = [
    { id: 'nan', score: Number.NaN },
    { id: 'low', score: 0.2 },
    { id: 'high-b', score: 0.9 },
    { id: 'high-a', score: 0.9 },
  ].sort(compareHybridConceptResults);

  assert.deepEqual(ordered.map((row) => row.id), ['high-a', 'high-b', 'low', 'nan']);
});
