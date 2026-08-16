import assert from 'node:assert/strict';
import test from 'node:test';

import { runPersonalizedPageRank } from '../../services/retrieval/concept-ppr-native.js';
import {
  extractQueryEntityAnchors,
  normalizeEntityAnchor,
} from '../../services/retrieval/query-entity-anchors.js';

test('query entity anchors are deterministic and normalized', () => {
  const text = 'HOM AIMOS discussed Zurich on 2026-08-16 with OpenAI.';
  assert.deepEqual(extractQueryEntityAnchors(text), extractQueryEntityAnchors(text));
  assert.ok(extractQueryEntityAnchors(text).some((entity) => entity.name === 'zurich'));
  assert.equal(normalizeEntityAnchor('  Signed   Provenance  '), 'signed provenance');
});

test('Concept/PPR conserves probability and propagates through relations', () => {
  const scores = runPersonalizedPageRank({
    nodeIds: ['a', 'b', 'c'],
    edges: [
      { source: 'a', target: 'b', relation_type: 'RELATED_TO', weight: 1 },
      { source: 'b', target: 'c', relation_type: 'RELATED_TO', weight: 1 },
    ],
    seedWeights: new Map([['a', 1]]),
    damping: 0.5,
    iterations: 30,
  });
  const total = [...scores.values()].reduce((sum, score) => sum + score, 0);
  assert.ok(Math.abs(total - 1) < 1e-9);
  assert.ok(scores.get('a') > scores.get('b'));
  assert.ok(scores.get('b') > scores.get('c'));
  assert.ok(scores.get('c') > 0);
});

test('Concept/PPR dangling mass returns to the personalized teleport set', () => {
  const scores = runPersonalizedPageRank({
    nodeIds: ['seed', 'isolated'],
    edges: [],
    seedWeights: new Map([['seed', 1]]),
    damping: 0.5,
    iterations: 5,
  });
  assert.equal(scores.get('seed'), 1);
  assert.equal(scores.get('isolated'), 0);
});
