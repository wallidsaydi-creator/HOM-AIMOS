import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assignBoundedPrototypeBuckets,
  choosePrototypeCount,
  chunkText,
  fitDeterministicCodebook,
  generateHypotheticalQuestions,
} from '../../services/retrieval/quim-index.js';

function unitVector(axis, dimensions = 768) {
  return Array.from({ length: dimensions }, (_, index) => index === axis ? 1 : 0);
}

test('QuIM chunking emits bounded text chunks with retained overlap, never characters', () => {
  const words = Array.from({ length: 25 }, (_, index) => `token${String(index).padStart(2, '0')}`);
  const chunks = chunkText(words.join(' '), 10, 24);
  assert.ok(chunks.length >= 3);
  assert.ok(chunks.every((chunk) => typeof chunk === 'string' && chunk.includes('token')));
  assert.ok(chunks.every((chunk) => chunk.split(/\s+/).length <= 10));
  assert.ok(chunks[0].split(/\s+/).some((word) => chunks[1].includes(word)));
});

test('QuIM deterministic questions are source-grounded and bounded', () => {
  const first = generateHypotheticalQuestions('HOM AIMOS uses Signed Provenance for persistent memory security.', 5);
  const second = generateHypotheticalQuestions('HOM AIMOS uses Signed Provenance for persistent memory security.', 5);
  assert.deepEqual(first, second);
  assert.equal(first.length, 5);
  assert.ok(first.some((question) => /HOM AIMOS|Signed Provenance/.test(question)));
});

test('QuIM codebook and capacity assignment are deterministic and bounded', () => {
  const rows = Array.from({ length: 18 }, (_, index) => ({
    question_sha256: index.toString(16).padStart(64, '0'),
    embedding: unitVector(index % 3),
  }));
  const count = choosePrototypeCount(rows.length);
  const firstCodebook = fitDeterministicCodebook(rows, count, 2);
  const secondCodebook = fitDeterministicCodebook(rows, count, 2);
  assert.deepEqual(firstCodebook, secondCodebook);
  const first = assignBoundedPrototypeBuckets(rows, firstCodebook);
  const second = assignBoundedPrototypeBuckets(rows, secondCodebook);
  assert.deepEqual(first, second);
  assert.equal(first.rows.length, rows.length);
  assert.ok(first.maxBucketSize <= Math.ceil(rows.length / count * 1.5));
});
