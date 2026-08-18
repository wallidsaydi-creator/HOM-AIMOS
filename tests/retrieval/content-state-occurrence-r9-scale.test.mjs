import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  latencySummary,
  resolveGeometricWindowExhaustion,
  resolveOptionalProjectionUse,
  summarizeSortedStateStream,
  syntheticSortedOccurrences,
} from '../../eval/mutmem-v2/content-state-occurrence-r9-scale.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('compact state stream accounts all-unique, duplicate, mixed poison, and principals', () => {
  const unique = summarizeSortedStateStream(syntheticSortedOccurrences({ count: 200, scenario: 'all_unique' }));
  const duplicate = summarizeSortedStateStream(syntheticSortedOccurrences({ count: 200, scenario: 'maximum_duplicate' }));
  const mixed = summarizeSortedStateStream(syntheticSortedOccurrences({ count: 200, scenario: 'mixed_poison' }));
  const principals = summarizeSortedStateStream(syntheticSortedOccurrences({ count: 200, scenario: 'multi_principal' }));
  assert.equal(unique.unique_state_count, 200);
  assert.equal(duplicate.unique_state_count, 1);
  assert.equal(duplicate.collapsed_occurrence_count, 199);
  assert.equal(mixed.unique_state_count, 50);
  assert.ok(mixed.blocked_state_count > 0);
  assert.equal(principals.unique_state_count, 50);
  assert.equal(principals.principal_state_count, 200);
  assert.equal(unique.membership_operations, 200);
});

test('compact stream rejects malformed and unsorted evidence', () => {
  const records = [...syntheticSortedOccurrences({ count: 2, scenario: 'all_unique' })];
  assert.throws(() => summarizeSortedStateStream([...records].reverse()), /stream_not_sorted/);
  assert.throws(
    () => summarizeSortedStateStream([{ ...records[0], occurrence_ref: '' }]),
    /record_invalid/,
  );
});

test('window exhaustion distinguishes bounded cap from verified index exhaustion', () => {
  const windows = [
    { opened: 24, clean_unique: 3 },
    { opened: 48, clean_unique: 6 },
    { opened: 96, clean_unique: 9 },
    { opened: 120, clean_unique: 9 },
  ];
  assert.equal(resolveGeometricWindowExhaustion({
    cleanUniqueByWindow: windows, requestedK: 10, candidateCap: 120,
  }).status, 'bounded_window_exhausted');
  assert.equal(resolveGeometricWindowExhaustion({
    cleanUniqueByWindow: windows, requestedK: 10, candidateCap: 120, indexExhausted: true,
  }).status, 'exhausted_unique');
  assert.equal(resolveGeometricWindowExhaustion({
    cleanUniqueByWindow: windows, requestedK: 9, candidateCap: 120,
  }).status, 'satisfied');
});

test('optional projection mismatch uses only bounded canonical fallback', () => {
  const expected = 'a'.repeat(64);
  assert.equal(resolveOptionalProjectionUse({
    expectedSourceRoot: expected, observedSourceRoot: expected,
  }).mode, 'verified_projection');
  assert.equal(resolveOptionalProjectionUse({
    expectedSourceRoot: expected, observedSourceRoot: 'b'.repeat(64), canonicalFallbackBounded: true,
  }).mode, 'bounded_canonical_fallback');
  assert.throws(() => resolveOptionalProjectionUse({
    expectedSourceRoot: expected, observedSourceRoot: 'b'.repeat(64),
  }), /projection_source_root_invalid/);
});

test('latency summary is deterministic and reports exact order statistics', () => {
  assert.deepEqual(latencySummary([5, 1, 4, 2, 3]), {
    n: 5, p50_ms: 3, p95_ms: 5, p99_ms: 5, max_ms: 5,
  });
});

test('R9 scale owner has no database, filesystem, network, signer, or environment authority', () => {
  const source = fs.readFileSync(path.join(
    ROOT, 'eval/mutmem-v2/content-state-occurrence-r9-scale.mjs',
  ), 'utf8');
  assert.doesNotMatch(source, /db\/connection|node:fs|fetch\(|process\.env|signAs|privateKey/);
});
