import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildR8ClassMap,
  continuityDecisionHash,
} from '../../eval/mutmem-v2/content-state-occurrence-r8-continuity.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const IDS = [
  '10000000-0000-4000-8000-000000000001',
  '10000000-0000-4000-8000-000000000002',
  '10000000-0000-4000-8000-000000000003',
];
function memory(index, hash = 'a'.repeat(64)) {
  return {
    memory_id: IDS[index], company_id: 'hom', live_content_hash: hash,
    principal_id: 'agent-a', supersedes_id: index === 1 ? IDS[0] : null,
    topology_commitment: (index + 1).toString(16).repeat(64).slice(0, 64),
    evidence_scope_commitment: (index + 4).toString(16).repeat(64).slice(0, 64),
  };
}
function occurrence(index, memoryIndex, hash = 'a'.repeat(64)) {
  return {
    occurrence_ref: (index + 7).toString(16).repeat(64).slice(0, 64),
    memory_id: IDS[memoryIndex], live_content_hash: hash,
    provenance_leaf_hash: (index + 10).toString(16).repeat(64).slice(0, 64),
    event_type: index === 2 ? 'SAVE_REASSERT' : 'SAVE',
    signed_time: 1_787_000_000 + index, signature_form_version: index === 2 ? 3 : 1,
  };
}

test('R8 partitions every occurrence exactly once and accounts repeated states', () => {
  const map = buildR8ClassMap({
    companyId: 'hom',
    memories: [memory(0), memory(1), memory(2, 'b'.repeat(64))],
    occurrences: [occurrence(0, 0), occurrence(1, 1), occurrence(2, 0), occurrence(3, 2, 'b'.repeat(64))],
  });
  assert.equal(map.summary.memory_count, 3);
  assert.equal(map.summary.occurrence_count, 4);
  assert.equal(map.summary.content_state_count, 2);
  assert.equal(map.summary.repeated_group_count, 1);
  assert.equal(map.summary.repeated_row_count, 2);
  assert.equal(map.summary.excess_row_count, 1);
  assert.equal(map.partitions.flatMap((row) => row.occurrence_refs).length, 4);
  for (const key of ['occurrence_root', 'partition_root', 'evidence_scope_root', 'topology_root']) {
    assert.match(map.summary[key], /^[0-9a-f]{64}$/);
  }
});

test('R8 roots are invariant to input order but sensitive to membership', () => {
  const memories = [memory(0), memory(1)];
  const occurrences = [occurrence(0, 0), occurrence(1, 1), occurrence(2, 0)];
  const first = buildR8ClassMap({ companyId: 'hom', memories, occurrences });
  const second = buildR8ClassMap({
    companyId: 'hom', memories: [...memories].reverse(), occurrences: [...occurrences].reverse(),
  });
  assert.deepEqual(first.summary, second.summary);
  const changed = buildR8ClassMap({
    companyId: 'hom', memories, occurrences: occurrences.slice(0, 2),
  });
  assert.notEqual(first.summary.occurrence_root, changed.summary.occurrence_root);
  assert.notEqual(first.summary.partition_root, changed.summary.partition_root);
});

test('R8 fails on duplicate, missing, cross-state, and orphan occurrences', () => {
  assert.throws(
    () => buildR8ClassMap({ companyId: 'hom', memories: [memory(0)], occurrences: [] }),
    /memory_without_occurrence/,
  );
  assert.throws(
    () => buildR8ClassMap({
      companyId: 'hom', memories: [memory(0)], occurrences: [occurrence(0, 0), occurrence(0, 0)],
    }),
    /occurrence_membership_invalid/,
  );
  assert.throws(
    () => buildR8ClassMap({
      companyId: 'hom', memories: [memory(0)], occurrences: [occurrence(0, 0, 'b'.repeat(64))],
    }),
    /occurrence_membership_invalid/,
  );
  assert.throws(
    () => buildR8ClassMap({
      companyId: 'hom', memories: [memory(0)], occurrences: [occurrence(0, 1)],
    }),
    /occurrence_membership_invalid/,
  );
});

test('continuity decision enforces genesis and predecessor sequence', () => {
  const body = {
    schema: 'hom.aimos.content-state-occurrence-continuity-event/v1',
    sequence: 1,
    occurrence_root: 'a'.repeat(64), partition_root: 'b'.repeat(64),
    evidence_scope_root: 'c'.repeat(64), topology_root: 'd'.repeat(64),
    source_closure_sha256: 'e'.repeat(64), external_checkpoint_sha256: 'f'.repeat(64),
    predecessor_event_id: null, predecessor_decision_sha256: null,
  };
  assert.match(continuityDecisionHash(body), /^[0-9a-f]{64}$/);
  assert.throws(
    () => continuityDecisionHash({ ...body, predecessor_decision_sha256: '1'.repeat(64) }),
    /continuity_genesis_invalid/,
  );
  assert.match(continuityDecisionHash({
    ...body,
    sequence: 2,
    predecessor_event_id: IDS[0],
    predecessor_decision_sha256: '1'.repeat(64),
  }), /^[0-9a-f]{64}$/);
});

test('R8 maximum duplicate class remains linear and complete', () => {
  const memories = Array.from({ length: 20_000 }, (_, index) => ({
    memory_id: `20000000-0000-4000-8000-${index.toString().padStart(12, '0')}`,
    company_id: 'hom', live_content_hash: 'f'.repeat(64), principal_id: 'agent-scale',
    supersedes_id: null,
    topology_commitment: index.toString(16).padStart(64, '0'),
    evidence_scope_commitment: (index + 20_000).toString(16).padStart(64, '0'),
  }));
  const occurrences = memories.map((row, index) => ({
    occurrence_ref: (index + 40_000).toString(16).padStart(64, '0'),
    memory_id: row.memory_id, live_content_hash: row.live_content_hash,
    provenance_leaf_hash: (index + 60_000).toString(16).padStart(64, '0'),
    event_type: 'SAVE', signed_time: 1_787_000_000 + index, signature_form_version: 1,
  }));
  const started = performance.now();
  const map = buildR8ClassMap({ companyId: 'hom', memories, occurrences });
  const elapsed = performance.now() - started;
  assert.equal(map.summary.content_state_count, 1);
  assert.equal(map.summary.occurrence_count, 20_000);
  assert.equal(map.summary.excess_row_count, 19_999);
  assert.ok(elapsed < 2_500, `R8 20K class map took ${elapsed.toFixed(3)}ms`);
});

test('R8 kernel has no database, filesystem, network, signer, or environment authority', () => {
  const source = fs.readFileSync(path.join(
    ROOT, 'eval/mutmem-v2/content-state-occurrence-r8-continuity.mjs',
  ), 'utf8');
  assert.doesNotMatch(source, /db\/connection|node:fs|fetch\(|process\.env|signAs|privateKey/);
});
