import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildNativeStructuralRecallProjection,
  NATIVE_STRUCTURAL_RECALL_PROJECTION_CONTRACT,
} from '../../services/retrieval/native-recall-pipeline.js';

const REFERENCE = Date.parse('2026-08-31T12:00:00.000Z');
const MEMORIES = Object.freeze([
  Object.freeze({
    id: '11111111-1111-4111-8111-111111111111',
    value: 'The audit happened before deployment.',
    memory_type: 'event_log',
    source: 'test',
    valid_from: '2026-08-01T00:00:00.000Z',
    valid_until: '2026-08-02T00:00:00.000Z',
  }),
  Object.freeze({
    id: '22222222-2222-4222-8222-222222222222',
    value: 'Deployment completed in August 2026.',
    memory_type: 'declarative',
    source: 'test',
    created_at: '2026-08-03T00:00:00.000Z',
  }),
]);

test('thirteen structural services produce one deterministic zero-authority projection', () => {
  const before = JSON.stringify(MEMORIES);
  const first = buildNativeStructuralRecallProjection({
    queryText: 'What happened before August 2026?',
    memories: MEMORIES,
    referenceTimeMs: REFERENCE,
  });
  const second = buildNativeStructuralRecallProjection({
    queryText: 'What happened before August 2026?',
    memories: MEMORIES,
    referenceTimeMs: REFERENCE,
  });
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(MEMORIES), before);
  assert.equal(first.schema, NATIVE_STRUCTURAL_RECALL_PROJECTION_CONTRACT.schema);
  assert.equal(first.rank_influence, 0);
  assert.equal(first.independent_vote_count, 0);
  assert.equal(first.candidate_order_changed, false);
  assert.equal(first.candidate_membership_changed, false);
  assert.equal(first.canonical_memory_mutated, false);
  assert.equal(first.retention_changed, false);
  assert.equal(first.candidate_count, 2);
  assert.equal(first.timex.expression_count, 1);
  assert.equal(first.temporal_kb.bounded_fact_count, 2);
  assert.equal(first.temporal_graph.relation_counts.included_by, 2);
  assert.equal(first.multi_view_timeline.relation_counts.BEFORE, 1);
  assert.equal(first.interval_algebra.relation_counts.before, 1);
  assert.equal(first.streaming_horizon.active_query, true);
  assert.equal(first.tempeval.closed_relation_count, 2);
  assert.equal(first.tempquestions.temporal, true);
  assert.equal(first.ember_budget.capsule_count, 2);
  assert.equal(first.ember_budget.total_lexical_unit_count, 10);
  assert.equal(first.hippocampus.episode_count, 2);
  assert.match(first.evidence_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(first.decision_sha256, /^[0-9a-f]{64}$/);
});

test('structural services are direct canonical imports, not a resurrected wrapper or rank bundle', () => {
  const source = readFileSync(
    new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url),
    'utf8',
  );
  for (const moduleName of [
    'timex-normalizer.js',
    'temporal-knowledge-base.js',
    'temporal-kg-reasoning.js',
    'temporal-graph-fusion.js',
    'multi-view-timeline.js',
    'interval-algebra-rag.js',
    'situated-qa-context.js',
    'streaming-qa-horizon.js',
    'tempcourt-normalization.js',
    'tempeval-merge-closure.js',
    'tempquestions-intervals.js',
    'ember-retention-memory.js',
    'ai-hippocampus-memory-system.js',
  ]) {
    assert.match(source, new RegExp(`from ['\"][^'\"]*${moduleName.replaceAll('.', '\\.')}['\"]`));
  }
  assert.doesNotMatch(source, /applyNativePaperRecallOperators/);
  assert.doesNotMatch(source, /native_paper_recall_operators/);
});
