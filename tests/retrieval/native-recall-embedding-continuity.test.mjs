import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  NATIVE_RECALL_EMBEDDING_CONTINUITY_SCHEMA,
  buildNativeRecallEmbeddingContinuityDecision,
} from '../../services/retrieval/native-recall-pipeline.js';

const VECTOR = Object.freeze(Array.from({ length: 768 }, (_, index) => index / 768));

test('native embedding continuity commits every ordered selected memory and rejects invalid vectors', () => {
  const decision = buildNativeRecallEmbeddingContinuityDecision({
    returnPath: 'normal_recall',
    memories: [
      { id: '11111111-1111-4111-8111-111111111111', embedding: JSON.stringify(VECTOR) },
      { id: '22222222-2222-4222-8222-222222222222', embedding: [...VECTOR] },
    ],
  });
  assert.equal(decision.schema, NATIVE_RECALL_EMBEDDING_CONTINUITY_SCHEMA);
  assert.equal(decision.selected_memory_count, 2);
  assert.equal(decision.embedding_count, 2);
  assert.equal(decision.embedding_dimension, 768);
  assert.equal(decision.members.length, 2);
  assert.equal(decision.members[0].embedding_sha256, decision.members[1].embedding_sha256);
  assert.equal(decision.all_selected_memories_carry_embedding, true);
  assert.equal(decision.rank_authority, false);
  assert.throws(() => buildNativeRecallEmbeddingContinuityDecision({
    returnPath: 'normal_recall',
    memories: [{ id: '11111111-1111-4111-8111-111111111111', embedding: VECTOR.slice(1) }],
  }), /native_recall_embedding_continuity_invalid/);
});

test('all five return lanes and every normal-recall candidate SQL source carry embeddings natively', () => {
  const pipeline = readFileSync(new URL('../../services/retrieval/native-recall-pipeline.js', import.meta.url), 'utf8');
  const identifier = readFileSync(new URL('../../services/retrieval/identifier-recall.js', import.meta.url), 'utf8');
  const multiStage = readFileSync(new URL('../../services/retrieval/multi-stage-retrieval.js', import.meta.url), 'utf8');
  for (const lane of [
    'identifier_exact',
    'post_compaction_handoff',
    'semantic_cache',
    'adaptive_early_exit',
    'normal_recall',
  ]) {
    assert.match(pipeline, new RegExp(`returnPath: '${lane}'`));
  }
  assert.match(identifier, /embedding::text AS embedding/);
  assert.match(multiStage, /MEMORY_FIELDS[\s\S]*embedding::text AS embedding/);
  for (const channel of [
    'quim_lookup',
    'entity_graph',
    'bm25_pass',
    'identity_truth_rescue',
    'lexical_value_rescue',
    'benchmark_sibling_hydration',
    'qmd_fts',
    'qmd_key',
    'multi_stage_hyde',
  ]) {
    assert.match(pipeline, new RegExp(channel));
  }
  const candidateSelects = [...pipeline.matchAll(/`SELECT[\s\S]*?FROM (?:public\.)?aimos_memories(?:\s+m)?\b/g)]
    .map((match) => match[0])
    .filter((sql) => !sql.includes('SELECT DISTINCT value FROM aimos_memories'));
  assert.ok(candidateSelects.length >= 11);
  assert.equal(candidateSelects.every((sql) => /\bembedding\b/.test(sql)), true);
  assert.doesNotMatch(`${pipeline}\n${identifier}\n${multiStage}`, /native_calibration_shadow/);
});
