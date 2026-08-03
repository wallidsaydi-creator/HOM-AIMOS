import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);
const RUNTIME_SCHEMA_OWNERS = [
  'services/core/concept-graph.js',
  'services/retrieval/similarity-stats.js',
  'services/retrieval/embedding-stability.js',
  'services/retrieval/hnsw-optimizer.js',
  'services/retrieval/recall-calibrator.js',
  'services/retrieval/quim-index.js',
  'services/write/transformation-cache.js',
];

test('retrieval and cache services contain no runtime schema DDL', async () => {
  for (const relativePath of RUNTIME_SCHEMA_OWNERS) {
    const source = await readFile(new URL(relativePath, ROOT), 'utf8');
    assert.doesNotMatch(source, /\bCREATE\s+TABLE\b/i, relativePath);
    assert.doesNotMatch(source, /\bALTER\s+TABLE\b/i, relativePath);
    assert.doesNotMatch(source, /\bCREATE\s+(?:UNIQUE\s+)?INDEX\b/i, relativePath);
    assert.doesNotMatch(source, /\bensure(?:Projection)?Schema\b|\bensureTable\b/, relativePath);
  }
});

test('versioned migrations own every removed runtime relation and index', async () => {
  const authorities = new Map([
    ['migrations/007-concept-edges.sql', ['node_type', 'concept_edges', 'idx_concept_edges_source', 'idx_concept_edges_target']],
    ['migrations/008-quim-index.sql', ['quim_index', 'quim_prototypes', 'idx_quim_company_proto', 'idx_quim_chunk']],
    ['migrations/010-similarity-statistics.sql', ['similarity_statistics']],
    ['migrations/011-hnsw-embedding-index.sql', ['idx_aimos_memories_embedding_hnsw', 'm = 32', 'ef_construction = 200']],
    ['migrations/001-base-schema.sql', ['embedding_projections', 'recall_calibration', 'recall_observations', 'transformation_cache', 'idx_transformation_cache_company_last_hit']],
  ]);

  for (const [relativePath, objects] of authorities) {
    const migration = await readFile(new URL(relativePath, ROOT), 'utf8');
    for (const object of objects) {
      assert.ok(migration.includes(object), `${relativePath} must own ${object}`);
    }
  }
});

test('HNSW readiness verifies the exact migration-owned index and fails closed', async () => {
  const source = await readFile(new URL('services/retrieval/hnsw-optimizer.js', ROOT), 'utf8');
  assert.match(source, /FROM pg_indexes/);
  assert.match(source, /indexname = 'idx_aimos_memories_embedding_hnsw'/);
  assert.match(source, /MIGRATION_SCHEMA_MISSING/);
  assert.match(source, /MIGRATION_SCHEMA_MISMATCH/);
  assert.match(source, /m !== 32 \|\| efConstruction !== 200/);
});
