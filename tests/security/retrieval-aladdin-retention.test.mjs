import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const RETRIEVAL_PATHS = [
  'services/retrieval/fact-finder.js',
  'services/retrieval/magma-lineage-retriever.js',
  'services/retrieval/context-builder.js',
  'services/retrieval/hnsw-optimizer.js',
  'services/retrieval/procedural-reasoning-retriever.js',
  'services/retrieval/timeline-reconstructor.js',
  'services/retrieval/keypoint-decomposer.js',
  'services/retrieval/adaptive-recall.js',
  'services/retrieval/chronos-temporal-retriever.js',
];

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

test('retrieval candidates do not suppress retained memory lifecycle states', async () => {
  for (const relativePath of RETRIEVAL_PATHS) {
    const body = await source(relativePath);
    assert.doesNotMatch(body, /\b(?:[a-z]+\.)?is_active\s*=\s*true\b/i, relativePath);
    assert.doesNotMatch(body, /\b(?:expires_at|valid_until)\b\s*(?:<|<=|>|>=|IS\s+NOT\s+NULL)/i, relativePath);
    assert.doesNotMatch(body, /NOT\s+EXISTS[\s\S]{0,240}\bsupersedes_id\b/i, relativePath);
  }
});

test('retention expansion preserves tenant, clearance, ownership, and embedding gates', async () => {
  const adaptive = await source('services/retrieval/adaptive-recall.js');
  assert.match(adaptive, /m\.company_id = \$1/);
  assert.match(adaptive, /m\.clearance_level <= \$2/);
  assert.match(adaptive, /m\.embedding IS NOT NULL/);
  assert.match(adaptive, /m\.cube_scope = 'private' AND m\.agent_id = \$/);

  for (const relativePath of [
    'services/retrieval/magma-lineage-retriever.js',
    'services/retrieval/procedural-reasoning-retriever.js',
    'services/retrieval/chronos-temporal-retriever.js',
  ]) {
    const body = await source(relativePath);
    assert.match(body, /company_id = \$1/, relativePath);
    assert.match(body, /clearance_level <= \$2/, relativePath);
    assert.match(body, /clearance_level > 2 OR agent_id = \$/i, relativePath);
  }

  for (const relativePath of [
    'services/retrieval/hnsw-optimizer.js',
    'services/retrieval/keypoint-decomposer.js',
  ]) {
    const body = await source(relativePath);
    assert.match(body, /company_id = \$/i, relativePath);
    assert.match(body, /embedding IS NOT NULL/i, relativePath);
  }
});

test('temporal relevance and supersession evidence remain available without suppressing history', async () => {
  const timeline = await source('services/retrieval/timeline-reconstructor.js');
  assert.match(timeline, /m\.created_at >= \$/);
  assert.match(timeline, /m\.created_at <= \$/);
  assert.match(timeline, /supersedes_id::text/);
  assert.match(timeline, /isSupersession:/);

  const chronos = await source('services/retrieval/chronos-temporal-retriever.js');
  assert.match(chronos, /created_at >= \$3::timestamptz/);
  assert.match(chronos, /created_at <= \$4::timestamptz/);

  const magma = await source('services/retrieval/magma-lineage-retriever.js');
  assert.match(magma, /m\.supersedes_id = ANY\(\$2::uuid\[\]\)/);
});
