import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

async function source(path) {
  return readFile(new URL(path, ROOT), 'utf8');
}

test('every native graph projection mutation carries an atomic signed event reference', async () => {
  const [spiced, persistence, migration] = await Promise.all([
    source('services/dream/spiced-consolidator.js'),
    source('services/write/persist-memory.js'),
    source('migrations/078-signed-cross-ref-projection.sql'),
  ]);

  assert.match(spiced, /withTransaction\(async \(client\) =>/);
  assert.match(spiced, /'spiced_graph_projection'/);
  assert.match(spiced, /authority_event_id = EXCLUDED\.authority_event_id/);
  assert.doesNotMatch(spiced, /queryRetry/);
  assert.match(persistence, /'memory_cross_refs_seeded'/);
  assert.match(persistence, /similarity, authority_event_id/);
  assert.match(migration, /CHECK \(authority_event_id IS NOT NULL\)[\s\S]*NOT VALID/);
  assert.match(migration, /REFERENCES public\.aimos_events\(id\)[\s\S]*ON DELETE RESTRICT/);
  assert.match(migration, /GRANT UPDATE \(similarity, edge_strength, edge_type, authority_event_id\)/);
});
