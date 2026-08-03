import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('dream hierarchy projection is hash-bound and signed in one restricted transaction', async () => {
  const [job, migration] = await Promise.all([
    readFile(new URL('jobs/nightly-dream.js', ROOT), 'utf8'),
    readFile(new URL('migrations/079-signed-dream-summary-projection.sql', ROOT), 'utf8'),
  ]);
  assert.match(job, /withTransaction\(async \(client\) =>/);
  assert.match(job, /'dream_summary_layer_created'/);
  assert.match(job, /content_hash, authority_event_id/);
  assert.doesNotMatch(job, /logEvent\(companyId, 'dream_spiced_consolidation', JSON\.stringify/);
  assert.match(migration, /CHECK \(octet_length\(content_hash\) = 32\)[\s\S]*NOT VALID/);
  assert.match(migration, /CHECK \(authority_event_id IS NOT NULL\)[\s\S]*NOT VALID/);
  assert.match(migration, /REFERENCES public\.aimos_events\(id\)[\s\S]*ON DELETE RESTRICT/);
  assert.match(migration, /GRANT SELECT, INSERT ON public\.dream_summary_layers TO agent_runtime/);
});
