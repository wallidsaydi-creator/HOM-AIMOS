import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('public governance transport exposes no source-mutation authority', async () => {
  const route = await readFile(new URL('routes/governance.js', ROOT), 'utf8');
  assert.doesNotMatch(route, /\/improvement\/|executeImprovementCycle|activateImprovementArtifact|rollbackImprovementCycle/);
});

test('caller-supplied shell mutation owner is absent from the runtime tree', async () => {
  await assert.rejects(access(new URL('services/learning/meta-improvement.js', ROOT)));
  const nightly = await readFile(new URL('jobs/nightly-dream.js', ROOT), 'utf8');
  assert.doesNotMatch(nightly, /createImprovementCycle|ensureMetaImprovementSchema|collectImprovementSignals/);
});
