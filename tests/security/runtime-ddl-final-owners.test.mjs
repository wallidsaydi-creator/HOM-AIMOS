import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

test('final runtime services verify migration schema without issuing DDL', async () => {
  for (const file of [
    'jobs/nightly-dream.js',
    'services/learning/dual-skill-bank.js',
    'services/orchestration/scheduler.js',
  ]) {
    const source = await readFile(new URL(file, ROOT), 'utf8');
    assert.doesNotMatch(source, /\b(?:CREATE\s+(?:TABLE|INDEX)|ALTER\s+TABLE|DROP\s+TABLE|TRUNCATE)\b/i, file);
    assert.match(source, /information_schema\.columns/, file);
  }
});
