import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const MEMORY_PATHS = [
  'services/orchestration/agent-runner.js',
  'services/dream/curator.js',
  'services/write/rpe-gate.js',
  'services/learning/skill-consolidation.js',
];

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

test('owned memory reads do not hard-suppress retained rows', async () => {
  for (const relativePath of MEMORY_PATHS) {
    const body = await source(relativePath);
    assert.doesNotMatch(body, /\b(?:[a-z]+\.)?is_active\s*=\s*true\b/i, relativePath);
    assert.doesNotMatch(body, /\b(?:expires_at|valid_until)\b\s*(?:<|<=|>|>=|IS\s+NOT\s+NULL)/i, relativePath);
  }

  const runner = await source('services/orchestration/agent-runner.js');
  assert.doesNotMatch(runner, /created_at\s*>\s*NOW\(\)\s*-\s*INTERVAL/i);
  assert.match(runner, /persistedAgent\.isActive\s*=\s*true/, 'agent lifecycle state must remain independent of memory retention');
});

test('retention expansion preserves tenant and security predicates', async () => {
  const curator = await source('services/dream/curator.js');
  assert.match(curator, /FROM aimos_memories\s+WHERE company_id = \$2/);

  const rpe = await source('services/write/rpe-gate.js');
  assert.match(rpe, /FROM aimos_memories\s+WHERE company_id = \$2\s+AND embedding IS NOT NULL/);

  const skills = await source('services/learning/skill-consolidation.js');
  assert.match(skills, /JOIN aimos_memories b ON a\.company_id = b\.company_id/);
  assert.match(skills, /WHERE a\.company_id = \$1/);
  assert.match(skills, /WHERE requested\.id = \$1 AND requested\.company_id = \$2/);
  assert.match(skills, /version\.company_id = requested\.company_id/);
});

test('skill promotion resolves the current append-only projection without supersession exclusion', async () => {
  const skills = await source('services/learning/skill-consolidation.js');
  assert.match(skills, /JOIN LATERAL/);
  assert.match(skills, /version\.key = requested\.key/);
  assert.match(skills, /ORDER BY version\.created_at DESC NULLS LAST/);
  assert.doesNotMatch(skills, /has_successor|successor\.supersedes_id\s*=\s*m\.id/);
  assert.match(skills, /supersedes_id:\s*row\.id/);
});

test('agent runner no longer executes the fake antifragility scheduler check', async () => {
  const runner = await source('services/orchestration/agent-runner.js');
  assert.doesNotMatch(runner, /antifragility-scheduler|checkDelegationThreshold/);
});
