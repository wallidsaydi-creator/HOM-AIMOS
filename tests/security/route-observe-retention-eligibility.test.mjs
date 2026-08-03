import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

const MEMORY_READ_PATHS = [
  'jobs/heartbeat.js',
  'jobs/boot-integrity.js',
  'routes/aimos-mcp-streamable.js',
  'routes/aimos.js',
  'routes/memory.js',
  'services/observe/svdd-anomaly.js',
  'services/temporal/topic-budget.js',
  'services/temporal/temporal-fingerprinter.js',
  'services/retrieval/embedding-stability.js',
];

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

test('route, job, temporal, and observer memory reads retain every canonical row', async () => {
  for (const relativePath of MEMORY_READ_PATHS) {
    const body = await source(relativePath);
    assert.doesNotMatch(body, /\b(?:[a-z]+\.)?is_active\s*=\s*true\b/i, relativePath);
    assert.doesNotMatch(body, /\b(?:expires_at|valid_until)\b\s*(?:<|<=|>|>=|IS\s+NOT\s+NULL)/i, relativePath);
  }

  const coordination = await source('services/observe/coordination-audit.js');
  const memoryDimension = coordination.slice(
    coordination.indexOf('// Dimension 3: Memory'),
    coordination.indexOf('// Dimension 4: Tools'),
  );
  assert.doesNotMatch(memoryDimension, /is_active|expires_at|valid_until/i);
  assert.match(coordination, /retained_memories:/);

  const drift = await source('services/observe/retrieval-drift-monitor.js');
  const countProjection = drift.slice(
    drift.indexOf('async function getMemoryCounts'),
    drift.indexOf('async function getPreviousSnapshot'),
  );
  assert.doesNotMatch(countProjection, /is_active|expires_at|valid_until/i);
});

test('retention expansion preserves tenant, security, provenance, and bounded diagnostic intent', async () => {
  const route = await source('routes/aimos.js');
  assert.match(route, /WHERE company_id = :company AND clearance_level <= :clearance/);
  assert.match(route, /WHERE company_id = \$1 AND agent_id = \$2 AND memory_type = 'reasoning_state'/);
  assert.match(route, /m\.company_id = cr\.company_id/);
  assert.match(route, /m\.supersedes_id/);

  const boot = await source('jobs/boot-integrity.js');
  assert.match(boot, /WHERE company_id = \$1 AND embedding IS NOT NULL/);

  const fingerprints = await source('services/temporal/temporal-fingerprinter.js');
  assert.match(fingerprints, /company_id = \$1 AND agent_id = \$2/);
  assert.match(fingerprints, /COALESCE\(ts_created, created_at\) > NOW\(\) - INTERVAL '1 hour' \* \$3/);
});

test('registry eligibility remains independent while duplicate mutable message transport stays retired', async () => {
  const coordination = await source('services/observe/coordination-audit.js');
  assert.match(coordination, /FROM agent_registry[\s\S]*WHERE company_id = \$1 AND is_active = true/);
  assert.match(coordination, /FROM tool_registry[\s\S]*WHERE company_id = \$1 AND is_active = true/);

  const route = await source('routes/aimos.js');
  assert.doesNotMatch(route, /router\.(?:get|post|put|delete)\('\/agent-messages?/);

  const runner = await source('services/orchestration/agent-runner.js');
  assert.match(runner, /memory_type: 'agent_message'/);
  assert.doesNotMatch(runner, /DELETE\s+FROM\s+aimos_memories|expires_at\s*(?:<|>|=)/i);
});
