import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ROOT = new URL('../../', import.meta.url);
const RUNTIME_SERVICES = [
  'services/learning/error-normalizer.js',
  'services/observe/architecture-registry.js',
  'services/observe/retrieval-drift-monitor.js',
  'services/core/rule-hierarchy.js',
  'services/orchestration/trust-router.js',
];

const RUNTIME_DDL = /\b(?:CREATE|ALTER|DROP|TRUNCATE)\s+(?:TABLE|INDEX|SEQUENCE|TYPE|SCHEMA)\b/i;

test('learning and observability services never own runtime schema mutation', async () => {
  for (const servicePath of RUNTIME_SERVICES) {
    const source = await readFile(new URL(servicePath, ROOT), 'utf8');
    assert.doesNotMatch(source, RUNTIME_DDL, `${servicePath} contains runtime DDL`);
  }
});

test('installer migrations own every verified schema object', async () => {
  const [baseMigration, metaMigration] = await Promise.all([
    readFile(new URL('migrations/001-base-schema.sql', ROOT), 'utf8'),
    readFile(new URL('migrations/003-hyperbrain-meta-improvement.sql', ROOT), 'utf8'),
  ]);

  for (const tableName of [
    'skill_running_stats',
    'model_registry',
    'ai_debt_register',
    'aimos_retrieval_drift_snapshots',
    'rule_hierarchy',
    'agent_trust',
  ]) {
    assert.match(
      baseMigration,
      new RegExp(`CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${tableName}\\b`, 'i'),
      `001-base-schema.sql must own ${tableName}`,
    );
  }

  for (const tableName of ['improvement_cycles', 'mutation_artifacts', 'meta_versions']) {
    assert.match(
      metaMigration,
      new RegExp(`CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${tableName}\\b`, 'i'),
      `003-hyperbrain-meta-improvement.sql must own ${tableName}`,
    );
  }
});

test('runtime schema checks are read-only and fail before business queries', async () => {
  const sources = await Promise.all(
    RUNTIME_SERVICES.map((servicePath) => readFile(new URL(servicePath, ROOT), 'utf8')),
  );

  for (const source of sources) {
    assert.match(source, /FROM\s+[a-z_]+\s+WHERE\s+false/i);
  }
});
