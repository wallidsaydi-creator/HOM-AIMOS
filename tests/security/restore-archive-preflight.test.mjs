import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { preflightRestoreToc } from '../../scripts/db/preflight-restore-archive.mjs';

test('metadata gate requires ACL-bearing identity data and company policies', () => {
  const data = [
    'agent_identity', 'aimos_agent_revocation_events', 'aimos_events',
    'aimos_master_identity', 'aimos_memories', 'aimos_system_config',
    'schema_migrations',
  ];
  const policies = [
    'aimos_action_origin_verdicts', 'aimos_cognitive_weight_baselines',
    'aimos_cognitive_weight_projections', 'aimos_events', 'aimos_memories',
    'aimos_memory_epistemic_classifications', 'aimos_memory_origin_bindings',
    'aimos_origin_elevations', 'aimos_origin_ledger_entries',
    'aimos_request_receipts', 'dream_summary_layers', 'entity_memory_edges',
    'integration_tokens', 'procedural_skills', 'recommendation_log',
    'retrieval_pheromones', 'scheduled_tasks',
  ];
  const header = ';     dbname: aimos\n;     Dumped from database version: 18.3\n;     Dumped by pg_dump version: 18.3\n';
  const dataLines = data.map((name, index) => `${index + 1}; 0 1 TABLE DATA public ${name} owner`);
  const policyLines = policies.map((name, index) => `${index + 101}; 3256 1 POLICY public ${name} company_isolation owner`);
  const aclLine = '301; 0 0 ACL public TABLE aimos_memories owner';
  const valid = [header, ...dataLines, ...policyLines, aclLine].join('\n');
  assert.equal(preflightRestoreToc(valid).qualification, 'archive_metadata_only');
  assert.equal(preflightRestoreToc(valid).aclEntries, 1);
  assert.throws(() => preflightRestoreToc([header, ...dataLines, ...policyLines].join('\n')),
    /restore_archive_acl_omitted/);
  assert.throws(() => preflightRestoreToc([header, ...dataLines.slice(1), ...policyLines, aclLine].join('\n')),
    /restore_archive_identity_data_missing:agent_identity/);
  assert.throws(() => preflightRestoreToc([header, ...dataLines, ...policyLines.slice(1), aclLine].join('\n')),
    /restore_archive_company_policies_missing:aimos_action_origin_verdicts/);
});

test('legacy login retirement tolerates absent global role and checks final state', () => {
  const source = readFileSync(new URL('../../migrations/117-retire-legacy-aimos-app-login.sql', import.meta.url), 'utf8');
  assert.match(source, /IF EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app'\)/);
  assert.match(source, /ALTER ROLE aimos_app NOLOGIN PASSWORD NULL/);
  assert.match(source, /SELECT 1 FROM pg_authid/);
  assert.match(source, /legacy_aimos_app_authentication_retained/);
});
