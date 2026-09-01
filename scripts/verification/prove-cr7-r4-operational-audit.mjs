#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const R4_SOURCE_FILES = Object.freeze([
  'routes/agent-execution.js', 'routes/aimos.js', 'routes/mcp.js',
  'services/orchestration/run-metadata.js', 'services/orchestration/session-runner.js',
  'services/orchestration/agent-bdi-state.js', 'services/orchestration/agent-runner.js',
  'services/orchestration/agent-prompts.js', 'services/orchestration/interaction-graph-healer.js',
  'services/learning/agent-learning.js', 'services/learning/dual-skill-bank.js',
  'services/learning/error-normalizer.js', 'services/learning/prospect-theory.js',
  'services/observe/energy-budget.js', 'services/observe/retrieval-drift-monitor.js',
  'services/observe/semantic-intent.js', 'services/retrieval/embedding-stability.js',
  'services/retrieval/similarity-stats.js', 'services/security/knowledge-gate.js',
  'services/write/transformation-cache.js',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function read(relative) {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

function assert(value, reason) {
  if (!value) throw new Error(`cr7_r4_audit_failed:${reason}`);
}

const EXISTING_ATOMIC_CONTRACTS = Object.freeze({
  'services/core/directive-claims.js': {
    expectedEffects: 5,
    patterns: [/agentPool/, /logEvent\([\s\S]*\{ client, authority \}/, /last_event_id/, /authority_event_id/],
  },
  'jobs/nightly-dream.js': {
    expectedEffects: 1,
    patterns: [/withTransaction/, /dream_summary_layer_created/, /authority_event_id/],
  },
  'services/dream/spiced-consolidator.js': {
    expectedEffects: 1,
    patterns: [/withTransaction/, /memory_cross_refs/, /authority_event_id/, /\{ client, returnReceipt: true \}/],
  },
  'services/temporal/retrieval-pheromone.js': {
    expectedEffects: 1,
    patterns: [/withTransaction/, /retrieval_pheromone_deposited/, /\{ client \}/],
  },
});

export function proveCr7R4OperationalAudit() {
  const census = scanCr7EffectCensus();
  const openDatabase = census.effects.filter((effect) => (
    effect.ownership_status === 'OPEN_UNRECONCILED'
    && effect.effect_class === 'durable_database'
  ));
  assert(openDatabase.length === 0, `open_database_count:${openDatabase.length}`);
  const r4Effects = census.effects.filter((effect) => effect.ownership_status === 'R4_OPERATIONAL_ATOMIC');
  assert(r4Effects.length === 10, `r4_atomic_count:${r4Effects.length}`);

  const promoted = [];
  for (const [file, contract] of Object.entries(EXISTING_ATOMIC_CONTRACTS)) {
    const body = read(file);
    for (const pattern of contract.patterns) assert(pattern.test(body), `existing_atomic_contract:${file}:${pattern}`);
    const effects = r4Effects.filter((effect) => effect.file === file);
    assert(effects.length === contract.expectedEffects, `existing_atomic_effect_count:${file}:${effects.length}`);
    promoted.push(...effects.map((effect) => ({
      effect_id: effect.effect_id,
      file: effect.file,
      line: effect.line,
      verdict: 'ATOMIC_EXISTING',
      owner: file,
      proof_basis: 'restricted_same_transaction_signed_event_and_projection',
    })));
  }

  const scheduler = read('services/orchestration/scheduler.js');
  assert(/markScheduleStatus[\s\S]*withTransaction[\s\S]*schedule_run_reserved/.test(scheduler), 'schedule_status_owner_missing');
  assert(/createScheduledTask[\s\S]*withTransaction[\s\S]*schedule_created/.test(scheduler), 'schedule_create_owner_missing');
  const schedulerAtomic = r4Effects.filter((effect) => effect.file === 'services/orchestration/scheduler.js');
  assert(schedulerAtomic.length === 2, 'scheduler_effect_partition');
  promoted.push(...schedulerAtomic.map((effect) => ({
    effect_id: effect.effect_id,
    file: effect.file,
    line: effect.line,
    verdict: 'ATOMIC_EXISTING',
    owner: 'services/orchestration/scheduler.js',
    proof_basis: 'restricted_same_transaction_signed_schedule_event',
  })));

  const promotedIds = new Set(promoted.map((item) => item.effect_id));
  assert(promotedIds.size === 10, `existing_atomic_total:${promotedIds.size}`);
  const results = [...promoted]
    .sort((left, right) => left.effect_id.localeCompare(right.effect_id));
  const sourceManifest = R4_SOURCE_FILES.map((file) => ({ file, sha256: sha256(read(file)) }));
  const runSource = read('services/orchestration/run-metadata.js');
  const sessionSource = read('services/orchestration/session-runner.js');
  const routeSource = read('routes/aimos.js');
  assert(/agent_run_started/.test(runSource) && /agent_run_terminal/.test(runSource), 'run_event_owner_missing');
  assert(/start_mutation_hash/.test(runSource), 'run_terminal_start_binding_missing');
  assert(/session_lane_started/.test(sessionSource) && /session_lane_terminal/.test(sessionSource), 'session_event_owner_missing');
  assert(/memory_type: 'procedural'/.test(routeSource), 'procedural_canonical_save_missing');
  const body = {
    schema: 'hom.aimos.cr7-r4-operational-database-audit/v1',
    input_census_root_sha256: census.effect_root_sha256,
    frozen_a0_input_census_root_sha256: '8da16bf047890c0209e0ad215252cf684a8f184251779534d000b654c453f42a',
    frozen_a0_open_database_effect_count: 62,
    frozen_a0_open_database_file_count: 27,
    frozen_a1_existing_atomic_count: 10,
    frozen_a1_remediation_required_count: 52,
    frozen_a1_audit_root_sha256: '3438eb141a5a580ebdd8c54bee93a2eb7f40e1d07e5ec9d1f93685a8e2d78046',
    current_open_database_effect_count: openDatabase.length,
    current_r4_atomic_effect_count: promoted.length,
    r4_source_file_count: sourceManifest.length,
    r4_source_root_sha256: sha256(canonicalJson(sourceManifest)),
    verdict_counts: { R4_OPERATIONAL_ATOMIC: promoted.length, OPEN_DATABASE: openDatabase.length },
    reconstruction: {
      algorithm: 'single_pass_event_projection_map',
      time_complexity: 'O(n)',
      space_complexity: 'O(n)',
      committed_transition_to_terminal_bijection: true,
    },
    paper_authority: {
      inhibitory_error_normalization_sha256: '5df20d03d73678f51456442b83eb37b94dd59f77a17afd164bb02b158e32c9a7',
      kahneman_reference_point_sha256: '33f52599bff4484c55986a697739b5d51223f33d4a5f6567798e93defa39e30d',
      formulas_changed: false,
    },
    fresh_disposable_installation_deferred: true,
    results,
  };
  return Object.freeze({
    ...body,
    audit_root_sha256: sha256(canonicalJson(results)),
    proof_root_sha256: sha256(canonicalJson(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R4OperationalAudit(), null, 2));
}
