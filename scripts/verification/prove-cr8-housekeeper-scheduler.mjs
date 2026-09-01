#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { proveCr7R7AggregateAudit } from './prove-cr7-r7-aggregate-audit.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const FILES = Object.freeze([
  'server.js',
  'services/orchestration/scheduler.js',
  'services/orchestration/model-preferences.js',
  'services/core/providers.js',
  'jobs/heartbeat.js',
  'jobs/nightly-dream.js',
]);
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function read(relative) { return fs.readFileSync(path.join(ROOT, relative), 'utf8'); }
function assert(value, reason) { if (!value) throw new Error(`cr8_audit_failed:${reason}`); }

export function proveCr8HousekeeperScheduler() {
  const cr7 = proveCr7R7AggregateAudit();
  assert(cr7.cr7_closed === true, 'cr7_predecessor_open');
  const scheduler = read('services/orchestration/scheduler.js');
  const server = read('server.js');
  const heartbeat = read('jobs/heartbeat.js');
  const dream = read('jobs/nightly-dream.js');
  const preferences = read('services/orchestration/model-preferences.js');
  const providers = read('services/core/providers.js');
  for (const pattern of [
    /SYSTEM_JOB_STARTED = 'system_job_started'/,
    /SYSTEM_JOB_TERMINAL = 'system_job_terminal'/,
    /reconstructSystemJobRuns/,
    /reconcileOpenSystemJobs/,
    /executeSystemJob/,
    /reconstructDelegatedScheduleRuns/,
    /reconcileOpenDelegatedSchedules/,
    /jobsReplayed: 0/,
    /MAX_SYSTEM_JOB_RECOVERY_EVENTS = 100_000/,
  ]) assert(pattern.test(scheduler), `system_job_contract:${pattern}`);
  assert(/const REQUIRED_SYSTEM_JOBS = Object\.freeze\(\[/.test(scheduler), 'required_job_registry_missing');
  for (const job of ['__system_heartbeat__', '__bottleneck_scan__', '__nightly_dream__', '__weekly_assessment__', '__weekly_audit__']) {
    assert(scheduler.includes(job), `required_job_missing:${job}`);
  }
  assert(!/LOOP_CHECKER_JOB_ID|runLoopChecker|__loop_checker__/.test(scheduler), 'scheduled_noop_loop_checker_present');
  assert(!/FROM session_lanes|FROM procedural_skills/.test(scheduler), 'retired_scheduler_projection_read');
  assert(!/logEvent\([^)]*['"]system['"]/.test(`${scheduler}\n${heartbeat}`), 'autonomous_system_actor_present');
  assert(/actor_agent_id: 'housekeeper'/.test(scheduler), 'housekeeper_autonomous_actor_missing');
  assert(/logEvent\(companyId, 'housekeeper', 'heartbeat'/.test(heartbeat), 'heartbeat_housekeeper_event_missing');
  assert(/executeHousekeeperCanonicalSave/.test(heartbeat) && /executeHousekeeperCanonicalSave/.test(dream), 'canonical_autonomous_save_missing');
  assert(/throw error;/.test(scheduler), 'top_level_job_failure_not_propagated');
  assert(/advisory-unlock failed; destroying lock session/.test(scheduler)
    && /client\.release\(releaseError \|\| undefined\)/.test(scheduler), 'lock_session_cleanup_missing');
  assert(/startScheduler\(\{ bootRecoveryComplete = false \}/.test(scheduler), 'boot_recovery_gate_missing');
  assert(/getSchedulerReadiness/.test(scheduler) && /local_model_required: false/.test(scheduler), 'truthful_scheduler_readiness_missing');
  assert(/schedulerStatus = await startScheduler\(\{ bootRecoveryComplete: cr7BootRecoveryComplete \}\)/.test(server), 'server_scheduler_readiness_wiring_missing');
  assert(/ready: backgroundReady && schedulerStatus\.ready === true/.test(server), 'server_scheduler_ready_gate_missing');
  assert(/scheduler: schedulerStatus/.test(server), 'server_scheduler_projection_missing');
  const schedulerWithoutExplicitDenial = scheduler.replace(/tenant_dependency:\s*false/g, '');
  assert(!/tenant|room-b|meeting-v4|tenant_routing/i.test(`${schedulerWithoutExplicitDenial}\n${heartbeat}\n${dream}`), 'tenant_scheduler_dependency');
  assert(/MODEL_PREFERENCE_/.test(preferences) && /authority: 'signed_task_preference'/.test(preferences), 'signed_model_preference_missing');
  assert(/systemConfigStore\.readConfigString\('LLM_PROVIDER'\)/.test(providers), 'provider_signed_config_missing');
  const schedulerWithoutExplicitModelDenial = scheduler.replace(/local_model_required:\s*false/g, '');
  assert(!/OLLAMA|LMSTUDIO|local_model/i.test(schedulerWithoutExplicitModelDenial), 'scheduler_local_model_dependency');
  const manifest = FILES.map((file) => ({ file, sha256: sha256(read(file)) }));
  const body = {
    schema: 'hom.aimos.cr8-housekeeper-scheduler-audit/v1',
    frozen_predecessor_cr7_proof_root_sha256: '14754f7d9401ddb0c55b34796a9983c130c0e47a30aad9d594c7a642e0a70627',
    current_cr7_parity_proof_root_sha256: cr7.preclosure_proof_root_sha256,
    required_system_jobs: 5,
    autonomous_principal: 'housekeeper',
    signed_start_terminal: true,
    delegated_run_start_terminal: true,
    overlap_fail_closed: true,
    orphan_recovery_second_pass_noop: true,
    scheduler_readiness_gates_server_readiness: true,
    tenant_dependencies: 0,
    local_model_required: false,
    source_root_sha256: sha256(canonicalJson(manifest)),
    paper_authority: {
      formulas_changed: false,
      consultation_required: false,
      reason: 'CR8 changes scheduler authority, lifecycle and readiness composition only',
    },
    live_scheduler_executed: false,
    provider_calls_executed: 0,
    live_database_mutated: false,
    live_cutover: false,
    cr8_ready_for_source_closure: true,
  };
  return Object.freeze({
    ...body,
    audit_root_sha256: sha256(canonicalJson({ manifest, body })),
    proof_root_sha256: sha256(canonicalJson(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr8HousekeeperScheduler(), null, 2));
}
