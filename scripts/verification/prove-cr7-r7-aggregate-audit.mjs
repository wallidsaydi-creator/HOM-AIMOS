#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectServiceCensus } from '../architecture/sync-service-inventory.mjs';
import { verifyGenesisManifest } from '../verify-genesis-manifest.mjs';
import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';
import { proveCr7R1ExistingLedgerOwners } from './prove-cr7-r1-existing-ledger-owners.mjs';
import { proveCr7R2DatabaseLocalClosure } from './prove-cr7-r2-database-local-closure.mjs';
import { proveCr7R3SecurityAuthority } from './prove-cr7-r3-security-authority.mjs';
import { proveCr7R4OperationalAudit } from './prove-cr7-r4-operational-audit.mjs';
import { proveCr7R5MaterialEffectAudit } from './prove-cr7-r5-material-effect-audit.mjs';
import { proveCr7R6RecoverySetEquality } from './prove-cr7-r6-recovery-set-equality.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const VERIFIER_FILES = Object.freeze([
  'scripts/verification/prove-cr7-durable-action-census.mjs',
  'scripts/verification/prove-cr7-r1-existing-ledger-owners.mjs',
  'scripts/verification/prove-cr7-r2-database-local-closure.mjs',
  'scripts/verification/prove-cr7-r3-security-authority.mjs',
  'scripts/verification/prove-cr7-r4-operational-audit.mjs',
  'scripts/verification/prove-cr7-r5-material-effect-audit.mjs',
  'scripts/verification/prove-cr7-r6-recovery-set-equality.mjs',
]);

function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function read(relative) { return fs.readFileSync(path.join(ROOT, relative), 'utf8'); }
function assert(value, reason) { if (!value) throw new Error(`cr7_r7_audit_failed:${reason}`); }

export function proveCr7R7AggregateAudit() {
  const census = scanCr7EffectCensus();
  const r1 = proveCr7R1ExistingLedgerOwners();
  const r2 = proveCr7R2DatabaseLocalClosure();
  const r3 = proveCr7R3SecurityAuthority();
  const r4 = proveCr7R4OperationalAudit();
  const r5 = proveCr7R5MaterialEffectAudit();
  const r6 = proveCr7R6RecoverySetEquality();
  const genesis = verifyGenesisManifest({ brainRoot: ROOT });
  const services = collectServiceCensus(ROOT);
  const template = JSON.parse(read('architecture-authority.template.json'));
  const manifest = JSON.parse(read('hom-architecture-manifest.json'));
  const open = census.effects.filter((effect) => effect.ownership_status === 'OPEN_UNRECONCILED');
  const statusTotal = Object.values(census.by_ownership_status).reduce((sum, count) => sum + Number(count), 0);
  assert(census.effect_site_count === 104 && census.unclassified_effect_site_count === 0, 'census_totality');
  assert(open.length === 0 && statusTotal === census.effect_site_count, 'effect_partition');
  assert(r1.verdict_counts.ATOMIC === 23 && r1.verdict_counts.COMPLETE_START_TERMINAL === 14
    && r1.verdict_counts.PARTIAL === 0 && r1.verdict_counts.OPEN === 0, 'r1_ownership');
  assert(r2.valid === true && r2.migration_added === false, 'r2_database');
  assert(r3.verdict === 'PROVED', 'r3_security');
  assert(r4.current_open_database_effect_count === 0 && r4.paper_authority.formulas_changed === false, 'r4_operational');
  assert(r5.current_open_effect_count === 0 && r5.paper_authority.formulas_changed === false, 'r5_material');
  assert(r6.reconstruction.exactSetEquality === true && r6.boot_recovery_precedes_listen === true, 'r6_recovery');
  assert(genesis.version === 26 && genesis.corpusRoot === template.genesis_corpus.corpus_root, 'genesis_authority');
  assert(services.serviceCount === 295 && services.digest === template.service_inventory.census_sha256
    && services.digest === manifest.service_inventory.census_sha256, 'service_inventory');

  const isolatedRunner = read('scripts/test/run-isolated-security.mjs');
  const isolatedRunnerAdmissible = !/scripts\/genesis-install\.mjs/.test(isolatedRunner)
    && !/DROP DATABASE/.test(isolatedRunner)
    && !/auth-tier-system-self\.test\.mjs/.test(isolatedRunner);
  assert(isolatedRunnerAdmissible === false, 'isolated_runner_admissibility_detection');

  const frozenRoots = Object.freeze({
    r0_input_census: r2.input_r0_census_root_sha256,
    r1_input_audit: r2.input_r1_audit_root_sha256,
    r2_census: r2.frozen_r2_census_root_sha256,
    r2_owner_audit: r2.frozen_r2_owner_audit_root_sha256,
    r2_proof: r2.frozen_r2_proof_root_sha256,
    r4_a0_census: r4.frozen_a0_input_census_root_sha256,
    r4_a1_audit: r4.frozen_a1_audit_root_sha256,
    r5_a0_census: r5.frozen_corrected_a0_census_root_sha256,
    r6_frozen_r5_proof: r6.frozen_predecessor_r5_proof_root_sha256,
  });
  const currentRoots = Object.freeze({
    executable_census: census.effect_root_sha256,
    r1_audit: r1.audit_root_sha256,
    r2_proof: r2.proof_root_sha256,
    r3_proof: r3.proof_root_sha256,
    r4_proof: r4.proof_root_sha256,
    r5_proof: r5.proof_root_sha256,
    r6_proof: r6.proof_root_sha256,
    genesis_corpus: genesis.corpusRoot,
    service_census: services.digest,
  });
  const verifierManifest = VERIFIER_FILES.map((file) => ({ file, sha256: sha256(read(file)) }));
  const transferredGlobalConditions = Object.freeze([
    'admissible_isolated_zero_memory_database_not_executed',
    'controlled_isolated_process_restart_not_executed',
    'signed_cleanup_and_global_residue_census_not_executed',
  ]);
  const body = {
    schema: 'hom.aimos.cr7-r7-aggregate-preclosure-audit/v1',
    aggregate_static_verdict: 'PASSED',
    cr7_closed: true,
    current_effect_count: census.effect_site_count,
    current_open_effect_count: open.length,
    recovery_family_count: r6.recovery_family_count,
    historical_roots_preserved: frozenRoots,
    current_roots: currentRoots,
    verifier_source_root_sha256: sha256(canonicalJson(verifierManifest)),
    genesis_manifest_version: genesis.version,
    genesis_file_count: genesis.files.length,
    service_count: services.serviceCount,
    isolated_database: {
      required_in_r7: false,
      required_global: true,
      executed: false,
      transferred_to: 'CR11',
      current_runner_admissible: isolatedRunnerAdmissible,
      inadmissible_reasons: [
        'runs_fresh_genesis_and_creates_memory_rows',
        'replays_migrations',
        'direct_drop_database_cleanup',
      ],
    },
    fresh_disposable_brain_created: false,
    live_database_mutated: false,
    live_cutover: false,
    provider_calls_executed: 0,
    blocking_conditions: [],
    transferred_global_conditions: transferredGlobalConditions,
    ready_for_cr7_closure: true,
    paper_authority: {
      inhibitory_error_normalization_sha256: r4.paper_authority.inhibitory_error_normalization_sha256,
      kahneman_reference_point_sha256: r4.paper_authority.kahneman_reference_point_sha256,
      tbsp_sha256: r5.paper_authority.tbsp_sha256,
      formulas_changed: false,
      consultation_required: false,
      reason: 'R7 aggregates already-reviewed proof objects and changes no mathematical service',
    },
  };
  return Object.freeze({
    ...body,
    aggregate_audit_root_sha256: sha256(canonicalJson({ frozenRoots, currentRoots, verifierManifest })),
    preclosure_proof_root_sha256: sha256(canonicalJson(body)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R7AggregateAudit(), null, 2));
}
