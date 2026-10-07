import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  switchWithRollback, validateServiceTransition, validatedRehearsalReceipt,
  validateStagingMarker, AUTHORITY_TABLES,
  assertAuthorityFingerprintEqual, assertSourceLedgerCountsMatch,
  validateRetirementReceipt,
} from '../../scripts/db/cutover-canonical.mjs';
import { buildUserServiceManifest } from '../../scripts/service/manage-user-service.mjs';
import { secureClusterPaths } from '../../scripts/db/secure-cluster.mjs';

function definition(postgresPort) {
  return {
    instance: 'canonical', postgres_port: postgresPort, port: 9100,
    database: 'aimos', label: 'com.hom.aimos',
    source_root: '/tmp/aimos-source', node_path: '/bin/node',
    unit_path: '/tmp/com.hom.aimos.plist',
    manifest_path: '/tmp/service.json', postgres_bin: postgresPort === 5432
      ? null : '/tmp/postgresql-18/bin', platform: 'darwin',
  };
}

function health(postgresPort) {
  return { ready: true, runtime: {
    database_name: 'aimos', server_port: 9100,
    postgres_port: postgresPort,
  } };
}

test('service switch accepts only the same canonical service on private PostgreSQL', () => {
  const previous = definition(5432);
  const next = definition(55432);
  assert.equal(validateServiceTransition(previous, next), true);
  assert.throws(() => validateServiceTransition(previous,
    { ...next, source_root: '/tmp/other-source' }),
  /canonical_cutover_service_transition_invalid/);
  assert.throws(() => validateServiceTransition(previous,
    { ...next, database: 'other' }),
  /canonical_cutover_service_transition_invalid/);
});

test('post-switch verification failure restores the previous service and checks readiness', async () => {
  const calls = [];
  const previous = definition(5432);
  const next = definition(55432);
  const install = async (options) => {
    calls.push(options.postgresPort);
    return { health: health(options.postgresPort) };
  };
  await assert.rejects(switchWithRollback(previous, next, {
    install,
    verifyAfterSwitch: async () => { throw new Error('signed_probe_failed'); },
  }), /signed_probe_failed/);
  assert.deepEqual(calls, [55432, 5432]);
});

test('failed target install restarts a source service stopped for the final archive', async () => {
  const calls = [];
  const previous = definition(5432);
  const next = definition(55432);
  await assert.rejects(switchWithRollback(previous, next, {
    install: async (options) => {
      calls.push(options.postgresPort);
      if (options.postgresPort === 55432) throw new Error('target_install_failed');
      return { health: health(5432) };
    },
  }), /target_install_failed/);
  assert.deepEqual(calls, [55432, 5432]);
});

test('rollback failure preserves both errors', async () => {
  const previous = definition(5432);
  const next = definition(55432);
  await assert.rejects(switchWithRollback(previous, next, {
    install: async (options) => {
      if (options.postgresPort === 5432) throw new Error('old_service_restart_failed');
      return { health: health(55432) };
    },
    verifyAfterSwitch: async () => { throw new Error('target_proof_failed'); },
  }), (error) => error instanceof AggregateError
      && error.errors.length === 2
      && error.errors[0].message === 'target_proof_failed'
      && error.errors[1].message === 'old_service_restart_failed');
});

test('persistent apply requires an exact owner-only completed rehearsal receipt', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'aimos-cutover-receipt-'));
  const file = path.join(directory, 'receipt.json');
  const prepared = { archiveSha256: 'a'.repeat(64),
    aclArchiveSha256: 'b'.repeat(64), schemaSha256: 'c'.repeat(64),
    companion: { count: 515 }, preflight: { aclEntries: 0 } };
  const receipt = { result: 'isolated_restore_pass',
    archive_sha256: prepared.archiveSha256,
    acl_archive_sha256: prepared.aclArchiveSha256,
    schema_sha256: prepared.schemaSha256,
    archive_acl_entries: 515, applied_migrations: 4,
    retained_rows: { memories: 4770, events: 64023,
      request_receipts: 180 },
    identity: { master_count: 1, master_hash: 'd'.repeat(32),
      agent_count: 2, agent_hash: 'e'.repeat(32) },
    boundary: { force_rls_tables: 17, reader_restrictive_policies: 17,
      legacy_login_retired: true },
    serving_roles: ['agent_runtime', 'aimos_service_reader',
      'aimos_identity_writer'], scratch_cleaned: true };
  try {
    assert.throws(() => validatedRehearsalReceipt(null, prepared),
      /canonical_cutover_rehearsal_receipt_required/);
    writeFileSync(file, JSON.stringify(receipt), { mode: 0o600 });
    assert.equal(validatedRehearsalReceipt(file, prepared).archive_acl_entries, 515);
    writeFileSync(file, JSON.stringify({ ...receipt,
      schema_sha256: 'f'.repeat(64) }), { mode: 0o600 });
    assert.throws(() => validatedRehearsalReceipt(file, prepared),
      /canonical_cutover_rehearsal_receipt_invalid/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('source event and request-receipt divergence rejects a stale archive', () => {
  const rehearsal = { retained_rows: { events: 64023,
    request_receipts: 180 } };
  assert.equal(assertSourceLedgerCountsMatch(rehearsal,
    { events: 64023, request_receipts: 180 }), true);
  assert.throws(() => assertSourceLedgerCountsMatch(rehearsal,
    { events: 64024, request_receipts: 180 }),
  /canonical_cutover_source_signed_ledger_count_diverged/);
  assert.throws(() => assertSourceLedgerCountsMatch(rehearsal,
    { events: 64023, request_receipts: 181 }),
  /canonical_cutover_source_signed_ledger_count_diverged/);
});

test('full authority comparison includes signed events and durable receipts', () => {
  const baseline = Object.fromEntries(AUTHORITY_TABLES.map((name) => [name,
    { count: 1, hash: 'a'.repeat(32) }]));
  assert.equal(assertAuthorityFingerprintEqual(baseline, structuredClone(baseline)), true);
  for (const name of ['aimos_events', 'aimos_request_receipts']) {
    const changed = structuredClone(baseline);
    changed[name].hash = 'b'.repeat(32);
    assert.throws(() => assertAuthorityFingerprintEqual(baseline, changed,
      'source_authority_changed_before_switch'),
    new RegExp(`canonical_cutover_source_authority_changed_before_switch:${name}`));
  }
});

test('abandoned target reset binds a generation, source service and exact PGDATA', () => {
  const previous = definition(5432);
  const context = { state_root: path.join(os.tmpdir(), 'aimos-reset-fixture') };
  const generation = 'a'.repeat(32);
  const marker = { schema: 'hom.aimos.canonical-cutover-staging/v1',
    generation, target_data: secureClusterPaths(context.state_root).data,
    target_postgres_port: 55432,
    source_service_sha256: buildUserServiceManifest(previous).configuration_sha256,
    created_credential_services: ['aimos_cluster_admin_password',
      'aimos_service_reader_db_password'] };
  assert.equal(validateStagingMarker(marker,
    { context, previous, generation }), true);
  assert.throws(() => validateStagingMarker({ ...marker,
    target_data: '/tmp/other-data' }, { context, previous, generation }),
  /canonical_cutover_staging_marker_invalid/);
  assert.throws(() => validateStagingMarker({ ...marker,
    created_credential_services: [...marker.created_credential_services,
      'agent_runtime_db_password'] }, { context, previous, generation }),
  /canonical_cutover_staging_marker_invalid/);
});

test('source database retirement requires a proven private switch and final archive binding', () => {
  const installed = definition(55432);
  const fingerprint = Object.fromEntries(AUTHORITY_TABLES.map((name) => [name,
    { count: 1, hash: 'a'.repeat(32) }]));
  const receipt = {
    schema: 'hom.aimos.canonical-cutover-rollback/v1',
    status: 'switched', switched_at: new Date(0).toISOString(),
    target: buildUserServiceManifest(installed),
    source_database: { oid: '12345', datname: 'aimos', owner: 'owner',
      datallowconn: true },
    archive_path: '/tmp/owner-only-archive.dump',
    archive_sha256: 'b'.repeat(64),
    signed_proof: { result: 'restored_identity_signed_proof_pass',
      agent_id: 'actor' },
    actor_authority: { actor: 'actor', write_allowed: true,
      clearance_ceiling: 5 },
    post_switch_proof: { result: 'cutover_serving_signed_proof_pass',
      signed_save: 200, terminal_event_id: 'terminal-1' },
    source_authority: fingerprint,
  };
  assert.equal(validateRetirementReceipt(receipt, installed, 1), true);
  assert.throws(() => validateRetirementReceipt(receipt, installed, -1),
    /canonical_cutover_retirement_receipt_invalid/);
  assert.throws(() => validateRetirementReceipt({ ...receipt,
    status: 'source_retired' }, installed, 1),
  /canonical_cutover_retirement_receipt_invalid/);
  assert.throws(() => validateRetirementReceipt({ ...receipt,
    post_switch_proof: { result: 'cutover_serving_signed_proof_pass' } },
  installed, 1),
  /canonical_cutover_retirement_receipt_invalid/);
  assert.throws(() => validateRetirementReceipt({ ...receipt,
    source_authority: { ...fingerprint, aimos_request_receipts: undefined } },
  installed, 1),
  /canonical_cutover_retirement_source_fingerprint_invalid:aimos_request_receipts/);
});
