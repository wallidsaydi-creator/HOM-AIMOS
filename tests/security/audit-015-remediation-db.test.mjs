// Real PostgreSQL fault qualification owned by run-isolated-security.mjs.
// This process never opens a product listener or accesses credential custody.
import assert from 'node:assert/strict';
import pg from 'pg';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { runMigrations, getMigrationFiles, applyMigration, parseMigrationIndexContract, verifyMigrationIndex } from '../../migrations/run.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const expectedDatabase = process.argv[process.argv.indexOf('--aimos-db') + 1];
if (!/^aimos_test_security_aud015_[0-9]+_[a-f0-9]{6}$/.test(expectedDatabase)) throw new Error('audit_database_invalid');
const url = new URL(resolveAimosDatabaseUrl());
if (url.pathname !== `/${expectedDatabase}`) throw new Error('audit_database_route_mismatch');
const pool = new pg.Pool({ connectionString: url.href, max: 4, connectionTimeoutMillis: 3000 });
let owner;
let blocker;
let worker;
const result = { database: expectedDatabase, product_listener_started: false,
  genesis_invoked: false, new_identity: false, canonical_writes: false };

async function qualifyNativeBaseline() {
  const baseline = process.argv[process.argv.indexOf('--baseline-db') + 1];
  assert.equal(baseline, `${expectedDatabase}_baseline`);
  const baselineUrl = new URL(url.href); baselineUrl.pathname = `/${baseline}`;
  const nativePool = new pg.Pool({ connectionString: baselineUrl.href, max: 4 });
  let observer, held, roleBefore, upgrade;
  const roleState = async () => {
    // Password hashes remain in process memory; only the aggregate commitment
    // is retained. No global role or membership mutation is authorized.
    const roles = (await observer.query('SELECT * FROM pg_authid ORDER BY oid')).rows;
    const memberships = (await observer.query('SELECT * FROM pg_auth_members ORDER BY roleid,member,grantor')).rows;
    return { roles, memberships, sha256: createHash('sha256').update(JSON.stringify({ roles, memberships })).digest('hex') };
  };
  try {
    observer = await nativePool.connect();
    assert.equal((await observer.query('SELECT current_database() AS db')).rows[0].db, baseline);
    roleBefore = await roleState();
    const current = (await observer.query('SELECT current_user AS name')).rows[0].name;
    const byName = new Map(roleBefore.roles.map(r => [r.rolname, r]));
    for (const name of ['aimos_app','aimos_app_ro','aimos_flag_signer','agent_runtime',
      'pgsodium_keymaker','pgsodium_keyholder','pgsodium_keyiduser']) assert(byName.has(name), `existing_role_required:${name}`);
    assert(!byName.has('piro_runtime'), 'legacy_role_rename_must_be_noop');
    for (const [role, member] of [['pgsodium_keyholder','pgsodium_keymaker'],
      ['pgsodium_keyiduser','pgsodium_keyholder'],['pgsodium_keyiduser','pgsodium_keymaker']]) {
      assert(roleBefore.memberships.some(m => m.roleid === byName.get(role).oid
        && m.member === byName.get(member).oid && m.grantor === byName.get(current).oid
        && m.admin_option === false && m.inherit_option === true && m.set_option === true),
      'extension_membership_must_already_exist_with_same_grantor');
    }
    assert.equal((await observer.query("SELECT to_regclass('public.schema_migrations') IS NULL AS absent")).rows[0].absent, true);
    const fresh = await runMigrations(nativePool, { verbose: false });
    assert.equal(fresh.applied.length, getMigrationFiles().length); assert.equal(fresh.skipped.length, 0);
    assert.equal((await roleState()).sha256, roleBefore.sha256);
    const identities = (await observer.query('SELECT count(*)::int AS n FROM agent_identity')).rows[0].n;
    const memories = (await observer.query('SELECT count(*)::int AS n FROM aimos_memories')).rows[0].n;
    const masters = (await observer.query('SELECT count(*)::int AS n FROM aimos_master_identity')).rows[0].n;
    assert.equal(identities, 0); assert.equal(memories, 0); assert.equal(masters, 0);
    const rerun = await runMigrations(nativePool, { verbose: false });
    assert.equal(rerun.applied.length, 0); assert.equal(rerun.skipped.length, getMigrationFiles().length);

    const filename = '011-hnsw-embedding-index.sql';
    const sql = readFileSync(new URL(`../../migrations/${filename}`, import.meta.url), 'utf8');
    const contract = parseMigrationIndexContract(sql);
    // Explicit scratch predecessor/fault state, not a historical upgrade claim:
    // this one derived index and its marker are absent before the native retry.
    await observer.query('DROP INDEX public.idx_aimos_memories_embedding_hnsw');
    await assert.rejects(runMigrations(nativePool, { verbose: false }), /migration_index_not_valid/);
    assert.equal((await observer.query('SELECT count(*)::int AS n FROM schema_migrations WHERE filename=$1', [filename])).rows[0].n, 1);
    await observer.query('DELETE FROM schema_migrations WHERE filename=$1', [filename]);
    held = await nativePool.connect(); await held.query('BEGIN');
    await held.query('LOCK TABLE public.aimos_memories IN SHARE UPDATE EXCLUSIVE MODE');
    let settled = false;
    upgrade = runMigrations(nativePool, { verbose: false }).then(
      value => { settled = true; return { value }; }, error => { settled = true; return { error }; });
    const deadline = Date.now() + 5000; let runnerPid;
    while (!runnerPid) {
      const waiting = (await observer.query(`SELECT a.pid FROM pg_stat_activity a
        WHERE a.datname=current_database() AND a.wait_event_type='Lock'
          AND a.query LIKE '%CREATE INDEX CONCURRENTLY%' AND a.query LIKE '%idx_aimos_memories_embedding_hnsw%'
          AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory' AND l.granted)`)).rows;
      if (waiting.length === 1) runnerPid = waiting[0].pid;
      else {
        assert.equal(settled, false, 'native_upgrade_must_be_pending');
        if (Date.now() > deadline) throw new Error('native_upgrade_lock_observation_timeout');
        await new Promise(r => setTimeout(r, 20));
      }
    }
    await assert.rejects(runMigrations(nativePool, { verbose: false }), /migration_runner_already_active/);
    await held.query('ROLLBACK'); held.release(); held = null;
    const completed = await upgrade; if (completed.error) throw completed.error;
    assert.deepEqual(completed.value.applied, [filename]);
    assert.equal(await verifyMigrationIndex(observer, contract), true);
    assert.deepEqual((await observer.query('SELECT checksum FROM schema_migrations WHERE filename=$1', [filename])).rows,
      [{ checksum: createHash('sha256').update(sql).digest('hex') }]);
    // This is the same read-authorized installation owner used by the CLI.
    // The four mechanism cases separately exercise SELECT-only agent_runtime.
    await observer.query('BEGIN READ ONLY');
    const checked = await runMigrations(observer, { check: true, verbose: false });
    await observer.query('COMMIT'); assert.equal(checked.pending.length, 0);
    assert.equal((await roleState()).sha256, roleBefore.sha256);
    return { database: baseline, migrations_applied: fresh.applied.length, idempotent_rerun: true,
      applied_missing_index_denied: true, pending_upgrade: filename, native_upgrade_backend_pid: runnerPid,
      advisory_lock_observed_during_actual_concurrent_ddl: true, competing_upgrade_denied: true,
      identity_rows: identities, memory_rows: memories, master_rows: masters,
      global_role_and_membership_commitment: roleBefore.sha256, global_authority_unchanged: true,
      baseline_check_principal: 'existing_migration_owner_read_only',
      custody_or_product_installer_invoked: false, predecessor_state: 'explicitly manufactured scratch-only missing-index/marker state' };
  } finally {
    try {
      if (held) { await held.query('ROLLBACK'); held.release(); }
      if (upgrade) await upgrade;
      if (observer) await observer.query('ROLLBACK');
      if (roleBefore) assert.equal((await roleState()).sha256, roleBefore.sha256, 'global_role_state_changed');
    } finally { if (observer) observer.release(); await nativePool.end(); }
  }
}
try {
  owner = await pool.connect();
  assert.equal((await owner.query('SELECT current_database() AS name')).rows[0].name, expectedDatabase);
  await owner.query('BEGIN READ ONLY');
  await owner.query('SET LOCAL ROLE agent_runtime');
  const absent = await runMigrations(owner, { check: true, verbose: false });
  assert.equal(absent.trackingTableExists, false);
  assert.equal(absent.backfilled, 0);
  await owner.query('COMMIT');
  assert.equal((await owner.query("SELECT to_regclass('public.schema_migrations') IS NULL AS absent")).rows[0].absent, true);
  result.readonly_absent_tracking_table = true;

  await owner.query('CREATE TABLE schema_migrations (filename text PRIMARY KEY, checksum text)');
  await owner.query('GRANT SELECT ON schema_migrations TO agent_runtime');
  const filename = getMigrationFiles()[0];
  await owner.query('INSERT INTO schema_migrations VALUES ($1,NULL)', [filename]);
  await owner.query('BEGIN READ ONLY');
  await owner.query('SET LOCAL ROLE agent_runtime');
  const legacy = await runMigrations(owner, { check: true, verbose: false });
  assert.deepEqual(legacy.legacyUnverified, [filename]);
  assert.equal(legacy.backfilled, 0);
  await owner.query('COMMIT');
  assert.equal((await owner.query('SELECT checksum FROM schema_migrations WHERE filename=$1', [filename])).rows[0].checksum, null);
  result.readonly_legacy_checksum_preserved = true;

  const validHash = createHash('sha256').update(readFileSync(new URL(`../../migrations/${filename}`, import.meta.url))).digest('hex');
  await owner.query('UPDATE schema_migrations SET checksum=$1 WHERE filename=$2', [validHash, filename]);
  await owner.query('BEGIN READ ONLY');
  await owner.query('SET LOCAL ROLE agent_runtime');
  await runMigrations(owner, { check: true, verbose: false });
  await owner.query('COMMIT');
  await owner.query('UPDATE schema_migrations SET checksum=$1 WHERE filename=$2', ['a'.repeat(64), filename]);
  await owner.query('BEGIN READ ONLY');
  await owner.query('SET LOCAL ROLE agent_runtime');
  await assert.rejects(runMigrations(owner, { check: true, verbose: false }), /modified after it was applied/);
  await owner.query('COMMIT');
  await owner.query('UPDATE schema_migrations SET checksum=$1 WHERE filename=$2', [validHash, filename]);
  result.readonly_checksum_drift_rejected = true;

  await owner.query('CREATE TABLE aud015_rows (id integer, payload text)');
  await owner.query("INSERT INTO aud015_rows VALUES (1,'retained qualification row')");
  await owner.query("SELECT pg_advisory_lock(hashtextextended('hom.aimos.migrations',0))");
  await assert.rejects(runMigrations(pool, { verbose: false }), /migration_runner_already_active/);
  result.competing_runner_denied_before_ddl = true;

  await applyMigration(owner, 'audit-015-valid.sql', 'CREATE INDEX CONCURRENTLY IF NOT EXISTS aud015_valid ON public.aud015_rows (id);');
  assert.equal((await owner.query("SELECT count(*)::int AS n FROM schema_migrations WHERE filename='audit-015-valid.sql'")).rows[0].n, 1);
  await owner.query('CREATE INDEX aud015_wrong ON aud015_rows (payload)');
  await assert.rejects(applyMigration(owner, 'audit-015-wrong.sql',
    'CREATE INDEX CONCURRENTLY IF NOT EXISTS aud015_wrong ON public.aud015_rows (id);'), /migration_index_definition_mismatch/);
  result.same_name_wrong_definition_denied = true;
  await owner.query('ALTER TABLE aud015_rows ADD COLUMN "i""d" integer');
  await owner.query('CREATE INDEX aud015_quoted_column ON aud015_rows ("i""d")');
  await assert.rejects(applyMigration(owner, 'audit-015-quoted-column.sql',
    'CREATE INDEX CONCURRENTLY IF NOT EXISTS aud015_quoted_column ON public.aud015_rows (id);'), /migration_index_.*unsupported/);
  await owner.query('CREATE TABLE "aud015_""rows" (id integer)');
  await owner.query('CREATE INDEX aud015_quoted_relation ON "aud015_""rows" (id)');
  await assert.rejects(applyMigration(owner, 'audit-015-quoted-relation.sql',
    'CREATE INDEX CONCURRENTLY IF NOT EXISTS aud015_quoted_relation ON public.aud015_rows (id);'), /migration_index_.*unsupported/);
  result.quoted_identifier_substitution_denied = true;
  await assert.rejects(applyMigration(owner, 'audit-015-late-drop.sql',
    'CREATE INDEX CONCURRENTLY aud015_late_drop ON public.aud015_rows (id); DROP INDEX aud015_late_drop;'), /migration_index_not_valid/);
  assert.equal((await owner.query("SELECT count(*)::int AS n FROM schema_migrations WHERE filename IN ('audit-015-quoted-column.sql','audit-015-quoted-relation.sql','audit-015-late-drop.sql')")).rows[0].n, 0);
  result.final_validation_prevents_false_applied_row = true;

  blocker = await pool.connect();
  worker = await pool.connect();
  await blocker.query('BEGIN');
  await blocker.query("INSERT INTO aud015_rows VALUES (2,'held writer')");
  const pid = (await worker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  const sql = 'CREATE INDEX CONCURRENTLY IF NOT EXISTS aud015_interrupted ON public.aud015_rows (id);';
  const build = applyMigration(worker, 'audit-015-interrupted.sql', sql).then(
    () => ({ succeeded: true }), (error) => ({ succeeded: false, error }),
  );
  const deadline = Date.now() + 5000;
  while (!(await owner.query("SELECT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('public.aud015_interrupted')) AS exists")).rows[0].exists) {
    if (Date.now() > deadline) throw new Error('concurrent_index_phase_timeout');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal((await owner.query('SELECT pg_cancel_backend($1) AS cancelled', [pid])).rows[0].cancelled, true);
  const interrupted = await build;
  assert.equal(interrupted.succeeded, false);
  assert.equal(interrupted.error.cause.code, '57014');
  await blocker.query('ROLLBACK');
  assert.equal((await owner.query("SELECT indisvalid FROM pg_index WHERE indexrelid='aud015_interrupted'::regclass")).rows[0].indisvalid, false);
  await assert.rejects(applyMigration(owner, 'audit-015-interrupted.sql', sql), /migration_index_not_valid/);
  assert.equal((await owner.query("SELECT count(*)::int AS n FROM schema_migrations WHERE filename IN ('audit-015-wrong.sql','audit-015-interrupted.sql')")).rows[0].n, 0);
  result.interrupted_build_left_invalid_index_and_no_applied_row = true;
  result.invalid_same_name_retry_denied = true;
  await owner.query('DROP INDEX public.aud015_interrupted');
  await applyMigration(owner, 'audit-015-interrupted.sql', sql);
  assert.equal((await owner.query("SELECT count(*)::int AS n FROM schema_migrations WHERE filename='audit-015-interrupted.sql'")).rows[0].n, 1);
  result.explicit_derived_index_repair_then_retry_passed = true;
  await assert.rejects(applyMigration(owner, 'audit-015-valid.sql',
    'BEGIN; CREATE TABLE aud015_transaction_owner (id integer); COMMIT;'), /duplicate key/);
  assert.equal((await owner.query("SELECT to_regclass('public.aud015_transaction_owner') IS NULL AS absent")).rows[0].absent, true);
  result.embedded_transaction_does_not_escape_owner = true;
  await owner.query("SELECT pg_advisory_unlock(hashtextextended('hom.aimos.migrations',0))");
  result.native_baseline_and_upgrade = await qualifyNativeBaseline();
  console.log(JSON.stringify({ ...result, observed_at: new Date().toISOString() }, null, 2));
} finally {
  if (blocker) { await blocker.query('ROLLBACK').catch(() => {}); blocker.release(); }
  if (worker) worker.release();
  if (owner) owner.release();
  await pool.end();
}
