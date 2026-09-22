// Executes catalog fault qualification against a schema-only isolated database.
import assert from 'node:assert/strict';
import pg from 'pg';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { auditCurrentOriginLedger, currentOriginSourceContract } from '../../scripts/verification/audit-origin-ledger-current.mjs';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
if (!/^aimos_test_security_aud023_[0-9]+_[a-f0-9]{6}$/.test(database)) throw new Error('audit_database_invalid');
const url = new URL(resolveAimosDatabaseUrl());
if (url.pathname !== `/${database}`) throw new Error('audit_database_route_mismatch');
const pool = new pg.Pool({ connectionString:url.href,max:1,options:'-c pgsodium.enable_event_trigger=on' });
const client = await pool.connect();
try {
  assert.equal((await client.query('SELECT current_database() AS name')).rows[0].name, database);
  assert.equal((await client.query('SELECT count(*)::int AS n FROM aimos_memories')).rows[0].n, 0);
  assert.equal((await client.query('SELECT count(*)::int AS n FROM agent_identity')).rows[0].n, 0);
  for (const source of currentOriginSourceContract().sources.filter(s => s.path.startsWith('migrations/')))
    await client.query('INSERT INTO schema_migrations(filename,checksum) VALUES($1,$2)', [source.path.slice('migrations/'.length),source.sha256]);
  await client.query('BEGIN READ ONLY');
  const clean = await auditCurrentOriginLedger(client);
  await client.query('COMMIT');
  const cases = [
    ['missing_atomic_trigger', 'DROP TRIGGER ob2_atomic_origin_save ON aimos_memory_origin_bindings', /origin_trigger_invalid/],
    ['disabled_atomic_trigger', 'ALTER TABLE aimos_memory_origin_bindings DISABLE TRIGGER ob2_atomic_origin_save', /origin_trigger_invalid/],
    ['broken_deferred_atomicity', `DROP TRIGGER ob2_atomic_origin_save ON aimos_memory_origin_bindings;
      CREATE TRIGGER ob2_atomic_origin_save AFTER INSERT ON aimos_memory_origin_bindings FOR EACH ROW EXECUTE FUNCTION ob2_require_atomic_save_origin()`, /origin_trigger_invalid/],
    ['unapproved_mutating_trigger', `CREATE FUNCTION public.aud023_mutator() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN UPDATE public.aimos_origin_elevations SET maximum_uses=2; RETURN NEW; END $$;
      CREATE TRIGGER aud023_mutator AFTER INSERT ON aimos_origin_ledger_entries FOR EACH ROW EXECUTE FUNCTION aud023_mutator()`, /origin_unapproved_trigger/],
    ['rls_disabled', 'ALTER TABLE aimos_origin_elevations DISABLE ROW LEVEL SECURITY', /origin_rls_invalid/],
    ['force_rls_removed', 'ALTER TABLE aimos_origin_elevations NO FORCE ROW LEVEL SECURITY', /origin_rls_invalid/],
    ['policy_unscoped', 'ALTER POLICY aimos_origin_elevation_company_read ON aimos_origin_elevations USING (true)', /origin_policy_invalid/],
    ['update_acl', 'GRANT UPDATE ON aimos_origin_elevations TO agent_runtime', /origin_mutation_acl_exposed/],
    ['column_update_acl', 'GRANT UPDATE(maximum_uses) ON aimos_origin_elevations TO agent_runtime', /origin_mutation_acl_exposed/],
    ['truncate_acl', 'GRANT TRUNCATE ON aimos_origin_elevations TO agent_runtime', /origin_mutation_acl_exposed/],
    ['writer_body_changed', `CREATE OR REPLACE FUNCTION public.ob2_verify_signed_event(p_event_id uuid,p_company_id text)
      RETURNS public.aimos_events LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$BEGIN RETURN NULL; END$$`, /origin_function_body_invalid/],
    ['writer_argument_names_swapped', `DROP FUNCTION public.ob2_verify_signed_event(uuid,text);
      CREATE FUNCTION public.ob2_verify_signed_event(p_company_id uuid,p_event_id text)
      RETURNS public.aimos_events LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path=pg_catalog,public
      AS $audfault$${currentOriginSourceContract().functions.get('ob2_verify_signed_event').body}$audfault$`, /origin_function_argument_names_invalid/],
    ['writer_owner_changed', 'ALTER FUNCTION public.ob2_verify_signed_event(uuid,text) OWNER TO aimos_app', /origin_function_owner_invalid/],
    ['internal_execute_granted', 'GRANT EXECUTE ON FUNCTION public.ob2_verify_signed_event(uuid,text) TO agent_runtime', /origin_function_acl_invalid/],
    ['public_execute_granted', 'GRANT EXECUTE ON FUNCTION public.ob2_verify_signed_event(uuid,text) TO PUBLIC', /origin_function_acl_invalid/],
    ['definer_removed', 'ALTER FUNCTION public.ob2_verify_signed_event(uuid,text) SECURITY INVOKER', /origin_function_attributes_invalid/],
    ['search_path_changed', 'ALTER FUNCTION public.ob2_verify_signed_event(uuid,text) SET search_path=public,pg_catalog', /origin_function_attributes_invalid/],
    ['ob5_guard_disabled', 'ALTER TABLE aimos_action_origin_verdicts DISABLE TRIGGER ob5_verify_operator_action_authorization', /origin_trigger_invalid/],
    ['append_rule_added', 'CREATE RULE aud023_delete AS ON DELETE TO aimos_origin_elevations DO INSTEAD NOTHING', /origin_unapproved_rewrite_rule/],
    ['no_fork_index_removed', 'DROP INDEX aimos_origin_ledger_one_successor', /migration_index_not_valid/],
    ['no_fork_index_nonunique', 'DROP INDEX aimos_origin_ledger_one_successor; CREATE INDEX aimos_origin_ledger_one_successor ON aimos_origin_ledger_entries(company_id,prev_ledger_hash) WHERE prev_ledger_hash IS NOT NULL', /migration_index_definition_mismatch/],
    ['predecessor_fk_removed', 'ALTER TABLE aimos_origin_ledger_entries DROP CONSTRAINT aimos_origin_ledger_predecessor_fk', /origin_foreign_key_set_invalid/],
    ['predecessor_fk_cascade', `ALTER TABLE aimos_origin_ledger_entries DROP CONSTRAINT aimos_origin_ledger_predecessor_fk;
      ALTER TABLE aimos_origin_ledger_entries ADD CONSTRAINT aimos_origin_ledger_predecessor_fk FOREIGN KEY(prev_ledger_hash) REFERENCES aimos_origin_ledger_entries(ledger_hash) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED`, /origin_foreign_key_invalid/],
  ];
  const protectedTables = ['aimos_origin_ledger_entries','aimos_memory_origin_bindings',
    'aimos_origin_elevations','aimos_action_origin_verdicts','aimos_origin_family_profiles',
    'aimos_origin_family_definitions','aimos_memories','aimos_memory_provenance'];
  for (const table of protectedTables) {
    cases.push([`extra_trigger_${table}`, `CREATE FUNCTION public.aud023_mutator() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN UPDATE public.aimos_origin_elevations SET maximum_uses=2; RETURN NEW; END $$;
      CREATE TRIGGER aud023_mutator AFTER INSERT ON public.${table} FOR EACH ROW EXECUTE FUNCTION aud023_mutator()`, /origin_unapproved_trigger/]);
    cases.push([`extra_rule_${table}`, `CREATE RULE aud023_rule AS ON DELETE TO public.${table} DO INSTEAD NOTHING`, /origin_unapproved_rewrite_rule/]);
  }
  const riTriggers = (await client.query(`SELECT t.tgname,p.proname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
    WHERE t.tgconstraint=(SELECT oid FROM pg_constraint WHERE conrelid='public.aimos_origin_ledger_entries'::regclass
      AND conname='aimos_origin_ledger_predecessor_fk') ORDER BY t.tgname`)).rows;
  assert.equal(riTriggers.length,4);
  for (const trigger of riTriggers) {
    assert(/^RI_ConstraintTrigger_[ac]_[0-9]+$/.test(trigger.tgname));
    cases.push([`disabled_${trigger.proname}`, `ALTER TABLE public.aimos_origin_ledger_entries DISABLE TRIGGER "${trigger.tgname}"`, /origin_foreign_key_trigger_invalid/]);
  }
  cases.push(
    ['database_replica_default', `ALTER DATABASE "${database}" SET session_replication_role=replica`, /origin_replication_default_unsafe/],
    ['runtime_database_replica_default', `ALTER ROLE agent_runtime IN DATABASE "${database}" SET session_replication_role=replica`, /origin_replication_default_unsafe/],
    ['replica_audit_session', 'SET LOCAL session_replication_role=replica', /origin_replication_session_unsafe/],
    ['predecessor_fk_unenforced', 'ALTER TABLE public.aimos_origin_ledger_entries ALTER CONSTRAINT aimos_origin_ledger_predecessor_fk NOT ENFORCED', /origin_foreign_key_invalid/],
    ['retention_rule_disabled', 'ALTER TABLE public.aimos_memories DISABLE RULE block_memory_delete', /origin_unapproved_rewrite_rule/],
    ['retention_rule_removed', 'DROP RULE block_memory_delete ON public.aimos_memories', /origin_unapproved_rewrite_rule/],
    ['occurrence_uniqueness_removed', 'ALTER TABLE public.aimos_memory_origin_bindings DROP CONSTRAINT aimos_memory_origin_bindings_occurrence_id_key', /origin_occurrence_uniqueness_invalid/],
    ['occurrence_uniqueness_weakened', `ALTER TABLE public.aimos_memory_origin_bindings DROP CONSTRAINT aimos_memory_origin_bindings_occurrence_id_key;
      ALTER TABLE public.aimos_memory_origin_bindings ADD CONSTRAINT aimos_memory_origin_bindings_occurrence_id_key UNIQUE(occurrence_id,memory_id)`, /origin_occurrence_uniqueness_invalid/],
    ['occurrence_uniqueness_deferred', `ALTER TABLE public.aimos_memory_origin_bindings DROP CONSTRAINT aimos_memory_origin_bindings_occurrence_id_key;
      ALTER TABLE public.aimos_memory_origin_bindings ADD CONSTRAINT aimos_memory_origin_bindings_occurrence_id_key UNIQUE(occurrence_id) DEFERRABLE INITIALLY DEFERRED`, /origin_occurrence_uniqueness_invalid/],
    ['occurrence_null_allowed', 'ALTER TABLE public.aimos_memory_origin_bindings ALTER COLUMN occurrence_id DROP NOT NULL', /origin_occurrence_uniqueness_invalid/],
  );
  const denials = [];
  const missed = [];
  for (const [name, sql, expected] of cases) {
    await client.query('BEGIN');
    try {
      await client.query(sql);
      try {
        await assert.rejects(auditCurrentOriginLedger(client), expected, name);
        denials.push(name);
      } catch (error) { missed.push({name,error:error.message}); }
    } finally { await client.query('ROLLBACK'); }
  }
  await auditCurrentOriginLedger(client);
  assert.deepEqual(missed, [], 'current_origin_audit_missed_schema_faults');
  const replicaSwitchDenied = [];
  for (const role of ['agent_runtime','aimos_app']) {
    await client.query('BEGIN READ ONLY');
    try {
      await client.query(`SET LOCAL ROLE ${role}`);
      await assert.rejects(client.query('SET LOCAL session_replication_role=replica'), error=>error.code==='42501');
      replicaSwitchDenied.push(role);
    } finally { await client.query('ROLLBACK'); }
  }
  console.log(JSON.stringify({ success:true,database,clean_contract:clean.source_sha256,
    real_postgres_schema_faults_rejected:denials,runtime_replica_switch_denied:replicaSwitchDenied,
    canonical_mutation:false,canonical_rows_copied:false,
    genesis_invoked:false,product_listener_started:false,new_identity:false,observed_at:new Date().toISOString() },null,2));
} finally { client.release();await pool.end(); }
