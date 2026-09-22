#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { pool, agentPool } from '../../db/connection.js';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import { readOriginOperationAuthorityV2 } from '../../services/security/save-origin-binding.js';
import { verifyOriginOperationAuthorityV2 } from '../../services/security/protocol/origin-authority-v2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TABLES = Object.freeze([
  'aimos_origin_ledger_entries',
  'aimos_memory_origin_bindings',
  'aimos_origin_elevations',
  'aimos_action_origin_verdicts',
]);
const WRITERS = Object.freeze([
  'commit_memory_origin_binding_v1(jsonb,bytea,bytea,uuid,bytea,timestamp with time zone,text,bytea,timestamp with time zone,bytea)',
  'commit_origin_elevation_v1(jsonb,bytea,bytea,uuid,bytea,timestamp with time zone,text,bytea,timestamp with time zone,bytea)',
  'commit_action_origin_verdict_v1(jsonb,bytea,bytea,uuid,bytea,timestamp with time zone,text,bytea,timestamp with time zone,bytea)',
]);
const INTERNALS = Object.freeze([
  'ob2_raw_ed25519_pubkey(text,timestamp with time zone)',
  'ob2_origin_database_context_hash(text,timestamp with time zone,text)',
  'ob2_origin_ledger_envelope_hash(text,bytea,bytea,bytea,bytea,text,timestamp with time zone,timestamp with time zone)',
  'ob2_verify_origin_object(text,jsonb,bytea,bytea)',
  'ob2_verify_signed_event(uuid,text)',
  'ob2_verify_request_occurrence_authority(uuid,uuid,text,text,timestamp with time zone)',
  'ob2_commit_origin_ledger_entry(text,text,bytea,bytea,timestamp with time zone,text,bytea,timestamp with time zone,bytea)',
]);
const SOURCE_FILES = Object.freeze([
  'baselines/live-canonical/migration-098-099-uncertainty.json',
  'migrations/run.js',
  'migrations/100-origin-family-ledger-and-writers.sql',
  'migrations/101-origin-family-typed-writers.sql',
  'migrations/102-origin-action-verdict-family-order-fix.sql',
  'migrations/103-origin-writer-independent-crypto-parity.sql',
  'migrations/104-origin-event-local-timestamp-parity.sql',
  'migrations/105-origin-security-family-byte-order.sql',
  'services/security/origin-ledger.js',
  'services/security/save-origin-binding.js',
  'services/security/protocol/origin-authority-v2.js',
  'services/write/canonical-save-owner.js',
  'services/orchestration/tool-action-ledger.js',
  'scripts/verification/prove-origin-ledger-ob2-live.mjs',
  'scripts/verification/audit-origin-ledger-ob2.mjs',
  'tests/security/origin-ledger-ob2.test.mjs',
  'tests/install/migration-retained-uncertainty.test.mjs',
]);

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const assert = (value, code) => { if (!value) throw new Error(code); };

function walk(directory) {
  const output = [];
  for (const entry of readdirSync(path.join(ROOT, directory), { withFileTypes: true })) {
    const relative = path.join(directory, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) output.push(...walk(relative));
    else if (entry.isFile() && /\.(?:js|mjs|cjs)$/.test(entry.name)) output.push(relative);
  }
  return output;
}

// Real retained authority only. No fixture identities, signing, SAVE, or DDL.
// Missing native tool evidence stays unobserved rather than being fabricated.
async function auditNativeAuthorityShapes() {
  const client = await agentPool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SELECT set_config('app.current_client_id','hom',true),set_config('app.current_agent_id','housekeeper',true)");
    const request = (await client.query(`
      SELECT receipt.request_receipt_id AS id, encode(receipt.mutation_hash,'hex') AS hash,
             provenance.body_json AS body
        FROM aimos_request_receipts receipt
        JOIN aimos_memory_provenance provenance
          ON provenance.content_hash=receipt.request_hash AND provenance.sig=receipt.sig
         AND provenance.agent_id=receipt.actor_agent_id
         AND provenance.agent_valid_from=receipt.actor_valid_from
       WHERE receipt.company_id='hom' AND receipt.request_sig_form IN (3,4)
         AND provenance.event_type='SAVE' AND provenance.backfilled=false
       ORDER BY receipt.ts_signed DESC, receipt.request_receipt_id LIMIT 1
    `)).rows[0];
    const housekeeper = (await client.query(`
      SELECT id, encode(mutation_hash,'hex') AS hash FROM aimos_events
       WHERE company_id='hom' AND operation='canonical_save_action_started'
       ORDER BY ts DESC,id LIMIT 1
    `)).rows[0];
    const tool = (await client.query(`
      SELECT id, encode(mutation_hash,'hex') AS hash FROM aimos_events
       WHERE company_id='hom' AND operation='tool_execution_started'
       ORDER BY ts DESC,id LIMIT 1
    `)).rows[0];
    assert(request && housekeeper, 'ob2_native_authority_evidence_unavailable');
    const requestArgs = { client, companyId: 'hom', kind: 'verified_request',
      referenceId: request.id, expectedMutationSha256: request.hash, requestBody: request.body };
    const housekeeperArgs = { client, companyId: 'hom', kind: 'verified_housekeeper_action',
      referenceId: housekeeper.id, expectedMutationSha256: housekeeper.hash };
    const records = [await readOriginOperationAuthorityV2(requestArgs),
      await readOriginOperationAuthorityV2(housekeeperArgs)];
    if (tool) records.push(await readOriginOperationAuthorityV2({ client, companyId: 'hom',
      kind: 'verified_tool_action', referenceId: tool.id, expectedMutationSha256: tool.hash }));
    for (const record of records) verifyOriginOperationAuthorityV2(record);
    const denials = [];
    for (const [name, args, expected] of [
      ['request_id_substitution', { ...requestArgs, referenceId: housekeeper.id }, 'origin_authority_receipt_reference_mismatch'],
      ['request_body_substitution', { ...requestArgs, requestBody: { ...request.body, key: 'unauthorized:changed:key' } }, 'origin_authority_request_signature_invalid'],
      ['housekeeper_as_tool', { ...housekeeperArgs, kind: 'verified_tool_action' }, 'origin_authority_tool_event_invalid'],
      ['action_with_http_body', { ...housekeeperArgs, requestBody: request.body }, 'origin_authority_action_request_body_forbidden'],
      ['wrong_company', { ...housekeeperArgs, companyId: 'not-hom' }, 'origin_authority_transaction_scope_mismatch'],
    ]) {
      let observed = null;
      try { await readOriginOperationAuthorityV2(args); }
      catch (error) { observed = error.message; }
      assert(observed === expected, `ob2_authority_denial_not_proved:${name}:${observed}`);
      denials.push({ name, expected, observed });
    }
    return { database_role: 'agent_runtime', transaction: 'READ ONLY', database_mutation: false,
      records, denials, tool_positive_observed: Boolean(tool),
      save_pipeline_integration_proved: false, correction_1_closed: false };
  } finally {
    try { await client.query('ROLLBACK'); } finally { client.release(); }
  }
}

try {
  assert(process.argv.includes('--historical-ob2'),
    'historical_ob2_pre_activation_audit_only:use_scripts/verification/audit-origin-ledger-current.mjs');
  console.error('HISTORICAL OB2 PRE-ACTIVATION AUDIT — not a current-runtime readiness check.');
  const current = (await pool.query(`
    SELECT current_database() AS database, current_user,
           (SELECT count(*)::integer FROM schema_migrations) AS migration_count
  `)).rows[0];
  assert(current.database === 'aimos', 'ob2_audit_wrong_database');

  const migrationRows = (await pool.query(`
    SELECT filename, checksum FROM schema_migrations
     WHERE filename = ANY($1::text[]) ORDER BY filename
  `, [SOURCE_FILES.filter((file) => file.startsWith('migrations/1')).map((file) => path.basename(file))])).rows;
  assert(migrationRows.length === 6, 'ob2_audit_migration_count_invalid');
  for (const row of migrationRows) {
    assert(row.checksum === sha(readFileSync(path.join(ROOT, 'migrations', row.filename))),
      `ob2_audit_migration_checksum_invalid:${row.filename}`);
  }

  const tables = (await pool.query(`
    SELECT class.relname, class.relrowsecurity, class.relforcerowsecurity,
           owner.rolname AS owner,
           (SELECT count(*) FROM pg_trigger trigger
             WHERE trigger.tgrelid=class.oid AND NOT trigger.tgisinternal)::integer AS user_triggers
      FROM pg_class class
      JOIN pg_namespace namespace ON namespace.oid=class.relnamespace
      JOIN pg_roles owner ON owner.oid=class.relowner
     WHERE namespace.nspname='public' AND class.relname=ANY($1::text[])
     ORDER BY class.relname
  `, [TABLES])).rows;
  assert(tables.length === TABLES.length, 'ob2_audit_table_count_invalid');
  assert(tables.every((table) => table.relrowsecurity && table.relforcerowsecurity
    && table.user_triggers === 0), 'ob2_audit_rls_or_trigger_invalid');

  const tablePrivileges = [];
  for (const table of TABLES) {
    const privilege = (await pool.query(`
      SELECT has_table_privilege('agent_runtime',$1,'SELECT') AS select_allowed,
             has_table_privilege('agent_runtime',$1,'INSERT') AS insert_allowed,
             has_table_privilege('agent_runtime',$1,'UPDATE') AS update_allowed,
             has_table_privilege('agent_runtime',$1,'DELETE') AS delete_allowed,
             has_table_privilege('agent_runtime',$1,'TRUNCATE') AS truncate_allowed
    `, [`public.${table}`])).rows[0];
    assert(privilege.select_allowed === true
      && [privilege.insert_allowed, privilege.update_allowed,
        privilege.delete_allowed, privilege.truncate_allowed].every((value) => value === false),
    `ob2_audit_table_acl_invalid:${table}`);
    tablePrivileges.push({ table, ...privilege });
  }

  const functionPrivileges = [];
  for (const identity of WRITERS) {
    const allowed = (await pool.query(
      `SELECT has_function_privilege('agent_runtime',$1,'EXECUTE') AS allowed`,
      [`public.${identity}`],
    )).rows[0].allowed;
    assert(allowed === true, `ob2_audit_writer_execute_missing:${identity}`);
    functionPrivileges.push({ function: identity, allowed });
  }
  for (const identity of INTERNALS) {
    const allowed = (await pool.query(
      `SELECT has_function_privilege('agent_runtime',$1,'EXECUTE') AS allowed`,
      [`public.${identity}`],
    )).rows[0].allowed;
    assert(allowed === false, `ob2_audit_internal_execute_exposed:${identity}`);
    functionPrivileges.push({ function: identity, allowed });
  }
  const stateReader = (await pool.query(`
    SELECT has_function_privilege(
      'agent_runtime','public.ob2_read_origin_ledger_state(text)','EXECUTE') AS allowed
  `)).rows[0].allowed;
  assert(stateReader === true, 'ob2_audit_state_reader_missing');

  const functionDefs = (await pool.query(`
    SELECT proname, prosecdef, proconfig, pg_get_functiondef(proc.oid) AS definition
      FROM pg_proc proc JOIN pg_namespace namespace ON namespace.oid=proc.pronamespace
     WHERE namespace.nspname='public'
       AND proname=ANY($1::text[]) ORDER BY proname
  `, [[
    'commit_memory_origin_binding_v1', 'commit_origin_elevation_v1',
    'commit_action_origin_verdict_v1', 'ob2_verify_signed_event',
    'ob2_verify_request_occurrence_authority',
  ]])).rows;
  assert(functionDefs.length === 5 && functionDefs.every((fn) => fn.prosecdef
    && fn.proconfig?.includes('search_path=pg_catalog, public')),
  'ob2_audit_security_definer_contract_invalid');
  assert(functionDefs.filter((fn) => fn.proname.startsWith('ob2_verify_')).every((fn) =>
    fn.definition.includes('pgsodium.crypto_sign_verify_detached')),
  'ob2_audit_independent_signature_verification_missing');

  const profile = (await pool.query(`
    SELECT encode(profile_sha256,'hex') AS profile_sha256,
           octet_length(body_bytes)::integer AS body_bytes
      FROM aimos_origin_family_profiles
     WHERE schema_id='hom.aimos.origin-family-profile/v1'
  `)).rows[0];
  const familyCount = Number((await pool.query(`
    SELECT count(*) FROM aimos_origin_family_definitions
     WHERE profile_sha256=decode($1,'hex')
  `, [profile.profile_sha256])).rows[0].count);
  assert(profile.profile_sha256 === '49af981a17761ffe7798125b6c710a7fc6a498970b2e29c31c58ec6f2f2afe24'
    && familyCount === 30, 'ob2_audit_family_profile_invalid');

  const counts = (await pool.query(`
    SELECT
      (SELECT count(*)::integer FROM aimos_origin_ledger_entries) AS ledger_entries,
      (SELECT count(*)::integer FROM aimos_memory_origin_bindings) AS memory_bindings,
      (SELECT count(*)::integer FROM aimos_origin_elevations) AS elevations,
      (SELECT count(*)::integer FROM aimos_action_origin_verdicts) AS verdicts
  `)).rows[0];
  assert(Object.values(counts).every((value) => Number(value) === 0), 'ob2_audit_live_residue_invalid');

  const sourceEntries = SOURCE_FILES.map((file) => {
    const absolute = path.join(ROOT, file);
    assert(statSync(absolute).isFile(), `ob2_audit_source_missing:${file}`);
    return { path: file, sha256: sha(readFileSync(absolute)) };
  });
  const sourceRoot = sha(Buffer.from(canonicalJson(sourceEntries), 'utf8'));
  const productionFiles = ['services', 'routes', 'jobs', 'db', 'middleware'].flatMap(walk);
  const ownerImporters = productionFiles.filter((file) => file !== 'services/security/origin-ledger.js'
    && readFileSync(path.join(ROOT, file), 'utf8').includes('origin-ledger.js'));
  const protocolImporters = productionFiles.filter((file) => file !== 'services/security/protocol/origin-binding-v1.js'
    && readFileSync(path.join(ROOT, file), 'utf8').includes('origin-binding-v1.js'));
  assert(ownerImporters.length === 0, 'ob2_audit_owner_runtime_importer_invalid');
  assert(protocolImporters.length === 1
    && protocolImporters[0] === 'services/security/origin-ledger.js',
  'ob2_audit_protocol_importer_invalid');

  const nativeAuthority = await auditNativeAuthorityShapes();

  console.log(JSON.stringify({
    success: true,
    status: 'OB2_INDEPENDENT_DATABASE_AND_SOURCE_AUDIT_PASSED',
    database: current.database,
    migration_count: current.migration_count,
    migrations_verified: migrationRows.map((row) => row.filename),
    tables,
    table_privileges: tablePrivileges,
    function_privileges: functionPrivileges,
    state_reader_execute: stateReader,
    family_count: familyCount,
    live_rows: counts,
    source_file_count: sourceEntries.length,
    source_root_sha256: sourceRoot,
    owner_runtime_importers: ownerImporters,
    protocol_importers: protocolImporters,
    native_authority_v2: nativeAuthority,
    complexity: {
      append_head_lookup: 'O(log n) indexed with O(1) expected advisory lock',
      family_and_parent_validation: 'O(k + e), k <= 64',
      corroborator_validation: 'O(c), c <= 16',
      security_value_validation: 'O(v * f), v <= 64, f <= 64',
      verification_space: 'O(k + c + v)',
    },
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({ success: false, error: error.message }, null, 2));
  process.exitCode = 1;
} finally {
  await pool.end();
  await agentPool.end();
}
