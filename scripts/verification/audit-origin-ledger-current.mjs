#!/usr/bin/env node
// Current origin database contract. Expectations come from reviewed native SQL,
// never from the installed catalog. This owner performs SELECTs only.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { splitSqlStatements, parseMigrationIndexContract, verifyMigrationIndex } from '../../migrations/run.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const sha = value => createHash('sha256').update(value).digest('hex');
const typeSyntax = value => value.replace(/\btimestamptz\b/g, 'timestamp with time zone')
  .replace(/\bpublic\./g, '').replace(/\s+/g, ' ').replace(/\s*([(),])\s*/g, '$1').trim().toLowerCase();
const TABLES = Object.freeze({
  aimos_origin_ledger_entries: 'aimos_origin_ledger_company_read',
  aimos_memory_origin_bindings: 'aimos_memory_origin_company_read',
  aimos_origin_elevations: 'aimos_origin_elevation_company_read',
  aimos_action_origin_verdicts: 'aimos_action_origin_verdict_company_read',
});
const READ_TABLES = [...Object.keys(TABLES), 'aimos_origin_family_profiles', 'aimos_origin_family_definitions'];
const EXECUTABLE = new Set(['ob2_read_origin_ledger_state', 'ob3_native_save_input_ids',
  'commit_memory_origin_binding_v1', 'commit_memory_origin_binding_v2',
  'commit_origin_elevation_v2', 'commit_action_origin_verdict_v1',
  'select_origin_elevation_v2_for_action',
  'apply_signed_cognitive_reweight','verify_cognitive_weight_chain']);
const TRIGGERS = Object.freeze([
  ['aimos_memory_provenance', 'ob2_atomic_save_origin', 'ob2_require_atomic_save_origin', 5, true],
  ['aimos_memory_origin_bindings', 'ob2_atomic_origin_save', 'ob2_require_atomic_save_origin', 5, true],
  ['aimos_memories', 'ob2_atomic_memory_origin', 'ob2_require_atomic_save_origin', 5, true],
  ['aimos_memory_provenance', 'ob2_retained_binding_successor', 'ob2_require_retained_binding_successor', 5, true],
  ['aimos_action_origin_verdicts', 'ob5_verify_operator_action_authorization', 'ob5_verify_operator_action_authorization', 7, false],
]);
const TRIGGER_TABLES = [...new Set([...READ_TABLES, ...TRIGGERS.map(t => t[0])])];

export function currentOriginSourceContract() {
  const files = readdirSync(path.join(ROOT, 'migrations')).filter(name => /^(?:10[0-9]|11[0-5])-.*\.sql$/.test(name)).sort()
    .map(name => `migrations/${name}`);
  assert.equal(files.length, 16, 'origin_current_source_version_set_invalid');
  files.push('db/request-target.sql','db/signed-request-bytes.sql','db/atomic-save-origin.sql',
    'db/signed-json-bytes.sql','db/signed-event-bytes.sql','db/cognitive-ancestry.sql');
  const functions = new Map();
  const sources = [];
  const indexes = new Map();
  const foreignKeys = [];
  let occurrenceUniqueness;
  for (const file of files) {
    const text = readFileSync(path.join(ROOT, file), 'utf8');
    sources.push({ path: file, sha256: sha(text) });
    for (const statement of splitSqlStatements(text)) {
      const droppedIndex = statement.match(/^DROP INDEX (?:IF EXISTS )?(?:public\.)?(aimos_[a-z0-9_]+)\s*;?$/i)?.[1];
      if (droppedIndex) indexes.delete(droppedIndex);
      if (/CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?aimos_(?:(?:origin_ledger|action_origin)_one_(?:genesis|successor)|origin_elevation_v2_(?:request_action_unique|registry_action_lookup))\b/.test(statement)) {
        const contract = parseMigrationIndexContract(statement);
        indexes.set(contract.name[1], contract);
      }
      const table = statement.match(/CREATE TABLE public\.(\w+)\s*\(/)?.[1];
      if (table && READ_TABLES.includes(table)) {
        if (table === 'aimos_memory_origin_bindings') {
          assert(/\boccurrence_id uuid NOT NULL UNIQUE\s*,/.test(statement), 'origin_occurrence_uniqueness_source_invalid');
          occurrenceUniqueness = parseMigrationIndexContract('CREATE UNIQUE INDEX aimos_memory_origin_bindings_occurrence_id_key ON public.aimos_memory_origin_bindings USING btree (occurrence_id)');
        }
        for (const fk of statement.matchAll(/CONSTRAINT (\w+)\s+FOREIGN KEY\s*\(([^)]+)\)\s*REFERENCES public\.(\w+)\s*\(([^)]+)\)([^,]*)/g)) {
          foreignKeys.push({ table,name:fk[1],columns:fk[2].split(',').map(s=>s.trim()),parent:fk[3],
            parentColumns:fk[4].split(',').map(s=>s.trim()),deleteAction:/ON DELETE RESTRICT/.test(fk[5])?'r':'a',
            deferred:/DEFERRABLE/.test(fk[5]),initiallyDeferred:/INITIALLY DEFERRED/.test(fk[5]) });
        }
      }
      for (const fk of statement.matchAll(/ALTER TABLE public\.(\w+)\s+ADD CONSTRAINT (\w+)\s+FOREIGN KEY\s*\(([^)]+)\)\s*REFERENCES public\.(\w+)\s*\(([^)]+)\)([^;]*)/g)) {
        if (!READ_TABLES.includes(fk[1])) continue;
        foreignKeys.push({ table:fk[1],name:fk[2],columns:fk[3].split(',').map(s=>s.trim()),parent:fk[4],
          parentColumns:fk[5].split(',').map(s=>s.trim()),deleteAction:/ON DELETE RESTRICT/.test(fk[6])?'r':'a',
          deferred:/DEFERRABLE/.test(fk[6]),initiallyDeferred:/INITIALLY DEFERRED/.test(fk[6]) });
      }
      const match = statement.match(/CREATE (?:OR REPLACE )?FUNCTION public\.(\w+)\s*\(([\s\S]*?)\)\s*RETURNS ([\s\S]*?)\bAS\s+(\$\w*\$)([\s\S]*)\4\s*;?\s*$/i);
      if (!match) {
        assert(!/CREATE (?:OR REPLACE )?FUNCTION/i.test(statement), `origin_function_source_not_parsed:${file}`);
        continue;
      }
      const [, name, args, attributes, , body] = match;
      const types = args.trim() ? args.split(',').map(arg => arg.trim().replace(/\s+DEFAULT\s+[\s\S]*$/i, '')
        .replace(/^\w+\s+/, '').replace(/\btimestamptz\b/g, 'timestamp with time zone').replace(/\bpublic\./g, '')).join(',') : '';
      const language = attributes.match(/\bLANGUAGE\s+(\w+)/i)?.[1].toLowerCase();
      const defaultCount = [...args.matchAll(/\bDEFAULT\b/gi)].length;
      assert(defaultCount === 0 || (defaultCount === 1 && /\b\w+\s+jsonb\s+DEFAULT\s+NULL\s*$/i.test(args)),
        `origin_function_default_source_unsupported:${name}`);
      const argumentNames = args.trim() ? args.split(',').map(arg => arg.trim().split(/\s+/)[0]) : [];
      const outputs = attributes.match(/^\s*TABLE\s*\(([\s\S]*?)\)\s*LANGUAGE/i)?.[1];
      if (outputs) argumentNames.push(...outputs.split(',').map(arg => arg.trim().split(/\s+/)[0]));
      const searchPath = attributes.match(/\bSET\s+search_path\s*=\s*([\w, ]+)/i)?.[1]
        .trim().replace(/\s*,\s*/g, ', ');
      assert(language && searchPath, `origin_function_source_attributes_missing:${name}`);
      functions.set(name, { name, identity: `public.${name}(${types})`, body,
        result: typeSyntax(attributes.split(/\bLANGUAGE\b/i)[0]),
        argumentNames: argumentNames.length ? argumentNames : null,
        defaultCount, defaults: defaultCount ? 'NULL::jsonb' : null,
        language, securityDefiner: /SECURITY DEFINER/i.test(attributes),
        volatility: /\bIMMUTABLE\b/i.test(attributes) ? 'i' : /\bSTABLE\b/i.test(attributes) ? 's' : 'v',
        strict: /\bSTRICT\b/i.test(attributes), config: [`search_path=${searchPath}`], source: file });
    }
  }
  foreignKeys.push({ table:'aimos_memory_origin_bindings',name:'aimos_memory_origin_bindings_action_authority_event_id_fkey',
    columns:['action_authority_event_id'],parent:'aimos_events',parentColumns:['id'],deleteAction:'a',deferred:false,initiallyDeferred:false });
  for (const [, trigger, fn] of TRIGGERS) assert(functions.has(fn), `origin_trigger_source_missing:${trigger}`);
  assert(occurrenceUniqueness, 'origin_occurrence_uniqueness_source_missing');
  const retentionSource = 'migrations/001-base-schema.sql';
  const retentionBytes = readFileSync(path.join(ROOT,retentionSource),'utf8');
  const retentionRule = splitSqlStatements(retentionBytes).find(statement => /^CREATE OR REPLACE RULE block_memory_delete AS\b/.test(statement));
  assert.equal(retentionRule?.replace(/\s+/g,' ').trim(),
    'CREATE OR REPLACE RULE block_memory_delete AS ON DELETE TO aimos_memories DO INSTEAD NOTHING;',
    'origin_retention_rule_source_invalid');
  sources.push({path:retentionSource,sha256:sha(retentionBytes)});
  return { sources, sourceSha256: sha(JSON.stringify(sources)), functions, tables: TABLES, triggers: TRIGGERS,
    triggerTables: TRIGGER_TABLES, indexes:[...indexes.values()], foreignKeys, occurrenceUniqueness };
}

export async function auditCurrentOriginLedger(client) {
  const contract = currentOriginSourceContract();
  const objectSchemaConstraint = (await client.query(`SELECT pg_get_constraintdef(oid) AS definition
    FROM pg_constraint WHERE conrelid='public.aimos_origin_ledger_entries'::regclass
      AND conname='aimos_origin_ledger_object_schema'`)).rows;
  assert.equal(objectSchemaConstraint.length, 1, 'origin_object_schema_constraint_missing');
  for (const schema of [
    'hom.aimos.memory-origin-binding/v1',
    'hom.aimos.memory-origin-binding/v2',
    'hom.aimos.memory-origin-binding/v3',
    'hom.aimos.origin-elevation/v1',
    'hom.aimos.origin-elevation/v2',
    'hom.aimos.action-origin-verdict/v1',
  ]) assert(objectSchemaConstraint[0].definition.includes(`'${schema}'::text`),
    `origin_object_schema_constraint_invalid:${schema}`);
  const current = (await client.query(`SELECT current_database() AS database,
    pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname=current_database()`)).rows[0];
  assert(!['agent_runtime', 'aimos_app'].includes(current.owner), 'origin_database_runtime_owned');
  const applied = (await client.query('SELECT filename,checksum FROM schema_migrations WHERE filename=ANY($1)',
    [contract.sources.filter(s => s.path.startsWith('migrations/')).map(s => path.basename(s.path))])).rows;
  assert.equal(applied.length, contract.sources.filter(s=>s.path.startsWith('migrations/')).length, 'origin_current_migration_set_invalid');
  for (const source of contract.sources.filter(s => s.path.startsWith('migrations/'))) {
    assert.equal(applied.find(row => row.filename === path.basename(source.path))?.checksum,
      source.sha256, `origin_current_migration_checksum_invalid:${source.path}`);
  }
  const roles = (await client.query(`SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb
    FROM pg_roles WHERE rolname=ANY($1)`, [['agent_runtime', 'aimos_app']])).rows;
  assert.equal(roles.length, 2, 'origin_runtime_roles_missing');
  assert.equal((await client.query("SELECT current_setting('session_replication_role') AS mode")).rows[0].mode,
    'origin', 'origin_replication_session_unsafe');
  // O-enabled native guards require origin mode. Include non-inherited SET ROLE
  // paths; checking only immediately inherited parameter ACLs misses those paths.
  const replicationPrivileges = (await client.query(`SELECT s.rolname AS runtime,r.rolname,
    has_parameter_privilege(r.oid,'session_replication_role','SET,ALTER SYSTEM') AS allowed
    FROM pg_roles s JOIN pg_roles r ON pg_has_role(s.oid,r.oid,'SET')
    WHERE s.rolname=ANY($1) ORDER BY s.rolname,r.rolname`, [roles.map(r=>r.rolname)])).rows;
  for (const row of replicationPrivileges) assert(!row.allowed,
    `origin_replication_privilege_unsafe:${row.runtime}:${row.rolname}`);
  const replicationDefaults = (await client.query(`SELECT config FROM pg_db_role_setting s
    LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole
    CROSS JOIN LATERAL unnest(s.setconfig) config
    WHERE (s.setrole=0 OR r.rolname=ANY($1)) AND (s.setdatabase=0 OR d.datname=current_database())
      AND split_part(config,'=',1)='session_replication_role'`, [roles.map(r=>r.rolname)])).rows;
  assert(replicationDefaults.every(row=>row.config==='session_replication_role=origin'),
    'origin_replication_default_unsafe');
  for (const role of roles) {
    assert(!role.rolsuper && !role.rolbypassrls && !role.rolcreaterole && !role.rolcreatedb,
      `origin_runtime_role_privileged:${role.rolname}`);
    assert.equal((await client.query('SELECT pg_has_role($1,$2,\'MEMBER\') AS member',
      [role.rolname, current.owner])).rows[0].member, false, 'origin_runtime_owner_membership');
  }
  const tables = (await client.query(`SELECT c.relname,pg_get_userbyid(c.relowner) AS owner,
    c.relrowsecurity,c.relforcerowsecurity,c.relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1)`, [READ_TABLES])).rows;
  assert.equal(tables.length, READ_TABLES.length, 'origin_current_tables_missing');
  for (const table of tables) {
    assert.equal(table.owner, current.owner, `origin_table_owner_invalid:${table.relname}`);
    assert.equal(table.relkind, 'r', `origin_table_kind_invalid:${table.relname}`);
    if (Object.hasOwn(TABLES, table.relname)) assert(table.relrowsecurity && table.relforcerowsecurity,
      `origin_rls_invalid:${table.relname}`);
    for (const role of roles) {
      const acl = (await client.query(`SELECT
        has_table_privilege($1,$2,'SELECT') AS read,
        has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS write,
        has_any_column_privilege($1,$2,'INSERT,UPDATE,REFERENCES') AS column_write,
        has_schema_privilege($1,'public','CREATE') AS schema_create`, [role.rolname, `public.${table.relname}`])).rows[0];
      assert.equal(acl.read, role.rolname === 'agent_runtime', `origin_read_acl_invalid:${table.relname}:${role.rolname}`);
      assert(!acl.write && !acl.column_write && !acl.schema_create, `origin_mutation_acl_exposed:${table.relname}:${role.rolname}`);
    }
  }
  const policies = (await client.query(`SELECT c.relname,p.polname,p.polcmd,p.polpermissive,
    p.polroles::text AS roles,pg_get_expr(p.polqual,p.polrelid) AS expression,
    pg_get_expr(p.polwithcheck,p.polrelid) AS with_check
    FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1)`, [Object.keys(TABLES)])).rows;
  assert.equal(policies.length, 4, 'origin_policy_count_invalid');
  for (const [table, policy] of Object.entries(TABLES)) {
    const actual = policies.find(row => row.relname === table && row.polname === policy);
    assert(actual && actual.polcmd === 'r' && actual.polpermissive && actual.roles === '{0}'
      && actual.with_check === null && actual.expression === "(company_id = current_setting('app.current_client_id'::text, true))",
    `origin_policy_invalid:${table}`);
  }
  const functions = (await client.query(`SELECT p.oid,p.proname,p.prosrc,p.prosecdef,p.provolatile,p.proisstrict,
    p.proconfig,p.proleakproof,p.prosupport,pg_get_userbyid(p.proowner) AS owner,l.lanname,
    pg_get_function_result(p.oid) AS result,p.proargnames,p.pronargdefaults,pg_get_expr(p.proargdefaults,0) AS defaults,
    oidvectortypes(p.proargtypes) AS types
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
    WHERE n.nspname='public' AND (p.proname LIKE 'ob2\\_%' ESCAPE '\\'
      OR p.proname LIKE 'ob3\\_%' ESCAPE '\\' OR p.proname LIKE 'ob5\\_%' ESCAPE '\\'
      OR p.proname=ANY($1))`, [[...contract.functions.keys()]] )).rows;
  assert.equal(functions.length, contract.functions.size, 'origin_function_set_invalid');
  for (const expected of contract.functions.values()) {
    const fn = functions.find(row => `public.${row.proname}(${row.types.replace(/, /g, ',')})` === expected.identity);
    assert(fn, `origin_function_missing:${expected.identity}`);
    assert.equal(fn.owner, current.owner, `origin_function_owner_invalid:${expected.name}`);
    assert.equal(fn.prosrc, expected.body, `origin_function_body_invalid:${expected.name}`);
    assert.deepEqual(fn.proargnames,expected.argumentNames,`origin_function_argument_names_invalid:${expected.name}`);
    assert.deepEqual([typeSyntax(fn.result),fn.pronargdefaults,fn.defaults],
      [expected.result,expected.defaultCount,expected.defaults], `origin_function_signature_invalid:${expected.name}`);
    assert.deepEqual([fn.lanname,fn.prosecdef,fn.provolatile,fn.proisstrict,fn.proconfig,fn.proleakproof,fn.prosupport],
      [expected.language,expected.securityDefiner,expected.volatility,expected.strict,expected.config,false,'-'],
      `origin_function_attributes_invalid:${expected.name}`);
    for (const role of roles) assert.equal((await client.query(
      "SELECT has_function_privilege($1,$2::oid,'EXECUTE') AS allowed", [role.rolname, fn.oid])).rows[0].allowed,
    role.rolname === 'agent_runtime' && EXECUTABLE.has(expected.name), `origin_function_acl_invalid:${expected.name}:${role.rolname}`);
    assert.equal((await client.query(`SELECT EXISTS(SELECT 1 FROM pg_proc p,
      LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      WHERE p.oid=$1 AND a.grantee=0 AND a.privilege_type='EXECUTE') AS exposed`, [fn.oid])).rows[0].exposed,
    false, `origin_function_public_execute:${expected.name}`);
  }
  const triggers = (await client.query(`SELECT c.relname,t.tgname,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,
    t.tgnargs,t.tgargs,t.tgattr::text AS columns,t.tgqual IS NULL AS unconditional,p.proname,n.nspname AS function_schema
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace cn ON cn.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE NOT t.tgisinternal AND cn.nspname='public' AND c.relname=ANY($1)`,
  [TRIGGER_TABLES])).rows;
  for (const [table,name,fn,type,deferred] of TRIGGERS) {
    const t = triggers.find(t => t.relname === table && t.tgname === name);
    assert(t && t.proname === fn && t.function_schema === 'public' && t.tgtype === type
      && t.tgenabled === 'O' && t.tgdeferrable === deferred && t.tginitdeferred === deferred
      && t.tgnargs === 0 && t.tgargs.length === 0 && t.columns === '' && t.unconditional,
    `origin_trigger_invalid:${name}`);
  }
  for (const t of triggers)
    assert(TRIGGERS.some(([table,name]) => t.relname === table && t.tgname === name), `origin_unapproved_trigger:${t.relname}:${t.tgname}`);
  const eventTrigger = (await client.query(`SELECT t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,
    t.tgnargs,t.tgattr::text AS columns,t.tgqual IS NULL AS unconditional,
    t.tgfoid='public.require_signed_event_bytes_v1()'::regprocedure AS exact_function
    FROM pg_trigger t WHERE t.tgrelid='public.aimos_events'::regclass
      AND t.tgname='aimos_events_exact_payload_verified' AND NOT t.tgisinternal`)).rows;
  assert.deepEqual(eventTrigger,[{tgtype:5,tgenabled:'O',tgdeferrable:false,tginitdeferred:false,
    tgnargs:0,columns:'',unconditional:true,exact_function:true}], 'event_bytes_trigger_invalid');
  const eventColumn = (await client.query(`SELECT a.atttypid='bytea'::regtype AS bytes,
    a.attnotnull,a.attgenerated,a.attidentity,a.atthasdef
    FROM pg_attribute a WHERE a.attrelid='public.aimos_events'::regclass
      AND a.attname='signed_body_bytes' AND NOT a.attisdropped`)).rows;
  assert.deepEqual(eventColumn,[{bytes:true,attnotnull:false,attgenerated:'',attidentity:'',atthasdef:false}],
    'event_bytes_column_invalid');
  const eventConstraint=(await client.query(`SELECT contype,convalidated,conenforced,condeferrable,
    condeferred,pg_get_expr(conbin,conrelid) AS expression FROM pg_constraint
    WHERE conrelid='public.aimos_events'::regclass AND conname='aimos_events_exact_payload_pair'`)).rows;
  const eventPairExpression=`CASE
    WHEN (signed_body IS NULL) THEN (signed_body_bytes IS NULL)
    WHEN (signed_body ? 'payload_schema'::text) THEN (((signed_body ->> 'payload_schema'::text) = 'hom.aimos.event/v2'::text) AND (signed_body_bytes IS NOT NULL))
    ELSE (signed_body_bytes IS NULL) END`;
  assert.deepEqual(eventConstraint.map(row=>({...row,expression:row.expression.replace(/\s+/g,' ').trim()})),
    [{contype:'c',convalidated:true,conenforced:true,condeferrable:false,condeferred:false,
      expression:eventPairExpression.replace(/\s+/g,' ').trim()}], 'event_bytes_constraint_invalid');
  for (const role of roles) {
    const acl=(await client.query(`SELECT
      has_column_privilege($1,'public.aimos_events','signed_body_bytes','SELECT') AS read,
      has_column_privilege($1,'public.aimos_events','signed_body_bytes','INSERT') AS insert,
      has_column_privilege($1,'public.aimos_events','signed_body_bytes','UPDATE,REFERENCES') AS mutate,
      has_table_privilege($1,'public.aimos_events','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') AS broad_write`,
    [role.rolname])).rows[0];
    // Preserve both roles' existing event SELECT; it is not write authority.
    assert.deepEqual(acl,{read:true,insert:role.rolname==='agent_runtime',
      mutate:false,broad_write:false},`event_bytes_acl_invalid:${role.rolname}`);
  }
  const rules = (await client.query(`SELECT c.relname,r.rulename,r.ev_type,r.ev_enabled,r.is_instead,pg_get_ruledef(r.oid) AS definition
    FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1) ORDER BY c.relname,r.rulename`, [TRIGGER_TABLES])).rows;
  assert.deepEqual(rules,[{relname:'aimos_memories',rulename:'block_memory_delete',ev_type:'4',ev_enabled:'O',is_instead:true,
    definition:'CREATE RULE block_memory_delete AS\n    ON DELETE TO public.aimos_memories DO INSTEAD NOTHING;'}],
  'origin_unapproved_rewrite_rule');
  for (const index of contract.indexes) await verifyMigrationIndex(client,index);
  const foreignKeys = (await client.query(`SELECT c.oid,c.conrelid,c.confrelid,c.conindid,c.conname,t.relname AS table,p.relname AS parent,c.convalidated,
    c.conenforced,c.conperiod,
    c.condeferrable,c.condeferred,c.confdeltype,c.confupdtype,c.confmatchtype,
    ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n,i)
      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.i) AS columns,
    ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n,i)
      JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY k.i) AS parent_columns,
    pn.nspname AS parent_schema
    FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
    JOIN pg_class p ON p.oid=c.confrelid JOIN pg_namespace pn ON pn.oid=p.relnamespace
    WHERE c.contype='f' AND n.nspname='public' AND t.relname=ANY($1)`, [READ_TABLES])).rows;
  assert.equal(foreignKeys.length,contract.foreignKeys.length,'origin_foreign_key_set_invalid');
  for (const expected of contract.foreignKeys) {
    const fk=foreignKeys.find(c=>c.table===expected.table&&c.conname===expected.name);
    assert(fk,`origin_foreign_key_missing:${expected.name}`);
    assert.deepEqual([fk.parent,fk.parent_schema,fk.columns,fk.parent_columns,fk.convalidated,fk.condeferrable,
      fk.condeferred,fk.confdeltype,fk.confupdtype,fk.confmatchtype,fk.conenforced,fk.conperiod],
    [expected.parent,'public',expected.columns,expected.parentColumns,true,expected.deferred,expected.initiallyDeferred,
      expected.deleteAction,'a','s',true,false],`origin_foreign_key_invalid:${expected.name}`);
  }
  // PostgreSQL's native FK owner creates four AFTER ROW RI triggers per plain FK.
  // RESTRICT actions are immediate; NO ACTION and check triggers inherit the FK's deferral.
  // Source: PostgreSQL REL_18_STABLE tablecmds.c, CreateFKCheckTrigger/createForeignKeyActionTriggers.
  const riTriggers = (await client.query(`SELECT t.tgconstraint,t.tgrelid,t.tgconstrrelid,t.tgconstrindid,
    t.tgtype,t.tgenabled,t.tgisinternal,t.tgdeferrable,t.tginitdeferred,t.tgparentid,t.tgnargs,t.tgargs,
    t.tgattr::text AS columns,t.tgqual IS NULL AS unconditional,t.tgoldtable,t.tgnewtable,
    p.proname,n.nspname AS function_schema
    FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE t.tgconstraint=ANY($1::oid[])`, [foreignKeys.map(fk=>fk.oid)])).rows;
  for (const fk of foreignKeys) {
    const actual = riTriggers.filter(t=>t.tgconstraint===fk.oid);
    assert.equal(actual.length,4,`origin_foreign_key_trigger_invalid:${fk.conname}:count`);
    const required = [
      ['RI_FKey_check_ins',fk.conrelid,fk.confrelid,5,fk.condeferrable,fk.condeferred],
      ['RI_FKey_check_upd',fk.conrelid,fk.confrelid,17,fk.condeferrable,fk.condeferred],
      ['RI_FKey_noaction_upd',fk.confrelid,fk.conrelid,17,fk.condeferrable,fk.condeferred],
      [fk.confdeltype==='r'?'RI_FKey_restrict_del':'RI_FKey_noaction_del',fk.confrelid,fk.conrelid,9,
        fk.confdeltype==='r'?false:fk.condeferrable,fk.confdeltype==='r'?false:fk.condeferred],
    ];
    for (const [name,relation,parent,type,deferred,initiallyDeferred] of required) {
      const matches = actual.filter(t=>t.proname===name);
      const t=matches[0];
      assert(matches.length===1 && t.function_schema==='pg_catalog' && t.tgrelid===relation
        && t.tgconstrrelid===parent && t.tgconstrindid===fk.conindid && t.tgtype===type
        && t.tgenabled==='O' && t.tgisinternal && t.tgparentid===0 && t.tgdeferrable===deferred
        && t.tginitdeferred===initiallyDeferred && t.tgnargs===0 && t.tgargs.length===0
        && t.columns==='' && t.unconditional && t.tgoldtable===null && t.tgnewtable===null,
      `origin_foreign_key_trigger_invalid:${fk.conname}:${name}`);
    }
  }
  // The native atomic owner selects one binding by occurrence_id (non-STRICT INTO).
  // Its source-defined immediate uniqueness and NOT NULL cannot be inferred from FK presence.
  const uniqueness = (await client.query(`SELECT c.contype,c.condeferrable,c.condeferred,c.convalidated,
    c.conenforced,c.conperiod,c.conindid=candidate.oid AS exact_index,
    ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n,i)
      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.i) AS columns,
    a.attnotnull
    FROM pg_constraint c JOIN pg_class candidate ON candidate.relname='aimos_memory_origin_bindings_occurrence_id_key'
      AND candidate.relnamespace='public'::regnamespace
    JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attname='occurrence_id' AND NOT a.attisdropped
    WHERE c.conrelid='public.aimos_memory_origin_bindings'::regclass
      AND c.conname='aimos_memory_origin_bindings_occurrence_id_key'`)).rows;
  assert.deepEqual(uniqueness,[{contype:'u',condeferrable:false,condeferred:false,convalidated:true,
    conenforced:true,conperiod:false,exact_index:true,columns:['occurrence_id'],attnotnull:true}],
  'origin_occurrence_uniqueness_invalid');
  await verifyMigrationIndex(client,contract.occurrenceUniqueness);
  return { success: true, status: 'CURRENT_ORIGIN_SCHEMA_AUDIT_PASSED', ...current,
    source_sha256: contract.sourceSha256, source_files: contract.sources,
    tables_verified: tables.length, functions_verified: functions.length, required_triggers_verified: TRIGGERS.length,
    no_fork_indexes_verified:contract.indexes.length,foreign_keys_verified:foreignKeys.length,
    foreign_key_enforcement_triggers_verified:riTriggers.length,trigger_and_rule_tables_verified:TRIGGER_TABLES.length,
    occurrence_uniqueness_verified:true,
    replication_mode_authority_verified:true,
    event_bytes_trigger_and_column_acl_verified:true,
    event_bytes_pair_constraint_verified:true,
    audit_statements: 'SELECT_ONLY', historical_ob2_rewritten: false,
    phase_closure_assessed: false, scope: 'CURRENT_ORIGIN_DATABASE_CONTRACT_ONLY' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { pool, agentPool } = await import('../../db/connection.js');
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    console.log(JSON.stringify({ ...await auditCurrentOriginLedger(client), transaction: 'REPEATABLE READ READ ONLY', observed_at: new Date().toISOString() }, null, 2));
    await client.query('COMMIT');
  } catch (error) {
    console.error(JSON.stringify({ success:false, error:error.message })); process.exitCode=1;
  } finally { await client.query('ROLLBACK').catch(()=>{}); client.release(); await pool.end(); await agentPool.end(); }
}
