import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const EXPECTED_RUNTIME_SEQUENCES = Object.freeze([
  'public.concept_passage_edges_id_seq',
  'public.concept_relation_edges_id_seq',
  'public.dream_summary_layers_id_seq',
  'public.entity_memory_edges_id_seq',
  'public.memory_cross_refs_id_seq',
  'public.memory_valence_ledger_id_seq',
  'public.quim_index_id_seq',
  'public.quim_prototypes_id_seq',
  'public.retrieval_pheromones_id_seq',
  'public.supersession_events_id_seq',
]);

const EXPECTED_NON_EXTENSION_FUNCTIONS = Object.freeze([
  'apply_signed_cognitive_reweight(uuid,double precision,double precision,bytea,bytea)',
  'apply_signed_memory_epistemic_classification(uuid,text,integer,uuid,bytea)',
  'cognitive_weight_baseline_hash(text,uuid,uuid,bytea,bytea,real,integer,bigint,timestamp with time zone,bytea)',
  'commit_cognitive_weight_baseline(uuid,uuid,bytea,bytea,real,integer,bigint,timestamp with time zone,text,bytea)',
  'verify_all_cognitive_weight_chains()',
  'verify_cognitive_weight_baseline(uuid)',
  'verify_cognitive_weight_chain(uuid)',
  'verify_memory_epistemic_classification_chain(uuid)',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function commandVersion(command) {
  try {
    return execFileSync(command, ['--version'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

export function resolvePgToolchain({ pgBin = null } = {}) {
  const candidates = [
    pgBin,
    '/usr/local/opt/postgresql@18/bin',
    '/opt/homebrew/opt/postgresql@18/bin',
    '/usr/local/Cellar/postgresql@18/18.3/bin',
  ].filter(Boolean);
  for (const directory of candidates) {
    const psql = path.join(directory, 'psql');
    const pgDump = path.join(directory, 'pg_dump');
    const pgRestore = path.join(directory, 'pg_restore');
    if (![psql, pgDump, pgRestore].every((file) => fs.existsSync(file))) continue;
    const versions = {
      psql: commandVersion(psql),
      pg_dump: commandVersion(pgDump),
      pg_restore: commandVersion(pgRestore),
    };
    if (Object.values(versions).every((value) => /PostgreSQL\) 18\./.test(String(value)))) {
      return Object.freeze({ directory, psql, pgDump, pgRestore, versions });
    }
  }
  throw new Error('cr9_postgresql_18_toolchain_not_found');
}

export function runPsql(toolchain, database, sql, { tuplesOnly = true, env = null } = {}) {
  const args = ['-X', '-d', database, '-v', 'ON_ERROR_STOP=1', '-P', 'pager=off'];
  if (tuplesOnly) args.push('-At');
  return execFileSync(toolchain.psql, args, {
    input: `${String(sql).trim()}\n`,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: env ? { ...process.env, ...env } : process.env,
  }).trim();
}

export function queryJson(toolchain, database, sql) {
  const output = runPsql(toolchain, database, sql);
  if (!output) throw new Error('cr9_postgresql_json_query_empty');
  const payload = output.split(/\r?\n/).findLast((line) => /^[{[]/.test(line.trim()));
  if (!payload) throw new Error('cr9_postgresql_json_payload_missing');
  return JSON.parse(payload);
}

export function normalizeSchemaDump(rawDump) {
  const raw = String(rawDump || '');
  const matches = [...raw.matchAll(/^\\(?:un)?restrict\s+(\S+)\s*$/gm)];
  if (matches.length !== 2 || matches[0][1] !== matches[1][1]) {
    throw new Error('cr9_pg_dump_restrict_pair_invalid');
  }
  const token = matches[0][1];
  const withoutRestriction = raw
    .split(/\r?\n/)
    .filter((line) => !/^\\(?:un)?restrict\s+/.test(line))
    .join('\n');
  const deterministicToken = `homaimoscr9${sha256(Buffer.from(withoutRestriction, 'utf8'))}`;
  const occurrences = raw.split(token).length - 1;
  if (occurrences !== 2) throw new Error('cr9_pg_dump_restrict_token_reused');
  return `${raw.split(token).join(deterministicToken).trimEnd()}\n`;
}

export function captureSchemaDump(toolchain, database, { includePrivileges = true } = {}) {
  const args = ['--dbname', database, '--schema-only', '--no-owner', '--quote-all-identifiers'];
  if (!includePrivileges) args.push('--no-privileges');
  const capture = () => execFileSync(toolchain.pgDump, args, {
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  const first = normalizeSchemaDump(capture());
  const second = normalizeSchemaDump(capture());
  if (first !== second) throw new Error('cr9_schema_dump_nondeterministic');
  return Object.freeze({
    sql: first,
    sha256: sha256(Buffer.from(first, 'utf8')),
    bytes: Buffer.byteLength(first, 'utf8'),
    lines: first.split(/\r?\n/).length,
    repeated_identically: true,
    privileges_included: includePrivileges,
  });
}

function unwrapOuterParentheses(value) {
  let text = String(value || '').trim();
  while (text.startsWith('(') && text.endsWith(')')) {
    let depth = 0;
    let enclosesWholeValue = true;
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const character = text[index];
      if (character === "'" && text[index - 1] !== '\\') quoted = !quoted;
      if (quoted) continue;
      if (character === '(') depth += 1;
      if (character === ')') depth -= 1;
      if (depth === 0 && index < text.length - 1) {
        enclosesWholeValue = false;
        break;
      }
    }
    if (!enclosesWholeValue || depth !== 0) break;
    text = text.slice(1, -1).trim();
  }
  return text;
}

export function normalizeSemanticDefinition(value) {
  const text = String(value ?? '').replaceAll(/\s+/g, ' ').trim();
  const check = /^CHECK\s*\((.*)\)$/i.exec(text);
  if (check) return `CHECK (${unwrapOuterParentheses(check[1])})`;
  return text;
}

const SEMANTIC_SCHEMA_SQL = String.raw`
SELECT json_build_object(
  'extensions', (SELECT coalesce(json_agg(json_build_object('name',extname,'version',extversion,'schema',namespace.nspname)
    ORDER BY extname),'[]'::json) FROM pg_extension extension JOIN pg_namespace namespace ON namespace.oid=extension.extnamespace),
  'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname),'[]'::json) FROM pg_namespace
    WHERE nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp%'),
  'relations', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,'name',relation.relname,
    'kind',relation.relkind,'persistence',relation.relpersistence,'rls',relation.relrowsecurity,
    'force_rls',relation.relforcerowsecurity,'partition_key',pg_get_partkeydef(relation.oid))
    ORDER BY namespace.nspname,relation.relname),'[]'::json)
    FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'
      AND relation.relkind IN ('r','p','v','m','S','f')),
  'columns', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,'relation',relation.relname,
    'name',attribute.attname,'type',format_type(attribute.atttypid,attribute.atttypmod),
    'not_null',attribute.attnotnull,'identity',attribute.attidentity,'generated',attribute.attgenerated,
    'collation',CASE WHEN attribute.attcollation=0 THEN null ELSE collation_record.collname END,
    'default',pg_get_expr(default_value.adbin,default_value.adrelid,true))
    ORDER BY namespace.nspname,relation.relname,attribute.attnum),'[]'::json)
    FROM pg_attribute attribute JOIN pg_class relation ON relation.oid=attribute.attrelid
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
    LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    LEFT JOIN pg_collation collation_record ON collation_record.oid=attribute.attcollation
    WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'
      AND relation.relkind IN ('r','p','v','m','f') AND attribute.attnum>0 AND NOT attribute.attisdropped),
  'constraints', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,'relation',relation.relname,
    'name',constraint_record.conname,'type',constraint_record.contype,'deferrable',constraint_record.condeferrable,
    'deferred',constraint_record.condeferred,'validated',constraint_record.convalidated,
    'definition',pg_get_constraintdef(constraint_record.oid,true))
    ORDER BY namespace.nspname,relation.relname,constraint_record.conname),'[]'::json)
    FROM pg_constraint constraint_record JOIN pg_class relation ON relation.oid=constraint_record.conrelid
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'),
  'indexes', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,'table',table_relation.relname,
    'name',index_relation.relname,'method',access_method.amname,'unique',index_record.indisunique,
    'primary',index_record.indisprimary,'valid',index_record.indisvalid,'ready',index_record.indisready,
    'definition',pg_get_indexdef(index_relation.oid))
    ORDER BY namespace.nspname,table_relation.relname,index_relation.relname),'[]'::json)
    FROM pg_index index_record JOIN pg_class index_relation ON index_relation.oid=index_record.indexrelid
    JOIN pg_class table_relation ON table_relation.oid=index_record.indrelid
    JOIN pg_namespace namespace ON namespace.oid=table_relation.relnamespace
    JOIN pg_am access_method ON access_method.oid=index_relation.relam
    WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'),
  'triggers', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,'table',relation.relname,
    'name',trigger_record.tgname,'enabled',trigger_record.tgenabled,'definition',pg_get_triggerdef(trigger_record.oid,true))
    ORDER BY namespace.nspname,relation.relname,trigger_record.tgname),'[]'::json)
    FROM pg_trigger trigger_record JOIN pg_class relation ON relation.oid=trigger_record.tgrelid
    JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
    WHERE NOT trigger_record.tgisinternal AND namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'),
  'policies', (SELECT coalesce(json_agg(json_build_object('schema',schemaname,'table',tablename,'name',policyname,
    'permissive',permissive,'roles',roles,'command',cmd,'using',qual,'check',with_check)
    ORDER BY schemaname,tablename,policyname),'[]'::json) FROM pg_policies),
  'user_functions', (SELECT coalesce(json_agg(json_build_object('schema',namespace.nspname,
    'identity',procedure.oid::regprocedure::text,'result',pg_get_function_result(procedure.oid),
    'language',language.lanname,'volatility',procedure.provolatile,'strict',procedure.proisstrict,
    'security_definer',procedure.prosecdef,'parallel',procedure.proparallel,'configuration',procedure.proconfig,
    'definition',pg_get_functiondef(procedure.oid)) ORDER BY namespace.nspname,procedure.oid::regprocedure::text),'[]'::json)
    FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace
    JOIN pg_language language ON language.oid=procedure.prolang
    WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
      AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%'
      AND NOT EXISTS (SELECT 1 FROM pg_depend dependency WHERE dependency.classid='pg_proc'::regclass
        AND dependency.objid=procedure.oid AND dependency.deptype='e')),
  'sequences', (SELECT coalesce(json_agg(json_build_object('schema',schemaname,'name',sequencename,
    'type',data_type,'start',start_value,'minimum',min_value,'maximum',max_value,'increment',increment_by,
    'cycle',cycle,'cache',cache_size) ORDER BY schemaname,sequencename),'[]'::json)
    FROM pg_sequences WHERE schemaname NOT LIKE 'pg_%' AND schemaname<>'information_schema')
);
`;

function normalizeSemanticProjection(projection) {
  const normalized = structuredClone(projection);
  for (const group of ['relations', 'columns', 'constraints', 'indexes', 'triggers', 'policies', 'user_functions']) {
    for (const record of normalized[group] || []) {
      for (const key of ['partition_key', 'default', 'definition', 'using', 'check']) {
        if (record[key] != null) record[key] = normalizeSemanticDefinition(record[key]);
      }
    }
  }
  return normalized;
}

export function captureSemanticSchema(toolchain, database) {
  const projection = normalizeSemanticProjection(queryJson(
    toolchain,
    database,
    `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n${SEMANTIC_SCHEMA_SQL}\nCOMMIT;`,
  ));
  const root = sha256(Buffer.from(canonicalJson(projection), 'utf8'));
  return Object.freeze({
    schema: 'hom.aimos.cr9-semantic-schema-projection/v1',
    database,
    projection,
    root_sha256: root,
  });
}

const AUDIT_SQL = String.raw`
SELECT json_build_object(
  'server_version', current_setting('server_version'),
  'database', current_database(),
  'role', (SELECT json_build_object(
    'superuser',rolsuper,'inherit',rolinherit,'create_role',rolcreaterole,
    'create_db',rolcreatedb,'can_login',rolcanlogin,'replication',rolreplication,
    'bypass_rls',rolbypassrls
  ) FROM pg_roles WHERE rolname='agent_runtime'),
  'memberships', (SELECT coalesce(json_agg(parent.rolname ORDER BY parent.rolname),'[]'::json)
    FROM pg_auth_members membership JOIN pg_roles child ON child.oid=membership.member
    JOIN pg_roles parent ON parent.oid=membership.roleid WHERE child.rolname='agent_runtime'),
  'database_privileges', json_build_object(
    'connect',has_database_privilege('agent_runtime',current_database(),'CONNECT'),
    'create',has_database_privilege('agent_runtime',current_database(),'CREATE'),
    'temporary',has_database_privilege('agent_runtime',current_database(),'TEMPORARY')),
  'schema_privileges', json_build_object(
    'public_usage',has_schema_privilege('agent_runtime','public','USAGE'),
    'public_create',has_schema_privilege('agent_runtime','public','CREATE')),
  'table_privileges', (SELECT coalesce(json_agg(table_schema||'.'||table_name||':'||privilege_type
    ORDER BY table_schema,table_name,privilege_type),'[]'::json)
    FROM information_schema.role_table_grants WHERE grantee='agent_runtime'),
  'column_privileges', (SELECT coalesce(json_agg(n.nspname||'.'||c.relname||'.'||a.attname||':'||acl.privilege_type
    ORDER BY n.nspname,c.relname,a.attname,acl.privilege_type),'[]'::json)
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(a.attacl) acl LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
    WHERE n.nspname='public' AND grantee.rolname='agent_runtime'),
  'sequence_privileges', (SELECT coalesce(json_agg(n.nspname||'.'||c.relname||':'||privilege.priv
    ORDER BY n.nspname,c.relname,privilege.priv),'[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN (VALUES ('SELECT'),('USAGE'),('UPDATE')) privilege(priv)
    WHERE c.relkind='S' AND n.nspname='public'
      AND has_sequence_privilege('agent_runtime',c.oid,privilege.priv)),
  'required_insert_sequences', (WITH insertable AS (
      SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p')
        AND (has_table_privilege('agent_runtime',c.oid,'INSERT') OR has_any_column_privilege('agent_runtime',c.oid,'INSERT'))
    ), required AS (
      SELECT DISTINCT sequence_namespace.nspname,sequence.relname
      FROM insertable JOIN pg_attribute attribute ON attribute.attrelid=insertable.oid
        AND attribute.attnum>0 AND NOT attribute.attisdropped
      JOIN pg_depend dependency ON dependency.refobjid=insertable.oid
        AND dependency.refobjsubid=attribute.attnum AND dependency.deptype IN ('a','i')
      JOIN pg_class sequence ON sequence.oid=dependency.objid AND sequence.relkind='S'
      JOIN pg_namespace sequence_namespace ON sequence_namespace.oid=sequence.relnamespace
    ) SELECT coalesce(json_agg(nspname||'.'||relname ORDER BY nspname,relname),'[]'::json) FROM required),
  'non_extension_functions', (SELECT coalesce(json_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text),'[]'::json)
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND has_function_privilege('agent_runtime',p.oid,'EXECUTE')
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')),
  'public_non_extension_functions', (SELECT coalesce(json_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text),'[]'::json)
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND has_function_privilege('public',p.oid,'EXECUTE')
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')),
  'extension_versions', (SELECT json_object_agg(extname,extversion ORDER BY extname) FROM pg_extension),
  'delete_tables', (SELECT coalesce(json_agg(format('%I.%I',schemaname,tablename) ORDER BY schemaname,tablename),'[]'::json)
    FROM pg_tables WHERE has_table_privilege('agent_runtime',quote_ident(schemaname)||'.'||quote_ident(tablename),'DELETE')),
  'truncate_tables', (SELECT coalesce(json_agg(format('%I.%I',schemaname,tablename) ORDER BY schemaname,tablename),'[]'::json)
    FROM pg_tables WHERE has_table_privilege('agent_runtime',quote_ident(schemaname)||'.'||quote_ident(tablename),'TRUNCATE')),
  'owned_relations', (SELECT coalesce(json_agg(format('%I.%I',n.nspname,c.relname) ORDER BY n.nspname,c.relname),'[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
    WHERE r.rolname='agent_runtime'),
  'owned_functions', (SELECT coalesce(json_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text),'[]'::json)
    FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE r.rolname='agent_runtime'),
  'rls', (SELECT coalesce(json_agg(json_build_object('table',n.nspname||'.'||c.relname,'enabled',c.relrowsecurity,
    'forced',c.relforcerowsecurity,'owner',pg_get_userbyid(c.relowner)) ORDER BY n.nspname,c.relname),'[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p') AND c.relrowsecurity),
  'migrations_098_099', (SELECT json_agg(json_build_object('filename',filename,'checksum',checksum,'applied_at',applied_at)
    ORDER BY filename) FROM schema_migrations WHERE filename LIKE '098-%' OR filename LIKE '099-%'),
  'semantics_098_099', json_build_object(
    'receipt_index', pg_get_indexdef('public.aimos_request_receipts_company_mutation_lookup'::regclass),
    'valence_columns', (SELECT json_agg(json_build_object('name',column_name,'type',data_type,'nullable',is_nullable,'default',column_default)
      ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='memory_valence_ledger'
      AND column_name=ANY(ARRAY['evidence_schema_version','target_scope','target_live_content_hash','target_occurrence_ref','recall_event_id',
        'recall_event_mutation_hash','recall_merkle_root','security_closure_hash','outcome_id','outcome_event_id','outcome_event_mutation_hash'])),
    'valence_constraints', (SELECT json_agg(conname||':'||pg_get_constraintdef(oid,true) ORDER BY conname)
      FROM pg_constraint WHERE conrelid='public.memory_valence_ledger'::regclass
      AND conname=ANY(ARRAY['memory_valence_ledger_r7m_v2_complete','memory_valence_ledger_recall_event_fkey','memory_valence_ledger_outcome_event_fkey'])),
    'valence_indexes', (SELECT json_agg(indexname||':'||indexdef ORDER BY indexname) FROM pg_indexes
      WHERE schemaname='public' AND tablename='memory_valence_ledger'
      AND indexname=ANY(ARRAY['memory_valence_r7m_outcome_unique','memory_valence_r7m_outcome_event_unique','memory_valence_r7m_principal_state']))
  )
);
`;

export function auditLiveSchemaPrivileges(toolchain, database = 'aimos') {
  return queryJson(toolchain, database, `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n${AUDIT_SQL}\nCOMMIT;`);
}

export function evaluatePrivilegeClosure(audit) {
  const expectedSequencePrivileges = EXPECTED_RUNTIME_SEQUENCES
    .flatMap((sequence) => [`${sequence}:SELECT`, `${sequence}:USAGE`]).sort();
  const checks = Object.freeze({
    role_restricted: audit.role?.superuser === false && audit.role?.create_role === false
      && audit.role?.create_db === false && audit.role?.replication === false
      && audit.role?.bypass_rls === false,
    no_memberships: Array.isArray(audit.memberships) && audit.memberships.length === 0,
    database_exact: audit.database_privileges?.connect === true
      && audit.database_privileges?.create === false && audit.database_privileges?.temporary === false,
    schema_exact: audit.schema_privileges?.public_usage === true && audit.schema_privileges?.public_create === false,
    zero_delete: audit.delete_tables?.length === 0,
    zero_truncate: audit.truncate_tables?.length === 0,
    zero_ownership: audit.owned_relations?.length === 0 && audit.owned_functions?.length === 0,
    exact_sequences: canonicalJson(audit.sequence_privileges || []) === canonicalJson(expectedSequencePrivileges),
    exact_sequence_dependency_contract: canonicalJson(audit.required_insert_sequences || [])
      === canonicalJson(EXPECTED_RUNTIME_SEQUENCES),
    exact_non_extension_functions: canonicalJson(audit.non_extension_functions || [])
      === canonicalJson(EXPECTED_NON_EXTENSION_FUNCTIONS),
    no_public_application_functions: audit.public_non_extension_functions?.length === 0,
    rls_binds_runtime: Array.isArray(audit.rls) && audit.rls.length > 0
      && audit.rls.every((entry) => entry.enabled === true && entry.owner !== 'agent_runtime'),
    historical_migration_uncertainty_retained: Array.isArray(audit.migrations_098_099)
      && audit.migrations_098_099.length === 2,
    live_098_099_semantics_present: /aimos_request_receipts_company_mutation_lookup/.test(audit.semantics_098_099?.receipt_index || '')
      && audit.semantics_098_099?.valence_columns?.length === 11
      && audit.semantics_098_099?.valence_constraints?.length === 3
      && audit.semantics_098_099?.valence_indexes?.length === 3,
  });
  return Object.freeze({
    checks,
    valid: Object.values(checks).every(Boolean),
    excess_sequences: (audit.sequence_privileges || []).filter((entry) => !expectedSequencePrivileges.includes(entry)),
    missing_sequences: expectedSequencePrivileges.filter((entry) => !(audit.sequence_privileges || []).includes(entry)),
  });
}

function quoteIdent(identifier) {
  return `"${String(identifier).replaceAll('"', '""')}"`;
}

export function privilegeRepairSql(database = 'aimos') {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)) throw new Error('cr9_database_name_invalid');
  const sequences = EXPECTED_RUNTIME_SEQUENCES.map((name) => name.split('.').map(quoteIdent).join('.')).join(', ');
  return `
REVOKE TEMPORARY ON DATABASE ${quoteIdent(database)} FROM PUBLIC, agent_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM agent_runtime;
GRANT USAGE, SELECT ON SEQUENCE ${sequences} TO agent_runtime;
`;
}

export function tableCensus(toolchain, database) {
  const relations = queryJson(toolchain, database, `SELECT coalesce(json_agg(json_build_object('schema',n.nspname,'table',c.relname)
    ORDER BY n.nspname,c.relname),'[]'::json) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%';`);
  const rows = [];
  for (const relation of relations) {
    const qualified = `${quoteIdent(relation.schema)}.${quoteIdent(relation.table)}`;
    const count = Number(runPsql(toolchain, database, `SELECT count(*)::bigint FROM ${qualified};`));
    rows.push(Object.freeze({ ...relation, count }));
  }
  return Object.freeze({ rows: Object.freeze(rows), root_sha256: sha256(Buffer.from(canonicalJson(rows), 'utf8')) });
}

export function privilegeContract(audit) {
  const contract = {
    schema: 'hom.aimos.cr9-agent-runtime-privilege-contract/v1',
    role: audit.role,
    memberships: audit.memberships,
    database_privileges: audit.database_privileges,
    schema_privileges: audit.schema_privileges,
    table_privileges: audit.table_privileges,
    column_privileges: audit.column_privileges,
    sequence_privileges: audit.sequence_privileges,
    required_insert_sequences: audit.required_insert_sequences,
    non_extension_functions: audit.non_extension_functions,
    public_non_extension_functions: audit.public_non_extension_functions,
    extension_versions: audit.extension_versions,
    delete_tables: audit.delete_tables,
    truncate_tables: audit.truncate_tables,
    owned_relations: audit.owned_relations,
    owned_functions: audit.owned_functions,
    rls: audit.rls,
  };
  return Object.freeze({ ...contract, contract_sha256: sha256(Buffer.from(canonicalJson(contract), 'utf8')) });
}

export const CR9_POSTGRES_CONTRACT = Object.freeze({
  expectedRuntimeSequences: EXPECTED_RUNTIME_SEQUENCES,
  expectedNonExtensionFunctions: EXPECTED_NON_EXTENSION_FUNCTIONS,
});

export { canonicalJson, sha256 };
