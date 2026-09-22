import test from 'node:test';
import assert from 'node:assert/strict';
import { runMigrations, getMigrationFiles, parseMigrationIndexContract, verifyMigrationIndex } from '../../migrations/run.js';
import { readFileSync } from 'node:fs';
import { splitSqlStatements } from '../../migrations/run.js';

test('AUD-015 check does not initialize or backfill the migration ledger', async () => {
  for (const exists of [false, true]) {
    const statements = [];
    const inspection = {
      async query(sql) {
        const text = String(sql).trim(); statements.push(text);
        assert.match(text, /^SELECT\b/i, `inspection attempted mutation: ${text.slice(0, 70)}`);
        if (text.includes('to_regclass')) return { rows: [{ tracking_table: exists ? 'schema_migrations' : null }] };
        if (text.includes('FROM schema_migrations')) return { rows: [{ filename: getMigrationFiles()[0], checksum: null }] };
        return { rows: [] };
      },
    };
    const result = await runMigrations(inspection, { check: true, verbose: false });
    assert.equal(result.backfilled, 0);
    assert.equal(result.trackingTableExists, exists);
    assert.ok(result.pending.length > 0);
    assert.deepEqual(result.legacyUnverified, exists ? [getMigrationFiles()[0]] : []);
    assert.ok(statements.length > 0);
  }
});

test('AUD-015 admits only exact concurrent index definitions with valid catalog state', async () => {
  let count = 0;
  for (const filename of getMigrationFiles()) {
    const sql = readFileSync(new URL(`../../migrations/${filename}`, import.meta.url), 'utf8');
    for (const statement of splitSqlStatements(sql)) {
      if (!/CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY/i.test(statement)) continue;
      const contract = parseMigrationIndexContract(statement);
      const catalog = { definition: statement, indisvalid: true, indisready: true, indislive: true,
        indnullsnotdistinct: false, no_included_columns: true, no_expression: true };
      const client = { query: async () => ({ rows: [catalog] }) };
      assert.equal(await verifyMigrationIndex(client, contract), true);
      for (const flag of ['indisvalid', 'indisready', 'indislive', 'no_expression', 'no_included_columns']) {
        catalog[flag] = false;
        await assert.rejects(verifyMigrationIndex(client, contract), /migration_index_not_valid/);
        catalog[flag] = true;
      }
      catalog.definition = statement.replace(/\bON\s+(?:public\.)?\w+/i, 'ON public.wrong_relation');
      await assert.rejects(verifyMigrationIndex(client, contract), /migration_index_definition_mismatch/);
      count++;
    }
  }
  assert.equal(count, 10);
});

test('AUD-015 competing runner fails before any DDL on the held database session', async () => {
  const queries = [];
  let releases = 0;
  const client = { query: async (sql) => { queries.push(sql); return { rows: [{ locked: false }] }; },
    release: () => releases++ };
  await assert.rejects(runMigrations({ connect: async () => client }), /migration_runner_already_active/);
  assert.equal(queries.length, 1);
  assert.match(queries[0], /pg_try_advisory_lock/);
  assert.equal(releases, 1);
});

test('AUD-015 quoted lookalike identifiers are rejected rather than erased', () => {
  for (const statement of [
    'CREATE INDEX CONCURRENTLY q ON public.real_rows ("i""d");',
    'CREATE INDEX CONCURRENTLY q ON public."real_""rows" (id);',
    'CREATE INDEX CONCURRENTLY "q""q" ON public.real_rows (id);',
  ]) assert.throws(() => parseMigrationIndexContract(statement), /migration_index_.*unsupported/);
});

test('AUD-015 final index validation precedes applied-row recording', async () => {
  let present = false, recorded = false;
  const definition = 'CREATE INDEX CONCURRENTLY q ON public.real_rows (id)';
  const client = { async query(sql) {
    if (sql.includes('FROM pg_index')) return { rows: present ? [{ definition,
      indisvalid:true,indisready:true,indislive:true,indnullsnotdistinct:false,
      no_included_columns:true,no_expression:true }] : [] };
    if (sql.startsWith('CREATE INDEX')) present = true;
    if (sql.startsWith('DROP INDEX')) present = false;
    if (sql.startsWith('INSERT INTO schema_migrations')) recorded = true;
    return { rows: [] };
  } };
  const { applyMigration } = await import('../../migrations/run.js');
  await assert.rejects(applyMigration(client, 'audit-late-drop.sql', definition + '; DROP INDEX q;'), /migration_index_not_valid/);
  assert.equal(recorded, false);
});
