// Actual SQL codec functions inside the existing runner-owned database.
// No canonical DDL/data, new identity, signature, listener or memory copy.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { createHash } from 'node:crypto';
import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';
import { signedJsonBytesCommitmentV1 } from '../../services/security/protocol/mutmem-protocol.js';
import { wireCases, wireSchema } from './audit-018-wire-cases.mjs';
if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert(/^aimos_test_security_audr5_[0-9]+_[a-f0-9]{6}$/.test(database));
const c = new pg.Client({ connectionString: resolveAimosDatabaseUrl(), ssl: false }); await c.connect();
try {
  assert.equal((await c.query('SELECT current_database() AS db')).rows[0].db, database);
  await c.query('BEGIN'); await c.query("SET LOCAL statement_timeout='10s'");
  const before = (await c.query("SELECT pg_get_functiondef('public.ob2_canonical_json(jsonb)'::regprocedure) AS body")).rows[0].body;
  const definitions = readFileSync(new URL('../../db/signed-json-bytes.sql', import.meta.url), 'utf8');
  await c.query(definitions);
  const results = [];
  for (const item of wireCases) {
    await c.query('SAVEPOINT wire_case');
    let hash, reason;
    try { hash = (await c.query('SELECT encode(public.signed_json_bytes_commitment_v1($1,$2),\'hex\') AS hash', [wireSchema, item.wire])).rows[0].hash; }
    catch (error) { reason = error.message; await c.query('ROLLBACK TO SAVEPOINT wire_case'); }
    await c.query('RELEASE SAVEPOINT wire_case');
    assert.equal(!reason, item.accepted, `${item.name}:${reason}`);
    if (item.accepted) assert.equal(hash, signedJsonBytesCommitmentV1(wireSchema, item.wire).toString('hex'), item.name);
    else assert.equal(reason, 'signed_json_wire_invalid', item.name);
    results.push({ name: item.name, accepted: !reason, hash: hash ?? null, reason: reason ?? null });
  }
  assert.equal((await c.query("SELECT pg_get_functiondef('public.ob2_canonical_json(jsonb)'::regprocedure) AS body")).rows[0].body, before);
  assert.equal((await c.query("SELECT has_function_privilege('agent_runtime','public.signed_json_bytes_commitment_v1(text,bytea)','EXECUTE') AS allowed")).rows[0].allowed, false);
  await c.query('ROLLBACK');
  console.log(JSON.stringify({ database, definitions_sha256: createHash('sha256').update(definitions).digest('hex'),
    historical_sql_unchanged: true, runtime_execute_grant: false, candidate_ddl_rolled_back: true, results,
    typed_writer_integration_proved: false, production_changed: false, signature_created: false }, null, 2));
} finally { await c.end(); }
