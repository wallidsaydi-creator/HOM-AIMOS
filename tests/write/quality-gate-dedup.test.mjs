import test from 'node:test';
import assert from 'node:assert/strict';

import { wall2_filter } from '../../services/write/quality-gate.js';
import {
  findExactGenesisManifestBinding,
  findRecentCommittedDuplicate,
} from '../../services/write/persist-memory.js';

test('dedup compares the complete value rather than a shared prefix', () => {
  const sharedPrefix = `retained-session-prefix:${'x'.repeat(340)}`;
  const first = `${sharedPrefix}:sequence=9:turn=first`;
  const second = `${sharedPrefix}:sequence=11:turn=second`;

  assert.equal(wall2_filter('sess:test:turn:9', first, 'conversation_feed').pass, true);
  assert.equal(wall2_filter('sess:test:turn:11', second, 'conversation_feed').pass, true);
});

test('quality filtering is pure and defers exact-value dedup to persistence', () => {
  const value = `exact-dedup-fixture:${'y'.repeat(340)}:terminal`;

  const first = wall2_filter('fixture:first', value, 'declarative');
  const repeated = wall2_filter('fixture:second', value, 'declarative');
  assert.equal(first.pass, true);
  assert.equal(repeated.pass, true);
  assert.equal(first.dedup_status, 'pending_committed_check');
  assert.equal(repeated.dedup_status, 'pending_committed_check');
});

test('committed dedup has no process state and cannot be poisoned by rollback', async () => {
  const value = `rollback-safe-dedup:${'z'.repeat(340)}:terminal`;
  let committedRow = null;
  const statements = [];
  const client = {
    async query(sql, params = []) {
      statements.push({ sql, params });
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
      if (sql.includes('FROM aimos_memories')) {
        assert.equal(params[0], 'hom');
        assert.equal(params[1], value);
        assert.equal(params[2], null);
        assert.equal(params[3], null);
        assert.equal(params[4], null);
        return { rows: committedRow ? [committedRow] : [] };
      }
      throw new Error(`unexpected SQL: ${sql}`);
    },
  };

  // Two aborted/uncommitted attempts remain invisible because the helper owns
  // no process-local cache. A later retry is therefore still admissible.
  assert.equal(await findRecentCommittedDuplicate(client, 'hom', value), null);
  assert.equal(await findRecentCommittedDuplicate(client, 'hom', value), null);

  committedRow = { id: '00000000-0000-4000-8000-000000000001' };
  assert.deepEqual(await findRecentCommittedDuplicate(client, 'hom', value), committedRow);
  assert.equal(statements.filter(({ sql }) => sql.includes('pg_advisory_xact_lock')).length, 3);
});

test('committed dedup is isolated to the exact native session scope', async () => {
  const value = `paired-scope-value:${'p'.repeat(80)}`;
  const observed = [];
  const client = {
    async query(sql, params = []) {
      observed.push({ sql, params });
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [] };
      if (sql.includes('FROM aimos_memories')) return { rows: [] };
      throw new Error(`unexpected SQL: ${sql}`);
    },
  };

  await findRecentCommittedDuplicate(client, 'hom', value, { sessionId: 'prg_a_%\\b' });
  const lookup = observed.find(({ sql }) => sql.includes('FROM aimos_memories'));
  assert.equal(lookup.params[2], 'sess:prg\\_a\\_\\%\\\\b:%');
  assert.equal(lookup.params[3], 'sess:prg_a_%\\b:');
  assert.equal(lookup.params[4], 'sess:prg_a_%\\b:\uFFFF');
  assert.match(lookup.sql, /key LIKE \$3 ESCAPE/);
  assert.match(lookup.sql, /key COLLATE "C" >= \$4::text COLLATE "C"/);
  assert.match(lookup.sql, /key COLLATE "C" < \$5::text COLLATE "C"/);
  assert.match(observed[0].params[0], /aimos:dedup:v2:/);
});

test('Genesis corpus rebinding lookup binds every signed manifest field', async () => {
  const body = {
    genesis_manifest_schema: 'hom.aimos.genesis-manifest/v1',
    genesis_manifest_version: 5,
    genesis_corpus_root: 'a'.repeat(64),
    genesis_file_path: 'Guide/AGENTS.md',
    genesis_file_sha256: 'b'.repeat(64),
    genesis_file_bytes: 2763,
  };
  let observed;
  const client = {
    async query(sql, params) {
      observed = { sql, params };
      return { rows: [{ id: '00000000-0000-4000-8000-000000000005' }] };
    },
  };

  const row = await findExactGenesisManifestBinding(
    client,
    'hom',
    'guide:housekeeper:AGENTS',
    'retained guide bytes',
    body,
  );
  assert.equal(row.id, '00000000-0000-4000-8000-000000000005');
  assert.match(observed.sql, /JOIN aimos_memory_provenance/);
  assert.match(observed.sql, /m\.source = 'guide:genesis-install'/);
  assert.deepEqual(observed.params, [
    'hom',
    'guide:housekeeper:AGENTS',
    'retained guide bytes',
    body.genesis_manifest_schema,
    '5',
    body.genesis_corpus_root,
    body.genesis_file_path,
    body.genesis_file_sha256,
    2763,
  ]);
});
