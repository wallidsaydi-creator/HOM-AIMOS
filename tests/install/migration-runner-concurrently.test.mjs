import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { splitSqlStatements } from '../../migrations/run.js';

test('concurrent index migration is emitted as separate protocol statements', () => {
  const sql = readFileSync(
    new URL('../../migrations/094-native-retrieval-temporal-neighborhood-index.sql', import.meta.url),
    'utf8',
  );
  const statements = splitSqlStatements(sql);
  assert.equal(statements.length, 2);
  assert.match(statements[0], /CREATE\s+INDEX\s+CONCURRENTLY/i);
  assert.match(statements[1], /^COMMENT\s+ON\s+INDEX/i);
});

test('statement splitting preserves semicolons inside PostgreSQL lexical forms', () => {
  const statements = splitSqlStatements(`
    -- comment ; is not a boundary
    SELECT 'a;''b', "quoted;identifier";
    /* block ; comment */
    DO $body$ BEGIN PERFORM 'x;y'; END $body$;
    SELECT 3;
  `);
  assert.equal(statements.length, 3);
  assert.match(statements[0], /SELECT 'a;''b'/);
  assert.match(statements[1], /DO \$body\$/);
  assert.match(statements[2], /SELECT 3/);
});
