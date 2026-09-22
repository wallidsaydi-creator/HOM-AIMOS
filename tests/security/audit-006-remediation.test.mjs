import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const ROOT = new URL('../../', import.meta.url);
const read = path => readFileSync(new URL(path, ROOT), 'utf8');

test('transaction and canonical SAVE owners expose three-state commit truth and exact-operation reconciliation', () => {
  const connection = read('db/connection.js');
  const save = read('services/write/canonical-save-owner.js');
  assert.match(connection, /COMMITTED/);
  assert.match(connection, /NOT_COMMITTED/);
  assert.match(connection, /INDETERMINATE/);
  assert.match(connection, /pg_xact_status\(\$1::xid8\)/);
  assert.match(connection, /client\.release\(error\)/);
  assert.match(save, /save_operation_id/);
  assert.match(save, /readCompletedSave/);
  assert.match(save, /canonicalSaveOutcome/);
  assert.match(save, /repeatSave:false/);
  assert.doesNotMatch(save, /transaction_rolled_back:\s*true/);
});

