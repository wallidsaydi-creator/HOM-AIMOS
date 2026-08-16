import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const SOURCES = [
  '../../services/observe/event-ledger.js',
  '../../services/security/request-receipt-ledger.js',
];

test('read-only ledger verifiers serialize queries on checked-out transaction clients', async () => {
  for (const relative of SOURCES) {
    const source = await readFile(new URL(relative, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /Promise\.all\(\[\s*(?:conn|client)\.query\(/s, relative);
  }
});
