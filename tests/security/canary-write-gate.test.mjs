import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  buildCanaryWriteDisposition,
  CANARY_QUARANTINE_REASON,
} from '../../services/security/canary-write-gate.js';

test('a detected write canary forces retained quarantine and never suppression', () => {
  const result = buildCanaryWriteDisposition({
    canariesFound: ['SECRET-DEADBEEF'],
    kill_chain_diagnostics: { stage: 'PERSISTED' },
  });

  assert.equal(result.detected, true);
  assert.equal(result.quarantine, true);
  assert.equal(result.reject, false);
  assert.equal(result.reason, CANARY_QUARANTINE_REASON);
  assert.deepEqual(result.tokens, ['SECRET-DEADBEEF']);
});

test('a clean scan has no quarantine side effect', () => {
  const result = buildCanaryWriteDisposition({ canariesFound: [] });
  assert.equal(result.detected, false);
  assert.equal(result.quarantine, false);
  assert.equal(result.reject, false);
  assert.equal(result.reason, null);
});

test('production write boundary awaits native scan and signed disposition receipt', async () => {
  const source = await readFile(
    new URL('../../services/security/canary-write-gate.js', import.meta.url),
    'utf8',
  );
  assert.match(source, /await scanMemoryWrite\(/);
  assert.match(source, /await logEvent\(/);
  assert.match(source, /returnReceipt: true/);
  assert.doesNotMatch(source, /governorConfigLedger|ENFORCE_CANARY_WRITE|canary_write_rejected/);
});

test('REST and MCP saves both compose Canary disposition into native security quarantine', async () => {
  const [rest, mcp] = await Promise.all([
    readFile(new URL('../../routes/aimos.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/aimos-mcp-streamable.js', import.meta.url), 'utf8'),
  ]);
  for (const source of [rest, mcp]) {
    assert.match(source, /await evaluateCanaryWrite\(/);
    assert.match(source, /canaryDecision\.quarantine/);
    assert.match(source, /security_disposition:/);
  }
});
