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

test('one canonical SAVE owner composes Canary disposition for every transport', async () => {
  const [owner, rest, mcp] = await Promise.all([
    readFile(new URL('../../services/write/canonical-save-owner.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/aimos.js', import.meta.url), 'utf8'),
    readFile(new URL('../../routes/aimos-mcp-streamable.js', import.meta.url), 'utf8'),
  ]);
  assert.match(owner, /await deps\.evaluateCanaryWrite\(/);
  assert.match(owner, /canaryDecision\.quarantine/);
  assert.match(owner, /canary_disposition:/);
  assert.match(owner, /appendCanonicalSaveStage\(trace, 'SE', 'DISABLED'/);
  assert.match(rest, /executeCanonicalSave\(/);
  assert.match(mcp, /executeCanonicalSave\(/);
  assert.doesNotMatch(rest, /await evaluateCanaryWrite\(/);
  assert.doesNotMatch(mcp, /await evaluateCanaryWrite\(/);
});

test('canonical save scans are parented to signed request or internal-action receipts', async () => {
  const owner = await readFile(new URL('../../services/write/canonical-save-owner.js', import.meta.url), 'utf8');
  assert.match(owner, /runId: authority\?\.requestReceiptId \|\| receiptBinding\.evidence\?\.event_id \|\| ''/);
  assert.match(owner, /parentEventId: currentParentEventId/);
  assert.match(owner, /canonical_save_action_started/);
});
