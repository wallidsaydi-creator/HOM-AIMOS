import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  deriveHubThreshold,
  classifyConsensus,
  runHebbianConsensusBatch,
  HEBBIAN_CONSTANTS,
} from '../../services/dream/hebbian-consensus.js';
import { pool, agentPool } from '../../db/connection.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function row(strength, receiptCount = 4, neighborCount = 3) {
  return {
    association_strength: strength,
    receipt_count: receiptCount,
    neighbor_count: neighborCount,
  };
}

test('HeLa-Mem hub threshold is derived from supported positive association strength', () => {
  const threshold = deriveHubThreshold([
    row(0.10), row(0.12), row(0.13), row(0.14), row(0.15), row(0.60),
  ]);
  assert.equal(threshold.ready, true);
  assert.ok(threshold.threshold > threshold.q3);
  assert.equal(classifyConsensus(row(0.60), threshold.threshold), 1);
  assert.equal(classifyConsensus(row(0.15), threshold.threshold), 0);
  assert.equal(classifyConsensus(row(4, 1, 10), threshold.threshold), 0,
    'one receipt is not a learned association');
});

test('insufficient association population cannot activate a mutation', () => {
  const threshold = deriveHubThreshold([row(0.2), row(0.3), row(0.4)]);
  assert.equal(threshold.ready, false);
  assert.equal(threshold.threshold, null);
  assert.equal(classifyConsensus(row(10), threshold.threshold), 0);
});

test('Hebbian constants contain no decay, attenuation, or deletion lane', () => {
  assert.equal(HEBBIAN_CONSTANTS.association_learning_rate, 0.02);
  assert.equal(Object.hasOwn(HEBBIAN_CONSTANTS, 'decay_rate'), false);
  assert.equal(Object.hasOwn(HEBBIAN_CONSTANTS, 'align_low'), false);
  assert.equal(Object.hasOwn(HEBBIAN_CONSTANTS, 'inactive'), false);
});

test('Hebbian batching assigns complete principal states rather than occurrence UUIDs', () => {
  const source = fs.readFileSync(path.join(ROOT, 'services/dream/hebbian-consensus.js'), 'utf8');
  assert.match(source, /encode\(content_hash,'hex'\).*length\(agent_id\).*agent_id/s);
  assert.doesNotMatch(source, /hashtextextended\(id::text/);
  assert.doesNotMatch(source, /embedding IS NOT NULL/);
  assert.match(source, /hebbian_principal_state_batch_bound_exceeded/);
});

test('runHebbianConsensusBatch is inert unless the signed flag head is enabled', async () => {
  const off = await runHebbianConsensusBatch(0, 28, { readFlag: async () => false });
  assert.equal(off.enabled, false);
  assert.equal(off.reviewed, 0);
  assert.equal(off.reason, 'signed_activation_head_not_enabled');

  const noReader = await runHebbianConsensusBatch(0, 28, {});
  assert.equal(noReader.enabled, false);
  assert.equal(noReader.reason, 'signed_flag_reader_required');

  const unavailable = await runHebbianConsensusBatch(0, 28, {
    readFlag: async () => { throw new Error('ledger_down'); },
  });
  assert.equal(unavailable.enabled, false);
  assert.equal(unavailable.reason, 'signed_activation_head_unavailable:ledger_down');

  await Promise.allSettled([agentPool.end(), pool.end()]);
});
