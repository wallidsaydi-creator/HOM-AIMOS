import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyConsensus, runHebbianConsensusBatch, HEBBIAN_CONSTANTS } from '../../services/dream/hebbian-consensus.js';
import { pool, agentPool } from '../../db/connection.js';

// Consensus classification (HeLa-Mem hub vs fringe) — pure, no DB.
test('classifyConsensus: supported hub elevates, divergent outlier attenuates, middle is neutral', () => {
  assert.equal(classifyConsensus(0.97), 1, 'tight-cluster hub → elevate');
  assert.equal(classifyConsensus(HEBBIAN_CONSTANTS.ALIGN_HIGH), 1, 'exactly HIGH → elevate');
  assert.equal(classifyConsensus(0.74), -1, 'fringe member → attenuate');
  assert.equal(classifyConsensus(HEBBIAN_CONSTANTS.ALIGN_LOW), -1, 'exactly LOW → attenuate');
  const mid = (HEBBIAN_CONSTANTS.ALIGN_HIGH + HEBBIAN_CONSTANTS.ALIGN_LOW) / 2;
  assert.equal(classifyConsensus(mid), 0, 'between thresholds → no change');
});

// Shadow-first: the nightly pass does nothing until the governor flag is ON,
// and never reaches the DB on the disabled path.
test('runHebbianConsensusBatch is a no-op unless HEBBIAN_CONSENSUS is enabled', async () => {
  const off = await runHebbianConsensusBatch(0, 28, { readFlag: async () => false });
  assert.equal(off.enabled, false, 'flag OFF → disabled');
  assert.equal(off.reviewed, 0, 'no memory reviewed when disabled');

  const noFlagFn = await runHebbianConsensusBatch(0, 28, {});
  assert.equal(noFlagFn.enabled, false, 'absent flag reader → disabled (fail-closed)');

  const throws = await runHebbianConsensusBatch(0, 28, { readFlag: async () => { throw new Error('read fail'); } });
  assert.equal(throws.enabled, false, 'flag read error → disabled (fail-closed)');

  await Promise.allSettled([agentPool.end(), pool.end()]);
});
