import assert from 'node:assert/strict';
import test from 'node:test';

import { computeValence } from '../../services/governance/valence-judge.js';
import { referencePointWeightUpdate } from '../../services/learning/stdp-kernel.js';

test('valence is age-neutral and signed evidence can reverse', async () => {
  const negative = await computeValence('memory-1', {
    ledger: { readValenceEvents: async () => [
      { reward_sign: -1, evidence_count: 3 },
      { reward_sign: 1, evidence_count: 1 }
    ] }
  });
  const positive = await computeValence('memory-1', {
    ledger: { readValenceEvents: async () => [
      { reward_sign: -1, evidence_count: 3 },
      { reward_sign: 1, evidence_count: 5 }
    ] }
  });
  assert.ok(negative < 0);
  assert.ok(positive > 0);
  assert.equal(await computeValence('memory-1', { ledger: { readValenceEvents: async () => [] } }), 0);
});

test('reference-point mutation is reversible in log-space and never crosses the floor', () => {
  const down = referencePointWeightUpdate(1, -1, 0.2);
  const up = referencePointWeightUpdate(1, 1, 0.2);
  assert.ok(down < 1 && up > 1);
  assert.ok(Math.abs(Math.log(down) + Math.log(up)) < 1e-12);

  let weight = 1;
  weight = referencePointWeightUpdate(weight, -1, 0.5);
  weight = referencePointWeightUpdate(weight, -1, 0.5);
  assert.ok(weight >= 0.1 && weight < 1);
  weight = referencePointWeightUpdate(weight, 1, 0.5);
  weight = referencePointWeightUpdate(weight, 1, 0.5);
  weight = referencePointWeightUpdate(weight, 1, 0.5);
  assert.ok(weight > 1, 'corroborating outcomes must rehabilitate a de-emphasized memory');

  for (let i = 0; i < 100; i++) weight = referencePointWeightUpdate(weight, -1, 0.5);
  assert.equal(weight, 0.1);
});
