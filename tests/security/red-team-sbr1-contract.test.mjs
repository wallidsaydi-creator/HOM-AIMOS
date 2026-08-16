import assert from 'node:assert/strict';
import test from 'node:test';

import {
  computeArte,
  executeAttack,
  runCampaign,
  saberScore,
  validateDefense,
} from '../../services/security/red-team-toolkit.js';

const ATTACK = {
  id: 'SBR1-ATTACK',
  payload: 'attack',
  expectedBehavior: 'blocked',
};

test('timeouts, runtime errors, and missing native decisions are indeterminate', async () => {
  const timeout = await executeAttack(
    ATTACK,
    async () => new Promise(() => {}),
    { timeoutMs: 1 },
  );
  const runtimeError = await executeAttack(ATTACK, async () => {
    throw new Error('ECONNRESET');
  });
  const missingDecision = await executeAttack(ATTACK, async () => 'cannot comply');

  for (const result of [timeout, runtimeError, missingDecision]) {
    assert.equal(result.outcome, 'indeterminate');
    assert.equal(result.blocked, false);
    assert.equal(result.success, false);
  }
});

test('indeterminate and missing cases never raise intended-N block rate', () => {
  const validation = validateDefense({
    attackClass: 'fixture',
    intendedN: 3,
    blocked: 999,
    findings: [
      { vectorId: 'A-1', expectedBehavior: 'blocked', outcome: 'blocked', latencyMs: 2 },
      { vectorId: 'A-2', expectedBehavior: 'blocked', outcome: 'indeterminate', latencyMs: 3 },
    ],
  });

  assert.equal(validation.blocked, 1);
  assert.equal(validation.validN, 1);
  assert.equal(validation.indeterminate, 2);
  assert.equal(validation.missingCases, 1);
  assert.equal(validation.blockRate, 33.3);
  assert.equal(validation.validBlockRate, 100);
});

test('blocking benign controls degrades the diagnostic grade and cannot create a scalar score', async () => {
  const calibrated = await runCampaign(
    'prompt_injection',
    async (_payload, vector) => ({ pass: vector.expectedBehavior === 'allowed' }),
    { limit: 1 },
  );
  const refuseEverything = await runCampaign(
    'prompt_injection',
    async () => ({ pass: false }),
    { limit: 1 },
  );

  const calibratedValidation = validateDefense(calibrated);
  const refuseEverythingValidation = validateDefense(refuseEverything);
  assert.equal(calibratedValidation.blockRate, 100);
  assert.equal(calibratedValidation.falsePositiveRate, 0);
  assert.equal(calibratedValidation.grade, 'A');
  assert.equal(refuseEverythingValidation.blockRate, 100);
  assert.equal(refuseEverythingValidation.falsePositiveRate, 100);
  assert.equal(refuseEverythingValidation.grade, 'F');

  const posture = saberScore([refuseEverything]);
  assert.equal(posture.score, null);
  assert.equal(posture.status, 'diagnostic_vector_only_pending_preregistered_posture_formula');
  assert.equal(posture.breakdown.falsePositiveRate, 100);
});

test('ARTE matches the hand fixture and retains attacker-side interpretation', () => {
  const result = computeArte({
    performanceRatio: 0.4,
    normalizedTime: 0.2,
    normalizedCost: 0.1,
    thetaPerformance: 0.5,
    thetaTime: 0.3,
    thetaCost: 0.2,
  });
  assert.equal(result.status, 'computed');
  assert.ok(Math.abs(result.denominator - 0.28) < 1e-12);
  assert.ok(Math.abs(result.arte - 3.571428571428571) < 1e-12);
  assert.equal(result.interpretation, 'attacker_effectiveness_higher_is_more_effective');

  const strongerAttack = computeArte({
    performanceRatio: 0.2,
    normalizedTime: 0.2,
    normalizedCost: 0.1,
    thetaPerformance: 0.5,
    thetaTime: 0.3,
    thetaCost: 0.2,
  });
  assert.ok(strongerAttack.arte > result.arte);
});

test('ARTE fails closed on incomplete, invalid, or zero-denominator profiles', () => {
  assert.equal(computeArte({}).status, 'not_computable');
  assert.equal(computeArte({
    performanceRatio: 0.4,
    normalizedTime: 0.2,
    normalizedCost: 0.1,
    thetaPerformance: 0.4,
    thetaTime: 0.3,
    thetaCost: 0.2,
  }).reason, 'aimos_weight_profile_sum_invalid');
  assert.equal(computeArte({
    performanceRatio: 0,
    normalizedTime: 0,
    normalizedCost: 0,
    thetaPerformance: 0.5,
    thetaTime: 0.3,
    thetaCost: 0.2,
  }).reason, 'non_positive_denominator');
});
