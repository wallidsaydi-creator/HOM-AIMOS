import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  classifyThreatResponse,
  computeSecurityResponse,
} from '../../services/security/security-ladder.js';

test('decision tiers retain their documented boundaries', () => {
  assert.equal(classifyThreatResponse(0), 'observe');
  assert.equal(classifyThreatResponse(0.3), 'shape');
  assert.equal(classifyThreatResponse(0.6), 'challenge');
  assert.equal(classifyThreatResponse(0.8), 'block');
});

test('the ladder consumes normalized security evidence and returns its action contract', () => {
  const result = computeSecurityResponse({
    behavioralDrift: 1,
    manipulationRisk: 1,
    contextualRisk: 1,
  });

  assert.equal(result.anomalyScore, 1);
  assert.equal(result.tier, 'block');
  assert.equal(result.action, 'block');
  assert.deepEqual(result.components, {
    behavioralDrift: 1,
    manipulationRisk: 1,
    contextualRisk: 1,
  });
});

test('out-of-range and non-numeric evidence is clamped without inventing risk', () => {
  const result = computeSecurityResponse({
    behavioralDrift: -3,
    manipulationRisk: 12,
    contextualRisk: 'not-a-number',
  });

  assert.equal(result.anomalyScore, 0.35);
  assert.equal(result.action, 'shape');
  assert.deepEqual(result.components, {
    behavioralDrift: 0,
    manipulationRisk: 1,
    contextualRisk: 0,
  });
});

test('legacy request metadata cannot masquerade as anomaly evidence', () => {
  const result = computeSecurityResponse({
    promptLength: 999_999,
    agentId: 'reviewer',
    intent: 'security-code-review',
  });

  assert.equal(result.anomalyScore, 0);
  assert.equal(result.action, 'observe');
});

test('the gate obtains behavioral evidence before invoking the ladder', async () => {
  const source = await readFile(
    new URL('../../services/orchestration/agent-security-gates.js', import.meta.url),
    'utf8',
  );
  const baselineOffset = source.indexOf('await updateBehavioralBaseline(');
  const ladderOffset = source.indexOf('computeSecurityResponse({');

  assert.ok(baselineOffset >= 0, 'behavioral baseline owner must remain wired');
  assert.ok(ladderOffset > baselineOffset, 'the ladder must run after its evidence exists');
  assert.match(source, /behavioralDrift:\s*results\.behavioralCheck\.anomalyScore/);
  assert.match(source, /manipulationRisk,/);
  assert.match(source, /contextualRisk,/);
  assert.doesNotMatch(source.slice(ladderOffset, ladderOffset + 400), /promptLength/);
  assert.match(source.slice(ladderOffset, ladderOffset + 2_500), /await logEvent\(/);
  assert.doesNotMatch(source.slice(ladderOffset, ladderOffset + 2_500), /threat evaluation failed/);
});

test('positive model learns from signed native tool receipts, not a phantom table', async () => {
  const source = await readFile(
    new URL('../../services/security/security-ladder.js', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /agent_run_logs/);
  assert.match(source, /FROM aimos_events/);
  assert.match(source, /operation = 'tool_execution_succeeded'/);
  assert.match(source, /toolActionArgumentsHash\(params/);
});
