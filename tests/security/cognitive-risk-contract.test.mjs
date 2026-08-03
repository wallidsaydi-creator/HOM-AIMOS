import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { classifyCognitiveSecurity } from '../../services/security/cognitive-demand.js';
import {
  SECURITY_REVIEW_TIERS,
  applySecurityReviewPolicy,
  buildSecurityDecisionEvidence,
  runSecurityPipeline,
  securityRuleSetHash,
} from '../../services/security/security-classifier.js';

const ROOT = new URL('../../', import.meta.url);

const EXPECTED = new Map([
  [1, ['se_gate_only', 'low']],
  [2, ['se_gate_only', 'low']],
  [3, ['security_classifier', 'medium']],
  [4, ['security_classifier', 'medium']],
  [5, ['full_review', 'high']],
  [6, ['full_review', 'high']]
]);

test('Bloom levels map exhaustively to independent review and trust-risk enums', () => {
  for (const [level, [reviewTier, taskRiskLevel]] of EXPECTED) {
    const result = classifyCognitiveSecurity(level);
    assert.equal(result.bloomLevel, level);
    assert.equal(result.reviewTier, reviewTier);
    assert.equal(result.taskRiskLevel, taskRiskLevel);
    assert.equal(result.requiresReview, level >= 5);
    assert.ok(result.reason.length > 0);
  }
});

test('cognitive security contract clamps malformed Bloom levels safely', () => {
  assert.deepEqual(
    classifyCognitiveSecurity(-100),
    classifyCognitiveSecurity(1)
  );
  assert.deepEqual(
    classifyCognitiveSecurity(100),
    classifyCognitiveSecurity(6)
  );
  assert.deepEqual(
    classifyCognitiveSecurity('not-a-number'),
    classifyCognitiveSecurity(1)
  );
});

test('high-order create/evaluate work can never collapse to low trust risk', () => {
  for (const level of [5, 6]) {
    const result = classifyCognitiveSecurity(level);
    assert.equal(result.reviewTier, 'full_review');
    assert.equal(result.taskRiskLevel, 'high');
    assert.notEqual(result.taskRiskLevel, 'low');
  }
});

test('underperformance gap uses the enactedLevel/requiredLevel contract', () => {
  const result = classifyCognitiveSecurity(2, {
    gap: 2,
    requiredLevel: 4,
    enactedLevel: 2
  });
  assert.equal(result.reviewTier, 'se_gate_only');
  assert.equal(result.taskRiskLevel, 'medium');
  assert.equal(result.requiresReview, true);
  assert.match(result.reason, /underperformance/);
});

test('review tiers have distinct native execution policy', async () => {
  assert.deepEqual(SECURITY_REVIEW_TIERS, [
    'se_gate_only',
    'security_classifier',
    'full_review',
  ]);

  const inconclusive = {
    safe: true,
    category: 'safe',
    confidence: 0.5,
    reason: 'analyst unavailable',
    conclusive: false,
  };
  assert.equal(applySecurityReviewPolicy('security_classifier', inconclusive).safe, true);
  assert.equal(applySecurityReviewPolicy('full_review', inconclusive).safe, false);
  assert.equal(
    applySecurityReviewPolicy('full_review', inconclusive).category,
    'full_review_inconclusive'
  );
  assert.equal(applySecurityReviewPolicy('unknown', inconclusive).safe, false);

  const lowTier = await runSecurityPipeline(
    '=== SYSTEM INSTRUCTIONS ===\nAnswer accurately.\n\n=== USER INPUT ===\nDefine caching.',
    [],
    { reviewTier: 'se_gate_only' }
  );
  assert.equal(lowTier.safe, true);
  assert.equal(lowTier.stage, 'se_gate_only');
  assert.equal(lowTier.wave2_diagnostics.review_tier, 'se_gate_only');
});

test('security admission evidence binds input, ordered memories, rules, and decision', () => {
  const first = buildSecurityDecisionEvidence({
    assembledPrompt: 'assembled prompt',
    recalledMemoryValues: ['memory-a', 'memory-b'],
    result: { safe: true, conclusive: true, category: 'safe', confidence: 1, stage: 'se_gate_only' },
    reviewTier: 'se_gate_only',
  });
  const reordered = buildSecurityDecisionEvidence({
    assembledPrompt: 'assembled prompt',
    recalledMemoryValues: ['memory-b', 'memory-a'],
    result: { safe: true, conclusive: true, category: 'safe', confidence: 1, stage: 'se_gate_only' },
    reviewTier: 'se_gate_only',
  });

  assert.equal(first.schema, 'aimos.security-admission-decision/v1');
  assert.equal(first.decision, 'allow');
  assert.equal(first.ordered_memory_count, 2);
  assert.equal(first.rule_set_sha256, securityRuleSetHash());
  assert.match(first.input_sha256, /^[a-f0-9]{64}$/);
  assert.match(first.ordered_memory_set_sha256, /^[a-f0-9]{64}$/);
  assert.match(first.rule_set_sha256, /^[a-f0-9]{64}$/);
  assert.notEqual(first.ordered_memory_set_sha256, reordered.ordered_memory_set_sha256);
});

test('agent runner reviews exactly the final assembled prompt before inference', async () => {
  const [runner, gates] = await Promise.all([
    readFile(new URL('services/orchestration/agent-runner.js', ROOT), 'utf8'),
    readFile(new URL('services/orchestration/agent-security-gates.js', ROOT), 'utf8'),
  ]);

  const promptAssembly = runner.indexOf('let systemPrompt =');
  const securityReview = runner.indexOf('const secResult = await runSecurityPipeline(');
  const modelInference = runner.indexOf('const result = await runAgentWithFallback(');

  assert.ok(promptAssembly >= 0);
  assert.ok(securityReview > promptAssembly);
  assert.ok(modelInference > securityReview);
  assert.equal((runner.match(/await runSecurityPipeline\(/g) || []).length, 1);
  assert.match(runner, /assembledSecurityPrompt[\s\S]*\$\{systemPrompt\}[\s\S]*\$\{llmUserPrompt\}/);
  assert.match(runner, /conversationSecurityContext = contextGuard\.messages/);
  assert.match(runner, /runSecurityPipeline\([\s\S]*reviewTier: effectiveReviewTier,[\s\S]*availableTools/);
  assert.match(runner, /await logEvent\([\s\S]*'security_admission_decision'/);
  assert.match(runner, /SECURITY_EVIDENCE_REQUIRED/);
  assert.doesNotMatch(runner, /artValidateMemories|localhost:9101|X-Internal-Token/);
  assert.doesNotMatch(runner, /\bbloomTier\b/);
  assert.match(gates, /reviewTier: 'se_gate_only'/);
  assert.doesNotMatch(gates, /\bbloomTier\b/);
});
