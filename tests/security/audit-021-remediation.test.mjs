// Deterministic native arithmetic/domain checks, not signed-event mocks and
// not a substitute for canonical producer→Housekeeper→recall qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { memoryCreditTransition, memoryCreditValue, memoryCreditTarget,
  admitMemoryCreditProjection, memoryCreditEvidence } from '../../services/security/protocol/memory-credit.js';
import { computeTrustScore, getTrustBreakdown, normalizeAccessFrequency,
  normalizeCrossRefs } from '../../services/learning/trust-score.js';

test('AUD-021 native credit arithmetic preserves zero and endpoints and rejects invalid domains', () => {
  const zero = memoryCreditTransition(null, 0);
  assert.deepEqual(zero, { sum: 0, count: 1, score: 0 });
  const one = memoryCreditTransition(zero, 1);
  assert.deepEqual(one, { sum: 1, count: 2, score: 0.5 });
  const third = memoryCreditTransition(one, 0.25);
  assert.equal(third.score, 1.25 / 3);
  for (const value of [-1, 1.01, NaN, Infinity, -Infinity, null, '0.5', true]) {
    assert.throws(() => memoryCreditTransition(null, value), /memory_credit_arithmetic_invalid/);
  }
  assert.throws(() => memoryCreditTransition({ count: Number.MAX_SAFE_INTEGER, sum: 0 }, 0), /arithmetic_invalid/);
  assert.throws(() => memoryCreditTransition({ count: 1, sum: 2 }, 0), /arithmetic_invalid/);
});

test('AUD-021 unmeasured native target is explicit; raw columns and copied credit are not evidence', () => {
  // Exact retained target from the canonical R7 recall; no invented signature.
  const target = memoryCreditTarget('511d7516-c786-4b62-b9b3-f2fd6c2c0ec5',
    'f83fe21fe36e2c318861b50582c5bfbbe6aed401d93eab0a2b5965edd48ef35e',
    '71c8d90b4076b4efdde0b5a8f71a6cb7e5502fa8efd7fc664c6bdc8de2c37d36');
  const credit = admitMemoryCreditProjection(target);
  const memory = { id: target.memory_id, credit_score: 0.5, memory_credit: credit,
    provenance_proof: { live_content_hash: target.live_content_hash, disclosure_occurrence_ref: target.occurrence_ref } };
  assert.equal(memoryCreditValue(memory), null);
  assert.equal(memoryCreditEvidence(memory).state, 'UNMEASURED');
  assert.throws(() => memoryCreditEvidence({ ...memory, memory_credit: { ...credit } }), /admission_required/);
  assert.throws(() => memoryCreditEvidence({ ...memory, id: '1b003699-53f0-4d40-a0ff-8a9199274174' }), /target_substitution/);
  assert.equal(memoryCreditValue({ credit_score: 1 }), null);
  assert.equal(computeTrustScore({ credit_score: 1, access_count: 0, graph_links: [] }), 0);
});

test('AUD-021 ranking domains are finite and breakdown uses the same scale as its total', () => {
  for (const value of [-1, NaN, Infinity, 'bad', '', {}, true]) {
    assert.throws(() => normalizeAccessFrequency(value), /ranking_count_domain_invalid/);
    assert.throws(() => normalizeCrossRefs(value), /ranking_count_domain_invalid/);
  }
  assert.throws(() => computeTrustScore({ graph_links: {} }), /ranking_reference_list_invalid/);
  assert.throws(() => computeTrustScore({ access_count: NaN }), /ranking_count_domain_invalid/);
  assert.equal(normalizeAccessFrequency('0'), 0);
  assert.equal(normalizeAccessFrequency(200, 100), 1);
  const memory = { access_count: 100, graph_links: [] }, options = { memoryCount: 1_000_000 };
  const breakdown = getTrustBreakdown(memory, options);
  assert.equal(breakdown.total_trust, computeTrustScore(memory, options));
  assert.equal(breakdown.total_trust, Object.values(breakdown.components).reduce((sum, c) => sum + c.contribution, 0));
});
