import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  computeConsolidationAmplificationFactor,
} from '../../services/dream/spiced-consolidator.js';

const ROOT = new URL('../../', import.meta.url);

test('Cohen-Grossberg dampening scales only positive amplification surplus', () => {
  const samples = [
    Number.NEGATIVE_INFINITY,
    -1,
    0,
    0.1,
    0.25,
    0.5,
    0.75,
    1,
    2,
    Number.POSITIVE_INFINITY,
    Number.NaN,
  ];

  for (const gamma of samples) {
    const factor = computeConsolidationAmplificationFactor(gamma);
    assert.ok(Number.isFinite(factor), `factor must be finite for ${gamma}`);
    assert.ok(factor >= 1, `factor ${factor} reduced canonical weight for ${gamma}`);
    assert.ok(factor <= 1.3, `factor ${factor} exceeded consolidation cap for ${gamma}`);
  }

  const ordered = [0.1, 0.25, 0.5, 0.75, 1]
    .map(computeConsolidationAmplificationFactor);
  for (let index = 1; index < ordered.length; index++) {
    assert.ok(ordered[index] >= ordered[index - 1]);
  }
  assert.equal(computeConsolidationAmplificationFactor(0.1), 1.03);
  assert.equal(computeConsolidationAmplificationFactor(1), 1.3);
});

test('live dream path contains no age-based weight mutation or global downscale owner', async () => {
  const [spiced, stdp, nightly, dreamE2e] = await Promise.all([
    readFile(new URL('services/dream/spiced-consolidator.js', ROOT), 'utf8'),
    readFile(new URL('services/learning/stdp-kernel.js', ROOT), 'utf8'),
    readFile(new URL('jobs/nightly-dream.js', ROOT), 'utf8'),
    readFile(new URL('jobs/dream-e2e.js', ROOT), 'utf8'),
  ]);

  assert.doesNotMatch(spiced, /export async function (?:renormalize|renormalizeScoped|sleepDecay)\b/);
  assert.doesNotMatch(spiced, /last_accessed_at\s*<\s*NOW\(\)|EXTRACT\(EPOCH FROM \(NOW\(\) - COALESCE/);
  assert.doesNotMatch(stdp, /export async function homeostaticRescale\b/);
  assert.doesNotMatch(nightly, /pheromoneResult|forgettingCurveResult/);
  assert.equal((nightly.match(/mutation_authority: 'housekeeper'/g) || []).length, 3);
  assert.doesNotMatch(nightly, /signAsHousekeeper|memoryProvenanceLedger|commitProvenance/);
  assert.doesNotMatch(dreamE2e, /\brenormalize\b|\bsleepDecay\b/);
  // Monotone SPICED promotion (never lowers, capped at CONSOLIDATION_CAP). The
  // guarantee moved from a raw SQL `GREATEST(current, LEAST(cap, current*gamma))`
  // to this JS computation because migration 080 revoked UPDATE(retrieval_weight)
  // from agent_runtime — the weight is now applied only via the signed function.
  assert.match(
    spiced,
    /Math\.max\(oldWeight, Math\.min\(CONSOLIDATION_CAP, oldWeight \* effectiveGamma\)\)/
  );
  assert.match(spiced, /apply_signed_cognitive_reweight/);
});
