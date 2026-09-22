// Exhaustive numerical qualification of the native primitive, not a live
// mutation proof. --full-grid traverses every current/proposed stored pair.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { summarizeCertifiedTrajectory, controlCertifiedTrajectoryProposal }
  from '../../services/learning/neuroplasticity-stability-control.js';

const full = process.argv.includes('--full-grid');
const memoryId = '11111111-1111-4111-8111-111111111111';
const saturation = Array.from({ length: 128 }, (_, i) => ({
  old_weight_milli: i % 2 ? 3000 : 100,
  new_weight_milli: i % 2 ? 100 : 3000,
  projection_hash: (i + 1).toString(16).padStart(64, '0'),
}));
function histories(m) {
  const adjacent = m === 3000 ? m - 1 : m + 1;
  return [[], [
    { old_weight_milli: m, new_weight_milli: adjacent, projection_hash: '1'.repeat(64) },
    { old_weight_milli: adjacent, new_weight_milli: m, projection_hash: '2'.repeat(64) },
  ], [...saturation, ...(m === 100 ? [] : [{ old_weight_milli: 100,
    new_weight_milli: m, projection_hash: 'f'.repeat(64) }])]]
    .map(rows => summarizeCertifiedTrajectory(rows, { currentWeight: m / 1000, expectedChainLength: rows.length }));
}
function control(m, p, trajectory) {
  return controlCertifiedTrajectoryProposal({ memoryId, currentWeight: m / 1000,
    proposedWeight: p / 1000, trajectory, mutationOwner: 'SPICED_CONSOLIDATION' });
}

test('AUD-019 stored-grid direction, bounds, certificate and nonzero motion', () => {
  let cases = 0;
  const decimalCases = [];
  for (let m = 100; m <= 3000; m++) {
    for (const trajectory of histories(m)) {
      const proposals = full ? Array.from({ length: 2901 }, (_, i) => i + 100)
        : [...new Set([100, m - 1, m, m + 1, Math.round(m * 1.3), 3000])].filter(p => p >= 100 && p <= 3000);
      for (const p of proposals) {
        const result = control(m, p, trajectory), d = result.decision;
        const q = d.controlled_weight_milli;
        assert.equal(d.schema, 'hom.aimos.certified-neuroplasticity-control/v3');
        assert(Number.isSafeInteger(q) && q >= Math.min(m, p) && q <= Math.max(m, p));
        assert.equal(Math.sign(q - m), Math.sign(p - m));
        assert.equal(result.controlled_weight, q / 1000);
        assert(Math.abs(d.controlled_log_step_ppm) <= d.trust_radius_log_ppm);
        assert(Math.abs(Math.log(q / m)) <= d.trust_radius_log_ppm / 1e6);
        assert.equal(d.controlled_log_step_ppm,
          Math.sign(p - m) * Math.ceil(Math.abs(Math.log(q / m)) * 1e6));
        if (p === 100 || p === 3000) decimalCases.push([m, q, d.trust_radius_log_ppm]);
        cases++;
      }
    }
  }
  // Independent 60-digit arithmetic checks every extreme proposal certificate,
  // including all low-grid locations where continuous rounding previously failed.
  const independent = spawnSync('python3', ['-B', '-c',
    'import json,sys,decimal\ndecimal.getcontext().prec=60\nD=decimal.Decimal\ncases=json.load(sys.stdin)\nfor m,q,b in cases:\n assert abs((D(q)/D(m)).ln()) <= D(b)/D(1000000),(m,q,b)\nprint(len(cases))'],
  { input: JSON.stringify(decimalCases), encoding: 'utf8', maxBuffer: 1024 * 1024 });
  assert.equal(independent.status, 0, independent.stderr);
  assert.equal(Number(independent.stdout), decimalCases.length);
  if (full) assert.equal(cases, 3 * 2901 * 2901);
  console.log(JSON.stringify({ native_grid_cases: cases, independent_decimal_certificates: decimalCases.length,
    exhaustive: full, live_mutation_claimed: false }));
});

test('AUD-019 malformed trajectory counters cannot enter a signed decision', () => {
  const baseline = histories(1000)[0];
  for (const [field, value] of [['chain_length', NaN], ['chain_length', -1],
    ['chain_length', 0.5], ['reversal_count', Infinity], ['reversal_count', 1],
    ['total_log_variation_ppm', NaN], ['total_log_variation_ppm', -1],
    ['reversal_rate_ppm', 1], ['total_log_variation_ppm', 1]]) {
    assert.throws(() => control(1000, 1300, { ...baseline, [field]: value }), /summary_invalid/);
  }
});
