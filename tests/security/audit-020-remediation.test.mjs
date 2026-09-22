// Numerical invariants only; native database loading is qualified separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { computeLyapunovV, computeDeltaV, computeDampenGamma }
  from '../../services/governance/cohen-grossberg-energy-governor.js';

test('AUD-020 joint state/matrix permutations have bit-exact physical energy', () => {
  const rows = [{ id: 'a', weight: 0.1, valence: -1 },
    { id: 'b', weight: 1.317, valence: 0.4 }, { id: 'c', weight: 3, valence: 1 }];
  const C = [[0, 0.35, 0.8], [0.35, 0.1, 1.2], [0.8, 1.2, 0]];
  const energy = computeLyapunovV(rows, C);
  for (const p of [[0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0]]) {
    assert.equal(computeLyapunovV(p.map(i => rows[i]), p.map(i => p.map(j => C[i][j]))), energy);
  }
  assert.notEqual(computeLyapunovV([...rows].reverse(), C), energy,
    'unkeyed row-only permutation must not be mistaken for the same physical state');
  assert.equal(computeDeltaV(energy, energy), 0);
  assert.equal(computeDampenGamma(0), 1);
});

test('AUD-020 incomplete, duplicate, asymmetric and nonfinite windows fail explicitly', () => {
  const row = { id: 'a', weight: 1, valence: 0 };
  for (const [rows, C] of [[[row], []], [[row, row], [[0, 0], [0, 0]]],
    [[row], [[NaN]]], [[row], [[-1]]], [[{ ...row, weight: null }], [[0]]],
    [[{ ...row, valence: Infinity }], [[0]]],
    [[row, { ...row, id: 'b' }], [[0, 1], [2, 0]]]]) {
    assert.throws(() => computeLyapunovV(rows, C), /cg_(window_state_invalid|matrix_not_symmetric)/);
  }
  for (const x of [NaN, Infinity, null, '1']) {
    assert.throws(() => computeDeltaV(x, 0), /cg_energy_nonfinite/);
    assert.throws(() => computeDampenGamma(x), /cg_energy_nonfinite/);
  }
});
