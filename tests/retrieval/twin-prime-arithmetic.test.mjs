import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  GAUSSIAN_DELTA_MAX,
  QUANTIZED_AXIS_MAX,
  QUANTIZED_AXIS_OFFSET,
  UINT64_LIMIT,
  computeB2Distance,
  computeTwinPrimeDistance,
  gaussianNorm,
  gaussianTwinIndicator,
  hyperplaneCoefficient,
  isGaussianPrime,
  isPrime64,
  normalizeEmbedding,
  quantizeTime,
  relativeGaussianCoordinate,
  simHash31,
} from '../../services/retrieval/twin-prime-arithmetic.js';

function trialDivisionPrime(value) {
  if (value < 2) return false;
  if (value % 2 === 0) return value === 2;
  for (let divisor = 3; divisor * divisor <= value; divisor += 2) {
    if (value % divisor === 0) return false;
  }
  return true;
}

test('published deterministic hyperplane and SimHash vectors are stable', () => {
  assert.deepEqual([
    hyperplaneCoefficient(0, 0),
    hyperplaneCoefficient(0, 1),
    hyperplaneCoefficient(1, 0),
    hyperplaneCoefficient(30, 0),
    hyperplaneCoefficient(30, 17),
  ], [-1, 1, -1, -1, 1]);

  assert.deepEqual(simHash31([1]), {
    unsigned: 179574408,
    coordinate: -894167416,
  });
  assert.deepEqual(simHash31([3, -4, 12]), {
    unsigned: 1555737862,
    coordinate: 481996038,
  });
  assert.deepEqual(simHash31([1, 2, 3, 4, 5]), {
    unsigned: 951191823,
    coordinate: -122550001,
  });
  assert.deepEqual(simHash31([-1, -1]), {
    unsigned: 2011167743,
    coordinate: 937425919,
  });
});

test('embedding normalization is finite, stable, and rejects undefined geometry', () => {
  const normalized = normalizeEmbedding([3, 4]);
  assert.ok(Math.abs(normalized[0] - 0.6) < 1e-15);
  assert.ok(Math.abs(normalized[1] - 0.8) < 1e-15);

  const huge = normalizeEmbedding([Number.MAX_VALUE, Number.MAX_VALUE]);
  assert.ok(huge.every(Number.isFinite));
  assert.ok(Math.abs(huge[0] - Math.SQRT1_2) < 1e-15);
  assert.deepEqual(normalizeEmbedding(new Float32Array([0, -2, 0])), [0, -1, 0]);

  assert.throws(() => normalizeEmbedding([]), /embedding_must_not_be_empty/);
  assert.throws(() => normalizeEmbedding([0, -0]), /embedding_zero_norm/);
  assert.throws(() => normalizeEmbedding([1, NaN]), /embedding_value_nonfinite:1/);
  assert.throws(() => normalizeEmbedding([Infinity]), /embedding_value_nonfinite:0/);
  assert.throws(() => normalizeEmbedding('1,2'), /embedding_must_be_numeric_vector/);
});

test('time quantization uses exact clamped rational rounding', () => {
  assert.equal(quantizeTime(0, 0, 10), -QUANTIZED_AXIS_OFFSET);
  assert.equal(quantizeTime(5, 0, 10), 0);
  assert.equal(quantizeTime(10, 0, 10), QUANTIZED_AXIS_OFFSET - 1);
  assert.equal(quantizeTime(-100, 0, 10), -QUANTIZED_AXIS_OFFSET);
  assert.equal(quantizeTime(100, 0, 10), QUANTIZED_AXIS_OFFSET - 1);
  assert.equal(quantizeTime(0.5, 0, 1), 0);
  assert.equal(quantizeTime(123, 9, 9), 0);
  assert.equal(QUANTIZED_AXIS_MAX, 2147483647);

  assert.throws(() => quantizeTime(1, 2, 0), /scope_time_bounds_reversed/);
  assert.throws(() => quantizeTime(0.25, 0, 1), /time_must_be_safe_integer_or_half_integer/);
  assert.throws(() => quantizeTime(NaN, 0, 1), /time_must_be_finite_number_in_range/);
});

test('relative Gaussian coordinates stay within the declared quantized axes', () => {
  assert.deepEqual(
    relativeGaussianCoordinate(-QUANTIZED_AXIS_OFFSET, QUANTIZED_AXIS_OFFSET - 1, 7, -9),
    { real: GAUSSIAN_DELTA_MAX, imaginary: -16 },
  );
  assert.throws(
    () => relativeGaussianCoordinate(-QUANTIZED_AXIS_OFFSET - 1, 0, 0, 0),
    /query_subject_must_be_safe_integer_in_range/,
  );
});

test('deterministic 64-bit primality matches an exhaustive independent oracle', () => {
  for (let candidate = 0; candidate <= 65536; candidate += 1) {
    assert.equal(isPrime64(candidate), trialDivisionPrime(candidate), `candidate=${candidate}`);
  }
});

test('deterministic 64-bit primality rejects Carmichael and strong pseudoprime corpus', () => {
  const composites = [
    561n,
    1105n,
    1729n,
    2465n,
    2821n,
    6601n,
    3215031751n,
    2152302898747n,
    3474749660383n,
    341550071728321n,
    3825123056546413051n,
    18446744073709551556n,
  ];
  for (const candidate of composites) assert.equal(isPrime64(candidate), false, String(candidate));

  assert.equal(isPrime64(18446744073709551557n), true);
  assert.throws(() => isPrime64(UINT64_LIMIT), /prime_candidate_outside_uint64/);
  assert.throws(() => isPrime64(3.5), /prime_candidate_must_be_bigint_or_safe_integer/);
  assert.throws(() => isPrime64('3'), /prime_candidate_must_be_bigint_or_safe_integer/);
});

test('Gaussian primality handles zero, units, axes, signs, and interior points', () => {
  assert.equal(isGaussianPrime(0, 0), false);
  assert.equal(isGaussianPrime(1, 0), false);
  assert.equal(isGaussianPrime(0, -1), false);
  assert.equal(isGaussianPrime(3, 0), true);
  assert.equal(isGaussianPrime(-7, 0), true);
  assert.equal(isGaussianPrime(5, 0), false);
  assert.equal(isGaussianPrime(1, 1), true);
  assert.equal(isGaussianPrime(-2, 1), true);
  assert.equal(isGaussianPrime(2, 2), false);
});

test('Gaussian twin indicator implements delta and delta plus one-plus-i exactly', () => {
  assert.equal(gaussianTwinIndicator(2, 1), 1);
  assert.equal(gaussianTwinIndicator(3, 0), 1);
  assert.equal(gaussianTwinIndicator(0, 3), 1);
  assert.equal(gaussianTwinIndicator(1, 1), 0);
  assert.equal(gaussianTwinIndicator(-2, -1), 0);

  const maxShiftedNorm = gaussianNorm(
    BigInt(GAUSSIAN_DELTA_MAX) + 1n,
    BigInt(GAUSSIAN_DELTA_MAX) + 1n,
  );
  assert.equal(maxShiftedNorm, 1n << 63n);
  assert.ok(maxShiftedNorm < UINT64_LIMIT);
  assert.doesNotThrow(() => gaussianTwinIndicator(GAUSSIAN_DELTA_MAX, GAUSSIAN_DELTA_MAX));
  assert.throws(
    () => gaussianTwinIndicator(GAUSSIAN_DELTA_MAX + 1, 0),
    /gaussian_delta_outside_quantized_bound/,
  );
  assert.throws(() => gaussianNorm(1n << 32n, 0n), /gaussian_norm_outside_uint64/);
});

test('B2 and T score boundaries reject malformed values and preserve gamma-zero identity', () => {
  const b2 = computeB2Distance(0.25, 0.5, 0.125);
  assert.equal(b2, 0.3125);
  assert.equal(computeTwinPrimeDistance(b2, 0, 1), b2);
  assert.equal(computeTwinPrimeDistance(b2, 0.125, 0), b2);
  assert.equal(computeTwinPrimeDistance(b2, 0.125, 1), 0.1875);

  assert.throws(() => computeB2Distance(-0.1, 0, 0), /semantic_distance_must_be_finite_number_in_range/);
  assert.throws(() => computeB2Distance(0, 1.1, 0), /temporal_distance_must_be_finite_number_in_range/);
  assert.throws(() => computeB2Distance(0, 0, -1), /lambda_t_must_be_finite_number_in_range/);
  assert.throws(() => computeTwinPrimeDistance(0, -1, 0), /gamma_must_be_finite_number_in_range/);
  assert.throws(() => computeTwinPrimeDistance(0, 0, true), /tau_must_be_binary/);
});

test('SimHash vectors are identical across two independent Node processes', () => {
  const program = [
    "import { simHash31, quantizeTime, gaussianTwinIndicator } from './services/retrieval/twin-prime-arithmetic.js';",
    "console.log(JSON.stringify({sim:simHash31([3,-4,12]),time:quantizeTime(0.5,0,1),tau:gaussianTwinIndicator(2,1)}));",
  ].join('');
  const outputs = Array.from({ length: 2 }, () => spawnSync(process.execPath, [
    '--input-type=module',
    '--eval',
    program,
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
  }));

  for (const result of outputs) {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
  }
  assert.equal(outputs[0].stdout, outputs[1].stdout);
  assert.equal(outputs[0].stdout.trim(), JSON.stringify({
    sim: { unsigned: 1555737862, coordinate: 481996038 },
    time: 0,
    tau: 1,
  }));
});
