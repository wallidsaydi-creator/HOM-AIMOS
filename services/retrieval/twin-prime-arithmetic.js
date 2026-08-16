/**
 * TWIN-PRIME RETRIEVAL ARITHMETIC
 *
 * Paper / corpus authority:
 * - Vatwani, "Bounded gaps between Gaussian primes" (2017): Gaussian
 *   primality in Z[i] and the conjectural p, p + (1 + i) relation.
 * - Shanks, "A Note on Gaussian Twin Primes" (1960): historical Gaussian
 *   twin-prime definition and density context.
 * - Goldston-Pintz-Yildirim, Maynard, and DHJ Polymath: bounded rational-prime
 *   gaps are theorem context only. Their constants are not memory radii.
 *
 * Pipeline position:
 * - TP-G1 pure arithmetic kernel; not yet wired into native recall.
 *
 * Authority boundary:
 * - no database, keychain, transport, configuration, logging, retention, or
 *   ranking-selection authority;
 * - no admission, deletion, decay, suppression, or quarantine decision;
 * - all prime arithmetic is exact and bounded below 2^64.
 */

import { createHash } from 'node:crypto';

export const TWIN_PRIME_ARITHMETIC_VERSION = 'hom-aimos/twin-prime-arithmetic/v1';
export const SIMHASH_BITS = 31;
export const QUANTIZED_AXIS_OFFSET = 2 ** 30;
export const QUANTIZED_AXIS_MAX = (2 ** 31) - 1;
export const GAUSSIAN_DELTA_MAX = (2 ** 31) - 1;
export const UINT64_LIMIT = 1n << 64n;

const SIMHASH_DOMAIN = 'hom-aimos/twin-prime/v1/simhash\0';
const MILLER_RABIN_BASES_64 = Object.freeze([
  2n,
  325n,
  9375n,
  28178n,
  450775n,
  9780504n,
  1795265022n,
]);
const SMALL_PRIMES = Object.freeze([
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n,
]);

const coefficientCache = new Map();
const MAX_CACHED_DIMENSIONS = 4;

function assertInteger(value, name, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${name}_must_be_safe_integer_in_range`);
  }
  return value;
}

function assertFinite(value, name, { min = -Infinity, max = Infinity } = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    throw new TypeError(`${name}_must_be_finite_number_in_range`);
  }
  return value;
}

function dateMilliseconds(value, name) {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) {
    throw new TypeError(`${name}_must_be_valid_time`);
  }
  return milliseconds;
}

export function parseNumericVector(value) {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    return Array.from(value, (entry, index) => assertFinite(entry, `embedding_${index}`));
  }
  const text = String(value || '').trim();
  if (!text.startsWith('[') || !text.endsWith(']')) {
    throw new TypeError('embedding_pgvector_invalid');
  }
  const values = text.slice(1, -1).split(',').map(
    (entry, index) => assertFinite(Number(entry), `embedding_${index}`),
  );
  if (!values.length) throw new TypeError('embedding_pgvector_empty');
  return values;
}

export function cosineDistance(left, right) {
  const a = parseNumericVector(left);
  const b = parseNumericVector(right);
  if (a.length === 0 || a.length !== b.length) throw new TypeError('cosine_vectors_invalid');
  let dot = 0;
  let normLeft = 0;
  let normRight = 0;
  for (let index = 0; index < a.length; index += 1) {
    dot += a[index] * b[index];
    normLeft += a[index] * a[index];
    normRight += b[index] * b[index];
  }
  if (!(normLeft > 0) || !(normRight > 0)) throw new RangeError('cosine_zero_norm');
  const cosine = Math.max(-1, Math.min(1, dot / Math.sqrt(normLeft * normRight)));
  return 1 - cosine;
}

export function buildTwinPrimeTemporalCoordinates({
  temporalScope = {},
  requestTimeMs,
  scopeMin,
  scopeMax,
} = {}) {
  const request = assertInteger(Number(requestTimeMs), 'request_time_ms', { min: 1 });
  const minimum = assertInteger(Number(scopeMin), 'scope_min_time_ms', { min: 1 });
  const maximum = assertInteger(Number(scopeMax), 'scope_max_time_ms', { min: minimum });
  const start = temporalScope?.start_day
    ? dateMilliseconds(`${temporalScope.start_day}T00:00:00.000Z`, 'temporal_start')
    : null;
  const end = temporalScope?.end_day_exclusive
    ? dateMilliseconds(`${temporalScope.end_day_exclusive}T00:00:00.000Z`, 'temporal_end')
    : null;
  const constrained = start != null || end != null;
  const anchor = start != null && end != null
    ? (start + end) / 2
    : start ?? end ?? request;
  return Object.freeze({
    start,
    end,
    constrained,
    anchor,
    queryQuantized: quantizeTime(anchor, minimum, maximum),
  });
}

export function twinPrimeTemporalDistance(memoryTimeMs, temporal, scopeSpanMs) {
  const memoryTime = assertInteger(Number(memoryTimeMs), 'memory_time_ms', { min: 1 });
  const scopeSpan = assertInteger(Number(scopeSpanMs), 'scope_span_ms', { min: 1 });
  if (!temporal || temporal.constrained !== true) return 0;
  if (temporal.start != null && temporal.end != null) {
    if (memoryTime >= temporal.start && memoryTime < temporal.end) return 0;
    const boundaryDistance = memoryTime < temporal.start
      ? temporal.start - memoryTime
      : memoryTime - temporal.end;
    return Math.min(1, boundaryDistance / scopeSpan);
  }
  return Math.min(1, Math.abs(memoryTime - temporal.anchor) / scopeSpan);
}

function toBoundedBigInt(value, name) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  throw new TypeError(`${name}_must_be_bigint_or_safe_integer`);
}

function toTwiceSafeInteger(value, name) {
  assertFinite(value, name);
  const doubled = value * 2;
  if (!Number.isSafeInteger(doubled)) {
    throw new TypeError(`${name}_must_be_safe_integer_or_half_integer`);
  }
  return BigInt(doubled);
}

function modularPow(base, exponent, modulus) {
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    power >>= 1n;
  }
  return result;
}

function hyperplaneForDimensions(dimensions) {
  const cached = coefficientCache.get(dimensions);
  if (cached) return cached;

  const coefficients = Array.from({ length: SIMHASH_BITS }, (_, bit) => {
    const row = new Int8Array(dimensions);
    for (let dimension = 0; dimension < dimensions; dimension += 1) {
      row[dimension] = hyperplaneCoefficient(bit, dimension);
    }
    return row;
  });

  if (coefficientCache.size >= MAX_CACHED_DIMENSIONS) {
    coefficientCache.delete(coefficientCache.keys().next().value);
  }
  coefficientCache.set(dimensions, coefficients);
  return coefficients;
}

export function normalizeEmbedding(embedding) {
  if (!Array.isArray(embedding) && !ArrayBuffer.isView(embedding)) {
    throw new TypeError('embedding_must_be_numeric_vector');
  }
  if (embedding.length === 0) throw new TypeError('embedding_must_not_be_empty');

  let scale = 0;
  let scaledSquares = 1;
  const values = new Float64Array(embedding.length);

  for (let index = 0; index < embedding.length; index += 1) {
    const value = embedding[index];
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new TypeError(`embedding_value_nonfinite:${index}`);
    }
    values[index] = value;
    const magnitude = Math.abs(value);
    if (magnitude === 0) continue;
    if (scale < magnitude) {
      const ratio = scale / magnitude;
      scaledSquares = 1 + (scaledSquares * ratio * ratio);
      scale = magnitude;
    } else {
      const ratio = magnitude / scale;
      scaledSquares += ratio * ratio;
    }
  }

  if (scale === 0) throw new RangeError('embedding_zero_norm');
  const normalizedScale = Math.sqrt(scaledSquares);
  return Array.from(values, (value) => {
    const normalized = (value / scale) / normalizedScale;
    return Object.is(normalized, -0) ? 0 : normalized;
  });
}

export function hyperplaneCoefficient(bit, dimension) {
  assertInteger(bit, 'simhash_bit', { min: 0, max: SIMHASH_BITS - 1 });
  assertInteger(dimension, 'embedding_dimension', { min: 0 });
  const digest = createHash('sha256')
    .update(`${SIMHASH_DOMAIN}${bit}\0${dimension}`, 'utf8')
    .digest();
  return (digest[digest.length - 1] & 1) === 1 ? 1 : -1;
}

export function simHash31(embedding) {
  const normalized = normalizeEmbedding(embedding);
  const hyperplanes = hyperplaneForDimensions(normalized.length);
  let unsigned = 0n;

  for (let bit = 0; bit < SIMHASH_BITS; bit += 1) {
    let sum = 0;
    let compensation = 0;
    const coefficients = hyperplanes[bit];
    for (let dimension = 0; dimension < normalized.length; dimension += 1) {
      const term = (coefficients[dimension] * normalized[dimension]) - compensation;
      const next = sum + term;
      compensation = (next - sum) - term;
      sum = next;
    }
    if (sum >= 0) unsigned |= 1n << BigInt(bit);
  }

  const unsignedNumber = Number(unsigned);
  return Object.freeze({
    unsigned: unsignedNumber,
    coordinate: unsignedNumber - QUANTIZED_AXIS_OFFSET,
  });
}

export function quantizeTime(time, scopeMin, scopeMax) {
  const time2 = toTwiceSafeInteger(time, 'time');
  const min2 = toTwiceSafeInteger(scopeMin, 'scope_min');
  const max2 = toTwiceSafeInteger(scopeMax, 'scope_max');
  if (max2 < min2) throw new RangeError('scope_time_bounds_reversed');
  if (max2 === min2) return 0;

  const clamped = time2 < min2 ? min2 : (time2 > max2 ? max2 : time2);
  const numerator = clamped - min2;
  const denominator = max2 - min2;
  const rounded = ((2n * numerator * BigInt(QUANTIZED_AXIS_MAX)) + denominator)
    / (2n * denominator);
  return Number(rounded) - QUANTIZED_AXIS_OFFSET;
}

export function relativeGaussianCoordinate(querySubject, memorySubject, queryTime, memoryTime) {
  for (const [name, value] of [
    ['query_subject', querySubject],
    ['memory_subject', memorySubject],
    ['query_time', queryTime],
    ['memory_time', memoryTime],
  ]) {
    assertInteger(value, name, {
      min: -QUANTIZED_AXIS_OFFSET,
      max: QUANTIZED_AXIS_OFFSET - 1,
    });
  }

  return Object.freeze({
    real: memorySubject - querySubject,
    imaginary: memoryTime - queryTime,
  });
}

export function isPrime64(value) {
  const candidate = toBoundedBigInt(value, 'prime_candidate');
  if (candidate < 2n) return false;
  if (candidate >= UINT64_LIMIT) throw new RangeError('prime_candidate_outside_uint64');

  for (const prime of SMALL_PRIMES) {
    if (candidate === prime) return true;
    if (candidate % prime === 0n) return false;
  }

  let oddPart = candidate - 1n;
  let powerOfTwo = 0;
  while ((oddPart & 1n) === 0n) {
    oddPart >>= 1n;
    powerOfTwo += 1;
  }

  for (const declaredBase of MILLER_RABIN_BASES_64) {
    const base = declaredBase % candidate;
    if (base === 0n) continue;
    let witness = modularPow(base, oddPart, candidate);
    if (witness === 1n || witness === candidate - 1n) continue;

    let composite = true;
    for (let round = 1; round < powerOfTwo; round += 1) {
      witness = (witness * witness) % candidate;
      if (witness === candidate - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

export function gaussianNorm(real, imaginary) {
  const a = toBoundedBigInt(real, 'gaussian_real');
  const b = toBoundedBigInt(imaginary, 'gaussian_imaginary');
  const norm = (a * a) + (b * b);
  if (norm >= UINT64_LIMIT) throw new RangeError('gaussian_norm_outside_uint64');
  return norm;
}

export function isGaussianPrime(real, imaginary) {
  const a = toBoundedBigInt(real, 'gaussian_real');
  const b = toBoundedBigInt(imaginary, 'gaussian_imaginary');
  if (a === 0n && b === 0n) return false;

  if (a === 0n || b === 0n) {
    const axis = a === 0n ? (b < 0n ? -b : b) : (a < 0n ? -a : a);
    if (axis >= UINT64_LIMIT) throw new RangeError('gaussian_axis_outside_uint64');
    return axis % 4n === 3n && isPrime64(axis);
  }

  return isPrime64(gaussianNorm(a, b));
}

export function gaussianTwinIndicator(real, imaginary) {
  const a = toBoundedBigInt(real, 'gaussian_delta_real');
  const b = toBoundedBigInt(imaginary, 'gaussian_delta_imaginary');
  const bound = BigInt(GAUSSIAN_DELTA_MAX);
  if (a < -bound || a > bound || b < -bound || b > bound) {
    throw new RangeError('gaussian_delta_outside_quantized_bound');
  }
  return isGaussianPrime(a, b) && isGaussianPrime(a + 1n, b + 1n) ? 1 : 0;
}

export function computeB2Distance(semanticDistance, temporalDistance, lambdaT) {
  const semantic = assertFinite(semanticDistance, 'semantic_distance', { min: 0, max: 2 });
  const temporal = assertFinite(temporalDistance, 'temporal_distance', { min: 0, max: 1 });
  const lambda = assertFinite(lambdaT, 'lambda_t', { min: 0 });
  const distance = semantic + (lambda * temporal);
  if (!Number.isFinite(distance)) throw new RangeError('b2_distance_nonfinite');
  return distance;
}

export function computeTwinPrimeDistance(b2Distance, gamma, tau) {
  const baseline = assertFinite(b2Distance, 'b2_distance', { min: 0 });
  const coefficient = assertFinite(gamma, 'gamma', { min: 0 });
  if (tau !== 0 && tau !== 1) throw new TypeError('tau_must_be_binary');
  if (coefficient === 0 || tau === 0) return baseline;
  const distance = baseline - (coefficient * tau);
  if (!Number.isFinite(distance)) throw new RangeError('twin_prime_distance_nonfinite');
  return distance;
}
