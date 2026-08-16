// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: epistemic-edit-certifier.js + certificate verifier
// → Calls: node:crypto only
// Pipeline: SECURITY | Pure CERT-ED mathematical and commitment owner
// Paper: Huang et al., CERT-ED, Findings of EMNLP 2024, Theorem 2
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';

export const EPISTEMIC_EDIT_CERTIFICATE_SCHEMA = 'aimos.epistemic-edit-certificate/v1';
export const EPISTEMIC_EDIT_TOKENIZER_VERSION = 'aimos.whitespace-nfc/v1';
export const EPISTEMIC_BINARY_PROJECTION_VERSION = 'aimos.epistemic-untrusted-binary/v1';
export const EPISTEMIC_EDIT_FORMULA_VERSION = 'cert-ed-levenshtein-hoeffding-ppm/v1';
export const PROBABILITY_SCALE = 1_000_000;

const UNTRUSTED_LABELS = new Set([
  'poison_suspect',
  'poison_likely',
  'poison_confirmed',
]);

function assertInteger(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`epistemic_certificate_${name}_invalid`);
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('epistemic_certificate_non_finite_number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ));
    return `{${entries.join(',')}}`;
  }
  throw new Error('epistemic_certificate_non_canonical_type');
}

export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function canonicalizeEditTokens(value = '') {
  const normalized = String(value ?? '')
    .replace(/\r\n?/g, '\n')
    .normalize('NFC')
    .trim();
  return normalized ? normalized.split(/\s+/u) : [];
}

export function reconstructEditTokens(tokens = []) {
  if (!Array.isArray(tokens) || tokens.some((token) => typeof token !== 'string')) {
    throw new Error('epistemic_certificate_tokens_invalid');
  }
  return tokens.join(' ');
}

export function projectEpistemicLabel(label) {
  return UNTRUSTED_LABELS.has(String(label || '')) ? 'U' : 'N';
}

export function normalizeProbabilityRational(value, name = 'probability') {
  const numerator = Number(value?.numerator);
  const denominator = Number(value?.denominator);
  assertInteger(numerator, `${name}_numerator`, 1, 1_000_000);
  assertInteger(denominator, `${name}_denominator`, 2, 1_000_000);
  if (numerator >= denominator) throw new Error(`epistemic_certificate_${name}_invalid`);
  return Object.freeze({ numerator, denominator });
}

export function computeConservativeCertificateMath({
  selectedCount,
  nCertify,
  alphaFamily,
  nMax,
  pDel,
  maxRadius = 100_000,
}) {
  assertInteger(selectedCount, 'selected_count', 0, 10_000_000);
  assertInteger(nCertify, 'n_certify', 1, 10_000_000);
  assertInteger(nMax, 'n_max', 1, 1_000_000);
  assertInteger(maxRadius, 'max_radius', 0, 1_000_000);
  if (selectedCount > nCertify) throw new Error('epistemic_certificate_count_exceeds_n');

  const alpha = normalizeProbabilityRational(alphaFamily, 'alpha_family');
  const deletion = normalizeProbabilityRational(pDel, 'p_del');
  const alphaReciprocal = (alpha.denominator * nMax) / alpha.numerator;
  if (!Number.isFinite(alphaReciprocal) || alphaReciprocal <= 1) {
    throw new Error('epistemic_certificate_alpha_i_invalid');
  }

  const fractionPpm = Math.floor((selectedCount * PROBABILITY_SCALE) / nCertify);
  const penalty = Math.sqrt(Math.log(alphaReciprocal) / (2 * nCertify));
  const penaltyPpm = Math.ceil(penalty * PROBABILITY_SCALE);
  const muPpm = Math.max(0, fractionPpm - penaltyPpm);
  const runnerUpperPpm = PROBABILITY_SCALE - muPpm;

  if (muPpm <= PROBABILITY_SCALE / 2) {
    return Object.freeze({
      outcome: 'abstain',
      reason: 'confidence_not_above_half',
      fraction_ppm: fractionPpm,
      penalty_ppm: penaltyPpm,
      mu_lower_ppm: muPpm,
      runner_upper_ppm: runnerUpperPpm,
      radius: null,
    });
  }

  const argumentPpm = 1_500_000 - muPpm;
  let radius = 0;
  let numeratorPower = 1n;
  let denominatorPower = 1n;
  const pNumerator = BigInt(deletion.numerator);
  const pDenominator = BigInt(deletion.denominator);
  const argument = BigInt(argumentPpm);
  const scale = BigInt(PROBABILITY_SCALE);

  for (let candidate = 1; candidate <= maxRadius; candidate += 1) {
    numeratorPower *= pNumerator;
    denominatorPower *= pDenominator;
    if (numeratorPower * scale < argument * denominatorPower) break;
    radius = candidate;
  }

  return Object.freeze({
    outcome: 'certified',
    reason: null,
    fraction_ppm: fractionPpm,
    penalty_ppm: penaltyPpm,
    mu_lower_ppm: muPpm,
    runner_upper_ppm: runnerUpperPpm,
    theorem_argument_ppm: argumentPpm,
    radius,
  });
}

export function applyDeletionBitmap(tokens, bitmapBase64) {
  if (!Array.isArray(tokens)) throw new Error('epistemic_certificate_tokens_invalid');
  const bitmap = Buffer.from(String(bitmapBase64 || ''), 'base64');
  const expectedBytes = Math.ceil(tokens.length / 8);
  if (bitmap.length !== expectedBytes) throw new Error('epistemic_certificate_bitmap_length_mismatch');
  if (tokens.length % 8 && bitmap.length) {
    const unusedMask = (0xff << (tokens.length % 8)) & 0xff;
    if ((bitmap[bitmap.length - 1] & unusedMask) !== 0) {
      throw new Error('epistemic_certificate_bitmap_unused_bits_set');
    }
  }
  return tokens.filter((_, index) => (bitmap[Math.floor(index / 8)] & (1 << (index % 8))) === 0);
}

export function canonicalMemoryCommitment(memory = {}) {
  const contentHash = Buffer.isBuffer(memory.content_hash)
    ? memory.content_hash.toString('hex')
    : String(memory.live_content_hash || memory.content_hash || '');
  return Object.freeze({
    id: String(memory.id || memory.memory_id || ''),
    key: String(memory.key || ''),
    source: String(memory.source || ''),
    memory_type: String(memory.memory_type || memory.memoryType || ''),
    live_content_hash: contentHash || null,
    value_sha256: createHash('sha256').update(String(memory.value || ''), 'utf8').digest('hex'),
  });
}

export function buildEpistemicCertificateInputCommitment(memory, peers, classifierSourceSha256) {
  if (!/^[0-9a-f]{64}$/.test(String(classifierSourceSha256 || ''))) {
    throw new Error('epistemic_certificate_classifier_source_hash_invalid');
  }
  const orderedPeers = Array.isArray(peers) ? peers : [];
  const candidate = canonicalMemoryCommitment(memory);
  const peerCommitments = orderedPeers.map(canonicalMemoryCommitment);
  const tokens = canonicalizeEditTokens(memory?.value);
  return Object.freeze({
    candidate,
    ordered_peers: peerCommitments,
    ordered_peer_root_sha256: sha256Canonical(peerCommitments),
    classifier_source_sha256: classifierSourceSha256,
    tokenizer_version: EPISTEMIC_EDIT_TOKENIZER_VERSION,
    token_count: tokens.length,
    token_sequence_sha256: sha256Canonical(tokens),
    input_sha256: sha256Canonical({ candidate, peerCommitments, classifierSourceSha256 }),
  });
}

