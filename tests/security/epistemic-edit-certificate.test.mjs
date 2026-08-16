import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

import {
  applyDeletionBitmap,
  canonicalizeEditTokens,
  computeConservativeCertificateMath,
} from '../../services/security/epistemic-edit-certificate-math.js';
import {
  certifyEpistemicEditRobustness,
  certifyEpistemicEditRobustnessFromPlan,
  generateEpistemicDeletionPlan,
} from '../../services/security/epistemic-edit-certifier.js';
import { verifyEpistemicEditCertificate } from '../../services/security/epistemic-edit-certificate-verifier.js';

const classifierSourceSha256 = createHash('sha256')
  .update(readFileSync(new URL('../../services/security/memory-epistemic-classifier-kernel.js', import.meta.url)))
  .digest('hex');

const memory = {
  id: '00000000-0000-4000-8000-000000000001',
  key: 'reference:test',
  source: 'benchmark:a',
  memory_type: 'research',
  value: 'What is the access code? The access code is 4829 and remains unchanged.',
  content_hash: 'a'.repeat(64),
};

test('CERT-ED hand fixture conservatively certifies radius five', () => {
  const result = computeConservativeCertificateMath({
    selectedCount: 3800,
    nCertify: 4000,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 100,
    pDel: { numerator: 9, denominator: 10 },
  });
  assert.equal(result.outcome, 'certified');
  assert.equal(result.radius, 5);
  assert.ok(result.mu_lower_ppm <= 919177);
});

test('confidence at or below one half abstains', () => {
  const result = computeConservativeCertificateMath({
    selectedCount: 50,
    nCertify: 100,
    alphaFamily: { numerator: 5, denominator: 100 },
    nMax: 100,
    pDel: { numerator: 9, denominator: 10 },
  });
  assert.deepEqual({ outcome: result.outcome, radius: result.radius }, { outcome: 'abstain', radius: null });
});

test('tokenizer canonicalizes Unicode and line endings', () => {
  assert.deepEqual(canonicalizeEditTokens('  Cafe\u0301\r\n  au\t lait  '), ['Café', 'au', 'lait']);
});

test('bitmap rejects non-zero unused bits', () => {
  assert.throws(() => applyDeletionBitmap(['a'], Buffer.from([0x80]).toString('base64')), /unused_bits_set/);
});

test('native certifier emits a replay-verifiable bounded certificate', () => {
  const certificate = certifyEpistemicEditRobustness({
    memory,
    peers: [],
    classifierSourceSha256,
    pDel: { numerator: 9, denominator: 10 },
    nSelect: 60,
    nCertify: 120,
    nMax: 1,
  });
  const verified = verifyEpistemicEditCertificate({
    certificate,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.outcome, certificate.decision.outcome);
});

test('pre-outcome deletion plan is self-bound and deterministically replayable', () => {
  const parameters = {
    memory,
    peers: [],
    classifierSourceSha256,
    pDel: { numerator: 3, denominator: 4 },
    nSelect: 40,
    nCertify: 80,
    nMax: 1,
  };
  const deletionPlan = generateEpistemicDeletionPlan(parameters);
  const first = certifyEpistemicEditRobustnessFromPlan({ ...parameters, deletionPlan });
  const second = certifyEpistemicEditRobustnessFromPlan({ ...parameters, deletionPlan });
  assert.deepEqual(second, first);

  const tampered = structuredClone(deletionPlan);
  tampered.selection_bitmaps[0] = Buffer.alloc(
    Buffer.from(tampered.selection_bitmaps[0], 'base64').length,
  ).toString('base64');
  assert.throws(
    () => certifyEpistemicEditRobustnessFromPlan({ ...parameters, deletionPlan: tampered }),
    /deletion_plan_hash_invalid/,
  );
});

test('transcript and input tampering fail closed', () => {
  const certificate = certifyEpistemicEditRobustness({
    memory,
    peers: [],
    classifierSourceSha256,
    nSelect: 20,
    nCertify: 40,
    nMax: 1,
  });
  const tamperedTranscript = structuredClone(certificate);
  tamperedTranscript.transcripts.certification[0].output = tamperedTranscript.transcripts.certification[0].output === 'U' ? 'N' : 'U';
  assert.equal(verifyEpistemicEditCertificate({
    certificate: tamperedTranscript,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
  }).valid, false);
  assert.equal(verifyEpistemicEditCertificate({
    certificate,
    memory: { ...memory, value: `${memory.value} changed` },
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
  }).valid, false);
  assert.equal(verifyEpistemicEditCertificate({
    certificate,
    memory,
    peers: [],
    expectedClassifierSourceSha256: 'f'.repeat(64),
  }).reason, 'classifier_source_hash_mismatch');
});

test('resource exhaustion becomes a verifiable abstention', () => {
  const certificate = certifyEpistemicEditRobustness({
    memory,
    classifierSourceSha256,
    nSelect: 10,
    nCertify: 10,
    nMax: 1,
    resourceCaps: { maxTokens: 2, maxPeers: 1, maxSamples: 100 },
  });
  assert.equal(certificate.decision.outcome, 'abstain');
  assert.equal(certificate.decision.reason, 'resource_cap_exceeded');
  assert.equal(verifyEpistemicEditCertificate({
    certificate,
    memory,
    peers: [],
    expectedClassifierSourceSha256: classifierSourceSha256,
  }).valid, true);
});

test('dormant certificate modules import no database, network, route, keychain, or environment authority', () => {
  for (const relative of [
    '../../services/security/memory-epistemic-classifier-kernel.js',
    '../../services/security/epistemic-edit-certificate-math.js',
    '../../services/security/epistemic-edit-certifier.js',
    '../../services/security/epistemic-edit-certificate-verifier.js',
  ]) {
    const source = readFileSync(new URL(relative, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /(?:from|import\()\s*['"][^'"]*(?:db\/|routes?\/|event-ledger|keychain)/i);
    assert.doesNotMatch(source, /process\.env|fetch\(|https?:\/\//i);
  }
});
