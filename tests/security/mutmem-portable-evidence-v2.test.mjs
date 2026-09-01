import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  MUTMEM_PORTABLE_EVIDENCE_V2,
  MUTMEM_RECALL_RESULT_KINDS_V2,
  MUTMEM_RECALL_SINGLETON_KINDS_V2,
  createMutMemPortableEvidenceEnvelopeV2,
  createMutMemPortableObjectV2,
  mutMemPortableEnvelopeHashV2,
  mutMemPortableObjectHashV2,
} from '../../services/security/protocol/mutmem-portable-evidence-v2.js';

const MASTER = 'ab'.repeat(32);
const MEMORY_A = '11111111-1111-4111-8111-111111111111';

function singleton(kind, suffix = '') {
  const schema = `hom.aimos.fixture.${kind}/v1`;
  return createMutMemPortableObjectV2({
    kind,
    schema,
    body: { schema, kind, suffix, fixture: true },
  });
}

function resultObject(kind, resultOrdinal, subjectId, suffix = '') {
  const schema = `hom.aimos.fixture.${kind}/v1`;
  return createMutMemPortableObjectV2({
    kind,
    schema,
    resultOrdinal,
    subjectId,
    body: { schema, kind, memory_id: subjectId, result_ordinal: resultOrdinal, suffix },
  });
}

function objects({ resultCount = 1, suffix = '' } = {}) {
  return [
    ...MUTMEM_RECALL_SINGLETON_KINDS_V2.map((kind) => singleton(kind, suffix)),
    ...Array.from({ length: resultCount }, (_, resultOrdinal) => {
      const subjectId = resultOrdinal === 0
        ? MEMORY_A
        : `00000000-0000-4000-8000-${String(resultOrdinal + 1).padStart(12, '0')}`;
      return MUTMEM_RECALL_RESULT_KINDS_V2.map(
        (kind) => resultObject(kind, resultOrdinal, subjectId, suffix),
      );
    }).flat(),
  ];
}

function envelope(overrides = {}) {
  return createMutMemPortableEvidenceEnvelopeV2({
    bundleId: 'P1-PE-CV-001',
    companyId: 'hom',
    expectedMasterFingerprint: MASTER,
    resultCount: 1,
    objects: objects(),
    ...overrides,
  });
}

test('P1 current envelope has exact mandatory membership and deterministic order', () => {
  const first = envelope();
  const permuted = envelope({ objects: [...objects()].reverse() });
  assert.deepEqual(first, permuted);
  assert.equal(first.format.schema, 'hom.aimos.mutmem-portable-evidence/v2');
  assert.equal(first.format.native_receipt_schema,
    'hom-aimos/recall-merkle/v3-epistemic-and-security-closure');
  assert.equal(first.object_count,
    MUTMEM_RECALL_SINGLETON_KINDS_V2.length + MUTMEM_RECALL_RESULT_KINDS_V2.length);
  assert.deepEqual(
    first.objects.map((object) => object.kind),
    [...MUTMEM_RECALL_SINGLETON_KINDS_V2, ...MUTMEM_RECALL_RESULT_KINDS_V2],
  );
  assert.deepEqual(first.objects.map((object) => object.ordinal),
    Array.from({ length: first.object_count }, (_, ordinal) => ordinal));
  assert.match(first.object_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(first.bundle_sha256, /^[0-9a-f]{64}$/);
  assert.equal(first.objects[0].body_sha256,
    'fb74eec7a7f70476c98f482d9b886811fd36ac6ace9b390f4f50a3c337c80cb5');
  assert.equal(first.object_root_sha256,
    '7c6de7d4524ee7991fb27d9de5c221d9617f1e553685078b88dcac9ffd1eccd2');
  assert.equal(first.bundle_sha256,
    '8060986eba9c0efc53663e4e7e878d041461c15e6df07882597d556d25e5c3e0');
});

test('P1 envelope uses typed object and bundle commitments', () => {
  const evidence = singleton('trust_anchor');
  assert.equal(
    evidence.body_sha256,
    mutMemPortableObjectHashV2({
      kind: evidence.kind,
      schema: evidence.schema,
      body: evidence.body,
    }).toString('hex'),
  );
  const bundle = envelope();
  assert.equal(
    bundle.bundle_sha256,
    mutMemPortableEnvelopeHashV2({
      bundleId: bundle.bundle_id,
      companyId: bundle.company_id,
      expectedMasterFingerprint: bundle.expected_master_fingerprint,
      resultCount: bundle.result_count,
      objectRootSha256: bundle.object_root_sha256,
    }).toString('hex'),
  );
  const changedRoot = envelope({ expectedMasterFingerprint: 'cd'.repeat(32) });
  assert.notEqual(changedRoot.bundle_sha256, bundle.bundle_sha256);
  const changedBody = envelope({ objects: objects({ suffix: 'changed' }) });
  assert.notEqual(changedBody.object_root_sha256, bundle.object_root_sha256);
  assert.notEqual(changedBody.bundle_sha256, bundle.bundle_sha256);
});

test('P1 envelope requires the complete singleton and per-result partitions', () => {
  assert.throws(
    () => envelope({ objects: objects().filter((object) => object.kind !== 'request_receipt') }),
    /mutmem_portable_evidence_v2:singleton_missing:request_receipt/,
  );
  assert.throws(
    () => envelope({ objects: [...objects(), singleton('request_receipt')] }),
    /mutmem_portable_evidence_v2:singleton_duplicate/,
  );
  assert.throws(
    () => envelope({ objects: objects().filter((object) => object.kind !== 'occurrence') }),
    /mutmem_portable_evidence_v2:result_kind_missing:0:occurrence/,
  );
  const mismatched = objects().map((object) => (
    object.kind === 'occurrence'
      ? resultObject('occurrence', 0, '22222222-2222-4222-8222-222222222222')
      : object
  ));
  assert.throws(
    () => envelope({ objects: mismatched }),
    /mutmem_portable_evidence_v2:result_subject_mismatch/,
  );
});

test('P1 envelope does not accept a self-selected or malformed trust root', () => {
  assert.throws(
    () => envelope({ expectedMasterFingerprint: null }),
    /mutmem_portable_evidence_v2:expected_master_fingerprint_invalid/,
  );
  assert.throws(
    () => envelope({ expectedMasterFingerprint: 'not-a-root' }),
    /mutmem_portable_evidence_v2:expected_master_fingerprint_invalid/,
  );
  assert.equal(MUTMEM_PORTABLE_EVIDENCE_V2.trust_anchor_mode,
    'external_expected_master_fingerprint_required');
});

test('P1 typed objects reject schema ambiguity and unsafe cross-language integers', () => {
  assert.throws(
    () => createMutMemPortableObjectV2({
      kind: 'trust_anchor',
      schema: 'hom.aimos.fixture.trust-anchor/v1',
      body: { schema: 'hom.aimos.fixture.different/v1' },
    }),
    /mutmem_portable_evidence_v2:object_body_schema_mismatch/,
  );
  assert.throws(
    () => createMutMemPortableObjectV2({
      kind: 'trust_anchor',
      schema: 'hom.aimos.fixture.trust-anchor/v1',
      body: {
        schema: 'hom.aimos.fixture.trust-anchor/v1',
        unsafe_integer: Number.MAX_SAFE_INTEGER + 1,
      },
    }),
    /mutmem_portable_evidence_v2:object_body_number_invalid/,
  );
});

test('P1 envelope is immutable and does not mutate caller objects', () => {
  const source = objects();
  const snapshot = structuredClone(source);
  const bundle = envelope({ objects: source });
  assert.deepEqual(source, snapshot);
  assert(Object.isFrozen(bundle));
  assert(Object.isFrozen(bundle.objects));
  assert(Object.isFrozen(bundle.objects[0].body));
  assert.throws(() => { bundle.objects[0].body.fixture = false; }, TypeError);
});

test('P1 envelope owner has no runtime, signer, database, filesystem, network, or policy authority', async () => {
  const source = await readFile(
    new URL('../../services/security/protocol/mutmem-portable-evidence-v2.js', import.meta.url),
    'utf8',
  );
  assert.deepEqual(
    [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((match) => match[1]),
    ['node:crypto', './canonical-json.js', './mutmem-protocol.js'],
  );
  assert.doesNotMatch(source,
    /process\.env|fetch\(|readFile\(|writeFile\(|query\(|pool\.|sign\(|createPrivateKey|services\/retrieval|routes\/|jobs\//);
  assert.match(source, /Independent verification belongs\s*\/\/ to P2/);
});
