// Differential protocol regression, not a production enrollment or live proof.
// Published vectors remain unchanged; current test-only fixtures carry the
// complete receipt binding. These are regression vectors, not live proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { encodeOccurrenceV3, occurrenceCommitmentV3, verifyOccurrenceSignatureV3 }
  from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { verifyRecallEnvelope } from '../../verifiers/mutmem-v2/node/recall-verifier.mjs';
import { createMutMemPortableObjectV2, createMutMemPortableEvidenceEnvelopeV2 }
  from '../../services/security/protocol/mutmem-portable-evidence-v2.js';
import { createP2RecallCryptographicVectors } from '../../scripts/verification/mutmem-p2-crypto-vector-factory.mjs';

const root = new URL('../../', import.meta.url).pathname;
const historical = JSON.parse(readFileSync(root + 'verifiers/mutmem-conformance/v2/p2-crypto-vectors.json'))
  .recall.vectors.find(vector => vector.id === 'P2-CRYPTO-RECALL-VALID');
const frozen = createP2RecallCryptographicVectors().find(vector => vector.id === 'P2-CRYPTO-RECALL-VALID');
const occurrence = frozen.bundle.objects.find(object => object.kind === 'occurrence').body;
const publicKey = frozen.bundle.objects.find(object => object.kind === 'housekeeper_identity_epoch').body.public_key_b64u;
const record = occurrence.native_body;
const fields = ['sig_form_version', 'ts_signed_unix_seconds', 'signer_valid_from_unix_ms',
  'predecessor_present', 'request_receipt_present', 'authorization_event_present'];
const optional = { predecessor_present: 'predecessor_commitment_hex',
  request_receipt_present: 'request_receipt_mutation_hash_hex', authorization_event_present: 'authorization_event_id' };
const invalidHost = { nan: NaN, infinity: Infinity, negative_infinity: -Infinity };

function python(cases) {
  const source = `import sys,json
sys.path.insert(0,${JSON.stringify(root + 'verifiers/mutmem-v2/python')})
from crypto_kernel import encode_occurrence_v3,verify_occurrence_signature_v3
request=json.load(sys.stdin)
out=[]
for case in request['cases']:
 r=json.loads(case['wire'])
 if 'host_value' in case:r[case['field']]={'nan':float('nan'),'infinity':float('inf'),'negative_infinity':float('-inf')}[case['host_value']]
 try:out.append({'accepted':True,'bytes':encode_occurrence_v3(r).hex(),'signature_valid':verify_occurrence_signature_v3(r,request['signature'],request['public_key'])})
 except Exception as error:out.append({'accepted':False,'reason':getattr(error,'reason',type(error).__name__)})
print(json.dumps(out))`;
  const run = spawnSync(process.env.MUTMEM_P2_PYTHON || 'python3', ['-c', source], {
    input: JSON.stringify({ cases, signature: occurrence.signature_b64u, public_key: publicKey }), encoding: 'utf8', maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(run.status, 0, run.stderr); return JSON.parse(run.stdout);
}
function node(case_) {
  const r = JSON.parse(case_.wire);
  if (case_.host_value) r[case_.field] = invalidHost[case_.host_value];
  try { return { accepted: true, bytes: encodeOccurrenceV3(r).toString('hex'),
    signature_valid: verifyOccurrenceSignatureV3(r, occurrence.signature_b64u, publicKey) }; }
  catch (error) { return { accepted: false, reason: error.reason }; }
}

test('AUD-016 preserves original signed occurrence bytes and complete envelope verification', () => {
  assert.deepEqual(occurrence, historical.bundle.objects.find(object => object.kind === 'occurrence').body);
  assert.equal(occurrenceCommitmentV3(record), occurrence.occurrence_ref);
  const [p] = python([{ wire: JSON.stringify(record) }]);
  assert.equal(p.bytes, encodeOccurrenceV3(record).toString('hex'));
  assert.equal(p.signature_valid, true);
  assert.equal(verifyRecallEnvelope(frozen.bundle, { expectedMasterFingerprint: frozen.expected_master_fingerprint }).valid, true);
});

test('AUD-016 all integer fields share exact JSON numeric-value admission and bytes', () => {
  const cases = [];
  for (const field of fields) {
    const values = [0, -0, 1, 3, record[field], record[field] + 0.5, 1.5, -1,
      Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, -Number.MAX_SAFE_INTEGER,
      true, false, '1', '3', '', null];
    for (const value of values) {
      const r = { ...record, [field]: value };
      if (value === 0 && optional[field]) r[optional[field]] = '';
      const accepted = typeof value === 'number' && Number.isSafeInteger(value)
        && (field === 'sig_form_version' ? value === 3 : optional[field] ? value === 0 || value === 1
          : field === 'ts_signed_unix_seconds' ? value >= 0 : true);
      cases.push({ field, wire: JSON.stringify(r), accepted });
    }
    for (const host_value of Object.keys(invalidHost)) cases.push({ field, host_value, wire: JSON.stringify(record), accepted: false });
    // Preserve lexical numeric alternatives that parse to the same JSON value.
    for (const suffix of ['.0', 'e0']) cases.push({ field,
      wire: JSON.stringify(record).replace(`"${field}":${record[field]}`, `"${field}":${record[field]}${suffix}`), accepted: true });
  }
  const independent = python(cases);
  for (const [index, case_] of cases.entries()) {
    const n = node(case_), p = independent[index];
    assert.equal(n.accepted, case_.accepted, `Node domain:${case_.field}:${case_.wire}`);
    assert.equal(p.accepted, case_.accepted, `Python domain:${case_.field}:${case_.wire}`);
    if (case_.accepted) assert.deepEqual(p, n, `${case_.field}:bytes/signature parity`);
    else { assert.equal(p.reason, 'OCCURRENCE_ENCODING_INVALID'); assert.equal(n.reason, p.reason); }
  }
});

test('AUD-016 fractional substitutions cannot reuse the unchanged signed commitment', () => {
  const cases = ['sig_form_version', 'ts_signed_unix_seconds', 'signer_valid_from_unix_ms', 'predecessor_present']
    .map(field => ({ field, wire: JSON.stringify({ ...record, [field]: record[field] + 0.5 }) }));
  for (const result of python(cases)) assert.equal(result.accepted, false);
  for (const case_ of cases) assert.equal(node(case_).accepted, false);
});

test('AUD-016 complete envelopes reject fractional native fields after unsigned roots are recomputed', () => {
  const bundles = fields.map(field => {
    const objects = frozen.bundle.objects.map(object => createMutMemPortableObjectV2({
      kind: object.kind, schema: object.schema, subjectId: object.subject_id, resultOrdinal: object.result_ordinal,
      body: object.kind === 'occurrence' ? { ...object.body, native_body: { ...record, [field]: record[field] + 0.5 } } : object.body,
    }));
    return createMutMemPortableEvidenceEnvelopeV2({ bundleId: frozen.bundle.bundle_id, companyId: frozen.bundle.company_id,
      expectedMasterFingerprint: frozen.expected_master_fingerprint, resultCount: frozen.bundle.result_count, objects });
  });
  for (const bundle of bundles) assert.throws(() => verifyRecallEnvelope(bundle, { expectedMasterFingerprint: frozen.expected_master_fingerprint }),
    error => error.reason === 'OCCURRENCE_NATIVE_BODY_INVALID');
  const run = spawnSync(process.env.MUTMEM_P2_PYTHON || 'python3',
    [root + 'verifiers/mutmem-v2/python/verifier_cli.py'], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024,
      input: JSON.stringify({ operation: 'batch', profile: 'recall', items: bundles.map(bundle => ({ bundle,
        expected_master_fingerprint: frozen.expected_master_fingerprint, verify_cryptography: true })) }) });
  assert.equal(run.status, 0, run.stderr + run.stdout);
  const terminals = JSON.parse(run.stdout).terminals;
  assert.equal(terminals.length, fields.length);
  for (const terminal of terminals) {
    assert.equal(terminal.valid, false);
    assert.equal(terminal.reason, 'OCCURRENCE_NATIVE_BODY_INVALID');
    assert.notEqual(terminal.reason, 'ENVELOPE_COMMITMENT_INVALID', 'must test native semantic validation, not a stale unsigned checksum');
  }
});
