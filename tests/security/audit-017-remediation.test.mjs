// Strict wire-domain regression; constructor normalization is tested separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createMemoryOriginBindingV1, verifyOriginDerivationV1, originProtocolHashV1,
  ORIGIN_FAMILY_PROFILE_BODY_V1 } from '../../services/security/protocol/origin-binding-v1.js';
import { untrustedBindingInput } from '../../scripts/verification/origin-binding-ob1-fixtures.mjs';

const pythonPath = new URL('../../verifiers/origin-binding/v1/verify.py', import.meta.url).pathname;
function independent(values) {
  const program = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('origin_independent',${JSON.stringify(pythonPath)})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=json.load(sys.stdin);v=m.ProtocolVerifier(r['profile']);out=[]
for x in r['values']:
 try:v.binding(x,with_hash=True);out.append({'valid':True,'bytes':m.canonical_json(x)})
 except m.VerifyError as e:out.append({'valid':False,'reason':e.code})
print(json.dumps(out))`;
  const run = spawnSync('python3', ['-c', program], { input: JSON.stringify({ profile: ORIGIN_FAMILY_PROFILE_BODY_V1, values }), encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr); return JSON.parse(run.stdout);
}
function wireAt(timestamp, field = 'created_at') {
  const body = untrustedBindingInput();
  if (field === 'created_at') body.created_at = timestamp;
  else body.actor.valid_from = timestamp;
  // Recompute only the unsigned object commitment, not a signature.
  return { ...body, binding_sha256: originProtocolHashV1(body).toString('hex') };
}

test('AUD-017 strict native and independent wires agree on real calendar and UTC-millisecond domain', () => {
  const valid = ['0000-02-29T00:00:00.000Z', '0001-01-01T00:00:00.000Z',
    '1900-02-28T23:59:59.999Z', '2000-02-29T00:00:00.000Z', '2024-02-29T12:30:00.001Z',
    '2026-09-08T00:00:00.000Z', '9999-12-31T23:59:59.999Z'];
  const invalid = ['2026-02-31T25:61:61.000Z', '2026-02-29T00:00:00.000Z',
    '1900-02-29T00:00:00.000Z', '2100-02-29T00:00:00.000Z', '2026-04-31T00:00:00.000Z',
    '2026-00-01T00:00:00.000Z', '2026-13-01T00:00:00.000Z', '2026-01-00T00:00:00.000Z',
    '2026-01-01T24:00:00.000Z', '2026-01-01T23:60:00.000Z', '2026-01-01T23:59:60.000Z',
    '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.00Z', '2026-01-01T00:00:00.0000Z',
    '2026-01-01T01:00:00.000+01:00', '2026-01-01t00:00:00.000z',
    '+010000-01-01T00:00:00.000Z', '-000001-01-01T00:00:00.000Z',
    '２０２６-01-01T00:00:00.000Z', '', null];
  const cases = [];
  for (const field of ['created_at', 'actor.valid_from']) {
    for (const value of valid) cases.push({ wire: wireAt(value, field), valid: true });
    for (const value of invalid) cases.push({ wire: wireAt(value, field), valid: false });
  }
  const results = independent(cases.map(c => c.wire));
  for (const [i, c] of cases.entries()) {
    let native = false;
    try { native = verifyOriginDerivationV1({ child: c.wire, parents: [] }).valid; } catch {}
    assert.equal(native, c.valid, `native:${JSON.stringify(c.wire)}`);
    assert.equal(results[i].valid, c.valid, `Python:${JSON.stringify(c.wire)}`);
    if (!c.valid) assert.equal(results[i].reason, 'timestamp_invalid');
  }
});

test('AUD-017 constructors may normalize hash case but strict wire admission cannot', () => {
  const input = untrustedBindingInput();
  input.content_sha256 = input.content_sha256.toUpperCase();
  const normalized = createMemoryOriginBindingV1(input);
  const noncanonical = { ...normalized, content_sha256: normalized.content_sha256.toUpperCase() };
  const hashAlias = { ...normalized, binding_sha256: normalized.binding_sha256.toUpperCase() };
  assert.equal(verifyOriginDerivationV1({ child: normalized }).valid, true);
  assert.throws(() => verifyOriginDerivationV1({ child: noncanonical }));
  assert.throws(() => verifyOriginDerivationV1({ child: hashAlias }));
  assert.deepEqual(independent([normalized, noncanonical, hashAlias]).map(r => r.valid), [true, false, false]);
});
