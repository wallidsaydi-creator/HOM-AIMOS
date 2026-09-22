// Differential byte regressions, not evidence of live database admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { canonicalJson as native } from '../../services/security/protocol/canonical-json.js';
import { canonicalJson as independentNode } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { originProtocolBytesV1 } from '../../services/security/protocol/origin-binding-v1.js';

const root = new URL('../../', import.meta.url).pathname;
function python(rawValues, owner = 'crypto') {
  const program = `import importlib.util,json,sys
owner=${JSON.stringify(owner)}
path=${JSON.stringify(root)}+('verifiers/mutmem-v2/python/crypto_kernel.py' if owner=='crypto' else 'verifiers/origin-binding/v1/verify.py')
s=importlib.util.spec_from_file_location('audit018_independent',path)
m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
out=[]
for raw in json.load(sys.stdin):
 try:out.append({'accepted':True,'bytes':m.canonical_json(json.loads(raw))})
 except (ValueError,m.VerifyError if owner=='origin' else m.MutMemKernelError) as e:out.append({'accepted':False,'reason':str(e)})
print(json.dumps(out,ensure_ascii=True))`;
  const run = spawnSync('python3', ['-c', program], { input: JSON.stringify(rawValues), encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const rows = JSON.parse(run.stdout); assert.equal(rows.length, rawValues.length); return rows;
}
function outcome(fn, raw) {
  try { return { accepted: true, bytes: fn(JSON.parse(raw)) }; }
  catch (error) { return { accepted: false, reason: error.message }; }
}

test('AUD-018 independent crypto accepts the same numeric values and bytes as its Node peer', () => {
  const raw = ['0', '-0', '1.0', '1e0', '-1.0', '9007199254740991', '9007199254740991.0',
    '9007199254740992', '9007199254740992.0', '-9007199254740992.0', '1e20', '1e21', '1e23',
    '1e-27', '5e-324', '1e-7', '0.000001', '0.1', '333333333.33333329', '4.50', '2e-3',
    '1e400', '-1e400'];
  const rows = python(raw);
  for (const [i, value] of raw.entries()) {
    const node = outcome(independentNode, value);
    assert.equal(rows[i].accepted, node.accepted, value);
    if (node.accepted) assert.equal(rows[i].bytes, node.bytes, value);
    else assert.match(rows[i].reason, /CANONICAL_NUMBER_INVALID/);
  }
});

test('AUD-018 origin independent bytes match native UTF-16 ordering and safe integral JSON values', () => {
  const raw = [JSON.stringify({ '\ue000': 1, '\u{10000}': 2 }),
    JSON.stringify({ z: [{ '\ue000': 'z', '\u{10000}': 'a' }], a: { 2: true, 10: null, 1: false } }),
    JSON.stringify({ escapes: '\b\t\n\f\r"\\/\u0000\u2028\u2029', unicode: 'é😀' }),
    JSON.stringify({ surrogate: '\ud800', low: '\udfff' }),
    '{"n":1.0}', '{"n":1e0}', '{"n":-0.0}', '{"n":9007199254740991.0}'];
  const rows = python(raw, 'origin');
  for (const [i, value] of raw.entries()) {
    assert.equal(rows[i].accepted, true, value);
    assert.equal(rows[i].bytes, native(JSON.parse(value)), value);
    assert.equal(rows[i].bytes, independentNode(JSON.parse(value)), value);
  }
});

test('AUD-018 origin numeric restriction is distinct from the wider historical native JSON codec', () => {
  const values = [0.1, 1e-7, 9007199254740992, null, true, '1'];
  const raw = values.map(n => JSON.stringify({ schema: 'hom.aimos.memory-origin-binding/v1', n }));
  const rows = python(raw, 'origin');
  for (const [i, text] of raw.entries()) {
    let accepted = true;
    try { originProtocolBytesV1(JSON.parse(text)); } catch { accepted = false; }
    assert.equal(rows[i].accepted, accepted, text);
    // Preserved historical native serializer is not falsely claimed to impose the origin domain.
    assert.equal(typeof native(JSON.parse(text)), 'string');
  }
});
