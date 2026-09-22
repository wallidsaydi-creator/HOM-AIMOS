import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { signedJsonBytesCommitmentV1 as native } from '../../services/security/protocol/mutmem-protocol.js';
import { signedJsonBytesCommitmentV1 as independent } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { wireSchema, wireCases } from './audit-018-wire-cases.mjs';

export function pythonCommitments(cases) {
  const path = new URL('../../verifiers/mutmem-v2/python', import.meta.url).pathname;
  const program = `import sys,json
sys.path.insert(0,${JSON.stringify(path)})
from crypto_kernel import signed_json_bytes_commitment_v1
out=[]
for c in json.load(sys.stdin):
 try:out.append({'accepted':True,'hash':signed_json_bytes_commitment_v1(c['schema'],bytes.fromhex(c['hex'])).hex()})
 except ValueError as e:out.append({'accepted':False,'reason':str(e)})
print(json.dumps(out))`;
  const run = spawnSync('python3', ['-c', program], { input: JSON.stringify(cases.map(c => ({
    schema: c.schema ?? wireSchema, hex: c.wire.toString('hex') }))), encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr); const result = JSON.parse(run.stdout);
  assert.equal(result.length, cases.length); return result;
}

test('AUD-018 new exact-byte profile agrees without reserializing numbers or keys', () => {
  const python = pythonCommitments(wireCases);
  for (const [i, c] of wireCases.entries()) {
    assert.equal(python[i].accepted, c.accepted, c.name);
    for (const hash of [native, independent]) {
      if (c.accepted) assert.equal(hash(wireSchema, c.wire).toString('hex'), python[i].hash, c.name);
      else assert.throws(() => hash(wireSchema, c.wire), /signed_json_wire_invalid/, c.name);
    }
  }
});

test('AUD-018 type and exact spelling are cryptographically distinct; no hash-only authority claim', () => {
  const body = Buffer.from('{"a":1}');
  assert.notDeepEqual(native(wireSchema, body), native('hom.aimos.request/v5', body));
  assert.notDeepEqual(native(wireSchema, body), native(wireSchema, Buffer.from('{"a":1.0}')));
  for (const schema of ['', 'hom.event', 'hom.event/v0', 'hom.évent/v1', 'a'.repeat(201) + '/v1']) {
    assert.throws(() => native(schema, body), /signed_json_schema_invalid/);
    assert.throws(() => independent(schema, body), /signed_json_schema_invalid/);
  }
  assert.throws(() => native(wireSchema, Buffer.alloc(0)), /signed_json_size_invalid/);
});
