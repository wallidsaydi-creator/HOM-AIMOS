// Exercise installed Express parsing, not a substitute product route or signer.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { spawnSync } from 'node:child_process';
import { parseJsonWire as independentParse, decodeCertificate } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import * as jsonProtocol from '../../services/security/protocol/canonical-json.js';

test('AUD-018 unterminated escaped strings are rejected in a bounded forward scan', () => {
  const input = '{"a":"' + '\\"'.repeat(32768);
  for (const owner of ['services/security/protocol/canonical-json.js', 'verifiers/mutmem-v2/node/crypto-kernel.mjs']) {
    const path = new URL('../../' + owner, import.meta.url).href;
    const run = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import {readFileSync} from 'node:fs';import {parseJsonWire} from ${JSON.stringify(path)};
      const input=readFileSync(0,'utf8'),started=performance.now();
      try {parseJsonWire(input);process.exitCode=2;} catch {
        if(performance.now()-started>1200)process.exitCode=3;
        else console.log('REJECTED');}`], {
      // Retain the 1200ms parser bound; do not charge competing-process startup
      // and module loading to parser complexity. Hung parsers still fail.
      input, encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
    assert.equal(run.error, undefined, owner);
    assert.equal(run.status, 0, owner); assert.equal(run.stdout.trim(), 'REJECTED');
  }
});

test('AUD-018 all independent wire parsers reject duplicates without rejecting separate objects', () => {
  const raw = ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"😀":1,"\\ud83d\\ude00":2}',
    '{"nested":[{"a":1,"a":2}]}', '{"__proto__":0,"__proto__":1}',
    '{"a":{"x":1},"b":{"x":2}}', '{"a":1,"A":2}', '{"é":1,"é":2}'];
  const root = new URL('../../', import.meta.url).pathname;
  for (const owner of ['crypto', 'origin']) {
    const program = `import importlib.util,json,sys
path=${JSON.stringify(root)}+${JSON.stringify(owner === 'crypto' ? 'verifiers/mutmem-v2/python/crypto_kernel.py' : 'verifiers/origin-binding/v1/verify.py')}
s=importlib.util.spec_from_file_location('audit018_parse',path);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
out=[]
for raw in json.load(sys.stdin):
 try:m.parse_json_wire(raw);out.append(True)
 except Exception:out.append(False)
print(json.dumps(out))`;
    const run = spawnSync('python3', ['-c', program], { input: JSON.stringify(raw), encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(JSON.parse(run.stdout), [false, false, false, false, false, true, true, true]);
  }
  for (const [i, text] of raw.entries()) for (const parse of [independentParse, jsonProtocol.parseJsonWire]) {
    if (i < 5) assert.throws(() => parse(text), /duplicate_member/i);
    else assert.deepEqual(parse(text), JSON.parse(text));
  }
  const certificate = Buffer.from('{"body":{},"sig":"a","sig":"b"}').toString('base64url');
  assert.throws(() => decodeCertificate(certificate), error => error.reason === 'CERTIFICATE_INVALID');
  const cli = spawnSync('python3', [root + 'verifiers/mutmem-v2/python/kernel_cli.py'], {
    input: '{"operation":"canonical_json","value":{"role":1,"role":2}}', encoding: 'utf8' });
  assert.equal(cli.status, 1); assert.match(JSON.parse(cli.stdout).error, /JSON_DUPLICATE_MEMBER/);
});

test('AUD-018 native JSON admission rejects duplicate and escaped-alias members before dispatch', async t => {
  const app = express(); let dispatched = 0;
  app.use(express.json({ limit: '1mb', verify: (_req, _res, bytes, encoding) => {
    try { jsonProtocol.assertUniqueJsonMembers(new TextDecoder(encoding, { fatal: true }).decode(bytes)); }
    catch (error) { error.status = 400; throw error; }
  } }));
  app.post('/', (req, res) => { dispatched++; res.json({ canonical: jsonProtocol.canonicalJson(req.body) }); });
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ reason: error.code || error.type }));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const url = `http://127.0.0.1:${server.address().port}/`;
  const request = body => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  const invalid = ['{"role":"a","role":"b"}', '{"role":"a","\\u0072ole":"b"}',
    '{"outer":[{"role":1,"role":2}]}', '{"__proto__":1,"__proto__":2}',
    '{"constructor":1,"constructor":2}', '{"😀":1,"\\ud83d\\ude00":2}',
    '{"":1,"":2}'];
  for (const raw of invalid) {
    const before = dispatched, response = await request(raw);
    const body = await response.json();
    assert.equal(response.status, 400, raw);
    assert.equal(body.reason, 'json_duplicate_member');
    assert.equal(dispatched, before, 'ambiguous input must not reach the handler');
  }
  const valid = ['{"left":{"a":1},"right":{"a":2}}', '{"a":[{"a":1},{"a":2}]}',
    '{"s":"a,\\\"b\\\":c { } [ ]","a":2}', '{"é":1,"é":2}',
    '{"z":4.50,"a":1e-7}', '{"a":1,"ab":2}'];
  for (const raw of valid) {
    const response = await request(raw); assert.equal(response.status, 200, raw);
    assert.equal((await response.json()).canonical, jsonProtocol.canonicalJson(JSON.parse(raw)));
  }
  const malformed = await request('{"a":'); assert.equal(malformed.status, 400); await malformed.text();
});
