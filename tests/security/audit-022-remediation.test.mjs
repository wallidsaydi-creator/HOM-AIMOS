import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import http from 'node:http';
import express from 'express';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const require = createRequire(import.meta.url);
const expressRequire = createRequire(require.resolve('express'));
const qs = expressRequire('qs');

test('GHSA-x5fp-wj9c-mxmx: bracket/comma arrays obey their bound in installed qs', () => {
  for (const key of ['a', 'a[]']) {
    assert.throws(() => qs.parse(`${key}=1,2,3,4`, {
      comma: true, arrayLimit: 3, throwOnLimitExceeded: true,
    }), RangeError);
  }
});

test('GHSA-4mjr-xmp4-gh2g: hostile constructor properties cannot crash parse/stringify', () => {
  for (const options of [{ plainObjects: true }, { allowPrototypes: true }]) {
    const parsed = qs.parse('x[constructor][isBuffer]=not-a-function', options);
    assert.doesNotThrow(() => qs.stringify(parsed));
  }
});

test('installed Express preserves native simple queries, bounded JSON and canonical body bytes', async t => {
  const app = express();
  assert.equal(app.get('query parser'), 'simple');
  app.use(express.json({ limit: '1mb' }));
  app.all('/parse', (req, res) => res.json({
    query: req.query, body: req.body ?? null, canonical: canonicalJson(req.body ?? null),
  }));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ type: error.type }));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const url = `http://127.0.0.1:${server.address().port}/parse`;
  const response = await fetch(url + '?a[]=1,2,3,4&x[constructor][isBuffer]=bad', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: ' { "z": 1, "a": {"content":"native session", "n": 2} } ',
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.query['a[]'], '1,2,3,4');
  assert.equal(payload.canonical, canonicalJson({ a: { content: 'native session', n: 2 }, z: 1 }));
  const malformed = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  assert.equal(malformed.status, 400); await malformed.text();
  const oversized = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ value: 'a'.repeat(1024 * 1024) }) });
  assert.equal(oversized.status, 413); await oversized.text();
  const form = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'a[]=1,2,3,4' });
  assert.equal((await form.json()).body, null, 'URL-encoded body parsing is not enabled');
});
