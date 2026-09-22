import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import * as outbound from '../../services/orchestration/http.js';

test('public destination policy denies a real loopback socket before any HTTP request', async t => {
  let requests = 0;
  const peer = http.createServer((_req, res) => { requests++; res.end('{}'); });
  await new Promise(resolve => peer.listen(0, '127.0.0.1', resolve));
  t.after(async () => { peer.closeAllConnections(); await new Promise(resolve => peer.close(resolve)); });
  await assert.rejects(outbound.fetchWithTimeout(`http://127.0.0.1:${peer.address().port}`, {
    destinationPolicy: 'public', retry: false,
  }, 500), /http_destination_forbidden/);
  assert.equal(requests, 0);
});

test('binary classification rejects special/mapped/scoped addresses without contacting them', () => {
  assert.equal(typeof outbound.assertPublicHttpUrl, 'function');
  for (const host of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '192.0.2.1', '[::ffff:127.0.0.1]', '[::ffff:7f00:1]',
    '[::ffff:a00:1]', '[::ffff:a9fe:a9fe]', '[::]', '[::1]', '[fe80::1]',
    '[fe90::1]', '[febf::1]', '[fc00::1]', '[fd00::1]', '[fec0::1]', '[ff02::1]',
    '[64:ff9b::a00:1]', '[2001:db8::1]', '[2002:7f00:1::1]']) {
    assert.throws(() => outbound.assertPublicHttpUrl(`http://${host}/`), /http_destination_forbidden/, host);
  }
  for (const url of ['file:///etc/passwd', 'http://user:secret@example.com', 'http://localhost.',
    'http://x.localhost', 'http://[fe80::1%25en0]/']) {
    assert.throws(() => outbound.assertPublicHttpUrl(url), /http_destination/);
  }
  for (const url of ['https://example.com', 'https://1.1.1.1', 'https://[2606:4700:4700::1111]']) {
    assert.equal(outbound.assertPublicHttpUrl(url).href, new URL(url).href);
  }
});

test('public requests cannot override their transport, Host, or redirect policy', async () => {
  for (const options of [{ dispatcher: {} }, { headers: { Host: 'localhost' } }, { redirect: 'follow' }]) {
    await assert.rejects(outbound.fetchWithTimeout('https://example.com', {
      destinationPolicy: 'public', ...options,
    }), /http_destination_policy_override/);
  }
});
