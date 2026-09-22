// Operator-approved test-only DNS input bridge. No production importers.
// Real UDP DNS packets feed the unchanged production lookup and dispatcher.
// This does NOT qualify host resolver configuration or replace its OS checks.
import assert from 'node:assert/strict';
import dns from 'node:dns';
import dgram from 'node:dgram';
import net from 'node:net';
import dc from 'node:diagnostics_channel';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fetchWithTimeout, publicHttpLookup, isPublicHttpAddress } from '../../services/orchestration/http.js';

assert(process.argv.includes('--live-dns-qualification'), 'explicit_dns_qualification_required');
const self = fileURLToPath(import.meta.url);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const modes = ['mixed_public_first', 'mixed_private_first', 'mixed_ipv6',
  'changed_before_dial', 'pinned_after_answer', 'retry_changed'];
const selected = process.argv.find(value => value.startsWith('--case='))?.slice(7);

if (!selected) {
  const addresses = await dns.promises.lookup('example.com', { all: true, family: 4 });
  const publicIp = addresses.find(row => isPublicHttpAddress(row.address))?.address;
  assert(publicIp, 'public_positive_endpoint_required');
  const cases = [];
  let activeChild = null, stopping = false;
  const stop = () => { stopping = true; activeChild?.kill('SIGKILL'); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  try {
    for (const mode of modes) {
      assert(!stopping, 'dns_qualification_cancelled');
      const pending = promisify(execFile)(process.execPath,
        [self, '--live-dns-qualification', `--case=${mode}`, `--public-ip=${publicIp}`],
        { timeout: 20000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024 });
      activeChild = pending.child;
      const { stdout } = await pending;
      activeChild = null; cases.push(JSON.parse(stdout));
    }
    assert(!stopping, 'dns_qualification_cancelled');
  } finally {
    activeChild?.kill('SIGKILL');
    process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
  }
  console.log(JSON.stringify({ at: new Date().toISOString(), node: process.version, executable: process.execPath,
    mechanism: 'child_local_UDP_DNS_bridge',
    bridge_scope: 'dns.lookup input only, restored before each child exit',
    production_source_sha256: sha(readFileSync(new URL('../../services/orchestration/http.js', import.meta.url))),
    qualification_source_sha256: sha(readFileSync(self)), host_dns_changed: false,
    credentials_sent: false, canonical_database_touched: false, cases }, null, 2));
} else {
  assert(modes.includes(selected));
  const publicIp = process.argv.find(value => value.startsWith('--public-ip='))?.slice(12);
  assert(net.isIPv4(publicIp) && isPublicHttpAddress(publicIp));
  const host = selected === 'pinned_after_answer' ? 'example.com' : `r4-${selected.replaceAll('_', '-')}.invalid`;
  const originalLookup = dns.lookup;
  const originalServers = dns.getServers();
  const resolver = new dns.promises.Resolver({ timeout: 1000, tries: 1 });
  const udp = dgram.createSocket('udp4');
  const forbiddenPeer = net.createServer(socket => socket.end());
  let udpStarted = false, tcpStarted = false, phase = 'public', lookups = 0;
  let forbiddenPeerConnections = 0, expectedControl = false, detectorControls = 0;
  const sockets = new Set(), attempts = [], connected = [], connectErrors = [], packets = [], decoded = [];
  const onSocket = ({ socket }) => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('connectionAttempt', (address, port, family) => {
      if (expectedControl) { if (address === '127.0.0.1') detectorControls++; return; }
      attempts.push({ address, port, family });
    });
  };
  const onConnected = ({ socket }) => connected.push({ address: socket.remoteAddress,
    port: socket.remotePort, tls_authorized: socket.authorized, servername: socket.servername });
  const onConnectError = ({ error }) => connectErrors.push(error.code || error.name);
  const onPeerSocket = socket => {
    if (!expectedControl) forbiddenPeerConnections++;
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  };
  forbiddenPeer.on('connection', onPeerSocket);
  udp.on('message', (query, peer) => {
    // Only the native resolver in this child sends bounded A/AAAA questions.
    let offset = 12; const labels = [];
    while (query[offset]) {
      const length = query[offset++]; assert(length <= 63);
      labels.push(query.subarray(offset, offset + length).toString('ascii')); offset += length;
    }
    const type = query.readUInt16BE(offset + 1), end = offset + 5;
    assert.equal(labels.join('.'), host); assert([1, 28].includes(type));
    let a = phase === 'private' ? ['127.0.0.1'] : [publicIp], aaaa = [];
    if (selected === 'mixed_public_first') a = [publicIp, '127.0.0.1'];
    if (selected === 'mixed_private_first') a = ['127.0.0.1', publicIp];
    if (selected === 'mixed_ipv6') aaaa = ['::1'];
    const answers = type === 1 ? a : aaaa;
    const header = Buffer.from(query.subarray(0, 12));
    header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answers.length, 6); header.writeUInt32BE(0, 8);
    const records = answers.map(address => {
      const bytes = type === 1 ? Buffer.from(address.split('.').map(Number))
        : Buffer.concat([Buffer.alloc(15), Buffer.from([1])]);
      const record = Buffer.alloc(12); record.writeUInt16BE(0xc00c, 0);
      record.writeUInt16BE(type, 2); record.writeUInt16BE(1, 4);
      record.writeUInt16BE(bytes.length, 10);
      return Buffer.concat([record, bytes]);
    });
    const response = Buffer.concat([header, query.subarray(12, end), ...records]);
    packets.push({ phase, type, answers, query_sha256: sha(query), response_sha256: sha(response) });
    udp.send(response, peer.port, peer.address);
  });
  let evidence;
  try {
    await new Promise((resolve, reject) => { udp.once('error', reject); udp.bind(0, '127.0.0.1', resolve); });
    udpStarted = true;
    await new Promise((resolve, reject) => { forbiddenPeer.once('error', reject); forbiddenPeer.listen(0, '127.0.0.1', resolve); });
    tcpStarted = true;
    resolver.setServers([`127.0.0.1:${udp.address().port}`]);
    dc.subscribe('net.client.socket', onSocket);
    dc.subscribe('undici:client:connected', onConnected);
    dc.subscribe('undici:client:connectError', onConnectError);
    // Positive control: the observer and owned sink detect a real local dial.
    expectedControl = true;
    await new Promise((resolve, reject) => {
      const socket = net.connect(forbiddenPeer.address().port, '127.0.0.1');
      socket.once('error', reject); socket.once('close', resolve); socket.resume();
    });
    expectedControl = false; assert.equal(detectorControls, 1);
    dns.lookup = (hostname, options, callback) => {
      if (hostname !== host) return originalLookup(hostname, options, callback);
      assert.equal(options.all, true); assert.equal(options.verbatim, true); lookups++;
      const resolveType = async family => {
        try { return (await (family === 4 ? resolver.resolve4(host) : resolver.resolve6(host)))
          .map(address => ({ address, family })); }
        catch (error) { if (error.code === 'ENODATA') return []; throw error; }
      };
      Promise.all([resolveType(4), resolveType(6)]).then(groups => {
        const answers = groups.flat(); decoded.push(answers);
        if (selected.startsWith('changed') || selected === 'pinned_after_answer' || selected === 'retry_changed') phase = 'private';
        callback(null, answers);
      }, callback);
    };
    if (selected === 'changed_before_dial') {
      const approved = await promisify(publicHttpLookup)(host, { all: true });
      assert.deepEqual(approved, [{ address: publicIp, family: 4 }]);
    }
    const tlsCase = ['pinned_after_answer', 'retry_changed'].includes(selected);
    const url = tlsCase ? `https://${host}/` : `http://${host}:${forbiddenPeer.address().port}/`;
    let response, failure;
    try {
      response = await fetchWithTimeout(url, { destinationPolicy: 'public', retry: selected === 'retry_changed' }, 10000);
      const text = await response.text();
      assert.equal(selected, 'pinned_after_answer', 'forbidden_exchange_completed');
      assert.equal(response.status, 200); assert(text.includes('Example Domain'));
    } catch (error) { failure = error; }
    finally { if (response?.body && !response.bodyUsed) await response.body.cancel(); }
    if (selected === 'pinned_after_answer') {
      assert.ifError(failure); assert.equal(lookups, 1);
      assert.deepEqual(await resolver.resolve4(host), ['127.0.0.1']);
      assert.equal(connected.length, 1);
      assert.deepEqual(connected[0], { address: publicIp, port: 443, tls_authorized: true, servername: host });
      assert.equal(attempts.length, 1); assert.equal(attempts[0].address, publicIp);
    } else {
      assert(failure, 'native_destination_denial_required');
      assert.equal(failure.cause?.message || failure.message, 'http_destination_forbidden');
      if (selected === 'retry_changed') {
        assert.equal(lookups, 2);
        // The public peer may reject unknown SNI before serving a certificate.
        // Observe the actual public dial/failure, not one vendor's TLS error code.
        assert(connectErrors.length > 0, 'first_public_connection_failure_required');
        assert.equal(connected.length, 0);
        assert.equal(attempts.length, 1); assert.equal(attempts[0].address, publicIp);
      } else {
        assert.equal(lookups, selected === 'changed_before_dial' ? 2 : 1);
        assert.equal(attempts.length, 0);
      }
    }
    const publicAnswer = { address: publicIp, family: 4 }, privateAnswer = { address: '127.0.0.1', family: 4 };
    if (selected === 'mixed_public_first') assert.deepEqual(decoded, [[publicAnswer, privateAnswer]]);
    else if (selected === 'mixed_private_first') assert.deepEqual(decoded, [[privateAnswer, publicAnswer]]);
    else if (selected === 'mixed_ipv6') assert.deepEqual(decoded, [[publicAnswer, { address: '::1', family: 6 }]]);
    else assert.deepEqual(decoded, selected === 'pinned_after_answer' ? [[publicAnswer]] : [[publicAnswer], [privateAnswer]]);
    assert.equal(attempts.filter(attempt => !isPublicHttpAddress(attempt.address)).length, 0);
    assert.equal(forbiddenPeerConnections, 0);
    evidence = { case: selected, lookups, decoded_answers: decoded, dns_packets: packets,
      connection_attempts: attempts, tls_connections: connected, connection_errors: connectErrors,
      forbidden_connection_attempts: 0, forbidden_peer_connections: 0, detector_positive_controls: detectorControls };
  } finally {
    dns.lookup = originalLookup; resolver.cancel();
    dc.unsubscribe('net.client.socket', onSocket); dc.unsubscribe('undici:client:connected', onConnected);
    dc.unsubscribe('undici:client:connectError', onConnectError);
    await Promise.all([...sockets].map(socket => new Promise(resolve => {
      if (socket.closed) { sockets.delete(socket); resolve(); return; }
      socket.once('close', resolve); socket.destroy();
    })));
    if (tcpStarted) await new Promise(resolve => forbiddenPeer.close(resolve));
    if (udpStarted) await new Promise(resolve => udp.close(resolve));
  }
  assert.equal(dns.lookup, originalLookup);
  assert.deepEqual(dns.getServers(), originalServers);
  assert.equal(sockets.size, 0);
  console.log(JSON.stringify({ ...evidence, dns_bridge_restored: true, global_resolver_unchanged: true, peers_closed: true }));
}
