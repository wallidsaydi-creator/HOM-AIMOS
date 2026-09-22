// Explicit live network qualification. No metadata endpoint, foreign private
// host, credential forwarding, new identity, or persistent peer is exercised.
import assert from 'node:assert/strict';
import http from 'node:http';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fetchWithTimeout, publicHttpLookup } from '../../services/orchestration/http.js';
import { pool, agentPool } from '../../db/connection.js';
import { materialEffectOwner } from '../../services/security/material-effect-owner.js';
import { readVerifiedEventById } from '../../services/observe/event-ledger.js';

if (!process.argv.includes('--live-fire')) throw new Error('owned_live_fire_required');
const database = process.argv[process.argv.indexOf('--aimos-db') + 1];
assert(/^aimos_test_security_audr4_[0-9]+_[a-f0-9]{6}$/.test(database));
const evidence = { database, real_public_MCP: false, real_public_redirect: false,
  real_OS_DNS: false, production_database_write: false, secrets_sent: false };
let forbiddenSockets = 0;
const forbiddenPeer = http.createServer((_req, res) => res.end('forbidden'));
forbiddenPeer.on('connection', () => forbiddenSockets++);
let started = false;
try {
  assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name, database);
  await new Promise(resolve => forbiddenPeer.listen(0, '127.0.0.1', resolve)); started = true;
  const lookup = promisify(publicHttpLookup);
  await assert.rejects(lookup('localhost', { all: true }), /http_destination_forbidden/);
  const publicAddresses = await lookup('example.com', { all: true });
  assert.equal(publicAddresses.length, 1, 'socket lookup must hand off one approved address');
  evidence.real_OS_DNS = true;
  evidence.dial_address = publicAddresses[0];
  const target = `http://127.0.0.1:${forbiddenPeer.address().port}/`;
  const redirect = `https://httpbin.org/redirect-to?url=${encodeURIComponent(target)}`;
  await assert.rejects(fetchWithTimeout(redirect, { destinationPolicy: 'public', retry: false }, 10000), /http_destination_redirect_forbidden/);
  assert.equal(forbiddenSockets, 0); evidence.real_public_redirect = true;

  const dnsEffect = await materialEffectOwner.begin({ kind: 'external', operation: 'r4_controlled_dns_qualification',
    targetIdentifier: 'owned_child_DNS_boundary', inputProjection: {
      bridge: 'operator_approved_child_only_dns_input', native_policy_unchanged: true,
      cases: ['mixed_public_first', 'mixed_private_first', 'mixed_ipv6', 'changed_before_dial', 'pinned_after_answer', 'retry_changed'],
    } });
  try {
    const { stdout } = await promisify(execFile)(process.execPath,
      [fileURLToPath(new URL('./audit-004-dns-qualification.mjs', import.meta.url)), '--live-dns-qualification'],
      { timeout: 120000, killSignal: 'SIGTERM', maxBuffer: 1024 * 1024 });
    evidence.controlled_dns = JSON.parse(stdout);
    assert.equal(evidence.controlled_dns.cases.length, 6);
    await materialEffectOwner.finish({ action: dnsEffect, disposition: 'SUCCEEDED',
      resultProjection: evidence.controlled_dns, resultClass: 'unchanged_native_dns_boundary_qualified' });
  } catch (error) {
    await materialEffectOwner.finish({ action: dnsEffect, disposition: 'INDETERMINATE',
      resultProjection: { error: error.message }, resultClass: 'controlled_dns_qualification_not_proven' });
    throw error;
  }
  const dnsTerminals = (await pool.query(`SELECT id FROM aimos_events WHERE operation='material_effect_terminal'
    AND metadata->>'effect_operation'='r4_controlled_dns_qualification'`)).rows;
  assert.equal(dnsTerminals.length, 1);
  assert.equal((await readVerifiedEventById(dnsTerminals[0].id, 'hom')).metadata.disposition, 'SUCCEEDED');
  evidence.signed_dns_terminal = dnsTerminals[0].id;

  const endpoint = 'https://mcp.context7.com/mcp';
  const payload = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-03-26', capabilities: {},
    clientInfo: { name: 'HOM-AIMOS-R4-read-only-qualification', version: '1.0.4' },
  } };
  const effect = await materialEffectOwner.begin({ kind: 'external', operation: 'r4_public_mcp_qualification',
    targetIdentifier: endpoint, inputProjection: payload });
  let response;
  try {
    response = await fetchWithTimeout(endpoint, { method: 'POST', destinationPolicy: 'public', retry: false,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify(payload) }, 10000);
    const text = await response.text(); assert.equal(response.status, 200);
    const event = text.split(/\r?\n/).find(line => line.startsWith('data:'));
    const result = JSON.parse(event ? event.slice(5) : text);
    assert.equal(result.id, 1); assert.equal(result.jsonrpc, '2.0');
    assert.equal(result.result.protocolVersion, '2025-03-26');
    assert(result.result.capabilities.tools);
    await materialEffectOwner.finish({ action: effect, disposition: 'SUCCEEDED',
      resultProjection: result, resultClass: 'public_mcp_initialized' });
    evidence.real_public_MCP = true;
    evidence.public_MCP_server = result.result.serverInfo.name;
  } catch (error) {
    await materialEffectOwner.finish({ action: effect, disposition: 'INDETERMINATE',
      resultProjection: { error: error.message }, resultClass: 'public_mcp_completion_not_proven' });
    throw error;
  } finally { if (response?.body && !response.bodyUsed) await response.body.cancel().catch(() => {}); }
  const rows = (await pool.query(`SELECT id FROM aimos_events WHERE operation='material_effect_terminal'
    AND metadata->>'effect_operation'='r4_public_mcp_qualification'`)).rows;
  assert.equal(rows.length, 1);
  assert.equal((await readVerifiedEventById(rows[0].id, 'hom')).metadata.disposition, 'SUCCEEDED');
  evidence.signed_public_exchange_terminal = rows[0].id;
  evidence.forbidden_sockets = forbiddenSockets;
} finally {
  if (started) { forbiddenPeer.closeAllConnections(); await new Promise(resolve => forbiddenPeer.close(resolve)); }
  await Promise.allSettled([pool.end(), agentPool.end()]);
}
evidence.peer_stopped = true;
console.log(JSON.stringify(evidence, null, 2));
