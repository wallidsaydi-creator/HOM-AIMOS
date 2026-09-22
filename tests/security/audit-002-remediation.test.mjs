import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import router from '../../routes/aimos-mcp-streamable.js';
import { agentRevocationCache } from '../../services/security/agent-revocation-cache.js';

const ACTOR_A = Object.freeze({
  id: 'audit-002-actor-a',
  epoch: '2026-09-05T00:00:00.000Z',
});
const ACTOR_B = Object.freeze({
  id: 'audit-002-actor-b',
  epoch: '2026-09-05T00:00:01.000Z',
});

function actorHeaders(actor, extra = {}) {
  return {
    'x-audit-actor': actor.id,
    'x-audit-epoch': actor.epoch,
    ...extra,
  };
}

function openSse(base, sessionId, actor) {
  return new Promise((resolve, reject) => {
    const request = http.get(`${base}/mcp?sessionId=${encodeURIComponent(sessionId)}`, {
      headers: actorHeaders(actor, { accept: 'text/event-stream' }),
    });
    request.once('error', reject);
    request.once('response', (response) => {
      const chunks = [];
      response.setEncoding('utf8');
      response.on('data', (chunk) => chunks.push(chunk));
      resolve({ request, response, chunks });
    });
  });
}

async function requestJson(base, method, sessionId, actor, body = null) {
  const response = await fetch(`${base}/mcp?sessionId=${encodeURIComponent(sessionId)}`, {
    method,
    headers: actorHeaders(actor, { 'content-type': 'application/json' }),
    ...(body == null ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, text: await response.text() };
}

async function waitFor(predicate, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('audit_002_wait_timeout');
}

test('AUD-002 binds SSE ownership to actor, epoch and company and makes reconnect generation-safe', async (t) => {
  const revocations = t.mock.method(agentRevocationCache, 'lookup', async () => ({ found: true, revoked: false }));
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    const actorAgentId = String(req.headers['x-audit-actor'] || '');
    const actorValidFromIso = String(req.headers['x-audit-epoch'] || '');
    req.agentId = actorAgentId;
    req.identityValidFromIso = actorValidFromIso;
    req.identityAuthenticatedBy = 'envelope';
    req.identityCert = { valid_until: Math.floor(Date.now() / 1000) + 600 };
    req.executionContext = Object.freeze({
      actorAgentId,
      actorValidFromIso,
      companyId: 'hom',
      identityTier: 'T1',
      authSource: 'envelope',
    });
    next();
  });
  app.use('/mcp', router);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  });

  const foreignSession = `audit-002-foreign-${Date.now()}`;
  const ownerStream = await openSse(base, foreignSession, ACTOR_A);
  t.after(() => ownerStream.request.destroy());
  assert.equal(ownerStream.response.statusCode, 200);

  const foreignGet = await openSse(base, foreignSession, ACTOR_B);
  foreignGet.request.destroy();
  assert.equal(foreignGet.response.statusCode, 403);

  const foreignPost = await requestJson(base, 'POST', foreignSession, ACTOR_B, {
    jsonrpc: '2.0', id: 1, method: 'ping', params: {},
  });
  assert.equal(foreignPost.status, 403);

  const foreignDelete = await requestJson(base, 'DELETE', foreignSession, ACTOR_B);
  assert.equal(foreignDelete.status, 403);
  const changedEpoch = await openSse(base, foreignSession, { ...ACTOR_A, epoch: ACTOR_B.epoch });
  changedEpoch.request.destroy();
  assert.equal(changedEpoch.response.statusCode, 403);

  const generationSession = `audit-002-generation-${Date.now()}`;
  const oldStream = await openSse(base, generationSession, ACTOR_A);
  const currentStream = await openSse(base, generationSession, ACTOR_A);
  t.after(() => oldStream.request.destroy());
  t.after(() => currentStream.request.destroy());
  assert.equal(currentStream.response.statusCode, 200);

  oldStream.request.destroy();
  const response = await requestJson(base, 'POST', generationSession, ACTOR_A, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'audit_002_unknown_tool', arguments: {} },
  });
  assert.equal(response.status, 200);
  await waitFor(() => currentStream.chunks.join('').includes('event: response'));
  assert.match(currentStream.chunks.join(''), /audit_002_unknown_tool/);

  const ownerDelete = await requestJson(base, 'DELETE', generationSession, ACTOR_A);
  assert.equal(ownerDelete.status, 204);

  const pendingSession = `audit-002-pending-${Date.now()}`;
  const pendingOriginal = await openSse(base, pendingSession, ACTOR_A);
  t.after(() => pendingOriginal.request.destroy());
  let releaseDelivery;
  let deliveryReached;
  const deliveryEntered = new Promise((resolve) => { deliveryReached = resolve; });
  revocations.mock.mockImplementationOnce(async () => {
    deliveryReached();
    await new Promise((resolve) => { releaseDelivery = resolve; });
    return { found: true, revoked: false };
  });
  const pending = requestJson(base, 'POST', pendingSession, ACTOR_A, {
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'aud002_pending_response', arguments: {} },
  });
  await deliveryEntered;
  const attacker = await openSse(base, pendingSession, ACTOR_B);
  t.after(() => attacker.request.destroy());
  assert.equal(attacker.response.statusCode, 403);
  const replacement = await openSse(base, pendingSession, ACTOR_A);
  t.after(() => replacement.request.destroy());
  pendingOriginal.request.destroy();
  releaseDelivery();
  assert.equal((await pending).status, 200);
  await waitFor(() => replacement.chunks.join('').includes('aud002_pending_response'));
  assert.equal(attacker.chunks.join('').includes('aud002_pending_response'), false);

  revocations.mock.mockImplementationOnce(async () => ({ found: true, revoked: true }));
  const revoked = await requestJson(base, 'POST', pendingSession, ACTOR_A, {
    jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'aud002_revoked_response', arguments: {} },
  });
  assert.equal(revoked.status, 403);
  assert.equal(replacement.chunks.join('').includes('aud002_revoked_response'), false);
  revocations.mock.mockImplementationOnce(async () => ({ found: true, revoked: true }));
  const revokedBatch = await requestJson(base, 'POST', pendingSession, ACTOR_A, [
    { jsonrpc: '2.0', id: 5, method: 'ping' },
    { jsonrpc: '2.0', id: 6, method: 'ping' },
  ]);
  assert.equal(revokedBatch.status, 403);
  assert.equal((await requestJson(base, 'DELETE', pendingSession, ACTOR_A)).status, 204);
});
