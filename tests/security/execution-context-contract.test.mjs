import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { createAuthGate } from '../../services/security/auth-gate.js';

function responseHarness() {
  return {
    statusCode: 200,
    payload: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
}

function verifiedTier() {
  return {
    tier: 'T1',
    cert: { agent_id: 'actor-agent' },
    prevChainHash: null,
    validFromIso: '2026-07-11T00:00:00.000Z',
    error: null,
    certString: 'cert',
    sigBytes: Buffer.alloc(64, 1),
    nonce: 'nonce',
    signedTs: 1783728000,
  };
}

function verifiedSystemSelfTier() {
  return {
    ...verifiedTier(),
    tier: 'T1_SYSTEM_SELF',
    cert: { agent_id: 'housekeeper' },
  };
}

function admittedDeps() {
  return {
    reserveVerifiedRequest: async () => ({
      request_receipt_id: 'receipt-test',
      request_hash: Buffer.alloc(32, 2),
      mutation_hash: Buffer.alloc(32, 1),
    }),
    logEvent: async () => ({
      event_id: 'admission-event-test',
      mutation_hash: '3'.repeat(64),
    }),
  };
}

test('auth gate emits one frozen actor/company execution context', async () => {
  const gate = createAuthGate({
    deriveTier: async () => verifiedTier(),
    ...admittedDeps(),
  });
  const req = {
    path: '/tasks',
    headers: {},
    body: { company_id: 'hom' },
    query: {},
  };
  const res = responseHarness();
  let nextCalled = false;
  await gate(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
  assert.equal(req.executionContext.actorAgentId, 'actor-agent');
  assert.equal(req.executionContext.companyId, 'hom');
  assert.equal(req.executionContext.authSource, 'envelope');
  assert.equal(req.executionContext.requestAdmissionEventId, 'admission-event-test');
  assert.equal(req.executionContext.requestAdmissionMutationHash, '3'.repeat(64));
  assert.equal(Object.isFrozen(req.executionContext), true);
});

test('auth gate rejects caller-selected company scope and shared HMAC authority', async () => {
  const gate = createAuthGate({
    deriveTier: async () => verifiedTier(),
    ...admittedDeps(),
  });
  const companyReq = { path: '/tasks', headers: {}, body: { company_id: 'other' }, query: {} };
  const companyRes = responseHarness();
  await gate(companyReq, companyRes, () => {});
  assert.equal(companyRes.statusCode, 403);
  assert.equal(companyRes.payload.error, 'company_scope_mismatch');

  const hmacGate = createAuthGate({
    deriveTier: async () => ({ tier: 'T0', cert: null, error: null }),
    reserveVerifiedRequest: async () => { throw new Error('must_not_run'); },
  });
  const hmacReq = { path: '/tasks', headers: { 'x-internal-token': 'shared-token' }, body: {}, query: {} };
  const hmacRes = responseHarness();
  await hmacGate(hmacReq, hmacRes, () => {});
  assert.equal(hmacRes.statusCode, 401);
  assert.equal(hmacRes.payload.error, 'internal_service_principal_required');
});

test('system-self housekeeper is admitted only to the exact native session routes', async () => {
  const gate = createAuthGate({
    deriveTier: async () => verifiedSystemSelfTier(),
    ...admittedDeps(),
  });

  for (const path of ['/aimos/session/turn', '/aimos/session/finalize']) {
    const req = { path, headers: {}, body: { company_id: 'hom' }, query: {} };
    const res = responseHarness();
    let nextCalled = false;
    await gate(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true, `${path} must reach its native route owner`);
    assert.equal(req.executionContext.identityTier, 'T1_SYSTEM_SELF');
    assert.equal(req.executionContext.actorAgentId, 'housekeeper');
  }

  const deniedReq = {
    path: '/aimos/compaction/save',
    headers: {},
    body: { company_id: 'hom' },
    query: {},
  };
  const deniedRes = responseHarness();
  let deniedNextCalled = false;
  await gate(deniedReq, deniedRes, () => { deniedNextCalled = true; });
  assert.equal(deniedNextCalled, false);
  assert.equal(deniedRes.statusCode, 401);
  assert.equal(deniedRes.payload.error, 'system_self_unauthorized_route');
});

test('execution, MCP, and permission sources retain actor authority and append-only grants', () => {
  const agentExecution = fs.readFileSync(new URL('../../routes/agent-execution.js', import.meta.url), 'utf8');
  const task = fs.readFileSync(new URL('../../routes/task.js', import.meta.url), 'utf8');
  const mcp = fs.readFileSync(new URL('../../routes/aimos-mcp-streamable.js', import.meta.url), 'utf8');
  const permissions = fs.readFileSync(new URL('../../services/core/permissions.js', import.meta.url), 'utf8');
  const migration = fs.readFileSync(new URL('../../migrations/047-append-only-authorization-events.sql', import.meta.url), 'utf8');

  assert.match(agentExecution, /authorizeExecutionTarget\(req, req\.params\.id\)/);
  assert.match(agentExecution, /requiredCapability: 'delegate'/);
  assert.match(task, /actorPermissions\.delegate !== true/);
  assert.match(mcp, /mutation_authority: authContext\.mutationAuthority/);
  assert.doesNotMatch(mcp, /mutation_authority: 'housekeeper'/);
  assert.doesNotMatch(permissions, /process\.env|ON CONFLICT|UPDATE agent_permissions/);
  assert.match(permissions, /INSERT INTO aimos_authorization_events/);
  assert.match(migration, /REVOKE UPDATE, DELETE, TRUNCATE/);
  assert.match(migration, /FOREIGN KEY \(actor_agent_id, actor_valid_from\)/);
});
