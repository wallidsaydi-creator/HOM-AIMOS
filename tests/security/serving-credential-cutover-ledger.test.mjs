import assert from 'node:assert/strict';
import test from 'node:test';

import { appendServingCredentialRoots } from '../../scripts/db/ledger-serving-credentials.mjs';

function fixture() {
  const services = [
    ['aimos_service_reader_db_password', 'genesis_service_reader_database_role'],
    ['aimos_identity_writer_db_password', 'genesis_identity_writer_database_role'],
  ];
  const credentials = new Map([
    ['agent_runtime_db_password', { slot: 'com.aimos.credentials.agent_runtime_db_password',
      value: 'runtime-secret', hash: 'a'.repeat(64) }],
    ...services.map(([service], index) => [service,
      { slot: `com.aimos.credentials.${service}`,
        value: `test-secret-${index}`, hash: String(index + 1).repeat(64) }]),
  ]);
  const rows = new Map([[credentials.get('agent_runtime_db_password').slot,
    [{ body_json: { credential_hash: 'a'.repeat(64) } }]]]);
  const commits = [];
  const ledger = {
    getSlotChain: async (slot) => rows.get(slot) || [],
    commitCredentialLifecycle: async (request) => {
      commits.push(request);
      assert.equal(request.eventType, 'STORE');
      assert.equal(request.slotId, `com.aimos.credentials.${request.serviceName}`);
      assert.equal(request.body.genesis_root, true);
      assert.equal(request.body.event_type, 'STORE');
      assert.equal(request.body.reason,
        services.find(([service]) => service === request.serviceName)?.[1]);
      assert.equal(request.body.credential_hash,
        credentials.get(request.serviceName).hash);
      assert.equal(request.body.operator, 'housekeeper');
      assert.equal(request.body.signer_agent_id, 'housekeeper');
      rows.set(request.slotId, [{ body_json: {
        credential_hash: request.body.credential_hash,
      } }]);
      return { ok: true, mutationHash: Buffer.alloc(32, commits.length) };
    },
  };
  const signer = async (body) => ({ body, agentId: 'housekeeper',
    validFromIso: '2026-01-01T00:00:00.000Z', certString: 'fixture-cert',
    signedTs: 1, nonce: Buffer.alloc(16), sigBytes: Buffer.alloc(64),
    identityTier: 'T1_SYSTEM_SELF' });
  const args = { runtimeService: 'agent_runtime_db_password', services,
    credentialReader: (service) => credentials.get(service), ledger, signer };
  return { args, rows, commits, credentials };
}

test('new serving credentials receive exact signed first STORE roots once', async () => {
  const { args, commits } = fixture();
  const first = await appendServingCredentialRoots(args);
  assert.equal(first.result, 'serving_credentials_signed');
  assert.deepEqual(first.services.map((row) => row.disposition),
    ['first_store_signed', 'first_store_signed']);
  assert.equal(commits.length, 2);
  const second = await appendServingCredentialRoots(args);
  assert.deepEqual(second.services.map((row) => row.disposition),
    ['existing_verified', 'existing_verified']);
  assert.equal(commits.length, 2, 'rerun must not append duplicate roots');
});

test('mismatched retained runtime or serving hash fails before appending', async () => {
  const a = fixture();
  a.rows.set(a.credentials.get('agent_runtime_db_password').slot,
    [{ body_json: { credential_hash: 'f'.repeat(64) } }]);
  await assert.rejects(appendServingCredentialRoots(a.args),
    /runtime_credential_lifecycle_mismatch/);
  assert.equal(a.commits.length, 0);

  const b = fixture();
  b.rows.set(b.credentials.get('aimos_service_reader_db_password').slot,
    [{ body_json: { credential_hash: 'f'.repeat(64) } }]);
  await assert.rejects(appendServingCredentialRoots(b.args),
    /serving_credential_lifecycle_mismatch:aimos_service_reader_db_password/);
  assert.equal(b.commits.length, 0);
});
