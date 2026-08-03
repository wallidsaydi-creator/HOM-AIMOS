import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createSaveEnvelopeOrchestrator } from '../../services/security/save-envelope.js';
import { genesisHashFor } from '../../services/security/identity-chain.js';

function makeClient({ updateRowCount = 1 } = {}) {
  const statements = [];
  return {
    statements,
    async query(sql) {
      statements.push(String(sql).trim());
      if (String(sql).includes('SELECT 1') && String(sql).includes('FROM agent_identity')) return { rows: [{ '?column?': 1 }] };
      if (String(sql).includes('FROM aimos_agent_revocation_events')) return { rows: [] };
      if (String(sql).includes('UPDATE agent_identity')) return { rowCount: updateRowCount, rows: [] };
      if (String(sql).includes('SELECT chain_head')) return { rows: [{ chain_head: null }] };
      return { rowCount: 1, rows: [] };
    }
  };
}

function args(client) {
  const agentId = 'test-agent';
  const validFromIso = '2026-07-11T00:00:00.000Z';
  return {
    memoryId: '11111111-1111-4111-8111-111111111111',
    body: { key: 'test', value: 'atomic envelope contract' },
    agentId,
    validFromIso,
    claimedPrev: genesisHashFor(agentId, validFromIso),
    certString: 'test-cert',
    signedTs: 1783728000,
    nonce: randomBytes(16).toString('base64url'),
    sigBytes: randomBytes(64),
    identityTier: 'T2',
    requestSigForm: 4,
    signedMethod: 'POST',
    signedPath: '/aimos/save',
    signedClaims: {
      prev_chain_hash: genesisHashFor(agentId, validFromIso).toString('base64url'),
      device_fp: null,
    },
    client
  };
}

test('injected envelope client participates without BEGIN, COMMIT, or release', async () => {
  const client = makeClient();
  const orchestrator = createSaveEnvelopeOrchestrator({
    pool: { connect: async () => { throw new Error('pool must not be used'); } }
  });
  const result = await orchestrator.commitEnvelope(args(client));
  assert.equal(result.ok, true);
  assert(client.statements.some((sql) => sql.includes('UPDATE agent_identity')));
  assert(client.statements.some((sql) => sql.includes('INSERT INTO aimos_save_envelope')));
  assert(!client.statements.includes('BEGIN'));
  assert(!client.statements.includes('COMMIT'));
  assert(!client.statements.includes('ROLLBACK'));
});

test('injected envelope fork returns failure to transaction owner without local rollback', async () => {
  const client = makeClient({ updateRowCount: 0 });
  const orchestrator = createSaveEnvelopeOrchestrator({
    pool: { connect: async () => { throw new Error('pool must not be used'); } }
  });
  const result = await orchestrator.commitEnvelope(args(client));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'fork_detected');
  assert(!client.statements.includes('ROLLBACK'));
  assert(!client.statements.some((sql) => sql.includes('INSERT INTO aimos_save_envelope')));
});

test('injected envelope replay preserves replay_detected without querying an aborted transaction', async () => {
  const statements = [];
  const client = {
    async query(sql) {
      const text = String(sql).trim();
      statements.push(text);
      if (text.includes('SELECT 1') && text.includes('FROM agent_identity')) return { rows: [{ '?column?': 1 }] };
      if (text.includes('FROM aimos_agent_revocation_events')) return { rows: [] };
      if (text.includes('UPDATE agent_identity')) return { rowCount: 1, rows: [] };
      if (text.includes('INSERT INTO aimos_save_envelope')) {
        const error = new Error('duplicate nonce');
        error.code = '23505';
        error.constraint = 'aimos_save_envelope_nonce_unique';
        throw error;
      }
      if (text.includes('SELECT chain_head')) {
        throw new Error('aborted transaction must not be queried');
      }
      return { rowCount: 1, rows: [] };
    }
  };
  const orchestrator = createSaveEnvelopeOrchestrator({
    pool: { connect: async () => { throw new Error('pool must not be used'); } }
  });
  const result = await orchestrator.commitEnvelope(args(client));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'replay_detected');
  assert.equal(result.currentHead, null);
  assert(!statements.some((sql) => sql.includes('SELECT chain_head')));
  assert(!statements.includes('ROLLBACK'));
});
