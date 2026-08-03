import test from 'node:test';
import assert from 'node:assert/strict';

import { generateKeypair, signPayload } from '../../services/security/agent-identity.js';
import { createMemoryProvenanceLedger } from '../../services/security/memory-provenance.js';

function createCapturingClient() {
  const inserts = [];
  const queries = [];
  return {
    inserts,
    queries,
    async query(sql, params = []) {
      queries.push({ sql, params });
      if (sql.includes('information_schema.columns')) return { rows: [{ '?column?': 1 }] };
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [{}] };
      if (sql.includes('SELECT mutation_hash')) return { rows: [] };
      if (sql.includes('SELECT 1 FROM aimos_memory_provenance')) return { rows: [] };
      if (sql.includes('INSERT INTO aimos_memory_provenance')) {
        inserts.push({ sql, params });
        return { rowCount: 1, rows: [] };
      }
      throw new Error(`unexpected SQL in provenance tier test: ${sql}`);
    }
  };
}

function signedFixture(identityTier) {
  const { privkey } = generateKeypair();
  const signedTs = 1_783_715_000;
  const nonce = `tier-test-${identityTier}`;
  const body = {
    event_type: 'SAVE',
    memory_id: '11111111-1111-4111-8111-111111111111',
    key: 'tier:test',
    value: 'native provenance tier contract',
    ts_signed: signedTs
  };
  return {
    memoryId: body.memory_id,
    body,
    agentId: 'housekeeper',
    validFromIso: '2026-07-10T20:00:00.000Z',
    certString: 'self-signed-housekeeper-cert',
    signedTs,
    nonce,
    sigBytes: Buffer.from(signPayload(privkey, body, nonce, signedTs), 'base64url'),
    identityTier,
    eventType: 'SAVE',
    bodyJson: body,
    liveContentHash: Buffer.alloc(32, 7)
  };
}

test('native provenance ledger stores T1_SYSTEM_SELF as canonical T1', async () => {
  const client = createCapturingClient();
  const ledger = createMemoryProvenanceLedger({ queryFn: client.query.bind(client) });
  const result = await ledger.commitProvenance({ ...signedFixture('T1_SYSTEM_SELF'), client });

  assert.equal(result.ok, true);
  assert.equal(result.isGenesis, true);
  assert.equal(client.inserts.length, 1);
  // Migration 040 column shape: identity_tier is parameter 11 (index 10).
  assert.equal(client.inserts[0].params[10], 'T1');
  assert.equal(result.contentHash.length, 32);
  assert.equal(result.mutationHash.length, 32);
});

test('native provenance ledger preserves ordinary signer tiers', async () => {
  const client = createCapturingClient();
  const ledger = createMemoryProvenanceLedger({ queryFn: client.query.bind(client) });
  const result = await ledger.commitProvenance({ ...signedFixture('T2'), client });

  assert.equal(result.ok, true);
  assert.equal(client.inserts.length, 1);
  assert.equal(client.inserts[0].params[10], 'T2');
});

test('native provenance ledger retains the request signature context', async () => {
  const client = createCapturingClient();
  const ledger = createMemoryProvenanceLedger({ queryFn: client.query.bind(client) });
  const fixture = signedFixture('T2');
  const result = await ledger.commitProvenance({
    ...fixture,
    requestSigForm: 4,
    signedMethod: 'POST',
    signedPath: '/aimos/save',
    signedClaims: {
      prev_chain_hash: Buffer.alloc(32, 5).toString('base64url'),
      device_fp: null,
    },
    client,
  });

  assert.equal(result.ok, true);
  assert.match(client.inserts[0].sql, /request_sig_form, signed_method, signed_path, signed_claims/);
  assert.equal(client.inserts[0].params.at(-4), 4);
  assert.equal(client.inserts[0].params.at(-3), 'POST');
  assert.equal(client.inserts[0].params.at(-2), '/aimos/save');
  assert.equal(JSON.parse(client.inserts[0].params.at(-1)).device_fp, null);
});

test('native provenance ledger still rejects unknown signer tiers before SQL', async () => {
  const client = createCapturingClient();
  const ledger = createMemoryProvenanceLedger({ queryFn: client.query.bind(client) });
  const result = await ledger.commitProvenance({ ...signedFixture('SYSTEM'), client });

  assert.deepEqual(result, { ok: false, reason: 'malformed_input' });
  assert.equal(client.queries.length, 0);
  assert.equal(client.inserts.length, 0);
});
