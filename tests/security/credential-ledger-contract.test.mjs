import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import {
  computeMutationHash,
  createCredentialLedger,
  verifyCredentialLifecycleChain,
} from '../../services/security/credential-ledger.js';
import {
  canonicalJson,
  generateKeypair,
  issueCert,
  signPayload,
} from '../../services/security/agent-identity.js';

function validCommit(overrides = {}) {
  const body = {
    event_type: 'STORE',
    service: 'test-service',
    slot_id: 'com.aimos.credentials.test-service',
    credential_hash: 'a'.repeat(64),
    valid_from: '2026-07-11T00:00:00.000Z',
    valid_until: null,
    signer_agent_id: 'housekeeper',
    ts_signed: 1783728000,
  };
  return {
    serviceName: 'test-service',
    slotId: 'com.aimos.credentials.test-service',
    body,
    bodyJson: body,
    agentId: 'housekeeper',
    validFromIso: '2026-07-11T00:00:00.000Z',
    certString: 'test-cert',
    signedTs: 1783728000,
    nonce: randomBytes(16).toString('base64url'),
    sigBytes: randomBytes(64),
    identityTier: 'T1_SYSTEM_SELF',
    eventType: 'STORE',
    ...overrides,
  };
}

test('credential lifecycle rejects divergence between signed and persisted bodies before SQL', async () => {
  let queried = false;
  const ledger = createCredentialLedger({
    verifyAuthorityFn: async () => ({ ok: true }),
    queryFn: async () => {
      queried = true;
      throw new Error('SQL must not run');
    },
  });
  const result = await ledger.commitCredentialLifecycle(validCommit({
    bodyJson: { event_type: 'STORE', credential_hash: 'b'.repeat(64) },
  }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'signed_body_mismatch');
  assert.equal(queried, false);
});

test('credential lifecycle requires an identity epoch before SQL', async () => {
  let queried = false;
  const ledger = createCredentialLedger({
    verifyAuthorityFn: async () => ({ ok: true }),
    queryFn: async () => {
      queried = true;
      throw new Error('SQL must not run');
    },
  });
  const result = await ledger.commitCredentialLifecycle(validCommit({ validFromIso: null }));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'malformed_agent_epoch');
  assert.equal(queried, false);
});

test('latest credential lookup treats a terminal REVOKE as no active credential', async () => {
  const statements = [];
  const ledger = createCredentialLedger({
    verifyAuthorityFn: async () => ({ ok: true }),
    queryFn: async (statement) => {
      statements.push(String(statement));
      return { rows: [] };
    },
  });
  const latest = await ledger.getLatestStoreForSlot('com.aimos.credentials.test-service');
  assert.equal(latest, null);
  assert.match(statements.join('\n'), /FROM aimos_credential_lifecycle lifecycle/);
  assert.doesNotMatch(statements.join('\n'), /ORDER BY lifecycle\.created_at|ORDER BY lifecycle\.provenance_id/);
});

test('credential lifecycle insert carries epoch and certificate fingerprint', async () => {
  const statements = [];
  const client = {
    async query(sql) {
      const text = String(sql);
      statements.push(text);
      if (text.includes('SELECT mutation_hash')) return { rows: [] };
      return { rowCount: 1, rows: [] };
    }
  };
  const ledger = createCredentialLedger({
    pool: { connect: async () => { throw new Error('pool must not be used'); } },
    verifyAuthorityFn: async () => ({ ok: true }),
  });
  const result = await ledger.commitCredentialLifecycle(validCommit({ client }));
  assert.equal(result.ok, true);
  const insert = statements.find((sql) => sql.includes('INSERT INTO aimos_credential_lifecycle'));
  assert.ok(insert);
  assert.match(insert, /agent_valid_from/);
  assert.match(insert, /cert_fingerprint/);
});

test('credential lifecycle rejects an unverified signature before SQL', async () => {
  let queried = false;
  const ledger = createCredentialLedger({
    queryFn: async () => {
      queried = true;
      throw new Error('SQL must not run');
    },
    verifyAuthorityFn: async () => ({ ok: false, reason: 'sig_invalid' }),
  });
  const result = await ledger.commitCredentialLifecycle(validCommit());
  assert.deepEqual(result, { ok: false, reason: 'sig_invalid' });
  assert.equal(queried, false);
});

test('complete credential chain binds service, slot, event, signer epoch, hash, and signature', () => {
  const signer = generateKeypair();
  const validFromUnix = 1_700_000_000;
  const validFrom = new Date(validFromUnix * 1000).toISOString();
  const cert = issueCert(signer.privkey, {
    v: 1,
    agent_id: 'housekeeper',
    pubkey: signer.pubkey,
    device_fp: 'credential-chain-device',
    valid_from: validFromUnix,
    valid_until: 2_000_000_000,
    issuer: 'housekeeper',
    issued_at: validFromUnix,
  });
  const certFingerprint = createHash('sha256').update(cert, 'utf8').digest('hex');
  const makeRow = ({ eventType, hash, previous = null, ts, nonce, id, bodyExtra = {}, proofVersion = 2 }) => {
    const body = {
      event_type: eventType,
      service: 'test-service',
      slot_id: 'com.aimos.credentials.test-service',
      credential_hash: hash,
      ...(proofVersion === 2 ? { signer_agent_id: 'housekeeper' } : {}),
      ts_signed: ts,
      ...bodyExtra,
    };
    const contentHash = createHash('sha256').update(canonicalJson(body), 'utf8').digest();
    const mutationHash = computeMutationHash(contentHash, previous, nonce, ts);
    return {
      provenance_id: id,
      service_name: body.service,
      slot_id: body.slot_id,
      event_type: eventType,
      agent_id: 'housekeeper',
      agent_valid_from: validFrom,
      cert_fingerprint: certFingerprint,
      identity_tier: 'T1_SYSTEM_SELF',
      proof_version: proofVersion,
      body_json: body,
      content_hash: contentHash,
      mutation_hash: mutationHash,
      prev_mutation_hash: previous,
      ts_signed: ts,
      nonce,
      sig: Buffer.from(signPayload(signer.privkey, body, nonce, ts), 'base64url'),
      is_genesis: previous === null,
      created_at: new Date(ts * 1000),
      pubkey: signer.pubkey,
      cert,
      revoked_at: null,
      revocation_ts_signed: null,
    };
  };
  const first = makeRow({
    eventType: 'STORE',
    hash: 'a'.repeat(64),
    ts: 1_800_000_000,
    nonce: 'credential-chain-1',
    id: '11111111-1111-4111-8111-111111111111',
  });
  const second = makeRow({
    eventType: 'ROTATE',
    hash: 'b'.repeat(64),
    previous: first.mutation_hash,
    ts: 1_800_000_001,
    nonce: 'credential-chain-2',
    id: '22222222-2222-4222-8222-222222222222',
  });
  const verified = verifyCredentialLifecycleChain([first, second]);
  assert.equal(verified.verified, true);
  assert.equal(verified.effectiveStore.provenance_id, second.provenance_id);
  assert.throws(
    () => verifyCredentialLifecycleChain([first, { ...second, service_name: 'forged' }]),
    /row_mismatch/,
  );
  assert.throws(
    () => verifyCredentialLifecycleChain([first, { ...second, sig: Buffer.alloc(64) }]),
    /signature_invalid/,
  );

  const useId = '33333333-3333-4333-8333-333333333333';
  const reserved = makeRow({
    eventType: 'USE_RESERVED',
    hash: 'b'.repeat(64),
    previous: second.mutation_hash,
    ts: 1_800_000_002,
    nonce: 'credential-chain-use-reserved',
    id: '44444444-4444-4444-8444-444444444444',
    bodyExtra: {
      use_id: useId,
      effective_provenance_id: second.provenance_id,
      effective_mutation_hash: second.mutation_hash.toString('hex'),
      operation: 'test_external_read',
      endpoint: 'https://example.test/v1/items',
      request_hash: 'c'.repeat(64),
      subject_agent_id: 'housekeeper',
      authority_kind: 'housekeeper_autonomous',
      request_receipt_id: null,
      request_admission_event_id: null,
      autonomous_action_event_id: '77777777-7777-4777-8777-777777777777',
      autonomous_action_mutation_hash: 'e'.repeat(64),
    },
  });
  const completed = makeRow({
    eventType: 'USE_COMPLETED',
    hash: 'b'.repeat(64),
    previous: reserved.mutation_hash,
    ts: 1_800_000_003,
    nonce: 'credential-chain-use-completed',
    id: '55555555-5555-4555-8555-555555555555',
    bodyExtra: {
      use_id: useId,
      reservation_provenance_id: reserved.provenance_id,
      reservation_mutation_hash: reserved.mutation_hash.toString('hex'),
      outcome_hash: 'd'.repeat(64),
    },
  });
  const used = verifyCredentialLifecycleChain([first, second, reserved, completed]);
  assert.equal(used.effectiveStore.provenance_id, second.provenance_id);
  assert.deepEqual(used.openCredentialUses, []);
  assert.throws(
    () => verifyCredentialLifecycleChain([
      first,
      second,
      reserved,
      { ...completed, body_json: { ...completed.body_json, reservation_mutation_hash: 'e'.repeat(64) } },
    ]),
    /hash_mismatch|terminal_without_reservation/,
  );

  const retainedV1 = makeRow({
    eventType: 'STORE',
    hash: 'f'.repeat(64),
    ts: 1_800_000_010,
    nonce: 'credential-chain-retained-v1',
    id: '66666666-6666-4666-8666-666666666666',
    proofVersion: 1,
  });
  assert.equal(verifyCredentialLifecycleChain([retainedV1]).effectiveStore.provenance_id, retainedV1.provenance_id);
  assert.throws(
    () => verifyCredentialLifecycleChain([{ ...retainedV1, proof_version: 2 }]),
    /row_mismatch/,
  );
});

test('credential use rejects unverified user authority before reading a credential chain', async () => {
  let queried = false;
  const ledger = createCredentialLedger({
    queryFn: async () => {
      queried = true;
      throw new Error('credential chain must not be read');
    },
  });
  await assert.rejects(
    ledger.reserveCredentialUse({
      endpoint: 'https://example.test/v1/items',
      subjectAgentId: 'unverified-agent',
    }),
    /credential_use_non_housekeeper_requires_verified_request/,
  );
  assert.equal(queried, false);
});

test('credential use requires both request receipt id and mutation hash', async () => {
  const ledger = createCredentialLedger({ queryFn: async () => ({ rows: [] }) });
  await assert.rejects(
    ledger.reserveCredentialUse({
      endpoint: 'https://example.test/v1/items',
      subjectAgentId: 'receipt-agent',
      requestReceiptId: '11111111-1111-4111-8111-111111111111',
    }),
    /credential_use_request_receipt_incomplete/,
  );
});

test('credential use rejects an unverifiable claimed autonomous parent before reading the credential', async () => {
  let eventChecked = false;
  const ledger = createCredentialLedger({
    queryFn: async () => ({ rows: [] }),
    verifyAutonomousEventFn: async () => {
      eventChecked = true;
      throw new Error('event_receipt_not_found');
    },
  });
  await assert.rejects(
    ledger.reserveCredentialUse({
      endpoint: 'https://example.test/v1/items',
      subjectAgentId: 'housekeeper',
      autonomousActionEventId: '22222222-2222-4222-8222-222222222222',
    }),
    /event_receipt_not_found/,
  );
  assert.equal(eventChecked, true);
});
