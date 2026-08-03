import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { cognitiveBaselineHash } from '../../services/security/housekeeper-signer.js';
import { verifyPortableCognitiveState } from '../../services/security/cognitive-weight-verifier.js';

const base = {
  companyId: 'hom',
  memoryId: '11111111-1111-4111-8111-111111111111',
  eventId: '22222222-2222-4222-8222-222222222222',
  eventMutationHash: Buffer.alloc(32, 1),
  liveContentHash: Buffer.alloc(32, 2),
  observedWeight: Math.fround(1.2344),
  weightMilli: 1234,
  observedTs: 1_800_000_000,
  signerValidFromIso: '2026-07-11T19:13:08.000Z',
  certFingerprint: 'ab'.repeat(32),
};

test('cognitive baseline hash binds exact float, event, memory, epoch, and content', () => {
  const first = cognitiveBaselineHash(base);
  const again = cognitiveBaselineHash({ ...base });
  assert.equal(first.length, 32);
  assert(first.equals(again));
  for (const changed of [
    { eventId: '33333333-3333-4333-8333-333333333333' },
    { eventMutationHash: Buffer.alloc(32, 3) },
    { liveContentHash: Buffer.alloc(32, 4) },
    { observedWeight: Math.fround(1.2345), weightMilli: 1235 },
    { observedTs: base.observedTs + 1 },
    { signerValidFromIso: '2026-07-11T19:13:09.000Z' },
    { certFingerprint: 'cd'.repeat(32) },
  ]) {
    assert.equal(first.equals(cognitiveBaselineHash({ ...base, ...changed })), false);
  }
});

test('portable corpus classifier rejects unattested non-default empty state', () => {
  const common = { id: base.memoryId, company_id: 'hom', content_hash: base.liveContentHash };
  const defaultState = verifyPortableCognitiveState({ memory: { ...common, retrieval_weight: 1 } });
  assert.deepEqual(
    { status: defaultState.certification_status, ok: defaultState.ok },
    { status: 'default_empty_chain', ok: true },
  );
  const unattested = verifyPortableCognitiveState({ memory: { ...common, retrieval_weight: Math.fround(1.2344) } });
  assert.deepEqual(
    { status: unattested.certification_status, ok: unattested.ok, reason: unattested.reason },
    { status: 'unattested_initial_weight', ok: false, reason: 'unattested_initial_weight' },
  );
});

test('migration 091 closes epoch, display, baseline, ACL, and vacuous-corpus gaps', async () => {
  const migration = await readFile(new URL('../../migrations/091-cognitive-baseline-and-epoch-proof.sql', import.meta.url), 'utf8');
  assert.match(migration, /p\.agent_valid_from IS NOT NULL/);
  assert.match(migration, /clock_timestamp\(\) >= v_agent_until/);
  assert.match(migration, /v_revocation_ts IS NOT NULL/);
  assert.match(migration, /v_identity_cert_fingerprint IS DISTINCT FROM v_prov_cert_fingerprint/);
  assert.match(migration, /float4send\(old_weight\).*float4send\(\(old_weight_milli/s);
  assert.match(migration, /cognitive_initial_weight_attestation_required/);
  assert.match(migration, /FROM public\.aimos_memories mem/);
  assert.match(migration, /'unattested_initial_weight'/);
  assert.match(migration, /REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public\.aimos_cognitive_weight_baselines FROM agent_runtime/);
  assert.match(migration, /ON DELETE RESTRICT/);
});
