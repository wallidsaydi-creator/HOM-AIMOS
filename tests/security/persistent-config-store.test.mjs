import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  generateKeypair,
  pubkeyFingerprint,
  signPayload,
  verifyPayloadSig,
  verifyStoredPayloadSig
} from '../../services/security/agent-identity.js';
import { createSystemConfigStore } from '../../services/security/system-config-store.js';
import {
  SYSTEM_CONFIG_CONSTANTS,
  MAGMA_RETRIEVAL_CALIBRATION_VERSION,
  MAGMA_RETRIEVAL_POLICY_VERSION,
  TWIN_PRIME_POLICY_VERSION,
  computeSystemConfigMutationHash,
  validateMagmaRetrievalCalibration,
  validateMagmaRetrievalPolicy,
  validateTwinPrimeRetrievalPolicy,
  validateSystemConfigValue,
} from '../../services/security/system-config-ledger.js';
import { contentHash } from '../../services/security/identity-chain.js';

const DAY_SECONDS = 86_400;

test('model preference validation commits one canonical provider/model pair', () => {
  assert.deepEqual(
    validateSystemConfigValue('MODEL_PREFERENCE_CODING', '{"model":"gpt-5","provider":"OPENAI"}'),
    { ok: true, value: '{"provider":"openai","model":"gpt-5"}' },
  );
  assert.deepEqual(
    validateSystemConfigValue('MODEL_PREFERENCE_CODING', '{"provider":"openai"}'),
    { ok: false, reason: 'invalid_model_preference' },
  );
  assert.deepEqual(
    validateSystemConfigValue('MODEL_PREFERENCE_CODING', '{"provider":"openai","model":"gpt-5","fallback":"x"}'),
    { ok: false, reason: 'invalid_model_preference' },
  );
});

test('twin-prime policy is a strict composite signed value with preregistered coefficients', () => {
  const valid = JSON.stringify({
    gamma: '1/128',
    arm: 'T',
    early_exit: 'off',
    version: TWIN_PRIME_POLICY_VERSION,
    execution: 'shadow',
    lambda_t: '1/64',
    cache: 'off',
  });
  assert.deepEqual(validateTwinPrimeRetrievalPolicy(valid), {
    ok: true,
    value: JSON.stringify({
      version: TWIN_PRIME_POLICY_VERSION,
      arm: 'T',
      lambda_t: '1/64',
      gamma: '1/128',
      execution: 'shadow',
      cache: 'off',
      early_exit: 'off',
    }),
    policy: {
      version: TWIN_PRIME_POLICY_VERSION,
      arm: 'T',
      lambda_t: '1/64',
      gamma: '1/128',
      execution: 'shadow',
      cache: 'off',
      early_exit: 'off',
    },
  });
  assert.equal(
    validateSystemConfigValue('TWIN_PRIME_RETRIEVAL_POLICY', valid).ok,
    true,
  );

  const rejected = [
    { ...JSON.parse(valid), extra: true },
    { ...JSON.parse(valid), version: 'future' },
    { ...JSON.parse(valid), arm: 'B3' },
    { ...JSON.parse(valid), lambda_t: 0 },
    { ...JSON.parse(valid), gamma: '1/3' },
    { ...JSON.parse(valid), execution: 'request' },
    { ...JSON.parse(valid), cache: 'on' },
    { ...JSON.parse(valid), early_exit: 'on' },
    { ...JSON.parse(valid), arm: 'B0', lambda_t: '1/64', gamma: '0' },
    { ...JSON.parse(valid), arm: 'B1', lambda_t: '0', gamma: '1/128' },
    { ...JSON.parse(valid), arm: 'B2', gamma: '1/128' },
  ];
  for (const policy of rejected) {
    assert.equal(validateTwinPrimeRetrievalPolicy(JSON.stringify(policy)).ok, false);
  }
});

test('MAGMA policy binds activation to the exact proof and unchanged preregistered ceiling', () => {
  const valid = JSON.stringify({
    runner_sha256: 'c3094713c6816685dbd332dfc89a1ae51c4d2b561265f28efb761ed532ee1877',
    proof_sha256: '52134f1d254174113bfaa92bd34e2317f45702d058e891de51ddd203367751b7',
    version: MAGMA_RETRIEVAL_POLICY_VERSION,
    max_nodes: 200,
    candidate_p95_ceiling_ms: 250,
    result_limit: 20,
    max_depth: 3,
    execution: 'shadow',
    early_exit: 'off',
    cache: 'off',
  });
  const result = validateMagmaRetrievalPolicy(valid);
  assert.equal(result.ok, true);
  assert.equal(result.policy.candidate_p95_ceiling_ms, 250);
  assert.equal(validateSystemConfigValue('MAGMA_RETRIEVAL_POLICY', valid).ok, true);

  const rejected = [
    { ...JSON.parse(valid), extra: true },
    { ...JSON.parse(valid), version: 'future' },
    { ...JSON.parse(valid), execution: 'request' },
    { ...JSON.parse(valid), max_depth: 4 },
    { ...JSON.parse(valid), max_nodes: 201 },
    { ...JSON.parse(valid), result_limit: 21 },
    { ...JSON.parse(valid), candidate_p95_ceiling_ms: 800 },
    { ...JSON.parse(valid), proof_sha256: 'pending' },
    { ...JSON.parse(valid), runner_sha256: '0'.repeat(63) },
    { ...JSON.parse(valid), cache: 'on' },
    { ...JSON.parse(valid), early_exit: 'on' },
  ];
  for (const policy of rejected) {
    assert.equal(validateMagmaRetrievalPolicy(JSON.stringify(policy)).ok, false);
  }
});

test('MAGMA v2 calibration adjusts only bounded gear mathematics and has no execution field', () => {
  const valid = JSON.stringify({
    version: MAGMA_RETRIEVAL_CALIBRATION_VERSION,
    max_depth: 3,
    max_nodes: 200,
    result_limit: 20,
    beam_width: 5,
    rrf_k: 60,
    candidate_p95_ceiling_ms: 250,
    proof_sha256: 'a'.repeat(64),
    runner_sha256: 'b'.repeat(64),
  });
  const result = validateMagmaRetrievalCalibration(valid);
  assert.equal(result.ok, true);
  assert.equal(Object.hasOwn(result.calibration, 'execution'), false);
  assert.equal(validateSystemConfigValue('MAGMA_RETRIEVAL_CALIBRATION', valid).ok, true);

  for (const rejected of [
    { ...JSON.parse(valid), execution: 'enforce' },
    { ...JSON.parse(valid), max_depth: 4 },
    { ...JSON.parse(valid), max_nodes: 49 },
    { ...JSON.parse(valid), result_limit: 200 },
    { ...JSON.parse(valid), beam_width: 6 },
    { ...JSON.parse(valid), rrf_k: 61 },
  ]) {
    assert.equal(validateMagmaRetrievalCalibration(JSON.stringify(rejected)).ok, false);
  }
});

function configRow(privkey, {
  pubkey,
  configKey = 'OPERATOR_AGENT_ID',
  value = 'codex-auditor',
  ts = 1_700_000_000,
  nonce = 'config-ledger-nonce',
  previous = null,
  configId = 1,
} = {}) {
  const body = {
    config_key: configKey,
    value_text: value,
    reason: 'persistent-config-test',
    operator: 'test-master',
    identity_tier: 'T0',
    ts_signed: ts,
    prev_value: previous?.value_text ?? null
  };
  const sig = signPayload(privkey, body, nonce, ts);
  const cHash = contentHash(body);
  const previousHash = previous?.mutation_hash || null;
  const mutationHash = computeSystemConfigMutationHash(cHash, previousHash, nonce, ts);
  return {
    config_id: configId,
    config_key: configKey,
    value_text: value,
    cert_fingerprint: pubkeyFingerprint(pubkey),
    content_hash: cHash,
    mutation_hash: mutationHash,
    prev_mutation_hash: previousHash,
    nonce,
    ts_signed: ts,
    sig: Buffer.from(sig, 'base64url'),
    is_genesis: previous == null,
    body_json: body,
    created_at: new Date(ts * 1000),
  };
}

test('stored Ed25519 payload remains valid after request freshness expires', () => {
  const { pubkey, privkey } = generateKeypair();
  const ts = 1_700_000_000;
  const now = ts + (90 * DAY_SECONDS);
  const nonce = crypto.randomBytes(16).toString('base64url');
  const body = { config_key: 'OPERATOR_AGENT_ID', value_text: 'codex-auditor' };
  const sig = signPayload(privkey, body, nonce, ts);

  assert.deepEqual(
    verifyStoredPayloadSig(pubkey, body, nonce, ts, sig),
    { valid: true, reason: null }
  );
  assert.deepEqual(
    verifyPayloadSig(pubkey, body, nonce, ts, sig, { nowFn: () => now }),
    { valid: false, reason: 'clock_skew' }
  );
  assert.equal(
    verifyStoredPayloadSig(pubkey, { ...body, value_text: 'tampered' }, nonce, ts, sig).reason,
    'sig_invalid'
  );
  assert.equal(Buffer.from(sig, 'base64url').length, 64);
});

test('system config accepts an old signed row and binds signed body to row columns', async () => {
  const { pubkey, privkey } = generateKeypair();
  const row = configRow(privkey, { pubkey });
  const events = [];
  let rows = [row];
  const store = createSystemConfigStore({
    queryFn: async () => ({ rows }),
    masterPubkeyFn: async () => pubkey,
    nowFn: () => (row.ts_signed + (90 * DAY_SECONDS)) * 1000,
    logEventFn: async (...args) => events.push(args)
  });

  const loaded = await store.loadAll();
  assert.equal(loaded.ok, true);
  assert.equal(store.isLoaded(), true);
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'codex-auditor');
  assert.equal(store._peek().OPERATOR_AGENT_ID.source, 'verified');
  assert.deepEqual(store.readVerifiedConfig('OPERATOR_AGENT_ID'), {
    value: 'codex-auditor',
    mutation_hash: row.mutation_hash.toString('hex'),
    verified_at: (row.ts_signed + (90 * DAY_SECONDS)) * 1000,
    source: 'verified',
  });
  assert.equal(Object.isFrozen(store.readVerifiedConfig('OPERATOR_AGENT_ID')), true);
  assert.equal(store.readVerifiedConfig('MISSING_CONFIG'), null);
  assert.equal(events.length, 0);

  rows = [{ ...row, value_text: 'db-column-tamper' }];
  const reloaded = await store.reload();
  assert.equal(reloaded.ok, false);
  assert.equal(reloaded.reason, 'SIGNED_BODY_ROW_MISMATCH');
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'codex-auditor');
  assert.equal(events.at(-1)[2], 'system_config_verify_failed');
});

test('system config reload retains last-known-good state on infrastructure failure', async () => {
  const { pubkey, privkey } = generateKeypair();
  const row = configRow(privkey, { pubkey, value: 'operator-live' });
  let failQuery = false;
  const events = [];
  const store = createSystemConfigStore({
    queryFn: async () => {
      if (failQuery) throw new Error('database unavailable');
      return { rows: [row] };
    },
    masterPubkeyFn: async () => pubkey,
    logEventFn: async (...args) => events.push(args)
  });

  assert.equal((await store.loadAll()).ok, true);
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'operator-live');

  failQuery = true;
  const result = await store.reload();
  assert.deepEqual(result, { ok: false, reason: 'DB_QUERY_FAILED' });
  assert.equal(store.isLoaded(), true);
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'operator-live');
  assert.equal(events.at(-1)[2], 'system_config_store_load_failed');
});

test('initial system config verification failure remains fail-to-null', async () => {
  const { pubkey, privkey } = generateKeypair();
  const valid = configRow(privkey, { pubkey });
  const store = createSystemConfigStore({
    queryFn: async () => ({ rows: [{ ...valid, sig: Buffer.alloc(64) }] }),
    masterPubkeyFn: async () => pubkey,
    logEventFn: async () => {}
  });

  const result = await store.loadAll();
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'sig_invalid');
  assert.equal(store.isLoaded(), true);
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), null);
  assert.deepEqual(store._peek(), {});
});

test('topology config schema is typed and rejects reserved legacy ports', () => {
  assert.equal(SYSTEM_CONFIG_CONSTANTS.ALLOWED_CONFIG_KEYS.includes('AIMOS_BASE_URL'), true);
  assert.deepEqual(
    validateSystemConfigValue('AIMOS_BASE_URL', 'http://127.0.0.1:9100'),
    { ok: true, value: 'http://127.0.0.1:9100', configKey: 'AIMOS_BASE_URL' }
  );
  assert.equal(
    validateSystemConfigValue('AIMOS_BASE_URL', 'http://127.0.0.1:9000').reason,
    'legacy_port_reserved'
  );
  assert.equal(
    validateSystemConfigValue('AIMOS_BASE_URL', 'http://127.0.0.1:9100/aimos').reason,
    'origin_only_required'
  );
});

test('typed topology config remains signature-bound in the persistent ledger store', async () => {
  const { pubkey, privkey } = generateKeypair();
  const row = configRow(privkey, {
    pubkey,
    configKey: 'AIMOS_BASE_URL',
    value: 'http://127.0.0.1:9100',
    nonce: 'topology-config-ledger-nonce'
  });
  const store = createSystemConfigStore({
    queryFn: async () => ({ rows: [row] }),
    masterPubkeyFn: async () => pubkey,
    logEventFn: async () => {}
  });

  assert.equal((await store.loadAll()).ok, true);
  assert.equal(store.readConfigString('AIMOS_BASE_URL'), 'http://127.0.0.1:9100');
  assert.equal(store._peek().AIMOS_BASE_URL.source, 'verified');
  assert.equal(Buffer.from(row.sig).length, 64);
});

test('system config load verifies every append-only chain link before publishing latest state', async () => {
  const { pubkey, privkey } = generateKeypair();
  const genesis = configRow(privkey, {
    pubkey,
    value: 'operator-one',
    nonce: 'config-chain-genesis',
    configId: 1,
  });
  const successor = configRow(privkey, {
    pubkey,
    value: 'operator-two',
    nonce: 'config-chain-successor',
    ts: genesis.ts_signed + 1,
    previous: genesis,
    configId: 2,
  });
  let rows = [genesis, successor];
  const store = createSystemConfigStore({
    queryFn: async () => ({ rows }),
    masterPubkeyFn: async () => pubkey,
    logEventFn: async () => {},
  });

  assert.equal((await store.loadAll()).ok, true);
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'operator-two');

  rows = [genesis, { ...successor, prev_mutation_hash: Buffer.alloc(32, 7) }];
  const result = await store.reload();
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'CHAIN_LINK_MISMATCH');
  assert.equal(store.readConfigString('OPERATOR_AGENT_ID'), 'operator-two');
});
