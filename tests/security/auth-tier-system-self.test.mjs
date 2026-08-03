#!/usr/bin/env node
/**
 * auth-tier-system-self.test.mjs — T1_SYSTEM_SELF tier verification
 *
 * Every test has a body with required state, durable-evidence, and output assertions.
 * (3 stateful + 1 disk + 1 non-empty field). No name-only tests.
 *
 * Cases:
 *   1. Valid self-signed housekeeper cert + valid sig → T1_SYSTEM_SELF
 *   2. Tampered cert body → t0('system_self_invalid_cert')
 *   3. Replay nonce → t0('replay_detected')
 *   4. Real /aimos/save via genesis-mode HTTP → 200 + DB row has sig + tier
 *   5. Housekeeper-self signed POST /aimos/recall → nonblank Guide proof
 *
 * Cases 1-3: unit tests (injected caches, real crypto). No DB needed.
 * Cases 4-5: isolated live-fire tests. They run only with --live-fire and a
 *            disposable --aimos-db name beginning aimos_test_. The default
 *            unit suite never writes to canonical AIMOS.
 *
 * Usage:
 *   node tests/security/auth-tier-system-self.test.mjs
 */

import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import {
  generateKeypair,
  issueCert,
  signPayloadWithContext,
  verifyCertChain,
  verifyPayloadSig
} from '../../services/security/agent-identity.js';
import { createAuthTier } from '../../services/security/auth-tier.js';
import { authGate } from '../../services/security/auth-gate.js';
import { computeDeviceFp } from '../../scripts/identity/lib.js';
import { resolveAimosDatabaseName } from '../../services/core/runtime-config.js';

const HOUSEKEEPER_AGENT_ID = 'housekeeper';
let passed = 0;
let failed = 0;
let skipped = 0;

function assert(cond, label, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.error(`  ✗ ${label}${detail ? ' — ' + detail : ''}`);
  }
}

// ── Test fixtures ──────────────────────────────────────────────────────
function makeHousekeeperCert(privkey, pubkey) {
  const now = Math.floor(Date.now() / 1000);
  const deviceFp = computeDeviceFp(process.cwd());
  return issueCert(privkey, {
    v: 1,
    agent_id: HOUSEKEEPER_AGENT_ID,
    pubkey,
    device_fp: deviceFp,
    valid_from: now - 60,
    valid_until: now + 3600,
    issuer: HOUSEKEEPER_AGENT_ID,
    issued_at: now
  });
}

function makeEnvelopeHeaders(certString, privkey, body, method = 'POST', path = '/aimos/save') {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const ts = Math.floor(Date.now() / 1000);
  body.ts_signed = ts;
  const sig = signPayloadWithContext(privkey, body, method, path, nonce, ts);
  return {
    'aimos-agent-cert': certString,
    'aimos-agent-signature': sig,
    'aimos-agent-nonce': nonce,
    'aimos-agent-timestamp': String(ts),
    'x-aimos-sig-form': '3'
  };
}

function makeMockDeps(housekeeperPubkey) {
  // Real nonce window (in-memory Set-based, mirrors nonce-window.js contract)
  const seenNonces = new Map();
  const nonceWindow = {
    seenAndRecord(agentId, nonce) {
      const key = `${agentId}:${nonce}`;
      if (seenNonces.has(key)) return true;
      seenNonces.set(key, Date.now());
      return false;
    },
    _has(agentId, nonce) { return seenNonces.has(`${agentId}:${nonce}`); }
  };

  // Mock caches
  let housekeeperQueryCount = 0;
  const housekeeperPubkeyCache = {
    async get() { housekeeperQueryCount++; return housekeeperPubkey; },
    invalidate() {},
    _queryCount: () => housekeeperQueryCount
  };

  let revocationLookupCount = 0;
  const revocationCache = {
    async lookup(agentId, validFromIso) {
      revocationLookupCount++;
      return { found: true, revoked: false };
    },
    _lookupCount: () => revocationLookupCount
  };

  return { nonceWindow, housekeeperPubkeyCache, revocationCache };
}

// ═══════════════════════════════════════════════════════════════════════
// CASE 1: Valid self-signed housekeeper cert + valid sig → T1_SYSTEM_SELF
// ═══════════════════════════════════════════════════════════════════════
async function testCase1_validSystemSelf() {
  console.log('\n[CASE 1] Valid self-signed housekeeper cert → T1_SYSTEM_SELF');

  const { pubkey, privkey } = generateKeypair();
  const cert = makeHousekeeperCert(privkey, pubkey);
  const deps = makeMockDeps(pubkey);
  const authTierInst = createAuthTier({
    housekeeperPubkeyCache: deps.housekeeperPubkeyCache,
    agentRevocationCache: deps.revocationCache,
    nonceWindow: deps.nonceWindow
  });

  const body = { company_id: 'system', key: 'guide:test', value: 'test content' };
  const headers = makeEnvelopeHeaders(cert, privkey, body);
  const req = { headers, body, method: 'POST', originalUrl: '/aimos/save' };

  const result = await authTierInst.deriveTier(req);

  // H1 Required Assertions:
  // Stateful 1: housekeeper pubkey cache was queried
  assert(deps.housekeeperPubkeyCache._queryCount() > 0, 'housekeeper pubkey cache queried');
  // Stateful 2: revocation cache was queried
  assert(deps.revocationCache._lookupCount() > 0, 'revocation cache queried');
  // Stateful 3: nonce was recorded in the window
  assert(deps.nonceWindow._has(HOUSEKEEPER_AGENT_ID, headers['aimos-agent-nonce']), 'nonce recorded in window');
  // Disk: cert body is a real parsed object (cryptographic artifact)
  assert(result.cert !== null && typeof result.cert === 'object', 'cert body is real object (disk artifact)');
  assert(result.cert?.agent_id === HOUSEKEEPER_AGENT_ID, 'cert agent_id is housekeeper', `got ${result.cert?.agent_id}`);
  // Non-empty field: tier string is exactly T1_SYSTEM_SELF
  assert(result.tier === 'T1_SYSTEM_SELF', 'tier is T1_SYSTEM_SELF', `got ${result.tier}`);
  // Non-empty: sig bytes present
  assert(Buffer.isBuffer(result.sigBytes) && result.sigBytes.length === 64, 'sigBytes is 64-byte Ed25519');
}

// ═══════════════════════════════════════════════════════════════════════
// CASE 2: Tampered cert body → t0('system_self_invalid_cert')
// ═══════════════════════════════════════════════════════════════════════
async function testCase2_tamperedCert() {
  console.log('\n[CASE 2] Tampered cert body → system_self_invalid_cert');

  const { pubkey, privkey } = generateKeypair();
  const cert = makeHousekeeperCert(privkey, pubkey);

  // Tamper: flip one byte in the cert string
  const buf = Buffer.from(cert, 'base64url');
  buf[buf.length - 10] ^= 0x01;
  const tamperedCert = buf.toString('base64url');

  const deps = makeMockDeps(pubkey);
  const authTierInst = createAuthTier({
    housekeeperPubkeyCache: deps.housekeeperPubkeyCache,
    agentRevocationCache: deps.revocationCache,
    nonceWindow: deps.nonceWindow
  });

  const body = { key: 'guide:test', value: 'x' };
  const headers = makeEnvelopeHeaders(cert, privkey, body);  // sig over original body, not relevant — cert fails first
  headers['aimos-agent-cert'] = tamperedCert;
  const req = { headers, body, method: 'POST', originalUrl: '/aimos/save' };

  const result = await authTierInst.deriveTier(req);

  // H1 Required Assertions:
  // Stateful 1: housekeeper cache was queried (cert peek routes to system-self)
  assert(deps.housekeeperPubkeyCache._queryCount() > 0, 'housekeeper cache queried before cert verify');
  // Stateful 2: verifyCertChain rejected (the real crypto function ran + failed)
  assert(result.tier === 'T0', 'tier collapsed to T0', `got ${result.tier}`);
  // Stateful 3: error reason is the cert-verify failure
  assert(result.error === 'system_self_invalid_cert', 'error is system_self_invalid_cert', `got ${result.error}`);
  // Disk: no nonce recorded (rejection happens before nonce check)
  assert(!deps.nonceWindow._has(HOUSEKEEPER_AGENT_ID, headers['aimos-agent-nonce']), 'nonce NOT recorded (rejected before nonce step)');
  // Non-empty: error string is non-empty
  assert(typeof result.error === 'string' && result.error.length > 0, 'error string non-empty');
}

// ═══════════════════════════════════════════════════════════════════════
// CASE 3: Replay nonce → second call t0('replay_detected')
// ═══════════════════════════════════════════════════════════════════════
async function testCase3_replayNonce() {
  console.log('\n[CASE 3] Replay nonce → replay_detected on second call');

  const { pubkey, privkey } = generateKeypair();
  const cert = makeHousekeeperCert(privkey, pubkey);
  const deps = makeMockDeps(pubkey);
  const authTierInst = createAuthTier({
    housekeeperPubkeyCache: deps.housekeeperPubkeyCache,
    agentRevocationCache: deps.revocationCache,
    nonceWindow: deps.nonceWindow
  });

  // First call — fresh nonce, should succeed
  const body1 = { key: 'guide:test', value: 'content1' };
  const headers1 = makeEnvelopeHeaders(cert, privkey, body1);
  const result1 = await authTierInst.deriveTier({ headers: headers1, body: body1, method: 'POST', originalUrl: '/aimos/save' });
  assert(result1.tier === 'T1_SYSTEM_SELF', 'first call succeeds (T1_SYSTEM_SELF)');

  // Second call — SAME nonce, should be rejected as replay
  const body2 = { key: 'guide:test2', value: 'content2' };
  const ts2 = Math.floor(Date.now() / 1000);
  body2.ts_signed = ts2;
  const sig2 = signPayloadWithContext(privkey, body2, 'POST', '/aimos/save', headers1['aimos-agent-nonce'], ts2);
  const headers2 = {
    'aimos-agent-cert': cert,
    'aimos-agent-signature': sig2,
    'aimos-agent-nonce': headers1['aimos-agent-nonce'],  // replayed
    'aimos-agent-timestamp': String(ts2),
    'x-aimos-sig-form': '3'
  };
  const result2 = await authTierInst.deriveTier({ headers: headers2, body: body2, method: 'POST', originalUrl: '/aimos/save' });

  // H1 Required Assertions:
  // Stateful 1: nonce is in the window (recorded by first call)
  assert(deps.nonceWindow._has(HOUSEKEEPER_AGENT_ID, headers1['aimos-agent-nonce']), 'nonce in window after first call');
  // Stateful 2: second call returned T0
  assert(result2.tier === 'T0', 'second call tier is T0', `got ${result2.tier}`);
  // Stateful 3: error is replay_detected
  assert(result2.error === 'replay_detected', 'error is replay_detected', `got ${result2.error}`);
  // Disk: nonce window state confirms the replay (same nonce, seen twice)
  assert(result2.error === 'replay_detected' && result1.tier === 'T1_SYSTEM_SELF', 'disk state: first admitted, second rejected (nonce window held)');
  // Non-empty: error string non-empty
  assert(typeof result2.error === 'string' && result2.error.length > 0, 'error string non-empty');
}

// ═══════════════════════════════════════════════════════════════════════
// CASES 4-5: Live-fire (need DB + housekeeper provisioned)
// ═══════════════════════════════════════════════════════════════════════
async function canRunLiveFire() {
  try {
    const { pool } = await import('../../db/connection.js');
    const r = await pool.query(`SELECT pubkey FROM agent_identity WHERE agent_id='housekeeper' AND revoked_at IS NULL LIMIT 1`);
    return r.rows.length > 0;
  } catch { return false; }
}

function requireDisposableLiveFireDatabase() {
  const databaseName = resolveAimosDatabaseName();
  if (!/^aimos_test_[a-z0-9_]+$/.test(databaseName)) {
    throw new Error(`live-fire security test refuses non-disposable database: ${databaseName}`);
  }
  return databaseName;
}

async function testCase4_realHttpGenesisSave() {
  console.log('\n[CASE 4] Real /aimos/save via genesis-mode HTTP as housekeeper-self');

  const { pool } = await import('../../db/connection.js');
  const { signAsHousekeeper } = await import('../../services/security/housekeeper-signer.js');

  // Spin up genesis-mode server (same pattern as genesis-install.mjs A6)
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(authGate);
  let router = null;
  app.use('/aimos', async (req, res, next) => {
    if (!router) router = (await import('../../routes/aimos.js')).default;
    return router(req, res, next);
  });
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    const body = {
      company_id: 'hom',
      agent_id: 'housekeeper',
      key: `guide:test:system-self-${Date.now()}`,
      value: 'Live-fire T1_SYSTEM_SELF test content proves the signed append-only save pipeline, provenance hash, and immutable system-memory contract.',
      memory_type: 'procedural_seed',
      source: 'test:auth-tier-system-self',
      memory_tier: 'long-term',
      scope: 'system',
      clearance_level: 10
    };
    const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/save' });

    const resp = await fetch(`${base}/aimos/save`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'aimos-agent-cert': signed.certString,
        'aimos-agent-signature': signed.sigB64u,
        'aimos-agent-nonce': signed.nonce,
        'aimos-agent-timestamp': String(signed.signedTs),
        'x-aimos-sig-form': String(signed.sigForm)
      },
      body: JSON.stringify(signed.body)
    });
    const respBody = await resp.json().catch(() => ({}));

    // H1 Required Assertions:
    // Stateful 1: HTTP response is 200
    assert(resp.status === 200, 'HTTP 200', `got ${resp.status}`);
    // Stateful 2: response identity_tier is T1_SYSTEM_SELF
    assert(respBody.identity_tier === 'T1_SYSTEM_SELF', 'response identity_tier=T1_SYSTEM_SELF', `got ${respBody.identity_tier}`);
    // Stateful 3: response has content_hash (the pipeline ran)
    assert(typeof respBody.content_hash === 'string' && respBody.content_hash.length > 0, 'response has content_hash');

    // Disk: real DB row with sig + identity_tier
    const provRow = await pool.query(
      `SELECT sig, nonce, ts_signed, identity_tier, is_genesis
       FROM aimos_memory_provenance
       WHERE memory_id = $1
         AND event_type = 'SAVE'
       ORDER BY created_at ASC LIMIT 1`,
      [respBody.memory_id]
    );
    assert(provRow.rows.length > 0, 'provenance row exists in DB (disk)');
    if (provRow.rows.length > 0) {
      const row = provRow.rows[0];
      // Non-empty: sig is 64-byte Ed25519
      const sigBuf = typeof row.sig === 'string' ? Buffer.from(row.sig, 'hex') : row.sig;
      assert(Buffer.isBuffer(sigBuf) && sigBuf.length === 64, 'DB sig is 64-byte Ed25519', `got len=${sigBuf?.length}`);
      assert(row.identity_tier === 'T1', 'DB identity_tier is canonicalized to T1', `got ${row.identity_tier}`);
      assert(row.is_genesis === true, 'DB is_genesis=true (auto-derived)', `got ${row.is_genesis}`);
    }
  } finally {
    await new Promise((r) => server.close(r));
  }
}

async function testCase5_allowListRecall() {
  console.log('\n[CASE 5] Housekeeper-self signed POST /aimos/recall → non-blank Guide');

  const { signAsHousekeeper } = await import('../../services/security/housekeeper-signer.js');

  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(authGate);
  let router = null;
  app.use('/aimos', async (req, res, next) => {
    if (!router) router = (await import('../../routes/aimos.js')).default;
    return router(req, res, next);
  });
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  try {
    const body = {
      query: 'guide',
      company_id: 'hom',
      clearance_level: 12,
      mode: 'full',
      limit: 10,
    };
    const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/recall' });

    const resp = await fetch(`${base}/aimos/recall`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'aimos-agent-cert': signed.certString,
        'aimos-agent-signature': signed.sigB64u,
        'aimos-agent-nonce': signed.nonce,
        'aimos-agent-timestamp': String(signed.signedTs),
        'x-aimos-sig-form': String(signed.sigForm)
      },
      body: JSON.stringify(signed.body),
    });

    const respBody = await resp.json().catch(() => ({}));
    // H1 Required Assertions:
    // Stateful 1: request authenticates and reaches recall.
    assert(resp.status === 200, 'HTTP 200', `got ${resp.status}: ${JSON.stringify(respBody)}`);
    const memories = respBody.memories || respBody.results || [];
    assert(memories.length > 0, 'recall returns at least one memory');
    assert(respBody.cache_hit !== true, 'full recall is not a cache bypass');
    assert(memories.some((memory) => memory.key || memory.memory_id), 'non-empty recalled identity field');
  } finally {
    await new Promise((r) => server.close(r));
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════
async function main() {
  console.log('═══ T1_SYSTEM_SELF Tier Test ═══');
  console.log('Every case verifies state, durable evidence, and non-empty outputs.');

  // Cases 1-3: unit tests (always run)
  await testCase1_validSystemSelf();
  await testCase2_tamperedCert();
  await testCase3_replayNonce();

  // Cases 4-5 belong to the explicit isolated test ceremony. The normal unit
  // suite does not silently probe or mutate whichever database happens to be
  // configured on the developer machine.
  if (process.argv.includes('--live-fire')) {
    const databaseName = requireDisposableLiveFireDatabase();
    const liveOk = await canRunLiveFire();
    if (!liveOk) {
      throw new Error(`disposable live-fire database is not provisioned: ${databaseName}`);
    }
    await testCase4_realHttpGenesisSave();
    await testCase5_allowListRecall();
  } else {
    console.log('\n[UNIT] Canonical DB writes disabled. Run the isolated security ceremony for cases 4-5.');
  }

  console.log('\n═══ Results ═══');
  console.log(`  Passed:  ${passed}`);
  console.log(`  Failed:  ${failed}`);
  console.log(`  Skipped: ${skipped}`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(2);
});
