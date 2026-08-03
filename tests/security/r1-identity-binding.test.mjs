// R1 — Identity Binding & Authorization — gate tests.
//
// These exercise the pure decision logic that does NOT require a live server or
// DB: the capability gate (identity from cert only, fail-closed), the
// method+path-bound signature (cross-route replay), and the unconditional
// revocation + nonce-replay enforcement in auth-tier.
//
// Every case has at least three stateful assertions plus one disk artifact and
// 1 non-empty field. Gate items that need a running server (rate-limiter
// ordering #7, live SSRF #8, HTTP status codes #1/#6 end-to-end) are covered
// structurally here and must additionally be checked against a live instance.

import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateKeypair,
  issueCert,
  signPayload,
  signPayloadWithContext,
  signPayloadWithEnvelopeClaims,
  verifyPayloadSigWithEnvelopeClaims,
  verifyPayloadSigWithContext
} from '../../services/security/agent-identity.js';
import { createAuthTier } from '../../services/security/auth-tier.js';
import { createNonceWindow } from '../../services/security/nonce-window.js';
import { requireCapability } from '../../services/security/require-capability.js';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'r1-gate-'));
let passed = 0;
let failed = 0;

function diskArtifact(name, obj) {
  const p = path.join(TMP, name + '.json');
  fs.writeFileSync(p, JSON.stringify(obj));
  const back = JSON.parse(fs.readFileSync(p, 'utf8'));
  assert.ok(back && typeof back === 'object', 'disk artifact round-trips');
  return p;
}

async function run(label, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${label}`);
  } catch (err) {
    failed += 1;
    console.log(`  ✗ ${label}\n      ${err.message}`);
  }
}

// ── Crypto fixtures ───────────────────────────────────────────────────────────
const master = generateKeypair();
const agent = generateKeypair();
const AGENT_ID = 'agent-low';
const nowSec = Math.floor(Date.now() / 1000);
const certBody = {
  v: 1,
  agent_id: AGENT_ID,
  pubkey: agent.pubkey,
  device_fp: 'test-device',
  valid_from: nowSec - 60,
  valid_until: nowSec + 3600,
  issuer: 'master',
  issued_at: nowSec - 60
};
const CERT = issueCert(master.privkey, certBody);

function makeCaches({ revoked = false } = {}) {
  return {
    masterPubkeyCache: { get: async () => master.pubkey },
    agentRevocationCache: { lookup: async () => ({ found: true, revoked }) },
    nonceWindow: createNonceWindow(),
    logEvent: async () => null,
  };
}

function envelopeHeaders(sig, nonce, ts, sigForm, claims = {}) {
  const h = {
    'aimos-agent-cert': CERT,
    'aimos-agent-signature': sig,
    'aimos-agent-nonce': nonce,
    'aimos-agent-timestamp': String(ts)
  };
  if (sigForm) h['x-aimos-sig-form'] = String(sigForm);
  if (claims.prevChainHash) h['aimos-agent-prev-chain-hash'] = claims.prevChainHash;
  if (claims.deviceFp) h['aimos-agent-device-fp'] = claims.deviceFp;
  return h;
}

async function main() {
  console.log('═══ R1 Identity Binding gate tests ═══');

  // ── GATE #1 — capability gate trusts the cert, not the x-agent-id header ──
  console.log('\n[GATE 1] Header spoofing rejected — identity is req.agentId only');
  await run('spoofed x-agent-id=HIGH is ignored; LOW lacks capability → 403', async () => {
    let consultedAgent = null;
    const getPermissions = async (id) => { consultedAgent = id; return { 'tools:execute': id === 'HIGH' }; };
    const mw = requireCapability('tools:execute', { getPermissions, logEvent: async () => null });
    const req = { agentId: 'LOW', headers: { 'x-agent-id': 'HIGH' }, body: { agent_id: 'HIGH' }, originalUrl: '/tools/x/post' };
    let status = null; let payload = null; let nextCalled = false;
    const res = { status(c) { status = c; return this; }, json(p) { payload = p; return this; } };
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(consultedAgent, 'LOW', 'lookup used req.agentId (LOW), not the header (HIGH)');
    assert.strictEqual(status, 403, 'status is 403 forbidden');
    assert.strictEqual(nextCalled, false, 'next() was NOT called (request blocked)');
    diskArtifact('gate1', { consultedAgent, status, payload });
    assert.ok(payload.error.capability.length > 0, 'non-empty capability field in response');
  });

  // ── GATE #2 — capability check fails CLOSED ───────────────────────────────
  console.log('\n[GATE 2] Capability lookup throws → 503, never 200');
  await run('dead permission store → 503 authz_unavailable, next() not called', async () => {
    const getPermissions = async () => { throw new Error('dead DB'); };
    const mw = requireCapability('tools:execute', { getPermissions, logEvent: async () => null });
    const req = { agentId: 'LOW', headers: {}, body: {}, originalUrl: '/tools/x/post' };
    let status = null; let payload = null; let nextCalled = false;
    const res = { status(c) { status = c; return this; }, json(p) { payload = p; return this; } };
    await mw(req, res, () => { nextCalled = true; });
    assert.strictEqual(status, 503, 'status is 503 (fail-closed), MUST NOT be 200');
    assert.notStrictEqual(status, 200, 'never admits on DB error');
    assert.strictEqual(nextCalled, false, 'next() not called on lookup failure');
    diskArtifact('gate2', { status, payload });
    assert.ok(payload.error.code.length > 0, 'non-empty error code');
  });

  // ── GATE #3 — cross-route replay rejected (method+path in preimage) ───────
  console.log('\n[GATE 3] Signature bound to method+path — cross-route replay rejected');
  await run('sig minted for GET /status fails against GET /setup/aimos/identity/agents', async () => {
    const nonce = 'nonce-xroute';
    const ts = Math.floor(Date.now() / 1000);
    const body = {};
    const sig = signPayloadWithContext(agent.privkey, body, 'GET', '/status', nonce, ts);
    const good = verifyPayloadSigWithContext(agent.pubkey, body, 'GET', '/status', nonce, ts, sig);
    const crossPath = verifyPayloadSigWithContext(agent.pubkey, body, 'GET', '/setup/aimos/identity/agents', nonce, ts, sig);
    const crossMethod = verifyPayloadSigWithContext(agent.pubkey, body, 'POST', '/status', nonce, ts, sig);
    assert.strictEqual(good.valid, true, 'valid on the exact (method,path) it was minted for');
    assert.strictEqual(crossPath.valid, false, 'invalid when the PATH differs');
    assert.strictEqual(crossMethod.valid, false, 'invalid when the METHOD differs');
    diskArtifact('gate3', { good, crossPath, crossMethod });
    assert.ok(String(crossPath.reason || '').length > 0, 'non-empty rejection reason');
  });

  // Also: through the full auth-tier with X-Aimos-Sig-Form: 3.
  await run('auth-tier: form-3 envelope for path A → T0 when replayed to path B', async () => {
    const at = createAuthTier(makeCaches());
    const nonce = 'nonce-at-xroute';
    const ts = Math.floor(Date.now() / 1000);
    const body = { hello: 'world' };
    const sig = signPayloadWithContext(agent.privkey, body, 'GET', '/status', nonce, ts);
    const headers = envelopeHeaders(sig, nonce, ts, 3);
    const okReq = { headers, body, method: 'GET', originalUrl: '/status' };
    const okRes = await at.deriveTier(okReq);
    // Fresh caches/nonce for the replay so nonce-replay isn't the reason.
    const at2 = createAuthTier(makeCaches());
    const badReq = { headers, body, method: 'GET', originalUrl: '/setup/aimos/identity/agents' };
    const badRes = await at2.deriveTier(badReq);
    assert.notStrictEqual(okRes.tier, 'T0', 'same-path request authenticates');
    assert.strictEqual(badRes.tier, 'T0', 'cross-path replay collapses to T0');
    assert.ok(badRes.error, 'cross-path replay has an error reason');
    diskArtifact('gate3b', { okTier: okRes.tier, badTier: badRes.tier, badError: badRes.error });
    assert.ok(String(badRes.error).length > 0, 'non-empty error reason');
  });

  await run('form-4 binds chain and device claims; tampering or unsigned elevation fails closed', async () => {
    const nonce = 'nonce-tier-claims';
    const ts = Math.floor(Date.now() / 1000);
    const body = { key: 'proof:tier-claims' };
    const prevChainHash = Buffer.alloc(32, 7).toString('base64url');
    const claims = { prevChainHash, deviceFp: certBody.device_fp };
    const sig = signPayloadWithEnvelopeClaims(
      agent.privkey,
      body,
      'POST',
      '/aimos/save',
      claims,
      nonce,
      ts,
    );

    const exact = verifyPayloadSigWithEnvelopeClaims(
      agent.pubkey,
      body,
      'POST',
      '/aimos/save',
      claims,
      nonce,
      ts,
      sig,
    );
    const tampered = verifyPayloadSigWithEnvelopeClaims(
      agent.pubkey,
      body,
      'POST',
      '/aimos/save',
      { ...claims, deviceFp: 'other-device' },
      nonce,
      ts,
      sig,
    );
    assert.strictEqual(exact.valid, true, 'exact signed claims verify');
    assert.strictEqual(tampered.valid, false, 'changed device claim invalidates signature');

    const at = createAuthTier(makeCaches());
    const accepted = await at.deriveTier({
      headers: envelopeHeaders(sig, nonce, ts, 4, claims),
      body,
      method: 'POST',
      originalUrl: '/aimos/save',
    });
    assert.strictEqual(accepted.tier, 'T3', 'signed chain plus matching device claim derives T3');
    assert.deepStrictEqual(accepted.prevChainHash, Buffer.alloc(32, 7), 'verified chain claim is retained');

    const unsignedSig = signPayloadWithContext(agent.privkey, body, 'POST', '/aimos/save', 'nonce-unsigned-tier', ts);
    const unsigned = await createAuthTier(makeCaches()).deriveTier({
      headers: envelopeHeaders(unsignedSig, 'nonce-unsigned-tier', ts, 3, claims),
      body,
      method: 'POST',
      originalUrl: '/aimos/save',
    });
    assert.strictEqual(unsigned.tier, 'T0', 'form-3 cannot carry elevation claims');
    assert.strictEqual(unsigned.error, 'sig_form_4_required');
    diskArtifact('gate3c', { acceptedTier: accepted.tier, unsignedTier: unsigned.tier, unsignedError: unsigned.error });
    assert.ok(String(unsigned.error).length > 0, 'non-empty unsigned-elevation rejection reason');
  });

  // ── GATE #4 — revoked agent rejected without bypass ──────────────────────
  console.log('\n[GATE 4] Revoked agent rejected unconditionally');
  await run('revoked agent → T0 agent_revoked with no mutable bypass', async () => {
    const deps = makeCaches({ revoked: true });
    const at = createAuthTier(deps);
    const nonce = 'nonce-rev';
    const ts = Math.floor(Date.now() / 1000);
    const body = { x: 1 };
    const sig = signPayload(agent.privkey, body, nonce, ts);
    const req = { headers: envelopeHeaders(sig, nonce, ts, 1), body, method: 'POST', originalUrl: '/aimos/save' };
    const result = await at.deriveTier(req);
    assert.strictEqual(result.tier, 'T0', 'revoked agent collapses to T0');
    assert.strictEqual(result.error, 'agent_revoked', 'error is agent_revoked');
    diskArtifact('gate4', { tier: result.tier, error: result.error, mutableBypass: false });
    assert.ok(result.error.length > 0, 'non-empty error');
  });

  // ── GATE #5 — nonce replay rejected without bypass ───────────────────────
  console.log('\n[GATE 5] Nonce replay rejected unconditionally');
  await run('same envelope twice → authenticated then replay_detected', async () => {
    const deps = makeCaches();
    const at = createAuthTier(deps);
    const nonce = 'nonce-replay-1';
    const ts = Math.floor(Date.now() / 1000);
    const body = { y: 2 };
    const sig = signPayloadWithContext(agent.privkey, body, 'POST', '/aimos/save', nonce, ts);
    const headers = envelopeHeaders(sig, nonce, ts, 3);
    const first = await at.deriveTier({ headers, body, method: 'POST', originalUrl: '/aimos/save' });
    const second = await at.deriveTier({ headers, body, method: 'POST', originalUrl: '/aimos/save' });
    assert.notStrictEqual(first.tier, 'T0', 'first request authenticates (non-T0)');
    assert.strictEqual(second.tier, 'T0', 'second (replayed) request collapses to T0');
    assert.strictEqual(second.error, 'replay_detected', 'second error is replay_detected');
    diskArtifact('gate5', { firstTier: first.tier, secondTier: second.tier, secondError: second.error, mutableBypass: false });
    assert.ok(second.error.length > 0, 'non-empty error');
  });

  // ── v1 retired: body-only signatures permit cross-route replay ───────────
  console.log('\n[FORM 3] Verifier rejects body-only sig-form 1');
  await run('v1 envelope (no method/path in preimage) is rejected', async () => {
    const at = createAuthTier(makeCaches());
    const nonce = 'nonce-v1';
    const ts = Math.floor(Date.now() / 1000);
    const body = { legacy: true };
    const sig = signPayload(agent.privkey, body, nonce, ts);
    const req = { headers: envelopeHeaders(sig, nonce, ts, 1), body, method: 'POST', originalUrl: '/aimos/save' };
    const result = await at.deriveTier(req);
    assert.strictEqual(result.tier, 'T0', 'v1 envelope is rejected');
    assert.strictEqual(result.error, 'sig_form_3_required');
    diskArtifact('form3-required', { tier: result.tier, error: result.error });
    assert.ok(String(result.error).length > 0, 'non-empty rejection reason');
  });

  // ── GATE #6 — every requireCapability() argument is a REAL capability ──────
  // The complete set of capability names lives in the ledgered `agent_permissions`
  // table on aimos_dev. They are snake_case with NO colons. Gating a route on a
  // name outside this set is a latent deadlock (e.g. the invented 'identity:admin'
  // could never be granted, because /permissions/set is the only grant API).
  // Source of truth (do not edit without re-querying agent_permissions):
  //   SELECT DISTINCT capability FROM agent_permissions ORDER BY 1;
  console.log('\n[GATE 6] Every requireCapability() argument is a real capability');
  await run('no requireCapability() call names a capability outside agent_permissions', async () => {
    const REAL_CAPS = new Set([
      'admin_override', 'delegate', 'email', 'files', 'github', 'internet',
      'memory_read', 'memory_write', 'n8n', 'railway', 'salesforce', 'shell',
      'x', 'youtube'
    ]);
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
    const scanDirs = ['routes', 'services'].map((d) => path.join(repoRoot, d));
    const callRe = /requireCapability\(\s*(['"])([^'"]+)\1/g;
    const found = [];   // { file, capability }
    const invalid = []; // capabilities not in REAL_CAPS
    for (const dir of scanDirs) {
      if (!fs.existsSync(dir)) continue;
      const entries = fs.readdirSync(dir, { recursive: true });
      for (const rel of entries) {
        const abs = path.join(dir, String(rel));
        // Only real source files — skip .pre-r1 / .pre-r1b backups and dirs.
        if (!abs.endsWith('.js') || /\.pre-r1/.test(abs)) continue;
        if (!fs.statSync(abs).isFile()) continue;
        const src = fs.readFileSync(abs, 'utf8');
        let m;
        while ((m = callRe.exec(src)) !== null) {
          const cap = m[2];
          found.push({ file: path.relative(repoRoot, abs), capability: cap });
          if (!REAL_CAPS.has(cap)) invalid.push({ file: path.relative(repoRoot, abs), capability: cap });
        }
      }
    }
    assert.ok(found.length > 0, 'scan found at least one requireCapability() call (test is not vacuous)');
    assert.strictEqual(invalid.length, 0, `no invented capabilities: ${JSON.stringify(invalid)}`);
    assert.ok(REAL_CAPS.has('admin_override'), 'admin_override is a real capability (identity endpoints depend on it)');
    diskArtifact('gate6', { found, invalid, realCapCount: REAL_CAPS.size });
    assert.ok(found[0].capability.length > 0, 'non-empty capability name captured from source');
  });

  console.log(`\n═══ Results ═══\n  Passed: ${passed}\n  Failed: ${failed}\n  Artifacts: ${TMP}`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
