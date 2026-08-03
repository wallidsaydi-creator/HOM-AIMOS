// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — consumed by auth-tier.js (verifyCertChain, verifyPayloadSig for deriveTier), agent-runner test harnesses (signPayload, loadAgentPrivkey, getAgentCert for cert-envelope signing), and the Phase 1.2 canary live test.
// Purpose: Cryptographic identity primitives — Ed25519 keygen, sign, verify,
//          cert issuance, and master→agent cert chain verification
// Wire into: auth-tier.js, save-envelope.js, recall authorization, signed
//            capability authorization, and signed action ledgers.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * agent-identity.js — Cryptographic Identity Primitives
 * Source: RFC 8032 (Ed25519), RFC 8785 (JSON Canonicalization), NIST FIPS 186-5.
 * Phase 10 paper authority: Miller 2006 Robust Composition and Hardy 1988
 * The Confused Deputy. Native Aimos call-site signing follows object-capability
 * discipline: no ambient authority, no HTTP auth wrapper, no interception
 * layer between caller and cryptographic primitive.
 *
 * Formula contract:
 *   signed_message = JCS(body) || "\n" || nonce || "\n" || unix_ts
 *   request_sig    = Ed25519(agent_privkey, signed_message)
 *   cert_envelope  = base64url(JCS({ body, sig: Ed25519(master, JCS(body)) }))
 *
 * Most exports are pure crypto utilities. Phase 10 adds two explicit call-site
 * material primitives, loadAgentPrivkey() and getAgentCert(), so callers can
 * sign native fetch requests inline without introducing an HTTP wrapper.
 * Master key signs agent certs. Agent certs sign per-request payloads.
 * Replay defense (nonce window) lives in Phase 4 auth middleware, not here.
 *
 * Encoding throughout: base64url (RFC 4648 §5). Keys are DER (SPKI public,
 * PKCS8 private) then base64url. Signatures are 64-byte raw Ed25519 then
 * base64url.
 */

import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
  randomBytes,
} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DEFAULT_SKEW_SECONDS = 300;
const CANONICAL_DEPTH_LIMIT = 32;
const _certCache = new Map();

// ═══════════════════════════════════════════════════════════════════════════════
// CANONICAL JSON (RFC 8785 practical subset)
// ═══════════════════════════════════════════════════════════════════════════════
// Sorted object keys (UTF-16 code-unit order), no insignificant whitespace,
// integers and finite floats only, no NaN/Infinity, recursion-depth-limited.
// Strings JSON-escaped; arrays preserve order. Sufficient for cert and payload
// canonicalization within Aimos's domain. Not a full RFC 8785 implementation.

export function canonicalJson(value, depth = 0) {
  if (depth > CANONICAL_DEPTH_LIMIT) {
    throw new Error('canonicalJson: depth limit exceeded');
  }
  if (value === null) return 'null';
  if (value === undefined) {
    throw new Error('canonicalJson: undefined is not serializable');
  }
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalJson: non-finite number');
    }
    return JSON.stringify(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (t === 'bigint') {
    throw new Error('canonicalJson: bigint not supported');
  }
  if (Array.isArray(value)) {
    const parts = value.map(v => canonicalJson(v, depth + 1));
    return '[' + parts.join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k], depth + 1));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalJson: unsupported type ${t}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE64URL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function bufToB64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function b64uToBuf(str) {
  return Buffer.from(str, 'base64url');
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYPAIR GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pubkey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    privkey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url')
  };
}

export function pubkeyFingerprint(pubkeyB64u) {
  const der = b64uToBuf(pubkeyB64u);
  return createHash('sha256').update(der).digest('hex');
}

export function pubkeyEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = b64uToBuf(a);
  const bb = b64uToBuf(b);
  if (ba.length !== bb.length) return false;
  return ba.equals(bb);
}

function loadPub(pubkeyB64u) {
  return createPublicKey({
    key: b64uToBuf(pubkeyB64u),
    format: 'der',
    type: 'spki'
  });
}

function loadPriv(privkeyB64u) {
  return createPrivateKey({
    key: b64uToBuf(privkeyB64u),
    format: 'der',
    type: 'pkcs8'
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALL-SITE MATERIAL PRIMITIVES (PHASE 10)
// ═══════════════════════════════════════════════════════════════════════════════

function expandHome(inputPath) {
  const raw = String(inputPath || '').trim();
  if (!raw) throw new Error('path must be non-empty');
  if (raw === '~') return os.homedir();
  if (raw.startsWith('~/')) return path.join(os.homedir(), raw.slice(2));
  return raw;
}

export function loadAgentPrivkey(keyPath) {
  if (!keyPath) throw new Error('loadAgentPrivkey: keyPath is required (no default)');
  const resolved = expandHome(keyPath);
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new Error(`loadAgentPrivkey: key not found at ${resolved}`);
  }

  if (!stat.isFile()) {
    throw new Error(`loadAgentPrivkey: key path is not a file: ${resolved}`);
  }

  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  if (uid !== null && stat.uid !== uid) {
    throw new Error('loadAgentPrivkey: key file must be owned by the current user');
  }

  const mode = stat.mode & 0o777;
  if (mode !== 0o600) {
    throw new Error(`loadAgentPrivkey: key file mode must be 0600, got 0${mode.toString(8)}`);
  }

  const privkey = fs.readFileSync(resolved, 'utf8').trim();
  if (!privkey) {
    throw new Error('loadAgentPrivkey: key file is empty');
  }
  return privkey;
}

function writeCertCacheFile(cachePath, cert, expiresAtMs) {
  if (!cachePath) return;
  const resolved = expandHome(cachePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    resolved,
    JSON.stringify({ cert, expires_at_ms: expiresAtMs || null }) + '\n',
    { mode: 0o600 }
  );
}

export async function getAgentCert(agentId, opts = {}) {
  const id = String(agentId || '').trim();
  if (!id) throw new Error('getAgentCert: agentId is required (no default)');

  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Date.now();
  const nowMs = nowFn();
  const cacheKey = `${id}|${opts.cachePath || ''}`;

  const queryFn = typeof opts.queryFn === 'function'
    ? opts.queryFn
    : (await import('../../db/connection.js')).query;
  const result = await queryFn(
    `SELECT identity.agent_id, identity.cert, identity.pubkey,
            identity.valid_from AS agent_valid_from, identity.valid_until,
            revocation.master_fingerprint, revocation.target_cert_hash,
            revocation.prior_identity_hash, revocation.signed_body,
            revocation.content_hash, revocation.mutation_hash,
            revocation.ts_signed, revocation.nonce, revocation.sig,
            master.master_pubkey,
            master.fingerprint AS enrolled_master_fingerprint
       FROM agent_identity identity
       LEFT JOIN aimos_agent_revocation_events revocation
         ON revocation.agent_id = identity.agent_id
        AND revocation.agent_valid_from = identity.valid_from
       LEFT JOIN aimos_master_identity master
         ON master.id = COALESCE(revocation.master_identity_id, 1)
      WHERE identity.agent_id = $1
      ORDER BY identity.valid_from DESC`,
    [id]
  );
  for (const row of result?.rows || []) {
    if (!row?.cert || !row?.pubkey) continue;
    const cert = String(row.cert);
    let certBody = null;
    try {
      certBody = JSON.parse(Buffer.from(cert, 'base64url').toString('utf8'))?.body || null;
    } catch {
      throw new Error('getAgentCert: cert_malformed');
    }
    const rootPubkey = certBody?.issuer === id ? row.pubkey : row.master_pubkey;
    if (!rootPubkey) throw new Error('getAgentCert: certificate_authority_missing');
    const certProof = verifyCertChain(cert, rootPubkey, { nowFn: () => Math.floor(nowMs / 1000) });
    const validFromUnix = Math.floor(new Date(row.agent_valid_from).getTime() / 1000);
    const validUntilUnix = Math.floor(new Date(row.valid_until).getTime() / 1000);
    if (
      !certProof.valid
      || certProof.body?.agent_id !== id
      || certProof.body?.pubkey !== row.pubkey
      || Number(certProof.body?.valid_from) !== validFromUnix
      || Number(certProof.body?.valid_until) !== validUntilUnix
    ) {
      throw new Error(`getAgentCert: certificate_invalid:${certProof.reason || 'identity_mismatch'}`);
    }
    if (row.signed_body) {
      if (!row.master_pubkey || row.master_fingerprint !== row.enrolled_master_fingerprint) {
        throw new Error('getAgentCert: revocation_proof_invalid');
      }
      const revocationProof = verifyAgentRevocationProof(row, row.master_pubkey, cert);
      if (!revocationProof.valid) throw new Error(`getAgentCert: revocation_proof_invalid:${revocationProof.reason}`);
      continue;
    }
    const expiresAtMs = new Date(row.valid_until).getTime();
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) continue;
    _certCache.set(cacheKey, { cert, expiresAtMs });
    writeCertCacheFile(opts.cachePath, cert, expiresAtMs);
    return cert;
  }
  throw new Error(`getAgentCert: no active cert for agent ${id}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAYLOAD SIGN / VERIFY
// ═══════════════════════════════════════════════════════════════════════════════

function buildSignedMessage(body, nonce, ts) {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new Error('signPayload: nonce must be non-empty string');
  }
  if (!Number.isInteger(ts)) {
    throw new Error('signPayload: ts must be integer unix seconds');
  }
  return canonicalJson(body) + '\n' + nonce + '\n' + String(ts);
}

export function signPayload(privkeyB64u, body, nonce, ts) {
  const priv = loadPriv(privkeyB64u);
  const msg = Buffer.from(buildSignedMessage(body, nonce, ts), 'utf8');
  const sig = cryptoSign(null, msg, priv);
  return bufToB64u(sig);
}

// Detached Ed25519 signature over RAW bytes (no envelope, no canonicalization).
// Used for signing a fixed-width value (e.g. a 32-byte content_hash) so the
// signature is verifiable in-DB via pgsodium.crypto_sign_verify_detached without
// reproducing JSON canonicalization. Returns the 64-byte sig as a Buffer.
export function signRaw(privkeyB64u, messageBuffer) {
  if (!Buffer.isBuffer(messageBuffer)) {
    throw new Error('signRaw: messageBuffer must be a Buffer');
  }
  return cryptoSign(null, messageBuffer, loadPriv(privkeyB64u));
}

// ─── v2 sig canonical form (backfill ceremony + future live writes) ─────────
// v2 folds memory_originated_at_unix into the signed preimage so the time
// origin time is cryptographically bound rather than merely stored as mutable
// metadata. This is the canonical form used by the provenance backfill.
//
// v2 = canonicalJson(body) || '\n' || nonce || '\n' || String(ts) || '\n' || String(memory_originated_at_unix)
// Used by scripts/backfill-ledger-reviewer.mjs for the 18,998 P-anchor
// re-attestation rows. v1 stays the live /save path (ts_signed ≈
// memory_originated_at for new writes, so v1 already binds the time axis
// there). The verify path branches on the row's sig_form_version column.

function buildSignedMessageV2(body, nonce, ts, memoryOriginatedAtUnix) {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new Error('signPayloadV2: nonce must be non-empty string');
  }
  if (!Number.isInteger(ts)) {
    throw new Error('signPayloadV2: ts must be integer unix seconds');
  }
  if (!Number.isInteger(memoryOriginatedAtUnix)) {
    throw new Error('signPayloadV2: memoryOriginatedAtUnix must be integer unix seconds');
  }
  return canonicalJson(body) + '\n' + nonce + '\n' + String(ts) + '\n' + String(memoryOriginatedAtUnix);
}

export function signPayloadV2(privkeyB64u, body, nonce, ts, memoryOriginatedAtUnix) {
  const priv = loadPriv(privkeyB64u);
  const msg = Buffer.from(buildSignedMessageV2(body, nonce, ts, memoryOriginatedAtUnix), 'utf8');
  const sig = cryptoSign(null, msg, priv);
  return bufToB64u(sig);
}

export function verifyPayloadSigV2(pubkeyB64u, body, nonce, ts, memoryOriginatedAtUnix, sigB64u, opts = {}) {
  const skew = Number.isFinite(opts.skewSeconds) ? opts.skewSeconds : DEFAULT_SKEW_SECONDS;
  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);

  if (!Number.isInteger(ts)) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (!Number.isInteger(memoryOriginatedAtUnix)) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof sigB64u !== 'string' || sigB64u.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }

  const now = nowFn();
  if (Math.abs(now - ts) > skew) {
    return { valid: false, reason: 'clock_skew' };
  }

  let pub, msg, sig;
  try {
    pub = loadPub(pubkeyB64u);
    msg = Buffer.from(buildSignedMessageV2(body, nonce, ts, memoryOriginatedAtUnix), 'utf8');
    sig = b64uToBuf(sigB64u);
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }

  let ok = false;
  try {
    ok = cryptoVerify(null, msg, pub, sig);
  } catch {
    return { valid: false, reason: 'sig_invalid' };
  }
  return ok ? { valid: true, reason: null } : { valid: false, reason: 'sig_invalid' };
}

// ─── R1 Step 2: method+path-bound preimage (X-Aimos-Sig-Form 3) ─────────────
// Defect: the sig-form-1 preimage signs only JCS(body)+nonce+ts, so a captured
// envelope replays across ANY route/method. Sig-form 3 folds the HTTP METHOD
// and PATH into the signed bytes so a signature is valid only for the exact
// (method, path) it was minted for.
//
// form-3 = JCS(body) || "\n" || METHOD || "\n" || PATH || "\n" || nonce || "\n" || String(ts)
//
// ⚠ NAMESPACE SEPARATION (do not conflate): `sig_form_version` (a DB column on
// aimos_memory_provenance rows, migration 027) and `X-Aimos-Sig-Form` (an HTTP
// request-envelope header) are SEPARATE namespaces. The numeral 2 is RESERVED
// by the provenance ledger — it means buildSignedMessageV2 (JCS(body)+nonce+ts+
// memory_originated_at_unix), a different subsystem (see below). Request
// envelopes use ONLY forms 1 and 3. Never emit or accept X-Aimos-Sig-Form: 2.
//
// PATH contract (write it down — ambiguity here is a bypass surface):
//   PATH is the request PATHNAME with the query string REMOVED
//   (i.e. req.originalUrl split on '?'[0]). The query string is NOT signed.
//   METHOD is upper-cased.
//
// Rollout is staged (H10). Stage N (this change): the verifier accepts form 1
// OR form 3; signers still emit form 1 and advertise it via X-Aimos-Sig-Form.
// Do NOT flip signers to form-3-only until every signer emits form 3.
function normalizeSigContext(method, path) {
  const m = String(method || '').toUpperCase();
  let p = String(path || '');
  const qIdx = p.indexOf('?');
  if (qIdx !== -1) p = p.slice(0, qIdx);
  return { method: m, path: p };
}

function buildSignedMessageWithContext(body, method, path, nonce, ts) {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new Error('signPayloadWithContext: nonce must be non-empty string');
  }
  if (!Number.isInteger(ts)) {
    throw new Error('signPayloadWithContext: ts must be integer unix seconds');
  }
  const { method: m, path: p } = normalizeSigContext(method, path);
  if (!m) throw new Error('signPayloadWithContext: method is required');
  if (!p) throw new Error('signPayloadWithContext: path is required');
  return canonicalJson(body) + '\n' + m + '\n' + p + '\n' + nonce + '\n' + String(ts);
}

export function signPayloadWithContext(privkeyB64u, body, method, path, nonce, ts) {
  const priv = loadPriv(privkeyB64u);
  const msg = Buffer.from(buildSignedMessageWithContext(body, method, path, nonce, ts), 'utf8');
  const sig = cryptoSign(null, msg, priv);
  return bufToB64u(sig);
}

export function verifyPayloadSigWithContext(pubkeyB64u, body, method, path, nonce, ts, sigB64u, opts = {}) {
  const skew = Number.isFinite(opts.skewSeconds) ? opts.skewSeconds : DEFAULT_SKEW_SECONDS;
  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);

  if (!Number.isInteger(ts)) return { valid: false, reason: 'malformed_input' };
  if (typeof nonce !== 'string' || nonce.length === 0) return { valid: false, reason: 'malformed_input' };
  if (typeof sigB64u !== 'string' || sigB64u.length === 0) return { valid: false, reason: 'malformed_input' };

  const now = nowFn();
  if (Math.abs(now - ts) > skew) return { valid: false, reason: 'clock_skew' };

  let pub, msg, sig;
  try {
    pub = loadPub(pubkeyB64u);
    msg = Buffer.from(buildSignedMessageWithContext(body, method, path, nonce, ts), 'utf8');
    sig = b64uToBuf(sigB64u);
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }

  let ok = false;
  try {
    ok = cryptoVerify(null, msg, pub, sig);
  } catch {
    return { valid: false, reason: 'sig_invalid' };
  }
  return ok ? { valid: true, reason: null } : { valid: false, reason: 'sig_invalid' };
}

// ─── Request envelope form 4: signed chain/device claims ────────────────────
// Form 3 binds body + HTTP method + pathname. Form 4 additionally binds the
// claims that elevate an authenticated request from T1 to T2/T3. Keeping this
// as a distinct preimage prevents an unsigned header from changing identity
// tier while preserving form 3 for requests that make no chain commitment.
//
// form-4 = JCS(body) || "\n" || METHOD || "\n" || PATH || "\n" ||
//          JCS({ prev_chain_hash, device_fp }) || "\n" || nonce || "\n" || ts
function buildSignedMessageWithEnvelopeClaims(body, method, path, claims, nonce, ts) {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new Error('signPayloadWithEnvelopeClaims: nonce must be non-empty string');
  }
  if (!Number.isInteger(ts)) {
    throw new Error('signPayloadWithEnvelopeClaims: ts must be integer unix seconds');
  }
  const { method: m, path: p } = normalizeSigContext(method, path);
  if (!m) throw new Error('signPayloadWithEnvelopeClaims: method is required');
  if (!p) throw new Error('signPayloadWithEnvelopeClaims: path is required');

  const prevChainHash = claims?.prevChainHash ?? claims?.prev_chain_hash ?? null;
  const deviceFp = claims?.deviceFp ?? claims?.device_fp ?? null;
  if (typeof prevChainHash !== 'string' || prevChainHash.length === 0) {
    throw new Error('signPayloadWithEnvelopeClaims: prev_chain_hash is required');
  }
  if (deviceFp !== null && (typeof deviceFp !== 'string' || deviceFp.length === 0)) {
    throw new Error('signPayloadWithEnvelopeClaims: device_fp must be a non-empty string');
  }
  const signedClaims = {
    prev_chain_hash: prevChainHash,
    device_fp: deviceFp,
  };
  return canonicalJson(body) + '\n' + m + '\n' + p + '\n' + canonicalJson(signedClaims) + '\n' + nonce + '\n' + String(ts);
}

export function signPayloadWithEnvelopeClaims(privkeyB64u, body, method, path, claims, nonce, ts) {
  const priv = loadPriv(privkeyB64u);
  const msg = Buffer.from(buildSignedMessageWithEnvelopeClaims(body, method, path, claims, nonce, ts), 'utf8');
  const sig = cryptoSign(null, msg, priv);
  return bufToB64u(sig);
}

export function verifyPayloadSigWithEnvelopeClaims(pubkeyB64u, body, method, path, claims, nonce, ts, sigB64u, opts = {}) {
  const skew = Number.isFinite(opts.skewSeconds) ? opts.skewSeconds : DEFAULT_SKEW_SECONDS;
  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);

  if (!Number.isInteger(ts)) return { valid: false, reason: 'malformed_input' };
  if (typeof nonce !== 'string' || nonce.length === 0) return { valid: false, reason: 'malformed_input' };
  if (typeof sigB64u !== 'string' || sigB64u.length === 0) return { valid: false, reason: 'malformed_input' };
  if (Math.abs(nowFn() - ts) > skew) return { valid: false, reason: 'clock_skew' };

  let pub, msg, sig;
  try {
    pub = loadPub(pubkeyB64u);
    msg = Buffer.from(buildSignedMessageWithEnvelopeClaims(body, method, path, claims, nonce, ts), 'utf8');
    sig = b64uToBuf(sigB64u);
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }

  try {
    return cryptoVerify(null, msg, pub, sig)
      ? { valid: true, reason: null }
      : { valid: false, reason: 'sig_invalid' };
  } catch {
    return { valid: false, reason: 'sig_invalid' };
  }
}

function verifyPayloadSigIntegrity(pubkeyB64u, body, nonce, ts, sigB64u) {
  if (!Number.isInteger(ts)) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof sigB64u !== 'string' || sigB64u.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }

  let pub, msg, sig;
  try {
    pub = loadPub(pubkeyB64u);
    msg = Buffer.from(buildSignedMessage(body, nonce, ts), 'utf8');
    sig = b64uToBuf(sigB64u);
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }

  let ok = false;
  try {
    ok = cryptoVerify(null, msg, pub, sig);
  } catch {
    return { valid: false, reason: 'sig_invalid' };
  }
  return ok ? { valid: true, reason: null } : { valid: false, reason: 'sig_invalid' };
}

/**
 * Verify a signature stored in an append-only ledger.
 *
 * Persisted signatures prove integrity and do not expire merely because wall
 * time advanced. Request freshness/replay remains the responsibility of
 * verifyPayloadSig(), which retains its bounded clock-skew check.
 */
export function verifyStoredPayloadSig(pubkeyB64u, body, nonce, ts, sigB64u) {
  return verifyPayloadSigIntegrity(pubkeyB64u, body, nonce, ts, sigB64u);
}

/** Verify a stored provenance-v2 signature without applying request freshness. */
export function verifyStoredPayloadSigV2(pubkeyB64u, body, nonce, ts, memoryOriginatedAtUnix, sigB64u) {
  try {
    const pub = loadPub(pubkeyB64u);
    const msg = Buffer.from(buildSignedMessageV2(body, nonce, ts, memoryOriginatedAtUnix), 'utf8');
    const sig = b64uToBuf(sigB64u);
    return cryptoVerify(null, msg, pub, sig)
      ? { valid: true, reason: null }
      : { valid: false, reason: 'sig_invalid' };
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }
}

/** Verify a stored form-3 request signature without applying request freshness. */
export function verifyStoredPayloadSigWithContext(pubkeyB64u, body, method, path, nonce, ts, sigB64u) {
  try {
    const pub = loadPub(pubkeyB64u);
    const msg = Buffer.from(buildSignedMessageWithContext(body, method, path, nonce, ts), 'utf8');
    const sig = b64uToBuf(sigB64u);
    return cryptoVerify(null, msg, pub, sig)
      ? { valid: true, reason: null }
      : { valid: false, reason: 'sig_invalid' };
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }
}

/** Verify a stored form-4 request signature without applying request freshness. */
export function verifyStoredPayloadSigWithEnvelopeClaims(pubkeyB64u, body, method, path, claims, nonce, ts, sigB64u) {
  try {
    const pub = loadPub(pubkeyB64u);
    const msg = Buffer.from(buildSignedMessageWithEnvelopeClaims(body, method, path, claims, nonce, ts), 'utf8');
    const sig = b64uToBuf(sigB64u);
    return cryptoVerify(null, msg, pub, sig)
      ? { valid: true, reason: null }
      : { valid: false, reason: 'sig_invalid' };
  } catch {
    return { valid: false, reason: 'malformed_input' };
  }
}

const AGENT_REVOCATION_SCHEMA = 'hom.aimos.agent-revocation/v1';
const AGENT_REVOCATION_DOMAIN = Buffer.from('aimos-agent-revocation-v1\0', 'utf8');

function sha256Buffer(value) {
  return createHash('sha256').update(value).digest();
}

function normalizeRevocationReason(reasonCode) {
  const value = String(reasonCode || 'operator_revoked').trim().toLowerCase();
  if (!/^[a-z0-9:_-]{1,64}$/.test(value)) {
    throw new Error('createAgentRevocationProof: invalid reason_code');
  }
  return value;
}

export function createAgentRevocationProof(masterPrivkeyB64u, {
  agentId,
  agentValidFrom,
  targetCert,
  masterFingerprint,
  reasonCode = 'operator_revoked',
}, opts = {}) {
  const id = String(agentId || '').trim();
  const validFrom = new Date(agentValidFrom);
  const cert = String(targetCert || '');
  const masterFp = String(masterFingerprint || '').toLowerCase();
  if (!id) throw new Error('createAgentRevocationProof: agent_id is required');
  if (!Number.isFinite(validFrom.getTime())) throw new Error('createAgentRevocationProof: agent_valid_from is invalid');
  if (!cert) throw new Error('createAgentRevocationProof: target cert is required');
  if (!/^[0-9a-f]{64}$/.test(masterFp)) throw new Error('createAgentRevocationProof: master fingerprint is invalid');

  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);
  const nonceFn = typeof opts.nonceFn === 'function' ? opts.nonceFn : () => randomBytes(16).toString('base64url');
  const signedTs = Number(nowFn());
  const nonce = String(nonceFn());
  if (!Number.isInteger(signedTs) || signedTs <= 0) throw new Error('createAgentRevocationProof: signed timestamp is invalid');
  if (!nonce) throw new Error('createAgentRevocationProof: nonce is required');

  const targetCertHash = sha256Buffer(Buffer.from(cert, 'utf8'));
  const priorIdentityHash = sha256Buffer(Buffer.from(canonicalJson({
    agent_id: id,
    agent_valid_from: validFrom.toISOString(),
    target_cert_hash: targetCertHash.toString('hex'),
  }), 'utf8'));
  const body = {
    schema: AGENT_REVOCATION_SCHEMA,
    event_type: 'REVOKE_AGENT_IDENTITY',
    agent_id: id,
    agent_valid_from: validFrom.toISOString(),
    target_cert_hash: targetCertHash.toString('hex'),
    prior_identity_hash: priorIdentityHash.toString('hex'),
    master_fingerprint: masterFp,
    reason_code: normalizeRevocationReason(reasonCode),
    revoked_at: new Date(signedTs * 1000).toISOString(),
  };
  const contentHash = sha256Buffer(Buffer.from(canonicalJson(body), 'utf8'));
  const sigB64u = signPayload(masterPrivkeyB64u, body, nonce, signedTs);
  const sigBytes = Buffer.from(sigB64u, 'base64url');
  const mutationHash = sha256Buffer(Buffer.concat([
    AGENT_REVOCATION_DOMAIN,
    priorIdentityHash,
    contentHash,
    sigBytes,
  ]));
  return {
    body,
    contentHash,
    priorIdentityHash,
    mutationHash,
    targetCertHash,
    signedTs,
    nonce,
    sigBytes,
    sigB64u,
  };
}

export function verifyAgentRevocationProof(row, masterPubkeyB64u, targetCert) {
  try {
    const body = typeof row?.signed_body === 'string' ? JSON.parse(row.signed_body) : row?.signed_body;
    if (!body || body.schema !== AGENT_REVOCATION_SCHEMA || body.event_type !== 'REVOKE_AGENT_IDENTITY') {
      return { valid: false, reason: 'revocation_body_invalid' };
    }
    const targetCertHash = sha256Buffer(Buffer.from(String(targetCert || ''), 'utf8'));
    const priorIdentityHash = sha256Buffer(Buffer.from(canonicalJson({
      agent_id: String(body.agent_id),
      agent_valid_from: new Date(body.agent_valid_from).toISOString(),
      target_cert_hash: targetCertHash.toString('hex'),
    }), 'utf8'));
    const contentHash = sha256Buffer(Buffer.from(canonicalJson(body), 'utf8'));
    const sigBytes = Buffer.from(row.sig);
    const mutationHash = sha256Buffer(Buffer.concat([
      AGENT_REVOCATION_DOMAIN,
      priorIdentityHash,
      contentHash,
      sigBytes,
    ]));
    const rowEpoch = new Date(row.agent_valid_from).toISOString();
    const exactFields = body.agent_id === row.agent_id
      && new Date(body.agent_valid_from).toISOString() === rowEpoch
      && body.target_cert_hash === targetCertHash.toString('hex')
      && body.prior_identity_hash === priorIdentityHash.toString('hex')
      && body.master_fingerprint === row.master_fingerprint
      && Buffer.from(row.target_cert_hash).equals(targetCertHash)
      && Buffer.from(row.prior_identity_hash).equals(priorIdentityHash)
      && Buffer.from(row.content_hash).equals(contentHash)
      && Buffer.from(row.mutation_hash).equals(mutationHash)
      && Number(row.ts_signed) === Math.floor(new Date(body.revoked_at).getTime() / 1000);
    if (!exactFields) return { valid: false, reason: 'revocation_hash_mismatch' };
    const sig = verifyStoredPayloadSig(
      masterPubkeyB64u,
      body,
      String(row.nonce),
      Number(row.ts_signed),
      sigBytes.toString('base64url'),
    );
    return sig.valid ? { valid: true, reason: null } : { valid: false, reason: sig.reason };
  } catch {
    return { valid: false, reason: 'revocation_proof_malformed' };
  }
}

export function verifyPayloadSig(pubkeyB64u, body, nonce, ts, sigB64u, opts = {}) {
  const skew = Number.isFinite(opts.skewSeconds) ? opts.skewSeconds : DEFAULT_SKEW_SECONDS;
  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);

  if (!Number.isInteger(ts)) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }
  if (typeof sigB64u !== 'string' || sigB64u.length === 0) {
    return { valid: false, reason: 'malformed_input' };
  }

  const now = nowFn();
  if (Math.abs(now - ts) > skew) {
    return { valid: false, reason: 'clock_skew' };
  }

  return verifyPayloadSigIntegrity(pubkeyB64u, body, nonce, ts, sigB64u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CERT ISSUANCE / CHAIN VERIFY
// ═══════════════════════════════════════════════════════════════════════════════
// Cert envelope: base64url(canonicalJson({ body, sig })) where sig is a
// base64url Ed25519 signature over canonicalJson(body) using the master key.
// Chain depth is fixed at 1 (master → agent) in this design.

const CERT_REQUIRED_FIELDS = [
  'v', 'agent_id', 'pubkey', 'device_fp',
  'valid_from', 'valid_until', 'issuer', 'issued_at'
];

export function issueCert(masterPrivkeyB64u, body) {
  for (const f of CERT_REQUIRED_FIELDS) {
    if (!(f in body)) throw new Error(`issueCert: missing field ${f}`);
  }
  if (body.v !== 1) throw new Error('issueCert: only v=1 supported');
  if (!Number.isInteger(body.valid_from) || !Number.isInteger(body.valid_until)) {
    throw new Error('issueCert: valid_from/valid_until must be integer unix seconds');
  }
  if (body.valid_until <= body.valid_from) {
    throw new Error('issueCert: valid_until must be after valid_from');
  }

  const priv = loadPriv(masterPrivkeyB64u);
  const canonicalBody = canonicalJson(body);
  const sig = cryptoSign(null, Buffer.from(canonicalBody, 'utf8'), priv);
  const envelope = { body, sig: bufToB64u(sig) };
  return Buffer.from(canonicalJson(envelope), 'utf8').toString('base64url');
}

export function verifyCertChain(certB64u, masterPubkeyB64u, opts = {}) {
  const nowFn = typeof opts.nowFn === 'function' ? opts.nowFn : () => Math.floor(Date.now() / 1000);

  let envelope;
  try {
    const json = b64uToBuf(certB64u).toString('utf8');
    envelope = JSON.parse(json);
  } catch {
    return { valid: false, reason: 'cert_malformed', body: null };
  }

  if (!envelope || typeof envelope !== 'object' || !envelope.body || typeof envelope.sig !== 'string') {
    return { valid: false, reason: 'cert_malformed', body: null };
  }

  const body = envelope.body;
  for (const f of CERT_REQUIRED_FIELDS) {
    if (!(f in body)) {
      return { valid: false, reason: 'cert_schema', body: null };
    }
  }

  let pub, msg, sig;
  try {
    pub = loadPub(masterPubkeyB64u);
    msg = Buffer.from(canonicalJson(body), 'utf8');
    sig = b64uToBuf(envelope.sig);
  } catch {
    return { valid: false, reason: 'cert_malformed', body: null };
  }

  let ok = false;
  try {
    ok = cryptoVerify(null, msg, pub, sig);
  } catch {
    return { valid: false, reason: 'cert_sig_invalid', body: null };
  }
  if (!ok) return { valid: false, reason: 'cert_sig_invalid', body: null };

  const now = nowFn();
  if (now < body.valid_from) {
    return { valid: false, reason: 'cert_not_yet_valid', body };
  }
  if (now > body.valid_until) {
    return { valid: false, reason: 'cert_expired', body };
  }

  return { valid: true, reason: null, body };
}
