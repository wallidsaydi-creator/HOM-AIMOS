// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: LIVE — single source of truth for the housekeeper system operational
// identity. Signs server-side commits to aimos_memory_provenance for:
//   . governor REWEIGHT events (cohen-grossberg + oja governors)
//   . governor config ledger toggles (governor-config-ledger.js)
//   . /heartbeat, /log-event, /reasoning-state, MCP aimos_save (Task 6-9)
//   . background jobs (heartbeat, nightly-dream, boot-integrity, etc.)
// Housekeeper is the non-user-enrollable system operational identity
// provisioned at deployment.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * housekeeper-signer.js — single source of truth for the housekeeper identity
 *
 * The housekeeper is the system's own agent — immutable, not user-enrollable,
 * tied to the system, manages the runtime (mutation, dreams, ledger, reasoning).
 * All server-side commits to aimos_memory_provenance that are not
 * user-initiated /save are signed by the housekeeper.
 *
 * Keypair continuity: the housekeeper privkey file at
 * `~/.aimos/agents/housekeeper.key` is retained with mode 0600. Existing key
 * material is reused so the certificate chain and signed history stay valid.
 *
 * The private-key path is
 * `os.homedir() + '/.aimos/agents/housekeeper.key'`, NEVER .env / process.env.
 * Passphrase via keychain or interactive prompt at server boot (same pattern
 * as aimos_flag_signer + the original housekeeper).
 *
 * Fail-closed behavior:
 *   If the housekeeper privkey/cert is missing (deployment bootstrap not yet
 *   run), the signer throws. State-owning callers must abort or roll back the
 *   corresponding mutation; diagnostic callers may omit only their diagnostic
 *   event. An unsigned canonical action is never allowed to become live.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { loadAgentPrivkey, signPayload, signPayloadWithContext, getAgentCert, signRaw } from './agent-identity.js';
import { cognitiveBaselineHash, cognitiveTransitionHash } from './protocol/mutmem-protocol.js';

export const HOUSEKEEPER_SIGNER_CONSTANTS = Object.freeze({
  HOUSEKEEPER_AGENT_ID: 'housekeeper',
  HOUSEKEEPER_KEY_PATH: path.join(os.homedir(), '.aimos', 'agents', 'housekeeper.key'),
  IDENTITY_TIER_MASTER_SIGNED: 'T1',           // housekeeper cert signed by user master
  IDENTITY_TIER_SELF_SIGNED: 'T1_SYSTEM_SELF'  // housekeeper self-signed (genesis / pre-master)
});

// Detect tier from the loaded cert. A self-signed housekeeper cert
// (issuer === 'housekeeper') is the bootstrap / system-write lane →
// T1_SYSTEM_SELF. Once the housekeeper cert is re-signed under the user
// master (issuer === master fingerprint / agent_id !== 'housekeeper'), the
// signer reports T1. The HTTP /save path uses req.identityTier set by
// auth-gate (authoritative); this is for non-HTTP callers (jobs, governors).
export function detectTierFromCert(certString) {
  try {
    const env = JSON.parse(Buffer.from(certString, 'base64url').toString('utf8'));
    const body = env?.body || env;
    return (body?.agent_id === 'housekeeper' && body?.issuer === 'housekeeper')
      ? HOUSEKEEPER_SIGNER_CONSTANTS.IDENTITY_TIER_SELF_SIGNED
      : HOUSEKEEPER_SIGNER_CONSTANTS.IDENTITY_TIER_MASTER_SIGNED;
  } catch {
    return HOUSEKEEPER_SIGNER_CONSTANTS.IDENTITY_TIER_MASTER_SIGNED;
  }
}

// In-memory cache — privkey + cert are loaded once per process. The privkey
// is the decrypted Ed25519 seed; the cert is the JSON envelope string.
let cachedPrivkey = null;
let cachedCertString = null;
let cachedValidFromIso = null;

/**
 * Load the housekeeper privkey from disk (cached after first call).
 * The path is derived from os.homedir(),
 * NEVER from process.env. Passphrase prompt handled inside loadAgentPrivkey
 * (keychain or interactive).
 *
 * @returns {string} privkeyB64u — base64url Ed25519 seed
 * @throws  {Error} if privkey file missing / unreadable / wrong format
 */
export function loadHousekeeperPrivkey() {
  if (cachedPrivkey) return cachedPrivkey;
  cachedPrivkey = loadAgentPrivkey(HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_KEY_PATH);
  return cachedPrivkey;
}

export function signCognitiveTransitionAsHousekeeper(transition) {
  const transitionHash = cognitiveTransitionHash(transition);
  return Object.freeze({
    transitionHash,
    transitionSig: signRaw(loadHousekeeperPrivkey(), transitionHash),
  });
}

export function signCognitiveBaselineAsHousekeeper(baseline) {
  const baselineHash = cognitiveBaselineHash(baseline);
  return Object.freeze({
    baselineHash,
    baselineSig: signRaw(loadHousekeeperPrivkey(), baselineHash),
  });
}

/**
 * Fetch the current non-revoked housekeeper cert from agent_identity.
 *
 * Authoritative signing deliberately rechecks the identity epoch on every
 * call. An in-process certificate cache would allow post-revocation signing
 * until restart and would make restart, rather than the ledger, the boundary.
 *
 * @returns {Promise<string>} certString — JSON envelope with valid_from + pubkey
 * @throws  {Error} if cert not enrolled (deployment bootstrap not run)
 */
export async function getHousekeeperCert(options = {}) {
  cachedCertString = await getAgentCert(
    HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
    options,
  );
  return cachedCertString;
}

/**
 * Extract validFromIso from a housekeeper cert JSON envelope.
 * Used by commitProvenance to record the agent_id + valid_from.
 */
export function extractValidFromIso(certString) {
  try {
    const serialized = String(certString || '');
    let certJson;
    try {
      certJson = JSON.parse(serialized);
    } catch {
      certJson = JSON.parse(Buffer.from(serialized, 'base64url').toString('utf8'));
    }
    const claims = certJson?.body || certJson;
    if (claims?.valid_from != null) {
      const raw = Number(claims.valid_from);
      return new Date(raw < 10_000_000_000 ? raw * 1000 : raw).toISOString();
    }
    if (claims?.iat != null) return new Date(Number(claims.iat) * 1000).toISOString();
  } catch { /* fall through */ }
  throw new Error('housekeeper certificate has no parseable valid_from epoch');
}

/**
 * Sign a payload as the housekeeper. Returns everything commitProvenance needs.
 *
 * IMPORTANT: this MUTATES the passed body object to set `body.ts_signed` to
 * the signature timestamp BEFORE signing. The sig covers JCS(body) || nonce
 * || signedTs where body.ts_signed === signedTs. Callers must NOT set
 * ts_signed on the body before calling this — pass a body without ts_signed
 * (or with it absent) and let this function populate it. The returned body
 * is the same object that was signed (with ts_signed now populated), safe to
 * pass to commitProvenance as both `body` and `bodyJson`.
 *
 * @param {object} body — JSON-canonicalized + signed. Must NOT have ts_signed
 *                       pre-set (this function sets it).
 * @returns {Promise<{ sigBytes: Buffer, sigB64u: string, signedTs: number, nonce: string,
 *                     certString: string, validFromIso: string, agentId: string,
 *                     identityTier: string, body: object }>}
 * @throws  {Error} if privkey/cert missing or signing fails
 */
export async function signAsHousekeeper(body, requestContext = null) {
  const privkey = loadHousekeeperPrivkey();
  const certString = await getHousekeeperCert();
  const validFromIso = extractValidFromIso(certString);

  const signedTs = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('base64url');

  // Persisted mutation bodies bind ts_signed inside the signed JSON. A GET has
  // no request body on the wire, so its form-3 envelope binds the empty body
  // plus the external timestamp instead; injecting ts_signed there would make
  // the verifier see different bytes from the signer.
  const isBodylessRequest = String(requestContext?.method || '').toUpperCase() === 'GET'
    || String(requestContext?.method || '').toUpperCase() === 'HEAD';
  if (!isBodylessRequest) body.ts_signed = signedTs;

  // This preserves the verifyPayloadSig invariant for persisted bodies:
  // sig = Ed25519_sign(JCS(body) || "\n" || nonce || "\n" || ts, privkey)
  // where body.ts_signed === ts.
  const useRequestContext = requestContext?.method && requestContext?.path;
  const sigB64u = useRequestContext
    ? signPayloadWithContext(privkey, body, requestContext.method, requestContext.path, nonce, signedTs)
    : signPayload(privkey, body, nonce, signedTs);
  const sigBytes = Buffer.from(sigB64u, 'base64url');
  if (sigBytes.length !== 64) {
    throw new Error(`housekeeper sig unexpected length ${sigBytes.length}`);
  }

  return {
    sigBytes,
    sigB64u,
    signedTs,
    nonce,
    certString,
    validFromIso,
    agentId: HOUSEKEEPER_SIGNER_CONSTANTS.HOUSEKEEPER_AGENT_ID,
    identityTier: detectTierFromCert(certString),
    sigForm: useRequestContext ? 3 : 1,
    signedMethod: useRequestContext ? String(requestContext.method).toUpperCase() : null,
    signedPath: useRequestContext ? String(requestContext.path).split('?')[0] : null,
    signedClaims: null,
    body
  };
}

/**
 * Clear the in-memory caches. Used by tests + server restart scenarios
 * where the cert/privkey may have been rotated on disk.
 */
export function clearHousekeeperCache() {
  cachedPrivkey = null;
  cachedCertString = null;
  cachedValidFromIso = null;
}

export default {
  HOUSEKEEPER_SIGNER_CONSTANTS,
  detectTierFromCert,
  loadHousekeeperPrivkey,
  getHousekeeperCert,
  extractValidFromIso,
  signAsHousekeeper,
  clearHousekeeperCache
};
