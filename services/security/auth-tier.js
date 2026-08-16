// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired (Phase 2) — deriveTier verifies the cert chain and Ed25519 body
// signature, then enforces exact-epoch revocation and nonce replay without any
// mutable bypass. auth-gate.js maps every T0 result to rejection.
// Language: The system quarantines against attack classes; it never guarantees protection. Success is measured via shadow logs and rejection-rate metrics, not by invariant claims.
// Purpose: Derive cryptographic identity tier (T0/T1/T2/T3) from request
//          envelope. Pure decision function: does NOT 401, does NOT
//          mutate req — returns a tier+error result that the middleware
//          (Phase 4A.ii server.js) maps to a response policy.
// Wire into: server.js auth chain (Phase 4A.ii).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * auth-tier.js — Cryptographic identity tier derivation
 * Source: composite of Phase 1 (agent-identity), Phase 3 (identity-chain),
 *         and Phase 4A.i caches (master-pubkey, agent-revocation, nonce).
 *
 * Tier ladder:
 *   T0 — no envelope (unauthenticated; rejected by server middleware)
 *   T1 — cert valid + sig valid, no chain commitment
 *   T2 — T1 + valid prev_chain_hash supplied
 *   T3 — T2 + device_fp matches cert
 *
 * Hard rules:
 *   - T0 is the unconditional fallback. No auth-tier failure ever
 *     elevates the caller above T0.
 *   - Sig/cert/replay failures return T0 with an error reason; auth-gate
 *     rejects T0 callers on every protected route.
 *   - This module is stateless except via the injected cache deps.
 */

import {
  verifyCertChain,
  verifyPayloadSigWithContext,
  verifyPayloadSigWithEnvelopeClaims,
} from './agent-identity.js';
import { masterPubkeyCache as defaultMasterCache } from './master-pubkey-cache.js';
import { housekeeperPubkeyCache as defaultHousekeeperCache } from './housekeeper-pubkey-cache.js';
import { agentRevocationCache as defaultRevocationCache } from './agent-revocation-cache.js';
import { nonceWindow as defaultNonceWindow } from './nonce-window.js';
import { logEvent } from '../observe/event-ledger.js';

// Cheap cert-peek: parse the envelope body WITHOUT verifying, to detect a
// self-signed housekeeper cert (issuer === agent_id === 'housekeeper') and
// route it to the T1_SYSTEM_SELF verification path BEFORE the master-pubkey
// hard gate (which would 401 a self-signed cert). Returns the body or null.
// The full verify happens in deriveTierSystemSelf — this just classifies.
function peekCertBody(certString) {
  try {
    const json = Buffer.from(certString, 'base64url').toString('utf8');
    const env = JSON.parse(json);
    return env?.body || null;
  } catch { return null; }
}

const HOUSEKEEPER_AGENT_ID = 'housekeeper';

const HEADER_NAMES = {
  cert: 'aimos-agent-cert',
  sig: 'aimos-agent-signature',
  nonce: 'aimos-agent-nonce',
  ts: 'aimos-agent-timestamp',
  prevChain: 'aimos-agent-prev-chain-hash',
  deviceFp: 'aimos-agent-device-fp'
};

// Express lowercases header names. We accept mixed case defensively
// (any caller — direct fetch(), non-Express tools, internal services —
// may pass headers in any casing; the parser must survive all of them).
function getHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return undefined;
  const target = String(name).toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === target) return headers[k];
  }
  return undefined;
}

export function parseEnvelope(headers) {
  const cert = getHeader(headers, HEADER_NAMES.cert);
  const sig = getHeader(headers, HEADER_NAMES.sig);
  const nonce = getHeader(headers, HEADER_NAMES.nonce);
  const ts = getHeader(headers, HEADER_NAMES.ts);
  const prevChain = getHeader(headers, HEADER_NAMES.prevChain);
  const deviceFp = getHeader(headers, HEADER_NAMES.deviceFp);

  // No envelope at all → unauthenticated; server middleware will 401
  if (!cert && !sig && !nonce && !ts && !prevChain && !deviceFp) {
    return null;
  }
  // Some headers present but core four incomplete → reject as malformed
  if (!cert || !sig || !nonce || !ts) {
    return { incomplete: true };
  }
  const tsInt = parseInt(String(ts), 10);
  if (!Number.isInteger(tsInt) || tsInt < 0) {
    return { incomplete: true };
  }
  return {
    cert: String(cert),
    sig: String(sig),
    nonce: String(nonce),
    ts: tsInt,
    prevChainHash: prevChain ? String(prevChain) : null,
    deviceFp: deviceFp ? String(deviceFp) : null
  };
}

// Phase 11.8 — additive: envelope may travel via req.body.envelope for
// inline callers (attack-constructors, smoke harnesses, MCP tools). Header
// wins when both are present; body fallback is fail-open for the envelope
// shape, fail-closed for everything else (cert chain verify, sig verify,
// nonce replay, revocation — unchanged).
export function extractEnvelope(req) {
  let env = parseEnvelope(req && req.headers ? req.headers : {});
  if (env !== null) return env;
  const bodyEnv = req && req.body && typeof req.body === 'object' ? req.body.envelope : null;
  if (!bodyEnv || typeof bodyEnv !== 'object') return null;
  const cert = bodyEnv.cert || null;
  const sig = bodyEnv.sig || null;
  const nonce = bodyEnv.nonce || null;
  const tsRaw = bodyEnv.signedTs ?? bodyEnv.ts ?? null;
  const prevChainHash = bodyEnv.prevChainHash ?? null;
  const deviceFp = bodyEnv.deviceFp ?? null;
  if (!cert || !sig || !nonce || !tsRaw) return { incomplete: true };
  const tsInt = parseInt(String(tsRaw), 10);
  if (!Number.isInteger(tsInt) || tsInt < 0) return { incomplete: true };
  return {
    cert: String(cert),
    sig: String(sig),
    nonce: String(nonce),
    ts: tsInt,
    prevChainHash: prevChainHash ? String(prevChainHash) : null,
    deviceFp: deviceFp ? String(deviceFp) : null
  };
}

export function createAuthTier(deps = {}) {
  const masterCache = deps.masterPubkeyCache || defaultMasterCache;
  const housekeeperCache = deps.housekeeperPubkeyCache || defaultHousekeeperCache;
  const revocationCache = deps.agentRevocationCache || defaultRevocationCache;
  const nonceStore = deps.nonceWindow || defaultNonceWindow;
  const logEventFn = typeof deps.logEvent === 'function' ? deps.logEvent : logEvent;
  const verifyCertFn = typeof deps.verifyCertChain === 'function'
    ? deps.verifyCertChain
    : verifyCertChain;
  const verifySigWithContextFn = typeof deps.verifyPayloadSigWithContext === 'function'
    ? deps.verifyPayloadSigWithContext
    : verifyPayloadSigWithContext;
  const verifySigWithEnvelopeClaimsFn = typeof deps.verifyPayloadSigWithEnvelopeClaims === 'function'
    ? deps.verifyPayloadSigWithEnvelopeClaims
    : verifyPayloadSigWithEnvelopeClaims;
  const nowFn = typeof deps.nowFn === 'function'
    ? deps.nowFn
    : () => Math.floor(Date.now() / 1000);
  const skewSeconds = Number.isFinite(deps.skewSeconds) ? deps.skewSeconds : 300;

  function t0(error = null) {
    return { tier: 'T0', cert: null, prevChainHash: null, validFromIso: null, error };
  }

  // T1_SYSTEM_SELF — self-signed housekeeper cert verified against the
  // housekeeper's OWN pubkey (not the user master). Housekeeper is a system operational
  // identity, provisioned at deployment, NOT user-enrollable. Its self-signed
  // cert is the bootstrap + system-write lane before/without a user master.
  // Hard-capped: cannot elevate to T2/T3. Revocation is enforce (not shadow)
  // — the lane is narrow and must fail-closed.
  async function deriveTierSystemSelf(env) {
    const housekeeperPubkey = await housekeeperCache.get();
    if (!housekeeperPubkey) return t0('housekeeper_not_provisioned');

    const certResult = verifyCertFn(env.cert, housekeeperPubkey, { nowFn });
    if (!certResult.valid) return t0('system_self_invalid_cert');
    const certBody = certResult.body;

    if (!certBody || certBody.agent_id !== HOUSEKEEPER_AGENT_ID || certBody.issuer !== HOUSEKEEPER_AGENT_ID) {
      return t0('system_self_invalid_cert');
    }
    if (!Number.isInteger(certBody.valid_from)) {
      return t0('cert_schema');
    }

    const validFromIso = new Date(certBody.valid_from * 1000).toISOString();
    const lookup = await revocationCache.lookup(HOUSEKEEPER_AGENT_ID, validFromIso);
    if (!lookup.found) return t0('housekeeper_not_enrolled');
    if (lookup.proofInvalid) return t0('revocation_proof_invalid');
    if (lookup.revoked) return t0('agent_revoked');  // enforce, not shadow

    const sigResult = verifySigWithContextFn(
      housekeeperPubkey,
      env.body || {},
      env.method,
      env.path,
      env.nonce,
      env.ts,
      env.sig,
      { skewSeconds, nowFn }
    );
    if (!sigResult.valid) return t0(sigResult.reason);

    if (nonceStore.seenAndRecord(HOUSEKEEPER_AGENT_ID, env.nonce)) {
      return t0('replay_detected');  // enforce, not shadow
    }

    return {
      tier: 'T1_SYSTEM_SELF',
      cert: certBody,
      prevChainHash: null,   // hard-capped — no chain advancement
      validFromIso,
      error: null,
      certString: env.cert,
      sigBytes: Buffer.from(env.sig, 'base64url'),
      nonce: env.nonce,
      signedTs: env.ts,
      requestSigForm: 3,
      signedMethod: env.method,
      signedPath: env.path,
      signedClaims: null,
    };
  }

  async function deriveTier(req) {
    const headers = req && req.headers ? req.headers : {};
    const env = extractEnvelope(req);

    if (env === null) return t0(null);
    if (env.incomplete) return t0('envelope_incomplete');

    // Self-signed housekeeper cert → T1_SYSTEM_SELF path (before the
    // master-pubkey hard gate, which would reject a self-signed cert).
    if (env.cert) {
      const peeked = peekCertBody(env.cert);
      if (peeked && peeked.agent_id === HOUSEKEEPER_AGENT_ID && peeked.issuer === HOUSEKEEPER_AGENT_ID) {
        const rawPath = req?.originalUrl || req?.url || '';
        return deriveTierSystemSelf({
          ...env,
          body: req.body || {},
          method: req?.method || '',
          path: rawPath.split('?')[0]
        });
      }
    }

    const masterPubkey = await masterCache.get();
    if (!masterPubkey) return t0('no_master_enrolled');

    const certResult = verifyCertFn(env.cert, masterPubkey, { nowFn });
    if (!certResult.valid) return t0(certResult.reason);
    const certBody = certResult.body;

    if (!certBody || typeof certBody.agent_id !== 'string' || !Number.isInteger(certBody.valid_from)) {
      return t0('cert_schema');
    }

    const validFromIso = new Date(certBody.valid_from * 1000).toISOString();
    const lookup = await revocationCache.lookup(certBody.agent_id, validFromIso);
    if (!lookup.found) return t0('agent_not_enrolled');
    if (lookup.proofInvalid) return t0('revocation_proof_invalid');
    if (lookup.revoked) {
      logEventFn(req.body?.company_id ?? null, certBody.agent_id,
        'reject_revoked_agent',
        null,
        { enforced: true, source_knowledge: 'R1 identity binding — master-signed exact-epoch revocation is terminal' }
      ).catch(() => {});
      return t0('agent_revoked');
    }

    // Request envelopes are method+pathname bound (form 3). Body-only form 1
    // is retired: accepting it would permit cross-route replay.
    const __declaredForm = String(getHeader(headers, 'x-aimos-sig-form') || '').trim();
    const __method = req?.method || '';
    // PATH contract: pathname only, query stripped (see agent-identity.js).
    const __rawPath = req?.originalUrl || req?.url || '';
    const __path = __rawPath.split('?')[0];
    const __hasTierClaims = env.prevChainHash !== null || env.deviceFp !== null;
    const sigResult = __hasTierClaims
      ? (__declaredForm === '4'
          ? verifySigWithEnvelopeClaimsFn(
              certBody.pubkey,
              req.body || {},
              __method,
              __path,
              { prevChainHash: env.prevChainHash, deviceFp: env.deviceFp },
              env.nonce,
              env.ts,
              env.sig,
              { skewSeconds, nowFn },
            )
          : { valid: false, reason: 'sig_form_4_required' })
      : (__declaredForm === '3'
          ? verifySigWithContextFn(certBody.pubkey, req.body || {}, __method, __path, env.nonce, env.ts, env.sig, { skewSeconds, nowFn })
          : { valid: false, reason: 'sig_form_3_required' });
    const __sigFormUsed = sigResult.valid ? Number(__declaredForm) : null;

    if (!sigResult.valid) {
      logEventFn(req.body?.company_id ?? null, certBody?.agent_id ?? 'unknown',
        'reject_bad_sig',
        null,
        { reason: sigResult.reason, declared_sig_form: __declaredForm || '1', method: __method, path: __path,
          source_knowledge: 'R1 Step 2 — body sig is a structural crypto guarantee (sig_invalid + clock_skew), enforced unconditionally.' }
      ).catch(() => {});
      return t0(sigResult.reason);
    }
    // Observability: record which signed form validated so the N+1 rollout can
    // watch v1 traffic drain to zero before rejecting v1 (stage N+2).
    logEventFn(req.body?.company_id ?? null, certBody.agent_id,
      'sig_form_used',
      null,
      { sig_form: __sigFormUsed, declared_sig_form: __declaredForm || '1', method: __method, path: __path,
        reasoning: 'Record the exact cryptographic request-signature form that authenticated this admitted request.',
        source_knowledge: 'R1 Step 2 stage N — verifier accepts sig-form 1|3; logging form for cutover watch.' }
    ).catch(() => {});

    if (nonceStore.seenAndRecord(certBody.agent_id, env.nonce)) {
      // R1 Step 3: nonce-replay enforcement is unconditional. A captured
      // envelope must not replay within the skew window.
      // Durability note: the in-memory LRU (nonce-window.js) is the fast path;
      // the durable cross-process backstop is the UNIQUE constraint in
      // migration 016 (aimos_save_envelope_nonce), translated to
      // replay_detected by save-envelope.js. Single-process replay is fully
      // covered here; cross-process durability rides on the save-path insert.
      logEventFn(req.body?.company_id ?? null, certBody.agent_id,
        'reject_replayed_nonce',
        null,
        { enforced: true, nonce: env.nonce,
          source_knowledge: 'R1 identity binding — request nonce replay is terminal' }
      ).catch(() => {});
      return t0('replay_detected');
    }

    let tier = 'T1';
    let prevChainHashBuf = null;
    if (env.prevChainHash) {
      let buf = null;
      try {
        const candidate = Buffer.from(env.prevChainHash, 'base64url');
        if (candidate.length === 32 && candidate.toString('base64url') === env.prevChainHash) buf = candidate;
      } catch { buf = null; }
      if (!buf) return t0('prev_chain_hash_malformed');
      tier = 'T2';
      prevChainHashBuf = buf;
    }
    if (env.deviceFp) {
      if (tier !== 'T2') return t0('device_fp_requires_chain');
      if (env.deviceFp !== certBody.device_fp) return t0('device_fp_mismatch');
      tier = 'T3';
    }

    return {
      tier,
      cert: certBody,
      prevChainHash: prevChainHashBuf,
      validFromIso,
      error: null,
      // Phase 4 — pass through the raw envelope fields so the route handler can
      // hand them to commitProvenance / commitLineage. These are the SAME values
      // that derived the tier (cert string, sig bytes, nonce, signed ts) — the
      // auth-tier has already validated the sig over canonicalJson(body)+'\n'+
      // nonce+'\n'+String(ts). commitProvenance stores them as the P-live
      // attestation row; commitLineage stores them as the D3 lineage row. The
      // cross-ledger reference key is the shared signed-message form.
      certString: env.cert,
      sigBytes: Buffer.from(env.sig, 'base64url'),
      nonce: env.nonce,
      signedTs: env.ts,
      requestSigForm: __sigFormUsed,
      signedMethod: __method,
      signedPath: __path,
      signedClaims: __sigFormUsed === 4
        ? Object.freeze({
            prev_chain_hash: env.prevChainHash,
            device_fp: env.deviceFp,
          })
        : null,
    };
  }

  return { deriveTier, parseEnvelope };
}

export const authTier = createAuthTier();
