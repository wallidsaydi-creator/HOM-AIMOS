// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: Wired — the AIMOS route surface admits verified cryptographic envelopes only.
// ← Called by: server.js (app.use(authGate()))
// → Calls: auth-tier.js (deriveTier)
// Pipeline: AUTH GATE | Position: Single auth authority
// ─────────────────────────────────────────────────────────────────────────────

/**
 * auth-gate.js — Single auth authority for Aimos
 *
 * Consolidates all auth decisions into ONE service. No auth logic lives
 * anywhere else in server.js or routes. This is the only gate.
 *
 * Authority: Miller 2006 Robust Composition (no dual auth paths),
 *            Hardy 1988 The Confused Deputy (no privilege escalation).
 *
 * Auth paths (in order):
 *   1. Open paths (/health, /healthz, /) → pass through
 *   2. First-run Aimos identity enrollment paths → pass through
 *   3. Cryptographic envelope → verified by auth-tier, sets req.identityAuthenticatedBy
 *   4. Neither → 401 "Unauthorized — cryptographic envelope required"
 *
 * Sets on req:
 *   req.identityTier          — 'T0'|'T1'|'T2'|'T3'
 *   req.identityCert           — parsed cert body (or null)
 *   req.prevChainHash          — chain hash buffer (or null)
 *   req.identityValidFromIso   — ISO timestamp (or null)
 *   req.identityError          — tier derivation error (or null)
 *   req.agentId                — agent_id from cert (or null)
 *   req.identityAuthenticatedBy — 'envelope' | undefined
 *   req.trustedPath            — true only for verified envelope auth
 *   req.trustedPathReason      — 'cert_validated_identity' when trustedPath=true
 *   req.internalService        — service name from internal token (or null)
 */

import { authTier } from './auth-tier.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { reserveVerifiedRequest } from './request-receipt-ledger.js';
import { logEvent } from '../observe/event-ledger.js';

// R1 Step 5: the blanket '/setup/aimos/identity/' open prefix is REMOVED. It
// exposed GET /setup/aimos/identity/agents (enumerate every enrolled agent id,
// pubkey fingerprint, validity window, and key-presence) with no auth. Only the
// specific first-run WRITE endpoints that genuinely predate an envelope stay
// open; the list endpoint now falls through to the gate and requires a verified
// cert + admin_override capability (enforced in routes/setup.js).
const OPEN_PATHS = new Set([
  '/', '/healthz', '/health',
  // First-run identity bootstrap — no agent envelope exists yet. These create
  // or select the envelope identity used for every subsequent request. enroll
  // additionally requires the master passphrase (knowledge factor) and is rate
  // limited + backoff-capped in routes/setup.js.
  '/setup/aimos/identity/enroll',
  '/setup/aimos/identity/connect',
  '/setup/aimos/identity/select'
]);
// T1_SYSTEM_SELF route allow-list — the housekeeper-self tier may only write
// to system routes (genesis saves, heartbeats, event log, reasoning state,
// dream cycle, signed recall, and native session composition). Any other route
// → 401 system_self_unauthorized_route. Per
// docs/security/tier-system-self-amendment.md (H9 amendment).
const SYSTEM_SELF_ALLOW = new Set([
  '/aimos/save',
  '/aimos/heartbeat',
  '/aimos/log-event',
  '/aimos/reasoning-state',
  '/aimos/dream',
  '/aimos/dream/state',
  '/aimos/recall',
  '/aimos/session/turn',
  '/aimos/session/finalize'
]);

/**
 * Create an Express middleware that enforces auth as a single authority.
 *
 * @param {Object} [deps] - Dependency injection for testing
 * @param {Function} [deps.deriveTier] - Override auth-tier derivation
 * @param {Set} [deps.openPaths] - Additional open paths beyond defaults
 * @returns {Function} Express middleware
 */
export function createAuthGate(deps = {}) {
  const deriveTier = deps.deriveTier || authTier.deriveTier.bind(authTier);
  const reserveRequest = deps.reserveVerifiedRequest || reserveVerifiedRequest;
  const appendAdmissionEvent = deps.logEvent || logEvent;
  const openPaths = deps.openPaths
    ? new Set([...OPEN_PATHS, ...deps.openPaths])
    : OPEN_PATHS;

  return async function authGate(req, res, next) {
    // Open paths — health checks and first-run identity bootstrap only.
    if (openPaths.has(req.path)) {
      return next();
    }

    // ── Step 1: Derive cryptographic identity tier ──────────────────────────
    try {
      const result = await deriveTier(req);
      req.identityTier = result.tier;
      req.identityCert = result.cert;
      req.prevChainHash = result.prevChainHash;
      req.identityValidFromIso = result.validFromIso;
      req.identityError = result.error;
      // Phase 4 — thread the raw validated envelope fields to the route handler.
      // commitProvenance / commitLineage store these as the P-live / D3
      // attestation rows. Undefined when T0 (no envelope or incomplete) — the
      // route handler's _validate gates on identityTier !== T0 first.
      req.identityCertString = result.certString || null;
      req.identitySigBytes = Buffer.isBuffer(result.sigBytes) ? result.sigBytes : null;
      req.identityNonce = result.nonce || null;
      req.identitySignedTs = Number.isInteger(result.signedTs) ? result.signedTs : null;
      req.identityRequestSigForm = Number.isInteger(result.requestSigForm) ? result.requestSigForm : null;
      req.identitySignedMethod = result.signedMethod || null;
      req.identitySignedPath = result.signedPath || null;
      req.identitySignedClaims = result.signedClaims || null;

      if (result.tier !== 'T0' && result.cert?.agent_id) {
        // T1_SYSTEM_SELF — enforce route allow-list BEFORE admission.
        // The housekeeper-self tier is narrow: system writes only. Any
        // attempt to hit a user route (recall, governance, etc.) → 401.
        if (result.tier === 'T1_SYSTEM_SELF' && !SYSTEM_SELF_ALLOW.has(req.path)) {
          return res.status(401).json({
            error: 'system_self_unauthorized_route',
            reason: 'T1_SYSTEM_SELF may only write to system routes'
          });
        }
        req.agentId = result.cert.agent_id;
        req.identityAuthenticatedBy = 'envelope';
        req.trustedPath = true;
        req.trustedPathReason = 'cert_validated_identity';
        const requestedCompany = req.body?.company_id ?? req.query?.company_id ?? AIMOS_COMPANY_ID;
        const systemCompanyAllowed = result.tier === 'T1_SYSTEM_SELF' && String(requestedCompany) === 'system';
        if (String(requestedCompany) !== AIMOS_COMPANY_ID && !systemCompanyAllowed) {
          return res.status(403).json({
            error: 'company_scope_mismatch',
            reason: `This HOM-AIMOS installation is cryptographically scoped to ${AIMOS_COMPANY_ID}`,
          });
        }
        let requestReceipt;
        let requestAdmission;
        try {
          requestReceipt = await reserveRequest({
            companyId: String(requestedCompany),
            actorAgentId: result.cert.agent_id,
            actorValidFromIso: result.validFromIso,
            certString: result.certString,
            pubkey: result.cert.pubkey,
            body: req.body || {},
            requestSigForm: result.requestSigForm,
            signedMethod: result.signedMethod,
            signedPath: result.signedPath,
            signedClaims: result.signedClaims || null,
            nonce: result.nonce,
            signedTs: result.signedTs,
            sigBytes: result.sigBytes,
          });
          requestAdmission = await appendAdmissionEvent(
            String(requestedCompany),
            result.cert.agent_id,
            'request_admission_verified',
            String(requestReceipt.request_receipt_id),
            {
              request_receipt_id: String(requestReceipt.request_receipt_id),
              request_receipt_mutation_hash: Buffer.from(requestReceipt.mutation_hash).toString('hex'),
              request_hash: Buffer.from(requestReceipt.request_hash).toString('hex'),
              actor_agent_id: result.cert.agent_id,
              actor_valid_from: new Date(result.validFromIso).toISOString(),
              signed_method: result.signedMethod,
              signed_path: result.signedPath,
              company_id: String(requestedCompany),
              reasoning: 'The housekeeper observed and retained the exact durable admission receipt after certificate-envelope verification and before route execution.',
            },
            null,
            { returnReceipt: true },
          );
          if (!requestAdmission?.event_id || !requestAdmission?.mutation_hash) {
            throw new Error('request_admission_event_unavailable');
          }
        } catch (error) {
          if (error?.code === 'AIMOS_REQUEST_REPLAY' || error?.message === 'request_replay_detected') {
            return res.status(409).json({ error: 'request_replay_detected' });
          }
          console.error('[auth-gate] durable request receipt failed:', error?.message || error);
          return res.status(503).json({ error: 'request_receipt_unavailable' });
        }
        req.executionContext = Object.freeze({
          actorAgentId: result.cert.agent_id,
          actorValidFromIso: result.validFromIso,
          companyId: String(requestedCompany),
          identityTier: result.tier,
          authSource: 'envelope',
          nonce: result.nonce || null,
          signedTs: Number.isInteger(result.signedTs) ? result.signedTs : null,
          requestSigForm: Number.isInteger(result.requestSigForm) ? result.requestSigForm : null,
          signedMethod: result.signedMethod || null,
          signedPath: result.signedPath || null,
          signedClaims: result.signedClaims || null,
          requestReceiptId: requestReceipt?.request_receipt_id || null,
          requestReceiptMutationHash: requestReceipt?.mutation_hash
            ? Buffer.from(requestReceipt.mutation_hash).toString('hex')
            : null,
          requestAdmissionEventId: requestAdmission?.event_id || null,
          requestAdmissionMutationHash: requestAdmission?.mutation_hash || null,
          internalService: null,
        });
        return next();
      }
    } catch (err) {
      req.identityTier = 'T0';
      req.identityCert = null;
      req.prevChainHash = null;
      req.identityValidFromIso = null;
      req.identityError = 'tier_derivation_threw';
      req.identityCertString = null;
      req.identitySigBytes = null;
      req.identityNonce = null;
      req.identitySignedTs = null;
      req.identityRequestSigForm = null;
      req.identitySignedMethod = null;
      req.identitySignedPath = null;
      req.identitySignedClaims = null;
      console.warn('[auth-gate] unexpected error during tier derivation:', err?.message || err);
    }

    // Shared HMAC tokens are not identities and therefore cannot enter the
    // main AIMOS route surface. ART validates its own narrow sidecar tokens;
    // autonomous housekeeper work calls native services directly.
    const internalToken = req.headers['x-internal-token'];
    if (internalToken) {
      return res.status(401).json({
        error: 'internal_service_principal_required',
        reason: 'Shared HMAC tokens are not admitted to the main AIMOS route surface'
      });
    }

    // ── Step 2: No valid credential — reject ──────────────────────────────
    // Phase 10B: Bearer tokens are removed. The only auth paths are
    // cryptographic envelopes only.
    return res.status(401).json({
      error: 'Unauthorized — cryptographic envelope required'
    });
  };
}

// Default export: production auth gate with standard dependencies
export const authGate = createAuthGate();
