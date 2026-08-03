// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// R1 Step 2 — the ONE place that builds a cryptographic envelope header set.
// Previously v1-api.js, aimos-sign-headers.js and setup.js each built
// cert+sig+nonce+ts independently; three copies of a signing routine are three
// chances to sign the wrong bytes. This is the single shared implementation.
// → Calls: agent-identity.js (loadAgentPrivkey, getAgentCert, signPayload,
//          signPayloadWithContext)
// ─────────────────────────────────────────────────────────────────────────────

import { randomBytes } from 'node:crypto';
import {
  signPayload,
  signPayloadWithContext,
  signPayloadWithEnvelopeClaims,
  loadAgentPrivkey,
  getAgentCert
} from './agent-identity.js';

// Stage of the H10 sig-form rollout that outbound signers emit (X-Aimos-Sig-Form).
//   1 → JCS(body)+nonce+ts.                     ← current (stage N)
//   3 → JCS(body)+METHOD+PATH+nonce+ts.         ← flip at stage N+1
// The verifier (auth-tier.js) already accepts BOTH. Do NOT set this to 3 until
// every signer (JS + Python) can emit form 3 in lockstep. This constant is the
// single switch for the coordinated flip.
//
// ⚠ Form 2 is RESERVED — it belongs to the provenance ledger's sig_form_version
// DB column (a different subsystem), NOT to request envelopes. Never set this
// to 2. Request envelopes use only forms 1 and 3.
export const OUTBOUND_SIG_FORM = 3;

/**
 * Build the cryptographic envelope headers for an outbound signed request.
 *
 * @param {string} agentId  the signing agent (its private key must be on disk)
 * @param {string} method   HTTP method the request will use (bound in sig-form 3)
 * @param {string} path     request pathname, query stripped (bound in sig-form 3)
 * @param {object} body     the JSON body that will be sent (signed)
 * @returns {Promise<Record<string,string>>} header map incl. X-Aimos-Sig-Form
 */
export async function buildEnvelopeHeaders(agentId, method, path, body, claims = {}) {
  const id = String(agentId || '').trim();
  if (!id) throw new Error('buildEnvelopeHeaders: agentId is required (no env default — env identity bypasses the cert envelope)');
  const payload = body || {};
  const privkey = loadAgentPrivkey(`~/.aimos/agents/${id}.key`);
  const cert = await getAgentCert(id);
  const nonce = randomBytes(16).toString('base64url');
  const ts = Math.floor(Date.now() / 1000);

  const normPath = String(path || '').split('?')[0];
  const prevChainHash = claims.prevChainHash ?? claims.prev_chain_hash ?? null;
  const deviceFp = claims.deviceFp ?? claims.device_fp ?? null;
  if (deviceFp && !prevChainHash) {
    throw new Error('buildEnvelopeHeaders: device_fp requires prev_chain_hash');
  }
  if (prevChainHash) {
    const decoded = Buffer.from(String(prevChainHash), 'base64url');
    if (decoded.length !== 32 || decoded.toString('base64url') !== String(prevChainHash)) {
      throw new Error('buildEnvelopeHeaders: prev_chain_hash must be canonical base64url for 32 bytes');
    }
  }
  const sigForm = prevChainHash ? 4 : OUTBOUND_SIG_FORM;
  const sig = sigForm === 4
    ? signPayloadWithEnvelopeClaims(
        privkey,
        payload,
        method,
        normPath,
        { prevChainHash: String(prevChainHash), deviceFp: deviceFp ? String(deviceFp) : null },
        nonce,
        ts,
      )
    : (OUTBOUND_SIG_FORM === 3
        ? signPayloadWithContext(privkey, payload, method, normPath, nonce, ts)
        : signPayload(privkey, payload, nonce, ts));

  const headers = {
    'Aimos-Agent-Cert': cert,
    'Aimos-Agent-Signature': sig,
    'Aimos-Agent-Nonce': nonce,
    'Aimos-Agent-Timestamp': String(ts),
    // Advertise which signed preimage this envelope used so the verifier can
    // log form usage and drive the N+1/N+2 cutover.
    'X-Aimos-Sig-Form': String(sigForm)
  };
  if (prevChainHash) headers['Aimos-Agent-Prev-Chain-Hash'] = String(prevChainHash);
  if (deviceFp) headers['Aimos-Agent-Device-Fp'] = String(deviceFp);
  return headers;
}

export default buildEnvelopeHeaders;
