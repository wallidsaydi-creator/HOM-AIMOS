// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// R1 Step 2 — the ONE place that builds a cryptographic envelope header set.
// Previously v1-api.js, aimos-sign-headers.js and setup.js each built
// cert+sig+nonce+ts independently; three copies of a signing routine are three
// chances to sign the wrong bytes. This is the single shared implementation.
// → Calls: agent-identity.js (loadAgentPrivkey, getAgentCert, signPayload,
//          signPayloadWithContext)
// ─────────────────────────────────────────────────────────────────────────────

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { AIMOS_AGENT_KEY_ROOT } from '../core/runtime-config.js';
import {
  signPayloadWithRequestTarget,
  loadAgentPrivkey,
  getAgentCert
} from './agent-identity.js';

// Current native request profile. Form 5 authenticates the exact target and
// optional chain/device claims. Historical forms 3/4 remain verifier-only here;
// form 2 belongs to the separate provenance signature namespace.
export const OUTBOUND_SIG_FORM = 5;

/**
 * Build the cryptographic envelope headers for an outbound signed request.
 *
 * @param {string} agentId  the signing agent (its private key must be on disk)
 * @param {string} method   HTTP method the request will use (bound in sig-form 3)
 * @param {string} requestPath exact origin-form request target, including query
 * @param {object} body     the JSON body that will be sent (signed)
 * @returns {Promise<Record<string,string>>} header map incl. X-Aimos-Sig-Form
 */
export async function buildEnvelopeHeaders(agentId, method, requestPath, body, claims = {}) {
  const id = String(agentId || '').trim();
  if (!id) throw new Error('buildEnvelopeHeaders: agentId is required (no env default — env identity bypasses the cert envelope)');
  const payload = body || {};
  const privkey = loadAgentPrivkey(path.join(AIMOS_AGENT_KEY_ROOT, `${id}.key`));
  const cert = await getAgentCert(id);
  const nonce = randomBytes(16).toString('base64url');
  const ts = Math.floor(Date.now() / 1000);

  const normPath = String(requestPath || '');
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
  const sigForm = OUTBOUND_SIG_FORM;
  const sig = signPayloadWithRequestTarget(privkey, payload, method, normPath,
    { prev_chain_hash: prevChainHash === null ? null : String(prevChainHash), device_fp: deviceFp === null ? null : String(deviceFp) }, nonce, ts);

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
