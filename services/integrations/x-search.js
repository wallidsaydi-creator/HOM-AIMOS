// ─── PIPELINE CONNECTIONS ───────────────────────────────────────────────────
// ← Called by: governance-resolver.js, tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: X/Twitter search tool implementation
// ────────────────────────────────────────────────────────────────────────────────
import { randomUUID } from 'node:crypto';

import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential, peekCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';

const X_API_BASES = ['https://api.x.com', 'https://api.twitter.com'];
let cachedBearerFromKeys = null;
const X_REQUEST_TIMEOUT_MS = 12_000;

function sameCredentialVersion(left, right) {
  return left?.slotId === right?.slotId
    && left?.credentialHash === right?.credentialHash
    && left?.effectiveProvenanceId === right?.effectiveProvenanceId
    && left?.effectiveMutationHash === right?.effectiveMutationHash;
}

function currentCachedDerivedBearer() {
  if (!cachedBearerFromKeys) return null;
  const key = checkoutCachedCredential('x_api_key');
  const secret = checkoutCachedCredential('x_api_secret');
  if (
    !key
    || !secret
    || !sameCredentialVersion(key, cachedBearerFromKeys.credentials[0])
    || !sameCredentialVersion(secret, cachedBearerFromKeys.credentials[1])
  ) {
    cachedBearerFromKeys = null;
    return null;
  }
  return cachedBearerFromKeys;
}

function toInt(value, fallback) {
  const n = Number(value);
  if (Number.isFinite(n)) return n;
  return fallback;
}

async function mintBearerFromKeySecret(useContext = {}) {
  if (!peekCachedCredential('x_api_key') || !peekCachedCredential('x_api_secret')) return null;

  for (const base of X_API_BASES) {
    const key = checkoutCachedCredential('x_api_key');
    const secret = checkoutCachedCredential('x_api_secret');
    if (!key || !secret) return null;

    const requestBody = 'grant_type=client_credentials';
    const credentials = [key, secret];
    const useGroupId = randomUUID();
    const reservationResults = await Promise.allSettled(credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_oauth2_client_credentials',
        endpoint: `${base}/oauth2/token`,
        requestHash: credentialUseEvidenceHash({ method: 'POST', body: requestBody }),
        subjectAgentId: useContext?.actorAgentId || 'housekeeper',
        requestReceiptId: useContext?.requestReceiptId || null,
        requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
        autonomousActionEventId: useContext?.autonomousActionEventId || null,
        useGroupId,
      })
    )));
    const reservations = reservationResults
      .filter((result) => result.status === 'fulfilled')
      .map((result) => result.value);
    const reservationFailure = reservationResults.find((result) => result.status === 'rejected');
    if (reservationFailure) {
      const outcomeHash = credentialUseEvidenceHash({ error_class: 'credential_group_reservation_failed' });
      await Promise.allSettled(reservations.map((reservation) => credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeHash,
        outcomeClass: 'credential_group_reservation_failed',
        errorClass: reservationFailure.reason?.name || 'credential_group_reservation_failed',
      })));
      throw reservationFailure.reason;
    }

    let response;
    try {
      const basic = Buffer.from(`${key.value}:${secret.value}`).toString('base64');
      response = await fetchWithTimeout(`${base}/oauth2/token`, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${basic}`,
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: requestBody
      }, X_REQUEST_TIMEOUT_MS);
    } catch (error) {
      const terminalResults = await Promise.allSettled(reservations.map((reservation) => (
        credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
          outcomeClass: 'transport_error',
          errorClass: error?.name || 'transport_error',
        })
      )));
      const terminalFailure = terminalResults.find((result) => result.status === 'rejected');
      if (terminalFailure) throw terminalFailure.reason;
      continue;
    }

    const terminalResults = await Promise.allSettled(reservations.map((reservation) => (
      credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeHash: credentialUseEvidenceHash({
          status: response.status,
          x_request_id: response.headers.get('x-request-id') || null,
        }),
        outcomeClass: `http_${response.status}`,
      })
    )));
    const terminalFailure = terminalResults.find((result) => result.status === 'rejected');
    if (terminalFailure) throw terminalFailure.reason;

    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.access_token) continue;
    cachedBearerFromKeys = Object.freeze({
      value: data.access_token,
      credentials: Object.freeze([key, secret]),
    });
    return cachedBearerFromKeys;
  }
  return null;
}

async function resolveBearerAuthorization(useContext = {}) {
  if (peekCachedCredential('x_bearer_token')) {
    const credential = checkoutCachedCredential('x_bearer_token');
    if (credential) return { value: credential.value, credentials: [credential] };
  }
  return currentCachedDerivedBearer() || mintBearerFromKeySecret(useContext);
}

export async function xSearchRecent({ query, maxResults = 10, useContext = {} }) {
  const capped = Math.min(Math.max(toInt(maxResults, 10), 10), 100);
  const q = String(query || '').trim();
  if (!q) throw new Error('query is required');

  let authorization = await resolveBearerAuthorization(useContext);
  if (!authorization) {
    throw new Error('X_BEARER_TOKEN is missing (and X key/secret fallback unavailable)');
  }

  const params = new URLSearchParams({
    query: q,
    max_results: String(capped),
    'tweet.fields': 'created_at,lang,public_metrics,author_id',
    expansions: 'author_id',
    'user.fields': 'username,name,verified,public_metrics'
  });
  const requestHash = credentialUseEvidenceHash({
    method: 'GET',
    query: Object.fromEntries(params),
  });

  let lastError = null;
  for (const base of X_API_BASES) {
    const url = `${base}/2/tweets/search/recent?${params.toString()}`;
    const useGroupId = authorization.credentials.length > 1 ? randomUUID() : null;
    const reservationResults = await Promise.allSettled(authorization.credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_search_recent',
        endpoint: `${base}/2/tweets/search/recent`,
        requestHash,
        subjectAgentId: useContext?.actorAgentId || 'housekeeper',
        requestReceiptId: useContext?.requestReceiptId || null,
        requestReceiptMutationHash: useContext?.requestReceiptMutationHash || null,
        requestAdmissionEventId: useContext?.requestAdmissionEventId || null,
        requestAdmissionMutationHash: useContext?.requestAdmissionMutationHash || null,
        autonomousActionEventId: useContext?.autonomousActionEventId || null,
        useGroupId,
      })
    )));
    const reservations = reservationResults
      .filter((result) => result.status === 'fulfilled')
      .map((result) => result.value);
    const reservationFailure = reservationResults.find((result) => result.status === 'rejected');
    if (reservationFailure) {
      const outcomeHash = credentialUseEvidenceHash({ error_class: 'credential_group_reservation_failed' });
      await Promise.allSettled(reservations.map((reservation) => credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeHash,
        outcomeClass: 'credential_group_reservation_failed',
        errorClass: reservationFailure.reason?.name || 'credential_group_reservation_failed',
      })));
      throw reservationFailure.reason;
    }

    let response;
    try {
      response = await fetchWithTimeout(url, {
        headers: {
          Authorization: `Bearer ${authorization.value}`
        }
      }, X_REQUEST_TIMEOUT_MS);
    } catch (error) {
      const terminalResults = await Promise.allSettled(reservations.map((reservation) => (
        credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
          outcomeClass: 'transport_error',
          errorClass: error?.name || 'transport_error',
        })
      )));
      const terminalFailure = terminalResults.find((result) => result.status === 'rejected');
      if (terminalFailure) throw terminalFailure.reason;
      lastError = error?.message || String(error);
      continue;
    }

    const terminalResults = await Promise.allSettled(reservations.map((reservation) => (
      credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeHash: credentialUseEvidenceHash({
          status: response.status,
          x_request_id: response.headers.get('x-request-id') || null,
        }),
        outcomeClass: `http_${response.status}`,
      })
    )));
    const terminalFailure = terminalResults.find((result) => result.status === 'rejected');
    if (terminalFailure) throw terminalFailure.reason;

    if (response.status === 401 && !peekCachedCredential('x_bearer_token')) {
      const reminted = await mintBearerFromKeySecret(useContext);
      if (reminted) {
        authorization = reminted;
        continue;
      }
    }

    if (!response.ok) {
      const responseText = await response.text().catch(() => '');
      const lowered = responseText.toLowerCase();
      if (
        lowered.includes('fund')
        || lowered.includes('payment')
        || lowered.includes('project')
        || lowered.includes('elevated')
      ) {
        lastError = `X API not ready (${response.status}): account/token requires funded or elevated access`;
      } else {
        lastError = `X API error (${response.status}): ${responseText}`;
      }
      continue;
    }

    const data = await response.json().catch((error) => {
      lastError = error?.message || String(error);
      return null;
    });
    if (!data) continue;
    const users = new Map((data.includes?.users || []).map(u => [u.id, u]));

    const posts = (data.data || []).map(tweet => {
      const author = users.get(tweet.author_id) || {};
      return {
        id: tweet.id,
        text: tweet.text || '',
        author_name: author.name || '',
        username: author.username || '',
        verified: !!author.verified,
        created_at: tweet.created_at || null,
        metrics: tweet.public_metrics || {},
        url: author.username
          ? `https://x.com/${author.username}/status/${tweet.id}`
          : `https://x.com/i/web/status/${tweet.id}`
      };
    });

    return {
      provider: 'x',
      query: q,
      count: posts.length,
      posts
    };
  }

  throw new Error(lastError || 'X search failed');
}
