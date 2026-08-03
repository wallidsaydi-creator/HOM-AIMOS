// ─── PIPELINE CONNECTIONS ───────────────────────────────────────────────────
// ← Called by: tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: X/Twitter post/DM tool implementation
// ───────────────────────────────────────────────────────────────────────────────
import crypto from 'crypto';

import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential, peekCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';

const X_API_BASES = ['https://api.x.com', 'https://api.twitter.com'];
let cachedBearerFromKeys = null;

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

function hasOAuth1Credentials() {
  return peekCachedCredential('x_api_key')
    && peekCachedCredential('x_api_secret')
    && peekCachedCredential('x_access_token')
    && peekCachedCredential('x_access_token_secret');
}

function checkoutOAuth1Credentials() {
  const credentials = {
    consumerKey: checkoutCachedCredential('x_api_key'),
    consumerSecret: checkoutCachedCredential('x_api_secret'),
    accessToken: checkoutCachedCredential('x_access_token'),
    tokenSecret: checkoutCachedCredential('x_access_token_secret'),
  };
  return Object.values(credentials).every(Boolean) ? credentials : null;
}

// OAuth 1.0a percent-encoding: encode everything except unreserved chars (RFC 3986)
function oauthEncode(str) {
  return encodeURIComponent(String(str)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

// Build the OAuth 1.0a Authorization header for a POST request with no query params.
// The X POST /2/tweets endpoint only takes a JSON body — no URL query params — so the
// parameter set used for the signature is purely the oauth_* params themselves.
function buildOAuth1Header(method, url, credentials) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const timestamp = String(Math.floor(Date.now() / 1000));

  const oauthParams = {
    oauth_consumer_key: credentials.consumerKey.value,
    oauth_nonce: nonce,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: timestamp,
    oauth_token: credentials.accessToken.value,
    oauth_version: '1.0'
  };

  const paramString = Object.keys(oauthParams)
    .sort()
    .map((key) => `${oauthEncode(key)}=${oauthEncode(oauthParams[key])}`)
    .join('&');
  const signingKey = `${oauthEncode(credentials.consumerSecret.value)}&${oauthEncode(credentials.tokenSecret.value)}`;
  const baseString = `${method.toUpperCase()}&${oauthEncode(url)}&${oauthEncode(paramString)}`;
  const signature = crypto
    .createHmac('sha1', signingKey)
    .update(baseString)
    .digest('base64');
  const headerParts = { ...oauthParams, oauth_signature: signature };

  return 'OAuth ' + Object.keys(headerParts)
    .sort()
    .map((key) => `${oauthEncode(key)}="${oauthEncode(headerParts[key])}"`)
    .join(', ');
}

async function mintBearerFromKeySecret(useContext = {}) {
  if (!peekCachedCredential('x_api_key') || !peekCachedCredential('x_api_secret')) return null;

  for (const base of X_API_BASES) {
    const key = checkoutCachedCredential('x_api_key');
    const secret = checkoutCachedCredential('x_api_secret');
    if (!key || !secret) return null;

    const requestBody = 'grant_type=client_credentials';
    const credentials = [key, secret];
    const useGroupId = crypto.randomUUID();
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
      });
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

async function resolveAppBearerAuthorization(useContext = {}) {
  if (peekCachedCredential('x_bearer_token')) {
    const credential = checkoutCachedCredential('x_bearer_token');
    if (credential) return { value: credential.value, credentials: [credential] };
  }
  return currentCachedDerivedBearer() || mintBearerFromKeySecret(useContext);
}

async function resolveReadAuthorization(useContext = {}) {
  if (peekCachedCredential('x_access_token')) {
    const credential = checkoutCachedCredential('x_access_token');
    if (credential) return { value: credential.value, credentials: [credential] };
  }
  const authorization = await resolveAppBearerAuthorization(useContext);
  if (authorization) return authorization;
  throw new Error('X not configured. Set X_BEARER_TOKEN or X_API_KEY/X_API_SECRET.');
}

function resolvePostAuthorization(url) {
  if (hasOAuth1Credentials()) {
    const oauthCredentials = checkoutOAuth1Credentials();
    if (oauthCredentials) {
      return {
        header: buildOAuth1Header('POST', url, oauthCredentials),
        credentials: [
          oauthCredentials.consumerKey,
          oauthCredentials.consumerSecret,
          oauthCredentials.accessToken,
          oauthCredentials.tokenSecret,
        ],
      };
    }
  }
  if (peekCachedCredential('x_access_token')) {
    const credential = checkoutCachedCredential('x_access_token');
    if (credential) return { header: `Bearer ${credential.value}`, credentials: [credential] };
  }
  return null;
}

async function xGet(path, useContext = {}) {
  const parsedPath = new URL(path, 'https://x.invalid');
  const requestHash = credentialUseEvidenceHash({
    method: 'GET',
    query: Object.fromEntries(parsedPath.searchParams),
  });
  let lastError = null;

  for (const base of X_API_BASES) {
    const authorization = await resolveReadAuthorization(useContext);
    const useGroupId = authorization.credentials.length > 1 ? crypto.randomUUID() : null;
    const reservationResults = await Promise.allSettled(authorization.credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_api_read',
        endpoint: `${base}${parsedPath.pathname}`,
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
      response = await fetchWithTimeout(`${base}${path}`, {
        headers: { Authorization: `Bearer ${authorization.value}` }
      });
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

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      lastError = payload?.detail || payload?.title || `X API error (${response.status})`;
      continue;
    }
    return payload;
  }
  throw new Error(lastError || 'X API request failed');
}

function mapProfile(user) {
  return {
    id: user?.id || '',
    name: user?.name || '',
    username: user?.username || '',
    bio: user?.description || '',
    avatar: user?.profile_image_url || '',
    followers: Number(user?.public_metrics?.followers_count || 0),
    following: Number(user?.public_metrics?.following_count || 0),
    tweets: Number(user?.public_metrics?.tweet_count || 0),
    verified: !!user?.verified
  };
}

export async function xGetMyProfile(useContext = {}) {
  const data = await xGet(
    '/2/users/me?user.fields=description,profile_image_url,public_metrics,verified',
    useContext,
  );
  return {
    success: true,
    profile: mapProfile(data?.data || {})
  };
}

export async function xGetMyTimeline({ max = 20, useContext = {} } = {}) {
  const profileData = await xGet(
    '/2/users/me?user.fields=description,profile_image_url,public_metrics,verified',
    useContext,
  );
  const userId = String(profileData?.data?.id || '').trim();
  if (!userId) throw new Error('Unable to resolve authenticated X user.');

  const capped = Math.min(Math.max(Number(max) || 20, 1), 100);
  const params = new URLSearchParams({
    max_results: String(capped),
    'tweet.fields': 'created_at,public_metrics'
  });
  const timeline = await xGet(`/2/users/${encodeURIComponent(userId)}/tweets?${params}`, useContext);

  const tweets = (timeline?.data || []).map((tweet) => ({
    id: tweet.id,
    text: tweet.text || '',
    created_at: tweet.created_at || null,
    likes: Number(tweet?.public_metrics?.like_count || 0),
    retweets: Number(tweet?.public_metrics?.retweet_count || 0),
    replies: Number(tweet?.public_metrics?.reply_count || 0),
    quotes: Number(tweet?.public_metrics?.quote_count || 0),
    url: `https://x.com/${profileData?.data?.username || 'i'}/status/${tweet.id}`
  }));

  return {
    success: true,
    profile: mapProfile(profileData?.data || {}),
    count: tweets.length,
    tweets
  };
}

export async function xPostTweet({ text, useContext = {} }) {
  const bodyText = String(text || '').trim();
  if (!bodyText) throw new Error('text is required');
  if (!hasOAuth1Credentials() && !peekCachedCredential('x_access_token')) {
    throw new Error('X posting not configured. Set X_API_KEY + X_ACCESS_TOKEN (OAuth 1.0a) or X_USER_ACCESS_TOKEN (bearer).');
  }

  const requestBody = { text: bodyText };
  const requestHash = credentialUseEvidenceHash({ method: 'POST', body: requestBody });
  let lastError = null;
  for (const base of X_API_BASES) {
    const url = `${base}/2/tweets`;
    const authorization = resolvePostAuthorization(url);
    if (!authorization) throw new Error('X posting credential checkout failed.');
    const useGroupId = authorization.credentials.length > 1 ? crypto.randomUUID() : null;
    const reservationResults = await Promise.allSettled(authorization.credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_post_tweet',
        endpoint: url,
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
        method: 'POST',
        headers: {
          Authorization: authorization.header,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });
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
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      lastError = payload?.detail || payload?.title || `X API error (${response.status})`;
      continue;
    }
    return {
      success: true,
      tweet: {
        id: payload?.data?.id || '',
        text: payload?.data?.text || bodyText,
        url: payload?.data?.id ? `https://x.com/i/web/status/${payload.data.id}` : ''
      }
    };
  }
  throw new Error(lastError || 'X post failed');
}

export async function xReplyToTweet({ text, replyToTweetId, useContext = {} }) {
  const bodyText = String(text || '').trim();
  const targetId = String(replyToTweetId || '').trim();
  if (!bodyText) throw new Error('text is required');
  if (!targetId) throw new Error('replyToTweetId is required');
  if (!hasOAuth1Credentials() && !peekCachedCredential('x_access_token')) {
    throw new Error('X posting not configured. Set X_API_KEY + X_ACCESS_TOKEN (OAuth 1.0a) or X_USER_ACCESS_TOKEN (bearer).');
  }

  const requestBody = { text: bodyText, reply: { in_reply_to_tweet_id: targetId } };
  const requestHash = credentialUseEvidenceHash({ method: 'POST', body: requestBody });
  let lastError = null;
  for (const base of X_API_BASES) {
    const url = `${base}/2/tweets`;
    const authorization = resolvePostAuthorization(url);
    if (!authorization) throw new Error('X posting credential checkout failed.');
    const useGroupId = authorization.credentials.length > 1 ? crypto.randomUUID() : null;
    const reservationResults = await Promise.allSettled(authorization.credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_reply_to_tweet',
        endpoint: url,
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
        method: 'POST',
        headers: {
          Authorization: authorization.header,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });
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
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      lastError = payload?.detail || payload?.title || `X API error (${response.status})`;
      continue;
    }
    return {
      success: true,
      tweet: {
        id: payload?.data?.id || '',
        text: payload?.data?.text || bodyText,
        url: payload?.data?.id ? `https://x.com/i/web/status/${payload.data.id}` : ''
      }
    };
  }
  throw new Error(lastError || 'X reply failed');
}

export async function xQuoteTweet({ text, quoteTweetId, useContext = {} }) {
  const bodyText = String(text || '').trim();
  const targetId = String(quoteTweetId || '').trim();
  if (!bodyText) throw new Error('text is required');
  if (!targetId) throw new Error('quoteTweetId is required');
  if (!hasOAuth1Credentials() && !peekCachedCredential('x_access_token')) {
    throw new Error('X posting not configured. Set X_API_KEY + X_ACCESS_TOKEN (OAuth 1.0a) or X_USER_ACCESS_TOKEN (bearer).');
  }

  const requestBody = { text: bodyText, quote_tweet_id: targetId };
  const requestHash = credentialUseEvidenceHash({ method: 'POST', body: requestBody });
  let lastError = null;
  for (const base of X_API_BASES) {
    const url = `${base}/2/tweets`;
    const authorization = resolvePostAuthorization(url);
    if (!authorization) throw new Error('X posting credential checkout failed.');
    const useGroupId = authorization.credentials.length > 1 ? crypto.randomUUID() : null;
    const reservationResults = await Promise.allSettled(authorization.credentials.map((credential) => (
      credentialLedger.reserveCredentialUse({
        ...credential,
        operation: 'x_quote_tweet',
        endpoint: url,
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
        method: 'POST',
        headers: {
          Authorization: authorization.header,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });
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
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      lastError = payload?.detail || payload?.title || `X API error (${response.status})`;
      continue;
    }
    return {
      success: true,
      tweet: {
        id: payload?.data?.id || '',
        text: payload?.data?.text || bodyText,
        url: payload?.data?.id ? `https://x.com/i/web/status/${payload.data.id}` : ''
      }
    };
  }
  throw new Error(lastError || 'X quote tweet failed');
}
