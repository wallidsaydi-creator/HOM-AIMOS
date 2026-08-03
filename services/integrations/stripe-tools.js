// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: Stripe payment tool implementation
// ─────────────────────────────────────────────────────────────────────────────
import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
const STRIPE_BASE_URL = 'https://api.stripe.com/v1';

function toInt(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

async function stripeRequest(path, params = {}, useContext = {}) {
  const credential = checkoutCachedCredential('stripe_secret_key');
  if (!credential) {
    throw new Error('STRIPE_SECRET_KEY is missing');
  }

  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    query.set(k, String(v));
  }

  const requestEvidence = { method: 'GET', path, params: Object.fromEntries(query) };
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'stripe_api_read',
    endpoint: `${STRIPE_BASE_URL}${path}`,
    requestHash: credentialUseEvidenceHash(requestEvidence),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });

  const url = `${STRIPE_BASE_URL}${path}${query.toString() ? `?${query.toString()}` : ''}`;
  let response;
  try {
    response = await fetchWithTimeout(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${credential.value}`
      }
    });
  } catch (error) {
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
      outcomeClass: 'transport_error',
      errorClass: error?.name || 'transport_error',
    });
    throw error;
  }

  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({
      status: response.status,
      stripe_request_id: response.headers.get('request-id') || null,
    }),
    outcomeClass: `http_${response.status}`,
  });

  if (!response.ok) {
    const json = await response.json().catch(async () => ({ error: { message: await response.text() } }));
    throw new Error(json?.error?.message || `Stripe error (${response.status})`);
  }
  const json = await response.json();
  return json;
}

export async function stripeAccountSummary(useContext = {}) {
  const account = await stripeRequest('/account', {}, useContext);
  return {
    id: account.id,
    business_type: account.business_type,
    country: account.country,
    email: account.email,
    default_currency: account.default_currency,
    charges_enabled: !!account.charges_enabled,
    payouts_enabled: !!account.payouts_enabled,
    details_submitted: !!account.details_submitted
  };
}

export async function stripeListCustomers({ limit = 10, email = '', useContext = {} } = {}) {
  const capped = Math.min(Math.max(toInt(limit, 10), 1), 100);
  return stripeRequest('/customers', { limit: capped, email }, useContext);
}

export async function stripeListSubscriptions({ limit = 10, status = 'all', useContext = {} } = {}) {
  const capped = Math.min(Math.max(toInt(limit, 10), 1), 100);
  return stripeRequest('/subscriptions', { limit: capped, status }, useContext);
}

export async function stripeListPaymentIntents({ limit = 10, useContext = {} } = {}) {
  const capped = Math.min(Math.max(toInt(limit, 10), 1), 100);
  return stripeRequest('/payment_intents', { limit: capped }, useContext);
}
