// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: governance-resolver.js, telegram-bot.js, scheduler.js, tool-registry.js
// Pipeline: Cross-cutting search | Position: Web search provider (Perplexity/Brave)
// ─────────────────────────────────────────────────────────────────────────────
import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';

const WEB_REQUEST_TIMEOUT_MS = 12_000;

export async function searchWeb({ query, maxResults = 5, useContext = {} }) {
  const primary = await searchPerplexity(query, useContext).catch(() => null);
  if (primary) return { provider: 'perplexity', ...primary };

  const fallback = await searchBrave(query, maxResults, useContext).catch(() => null);
  if (fallback) return { provider: 'brave', ...fallback };

  return { provider: 'none', answer: null, results: [] };
}

async function searchPerplexity(query, useContext) {
  const credential = checkoutCachedCredential('perplexity_api_key');
  if (!credential) return null;
  const model = systemConfigStore.readConfigString('PERPLEXITY_MODEL') || 'sonar-pro';
  const requestBody = {
    model,
    messages: [
      {
        role: 'system',
        content: 'You are a web research assistant. Provide a concise answer and include sources if available.'
      },
      { role: 'user', content: query }
    ],
    temperature: 0.2
  };
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'perplexity_web_search',
    endpoint: 'https://api.perplexity.ai/chat/completions',
    requestHash: credentialUseEvidenceHash({ method: 'POST', body: requestBody }),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });

  let res;
  try {
    res = await fetchWithTimeout('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${credential.value}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    }, WEB_REQUEST_TIMEOUT_MS);
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
    outcomeHash: credentialUseEvidenceHash({ status: res.status }),
    outcomeClass: `http_${res.status}`,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Perplexity error (${res.status}): ${text}`);
  }

  const data = await res.json();
  if (!Array.isArray(data?.choices) || data.choices.length === 0) {
    return { answer: '', results: [] };
  }
  const answer = data?.choices?.[0]?.message?.content || '';
  const citations = data?.citations || data?.choices?.[0]?.citations || [];

  return { answer, results: citations.map(url => ({ title: url, url, description: '' })) };
}

async function searchBrave(query, maxResults, useContext) {
  const credential = checkoutCachedCredential('brave_api_key');
  if (!credential) return null;

  const url = new URL('https://api.search.brave.com/res/v1/web/search');
  url.searchParams.set('q', query);
  url.searchParams.set('count', String(maxResults));

  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'brave_web_search',
    endpoint: 'https://api.search.brave.com/res/v1/web/search',
    requestHash: credentialUseEvidenceHash({
      method: 'GET',
      query: { q: query, count: String(maxResults) },
    }),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });
  let res;
  try {
    res = await fetchWithTimeout(url, {
      headers: { 'X-Subscription-Token': credential.value }
    }, WEB_REQUEST_TIMEOUT_MS);
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
    outcomeHash: credentialUseEvidenceHash({ status: res.status }),
    outcomeClass: `http_${res.status}`,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Brave error (${res.status}): ${text}`);
  }

  const data = await res.json();
  const results = (data?.web?.results || []).slice(0, maxResults).map(item => ({
    title: item.title,
    url: item.url,
    description: item.description || ''
  }));

  return { answer: null, results };
}
