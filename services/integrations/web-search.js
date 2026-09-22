// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: governance-resolver.js, telegram-bot.js, scheduler.js, tool-registry.js
// Pipeline: Cross-cutting search | Position: Web search provider (Perplexity/Brave)
// ─────────────────────────────────────────────────────────────────────────────
import { fetchWithTimeout, markHttpIndeterminate } from '../orchestration/http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';
import { performance } from 'node:perf_hooks';

const WEB_REQUEST_TIMEOUT_MS = 12_000;

export async function searchWeb({ query, maxResults = 5, useContext = {} }) {
  const deadlineAt = Math.min(useContext.deadlineAt ?? Infinity, performance.now() + WEB_REQUEST_TIMEOUT_MS);
  const primary = await searchPerplexity(query, useContext, deadlineAt).catch(error => {
    if (useContext.signal?.aborted || /Timeout|Abort/.test(error?.name || '') || error?.httpOutcome === 'INDETERMINATE') throw error;
    return null;
  });
  if (primary) return { provider: 'perplexity', ...primary };

  const fallback = await searchBrave(query, maxResults, useContext, deadlineAt).catch(error => {
    if (useContext.signal?.aborted || /Timeout|Abort/.test(error?.name || '')) throw error;
    return null;
  });
  if (fallback) return { provider: 'brave', ...fallback };

  return { provider: 'none', answer: null, results: [] };
}

async function searchPerplexity(query, useContext, deadlineAt) {
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
  let data;
  try {
    res = await fetchWithTimeout('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${credential.value}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody),
      signal: useContext?.signal,
      deadlineAt,
      destinationPolicy: 'public',
    }, WEB_REQUEST_TIMEOUT_MS);
    data = await res.json();
  } catch (error) {
    error = markHttpIndeterminate(error);
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'indeterminate',
      outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
      outcomeClass: 'transport_error',
      errorClass: error?.name || 'transport_error',
    });
    throw error;
  } finally {
    if (res?.body && !res.body.locked && !res.bodyUsed) await res.body.cancel().catch(() => {});
  }
  if (!res.ok) {
    const text = await res.text();
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(text) }),
      outcomeClass: `http_${res.status}`,
      errorClass: `http_${res.status}`,
    });
    throw new Error(`Perplexity error (${res.status}): ${text}`);
  }


  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(data) }),
    outcomeClass: `http_${res.status}`,
  });
  if (!Array.isArray(data?.choices) || data.choices.length === 0) {
    return { answer: '', results: [] };
  }
  const answer = data?.choices?.[0]?.message?.content || '';
  const citations = data?.citations || data?.choices?.[0]?.citations || [];

  return { answer, results: citations.map(url => ({ title: url, url, description: '' })) };
}

async function searchBrave(query, maxResults, useContext, deadlineAt) {
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
  let data;
  try {
    res = await fetchWithTimeout(url, {
      headers: { 'X-Subscription-Token': credential.value },
      signal: useContext?.signal,
      deadlineAt,
      destinationPolicy: 'public',
    }, WEB_REQUEST_TIMEOUT_MS);
    data = await res.json();
  } catch (error) {
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'indeterminate',
      outcomeHash: credentialUseEvidenceHash({ error_class: error?.name || 'transport_error' }),
      outcomeClass: 'transport_error',
      errorClass: error?.name || 'transport_error',
    });
    throw error;
  } finally {
    if (res?.body && !res.body.locked && !res.bodyUsed) await res.body.cancel().catch(() => {});
  }
  if (!res.ok) {
    const text = await res.text();
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(text) }),
      outcomeClass: `http_${res.status}`,
      errorClass: `http_${res.status}`,
    });
    throw new Error(`Brave error (${res.status}): ${text}`);
  }


  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({ status: res.status, response_hash: credentialUseEvidenceHash(data) }),
    outcomeClass: `http_${res.status}`,
  });
  const results = (data?.web?.results || []).slice(0, maxResults).map(item => ({
    title: item.title,
    url: item.url,
    description: item.description || ''
  }));

  return { answer: null, results };
}
