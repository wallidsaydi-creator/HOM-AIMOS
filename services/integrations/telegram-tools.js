// Native Telegram credential-use owner. Every outbound request reserves the
// exact verified Keychain version and appends a retained terminal receipt.

import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';

const TELEGRAM_ORIGIN = 'https://api.telegram.org';
const TELEGRAM_TIMEOUT_MS = 12_000;

export async function telegramSendMessage({ chatId, text, parseMode = null, useContext = {} }) {
  const credential = checkoutCachedCredential('telegram_bot_token');
  if (!credential) throw new Error('telegram_credential_not_enrolled');
  const body = {
    chat_id: String(chatId),
    text: String(text),
    ...(parseMode ? { parse_mode: parseMode } : {}),
  };
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'telegram_send_message',
    endpoint: `${TELEGRAM_ORIGIN}/bot{credential}/sendMessage`,
    requestHash: credentialUseEvidenceHash({ method: 'POST', body }),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });
  let response;
  try {
    response = await fetchWithTimeout(`${TELEGRAM_ORIGIN}/bot${credential.value}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }, TELEGRAM_TIMEOUT_MS);
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
  const payload = await response.json().catch(() => ({}));
  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({
      status: response.status,
      telegram_ok: payload?.ok === true,
      telegram_result_id: payload?.result?.message_id || null,
    }),
    outcomeClass: `http_${response.status}`,
  });
  if (!response.ok || payload?.ok === false) {
    throw new Error(payload?.description || `Telegram API error (${response.status})`);
  }
  return payload;
}

export async function telegramGetUpdates({ limit = 20, useContext = {} } = {}) {
  const credential = checkoutCachedCredential('telegram_bot_token');
  if (!credential) throw new Error('telegram_credential_not_enrolled');
  const capped = Math.min(Math.max(Number(limit) || 20, 1), 100);
  const reservation = await credentialLedger.reserveCredentialUse({
    ...credential,
    operation: 'telegram_get_updates',
    endpoint: `${TELEGRAM_ORIGIN}/bot{credential}/getUpdates`,
    requestHash: credentialUseEvidenceHash({ method: 'GET', query: { limit: capped } }),
    subjectAgentId: useContext.actorAgentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  });
  let response;
  try {
    response = await fetchWithTimeout(
      `${TELEGRAM_ORIGIN}/bot${credential.value}/getUpdates?limit=${capped}`,
      { method: 'GET' },
      TELEGRAM_TIMEOUT_MS,
    );
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
  const payload = await response.json().catch(() => ({}));
  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({
      status: response.status,
      telegram_ok: payload?.ok === true,
      update_count: Array.isArray(payload?.result) ? payload.result.length : null,
    }),
    outcomeClass: `http_${response.status}`,
  });
  if (!response.ok || payload?.ok === false) {
    throw new Error(payload?.description || `Telegram API error (${response.status})`);
  }
  return payload;
}
