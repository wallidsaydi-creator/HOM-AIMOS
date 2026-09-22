// Native Telegram credential-use owner. Every outbound request reserves the
// exact verified Keychain version and appends a retained terminal receipt.

import { fetchWithTimeout } from '../orchestration/http.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { verifyToolActionAuthority } from '../orchestration/tool-action-ledger.js';

const TELEGRAM_ORIGIN = 'https://api.telegram.org';
const TELEGRAM_TIMEOUT_MS = 12_000;

export async function telegramSendMessage({ chatId, text, parseMode = null, useContext = {} }) {
  const authorizedArgs = useContext.toolActionArguments || {
    chat_id: chatId, text, parse_mode: parseMode,
  };
  if (authorizedArgs.chat_id !== chatId || authorizedArgs.text !== text
      || (authorizedArgs.parse_mode ?? null) !== parseMode) {
    throw new Error('telegram_action_argument_substitution');
  }
  await verifyToolActionAuthority(useContext.toolActionAuthority, {
    expectedCompanyId: AIMOS_COMPANY_ID,
    expectedTool: 'telegram_send',
    expectedActorAgentId: useContext.actorAgentId,
    expectedArguments: authorizedArgs,
  });
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
  let payload;
  try {
    response = await fetchWithTimeout(`${TELEGRAM_ORIGIN}/bot${credential.value}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),

      signal: useContext?.signal,
      deadlineAt: useContext?.deadlineAt,
      destinationPolicy: 'public',
    }, TELEGRAM_TIMEOUT_MS);
    payload = await response.json();
    if (typeof payload?.ok !== 'boolean') throw new Error('telegram_response_invalid');
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
    if (response?.body && !response.body.locked && !response.bodyUsed) await response.body.cancel().catch(() => {});
  }

  if (!response.ok || payload?.ok === false) {
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({
        status: response.status,
        telegram_ok: payload?.ok === true,
        response_hash: credentialUseEvidenceHash(payload),
      }),
      outcomeClass: `http_${response.status}`,
      errorClass: String(payload?.description || `http_${response.status}`),
    });
    throw new Error(payload?.description || `Telegram API error (${response.status})`);
  }
  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({
      status: response.status,
      telegram_ok: true,
      telegram_result_id: payload?.result?.message_id || null,
    }),
    outcomeClass: `http_${response.status}`,
  });
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
  let payload;
  try {
    response = await fetchWithTimeout(
      `${TELEGRAM_ORIGIN}/bot${credential.value}/getUpdates?limit=${capped}`,
      { method: 'GET' ,
      signal: useContext?.signal,
      deadlineAt: useContext?.deadlineAt,
      destinationPolicy: 'public',
    },
      TELEGRAM_TIMEOUT_MS,
    );
    payload = await response.json();
    if (typeof payload?.ok !== 'boolean') throw new Error('telegram_response_invalid');
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
    if (response?.body && !response.body.locked && !response.bodyUsed) await response.body.cancel().catch(() => {});
  }

  if (!response.ok || payload?.ok === false) {
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'failed',
      outcomeHash: credentialUseEvidenceHash({
        status: response.status,
        telegram_ok: payload?.ok === true,
        response_hash: credentialUseEvidenceHash(payload),
      }),
      outcomeClass: `http_${response.status}`,
      errorClass: String(payload?.description || `http_${response.status}`),
    });
    throw new Error(payload?.description || `Telegram API error (${response.status})`);
  }
  await credentialLedger.finalizeCredentialUse({
    reservation,
    outcome: 'completed',
    outcomeHash: credentialUseEvidenceHash({
      status: response.status,
      telegram_ok: true,
      update_count: Array.isArray(payload?.result) ? payload.result.length : null,
    }),
    outcomeClass: `http_${response.status}`,
  });
  return payload;
}
