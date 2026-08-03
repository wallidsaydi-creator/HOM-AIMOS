// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js, telegram-bot.js
// Pipeline: TOOL_REGISTRY | Position: Google API tool implementation
// ─────────────────────────────────────────────────────────────────────────────
import { randomUUID } from 'node:crypto';
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { fetchWithTimeout } from '../orchestration/http.js';
import {
  appendIntegrationToken,
  getLatestIntegrationToken
} from './identity-vault.js';
import { checkoutCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';

const COMPANY = AIMOS_COMPANY_ID;
const GOOGLE_REQUEST_TIMEOUT_MS = 12_000;

async function refreshGoogleAccessToken(row, useContext = {}) {
  const refreshCheckout = row?.refresh_token_checkout || null;
  if (!refreshCheckout?.value) throw new Error('Google refresh token missing');
  const googleSecretCheckout = checkoutCachedCredential('google_client_secret');
  const googleClientId = systemConfigStore.readConfigString('GOOGLE_CLIENT_ID');
  if (!googleClientId || !googleSecretCheckout?.value) {
    throw new Error('Google OAuth client credentials missing');
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshCheckout.value,
    client_id: googleClientId,
    client_secret: googleSecretCheckout.value
  });
  const endpoint = 'https://oauth2.googleapis.com/token';
  const useGroupId = randomUUID();
  const requestHash = credentialUseEvidenceHash({
    method: 'POST',
    endpoint,
    grantType: 'refresh_token',
    clientIdHash: credentialUseEvidenceHash(googleClientId),
  });
  const context = useContext && typeof useContext === 'object' ? useContext : {};
  const authority = {
    subjectAgentId: context.actorAgentId || context.subjectAgentId || context.agentId || 'housekeeper',
    requestReceiptId: context.requestReceiptId || null,
    requestReceiptMutationHash: context.requestReceiptMutationHash || null,
    requestAdmissionEventId: context.requestAdmissionEventId || null,
    requestAdmissionMutationHash: context.requestAdmissionMutationHash || null,
    autonomousActionEventId: context.autonomousActionEventId || null,
  };
  let refreshReservation = null;
  let clientSecretReservation = null;
  let res = null;
  let terminalRecorded = false;
  try {
    refreshReservation = await credentialLedger.reserveCredentialUse({
      ...refreshCheckout,
      operation: 'google.oauth.refresh.refresh_token',
      endpoint,
      requestHash,
      useGroupId,
      ...authority,
    });
    clientSecretReservation = await credentialLedger.reserveCredentialUse({
      ...googleSecretCheckout,
      operation: 'google.oauth.refresh.client_secret',
      endpoint,
      requestHash,
      useGroupId,
      ...authority,
    });
    res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    }, GOOGLE_REQUEST_TIMEOUT_MS);
    const data = await res.json();
    if (!res.ok || data.error) {
      const outcomeHash = credentialUseEvidenceHash({
        status: res.status,
        providerError: data.error || null,
      });
      await Promise.all([
        credentialLedger.finalizeCredentialUse({
          reservation: refreshReservation,
          outcome: 'failed',
          outcomeClass: 'google_oauth_rejected',
          errorClass: String(data.error || `http_${res.status}`),
          outcomeHash,
        }),
        credentialLedger.finalizeCredentialUse({
          reservation: clientSecretReservation,
          outcome: 'failed',
          outcomeClass: 'google_oauth_rejected',
          errorClass: String(data.error || `http_${res.status}`),
          outcomeHash,
        }),
      ]);
      terminalRecorded = true;
      throw new Error(data.error_description || data.error || `Google token refresh failed (${res.status})`);
    }
    const outcomeHash = credentialUseEvidenceHash({
      status: res.status,
      responseHash: credentialUseEvidenceHash(data),
    });
    const credentialUseEvidence = await Promise.all([
      credentialLedger.finalizeCredentialUse({
        reservation: refreshReservation,
        outcome: 'completed',
        outcomeClass: 'google_oauth_response',
        outcomeHash,
      }),
      credentialLedger.finalizeCredentialUse({
        reservation: clientSecretReservation,
        outcome: 'completed',
        outcomeClass: 'google_oauth_response',
        outcomeHash,
      }),
    ]);
    terminalRecorded = true;
    return { data, credentialUseEvidence };
  } catch (error) {
    if (!terminalRecorded) {
      const outcomeClass = res ? 'google_oauth_response_invalid' : 'google_oauth_transport_failed';
      const errorClass = error?.name || 'google_oauth_failed';
      const outcomeHash = credentialUseEvidenceHash({
        status: res?.status || null,
        error: error?.message || String(error),
      });
      if (refreshReservation) {
        await credentialLedger.finalizeCredentialUse({
          reservation: refreshReservation,
          outcome: 'failed',
          outcomeClass,
          errorClass,
          outcomeHash,
        });
      }
      if (clientSecretReservation) {
        await credentialLedger.finalizeCredentialUse({
          reservation: clientSecretReservation,
          outcome: 'failed',
          outcomeClass,
          errorClass,
          outcomeHash,
        });
      }
    }
    throw error;
  }
}

async function forceRefreshGoogleToken(row, useContext = {}) {
  const { data: refreshed, credentialUseEvidence } = await refreshGoogleAccessToken(row, useContext);
  const expiresAt = refreshed.expires_in
    ? new Date(Date.now() + Number(refreshed.expires_in) * 1000)
    : null;
  await appendIntegrationToken({
    companyId: COMPANY,
    provider: 'google',
    accessToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token || row.refresh_token || null,
    expiresAt,
    metadata: {
      ...(row.metadata || {}),
      provider: 'google',
      refreshed_from: row.provider || 'google'
    },
    authType: 'oauth',
    initiatingSubjectAgentId: useContext.actorAgentId
      || useContext.subjectAgentId
      || useContext.agentId
      || 'housekeeper',
    credentialUseEvidence,
  });
  const updated = await getLatestIntegrationToken(COMPANY, 'google', ['gmail']);
  if (!updated?.access_token_checkout?.value) {
    throw new Error('Google refreshed access token failed lifecycle materialization');
  }
  return updated;
}

async function getGoogleToken(useContext = {}) {
  const row = await getLatestIntegrationToken(COMPANY, 'google', ['gmail']);
  if (!row?.credential_integrity || !row.access_token_checkout?.value) {
    throw new Error('Google not connected or credential lifecycle verification failed');
  }

  if (row.expires_at) {
    const expiresAt = new Date(row.expires_at).getTime();
    const now = Date.now();
    if (Number.isFinite(expiresAt) && expiresAt <= now + 60_000 && row.refresh_token) {
      return forceRefreshGoogleToken(row, useContext);
    }
  }

  return row;
}

async function gFetch(path, options = {}, useContext = {}, responseMode = 'json') {
  let row = await getGoogleToken(useContext);
  const base = 'https://www.googleapis.com';
  const target = new URL(path, base);
  const endpoint = `${target.origin}${target.pathname}`;
  const method = String(options.method || 'GET').toUpperCase();
  const requestHash = credentialUseEvidenceHash({
    method,
    targetHash: credentialUseEvidenceHash(target.toString()),
    bodyHash: options.body == null ? null : credentialUseEvidenceHash(String(options.body)),
  });
  const context = useContext && typeof useContext === 'object' ? useContext : {};
  const authority = {
    subjectAgentId: context.actorAgentId || context.subjectAgentId || context.agentId || 'housekeeper',
    requestReceiptId: context.requestReceiptId || null,
    requestReceiptMutationHash: context.requestReceiptMutationHash || null,
    requestAdmissionEventId: context.requestAdmissionEventId || null,
    requestAdmissionMutationHash: context.requestAdmissionMutationHash || null,
    autonomousActionEventId: context.autonomousActionEventId || null,
  };

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const checkout = row.access_token_checkout;
    const reservation = await credentialLedger.reserveCredentialUse({
      ...checkout,
      operation: `google.api.${method.toLowerCase()}`,
      endpoint,
      requestHash,
      ...authority,
    });
    let res = null;
    let terminalRecorded = false;
    try {
      res = await fetchWithTimeout(target.toString(), {
        ...options,
        headers: {
          Authorization: `Bearer ${checkout.value}`,
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      }, GOOGLE_REQUEST_TIMEOUT_MS);
      if (res.status === 401 && attempt === 0 && row.refresh_token_checkout?.value) {
        terminalRecorded = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          outcomeClass: 'google_access_rejected',
          errorClass: 'http_401',
          outcomeHash: credentialUseEvidenceHash({ status: res.status, attempt }),
        });
        row = await forceRefreshGoogleToken(row, useContext);
        continue;
      }
      if (!res.ok) {
        const err = await res.text();
        terminalRecorded = true;
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          outcomeClass: 'google_api_rejected',
          errorClass: `http_${res.status}`,
          outcomeHash: credentialUseEvidenceHash({
            status: res.status,
            responseHash: credentialUseEvidenceHash(err),
          }),
        });
        throw new Error(`Google API error (${res.status}): ${err}`);
      }
      const result = responseMode === 'text' ? await res.text() : await res.json();
      terminalRecorded = true;
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'completed',
        outcomeClass: 'google_api_response',
        outcomeHash: credentialUseEvidenceHash({
          status: res.status,
          responseHash: credentialUseEvidenceHash(result),
        }),
      });
      return result;
    } catch (error) {
      if (!terminalRecorded) {
        await credentialLedger.finalizeCredentialUse({
          reservation,
          outcome: 'failed',
          outcomeClass: res ? 'google_api_response_invalid' : 'google_api_transport_failed',
          errorClass: error?.name || 'google_api_failed',
          outcomeHash: credentialUseEvidenceHash({
            status: res?.status || null,
            error: error?.message || String(error),
          }),
        });
      }
      throw error;
    }
  }
  throw new Error('Google API retry exhausted');
}

// ─── GMAIL ────────────────────────────────────────────────────────────────────

export async function gmailListInbox({ maxResults = 10, query: q = '' } = {}, credentialUseContext = {}) {
  const params = new URLSearchParams({ maxResults, q: q || 'in:inbox' });
  const list = await gFetch(`/gmail/v1/users/me/messages?${params}`, {}, credentialUseContext);
  const ids = (list.messages || []).slice(0, maxResults);
  const messages = await Promise.all(ids.map(m => gmailGetMessage(m.id, credentialUseContext)));
  return messages;
}

export async function gmailGetMessage(id, credentialUseContext = {}) {
  const msg = await gFetch(`/gmail/v1/users/me/messages/${id}?format=full`, {}, credentialUseContext);
  const headers = Object.fromEntries(
    (msg.payload?.headers || []).map((h) => [String(h.name || '').toLowerCase(), h.value])
  );
  return {
    id: msg.id,
    threadId: msg.threadId,
    from: headers.from,
    to: headers.to,
    subject: headers.subject,
    date: headers.date,
    snippet: msg.snippet,
    labelIds: msg.labelIds
  };
}

export async function gmailSearchMessages({ query: q, maxResults = 10 }, credentialUseContext = {}) {
  const params = new URLSearchParams({ q, maxResults });
  const list = await gFetch(`/gmail/v1/users/me/messages?${params}`, {}, credentialUseContext);
  const ids = (list.messages || []).slice(0, maxResults);
  return Promise.all(ids.map(m => gmailGetMessage(m.id, credentialUseContext)));
}

export async function gmailSendMessage({
  to,
  subject,
  body,
  threadId = null,
  inReplyTo = null,
  references = null,
}, credentialUseContext = {}) {
  const sanitizeMimeValue = (value) => String(value ?? '').replace(/[\r\n]+/g, ' ').trim();
  const safeTo = sanitizeMimeValue(to);
  const safeSubject = sanitizeMimeValue(subject);
  const safeInReplyTo = sanitizeMimeValue(inReplyTo);
  const safeReferences = sanitizeMimeValue(references);
  const safeBody = String(body ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const headers = [
    `To: ${safeTo}`,
    `Subject: ${safeSubject}`,
    'Content-Type: text/plain; charset=utf-8'
  ];
  if (safeInReplyTo) headers.push(`In-Reply-To: ${safeInReplyTo}`);
  if (safeReferences) headers.push(`References: ${safeReferences}`);
  const mime = `${headers.join('\r\n')}\r\n\r\n${safeBody}`;
  const raw = Buffer
    .from(mime, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return gFetch('/gmail/v1/users/me/messages/send', {
    method: 'POST',
    body: JSON.stringify({
      raw,
      ...(threadId ? { threadId } : {})
    })
  }, credentialUseContext);
}

export async function gmailGetThread(threadId, credentialUseContext = {}) {
  const thread = await gFetch(`/gmail/v1/users/me/threads/${threadId}?format=metadata`, {}, credentialUseContext);
  return thread;
}

export async function gmailReplyMessage({ messageId, body }, credentialUseContext = {}) {
  if (!messageId) throw new Error('messageId is required');
  const message = await gFetch(
    `/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}?format=full`,
    {},
    credentialUseContext,
  );
  const headers = Object.fromEntries(
    (message.payload?.headers || []).map((h) => [String(h.name || '').toLowerCase(), h.value])
  );
  const to = headers.from || '';
  const baseSubject = String(headers.subject || '').trim();
  const subject = /^re:/i.test(baseSubject) ? baseSubject : `Re: ${baseSubject}`;
  const inReplyTo = headers['message-id'] || '';
  const references = headers.references
    ? `${headers.references} ${inReplyTo}`.trim()
    : inReplyTo;

  return gmailSendMessage({
    to,
    subject,
    body: String(body || ''),
    threadId: message.threadId || null,
    inReplyTo,
    references,
  }, credentialUseContext);
}

// ─── YOUTUBE ──────────────────────────────────────────────────────────────────

export async function youtubeSearch({ query: q, maxResults = 10, type = 'video' }, credentialUseContext = {}) {
  const params = new URLSearchParams({ q, maxResults, type, part: 'snippet' });
  return gFetch(`/youtube/v3/search?${params}`, {}, credentialUseContext);
}

export async function youtubeChannelStats(channelId, credentialUseContext = {}) {
  const id = channelId || systemConfigStore.readConfigString('YOUTUBE_CHANNEL_ID');
  const params = new URLSearchParams({ id, part: 'snippet,statistics' });
  return gFetch(`/youtube/v3/channels?${params}`, {}, credentialUseContext);
}

export async function youtubeVideoDetails(videoId, credentialUseContext = {}) {
  const params = new URLSearchParams({ id: videoId, part: 'snippet,statistics,contentDetails' });
  return gFetch(`/youtube/v3/videos?${params}`, {}, credentialUseContext);
}

export async function youtubeListChannelVideos({ channelId, maxResults = 20 } = {}, credentialUseContext = {}) {
  const id = channelId || systemConfigStore.readConfigString('YOUTUBE_CHANNEL_ID');
  const params = new URLSearchParams({
    channelId: id,
    maxResults,
    order: 'date',
    type: 'video',
    part: 'snippet'
  });
  return gFetch(`/youtube/v3/search?${params}`, {}, credentialUseContext);
}

// ─── DRIVE ────────────────────────────────────────────────────────────────────

export async function driveListFiles({ query: q = '', maxResults = 20, mimeType } = {}, credentialUseContext = {}) {
  let qStr = q;
  if (mimeType) qStr = `mimeType='${mimeType}'${q ? ` and ${q}` : ''}`;
  const params = new URLSearchParams({
    q: qStr || 'trashed=false',
    pageSize: maxResults,
    fields: 'files(id,name,mimeType,size,modifiedTime,parents)'
  });
  return gFetch(`/drive/v3/files?${params}`, {}, credentialUseContext);
}

export async function driveGetFile(fileId, credentialUseContext = {}) {
  const meta = await gFetch(
    `/drive/v3/files/${fileId}?fields=id,name,mimeType,size,modifiedTime`,
    {},
    credentialUseContext,
  );
  return meta;
}

export async function driveReadTextFile(fileId, credentialUseContext = {}) {
  return gFetch(
    `/drive/v3/files/${fileId}?alt=media`,
    {},
    credentialUseContext,
    'text',
  );
}

// ─── CALENDAR ─────────────────────────────────────────────────────────────────

export async function calendarListEvents({
  calendarId = 'primary',
  maxResults = 20,
  timeMin,
} = {}, credentialUseContext = {}) {
  const params = new URLSearchParams({
    maxResults,
    singleEvents: 'true',
    orderBy: 'startTime',
    timeMin: timeMin || new Date().toISOString()
  });
  return gFetch(
    `/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events?${params}`,
    {},
    credentialUseContext,
  );
}

export async function calendarCreateEvent({
  summary,
  description = '',
  start,
  end,
  calendarId = 'primary',
}, credentialUseContext = {}) {
  return gFetch(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, {
    method: 'POST',
    body: JSON.stringify({
      summary,
      description,
      start: { dateTime: start, timeZone: 'UTC' },
      end: { dateTime: end, timeZone: 'UTC' }
    })
  }, credentialUseContext);
}

export async function calendarTodayEvents(credentialUseContext = {}) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const params = new URLSearchParams({
    singleEvents: 'true',
    orderBy: 'startTime',
    timeMin: today.toISOString(),
    timeMax: tomorrow.toISOString()
  });
  const raw = await gFetch(`/calendar/v3/calendars/primary/events?${params}`, {}, credentialUseContext);
  const formatter = new Intl.DateTimeFormat('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  });
  const events = (raw.items || []).map((item) => {
    const start = item?.start?.dateTime || item?.start?.date || null;
    const end = item?.end?.dateTime || item?.end?.date || null;
    let time = 'All day';
    if (item?.start?.dateTime) {
      try {
        time = formatter.format(new Date(item.start.dateTime));
      } catch {
        time = String(item.start.dateTime || '');
      }
    }
    return {
      id: item.id,
      summary: item.summary || '(No title)',
      description: item.description || '',
      location: item.location || '',
      status: item.status || '',
      htmlLink: item.htmlLink || '',
      start,
      end,
      time
    };
  });
  return {
    success: true,
    date: today.toISOString().slice(0, 10),
    events
  };
}

// ─── DOCS ─────────────────────────────────────────────────────────────────────

export async function docsGetDocument(documentId, credentialUseContext = {}) {
  return gFetch(`/docs/v1/documents/${documentId}`, {}, credentialUseContext);
}

export async function sheetsGetValues(spreadsheetId, range = 'Sheet1', credentialUseContext = {}) {
  return gFetch(
    `/sheets/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(range)}`,
    {},
    credentialUseContext,
  );
}

// ─── PROFILE ──────────────────────────────────────────────────────────────────

export async function googleGetProfile(credentialUseContext = {}) {
  return gFetch('/oauth2/v2/userinfo', {}, credentialUseContext);
}
