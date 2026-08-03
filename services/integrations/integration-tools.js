// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// ← Called by: tool-registry.js
// Pipeline: TOOL_REGISTRY | Position: Integration tool implementation
// ─────────────────────────────────────────────────────────────────────────────
import { AIMOS_COMPANY_ID } from '../core/runtime-config.js';
import { execFile } from 'child_process';
import { fetchWithTimeout } from '../orchestration/http.js';
import {
  getLatestIntegrationToken
} from './identity-vault.js';
import { peekCachedCredential } from '../security/credential-cache.js';
import { credentialLedger, credentialUseEvidenceHash } from '../security/credential-ledger.js';
import { systemConfigStore } from '../security/system-config-store.js';

const COMPANY = AIMOS_COMPANY_ID;

function toInt(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

async function getTokenRow(provider) {
  const aliases = provider === 'gmail' ? ['google'] : [];
  return getLatestIntegrationToken(COMPANY, provider, aliases);
}

function credentialAuthority(useContext = {}) {
  return {
    subjectAgentId: useContext.actorAgentId || useContext.subjectAgentId || useContext.agentId || 'housekeeper',
    requestReceiptId: useContext.requestReceiptId || null,
    requestReceiptMutationHash: useContext.requestReceiptMutationHash || null,
    requestAdmissionEventId: useContext.requestAdmissionEventId || null,
    requestAdmissionMutationHash: useContext.requestAdmissionMutationHash || null,
    autonomousActionEventId: useContext.autonomousActionEventId || null,
  };
}

async function githubRequest(target, operation, requestEvidence, useContext = {}) {
  const row = await getTokenRow('github');
  const checkout = row?.access_token_checkout || null;
  if (!checkout?.value) throw new Error('GitHub not connected');
  const endpoint = `${target.origin}${target.pathname}`;
  const reservation = await credentialLedger.reserveCredentialUse({
    ...checkout,
    operation,
    endpoint,
    requestHash: credentialUseEvidenceHash(requestEvidence),
    ...credentialAuthority(useContext),
  });
  let response = null;
  let terminalRecorded = false;
  try {
    response = await fetchWithTimeout(target.toString(), {
      headers: {
        Authorization: `Bearer ${checkout.value}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    const json = await response.json();
    if (!response.ok) {
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeClass: 'github_api_rejected',
        errorClass: `http_${response.status}`,
        outcomeHash: credentialUseEvidenceHash({ status: response.status, responseHash: credentialUseEvidenceHash(json) }),
      });
      terminalRecorded = true;
      throw new Error(json?.message || `GitHub error (${response.status})`);
    }
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'github_api_response',
      outcomeHash: credentialUseEvidenceHash({ status: response.status, responseHash: credentialUseEvidenceHash(json) }),
    });
    terminalRecorded = true;
    return json;
  } catch (error) {
    if (!terminalRecorded) {
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeClass: response ? 'github_api_response_invalid' : 'github_api_transport_failed',
        errorClass: error?.name || 'github_api_failed',
        outcomeHash: credentialUseEvidenceHash({ status: response?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
}

function runAppleScript(script) {
  return new Promise((resolve, reject) => {
    execFile('osascript', ['-e', script], { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve(stdout.trim());
    });
  });
}

function escapeAppleScriptString(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, ' ')
    // Strip any remaining ASCII control characters (0x00-0x1F except \n which is already handled)
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x09\x0b\x0c\x0e-\x1f]/g, '');
}

function hasDirectCredential(provider) {
  switch (provider) {
    case 'x': return !!(peekCachedCredential('x_bearer_token') || peekCachedCredential('x_api_key'));
    case 'stripe': return peekCachedCredential('stripe_secret_key');
    case 'telegram': return peekCachedCredential('telegram_bot_token');
    case 'imessage': return false;
    default: return false;
  }
}

export async function listIntegrationStatus() {
  const providers = [
    'google', 'gmail', 'youtube', 'calendar', 'drive',
    'github', 'openai', 'codex', 'x', 'salesforce', 'stripe', 'telegram', 'imessage',
  ];
  const googleConnected = peekCachedCredential('oauth_google_access_token')
    || peekCachedCredential('oauth_gmail_access_token');

  return providers.map(id => {
    const googleFamily = ['google', 'gmail', 'youtube', 'calendar', 'drive'].includes(id);
    const oauthProvider = googleFamily ? null : id;
    const connected = googleFamily
      ? googleConnected
      : (oauthProvider ? peekCachedCredential(`oauth_${oauthProvider}_access_token`) : false)
        || hasDirectCredential(id);

    return {
      id,
      enabled: Boolean(connected),
      connected: !!connected
    };
  });
}

export async function githubListRepos({ limit = 20, visibility = 'all' } = {}, useContext = {}) {
  const capped = Math.min(Math.max(toInt(limit, 20), 1), 100);
  const params = new URLSearchParams({
    per_page: String(capped),
    sort: 'updated',
    visibility
  });
  const target = new URL(`https://api.github.com/user/repos?${params.toString()}`);
  return githubRequest(target, 'github.repos.list', {
    method: 'GET', path: target.pathname, query: Object.fromEntries(params),
  }, useContext);
}

export async function githubSearchIssues({ query: q, limit = 10 } = {}, useContext = {}) {
  if (!q) throw new Error('query is required');

  const capped = Math.min(Math.max(toInt(limit, 10), 1), 100);
  const params = new URLSearchParams({
    q,
    per_page: String(capped)
  });
  const target = new URL(`https://api.github.com/search/issues?${params.toString()}`);
  return githubRequest(target, 'github.issues.search', {
    method: 'GET', path: target.pathname, query: Object.fromEntries(params),
  }, useContext);
}

export async function salesforceListObjects({ limit = 50 } = {}, useContext = {}) {
  const row = await getTokenRow('salesforce');
  const checkout = row?.access_token_checkout || null;
  const configuredInstanceUrl = systemConfigStore.readConfigString('SALESFORCE_ORIGIN');
  if (!checkout?.value || !configuredInstanceUrl) throw new Error('Salesforce not connected');
  const instance = new URL(configuredInstanceUrl);
  const salesforceHost = instance.hostname.toLowerCase();
  const approvedHost = salesforceHost === 'salesforce.com'
    || salesforceHost.endsWith('.salesforce.com')
    || salesforceHost === 'force.com'
    || salesforceHost.endsWith('.force.com');
  if (
    instance.protocol !== 'https:'
    || instance.username
    || instance.password
    || instance.port
    || instance.pathname !== '/'
    || instance.search
    || instance.hash
    || !approvedHost
  ) {
    throw new Error('Signed Salesforce instance URL is invalid');
  }
  const target = new URL('/services/data/v60.0/sobjects', instance);
  const reservation = await credentialLedger.reserveCredentialUse({
    ...checkout,
    operation: 'salesforce.objects.list',
    endpoint: `${target.origin}${target.pathname}`,
    requestHash: credentialUseEvidenceHash({ method: 'GET', origin: target.origin, path: target.pathname }),
    ...credentialAuthority(useContext),
  });
  let res = null;
  let terminalRecorded = false;
  let json = null;
  try {
    res = await fetchWithTimeout(target.toString(), {
      headers: { Authorization: `Bearer ${checkout.value}` },
    });
    json = await res.json();
    if (!res.ok) {
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeClass: 'salesforce_api_rejected',
        errorClass: `http_${res.status}`,
        outcomeHash: credentialUseEvidenceHash({ status: res.status, responseHash: credentialUseEvidenceHash(json) }),
      });
      terminalRecorded = true;
      throw new Error(json?.[0]?.message || `Salesforce error (${res.status})`);
    }
    await credentialLedger.finalizeCredentialUse({
      reservation,
      outcome: 'completed',
      outcomeClass: 'salesforce_api_response',
      outcomeHash: credentialUseEvidenceHash({ status: res.status, responseHash: credentialUseEvidenceHash(json) }),
    });
    terminalRecorded = true;
  } catch (error) {
    if (!terminalRecorded) {
      await credentialLedger.finalizeCredentialUse({
        reservation,
        outcome: 'failed',
        outcomeClass: res ? 'salesforce_api_response_invalid' : 'salesforce_api_transport_failed',
        errorClass: error?.name || 'salesforce_api_failed',
        outcomeHash: credentialUseEvidenceHash({ status: res?.status || null, error: error?.message || String(error) }),
      });
    }
    throw error;
  }
  const capped = Math.min(Math.max(toInt(limit, 50), 1), 500);
  return {
    total: (json.sobjects || []).length,
    sobjects: (json.sobjects || []).slice(0, capped)
  };
}

export async function githubListMyIssues({ limit = 20 } = {}, useContext = {}) {
  const capped = Math.min(Math.max(toInt(limit, 20), 1), 100);
  const params = new URLSearchParams({
    q: 'is:issue is:open author:@me',
    per_page: String(capped)
  });

  const target = new URL(`https://api.github.com/search/issues?${params.toString()}`);
  const json = await githubRequest(target, 'github.issues.mine', {
    method: 'GET', path: target.pathname, query: Object.fromEntries(params),
  }, useContext);
  return (json?.items || []).map((item) => ({
    id: item.id,
    number: item.number,
    title: item.title,
    repo: String(item.repository_url || '').split('/').slice(-1)[0] || '',
    state: item.state,
    url: item.html_url,
    updated_at: item.updated_at
  }));
}

export async function githubListMyPullRequests({ limit = 20 } = {}, useContext = {}) {
  const capped = Math.min(Math.max(toInt(limit, 20), 1), 100);
  const params = new URLSearchParams({
    q: 'is:pr is:open author:@me',
    per_page: String(capped)
  });

  const target = new URL(`https://api.github.com/search/issues?${params.toString()}`);
  const json = await githubRequest(target, 'github.pull_requests.mine', {
    method: 'GET', path: target.pathname, query: Object.fromEntries(params),
  }, useContext);
  return (json?.items || []).map((item) => ({
    id: item.id,
    number: item.number,
    title: item.title,
    repo: String(item.repository_url || '').split('/').slice(-1)[0] || '',
    state: item.state,
    url: item.html_url,
    updated_at: item.updated_at
  }));
}

export async function imessageListChats({ limit = 10 } = {}) {
  const capped = Math.min(Math.max(toInt(limit, 10), 1), 100);
  const script = `
    tell application "Messages"
      set chatList to {}
      set allChats to chats
      repeat with i from 1 to (count of allChats)
        if i > ${capped} then exit repeat
        set c to item i of allChats
        set end of chatList to name of c
      end repeat
      return chatList
    end tell
  `;
  const result = await runAppleScript(script);
  return result.split(', ').filter(Boolean);
}

export async function imessageSearchContact({ query }) {
  if (!query) throw new Error('query is required');
  const safeQuery = escapeAppleScriptString(query);
  // Use Contacts.app — Messages.app "buddies" is deprecated on macOS 12+
  const script = `
    tell application "Contacts"
      set matchResults to {}
      repeat with p in every person
        set pName to name of p
        set pPhone to ""
        set pEmail to ""
        if (count of phones of p) > 0 then set pPhone to value of phone 1 of p
        if (count of emails of p) > 0 then set pEmail to value of email 1 of p
        if pName contains "${safeQuery}" or pPhone contains "${safeQuery}" or pEmail contains "${safeQuery}" then
          set end of matchResults to (pName & " (" & pPhone & ")")
        end if
      end repeat
      return matchResults
    end tell
  `;
  const result = await runAppleScript(script);
  return result.split(', ').filter(Boolean);
}

export async function contactsSearch({ query }) {
  if (!query) throw new Error('query is required');
  const safeQuery = escapeAppleScriptString(query);
  const script = `
    tell application "Contacts"
      set results to {}
      repeat with p in every person
        set pName to name of p
        set pPhone to ""
        set pEmail to ""
        if (count of phones of p) > 0 then set pPhone to value of phone 1 of p
        if (count of emails of p) > 0 then set pEmail to value of email 1 of p
        if pName contains "${safeQuery}" or pPhone contains "${safeQuery}" or pEmail contains "${safeQuery}" then
          set end of results to (pName & " | " & pPhone & " | " & pEmail)
        end if
      end repeat
      return results
    end tell
  `;
  const result = await runAppleScript(script);
  return result
    .split(', ')
    .filter(Boolean)
    .map((entry) => {
      const [name = '', phone = '', email = ''] = entry.split(' | ');
      return {
        name: name.trim(),
        phone: phone.trim(),
        email: email.trim()
      };
    });
}

export async function imessageSend({ to, message }) {
  if (!to || !message) throw new Error('to and message are required');
  const safe = escapeAppleScriptString(message);

  // If "to" is a name (not a phone/email), resolve it via Contacts first
  const looksLikeHandle = /^[\+\d]/.test(to.trim()) || to.includes('@');
  let handle = to.trim();

  if (!looksLikeHandle) {
    const safeQuery = escapeAppleScriptString(to);
    const lookupScript = `
      tell application "Contacts"
        set matchResults to {}
        repeat with p in every person
          set pName to name of p
          if pName contains "${safeQuery}" then
            if (count of phones of p) > 0 then
              set end of matchResults to value of phone 1 of p
            else if (count of emails of p) > 0 then
              set end of matchResults to value of email 1 of p
            end if
          end if
        end repeat
        return matchResults
      end tell
    `;
    try {
      const raw = await runAppleScript(lookupScript);
      const found = raw.split(', ').map(s => s.trim()).filter(Boolean);
      if (found.length === 0) throw new Error(`No contact found for "${to}" in Contacts.app`);
      handle = found[0];
    } catch (err) {
      throw new Error(`Contacts lookup failed for "${to}": ${err.message}`);
    }
  }

  const safeHandle = escapeAppleScriptString(handle);
  // service lookup broken on macOS 12+; buddy without explicit service works
  const script = `
    tell application "Messages"
      try
        send "${safe}" to buddy "${safeHandle}"
        return "sent"
      on error errMsg
        error errMsg
      end try
    end tell
  `;

  try {
    const result = await runAppleScript(script);
    if (result === "sent") return { success: true, sentTo: handle };
    throw new Error(result);
  } catch (err) {
    throw new Error(`iMessage failure: ${err.message}`);
  }
}
