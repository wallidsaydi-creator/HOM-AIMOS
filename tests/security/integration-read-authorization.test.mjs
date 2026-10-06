import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createCredentialLedger, credentialUseCapability } from '../../services/security/credential-ledger.js';
import { requireCapability } from '../../services/security/require-capability.js';
import { defaultPermissions } from '../../services/core/permissions.js';
import { canonicalJson } from '../../services/security/agent-identity.js';
import { gmailGetMessage, gmailListInbox } from '../../services/integrations/google-tools.js';
import { stripeAccountSummary } from '../../services/integrations/stripe-tools.js';

const EPOCH = '2026-10-06T00:00:00.000Z';
const HASH = 'a'.repeat(64);
const argsHash = (value) => createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
const context = {
  actorAgentId: 'reader',
  actorValidFromIso: EPOCH,
  requestReceiptId: 'receipt',
  requestReceiptMutationHash: HASH,
  requestAdmissionEventId: 'admission',
  requestAdmissionMutationHash: HASH,
};

function admission() {
  return {
    id: 'admission',
    signer_agent_id: 'housekeeper',
    operation: 'request_admission_verified',
    key: 'receipt',
    agent_id: 'reader',
    authority_kind: 'housekeeper_observation_of_verified_request',
    mutation_hash: Buffer.from(HASH, 'hex'),
    metadata: {
      request_receipt_id: 'receipt',
      request_receipt_mutation_hash: HASH,
      request_hash: HASH,
      actor_agent_id: 'reader',
      actor_valid_from: EPOCH,
    },
  };
}

function ledgerWithPermissions(permissions, observations) {
  return createCredentialLedger({
    verifyRequestAuthorityFn: async ({ actorAgentId }) => {
      observations.push('verified_receipt');
      assert.equal(actorAgentId, 'reader');
      return { actorAgentId, actorValidFromIso: EPOCH, requestHash: HASH };
    },
    verifyAutonomousEventFn: async () => {
      observations.push('verified_admission');
      return admission();
    },
    getPermissionsFn: async (agentId, companyId, options) => {
      observations.push('checked_grant');
      assert.equal(agentId, 'reader');
      assert.equal(companyId, 'hom');
      assert.equal(options.subjectValidFromIso, EPOCH);
      return permissions;
    },
    queryFn: async () => {
      observations.push('read_credential_chain');
      throw new Error('credential access must not occur');
    },
  });
}

test('sensitive credential endpoints map to explicit grants', async () => {
  for (const capability of ['drive', 'google_account', 'stripe']) {
    assert.equal(defaultPermissions()[capability], false);
  }
  const cases = [
    ['google.api.get', 'https://www.googleapis.com/gmail/v1/users/me/messages', 'email'],
    ['google.api.get', 'https://www.googleapis.com/calendar/v3/calendars/primary/events', 'email'],
    ['google.api.get', 'https://www.googleapis.com/drive/v3/files', 'drive'],
    ['google.api.get', 'https://www.googleapis.com/docs/v1/documents/123', 'drive'],
    ['google.api.get', 'https://www.googleapis.com/sheets/v4/spreadsheets/123', 'drive'],
    ['google.api.get', 'https://www.googleapis.com/youtube/v3/videos', 'youtube'],
    ['google.api.get', 'https://www.googleapis.com/oauth2/v2/userinfo', 'google_account'],
    ['stripe_api_read', 'https://api.stripe.com/v1/customers', 'stripe'],
    ['x_api_read', 'https://api.x.com/2/users/me', 'x'],
    ['x_search_recent', 'https://api.twitter.com/2/tweets/search/recent', 'x'],
    ['telegram_get_updates', 'https://api.telegram.org/bot{credential}/getUpdates', 'email'],
    ['github.repos.list', 'https://api.github.com/user/repos', 'github'],
    ['salesforce.objects.list', 'https://acme.my.salesforce.com/services/data/v60.0/sobjects', 'salesforce'],
    ['salesforce.objects.list', 'https://acme.force.com/services/data/v60.0/sobjects', 'salesforce'],
    ['perplexity_web_search', 'https://api.perplexity.ai/chat/completions', 'internet'],
    ['brave_web_search', 'https://api.search.brave.com/res/v1/web/search', 'internet'],
    ['imessage_list_chats', 'aimos-local://messages/chats', 'email'],
    ['imessage_search_contact', 'aimos-local://messages/search-contact', 'email'],
    ['imessage_request_access', 'aimos-local://messages/request-access', 'email'],
    ['imessage_send', 'aimos-local://messages/send', 'email'],
    ['contacts_search', 'aimos-local://contacts/search', 'email'],
    ['integration_status', 'aimos-local://integrations/status', 'admin_override'],
  ];
  for (const [operation, endpoint, expected] of cases) {
    assert.equal(credentialUseCapability(operation, endpoint), expected);
  }
  assert.throws(() => credentialUseCapability('stripe_api_read', 'https://evil.example/v1/customers'), /capability_unknown/);
  assert.throws(() => credentialUseCapability('google.api.get', 'https://www.googleapis.com/unknown/private'), /capability_unknown/);
  for (const [operation, endpoint] of [
    ['x_api_read', 'https://evil.example/2/users/me'],
    ['telegram_get_updates', 'https://api.telegram.org/bot{credential}/sendMessage'],
    ['github.repos.list', 'https://api.github.com/user/secrets'],
    ['salesforce.objects.list', 'https://evil.example/services/data/v60.0/sobjects'],
    ['perplexity_web_search', 'https://evil.example/chat/completions'],
    ['imessage_list_chats', 'aimos-local://contacts/search'],
  ]) {
    assert.throws(() => credentialUseCapability(operation, endpoint), /capability_unknown/, operation);
  }
  assert.throws(() => credentialUseCapability('google.api.get', cases[0][1], 'drive'), /capability_mismatch/);
  assert.throws(() => credentialUseCapability('stripe_api_read', 'https://api.stripe.com/v1/customers?secret=leak'), /endpoint_not_template/);
  for (const [operation, endpoint] of cases.slice(8)) {
    const observations = [];
    const ledger = ledgerWithPermissions({}, observations);
    await assert.rejects(ledger.authorizeCredentialUse({ operation, endpoint, useContext: context }), /credential_use_capability_denied/);
    assert.deepEqual(observations, ['verified_receipt', 'verified_admission', 'checked_grant']);
  }
});

test('native credential authority denies missing grant before credential chain access', async () => {
  const observations = [];
  const ledger = ledgerWithPermissions({ email: false }, observations);
  await assert.rejects(ledger.authorizeCredentialUse({
    operation: 'google.api.get',
    endpoint: 'https://www.googleapis.com/gmail/v1/users/me/messages',
    useContext: context,
  }), /credential_use_capability_denied:email/);
  assert.deepEqual(observations, ['verified_receipt', 'verified_admission', 'checked_grant']);
});

test('shared executive briefing requires exact-epoch admin authority before read or mutation', async () => {
  const source = await readFile(new URL('../../routes/briefing.js', import.meta.url), 'utf8');
  assert.match(source, /router\.get\('\/config', requireCapability\('admin_override'\)/);
  assert.match(source, /router\.post\('\/config', requireCapability\('admin_override'\)/);
  assert.match(source, /router\.get\('\/today', requireCapability\('admin_override'\)/);
  assert.match(source, /router\.get\('\/push', requireCapability\('admin_override'\)/);
  assert.match(source, /FROM aimos_directives[\s\S]*WHERE company_id = \$1/);
  let downstreamEffects = 0;
  const middleware = requireCapability('admin_override', {
    getPermissions: async (_agentId, _companyId, options) => {
      assert.equal(options.subjectValidFromIso, EPOCH);
      return { admin_override: false, email: true };
    },
    logEvent: async () => {},
  });
  for (const [method, originalUrl] of [
    ['GET', '/briefing/config'],
    ['POST', '/briefing/config'],
    ['GET', '/briefing/today'],
    ['GET', '/briefing/push'],
  ]) {
    const response = {
      status(code) { this.code = code; return this; },
      json(body) { this.body = body; return this; },
    };
    await middleware({
      method,
      agentId: 'reader',
      executionContext: { actorAgentId: 'reader', actorValidFromIso: EPOCH, companyId: 'hom' },
      body: { sections: { email: false } },
      query: {},
      originalUrl,
    }, response, () => { downstreamEffects += 1; });
    assert.equal(response.code, 403, originalUrl);
  }
  assert.equal(downstreamEffects, 0, 'no task query, provider checkout, or AppleScript handler can run');
});

test('native credential authority accepts exact epoch grant and rejects epoch substitution', async () => {
  const ledger = ledgerWithPermissions({ stripe: true }, []);
  const operation = 'stripe_api_read';
  const endpoint = 'https://api.stripe.com/v1/customers';
  assert.equal((await ledger.authorizeCredentialUse({ operation, endpoint, useContext: context })).capability, 'stripe');
  await assert.rejects(ledger.authorizeCredentialUse({
    operation, endpoint,
    useContext: { ...context, actorValidFromIso: '2026-10-05T00:00:00.000Z' },
  }), /credential_use_actor_epoch_mismatch/);
});

test('a non-Housekeeper admission cannot license credential checkout or reservation', async () => {
  const observations = [];
  const ledger = createCredentialLedger({
    verifyRequestAuthorityFn: async () => ({ actorValidFromIso: EPOCH, requestHash: HASH }),
    verifyAutonomousEventFn: async () => ({ ...admission(), signer_agent_id: 'reader' }),
    getPermissionsFn: async () => { observations.push('grant'); return { email: true }; },
    queryFn: async () => { observations.push('credential_chain'); throw new Error('credential access must not occur'); },
  });
  const operation = 'google.api.get';
  const endpoint = 'https://www.googleapis.com/gmail/v1/users/me/messages';
  await assert.rejects(ledger.authorizeCredentialUse({ operation, endpoint, useContext: context }),
    /credential_use_request_admission_invalid/);
  await assert.rejects(ledger.reserveCredentialUse({
    serviceName: 'google', slotId: 'test-slot', credentialHash: HASH,
    effectiveProvenanceId: 'provenance', effectiveMutationHash: HASH,
    operation, endpoint, requestHash: HASH, subjectAgentId: 'reader',
    actorValidFromIso: EPOCH,
    requestReceiptId: context.requestReceiptId,
    requestReceiptMutationHash: context.requestReceiptMutationHash,
    requestAdmissionEventId: context.requestAdmissionEventId,
    requestAdmissionMutationHash: context.requestAdmissionMutationHash,
  }), /credential_use_request_admission_invalid/);
  assert.deepEqual(observations, []);
});

test('native credential authority requires verified admission and an operation-bound Housekeeper action', async () => {
  const ledger = ledgerWithPermissions({ email: true }, []);
  await assert.rejects(ledger.authorizeCredentialUse({
    operation: 'google.api.get',
    endpoint: 'https://www.googleapis.com/gmail/v1/users/me/messages',
    useContext: { ...context, requestAdmissionEventId: null },
  }), /credential_use_request_admission_incomplete/);
  await assert.rejects(ledger.authorizeCredentialUse({
    operation: 'google.api.get',
    endpoint: 'https://www.googleapis.com/gmail/v1/users/me/messages',
    useContext: { actorAgentId: 'housekeeper' },
  }), /credential_use_verified_authority_required/);
  const autonomous = createCredentialLedger({
    verifyAutonomousEventFn: async () => ({
      signer_agent_id: 'housekeeper',
      operation: 'tool_execution_started',
      metadata: { schema: 'aimos.tool-action/v1', dispatch_allowed: true, actor_agent_id: 'housekeeper', tool: 'drive_list', args_sha256: argsHash({}) },
    }),
  });
  await assert.rejects(autonomous.authorizeCredentialUse({
    operation: 'google.api.get',
    endpoint: 'https://www.googleapis.com/gmail/v1/users/me/messages',
    useContext: { actorAgentId: 'housekeeper', autonomousActionEventId: 'action', toolActionArguments: {} },
  }), /credential_use_autonomous_action_invalid/);
  const allowed = await autonomous.authorizeCredentialUse({
    operation: 'google.api.get',
    endpoint: 'https://www.googleapis.com/drive/v3/files',
    requestTarget: 'https://www.googleapis.com/drive/v3/files?q=trashed%3Dfalse&pageSize=20',
    useContext: { actorAgentId: 'housekeeper', autonomousActionEventId: 'action', toolActionArguments: {} },
  });
  assert.equal(allowed.capability, 'drive');
});

test('Housekeeper dynamic resource IDs must match signed tool arguments before checkout', async () => {
  for (const [tool, args, operation, endpoint] of [
    ['drive_read', { file_id: 'file-A' }, 'google.api.get', 'https://www.googleapis.com/drive/v3/files/file-B'],
    ['docs_read', { document_id: 'doc-A' }, 'google.api.get', 'https://www.googleapis.com/docs/v1/documents/doc-B'],
    ['sheets_read', { spreadsheet_id: 'sheet-A', range: 'Sheet1!A1' }, 'google.api.get', 'https://www.googleapis.com/sheets/v4/spreadsheets/sheet-B/values/Sheet1!A1'],
    ['gmail_reply', { messageId: 'msg-A', body: 'reply' }, 'google.api.get', 'https://www.googleapis.com/gmail/v1/users/me/messages/msg-B'],
  ]) {
    let credentialQueried = false;
    const ledger = createCredentialLedger({
      verifyAutonomousEventFn: async () => ({
        signer_agent_id: 'housekeeper', operation: 'tool_execution_started',
        metadata: {
          schema: 'aimos.tool-action/v1', dispatch_allowed: true,
          actor_agent_id: 'housekeeper', tool, args_sha256: argsHash(args),
        },
      }),
      queryFn: async () => { credentialQueried = true; throw new Error('credential queried'); },
    });
    await assert.rejects(ledger.authorizeCredentialUse({
      operation, endpoint,
      useContext: { actorAgentId: 'housekeeper', autonomousActionEventId: 'action', toolActionArguments: args },
    }), /credential_use_autonomous_action_invalid/, tool);
    assert.equal(credentialQueried, false, tool);
  }
});

test('Housekeeper Google list and YouTube queries match signed arguments', async () => {
  for (const [tool, args, endpoint, goodTarget, badTarget] of [
    ['gmail_search', { query: 'from:alice', max: 5 }, 'https://www.googleapis.com/gmail/v1/users/me/messages',
      'https://www.googleapis.com/gmail/v1/users/me/messages?q=from%3Aalice&maxResults=5',
      'https://www.googleapis.com/gmail/v1/users/me/messages?q=from%3Abob&maxResults=5'],
    ['youtube_search', { query: 'security', max: 10 }, 'https://www.googleapis.com/youtube/v3/search',
      'https://www.googleapis.com/youtube/v3/search?q=security&maxResults=10&type=video',
      'https://www.googleapis.com/youtube/v3/search?q=unrelated&maxResults=10&type=video'],
  ]) {
    const ledger = createCredentialLedger({
      verifyAutonomousEventFn: async () => ({
        signer_agent_id: 'housekeeper', operation: 'tool_execution_started',
        metadata: {
          schema: 'aimos.tool-action/v1', dispatch_allowed: true,
          actor_agent_id: 'housekeeper', tool, args_sha256: argsHash(args),
        },
      }),
    });
    const useContext = { actorAgentId: 'housekeeper', autonomousActionEventId: 'action', toolActionArguments: args };
    assert.equal((await ledger.authorizeCredentialUse({
      operation: 'google.api.get', endpoint, requestTarget: goodTarget, useContext,
    })).capability, tool === 'youtube_search' ? 'youtube' : 'email');
    await assert.rejects(ledger.authorizeCredentialUse({
      operation: 'google.api.get', endpoint, requestTarget: badTarget, useContext,
    }), /credential_use_autonomous_action_invalid/);
  }
});

test('Housekeeper channel and today-calendar tools enforce their fixed query windows', async () => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  for (const [tool, endpoint, goodTarget, badTarget, capability] of [
    ['youtube_channel', 'https://www.googleapis.com/youtube/v3/search',
      'https://www.googleapis.com/youtube/v3/search?channelId=channel-1&maxResults=10&order=date&type=video&part=snippet',
      'https://www.googleapis.com/youtube/v3/search?channelId=channel-1&maxResults=100&order=date&type=video&part=snippet', 'youtube'],
    ['calendar_today', 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      `https://www.googleapis.com/calendar/v3/calendars/primary/events?${new URLSearchParams({ singleEvents: 'true', orderBy: 'startTime', timeMin: today.toISOString(), timeMax: tomorrow.toISOString() })}`,
      `https://www.googleapis.com/calendar/v3/calendars/primary/events?${new URLSearchParams({ singleEvents: 'true', orderBy: 'startTime', timeMin: today.toISOString(), timeMax: new Date(tomorrow.getTime() + 86400000).toISOString() })}`, 'email'],
  ]) {
    const args = {};
    const ledger = createCredentialLedger({
      verifyAutonomousEventFn: async () => ({
        signer_agent_id: 'housekeeper', operation: 'tool_execution_started',
        metadata: { schema: 'aimos.tool-action/v1', dispatch_allowed: true,
          actor_agent_id: 'housekeeper', tool, args_sha256: argsHash(args) },
      }),
    });
    const useContext = { actorAgentId: 'housekeeper', autonomousActionEventId: 'action', toolActionArguments: args };
    assert.equal((await ledger.authorizeCredentialUse({
      operation: 'google.api.get', endpoint, requestTarget: goodTarget, useContext,
    })).capability, capability);
    await assert.rejects(ledger.authorizeCredentialUse({
      operation: 'google.api.get', endpoint, requestTarget: badTarget, useContext,
    }), /credential_use_autonomous_action_invalid/);
  }
});

test('direct autonomous Gmail message fetch requires signed message ID or private list proof before checkout', async () => {
  await assert.rejects(gmailGetMessage('message-B', {
    actorAgentId: 'housekeeper', autonomousActionEventId: 'action',
    toolActionArguments: { query: 'from:alice', max: 5 },
  }), /gmail_message_not_in_verified_list_response/);
});

test('Google and Stripe native reads reject missing authority before credential checkout', async () => {
  await assert.rejects(gmailListInbox({}, {}), /credential_use_actor_missing/);
  await assert.rejects(stripeAccountSummary({}), /credential_use_actor_missing/);
});

test('route capability check uses signed actor epoch and denies a missing grant', async () => {
  const calls = [];
  const middleware = requireCapability('email', {
    getPermissions: async (agentId, companyId, options) => {
      calls.push({ agentId, companyId, options });
      return { email: false };
    },
    logEvent: async () => {},
  });
  const req = { agentId: 'reader', executionContext: { actorAgentId: 'reader', actorValidFromIso: EPOCH, companyId: 'hom' }, body: {}, query: {}, originalUrl: '/tools/gmail/inbox' };
  const res = { status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  let advanced = false;
  await middleware(req, res, () => { advanced = true; });
  assert.equal(res.code, 403);
  assert.equal(advanced, false);
  assert.deepEqual(calls, [{ agentId: 'reader', companyId: 'hom', options: { subjectValidFromIso: EPOCH } }]);
});
