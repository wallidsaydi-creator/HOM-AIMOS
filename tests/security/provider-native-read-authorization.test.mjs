import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { xSearchRecent } from '../../services/integrations/x-search.js';
import { xGetMyProfile } from '../../services/integrations/x-tools.js';
import { telegramGetUpdates } from '../../services/integrations/telegram-tools.js';
import {
  githubListRepos,
  listIntegrationStatus,
  imessageListChats,
  imessageSearchContact,
  contactsSearch,
} from '../../services/integrations/integration-tools.js';
import { searchWeb } from '../../services/integrations/web-search.js';

test('native account reads deny missing verified actor before credential or AppleScript access', async () => {
  const calls = [
    () => xSearchRecent({ query: 'security', useContext: {} }),
    () => xGetMyProfile({}),
    () => telegramGetUpdates({ useContext: {} }),
    () => githubListRepos({}, {}),
    () => listIntegrationStatus({}),
    () => imessageListChats({}, {}),
    () => imessageSearchContact({ query: 'Alice' }, {}),
    () => contactsSearch({ query: 'Alice' }, {}),
    () => searchWeb({ query: 'security', useContext: {} }),
  ];
  for (const call of calls) {
    await assert.rejects(call(), /credential_use_actor_missing/);
  }
});

test('integration status tool forwards verified execution context to its native owner', async () => {
  const registry = await readFile(new URL('../../services/orchestration/tool-registry.js', import.meta.url), 'utf8');
  const start = registry.indexOf('  integrations_status: {');
  const end = registry.indexOf('  github_list_repos: {', start);
  assert.ok(start >= 0 && end > start);
  assert.match(registry.slice(start, end), /listIntegrationStatus\(\s*invocationOptions\.credentialUseContext \|\| \{\}/);
});

test('Telegram recent route preserves the exact signed actor epoch at native admission', async () => {
  const routes = await readFile(new URL('../../routes/tools.js', import.meta.url), 'utf8');
  const start = routes.indexOf("router.get('/telegram/recent'");
  const end = routes.indexOf("router.post('/github/repos'", start);
  assert.ok(start >= 0 && end > start);
  const body = routes.slice(start, end);
  assert.match(body, /telegramGetUpdates\(\{\s*limit,\s*useContext: req\.executionContext/);
  assert.doesNotMatch(body, /useContext:\s*\{/);
});

test('Salesforce and X write owners authorize before credential checkout', async () => {
  const [integrations, xTools] = await Promise.all([
    readFile(new URL('../../services/integrations/integration-tools.js', import.meta.url), 'utf8'),
    readFile(new URL('../../services/integrations/x-tools.js', import.meta.url), 'utf8'),
  ]);
  const salesforce = integrations.slice(
    integrations.indexOf('export async function salesforceListObjects'),
    integrations.indexOf('export async function githubListMyIssues'),
  );
  assert.ok(salesforce.indexOf("operation: 'salesforce.objects.list'") >= 0);
  assert.ok(salesforce.indexOf('authorizeCredentialUse') < salesforce.indexOf("getTokenRow('salesforce')"));
  for (const name of ['xPostTweet', 'xReplyToTweet', 'xQuoteTweet']) {
    const start = xTools.indexOf(`export async function ${name}`);
    const body = xTools.slice(start, xTools.indexOf('  if (!hasOAuth1Credentials()', start));
    assert.ok(start >= 0 && body.includes('authorizeCredentialUse'), `${name} checks grant before credential presence`);
  }
});
