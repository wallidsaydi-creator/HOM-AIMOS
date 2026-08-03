import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateSystemConfigValue } from '../../services/security/system-config-ledger.js';
import { parseIdentityVaultCredentialService } from '../../services/security/credential-store.js';
import { __private__ as identityVaultPrivate } from '../../services/integrations/identity-vault.js';

const root = new URL('../../', import.meta.url);
const source = (path) => readFileSync(new URL(path, root), 'utf8');
const workspace = fileURLToPath(root);

function runtimeSources(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    const absolute = `${directory}/${entry}`;
    if (statSync(absolute).isDirectory()) files.push(...runtimeSources(absolute));
    else if (/\.(?:js|mjs|sh)$/.test(entry)) files.push(absolute);
  }
  return files;
}

test('legacy integration_tokens projection has zero runtime readers or writers', () => {
  const allowed = new Set([`${workspace}/services/security/whole-brain-purge.js`]);
  const offenders = ['services', 'routes', 'jobs', 'scripts']
    .flatMap((directory) => runtimeSources(`${workspace}/${directory}`))
    .filter((file) => !allowed.has(file))
    .filter((file) => /\bintegration_tokens\b/.test(readFileSync(file, 'utf8')));
  assert.deepEqual(offenders, []);
  for (const file of allowed) {
    assert.match(readFileSync(file, 'utf8'), /\bintegration_tokens\b/);
  }
  const migration = source('migrations/086-retire-integration-token-authority.sql');
  assert.match(migration, /REVOKE ALL ON public\.integration_tokens FROM agent_runtime/);
  assert.match(migration, /Retained legacy OAuth projection/);
  assert.match(migration, /NOT VALID/);
});

test('identity-vault metadata rejects secret-shaped fields before enrollment', () => {
  assert.deepEqual(identityVaultPrivate.normalizeVaultMetadata({ instance_url: 'https://example.test' }), {
    instance_url: 'https://example.test',
  });
  assert.throws(
    () => identityVaultPrivate.normalizeVaultMetadata({ nested: { access_token: 'plaintext' } }),
    /forbidden secret field/,
  );
});

test('OAuth credential services have one native provider/kind naming authority', () => {
  assert.deepEqual(parseIdentityVaultCredentialService('oauth_github_access_token'), {
    provider: 'github',
    credentialKind: 'access',
  });
  assert.deepEqual(parseIdentityVaultCredentialService('oauth_google_refresh_token'), {
    provider: 'google',
    credentialKind: 'refresh',
  });
  assert.equal(parseIdentityVaultCredentialService('github_client_secret'), null);
});

test('Salesforce origin is signed, normalized, and SSRF constrained', () => {
  assert.deepEqual(
    validateSystemConfigValue('SALESFORCE_ORIGIN', 'https://acme.my.salesforce.com'),
    { ok: true, value: 'https://acme.my.salesforce.com' },
  );
  for (const value of [
    'http://acme.my.salesforce.com',
    'https://127.0.0.1',
    'https://example.com',
    'https://user:pass@acme.my.salesforce.com',
    'https://acme.my.salesforce.com/path',
    'https://acme.my.salesforce.com?target=internal',
  ]) {
    assert.equal(validateSystemConfigValue('SALESFORCE_ORIGIN', value).ok, false, value);
  }
});

test('GitHub and Salesforce use exact credential reservations and terminal receipts', () => {
  const integrationTools = source('services/integrations/integration-tools.js');
  assert.match(integrationTools, /async function githubRequest[\s\S]*reserveCredentialUse[\s\S]*finalizeCredentialUse/);
  assert.match(integrationTools, /salesforceListObjects[\s\S]*reserveCredentialUse[\s\S]*finalizeCredentialUse/);
  assert.doesNotMatch(integrationTools, /row\?\.access_token\s*\|\|/);

  const registry = source('services/orchestration/tool-registry.js');
  for (const tool of ['githubListRepos', 'githubSearchIssues', 'salesforceListObjects']) {
    assert.match(registry, new RegExp(`${tool}\\([\\s\\S]{0,220}credentialUseContext`), tool);
  }
});

test('direct GitHub and Salesforce routes bind signed POST bodies and capabilities', () => {
  const routes = source('routes/tools.js');
  for (const path of ['github/repos', 'github/issues/search', 'github/issues', 'github/prs']) {
    assert.match(routes, new RegExp(`router\\.post\\('/${path}', requireCapability\\('github'\\)`), path);
  }
  assert.match(routes, /router\.post\('\/salesforce\/objects', requireCapability\('salesforce'\)/);
  assert.doesNotMatch(routes, /GITHUB_TOKEN|SALESFORCE_ACCESS_TOKEN|SALESFORCE_INSTANCE_URL/);
  assert.doesNotMatch(routes, /router\.get\('\/(?:github|salesforce)\//);
});
