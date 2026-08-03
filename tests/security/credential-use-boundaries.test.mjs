import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

for (const relativePath of [
  'services/integrations/stripe-tools.js',
  'services/integrations/web-search.js',
  'services/integrations/telegram-tools.js',
  'services/orchestration/agent-tools.js',
]) {
  test(`${relativePath} explicitly reserves and finalizes credential use`, async () => {
    const source = await readFile(new URL(relativePath, ROOT), 'utf8');
    assert.match(source, /checkoutCachedCredential\(/);
    assert.match(source, /reserveCredentialUse\(/);
    assert.match(source, /finalizeCredentialUse\(/);
    assert.doesNotMatch(source, /getCachedCredential\(/);
    assert.doesNotMatch(source, /process\.env/);
  });
}

test('Telegram ledger endpoints never contain the credential-bearing runtime URL', async () => {
  const source = await readFile(new URL('services/integrations/telegram-tools.js', ROOT), 'utf8');
  assert.match(source, /bot\{credential\}\/sendMessage/);
  assert.match(source, /bot\{credential\}\/getUpdates/);
  assert.doesNotMatch(source, /endpoint:\s*`[^`]*credential\.value/);
});

test('Gemini model calls keep API keys out of ledger endpoint and request hashes', async () => {
  const source = await readFile(new URL('services/orchestration/agent-tools.js', ROOT), 'utf8');
  assert.doesNotMatch(source, /endpoint:\s*`[^`]*credential\.value/);
  assert.doesNotMatch(source, /requestHash:[^\n]*credential\.value/);
  assert.match(source, /credentialUseEvidenceHash\(\{ method: 'POST', model/);
});

test('OAuth-backed model calls retain the identity-vault credential checkout', async () => {
  const source = await readFile(new URL('services/core/providers.js', ROOT), 'utf8');
  assert.match(source, /vault\.accessCredentialCheckout/);
  assert.doesNotMatch(source, /vault\.accessToken \? null/);
  const vaultBranches = source.match(/credentialCheckout: vault\.accessCredentialCheckout/g) || [];
  assert.ok(vaultBranches.length >= 3, 'Gemini, OpenAI, and Codex vault paths retain checkouts');
});

test('unwired Telegram polling placeholder is retired', async () => {
  await assert.rejects(access(new URL('services/integrations/telegram-bot.js', ROOT)));
});

test('Golem findings use native signed persistence without a bearer-token loopback', async () => {
  const source = await readFile(new URL('../../jobs/golem-scanner.js', import.meta.url), 'utf8');
  assert.match(source, /persistMemory\(\{/);
  assert.match(source, /mutation_authority: 'housekeeper'/);
  assert.doesNotMatch(source, /getCachedCredential|aimos_api_token|\/aimos\/memories/);
});
