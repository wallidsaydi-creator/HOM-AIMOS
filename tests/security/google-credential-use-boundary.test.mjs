import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../../', import.meta.url);
const googleTools = readFileSync(new URL('services/integrations/google-tools.js', root), 'utf8');
const identityVault = readFileSync(new URL('services/integrations/identity-vault.js', root), 'utf8');

test('Google outbound boundaries use lifecycle-bound credential checkouts', () => {
  assert.match(googleTools, /checkoutCachedCredential\('google_client_secret'\)/);
  assert.match(googleTools, /row\.access_token_checkout/);
  assert.match(googleTools, /row\?\.refresh_token_checkout/);
  assert.match(googleTools, /credentialLedger\.reserveCredentialUse\(/);
  assert.match(googleTools, /credentialLedger\.finalizeCredentialUse\(/);
  assert.doesNotMatch(googleTools, /getCachedCredential\(/);
  assert.doesNotMatch(googleTools, /process\.env/);
});

test('Google Drive media reads share the signed native Google boundary', () => {
  assert.match(
    googleTools,
    /driveReadTextFile[\s\S]*?return gFetch\([\s\S]*?'text',[\s\S]*?\);/,
  );
  assert.equal(
    (googleTools.match(/fetchWithTimeout\(/g) || []).length,
    2,
    'only OAuth refresh and the native Google API boundary may perform HTTP fetches',
  );
});

test('identity vault materialization binds plaintext to the verified effective lifecycle row', () => {
  assert.match(identityVault, /accessLifecycle\?\.effectiveStore/);
  assert.match(identityVault, /refreshLifecycle\?\.effectiveStore/);
  assert.match(identityVault, /effectiveProvenanceId:/);
  assert.match(identityVault, /effectiveMutationHash:/);
  assert.match(identityVault, /access_token_checkout: accessCheckout/);
  assert.match(identityVault, /refresh_token_checkout: refreshCheckout/);
  assert.doesNotMatch(identityVault, /INSERT INTO integration_tokens[\s\S]*?access_token,\s*refresh_token,/);
});
