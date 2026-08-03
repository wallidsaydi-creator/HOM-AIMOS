import test from 'node:test';
import assert from 'node:assert/strict';

import {
  listCredentialKeychainItemsSync,
  parseCredentialKeychainInventory,
} from '../../services/security/credential-store.js';

const FIXTURE = `
keychain: "/Users/test/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="aimos"
    "svce"<blob>="com.aimos.credentials.github_client_secret"
class: "genp"
attributes:
    "acct"<blob>="someone-else"
    "svce"<blob>="com.aimos.credentials.not-owned"
class: "genp"
attributes:
    "acct"<blob>="aimos"
    "svce"<blob>="unrelated.service"
class: "genp"
attributes:
    "acct"<blob>="aimos"
    "svce"<blob>="com.aimos.credentials.github_client_secret.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
class: "genp"
attributes:
    "acct"<blob>="aimos-native-v1"
    "svce"<blob>="com.aimos.credentials.oauth_codex_access_token"
class: "genp"
attributes:
    "acct"<blob>="aimos-native-v2"
    "svce"<blob>="com.aimos.credentials.oauth_codex_refresh_token"
`;

test('Keychain inventory returns only exact AIMOS credential namespace metadata', () => {
  assert.deepEqual(parseCredentialKeychainInventory(FIXTURE), [
    { service: 'com.aimos.credentials.github_client_secret', account: 'aimos' },
    {
      service: `com.aimos.credentials.github_client_secret.${'a'.repeat(64)}`,
      account: 'aimos',
    },
    {
      service: 'com.aimos.credentials.oauth_codex_access_token',
      account: 'aimos-native-v1',
    },
    {
      service: 'com.aimos.credentials.oauth_codex_refresh_token',
      account: 'aimos-native-v2',
    },
  ]);
});

test('Keychain inventory never requests decrypted or raw secret output', () => {
  let observed;
  const items = listCredentialKeychainItemsSync((file, args, options) => {
    observed = { file, args, options };
    return FIXTURE;
  });
  assert.equal(items.length, 4);
  assert.equal(observed.file, 'security');
  assert.deepEqual(observed.args, ['dump-keychain']);
  assert.equal(observed.args.includes('-d'), false);
  assert.equal(observed.args.includes('-r'), false);
});
