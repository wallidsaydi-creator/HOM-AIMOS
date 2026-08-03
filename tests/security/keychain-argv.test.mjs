import test from 'node:test';
import assert from 'node:assert/strict';

import {
  keychainCredentialGetSync,
  keychainLegacyV1GetSync,
  keychainSetSync,
} from '../../scripts/identity/keychain.js';

test('native Keychain write keeps plaintext out of argv and verifies exact storage', () => {
  const secret = 'credential secret\nwith punctuation $() `data`';
  const calls = [];
  keychainSetSync(
    'com.aimos.credentials.test',
    'aimos-native-v2',
    secret,
    (file, args, options) => {
      calls.push({ file, args, options });
      return args[0] === 'find-generic-password' ? `${secret}\n` : '';
    },
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].file, '/usr/bin/security');
  assert.deepEqual(calls[0].args, ['-i']);
  assert.equal(calls[0].args.includes(secret), false);
  assert.equal(calls[0].options.input.includes(secret), false);
  assert.match(calls[0].options.input, new RegExp(Buffer.from(secret, 'utf8').toString('hex')));
  assert.deepEqual(calls[0].options.stdio, ['pipe', 'ignore', 'pipe']);
  assert.equal(calls[1].file, '/usr/bin/security');
  assert.deepEqual(calls[1].args, [
    'find-generic-password',
    '-w',
    '-s', 'com.aimos.credentials.test',
    '-a', 'aimos-native-v2',
  ]);
});

test('current credential read uses Apple security and preserves whitespace', () => {
  let observed = null;
  const value = keychainCredentialGetSync(
    'com.aimos.credentials.test',
    'aimos-native-v2',
    (file, args, options) => {
      observed = { file, args, options };
      return '  credential-secret-value  \n';
    },
  );
  assert.equal(value, '  credential-secret-value  ');
  assert.equal(observed.file, '/usr/bin/security');
  assert.deepEqual(observed.args, [
    'find-generic-password',
    '-w',
    '-s', 'com.aimos.credentials.test',
    '-a', 'aimos-native-v2',
  ]);
});

test('retained v1 credential read stays on its original native executable', () => {
  const calls = [];
  const value = keychainLegacyV1GetSync(
    'com.aimos.credentials.test',
    'aimos-native-v1',
    (file, args, options) => {
      calls.push({ file, args, options });
      return file === '/usr/bin/security' ? '' : 'credential-secret-value';
    },
  );
  assert.equal(value, 'credential-secret-value');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].args, [
    'find-generic-password',
    '-s', 'com.aimos.credentials.test',
    '-a', 'aimos-native-v1',
  ]);
  assert.equal(calls[1].file, 'aimos-keychain-credential-v1');
  assert.deepEqual(calls[1].args, [
    'get',
    'com.aimos.credentials.test',
    'aimos-native-v1',
  ]);
});

test('Keychain identifiers reject command-interpreter metacharacters', () => {
  assert.throws(
    () => keychainSetSync('service;other', 'account', 'value', () => ''),
    /keychain service is malformed/,
  );
});
