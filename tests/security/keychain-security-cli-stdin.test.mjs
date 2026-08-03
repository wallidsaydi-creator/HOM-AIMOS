import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const SECURITY = '/usr/bin/security';

function runSecurity(args, options = {}) {
  const result = spawnSync(SECURITY, args, {
    encoding: null,
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 10_000,
    ...options,
  });
  assert.equal(result.status, 0, Buffer.from(result.stderr || '').toString('utf8'));
  return result;
}

function commandToken(value) {
  const serialized = String(value);
  if (!/^[A-Za-z0-9._/-]+$/.test(serialized)) throw new Error('unsupported command token');
  return serialized;
}

function writePassword({ keychainPath, service, account, secret, update = false }) {
  const command = [
    'add-generic-password',
    ...(update ? ['-U'] : []),
    '-s', commandToken(service),
    '-a', commandToken(account),
    '-X', Buffer.from(secret, 'utf8').toString('hex'),
    commandToken(keychainPath),
  ].join(' ');
  const argv = ['-i'];
  const result = runSecurity(argv, {
    input: Buffer.from(`${command}\n`, 'utf8'),
  });
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.length, 0, result.stderr.toString('utf8'));
  assert.equal(argv.includes(secret), false);
}

function readPassword({ keychainPath, service, account }) {
  const result = runSecurity([
    'find-generic-password',
    '-w',
    '-s', service,
    '-a', account,
    keychainPath,
  ]);
  const output = Buffer.from(result.stdout);
  return output.subarray(0, output.at(-1) === 0x0a ? -1 : undefined).toString('utf8');
}

test('Apple security stdin mode writes exact complex values without plaintext argv', () => {
  assert.equal(process.platform, 'darwin');
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'aimos-security-stdin-'));
  const keychainPath = path.join(temporaryRoot, 'release-test.keychain-db');
  const keychainPassword = 'isolated-test-keychain-password';
  const service = 'aimos.release-test.service';
  const account = 'release-test-account';
  const firstSecret = 'space "double" \'single\' \\ slash $dollar ;semi `tick` =+/._-';
  const secondSecret = 'updated \\ value "two" $() ; still-data';
  try {
    runSecurity(['create-keychain', '-p', keychainPassword, keychainPath]);
    runSecurity(['unlock-keychain', '-p', keychainPassword, keychainPath]);
    writePassword({ keychainPath, service, account, secret: firstSecret, update: true });
    assert.equal(readPassword({ keychainPath, service, account }), firstSecret);
    writePassword({ keychainPath, service, account, secret: secondSecret, update: true });
    assert.equal(readPassword({ keychainPath, service, account }), secondSecret);
  } finally {
    spawnSync(SECURITY, ['delete-keychain', keychainPath], {
      encoding: 'utf8',
      stdio: ['ignore', 'ignore', 'ignore'],
      timeout: 10_000,
    });
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
