import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '..', '..');
const identityRoot = path.join(ROOT, 'scripts', 'identity');

test('public Keychain lane uses the Apple-signed native tool without build artifacts', () => {
  assert.equal(process.platform, 'darwin');
  const runtime = readFileSync(path.join(identityRoot, 'keychain.js'), 'utf8');
  assert.match(runtime, /const SECURITY = '\/usr\/bin\/security'/);
  assert.match(runtime, /\['-i'\]/);
  assert.match(runtime, /secretBytes\.toString\('hex'\)/);
  assert.doesNotMatch(runtime, /xcrun|clang|copyFileSync/);
  assert.equal(existsSync(path.join(identityRoot, 'native')), false);

  const verification = spawnSync('/usr/bin/codesign', [
    '--verify',
    '--strict',
    '/usr/bin/security',
  ], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10_000,
  });
  assert.equal(verification.status, 0, verification.stderr);
});

test('retained v1 helper authority is source-bound and cannot affect fresh installs', () => {
  const manifest = JSON.parse(readFileSync(
    path.join(identityRoot, 'keychain-helper-manifest.json'),
    'utf8',
  ));
  const source = readFileSync(path.join(identityRoot, 'keychain-set.c'));
  assert.equal(manifest.schema_version, 'aimos.keychain-helper-legacy-manifest/v1');
  assert.equal(manifest.abi, 'v1');
  assert.equal(manifest.source_sha256, createHash('sha256').update(source).digest('hex'));
  assert.equal('artifacts' in manifest, false);
});
