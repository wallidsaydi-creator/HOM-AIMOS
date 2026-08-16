#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEST_ROOT = path.join(ROOT, 'tests');

// These tests exercise real signed routes and a real database. They are owned
// by run-isolated-security.mjs, which provisions an aimos_test_security_*
// database and refuses canonical databases. Keeping them out of the source
// suite prevents both fake skips and accidental writes to a developer brain.
const ISOLATED_SECURITY_OWNER = 'scripts/test/run-isolated-security.mjs';
const LIVE_FIRE_OWNERS = new Map([
  ['tests/security/auth-tier-system-self.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-baseline-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-chain-bidirectional-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-chain-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/event-ledger-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/hebbian-consensus-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/native-persistence-atomicity.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/native-tool-action-db.test.mjs', ISOLATED_SECURITY_OWNER],
  // S5 has stricter lifecycle ownership: a purpose-named Genesis brain,
  // retained custody evidence, and an explicit master-signed purge. It must
  // never be folded into the generic auto-drop runner.
  ['tests/security/mutmem-v2-s5-production-corpus-db.test.mjs',
    'scripts/verification/run-mutmem-v2-s5-disposable-genesis.mjs'],
]);
const LIVE_FIRE_TESTS = new Set(LIVE_FIRE_OWNERS.keys());

function walk(directory) {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const absolute = path.join(directory, entry.name);
      return entry.isDirectory() ? walk(absolute) : [absolute];
    });
}

const allTests = walk(TEST_ROOT)
  .filter((file) => file.endsWith('.test.mjs'))
  .map((file) => path.relative(ROOT, file).split(path.sep).join('/'))
  .sort();
const benchmarkTests = allTests.filter((file) => file.startsWith('tests/benchmark/'));
if (benchmarkTests.length === 0) throw new Error('benchmark contract test suite is empty');

const unknownLiveFire = allTests.filter((file) => {
  const source = readFileSync(path.join(ROOT, file), 'utf8');
  return source.includes('--live-fire') && !LIVE_FIRE_TESTS.has(file);
});
if (unknownLiveFire.length > 0) {
  throw new Error(`live-fire tests missing suite ownership: ${unknownLiveFire.join(', ')}`);
}

for (const [file, owner] of LIVE_FIRE_OWNERS) {
  if (!allTests.includes(file)) throw new Error(`declared live-fire test is missing: ${file}`);
  const isolatedRunner = readFileSync(path.join(ROOT, owner), 'utf8');
  const basename = path.basename(file);
  if (!isolatedRunner.includes(basename)) {
    throw new Error(`live-fire test is not executed by declared owner ${owner}: ${file}`);
  }
}

const benchmarkOnly = process.argv.includes('--benchmark-only');
const selectedTests = benchmarkOnly
  ? benchmarkTests
  : allTests.filter((file) => !LIVE_FIRE_TESTS.has(file) && !benchmarkTests.includes(file));
if (selectedTests.length === 0) throw new Error('selected test suite is empty');

console.log(
  benchmarkOnly
    ? `Running ${selectedTests.length} benchmark contract tests against the prepared canonical corpus.`
    : `Running ${selectedTests.length} source tests; ${benchmarkTests.length} benchmark contract tests and ${LIVE_FIRE_TESTS.size} live-fire tests have separate owners.`
);
const result = spawnSync(process.execPath, [
  '--test',
  '--test-concurrency=4',
  ...selectedTests,
], {
  cwd: ROOT,
  env: {
    ...process.env,
    PYTHONDONTWRITEBYTECODE: '1',
  },
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.status !== 0) process.exitCode = result.status ?? 1;
