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
const LIVE_FIRE_TESTS = new Set([
  'tests/security/auth-tier-system-self.test.mjs',
  'tests/security/cognitive-weight-baseline-db.test.mjs',
  'tests/security/cognitive-weight-chain-bidirectional-db.test.mjs',
  'tests/security/cognitive-weight-chain-db.test.mjs',
  'tests/security/event-ledger-db.test.mjs',
  'tests/security/hebbian-consensus-db.test.mjs',
  'tests/security/native-persistence-atomicity.test.mjs',
  'tests/security/native-tool-action-db.test.mjs',
]);

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

const isolatedRunner = readFileSync(path.join(ROOT, 'scripts/test/run-isolated-security.mjs'), 'utf8');
for (const file of LIVE_FIRE_TESTS) {
  if (!allTests.includes(file)) throw new Error(`declared live-fire test is missing: ${file}`);
  const basename = path.basename(file);
  if (!isolatedRunner.includes(basename)) {
    throw new Error(`live-fire test is not executed by isolated runner: ${file}`);
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
  stdio: 'inherit',
});

if (result.error) throw result.error;
if (result.status !== 0) process.exitCode = result.status ?? 1;
