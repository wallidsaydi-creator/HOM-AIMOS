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
  ['tests/security/audit-018-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-018-event-bytes-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-018-request-bytes-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-009-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-004-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-006-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-014-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-005-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-005-projection-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-002-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-003-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-023-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/audit-015-remediation-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/auth-tier-system-self.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-baseline-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-chain-bidirectional-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cognitive-weight-chain-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/event-ledger-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/hebbian-consensus-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/native-persistence-atomicity.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/canonical-save-owner-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cr5-session-convergence-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/cr7-r2-database-local-closure-db.test.mjs', ISOLATED_SECURITY_OWNER],
  ['tests/security/native-tool-action-db.test.mjs', ISOLATED_SECURITY_OWNER],
  // S5 has stricter lifecycle ownership: a purpose-named Genesis brain,
  // retained custody evidence, and an explicit master-signed purge. It must
  // never be folded into the generic auto-drop runner.
  ['tests/security/mutmem-v2-s5-production-corpus-db.test.mjs',
    'scripts/verification/run-mutmem-v2-s5-disposable-genesis.mjs'],
]);
// These existing canonical checks are their own explicit CLI entrypoints.
// Registration prevents a source-suite invocation from executing live writes
// or signals; it does not run them or count them as passed.
for (const file of [
  'audit-007-failure-owner-live.test.mjs',
  'audit-010-remediation.test.mjs', 'audit-010-capacity-live.test.mjs',
  'audit-010-live-route-queue.test.mjs',
  'audit-011-remediation.test.mjs', 'audit-011-lock-loss-live.test.mjs',
  'audit-011-pool-contention-live.test.mjs',
  'audit-012-save-drain-live.test.mjs', 'audit-012-stream-drain-live.test.mjs',
  'audit-012-scheduled-drain-live.test.mjs', 'audit-012-save-postcommit-live.test.mjs',
  'audit-021-credit-live.test.mjs',
]) {
  const relative = `tests/security/${file}`;
  LIVE_FIRE_OWNERS.set(relative, relative);
}
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
  if (owner === file) {
    if (!/assert\(\s*process\.argv\.includes\(['"]--live-fire['"]\)/.test(isolatedRunner)) {
      throw new Error(`canonical live test lacks explicit opt-in: ${file}`);
    }
    continue;
  }
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

if (!benchmarkOnly) {
  // Source tests do not necessarily import late-loaded integrations. Compile
  // the actual runtime tree too, before reporting an aggregate green result.
  const runtimeFiles = [path.join(ROOT, 'server.js'),
    ...['routes', 'services', 'jobs', 'db', 'middleware'].flatMap(dir => walk(path.join(ROOT, dir)))
  ].filter(file => /\.(?:js|mjs)$/.test(file));
  for (const file of runtimeFiles) {
    const syntax = spawnSync(process.execPath, ['--check', file], { cwd: ROOT, stdio: 'inherit' });
    if (syntax.error) throw syntax.error;
    if (syntax.status !== 0) throw new Error(`runtime_syntax_invalid:${path.relative(ROOT, file)}`);
  }
  console.log(`Native runtime syntax: ${runtimeFiles.length}/${runtimeFiles.length} passed.`);
}

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
