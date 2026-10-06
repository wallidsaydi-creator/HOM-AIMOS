#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEST_ROOT = path.join(ROOT, 'tests');
const HISTORICAL_SOURCE_ARCHIVE = 'scripts/verification/fixtures/cr7-r7-public-main-678af3c.tar.gz';
const HISTORICAL_SOURCE_SHA256 = '5a878f566a00226c17722012c9092c3417889bd651bb33366427c294747f3890';
const HISTORICAL_SOURCE_COMMIT = '678af3c8766b200f9d61d44f153f0198bf147edc';
const HISTORICAL_PROOF_ROOTS = Object.freeze([
  ['scripts/verification/prove-cr7-r7-aggregate-audit.mjs',
    'preclosure_proof_root_sha256', '0b57d2e65d15a0fba47b96d041dc52f198b640bae5876828b6c52333e84bebe4'],
  ['scripts/verification/prove-cr8-housekeeper-scheduler.mjs',
    'proof_root_sha256', '880f9a47b6ac56cf56fbfbf795701e647328d53c4e89a9b202f21cf3de1bb82e'],
]);
const HISTORICAL_TESTS = Object.freeze([
  'tests/security/cr7-durable-action-census.test.mjs',
  'tests/security/cr7-r1-existing-ledger-owner-audit.test.mjs',
  'tests/security/cr7-r2-database-local-verifier.test.mjs',
  'tests/security/cr7-r3-security-authority.test.mjs',
  'tests/security/cr7-r4-operational-audit.test.mjs',
  'tests/security/cr7-r5-material-effect-owner.test.mjs',
  'tests/security/cr7-r6-recovery-set-equality.test.mjs',
  'tests/security/cr7-r7-aggregate-audit.test.mjs',
  'tests/security/cr8-housekeeper-scheduler-autonomy.test.mjs',
]);
const FROZEN_CURRENT_TESTS = new Set(HISTORICAL_TESTS.filter((file) =>
  file !== 'tests/security/cr8-housekeeper-scheduler-autonomy.test.mjs'));

function runHistoricalSourceProof() {
  const archive = path.join(ROOT, HISTORICAL_SOURCE_ARCHIVE);
  const digest = createHash('sha256').update(readFileSync(archive)).digest('hex');
  if (digest !== HISTORICAL_SOURCE_SHA256) throw new Error('historical_cr7_archive_hash_mismatch');
  const listing = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (listing.error || listing.status !== 0) throw listing.error || new Error('historical_cr7_archive_listing_failed');
  const members = listing.stdout.trim().split('\n');
  for (const member of members) {
    const parts = member.split('/').filter(Boolean);
    if (!member || member.startsWith('/') || member.includes('\\')
        || parts.some((part) => part === '.' || part === '..')
        || /(?:^|\/)(?:node_modules|\.git)(?:\/|$)/.test(member)
        || /(?:^|\/)\.env(?:\.|\/|$)/.test(member)
        || /\.(?:key|pem|dump)$/i.test(member)) {
      throw new Error(`historical_cr7_archive_member_rejected:${member}`);
    }
  }
  for (const file of ['server.js', 'package.json', ...HISTORICAL_TESTS,
    ...HISTORICAL_PROOF_ROOTS.map(([file]) => file)]) {
    if (!members.includes(file)) throw new Error(`historical_cr7_archive_file_missing:${file}`);
  }
  const scratch = mkdtempSync(path.join(tmpdir(), 'aimos-cr7-r7-public-'));
  try {
    const unpack = spawnSync('tar', ['-xzf', archive, '-C', scratch], { stdio: 'inherit' });
    if (unpack.error || unpack.status !== 0) throw unpack.error || new Error('historical_cr7_archive_extract_failed');
    const modules = path.join(ROOT, 'node_modules');
    if (!existsSync(modules)) throw new Error('historical_cr7_node_modules_missing');
    symlinkSync(modules, path.join(scratch, 'node_modules'), 'dir');
    console.log(`Historical CR7 R0–R7 and CR8: ${HISTORICAL_TESTS.length} source files from public commit ${HISTORICAL_SOURCE_COMMIT}.`);
    const result = spawnSync(process.execPath, [
      '--test', '--test-concurrency=4', ...HISTORICAL_TESTS,
    ], { cwd: scratch, env: process.env, stdio: 'inherit' });
    if (result.error || result.status !== 0) throw result.error || new Error('historical_cr7_source_proof_failed');
    for (const [file, field, expected] of HISTORICAL_PROOF_ROOTS) {
      const proof = spawnSync(process.execPath, [file], {
        cwd: scratch, env: process.env, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
      });
      if (proof.error || proof.status !== 0) throw proof.error || new Error(`historical_proof_failed:${file}`);
      const body = JSON.parse(proof.stdout);
      if (body[field] !== expected) throw new Error(`historical_proof_root_changed:${file}`);
    }
    console.log('Historical R7 and CR8 proof roots match the pinned public source.');
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

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
for (const file of HISTORICAL_TESTS) {
  if (!allTests.includes(file)) throw new Error(`historical_cr7_test_missing:${file}`);
}
if (process.argv.includes('--historical-only')) {
  runHistoricalSourceProof();
  process.exit(0);
}
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
  : allTests.filter((file) => !LIVE_FIRE_TESTS.has(file)
    && !benchmarkTests.includes(file)
    && !FROZEN_CURRENT_TESTS.has(file));
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
  runHistoricalSourceProof();
}

console.log(
  benchmarkOnly
    ? `Running ${selectedTests.length} benchmark contract tests against the prepared canonical corpus.`
    : `Running ${selectedTests.length} current source tests, including R8 and the current CR8 successor; ${HISTORICAL_TESTS.length} frozen test files passed against the pinned public source, while ${benchmarkTests.length} benchmark and ${LIVE_FIRE_TESTS.size} live-fire tests have separate owners.`
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
