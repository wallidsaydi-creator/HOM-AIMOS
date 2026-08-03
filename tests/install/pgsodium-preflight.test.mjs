import assert from 'node:assert/strict';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ensurePgsodium,
  PGSODIUM_LOCK_PATH,
  readPgsodiumLock,
} from '../../scripts/db/ensure-pgsodium.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function fakeInstallation(scratch) {
  const bindir = path.join(scratch, 'bin');
  const pkglibdir = path.join(scratch, 'lib');
  const sharedir = path.join(scratch, 'share');
  const extension = path.join(sharedir, 'extension');
  mkdirSync(bindir, { recursive: true });
  mkdirSync(pkglibdir, { recursive: true });
  mkdirSync(extension, { recursive: true });
  writeFileSync(path.join(bindir, 'pg_config'), '#!/bin/sh\nexit 0\n');
  chmodSync(path.join(bindir, 'pg_config'), 0o755);
  writeFileSync(path.join(pkglibdir, 'pgsodium.dylib'), 'verified-library');
  writeFileSync(path.join(extension, 'pgsodium.control'), "default_version = '3.1.11'\n");
  writeFileSync(path.join(extension, 'pgsodium--3.1.11.sql'), 'SELECT 1;\n');
  return { bindir, pkglibdir, sharedir };
}

function poolClass(facts) {
  return class MockPool {
    async query(sql) {
      if (/SELECT 1/.test(sql)) return { rows: [{ '?column?': 1 }] };
      if (/FROM pg_config/.test(sql)) {
        return { rows: [
          { name: 'BINDIR', setting: facts.bindir },
          { name: 'PKGLIBDIR', setting: facts.pkglibdir },
          { name: 'SHAREDIR', setting: facts.sharedir },
          { name: 'VERSION', setting: 'PostgreSQL 18.3 (test)' },
        ] };
      }
      if (/FROM pg_available_extensions/.test(sql)) {
        return { rows: [
          { name: 'pgsodium', default_version: '3.1.11', installed_version: null },
          { name: 'vector', default_version: '0.8.2', installed_version: null },
        ] };
      }
      throw new Error(`unexpected SQL: ${sql}`);
    }
    async end() {}
  };
}

test('pgsodium source lock binds tag, URL, bytes, and SHA-256', () => {
  const lock = readPgsodiumLock();
  assert.equal(lock.version, '3.1.11');
  assert.equal(lock.tag, `v${lock.version}`);
  assert.equal(lock.source_bytes, 115438);
  assert.match(lock.source_sha256, /^[0-9a-f]{64}$/);
  assert.equal(lock.source_url.endsWith(`/refs/tags/${lock.tag}`), true);
});

test('same-version artifacts require a matching locked-source attestation', async () => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'aimos-pgsodium-preflight-'));
  try {
    const facts = fakeInstallation(scratch);
    const calls = [];
    const execFn = (file, args) => {
      calls.push([file, ...args]);
      if (file === 'pkg-config') return '1.0.22\n';
      if (file === 'bash') {
        writeFileSync(path.join(facts.pkglibdir, 'pgsodium.dylib'), 'verified-library');
        return 'locked build complete\n';
      }
      throw new Error(`unexpected command: ${file}`);
    };
    const options = {
      databaseUrl: 'postgresql://tester@localhost:5432/aimos_test',
      PoolClass: poolClass(facts),
      execFn,
    };
    const first = await ensurePgsodium(options);
    assert.equal(first.source_install_performed, true, 'version label alone must not bypass locked build');
    assert.match(first.source_attestation_sha256, /^[0-9a-f]{64}$/);
    assert.match(first.node_version, /^v(?:20|24)\./);
    assert.equal(first.pgvector_available_version, '0.8.2');
    assert.equal(calls.some(([file]) => file === 'bash'), true);

    calls.length = 0;
    const second = await ensurePgsodium(options);
    assert.equal(second.source_install_performed, false);
    assert.equal(calls.some(([file]) => file === 'bash'), false);

    writeFileSync(first.library_file, 'tampered-library');
    calls.length = 0;
    const repaired = await ensurePgsodium(options);
    assert.equal(repaired.source_install_performed, true, 'artifact drift must invalidate the attestation');
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('tag/version/source URL inconsistency fails closed', () => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'aimos-pgsodium-lock-'));
  try {
    const lock = JSON.parse(readFileSync(PGSODIUM_LOCK_PATH, 'utf8'));
    lock.tag = 'v3.1.10';
    const file = path.join(scratch, 'lock.json');
    writeFileSync(file, JSON.stringify(lock));
    assert.throws(() => readPgsodiumLock(file), /pgsodium_dependency_lock_invalid/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('build path is checksum-locked, staged, and has no HEAD, git, sudo, or ENV override', () => {
  const build = readFileSync(path.join(root, 'scripts', 'db', 'build-pgsodium.sh'), 'utf8');
  assert.match(build, /source byte count mismatch/);
  assert.match(build, /source SHA-256 mismatch/);
  assert.match(build, /DESTDIR=\$STAGE/);
  assert.match(build, /live pgsodium control\/SQL set differs/);
  assert.doesNotMatch(build, /git clone|refs\/heads|\bsudo\b/);
  assert.doesNotMatch(build, /\$\{(?:PG_CONFIG|PGSODIUM_REF|WORKDIR):-/);
});

test('Genesis verifies corpus, zero-ENV state, and pgsodium before A2', () => {
  const genesis = readFileSync(path.join(root, 'scripts', 'genesis-install.mjs'), 'utf8');
  const corpus = genesis.indexOf('await phaseA0VerifyGenesisCorpus();');
  const noEnv = genesis.indexOf('await verifyPhaseA1EnvPurge();');
  const dependency = genesis.indexOf('await phaseA0_5PgsodiumPreflight();');
  const database = genesis.indexOf('await phaseA2DbBootstrap();');
  assert.ok(corpus >= 0 && corpus < noEnv && noEnv < dependency && dependency < database);
  assert.doesNotMatch(
    genesis.slice(0, genesis.indexOf('const PROJECT_ROOT')),
    /from ['"](?:pg|express|\.\.?\/)/,
    'initial static imports must be Node built-ins only',
  );
});

test('database postcondition pins pgsodium and runtime roles lose direct extension access', () => {
  const version = readFileSync(path.join(root, 'migrations', '088-pgsodium-version-postcondition.sql'), 'utf8');
  const acl = readFileSync(path.join(root, 'migrations', '087-lock-pgsodium-runtime-surface.sql'), 'utf8');
  assert.match(version, /v_installed IS DISTINCT FROM '3\.1\.11'/);
  assert.match(version, /v_available IS DISTINCT FROM '3\.1\.11'/);
  assert.match(acl, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pgsodium FROM agent_runtime/);
  assert.match(acl, /REVOKE ALL ON SCHEMA pgsodium FROM PUBLIC/);
});

test('preflight fails before database creation without PostgreSQL 18 or pgvector', async () => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'aimos-pg-runtime-preflight-'));
  try {
    const facts = fakeInstallation(scratch);
    const WrongMajorPool = poolClass(facts);
    WrongMajorPool.prototype.query = async function query(sql) {
      if (/SELECT 1/.test(sql)) return { rows: [{ '?column?': 1 }] };
      if (/FROM pg_config/.test(sql)) return { rows: [
        { name: 'BINDIR', setting: facts.bindir },
        { name: 'PKGLIBDIR', setting: facts.pkglibdir },
        { name: 'SHAREDIR', setting: facts.sharedir },
        { name: 'VERSION', setting: 'PostgreSQL 17.9 (test)' },
      ] };
      if (/FROM pg_available_extensions/.test(sql)) return { rows: [
        { name: 'pgsodium', default_version: '3.1.11', installed_version: null },
        { name: 'vector', default_version: '0.8.2', installed_version: null },
      ] };
      throw new Error(`unexpected SQL: ${sql}`);
    };
    await assert.rejects(
      ensurePgsodium({
        databaseUrl: 'postgresql://tester@localhost:5432/aimos_test',
        PoolClass: WrongMajorPool,
      }),
      /postgresql_18_required/,
    );

    const MissingVectorPool = poolClass(facts);
    MissingVectorPool.prototype.query = async function query(sql) {
      if (/SELECT 1/.test(sql)) return { rows: [{ '?column?': 1 }] };
      if (/FROM pg_config/.test(sql)) return { rows: [
        { name: 'BINDIR', setting: facts.bindir },
        { name: 'PKGLIBDIR', setting: facts.pkglibdir },
        { name: 'SHAREDIR', setting: facts.sharedir },
        { name: 'VERSION', setting: 'PostgreSQL 18.3 (test)' },
      ] };
      if (/FROM pg_available_extensions/.test(sql)) return { rows: [
        { name: 'pgsodium', default_version: '3.1.11', installed_version: null },
      ] };
      throw new Error(`unexpected SQL: ${sql}`);
    };
    await assert.rejects(
      ensurePgsodium({
        databaseUrl: 'postgresql://tester@localhost:5432/aimos_test',
        PoolClass: MissingVectorPool,
      }),
      /pgvector_extension_unavailable/,
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
