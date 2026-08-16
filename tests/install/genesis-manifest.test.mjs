import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  computeGenesisCorpusRoot,
  verifyGenesisManifest,
} from '../../scripts/verify-genesis-manifest.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const EXPECTED_VERSION = 19;
const EXPECTED_ROOT = 'dcbf73476b21690cecbda9d084e5784775f4e004af82f8877186e7f4df533bc7';

test('shipped Guide bytes produce the published deterministic corpus root', () => {
  const verified = verifyGenesisManifest({ brainRoot: root });
  assert.equal(verified.ok, true);
  assert.equal(verified.version, EXPECTED_VERSION);
  assert.equal(verified.files.length, 8);
  assert.equal(verified.corpusRoot, EXPECTED_ROOT);
  assert.equal(
    computeGenesisCorpusRoot([...verified.files].reverse()),
    EXPECTED_ROOT,
    'input order must not change the Merkle root'
  );
});

test('one changed Guide byte fails closed before Genesis can create a database', () => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'aimos-genesis-manifest-'));
  try {
    cpSync(path.join(root, 'Guide'), path.join(scratch, 'Guide'), { recursive: true });
    mkdirSync(path.join(scratch, 'scripts', 'db'), { recursive: true });
    cpSync(
      path.join(root, 'scripts', 'db', 'pgsodium-lock.json'),
      path.join(scratch, 'scripts', 'db', 'pgsodium-lock.json'),
      { recursive: true },
    );
    const target = path.join(scratch, 'Guide', 'aimos-guide-tier1-boot.md');
    const original = readFileSync(target);
    writeFileSync(target, Buffer.concat([original, Buffer.from('\nchanged-byte') ]));
    assert.throws(
      () => verifyGenesisManifest({ brainRoot: scratch }),
      /genesis_manifest_(size|hash)_mismatch/
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('one changed dependency-lock byte fails before Genesis can create a database', () => {
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'aimos-genesis-dependency-'));
  try {
    cpSync(path.join(root, 'Guide'), path.join(scratch, 'Guide'), { recursive: true });
    mkdirSync(path.join(scratch, 'scripts', 'db'), { recursive: true });
    cpSync(
      path.join(root, 'scripts', 'db', 'pgsodium-lock.json'),
      path.join(scratch, 'scripts', 'db', 'pgsodium-lock.json'),
      { recursive: true },
    );
    const lock = path.join(scratch, 'scripts', 'db', 'pgsodium-lock.json');
    writeFileSync(lock, Buffer.concat([readFileSync(lock), Buffer.from('\n')]));
    assert.throws(
      () => verifyGenesisManifest({ brainRoot: scratch }),
      /genesis_manifest_dependency_mismatch:pgsodium/,
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test('authority generation and Genesis ingestion bind the published root', () => {
  const runtime = JSON.parse(execFileSync(
    process.execPath,
    [path.join(root, 'scripts', 'identity', 'init-architecture-authority.js'), '--dry-run'],
    { cwd: root, encoding: 'utf8' }
  ));
  assert.equal(runtime.genesis_corpus.schema, 'hom.aimos.genesis-manifest/v1');
  assert.equal(runtime.genesis_corpus.version, EXPECTED_VERSION);
  assert.equal(runtime.genesis_corpus.corpus_root, EXPECTED_ROOT);
  assert.equal(runtime.genesis_corpus.file_count, 8);

  const genesisSource = readFileSync(path.join(root, 'scripts', 'genesis-install.mjs'), 'utf8');
  assert.ok(
    genesisSource.indexOf('await phaseA0VerifyGenesisCorpus();') < genesisSource.indexOf('await phaseA2DbBootstrap();'),
    'Guide verification must occur before DB creation'
  );
  for (const field of [
    'genesis_manifest_schema',
    'genesis_manifest_version',
    'genesis_corpus_root',
    'genesis_file_path',
    'genesis_file_sha256',
    'genesis_file_bytes',
  ]) {
    assert.match(genesisSource, new RegExp(`\\b${field}\\b`));
  }
});
