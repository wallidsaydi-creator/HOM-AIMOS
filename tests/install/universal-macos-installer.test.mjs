import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (file) => readFileSync(path.join(root, file), 'utf8');

test('public macOS installer declares one exact source-install dependency set', () => {
  const brewfile = read('Brewfile');
  const formulas = [...brewfile.matchAll(/^brew "([^"]+)"$/gm)].map((match) => match[1]);
  assert.deepEqual(formulas, ['node@24', 'postgresql@18', 'pgvector', 'libsodium', 'pkgconf']);
});

test('clean-machine installer discovers both macOS architectures and hands off to native Genesis', () => {
  const installer = read('install-macos.sh');
  assert.match(installer, /arm64\|x86_64/);
  assert.match(installer, /\/opt\/homebrew\/bin\/brew/);
  assert.match(installer, /\/usr\/local\/bin\/brew/);
  assert.match(installer, /xcode-select --install/);
  assert.match(installer, /bundle --file "\$ROOT\/Brewfile"/);
  assert.match(installer, /npm ci/);
  assert.match(installer, /scripts\/genesis-install\.mjs/);
  assert.match(installer, /--check/);
  assert.doesNotMatch(installer, /^\s*\/bin\/bash -c .*Homebrew\/install/m);
  assert.doesNotMatch(installer, /\bgpg\b|\bgpg2\b|process\.env|\.env\b|\bsudo\b/);
});

test('public documentation exposes automated and manual prerequisite paths without GPG', () => {
  const docs = `${read('README.md')}\n${read('DEPLOYMENT.md')}`;
  assert.match(docs, /\.\/install-macos\.sh --check/);
  assert.match(docs, /brew bundle --file Brewfile/);
  assert.match(docs, /brew services start postgresql@18/);
  assert.match(docs, /Node\.js 20 or 24/);
  assert.match(docs, /PostgreSQL 18/);
  assert.match(docs, /pgvector/);
  assert.match(docs, /pgsodium 3\.1\.11/);
  assert.doesNotMatch(docs, /GPG (?:is )?required|requires GPG|install GPG/i);
});

test('release ceremony installs the same Brewfile and runs the non-mutating preflight', () => {
  const workflow = read('.github/workflows/release-ceremony.yml');
  assert.match(workflow, /brew bundle --file Brewfile/);
  assert.match(workflow, /bash install-macos\.sh --check/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /attestations: write/);
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(workflow, /sbom-path: release\/aimos-backend\.cdx\.json/);
  assert.doesNotMatch(workflow, /\bgpg\b|\bgpg2\b|private[-_ ]key/i);
});
