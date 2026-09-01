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
  assert.deepEqual(formulas, ['node@26', 'postgresql@18', 'pgvector', 'libsodium', 'pkgconf']);
});

test('clean-machine installer discovers both macOS architectures and hands off to native Genesis', () => {
  const installer = read('install-macos.sh');
  assert.match(installer, /arm64\|x86_64/);
  assert.match(installer, /\/opt\/homebrew\/bin\/brew/);
  assert.match(installer, /\/usr\/local\/bin\/brew/);
  assert.match(installer, /"\$\(uname -m\)" = "arm64"/);
  assert.match(installer, /"\$\(uname -m\)" = "x86_64"/);
  assert.match(installer, /xcode-select --install/);
  assert.match(installer, /bundle --file "\$ROOT\/Brewfile"/);
  assert.doesNotMatch(installer, /^\s*npm ci\s*$/m);
  assert.match(installer, /--prefix node@26/);
  assert.ok(installer.indexOf('--prefix node@26') < installer.indexOf('command -v node'));
  assert.match(installer, /\[ "\$major" = "26" \]/);
  assert.match(installer, /\[ "\$major" = "24" \]/);
  assert.match(installer, /NPM_BIN="\$NODE_BINDIR\/npm"/);
  assert.match(installer, /"\$NPM_BIN" ci/);
  assert.match(installer, /scripts\/genesis-install\.mjs/);
  assert.match(installer, /scripts\/identity\/onboard-agent\.mjs/);
  assert.ok(installer.indexOf('scripts/genesis-install.mjs')
    < installer.indexOf('scripts/identity/onboard-agent.mjs'));
  assert.ok(installer.indexOf('scripts/identity/onboard-agent.mjs')
    < installer.indexOf('scripts/service/manage-user-service.mjs install'));
  assert.match(installer, /scripts\/service\/manage-user-service\.mjs install/);
  assert.match(installer, /--source-root "\$ROOT"/);
  assert.match(installer, /persistent user service/);
  assert.match(installer, /--check/);
  assert.match(installer, /--aimos-instance/);
  assert.match(installer, /--postgres-port/);
  assert.match(installer, /--agent-id/);
  assert.match(installer, /--model-provider/);
  assert.doesNotMatch(installer, /^\s*\/bin\/bash -c .*Homebrew\/install/m);
  assert.doesNotMatch(installer, /\bgpg\b|\bgpg2\b|process\.env|\.env\b|\bsudo\b/);
});

test('public documentation exposes automated and manual prerequisite paths without GPG', () => {
  const docs = `${read('README.md')}\n${read('DEPLOYMENT.md')}`;
  assert.match(docs, /\.\/install-macos\.sh --check/);
  assert.match(docs, /brew bundle --file Brewfile/);
  assert.match(docs, /brew services start postgresql@18/);
  assert.match(docs, /Node\.js 20, 24, or 26/);
  assert.match(docs, /PostgreSQL 18/);
  assert.match(docs, /pgvector/);
  assert.match(docs, /pgsodium 3\.1\.11/);
  assert.doesNotMatch(docs, /GPG (?:is )?required|requires GPG|install GPG/i);
});

test('release upload promotes the qualified Node 26 runtime into GitHub CI', () => {
  const packageJson = JSON.parse(read('package.json'));
  const packageLock = JSON.parse(read('package-lock.json'));
  const genesis = read('scripts/genesis-install.mjs');
  const ci = read('.github/workflows/ci.yml');
  const release = read('.github/workflows/release-ceremony.yml');
  assert.equal(packageJson.engines.node, '^20.0.0 || ^24.0.0 || ^26.0.0');
  assert.equal(packageLock.packages[''].engines.node, packageJson.engines.node);
  assert.match(genesis, /\[20, 24, 26\]\.includes\(major\)/);
  assert.match(ci, /node: \[20, 24, 26\]/);
  assert.match(release, /node-version: 26\.8\.1/);
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
