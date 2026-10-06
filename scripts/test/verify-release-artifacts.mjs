#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const pack = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
}))[0];
const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
const paths = pack.files.map((entry) => entry.path);
const required = [
  'package.json',
  'LICENSE',
  'COMMERCIAL-LICENSE.md',
  'DCO.md',
  'NOTICE',
  'README.md',
  'RELEASE.md',
  'SECURITY.md',
  'Guide/GENESIS-MANIFEST.json',
  'baselines/live-canonical/migration-098-099-uncertainty.json',
  'migrations/compatibility/029-runtime-role-password-removal.json',
  'Brewfile',
  'install-macos.sh',
  'server.js',
  'migrations/116-service-reader-role-acl.sql',
  'migrations/117-retire-legacy-aimos-app-login.sql',
  'migrations/118-serving-reader-and-identity-writer-acl.sql',
  'migrations/119-serving-identity-read-columns.sql',
  'scripts/db/activate-serving-roles.mjs',
  'scripts/db/audit-serving-roles.mjs',
  'scripts/db/cluster-admin.mjs',
  'scripts/db/qualify-secure-cluster.mjs',
  'scripts/db/preflight-restore-archive.mjs',
  'scripts/db/scram-verifier.mjs',
  'scripts/db/secure-cluster.mjs',
  'scripts/service/run-private-postgres.mjs',
  'scripts/test/probe-secure-serving.mjs',
  'scripts/verification/fixtures/cr7-r7-public-main-678af3c.tar.gz',
  'scripts/verification/prove-cr7-r8-file-write-successor.mjs',
  'scripts/verification/prove-cr8-r1-current-scheduler-successor.mjs',
  'tests/security/cr7-r8-file-write-successor.test.mjs',
  'services/security/postgres-serving-boundary.js',
  'tests/security/postgres-serving-boundary.test.mjs',
];
if (existsSync('RELEASE-SOURCE-MANIFEST.json')) {
  required.push('docs/benchmarks/POISONEDRAG-N100-EPISTEMIC-ABLATION-PREREGISTRATION.md');
}
const forbidden = [
  /^\.claude\//,
  /^plans\//,
  /^remediation\//,
  /^engineering\//,
  /^baselines\/(?!live-canonical\/migration-098-099-uncertainty\.json$)/,
  /^scratchpad\//,
  /^RELEASE-IMPROVEMENT-PLAN\.md$/,
  /^REMEDIATION-INDEX\.md$/,
  /^services\/\.cache\//,
  /^state\//,
  /^eval\/data\/(?!download\.sh$|locomo-LICENSE\.txt$|longmemeval-LICENSE$|canonical\/corpus-manifest\.json$)/,
  /^eval\/(?:public-)?results\//,
  /^eval\/V2-HANDOFF\.md$/,
  /^eval\/BENCHMARK-V2-ARCHITECTURE\.md$/,
  /^eval\/V2-RUNBOOK\.md$/,
  /^Guide\/aimos-codex-vc-boot\.md$/,
  /^services\/PHASE_0_STATUS\.md$/,
  /^docs\/security\/(?:phase0-|phase1a-|phase1b-|three-gap-remediation-|master-remediation-plan-).*\.md$/,
  /^tests\/benchmark\/(?:canonical-aggregate|canonical-corpus|canonical-single-query|locomo-official-protocol|poisonedrag-protocol|replay-sessions|run-isolated-resume)\.test\.mjs$/,
  /^architecture-authority\.json$/,
  /(?:^|\/)__pycache__\//,
  /\.pyc$/i,
  /(?:^|\/)\.env(?:\.|$)/,
  /\.pdf$/i,
  /paper\/.*\.(?:aux|log|out)$/i,
];

for (const file of required) assert(paths.includes(file), `release package missing ${file}`);
const leaked = paths.filter((file) => forbidden.some((pattern) => pattern.test(file)));
assert.deepEqual(leaked, [], `release package contains private/generated paths: ${leaked.join(', ')}`);
assert(pack.unpackedSize <= 20 * 1024 * 1024, `release package exceeds 20 MiB: ${pack.unpackedSize}`);

const bom = JSON.parse(execFileSync('npm', [
  'sbom',
  '--package-lock-only',
  '--omit=dev',
  '--sbom-format',
  'cyclonedx',
], {
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
}));

assert.equal(bom.bomFormat, 'CycloneDX');
assert.equal(bom.specVersion, '1.5');
assert.equal(bom.metadata?.component?.['bom-ref'], `aimos-backend@${packageJson.version}`);
assert.equal(bom.metadata?.component?.licenses?.[0]?.license?.id, 'AGPL-3.0-or-later');
assert(Array.isArray(bom.components) && bom.components.length > 0, 'runtime SBOM has no components');
assert(Array.isArray(bom.dependencies) && bom.dependencies.length > 0, 'runtime SBOM has no dependency graph');

console.log(JSON.stringify({
  package_file_count: paths.length,
  package_unpacked_bytes: pack.unpackedSize,
  sbom_format: `${bom.bomFormat} ${bom.specVersion}`,
  sbom_components: bom.components.length,
  sbom_dependencies: bom.dependencies.length,
}, null, 2));
