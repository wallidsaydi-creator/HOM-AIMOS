#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';

const pack = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
}))[0];
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
  'eval/publication/README.md',
  'eval/publication/mutation-integrity-verification.json',
  'eval/publication/poisonedrag-epistemic-ablation.json',
  'eval/publication/poisonedrag-epistemic-verification.json',
  'eval/publication/verified-benchmark-results.json',
  'Brewfile',
  'install-macos.sh',
  'server.js',
];
if (existsSync('RELEASE-SOURCE-MANIFEST.json')) {
  required.push('docs/benchmarks/POISONEDRAG-N100-EPISTEMIC-ABLATION-PREREGISTRATION.md');
}
const forbidden = [
  /^\.claude\//,
  /^plans\//,
  /^remediation\//,
  /^scratchpad\//,
  /^RELEASE-IMPROVEMENT-PLAN\.md$/,
  /^REMEDIATION-INDEX\.md$/,
  /^services\/\.cache\//,
  /^state\//,
  /^eval\/data\/(?!download\.sh$)/,
  /^eval\/(?:public-)?results\//,
  /^eval\/V2-HANDOFF\.md$/,
  /^eval\/BENCHMARK-V2-ARCHITECTURE\.md$/,
  /^eval\/V2-RUNBOOK\.md$/,
  /^Guide\/aimos-codex-vc-boot\.md$/,
  /^services\/PHASE_0_STATUS\.md$/,
  /^tests\/benchmark\/(?:canonical-aggregate|canonical-corpus|canonical-single-query|locomo-official-protocol|poisonedrag-protocol|replay-sessions|run-isolated-resume)\.test\.mjs$/,
  /^architecture-authority\.json$/,
  /(?:^|\/)\.env(?:\.|$)/,
  /\.pdf$/i,
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
assert.equal(bom.metadata?.component?.['bom-ref'], 'aimos-backend@1.0.0');
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
