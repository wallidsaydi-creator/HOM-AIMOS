#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  statSync,
} from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { canonicalJson } from '../../eval/poisonedrag/protocol.mjs';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function cliValue(argv, name) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

const requested = String(cliValue(process.argv.slice(2), '--root') || '').trim();
if (!requested) throw new Error('public_source_tree_root_required');
const root = path.resolve(requested);
const manifestFile = path.join(root, 'RELEASE-SOURCE-MANIFEST.json');
if (!existsSync(manifestFile) || lstatSync(manifestFile).isSymbolicLink()) {
  throw new Error('public_source_manifest_missing');
}
const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
assert.equal(manifest.schema, 'hom.aimos.public-source-manifest/v1');
const unsigned = { ...manifest };
delete unsigned.manifest_sha256;
assert.equal(
  manifest.manifest_sha256,
  sha256(Buffer.from(canonicalJson(unsigned), 'utf8')),
  'public source manifest self-hash mismatch',
);

const observed = [];
function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (directory === root && ['.git', 'node_modules'].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute);
    if (relative === 'RELEASE-SOURCE-MANIFEST.json') continue;
    assert.equal(entry.isSymbolicLink(), false, `public source symlink forbidden: ${relative}`);
    if (entry.isDirectory()) walk(absolute);
    else if (entry.isFile()) {
      observed.push({
        path: relative,
        bytes: statSync(absolute).size,
        sha256: sha256(readFileSync(absolute)),
      });
    }
  }
}
walk(root);
observed.sort((left, right) => left.path.localeCompare(right.path));
assert.deepEqual(observed, manifest.files, 'public source tree differs from manifest');
assert.equal(observed.length, manifest.file_count);
assert.equal(
  sha256(Buffer.from(canonicalJson(observed), 'utf8')),
  manifest.files_root_sha256,
  'public source files root mismatch',
);

for (const forbidden of [
  'architecture-authority.json',
  'scripts/verification/audit-ob5-independent-corroboration.mjs',
  'scripts/verification/generate-phase1-origin-closure-artifacts.mjs',
  'verifiers/origin-binding/phase1-closure',
  'tests/security/audit-007-remediation.test.mjs',
  'tests/security/audit-008-remediation.test.mjs',
  'tests/security/audit-018-event-domain-retained.test.mjs',
  'tests/security/audit-024-remediation.test.mjs',
  'tests/security/phase1-origin-closure.test.mjs',
  'plans',
  'engineering',
  'remediation',
  'research',
  'scratchpad',
  'eval/public-results',
  'eval/results',
  'eval/BENCHMARK-V2-ARCHITECTURE.md',
  'eval/V2-RUNBOOK.md',
  'Guide/aimos-codex-vc-boot.md',
  'services/PHASE_0_STATUS.md',
  'tests/benchmark/canonical-aggregate.test.mjs',
  'tests/benchmark/canonical-corpus.test.mjs',
  'tests/benchmark/canonical-single-query.test.mjs',
  'tests/benchmark/locomo-official-protocol.test.mjs',
  'tests/benchmark/poisonedrag-protocol.test.mjs',
  'tests/benchmark/replay-sessions.test.mjs',
  'tests/benchmark/run-isolated-resume.test.mjs',
  'state',
]) {
  assert.equal(existsSync(path.join(root, forbidden)), false, `private path shipped: ${forbidden}`);
}
for (const required of [
  '.github/workflows/ci.yml',
  '.github/workflows/release-ceremony.yml',
  '.github/dependabot.yml',
  '.gitleaks.toml',
  'package-lock.json',
  'baselines/live-canonical/migration-098-099-uncertainty.json',
  'db/atomic-save-origin.sql',
  'migrations/compatibility/029-runtime-role-password-removal.json',
  'migrations/100-origin-family-ledger-and-writers.sql',
  'migrations/101-origin-family-typed-writers.sql',
  'migrations/102-origin-action-verdict-family-order-fix.sql',
  'migrations/103-origin-writer-independent-crypto-parity.sql',
  'migrations/104-origin-event-local-timestamp-parity.sql',
  'migrations/105-origin-security-family-byte-order.sql',
  'migrations/106-consequential-action-verdict-binding.sql',
  'migrations/107-origin-elevation-license-binding.sql',
  'migrations/108-operator-action-authorization-verifier.sql',
  'migrations/109-origin-trust-registry-and-elevation-v2.sql',
  'migrations/110-origin-source-effect-projection-binding.sql',
  'migrations/111-origin-elevation-v2-ledger-domain.sql',
  'migrations/112-origin-corroborator-key-precedence.sql',
  'migrations/113-origin-elevation-attempt-continuity.sql',
  'migrations/114-origin-elevation-exact-selector.sql',
  'migrations/115-origin-ledger-genesis-context.sql',
  'scripts/identity/authorize-tool-action.js',
  'services/orchestration/tool-action-ledger.js',
  'services/orchestration/tool-registry.js',
  'services/security/origin-ledger.js',
  'services/security/save-origin-binding.js',
  'services/security/protocol/consequential-action-v1.js',
  'services/security/protocol/origin-authority-v2.js',
  'services/security/protocol/origin-binding-v1.js',
  'services/security/protocol/origin-corroboration-v1.js',
  'tests/security/consequential-action-ob5.test.mjs',
  'tests/security/native-tool-action-authority.test.mjs',
  'tests/security/native-tool-action-db.test.mjs',
  'tests/security/origin-binding-ob1-artifacts.test.mjs',
  'tests/security/origin-binding-v1.test.mjs',
  'tests/security/origin-corroboration-ob5.test.mjs',
  'tests/security/origin-ledger-ob2.test.mjs',
  'verifiers/origin-binding/v1/protocol-manifest.json',
  'verifiers/origin-binding/v1/vectors.json',
  'verifiers/origin-binding/v1/verify.py',
]) {
  assert.equal(existsSync(path.join(root, required)), true, `public source missing: ${required}`);
}

const privatePathPattern = [
  '/',
  'Users/(?!test(?:/|\")|<name>|\\.\\.\\.)[A-Za-z0-9._-]+/',
  '|/',
  'home/[A-Za-z0-9._-]+/',
].join('');
const privatePathRegex = new RegExp(privatePathPattern);
const privatePathMatches = observed
  .filter((entry) => {
    const value = readFileSync(path.join(root, entry.path));
    if (value.includes(0)) return false;
    return privatePathRegex.test(value.toString('utf8'));
  })
  .map((entry) => entry.path);
assert.deepEqual(
  privatePathMatches,
  [],
  `public source contains machine-private paths: ${privatePathMatches.join(', ')}`,
);

const disclosureRules = [
  { label: 'private-plan-path', pattern: new RegExp(['plans', 'Codex'].join('/'), 'i') },
  { label: 'private-model-handoff', pattern: new RegExp(['Claude', 'Fable'].join('\\s+'), 'i') },
  { label: 'private-model-handoff', pattern: new RegExp(['GLM', '5\\.2', 'handoff'].join('.*'), 'i') },
  { label: 'private-wiki-reference', pattern: /\[\[(?:hom-|feedback-)[^\]]+\]\]/i },
  { label: 'operator-home-path', pattern: new RegExp(['<operator', 'home>'].join('-'), 'i') },
  { label: 'temporary-backup-path', pattern: new RegExp(['/tmp/hom', 'phase0'].join('-'), 'i') },
  { label: 'investor-conduct-note', pattern: new RegExp(['VC', 'Investor Posture'].join(' \\/ '), 'i') },
  { label: 'release-deadline-note', pattern: new RegExp(['public release', 'THIS WEEK'].join(' '), 'i') },
  { label: 'private-artifact-note', pattern: new RegExp([
    ['LOCAL', 'file', 'only'].join(' '),
    ['never', 'an', 'artifact'].join(' '),
  ].join('.*'), 'i') },
  { label: 'personal-test-fixture', pattern: new RegExp(['speaker:', "'Wa", "lid'"].join('\\s*'), 'i') },
  { label: 'operator-verbatim', pattern: new RegExp(['\\bper', '(?:the )?operator\\b'].join(' '), 'i') },
  { label: 'operator-verbatim', pattern: new RegExp(['\\boperator', "['’]s ", '(?:directive|decision|rationale|quote|request)\\b'].join(''), 'i') },
  { label: 'private-plan-commentary', pattern: new RegExp(['\\bas written', 'in the plan\\b'].join(' '), 'i') },
  { label: 'private-plan-commentary', pattern: new RegExp(['\\bafter architect', 'approval\\b'].join(' '), 'i') },
  { label: 'private-plan-commentary', pattern: new RegExp(['\\bper', 'plan\\b'].join(' '), 'i') },
  { label: 'private-plan-file', pattern: new RegExp([
    '(?:plans/|plan\\s+)',
    '[a-z0-9_-]+\\.md',
  ].join(''), 'i') },
  { label: 'historical-test-narrative', pattern: new RegExp([
    'an earlier version',
    'of this script',
  ].join('.*'), 'i') },
  { label: 'internal-rule-label', pattern: new RegExp([
    '\\bH',
    '\\d+',
    '\\s+in spirit\\b',
  ].join(''), 'i') },
  { label: 'internal-development-marker', pattern: new RegExp([
    '(?:^|\\n)\\s*',
    '(?:(?://|#|--)\\s*)?',
    '(?:TO', 'DO|FIX', 'ME)',
    '(?:[-_: ]|$)',
  ].join(''), 'im') },
  { label: 'internal-conduct-note', pattern: new RegExp(['\\binternal', '(?:conduct|behavior|ceremony|note|memo)\\b'].join(' '), 'i') },
  { label: 'internal-conduct-note', pattern: new RegExp(['\\bprivate', '(?:roadmap|note|memo)\\b'].join(' '), 'i') },
  { label: 'private-test-policy', pattern: new RegExp(['CLAUDE\\.md', 'H[0-9]'].join('\\s+'), 'i') },
  { label: 'legacy-private-brain-path', pattern: new RegExp([
    '\\.claude',
    'vault',
    'hom',
    'backend',
    'brain',
  ].join('.*'), 'i') },
  { label: 'personal-enrollment-example', pattern: new RegExp(['walid', 'prime'].join('-'), 'i') },
];
const disclosureMatches = [];
for (const entry of observed) {
  const value = readFileSync(path.join(root, entry.path));
  if (value.includes(0)) continue;
  const text = value.toString('utf8');
  for (const rule of disclosureRules) {
    if (rule.pattern.test(text)) disclosureMatches.push(`${rule.label}:${entry.path}`);
  }
}
assert.deepEqual(
  disclosureMatches,
  [],
  `public source contains internal disclosure residue: ${disclosureMatches.join(', ')}`,
);

const legalName = ['Wa', 'lid', ' ', 'Sa', 'idi'].join('');
const legalNameFiles = observed
  .filter((entry) => {
    const value = readFileSync(path.join(root, entry.path));
    return !value.includes(0) && value.toString('utf8').includes(legalName);
  })
  .map((entry) => entry.path);
assert.deepEqual(
  legalNameFiles,
  ['NOTICE', 'paper/mutmem-v2-manuscript-contract.json', 'paper/mutmem-v2.tex'],
  'personal legal name may appear only in the copyright notice and authored manuscript metadata',
);

const benchmarkTests = observed
  .map((entry) => entry.path)
  .filter((file) => file.startsWith('tests/benchmark/'));
assert.deepEqual(
  benchmarkTests,
  ['tests/benchmark/publication-evidence.test.mjs'],
  'public source must carry only the canonical publication-evidence benchmark test',
);

const retainedBaselines = observed
  .map((entry) => entry.path)
  .filter((file) => file.startsWith('baselines/'));
assert.deepEqual(
  retainedBaselines,
  ['baselines/live-canonical/migration-098-099-uncertainty.json'],
  'public source may carry only the exact migration compatibility baseline',
);

if (existsSync(path.join(root, '.git'))) {
  const count = Number(execFileSync('git', ['rev-list', 'HEAD', '--count'], {
    cwd: root,
    encoding: 'utf8',
  }).trim() || 0);
  if (count > 0) {
    const roots = execFileSync('git', ['rev-list', '--max-parents=0', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim().split('\n').filter(Boolean);
    assert.equal(roots.length, 1, `public HEAD has ${roots.length} root commits`);
    const status = execFileSync('git', ['status', '--porcelain=v1'], {
      cwd: root,
      encoding: 'utf8',
    }).trim();
    assert.equal(status, '', 'committed public repository is dirty');
  }
}

console.log(JSON.stringify({
  root,
  file_count: observed.length,
  files_root_sha256: manifest.files_root_sha256,
  manifest_sha256: manifest.manifest_sha256,
  private_paths: 0,
  internal_disclosures: 0,
}, null, 2));
