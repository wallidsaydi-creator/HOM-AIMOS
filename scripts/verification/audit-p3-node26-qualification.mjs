#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = process.argv.find((value) => value.startsWith('--output='))?.slice(9) || null;
const FULL = process.argv.includes('--full');
const sha = (value) => createHash('sha256').update(value).digest('hex');
const read = (relative) => readFile(path.join(ROOT, relative), 'utf8');
const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
if (git.status !== 0) throw new Error('p3_node26_source_commit_unavailable');
const sourceCommit = git.stdout.trim();
const nodeDir = path.dirname(process.execPath);
const npm = path.join(nodeDir, 'npm');
const exactPath = [nodeDir, '/usr/local/bin', '/usr/bin', '/bin'].join(':');

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    env: { ...process.env, PATH: exactPath },
  });
  return {
    passed: result.status === 0,
    exit_code: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    output_sha256: sha(Buffer.from(`${result.stdout || ''}\n${result.stderr || ''}`)),
  };
}

function tap(result) {
  return {
    tests: Number(result.stdout.match(/^ℹ tests (\d+)$/m)?.[1] || 0),
    passed_count: Number(result.stdout.match(/^ℹ pass (\d+)$/m)?.[1] || 0),
    failed_count: Number(result.stdout.match(/^ℹ fail (\d+)$/m)?.[1] || 0),
    passed: result.passed,
    output_sha256: result.output_sha256,
  };
}

const [packageText, lockText, brewfile, installer, genesis, readme, deployment, contribution, ci, release] = await Promise.all([
  read('package.json'), read('package-lock.json'), read('Brewfile'), read('install-macos.sh'),
  read('scripts/genesis-install.mjs'), read('README.md'), read('DEPLOYMENT.md'),
  read('CONTRIBUTING.md'), read('.github/workflows/ci.yml'),
  read('.github/workflows/release-ceremony.yml'),
]);
const packageJson = JSON.parse(packageText);
const packageLock = JSON.parse(lockText);
const sourceContract = {
  package_engine_node26: packageJson.engines?.node === '^20.0.0 || ^24.0.0 || ^26.0.0',
  lock_engine_equal: packageLock.packages?.['']?.engines?.node === packageJson.engines?.node,
  brew_prefers_node26: /^brew "node@26"$/m.test(brewfile),
  installer_prefers_node26: /--prefix node@26/.test(installer)
    && /NPM_BIN="\$NODE_BINDIR\/npm"/.test(installer)
    && /"\$NPM_BIN" ci/.test(installer),
  genesis_accepts_node26: /\[20, 24, 26\]\.includes\(major\)/.test(genesis),
  docs_declare_node26: [readme, deployment, contribution]
    .every((value) => /Node\.js 20, 24, or 26/.test(value)),
  github_ci_deferred: /node: \[20, 24\]/.test(ci)
    && !/node: \[[^\]]*26/.test(ci)
    && /node-version: 20/.test(release)
    && !/node-version: 26/.test(release),
};
const nodeExecutableSha256 = sha(await readFile(process.execPath));
const installerCheck = run('bash', ['install-macos.sh', '--check']);
const p2 = run(process.execPath, [
  'scripts/verification/audit-mutmem-p2-clean-tree.mjs',
  '--python=/Library/Frameworks/Python.framework/Versions/3.14/bin/python3',
]);
const service = run(process.execPath, ['scripts/service/manage-user-service.mjs', 'status']);
let serviceStatus = null;
try { serviceStatus = JSON.parse(service.stdout); } catch { /* invalid below */ }
let serviceNodeVersion = null;
let serviceNodeSha256 = null;
if (serviceStatus?.definition?.node_path) {
  serviceNodeVersion = run(serviceStatus.definition.node_path, ['--version']).stdout.trim();
  try { serviceNodeSha256 = sha(await readFile(serviceStatus.definition.node_path)); } catch { /* invalid below */ }
}
const regressions = {};
if (FULL) {
  const lint = run(npm, ['run', 'lint']);
  const architecture = run(npm, ['run', 'test:architecture-authority']);
  Object.assign(regressions, {
    source: tap(run(npm, ['run', 'test:source'])),
    benchmark: tap(run(npm, ['run', 'test:benchmark:contracts'])),
    lint: { passed: lint.passed, output_sha256: lint.output_sha256 },
    architecture: { passed: architecture.passed, output_sha256: architecture.output_sha256 },
  });
  const pipeline = run(process.execPath, ['--input-type=module', '-e',
    "import('./services/pipeline-manifest.js').then(async m=>{const r=await m.validatePipelines();console.log(JSON.stringify({valid:r.valid,total:r.total,ok:r.ok,node:process.version}));process.exit(r.valid?0:1)})"]);
  regressions.pipeline = { ...JSON.parse(pipeline.stdout || '{}'), passed: pipeline.passed };
}
const checks = {
  running_under_node26: Number(process.versions.node.split('.')[0]) === 26,
  source_contract_complete: Object.values(sourceContract).every(Boolean),
  installer_preflight_node26: installerCheck.passed && /Node\.js:\s+v26\./.test(installerCheck.stdout),
  p2_clean_tree_node26: p2.passed && JSON.parse(p2.stdout).passed === true,
  service_uses_node26: service.passed && /^v26\./.test(serviceNodeVersion || ''),
  service_binary_matches_auditor: serviceNodeSha256 === nodeExecutableSha256,
  service_ready: serviceStatus?.health?.ready === true
    && serviceStatus?.health?.bootError == null,
  full_regression_node26: FULL
    && regressions.source?.passed && regressions.source?.failed_count === 0
    && regressions.benchmark?.passed && regressions.benchmark?.failed_count === 0
    && regressions.lint?.passed && regressions.architecture?.passed
    && regressions.pipeline?.passed && regressions.pipeline?.ok === 155,
};
const unsigned = {
  schema: 'hom.aimos.p3-node26-qualification/v1',
  source_commit: sourceCommit,
  node_executable: 'private_machine_path_omitted',
  node_version: process.version,
  node_executable_sha256: nodeExecutableSha256,
  npm_executable: 'sibling_of_selected_node_private_path_omitted',
  source_contract: sourceContract,
  installer_preflight: {
    passed: installerCheck.passed,
    output_sha256: installerCheck.output_sha256,
  },
  p2_clean_tree: {
    passed: p2.passed,
    output_sha256: p2.output_sha256,
  },
  service: {
    node_path: 'private_machine_path_omitted',
    node_path_matches_auditor: serviceNodeSha256 === nodeExecutableSha256,
    node_version: serviceNodeVersion,
    node_executable_sha256: serviceNodeSha256,
    configuration_sha256: serviceStatus?.definition?.configuration_sha256 || null,
    ready: serviceStatus?.health?.ready === true,
    scheduler_ready: serviceStatus?.health?.readiness?.scheduler?.ready === true,
  },
  regressions,
  checks,
  checks_total: Object.keys(checks).length,
  checks_passed: Object.values(checks).filter(Boolean).length,
  github_ci_changed: false,
  retained_failed_attempts: [{
    stage: 'qualification_artifact_serialization',
    runtime_judgment_completed: false,
    reason: 'undefined_sanitizer_fields_rejected_by_canonical_json',
  }],
  qualified: Object.values(checks).every(Boolean),
};
const result = { ...unsigned, qualification_sha256: sha(Buffer.from(canonicalJson(unsigned))) };
if (OUTPUT) await writeFile(path.resolve(OUTPUT), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
console.log(JSON.stringify(result, null, 2));
process.exit(result.qualified ? 0 : 1);
