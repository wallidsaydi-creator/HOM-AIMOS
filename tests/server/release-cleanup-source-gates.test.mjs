import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (relativePath) => readFileSync(path.join(root, relativePath), 'utf8');

test('zero-importer no-op modules are absent', () => {
  assert.equal(existsSync(path.join(root, 'services/session-compassion.js')), false);
  assert.equal(existsSync(path.join(root, 'services/retrieval/adaptive-save.js')), false);
  assert.equal(existsSync(path.join(root, 'services/core/hom-volume-layout.js')), false);
});

test('personal signal branch is absent from the native AIMOS tree', () => {
  for (const relativePath of [
    'jobs/signal-generators.js',
    'jobs/hourly-signal-scan.js',
    'jobs/sunday-signal-scan.js',
    'jobs/weekly-reflection.js',
    'routes/intelligence.js',
    'services/integrations/x-stream-intelligence.js',
  ]) {
    assert.equal(existsSync(path.join(root, relativePath)), false, relativePath);
  }

  assert.doesNotMatch(read('server.js'), /routes\/intelligence|x-stream-intelligence|X-STREAM/);
  assert.doesNotMatch(read('services/pipeline-manifest.js'), /weekly_reflection|jobs\/weekly-reflection/);
});

test('boot integrity verifies native files without resurrecting barrel wrappers', () => {
  const boot = read('jobs/boot-integrity.js');
  const server = read('server.js');
  assert.doesNotMatch(boot, /barrel:|services\/\$\{domain\}\/index\.js|security\/index\.js/);
  assert.equal(existsSync(path.join(root, 'services/security/index.js')), false);
  assert.match(boot, /system-config-store\.js/);
  assert.doesNotMatch(boot, /runRecallSpotCheck|recall_spot_check|RECALL-SPOT/);
  assert.doesNotMatch(server, /startPeriodicRecallCheck|stopPeriodicRecallCheck/);
});

test('advertised tool catalog contains no unavailable MCP placeholder', () => {
  const registry = read('services/orchestration/tool-registry.js');
  assert.doesNotMatch(registry, /\bmcp_connect\b|pending R10/);
});

test('public file outputs use AIMOS-owned roots without private harness paths', () => {
  const registry = read('services/orchestration/tool-registry.js');
  const shared = read('routes/agent-shared.js');

  assert.doesNotMatch(registry, /path\.join\(os\.homedir\(\), '\.claude', 'vault'/);
  assert.doesNotMatch(registry, /'hom', 'backend', 'brain'/);
  assert.match(registry, /path\.join\(home, '\.aimos', 'exports'\)/);
  assert.match(registry, /candidate === root \|\| candidate\.startsWith\(`\$\{root\}\$\{path\.sep\}`\)/);
  assert.match(shared, /path\.join\(os\.homedir\(\), '\.aimos', 'briefings'\)/);
});

test('uncalled save middleware is not part of the se-gate public API', () => {
  const source = read('services/security/se-gate.js');
  assert.doesNotMatch(source, /export\s+(?:async\s+)?function\s+seGateSave\b/);
  assert.match(source, /export\s+async\s+function\s+seGateRecall\b/);
});

test('live orchestration diagnostics retain their adaptive tau dependency', () => {
  const source = read('services/orchestration/meta-controller.js');
  assert.match(source, /export\s+function\s+computeAdaptiveTauBase\b/);
  assert.match(source, /adaptive_tau_base:\s*Number\(computeAdaptiveTauBase\(N\)/);
});

test('auth headers describe the enforced runtime and the parallel ART authority is absent', () => {
  const authTier = read('services/security/auth-tier.js');
  const agentRunner = read('services/orchestration/agent-runner.js');

  assert.doesNotMatch(authTier, /Each check is flag-gated with shadow-first semantics/);
  assert.doesNotMatch(authTier, /SECURITY_KILLSWITCH|readFlag/);
  assert.match(authTier, /return t0\('agent_revoked'\)/);
  assert.match(authTier, /return t0\('replay_detected'\)/);
  assert.equal(existsSync(path.join(root, 'services/security/art-sidecar.js')), false);
  assert.equal(existsSync(path.join(root, 'services/core/internal-auth.js')), false);
  assert.doesNotMatch(agentRunner, /9101|createInternalToken|artValidateMemories|X-Internal-Token/);
  assert.equal((agentRunner.match(/runSecurityPipeline\(/g) || []).length, 1);
});

test('deployment guide references only the available cleanup commands', () => {
  const deployment = read('DEPLOYMENT.md');

  assert.doesNotMatch(deployment, /scripts\/verify-architecture-authority\.js/);
  assert.doesNotMatch(deployment, /scripts\/reboot-memory-boot\.cjs/);
  assert.doesNotMatch(deployment, /scripts\/backfill-ledger-reviewer\.mjs/);
  assert.match(deployment, /scripts\/identity\/init-architecture-authority\.js --dry-run/);
  assert.match(deployment, /jobs\/boot-integrity\.js/);
  assert.match(deployment, /scripts\/ceremony\/attest-orphaned-memories\.mjs/);
});

test('dead direct dependencies are absent and the maintained transformer runtime is used', () => {
  const packageJson = JSON.parse(read('package.json'));
  const lock = JSON.parse(read('package-lock.json'));
  const deadDirect = ['nodemailer', 'playwright', 'playwright-core', 'sharp'];

  for (const dependency of deadDirect) {
    assert.equal(packageJson.dependencies?.[dependency], undefined, `${dependency} in package.json`);
    assert.equal(lock.packages?.['']?.dependencies?.[dependency], undefined, `${dependency} in lock root`);
  }

  assert.equal(packageJson.dependencies?.['@xenova/transformers'], undefined);
  assert.equal(packageJson.dependencies?.['@huggingface/transformers'], '^4.2.0');
  assert.equal(lock.packages?.['node_modules/nodemailer'], undefined);
  assert.equal(lock.packages?.['node_modules/playwright'], undefined);
  assert.equal(lock.packages?.['node_modules/playwright-core'], undefined);
  assert.equal(lock.packages?.['node_modules/@xenova/transformers'], undefined);
  assert.equal(
    lock.packages?.['node_modules/@huggingface/transformers']?.dependencies?.sharp,
    '^0.34.5'
  );
  assert.equal(packageJson.overrides?.sharp, '0.35.3');
  assert.equal(packageJson.overrides?.['adm-zip'], '0.6.0');
  assert.equal(lock.packages?.['node_modules/sharp']?.version, '0.35.3');
  assert.equal(lock.packages?.['node_modules/adm-zip']?.version, '0.6.0');

  const embeddings = read('services/core/embeddings.js');
  assert.match(embeddings, /const MODEL_REVISION = '[0-9a-f]{40}'/);
  assert.match(embeddings, /revision: MODEL_REVISION/);
  assert.doesNotMatch(embeddings, /from ['"]@xenova\/transformers['"]/);
});

test('public release documents contain no draft or operator placeholders', () => {
  for (const relativePath of ['README.md', 'SECURITY.md', 'THREAT-MODEL.md', 'DEPLOYMENT.md']) {
    const contents = read(relativePath);
    assert.doesNotMatch(contents, /content subject to operator approval|operator to set|NOT YET CONFIGURED/i, relativePath);
  }
  const serviceCount = JSON.parse(read('hom-architecture-manifest.json')).total_services;
  assert.match(read('README.md'), new RegExp(`current ${serviceCount}-service census`));
  assert.equal(existsSync(path.join(root, 'CONTRIBUTING.md')), true);
  assert.equal(existsSync(path.join(root, 'CHANGELOG.md')), true);
  assert.equal(existsSync(path.join(root, 'AGENTS.md')), true);
});

test('CI fails closed and every external action is commit-pinned', () => {
  const workflows = [
    read('.github/workflows/ci.yml'),
    read('.github/workflows/release-ceremony.yml'),
  ];
  for (const workflow of workflows) {
    assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
    const actions = [...workflow.matchAll(/uses:\s*[^@\s]+@([^\s#]+)/g)].map((match) => match[1]);
    assert.ok(actions.length > 0);
    assert.equal(actions.every((revision) => /^[0-9a-f]{40}$/.test(revision)), true);
  }
  assert.doesNotMatch(read('package.json'), /grep -v ['"]OK\$['"] \|\| echo/);
});

test('public dataset fetch is immutable and redistributable bytes stay untracked', () => {
  const download = read('eval/data/download.sh');
  assert.match(download, /LME_REVISION="[0-9a-f]{40}"/);
  assert.match(download, /LOCOMO_REVISION="[0-9a-f]{40}"/);
  assert.match(download, /LME_SHA256="[0-9a-f]{64}"/);
  assert.match(download, /LOCOMO_SHA256="[0-9a-f]{64}"/);
  assert.doesNotMatch(download, /TODO|NOT YET CONFIGURED/);
  const ignore = read('.gitignore');
  assert.match(ignore, /eval\/data\/\*\.json/);
  assert.match(ignore, /eval\/data\/canonical\//);
  assert.match(ignore, /\.claude\//);
});

test('obsolete paper draft and local package configuration are absent from the release tree', () => {
  assert.equal(existsSync(path.join(root, 'docs/security/Traceability Through a Cryptographic Ledger.pdf')), false);
  const npmIgnore = read('.npmignore');
  assert.match(npmIgnore, /^\.claude\/$/m);
  assert.match(npmIgnore, /^docs\/security\/\*\.pdf$/m);
});
