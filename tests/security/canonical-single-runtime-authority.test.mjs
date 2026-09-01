import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUNTIME_ROOTS = ['db', 'jobs', 'middleware', 'routes', 'services'];
const PRODUCT_PATH = /(^|\/)(?:tenant(?:[-_][a-z0-9_-]+)?|room-[ab]|meeting-v4)(?:\/|\.|$)/i;
const PRODUCT_IMPORT = /(?:tenant-native|tenant-pool|tenant-route|tenant-capability|tenant-identity|tenant-credential|tenant-lifecycle|tenant-zero|tenant-schema|room-b|meeting-v4|meeting_v4)/i;

function walk(relativePath) {
  const absolute = path.join(ROOT, relativePath);
  if (!statSync(absolute).isDirectory()) return [relativePath];
  return readdirSync(absolute, { withFileTypes: true })
    .flatMap((entry) => walk(path.join(relativePath, entry.name)));
}

function source(relativePath) {
  return readFileSync(path.join(ROOT, relativePath), 'utf8');
}

function importSpecifiers(text) {
  const result = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) result.push(match[1]);
  }
  return result;
}

test('production source contains no tenant, Room, or Meeting product module or import', () => {
  const runtimeFiles = ['server.js', ...RUNTIME_ROOTS.flatMap(walk)]
    .filter((file) => /\.(?:js|mjs|cjs|json)$/.test(file))
    .sort();

  assert.deepEqual(runtimeFiles.filter((file) => PRODUCT_PATH.test(file)), []);

  const forbiddenImports = runtimeFiles.flatMap((file) =>
    importSpecifiers(source(file))
      .filter((specifier) => PRODUCT_IMPORT.test(specifier))
      .map((specifier) => ({ file, specifier })),
  );
  assert.deepEqual(forbiddenImports, []);
});

test('authGate is the sole protected-route boundary and precedes every route mount', () => {
  const server = source('server.js');
  const authMount = 'app.use(authGate);';
  const authIndex = server.indexOf(authMount);
  assert.notEqual(authIndex, -1);
  assert.equal(server.split(authMount).length - 1, 1);

  const pathMounts = [...server.matchAll(/app\.use\(\s*['"]\//g)].map((match) => match.index);
  assert.ok(pathMounts.length > 0);
  assert.ok(pathMounts.every((index) => index > authIndex));

  for (const mount of ["'/aimos'", "'/mcp'", "'/security'", "'/v1'"]) {
    const index = server.indexOf(`app.use(${mount}`);
    assert.ok(index > authIndex, `${mount} must be mounted after authGate`);
  }

  const gate = source('services/security/auth-gate.js');
  assert.match(gate, /const OPEN_PATHS = new Set\(\[/);
  assert.match(gate, /'\/healthz'/);
  assert.match(gate, /'\/health'/);
  assert.match(gate, /reserveVerifiedRequest/);
  assert.match(gate, /request_admission_verified/);
});

test('canonical SAVE, RECALL, session, MCP, and security surfaces retain native owners', () => {
  const aimos = source('routes/aimos.js');
  assert.match(aimos, /import \{ executeCanonicalSave \} from ['"]\.\.\/services\/write\/canonical-save-owner\.js['"]/);
  assert.match(aimos, /import \{ sessionMemoryOwner \} from ['"]\.\.\/services\/orchestration\/session-memory-owner\.js['"]/);
  assert.match(aimos, /import \{ executeCanonicalRecall \} from ['"]\.\.\/services\/retrieval\/native-recall-pipeline\.js['"]/);
  for (const route of ['save', 'recall', 'session/turn', 'session/finalize']) {
    assert.match(aimos, new RegExp(`router\\.post\\('\\/${route.replace('/', '\\/')}'`));
  }

  const mcp = source('routes/aimos-mcp-streamable.js');
  assert.match(mcp, /executeCanonicalRecall/);
  assert.match(mcp, /services\/write\/canonical-save-owner\.js/);
  assert.match(source('routes/security.js'), /import \{ executeCanonicalSave \}/);
  assert.match(source('routes/v1-api.js'), /import \{ executeCanonicalRecall \}/);
});

test('health and scheduler own no tenant readiness or routing state', () => {
  const inspected = ['server.js', 'routes/status.js', 'services/orchestration/scheduler.js']
    .map((file) => ({ file, text: source(file) }));
  const forbidden = /tenant(?:Ready|Readiness|Count|Routing|Registry)|registeredTenants|activeTenants|readyTenants|unavailableTenants/i;
  const findings = inspected.filter(({ text }) => forbidden.test(text)).map(({ file }) => file);
  assert.deepEqual(findings, []);
});
