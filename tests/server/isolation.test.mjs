import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../../', import.meta.url);

function source(relativePath) {
  return readFileSync(new URL(relativePath, root), 'utf8');
}

test('AIMOS bootstrap surfaces are isolated from reserved legacy runtimes', () => {
  const server = source('server.js');
  const runtimeConfig = source('services/core/runtime-config.js');
  const credentialStore = source('services/security/credential-store.js');
  const nativeMcp = source('routes/aimos-mcp-streamable.js');
  const identityVault = source('services/integrations/identity-vault.js');

  assert.match(server, /const PORT = AIMOS_SERVER_PORT;/, 'server must use the AIMOS runtime constant');
  assert.match(runtimeConfig, /if \(raw == null\) return 9100;/, 'AIMOS must default to port 9100');
  assert.match(runtimeConfig, /RESERVED_LEGACY_PORTS\.includes\(port\)/, 'reserved legacy ports must be rejected');
  assert.doesNotMatch(runtimeConfig, /AIMOS_ART|9101/, 'AIMOS must not expose a second security authority');
  assert.doesNotMatch(server, /art-sidecar|9101|X-Internal-Token/, 'AIMOS server must have one native security surface');
  assert.doesNotMatch(server, /const PORT[^\n]*(?:9000|process\.env)/, 'AIMOS port must not reuse legacy or ENV authority');
  assert.doesNotMatch(nativeMcp, /http:\/\/(?:127\.0\.0\.1|localhost):900[01]/, 'native MCP must not advertise a reserved runtime');
  assert.match(nativeMcp, /AIMOS_API_BASE_URL/, 'native MCP must derive its advertised URL from runtime facts');
  assert.doesNotMatch(identityVault, /http:\/\/(?:127\.0\.0\.1|localhost):900[01]/, 'OAuth callback must not target a reserved runtime');
  assert.doesNotMatch(identityVault, /callback|AIMOS_OAUTH_CALLBACK_BASE_URL/, 'retired OAuth callback authority must stay absent');

  assert.match(credentialStore, /com\.aimos\.credentials/, 'AIMOS must use its own keychain namespace');
  assert.doesNotMatch(credentialStore, /com\.hom\.credentials/, 'AIMOS must not share predecessor credential slots');
});

test('P0 topology gate: unresolved same-process callers never target a reserved runtime', () => {
  const retainedSameProcessCallers = [
    'services/orchestration/tool-registry.js',
    'services/retrieval/asmr-pipeline.js',
    'routes/v1-api.js',
  ];
  const offenders = retainedSameProcessCallers.filter((relativePath) =>
    /(?:http:\/\/(?:127\.0\.0\.1|localhost):900[01]|process\.env\.PORT\s*\|\|\s*9000)/.test(source(relativePath))
  );

  assert.deepEqual(
    offenders,
    [],
    `same-process save/recall needs the central native use-case before convergence; unresolved legacy callers: ${offenders.join(', ')}`
  );
});

test('reserved-port scanner permits exact guards, not whole-file exemptions', () => {
  const gate = source('scripts/test/gate-reserved-ports.mjs');
  assert.doesNotMatch(gate, /const ALLOWED\s*=/);
  assert.match(gate, /isExactReservedPortGuard/);
  assert.match(gate, /run-poisonedrag-epistemic-ablation\.mjs/);
  assert.match(gate, /'package\.json'/);
  assert.match(gate, /top-level executable JavaScript entry point/);
});
