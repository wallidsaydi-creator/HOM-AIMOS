import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../../', import.meta.url);

async function source(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8');
}

test('command center exposes plugin inventory without unsigned filesystem mutation', async () => {
  const route = await source('routes/command-center.js');
  assert.match(route, /router\.get\('\/plugins'/);
  assert.doesNotMatch(route, /router\.post\('\/plugins\/(?:install|uninstall|load|unload)'/);

  const service = await source('services/orchestration/command-center.js');
  assert.doesNotMatch(service, /export function (?:installPlugin|uninstallPlugin|loadPlugin|unloadPlugin)\b/);
  assert.doesNotMatch(service, /fs\.rmSync\(/);
  assert.doesNotMatch(service, /fs\.copyFileSync\(/);
  assert.doesNotMatch(service, /writeCodexConfigText|setPluginEnabledInToml/);
});

test('command center skill surface is inventory-only and canonical execution stays under /skills', async () => {
  const route = await source('routes/command-center.js');
  assert.match(route, /router\.get\('\/skills'/);
  assert.doesNotMatch(route, /router\.post\('\/skills\/(?:load|execute)'/);

  const service = await source('services/orchestration/command-center.js');
  assert.doesNotMatch(service, /export (?:async )?function (?:loadSkill|executeUnifiedSkill)\b/);
  assert.doesNotMatch(service, /command-center-sessions\.json/);

  const canonicalRoute = await source('routes/skills.js');
  assert.match(canonicalRoute, /router\.post\('\/:name\/execute', requireCapability\('admin_override'\)/);
  assert.match(canonicalRoute, /executionContext: req\.executionContext/);
});

test('legacy agent-message table transport is retired in favor of retained memories', async () => {
  const route = await source('routes/aimos.js');
  assert.doesNotMatch(route, /router\.(?:get|post|put|delete)\('\/agent-messages?/);
  const runner = await source('services/orchestration/agent-runner.js');
  assert.match(runner, /memory_type: 'agent_message'/);
  assert.match(runner, /agent_message_read/);
  assert.doesNotMatch(runner, /UPDATE\s+aimos_memories|DELETE\s+FROM\s+aimos_memories/i);
});

test('specialist discovery retains all enrolled profiles independent of mutable active flags', async () => {
  const registry = await source('services/orchestration/tool-registry.js');
  const start = registry.indexOf('hive_search_specialists:');
  const end = registry.indexOf('\n  schedule_task:', start);
  assert.ok(start >= 0 && end > start, 'specialist search implementation is present');
  const specialistSearch = registry.slice(start, end);
  assert.match(specialistSearch, /FROM agent_profiles/);
  assert.doesNotMatch(specialistSearch, /is_active/);
});

test('agent messaging routes bind sender, inbox, and advisory author to the verified certificate', async () => {
  const route = await source('routes/agent-learning.js');
  assert.match(route, /req\.params\.id !== req\.agentId[\s\S]*verified_message_sender_mismatch/);
  assert.match(route, /sendAgentMessage\(req\.agentId, to, message/);
  assert.match(route, /req\.params\.id !== req\.agentId[\s\S]*verified_inbox_recipient_mismatch/);
  assert.match(route, /getAgentInbox\(req\.agentId, limit\)/);
  assert.match(route, /postAdvisory\(agentId, advice, req\.agentId\)/);
  assert.doesNotMatch(route, /from\s*\|\|\s*req\.agentId/);
});

test('governance resolution binds action inputs to signed bodies and the verified actor', async () => {
  const governance = await source('routes/governance.js');
  assert.match(governance, /router\.post\('\/resolve'/);
  assert.match(governance, /agentId = req\.agentId/);
  assert.match(governance, /agentId !== req\.agentId/);
  assert.doesNotMatch(governance, /router\.get\('\/(?:resolve|brain)'/);
  assert.doesNotMatch(governance, /auctionTask|contract-net\/auction/);

  const settings = await source('routes/settings.js');
  assert.match(settings, /router\.post\('\/model\/resolve'/);
  assert.doesNotMatch(settings, /router\.get\('\/model\/resolve'/);
});

test('agent creation fails closed when no verified model policy is available', async () => {
  const store = await source('services/orchestration/agent-store.js');
  assert.doesNotMatch(store, /gemma3:1b/);
  assert.match(store, /model_policy_unavailable:/);
  assert.match(store, /MODEL_POLICY_UNAVAILABLE/);

  const task = await source('routes/task.js');
  assert.match(task, /error\?\.code === 'MODEL_POLICY_UNAVAILABLE'/);
  assert.match(task, /res\.status\(503\)/);

  const governance = await source('services/orchestration/governance-resolver.js');
  assert.doesNotMatch(governance, /pickActiveProvider|discoverActiveProviders/);
  assert.match(governance, /if \(!modelId\) continue/);
  assert.match(governance, /throw new Error\(`model_policy_unavailable:/);
  const readiness = governance.slice(governance.indexOf('export async function ensureGovernanceReady'));
  assert.doesNotMatch(readiness, /hydrateAgentStoreFromGovernance|queuePersonaEmbeddingBackfill|UPDATE agent_profiles/);
});

test('task model preference is one signed composite value, never a torn provider/model pair', async () => {
  const ledger = await source('services/security/system-config-ledger.js');
  for (const taskType of ['CHAT', 'HEAVY', 'RESEARCH', 'FAST', 'CODING']) {
    assert.match(ledger, new RegExp(`MODEL_PREFERENCE_${taskType}: Object\\.freeze\\(\\{ type: 'model_preference'`));
  }
  assert.match(ledger, /JSON\.stringify\(\{ provider, model \}\)/);

  const preferences = await source('services/orchestration/model-preferences.js');
  assert.match(preferences, /readConfigString\(prefix\)/);
  assert.doesNotMatch(preferences, /readConfigString\(`\$\{prefix\}_PROVIDER`\)/);
  assert.doesNotMatch(preferences, /readConfigString\(`\$\{prefix\}_MODEL`\)/);
  assert.match(preferences, /preference\.authority === 'signed_task_preference'/);

  const settings = await source('routes/settings.js');
  assert.match(settings, /const preference = JSON\.stringify\(\{ provider, model \}\)/);
  assert.doesNotMatch(settings, /\$\{prefix\}_PROVIDER|\$\{prefix\}_MODEL/);
});

test('unsigned self-healing model mutation is absent from heartbeat and server lifecycle', async () => {
  const [server, heartbeat, pipeline] = await Promise.all([
    source('server.js'),
    source('jobs/heartbeat.js'),
    source('services/pipeline-manifest.js'),
  ]);
  for (const body of [server, heartbeat, pipeline]) {
    assert.doesNotMatch(body, /self-healing\.js|runSelfHealingCycle|startSelfHealingWatcher/);
  }
});

test('OAuth mutation is absent until one durable one-time signed ceremony owns it', async () => {
  const [integrations, setup, commandCenter, authGate] = await Promise.all([
    source('routes/integrations.js'),
    source('routes/setup.js'),
    source('services/orchestration/command-center.js'),
    source('services/security/auth-gate.js'),
  ]);
  for (const body of [integrations, setup, commandCenter]) {
    assert.doesNotMatch(body, /createOAuthState|validateOAuthState|ACTIVE_OAUTH_FLOWS|setupStates/);
    assert.doesNotMatch(body, /appendIntegrationToken|buildAuthUrl|buildOAuthConnectUrl/);
  }
  assert.doesNotMatch(integrations, /router\.(?:get|post)\('\/(?:connect|callback|toggle)/);
  assert.doesNotMatch(setup, /router\.post\('\/google\/(?:init|callback)'/);
  assert.doesNotMatch(authGate, /integrations\/callback|OPEN_PREFIXES/);
});
