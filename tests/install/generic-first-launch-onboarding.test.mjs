import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  defaultOnboardingKeychainAccount,
  normalizeOnboardingAgentId,
  normalizeOnboardingModelPreference,
  onboardingModelConfigEntries,
  PUBLIC_AGENT_CLEARANCE_DEFAULT,
  PUBLIC_AGENT_CLEARANCE_MAXIMUM,
} from '../../scripts/identity/onboarding-contract.mjs';
import { resolveAimosInstallationContext } from '../../services/installation-context.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relative) => readFileSync(path.join(ROOT, relative), 'utf8');
const owner = read('scripts/identity/onboard-agent.mjs');
const installer = read('install-macos.sh');
const genesisInstaller = read('scripts/genesis-install.mjs');

test('first launch accepts an operator-selected ordinary identity and rejects system identities', () => {
  assert.equal(normalizeOnboardingAgentId('my-agent_01'), 'my-agent_01');
  for (const invalid of ['', '../agent', 'agent.name', 'housekeeper', 'AIMOS_FLAG_SIGNER']) {
    assert.throws(() => normalizeOnboardingAgentId(invalid), /onboarding_/);
  }
});

test('public ordinary-agent onboarding is capped at clearance 10', () => {
  assert.equal(PUBLIC_AGENT_CLEARANCE_DEFAULT, 10);
  assert.equal(PUBLIC_AGENT_CLEARANCE_MAXIMUM, 10);
  assert.match(owner, /PUBLIC_AGENT_CLEARANCE_MAXIMUM/);
  assert.doesNotMatch(owner, /integerOption\('--clearance',\s*10,\s*0,\s*12\)/);
});

test('named installations derive a disjoint master Keychain account without a hidden identity', () => {
  const canonical = resolveAimosInstallationContext([], { homeDirectory: '/Users/example' });
  const named = resolveAimosInstallationContext([
    '--aimos-instance=p3_repro', '--aimos-postgres-port=55432',
  ], { homeDirectory: '/Users/example' });
  assert.equal(defaultOnboardingKeychainAccount(canonical, 'alice'), 'alice');
  assert.equal(defaultOnboardingKeychainAccount(named, 'alice'), 'alice-p3_repro');
});

test('optional model choice is one composite provider/model value for every task policy', () => {
  assert.equal(normalizeOnboardingModelPreference('', ''), null);
  assert.throws(() => normalizeOnboardingModelPreference('openai', ''), /incomplete/);
  const preference = normalizeOnboardingModelPreference('Codex', 'gpt-5.6-sol');
  assert.deepEqual(preference, { provider: 'codex', model: 'gpt-5.6-sol' });
  const entries = onboardingModelConfigEntries(preference);
  assert.deepEqual(entries.map((entry) => entry.configKey), [
    'MODEL_PREFERENCE_CHAT', 'MODEL_PREFERENCE_HEAVY', 'MODEL_PREFERENCE_RESEARCH',
    'MODEL_PREFERENCE_FAST', 'MODEL_PREFERENCE_CODING',
  ]);
  assert.equal(new Set(entries.map((entry) => entry.value)).size, 1);
});

test('generic onboarding reuses native ledgers in Housekeeper-first order', () => {
  const execution = owner.slice(owner.indexOf('async function main()'));
  const start = execution.indexOf("'first_launch_onboarding_started'");
  const master = execution.indexOf('await enrollMaster(');
  const agent = execution.indexOf('await enrollOrdinaryAgent(');
  const grant = execution.indexOf('recallAuthorizationService.commit');
  const config = execution.indexOf('await appendConfiguration(');
  const terminal = execution.indexOf("'first_launch_onboarding_terminal'");
  assert.ok(start >= 0 && start < master && master < agent && agent < grant && grant < config && config < terminal);
  assert.equal((owner.match(/readPassphrase\(/g) || []).length, 1);
  assert.match(owner, /guide_memories !== 8|before\.guide_memories !== 8/);
  assert.match(owner, /benchmark_specific: false/);
  assert.doesNotMatch(owner, /mutmem|campaign[-_ ]runner/i);
});

test('the one public installer owns generic onboarding before service start', () => {
  const genesis = installer.indexOf('scripts/genesis-install.mjs');
  const onboarding = installer.indexOf('scripts/identity/onboard-agent.mjs');
  const service = installer.indexOf('scripts/service/manage-user-service.mjs install');
  assert.ok(genesis >= 0 && genesis < onboarding && onboarding < service);
  assert.match(installer, /--agent-id ID/);
  assert.match(installer, /--model-provider ID/);
  assert.doesNotMatch(installer, /skip-onboarding|defer-onboarding|genesis-only/i);
  assert.doesNotMatch(installer, /mutmem|campaign[-_ ]runner/i);
  assert.match(installer, /status --instance %q/);
});

test('Genesis returns directly to one-passphrase generic onboarding without a manual reviewer ceremony', () => {
  assert.match(genesisInstaller, /requests the operator passphrase exactly once/);
  assert.match(genesisInstaller, /No manual enrollment ceremony or second passphrase entry is required/);
  assert.doesNotMatch(genesisInstaller, /LIVE REVIEWER CEREMONY|B1\. Enroll master|B11\.|master passphrase twice|Part B ceremony/i);
});
