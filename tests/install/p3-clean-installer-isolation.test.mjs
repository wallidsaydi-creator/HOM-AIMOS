import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const runner = await readFile(new URL(
  '../../scripts/verification/run-p3-clean-installer-qualification.mjs',
  import.meta.url,
), 'utf8');
const terminal = await readFile(new URL(
  '../../scripts/verification/commit-p3-installer-terminal.mjs',
  import.meta.url,
), 'utf8');

test('P3 qualification invokes the one public installer in a same-user namespace', () => {
  assert.match(runner, /'install-macos\.sh', '--yes'/);
  assert.match(runner, /--aimos-instance', INSTANCE/);
  assert.match(runner, /--postgres-port', String\(POSTGRES_PORT\)/);
  assert.match(runner, /--aimos-port', String\(HTTP_PORT\)/);
  assert.match(runner, /--agent-id', selectedAgentId/);
  assert.match(runner, /interactive: true/);
  assert.doesNotMatch(runner, /sysadminctl|dscl|useradd|groupadd|sudo|Fast User/i);
  assert.doesNotMatch(runner, /process\.env\.AIMOS|dotenv|['"]\.env/);
});

test('P3 qualification owns one retained PostgreSQL cluster without rewriting runtime role migrations', () => {
  assert.match(runner, /initdb/);
  assert.match(runner, /pg_ctl/);
  assert.match(runner, /'-l', path\.join\(stateRoot, 'postgres\.log'\)/);
  assert.match(runner, /POSTGRES_PORT = 25432/);
  assert.match(runner, /DATABASE = `aimos_installer_qual_\$\{qualificationId\}`/);
  assert.match(runner, /INSTANCE = `installer_qual_\$\{qualificationId\}`/);
  assert.doesNotMatch(runner, /p3_installer_qual|HTTP_PORT = 9303|POSTGRES_PORT = 55432/);
  assert.match(runner, /retainedInstallationCensus/);
  assert.match(runner, /retained_installation_ready/);
  assert.doesNotMatch(runner, /ALTER ROLE agent_runtime RENAME|CREATE ROLE agent_runtime_/);
});

test('P3 qualification keeps canonical live, binds before/after state and a signed terminal', () => {
  assert.match(runner, /canonicalBefore = await canonicalFingerprint\(\)/);
  assert.match(runner, /canonicalAfter = await canonicalFingerprint\(\)/);
  assert.match(runner, /canonical_unchanged/);
  assert.match(runner, /canonical_invariants_unchanged/);
  assert.match(runner, /canonical_event_prefix_preserved/);
  assert.match(runner, /eventPrefixPreserved/);
  assert.match(runner, /encode\(mutation_hash, 'hex'\)/);
  assert.doesNotMatch(runner, /SELECT \* FROM aimos_events/);
  assert.match(runner, /commit-p3-installer-terminal\.mjs/);
  assert.match(terminal, /p3_installer_qualification_terminal/);
  assert.match(terminal, /readVerifiedEventById/);
  assert.match(terminal, /signer_certificate: terminal\.signer_certificate/);
  assert.match(terminal, /signature: terminal\.signature/);
  assert.match(terminal, /portable_proof_complete: true/);
  assert.match(terminal, /memory_write: false/);
  assert.match(runner, /canonicalHealthBefore = canonicalHealth\(\)/);
  assert.match(runner, /canonicalHealthAfter = canonicalHealth\(\)/);
  assert.match(runner, /canonical_runtime_not_manipulated: true/);
  assert.doesNotMatch(runner, /--allow-canonical-downtime/);
  assert.doesNotMatch(runner, /stopCanonicalStack|restoreCanonicalStack|brew.*services.*stop/);
});

test('P3 failure cleanup is namespace-exact and never runs after successful qualification', () => {
  assert.match(runner, /context\.runtime_credential_service/);
  assert.match(runner, /keychainDeleteSync\(item\.service, item\.account\)/);
  assert.match(runner, /credentialInventory\(prefix\)/);
  assert.match(runner, /keychainDeleteSync\('aimos\.master', masterKeychainAccount\)/);
  assert.doesNotMatch(runner, /keychainGet|find-generic-password -w|readCredentialSync/);
  assert.match(runner, /disposableCensus/);
  assert.match(runner, /p3_disposable_cleanup_incomplete/);
  assert.match(runner, /postgresRoot, '-m', 'fast', '-w', 'stop'\]\);/);
  assert.doesNotMatch(runner, /postgresRoot, '-m', 'fast', '-w', 'stop'\], \{\s*allowFailure: true/);
  assert.match(runner, /if \(failure\) \{\s*try \{ failedAttemptCleanup = await cleanup\(\);/);
  assert.doesNotMatch(runner, /finally\s*\{[\s\S]*await cleanup\(\)/);
});

test('P3 writes one no-clobber qualification receipt inside the retained installation', () => {
  assert.match(runner, /path\.join\(stateRoot, 'evidence', 'p3-clean-installer-qualification\.json'\)/);
  assert.match(runner, /writeFile\(outputPath,[\s\S]*flag: 'wx'/);
});
