import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { generateKeypair, pubkeyFingerprint } from '../../services/security/agent-identity.js';
import { encryptMasterPrivkey, enrollAgentWithDeps, enrollMasterWithDeps } from '../../scripts/identity/lib.js';
import { proveCr7R3SecurityAuthority } from '../../scripts/verification/prove-cr7-r3-security-authority.mjs';

const ROOT = new URL('../../', import.meta.url);
const source = (relativePath) => readFile(new URL(relativePath, ROOT), 'utf8');

test('the certificate envelope remains the sole protected-request authority', async () => {
  const gate = await source('services/security/auth-gate.js');
  assert.match(gate, /reserveVerifiedRequest/);
  assert.match(gate, /request_admission_verified/);
  assert.match(gate, /identityAuthenticatedBy = 'envelope'/);
  assert.doesNotMatch(gate, /const OPEN_PREFIXES|req\.headers\[['"]authorization['"]\]/i);
  const openBlock = gate.slice(gate.indexOf('const OPEN_PATHS'), gate.indexOf('const SYSTEM_SELF_ALLOW'));
  assert.match(openBlock, /'\/health'/);
  assert.doesNotMatch(openBlock, /setup\/aimos\/identity/);
});

test('ordinary enrollment has one signed start and a row-co-committed terminal', async () => {
  const [route, library, db] = await Promise.all([
    source('routes/setup.js'),
    source('scripts/identity/lib.js'),
    source('scripts/identity/db.js'),
  ]);
  assert.match(route, /deferCommit: true/);
  for (const operation of ['enroll', 'connect', 'select']) {
    assert.match(route, new RegExp(`router\\.post\\('\\/aimos\\/identity\\/${operation}', requireCapability\\('admin_override'\\)`));
  }
  assert.match(route, /verifiedRequestAuthorityFromRequest\(req\)/);
  assert.match(route, /beginAgentEnrollment\(result\.agentRow, \{/);
  assert.match(route, /commitAgentEnrollment\(result\.agentRow, enrollmentStart/);
  assert.match(route, /markAgentEnrollmentIndeterminate/);
  assert.match(library, /if \(opts\.deferCommit !== true\) await deps\.db\.insertAgent/);
  assert.match(db, /identity_enrollment_started/);
  assert.match(db, /identity_enrollment_committed/);
  assert.match(db, /identity_enrollment_indeterminate/);
  assert.match(db, /master_enrollment_started/);
  assert.match(db, /master_enrollment_committed/);
  assert.match(db, /master_enrollment_indeterminate/);
  const commitStart = db.indexOf('export async function commitAgentEnrollment');
  const commitEnd = db.indexOf('export async function markAgentEnrollmentIndeterminate', commitStart);
  const commitBody = db.slice(commitStart, commitEnd);
  assert.match(commitBody, /BEGIN/);
  assert.match(commitBody, /INSERT INTO agent_identity/);
  assert.match(commitBody, /logEvent\(/);
  assert.match(commitBody, /\{ returnReceipt: true, client, identityQueryFn:/);
  assert.match(commitBody, /COMMIT/);
});

test('master enrollment is prepared before Keychain and database effects', async () => {
  let keychainWrites = 0;
  let databaseWrites = 0;
  const result = await enrollMasterWithDeps('cr7-r3-master-passphrase', {
    keychain: {
      get: async () => null,
      set: async () => { keychainWrites += 1; },
    },
    db: {
      getMaster: async () => null,
      insertMaster: async () => { databaseWrites += 1; },
    },
    kcService: 'aimos.master',
    kcAccount: 'test',
  }, { prepareOnly: true });
  assert.equal(result.ok, true);
  assert.equal(keychainWrites, 0);
  assert.equal(databaseWrites, 0);
  assert.match(result.encryptedBlob, /^[A-Za-z0-9_-]+$/);
  assert.equal(result.masterRow.fingerprint, result.fingerprint);
});

test('deferred enrollment produces a master-signed row without committing it early', async () => {
  const master = generateKeypair();
  const passphrase = 'cr7-r3-test-passphrase';
  let inserts = 0;
  const result = await enrollAgentWithDeps('test-agent', passphrase, {
    keychain: {
      get: async () => encryptMasterPrivkey(passphrase, master.privkey),
      set: async () => { throw new Error('not used'); },
    },
    db: {
      getMaster: async () => ({ master_pubkey: master.pubkey, fingerprint: pubkeyFingerprint(master.pubkey) }),
      getAgent: async () => null,
      insertAgent: async () => { inserts += 1; },
    },
    kcService: 'aimos.master',
    kcAccount: 'test',
    brainRoot: '/tmp/cr7-r3-test-root',
  }, { validityDays: 30, deferCommit: true });
  assert.equal(result.ok, true);
  assert.equal(inserts, 0);
  assert.equal(result.agentRow.agent_id, 'test-agent');
  assert.equal(result.agentRow.cert, result.cert);
});

test('Genesis explicitly owns the unavoidable pre-Housekeeper root', async () => {
  const genesis = await source('scripts/genesis-install.mjs');
  assert.match(genesis, /genesis_identity_root_committed/);
  assert.match(genesis, /root_disposition: 'GENESIS_ROOT'/);
  assert.match(genesis, /housekeeper_signing_material_sha256/);
  assert.match(genesis, /genesis_root: true/);
  assert.match(genesis, /exclusiveOperationKey: true/);
});

test('Keychain mutation is reachable only through signed custody or Genesis root', async () => {
  const [ledger, lane, vault, cli, genesis, bootstrap] = await Promise.all([
    source('services/security/credential-ledger.js'),
    source('services/write/credential-lane.js'),
    source('services/integrations/identity-vault.js'),
    source('scripts/identity/store-credential.js'),
    source('scripts/genesis-install.mjs'),
    source('scripts/bootstrap-db.mjs'),
  ]);
  assert.match(ledger, /credential_custody_started/);
  assert.match(ledger, /credential_custody_readback_verified/);
  assert.match(ledger, /credential_custody_committed/);
  assert.match(ledger, /credential_custody_indeterminate/);
  assert.match(ledger, /credential_custody_start_binding_invalid/);
  assert.match(ledger, /credential_custody_readback_binding_invalid/);
  assert.match(lane, /beginCredentialCustodyMutation/);
  assert.match(vault, /beginCredentialCustodyMutation/);
  assert.match(cli, /beginCredentialCustodyMutation/);
  assert.match(genesis, /genesis_root: true/);
  assert.match(bootstrap, /storeCredentialSync/);
  for (const body of [lane, vault, cli]) {
    assert.doesNotMatch(body, /await\s+storeCredential\s*\(|await\s+revokeCredential\s*\(/);
  }
});

test('authorization and configuration retain their existing signed chain owners', async () => {
  const [permissions, recall, config, store] = await Promise.all([
    source('services/core/permissions.js'),
    source('services/security/recall-authorization.js'),
    source('services/security/system-config-ledger.js'),
    source('services/security/system-config-store.js'),
  ]);
  assert.match(permissions, /verifyAuthorizationEventChain/);
  assert.match(permissions, /prev_mutation_hash/);
  assert.match(permissions, /agent_valid_from|subject_valid_from/);
  assert.match(recall, /verifyRecallAuthorizationChain/);
  assert.match(config, /computeSystemConfigMutationHash/);
  assert.match(store, /previousByKey/);
  assert.match(store, /verifyConfigRow/);
  assert.doesNotMatch(store, /process\.env/);
});

test('model selection has one signed authority and no mutable legacy writer', async () => {
  const [preferences, governance, registry] = await Promise.all([
    source('services/orchestration/model-preferences.js'),
    source('services/orchestration/governance-resolver.js'),
    source('services/observe/architecture-registry.js'),
  ]);
  assert.match(preferences, /readConfigString\(prefix\)/);
  assert.match(preferences, /authority: 'unavailable'/);
  assert.doesNotMatch(preferences, /pickActiveProvider|LLM_PROVIDER|runtime_default'/);
  assert.doesNotMatch(governance, /agent_model_policy/);
  assert.match(governance, /master_signed_system_config/);
  const start = registry.indexOf('export async function registerModel');
  const end = registry.indexOf('export async function getModelRegistry', start);
  assert.match(registry.slice(start, end), /model_registry_mutation_retired_use_signed_model_preference/);
  assert.doesNotMatch(registry.slice(start, end), /INSERT INTO model_registry/);
});

test('independent R3 verifier freezes the complete security authority projection', () => {
  const proof = proveCr7R3SecurityAuthority();
  assert.equal(proof.verdict, 'PROVED');
  assert.equal(proof.credentials.executable_keychain_effect_sites, 4);
  assert.equal(proof.model_policy.agent_model_policy_runtime_authority, false);
  assert.equal(proof.model_policy.model_registry_runtime_mutation, false);
  assert.match(proof.proof_root_sha256, /^[0-9a-f]{64}$/);
});
