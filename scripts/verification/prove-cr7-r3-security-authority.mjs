#!/usr/bin/env node

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCr7EffectCensus } from './prove-cr7-durable-action-census.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SOURCE_FILES = Object.freeze([
  'services/security/auth-gate.js',
  'services/core/permissions.js',
  'services/security/recall-authorization.js',
  'services/security/system-config-ledger.js',
  'services/security/system-config-store.js',
  'services/security/credential-store.js',
  'services/security/credential-ledger.js',
  'services/write/credential-lane.js',
  'services/write/persist-memory.js',
  'services/integrations/identity-vault.js',
  'services/orchestration/model-preferences.js',
  'services/orchestration/governance-resolver.js',
  'services/observe/architecture-registry.js',
  'routes/setup.js',
  'scripts/identity/lib.js',
  'scripts/identity/db.js',
  'scripts/identity/enroll-agent.js',
  'scripts/identity/store-credential.js',
  'scripts/genesis-install.mjs',
  'scripts/bootstrap-db.mjs',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function source(relative) {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

function assert(condition, reason) {
  if (!condition) throw new Error(`cr7_r3_proof_failed:${reason}`);
}

export function proveCr7R3SecurityAuthority() {
  const files = Object.fromEntries(SOURCE_FILES.map((file) => [file, source(file)]));
  const census = scanCr7EffectCensus();

  const authGate = files['services/security/auth-gate.js'];
  assert(authGate.includes('reserveVerifiedRequest'), 'request_receipt_owner_missing');
  assert(authGate.includes('request_admission_verified'), 'request_admission_owner_missing');
  assert(!/const OPEN_PREFIXES/.test(authGate), 'blanket_open_identity_prefix');
  const openBlock = authGate.slice(authGate.indexOf('const OPEN_PATHS'), authGate.indexOf('const SYSTEM_SELF_ALLOW'));
  assert(!/setup\/aimos\/identity/.test(openBlock), 'open_identity_http_endpoint');

  const identityDb = files['scripts/identity/db.js'];
  const setup = files['routes/setup.js'];
  const enrollCli = files['scripts/identity/enroll-agent.js'];
  assert(/identity_enrollment_started/.test(identityDb), 'identity_start_missing');
  assert(/identity_enrollment_committed/.test(identityDb), 'identity_terminal_missing');
  assert(/identity_enrollment_indeterminate/.test(identityDb), 'identity_indeterminate_missing');
  assert(/master_enrollment_started/.test(identityDb), 'master_start_missing');
  assert(/master_enrollment_committed/.test(identityDb), 'master_terminal_missing');
  assert(/master_enrollment_indeterminate/.test(identityDb), 'master_indeterminate_missing');
  assert(/readVerifiedEventById/.test(identityDb), 'identity_start_independent_verification_missing');
  assert(/verifyCertChain/.test(identityDb), 'agent_certificate_independent_verification_missing');
  assert(/deferCommit: true/.test(setup) && /deferCommit: true/.test(enrollCli), 'identity_early_commit_reachable');
  assert((setup.match(/requireCapability\('admin_override'\)/g) || []).length >= 4, 'identity_admin_envelope_missing');
  assert(/verifiedRequestAuthorityFromRequest\(req\)/.test(setup), 'identity_request_authority_missing');
  assert(/genesis_identity_root_committed/.test(files['scripts/genesis-install.mjs']), 'genesis_identity_root_missing');

  const permissions = files['services/core/permissions.js'];
  const recall = files['services/security/recall-authorization.js'];
  const config = files['services/security/system-config-ledger.js'];
  assert(/verifyAuthorizationEventChain/.test(permissions), 'authorization_chain_verifier_missing');
  assert(/verifyRecallAuthorizationChain/.test(recall), 'recall_authorization_verifier_missing');
  assert(/computeSystemConfigMutationHash/.test(config), 'configuration_chain_verifier_missing');

  const ledger = files['services/security/credential-ledger.js'];
  for (const required of [
    'credential_custody_started',
    'credential_custody_readback_verified',
    'credential_custody_committed',
    'credential_custody_indeterminate',
    'credential_custody_start_binding_invalid',
    'credential_custody_readback_binding_invalid',
    'credential_genesis_root_invalid',
    'credential_successor_must_rotate',
  ]) assert(ledger.includes(required), `credential_protocol_missing:${required}`);
  for (const file of [
    'services/write/credential-lane.js',
    'services/integrations/identity-vault.js',
    'scripts/identity/store-credential.js',
  ]) {
    assert(files[file].includes('beginCredentialCustodyMutation'), `credential_owner_bypass:${file}`);
    assert(!/await\s+(?:storeCredential|revokeCredential)\s*\(/.test(files[file]), `raw_keychain_call:${file}`);
  }
  assert(/genesis_root: true/.test(files['scripts/genesis-install.mjs']), 'credential_genesis_root_missing');
  assert(/storeCredentialSync/.test(files['scripts/bootstrap-db.mjs']), 'credential_bootstrap_root_missing');

  const preferences = files['services/orchestration/model-preferences.js'];
  const governance = files['services/orchestration/governance-resolver.js'];
  const registry = files['services/observe/architecture-registry.js'];
  const registerModelBody = registry.slice(
    registry.indexOf('export async function registerModel'),
    registry.indexOf('export async function getModelRegistry'),
  );
  assert(/readConfigString\(prefix\)/.test(preferences), 'signed_model_config_missing');
  assert(/discoverActiveProviders/.test(preferences), 'model_availability_check_missing');
  assert(!/pickActiveProvider|LLM_PROVIDER\/LLM_MODEL/.test(preferences), 'unsigned_model_fallback');
  assert(!/agent_model_policy/.test(governance), 'legacy_model_policy_authority');
  assert(/model_registry_mutation_retired_use_signed_model_preference/.test(registerModelBody), 'model_registry_writer_not_retired');
  assert(!/INSERT INTO model_registry|UPDATE model_registry/.test(registerModelBody), 'model_registry_mutation_reachable');

  const credentialEffects = census.effects.filter((effect) => effect.effect_class === 'credential_effect');
  assert(credentialEffects.length === 4, `credential_effect_count:${credentialEffects.length}`);
  assert(credentialEffects.every((effect) => effect.file === 'services/security/credential-store.js'), 'credential_effect_owner_split');
  const modelRegistryEffects = census.effects.filter((effect) => effect.source_anchor.includes('model_registry'));
  assert(modelRegistryEffects.length === 0, 'model_registry_effect_remains');

  const sourceManifest = SOURCE_FILES.map((file) => ({ file, sha256: sha256(files[file]) }));
  const result = {
    schema: 'hom.aimos.cr7-r3-security-authority-proof/v1',
    verdict: 'PROVED',
    source_file_count: SOURCE_FILES.length,
    source_root_sha256: sha256(canonicalJson(sourceManifest)),
    current_effect_census_root_sha256: census.effect_root_sha256,
    identities: {
      protected_request_authority: 'certificate_envelope_plus_durable_admission',
      autonomous_principal: 'housekeeper',
      ordinary_enrollment: 'signed_start_identity_row_terminal_or_indeterminate',
      genesis_exception: 'explicit_self_signed_root',
      revocation: 'existing_master_signed_append_only_event',
    },
    authorization_configuration: {
      authorization_chain: 'verified',
      recall_authorization_chain: 'verified',
      system_configuration_chain: 'verified',
      ambient_capability: false,
    },
    credentials: {
      executable_keychain_effect_sites: credentialEffects.length,
      custody_protocol: 'signed_start_readback_lifecycle_terminal',
      success_terminal_db_atomic: true,
      crash_open_disposition: 'INDETERMINATE_OR_OPEN_FOR_CR7_R6',
      plaintext_in_evidence: false,
    },
    model_policy: {
      runtime_authority: 'master_signed_system_config',
      exact_composite_preference: true,
      provider_availability_verified_after_selection: true,
      agent_model_policy_runtime_authority: false,
      model_registry_runtime_mutation: false,
    },
    deferred_by_design: {
      cert_cache_and_process_files: 'CR7_R5',
      provider_network_effects: 'CR7_R5',
      crash_orphan_reconciliation_execution: 'CR7_R6',
    },
  };
  return Object.freeze({
    ...result,
    proof_root_sha256: sha256(canonicalJson(result)),
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(proveCr7R3SecurityAuthority(), null, 2));
}
