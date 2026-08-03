// services/write/credential-lane.js
// Credential Lane — the save pipeline's dedicated path for credentials.
//
// The credential lane records HOW (slot_id + credential_hash) and
// WHO (agent_id), bound to the memory ledger via memory_id. The two ledgers
// are cryptographically bound through the shared memory_id + credential_hash.
//
// Detection: the save body's `key` matches a known credential service
// (CACHED_CREDENTIAL_SERVICES — the 18 slots: brave_api_key, perplexity_api_key,
// x_access_token, etc.). The system owns the list, the system checks. No LLM,
// no pattern matching, no client-set flag. New/unknown credentials go through
// the existing store-credential.js CLI.
//
// Flow:
//   1. storeCredential(service, value) → versioned keychain write
//   2. return credential-reference/provider memory specifications (no plaintext)
//   3. the native persistence owner inserts both specifications, their memory
//      provenance, and the lifecycle STORE event on one PostgreSQL transaction
//      with body carrying:
//      service, slot_id, credential_hash, agent_id, memory_id, session_id,
//      platform, account, ts_created, ts_saved — signed by housekeeper
//
// The unavoidable Keychain/DB boundary is reconciled by credential hash. A
// retry reuses the same versioned Keychain slot and the persistence owner finds
// any already-attested reference/lifecycle rows before appending missing state.
//
// This module owns detection and Keychain specification only. It does not
// recursively call persistence. The native owner remains persistMemory.

import {
  parseIdentityVaultCredentialService,
  storeCredential,
} from '../security/credential-store.js';
import { CACHED_CREDENTIAL_SERVICES } from '../security/credential-cache.js';

const CREDENTIAL_REFERENCE_TYPE = 'credential_reference';
const CREDENTIAL_PROVIDER_TYPE = 'credential_provider';

// The detector — called by persistMemory at the top of its body. Returns true
// if the save body's key matches a known credential service AND the memory is
// not already a credential_reference (which would cause infinite recursion).
export function isCredentialLaneSave({ key, memory_type }) {
  if (typeof key !== 'string' || !key) return false;
  if (memory_type === CREDENTIAL_REFERENCE_TYPE) return false;
  return CACHED_CREDENTIAL_SERVICES.includes(key);
}

export async function prepareCredentialMemory({
  company_id,
  agent_id,
  key,
  value,
  scope,
  clearance_level,
  memory_type,
  source,
  session_id,
  account,
  ts_created,
  valid_from,
  valid_until,
}) {
  if (typeof value !== 'string' || value === '') {
    return {
      rejected: true,
      reason: 'credential_lane_empty_value',
      save_feedback: { accepted: false, reasoning: 'Credential lane rejected empty value — nothing to store in keychain.' },
    };
  }

  const tsNow = Math.floor(Date.now() / 1000);
  const aid = agent_id || 'housekeeper';

  // 1. Keychain write — plaintext to com.aimos.credentials.<service>
  const stored = await storeCredential(key, value);

  // Produce exact DB memory specifications. The native persistence owner inserts
  // and attests these on one transaction; this lane never calls back into it.
  const referenceValue = JSON.stringify({
    slot_id: stored.slot,
    service_name: key,
    stored_at: 'keychain',
    credential_hash: stored.hash,
    credential_lane: true,
  });
  const referenceSpec = {
    company_id,
    agent_id: aid,
    key,
    value: referenceValue,
    scope,
    clearance_level,
    memory_type: CREDENTIAL_REFERENCE_TYPE,
    source: source || 'credential_lane',
    valid_from,
    valid_until,
    mutation_authority: 'housekeeper',
  };

  // Optional provider classification specification — an extra memory underneath
  // the credential_reference row carrying the provider/third-party name (e.g.
  // 'nvidia', 'brave', 'perplexity'). This avoids confusion when the generic
  // api_key slot is rotated across providers over time — each save has a
  // classification row identifying which provider issued the key.
  const providerSpec = account ? {
      company_id,
      agent_id: aid,
      key: `${key}.provider`,
      value: JSON.stringify({
        provider: account,
        slot_id: stored.slot,
        service_name: key,
        credential_hash: stored.hash,
        credential_memory_id: null,
        classified_at: tsNow,
      }),
      scope,
      clearance_level,
      memory_type: CREDENTIAL_PROVIDER_TYPE,
      source: source || 'credential_lane',
      valid_from,
      valid_until,
      mutation_authority: 'housekeeper',
    } : null;

  return {
    company_id,
    agent_id: aid,
    service_name: key,
    keychain_slot: stored.slot,
    keychain_version_slot: stored.versionSlot,
    credential_hash: stored.hash,
    session_id: session_id || null,
    account: account || null,
    ts_created: ts_created || tsNow,
    ts_saved: tsNow,
    referenceSpec,
    providerSpec,
  };
}

export function buildCredentialLifecycleBody(prepared, memoryId, {
  eventType = 'STORE',
  rotatedFrom = null,
  rotatedFromHash = null,
} = {}) {
  const vaultService = parseIdentityVaultCredentialService(prepared.service_name);
  return {
    event_type: eventType,
    service: prepared.service_name,
    slot_id: prepared.keychain_slot,
    credential_hash: prepared.credential_hash,
    valid_from: prepared.ts_created,
    valid_until: null,
    rotated_from: rotatedFrom,
    rotated_from_hash: rotatedFromHash,
    reason: 'save_pipeline_credential_lane',
    operator: prepared.agent_id,
    signer_agent_id: 'housekeeper',
    subject_agent_id: prepared.agent_id,
    memory_id: memoryId,
    session_id: prepared.session_id,
    platform: prepared.service_name,
    account: prepared.account,
    ...(vaultService ? {
      identity_vault: {
        namespace: 'identity_vault',
        company_id: prepared.company_id,
        provider: vaultService.provider,
        credential_kind: vaultService.credentialKind,
        expires_at: null,
        metadata: {},
        auth_type: 'oauth',
        cluster_id: 'identity_vault.auth',
        initiating_subject_agent_id: prepared.agent_id,
        credential_use_evidence: [],
      },
    } : {}),
    ts_created: prepared.ts_created,
    ts_saved: prepared.ts_saved,
  };
}

export const __private__ = { CREDENTIAL_REFERENCE_TYPE, CREDENTIAL_PROVIDER_TYPE };
