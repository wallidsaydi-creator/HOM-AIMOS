// services/security/credential-store.js
// Credential Lifecycle Ledger — keychain wrapper.
//
// Plaintext credentials live in macOS keychain at
// `com.aimos.credentials.<service>` — NEVER in .env, NEVER in process.env,
// NEVER on disk outside the keychain blob.
//
// This service wraps the existing keychain primitives in
// `scripts/identity/keychain.js` with the credential-slot convention +
// sha256 hash computation. The hash is what goes in the ledger (proves
// "same credential" across events without leaking the plaintext).
//
// Design decisions:
//   . credential_hash = sha256(plaintext) stored in ledger at T
//   . Plaintext lives in keychain only — slot com.aimos.credentials.<service>
//   . Trust boundary: agents can STORE (append); ROTATE/REVOKE are
//     operator/housekeeper only (enforced by the CLI, not this service)
//
// This service does NOT sign or ledger anything — that's the caller's
// job (store-credential.js CLI or backfill-credentials.mjs). The caller:
//   1. Computes the hash via computeCredentialHash(value)
//   2. Stores the plaintext via storeCredential(service, value)
//   3. Signs the body with signAsHousekeeper
//   4. Commits via credentialLedger.commitCredentialLifecycle(...)
//
// Phase B (USE linkage) will call readCredential + computeCredentialHash
// at sign time to include credential_slot + credential_hash in the signed
// body of memory-provenance USE events. Phase B is deferred.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  keychainGetSync,
  keychainCredentialGetSync,
  keychainLegacyV1GetSync,
  keychainSetSync
} from '../../scripts/identity/keychain.js';

export const CREDENTIAL_KEYCHAIN_PREFIX = 'com.aimos.credentials';
export const CREDENTIAL_KEYCHAIN_ACCOUNT = 'aimos-native-v2';
export const LEGACY_NATIVE_CREDENTIAL_KEYCHAIN_ACCOUNT = 'aimos-native-v1';
export const LEGACY_CREDENTIAL_KEYCHAIN_ACCOUNT = 'aimos';
export const CREDENTIAL_KEYCHAIN_ACCOUNTS = Object.freeze([
  CREDENTIAL_KEYCHAIN_ACCOUNT,
  LEGACY_NATIVE_CREDENTIAL_KEYCHAIN_ACCOUNT,
  LEGACY_CREDENTIAL_KEYCHAIN_ACCOUNT,
]);

export function credentialSlotId(service) {
  const svc = String(service || '').trim().toLowerCase();
  if (!svc) throw new Error('credentialSlotId: service is required');
  if (!/^[a-z0-9_-]+$/.test(svc)) {
    throw new Error(`credentialSlotId: invalid service name "${service}" (allowed: a-z0-9_-)`);
  }
  return `${CREDENTIAL_KEYCHAIN_PREFIX}.${svc}`;
}

export function parseIdentityVaultCredentialService(service) {
  const value = String(service || '').trim().toLowerCase();
  const match = /^oauth_([a-z0-9][a-z0-9_-]{0,63})_(access|refresh)_token$/.exec(value);
  if (!match) return null;
  return Object.freeze({ provider: match[1], credentialKind: match[2] });
}

export function computeCredentialHash(value) {
  if (value == null || value === '') {
    throw new Error('computeCredentialHash: value is required (cannot hash empty credential)');
  }
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

const POINTER_PREFIX = 'aimos-slot:';
const REVOKED_PREFIX = 'aimos-revoked:';

function credentialVersionSlot(service, hash) {
  return `${credentialSlotId(service)}.${hash}`;
}

function readCredentialValue(serviceName, account) {
  if (account === CREDENTIAL_KEYCHAIN_ACCOUNT) {
    return keychainCredentialGetSync(serviceName, account);
  }
  if (account === LEGACY_NATIVE_CREDENTIAL_KEYCHAIN_ACCOUNT) {
    return keychainLegacyV1GetSync(serviceName, account);
  }
  return keychainGetSync(serviceName, account);
}

function readLogicalCredential(service) {
  const logicalSlot = credentialSlotId(service);
  for (const account of CREDENTIAL_KEYCHAIN_ACCOUNTS) {
    const value = readCredentialValue(logicalSlot, account);
    if (value != null) return { logicalSlot, account, value };
  }
  return null;
}

function storeVersionedCredential(service, value) {
  const logicalSlot = credentialSlotId(service);
  const currentEntry = readLogicalCredential(service);
  const current = currentEntry?.value || null;
  if (current && !current.startsWith(POINTER_PREFIX) && !current.startsWith(REVOKED_PREFIX)) {
    const legacyHash = computeCredentialHash(current);
    if (currentEntry.account === CREDENTIAL_KEYCHAIN_ACCOUNT) {
      keychainSetSync(credentialVersionSlot(service, legacyHash), CREDENTIAL_KEYCHAIN_ACCOUNT, current);
    }
  }
  const hash = computeCredentialHash(value);
  const versionSlot = credentialVersionSlot(service, hash);
  keychainSetSync(versionSlot, CREDENTIAL_KEYCHAIN_ACCOUNT, String(value));
  keychainSetSync(logicalSlot, CREDENTIAL_KEYCHAIN_ACCOUNT, `${POINTER_PREFIX}${versionSlot}`);
  return { slot: logicalSlot, versionSlot, hash };
}

function readVersionedCredential(service) {
  const logical = readLogicalCredential(service);
  const logicalSlot = logical?.logicalSlot || credentialSlotId(service);
  const pointer = logical?.value || null;
  if (pointer == null || pointer.startsWith(REVOKED_PREFIX)) return null;
  if (!pointer.startsWith(POINTER_PREFIX)) {
    return {
      slot: logicalSlot,
      versionSlot: logicalSlot,
      keychainAccount: logical.account,
      value: pointer,
      hash: computeCredentialHash(pointer),
    };
  }
  const versionSlot = pointer.slice(POINTER_PREFIX.length);
  const value = readCredentialValue(versionSlot, logical.account);
  if (value == null) throw new Error(`credential pointer target missing: ${versionSlot}`);
  return {
    slot: logicalSlot,
    versionSlot,
    keychainAccount: logical.account,
    value,
    hash: computeCredentialHash(value),
  };
}

export async function storeCredential(service, value) {
  if (value == null || value === '') {
    throw new Error('storeCredential: value is required');
  }
  return storeVersionedCredential(service, value);
}

export async function readCredential(service) {
  return readVersionedCredential(service);
}

export function storeCredentialSync(service, value) {
  if (value == null || value === '') {
    throw new Error('storeCredentialSync: value is required');
  }
  return storeVersionedCredential(service, value);
}

export function readCredentialSync(service) {
  return readVersionedCredential(service);
}

export async function verifyCredential(service) {
  const entry = await readCredential(service);
  if (!entry) return { exists: false, slot: credentialSlotId(service), hash: null };
  return { exists: true, slot: entry.slot, hash: entry.hash };
}

export async function revokeCredential(service) {
  const slot = credentialSlotId(service);
  const current = readVersionedCredential(service);
  if (!current) return { slot, revoked: false, retained: true };
  keychainSetSync(slot, CREDENTIAL_KEYCHAIN_ACCOUNT, `${REVOKED_PREFIX}${current.hash}`);
  return { slot, revoked: true, retained: true, hash: current.hash, versionSlot: current.versionSlot };
}

export async function credentialExists(service) {
  const entry = await readCredential(service);
  return entry !== null;
}

export function parseCredentialKeychainInventory(output) {
  const text = String(output || '');
  const blocks = text.split(/(?=^class:\s)/m);
  const items = [];
  for (const block of blocks) {
    if (!/^class:\s+"genp"/m.test(block)) continue;
    const account = block.match(/^\s*"acct"[^=]*="([^"]*)"\s*$/m)?.[1] || null;
    const service = block.match(/^\s*"svce"[^=]*="([^"]*)"\s*$/m)?.[1] || null;
    if (!CREDENTIAL_KEYCHAIN_ACCOUNTS.includes(account)
        || !service?.startsWith(`${CREDENTIAL_KEYCHAIN_PREFIX}.`)) continue;
    if (!/^[A-Za-z0-9._-]+$/.test(service)) {
      throw new Error('credential keychain inventory contains an invalid AIMOS service name');
    }
    items.push({ service, account });
  }
  const unique = new Map(items.map((item) => [`${item.service}\0${item.account}`, item]));
  return [...unique.values()].sort((left, right) => left.service.localeCompare(right.service));
}

export function listCredentialKeychainItemsSync(runner = execFileSync) {
  const output = runner(
    'security',
    ['dump-keychain'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024 }
  );
  return parseCredentialKeychainInventory(output);
}
