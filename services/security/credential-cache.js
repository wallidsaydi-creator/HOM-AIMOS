// services/security/credential-cache.js
// Phase B.1 — sync-boot credential cache.
//
// Plaintext credentials live only in versioned macOS Keychain slots. Runtime
// configuration and process environment are never credential authority.
//
// This module restores live behavior: at server boot, after the DB connection
// + systemConfigStore load, loadCredentialCache() reads all 18 slots from
// keychain and populates a Map. Integration services then read from the cache
// synchronously via getCachedCredential(service). No async propagation needed.
//
// SIGHUP reloads the cache (same pattern as systemConfigStore) — operator
// runs store-credential.js ROTATE, then `kill -SIGHUP $(pgrep -f brain/server.js)`
// to pick up the new plaintext. Rotations are operator-initiated ceremonies;
// SIGHUP propagation matches the existing pattern.
//
// Cache invariants:
//   . If cache is not loaded yet (boot mid-flight), getCachedCredential returns
//     null + emits a one-shot console.warn. The server does NOT accept traffic
//     until loadCredentialCache completes (app.listen is gated on it).
//   . If a slot is missing from keychain (not stored, or revoked), the cache
//     stores null for that slot. getCachedCredential returns null. Callers
//     handle null (most have a `|| ''` fallback or a "service not configured"
//     branch).
//   . The cache stores the plaintext IN MEMORY only — never written to disk,
//     never logged, never serialized. Process exit clears it.
//
// The credential lane (services/write/credential-lane.js) calls storeCredential
// + commitCredentialLifecycle STORE when the save pipeline detects a credential
// key. This module is the B.1 foundation — the lane is the B.2 closure.

import { readCredential } from './credential-store.js';
import { credentialLedger } from './credential-ledger.js';

// Services loaded from keychain at boot (A1a extended to 35 total).
// Listed explicitly for auditability + to bound the boot read loop.
// LLM provider keys, Salesforce, and signing/HMAC secrets added in A1a.
// Slots with no current consumer are still loaded — forward-looking.
export const CACHED_CREDENTIAL_SERVICES = [
  'brave_api_key',
  'cf_api_token',
  'github_client_secret',
  'google_client_secret',
  'perplexity_api_key',
  'stripe_secret_key',
  'stripe_webhook_secret',
  'smtp_pass',
  'supabase_service_role_key',
  'x_access_token',
  'x_access_token_secret',
  'x_api_key',
  'x_api_secret',
  'x_bearer_token',
  'youtube_api_key',
  'telegram_bot_token',
  'aimos_api_token',
  'bearer_token',
  'api_key',

  // A1a — LLM provider keys + Salesforce + signing/HMAC secrets
  'openai_api_key',
  'anthropic_api_key',
  'gemini_api_key',
  'google_api_key',
  'lmstudio_api_key',
  'openrouter_api_key',
  'groq_api_key',
  'deepseek_api_key',
  'together_api_key',
  'xai_api_key',
  'venice_api_key',
  'codex_api_key',
  'salesforce_client_secret',
  'salesforce_access_token',
  'oauth_state_secret',
  'session_secret',
  'sentinel_audit_secret',
  // Identity-vault OAuth slots. These are versioned Keychain credentials;
  // PostgreSQL stores only their references and hashes.
  'oauth_google_access_token',
  'oauth_google_refresh_token',
  'oauth_github_access_token',
  'oauth_github_refresh_token',
  'oauth_salesforce_access_token',
  'oauth_salesforce_refresh_token',
  'oauth_openai_access_token',
  'oauth_openai_refresh_token',
  'oauth_codex_access_token',
  'oauth_codex_refresh_token'
];

const _cache = new Map(); // service -> { value, hash, slot } | null
let _loaded = false;
let _loadPromise = null;

async function readVerifiedCredential(service) {
  const entry = await readCredential(service);
  if (!entry) return null;
  const verified = await credentialLedger.readVerifiedSlotChain(entry.slot);
  const effective = verified.effectiveStore;
  if (!effective) throw new Error(`credential lifecycle is revoked or missing for ${service}`);
  const body = typeof effective.body_json === 'string'
    ? JSON.parse(effective.body_json)
    : effective.body_json;
  if (
    effective.service_name !== service
    || body?.service !== service
    || body?.slot_id !== entry.slot
    || body?.credential_hash !== entry.hash
  ) {
    throw new Error(`credential keychain/lifecycle binding mismatch for ${service}`);
  }
  return {
    ...entry,
    lifecycle: Object.freeze({
      provenanceId: String(effective.provenance_id),
      mutationHash: Buffer.from(effective.mutation_hash).toString('hex'),
      signerAgentId: effective.agent_id,
      signerValidFrom: new Date(effective.agent_valid_from).toISOString(),
    }),
  };
}

export function isCredentialCacheLoaded() {
  return _loaded;
}

export async function loadCredentialCache() {
  if (_loadPromise) return _loadPromise;
  _loadPromise = (async () => {
    const results = await Promise.all(
      CACHED_CREDENTIAL_SERVICES.map(async (service) => {
        try {
          const entry = await readVerifiedCredential(service);
          return [service, entry];
        } catch (err) {
          console.error(`[credential-cache] failed to read ${service} from keychain: ${err?.message || err}`);
          return [service, null];
        }
      })
    );
    for (const [service, entry] of results) {
      _cache.set(service, entry);
    }
    _loaded = true;
    const present = Array.from(_cache.values()).filter(Boolean).length;
    console.log(`[BOOT] credentialCache loaded — ${present}/${CACHED_CREDENTIAL_SERVICES.length} slots present`);
  })();
  return _loadPromise;
}

export async function reloadCredentialCache() {
  _loaded = false;
  _cache.clear();
  _loadPromise = null;
  return loadCredentialCache();
}

// Sync read — returns plaintext or null.
// If cache not loaded yet, returns null + one-shot warning (should not happen
// post-boot; indicates a consumer called before loadCredentialCache completed).
export function getCachedCredential(service) {
  if (!_loaded) {
    console.warn(`[credential-cache] getCachedCredential('${service}') called before cache loaded — returning null`);
    return null;
  }
  const entry = _cache.get(service);
  return entry ? entry.value : null;
}

// Sync read — returns the sha256 hash of the plaintext, or null.
// Used by Phase B.2 USE linkage to thread credential_hash to the signer.
export function getCachedCredentialHash(service) {
  if (!_loaded) return null;
  const entry = _cache.get(service);
  return entry ? entry.hash : null;
}

// Explicit materialization for an outbound credential operation. The returned
// immutable checkout binds the plaintext to the exact verified effective STORE
// or ROTATE row. Callers must reserve and finalize its use through the native
// credential ledger immediately around the external boundary.
export function checkoutCachedCredential(service) {
  if (!_loaded) throw new Error('credential_cache_not_loaded');
  const entry = _cache.get(service);
  if (!entry) return null;
  return Object.freeze({
    serviceName: service,
    value: entry.value,
    credentialHash: entry.hash,
    slotId: entry.slot,
    effectiveProvenanceId: entry.lifecycle.provenanceId,
    effectiveMutationHash: entry.lifecycle.mutationHash,
  });
}

// Sync presence check — returns boolean.
// Used by status/configured-check routes that only need to know if a
// credential is configured (no plaintext materialized).
export function peekCachedCredential(service) {
  if (!_loaded) return false;
  const entry = _cache.get(service);
  return entry != null;
}

export async function refreshCachedCredential(service) {
  if (!CACHED_CREDENTIAL_SERVICES.includes(service)) {
    throw new Error(`credential-cache: unregistered service ${service}`);
  }
  const entry = await readVerifiedCredential(service);
  _cache.set(service, entry);
  return entry;
}

// For diagnostics + tests — returns a snapshot of which slots are present.
export function _peekCredentialCache() {
  const snapshot = {};
  for (const [service, entry] of _cache.entries()) {
    snapshot[service] = entry ? { present: true, hash: entry.hash.slice(0, 12) + '...' } : { present: false };
  }
  return snapshot;
}
