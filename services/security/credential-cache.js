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

import { readCredential, credentialSlotId } from './credential-store.js';
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

export const CREDENTIAL_CACHE_STATES = Object.freeze({
  READY: 'READY',
  ABSENT: 'ABSENT',
  REVOKED: 'REVOKED',
  UNAVAILABLE: 'UNAVAILABLE',
});

function lifecycleEntry(effective) {
  return Object.freeze({
    provenanceId: String(effective.provenance_id),
    mutationHash: Buffer.from(effective.mutation_hash).toString('hex'),
    signerAgentId: effective.agent_id,
    signerValidFrom: new Date(effective.agent_valid_from).toISOString(),
  });
}

export function createCredentialCacheOwner({
  services = CACHED_CREDENTIAL_SERVICES,
  readCredentialFn = readCredential,
  readVerifiedSlotChainFn = credentialLedger.readVerifiedSlotChain.bind(credentialLedger),
  logFn = console,
} = {}) {
  const serviceSet = new Set(services);
  let snapshot = new Map();
  let loaded = false;
  let generation = 0;
  let initialLoad = null;
  let reloadTail = Promise.resolve();
  const revocationGenerations = new Map();

  function publishRevocation(service) {
    const revoked = Object.freeze({ state: CREDENTIAL_CACHE_STATES.REVOKED, entry: null });
    if (loaded && snapshot.get(service)?.state !== CREDENTIAL_CACHE_STATES.REVOKED) {
      const next = new Map(snapshot); next.set(service, revoked);
      revocationGenerations.set(service, publish(next));
    }
    return revoked;
  }

  function publishCandidate(candidate, startedGeneration) {
    for (const [service, revokedAt] of revocationGenerations) {
      if (revokedAt > startedGeneration) candidate.set(service, snapshot.get(service));
    }
    return publish(candidate);
  }

  async function buildState(service, prior = null) {
    const slot = credentialSlotId(service);
    const authorityRead = Promise.resolve().then(() => readVerifiedSlotChainFn(slot)).then(value => {
      if (value?.revoked === true) publishRevocation(service);
      return value;
    });
    const [material, authority] = await Promise.allSettled([
      Promise.resolve().then(() => readCredentialFn(service)), authorityRead,
    ]);
    // A verified revocation is authoritative even when Keychain is unavailable.
    // Stop exposing that slot immediately, without waiting for other services.
    if (authority.status === 'fulfilled' && authority.value?.revoked === true) {
      return publishRevocation(service);
    }
    if (material.status === 'rejected' || authority.status === 'rejected') {
      const error = material.reason || authority.reason;
      return Object.freeze({ state: CREDENTIAL_CACHE_STATES.UNAVAILABLE,
        retainedEntry: prior?.entry || prior?.retainedEntry || null,
        errorClass: String(error?.name || 'credential_read_failure') });
    }
    const entry = material.value;
    const verified = authority.value;
    if (!entry) {
      return Object.freeze(verified?.rowCount === 0
        ? { state: CREDENTIAL_CACHE_STATES.ABSENT, entry: null }
        : { state: CREDENTIAL_CACHE_STATES.UNAVAILABLE,
          retainedEntry: prior?.entry || prior?.retainedEntry || null,
          errorClass: 'credential_keychain_value_unavailable' });
    }
    const effective = verified?.effectiveStore;
    const body = typeof effective?.body_json === 'string'
      ? JSON.parse(effective.body_json) : effective?.body_json;
    if (!effective
        || effective.service_name !== service
        || body?.service !== service
        || body?.slot_id !== entry.slot
        || body?.credential_hash !== entry.hash) {
      return Object.freeze({ state: CREDENTIAL_CACHE_STATES.UNAVAILABLE,
        retainedEntry: prior?.entry || prior?.retainedEntry || null,
        errorClass: 'credential_authority_binding_invalid' });
    }
    return Object.freeze({ state: CREDENTIAL_CACHE_STATES.READY,
      entry: Object.freeze({ ...entry, lifecycle: lifecycleEntry(effective) }) });
  }

  async function buildSnapshot(previous) {
    const pairs = await Promise.all([...serviceSet].map(async (service) => (
      [service, await buildState(service, previous.get(service))]
    )));
    return new Map(pairs);
  }

  function publish(candidate) {
    snapshot = candidate;
    loaded = true;
    generation += 1;
    return generation;
  }

  function unavailableServices(candidate) {
    return [...candidate.entries()]
      .filter(([, state]) => state.state === CREDENTIAL_CACHE_STATES.UNAVAILABLE)
      .map(([service]) => service);
  }

  async function load() {
    if (loaded) return Object.freeze({ generation, unavailable: Object.freeze([]) });
    if (initialLoad) return initialLoad;
    initialLoad = enqueueReload(async () => {
      if (loaded) return Object.freeze({ generation, unavailable: Object.freeze([]) });
      const candidate = await buildSnapshot(new Map());
      const unavailable = unavailableServices(candidate);
      if (unavailable.length) {
        const error = new Error(`credential_cache_initial_load_unavailable:${unavailable.join(',')}`);
        error.unavailableServices = Object.freeze(unavailable);
        throw error;
      }
      const nextGeneration = publish(candidate);
      const present = [...candidate.values()].filter((state) => state.state === CREDENTIAL_CACHE_STATES.READY).length;
      logFn.log?.(`[BOOT] credentialCache loaded — ${present}/${serviceSet.size} slots present; generation=${nextGeneration}`);
      return Object.freeze({ generation: nextGeneration, unavailable: Object.freeze([]) });
    });
    try { return await initialLoad; } catch (error) { initialLoad = null; throw error; }
  }

  function enqueueReload(work) {
    const next = reloadTail.then(work, work);
    reloadTail = next.catch(() => {});
    return next;
  }

  async function reload() {
    if (!loaded) return load();
    return enqueueReload(async () => {
      const startedGeneration = generation;
      const candidate = await buildSnapshot(snapshot);
      const nextGeneration = publishCandidate(candidate, startedGeneration);
      const unavailable = unavailableServices(candidate);
      if (unavailable.length) {
        const error = new Error(`credential_cache_reload_unavailable:${unavailable.join(',')}`);
        error.generation = nextGeneration;
        error.unavailableServices = Object.freeze(unavailable);
        throw error;
      }
      return Object.freeze({ generation: nextGeneration, unavailable: Object.freeze([]) });
    });
  }

  async function refresh(service) {
    if (!serviceSet.has(service)) throw new Error(`credential-cache: unregistered service ${service}`);
    if (!loaded) await load();
    // Revocation is an immediate safety transition, including when a complete
    // reload is waiting on another service. READY publication still queues.
    try {
      if ((await readVerifiedSlotChainFn(credentialSlotId(service)))?.revoked === true) publishRevocation(service);
    } catch { /* The queued native state read reports UNAVAILABLE. */ }
    return enqueueReload(async () => {
      const startedGeneration = generation;
      const prior = snapshot.get(service) || null;
      const state = await buildState(service, prior);
      const candidate = new Map(snapshot);
      candidate.set(service, state);
      const nextGeneration = publishCandidate(candidate, startedGeneration);
      const effective = candidate.get(service);
      if (effective.state === CREDENTIAL_CACHE_STATES.UNAVAILABLE) {
        const error = new Error(`credential_cache_refresh_unavailable:${service}`);
        error.generation = nextGeneration;
        throw error;
      }
      return Object.freeze({ generation: nextGeneration, state: effective.state,
        entry: effective.state === CREDENTIAL_CACHE_STATES.READY ? effective.entry : null });
    });
  }

  function state(service) {
    if (!loaded) throw new Error('credential_cache_not_loaded');
    return snapshot.get(service) || Object.freeze({ state: CREDENTIAL_CACHE_STATES.ABSENT, entry: null });
  }

  function checkout(service) {
    const current = state(service);
    if (current.state === CREDENTIAL_CACHE_STATES.UNAVAILABLE) {
      throw new Error(`credential_cache_authority_unavailable:${service}`);
    }
    if (current.state !== CREDENTIAL_CACHE_STATES.READY) return null;
    const entry = current.entry;
    return Object.freeze({ serviceName: service, value: entry.value, credentialHash: entry.hash,
      slotId: entry.slot, effectiveProvenanceId: entry.lifecycle.provenanceId,
      effectiveMutationHash: entry.lifecycle.mutationHash });
  }

  function inspect() {
    const values = {};
    for (const [service, current] of snapshot.entries()) {
      values[service] = Object.freeze({ state: current.state,
        present: current.state === CREDENTIAL_CACHE_STATES.READY,
        ...(current.state === CREDENTIAL_CACHE_STATES.READY
          ? { hash: `${current.entry.hash.slice(0, 12)}...` } : {}) });
    }
    return Object.freeze({ loaded, generation, services: Object.freeze(values) });
  }

  return Object.freeze({ load, reload, refresh, checkout, state, inspect,
    isLoaded: () => loaded,
    get: (service) => {
      if (!loaded) return null;
      const current = snapshot.get(service);
      return current?.state === CREDENTIAL_CACHE_STATES.READY ? current.entry.value : null;
    },
    getHash: (service) => {
      if (!loaded) return null;
      const current = snapshot.get(service);
      return current?.state === CREDENTIAL_CACHE_STATES.READY ? current.entry.hash : null;
    },
    peek: (service) => loaded && snapshot.get(service)?.state === CREDENTIAL_CACHE_STATES.READY,
  });
}

const credentialCache = createCredentialCacheOwner();

export function isCredentialCacheLoaded() { return credentialCache.isLoaded(); }
export async function loadCredentialCache() { return credentialCache.load(); }
export async function reloadCredentialCache() { return credentialCache.reload(); }
export function getCachedCredential(service) { return credentialCache.get(service); }
export function getCachedCredentialHash(service) { return credentialCache.getHash(service); }
export function checkoutCachedCredential(service) { return credentialCache.checkout(service); }
export function peekCachedCredential(service) { return credentialCache.peek(service); }
export async function refreshCachedCredential(service) { return credentialCache.refresh(service); }
export function getCredentialCacheState(service) { return credentialCache.state(service).state; }
export function _peekCredentialCache() { return credentialCache.inspect(); }
