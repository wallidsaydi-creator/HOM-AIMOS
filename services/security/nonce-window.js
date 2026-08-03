// services/security/nonce-window.js
// Status: Wired (Phase 2.2) — consumed by auth-tier.deriveTier.nonceStore; SECURITY_ENFORCE_NONCE is shadow-first (default OFF = log-only, flag ON = enforce) with { failClosedValue: true } per BUG-02. Belt-and-braces twin: single-process LRU sliding window (this file) + durable cross-process backstop via migration 016 aimos_save_envelope_nonce_unique (caught and translated to replay_detected by save-envelope.js BUG-03 catch-mapping). Defaults: 100k entries, 600s TTL.
// Defaults: 100k entries, 600s TTL. Map insertion order = LRU tracking.
// Key format: `${agentId}:${nonce}`.
// Exports: createNonceWindow (factory), nonceWindow (default instance),
// clearNonceWindow (test-only hook that flushes the default window).

export function createNonceWindow({ capacity = 100000, windowTtlSecs = 600, nowFn = Date.now } = {}) {
  const store = new Map();
  const ttlMs = Math.max(1, Number(windowTtlSecs) * 1000);

  function nowMs() {
    const value = Number(nowFn());
    return Number.isFinite(value) ? value : Date.now();
  }

  function pruneExpired(now) {
    for (const [key, recordedAt] of store) {
      if ((now - recordedAt) < ttlMs) break;
      store.delete(key);
    }
  }

  return {
    seenAndRecord(agentId, nonce) {
      const key = `${agentId}:${nonce}`;
      const now = nowMs();
      pruneExpired(now);
      if (store.has(key)) {
        return true; // replay detected
      }
      store.set(key, now);
      // LRU eviction: Map iterates in insertion order; first key is the oldest.
      if (store.size > capacity) {
        const firstKey = store.keys().next().value;
        store.delete(firstKey);
      }
      return false; // newly recorded
    },
    has(agentId, nonce) {
      pruneExpired(nowMs());
      return store.has(`${agentId}:${nonce}`);
    },
    size() {
      return store.size;
    },
    clear() {
      store.clear();
    },
  };
}

export const nonceWindow = createNonceWindow();

/**
 * Test-only hook: explicit, intent-revealing entrypoint that flushes the
 * nonce LRU for cross-test-boundary resets (e.g. warm-restart cross-process
 * tests where a spawned process must start with an empty window).
 *
 * Production code continues to use nonceWindow.clear() directly. Tests and
 * harnesses should prefer this named hook for grep-ability + audit intent.
 *
 * @test-only
 */
export function clearNonceWindow() {
  nonceWindow.clear();
}
