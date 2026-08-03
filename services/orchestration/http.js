// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: LEAF UTILITY (80+ consumers, calls nothing)
// Exposed via: services/orchestration/http.js (direct imports across all domains)
// Available for: Timeout-aware HTTP fetch wrapper used throughout the codebase
// ─────────────────────────────────────────────────────────────────────────────
const DEFAULT_TIMEOUT_MS = 12_000;
// H3 bound: a single overall request deadline. Note: this is NOT a distinct
// connect (5s) + request (30s) split — the WHATWG fetch/AbortController surface
// exposes only one deadline for the whole request. A separate connect timeout
// requires a socket/agent-level change (custom http.Agent with a connect
// listener), which is out of scope for this pass. Documented, not faked.
const REQUEST_DEADLINE_MS = 30_000;
const MAX_RETRIES = 2; // 3 total attempts
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']);
export const FSM_STREAMING_SOURCE = 'Boosting AI Reliability with an FSM-Driven Streaming Inference Pipeline';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchOnce(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === 'AbortError') {
      const timeoutErr = new Error(`Request timed out after ${timeoutMs}ms`);
      timeoutErr.name = 'RequestTimeoutError';
      throw timeoutErr;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// H3: one overall request deadline (default 30s) + 2 retries with 200ms→500ms
// backoff. Retries apply ONLY to idempotent HTTP methods (a retried POST could
// double-submit). Callers may force retry with { retry: true } or disable it
// with { retry: false }.
export async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_DEADLINE_MS) {
  const method = String(options.method || 'GET').toUpperCase();
  const retryDefault = IDEMPOTENT_METHODS.has(method);
  const retryAllowed = options.retry === undefined ? retryDefault : Boolean(options.retry);
  const { retry: _retry, ...fetchOptions } = options;
  const backoffs = [200, 500];
  let lastError = null;

  const maxAttempts = retryAllowed ? MAX_RETRIES + 1 : 1;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fetchOnce(url, fetchOptions, timeoutMs);
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts - 1) {
        await sleep(backoffs[Math.min(attempt, backoffs.length - 1)]);
        continue;
      }
      throw error;
    }
  }
  throw lastError;
}

export function buildHttpRuntimeDiagnostics({
  url = '',
  method = 'GET',
  timeoutMs = DEFAULT_TIMEOUT_MS,
  elapsedMs = 0,
  status = null,
  error = null,
  stream = false,
} = {}) {
  const timedOut = String(error?.name || error || '').toLowerCase().includes('abort')
    || Number(elapsedMs || 0) > Number(timeoutMs || DEFAULT_TIMEOUT_MS);
  return {
    status: timedOut || error ? 'failed_safe' : 'observed',
    source_paper: FSM_STREAMING_SOURCE,
    diagnostic_only: true,
    request: {
      method: String(method || 'GET').toUpperCase(),
      url_host: (() => {
        try { return new URL(String(url || 'http://invalid.local')).host; } catch { return null; }
      })(),
      timeout_ms: Number(timeoutMs || DEFAULT_TIMEOUT_MS),
      elapsed_ms: Math.max(0, Number(elapsedMs || 0)),
      http_status: status == null ? null : Number(status),
      stream: Boolean(stream),
    },
    recovery: {
      typed_error: error ? String(error?.message || error).slice(0, 240) : null,
      timed_out: timedOut,
      retry_allowed_by_caller: true,
    },
    guardrails: {
      raw_protocol_user_visible: false,
      credentials_logged: false,
      request_mutated: false,
    },
  };
}
