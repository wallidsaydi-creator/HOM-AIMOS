// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// Status: native outbound HTTP deadline owner
// Exposed via: services/orchestration/http.js (direct imports across all domains)
// Returns the native Response; its abort signal remains live through the body.
// ─────────────────────────────────────────────────────────────────────────────
import { performance } from 'node:perf_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import dns from 'node:dns';
import net from 'node:net';
import ipaddr from 'ipaddr.js';
import { Agent } from 'undici';
import { getServingAbortSignal } from '../runtime/serving-control.js';
const DEFAULT_TIMEOUT_MS = 12_000;
const REQUEST_DEADLINE_MS = 30_000;
const MAX_RETRIES = 2; // 3 total attempts
const SAFE_RETRY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
export const FSM_STREAMING_SOURCE = 'Boosting AI Reliability with an FSM-Driven Streaming Inference Pipeline';

// AbortSignal.reason can be immutable or not be an Error at all. Classification
// must never prevent a signed terminal. Preserve mutable errors; otherwise use
// a native Error with the original reason as its cause, not a transport wrapper.
export function markHttpIndeterminate(reason) {
  try {
    if (reason && (typeof reason === 'object' || typeof reason === 'function')
        && Reflect.defineProperty(reason, 'httpOutcome', {
          value: 'INDETERMINATE', configurable: true, writable: true, enumerable: true,
        })) return reason;
  } catch { /* An immutable/custom reason still needs a terminal disposition. */ }
  let message = 'External operation completion is indeterminate', name = 'Error', code;
  try {
    if (typeof reason?.message === 'string') message = reason.message;
    if (typeof reason?.name === 'string') name = reason.name;
    if (typeof reason?.code === 'string') code = reason.code;
  } catch { /* Keep the original reason only as cause when accessors reject. */ }
  const error = new Error(message, { cause: reason });
  error.name = name;
  if (code !== undefined) error.code = code;
  error.httpOutcome = 'INDETERMINATE';
  return error;
}

function destinationError(code = 'http_destination_forbidden') {
  const error = new Error(code);
  error.statusCode = 400;
  error.noRetry = true;
  return error;
}

export function isPublicHttpAddress(address) {
  if (typeof address !== 'string' || address.includes('%') || !net.isIP(address)) return false;
  let parsed = ipaddr.parse(address);
  if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) parsed = parsed.toIPv4Address();
  // ipaddr's binary special-use ranges include private, link-local, metadata,
  // documentation, multicast, translation/tunnel and reserved addresses.
  if (parsed.range() !== 'unicast') return false;
  return parsed.kind() === 'ipv4' || parsed.match(ipaddr.parseCIDR('2000::/3'));
}

export function assertPublicHttpUrl(raw) {
  let parsed;
  try { parsed = new URL(raw); } catch { throw destinationError('http_destination_url_invalid'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw destinationError();
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const name = hostname.replace(/\.$/, '');
  if (!name || name === 'localhost' || name.endsWith('.localhost')
      || name.endsWith('.local') || !name.includes('.') && !net.isIP(name)
      || net.isIP(hostname) && !isPublicHttpAddress(hostname)) throw destinationError();
  return parsed;
}

// This IS the socket's lookup, not a preflight followed by another resolver.
// Validate the complete DNS answer before returning the one address that
// net/tls.connect will dial. TLS keeps the original hostname/SNI and CA checks.
export function publicHttpLookup(hostname, options, callback) {
  dns.lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
    if (error) return callback(error);
    if (!addresses?.length || addresses.some(({ address, family }) =>
      !isPublicHttpAddress(address) || net.isIP(address) !== family)) return callback(destinationError());
    const candidates = options.family ? addresses.filter(item => item.family === options.family) : addresses;
    if (!candidates.length) return callback(destinationError());
    const selected = candidates[0];
    if (options.all) callback(null, [selected]);
    else callback(null, selected.address, selected.family);
  });
}

// Native Node fetch dispatcher only; no replacement Response, stream, proxy
// or environment-selected transport. Its existing pool owns idle sockets.
const publicHttpAgent = new Agent({
  connect: { lookup: publicHttpLookup, rejectUnauthorized: true },
  autoSelectFamily: false,
});

// One monotonic operation budget includes dispatch, backoff and body/stream
// consumption. AbortSignal.timeout/any are native Node lifetime primitives:
// no Response proxy, replacement stream, detached timer or listener hook.
// Consumers retain their native body readers and cancel/release them in finally.
// Consequential methods require an operation-specific replay owner; this owner
// never grants blanket retry authority merely because retry:true was supplied.
export async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_DEADLINE_MS) {
  const method = String(options.method || 'GET').toUpperCase();
  const { retry, signal: callerSignal, deadlineAt, destinationPolicy, ...fetchOptions } = options;
  if (destinationPolicy !== undefined && destinationPolicy !== 'public') throw destinationError('http_destination_policy_invalid');
  if (destinationPolicy === 'public') {
    url = assertPublicHttpUrl(url);
    const headers = new Headers(fetchOptions.headers);
    if (fetchOptions.dispatcher !== undefined || fetchOptions.redirect !== undefined && fetchOptions.redirect !== 'error'
        || ['host', 'connection', 'proxy-authorization', 'proxy-connection', 'upgrade'].some(name => headers.has(name))) {
      throw destinationError('http_destination_policy_override');
    }
    fetchOptions.headers = headers;
    fetchOptions.dispatcher = publicHttpAgent;
    // Never dispatch to a Location, and never replay/forward credentials to it.
    fetchOptions.redirect = 'manual';
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > 2_147_483_647
      || (deadlineAt !== undefined && !Number.isFinite(deadlineAt))) throw new Error('http_deadline_invalid');
  if (retry !== undefined && typeof retry !== 'boolean') throw new Error('http_retry_policy_invalid');
  if (retry === true && !SAFE_RETRY_METHODS.has(method)) throw new Error('http_retry_not_authorized');
  callerSignal?.throwIfAborted();
  const start = performance.now();
  const deadline = Math.min(start + timeoutMs, deadlineAt ?? Infinity);
  const remaining = Math.ceil(deadline - performance.now());
  if (remaining <= 0) throw new DOMException('HTTP operation deadline exceeded', 'TimeoutError');
  const deadlineSignal = AbortSignal.timeout(remaining);
  const signal = AbortSignal.any([getServingAbortSignal(), deadlineSignal, ...(callerSignal ? [callerSignal] : [])]);
  signal.throwIfAborted();
  const retryAllowed = SAFE_RETRY_METHODS.has(method) && retry !== false;
  const backoffs = [200, 500];
  let lastError = null;

  const maxAttempts = retryAllowed ? MAX_RETRIES + 1 : 1;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      signal.throwIfAborted();
      const response = await fetch(url, { ...fetchOptions, signal });
      if (destinationPolicy === 'public' && [301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel();
        throw destinationError('http_destination_redirect_forbidden');
      }
      return response;
    } catch (error) {
      if (signal.aborted) throw SAFE_RETRY_METHODS.has(method) ? signal.reason : markHttpIndeterminate(signal.reason);
      if (!SAFE_RETRY_METHODS.has(method)) error = markHttpIndeterminate(error);
      lastError = error;
      if (attempt < maxAttempts - 1 && error?.noRetry !== true && error?.cause?.noRetry !== true) {
        try { await sleep(backoffs[attempt], undefined, { signal }); }
        catch (waitError) { throw signal.aborted ? signal.reason : waitError; }
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
  const timedOut = /timeout|abort/i.test(String(error?.name || error || ''))
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
      retry_allowed_by_caller: SAFE_RETRY_METHODS.has(String(method).toUpperCase()),
    },
    guardrails: {
      raw_protocol_user_visible: false,
      credentials_logged: false,
      request_mutated: false,
    },
  };
}
