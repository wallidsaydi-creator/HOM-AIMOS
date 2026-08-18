/** Authority-free R9 compact scale projection and work accounting. */

import { createHash } from 'node:crypto';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

export const R9_SCALE_CONTRACT = Object.freeze({
  schema: 'hom.aimos.content-state-occurrence-r9-scale/v1',
  request_cap: 200,
  graph_state_cap: 256,
  mutation_batch_cap: 500,
  persistent_projection_authority: false,
  canonical_fallback_required: true,
});

const DOMAIN = Buffer.from('hom.aimos.r9-compact-state-stream/v1\0', 'utf8');
const HEX32 = /^[0-9a-f]{64}$/;

function fail(code) { throw new Error(`r9_scale:${code}`); }
function frame(bytes) {
  const value = Buffer.from(bytes);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(value.length);
  return Buffer.concat([size, value]);
}

export function summarizeSortedStateStream(records) {
  if (!records || typeof records[Symbol.iterator] !== 'function') fail('records_required');
  const hash = createHash('sha256').update(DOMAIN);
  let previousState = null;
  let previousPrincipal = null;
  let state = null;
  let inputCount = 0;
  let stateCount = 0;
  let eligibleStateCount = 0;
  let blockedStateCount = 0;
  let maxOccurrencesPerState = 0;
  let principalStateCount = 0;
  let membershipOperations = 0;
  let peakHeapBytes = process.memoryUsage().heapUsed;
  const flush = () => {
    if (!state) return;
    stateCount += 1;
    if (state.eligible_count > 0 && state.content_blocked === false) eligibleStateCount += 1;
    else blockedStateCount += 1;
    maxOccurrencesPerState = Math.max(maxOccurrencesPerState, state.occurrence_count);
    hash.update(frame(Buffer.from(canonicalJson(state), 'utf8')));
  };
  for (const raw of records) {
    const stateHash = String(raw?.live_content_hash || '').toLowerCase();
    const principal = String(raw?.principal_id || '');
    const occurrenceRef = String(raw?.occurrence_ref || '').toLowerCase();
    if (!HEX32.test(stateHash) || !principal || !HEX32.test(occurrenceRef)
        || typeof raw.occurrence_eligible !== 'boolean'
        || typeof raw.content_eligible !== 'boolean') {
      fail('record_invalid');
    }
    if (previousState != null && (stateHash < previousState
        || (stateHash === previousState && principal < previousPrincipal))) {
      fail('stream_not_sorted');
    }
    if (stateHash !== previousState) {
      flush();
      state = {
        live_content_hash: stateHash,
        occurrence_count: 0,
        eligible_count: 0,
        content_blocked: false,
        principal_state_count: 0,
      };
      previousPrincipal = null;
    }
    if (principal !== previousPrincipal) {
      state.principal_state_count += 1;
      principalStateCount += 1;
      previousPrincipal = principal;
    }
    state.occurrence_count += 1;
    if (raw.occurrence_eligible) state.eligible_count += 1;
    if (!raw.content_eligible) state.content_blocked = true;
    inputCount += 1;
    membershipOperations += 1;
    previousState = stateHash;
    if ((inputCount & 0x3fff) === 0) {
      peakHeapBytes = Math.max(peakHeapBytes, process.memoryUsage().heapUsed);
    }
  }
  flush();
  peakHeapBytes = Math.max(peakHeapBytes, process.memoryUsage().heapUsed);
  return Object.freeze({
    schema: R9_SCALE_CONTRACT.schema,
    input_occurrence_count: inputCount,
    unique_state_count: stateCount,
    principal_state_count: principalStateCount,
    eligible_state_count: eligibleStateCount,
    blocked_state_count: blockedStateCount,
    collapsed_occurrence_count: inputCount - stateCount,
    max_occurrences_per_state: maxOccurrencesPerState,
    membership_operations: membershipOperations,
    state_stream_root_sha256: hash.digest('hex'),
    peak_heap_bytes: peakHeapBytes,
  });
}

export function* syntheticSortedOccurrences({ count, scenario = 'all_unique' } = {}) {
  const n = Number(count);
  if (!Number.isSafeInteger(n) || n < 1 || n > 1_000_000) fail('count_invalid');
  for (let index = 0; index < n; index += 1) {
    const stateOrdinal = scenario === 'maximum_duplicate'
      ? 0
      : scenario === 'multi_principal'
        ? Math.floor(index / 4)
      : scenario === 'mixed_poison'
        ? Math.floor(index / 4)
        : index;
    const stateHash = stateOrdinal.toString(16).padStart(64, '0');
    const poisonClass = scenario === 'mixed_poison' && stateOrdinal % 10 === 0;
    const occurrenceBlocked = scenario === 'mixed_poison' && !poisonClass && index % 13 === 0;
    yield {
      live_content_hash: stateHash,
      principal_id: scenario === 'multi_principal' ? `agent-${index % 4}` : 'agent-scale',
      occurrence_ref: (index + 1).toString(16).padStart(64, '0'),
      occurrence_eligible: !occurrenceBlocked,
      content_eligible: !poisonClass,
    };
  }
}

export function resolveGeometricWindowExhaustion({
  cleanUniqueByWindow = [],
  requestedK,
  candidateCap,
  indexExhausted = false,
} = {}) {
  const k = Number(requestedK);
  const cap = Number(candidateCap);
  if (!Array.isArray(cleanUniqueByWindow) || !Number.isSafeInteger(k) || k < 1
      || !Number.isSafeInteger(cap) || cap < 1) fail('window_input_invalid');
  let previous = -1;
  let windows = 0;
  for (const entry of cleanUniqueByWindow) {
    const opened = Number(entry.opened);
    const clean = Number(entry.clean_unique);
    if (!Number.isSafeInteger(opened) || opened < 1 || opened > cap
        || opened <= previous || !Number.isSafeInteger(clean) || clean < 0 || clean > opened) {
      fail('window_progression_invalid');
    }
    previous = opened;
    windows += 1;
    if (clean >= k) return Object.freeze({ status: 'satisfied', windows, opened, clean_unique: clean });
  }
  return Object.freeze({
    status: indexExhausted ? 'exhausted_unique' : 'bounded_window_exhausted',
    windows,
    opened: Math.max(0, previous),
    clean_unique: cleanUniqueByWindow.at(-1)?.clean_unique || 0,
  });
}

export function latencySummary(samples = []) {
  if (!Array.isArray(samples) || samples.length < 1
      || samples.some((value) => !Number.isFinite(value) || value < 0)) fail('latency_samples_invalid');
  const sorted = [...samples].sort((a, b) => a - b);
  const at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  return Object.freeze({
    n: sorted.length,
    p50_ms: at(0.50),
    p95_ms: at(0.95),
    p99_ms: at(0.99),
    max_ms: sorted.at(-1),
  });
}

export function resolveOptionalProjectionUse({
  expectedSourceRoot,
  observedSourceRoot,
  canonicalFallbackBounded = false,
} = {}) {
  const expected = String(expectedSourceRoot || '').toLowerCase();
  const observed = String(observedSourceRoot || '').toLowerCase();
  if (!HEX32.test(expected) || !HEX32.test(observed)) fail('projection_root_invalid');
  if (expected === observed) {
    return Object.freeze({ mode: 'verified_projection', projection_authority: false });
  }
  if (canonicalFallbackBounded === true) {
    return Object.freeze({
      mode: 'bounded_canonical_fallback',
      reason: 'projection_source_root_invalid',
      projection_authority: false,
    });
  }
  fail('projection_source_root_invalid');
}
