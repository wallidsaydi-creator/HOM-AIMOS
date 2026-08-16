#!/usr/bin/env node

/**
 * Native canonical benchmark replay.
 *
 * This process opens only an answer-free `hom.canonical-benchmark-sessions/v1`
 * artifact. Each turn crosses the signed production session route, and the
 * housekeeper finalizes each retained source session through the same route.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { signAsHousekeeper } from '../services/security/housekeeper-signer.js';
import { canonicalJson } from '../services/security/agent-identity.js';
import { sessionKeyPrefix } from '../services/shared/session-scope.js';
import { assessQuality } from '../services/write/quality-gate.js';
import { redactAimosValue } from '../services/write/persist-memory.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS_DIR = path.join(ROOT, 'data', 'canonical');
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const PROTECTED_PORTS = new Set([9000, 9001, 9100]);
const SESSION_IMAGE_TEXT_LIMIT_BYTES = 8192;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function orderedTurnIdHashesSha256(turns) {
  return sha256(JSON.stringify(turns.map((turn) => sha256(Buffer.from(turn.turn_id, 'utf8')))));
}

export function normalizeReplayImageContext(value) {
  if (!Array.isArray(value) || !value.length) return { imageContext: [], payloadRefs: [] };
  const payloadRefs = [];
  const imageContext = value.map((entry, index) => {
    const url = entry?.url == null ? null : String(entry.url).trim();
    if (!url || Buffer.byteLength(url, 'utf8') <= SESSION_IMAGE_TEXT_LIMIT_BYTES) return entry;
    const match = url.match(/^data:([^;,]+);base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!match) throw new Error(`replay_image_url_too_large:${index}`);
    const payload = Buffer.from(match[2], 'base64');
    if (!payload.length) throw new Error(`replay_image_data_invalid:${index}`);
    const payloadSha256 = sha256(payload);
    const transportUrl = `urn:sha256:${payloadSha256}`;
    payloadRefs.push({
      image_context_index: index,
      source_url_sha256: sha256(Buffer.from(url, 'utf8')),
      source_url_bytes: Buffer.byteLength(url, 'utf8'),
      media_type: match[1].toLowerCase(),
      payload_sha256: payloadSha256,
      payload_bytes: payload.length,
      transport_url: transportUrl,
    });
    return { ...entry, url: transportUrl };
  });
  return { imageContext, payloadRefs };
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function cliValues(argv, name) {
  const values = [];
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === name && argv[index + 1]) values.push(argv[index + 1]);
    else if (argv[index].startsWith(`${name}=`)) values.push(argv[index].slice(name.length + 1));
  }
  return values;
}

function cliValue(argv, name) {
  return cliValues(argv, name).at(-1) || null;
}

function cliFlag(argv, name) {
  return argv.slice(2).includes(name);
}

export function validateReplayOrigin(value) {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new Error('replay_origin_invalid');
  }
  if (parsed.protocol !== 'http:'
    || parsed.hostname !== '127.0.0.1'
    || parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash) {
    throw new Error('replay_origin_must_be_loopback_http_origin');
  }
  const port = Number(parsed.port || 80);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('replay_origin_port_invalid');
  if (PROTECTED_PORTS.has(port)) throw new Error(`replay_origin_protected_port:${port}`);
  return parsed.origin;
}

function parsePositiveInteger(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name}_invalid`);
  return number;
}

function parseArgs(argv) {
  const benchmark = String(cliValue(argv, '--benchmark') || '').trim().toLowerCase();
  if (!['locomo', 'longmemeval'].includes(benchmark)) throw new Error('benchmark_must_be_locomo_or_longmemeval');
  const sessionsFile = path.resolve(cliValue(argv, '--sessions-file')
    || path.join(DEFAULT_CORPUS_DIR, `${benchmark}-sessions.json`));
  const runDirRaw = cliValue(argv, '--run-dir');
  if (!runDirRaw) throw new Error('run_dir_required');
  const runId = String(cliValue(argv, '--run-id') || '').trim();
  if (!/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(runId)) throw new Error('run_id_invalid');
  const databaseName = String(cliValue(argv, '--aimos-db') || '').trim();
  if (databaseName !== `aimos_benchmark_${runId}`) {
    throw new Error('benchmark_database_must_match_run_id');
  }
  const scopeIds = cliValues(argv, '--scope-id');
  const selectionFile = cliValue(argv, '--selection-file');
  const all = cliFlag(argv, '--all');
  const scopeLimitRaw = cliValue(argv, '--scope-limit');
  if (!all && !scopeIds.length && scopeLimitRaw == null && !selectionFile) {
    throw new Error('explicit_scope_selection_required');
  }
  if (all && (scopeIds.length || scopeLimitRaw != null || selectionFile)) throw new Error('all_conflicts_with_scope_selection');
  if (scopeIds.length && scopeLimitRaw != null) throw new Error('scope_ids_conflict_with_scope_limit');
  if (selectionFile && (scopeIds.length || scopeLimitRaw != null)) throw new Error('selection_file_conflicts_with_scope_selection');
  return {
    benchmark,
    sessionsFile,
    runDir: path.resolve(runDirRaw),
    runId,
    databaseName,
    origin: validateReplayOrigin(cliValue(argv, '--aimos-base') || 'http://127.0.0.1:9200'),
    scopeIds,
    selectionFile: selectionFile ? path.resolve(selectionFile) : null,
    all,
    scopeOffset: parsePositiveInteger(cliValue(argv, '--scope-offset') || 0, 'scope_offset'),
    scopeLimit: scopeLimitRaw == null ? null : parsePositiveInteger(scopeLimitRaw, 'scope_limit', { min: 1 }),
    delayMs: parsePositiveInteger(cliValue(argv, '--delay-ms') || 2100, 'delay_ms', { max: 60_000 }),
    retries: parsePositiveInteger(cliValue(argv, '--retries') || 3, 'retries', { min: 1, max: 10 }),
    requestTimeoutMs: parsePositiveInteger(
      cliValue(argv, '--request-timeout-ms') || 120_000,
      'request_timeout_ms',
      { min: 1_000, max: 600_000 },
    ),
    dryRun: cliFlag(argv, '--dry-run'),
  };
}

function scopeIdsFromSelection(file, benchmark, runId) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) throw new Error('query_selection_invalid');
  const selection = JSON.parse(fs.readFileSync(file, 'utf8'));
  const unsigned = { ...selection };
  delete unsigned.selection_sha256;
  const canonicalSelection = selection?.schema === 'hom.canonical-query-selection/v1';
  const twinPrimeDiagnosticSelection = selection?.schema === 'hom.twin-prime-g1p-selection/v1';
  if ((!canonicalSelection && !twinPrimeDiagnosticSelection)
    || selection.run_id !== runId
    || selection.benchmark !== benchmark
    || selection.question_count !== selection.entries?.length
    || selection.selection_sha256 !== sha256(JSON.stringify(unsigned))) {
    throw new Error('query_selection_invalid');
  }
  const allowedEntryKeys = canonicalSelection
    ? new Set(['question_id', 'unit_id', 'scope_id', 'source_filter', 'input_sha256', 'gold_sha256'])
    : new Set(['question_id', 'unit_id', 'scope_id', 'source_filter', 'input_sha256', 'category']);
  for (const entry of selection.entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((key) => !allowedEntryKeys.has(key))
      || !String(entry.scope_id || '').trim()) {
      throw new Error('query_selection_entry_invalid');
    }
  }
  return [...new Set(selection.entries.map((entry) => entry.scope_id))];
}

function loadReplayArtifact(file, benchmark) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) throw new Error('replay_artifact_invalid');
  const bytes = fs.readFileSync(file);
  const artifact = JSON.parse(bytes);
  if (artifact?.schema !== 'hom.canonical-benchmark-sessions/v1'
    || artifact.benchmark !== benchmark
    || !Array.isArray(artifact.scopes)) {
    throw new Error('replay_artifact_schema_invalid');
  }
  const manifestFile = path.join(path.dirname(file), 'corpus-manifest.json');
  if (!fs.existsSync(manifestFile) || fs.lstatSync(manifestFile).isSymbolicLink()) {
    throw new Error('corpus_manifest_missing');
  }
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const fileName = path.basename(file);
  if (!manifest?.answer_key_boundary?.replay_inputs?.includes(fileName)) {
    throw new Error('artifact_not_authorized_for_replay');
  }
  const attestation = manifest.outputs?.find((entry) => entry.file === fileName);
  const digest = sha256(bytes);
  if (!attestation || attestation.sha256 !== digest || attestation.bytes !== bytes.length) {
    throw new Error('replay_artifact_hash_mismatch');
  }
  return { artifact, digest, manifestFile };
}

export function selectReplayScopes(scopes, {
  all = false,
  scopeIds = [],
  scopeOffset = 0,
  scopeLimit = null,
} = {}) {
  if (!Array.isArray(scopes)) throw new Error('replay_scopes_invalid');
  const byId = new Map(scopes.map((scope) => [scope.scope_id, scope]));
  if (byId.size !== scopes.length) throw new Error('replay_scope_id_duplicate');
  if (all) return [...scopes];
  if (scopeIds.length) {
    const unique = [...new Set(scopeIds)];
    if (unique.length !== scopeIds.length) throw new Error('replay_scope_selection_duplicate');
    return unique.map((scopeId) => {
      const scope = byId.get(scopeId);
      if (!scope) throw new Error(`replay_scope_missing:${scopeId}`);
      return scope;
    });
  }
  return scopes.slice(scopeOffset, scopeOffset + scopeLimit);
}

const REPLAY_SCOPE_KEYS = new Set(['scope_id', 'source_filter', 'sessions']);
const REPLAY_SESSION_KEYS = new Set(['session_id', 'source_session_id', 'source_date', 'turns']);
const REPLAY_TURN_KEYS = new Set([
  'turn_id',
  'role',
  'speaker',
  'content',
  'observed_at',
  'source_ref',
  'image_context',
]);
const REPLAY_IMAGE_KEYS = new Set(['url', 'caption', 'query']);

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

function validateScope(scope, context) {
  if (!scope || typeof scope !== 'object'
    || Array.isArray(scope)
    || !hasOnlyKeys(scope, REPLAY_SCOPE_KEYS)
    || !String(scope.scope_id || '').trim()
    || !String(scope.source_filter || '').trim()
    || scope.source_filter !== `benchmark:${scope.scope_id}`
    || !Array.isArray(scope.sessions)
    || !scope.sessions.length) {
    throw new Error('replay_scope_invalid');
  }
  for (const session of scope.sessions) {
    if (!session || typeof session !== 'object'
      || Array.isArray(session)
      || !hasOnlyKeys(session, REPLAY_SESSION_KEYS)
      || !String(session.session_id || '').trim()
      || !String(session.source_session_id || '').trim()
      || !Array.isArray(session.turns)
      || !session.turns.length) {
      throw new Error(`replay_session_invalid:${scope.scope_id}`);
    }
    if (context.sessionIds.has(session.session_id)) {
      throw new Error(`replay_session_id_duplicate:${session.session_id}`);
    }
    context.sessionIds.add(session.session_id);
    let priorObservedAt = -Infinity;
    for (let turnIndex = 0; turnIndex < session.turns.length; turnIndex += 1) {
      const turn = session.turns[turnIndex];
      if (!turn || typeof turn !== 'object'
        || Array.isArray(turn)
        || !hasOnlyKeys(turn, REPLAY_TURN_KEYS)
        || !String(turn.turn_id || '').trim()
        || !['user', 'assistant'].includes(turn.role)
        || !String(turn.content || '').trim()
        || !String(turn.observed_at || '').trim()) {
        throw new Error(`replay_turn_invalid:${session.session_id}`);
      }
      if (context.turnIds.has(turn.turn_id)) {
        throw new Error(`replay_turn_id_duplicate:${turn.turn_id}`);
      }
      context.turnIds.add(turn.turn_id);
      const observedAt = new Date(turn.observed_at);
      if (Number.isNaN(observedAt.getTime()) || observedAt.toISOString() !== turn.observed_at) {
        throw new Error(`replay_turn_observed_at_invalid:${turn.turn_id}`);
      }
      if (observedAt.getTime() < priorObservedAt) {
        throw new Error(`replay_turn_time_order_invalid:${session.session_id}`);
      }
      priorObservedAt = observedAt.getTime();
      if (turn.source_ref != null && (typeof turn.source_ref !== 'string'
        || turn.source_ref.trim() !== turn.source_ref
        || /[\x00-\x1F\x7F]/u.test(turn.source_ref)
        || Buffer.byteLength(turn.source_ref, 'utf8') > 4096)) {
        throw new Error(`replay_turn_source_ref_invalid:${turn.turn_id}`);
      }
      if (turn.speaker != null && (typeof turn.speaker !== 'string'
        || turn.speaker.trim() !== turn.speaker
        || /[\x00-\x1F\x7F]/u.test(turn.speaker)
        || Buffer.byteLength(turn.speaker, 'utf8') > 512)) {
        throw new Error(`replay_turn_speaker_invalid:${turn.turn_id}`);
      }
      const images = normalizeReplayImageContext(turn.image_context).imageContext;
      if (images.length > 16) throw new Error(`replay_turn_image_context_invalid:${turn.turn_id}`);
      for (const image of images) {
        if (!image || typeof image !== 'object' || Array.isArray(image)
          || !hasOnlyKeys(image, REPLAY_IMAGE_KEYS)
          || !Object.values(image).some((value) => typeof value === 'string' && value.trim())
          || Object.values(image).some((value) => value != null && (
            typeof value !== 'string'
            || value.trim() !== value
            || /[\x00-\x1F\x7F]/u.test(value)
            || Buffer.byteLength(value, 'utf8') > SESSION_IMAGE_TEXT_LIMIT_BYTES
          ))) {
          throw new Error(`replay_turn_image_context_invalid:${turn.turn_id}`);
        }
      }
      const turnIdHash = sha256(Buffer.from(turn.turn_id, 'utf8'));
      const sequence = turnIndex + 1;
      const record = {
        schema: 'aimos.session-turn/v1',
        session_id: session.session_id,
        sequence,
        turn_id_sha256: turnIdHash,
        role: turn.role,
        observed_at: turn.observed_at,
        source_ref: turn.source_ref ?? null,
        content: turn.content,
        ...(turn.speaker ? { speaker: turn.speaker } : {}),
        ...(images.length ? { image_context: images } : {}),
      };
      const key = `${sessionKeyPrefix(session.session_id)}turn:${String(sequence).padStart(12, '0')}:${turnIdHash}`;
      const persistedValue = canonicalJson(record);
      if (redactAimosValue(persistedValue) !== persistedValue) {
        throw new Error(`replay_turn_requires_credential_lane:${turn.turn_id}`);
      }
      const quality = assessQuality(key, persistedValue, 'conversation_feed', {
        agent_id: 'housekeeper',
        source: scope.source_filter,
        scope: 'global',
        clearance_level: 10,
      });
      if (!quality.pass) {
        throw new Error(`replay_turn_quality_gate_reject:${turn.turn_id}:${quality.reason}`);
      }
    }
  }
}

export function validateReplayScopes(scopes) {
  if (!Array.isArray(scopes) || !scopes.length) throw new Error('replay_scopes_invalid');
  const context = { sessionIds: new Set(), turnIds: new Set() };
  for (const scope of scopes) validateScope(scope, context);
  return {
    scopes: scopes.length,
    sessions: context.sessionIds.size,
    turns: context.turnIds.size,
  };
}

function requestEvidence(signed) {
  return {
    body_sha256: sha256(JSON.stringify(signed.body)),
    certificate_sha256: sha256(signed.certString),
    signature_b64u: signed.sigB64u,
    nonce: signed.nonce,
    signed_timestamp: signed.signedTs,
    signature_form: signed.sigForm,
  };
}

async function signedPost(origin, route, body, options = {}) {
  const attempts = [];
  const retries = options.retries || 3;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    const signed = await (options.signer || signAsHousekeeper)(body, { method: 'POST', path: route });
    const started = performance.now();
    let status = 0;
    let responseBody = {};
    let transportError = null;
    try {
      const response = await (options.fetchFn || fetch)(`${origin}${route}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Aimos-Agent-Cert': signed.certString,
          'Aimos-Agent-Signature': signed.sigB64u,
          'Aimos-Agent-Nonce': signed.nonce,
          'Aimos-Agent-Timestamp': String(signed.signedTs),
          'X-Aimos-Sig-Form': String(signed.sigForm),
        },
        body: JSON.stringify(signed.body),
        signal: AbortSignal.timeout(options.requestTimeoutMs || 120_000),
      });
      status = response.status;
      responseBody = await response.json().catch(() => ({}));
    } catch (error) {
      transportError = error?.message || String(error);
    }
    const evidence = {
      attempt,
      request: requestEvidence(signed),
      status,
      latency_ms: Math.round((performance.now() - started) * 100) / 100,
      response: responseBody,
      transport_error: transportError,
    };
    attempts.push(evidence);
    if (!transportError && status >= 200 && status < 300 && responseBody?.success === true) {
      return { result: responseBody, attempts };
    }
    const retryable = transportError || RETRYABLE_STATUS.has(status);
    if (!retryable || attempt === retries) {
      const error = new Error(`signed_replay_request_failed:${route}:${status || 'transport'}`);
      error.attempts = attempts;
      throw error;
    }
    await sleep(Math.min(10_000, 500 * (2 ** (attempt - 1))));
  }
  throw new Error('signed_replay_retry_exhausted');
}

function proofFileFor(runDir, sessionId) {
  return path.join(runDir, 'replay-progress', `${sha256(sessionId)}.json`);
}

function verifiedExistingProof(file, expected) {
  if (!fs.existsSync(file)) return null;
  if (fs.lstatSync(file).isSymbolicLink()) throw new Error(`replay_proof_symlink:${file}`);
  const proof = JSON.parse(fs.readFileSync(file, 'utf8'));
  const claimed = proof.proof_sha256;
  const unsigned = { ...proof };
  delete unsigned.proof_sha256;
  if (claimed !== sha256(JSON.stringify(unsigned))
    || proof.schema !== 'hom.canonical-session-replay-proof/v1'
    || proof.completed !== true
    || proof.run_id !== expected.runId
    || proof.corpus_sha256 !== expected.corpusSha256
    || proof.session_id !== expected.sessionId
    || proof.scope_id !== expected.scopeId
    || proof.source_filter !== expected.sourceFilter) {
    throw new Error(`replay_proof_conflict:${file}`);
  }
  return proof;
}

function writeExclusiveJson(file, value, mode = 0o600) {
  if (fs.existsSync(file)) throw new Error(`immutable_artifact_exists:${file}`);
  fs.writeFileSync(file, canonicalText(value), { flag: 'wx', mode });
}

async function replaySession(scope, session, context) {
  const proofFile = proofFileFor(context.runDir, session.session_id);
  const expected = {
    runId: context.runId,
    corpusSha256: context.corpusSha256,
    sessionId: session.session_id,
    scopeId: scope.scope_id,
    sourceFilter: scope.source_filter,
  };
  const existing = verifiedExistingProof(proofFile, expected);
  if (existing) return { proof: existing, reused: true };

  const turns = [];
  for (const turn of session.turns) {
    const normalizedImages = normalizeReplayImageContext(turn.image_context);
    const body = {
      company_id: 'hom',
      agent_id: 'housekeeper',
      session_id: session.session_id,
      turn_id: turn.turn_id,
      role: turn.role,
      content: turn.content,
      observed_at: turn.observed_at,
      source_ref: turn.source_ref || null,
      source: scope.source_filter,
      clearance_level: 10,
      ...(turn.speaker ? { speaker: turn.speaker } : {}),
      ...(normalizedImages.imageContext.length ? { image_context: normalizedImages.imageContext } : {}),
    };
    const posted = await signedPost(context.origin, '/aimos/session/turn', body, context);
    const expectedSequence = turns.length + 1;
    if (Number(posted.result.sequence) !== expectedSequence) {
      throw new Error(
        `session_turn_sequence_mismatch:${session.session_id}:${turn.turn_id}:${expectedSequence}:${posted.result.sequence}`,
      );
    }
    if (!posted.result.memory_id || (!posted.result.idempotent && (
      !/^[0-9a-f]{64}$/.test(String(posted.result.live_content_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(posted.result.save_mutation_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(posted.result.binding_mutation_hash || ''))
    ))) {
      throw new Error(`session_turn_cryptographic_evidence_missing:${session.session_id}`);
    }
    turns.push({
      turn_id: turn.turn_id,
      sequence: expectedSequence,
      quarantined: Boolean(posted.result.quarantined),
      body_sha256: sha256(JSON.stringify(body)),
      memory_id: posted.result.memory_id,
      idempotent: Boolean(posted.result.idempotent),
      live_content_hash: posted.result.live_content_hash || null,
      save_mutation_hash: posted.result.save_mutation_hash || null,
      binding_mutation_hash: posted.result.binding_mutation_hash || null,
      ...(normalizedImages.payloadRefs.length
        ? { image_payload_content_addresses: normalizedImages.payloadRefs }
        : {}),
      event_receipt: posted.result.event_receipt || null,
      attempts: posted.attempts,
    });
    if (context.delayMs) await sleep(context.delayMs);
  }

  const finalBody = {
    company_id: 'hom',
    agent_id: 'housekeeper',
    session_id: session.session_id,
    source: scope.source_filter,
    clearance_level: 10,
    expected_turn_count: session.turns.length,
    expected_turn_id_hashes_sha256: orderedTurnIdHashesSha256(session.turns),
  };
  const finalized = await signedPost(context.origin, '/aimos/session/finalize', finalBody, context);
  if (Number(finalized.result.turn_count) !== session.turns.length) {
    throw new Error(`session_finalization_turn_count_mismatch:${session.session_id}`);
  }
  if (Number(finalized.result.exchange_count) !== Math.ceil(session.turns.length / 2)) {
    throw new Error(`session_finalization_exchange_count_mismatch:${session.session_id}`);
  }
  if (!finalized.result.memory_id || !/^[0-9a-f]{64}$/.test(String(finalized.result.session_merkle_root || ''))
    || !/^[0-9a-f]{64}$/.test(String(finalized.result.exchange_merkle_root || ''))
    || (!finalized.result.idempotent && (
      !/^[0-9a-f]{64}$/.test(String(finalized.result.live_content_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(finalized.result.save_mutation_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(finalized.result.binding_mutation_hash || ''))
    ))) {
    throw new Error(`session_finalization_cryptographic_evidence_missing:${session.session_id}`);
  }
  const proof = {
    schema: 'hom.canonical-session-replay-proof/v1',
    run_id: context.runId,
    benchmark: context.benchmark,
    corpus_sha256: context.corpusSha256,
    scope_id: scope.scope_id,
    source_filter: scope.source_filter,
    source_session_id: session.source_session_id,
    session_id: session.session_id,
    turn_count: session.turns.length,
    turns,
    finalization: {
      body_sha256: sha256(JSON.stringify(finalBody)),
      memory_id: finalized.result.memory_id,
      idempotent: Boolean(finalized.result.idempotent),
      exchange_count: finalized.result.exchange_count,
      turn_id_hashes_sha256: finalized.result.turn_id_hashes_sha256,
      session_merkle_root: finalized.result.session_merkle_root,
      exchange_merkle_root: finalized.result.exchange_merkle_root,
      live_content_hash: finalized.result.live_content_hash || null,
      save_mutation_hash: finalized.result.save_mutation_hash || null,
      binding_mutation_hash: finalized.result.binding_mutation_hash || null,
      event_receipt: finalized.result.event_receipt || null,
      attempts: finalized.attempts,
    },
    completed: true,
  };
  proof.proof_sha256 = sha256(JSON.stringify(proof));
  writeExclusiveJson(proofFile, proof);
  // The server's envelope limiter counts finalization just like a turn. Pace
  // this request boundary too so short sessions cannot exceed 30 signed calls
  // per minute even though each individual turn was already paced.
  if (context.delayMs) await sleep(context.delayMs);
  return { proof, reused: false };
}

async function healthCheck(origin, timeoutMs, databaseName) {
  const response = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(timeoutMs) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ready !== true) throw new Error(`scratch_server_not_ready:${response.status}`);
  if (body.runtime?.database_name !== databaseName
    || body.runtime?.benchmark_scratch !== true
    || Number(body.runtime?.server_port) !== Number(new URL(origin).port)) {
    throw new Error('scratch_server_runtime_identity_mismatch');
  }
  return body;
}

async function main() {
  const args = parseArgs(process.argv);
  const loaded = loadReplayArtifact(args.sessionsFile, args.benchmark);
  const selectionScopeIds = args.selectionFile
    ? scopeIdsFromSelection(args.selectionFile, args.benchmark, args.runId)
    : null;
  const scopes = selectReplayScopes(loaded.artifact.scopes, selectionScopeIds
    ? { scopeIds: selectionScopeIds }
    : args);
  if (!scopes.length) throw new Error('replay_scope_selection_empty');
  const validatedTotals = validateReplayScopes(scopes);
  const totals = {
    ...validatedTotals,
  };
  if (args.dryRun) {
    console.log(JSON.stringify({
      mode: 'DRY_RUN',
      benchmark: args.benchmark,
      run_id: args.runId,
      database_name: args.databaseName,
      corpus_sha256: loaded.digest,
      origin: args.origin,
      totals,
      scope_ids: scopes.map((scope) => scope.scope_id),
      selection_file: args.selectionFile ? path.basename(args.selectionFile) : null,
    }, null, 2));
    return;
  }

  if (fs.existsSync(args.runDir) && fs.lstatSync(args.runDir).isSymbolicLink()) {
    throw new Error('run_dir_symlink_forbidden');
  }
  fs.mkdirSync(path.join(args.runDir, 'replay-progress'), { recursive: true, mode: 0o700 });
  const health = await healthCheck(args.origin, args.requestTimeoutMs, args.databaseName);
  const context = {
    ...args,
    corpusSha256: loaded.digest,
  };
  let completed = 0;
  let reused = 0;
  for (const scope of scopes) {
    for (const session of scope.sessions) {
      const result = await replaySession(scope, session, context);
      completed += 1;
      if (result.reused) reused += 1;
      console.log(JSON.stringify({
        event: 'session_replayed',
        benchmark: args.benchmark,
        scope_id: scope.scope_id,
        session_id: session.session_id,
        completed,
        total: totals.sessions,
        reused: result.reused,
        proof_sha256: result.proof.proof_sha256,
      }));
    }
  }
  const summary = {
    schema: 'hom.canonical-replay-summary/v1',
    run_id: args.runId,
    benchmark: args.benchmark,
    corpus_file: path.basename(args.sessionsFile),
    corpus_sha256: loaded.digest,
    database_name: args.databaseName,
    scratch_origin: args.origin,
    health: {
      service: health.service || null,
      version: health.version || null,
      ready: health.ready,
      runtime: health.runtime,
    },
    totals,
    completed_sessions: completed,
    reused_session_proofs: reused,
    failed_sessions: 0,
    concurrency: 1,
  };
  summary.summary_sha256 = sha256(JSON.stringify(summary));
  const summaryFile = path.join(
    args.runDir,
    `replay-summary-${args.benchmark}-${Date.now()}.json`,
  );
  writeExclusiveJson(summaryFile, summary);
  console.log(JSON.stringify({ success: true, summary_file: summaryFile, ...summary }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    if (error?.attempts) console.error(JSON.stringify({ attempts: error.attempts }, null, 2));
    process.exitCode = 1;
  });
}
