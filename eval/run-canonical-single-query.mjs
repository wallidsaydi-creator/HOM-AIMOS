#!/usr/bin/env node

/**
 * Canonical one-query benchmark execution.
 *
 * Phases are intentionally separate:
 *   prepare  — split selected public questions into input and gold artifacts;
 *   recall   — one signed native recall per input, with offline receipt proof;
 *   generate — GPT-5.4 reads only input + verified recall evidence;
 *   judge    — GPT-5.6 Terra reads one generated answer + one gold answer.
 *
 * Every retry is a new immutable attempt directory. A successful attempt is
 * never overwritten.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { pool, agentPool } from '../db/connection.js';
import { runProvider } from '../services/core/providers.js';
import { loadCredentialCache } from '../services/security/credential-cache.js';
import { canonicalJson } from '../services/security/agent-identity.js';
import { signAsHousekeeper } from '../services/security/housekeeper-signer.js';
import { systemConfigStore } from '../services/security/system-config-store.js';
import {
  normalizeNativeRecallCommand,
  recallMerkleRoot,
} from '../services/retrieval/native-recall.js';
import { resolveAimosDatabaseName } from '../services/core/runtime-config.js';
import { validateReplayOrigin } from './replay-sessions.mjs';
import {
  LOCOMO_OFFICIAL_PROTOCOL,
  LOCOMO_OFFICIAL_TOP_K,
  buildOfficialLocomoPrompt,
  normalizeOfficialLocomoPrediction,
  officialLocomoProtocolManifest,
  prepareOfficialLocomoInput,
} from './locomo-official-protocol.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS_DIR = path.join(ROOT, 'data', 'canonical');
const GENERATOR_MODEL = 'gpt-5.4';
const JUDGE_MODEL = 'gpt-5.6-terra';
const LOCOMO_FULL_DETAIL_TOKEN_BUDGET = 16_000;
const CANONICAL_BLIND_PROTOCOL = 'canonical-blind-v1';
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
export const GENERATOR_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['answer', 'abstained', 'cited_memory_ids', 'confidence'],
  properties: {
    answer: { type: 'string', minLength: 1, maxLength: 8000 },
    abstained: { type: 'boolean' },
    cited_memory_ids: {
      type: 'array',
      maxItems: 200,
      items: { type: 'string', minLength: 1, maxLength: 128 },
    },
    confidence: { type: 'number', minimum: 0, maximum: 1 },
  },
});
export const JUDGE_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['correct', 'score', 'reason', 'judge_confidence'],
  properties: {
    correct: { type: 'boolean' },
    score: { type: 'number', minimum: 0, maximum: 1 },
    reason: { type: 'string', minLength: 1, maxLength: 2000 },
    judge_confidence: { type: 'number', minimum: 0, maximum: 1 },
  },
});
export const GENERATOR_SYSTEM_PROMPT = [
  'Answer one long-term-memory benchmark question from the supplied verified HOM memories.',
  'Use a short phrase or sentence and preserve exact names, subjects, dates, quantities, and relationships.',
  'Use the most specific identity or relationship wording explicitly supported by the memories.',
  'Ordinary world knowledge may interpret or combine retrieved facts, but every personal or episodic claim must be grounded in the supplied memories.',
  'Do not answer about a related person, object, or event when the exact subject or relationship asked about is unsupported.',
  'Derive temporal differences, comparisons, and counts only when the supplied facts support the derivation.',
  'For a temporal answer, convert relative phrases such as yesterday or last year to an absolute date or year whenever the memory timestamp makes that derivation possible, then omit the relative phrase.',
  'Do not add extra facts. Do not invent or cite memory identifiers not present in the evidence.',
  'If the exact answer is unsupported, set abstained to true and answer exactly "Insufficient evidence."',
  'Return only the strict schema object.',
].join(' ');
export const JUDGE_SYSTEM_PROMPT = [
  'Judge one candidate answer against one gold answer for semantic correctness.',
  'Do not use other questions, aggregate HOM scores, competitor claims, or outside facts.',
  'A concise paraphrase or common equivalent is correct when it preserves the gold meaning; word-for-word identity is not required.',
  'Harmless contextual wording does not make an answer incorrect when the exact gold answer is also stated or unambiguously entailed.',
  'Wrong subject attribution, a contradicted relationship, a missing essential answer, or an extra claim that materially changes the answer is incorrect.',
  'When the gold answer is empty, only an explicit abstention or not-mentioned answer is correct.',
  'Return only the strict schema object.',
].join(' ');
const SELECTION_PROFILES = Object.freeze({
  b4: Object.freeze({
    locomo: Object.freeze({
      'single-hop': 1,
      temporal: 1,
      'open-domain': 1,
      'multi-hop': 1,
      adversarial: 1,
    }),
    longmemeval: Object.freeze({
      'single-session-preference': 1,
      'temporal-reasoning': 1,
      'knowledge-update': 1,
      'multi-session': 1,
      abstention: 1,
    }),
  }),
  b5: Object.freeze({
    locomo: Object.freeze({
      'single-hop': 5,
      temporal: 5,
      'open-domain': 5,
      'multi-hop': 5,
      adversarial: 5,
    }),
    longmemeval: Object.freeze({
      'single-session-preference': 5,
      'temporal-reasoning': 5,
      'knowledge-update': 5,
      'multi-session': 5,
      abstention: 5,
    }),
  }),
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalSha256(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
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

function integerArg(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name}_invalid`);
  return parsed;
}

function parseArgs(argv) {
  const phase = String(cliValue(argv, '--phase') || '').trim().toLowerCase();
  if (!['prepare', 'recall', 'generate', 'judge'].includes(phase)) throw new Error('benchmark_phase_invalid');
  const benchmark = String(cliValue(argv, '--benchmark') || '').trim().toLowerCase();
  if (!['locomo', 'longmemeval'].includes(benchmark)) throw new Error('benchmark_invalid');
  const protocol = String(cliValue(argv, '--protocol') || CANONICAL_BLIND_PROTOCOL).trim().toLowerCase();
  if (![CANONICAL_BLIND_PROTOCOL, LOCOMO_OFFICIAL_PROTOCOL].includes(protocol)) {
    throw new Error('benchmark_protocol_invalid');
  }
  if (protocol === LOCOMO_OFFICIAL_PROTOCOL && benchmark !== 'locomo') {
    throw new Error('locomo_official_protocol_requires_locomo');
  }
  if (protocol === LOCOMO_OFFICIAL_PROTOCOL && phase === 'judge') {
    throw new Error('locomo_official_protocol_uses_deterministic_scorer');
  }
  const runId = String(cliValue(argv, '--run-id') || '').trim();
  if (!/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(runId)) throw new Error('run_id_invalid');
  const runDirRaw = cliValue(argv, '--run-dir');
  if (!runDirRaw) throw new Error('run_dir_required');
  const questionLimitRaw = cliValue(argv, '--question-limit');
  const questionIds = cliValues(argv, '--question-id');
  const selectionProfile = String(cliValue(argv, '--selection-profile') || '').trim().toLowerCase() || null;
  if (selectionProfile && !SELECTION_PROFILES[selectionProfile]) throw new Error('selection_profile_invalid');
  const all = cliFlag(argv, '--all');
  if (phase === 'prepare') {
    const selectionModes = Number(all) + Number(questionIds.length > 0)
      + Number(questionLimitRaw != null) + Number(Boolean(selectionProfile));
    if (selectionModes !== 1) throw new Error('exactly_one_question_selection_mode_required');
  }
  const databaseName = cliValue(argv, '--aimos-db');
  if (phase === 'recall' && databaseName !== `aimos_benchmark_${runId}`) {
    throw new Error('benchmark_database_must_match_run_id');
  }
  const judgeReasoning = String(cliValue(argv, '--judge-reasoning') || 'high').trim().toLowerCase();
  if (!['medium', 'high'].includes(judgeReasoning)) throw new Error('judge_reasoning_invalid');
  const recallK = integerArg(cliValue(argv, '--recall-k') || 20, 'recall_k', { min: 1, max: 200 });
  if (protocol === LOCOMO_OFFICIAL_PROTOCOL && phase === 'recall' && recallK !== LOCOMO_OFFICIAL_TOP_K) {
    throw new Error(`locomo_official_recall_k_must_equal_${LOCOMO_OFFICIAL_TOP_K}`);
  }
  return {
    phase,
    benchmark,
    protocol,
    runId,
    runDir: path.resolve(runDirRaw),
    questionsFile: path.resolve(cliValue(argv, '--questions-file')
      || path.join(DEFAULT_CORPUS_DIR, `${benchmark}-questions.json`)),
    selectionFile: path.resolve(cliValue(argv, '--selection-file')
      || path.join(path.resolve(runDirRaw), `selection-${benchmark}.json`)),
    questionIds,
    selectionProfile,
    all,
    questionOffset: integerArg(cliValue(argv, '--question-offset') || 0, 'question_offset'),
    questionLimit: questionLimitRaw == null
      ? null
      : integerArg(questionLimitRaw, 'question_limit', { min: 1, max: 2486 }),
    databaseName,
    origin: phase === 'recall'
      ? validateReplayOrigin(cliValue(argv, '--aimos-base') || 'http://127.0.0.1:9200')
      : null,
    recallK,
    delayMs: integerArg(cliValue(argv, '--delay-ms') || 2100, 'delay_ms', { max: 60_000 }),
    retries: integerArg(cliValue(argv, '--retries') || 3, 'retries', { min: 1, max: 10 }),
    judgeReasoning,
  };
}

function readJson(file) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) throw new Error(`artifact_invalid:${file}`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function immutableJson(file, value, mode = 0o600) {
  const text = jsonText(value);
  if (fs.existsSync(file)) {
    if (fs.lstatSync(file).isSymbolicLink() || fs.readFileSync(file, 'utf8') !== text) {
      throw new Error(`immutable_artifact_conflict:${file}`);
    }
    return false;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, text, { flag: 'wx', mode });
  return true;
}

function loadQuestionArtifact(file, benchmark) {
  const bytes = fs.readFileSync(file);
  const artifact = JSON.parse(bytes);
  if (artifact?.schema !== 'hom.canonical-benchmark-questions/v1'
    || artifact.benchmark !== benchmark
    || !Array.isArray(artifact.questions)) {
    throw new Error('question_artifact_schema_invalid');
  }
  const manifest = readJson(path.join(path.dirname(file), 'corpus-manifest.json'));
  const name = path.basename(file);
  const attestation = manifest.outputs?.find((entry) => entry.file === name);
  if (!manifest.answer_key_boundary?.scorer_inputs?.includes(name)
    || !attestation
    || attestation.sha256 !== sha256(bytes)
    || attestation.bytes !== bytes.length) {
    throw new Error('question_artifact_attestation_invalid');
  }
  return { artifact, digest: sha256(bytes) };
}

function profileCategory(question, benchmark) {
  if (benchmark === 'longmemeval' && /_abs$/i.test(String(question.question_id || ''))) {
    return 'abstention';
  }
  return String(question.category || '').trim().toLowerCase();
}

export function selectProfileQuestions(questions, benchmark, profileName) {
  const quotas = SELECTION_PROFILES[profileName]?.[benchmark];
  if (!quotas) throw new Error('selection_profile_benchmark_invalid');
  const indexed = questions.map((question, index) => ({ question, index }));
  const selected = [];
  const selectedIds = new Set();
  const scopeUsage = new Map();
  for (const [category, quota] of Object.entries(quotas)) {
    for (let count = 0; count < quota; count += 1) {
      const candidate = indexed
        .filter(({ question }) => !selectedIds.has(question.question_id)
          && profileCategory(question, benchmark) === category)
        .sort((left, right) => {
          const leftUsage = scopeUsage.get(left.question.scope_id) || 0;
          const rightUsage = scopeUsage.get(right.question.scope_id) || 0;
          return leftUsage - rightUsage || left.index - right.index;
        })[0];
      if (!candidate) throw new Error(`selection_profile_quota_unavailable:${benchmark}:${category}`);
      selected.push(candidate.question);
      selectedIds.add(candidate.question.question_id);
      scopeUsage.set(candidate.question.scope_id, (scopeUsage.get(candidate.question.scope_id) || 0) + 1);
    }
  }
  return selected;
}

function selectQuestions(questions, args) {
  if (args.all) return [...questions];
  if (args.selectionProfile) return selectProfileQuestions(questions, args.benchmark, args.selectionProfile);
  if (args.questionIds.length) {
    const ids = [...new Set(args.questionIds)];
    if (ids.length !== args.questionIds.length) throw new Error('question_selection_duplicate');
    const byId = new Map(questions.map((question) => [question.question_id, question]));
    return ids.map((id) => {
      const question = byId.get(id);
      if (!question) throw new Error(`question_selection_missing:${id}`);
      return question;
    });
  }
  return questions.slice(args.questionOffset, args.questionOffset + args.questionLimit);
}

function unitId(questionId) {
  return sha256(Buffer.from(String(questionId), 'utf8'));
}

function selfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(JSON.stringify(unsigned));
}

function prepare(args) {
  const loaded = loadQuestionArtifact(args.questionsFile, args.benchmark);
  const selected = selectQuestions(loaded.artifact.questions, args);
  if (!selected.length) throw new Error('question_selection_empty');
  const entries = [];
  for (const question of selected) {
    const id = unitId(question.question_id);
    const evaluationCategory = profileCategory(question, args.benchmark);
    let input = {
      schema: 'hom.canonical-query-input/v1',
      question_id: question.question_id,
      benchmark: args.benchmark,
      scope_id: question.scope_id,
      source_filter: question.source_filter,
      category: evaluationCategory,
      ...(evaluationCategory !== question.category ? { source_category: question.category } : {}),
      question: question.question,
      ...(question.question_date ? { question_date: question.question_date } : {}),
    };
    if (args.protocol === LOCOMO_OFFICIAL_PROTOCOL) {
      input = prepareOfficialLocomoInput(input, question.answer);
    }
    const gold = {
      schema: 'hom.canonical-query-gold/v1',
      question_id: question.question_id,
      answer: question.answer,
      ...(question.expected_evidence ? { expected_evidence: question.expected_evidence } : {}),
      ...(question.answer_session_ids ? { answer_session_ids: question.answer_session_ids } : {}),
    };
    const questionDir = path.join(args.runDir, 'questions', id);
    immutableJson(path.join(questionDir, 'input.json'), input);
    immutableJson(path.join(args.runDir, 'gold', `${id}.json`), gold);
    entries.push({
      question_id: question.question_id,
      unit_id: id,
      scope_id: question.scope_id,
      source_filter: question.source_filter,
      input_sha256: canonicalSha256(input),
      gold_sha256: canonicalSha256(gold),
    });
  }
  const selection = {
    schema: 'hom.canonical-query-selection/v1',
    run_id: args.runId,
    benchmark: args.benchmark,
    protocol: args.protocol,
    selection_profile: args.selectionProfile,
    question_artifact_sha256: loaded.digest,
    question_count: entries.length,
    entries,
  };
  selection.selection_sha256 = selfHash(selection, 'selection_sha256');
  immutableJson(args.selectionFile, selection);
  console.log(JSON.stringify({ success: true, selection_file: args.selectionFile, ...selection }, null, 2));
}

function loadSelection(args) {
  const selection = readJson(args.selectionFile);
  if (selection?.schema !== 'hom.canonical-query-selection/v1'
    || selection.run_id !== args.runId
    || selection.benchmark !== args.benchmark
    || (selection.protocol || CANONICAL_BLIND_PROTOCOL) !== args.protocol
    || selection.question_count !== selection.entries?.length
    || selection.selection_sha256 !== selfHash(selection, 'selection_sha256')) {
    throw new Error('query_selection_invalid');
  }
  return selection;
}

function attemptRoot(args, entry, phase) {
  return path.join(args.runDir, 'questions', entry.unit_id, phase);
}

function verifyCompletedAttempt(directory) {
  const completeFile = path.join(directory, 'complete.json');
  if (!fs.existsSync(completeFile)) return null;
  const complete = readJson(completeFile);
  if (complete?.schema !== 'hom.canonical-query-attempt-complete/v1' || complete.status !== 'success') {
    throw new Error(`attempt_completion_invalid:${directory}`);
  }
  for (const [name, expected] of Object.entries(complete.files || {})) {
    const file = path.join(directory, name);
    if (!fs.existsSync(file) || sha256(fs.readFileSync(file)) !== expected) {
      throw new Error(`attempt_artifact_hash_mismatch:${file}`);
    }
  }
  if (complete.complete_sha256 !== selfHash(complete, 'complete_sha256')) {
    throw new Error(`attempt_completion_hash_mismatch:${directory}`);
  }
  return { directory, complete };
}

function successfulAttempt(args, entry, phase) {
  const root = attemptRoot(args, entry, phase);
  if (!fs.existsSync(root)) return null;
  const completed = fs.readdirSync(root, { withFileTypes: true })
    .filter((item) => item.isDirectory() && /^attempt-\d{4}$/.test(item.name))
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((item) => verifyCompletedAttempt(path.join(root, item.name)))
    .filter(Boolean);
  if (completed.length > 1) throw new Error(`multiple_successful_attempts:${entry.question_id}:${phase}`);
  return completed[0] || null;
}

function newAttempt(args, entry, phase) {
  const root = attemptRoot(args, entry, phase);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const numbers = fs.readdirSync(root)
    .map((name) => /^attempt-(\d{4})$/.exec(name))
    .filter(Boolean)
    .map((match) => Number(match[1]));
  const number = numbers.length ? Math.max(...numbers) + 1 : 1;
  if (number > 9999) throw new Error('attempt_sequence_exhausted');
  const directory = path.join(root, `attempt-${String(number).padStart(4, '0')}`);
  fs.mkdirSync(directory, { mode: 0o700 });
  return directory;
}

function completeAttempt(directory, phase) {
  const files = {};
  for (const name of fs.readdirSync(directory).sort()) {
    const file = path.join(directory, name);
    if (name === 'complete.json' || !fs.statSync(file).isFile()) continue;
    files[name] = sha256(fs.readFileSync(file));
  }
  const complete = {
    schema: 'hom.canonical-query-attempt-complete/v1',
    phase,
    status: 'success',
    files,
  };
  complete.complete_sha256 = selfHash(complete, 'complete_sha256');
  immutableJson(path.join(directory, 'complete.json'), complete);
  return complete;
}

function safeFailure(error) {
  return {
    name: String(error?.name || 'Error').slice(0, 128),
    message: String(error?.message || error || 'unknown_error')
      .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
      .replace(/\bsk-[A-Za-z0-9_-]+\b/g, '[REDACTED]')
      .slice(0, 2000),
  };
}

function writeFailure(directory, phase, error) {
  immutableJson(path.join(directory, 'failure.json'), {
    schema: 'hom.canonical-query-attempt-failure/v1',
    phase,
    status: 'failed',
    error: safeFailure(error),
  });
}

export function isRetryablePhaseFailure(error, phase) {
  const name = String(error?.name || '');
  const message = String(error?.message || error || '');
  if (/provider_model_substitution|query_(?:input|or_gold)_hash_mismatch|attempt_|artifact_|_attempt_missing|scratch_server_runtime_identity_mismatch|system_config_store_load_failed|credential/i.test(message)) {
    return false;
  }
  if (['AbortError', 'TimeoutError', 'TypeError'].includes(name)
    || /\b(?:timeout|timed out|ECONNRESET|ECONNREFUSED|EAI_AGAIN|socket|network|fetch failed)\b/i.test(message)) {
    return true;
  }
  if (phase === 'recall') {
    const status = Number(/signed_recall_failed:(\d{3}):/.exec(message)?.[1]);
    return RETRYABLE_STATUS.has(status);
  }
  const status = Number(/(?:HTTP\s+|error\s*\()(\d{3})/i.exec(message)?.[1]);
  if (RETRYABLE_STATUS.has(status)) return true;
  return /(?:response was empty|response ended with status (?:failed|incomplete)|semantic_contract_invalid|_not_bare_json|_json_invalid|provider_(?:response_incomplete|usage_missing))/i.test(message);
}

function retryDelayMs(args, attempt) {
  const base = args.phase === 'recall' ? Math.max(5_000, args.delayMs) : 1_000;
  return Math.min(30_000, base * (2 ** (attempt - 1)));
}

async function scratchHealth(args) {
  const response = await fetch(`${args.origin}/health`, { signal: AbortSignal.timeout(10_000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok
    || body.ready !== true
    || body.runtime?.database_name !== args.databaseName
    || body.runtime?.benchmark_scratch !== true
    || Number(body.runtime?.server_port) !== Number(new URL(args.origin).port)) {
    throw new Error('scratch_server_runtime_identity_mismatch');
  }
  return body;
}

export function signedRequestArtifact(signed) {
  return {
    body: signed.body,
    headers: {
      'Aimos-Agent-Cert': signed.certString,
      'Aimos-Agent-Signature': signed.sigB64u,
      'Aimos-Agent-Nonce': signed.nonce,
      'Aimos-Agent-Timestamp': String(signed.signedTs),
      'X-Aimos-Sig-Form': String(signed.sigForm),
    },
    body_sha256: canonicalSha256(signed.body),
    certificate_sha256: sha256(signed.certString),
  };
}

export function verifyRecallReceipt({
  requestBody,
  signedBody,
  responseBody,
  sourceFilter,
  expectedMemoryType = 'session_exchange',
  expectedKeyPrefix = null,
}) {
  const allowedMemoryTypes = Array.isArray(expectedMemoryType)
    ? new Set(expectedMemoryType.map(String))
    : new Set([String(expectedMemoryType)]);
  const memories = Array.isArray(responseBody?.memories) ? responseBody.memories : [];
  const receipt = responseBody?.recall_receipt;
  if (!receipt || !Array.isArray(receipt.evidence) || receipt.evidence.length !== memories.length) {
    throw new Error('recall_receipt_evidence_count_mismatch');
  }
  const unsignedRequest = { ...requestBody };
  const unsignedSignedBody = { ...signedBody };
  delete unsignedRequest.ts_signed;
  delete unsignedSignedBody.ts_signed;
  if (canonicalJson(unsignedRequest) !== canonicalJson(unsignedSignedBody)) {
    throw new Error('recall_signed_command_binding_invalid');
  }
  const command = normalizeNativeRecallCommand(signedBody);
  const expectedCommandHash = canonicalSha256(command);
  const expectedOuterHash = canonicalSha256(signedBody);
  const expectedRoot = recallMerkleRoot(receipt.evidence).toString('hex');
  if (receipt.command_hash !== expectedCommandHash
    || receipt.outer_request_hash !== expectedOuterHash
    || receipt.merkle_root !== expectedRoot
    || !/^[0-9a-f]{64}$/.test(String(receipt.authority_mutation_hash || ''))
    || !/^[0-9a-f]{64}$/.test(String(receipt.request_receipt_mutation_hash || ''))
    || !/^[0-9a-f]{64}$/.test(String(receipt.event_receipt?.mutation_hash || ''))) {
    throw new Error('recall_receipt_cryptographic_binding_invalid');
  }
  for (let index = 0; index < memories.length; index += 1) {
    const memory = memories[index];
    const evidence = receipt.evidence[index];
    const proof = memory?.provenance_proof;
    if (Number(evidence.ordinal) !== index
      || String(evidence.memory_id) !== String(memory?.id)
      || memory?.source !== sourceFilter
      || !allowedMemoryTypes.has(String(memory?.memory_type || ''))
      || (expectedKeyPrefix && !String(memory?.key || '').startsWith(expectedKeyPrefix))
      || !proof
      || evidence.live_content_hash !== proof.live_content_hash
      || evidence.save_mutation_hash !== proof.save_mutation_hash
      || evidence.binding_mutation_hash !== proof.binding_mutation_hash
      || !/^[0-9a-f]{64}$/.test(String(evidence.live_content_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(evidence.save_mutation_hash || ''))
      || !/^[0-9a-f]{64}$/.test(String(evidence.binding_mutation_hash || ''))) {
      throw new Error(`recall_receipt_memory_binding_invalid:${index}`);
    }
  }
  return {
    verified: true,
    result_count: memories.length,
    command_hash: expectedCommandHash,
    outer_request_hash: expectedOuterHash,
    merkle_root: expectedRoot,
  };
}

export function buildRecallRequestBody(input, recallK) {
  const body = {
    company_id: 'hom',
    agent_id: 'housekeeper',
    q: input.question,
    source_filter: input.source_filter,
    memory_type_filter: 'session_exchange',
    limit: recallK,
    clearance_level: 10,
    cache: false,
    answer_shape: 'full_detail',
  };
  if (input.benchmark === 'locomo') {
    body.full_detail_token_budget = LOCOMO_FULL_DETAIL_TOKEN_BUDGET;
  }
  return body;
}

async function recallOne(args, entry) {
  const input = readJson(path.join(args.runDir, 'questions', entry.unit_id, 'input.json'));
  if (canonicalSha256(input) !== entry.input_sha256) throw new Error('query_input_hash_mismatch');
  const directory = newAttempt(args, entry, 'recall');
  try {
    const body = buildRecallRequestBody(input, args.recallK);
    const signed = await signAsHousekeeper(body, { method: 'POST', path: '/aimos/recall' });
    const started = performance.now();
    const response = await fetch(`${args.origin}/aimos/recall`, {
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
      signal: AbortSignal.timeout(120_000),
    });
    const responseBody = await response.json().catch(() => ({}));
    const latencyMs = Math.round((performance.now() - started) * 100) / 100;
    if (!response.ok || responseBody.success !== true) {
      throw new Error(`signed_recall_failed:${response.status}:${responseBody.error || 'unknown'}`);
    }
    const verification = verifyRecallReceipt({
      requestBody: body,
      signedBody: signed.body,
      responseBody,
      sourceFilter: input.source_filter,
    });
    immutableJson(path.join(directory, 'recall-request.json'), signedRequestArtifact(signed));
    immutableJson(path.join(directory, 'recall-response.json'), responseBody);
    immutableJson(path.join(directory, 'recall-receipt.json'), responseBody.recall_receipt);
    immutableJson(path.join(directory, 'verification.json'), verification);
    immutableJson(path.join(directory, 'timings.json'), { latency_ms: latencyMs, http_status: response.status });
    completeAttempt(directory, 'recall');
    return { reused: false, directory, verification };
  } catch (error) {
    writeFailure(directory, 'recall', error);
    throw error;
  }
}

function strictObject(text, label) {
  const raw = String(text || '').trim();
  if (!raw.startsWith('{') || !raw.endsWith('}')) throw new Error(`${label}_not_bare_json`);
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid');
    return value;
  } catch {
    throw new Error(`${label}_json_invalid`);
  }
}

function usageEvidence(usage) {
  if (!usage
    || !Number.isSafeInteger(usage.inputTokens)
    || !Number.isSafeInteger(usage.outputTokens)
    || !Number.isSafeInteger(usage.totalTokens)) {
    throw new Error('provider_usage_missing');
  }
  return usage;
}

function credentialUseEvidence(evidence) {
  if (!evidence) throw new Error('credential_use_evidence_missing');
  const mutationHash = String(evidence.terminalMutationHash || '').toLowerCase();
  if (!evidence.useId || !evidence.terminalProvenanceId || !/^[0-9a-f]{64}$/.test(mutationHash)) {
    throw new Error('credential_use_evidence_invalid');
  }
  return {
    use_id: String(evidence.useId),
    terminal_provenance_id: String(evidence.terminalProvenanceId),
    terminal_mutation_hash: mutationHash,
    outcome: String(evidence.outcome || ''),
  };
}

export function providerEvidence(response, requestedModel, reasoningEffort) {
  if (response.model !== requestedModel) throw new Error(`provider_model_substitution:${response.model || 'missing'}`);
  if (response.status !== 'completed' || !response.responseId) throw new Error('provider_response_incomplete');
  return {
    provider: 'codex',
    requested_model: requestedModel,
    actual_model: response.model,
    reasoning_effort: reasoningEffort,
    response_id: response.responseId,
    status: response.status,
    usage: usageEvidence(response.usage),
    credential_use: credentialUseEvidence(response.credentialUseEvidence),
  };
}

export function evidenceForGenerator(responseBody) {
  return (responseBody.memories || []).map((memory, index) => ({
    returned_rank: index + 1,
    memory_id: String(memory.id),
    key: memory.key,
    memory_type: memory.memory_type,
    source: memory.source,
    created_at: memory.created_at,
    valid_from: memory.valid_from,
    valid_until: memory.valid_until,
    score: memory.calibrated_recall_score ?? memory.rerank_score ?? null,
    evidence_handling: memory.evidence_handling ?? null,
    epistemic_state: memory.epistemic_state ?? null,
    epistemic_score: memory.epistemic_score ?? null,
    epistemic_decision_version: memory.epistemic_decision_version ?? null,
    epistemic_signals: memory.epistemic_signals ?? null,
    freshness_state: memory.freshness_state ?? null,
    verified_by: memory.verified_by ?? null,
    verification_basis: memory.verification_basis ?? null,
    value: memory.value,
  }));
}

export function buildGeneratorPrompt(input, evidence) {
  return [
    `Question: ${input.question}`,
    input.question_date ? `Question date: ${input.question_date}` : null,
    '',
    'Cryptographically provenance-verified HOM memories in native returned order:',
    'Epistemic labels are separate from provenance. Do not use evidence_handling="untrusted_reference_only" as factual support; abstain if no adequate supported or unverified reference evidence remains.',
    JSON.stringify(evidence),
  ].filter((value) => value != null).join('\n');
}

export function buildJudgePrompt(input, gold, answer) {
  return [
    `Question: ${input.question}`,
    input.question_date ? `Question date: ${input.question_date}` : null,
    `Gold answer: ${gold.answer}`,
    `Candidate answer: ${answer.answer}`,
    `Candidate abstained: ${answer.abstained}`,
  ].filter((value) => value != null).join('\n');
}

export function validateGeneratorOutput(output, evidence = []) {
  return validateGeneratorOutputDetailed(output, evidence).valid;
}

export function validateGeneratorOutputDetailed(output, evidence = []) {
  const allowedIds = new Set(evidence.map((memory) => String(memory.memory_id)));
  const citedIds = Array.isArray(output?.cited_memory_ids)
    ? output.cited_memory_ids.map((id) => String(id))
    : [];
  const answer = typeof output?.answer === 'string' ? output.answer.trim() : '';
  const abstentionAnswer = /^insufficient evidence\.?$/i.test(answer);
  if (!answer) return { valid: false, reason: 'answer_missing' };
  if (typeof output?.abstained !== 'boolean') {
    return { valid: false, reason: 'abstained_not_boolean' };
  }
  if (!Array.isArray(output?.cited_memory_ids)) {
    return { valid: false, reason: 'cited_memory_ids_not_array' };
  }
  const unboundIds = [...new Set(citedIds.filter((id) => !allowedIds.has(id)))];
  if (unboundIds.length) {
    return {
      valid: false,
      reason: 'cited_memory_id_not_in_returned_evidence',
      unbound_cited_memory_ids: unboundIds,
    };
  }
  if (new Set(citedIds).size !== citedIds.length) {
    return { valid: false, reason: 'duplicate_cited_memory_id' };
  }
  if (output.abstained && !abstentionAnswer) {
    return { valid: false, reason: 'abstention_answer_mismatch' };
  }
  if (!output.abstained && abstentionAnswer) {
    return { valid: false, reason: 'non_abstention_answer_mismatch' };
  }
  if (!output.abstained && citedIds.length === 0) {
    return { valid: false, reason: 'non_abstention_citation_missing' };
  }
  if (!Number.isFinite(output?.confidence)) {
    return { valid: false, reason: 'confidence_not_finite' };
  }
  if (output.confidence < 0 || output.confidence > 1) {
    return { valid: false, reason: 'confidence_out_of_range' };
  }
  return { valid: true, reason: null };
}

function redactedDiagnosticText(value) {
  return String(value || '')
    .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
    .replace(/\bsk-[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .slice(0, 32_000);
}

export function rejectedProviderOutputArtifact({
  response,
  requestedModel,
  reasoningEffort,
  systemPrompt,
  userPrompt,
  responseSchema,
  validation,
  error,
}) {
  let credentialUse = null;
  try {
    credentialUse = credentialUseEvidence(response?.credentialUseEvidence);
  } catch {
    credentialUse = null;
  }
  const responseText = redactedDiagnosticText(response?.text);
  const artifact = {
    schema: 'hom.canonical-rejected-provider-output/v1',
    provider: 'codex',
    requested_model: requestedModel,
    actual_model: response?.model || null,
    reasoning_effort: reasoningEffort,
    response_id: response?.responseId || null,
    status: response?.status || null,
    usage: response?.usage || null,
    credential_use: credentialUse,
    prompt_sha256: sha256(Buffer.from(`${systemPrompt}\n${userPrompt}`, 'utf8')),
    response_schema_sha256: canonicalSha256(responseSchema),
    response_text: responseText,
    response_text_sha256: sha256(Buffer.from(responseText, 'utf8')),
    validation: validation || null,
    error: safeFailure(error),
  };
  artifact.artifact_sha256 = selfHash(artifact, 'artifact_sha256');
  return artifact;
}

export function validateJudgeOutputDetailed(output) {
  if (typeof output?.correct !== 'boolean') {
    return { valid: false, reason: 'correct_not_boolean' };
  }
  if (!Number.isFinite(output?.score)) {
    return { valid: false, reason: 'score_not_finite' };
  }
  if (output.score < 0 || output.score > 1) {
    return { valid: false, reason: 'score_out_of_range' };
  }
  if (typeof output?.reason !== 'string' || !output.reason.trim()) {
    return { valid: false, reason: 'reason_missing' };
  }
  if (!Number.isFinite(output?.judge_confidence)) {
    return { valid: false, reason: 'judge_confidence_not_finite' };
  }
  if (output.judge_confidence < 0 || output.judge_confidence > 1) {
    return { valid: false, reason: 'judge_confidence_out_of_range' };
  }
  return { valid: true, reason: null };
}

export async function ensureProviderRuntime() {
  if (resolveAimosDatabaseName() !== 'aimos') throw new Error('provider_phase_requires_canonical_aimos_database');
  const loaded = await systemConfigStore.loadAll();
  if (!loaded.ok) throw new Error(`system_config_store_load_failed:${loaded.reason}`);
  await loadCredentialCache();
}

async function generateOne(args, entry) {
  const input = readJson(path.join(args.runDir, 'questions', entry.unit_id, 'input.json'));
  if (canonicalSha256(input) !== entry.input_sha256) throw new Error('query_input_hash_mismatch');
  const recall = successfulAttempt(args, entry, 'recall');
  if (!recall) throw new Error('verified_recall_attempt_missing');
  const responseBody = readJson(path.join(recall.directory, 'recall-response.json'));
  const evidence = evidenceForGenerator(responseBody);
  const directory = newAttempt(args, entry, 'generate');
  const officialProtocol = args.protocol === LOCOMO_OFFICIAL_PROTOCOL;
  const systemPrompt = officialProtocol ? '' : GENERATOR_SYSTEM_PROMPT;
  const userPrompt = officialProtocol
    ? buildOfficialLocomoPrompt(input, responseBody.memories || [])
    : buildGeneratorPrompt(input, evidence);
  const responseSchema = officialProtocol ? { type: 'string' } : GENERATOR_SCHEMA;
  let response = null;
  let validation = null;
  try {
    const started = performance.now();
    response = await runProvider({
      provider: 'codex',
      model: GENERATOR_MODEL,
      systemPrompt,
      userPrompt,
      reasoningEffort: 'medium',
      textVerbosity: 'low',
      ...(officialProtocol
        ? {}
        : { responseSchema: { name: 'hom_benchmark_generator', schema: GENERATOR_SCHEMA } }),
      returnMetadata: true,
      useContext: { subjectAgentId: 'housekeeper' },
    });
    const latencyMs = Math.round((performance.now() - started) * 100) / 100;
    let output;
    if (officialProtocol) {
      const rawAnswer = String(response.text || '').trim();
      validation = {
        valid: rawAnswer.length > 0 && rawAnswer.length <= 8000,
        reason: rawAnswer.length === 0 ? 'answer_missing' : rawAnswer.length > 8000 ? 'answer_too_long' : null,
      };
      if (!validation.valid) throw new Error('generator_semantic_contract_invalid');
      output = {
        schema: 'hom.locomo-official-answer/v1',
        raw_answer: rawAnswer,
        answer: normalizeOfficialLocomoPrediction(rawAnswer, input),
      };
    } else {
      output = strictObject(response.text, 'generator_response');
      validation = validateGeneratorOutputDetailed(output, evidence);
      if (!validation.valid) throw new Error('generator_semantic_contract_invalid');
    }
    const provider = providerEvidence(response, GENERATOR_MODEL, 'medium');
    immutableJson(path.join(directory, 'generator-request.json'), {
      protocol: args.protocol,
      ...(officialProtocol ? { protocol_manifest: officialLocomoProtocolManifest() } : {}),
      system_prompt: systemPrompt || null,
      user_prompt: userPrompt,
      prompt_sha256: sha256(Buffer.from(`${systemPrompt}\n${userPrompt}`, 'utf8')),
      schema: officialProtocol ? null : GENERATOR_SCHEMA,
      schema_sha256: officialProtocol ? null : canonicalSha256(GENERATOR_SCHEMA),
      recall_attempt_complete_sha256: recall.complete.complete_sha256,
    });
    immutableJson(path.join(directory, 'answer.json'), output);
    immutableJson(path.join(directory, 'provider-evidence.json'), provider);
    immutableJson(path.join(directory, 'timings.json'), { latency_ms: latencyMs });
    completeAttempt(directory, 'generate');
    return { reused: false, directory };
  } catch (error) {
    if (response) {
      immutableJson(path.join(directory, 'rejected-provider-output.json'), rejectedProviderOutputArtifact({
        response,
        requestedModel: GENERATOR_MODEL,
        reasoningEffort: 'medium',
        systemPrompt,
        userPrompt,
        responseSchema,
        validation,
        error,
      }));
    }
    writeFailure(directory, 'generate', error);
    throw error;
  }
}

async function judgeOne(args, entry) {
  const input = readJson(path.join(args.runDir, 'questions', entry.unit_id, 'input.json'));
  const gold = readJson(path.join(args.runDir, 'gold', `${entry.unit_id}.json`));
  if (canonicalSha256(input) !== entry.input_sha256 || canonicalSha256(gold) !== entry.gold_sha256) {
    throw new Error('query_or_gold_hash_mismatch');
  }
  const generated = successfulAttempt(args, entry, 'generate');
  if (!generated) throw new Error('generated_answer_attempt_missing');
  const answer = readJson(path.join(generated.directory, 'answer.json'));
  const directory = newAttempt(args, entry, 'judge');
  const userPrompt = buildJudgePrompt(input, gold, answer);
  let response = null;
  let validation = null;
  try {
    const started = performance.now();
    response = await runProvider({
      provider: 'codex',
      model: JUDGE_MODEL,
      systemPrompt: JUDGE_SYSTEM_PROMPT,
      userPrompt,
      reasoningEffort: args.judgeReasoning,
      textVerbosity: 'low',
      responseSchema: { name: 'hom_benchmark_judge', schema: JUDGE_SCHEMA },
      returnMetadata: true,
      useContext: { subjectAgentId: 'housekeeper' },
    });
    const latencyMs = Math.round((performance.now() - started) * 100) / 100;
    const output = strictObject(response.text, 'judge_response');
    validation = validateJudgeOutputDetailed(output);
    if (!validation.valid) {
      throw new Error('judge_semantic_contract_invalid');
    }
    const provider = providerEvidence(response, JUDGE_MODEL, args.judgeReasoning);
    immutableJson(path.join(directory, 'judge-request.json'), {
      system_prompt: JUDGE_SYSTEM_PROMPT,
      user_prompt: userPrompt,
      prompt_sha256: sha256(Buffer.from(`${JUDGE_SYSTEM_PROMPT}\n${userPrompt}`, 'utf8')),
      schema: JUDGE_SCHEMA,
      schema_sha256: canonicalSha256(JUDGE_SCHEMA),
      generated_attempt_complete_sha256: generated.complete.complete_sha256,
    });
    immutableJson(path.join(directory, 'verdict.json'), output);
    immutableJson(path.join(directory, 'provider-evidence.json'), provider);
    immutableJson(path.join(directory, 'timings.json'), { latency_ms: latencyMs });
    completeAttempt(directory, 'judge');
    return { reused: false, directory };
  } catch (error) {
    if (response) {
      immutableJson(path.join(directory, 'rejected-provider-output.json'), rejectedProviderOutputArtifact({
        response,
        requestedModel: JUDGE_MODEL,
        reasoningEffort: args.judgeReasoning,
        systemPrompt: JUDGE_SYSTEM_PROMPT,
        userPrompt,
        responseSchema: JUDGE_SCHEMA,
        validation,
        error,
      }));
    }
    writeFailure(directory, 'judge', error);
    throw error;
  }
}

function stageSummary(args, selection, completed, reused, failures) {
  const summary = {
    schema: 'hom.canonical-query-phase-summary/v1',
    run_id: args.runId,
    benchmark: args.benchmark,
    protocol: args.protocol,
    phase: args.phase,
    selected: selection.question_count,
    completed,
    reused,
    failures,
    missing: selection.question_count - completed,
  };
  summary.summary_sha256 = selfHash(summary, 'summary_sha256');
  const file = path.join(args.runDir, `phase-${args.phase}-${args.benchmark}-${Date.now()}.json`);
  immutableJson(file, summary);
  return { file, summary };
}

async function executePhase(args) {
  const selection = loadSelection(args);
  if (args.phase === 'recall') await scratchHealth(args);
  if (['generate', 'judge'].includes(args.phase)) await ensureProviderRuntime();
  let completed = 0;
  let reused = 0;
  const failures = [];
  for (const entry of selection.entries) {
    const prior = successfulAttempt(args, entry, args.phase);
    if (prior) {
      completed += 1;
      reused += 1;
      continue;
    }
    let succeeded = false;
    for (let attempt = 1; attempt <= args.retries; attempt += 1) {
      try {
        if (args.phase === 'recall') await recallOne(args, entry);
        else if (args.phase === 'generate') await generateOne(args, entry);
        else await judgeOne(args, entry);
        completed += 1;
        succeeded = true;
        break;
      } catch (error) {
        const retryable = isRetryablePhaseFailure(error, args.phase);
        if (!retryable || attempt === args.retries) {
          failures.push({
            question_id: entry.question_id,
            attempts: attempt,
            retryable,
            ...safeFailure(error),
          });
          break;
        }
        const delay = retryDelayMs(args, attempt);
        console.log(JSON.stringify({
          event: 'benchmark_unit_retry',
          benchmark: args.benchmark,
          phase: args.phase,
          question_id: entry.question_id,
          failed_attempt: attempt,
          next_attempt: attempt + 1,
          delay_ms: delay,
          error: safeFailure(error),
        }));
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    if (!succeeded && failures.at(-1)?.question_id !== entry.question_id) {
      throw new Error(`benchmark_retry_state_invalid:${entry.question_id}`);
    }
    if (args.delayMs) await new Promise((resolve) => setTimeout(resolve, args.delayMs));
  }
  const summary = stageSummary(args, selection, completed, reused, failures);
  console.log(JSON.stringify({ success: failures.length === 0, summary_file: summary.file, ...summary.summary }, null, 2));
  if (failures.length) process.exitCode = 1;
}

async function main() {
  const args = parseArgs(process.argv);
  if (fs.existsSync(args.runDir) && fs.lstatSync(args.runDir).isSymbolicLink()) {
    throw new Error('run_dir_symlink_forbidden');
  }
  if (args.phase === 'prepare') prepare(args);
  else await executePhase(args);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
    .catch((error) => {
      console.error(error?.stack || error);
      process.exitCode = 1;
    })
    .finally(async () => {
      await Promise.allSettled([pool.end(), agentPool.end()]);
    });
}
