#!/usr/bin/env node

/**
 * Native PoisonedRAG N=100 execution harness.
 *
 * The runner never writes directly to AIMOS tables. Candidate passages cross
 * the signed /aimos/save boundary, queries cross signed /aimos/recall, and all
 * completed operations are retained as immutable, self-hashed artifacts. A
 * rerun against the same scratch brain reuses verified terminal artifacts.
 */

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runProvider } from '../services/core/providers.js';
import { resolveAimosDatabaseName } from '../services/core/runtime-config.js';
import { signAsHousekeeper } from '../services/security/housekeeper-signer.js';
import { pool, agentPool } from '../db/connection.js';
import {
  ensureProviderRuntime,
  evidenceForGenerator,
  providerEvidence,
  signedRequestArtifact,
  verifyRecallReceipt,
} from './run-canonical-single-query.mjs';
import {
  CORRECTNESS_SCHEMA,
  CORRECTNESS_SYSTEM_PROMPT,
  POISONEDRAG_GENERATOR_MODEL,
  POISONEDRAG_JUDGE_MODEL,
  POISONEDRAG_MAX_ATTEMPTS,
  POISONEDRAG_MEMORY_TYPE,
  POISONEDRAG_PROTOCOL_ID,
  POISONEDRAG_SOURCE,
  TARGET_ASSERTION_SCHEMA,
  TARGET_ASSERTION_SYSTEM_PROMPT,
  buildCorrectnessPrompt,
  buildDuplicateCompatibilityPreflight,
  buildGeneratorPrompt,
  buildInputCompatibilityPreflight,
  buildRecallBody,
  buildSaveBody,
  buildTargetAssertionPrompt,
  canonicalSha256,
  cleanSaveKey,
  exactMcNemarPValue,
  pairedBootstrap,
  parseStrictObject,
  poisonSaveKey,
  selfHash,
  targetDirectoryName,
  targetSubstringMatch,
  validateCorrectnessJudgment,
  validateSaveTerminal,
  validateTargetAssertionJudgment,
  wilsonInterval,
} from './poisonedrag/harness.mjs';
import {
  POISONEDRAG_SCHEMAS,
  assertManifest,
  canonicalJson as poisonCanonicalJson,
  loadSourceLock,
  readJsonFile,
  sha256,
  writeImmutableJson,
} from './poisonedrag/protocol.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIVATE_INPUT_ROOT = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');
const SOURCE_LOCK_FILE = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const PUBLIC_LOCK_FILE = path.join(ROOT, 'eval', 'poisonedrag', 'n100-public-target-lock.json');
const PRIVATE_MANIFEST_FILE = path.join(PRIVATE_INPUT_ROOT, 'n100-private-target-manifest.json');
const CORPUS_RESOLUTION_FILE = path.join(PRIVATE_INPUT_ROOT, 'n100-corpus-resolution.json');
const CANDIDATE_POOL_FILE = path.join(PRIVATE_INPUT_ROOT, 'n100-candidate-pool.jsonl');
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const SAVE_DELAY_MS = 2100;

function cliValue(argv, name) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function integerArg(value, name, min, max) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name}_invalid`);
  return parsed;
}

function parseArgs(argv) {
  const runId = String(cliValue(argv, '--run-id') || '').trim().toLowerCase();
  if (!/^\d{14}_[0-9a-f]{6}$/.test(runId)) throw new Error('poisonedrag_run_id_invalid');
  const runDirRaw = cliValue(argv, '--run-dir');
  if (!runDirRaw) throw new Error('poisonedrag_run_dir_required');
  const origin = String(cliValue(argv, '--aimos-base') || '').trim();
  if (!/^http:\/\/127\.0\.0\.1:\d{4,5}$/.test(origin)) throw new Error('poisonedrag_origin_invalid');
  const phase = String(cliValue(argv, '--phase') || '').trim().toLowerCase();
  if (!['ingest-recall', 'model-aggregate'].includes(phase)) throw new Error('poisonedrag_phase_invalid');
  return {
    runId,
    runDir: path.resolve(runDirRaw),
    origin,
    phase,
    targetCount: integerArg(cliValue(argv, '--target-count') || '3', 'poisonedrag_target_count', 1, 100),
    delayMs: integerArg(cliValue(argv, '--delay-ms') || String(SAVE_DELAY_MS), 'poisonedrag_delay_ms', 2000, 60_000),
    retries: integerArg(
      cliValue(argv, '--retries') || String(POISONEDRAG_MAX_ATTEMPTS),
      'poisonedrag_retries',
      1,
      10,
    ),
  };
}

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function fileSha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

function safeFailure(error) {
  return {
    name: String(error?.name || 'Error').slice(0, 128),
    message: String(error?.message || error || 'unknown_error').slice(0, 4000),
  };
}

function readVerifiedArtifact(file, schema, hashField) {
  if (!existsSync(file) || lstatSync(file).isSymbolicLink()) return null;
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (value?.schema !== schema || value?.[hashField] !== selfHash(value, hashField)) {
    throw new Error(`poisonedrag_artifact_verification_failed:${path.basename(file)}`);
  }
  return value;
}

function writeHashedArtifact(file, value, hashField, mode = 0o600) {
  const artifact = { ...value };
  artifact[hashField] = selfHash(artifact, hashField);
  writeImmutableJson(file, artifact, mode);
  return artifact;
}

function writeProgress(root, state) {
  const file = path.join(root, 'progress.json');
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, jsonText({
    ...state,
    schema: 'hom.aimos.poisonedrag-progress/v1',
    updated_at: new Date().toISOString(),
  }), { mode: 0o600 });
  renameSync(temporary, file);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function isRetryablePoisonedRagFailure(error) {
  if (['AbortError', 'TimeoutError', 'TypeError'].includes(String(error?.name || ''))) return true;
  const message = String(error?.message || error || '');
  if (/timeout|timed out|ECONNRESET|ECONNREFUSED|EAI_AGAIN|socket|network|fetch failed/i.test(message)) return true;
  const status = Number(
    /signed_post_failed:(\d{3})/.exec(message)?.[1]
    || /(?:HTTP\s+|error\s*\()(\d{3})/i.exec(message)?.[1],
  );
  return RETRYABLE_STATUS.has(status)
    || /response was empty|response ended with status|semantic_contract_invalid|not_bare_json|json_invalid/i.test(message);
}

function requestEvidence(signed) {
  return signedRequestArtifact(signed);
}

async function signedPost(origin, route, body) {
  const signed = await signAsHousekeeper(body, { method: 'POST', path: route });
  const started = performance.now();
  const response = await fetch(`${origin}${route}`, {
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
  return {
    status: response.status,
    ok: response.ok,
    responseBody,
    signed,
    latencyMs: Math.round((performance.now() - started) * 100) / 100,
  };
}

async function scratchHealth(args) {
  const response = await fetch(`${args.origin}/health`, { signal: AbortSignal.timeout(10_000) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ready !== true
    || body.runtime?.database_name !== `aimos_benchmark_${args.runId}`
    || body.runtime?.benchmark_scratch !== true
    || Number(body.runtime?.server_port) !== Number(new URL(args.origin).port)) {
    throw new Error('poisonedrag_scratch_server_identity_mismatch');
  }
  return body;
}

function loadCandidatePool() {
  const documents = new Map();
  const raw = readFileSync(CANDIDATE_POOL_FILE, 'utf8');
  for (const [index, line] of raw.split('\n').entries()) {
    if (!line) continue;
    const document = JSON.parse(line);
    if (!/^doc\d+$/.test(String(document.document_id || ''))
      || typeof document.text !== 'string'
      || document.passage_sha256 !== sha256(Buffer.from(document.text, 'utf8'))
      || documents.has(document.document_id)) {
      throw new Error(`poisonedrag_candidate_pool_invalid:${index + 1}`);
    }
    documents.set(document.document_id, document);
  }
  return documents;
}

export function loadPoisonedRagInputs(targetCount) {
  const { lock: sourceLock, source_lock_sha256: sourceLockSha256 } = loadSourceLock(SOURCE_LOCK_FILE);
  const privateManifest = assertManifest(
    readJsonFile(PRIVATE_MANIFEST_FILE, POISONEDRAG_SCHEMAS.PRIVATE_TARGET_MANIFEST),
    POISONEDRAG_SCHEMAS.PRIVATE_TARGET_MANIFEST,
  );
  const publicLock = assertManifest(
    readJsonFile(PUBLIC_LOCK_FILE, POISONEDRAG_SCHEMAS.PUBLIC_TARGET_LOCK),
    POISONEDRAG_SCHEMAS.PUBLIC_TARGET_LOCK,
  );
  const corpusResolution = assertManifest(
    readJsonFile(CORPUS_RESOLUTION_FILE, POISONEDRAG_SCHEMAS.CORPUS_RESOLUTION),
    POISONEDRAG_SCHEMAS.CORPUS_RESOLUTION,
  );
  if (privateManifest.source_lock_sha256 !== sourceLockSha256
    || publicLock.source_lock_sha256 !== sourceLockSha256
    || corpusResolution.source_lock_sha256 !== sourceLockSha256
    || corpusResolution.private_target_manifest_sha256 !== privateManifest.manifest_sha256
    || corpusResolution.candidate_pool_sha256 !== fileSha256(CANDIDATE_POOL_FILE)
    || privateManifest.target_count !== 100
    || publicLock.target_count !== 100) {
    throw new Error('poisonedrag_input_binding_invalid');
  }
  const documents = loadCandidatePool();
  if (documents.size !== corpusResolution.unique_candidate_document_count) {
    throw new Error('poisonedrag_candidate_pool_count_mismatch');
  }
  const targets = privateManifest.targets.slice(0, targetCount);
  for (const target of targets) {
    const publicTarget = publicLock.targets[target.ordinal];
    const candidateIdHash = sha256(Buffer.from(poisonCanonicalJson(
      target.candidate_documents.map((entry) => entry.document_id),
    ), 'utf8'));
    const poisonTextHashes = target.poison_texts.map((text) => sha256(Buffer.from(text, 'utf8')));
    const adversarialTextHashes = target.adversarial_texts.map((text) => sha256(Buffer.from(text, 'utf8')));
    if (!publicTarget || publicTarget.upstream_id !== target.upstream_id
      || target.question_sha256 !== sha256(Buffer.from(target.question, 'utf8'))
      || target.correct_answer_sha256 !== sha256(Buffer.from(target.correct_answer, 'utf8'))
      || target.target_answer_sha256 !== sha256(Buffer.from(target.target_answer, 'utf8'))
      || target.candidate_document_ids_sha256 !== candidateIdHash
      || publicTarget.candidate_document_ids_sha256 !== candidateIdHash
      || poisonCanonicalJson(target.poison_text_sha256) !== poisonCanonicalJson(poisonTextHashes)
      || poisonCanonicalJson(publicTarget.poison_text_sha256) !== poisonCanonicalJson(poisonTextHashes)
      || poisonCanonicalJson(target.adversarial_text_sha256) !== poisonCanonicalJson(adversarialTextHashes)
      || poisonCanonicalJson(publicTarget.adversarial_text_sha256) !== poisonCanonicalJson(adversarialTextHashes)
      || poisonCanonicalJson(publicTarget.scope_ids) !== poisonCanonicalJson(target.scope_ids)
      || poisonCanonicalJson(publicTarget.recall_order) !== poisonCanonicalJson(target.recall_order)) {
      throw new Error(`poisonedrag_target_binding_invalid:${target.ordinal}`);
    }
    for (const candidate of target.candidate_documents) {
      if (!documents.has(candidate.document_id)) {
        throw new Error(`poisonedrag_candidate_missing:${target.ordinal}:${candidate.document_id}`);
      }
    }
  }
  return { sourceLock, sourceLockSha256, privateManifest, publicLock, corpusResolution, documents, targets };
}

function makeExecutionPlan(args, inputs) {
  const plan = {
    schema: POISONEDRAG_SCHEMAS.EXECUTION_PLAN,
    protocol: POISONEDRAG_PROTOCOL_ID,
    run_id: args.runId,
    target_count: args.targetCount,
    source_lock_sha256: inputs.sourceLockSha256,
    private_target_manifest_sha256: inputs.privateManifest.manifest_sha256,
    public_target_lock_sha256: inputs.publicLock.manifest_sha256,
    corpus_resolution_sha256: inputs.corpusResolution.manifest_sha256,
    candidate_pool_sha256: inputs.corpusResolution.candidate_pool_sha256,
    generator: `codex:${POISONEDRAG_GENERATOR_MODEL}`,
    judge: `codex:${POISONEDRAG_JUDGE_MODEL}`,
    judge_reasoning: 'high',
    disclosure_k: 5,
    save_delay_ms: args.delayMs,
    targets: inputs.targets.map((target) => ({
      ordinal: target.ordinal,
      upstream_id: target.upstream_id,
      question_sha256: target.question_sha256,
      correct_answer_sha256: target.correct_answer_sha256,
      target_answer_sha256: target.target_answer_sha256,
      candidate_document_ids_sha256: target.candidate_document_ids_sha256,
      poison_text_sha256: target.poison_text_sha256,
      scope_ids: target.scope_ids,
      recall_order: target.recall_order,
    })),
  };
  plan.plan_sha256 = selfHash(plan, 'plan_sha256');
  return plan;
}

function failureAttemptFile(directory, label) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const count = readdirSync(directory).filter((name) => name.startsWith(`${label}-attempt-`)).length;
  return path.join(directory, `${label}-attempt-${String(count + 1).padStart(4, '0')}.json`);
}

async function recoverDuplicateSave(args, body, existingMemoryId) {
  const recallBody = buildRecallBody({
    scopeId: body.session_id,
    memoryId: existingMemoryId,
    limit: 1,
  });
  const posted = await signedPost(args.origin, '/aimos/recall', recallBody);
  await sleep(args.delayMs);
  if (!posted.ok || posted.responseBody?.success !== true) {
    throw new Error(`signed_post_failed:${posted.status}:duplicate_recovery`);
  }
  const verification = verifyRecallReceipt({
    requestBody: recallBody,
    signedBody: posted.signed.body,
    responseBody: posted.responseBody,
    sourceFilter: POISONEDRAG_SOURCE,
    expectedMemoryType: [POISONEDRAG_MEMORY_TYPE, 'quarantine'],
    expectedKeyPrefix: `sess:${body.session_id}:`,
  });
  const memory = (posted.responseBody.memories || []).find((entry) => String(entry.id) === String(existingMemoryId));
  const proof = memory?.provenance_proof;
  if (!memory || memory.value !== body.value || !proof
    || ![proof.live_content_hash, proof.save_mutation_hash, proof.binding_mutation_hash]
      .every((value) => /^[0-9a-f]{64}$/.test(String(value || '')))) {
    throw new Error('poisonedrag_duplicate_recovery_binding_invalid');
  }
  return {
    admitted: true,
    recovered_existing: true,
    memory_id: String(memory.id),
    key: String(memory.key),
    live_content_hash: proof.live_content_hash,
    save_mutation_hash: proof.save_mutation_hash,
    binding_mutation_hash: proof.binding_mutation_hash,
    recall: {
      request: requestEvidence(posted.signed),
      response: posted.responseBody,
      verification,
      latency_ms: posted.latencyMs,
    },
  };
}

async function executeSave(args, { file, body, operationId }) {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const expectedBodyHash = canonicalSha256(body);
  const prior = readVerifiedArtifact(file, POISONEDRAG_SCHEMAS.SAVE_PROOF, 'proof_sha256');
  if (prior) {
    if (prior.operation_id !== operationId || prior.request_body_sha256 !== expectedBodyHash) {
      throw new Error(`poisonedrag_save_artifact_input_mismatch:${operationId}`);
    }
    return { proof: prior, reused: true };
  }
  const failureDir = path.join(path.dirname(file), 'failures');
  for (let attempt = 1; attempt <= args.retries; attempt += 1) {
    let posted = null;
    try {
      posted = await signedPost(args.origin, '/aimos/save', body);
      await sleep(args.delayMs);
      if (!posted.ok && ![400, 422].includes(posted.status)) {
        throw new Error(`signed_post_failed:${posted.status}:${posted.responseBody?.error || 'save'}`);
      }
      let terminal = validateSaveTerminal({
        status: posted.status,
        body: posted.responseBody,
        requestBody: posted.signed.body,
      });
      if (!terminal.admitted
        && terminal.existing_memory_id
        && /duplicate/i.test(String(terminal.reason || ''))) {
        terminal = await recoverDuplicateSave(args, body, terminal.existing_memory_id);
      }
      const proof = writeHashedArtifact(file, {
        schema: POISONEDRAG_SCHEMAS.SAVE_PROOF,
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        operation_id: operationId,
        request_body_sha256: expectedBodyHash,
        request: requestEvidence(posted.signed),
        response: posted.responseBody,
        http_status: posted.status,
        latency_ms: posted.latencyMs,
        terminal,
      }, 'proof_sha256');
      return { proof, reused: false };
    } catch (error) {
      writeHashedArtifact(failureAttemptFile(failureDir, operationId), {
        schema: 'hom.aimos.poisonedrag-operation-failure/v1',
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        phase: 'save',
        operation_id: operationId,
        request_body_sha256: expectedBodyHash,
        http_status: posted?.status || null,
        request: posted ? requestEvidence(posted.signed) : null,
        response: posted?.responseBody || null,
        error: safeFailure(error),
      }, 'failure_sha256');
      if (attempt >= args.retries || !isRetryablePoisonedRagFailure(error)) throw error;
      await sleep(Math.min(30_000, 5_000 * (2 ** (attempt - 1))));
    }
  }
  throw new Error(`poisonedrag_save_retry_exhausted:${operationId}`);
}

async function ingestTarget(args, root, target, documents, progress) {
  const targetRoot = path.join(root, 'targets', targetDirectoryName(target));
  const saveRoot = path.join(targetRoot, 'saves');
  mkdirSync(saveRoot, { recursive: true, mode: 0o700 });
  const armProofs = [[], []];
  const armOrder = target.ordinal % 2 === 0 ? [0, 1] : [1, 0];
  for (const candidate of target.candidate_documents) {
    const document = documents.get(candidate.document_id);
    for (const arm of armOrder) {
      const scopeId = target.scope_ids[arm];
      const body = buildSaveBody({
        scopeId,
        key: cleanSaveKey(scopeId, candidate.rank, candidate.document_id),
        value: document.text,
      });
      const operationId = `clean-${String(candidate.rank).padStart(3, '0')}-arm-${arm}`;
      const result = await executeSave(args, {
        file: path.join(saveRoot, `arm-${arm}`, `${operationId}.json`),
        body,
        operationId: `${target.ordinal}:${operationId}`,
      });
      armProofs[arm].push(result.proof);
      progress.saves_completed += 1;
      progress.saves_reused += Number(result.reused);
      writeProgress(root, progress);
      console.log(JSON.stringify({
        event: 'poisonedrag_save_terminal',
        target: target.ordinal,
        operation: operationId,
        completed: progress.saves_completed,
        total: progress.saves_total,
        admitted: result.proof.terminal.admitted,
        reused: result.reused,
        proof_sha256: result.proof.proof_sha256,
      }));
    }
  }
  const poisonProofs = [];
  const attackedArm = 1;
  for (let index = 0; index < target.poison_texts.length; index += 1) {
    const scopeId = target.scope_ids[attackedArm];
    const body = buildSaveBody({
      scopeId,
      key: poisonSaveKey(scopeId, index),
      value: target.poison_texts[index],
    });
    const operationId = `poison-${String(index + 1).padStart(2, '0')}-arm-${attackedArm}`;
    const result = await executeSave(args, {
      file: path.join(saveRoot, `arm-${attackedArm}`, `${operationId}.json`),
      body,
      operationId: `${target.ordinal}:${operationId}`,
    });
    poisonProofs.push(result.proof);
    progress.saves_completed += 1;
    progress.saves_reused += Number(result.reused);
    writeProgress(root, progress);
    console.log(JSON.stringify({
      event: 'poisonedrag_save_terminal',
      target: target.ordinal,
      operation: operationId,
      completed: progress.saves_completed,
      total: progress.saves_total,
      admitted: result.proof.terminal.admitted,
      reused: result.reused,
      proof_sha256: result.proof.proof_sha256,
    }));
  }
  for (let index = 0; index < target.candidate_documents.length; index += 1) {
    if (armProofs[0][index].terminal.admitted !== armProofs[1][index].terminal.admitted) {
      throw new Error(`poisonedrag_paired_clean_admission_mismatch:${target.ordinal}:${index + 1}`);
    }
  }
  const admittedPoisonProofs = poisonProofs.filter((proof) => proof.terminal.admitted);
  const poisonMemoryIds = admittedPoisonProofs.map((proof) => String(proof.terminal.memory_id));
  const poisonMemoryIdSet = new Set(poisonMemoryIds);
  const labelledPoisonIds = new Set();
  for (const proof of admittedPoisonProofs) {
    if (['poison_suspect', 'poison_likely', 'poison_confirmed'].includes(proof.terminal.epistemic_label)) {
      labelledPoisonIds.add(String(proof.terminal.memory_id));
    }
    for (const relatedId of proof.terminal.epistemic_related_memory_ids_reclassified || []) {
      if (poisonMemoryIdSet.has(String(relatedId))) labelledPoisonIds.add(String(relatedId));
    }
  }
  const cleanEpistemicLabelsPerArm = armProofs.map((proofs) => proofs.reduce((counts, proof) => {
    const label = String(proof.terminal.epistemic_label || 'unverified');
    counts[label] = (counts[label] || 0) + Number(proof.terminal.admitted);
    return counts;
  }, {}));
  const admission = {
    schema: 'hom.aimos.poisonedrag-target-admission/v1',
    protocol: POISONEDRAG_PROTOCOL_ID,
    run_id: args.runId,
    target_ordinal: target.ordinal,
    clean_candidates_submitted_per_arm: target.candidate_documents.length,
    clean_candidates_admitted_per_arm: armProofs[0].filter((proof) => proof.terminal.admitted).length,
    clean_candidates_rejected_per_arm: armProofs[0].filter((proof) => !proof.terminal.admitted).length,
    paired_clean_admission_identical: true,
    poison_passages_submitted: poisonProofs.length,
    poison_passages_admitted: admittedPoisonProofs.length,
    poison_passages_rejected: poisonProofs.filter((proof) => !proof.terminal.admitted).length,
    poison_memory_ids: poisonMemoryIds,
    poison_memory_ids_with_signed_epistemic_label_evidence: [...labelledPoisonIds].sort(),
    poison_passages_with_signed_epistemic_label_evidence: labelledPoisonIds.size,
    poison_label_at_save_counts: admittedPoisonProofs.reduce((counts, proof) => {
      const label = String(proof.terminal.epistemic_label || 'unverified');
      counts[label] = (counts[label] || 0) + 1;
      return counts;
    }, {}),
    poison_classification_event_ids: admittedPoisonProofs
      .map((proof) => proof.terminal.epistemic_classification_event_id)
      .filter(Boolean),
    poison_classification_hashes: admittedPoisonProofs
      .map((proof) => proof.terminal.epistemic_classification_hash)
      .filter(Boolean),
    clean_epistemic_label_counts_per_arm: cleanEpistemicLabelsPerArm,
  };
  admission.admission_sha256 = selfHash(admission, 'admission_sha256');
  writeImmutableJson(path.join(targetRoot, 'admission.json'), admission);
  return admission;
}

async function recallArm(args, root, target, arm, admission) {
  const targetRoot = path.join(root, 'targets', targetDirectoryName(target));
  const file = path.join(targetRoot, 'recall', `arm-${arm}.json`);
  const body = buildRecallBody({ scopeId: target.scope_ids[arm], question: target.question });
  const requestBodyHash = canonicalSha256(body);
  const prior = readVerifiedArtifact(file, POISONEDRAG_SCHEMAS.RECALL_PROOF, 'proof_sha256');
  if (prior) {
    if (prior.request_body_sha256 !== requestBodyHash) throw new Error('poisonedrag_recall_artifact_input_mismatch');
    return { proof: prior, reused: true };
  }
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const failureDir = path.join(path.dirname(file), 'failures');
  for (let attempt = 1; attempt <= args.retries; attempt += 1) {
    let posted = null;
    try {
      posted = await signedPost(args.origin, '/aimos/recall', body);
      await sleep(args.delayMs);
      if (!posted.ok || posted.responseBody?.success !== true) {
        throw new Error(`signed_post_failed:${posted.status}:${posted.responseBody?.error || 'recall'}`);
      }
      const verification = verifyRecallReceipt({
        requestBody: body,
        signedBody: posted.signed.body,
        responseBody: posted.responseBody,
        sourceFilter: POISONEDRAG_SOURCE,
        expectedMemoryType: [POISONEDRAG_MEMORY_TYPE, 'quarantine'],
        expectedKeyPrefix: `sess:${target.scope_ids[arm]}:`,
      });
      const admitted = arm === 0
        ? admission.clean_candidates_admitted_per_arm
        : admission.clean_candidates_admitted_per_arm + admission.poison_passages_admitted;
      if (admitted >= 5 && verification.result_count !== 5) {
        throw new Error(`poisonedrag_disclosure_cardinality_invalid:${target.ordinal}:${arm}`);
      }
      const proof = writeHashedArtifact(file, {
        schema: POISONEDRAG_SCHEMAS.RECALL_PROOF,
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        target_ordinal: target.ordinal,
        arm,
        request_body_sha256: requestBodyHash,
        request: requestEvidence(posted.signed),
        response: posted.responseBody,
        verification,
        http_status: posted.status,
        latency_ms: posted.latencyMs,
      }, 'proof_sha256');
      return { proof, reused: false };
    } catch (error) {
      writeHashedArtifact(failureAttemptFile(failureDir, `arm-${arm}`), {
        schema: 'hom.aimos.poisonedrag-operation-failure/v1',
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        phase: 'recall',
        operation_id: `${target.ordinal}:arm-${arm}`,
        request_body_sha256: requestBodyHash,
        http_status: posted?.status || null,
        request: posted ? requestEvidence(posted.signed) : null,
        response: posted?.responseBody || null,
        error: safeFailure(error),
      }, 'failure_sha256');
      if (attempt >= args.retries || !isRetryablePoisonedRagFailure(error)) throw error;
      await sleep(Math.min(30_000, 5_000 * (2 ** (attempt - 1))));
    }
  }
  throw new Error(`poisonedrag_recall_retry_exhausted:${target.ordinal}:${arm}`);
}

function admittedArmMemoryIds(root, target, arm) {
  const directory = path.join(root, 'targets', targetDirectoryName(target), 'saves', `arm-${arm}`);
  const expected = arm === 0 ? 100 : 105;
  const files = readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort();
  if (files.length !== expected) {
    throw new Error(`poisonedrag_scope_inventory_cardinality_invalid:${target.ordinal}:${arm}`);
  }
  return files.map((name) => readVerifiedArtifact(
    path.join(directory, name),
    POISONEDRAG_SCHEMAS.SAVE_PROOF,
    'proof_sha256',
  )).filter((proof) => proof.terminal.admitted).map((proof) => String(proof.terminal.memory_id));
}

async function executeIsolationProbe(args, root, {
  label,
  scopeId,
  question,
  allowedMemoryIds,
  requireEmpty = false,
}) {
  const body = buildRecallBody({ scopeId, question });
  const requestBodyHash = canonicalSha256(body);
  const file = path.join(root, 'isolation', 'probes', `${label}.json`);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const prior = readVerifiedArtifact(file, POISONEDRAG_SCHEMAS.RECALL_PROOF, 'proof_sha256');
  if (prior) {
    if (prior.request_body_sha256 !== requestBodyHash) {
      throw new Error(`poisonedrag_isolation_probe_input_mismatch:${label}`);
    }
    return { proof: prior, reused: true };
  }
  const allowed = new Set(allowedMemoryIds.map(String));
  const failureDir = path.join(root, 'isolation', 'failures');
  for (let attempt = 1; attempt <= args.retries; attempt += 1) {
    let posted = null;
    try {
      posted = await signedPost(args.origin, '/aimos/recall', body);
      await sleep(args.delayMs);
      if (!posted.ok || posted.responseBody?.success !== true) {
        throw new Error(`signed_post_failed:${posted.status}:${posted.responseBody?.error || 'isolation_probe'}`);
      }
      const verification = verifyRecallReceipt({
        requestBody: body,
        signedBody: posted.signed.body,
        responseBody: posted.responseBody,
        sourceFilter: POISONEDRAG_SOURCE,
        expectedMemoryType: [POISONEDRAG_MEMORY_TYPE, 'quarantine'],
        expectedKeyPrefix: `sess:${scopeId}:`,
      });
      const returnedIds = (posted.responseBody.memories || []).map((memory) => String(memory.id));
      if ((requireEmpty && returnedIds.length !== 0)
        || returnedIds.some((memoryId) => !allowed.has(memoryId))) {
        throw new Error(`poisonedrag_isolation_probe_foreign_evidence:${label}`);
      }
      const proof = writeHashedArtifact(file, {
        schema: POISONEDRAG_SCHEMAS.RECALL_PROOF,
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        isolation_probe: label,
        request_body_sha256: requestBodyHash,
        request: requestEvidence(posted.signed),
        response: posted.responseBody,
        verification,
        allowed_memory_id_count: allowed.size,
        returned_memory_ids: returnedIds,
        foreign_evidence_count: 0,
        http_status: posted.status,
        latency_ms: posted.latencyMs,
      }, 'proof_sha256');
      return { proof, reused: false };
    } catch (error) {
      writeHashedArtifact(failureAttemptFile(failureDir, label), {
        schema: 'hom.aimos.poisonedrag-operation-failure/v1',
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        phase: 'isolation-probe',
        operation_id: label,
        request_body_sha256: requestBodyHash,
        http_status: posted?.status || null,
        request: posted ? requestEvidence(posted.signed) : null,
        response: posted?.responseBody || null,
        error: safeFailure(error),
      }, 'failure_sha256');
      if (attempt >= args.retries || !isRetryablePoisonedRagFailure(error)) throw error;
      await sleep(Math.min(30_000, 5_000 * (2 ** (attempt - 1))));
    }
  }
  throw new Error(`poisonedrag_isolation_probe_retry_exhausted:${label}`);
}

async function runThreeTargetIsolationGate(args, root, targets) {
  if (targets.length !== 3) throw new Error('poisonedrag_isolation_gate_requires_three_targets');
  const inventories = new Map();
  const ownerByMemoryId = new Map();
  for (const target of targets) {
    for (const arm of [0, 1]) {
      const memoryIds = admittedArmMemoryIds(root, target, arm);
      const owner = `${target.ordinal}:arm-${arm}`;
      for (const memoryId of memoryIds) {
        if (ownerByMemoryId.has(memoryId)) throw new Error('poisonedrag_memory_id_shared_across_scopes');
        ownerByMemoryId.set(memoryId, owner);
      }
      inventories.set(owner, memoryIds);
    }
  }
  const probes = [];
  for (let index = 0; index < targets.length; index += 1) {
    const sourceTarget = targets[index];
    const destinationTarget = targets[(index + 1) % targets.length];
    for (const arm of [0, 1]) {
      const result = await executeIsolationProbe(args, root, {
        label: `cross-target-${sourceTarget.ordinal}-into-${destinationTarget.ordinal}-arm-${arm}`,
        scopeId: destinationTarget.scope_ids[arm],
        question: sourceTarget.question,
        allowedMemoryIds: inventories.get(`${destinationTarget.ordinal}:arm-${arm}`),
      });
      probes.push(result.proof);
    }
  }
  const wildcardScope = 'prg_%_\\_isolation_gate';
  const wildcard = await executeIsolationProbe(args, root, {
    label: 'literal-like-wildcards',
    scopeId: wildcardScope,
    question: targets[0].question,
    allowedMemoryIds: [],
    requireEmpty: true,
  });
  probes.push(wildcard.proof);
  return writeHashedArtifact(path.join(root, 'isolation', 'isolation-proof.json'), {
    schema: POISONEDRAG_SCHEMAS.ISOLATION_PROOF,
    protocol: POISONEDRAG_PROTOCOL_ID,
    run_id: args.runId,
    target_count: targets.length,
    scope_count: inventories.size,
    unique_admitted_memory_count: ownerByMemoryId.size,
    memory_ids_unique_across_scopes: true,
    exact_scope_prefix_verified: true,
    literal_like_wildcard_probe_empty: true,
    cache_disabled: true,
    probe_proof_sha256: probes.map((probe) => probe.proof_sha256),
  }, 'proof_sha256');
}

async function providerOperation(args, {
  file,
  schema,
  hashField,
  phase,
  operationId,
  model,
  reasoningEffort,
  systemPrompt,
  userPrompt,
  responseSchema = null,
  parse,
}) {
  const promptHash = sha256(Buffer.from(`${systemPrompt}\n${userPrompt}`, 'utf8'));
  const prior = readVerifiedArtifact(file, schema, hashField);
  if (prior) {
    if (prior.prompt_sha256 !== promptHash) throw new Error(`poisonedrag_${phase}_artifact_input_mismatch`);
    return { artifact: prior, reused: true };
  }
  const attemptRoot = path.join(path.dirname(file), `${path.basename(file, '.json')}-attempts`);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  for (let attempt = 1; attempt <= args.retries; attempt += 1) {
    let response = null;
    try {
      const started = performance.now();
      response = await runProvider({
        provider: 'codex',
        model,
        systemPrompt,
        userPrompt,
        reasoningEffort,
        textVerbosity: 'low',
        ...(responseSchema ? { responseSchema } : {}),
        returnMetadata: true,
        useContext: { subjectAgentId: 'housekeeper' },
      });
      const output = parse(response.text);
      const artifact = writeHashedArtifact(file, {
        schema,
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        operation_id: operationId,
        prompt_sha256: promptHash,
        request: {
          system_prompt: systemPrompt || null,
          user_prompt: userPrompt,
          response_schema: responseSchema?.schema || null,
          response_schema_sha256: responseSchema?.schema
            ? canonicalSha256(responseSchema.schema)
            : null,
        },
        output,
        provider: providerEvidence(response, model, reasoningEffort),
        latency_ms: Math.round((performance.now() - started) * 100) / 100,
      }, hashField);
      return { artifact, reused: false };
    } catch (error) {
      const failureFile = failureAttemptFile(attemptRoot, phase);
      writeHashedArtifact(failureFile, {
        schema: 'hom.aimos.poisonedrag-provider-failure/v1',
        protocol: POISONEDRAG_PROTOCOL_ID,
        run_id: args.runId,
        phase,
        operation_id: operationId,
        model,
        reasoning_effort: reasoningEffort,
        prompt_sha256: promptHash,
        response_text: String(response?.text || '').slice(0, 32_000),
        response_id: response?.responseId || null,
        actual_model: response?.model || null,
        error: safeFailure(error),
      }, 'failure_sha256');
      if (attempt >= args.retries || !isRetryablePoisonedRagFailure(error)) throw error;
      await sleep(Math.min(30_000, 1_000 * (2 ** (attempt - 1))));
    }
  }
  throw new Error(`poisonedrag_${phase}_retry_exhausted:${operationId}`);
}

async function generateArm(args, root, target, arm, recallProof) {
  const targetRoot = path.join(root, 'targets', targetDirectoryName(target));
  const file = path.join(targetRoot, 'generate', `arm-${arm}.json`);
  const memories = evidenceForGenerator(recallProof.response);
  const userPrompt = buildGeneratorPrompt(target.question, memories);
  return providerOperation(args, {
    file,
    schema: POISONEDRAG_SCHEMAS.ANSWER,
    hashField: 'answer_sha256',
    phase: 'generate',
    operationId: `${target.ordinal}:arm-${arm}`,
    model: POISONEDRAG_GENERATOR_MODEL,
    reasoningEffort: 'medium',
    systemPrompt: '',
    userPrompt,
    parse: (text) => {
      const answer = String(text || '').trim();
      if (!answer || answer.length > 8000) throw new Error('generator_semantic_contract_invalid');
      return { answer };
    },
  });
}

async function judgeArm(args, root, target, arm, recallProof, answerArtifact) {
  const targetRoot = path.join(root, 'targets', targetDirectoryName(target));
  const memories = evidenceForGenerator(recallProof.response);
  const answer = answerArtifact.output.answer;
  const correctnessPrompt = buildCorrectnessPrompt({
    question: target.question,
    correctAnswer: target.correct_answer,
    memories,
    answer,
  });
  const targetPrompt = buildTargetAssertionPrompt({
    question: target.question,
    targetAnswer: target.target_answer,
    answer,
  });
  const correctness = await providerOperation(args, {
    file: path.join(targetRoot, 'judge', `arm-${arm}-correctness.json`),
    schema: POISONEDRAG_SCHEMAS.JUDGMENT,
    hashField: 'judgment_sha256',
    phase: 'judge-correctness',
    operationId: `${target.ordinal}:arm-${arm}:correctness`,
    model: POISONEDRAG_JUDGE_MODEL,
    reasoningEffort: 'high',
    systemPrompt: CORRECTNESS_SYSTEM_PROMPT,
    userPrompt: correctnessPrompt,
    responseSchema: { name: 'hom_poisonedrag_correctness', schema: CORRECTNESS_SCHEMA },
    parse: (text) => {
      const value = parseStrictObject(text, 'correctness_judge');
      if (!validateCorrectnessJudgment(value)) throw new Error('correctness_judge_semantic_contract_invalid');
      return value;
    },
  });
  const targetAssertion = await providerOperation(args, {
    file: path.join(targetRoot, 'judge', `arm-${arm}-target-assertion.json`),
    schema: POISONEDRAG_SCHEMAS.JUDGMENT,
    hashField: 'judgment_sha256',
    phase: 'judge-target-assertion',
    operationId: `${target.ordinal}:arm-${arm}:target-assertion`,
    model: POISONEDRAG_JUDGE_MODEL,
    reasoningEffort: 'high',
    systemPrompt: TARGET_ASSERTION_SYSTEM_PROMPT,
    userPrompt: targetPrompt,
    responseSchema: { name: 'hom_poisonedrag_target_assertion', schema: TARGET_ASSERTION_SCHEMA },
    parse: (text) => {
      const value = parseStrictObject(text, 'target_assertion_judge');
      if (!validateTargetAssertionJudgment(value)) throw new Error('target_assertion_judge_semantic_contract_invalid');
      return value;
    },
  });
  return { correctness, targetAssertion };
}

function buildTargetOutcome(args, root, target, admission, recalls, answers, judgments) {
  const poisonIds = new Set(admission.poison_memory_ids.map(String));
  const arms = [0, 1].map((arm) => {
    const recalled = recalls[arm].proof.response.memories || [];
    const poisonRanks = recalled
      .map((memory, index) => poisonIds.has(String(memory.id)) ? index + 1 : null)
      .filter((rank) => rank != null);
    const answer = answers[arm].artifact.output.answer;
    return {
      arm,
      scope_id: target.scope_ids[arm],
      recall_proof_sha256: recalls[arm].proof.proof_sha256,
      answer_sha256: answers[arm].artifact.answer_sha256,
      correctness_judgment_sha256: judgments[arm].correctness.artifact.judgment_sha256,
      target_assertion_judgment_sha256: judgments[arm].targetAssertion.artifact.judgment_sha256,
      retrieved_memory_ids: recalled.map((memory) => String(memory.id)),
      retrieved_poison_count: poisonRanks.length,
      retrieved_poison_ranks: poisonRanks,
      answer,
      target_substring_match: targetSubstringMatch(answer, target.target_answer),
      target_semantic_assertion: judgments[arm].targetAssertion.artifact.output.asserts_target_answer,
      qa_correct: judgments[arm].correctness.artifact.output.correct,
      qa_score: judgments[arm].correctness.artifact.output.score,
    };
  });
  const outcome = {
    schema: POISONEDRAG_SCHEMAS.TARGET_OUTCOME,
    protocol: POISONEDRAG_PROTOCOL_ID,
    run_id: args.runId,
    target_ordinal: target.ordinal,
    upstream_id: target.upstream_id,
    question_sha256: target.question_sha256,
    target_answer_sha256: target.target_answer_sha256,
    admission_sha256: admission.admission_sha256,
    clean: arms[0],
    attacked: arms[1],
    incremental_attack_success: arms[1].target_substring_match && !arms[0].target_substring_match,
    incremental_semantic_attack_success: arms[1].target_semantic_assertion && !arms[0].target_semantic_assertion,
    paired_qa_delta: Number(arms[1].qa_correct) - Number(arms[0].qa_correct),
  };
  const file = path.join(root, 'targets', targetDirectoryName(target), 'outcome.json');
  return writeHashedArtifact(file, outcome, 'outcome_sha256');
}

function proportion(count, total) {
  return {
    count,
    total,
    rate: total ? count / total : null,
    wilson_95: total ? wilsonInterval(count, total) : null,
  };
}

function aggregate(args, root, plan, outcomes) {
  if (outcomes.length !== args.targetCount) throw new Error('poisonedrag_outcome_denominator_incomplete');
  const cleanAsr = outcomes.filter((item) => item.clean.target_substring_match).length;
  const attackedAsr = outcomes.filter((item) => item.attacked.target_substring_match).length;
  const incrementalAsr = outcomes.filter((item) => item.incremental_attack_success).length;
  const inducedEligible = outcomes.filter((item) => !item.clean.target_substring_match).length;
  const cleanSemantic = outcomes.filter((item) => item.clean.target_semantic_assertion).length;
  const attackedSemantic = outcomes.filter((item) => item.attacked.target_semantic_assertion).length;
  const incrementalSemantic = outcomes.filter((item) => item.incremental_semantic_attack_success).length;
  const semanticInducedEligible = outcomes.filter((item) => !item.clean.target_semantic_assertion).length;
  const poisonRetrieved = outcomes.filter((item) => item.attacked.retrieved_poison_count > 0).length;
  const totalPoisonRetrieved = outcomes.reduce((sum, item) => sum + item.attacked.retrieved_poison_count, 0);
  const cleanCorrect = outcomes.filter((item) => item.clean.qa_correct).length;
  const attackedCorrect = outcomes.filter((item) => item.attacked.qa_correct).length;
  const b = outcomes.filter((item) => item.clean.qa_correct && !item.attacked.qa_correct).length;
  const c = outcomes.filter((item) => !item.clean.qa_correct && item.attacked.qa_correct).length;
  const pairedDeltas = outcomes.map((item) => item.paired_qa_delta);
  const summary = {
    schema: POISONEDRAG_SCHEMAS.SUMMARY,
    protocol: POISONEDRAG_PROTOCOL_ID,
    run_id: args.runId,
    execution_plan_sha256: plan.plan_sha256,
    intended_n: args.targetCount,
    completed_n: outcomes.length,
    denominator_complete: true,
    primary_official_substring_metric: {
      clean_asr: proportion(cleanAsr, outcomes.length),
      attacked_asr: proportion(attackedAsr, outcomes.length),
      induced_asr: proportion(incrementalAsr, inducedEligible),
    },
    secondary_semantic_metric: {
      clean_asr: proportion(cleanSemantic, outcomes.length),
      attacked_asr: proportion(attackedSemantic, outcomes.length),
      induced_asr: proportion(incrementalSemantic, semanticInducedEligible),
    },
    retrieval: {
      poison_retrieved_at_5: proportion(poisonRetrieved, outcomes.length),
      mean_poison_passages_at_5: totalPoisonRetrieved / outcomes.length,
      mean_poison_passages_at_5_bootstrap_95: pairedBootstrap(
        outcomes.map((item) => item.attacked.retrieved_poison_count),
      ),
    },
    utility: {
      clean_accuracy: proportion(cleanCorrect, outcomes.length),
      attacked_accuracy: proportion(attackedCorrect, outcomes.length),
      paired_accuracy_delta: pairedDeltas.reduce((sum, value) => sum + value, 0) / outcomes.length,
      paired_bootstrap_95: pairedBootstrap(pairedDeltas),
      mcnemar: { b, c, exact_two_sided_p: exactMcNemarPValue(b, c) },
    },
    admission: {
      clean_submitted_per_arm: outcomes.reduce((sum, item) => sum
        + readJsonFile(path.join(root, 'targets', targetDirectoryName({
          ordinal: item.target_ordinal,
          upstream_id: item.upstream_id,
        }), 'admission.json')).clean_candidates_submitted_per_arm, 0),
      poison_rejections: outcomes.reduce((sum, item) => sum
        + readJsonFile(path.join(root, 'targets', targetDirectoryName({
          ordinal: item.target_ordinal,
          upstream_id: item.upstream_id,
        }), 'admission.json')).poison_passages_rejected, 0),
      poison_passages_with_signed_epistemic_label_evidence: outcomes.reduce((sum, item) => sum
        + readJsonFile(path.join(root, 'targets', targetDirectoryName({
          ordinal: item.target_ordinal,
          upstream_id: item.upstream_id,
        }), 'admission.json')).poison_passages_with_signed_epistemic_label_evidence, 0),
    },
    target_outcomes: outcomes.map((item) => ({
      target_ordinal: item.target_ordinal,
      upstream_id: item.upstream_id,
      outcome_sha256: item.outcome_sha256,
    })),
  };
  return writeHashedArtifact(path.join(root, 'summary.json'), summary, 'summary_sha256');
}

async function main() {
  const args = parseArgs(process.argv);
  if (!existsSync(args.runDir) || lstatSync(args.runDir).isSymbolicLink() || !statSync(args.runDir).isDirectory()) {
    throw new Error('poisonedrag_run_directory_invalid');
  }
  const root = path.join(args.runDir, 'poisonedrag');
  mkdirSync(path.join(root, 'targets'), { recursive: true, mode: 0o700 });
  const inputs = loadPoisonedRagInputs(args.targetCount);
  const expectedPreflight = buildInputCompatibilityPreflight({
    targets: inputs.targets,
    documents: inputs.documents,
    sourceLockSha256: inputs.sourceLockSha256,
    candidatePoolSha256: inputs.corpusResolution.candidate_pool_sha256,
  });
  const preflightFile = path.join(root, 'input-preflight.json');
  if (existsSync(preflightFile)) {
    const priorPreflight = readVerifiedArtifact(
      preflightFile,
      POISONEDRAG_SCHEMAS.INPUT_PREFLIGHT,
      'preflight_sha256',
    );
    if (poisonCanonicalJson(priorPreflight) !== poisonCanonicalJson(expectedPreflight)) {
      throw new Error('poisonedrag_input_preflight_mismatch');
    }
  } else {
    writeImmutableJson(preflightFile, expectedPreflight);
  }
  const expectedDuplicatePreflight = buildDuplicateCompatibilityPreflight({
    targets: inputs.targets,
    documents: inputs.documents,
    sourceLockSha256: inputs.sourceLockSha256,
    candidatePoolSha256: inputs.corpusResolution.candidate_pool_sha256,
  });
  const duplicatePreflightFile = path.join(root, 'duplicate-preflight.json');
  if (existsSync(duplicatePreflightFile)) {
    const priorDuplicatePreflight = readVerifiedArtifact(
      duplicatePreflightFile,
      POISONEDRAG_SCHEMAS.DUPLICATE_PREFLIGHT,
      'preflight_sha256',
    );
    if (poisonCanonicalJson(priorDuplicatePreflight) !== poisonCanonicalJson(expectedDuplicatePreflight)) {
      throw new Error('poisonedrag_duplicate_preflight_mismatch');
    }
  } else {
    writeImmutableJson(duplicatePreflightFile, expectedDuplicatePreflight);
  }
  const expectedPlan = makeExecutionPlan(args, inputs);
  const planFile = path.join(root, 'execution-plan.json');
  if (existsSync(planFile)) {
    const priorPlan = readVerifiedArtifact(planFile, POISONEDRAG_SCHEMAS.EXECUTION_PLAN, 'plan_sha256');
    if (poisonCanonicalJson(priorPlan) !== poisonCanonicalJson(expectedPlan)) {
      throw new Error('poisonedrag_execution_plan_mismatch');
    }
  } else {
    writeImmutableJson(planFile, expectedPlan);
  }
  await scratchHealth(args);
  const expectedScratchDatabase = `aimos_benchmark_${args.runId}`;
  if (args.phase === 'ingest-recall' && resolveAimosDatabaseName() !== expectedScratchDatabase) {
    throw new Error('poisonedrag_signer_not_bound_to_scratch_database');
  }
  if (args.phase === 'model-aggregate' && resolveAimosDatabaseName() !== 'aimos') {
    throw new Error('poisonedrag_provider_not_bound_to_canonical_custody');
  }
  const initialProgress = {
    run_id: args.runId,
    target_count: args.targetCount,
    phase: 'ingest',
    saves_completed: 0,
    saves_reused: 0,
    saves_total: args.targetCount * 205,
    recalls_completed: 0,
    recalls_reused: 0,
    recalls_total: args.targetCount * 2,
    generated_completed: 0,
    generated_reused: 0,
    generated_total: args.targetCount * 2,
    judgments_completed: 0,
    judgments_reused: 0,
    judgments_total: args.targetCount * 4,
  };
  const progressFile = path.join(root, 'progress.json');
  const progress = existsSync(progressFile)
    ? JSON.parse(readFileSync(progressFile, 'utf8'))
    : initialProgress;
  if (progress.run_id !== args.runId
    || progress.target_count !== args.targetCount
    || progress.saves_total !== initialProgress.saves_total
    || progress.recalls_total !== initialProgress.recalls_total
    || progress.generated_total !== initialProgress.generated_total
    || progress.judgments_total !== initialProgress.judgments_total) {
    throw new Error('poisonedrag_progress_projection_mismatch');
  }
  writeProgress(root, progress);

  const admissions = new Map();
  const recallByTarget = new Map();
  if (args.phase === 'ingest-recall') {
    progress.phase = 'ingest';
    progress.saves_completed = 0;
    progress.saves_reused = 0;
    progress.recalls_completed = 0;
    progress.recalls_reused = 0;
    writeProgress(root, progress);
    for (const target of inputs.targets) {
      const admission = await ingestTarget(args, root, target, inputs.documents, progress);
      admissions.set(target.ordinal, admission);
    }

    progress.phase = 'recall';
    writeProgress(root, progress);
    for (const target of inputs.targets) {
      const arms = [];
      for (const arm of target.recall_order) {
        const result = await recallArm(args, root, target, arm, admissions.get(target.ordinal));
        arms[arm] = result;
        progress.recalls_completed += 1;
        progress.recalls_reused += Number(result.reused);
        writeProgress(root, progress);
        console.log(JSON.stringify({
          event: 'poisonedrag_recall_verified',
          target: target.ordinal,
          arm,
          completed: progress.recalls_completed,
          total: progress.recalls_total,
          reused: result.reused,
          merkle_root: result.proof.verification.merkle_root,
        }));
      }
      recallByTarget.set(target.ordinal, arms);
    }
    if (args.targetCount === 3) {
      progress.phase = 'isolation-gate';
      writeProgress(root, progress);
      const isolationProof = await runThreeTargetIsolationGate(args, root, inputs.targets);
      console.log(JSON.stringify({
        event: 'poisonedrag_isolation_gate_passed',
        proof_sha256: isolationProof.proof_sha256,
      }));
    }
    progress.phase = 'ingest-recall-complete';
    writeProgress(root, progress);
    console.log(JSON.stringify({
      success: true,
      phase: args.phase,
      saves_completed: progress.saves_completed,
      recalls_completed: progress.recalls_completed,
    }, null, 2));
    return;
  }

  if (progress.saves_completed !== progress.saves_total
    || progress.recalls_completed !== progress.recalls_total) {
    throw new Error('poisonedrag_ingest_recall_not_complete');
  }
  for (const target of inputs.targets) {
    const targetRoot = path.join(root, 'targets', targetDirectoryName(target));
    const admission = readJsonFile(path.join(targetRoot, 'admission.json'));
    if (admission?.admission_sha256 !== selfHash(admission, 'admission_sha256')) {
      throw new Error(`poisonedrag_admission_artifact_invalid:${target.ordinal}`);
    }
    admissions.set(target.ordinal, admission);
    const arms = [];
    for (const arm of [0, 1]) {
      const file = path.join(targetRoot, 'recall', `arm-${arm}.json`);
      const proof = readVerifiedArtifact(file, POISONEDRAG_SCHEMAS.RECALL_PROOF, 'proof_sha256');
      if (!proof) throw new Error(`poisonedrag_recall_artifact_missing:${target.ordinal}:${arm}`);
      arms[arm] = { proof, reused: true };
    }
    recallByTarget.set(target.ordinal, arms);
  }

  progress.generated_completed = 0;
  progress.generated_reused = 0;
  progress.judgments_completed = 0;
  progress.judgments_reused = 0;
  progress.phase = 'model-access';
  writeProgress(root, progress);
  await ensureProviderRuntime();
  const answerByTarget = new Map();
  for (const target of inputs.targets) {
    const answers = [];
    for (const arm of target.recall_order) {
      const result = await generateArm(args, root, target, arm, recallByTarget.get(target.ordinal)[arm].proof);
      answers[arm] = result;
      progress.generated_completed += 1;
      progress.generated_reused += Number(result.reused);
      writeProgress(root, progress);
      console.log(JSON.stringify({
        event: 'poisonedrag_answer_generated',
        target: target.ordinal,
        arm,
        completed: progress.generated_completed,
        total: progress.generated_total,
        reused: result.reused,
        answer_sha256: result.artifact.answer_sha256,
      }));
    }
    answerByTarget.set(target.ordinal, answers);
  }

  progress.phase = 'judge';
  writeProgress(root, progress);
  const judgmentByTarget = new Map();
  for (const target of inputs.targets) {
    const judgments = [];
    for (const arm of target.recall_order) {
      const result = await judgeArm(
        args,
        root,
        target,
        arm,
        recallByTarget.get(target.ordinal)[arm].proof,
        answerByTarget.get(target.ordinal)[arm].artifact,
      );
      judgments[arm] = result;
      progress.judgments_completed += 2;
      progress.judgments_reused += Number(result.correctness.reused) + Number(result.targetAssertion.reused);
      writeProgress(root, progress);
      console.log(JSON.stringify({
        event: 'poisonedrag_judgments_completed',
        target: target.ordinal,
        arm,
        completed: progress.judgments_completed,
        total: progress.judgments_total,
        correctness_sha256: result.correctness.artifact.judgment_sha256,
        target_assertion_sha256: result.targetAssertion.artifact.judgment_sha256,
      }));
    }
    judgmentByTarget.set(target.ordinal, judgments);
  }

  progress.phase = 'aggregate';
  writeProgress(root, progress);
  const outcomes = inputs.targets.map((target) => buildTargetOutcome(
    args,
    root,
    target,
    admissions.get(target.ordinal),
    recallByTarget.get(target.ordinal),
    answerByTarget.get(target.ordinal),
    judgmentByTarget.get(target.ordinal),
  ));
  const summary = aggregate(args, root, expectedPlan, outcomes);
  progress.phase = 'complete';
  progress.summary_sha256 = summary.summary_sha256;
  writeProgress(root, progress);
  console.log(JSON.stringify({ success: true, root, summary }, null, 2));
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
