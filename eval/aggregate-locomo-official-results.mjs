#!/usr/bin/env node

/**
 * Reconstruct the upstream-compatible LoCoMo QA score from immutable HOM
 * recall and reader artifacts. No LLM judge participates in this aggregate.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../services/security/agent-identity.js';
import { scoreRetrievalEvidence } from './aggregate-canonical-results.mjs';
import { verifyRecallReceipt } from './run-canonical-single-query.mjs';
import {
  LOCOMO_OFFICIAL_DATASET_SHA256,
  LOCOMO_OFFICIAL_PROTOCOL,
  LOCOMO_OFFICIAL_TOP_K,
  officialLocomoProtocolManifest,
  officialLocomoScore,
} from './locomo-official-protocol.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SESSIONS_FILE = path.join(ROOT, 'data', 'canonical', 'locomo-sessions.json');
const READER_MODEL = 'gpt-5.4';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalSha256(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function selfHash(value, field) {
  const unsigned = { ...value };
  delete unsigned[field];
  return sha256(JSON.stringify(unsigned));
}

function readJson(file) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink() || !fs.statSync(file).isFile()) {
    throw new Error(`artifact_invalid:${file}`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function cliValue(argv, name) {
  const inline = argv.slice(2).find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function parseArgs(argv) {
  const runId = String(cliValue(argv, '--run-id') || '').trim();
  if (!/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(runId)) throw new Error('run_id_invalid');
  const runDirRaw = cliValue(argv, '--run-dir');
  if (!runDirRaw) throw new Error('run_dir_required');
  const runDir = path.resolve(runDirRaw);
  return {
    runId,
    runDir,
    selectionFile: path.resolve(cliValue(argv, '--selection-file') || path.join(runDir, 'selection-locomo.json')),
    sessionsFile: path.resolve(cliValue(argv, '--sessions-file') || DEFAULT_SESSIONS_FILE),
  };
}

function verifyComplete(directory, phase) {
  const complete = readJson(path.join(directory, 'complete.json'));
  if (complete?.schema !== 'hom.canonical-query-attempt-complete/v1'
    || complete.phase !== phase
    || complete.status !== 'success'
    || complete.complete_sha256 !== selfHash(complete, 'complete_sha256')) {
    throw new Error(`attempt_completion_invalid:${phase}`);
  }
  for (const [name, expected] of Object.entries(complete.files || {})) {
    const file = path.join(directory, name);
    if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()
      || sha256(fs.readFileSync(file)) !== expected) {
      throw new Error(`attempt_artifact_hash_mismatch:${phase}:${name}`);
    }
  }
  return complete;
}

function completedAttempt(runDir, unitId, phase) {
  const root = path.join(runDir, 'questions', unitId, phase);
  if (!fs.existsSync(root) || fs.lstatSync(root).isSymbolicLink()) throw new Error(`attempt_missing:${phase}`);
  const complete = fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^attempt-\d{4}$/.test(entry.name))
    .sort((left, right) => left.name.localeCompare(right.name))
    .map((entry) => {
      const directory = path.join(root, entry.name);
      return fs.existsSync(path.join(directory, 'complete.json'))
        ? { directory, complete: verifyComplete(directory, phase) }
        : null;
    })
    .filter(Boolean);
  if (complete.length !== 1) throw new Error(`successful_attempt_count_invalid:${phase}:${complete.length}`);
  return complete[0];
}

function safeError(error) {
  return String(error?.message || error || 'unknown_error')
    .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
    .replace(/\bsk-[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .slice(0, 1000);
}

function sum(rows, accessor) {
  return rows.reduce((total, row) => total + Number(accessor(row) || 0), 0);
}

function mean(rows, accessor) {
  return rows.length ? sum(rows, accessor) / rows.length : null;
}

function summarize(rows) {
  const complete = rows.filter((row) => row.status === 'complete');
  const retrieval = complete.filter((row) => row.retrieval.eligible);
  const scoreMean = mean(complete, (row) => row.official_qa_score);
  return {
    selected: rows.length,
    complete: complete.length,
    incomplete: rows.length - complete.length,
    official_qa: {
      evaluated: complete.length,
      mean_f1: scoreMean,
      score_percent: scoreMean == null ? null : scoreMean * 100,
    },
    retrieval: {
      eligible: retrieval.length,
      any_hit_at_k: mean(retrieval, (row) => Number(row.retrieval.any_hit_at_k)),
      hit_at_1: mean(retrieval, (row) => Number(row.retrieval.hit_at_1)),
      mean_reciprocal_rank: mean(retrieval, (row) => row.retrieval.reciprocal_rank),
      mean_evidence_recall_at_k: mean(retrieval, (row) => row.retrieval.evidence_recall_at_k),
      mean_ndcg_at_k: mean(retrieval, (row) => row.retrieval.ndcg_at_k),
    },
    usage: {
      reader_input_tokens: sum(complete, (row) => row.reader_usage.inputTokens),
      reader_output_tokens: sum(complete, (row) => row.reader_usage.outputTokens),
    },
    latency_ms: {
      recall_mean: mean(complete, (row) => row.latency_ms.recall),
      reader_mean: mean(complete, (row) => row.latency_ms.reader),
    },
  };
}

function immutableText(file, text) {
  if (fs.existsSync(file)) {
    if (fs.lstatSync(file).isSymbolicLink() || fs.readFileSync(file, 'utf8') !== text) {
      throw new Error(`immutable_aggregate_conflict:${file}`);
    }
    return;
  }
  fs.writeFileSync(file, text, { flag: 'wx', mode: 0o600 });
}

function aggregate(args) {
  const selection = readJson(args.selectionFile);
  if (selection?.schema !== 'hom.canonical-query-selection/v1'
    || selection.run_id !== args.runId
    || selection.benchmark !== 'locomo'
    || selection.protocol !== LOCOMO_OFFICIAL_PROTOCOL
    || selection.question_count !== selection.entries?.length
    || selection.selection_sha256 !== selfHash(selection, 'selection_sha256')) {
    throw new Error('locomo_official_selection_invalid');
  }
  const sessionsBytes = fs.readFileSync(args.sessionsFile);
  const sessions = JSON.parse(sessionsBytes);
  if (sessions?.schema !== 'hom.canonical-benchmark-sessions/v1'
    || sessions.benchmark !== 'locomo'
    || sessions.source_dataset_sha256 !== LOCOMO_OFFICIAL_DATASET_SHA256) {
    throw new Error('locomo_official_session_artifact_invalid');
  }

  const rows = selection.entries.map((entry) => {
    try {
      const input = readJson(path.join(args.runDir, 'questions', entry.unit_id, 'input.json'));
      const gold = readJson(path.join(args.runDir, 'gold', `${entry.unit_id}.json`));
      if (input.protocol !== LOCOMO_OFFICIAL_PROTOCOL
        || canonicalSha256(input) !== entry.input_sha256
        || canonicalSha256(gold) !== entry.gold_sha256) {
        throw new Error('locomo_official_query_or_gold_hash_mismatch');
      }
      const recall = completedAttempt(args.runDir, entry.unit_id, 'recall');
      const generate = completedAttempt(args.runDir, entry.unit_id, 'generate');
      const recallRequest = readJson(path.join(recall.directory, 'recall-request.json'));
      const recallResponse = readJson(path.join(recall.directory, 'recall-response.json'));
      const requestBody = { ...recallRequest.body };
      delete requestBody.ts_signed;
      const verified = verifyRecallReceipt({
        requestBody,
        signedBody: recallRequest.body,
        responseBody: recallResponse,
        sourceFilter: input.source_filter,
      });
      if (Number(requestBody.limit) !== LOCOMO_OFFICIAL_TOP_K) {
        throw new Error('locomo_official_signed_recall_k_invalid');
      }
      const answer = readJson(path.join(generate.directory, 'answer.json'));
      const readerRequest = readJson(path.join(generate.directory, 'generator-request.json'));
      const readerProvider = readJson(path.join(generate.directory, 'provider-evidence.json'));
      if (answer?.schema !== 'hom.locomo-official-answer/v1'
        || readerRequest.protocol !== LOCOMO_OFFICIAL_PROTOCOL
        || readerRequest.schema !== null
        || readerProvider.actual_model !== READER_MODEL) {
        throw new Error('locomo_official_reader_evidence_invalid');
      }
      const memories = recallResponse.memories || [];
      const retrieval = scoreRetrievalEvidence({
        benchmark: 'locomo',
        memories: memories.slice(0, LOCOMO_OFFICIAL_TOP_K),
        expectedEvidence: gold.expected_evidence || [],
      });
      const recallTiming = readJson(path.join(recall.directory, 'timings.json'));
      const readerTiming = readJson(path.join(generate.directory, 'timings.json'));
      return {
        schema: 'hom.locomo-official-row/v1',
        status: 'complete',
        run_id: args.runId,
        protocol: LOCOMO_OFFICIAL_PROTOCOL,
        question_id: entry.question_id,
        unit_id: entry.unit_id,
        scope_id: input.scope_id,
        category: input.category,
        question: input.question,
        gold_answer: gold.answer,
        raw_reader_answer: answer.raw_answer,
        normalized_reader_answer: answer.answer,
        official_qa_score: officialLocomoScore(answer.answer, gold.answer, input.category),
        retrieval_k: LOCOMO_OFFICIAL_TOP_K,
        retrieval,
        returned_memory_count: memories.length,
        returned_memory_ids: memories.map((memory) => String(memory.id)),
        recall_merkle_root: verified.merkle_root,
        recall_attempt_sha256: recall.complete.complete_sha256,
        reader_attempt_sha256: generate.complete.complete_sha256,
        reader_prompt_sha256: readerRequest.prompt_sha256,
        reader_usage: readerProvider.usage,
        reader_credential_use: readerProvider.credential_use,
        latency_ms: {
          recall: recallTiming.latency_ms,
          reader: readerTiming.latency_ms,
        },
      };
    } catch (error) {
      return {
        schema: 'hom.locomo-official-row/v1',
        status: 'incomplete',
        run_id: args.runId,
        protocol: LOCOMO_OFFICIAL_PROTOCOL,
        question_id: entry.question_id,
        unit_id: entry.unit_id,
        error: safeError(error),
      };
    }
  });

  const categories = {};
  for (const category of [...new Set(rows.filter((row) => row.status === 'complete').map((row) => row.category))].sort()) {
    categories[category] = summarize(rows.filter((row) => row.category === category));
  }
  const rowsText = `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
  const rowsFile = path.join(args.runDir, 'locomo-official-rows.jsonl');
  const summary = {
    schema: 'hom.locomo-official-summary/v1',
    run_id: args.runId,
    benchmark: 'locomo',
    protocol: officialLocomoProtocolManifest(),
    reader: `codex:${READER_MODEL}`,
    reader_reasoning: 'medium',
    judge: null,
    selection_sha256: selection.selection_sha256,
    session_artifact_sha256: sha256(sessionsBytes),
    rows_file: path.basename(rowsFile),
    rows_sha256: sha256(rowsText),
    publication_label: `LoCoMo upstream-compatible QA F1 (HOM composed-session RAG, ${READER_MODEL}, K=${LOCOMO_OFFICIAL_TOP_K})`,
    comparability_note: 'The prompt and deterministic scorer match pinned upstream LoCoMo semantics. The reader, retriever, cryptographic save/recall pipeline, and composed session_exchange memory unit are HOM configuration variables and must accompany every comparison.',
    metrics: summarize(rows),
    by_category: categories,
  };
  summary.summary_sha256 = selfHash(summary, 'summary_sha256');
  const summaryFile = path.join(args.runDir, 'locomo-official-summary.json');
  immutableText(rowsFile, rowsText);
  immutableText(summaryFile, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify({
    success: summary.metrics.incomplete === 0,
    summary_file: summaryFile,
    ...summary,
  }, null, 2));
  if (summary.metrics.incomplete !== 0) process.exitCode = 1;
}

function main() {
  const args = parseArgs(process.argv);
  if (!fs.existsSync(args.runDir) || fs.lstatSync(args.runDir).isSymbolicLink()) throw new Error('run_dir_invalid');
  aggregate(args);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error?.stack || error);
    process.exitCode = 1;
  }
}
