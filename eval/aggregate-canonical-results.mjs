#!/usr/bin/env node

/**
 * Reconstruct canonical benchmark metrics from immutable per-question proof.
 *
 * Retrieval is measured against dataset evidence annotations. Judged QA is
 * measured only from GPT-5.6 Terra verdicts. The two quantities are never
 * merged. Every successful recall is cryptographically reverified before its
 * row contributes to an aggregate.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../services/security/agent-identity.js';
import { verifyRecallReceipt } from './run-canonical-single-query.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS_DIR = path.join(ROOT, 'data', 'canonical');

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
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink()) {
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
  const benchmark = String(cliValue(argv, '--benchmark') || '').trim().toLowerCase();
  if (!['locomo', 'longmemeval'].includes(benchmark)) throw new Error('benchmark_invalid');
  const runId = String(cliValue(argv, '--run-id') || '').trim();
  if (!/^[a-z0-9][a-z0-9_-]{5,63}$/i.test(runId)) throw new Error('run_id_invalid');
  const runDirRaw = cliValue(argv, '--run-dir');
  if (!runDirRaw) throw new Error('run_dir_required');
  const runDir = path.resolve(runDirRaw);
  return {
    benchmark,
    runId,
    runDir,
    selectionFile: path.resolve(cliValue(argv, '--selection-file')
      || path.join(runDir, `selection-${benchmark}.json`)),
    sessionsFile: path.resolve(cliValue(argv, '--sessions-file')
      || path.join(DEFAULT_CORPUS_DIR, `${benchmark}-sessions.json`)),
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
  if (!fs.existsSync(root) || fs.lstatSync(root).isSymbolicLink()) {
    throw new Error(`attempt_missing:${phase}`);
  }
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

function sessionMap(artifact, scopeId) {
  const scope = artifact.scopes.find((entry) => entry.scope_id === scopeId);
  if (!scope) throw new Error(`session_scope_missing:${scopeId}`);
  return new Map(scope.sessions.map((session) => [session.source_session_id, session.session_id]));
}

function parseMemoryRecord(memory) {
  try {
    const parsed = typeof memory?.value === 'string' ? JSON.parse(memory.value) : memory?.value;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function locomoCoverage(memory, expected) {
  const record = parseMemoryRecord(memory);
  const refs = Array.isArray(record?.turns)
    ? record.turns.map((turn) => String(turn?.source_ref || '')).filter(Boolean)
    : [];
  return expected.filter((evidence) => refs.some((ref) => ref === evidence || ref.endsWith(`:${evidence}`)));
}

function longMemEvalCoverage(memory, expected, sourceToCanonical) {
  const memorySession = String(memory?.session_id || '');
  return expected.filter((sourceSessionId) => sourceToCanonical.get(sourceSessionId) === memorySession);
}

export function scoreRetrievalEvidence({ benchmark, memories, expectedEvidence, sourceToCanonical = new Map() }) {
  const expected = [...new Set((expectedEvidence || []).map(String).filter(Boolean))];
  if (!expected.length) {
    return {
      eligible: false,
      expected_evidence_count: 0,
      matched_evidence: [],
      evidence_recall_at_k: null,
      any_hit_at_k: null,
      hit_at_1: null,
      reciprocal_rank: null,
      ndcg_at_k: null,
      first_relevant_rank: null,
      returned: memories.length,
    };
  }
  const matched = new Set();
  const uniqueRelevance = [];
  let firstRelevantRank = null;
  memories.forEach((memory, index) => {
    const covered = benchmark === 'locomo'
      ? locomoCoverage(memory, expected)
      : longMemEvalCoverage(memory, expected, sourceToCanonical);
    if (covered.length && firstRelevantRank == null) firstRelevantRank = index + 1;
    const newlyCovered = covered.filter((item) => !matched.has(item));
    newlyCovered.forEach((item) => matched.add(item));
    uniqueRelevance.push(newlyCovered.length ? 1 : 0);
  });
  const dcg = uniqueRelevance.reduce(
    (sum, relevant, index) => sum + (relevant ? 1 / Math.log2(index + 2) : 0),
    0,
  );
  const idealRelevant = Math.min(expected.length, memories.length);
  let idealDcg = 0;
  for (let index = 0; index < idealRelevant; index += 1) idealDcg += 1 / Math.log2(index + 2);
  return {
    eligible: true,
    expected_evidence_count: expected.length,
    matched_evidence: [...matched].sort(),
    evidence_recall_at_k: matched.size / expected.length,
    any_hit_at_k: matched.size > 0,
    hit_at_1: firstRelevantRank === 1,
    reciprocal_rank: firstRelevantRank ? 1 / firstRelevantRank : 0,
    ndcg_at_k: idealDcg ? dcg / idealDcg : 0,
    first_relevant_rank: firstRelevantRank,
    returned: memories.length,
  };
}

function safeError(error) {
  return String(error?.message || error || 'unknown_error').slice(0, 1000);
}

function sum(rows, field) {
  return rows.reduce((total, row) => total + Number(row?.[field] || 0), 0);
}

function mean(rows, field) {
  return rows.length ? sum(rows, field) / rows.length : null;
}

function summarizeRetrieval(rows, field) {
  const eligible = rows.filter((row) => row[field]?.eligible);
  return {
    eligible: eligible.length,
    any_hit_at_k: mean(eligible.map((row) => ({ value: Number(row[field].any_hit_at_k) })), 'value'),
    hit_at_1: mean(eligible.map((row) => ({ value: Number(row[field].hit_at_1) })), 'value'),
    mean_reciprocal_rank: mean(eligible.map((row) => ({ value: row[field].reciprocal_rank })), 'value'),
    mean_evidence_recall_at_k: mean(eligible.map((row) => ({ value: row[field].evidence_recall_at_k })), 'value'),
    mean_ndcg_at_k: mean(eligible.map((row) => ({ value: row[field].ndcg_at_k })), 'value'),
  };
}

function summarizeRows(rows) {
  const complete = rows.filter((row) => row.status === 'complete');
  const judged = complete.filter((row) => typeof row.verdict.correct === 'boolean');
  return {
    selected: rows.length,
    complete: complete.length,
    incomplete: rows.length - complete.length,
    retrieval: summarizeRetrieval(complete, 'retrieval'),
    returned_evidence_retrieval: summarizeRetrieval(complete, 'returned_evidence_retrieval'),
    judged_qa: {
      judged: judged.length,
      correct: judged.filter((row) => row.verdict.correct).length,
      accuracy: judged.length ? judged.filter((row) => row.verdict.correct).length / judged.length : null,
      mean_score: mean(judged.map((row) => ({ value: row.verdict.score })), 'value'),
    },
    usage: {
      generator_input_tokens: sum(complete.map((row) => row.generator_usage), 'inputTokens'),
      generator_output_tokens: sum(complete.map((row) => row.generator_usage), 'outputTokens'),
      judge_input_tokens: sum(complete.map((row) => row.judge_usage), 'inputTokens'),
      judge_output_tokens: sum(complete.map((row) => row.judge_usage), 'outputTokens'),
    },
    latency_ms: {
      recall_mean: mean(complete.map((row) => ({ value: row.latency_ms.recall })), 'value'),
      generator_mean: mean(complete.map((row) => ({ value: row.latency_ms.generator })), 'value'),
      judge_mean: mean(complete.map((row) => ({ value: row.latency_ms.judge })), 'value'),
    },
  };
}

function aggregate(args) {
  const selection = readJson(args.selectionFile);
  if (selection?.schema !== 'hom.canonical-query-selection/v1'
    || selection.run_id !== args.runId
    || selection.benchmark !== args.benchmark
    || selection.question_count !== selection.entries?.length
    || selection.selection_sha256 !== selfHash(selection, 'selection_sha256')) {
    throw new Error('query_selection_invalid');
  }
  const sessions = readJson(args.sessionsFile);
  if (sessions?.schema !== 'hom.canonical-benchmark-sessions/v1' || sessions.benchmark !== args.benchmark) {
    throw new Error('session_artifact_invalid');
  }

  const rows = selection.entries.map((entry) => {
    try {
      const input = readJson(path.join(args.runDir, 'questions', entry.unit_id, 'input.json'));
      const gold = readJson(path.join(args.runDir, 'gold', `${entry.unit_id}.json`));
      if (canonicalSha256(input) !== entry.input_sha256 || canonicalSha256(gold) !== entry.gold_sha256) {
        throw new Error('query_or_gold_hash_mismatch');
      }
      const recall = completedAttempt(args.runDir, entry.unit_id, 'recall');
      const generate = completedAttempt(args.runDir, entry.unit_id, 'generate');
      const judge = completedAttempt(args.runDir, entry.unit_id, 'judge');
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
      const answer = readJson(path.join(generate.directory, 'answer.json'));
      const generatorProvider = readJson(path.join(generate.directory, 'provider-evidence.json'));
      const verdict = readJson(path.join(judge.directory, 'verdict.json'));
      const judgeProvider = readJson(path.join(judge.directory, 'provider-evidence.json'));
      if (generatorProvider.actual_model !== 'gpt-5.4' || judgeProvider.actual_model !== 'gpt-5.6-terra') {
        throw new Error('provider_model_identity_invalid');
      }
      const recallTiming = readJson(path.join(recall.directory, 'timings.json'));
      const generateTiming = readJson(path.join(generate.directory, 'timings.json'));
      const judgeTiming = readJson(path.join(judge.directory, 'timings.json'));
      const expectedEvidence = args.benchmark === 'locomo'
        ? (gold.expected_evidence || [])
        : (gold.answer_session_ids || []);
      const returnedMemories = recallResponse.memories || [];
      const retrievalK = Number(requestBody.limit);
      if (!Number.isInteger(retrievalK) || retrievalK < 1 || retrievalK > 200) {
        throw new Error('signed_recall_k_invalid');
      }
      const retrieval = scoreRetrievalEvidence({
        benchmark: args.benchmark,
        memories: returnedMemories.slice(0, retrievalK),
        expectedEvidence,
        sourceToCanonical: sessionMap(sessions, input.scope_id),
      });
      const returnedEvidenceRetrieval = scoreRetrievalEvidence({
        benchmark: args.benchmark,
        memories: returnedMemories,
        expectedEvidence,
        sourceToCanonical: sessionMap(sessions, input.scope_id),
      });
      return {
        schema: 'hom.canonical-benchmark-row/v2',
        status: 'complete',
        run_id: args.runId,
        benchmark: args.benchmark,
        question_id: entry.question_id,
        unit_id: entry.unit_id,
        scope_id: input.scope_id,
        category: input.category,
        question: input.question,
        gold_answer: gold.answer,
        generated_answer: answer,
        verdict,
        retrieval_k: retrievalK,
        retrieval,
        returned_evidence_retrieval: returnedEvidenceRetrieval,
        native_output: {
          answer_shape: recallResponse.answer_shape || null,
          returned_memory_count: returnedMemories.length,
          raw_memory_count: Number(recallResponse.raw_memory_count ?? returnedMemories.length),
          full_detail_token_budget: Number(requestBody.full_detail_token_budget || 0) || null,
        },
        returned_memory_ids_at_k: returnedMemories.slice(0, retrievalK).map((memory) => String(memory.id)),
        returned_memory_ids: returnedMemories.map((memory) => String(memory.id)),
        recall_merkle_root: verified.merkle_root,
        recall_attempt_sha256: recall.complete.complete_sha256,
        generate_attempt_sha256: generate.complete.complete_sha256,
        judge_attempt_sha256: judge.complete.complete_sha256,
        generator_usage: generatorProvider.usage,
        judge_usage: judgeProvider.usage,
        generator_credential_use: generatorProvider.credential_use,
        judge_credential_use: judgeProvider.credential_use,
        latency_ms: {
          recall: recallTiming.latency_ms,
          generator: generateTiming.latency_ms,
          judge: judgeTiming.latency_ms,
        },
      };
    } catch (error) {
      return {
        schema: 'hom.canonical-benchmark-row/v2',
        status: 'incomplete',
        run_id: args.runId,
        benchmark: args.benchmark,
        question_id: entry.question_id,
        unit_id: entry.unit_id,
        error: safeError(error),
      };
    }
  });

  const categories = {};
  for (const category of [...new Set(rows.filter((row) => row.status === 'complete').map((row) => row.category))].sort()) {
    categories[category] = summarizeRows(rows.filter((row) => row.category === category));
  }
  const rowsText = `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
  const rowsFile = path.join(args.runDir, `canonical-rows-${args.benchmark}.jsonl`);
  const completeRows = rows.filter((row) => row.status === 'complete');
  const retrievalKValues = [...new Set(completeRows.map((row) => row.retrieval_k))];
  if (retrievalKValues.length > 1) throw new Error('aggregate_retrieval_k_drift');
  const summary = {
    schema: 'hom.canonical-benchmark-summary/v2',
    run_id: args.runId,
    benchmark: args.benchmark,
    generator: 'codex:gpt-5.4',
    judge: 'codex:gpt-5.6-terra',
    selection_sha256: selection.selection_sha256,
    session_artifact_sha256: sha256(fs.readFileSync(args.sessionsFile)),
    retrieval_contract: {
      primary_metric: 'native_returned_rank_at_k',
      k: retrievalKValues[0] || null,
      returned_evidence_metric: 'all_native_returned_evidence_after_output_calibration',
      note: 'The primary at-k metric slices the cryptographically receipted native returned order. The returned-evidence metric is reported separately and is never labeled at-k.',
    },
    rows_file: path.basename(rowsFile),
    rows_sha256: sha256(rowsText),
    metrics: summarizeRows(rows),
    by_category: categories,
  };
  summary.summary_sha256 = selfHash(summary, 'summary_sha256');
  const summaryFile = path.join(args.runDir, `canonical-summary-${args.benchmark}.json`);
  for (const [file, text] of [
    [rowsFile, rowsText],
    [summaryFile, `${JSON.stringify(summary, null, 2)}\n`],
  ]) {
    if (fs.existsSync(file)) {
      if (fs.lstatSync(file).isSymbolicLink() || fs.readFileSync(file, 'utf8') !== text) {
        throw new Error(`immutable_aggregate_conflict:${file}`);
      }
    } else {
      fs.writeFileSync(file, text, { flag: 'wx', mode: 0o600 });
    }
  }
  console.log(JSON.stringify({ success: summary.metrics.incomplete === 0, summary_file: summaryFile, ...summary }, null, 2));
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
