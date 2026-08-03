#!/usr/bin/env node
/**
 * LoCoMo + LongMemEval Aimos benchmark harness.
 *
 * Two modes:
 * - official: benchmark compliance. Uses source-filtered full-detail recall and
 *   checks whether the expected answer/evidence is present in returned evidence.
 * - aimos: product diagnostic. Uses normal calibrated recall and records
 *   Aimos answer shape, handles, temporal scope, and evidence quality.
 *
 * The harness never writes answer keys into Aimos. It ingests benchmark
 * conversation evidence only, under dedicated source tags.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { buildEnvelopeHeaders } from '../services/security/envelope-headers.js';
import { pool, agentPool } from '../db/connection.js';
import { runProvider } from '../services/core/providers.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
const RESULTS_DIR = path.join(__dirname, 'results');

const SOURCE = {
  longmemeval: 'benchmark_longmemeval_official',
  locomo: 'benchmark_locomo_official',
};

const DATASET_FILE = {
  longmemeval: path.join(DATA_DIR, 'longmemeval-full.json'),
  locomo: path.join(DATA_DIR, 'official-locomo10.json'),
};

const CATEGORY_MAP_LOCOMO = {
  1: 'single-hop',
  2: 'temporal',
  3: 'open-domain',
  4: 'multi-hop',
  5: 'adversarial',
};

const ANSWER_GENERATOR_PROMPT_VERSION = 'aimos-benchmark-answer-generator-v4-native-cognitive-support';
const ANSWER_JUDGE_PROMPT_VERSION = 'aimos-benchmark-answer-judge-v1';

function parseArgs(argv) {
  const args = {
    benchmark: 'both',
    mode: 'both',
    sample: 20,
    offset: 0,
    full: false,
    ingestMissing: false,
    ingestOnly: false,
    limit: 20,
    aimosBase: 'http://127.0.0.1:9100',
    agentId: 'housekeeper',
    longMemEvalFile: DATASET_FILE.longmemeval,
    ingestDelayMs: 1100,
    requestIntervalMs: 2100,
    retries: 5,
    progressEvery: 1,
    generatorProvider: null,
    generatorModel: null,
    judgeProvider: null,
    judgeModel: null,
    judgeMaxChars: 32000,
    providerRetryLimit: 4,
    providerMaxResetWaitSeconds: 1800,
    disableLexicalAutoPass: true,
    memoryTypeFilter: 'session_debrief',
    outputDir: RESULTS_DIR,
    ledgerDir: null,
    printConfig: false,
    recordDir: null,
    replayDir: null,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === '--benchmark' && next) args.benchmark = next;
    else if (arg === '--mode' && next) args.mode = next;
    else if (arg === '--sample' && next) args.sample = Number(next);
    else if (arg === '--offset' && next) args.offset = Number(next);
    else if (arg === '--limit' && next) args.limit = Number(next);
    else if (arg === '--aimos-base' && next) args.aimosBase = next;
    else if (arg === '--agent-id' && next) args.agentId = next;
    else if (arg === '--longmemeval-file' && next) args.longMemEvalFile = path.resolve(next);
    else if (arg === '--ingest-delay-ms' && next) args.ingestDelayMs = Number(next);
    else if (arg === '--request-interval-ms' && next) args.requestIntervalMs = Number(next);
    else if (arg === '--retries' && next) args.retries = Number(next);
    else if (arg === '--progress-every' && next) args.progressEvery = Number(next);
    else if (arg === '--generator-provider' && next) args.generatorProvider = next;
    else if (arg === '--generator-model' && next) args.generatorModel = next;
    else if (arg === '--judge-provider' && next) args.judgeProvider = next;
    else if (arg === '--judge-model' && next) args.judgeModel = next;
    else if (arg === '--judge-max-chars' && next) args.judgeMaxChars = Number(next);
    else if (arg === '--provider-retry-limit' && next) args.providerRetryLimit = Number(next);
    else if (arg === '--provider-max-reset-wait-seconds' && next) args.providerMaxResetWaitSeconds = Number(next);
    else if (arg === '--memory-type-filter' && next) args.memoryTypeFilter = next;
    else if (arg === '--ledger-dir' && next) args.ledgerDir = next;
    else if (arg === '--output-dir' && next) args.outputDir = path.resolve(next);
    else if (arg === '--disable-lexical-auto-pass') args.disableLexicalAutoPass = true;
    else if (arg === '--enable-lexical-auto-pass') args.disableLexicalAutoPass = false;
    else if (arg === '--print-config') args.printConfig = true;
    else if (arg === '--record' && next) { args.recordDir = next; i += 1; }
    else if (arg === '--replay' && next) { args.replayDir = next; i += 1; }
    else if (arg === '--full') args.full = true;
    else if (arg === '--ingest-missing') args.ingestMissing = true;
    else if (arg === '--ingest-only') args.ingestOnly = true;
  }

  if (!['both', 'longmemeval', 'locomo'].includes(args.benchmark)) {
    throw new Error(`Unsupported --benchmark ${args.benchmark}`);
  }
  if (!['both', 'all', 'official', 'aimos', 'judge'].includes(args.mode)) {
    throw new Error(`Unsupported --mode ${args.mode}`);
  }
  if (['judge', 'all'].includes(args.mode)) {
    if (!args.generatorProvider || !args.generatorModel) {
      throw new Error('Judge mode requires --generator-provider and --generator-model');
    }
    args.judgeProvider ||= args.generatorProvider;
    args.judgeModel ||= args.generatorModel;
  }
  if (!Number.isFinite(args.sample) || args.sample < 1) args.sample = 20;
  if (!Number.isFinite(args.offset) || args.offset < 0) args.offset = 0;
  if (!Number.isFinite(args.limit) || args.limit < 1) args.limit = 20;
  if (!Number.isFinite(args.ingestDelayMs) || args.ingestDelayMs < 0) args.ingestDelayMs = 1100;
  if (!Number.isFinite(args.requestIntervalMs) || args.requestIntervalMs < 0) args.requestIntervalMs = 2100;
  if (!Number.isFinite(args.retries) || args.retries < 1) args.retries = 5;
  if (!Number.isFinite(args.progressEvery) || args.progressEvery < 1) args.progressEvery = 1;
  if (!Number.isFinite(args.judgeMaxChars) || args.judgeMaxChars < 4000) args.judgeMaxChars = 32000;
  if (!Number.isFinite(args.providerRetryLimit) || args.providerRetryLimit < 0) args.providerRetryLimit = 4;
  if (!Number.isFinite(args.providerMaxResetWaitSeconds) || args.providerMaxResetWaitSeconds < 0) args.providerMaxResetWaitSeconds = 1800;
  return args;
}

function normalizeMemoryTypeFilter(value) {
  const raw = String(value ?? '').trim();
  if (!raw || ['all', 'none', 'off', '*'].includes(raw.toLowerCase())) return null;
  return raw;
}

function prepareLedger(args) {
  if (!args.ledgerDir) return null;
  const dir = path.resolve(args.ledgerDir);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'rows.jsonl'), '');
  fs.writeFileSync(path.join(dir, 'failures.jsonl'), '');
  fs.writeFileSync(path.join(dir, 'progress.jsonl'), '');
  fs.writeFileSync(path.join(dir, 'summary.json'), '{}\n');
  fs.writeFileSync(path.join(dir, 'command.txt'), `${process.argv.join(' ')}\n`);
  return {
    dir,
    rows: path.join(dir, 'rows.jsonl'),
    failures: path.join(dir, 'failures.jsonl'),
    progress: path.join(dir, 'progress.jsonl'),
    summary: path.join(dir, 'summary.json'),
  };
}

function appendJsonl(file, row) {
  fs.appendFileSync(file, `${JSON.stringify(row)}\n`);
}

function classifyFailure(row) {
  const judge = row.modes.judge;
  const official = row.modes.official;
  if (judge) {
    if (judge.judged_correct === true) return null;
    if (judge.error) return 'generator_or_judge_error';
    if (judge.http_status && judge.http_status !== 200) return 'aimos_http_error';
    if (!judge.official_evidence_pass) return 'retrieval_evidence_missing';
    if (String(judge.generated_answer || '').trim().toLowerCase() === 'insufficient_evidence') {
      return 'qa_false_abstention_with_evidence';
    }
    return 'qa_answer_mismatch_with_evidence';
  }
  if (official) {
    // official is scoreRetrieval output: retrieval_hit is a RETRIEVAL result, not QA correctness.
    if (official.retrieval_hit) return null;
    if (official.http_status && official.http_status !== 200) return 'aimos_http_error';
    return 'retrieval_evidence_missing';
  }
  return null;
}

function compactLedgerRow(row, dataset, index, total) {
  const judge = row.modes.judge;
  const official = row.modes.official;
  const aimosMode = row.modes.aimos;
  const evidenceMode = official || judge;
  const failure_type = classifyFailure(row);
  return {
    ts: new Date().toISOString(),
    benchmark: row.benchmark,
    dataset_source: dataset.source,
    index: index + 1,
    total,
    id: row.id,
    category: row.category,
    question: row.question,
    expected_answer: row.expected_answer,
    expected_evidence: row.expected_evidence,
    status: failure_type ? 'fail' : 'pass',
    failure_type,
    official_evidence_pass: official?.retrieval_hit ?? judge?.official_evidence_pass ?? null,
    retrieval_hit: official?.retrieval_hit ?? judge?.retrieval_hit ?? null,
    judged_correct: judge?.judged_correct ?? null,
    answer_exact_match: judge?.answer_exact_match ?? null,
    answer_f1: judge?.answer_f1 ?? null,
    judge_score: judge?.judge_score ?? null,
    judge_reason: judge?.judge_reason ?? null,
    judge_path: judge?.judge_path ?? null,
    lexical_auto_pass: judge?.lexical_auto_pass ?? null,
    lexical_match: judge?.lexical_match ?? null,
    generated_answer: judge?.generated_answer ?? null,
    generator_confidence: judge?.generator_confidence ?? null,
    generator_rationale: judge?.generator_rationale ?? null,
    generated_evidence_keys: judge?.generated_evidence_keys ?? [],
    native_support_hints: judge?.native_support_hints ?? [],
    answer_rank: evidenceMode?.answer_rank ?? null,
    expected_evidence_rank: evidenceMode?.expected_evidence_rank ?? null,
    expected_session_rank: evidenceMode?.expected_session_rank ?? null,
    best_rank: evidenceMode?.best_rank ?? null,
    hit_at_1: evidenceMode?.hit_at_1 ?? null,
    hit_at_5: evidenceMode?.hit_at_5 ?? null,
    hit_at_10: evidenceMode?.hit_at_10 ?? null,
    reciprocal_rank: evidenceMode?.reciprocal_rank ?? null,
    relevant_returned: evidenceMode?.relevant_returned ?? null,
    observed_precision: evidenceMode?.observed_precision ?? null,
    returned: evidenceMode?.returned ?? aimosMode?.returned ?? null,
    polluted_returned: evidenceMode?.polluted_returned ?? aimosMode?.polluted_returned ?? null,
    returned_keys: evidenceMode?.returned_keys ?? [],
    latency_ms: evidenceMode?.latency_ms ?? aimosMode?.latency_ms ?? null,
    http_status: evidenceMode?.http_status ?? aimosMode?.http_status ?? null,
    error: evidenceMode?.error ?? aimosMode?.error ?? null,
  };
}

function writeLedgerProgress(args, row, dataset, index, total, results) {
  if (!args.ledger) return;
  const compact = compactLedgerRow(row, dataset, index, total);
  appendJsonl(args.ledger.rows, compact);
  if (compact.failure_type) appendJsonl(args.ledger.failures, compact);
  appendJsonl(args.ledger.progress, {
    ts: compact.ts,
    benchmark: row.benchmark,
    index: index + 1,
    total,
    id: row.id,
    status: compact.status,
    failure_type: compact.failure_type,
    judged_pass: compact.judged_pass,
    official_evidence_pass: compact.official_evidence_pass,
    judge_score: compact.judge_score,
    judge_path: compact.judge_path,
  });
  fs.writeFileSync(args.ledger.summary, `${JSON.stringify(summarize(results), null, 2)}\n`);
}

function sha256File(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function normalizeText(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function answerInText(answer, text) {
  const a = normalizeText(answer);
  const t = normalizeText(text);
  if (!a || !t) return false;
  if (t.includes(a)) return true;

  const answerWords = a.split(' ').filter(w => w.length > 2);
  if (answerWords.length === 0) return false;
  const textWords = new Set(t.split(' '));
  const matched = answerWords.filter(w => textWords.has(w)).length;
  return matched / answerWords.length >= 0.8;
}

function safeKeyPart(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 120);
}

function stringifyMessage(message) {
  const role = String(message?.role || message?.speaker || 'unknown').toUpperCase();
  const content = String(message?.content || message?.text || '').trim();
  return `[${role}]\n${content}`;
}

/**
 * Build the LongMemEval dataset for the harness.
 *
 * Supports two input formats from DATASET_FILE.longmemeval:
 *
 * Format A — original flat row format (official-longmemeval-aimos.json):
 *   Each row has: question_id, haystack_sessions[], haystack_session_ids[],
 *   haystack_dates[], question, answer, question_type, answer_session_ids[].
 *
 * Format B — scenario format (longmemeval-full.json, produced by prepare-longmemeval.mjs):
 *   Each scenario has: id, sessions[{id, messages[]}], questions[{id, question, answer, category}].
 *
 * The format is auto-detected from the first element's shape.
 * Run eval/prepare-longmemeval.mjs to inspect the transform from Format B → human-readable diff.
 */
function buildLongMemEval(datasetFile = DATASET_FILE.longmemeval) {
  const raw = JSON.parse(fs.readFileSync(datasetFile, 'utf8'));
  const sessions = new Map();
  const questions = [];

  // Detect format: Format A has question_id at top level; Format B has sessions + questions per scenario.
  const isFormatA = Array.isArray(raw) && raw.length > 0 && raw[0].question_id !== undefined;

  if (isFormatA) {
    // Format A: flat question rows, each carrying their own haystack sessions
    for (const row of raw) {
      const questionId = String(row.question_id);
      const haystackSessions = row.haystack_sessions || [];
      const haystackSessionIds = row.haystack_session_ids || [];
      const haystackDates = row.haystack_dates || [];
      const effectiveSessionIds = haystackSessions.map((_, index) =>
        String(haystackSessionIds[index] || `${questionId}:${index}`)
      );

      for (let i = 0; i < haystackSessions.length; i += 1) {
        const sessionId = effectiveSessionIds[i];
        if (!sessions.has(sessionId)) {
          const transcript = (haystackSessions[i] || [])
            .map(stringifyMessage)
            .join('\n\n');
          sessions.set(sessionId, {
            benchmark: 'longmemeval',
            dataset: 'longmemeval-full',
            sessionId,
            sampleId: questionId,
            date: haystackDates[i] || row.question_date || null,
            key: `benchmark:longmemeval:official:session:${safeKeyPart(sessionId)}`,
            value: [
              'BENCHMARK_EVIDENCE',
              'benchmark: LongMemEval',
              'dataset: longmemeval-full',
              `session_id: ${sessionId}`,
              `date: ${haystackDates[i] || ''}`,
              '',
              transcript,
            ].join('\n'),
          });
        }
      }

      questions.push({
        benchmark: 'longmemeval',
        id: questionId,
        question: String(row.question || ''),
        answer: String(row.answer ?? ''),
        category: String(row.question_type || 'unknown'),
        expectedEvidence: (row.answer_session_ids || []).map(String),
        retrievalSessions: effectiveSessionIds,
        source: SOURCE.longmemeval,
      });
    }
  } else {
    // Format B: scenario-keyed format (longmemeval-full.json)
    // Each top-level entry is a scenario with its own sessions and questions.
    for (const scenario of raw) {
      const scenarioId = String(scenario.id || '');
      const scenarioSessions = Array.isArray(scenario.sessions) ? scenario.sessions : [];

      for (const session of scenarioSessions) {
        const sessionId = `${scenarioId}:${session.id || ''}`;
        if (!sessions.has(sessionId)) {
          const messages = Array.isArray(session.messages) ? session.messages : [];
          const transcript = messages.map(stringifyMessage).join('\n\n');
          sessions.set(sessionId, {
            benchmark: 'longmemeval',
            dataset: 'longmemeval-full',
            sessionId,
            sampleId: scenarioId,
            date: session.date || null,
            key: `benchmark:longmemeval:official:session:${safeKeyPart(sessionId)}`,
            value: [
              'BENCHMARK_EVIDENCE',
              'benchmark: LongMemEval',
              'dataset: longmemeval-full',
              `scenario_id: ${scenarioId}`,
              `session_id: ${sessionId}`,
              `date: ${session.date || ''}`,
              '',
              transcript,
            ].join('\n'),
          });
        }
      }

      for (const q of (Array.isArray(scenario.questions) ? scenario.questions : [])) {
        const questionId = `${scenarioId}:${q.id || ''}`;
        // In Format B there are no explicit answer_session_ids; all sessions are haystack sessions.
        const allSessionIds = scenarioSessions.map(s => `${scenarioId}:${s.id || ''}`);
        questions.push({
          benchmark: 'longmemeval',
          id: questionId,
          question: String(q.question || ''),
          answer: String(q.answer ?? ''),
          category: String(q.category || q.question_type || 'unknown'),
          expectedEvidence: allSessionIds,
          retrievalSessions: allSessionIds,
          source: SOURCE.longmemeval,
        });
      }
    }
  }

  return { benchmark: 'longmemeval', source: SOURCE.longmemeval, questions, sessions: [...sessions.values()] };
}

function buildLoCoMo() {
  const rows = JSON.parse(fs.readFileSync(DATASET_FILE.locomo, 'utf8'));
  const sessions = [];
  const questions = [];

  for (const row of rows) {
    const sampleId = String(row.sample_id);
    const conversation = row.conversation || {};
    const evidenceToSession = new Map();
    const sampleSessionIds = [];

    for (const [key, turns] of Object.entries(conversation)) {
      const match = key.match(/^session_(\d+)$/);
      if (!match || !Array.isArray(turns)) continue;

      const sessionNumber = match[1];
      const sessionId = `${sampleId}:session_${sessionNumber}`;
      sampleSessionIds.push(sessionId);
      const date = conversation[`session_${sessionNumber}_date_time`] || null;
      const transcript = turns.map(turn => {
        if (turn?.dia_id) evidenceToSession.set(String(turn.dia_id), sessionId);
        const media = turn?.blip_caption ? `\n[MEDIA] ${turn.blip_caption}` : '';
        const query = turn?.query ? `\n[QUERY] ${turn.query}` : '';
        return `[${turn?.dia_id || '?'}] ${turn?.speaker || 'unknown'}: ${turn?.text || ''}${media}${query}`;
      }).join('\n');

      sessions.push({
        benchmark: 'locomo',
        dataset: 'official-locomo10',
        sessionId,
        sampleId,
        date,
        key: `benchmark:locomo:official:session:${safeKeyPart(sessionId)}`,
        value: [
          'BENCHMARK_EVIDENCE',
          'benchmark: LoCoMo',
          'dataset: official-locomo10',
          `sample_id: ${sampleId}`,
          `session_id: ${sessionId}`,
          `date: ${date || ''}`,
          '',
          transcript,
        ].join('\n'),
      });
    }

    for (let i = 0; i < (row.qa || []).length; i += 1) {
      const qa = row.qa[i];
      const evidence = (qa.evidence || []).map(String);
      const expectedSessions = [...new Set(evidence.map(id => evidenceToSession.get(id)).filter(Boolean))];
      questions.push({
        benchmark: 'locomo',
        id: `${sampleId}:q${String(i + 1).padStart(3, '0')}`,
        question: String(qa.question || ''),
        answer: String(qa.answer ?? ''),
        category: CATEGORY_MAP_LOCOMO[qa.category] || `category-${qa.category}`,
        expectedEvidence: evidence,
        expectedSessions,
        retrievalSessions: sampleSessionIds,
        source: SOURCE.locomo,
      });
    }
  }

  return { benchmark: 'locomo', source: SOURCE.locomo, questions, sessions };
}

function selectQuestions(dataset, args) {
  if (args.full) return dataset.questions;
  return dataset.questions.slice(args.offset, args.offset + args.sample);
}

class AimosHttp {
  constructor({ baseUrl, agentId, requestIntervalMs = 2100 }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.agentId = agentId;
    this.requestIntervalMs = requestIntervalMs;
    this.lastRequestAt = 0;
  }

  async pace() {
    const waitMs = this.requestIntervalMs - (Date.now() - this.lastRequestAt);
    if (waitMs > 0) await sleep(waitMs);
    this.lastRequestAt = Date.now();
  }

  async headers(method, pathname, body = {}, includeJson = false) {
    const headers = await buildEnvelopeHeaders(this.agentId, method, pathname, body);
    if (includeJson) headers['Content-Type'] = 'application/json';
    return headers;
  }

  async get(pathname, params = {}) {
    await this.pace();
    const url = new URL(`${this.baseUrl}${pathname}`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
    const started = Date.now();
    const res = await fetch(url, {
      method: 'GET',
      headers: await this.headers('GET', pathname, {}),
      signal: AbortSignal.timeout(90_000),
    });
    const body = await readJsonResponse(res);
    return { status: res.status, ok: res.ok, latencyMs: Date.now() - started, body };
  }

  async post(pathname, body) {
    await this.pace();
    const started = Date.now();
    const res = await fetch(`${this.baseUrl}${pathname}`, {
      method: 'POST',
      headers: await this.headers('POST', pathname, body, true),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(45_000),
    });
    const parsed = await readJsonResponse(res);
    return { status: res.status, ok: res.ok, latencyMs: Date.now() - started, body: parsed };
  }
}

async function readJsonResponse(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text.slice(0, 1000) };
  }
}

async function recall(aimos, question, source, options = {}) {
  const params = {
    q: question,
    limit: options.limit || 20,
    clearance_level: 10,
    source_filter: source,
    memory_type_filter: normalizeMemoryTypeFilter(options.memoryTypeFilter ?? 'session_debrief'),
    answer_shape: options.answerShape,
  };
  const retries = Math.max(1, Number(options.retries || 3));
  let last = null;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      last = await aimos.post('/aimos/recall', params);
      if (last.ok || ![0, 408, 425, 429, 500, 502, 503, 504].includes(Number(last.status))) {
        return last;
      }
    } catch (error) {
      last = {
        status: 0,
        ok: false,
        latencyMs: 90_000,
        body: { error: error?.message || String(error) },
      };
    }
    await sleep(1000 * attempt);
  }
  return last;
}

function memoryMatchesBenchmarkSource(memory, source) {
  const key = String(memory?.key || '');
  const value = String(memory?.value || '');
  const sourceValue = String(memory?.source || '');
  if (sourceValue === source) return true;
  if (source === SOURCE.longmemeval) {
    return key.startsWith('benchmark:longmemeval:official:')
      || value.includes('benchmark: LongMemEval');
  }
  if (source === SOURCE.locomo) {
    return key.startsWith('benchmark:locomo:official:')
      || value.includes('benchmark: LoCoMo');
  }
  return false;
}

function extractEvidenceIds(text) {
  const out = new Set();
  const raw = String(text || '');
  for (const match of raw.matchAll(/\bD\d+:\d+\b/g)) out.add(match[0]);
  for (const match of raw.matchAll(/\bsession_id:\s*([^\n]+)/gi)) out.add(match[1].trim());
  return out;
}

function rankFromIndex(index) {
  return index >= 0 ? index + 1 : null;
}

function minRank(...ranks) {
  const present = ranks.filter(rank => Number.isFinite(rank) && rank > 0);
  return present.length ? Math.min(...present) : null;
}

function hitAt(rank, k) {
  return Number.isFinite(rank) && rank > 0 && rank <= k;
}

function memoryHitProfile(question, memory) {
  const text = `${memory?.key || ''}\n${memory?.value || ''}`;
  const key = String(memory?.key || '');
  const extractedIds = extractEvidenceIds(text);
  const answer = answerInText(question.answer, text);
  const evidence = (question.expectedEvidence || []).some(id =>
    extractedIds.has(id) || key.includes(safeKeyPart(id))
  );
  const session = (question.expectedSessions || question.expectedEvidence || []).some(id =>
    key.includes(safeKeyPart(id)) || extractedIds.has(id)
  );
  return {
    answer,
    evidence,
    session,
    relevant: answer || evidence || session,
  };
}

/**
 * scoreRetrieval — measures whether the gold evidence or session entered the recalled set.
 *
 * This is a RETRIEVAL metric (recall@k, MRR). It answers:
 *   "Did the memory system surface the relevant evidence?"
 *
 * The returned `retrieval_hit` field MUST NOT be used as a QA correctness indicator.
 * For answer accuracy use scoreAnswer() (lexical) or judgeGeneratedAnswer() (LLM-judged).
 *
 * Renamed from scoreOfficial() per R6 Step 1 — separation of retrieval vs answer metrics.
 */
function scoreRetrieval(question, response) {
  const rawMemories = Array.isArray(response.body?.memories) ? response.body.memories : [];
  const memories = rawMemories.filter(memory => memoryMatchesBenchmarkSource(memory, question.source));
  const evidenceText = memories.map(m => `${m.key || ''}\n${m.value || ''}`).join('\n\n---\n\n');
  const returnedKeys = memories.map(m => String(m.key || ''));
  const extractedIds = extractEvidenceIds(evidenceText);
  const hitProfiles = memories.map(memory => memoryHitProfile(question, memory));

  const answerPresent = answerInText(question.answer, evidenceText);
  const expectedSessionHit = (question.expectedSessions || question.expectedEvidence || []).some(id =>
    returnedKeys.some(key => key.includes(safeKeyPart(id))) || extractedIds.has(id)
  );
  const expectedEvidenceHit = (question.expectedEvidence || []).some(id =>
    extractedIds.has(id) || returnedKeys.some(key => key.includes(safeKeyPart(id)))
  );

  const answerRank = rankFromIndex(hitProfiles.findIndex(hit => hit.answer));
  const expectedEvidenceRank = rankFromIndex(hitProfiles.findIndex(hit => hit.evidence));
  const expectedSessionRank = rankFromIndex(hitProfiles.findIndex(hit => hit.session));
  const bestRank = minRank(answerRank, expectedEvidenceRank, expectedSessionRank);
  const relevantReturned = hitProfiles.filter(hit => hit.relevant).length;
  // retrieval_hit: did the gold evidence/session appear in the recalled set?
  // This is recall@k, NOT answer accuracy. Do NOT interpret as QA correctness.
  const retrieval_hit = expectedEvidenceHit || expectedSessionHit;

  return {
    retrieval_hit,
    answer_present_in_evidence: answerPresent,
    expected_evidence_hit: expectedEvidenceHit,
    expected_session_hit: expectedSessionHit,
    answer_rank: answerRank,
    expected_evidence_rank: expectedEvidenceRank,
    expected_session_rank: expectedSessionRank,
    best_rank: bestRank,
    hit_at_1: hitAt(bestRank, 1),
    hit_at_5: hitAt(bestRank, 5),
    hit_at_10: hitAt(bestRank, 10),
    reciprocal_rank: bestRank ? 1 / bestRank : 0,
    relevant_returned: relevantReturned,
    observed_precision: memories.length ? relevantReturned / memories.length : 0,
    returned: memories.length,
    polluted_returned: rawMemories.length - memories.length,
    returned_keys: returnedKeys.slice(0, 10),
    latency_ms: response.latencyMs,
    http_status: response.status,
    error: response.ok ? null : response.body?.error || response.body?.raw || 'http_error',
  };
}

/**
 * scoreAnswer — lexical answer MEASUREMENTS only. No verdict.
 *
 * Returns { exact_match, f1, precision, recall } and NOTHING that decides
 * correctness. There is deliberately no `pass` field: any lexical F1 threshold
 * is an arbitrary cutoff that silently decides QA correctness by token overlap
 * — the same failure mode as the removed 80%-overlap auto-pass. For example
 * "his brother" vs "her brother" scores half F1; that must never count as a pass.
 *
 * Correctness verdicts come from ONE place only: the LLM judge
 * (judgeGeneratedAnswer → judged_correct). These are separate quantities.
 * Intentionally separate from scoreRetrieval(). Never OR them together.
 */
function scoreAnswer(question, candidateAnswer) {
  const normExpected = normalizeText(question.answer);
  const normCandidate = normalizeText(candidateAnswer);

  // Exact match after normalization (a measurement, not a verdict)
  const exact_match = normExpected.length > 0 && normExpected === normCandidate;

  // Token precision / recall / F1 over unigram tokens
  const expTokens = normExpected.split(' ').filter(Boolean);
  const candTokens = normCandidate.split(' ').filter(Boolean);
  let precision = 0;
  let recall = 0;
  let f1 = 0;
  if (expTokens.length > 0 && candTokens.length > 0) {
    const expSet = new Map();
    for (const t of expTokens) expSet.set(t, (expSet.get(t) || 0) + 1);
    let overlap = 0;
    for (const t of candTokens) {
      if ((expSet.get(t) || 0) > 0) {
        overlap += 1;
        expSet.set(t, expSet.get(t) - 1);
      }
    }
    precision = overlap / candTokens.length;
    recall = overlap / expTokens.length;
    f1 = (precision + recall > 0) ? (2 * precision * recall) / (precision + recall) : 0;
  }

  // Measurements ONLY. No `pass`. No threshold. The LLM judge decides correctness.
  return { exact_match, f1, precision, recall };
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function summarizeOfficialRankMetrics(rows) {
  const officialRows = rows
    .map(row => row.modes.official || row.modes.judge)
    .filter(mode => mode && Number.isFinite(Number(mode.reciprocal_rank)));
  const returned = officialRows.map(mode => Number(mode.returned || 0));
  return {
    hit_at_1: mean(officialRows.map(mode => mode.hit_at_1 ? 1 : 0)),
    hit_at_5: mean(officialRows.map(mode => mode.hit_at_5 ? 1 : 0)),
    hit_at_10: mean(officialRows.map(mode => mode.hit_at_10 ? 1 : 0)),
    mrr: mean(officialRows.map(mode => Number(mode.reciprocal_rank || 0))),
    observed_precision: mean(officialRows.map(mode => Number(mode.observed_precision || 0))),
    returned: {
      min: returned.length ? Math.min(...returned) : 0,
      median: median(returned),
      mean: mean(returned),
      max: returned.length ? Math.max(...returned) : 0,
    },
  };
}

function scoreAimosDiagnostic(question, response) {
  const body = response.body || {};
  const rawMemories = Array.isArray(body.memories) ? body.memories : [];
  const memories = rawMemories.filter(memory => memoryMatchesBenchmarkSource(memory, question.source));
  const cards = Array.isArray(body.evidence_cards) ? body.evidence_cards : [];
  const handles = Array.isArray(body.detail_handles) ? body.detail_handles : [];
  const combinedText = [
    body.summary,
    body.working_memory,
    ...memories.map(m => m.value),
    ...cards.map(c => c.text || c.summary || c.snippet),
  ].filter(Boolean).join('\n');

  return {
    answer_shape: body.answer_shape || null,
    answer_present: answerInText(question.answer, combinedText),
    returned: memories.length,
    polluted_returned: rawMemories.length - memories.length,
    evidence_cards: cards.length,
    detail_handles: handles.length,
    raw_memory_count: body.diagnostics?.raw_memory_count ?? body.recall_meta?.raw_memory_count ?? null,
    estimated_tokens: body.diagnostics?.estimated_tokens ?? null,
    temporal_scope: body.recall_meta?.temporal_scope?.dayBuckets || body.diagnostics?.temporal_scope || [],
    latency_ms: response.latencyMs,
    http_status: response.status,
    error: response.ok ? null : body.error || body.raw || 'http_error',
  };
}

function evidenceTextFromResponse(question, response, maxChars = 32000) {
  const rawMemories = Array.isArray(response.body?.memories) ? response.body.memories : [];
  const memories = rawMemories.filter(memory => memoryMatchesBenchmarkSource(memory, question.source));
  const supportBlock = nativeSupportTextFromResponse(response, Math.min(6000, Math.floor(maxChars * 0.24)));
  const remainingChars = Math.max(1000, maxChars - supportBlock.length - (supportBlock ? 16 : 0));
  const blocks = memories.map((memory, index) => [
    `EVIDENCE_${index + 1}`,
    `key: ${memory.key || ''}`,
    `created_at: ${memory.created_at || ''}`,
    `valid_from: ${memory.valid_from || ''}`,
    `valid_until: ${memory.valid_until || ''}`,
    '',
    String(memory.value || '').slice(0, Math.max(1000, Math.floor(remainingChars / Math.max(1, memories.length)))),
  ].join('\n'));
  return [
    supportBlock,
    blocks.join('\n\n---\n\n'),
  ].filter(Boolean).join('\n\n---\n\n').slice(0, maxChars);
}

function nativeSupportFromResponse(response) {
  const support = response.body?.answer_generation_support
    || response.body?.recall_meta?.answer_generation_support
    || null;
  return support && typeof support === 'object' ? support : null;
}

function nativeSupportHintNames(response) {
  const support = nativeSupportFromResponse(response);
  if (!support) return [];
  if (Array.isArray(support.active_hints)) return support.active_hints;
  const hints = support.hints && typeof support.hints === 'object' ? support.hints : {};
  return Object.keys(hints).filter(key => String(hints[key] || '').trim());
}

function nativeSupportTextFromResponse(response, maxChars = 6000) {
  const support = nativeSupportFromResponse(response);
  if (!support) return '';
  const hints = support.hints && typeof support.hints === 'object' ? support.hints : {};
  const hintBlocks = Object.entries(hints)
    .filter(([, value]) => String(value || '').trim())
    .map(([key, value]) => [
      `hint: ${key}`,
      String(value || '').trim(),
    ].join('\n'));
  if (!hintBlocks.length) return '';
  return [
    'AIMOS_NATIVE_CALIBRATION',
    `support_version: ${support.support_version || 'unknown'}`,
    `source: ${support.source || 'native_recall_output_calibrator'}`,
    `intent: ${support.intent || ''}`,
    'expected_answer_visible: false',
    'benchmark_row_ids_visible: false',
    'native_rank_override: false',
    '',
    ...hintBlocks,
  ].join('\n').slice(0, maxChars);
}

function parseJsonObject(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {}
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) {
    try {
      return JSON.parse(fenced[1].trim());
    } catch {}
  }
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(text.slice(start, end + 1));
    } catch {}
  }
  return null;
}

function providerResetSecondsFromError(error) {
  const message = String(error?.message || error || '');
  if (!/\b429\b|usage_limit|rate_limit|resets_in_seconds/i.test(message)) return null;
  const jsonMatch = message.match(/\{[\s\S]*\}$/);
  if (!jsonMatch) return null;
  try {
    const parsed = JSON.parse(jsonMatch[0]);
    const seconds = Number(parsed?.error?.resets_in_seconds ?? parsed?.resets_in_seconds);
    return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
  } catch {
    return null;
  }
}

async function runBenchmarkProvider(payload, args, role) {
  const maxAttempts = Math.max(1, Math.trunc(args.providerRetryLimit || 0) + 1);
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await runProvider(payload);
    } catch (error) {
      const resetSeconds = providerResetSecondsFromError(error);
      const canRetry = resetSeconds !== null
        && resetSeconds <= args.providerMaxResetWaitSeconds
        && attempt < maxAttempts;
      if (!canRetry) throw error;
      const waitMs = Math.ceil((resetSeconds + 5) * 1000);
      console.log(`[provider:${role}] temporary quota/rate limit; retry ${attempt}/${maxAttempts - 1} after ${resetSeconds}s`);
      await sleep(waitMs);
    }
  }
  throw new Error(`[provider:${role}] exhausted provider retry loop`);
}

async function generateAnswerFromEvidence(question, response, args) {
  const evidence = evidenceTextFromResponse(question, response, args.judgeMaxChars);
  if (!evidence.trim()) {
    return {
      answer: 'insufficient_evidence',
      evidence_keys: [],
      confidence: 0,
      raw: '',
      parsed: null,
      error: 'no_evidence_returned',
    };
  }

  const systemPrompt = [
    `Prompt: ${ANSWER_GENERATOR_PROMPT_VERSION}`,
    'You answer benchmark memory questions using only the provided Aimos evidence.',
    'Do not use outside knowledge. Do not infer from the expected answer; it is not provided.',
    'The evidence may contain distractors. Resolve temporal, entity, and preference constraints from the evidence.',
    'If AIMOS_NATIVE_CALIBRATION is present, treat its hints as deterministic arithmetic or sufficiency analysis derived from the native Aimos evidence, unless contradicted by stronger evidence.',
    'For temporal/order/delta/count questions, combine dated evidence blocks and compute the interval.',
    'When AGGREGATE_OPERATION_HINT is present, answer from preferred_answer or preferred_count after checking its distinct evidence rows; do not recount unrelated distractors.',
    'When CONTRASTIVE_ABSENCE_HINT is present, answer from its preferred_answer: state insufficient evidence and include the missing role/location/entity contrast.',
    'If a temporal hint says precision: approximate or includes exact_day_count_is_derived_from_coarse_month_cues, answer with preferred_answer or the nearest natural interval, not the exact derived day count.',
    'When COMPARISON_SUFFICIENCY_HINT says insufficient_pair_evidence, answer insufficient_evidence unless another deterministic hint fully grounds both comparison roles.',
    'When CURRENT_STATE_HINT is present, answer from its latest/direct state unless later stronger evidence contradicts it.',
    'When PREFERENCE_GROUNDING_HINT is present, use its highest-specificity matching preference rows; if it includes preferred_answer, answer at that evidence-grounded criteria level and do not invent unsupported venues or events.',
    'When SPEAKER_TEMPORAL_POINT_HINT is present, answer with its preferred absolute date/year/month instead of repeating a relative phrase.',
    'When SPEAKER_INFERENCE_HINT is present, use its smallest evidence-grounded bridge unless stronger same-speaker evidence contradicts it.',
    'When TEMPORAL_HINT includes preferred_answer, use that answer; otherwise report the requested exclusive/inclusive interval according to the question wording.',
    'For current-state questions, prefer the latest directly relevant state and mention the current value only.',
    'For preference/user-fact questions, extract the specific fact from speaker-bound evidence.',
    'Return the best supported concise answer when any evidence block supports one.',
    'Use "insufficient_evidence" only when no evidence block supports a concrete answer.',
    'Return compact JSON only with keys: answer, evidence_keys, confidence, rationale.',
  ].join('\n');
  const userPrompt = [
    `Question: ${question.question}`,
    '',
    'Aimos evidence:',
    evidence,
  ].join('\n');

  const raw = await runBenchmarkProvider({
    provider: args.generatorProvider,
    model: args.generatorModel,
    systemPrompt,
    userPrompt,
  }, args, 'generator');
  const parsed = parseJsonObject(raw);
  return {
    answer: String(parsed?.answer || raw || '').trim(),
    evidence_keys: Array.isArray(parsed?.evidence_keys) ? parsed.evidence_keys : [],
    confidence: Number(parsed?.confidence ?? 0),
    rationale: String(parsed?.rationale || ''),
    raw,
    parsed,
    error: null,
  };
}

async function judgeGeneratedAnswer(question, generated, args) {
  const lexicalMatch = answerInText(question.answer, generated.answer);
  if (lexicalMatch && !args.disableLexicalAutoPass) {
    // AUDIT LOG: every lexical auto-pass is logged so the rate is auditable.
    // To disable: pass --disable-lexical-auto-pass (which is now the DEFAULT).
    console.warn(
      `[LEXICAL_AUTO_PASS] id=${question.id} expected=${String(question.answer).slice(0, 80)} generated=${String(generated.answer).slice(0, 80)}`
    );
    return {
      judged_correct: true,
      score: 1,
      reason: 'exact_or_token_overlap_match',
      judge_path: 'lexical_auto_pass',
      lexical_auto_pass: true,
      lexical_match: true,
      raw: '',
      parsed: null,
      error: null,
    };
  }

  const systemPrompt = [
    `Prompt: ${ANSWER_JUDGE_PROMPT_VERSION}`,
    'You are a strict benchmark judge.',
    'Compare the expected answer and generated answer for semantic equivalence.',
    'Return compact JSON only with keys: pass, score, reason.',
    'Score 1.0 means equivalent; 0.0 means wrong; pass requires semantic equivalence.',
  ].join('\n');
  const userPrompt = [
    `Question: ${question.question}`,
    `Expected answer: ${question.answer}`,
    `Generated answer: ${generated.answer}`,
  ].join('\n');

  const raw = await runBenchmarkProvider({
    provider: args.judgeProvider,
    model: args.judgeModel,
    systemPrompt,
    userPrompt,
  }, args, 'judge');
  const parsed = parseJsonObject(raw);
  const score = Number(parsed?.score ?? 0);
  return {
    judged_correct: parsed?.pass === true || score >= 0.85,
    score: Number.isFinite(score) ? score : 0,
    reason: String(parsed?.reason || ''),
    judge_path: 'model_judge',
    lexical_auto_pass: false,
    lexical_match: lexicalMatch,
    raw,
    parsed,
    error: null,
  };
}

async function scoreJudgedAnswer(question, response, args) {
  const retrieval = scoreRetrieval(question, response);
  try {
    const generated = await generateAnswerFromEvidence(question, response, args);
    const judged = await judgeGeneratedAnswer(question, generated, args);
    // Lexical MEASUREMENTS only (no verdict) — computed on the generated answer.
    const lexical = scoreAnswer(question, generated.answer);
    return {
      // judged_correct is the ONLY correctness verdict; it comes from the LLM judge.
      judged_correct: judged.judged_correct,
      retrieval_hit: retrieval.retrieval_hit,
      // retained for backward compat with downstream ledger readers; mirrors retrieval_hit
      official_evidence_pass: retrieval.retrieval_hit,
      // lexical measurements — descriptive only, never decide correctness
      answer_exact_match: lexical.exact_match,
      answer_f1: lexical.f1,
      answer_precision: lexical.precision,
      answer_recall: lexical.recall,
      generated_answer: generated.answer,
      generator_confidence: generated.confidence,
      generator_rationale: generated.rationale,
      generated_evidence_keys: generated.evidence_keys,
      native_support_hints: nativeSupportHintNames(response),
      judge_score: judged.score,
      judge_reason: judged.reason,
      judge_path: judged.judge_path,
      lexical_auto_pass: judged.lexical_auto_pass,
      lexical_match: judged.lexical_match,
      answer_rank: retrieval.answer_rank,
      expected_evidence_rank: retrieval.expected_evidence_rank,
      expected_session_rank: retrieval.expected_session_rank,
      best_rank: retrieval.best_rank,
      hit_at_1: retrieval.hit_at_1,
      hit_at_5: retrieval.hit_at_5,
      hit_at_10: retrieval.hit_at_10,
      reciprocal_rank: retrieval.reciprocal_rank,
      relevant_returned: retrieval.relevant_returned,
      observed_precision: retrieval.observed_precision,
      returned: retrieval.returned,
      polluted_returned: retrieval.polluted_returned,
      returned_keys: retrieval.returned_keys,
      latency_ms: response.latencyMs,
      http_status: response.status,
      error: generated.error || judged.error || null,
      prompt_versions: {
        generator: ANSWER_GENERATOR_PROMPT_VERSION,
        judge: ANSWER_JUDGE_PROMPT_VERSION,
      },
    };
  } catch (error) {
    return {
      // judge did not run — no verdict. null excludes this item from judged accuracy denominator.
      judged_correct: null,
      retrieval_hit: retrieval.retrieval_hit,
      official_evidence_pass: retrieval.retrieval_hit,
      answer_exact_match: null,
      answer_f1: null,
      answer_precision: null,
      answer_recall: null,
      generated_answer: null,
      generator_confidence: 0,
      generator_rationale: '',
      generated_evidence_keys: [],
      native_support_hints: nativeSupportHintNames(response),
      judge_score: 0,
      judge_reason: '',
      judge_path: 'error',
      lexical_auto_pass: false,
      lexical_match: false,
      answer_rank: retrieval.answer_rank,
      expected_evidence_rank: retrieval.expected_evidence_rank,
      expected_session_rank: retrieval.expected_session_rank,
      best_rank: retrieval.best_rank,
      hit_at_1: retrieval.hit_at_1,
      hit_at_5: retrieval.hit_at_5,
      hit_at_10: retrieval.hit_at_10,
      reciprocal_rank: retrieval.reciprocal_rank,
      relevant_returned: retrieval.relevant_returned,
      observed_precision: retrieval.observed_precision,
      returned: retrieval.returned,
      polluted_returned: retrieval.polluted_returned,
      returned_keys: retrieval.returned_keys,
      latency_ms: response.latencyMs,
      http_status: response.status,
      error: error?.message || String(error),
      prompt_versions: {
        generator: ANSWER_GENERATOR_PROMPT_VERSION,
        judge: ANSWER_JUDGE_PROMPT_VERSION,
      },
    };
  }
}

function evidenceScope(dataset, args) {
  const questions = selectQuestions(dataset, args);
  const requiredSessionIds = new Set(
    questions.flatMap(question => question.retrievalSessions || [])
  );
  const sessions = requiredSessionIds.size
    ? dataset.sessions.filter(session => requiredSessionIds.has(session.sessionId))
    : dataset.sessions;
  const digest = createHash('sha256')
    .update(JSON.stringify({
      questions: questions.map(question => question.id),
      sessions: sessions.map(session => session.key),
    }))
    .digest('hex')
    .slice(0, 16);
  return { questions, sessions, digest };
}

async function hasSentinel(aimos, dataset, scope) {
  const sentinelKey = `benchmark:${dataset.benchmark}:official:sentinel:${scope.digest}`;
  const res = await recall(aimos, `full detail ${sentinelKey}`, dataset.source, {
    limit: 3,
    answerShape: 'full_detail',
  });
  const memories = Array.isArray(res.body?.memories) ? res.body.memories : [];
  return {
    present: memories.some(m => String(m.key || '').includes(sentinelKey)),
    status: res.status,
    returned: memories.length,
  };
}

async function saveEvidence(aimos, dataset, args) {
  const scope = evidenceScope(dataset, args);
  const sentinel = await hasSentinel(aimos, dataset, scope);
  if (sentinel.present && args.ingestMissing) {
    return { skipped: true, reason: 'sentinel_present', saved: 0, failed: 0, total: scope.sessions.length };
  }
  if (!args.ingestMissing) {
    return { skipped: true, reason: 'ingest_not_requested', saved: 0, failed: 0, total: scope.sessions.length };
  }

  const presentKeys = await existingEvidenceKeys(dataset, scope.sessions);
  const sessionsToSave = scope.sessions.filter(session => !presentKeys.has(session.key));
  let saved = 0;
  let failed = 0;
  let skippedExisting = scope.sessions.length - sessionsToSave.length;
  if (skippedExisting > 0) {
    console.log(`[ingest:${dataset.benchmark}] skipping ${skippedExisting} existing evidence rows`);
  }

  for (const session of sessionsToSave) {
    const body = {
      key: session.key,
      value: session.value,
      memory_type: 'session_debrief',
      source: dataset.source,
      agent_id: args.agentId,
      company_id: 'hom',
      clearance_level: 10,
      scope: 'global',
      metadata: {
        benchmark: dataset.benchmark,
        dataset: session.dataset,
        session_id: session.sessionId,
        sample_id: session.sampleId,
        date: session.date,
        answer_key_included: false,
      },
    };
    const res = await postWithRetry(aimos, '/aimos/save', body, args);
    if (res.ok) saved += 1;
    else failed += 1;
    if ((saved + failed) % 50 === 0) {
      console.log(`[ingest:${dataset.benchmark}] ${saved + failed}/${sessionsToSave.length} saved=${saved} failed=${failed} skipped=${skippedExisting}`);
    }
    if (args.ingestDelayMs > 0) {
      await sleep(args.ingestDelayMs);
    }
  }

  const sentinelBody = {
    key: `benchmark:${dataset.benchmark}:official:sentinel:${scope.digest}`,
    value: [
      'BENCHMARK_INGEST_SENTINEL',
      `benchmark: ${dataset.benchmark}`,
      `source: ${dataset.source}`,
      `sessions: ${scope.sessions.length}`,
      `questions: ${scope.questions.length}`,
      `ingested_at: ${new Date().toISOString()}`,
      'answer_key_included: false',
    ].join('\n'),
    memory_type: 'session_debrief',
    source: dataset.source,
    agent_id: args.agentId,
    company_id: 'hom',
    clearance_level: 10,
    scope: 'global',
  };
  const sentinelSave = await postWithRetry(aimos, '/aimos/save', sentinelBody, args);
  if (!sentinelSave.ok) failed += 1;

  return { skipped: false, saved, failed, skipped_existing: skippedExisting, total: scope.sessions.length, sentinel_status: sentinelSave.status };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function existingEvidenceKeys(dataset, sessions = dataset.sessions) {
  const keys = sessions.map(session => session.key);
  const present = new Set();
  for (let i = 0; i < keys.length; i += 500) {
    const chunk = keys.slice(i, i + 500);
    const res = await pool.query(
      `
      SELECT key
      FROM aimos_memories
      WHERE company_id = 'hom'
        AND source = $1
        AND key = ANY($2::text[])
      `,
      [dataset.source, chunk]
    );
    for (const row of res.rows) present.add(row.key);
  }
  return present;
}

async function postWithRetry(aimos, pathname, body, args) {
  let last = null;
  for (let attempt = 1; attempt <= args.retries; attempt += 1) {
    last = await aimos.post(pathname, body);
    if (last.ok) return last;
    if (![408, 409, 425, 429, 500, 502, 503, 504].includes(Number(last.status))) return last;
    const waitMs = Math.max(args.ingestDelayMs, 1000) * attempt;
    await sleep(waitMs);
  }
  return last;
}

async function runDataset(aimos, dataset, args) {
  const questions = selectQuestions(dataset, args);
  const modes = args.mode === 'both'
    ? ['official', 'aimos']
    : args.mode === 'all'
      ? ['official', 'aimos', 'judge']
      : [args.mode];
  const results = [];

  for (let i = 0; i < questions.length; i += 1) {
    const q = questions[i];
    const row = {
      benchmark: q.benchmark,
      id: q.id,
      category: q.category,
      question: q.question,
      expected_answer: q.answer,
      expected_evidence: q.expectedEvidence,
      modes: {},
    };

    if (modes.includes('official')) {
      const res = await recall(aimos, q.question, q.source, {
        limit: args.limit,
        answerShape: 'full_detail',
        memoryTypeFilter: args.memoryTypeFilter,
      });
      row.modes.official = scoreRetrieval(q, res);
      if (args.recordDir) {
        appendJsonl(path.join(args.recordDir, 'responses.jsonl'), {
          mode: 'official', question: q, response: { body: res.body, status: res.status, ok: res.ok, latencyMs: res.latencyMs },
        });
      }
    }

    if (modes.includes('aimos')) {
      const res = await recall(aimos, q.question, q.source, {
        limit: args.limit,
        memoryTypeFilter: args.memoryTypeFilter,
      });
      row.modes.aimos = scoreAimosDiagnostic(q, res);
      if (args.recordDir) {
        appendJsonl(path.join(args.recordDir, 'responses.jsonl'), {
          mode: 'aimos', question: q, response: { body: res.body, status: res.status, ok: res.ok, latencyMs: res.latencyMs },
        });
      }
    }

    if (modes.includes('judge')) {
      const res = await recall(aimos, q.question, q.source, {
        limit: args.limit,
        answerShape: 'full_detail',
        memoryTypeFilter: args.memoryTypeFilter,
      });
      row.modes.judge = await scoreJudgedAnswer(q, res, args);
      if (args.recordDir) {
        appendJsonl(path.join(args.recordDir, 'responses.jsonl'), {
          mode: 'judge',
          question: q,
          response: { body: res.body, status: res.status, ok: res.ok, latencyMs: res.latencyMs },
          generated_answer: row.modes.judge?.generated_answer || null,
          judge_verdict: {
            judged_correct: row.modes.judge?.judged_correct,
            answer_exact_match: row.modes.judge?.answer_exact_match,
            answer_f1: row.modes.judge?.answer_f1,
            answer_precision: row.modes.judge?.answer_precision,
            answer_recall: row.modes.judge?.answer_recall,
            score: row.modes.judge?.judge_score,
            reason: row.modes.judge?.judge_reason,
            judge_path: row.modes.judge?.judge_path,
            lexical_auto_pass: row.modes.judge?.lexical_auto_pass,
            lexical_match: row.modes.judge?.lexical_match,
          },
        });
      }
    }

    results.push(row);
    if (Array.isArray(args.ledgerAggregate)) args.ledgerAggregate.push(row);
    writeLedgerProgress(
      args,
      row,
      dataset,
      i,
      questions.length,
      Array.isArray(args.ledgerAggregate) ? args.ledgerAggregate : results
    );
    const official = row.modes.official;
    const aimosMode = row.modes.aimos;
    const judgeMode = row.modes.judge;
    // Console status only. Judge mode: judged_correct (LLM verdict); null verdict → DIAG.
    // Retrieval-only mode: retrieval_hit (a retrieval result, NOT a QA verdict).
    const primaryStatus = judgeMode
      ? judgeMode.judged_correct
      : (official ? official.retrieval_hit : null);
    const status = (primaryStatus === true || primaryStatus === false)
      ? (primaryStatus ? 'PASS' : 'FAIL')
      : 'DIAG';
    if (status === 'FAIL' || (i + 1) % args.progressEvery === 0 || i === 0 || i === questions.length - 1) {
      console.log(`[${dataset.benchmark}] ${i + 1}/${questions.length} ${status} ${q.id} ${q.question.slice(0, 80)}`);
      if (aimosMode?.answer_shape) {
        console.log(`  aimos_shape=${aimosMode.answer_shape} cards=${aimosMode.evidence_cards} handles=${aimosMode.detail_handles}`);
      }
      if (judgeMode?.generated_answer) {
        console.log(`  judge_score=${judgeMode.judge_score} answer=${String(judgeMode.generated_answer).slice(0, 100)}`);
      }
    }
  }

  return results;
}

/**
 * accumulateRow — fold one result row into a summary accumulator.
 * Keeps the four metric families strictly separate:
 *   retrieval (official_correct), lexical exact-match, lexical F1, LLM-judged correctness.
 * A judge item counts toward judged_n ONLY if it produced a boolean verdict
 * (judged_correct === true|false); a null verdict (judge did not run) is excluded.
 */
function accumulateRow(acc, row) {
  const judge = row.modes.judge;
  // retrieval_hit: gold evidence/session entered the recalled set (recall@k, NOT QA accuracy)
  const retrievalHit = row.modes.official?.retrieval_hit ?? judge?.retrieval_hit ?? false;
  if (retrievalHit) acc.official_correct += 1;

  if (judge) {
    // Lexical measurements — descriptive only, never a verdict.
    if (judge.answer_exact_match !== null && judge.answer_exact_match !== undefined) {
      acc.answer_measured_n += 1;
      if (judge.answer_exact_match === true) acc.answer_exact_match_count += 1;
      if (typeof judge.answer_f1 === 'number') acc.answer_f1_sum += judge.answer_f1;
    }
    // LLM-judged correctness — the ONLY correctness verdict. null (judge did not run) excluded.
    if (judge.judged_correct === true || judge.judged_correct === false) {
      acc.judged_n += 1;
      if (judge.judged_correct === true) acc.judged_correct_count += 1;
    }
    if (judge.judge_path === 'model_judge') acc.model_judged_total += 1;
    if (judge.lexical_auto_pass) acc.lexical_auto_pass_total += 1;
    if (judge.lexical_match) acc.lexical_match_total += 1;
  }
}

function summarize(results) {
  const summary = {};
  for (const row of results) {
    const bench = row.benchmark;
    summary[bench] ||= {
      total: 0,
      // retrieval
      official_correct: 0,          // count of retrieval_hit
      // answer — lexical measurements (descriptive; NOT correctness)
      answer_exact_match_count: 0,  // count of exact_match === true
      answer_f1_sum: 0,             // sum of f1 for averaging
      answer_measured_n: 0,         // items where lexical was measured
      // answer — LLM judge (the ONLY correctness verdict)
      judged_correct_count: 0,      // count of judged_correct === true
      judged_n: 0,                  // items where the judge produced a boolean verdict
      model_judged_total: 0,
      lexical_auto_pass_total: 0,
      lexical_match_total: 0,
      aimos_answer_present: 0,
      by_category: {},
      aimos_shapes: {},
    };
    const s = summary[bench];
    s.total += 1;
    accumulateRow(s, row);
    if (row.modes.aimos?.answer_present) s.aimos_answer_present += 1;
    const cat = row.category || 'unknown';
    s.by_category[cat] ||= {
      total: 0,
      official_correct: 0,
      answer_exact_match_count: 0,
      answer_f1_sum: 0,
      answer_measured_n: 0,
      judged_correct_count: 0,
      judged_n: 0,
      model_judged_total: 0,
      lexical_auto_pass_total: 0,
      lexical_match_total: 0,
    };
    s.by_category[cat].total += 1;
    accumulateRow(s.by_category[cat], row);
    const shape = row.modes.aimos?.answer_shape || 'none';
    s.aimos_shapes[shape] = (s.aimos_shapes[shape] || 0) + 1;
  }

  // Derive the four separate, clearly-named rates. Never combined.
  const deriveRates = (a) => {
    // 1) Retrieval: recall@k — gold evidence entered the recalled set. NOT QA accuracy.
    a.retrieval_recall_rate = a.total ? a.official_correct / a.total : 0;
    // 2) Answer exact-match rate — lexical measurement, descriptive only.
    a.answer_exact_match_rate = a.answer_measured_n ? a.answer_exact_match_count / a.answer_measured_n : null;
    // 3) Answer mean token-F1 — lexical measurement, descriptive only.
    a.answer_mean_f1 = a.answer_measured_n ? a.answer_f1_sum / a.answer_measured_n : null;
    // 4) Answer judged accuracy — LLM judge, the ONLY correctness verdict.
    //    Denominator is judged_n (items with a boolean verdict); null items excluded.
    a.answer_judged_accuracy = a.judged_n ? a.judged_correct_count / a.judged_n : null;
  };

  for (const s of Object.values(summary)) {
    deriveRates(s);
    s._notes = {
      retrieval_recall_rate: 'recall@k — gold evidence in recalled set; NOT answer accuracy',
      answer_exact_match_rate: 'lexical exact-match measurement; NOT a correctness verdict',
      answer_mean_f1: 'lexical token-F1 measurement; NOT a correctness verdict',
      answer_judged_accuracy: 'LLM-judge correctness over judged_n items (null verdicts excluded)',
    };
    s.aimos_answer_presence_rate = s.total ? s.aimos_answer_present / s.total : 0;
    for (const cat of Object.values(s.by_category)) {
      deriveRates(cat);
    }
  }
  for (const [bench, s] of Object.entries(summary)) {
    s.official_rank_metrics = summarizeOfficialRankMetrics(results.filter(row => row.benchmark === bench));
  }
  return summary;
}

function printConfig(args) {
  const config = {
    scoring: {
      lexical_auto_pass: !args.disableLexicalAutoPass,
      lexical_auto_pass_note: args.disableLexicalAutoPass
        ? 'DISABLED (default) — LLM judge used for all items'
        : 'ENABLED via --enable-lexical-auto-pass — every auto-pass is logged to stderr',
      no_lexical_threshold_decides_correctness: true,
      correctness_verdict_source: 'LLM judge ONLY (judged_correct). No lexical threshold '
        + '(no exact-match, no F1 cutoff) decides QA correctness. scoreAnswer() returns '
        + 'measurements only: { exact_match, f1, precision, recall } — never a pass/verdict.',
      retrieval_metric: 'scoreRetrieval() — recall@k / MRR / nDCG@k (evidence presence in recalled set)',
      answer_measurements: 'scoreAnswer() — exact_match, f1, precision, recall (DESCRIPTIVE ONLY)',
      answer_correctness: args.mode === 'judge' || args.mode === 'all'
        ? 'scoreJudgedAnswer() → judged_correct (LLM-judged; the only correctness verdict)'
        : 'not active (judge mode off) — retrieval metrics only',
      reported_rates: [
        'retrieval_recall_rate (from scoreRetrieval.retrieval_hit)',
        'answer_exact_match_rate (from scoreAnswer.exact_match; measurement)',
        'answer_mean_f1 (from scoreAnswer.f1; measurement)',
        'answer_judged_accuracy (from LLM judge; denominator = judged_n, null verdicts excluded)',
      ],
      retrieval_and_answer_are_separate: true,
    },
    dataset: {
      longmemeval: DATASET_FILE.longmemeval,
      locomo: DATASET_FILE.locomo,
    },
    run: {
      benchmark: args.benchmark,
      mode: args.mode,
      sample: args.full ? 'full' : args.sample,
      offset: args.offset,
      limit: args.limit,
      aimos_base: args.aimosBase,
      agent_id: args.agentId,
      record_dir: args.recordDir,
      replay_dir: args.replayDir,
      generator_provider: args.generatorProvider,
      generator_model: args.generatorModel,
      judge_provider: args.judgeProvider,
      judge_model: args.judgeModel,
    },
  };
  console.log(JSON.stringify(config, null, 2));
}

/**
 * replayRun — recompute metrics from previously recorded responses on disk.
 * Reads <replayDir>/responses.jsonl and <replayDir>/run-meta.json; no server, no DB, no API keys.
 */
async function replayRun(replayDir) {
  const metaPath = path.join(replayDir, 'run-meta.json');
  const responsesPath = path.join(replayDir, 'responses.jsonl');
  if (!fs.existsSync(metaPath)) throw new Error(`Replay dir missing run-meta.json: ${replayDir}`);
  if (!fs.existsSync(responsesPath)) throw new Error(`Replay dir missing responses.jsonl: ${replayDir}`);

  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const lines = fs.readFileSync(responsesPath, 'utf8').split('\n').filter(Boolean);
  const rows = [];
  for (const line of lines) {
    const recorded = JSON.parse(line);
    const question = recorded.question;
    const response = recorded.response;
    const modes = {};

    if (recorded.mode === 'official' || recorded.mode === 'both') {
      modes.official = scoreRetrieval(question, response);
    }
    if (recorded.mode === 'judge' || recorded.mode === 'all') {
      const retrieval = scoreRetrieval(question, response);
      // Replay judge verdict from disk (no LLM call)
      const judgeVerdict = recorded.judge_verdict || null;
      if (judgeVerdict) {
        modes.judge = {
          // judged_correct is the ONLY correctness verdict; replayed from recorded judge output.
          judged_correct: judgeVerdict.judged_correct ?? null,
          retrieval_hit: retrieval.retrieval_hit,
          official_evidence_pass: retrieval.retrieval_hit,
          // lexical measurements — descriptive only
          answer_exact_match: judgeVerdict.answer_exact_match ?? null,
          answer_f1: judgeVerdict.answer_f1 ?? null,
          answer_precision: judgeVerdict.answer_precision ?? null,
          answer_recall: judgeVerdict.answer_recall ?? null,
          generated_answer: recorded.generated_answer || '',
          judge_score: judgeVerdict.score,
          judge_reason: judgeVerdict.reason,
          judge_path: judgeVerdict.judge_path || 'replay',
          lexical_auto_pass: judgeVerdict.lexical_auto_pass || false,
          lexical_match: judgeVerdict.lexical_match || false,
          answer_rank: retrieval.answer_rank,
          expected_evidence_rank: retrieval.expected_evidence_rank,
          expected_session_rank: retrieval.expected_session_rank,
          best_rank: retrieval.best_rank,
          hit_at_1: retrieval.hit_at_1,
          hit_at_5: retrieval.hit_at_5,
          hit_at_10: retrieval.hit_at_10,
          reciprocal_rank: retrieval.reciprocal_rank,
          relevant_returned: retrieval.relevant_returned,
          observed_precision: retrieval.observed_precision,
          returned: retrieval.returned,
          polluted_returned: retrieval.polluted_returned,
          returned_keys: retrieval.returned_keys,
          latency_ms: response.latencyMs,
          http_status: response.status,
          error: null,
        };
      }
    }

    rows.push({
      benchmark: question.benchmark,
      id: question.id,
      category: question.category,
      question: question.question,
      expected_answer: question.answer,
      expected_evidence: question.expectedEvidence,
      modes,
    });
  }

  const summary = summarize(rows);
  const output = { meta: { ...meta, replayed_at: new Date().toISOString(), replay_dir: replayDir }, summary, results: rows };
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const replayOutputDir = path.resolve(meta.output_dir || RESULTS_DIR);
  const outFile = path.join(replayOutputDir, `replay-${stamp}.json`);
  fs.mkdirSync(replayOutputDir, { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
  console.log(JSON.stringify({ replayed: outFile, summary }, null, 2));
  return output;
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.printConfig) {
    printConfig(args);
    return;
  }

  if (args.replayDir) {
    await replayRun(args.replayDir);
    return;
  }

  const benchmarks = args.benchmark === 'both' ? ['longmemeval', 'locomo'] : [args.benchmark];
  const datasets = benchmarks.map(name => name === 'longmemeval' ? buildLongMemEval(args.longMemEvalFile) : buildLoCoMo());

  // Prepare record dir for --record mode
  if (args.recordDir) {
    fs.mkdirSync(args.recordDir, { recursive: true });
    fs.writeFileSync(path.join(args.recordDir, 'responses.jsonl'), '');
    console.log(`[record] Writing responses to ${args.recordDir}/responses.jsonl`);
  }

  fs.mkdirSync(args.outputDir, { recursive: true });
  args.ledger = prepareLedger(args);
  args.ledgerAggregate = args.ledger ? [] : null;
  const aimos = new AimosHttp({
    baseUrl: args.aimosBase,
    agentId: args.agentId,
    requestIntervalMs: args.requestIntervalMs,
  });

  const health = await fetch(`${args.aimosBase.replace(/\/$/, '')}/health`, {
    signal: AbortSignal.timeout(8_000),
  }).then(r => r.json()).catch(error => ({ ready: false, error: error.message }));

  const ingest = {};
  for (const dataset of datasets) {
    const scope = evidenceScope(dataset, args);
    const sentinel = await hasSentinel(aimos, dataset, scope);
    console.log(`[presence:${dataset.benchmark}] sentinel=${sentinel.present} returned=${sentinel.returned} status=${sentinel.status}`);
    ingest[dataset.benchmark] = await saveEvidence(aimos, dataset, args);
  }

  if (args.ledger) {
    fs.writeFileSync(path.join(args.ledger.dir, 'run-meta.json'), `${JSON.stringify({
      run_started_at: new Date().toISOString(),
      output_dir: args.outputDir,
      aimos_base: args.aimosBase,
      agent_id: args.agentId,
      benchmark: args.benchmark,
      mode: args.mode,
      sample: args.full ? 'full' : args.sample,
      offset: args.offset,
      limit: args.limit,
      request_interval_ms: args.requestIntervalMs,
      judge_config: ['judge', 'all'].includes(args.mode) ? {
        generator_provider: args.generatorProvider,
        generator_model: args.generatorModel,
        judge_provider: args.judgeProvider,
        judge_model: args.judgeModel,
        judge_max_chars: args.judgeMaxChars,
        provider_retry_limit: args.providerRetryLimit,
        provider_max_reset_wait_seconds: args.providerMaxResetWaitSeconds,
        lexical_auto_pass_disabled: args.disableLexicalAutoPass,
        generator_prompt_version: ANSWER_GENERATOR_PROMPT_VERSION,
        judge_prompt_version: ANSWER_JUDGE_PROMPT_VERSION,
        native_answer_generation_support: true,
      } : null,
      recall_config: {
        source_filter: 'benchmark_source',
        memory_type_filter: normalizeMemoryTypeFilter(args.memoryTypeFilter),
        answer_shape: ['official', 'judge', 'all', 'both'].includes(args.mode) ? 'full_detail_for_official_or_judge' : 'default',
      },
      health,
      datasets: Object.fromEntries(datasets.map(d => [d.benchmark, {
        source: d.source,
        input_file: d.benchmark === 'longmemeval' ? args.longMemEvalFile : DATASET_FILE.locomo,
        input_sha256: sha256File(d.benchmark === 'longmemeval' ? args.longMemEvalFile : DATASET_FILE.locomo),
        questions: d.questions.length,
        sessions: d.sessions.length,
      }])),
      ingest,
    }, null, 2)}\n`);
  }

  // Write run-meta.json to record dir if --record is active (enables --replay later)
  if (args.recordDir) {
    fs.writeFileSync(path.join(args.recordDir, 'run-meta.json'), `${JSON.stringify({
      recorded_at: new Date().toISOString(),
      aimos_base: args.aimosBase,
      agent_id: args.agentId,
      benchmark: args.benchmark,
      mode: args.mode,
      scoring: { lexical_auto_pass: !args.disableLexicalAutoPass },
    }, null, 2)}\n`);
  }

  let results = [];
  if (!args.ingestOnly) {
    for (const dataset of datasets) {
      const datasetResults = await runDataset(aimos, dataset, args);
      results = results.concat(datasetResults);
    }
  }

  const output = {
    meta: {
      run_at: new Date().toISOString(),
      aimos_base: args.aimosBase,
      agent_id: args.agentId,
      benchmark: args.benchmark,
      mode: args.mode,
      sample: args.full ? 'full' : args.sample,
      offset: args.offset,
      limit: args.limit,
      ledger_dir: args.ledger?.dir || null,
      judge_config: ['judge', 'all'].includes(args.mode) ? {
        generator_provider: args.generatorProvider,
        generator_model: args.generatorModel,
        judge_provider: args.judgeProvider,
        judge_model: args.judgeModel,
        judge_max_chars: args.judgeMaxChars,
        provider_retry_limit: args.providerRetryLimit,
        provider_max_reset_wait_seconds: args.providerMaxResetWaitSeconds,
        lexical_auto_pass_disabled: args.disableLexicalAutoPass,
        generator_prompt_version: ANSWER_GENERATOR_PROMPT_VERSION,
        judge_prompt_version: ANSWER_JUDGE_PROMPT_VERSION,
        native_answer_generation_support: true,
        recall_shape: 'full_detail',
        temperature_control: 'provider_adapter_default',
      } : null,
      recall_config: {
        source_filter: 'benchmark_source',
        memory_type_filter: normalizeMemoryTypeFilter(args.memoryTypeFilter),
        answer_shape: ['official', 'judge', 'all', 'both'].includes(args.mode) ? 'full_detail_for_official_or_judge' : 'default',
      },
      health,
      datasets: Object.fromEntries(datasets.map(d => [d.benchmark, {
        source: d.source,
        input_file: d.benchmark === 'longmemeval' ? args.longMemEvalFile : DATASET_FILE.locomo,
        input_sha256: sha256File(d.benchmark === 'longmemeval' ? args.longMemEvalFile : DATASET_FILE.locomo),
        questions: d.questions.length,
        sessions: d.sessions.length,
      }])),
      ingest,
    },
    summary: summarize(results),
    results,
  };

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outFile = path.join(args.outputDir, `locomo-longmem-${stamp}.json`);
  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
  if (args.ledger) {
    const hashFiles = {
      final_result_json: outFile,
      rows_jsonl: args.ledger.rows,
      failures_jsonl: args.ledger.failures,
      progress_jsonl: args.ledger.progress,
      summary_json: args.ledger.summary,
      run_meta_json: path.join(args.ledger.dir, 'run-meta.json'),
      command_txt: path.join(args.ledger.dir, 'command.txt'),
    };
    const hashes = {};
    for (const [name, file] of Object.entries(hashFiles)) {
      hashes[name] = { path: file, sha256: sha256File(file) };
    }
    fs.writeFileSync(path.join(args.ledger.dir, 'final-result-path.txt'), `${outFile}\n`);
    fs.writeFileSync(path.join(args.ledger.dir, 'hashes.json'), `${JSON.stringify(hashes, null, 2)}\n`);
    fs.writeFileSync(path.join(args.ledger.dir, 'complete.json'), `${JSON.stringify({
      completed_at: new Date().toISOString(),
      final_result_json: outFile,
      summary: output.summary,
      hashes,
    }, null, 2)}\n`);
  }
  console.log(JSON.stringify({ saved: outFile, summary: output.summary }, null, 2));
}

// Entry-point guard: only run main() when executed directly, not when imported.
// This allows `import('./eval/run-locomo-longmem-benchmarks.js')` to work in tests and CI
// without spawning a live server, DB connections, or network requests.
const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  main()
    .catch(error => {
      console.error(error && error.stack ? error.stack : error);
      process.exitCode = 1;
    })
    .finally(async () => {
      await Promise.allSettled([pool.end(), agentPool.end()]);
    });
}

// Exports for testing and CI replay without a live server.
export {
  buildLongMemEval,
  buildLoCoMo,
  scoreRetrieval,
  scoreAnswer,
  summarize,
  answerInText,
  normalizeText,
  printConfig,
  replayRun,
};
