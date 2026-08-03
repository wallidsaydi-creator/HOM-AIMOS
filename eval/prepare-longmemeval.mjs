#!/usr/bin/env node
/**
 * eval/prepare-longmemeval.mjs — deterministic transform from longmemeval-full.json
 * to the harness-compatible flat-row format (Format A).
 *
 * Usage:
 *   node eval/prepare-longmemeval.mjs
 *   node eval/prepare-longmemeval.mjs --input eval/data/longmemeval-full.json --output eval/data/longmemeval-aimos.json
 *   node eval/prepare-longmemeval.mjs --dry-run   # print stats only
 *
 * The output is a JSON array of flat rows, each of which matches the Format A
 * schema expected by buildLongMemEval() when isFormatA is true:
 *   {
 *     question_id, question, answer, question_type,
 *     haystack_sessions, haystack_session_ids, haystack_dates,
 *     answer_session_ids
 *   }
 *
 * The transform is intentionally reproducible: given the same input file,
 * it always produces byte-for-byte identical output. No randomness, no timestamps.
 *
 * Input format (Format B — longmemeval-full.json):
 *   [ { id, metadata, sessions: [{id, date?, messages: [{role, content}]}], questions: [{id, question, answer, category}] } ]
 *
 * This script is part of R6 (Benchmark Integrity) remediation.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const args = {
    input: path.join(__dirname, 'data', 'longmemeval-full.json'),
    output: path.join(__dirname, 'data', 'longmemeval-aimos.json'),
    dryRun: false,
  };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--input' && argv[i + 1]) { args.input = argv[i + 1]; i++; }
    else if (argv[i] === '--output' && argv[i + 1]) { args.output = argv[i + 1]; i++; }
    else if (argv[i] === '--dry-run') args.dryRun = true;
  }
  return args;
}

/**
 * Transform Format B (scenario-keyed) → Format A (flat question rows).
 *
 * Each question in a scenario becomes one flat row. All sessions in the
 * scenario are treated as haystack sessions. Since Format B does not carry
 * explicit answer_session_ids, all session ids are listed (conservative: any
 * session may contain the evidence).
 */
function transform(scenarios) {
  const rows = [];
  for (const scenario of scenarios) {
    const scenarioId = String(scenario.id || '');
    const scenarioSessions = Array.isArray(scenario.sessions) ? scenario.sessions : [];

    const haystackSessionIds = scenarioSessions.map(s => `${scenarioId}:${s.id || ''}`);
    const haystackDates = scenarioSessions.map(s => s.date || null);
    const haystackSessions = scenarioSessions.map(s =>
      (Array.isArray(s.messages) ? s.messages : []).map(m => ({
        role: m.role || 'unknown',
        content: m.content || m.text || '',
      }))
    );

    for (const q of (Array.isArray(scenario.questions) ? scenario.questions : [])) {
      rows.push({
        question_id: `${scenarioId}:${q.id || ''}`,
        question: String(q.question || ''),
        answer: String(q.answer ?? ''),
        question_type: String(q.category || q.question_type || 'unknown'),
        haystack_sessions: haystackSessions,
        haystack_session_ids: haystackSessionIds,
        haystack_dates: haystackDates,
        // answer_session_ids: not present in Format B; use all sessions (conservative)
        answer_session_ids: haystackSessionIds,
      });
    }
  }
  return rows;
}

function main() {
  const args = parseArgs(process.argv);
  const input = fs.readFileSync(args.input, 'utf8');
  const scenarios = JSON.parse(input);

  if (!Array.isArray(scenarios)) {
    throw new Error(`Expected a JSON array in ${args.input}, got ${typeof scenarios}`);
  }

  const rows = transform(scenarios);

  const stats = {
    input_file: args.input,
    output_file: args.output,
    scenarios: scenarios.length,
    total_sessions: scenarios.reduce((n, s) => n + (s.sessions?.length || 0), 0),
    total_questions: rows.length,
    question_types: [...new Set(rows.map(r => r.question_type))].sort(),
  };

  console.log(JSON.stringify({ transform_stats: stats }, null, 2));

  if (args.dryRun) {
    console.log('[dry-run] No file written.');
    return;
  }

  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, JSON.stringify(rows, null, 2));
  console.log(`[done] Wrote ${rows.length} rows to ${args.output}`);
}

main();
