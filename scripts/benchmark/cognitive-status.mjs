#!/usr/bin/env node

// Report cognitive-pass completion for a run across both durable phases:
// answers/ (generator) and verdicts/ (judge). Prints which batches still need
// each phase so the resumable pass can continue from durable artifacts.
//
// Usage: node scripts/benchmark/cognitive-status.mjs <runDir>

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';

const runDir = process.argv[2];
if (!runDir) { console.error('usage: cognitive-status.mjs <runDir>'); process.exit(2); }
const batchesDir = path.join(runDir, 'cognitive', 'batches');
const answersDir = path.join(runDir, 'cognitive', 'answers');
const verdictsDir = path.join(runDir, 'cognitive', 'verdicts');
if (!existsSync(batchesDir)) { console.error(`missing ${batchesDir}`); process.exit(2); }

const total = readdirSync(batchesDir).filter(f => /^batch-\d+\.json$/.test(f)).length;

function validArray(file, expectLen, pred) {
  if (!existsSync(file)) return false;
  try {
    const v = JSON.parse(readFileSync(file, 'utf8'));
    return Array.isArray(v) && v.length === expectLen && v.every(pred);
  } catch { return false; }
}
function summarize(rangeLabel, list) {
  if (!list.length) return { count: 0 };
  const contiguous = list.length === (list[list.length - 1] - list[0] + 1);
  return {
    count: list.length,
    [rangeLabel + '_start']: list[0],
    [rangeLabel + '_end']: list[list.length - 1],
    contiguous,
    list: list.length <= 60 ? list : `${list.length} (non-contiguous — pass batchIndices)`
  };
}

const needGen = [], needJudge = [];
let judgedQ = 0, correctQ = 0;
for (let i = 0; i < total; i++) {
  const idx = String(i).padStart(4, '0');
  const bf = path.join(batchesDir, `batch-${idx}.json`);
  let blen = 0;
  try { blen = JSON.parse(readFileSync(bf, 'utf8')).length; } catch { blen = -1; }
  const answerOk = validArray(path.join(answersDir, `batch-${idx}.json`), blen, r => r && typeof r.id === 'string');
  const verdictFile = path.join(verdictsDir, `batch-${idx}.json`);
  const verdictOk = validArray(verdictFile, blen, r => r && typeof r.correct === 'boolean' && r.id);
  if (!answerOk) needGen.push(i);
  if (!verdictOk) needJudge.push(i);
  if (verdictOk) {
    const v = JSON.parse(readFileSync(verdictFile, 'utf8'));
    judgedQ += v.length; correctQ += v.filter(r => r.correct === true).length;
  }
}

const out = {
  run_dir: runDir,
  total_batches: total,
  gen_done: total - needGen.length,
  judge_done: total - needJudge.length,
  judged_questions: judgedQ,
  judged_correct: correctQ,
  running_accuracy: judgedQ ? Number((correctQ / judgedQ).toFixed(4)) : null,
  next_phase: needGen.length ? 'gen' : (needJudge.length ? 'judge' : null),
  complete: needGen.length === 0 && needJudge.length === 0,
  gen: summarize('resume', needGen),
  judge: summarize('resume', needJudge)
};
console.log(JSON.stringify(out, null, 2));
