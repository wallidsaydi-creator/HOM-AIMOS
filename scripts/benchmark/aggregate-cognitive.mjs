#!/usr/bin/env node

// Aggregate the cognitive workflow's per-batch verdict files into judged
// accuracy, broken down by benchmark and category, and hash the artifacts.
//
// Usage: node scripts/benchmark/aggregate-cognitive.mjs <runDir>

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const runDir = process.argv[2];
if (!runDir) { console.error('usage: aggregate-cognitive.mjs <runDir>'); process.exit(2); }

const verdictsDir = path.join(runDir, 'cognitive', 'verdicts');
const manifestFile = path.join(runDir, 'cognitive', 'batches-manifest.json');
if (!existsSync(verdictsDir)) { console.error(`missing ${verdictsDir}`); process.exit(2); }
const manifest = existsSync(manifestFile) ? JSON.parse(readFileSync(manifestFile, 'utf8')) : {};

function blank() { return { total: 0, correct: 0, by_category: {} }; }
function rate(x) { return x.total ? Number((x.correct / x.total).toFixed(4)) : null; }

const perBenchmark = {};
const seen = new Set();
let dupes = 0;
let files = 0;

for (const name of readdirSync(verdictsDir).sort()) {
  if (!name.endsWith('.json')) continue;
  files += 1;
  let rows;
  try { rows = JSON.parse(readFileSync(path.join(verdictsDir, name), 'utf8')); } catch { continue; }
  if (!Array.isArray(rows)) continue;
  for (const r of rows) {
    const id = String(r.id ?? '');
    const bench = String(r.benchmark || 'unknown');
    const cat = String(r.category || 'unknown');
    const key = `${bench}:${id}`;
    if (seen.has(key)) { dupes += 1; continue; }
    seen.add(key);
    const b = (perBenchmark[bench] ||= blank());
    const c = (b.by_category[cat] ||= { total: 0, correct: 0 });
    b.total += 1; c.total += 1;
    if (r.correct === true) { b.correct += 1; c.correct += 1; }
  }
}

const summary = {
  run_id: path.basename(runDir),
  judge: manifest.judge || null,
  generator: manifest.generator || null,
  verdict_files: files,
  duplicate_ids_skipped: dupes,
  by_benchmark: {},
};
for (const [bench, b] of Object.entries(perBenchmark)) {
  const cats = {};
  for (const [cat, c] of Object.entries(b.by_category)) cats[cat] = { total: c.total, correct: c.correct, judged_accuracy: rate(c) };
  summary.by_benchmark[bench] = { total: b.total, correct: b.correct, judged_accuracy: rate(b), by_category: cats };
}
if (manifest.total_questions != null) {
  summary.coverage = { expected_questions: manifest.total_questions, judged_questions: seen.size, complete: seen.size === manifest.total_questions };
}

const outFile = path.join(runDir, 'cognitive', 'cognitive-summary.json');
writeFileSync(outFile, `${JSON.stringify(summary, null, 2)}\n`);

// Hash the cognitive artifacts (verdicts + summary + manifest).
const hashes = {};
for (const name of readdirSync(verdictsDir).sort()) {
  const f = path.join(verdictsDir, name);
  hashes[path.relative(runDir, f)] = createHash('sha256').update(readFileSync(f)).digest('hex');
}
for (const f of [outFile, manifestFile]) {
  if (existsSync(f)) hashes[path.relative(runDir, f)] = createHash('sha256').update(readFileSync(f)).digest('hex');
}
writeFileSync(path.join(runDir, 'cognitive', 'cognitive-hashes.json'), `${JSON.stringify(hashes, null, 2)}\n`);

console.log(JSON.stringify(summary, null, 2));
