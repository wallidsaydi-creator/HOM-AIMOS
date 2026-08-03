#!/usr/bin/env node

// Turn a recorded retrieval pass (official/record/responses.jsonl) into small
// per-batch JSON files the cognitive workflow's subagents read directly.
//
// Each question becomes { id, benchmark, category, question, gold, evidence }
// where `evidence` is a top-K, length-capped view of what HOM recalled — the
// standard RAG shape a downstream model would actually be handed. The external
// generator answers ONLY from this evidence; the judge scores against `gold`.
// HOM's retrieval is the product under test; the LLM only sees what HOM surfaced.
//
// responses.jsonl can be multiple GB (full_detail returns whole transcripts),
// so it is streamed line-by-line rather than read into memory.
//
// Usage: node scripts/benchmark/prepare-cognitive-batches.mjs <runDir> [batchSize] [topK] [charCap]

import { createHash } from 'node:crypto';
import { createReadStream, mkdirSync, writeFileSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import path from 'node:path';

const runDir = process.argv[2];
const batchSize = Number(process.argv[3] || 8);
const topK = Number(process.argv[4] || 8);
const charCap = Number(process.argv[5] || 3000);
if (!runDir) { console.error('usage: prepare-cognitive-batches.mjs <runDir> [batchSize] [topK] [charCap]'); process.exit(2); }

const responsesFile = path.join(runDir, 'official', 'record', 'responses.jsonl');
if (!existsSync(responsesFile)) { console.error(`missing ${responsesFile}`); process.exit(2); }

const outDir = path.join(runDir, 'cognitive', 'batches');
mkdirSync(outDir, { recursive: true });
for (const f of readdirSync(outDir)) rmSync(path.join(outDir, f));

function trimEvidence(memories) {
  return memories.slice(0, topK).map(m => ({
    key: String(m.key || ''),
    value: String(m.value || '').slice(0, charCap)
  }));
}

const items = [];
const rl = createInterface({ input: createReadStream(responsesFile, { encoding: 'utf8' }), crlfDelay: Infinity });
let parsed = 0;
for await (const line of rl) {
  if (!line) continue;
  let rec;
  try { rec = JSON.parse(line); } catch { continue; }
  if (rec.mode !== 'official') continue;
  parsed += 1;
  const q = rec.question || {};
  const memories = Array.isArray(rec.response?.body?.memories) ? rec.response.body.memories : [];
  items.push({
    id: String(q.id ?? ''),
    benchmark: String(q.benchmark || rec.benchmark || ''),
    category: String(q.category || 'unknown'),
    question: String(q.question || ''),
    gold: String(q.answer ?? q.expectedAnswer ?? ''),
    evidence: trimEvidence(memories)
  });
}

// Deterministic order (by benchmark then id) so batches are reproducible.
items.sort((a, b) => (a.benchmark + a.id).localeCompare(b.benchmark + b.id));

const batchPaths = [];
for (let i = 0; i < items.length; i += batchSize) {
  const batch = items.slice(i, i + batchSize);
  const idx = String(batchPaths.length).padStart(4, '0');
  const file = path.join(outDir, `batch-${idx}.json`);
  writeFileSync(file, JSON.stringify(batch, null, 2));
  batchPaths.push(file);
}

// Stream-hash the (large) source file.
const responsesSha = await new Promise((resolve, reject) => {
  const h = createHash('sha256');
  createReadStream(responsesFile).on('data', d => h.update(d)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
});

const manifest = {
  run_dir: runDir,
  responses_sha256: responsesSha,
  total_questions: items.length,
  batch_size: batchSize,
  evidence_top_k: topK,
  evidence_char_cap: charCap,
  batch_count: batchPaths.length,
  by_benchmark: items.reduce((acc, it) => { acc[it.benchmark] = (acc[it.benchmark] || 0) + 1; return acc; }, {}),
  batch_paths: batchPaths
};
const manifestFile = path.join(runDir, 'cognitive', 'batches-manifest.json');
writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
console.log(JSON.stringify({ manifest_file: manifestFile, total_questions: items.length, batch_count: batchPaths.length, by_benchmark: manifest.by_benchmark, evidence_top_k: topK, evidence_char_cap: charCap }, null, 2));
