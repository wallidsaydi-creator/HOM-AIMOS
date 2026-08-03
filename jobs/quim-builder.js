/**
 * quim-builder.js — Background job to build/maintain QuIM inverted question index
 * Source: QuIM-RAG (2026) — Inverted Question Matching for Enhanced QA
 *
 * Runs periodically (nightly recommended) to index new memories that haven't
 * been processed yet. Builds hypothetical questions, embeds them, quantizes to
 * prototypes, and populates the inverted index.
 *
 * Usage:
 *   node jobs/quim-builder.js              # One-shot build
 *   node jobs/quim-builder.js --limit 500  # Process 500 memories max
 *   node jobs/quim-builder.js --full       # Rebuild entire index
 */

import { buildQuimIndex, getQuimStats } from '../services/retrieval/quim-index.js';

const args = process.argv.slice(2);
const isFull = args.includes('--full');
const limitIdx = args.indexOf('--limit');
const limit = limitIdx >= 0 ? parseInt(args[limitIdx + 1], 10) : undefined;

async function main() {
  console.log('=== QuIM Index Builder ===');
  console.log(`Mode: ${isFull ? 'full rebuild' : 'incremental'}`);
  if (limit) console.log(`Limit: ${limit} memories`);
  console.log('');

  const start = Date.now();
  const result = await buildQuimIndex(undefined, { incremental: !isFull, limit });
  const elapsed = Date.now() - start;

  console.log(`Indexed: ${result.indexed} memories`);
  console.log(`Questions generated: ${result.questions}`);
  console.log(`Total prototypes: ${result.prototypes}`);
  console.log(`Time: ${elapsed}ms`);
  console.log('');

  const stats = await getQuimStats();
  console.log(`Index stats:`);
  console.log(`  Total entries: ${stats.indexEntries}`);
  console.log(`  Total prototypes: ${stats.prototypes}`);

  process.exit(0);
}

main().catch(err => {
  console.error('QuIM builder failed:', err.message);
  process.exit(1);
});
