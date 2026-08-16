#!/usr/bin/env node

// Generate the focused V2-S4 parity corpus. This is deliberately narrower
// than the 28-class V2-S5 production conformance corpus.

import { createHash } from 'node:crypto';
import { mkdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  createFocusedVectors,
  nodeVerdict,
} from './mutmem-v2-s4-fixture-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUTPUT = path.join(ROOT, 'verifiers/mutmem-python/fixtures');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function main() {
  try {
    await stat(path.join(OUTPUT, 'manifest.json'));
    throw new Error('mutmem_v2_s4_fixture_manifest_already_exists');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  await mkdir(OUTPUT, { recursive: true });
  const records = [];
  for (const vector of createFocusedVectors()) {
    const filename = `${vector.id}.json`;
    const raw = `${JSON.stringify(vector.bundle)}\n`;
    const node = nodeVerdict(vector.bundle);
    if (node.verdict !== vector.expected || node.reason !== vector.reason) {
      throw new Error(`mutmem_v2_s4_fixture_expectation_mismatch:${vector.id}`);
    }
    await writeFile(path.join(OUTPUT, filename), raw, { flag: 'wx', mode: 0o644 });
    const normalizedResult = {
      verdict: node.verdict,
      primary_reason: node.reason,
      records: node.proof?.records ?? null,
      sql_rows: node.proof?.sqlRows ?? null,
      parity: node.proof?.parity ?? null,
      proof_root: node.proof?.proofRoot?.toString('hex') ?? null,
      bundle_sha256: node.proof?.bundleSha256?.toString('hex')
        ?? sha256(Buffer.from(canonicalJson(vector.bundle), 'utf8')),
      event_stream_results: node.proof?.eventStreamResults ?? null,
    };
    records.push({
      vector_id: vector.id,
      filename,
      fixture_sha256: sha256(Buffer.from(raw, 'utf8')),
      expected_verdict: vector.expected,
      expected_primary_reason: vector.reason,
      producer_result_sha256: sha256(Buffer.from(canonicalJson(normalizedResult), 'utf8')),
      expected_bundle_sha256: normalizedResult.bundle_sha256,
      expected_proof_root: normalizedResult.proof_root,
    });
  }
  const manifest = {
    schema: 'hom.aimos.mutmem-v2-s4-focused-fixture-manifest/v1',
    scope: 'focused_cross_language_parity_not_v2_s5_full_corpus',
    synthetic_keys: true,
    private_keys_retained: false,
    live_aimos_data_included: false,
    vector_count: records.length,
    vectors: records,
  };
  const rawManifest = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(path.join(OUTPUT, 'manifest.json'), rawManifest, { flag: 'wx', mode: 0o644 });
  await writeFile(
    path.join(OUTPUT, 'manifest.json.sha256'),
    `${sha256(Buffer.from(rawManifest, 'utf8'))}  manifest.json\n`,
    { flag: 'wx', mode: 0o644 },
  );
  process.stdout.write(`${JSON.stringify({
    success: true,
    output: OUTPUT,
    vector_count: records.length,
    manifest_sha256: sha256(Buffer.from(rawManifest, 'utf8')),
  }, null, 2)}\n`);
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || error}`);
  process.exitCode = 1;
});
