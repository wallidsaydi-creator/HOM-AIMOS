#!/usr/bin/env node

// Reproducible bounded-work measurement for the independent RFC 6962 kernels.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { recallMerkleRoot } from '../../verifiers/mutmem-v2/node/crypto-kernel.mjs';
import { canonicalJson } from '../../services/security/protocol/canonical-json.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PYTHON = process.argv.find((value) => value.startsWith('--python='))?.slice(9)
  || 'python3';
const count = Number(process.argv.find((value) => value.startsWith('--count='))?.slice(8) || 100_000);
const output = process.argv.find((value) => value.startsWith('--output='))?.slice(9) || null;
if (!Number.isSafeInteger(count) || count < 1 || count > 100_000) {
  throw new Error('p2_resource_measurement_count_invalid');
}
const maximumElapsedMs = 5_000;
const maximumPeakRssBytes = 256 * 1024 * 1024;
const entries = Array.from({ length: count }, (_, ordinal) => ({
  ordinal,
  value: `entry-${ordinal}`,
}));
const rssBefore = process.memoryUsage().rss;
const nodeStart = performance.now();
const nodeRoot = recallMerkleRoot(entries).toString('hex');
const nodeElapsedMs = performance.now() - nodeStart;
const nodePeakRssBytes = Math.max(rssBefore, process.memoryUsage().rss);
const python = spawnSync(PYTHON, [path.join(
  ROOT,
  'verifiers/mutmem-v2/python/kernel_cli.py',
)], {
  input: JSON.stringify({ operation: 'measure_merkle', count }),
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
});
if (python.status !== 0) throw new Error(`p2_python_measurement_failed:${python.stderr}:${python.stdout}`);
const pythonResult = JSON.parse(python.stdout);
const result = {
  schema: 'hom.aimos.mutmem-p2-resource-measurement/v1',
  intended_n: count,
  exact_root_parity: pythonResult.root_sha256 === nodeRoot,
  thresholds: {
    maximum_elapsed_ms_per_implementation: maximumElapsedMs,
    maximum_peak_rss_bytes_per_implementation: maximumPeakRssBytes,
  },
  node: {
    root_sha256: nodeRoot,
    elapsed_ms: Number(nodeElapsedMs.toFixed(3)),
    peak_rss_bytes: nodePeakRssBytes,
    time_complexity: 'O(n)',
    auxiliary_peak_space: 'O(log n)',
    node_version: process.version,
  },
  python: pythonResult,
};
result.passed = result.exact_root_parity
  && result.node.elapsed_ms <= maximumElapsedMs
  && result.python.elapsed_ms <= maximumElapsedMs
  && result.node.peak_rss_bytes <= maximumPeakRssBytes
  && result.python.peak_rss_bytes <= maximumPeakRssBytes;
result.measurement_sha256 = createHash('sha256')
  .update(Buffer.from(canonicalJson(result), 'utf8')).digest('hex');
if (output) await writeFile(path.resolve(output), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
console.log(JSON.stringify(result, null, 2));
if (!result.passed) process.exitCode = 1;
