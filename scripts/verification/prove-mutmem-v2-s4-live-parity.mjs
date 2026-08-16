#!/usr/bin/env node

// Read-only parity proof over one transaction-consistent live AIMOS snapshot.
// The evidence bundle is streamed to the clean-room verifier and is not
// persisted. The receipt contains only hashes, counts, and verifier summaries.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentPool } from '../../db/connection.js';
import {
  readCognitiveWeightEvidenceBundle,
} from '../../services/security/cognitive-weight-verifier.js';
import {
  verifyCognitiveWeightEvidenceBundle,
} from '../../services/security/protocol/cognitive-weight-evidence.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const VERIFY = path.join(ROOT, 'verifiers/mutmem-python/verify.py');
const OWNER = path.join(ROOT, 'verifiers/mutmem-python/mutmem_verifier.py');
const OUTPUT = path.join(ROOT, 'artifacts/security/mutmem-v2/s4');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function verifyWithPython(bundle) {
  const raw = JSON.stringify(bundle);
  const child = spawn('python3', [VERIFY, 'verify-bundle', '-'], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (part) => { stdout += part; });
  child.stderr.on('data', (part) => { stderr += part; });
  const terminal = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  child.stdin.end(raw);
  const ended = await terminal;
  const output = JSON.parse(stdout);
  assert.equal(ended.signal, null, `clean-room verifier terminated by ${ended.signal}`);
  assert.equal(ended.code, 0, stderr || output.primary_reason);
  assert.equal(output.verdict, 'valid');
  return { output, bundleBytes: Buffer.byteLength(raw) };
}

async function main() {
  const bundle = await readCognitiveWeightEvidenceBundle({ companyId: 'hom' });
  const node = verifyCognitiveWeightEvidenceBundle(bundle);
  const pythonResult = await verifyWithPython(bundle);
  const python = pythonResult.output;
  assert.deepEqual(python.records, node.records);
  assert.deepEqual(python.sql_rows, node.sqlRows);
  assert.equal(python.parity, node.parity);
  assert.equal(python.proof_root, node.proofRoot.toString('hex'));
  assert.equal(python.bundle_sha256, node.bundleSha256.toString('hex'));
  assert.deepEqual(python.event_stream_results, node.eventStreamResults);

  const pythonSourceSha256 = sha256(await readFile(OWNER));
  const pythonCliSha256 = sha256(await readFile(VERIFY));
  const receipt = {
    schema: 'hom.aimos.mutmem-v2-s4-live-parity/v1',
    authority: 'read_only_evidence_verification',
    database_mutation: false,
    live_bundle_persisted: false,
    company_id: 'hom',
    bundle_bytes: pythonResult.bundleBytes,
    bundle_sha256: python.bundle_sha256,
    proof_root_sha256: python.proof_root,
    records: python.records.length,
    valid_records: python.records.filter((record) => record.ok).length,
    sql_portable_parity: python.parity,
    event_streams: python.event_stream_results.length,
    valid_event_streams: python.event_stream_results.filter((stream) => stream.valid).length,
    node_python_exact_parity: true,
    python_source_sha256: pythonSourceSha256,
    python_cli_sha256: pythonCliSha256,
    python_reported_source_sha256: python.source_sha256,
  };
  await mkdir(OUTPUT, { recursive: true });
  const filename = [
    'mutmem-v2-s4-live-parity',
    python.bundle_sha256.slice(0, 16),
    pythonSourceSha256.slice(0, 16),
    pythonCliSha256.slice(0, 16),
  ].join('-') + '.json';
  const raw = `${JSON.stringify(receipt, null, 2)}\n`;
  await writeFile(path.join(OUTPUT, filename), raw, { flag: 'wx', mode: 0o644 });
  await writeFile(
    path.join(OUTPUT, `${filename}.sha256`),
    `${sha256(Buffer.from(raw, 'utf8'))}  ${filename}\n`,
    { flag: 'wx', mode: 0o644 },
  );
  process.stdout.write(`${JSON.stringify({
    success: true,
    receipt: path.join(OUTPUT, filename),
    receipt_sha256: sha256(Buffer.from(raw, 'utf8')),
    ...receipt,
  }, null, 2)}\n`);
}

main()
  .catch((error) => {
    console.error(`[FATAL] ${error?.message || error}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await agentPool.end().catch(() => {});
  });
