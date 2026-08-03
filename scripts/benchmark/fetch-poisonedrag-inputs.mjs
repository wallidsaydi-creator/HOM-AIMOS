#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  statfsSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';

import {
  POISONEDRAG_SCHEMAS,
  canonicalJson,
  loadSourceLock,
  sha256,
  verifyPinnedFile,
  writeImmutableJson,
} from '../../eval/poisonedrag/protocol.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const DEFAULT_PRIVATE_DIR = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');
const MIN_NQ_HEADROOM_BYTES = 4 * 1024 ** 3;

function cliValue(argv, name) {
  const inline = argv.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function parseFetchArgs(argv) {
  const live = argv.includes('--live');
  const includeNq = argv.includes('--include-nq');
  const accepted = argv.includes('--accept-dataset-licenses');
  if (live && !accepted) throw new Error('--live requires --accept-dataset-licenses');
  if (includeNq && !live) {
    // Dry-run still reports NQ requirements; it does not download anything.
  }
  return {
    live,
    includeNq,
    accepted,
    sourceLock: path.resolve(cliValue(argv, '--source-lock') || DEFAULT_LOCK),
    outputDir: path.resolve(cliValue(argv, '--output-dir') || DEFAULT_PRIVATE_DIR),
  };
}

function availableBytes(directory) {
  const stats = statfsSync(directory);
  return Number(stats.bavail) * Number(stats.bsize);
}

async function downloadPinnedArtifact(artifact, target, algorithms) {
  const existing = await verifyPinnedFile(target, artifact, algorithms);
  if (existing.status === 'verified') return { ...existing, reused: true, url: artifact.url };

  const response = await fetch(artifact.url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(30 * 60_000),
    headers: {
      'Accept-Encoding': 'identity',
      'User-Agent': 'HOM-AIMOS-PoisonedRAG-Reproducer/1.0',
    },
  });
  if (!response.ok || !response.body) throw new Error(`download_failed:${response.status}:${artifact.url}`);
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength !== artifact.bytes) {
    throw new Error(`download_content_length_mismatch:${path.basename(target)}`);
  }

  const partial = `${target}.partial-${Date.now()}`;
  const output = createWriteStream(partial, { flags: 'wx', mode: 0o600 });
  const hashes = new Map(algorithms.map((algorithm) => [algorithm, createHash(algorithm)]));
  let bytes = 0;
  try {
    for await (const chunk of response.body) {
      const buffer = Buffer.from(chunk);
      bytes += buffer.length;
      for (const hash of hashes.values()) hash.update(buffer);
      if (!output.write(buffer)) await once(output, 'drain');
    }
    output.end();
    await once(output, 'close');
  } catch (error) {
    output.destroy();
    throw error;
  }
  const observed = {
    bytes,
    ...Object.fromEntries([...hashes].map(([algorithm, hash]) => [algorithm, hash.digest('hex')])),
  };
  const valid = bytes === artifact.bytes
    && algorithms.every((algorithm) => !artifact[algorithm] || artifact[algorithm] === observed[algorithm]);
  if (!valid) {
    const rejected = `${target}.rejected-${Date.now()}`;
    renameSync(partial, rejected);
    throw new Error(`download_hash_or_size_mismatch:${path.basename(target)}:${rejected}`);
  }
  if (existsSync(target)) throw new Error(`download_target_race:${target}`);
  renameSync(partial, target);
  return { status: 'verified', file: target, ...observed, reused: false, url: artifact.url };
}

export async function inspectPoisonedRagInputs(args) {
  const { lock, source_lock_sha256: sourceLockSha256 } = loadSourceLock(args.sourceLock);
  const names = ['license', 'target_fixture', 'contriever_top100'];
  if (args.includeNq) names.push('nq_archive');
  const artifacts = [];
  for (const name of names) {
    const spec = lock.artifacts[name];
    const target = path.join(args.outputDir, spec.file);
    const algorithms = name === 'nq_archive' ? ['sha256', 'md5'] : ['sha256'];
    const observed = await verifyPinnedFile(target, spec, algorithms);
    artifacts.push({ name, expected: spec, observed });
  }
  return {
    mode: args.live ? 'LIVE' : 'DRY_RUN',
    source_lock_sha256: sourceLockSha256,
    output_directory: args.outputDir,
    include_nq: args.includeNq,
    artifacts,
  };
}

async function main() {
  const args = parseFetchArgs(process.argv.slice(2));
  const { lock, source_lock_sha256: sourceLockSha256 } = loadSourceLock(args.sourceLock);
  if (!args.live) {
    console.log(JSON.stringify(await inspectPoisonedRagInputs(args), null, 2));
    return;
  }

  mkdirSync(args.outputDir, { recursive: true, mode: 0o700 });
  if (lstatSync(args.outputDir).isSymbolicLink()) throw new Error('private_output_directory_symlink_forbidden');
  if (args.includeNq && availableBytes(args.outputDir) < MIN_NQ_HEADROOM_BYTES) {
    throw new Error(`insufficient_nq_download_headroom:${MIN_NQ_HEADROOM_BYTES}`);
  }

  const artifactNames = ['license', 'target_fixture', 'contriever_top100'];
  if (args.includeNq) artifactNames.push('nq_archive');
  const artifacts = [];
  for (const name of artifactNames) {
    const spec = lock.artifacts[name];
    const algorithms = name === 'nq_archive' ? ['sha256', 'md5'] : ['sha256'];
    artifacts.push({
      name,
      ...(await downloadPinnedArtifact(spec, path.join(args.outputDir, spec.file), algorithms)),
    });
  }

  const receipt = {
    schema: POISONEDRAG_SCHEMAS.DOWNLOAD_RECEIPT,
    source_lock_sha256: sourceLockSha256,
    accepted_dataset_terms: true,
    include_nq: args.includeNq,
    artifacts: artifacts.map((artifact) => ({
      name: artifact.name,
      file: path.basename(artifact.file),
      url: artifact.url,
      bytes: artifact.bytes,
      sha256: artifact.sha256,
      ...(artifact.md5 ? { md5: artifact.md5 } : {}),
    })),
  };
  receipt.receipt_sha256 = sha256(Buffer.from(canonicalJson(receipt), 'utf8'));
  const receiptName = args.includeNq ? 'download-receipt-with-nq.json' : 'download-receipt-core.json';
  const written = writeImmutableJson(path.join(args.outputDir, receiptName), receipt);
  console.log(JSON.stringify({ success: true, ...written, receipt_sha256: receipt.receipt_sha256 }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
