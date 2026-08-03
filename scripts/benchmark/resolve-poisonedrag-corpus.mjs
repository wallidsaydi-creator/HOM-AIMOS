#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yauzl from 'yauzl';

import {
  POISONEDRAG_SCHEMAS,
  assertManifest,
  canonicalJson,
  hashFile,
  loadSourceLock,
  manifestDigest,
  readJsonFile,
  sha256,
  verifyPinnedFile,
  writeImmutableJson,
} from '../../eval/poisonedrag/protocol.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const DEFAULT_PRIVATE_DIR = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');

function cliValue(argv, name) {
  const inline = argv.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function parseResolveArgs(argv) {
  return {
    live: argv.includes('--live'),
    sourceLock: path.resolve(cliValue(argv, '--source-lock') || DEFAULT_LOCK),
    inputDir: path.resolve(cliValue(argv, '--input-dir') || DEFAULT_PRIVATE_DIR),
    targetManifest: path.resolve(cliValue(argv, '--target-manifest')
      || path.join(DEFAULT_PRIVATE_DIR, 'n100-private-target-manifest.json')),
    candidateOutput: path.resolve(cliValue(argv, '--candidate-output')
      || path.join(DEFAULT_PRIVATE_DIR, 'n100-candidate-pool.jsonl')),
    receiptOutput: path.resolve(cliValue(argv, '--receipt-output')
      || path.join(DEFAULT_PRIVATE_DIR, 'n100-corpus-resolution.json')),
  };
}

function verifiedNqReceipt(directory, archiveFile, sourceLockSha256) {
  const file = path.join(directory, 'download-receipt-with-nq.json');
  const receipt = readJsonFile(file, POISONEDRAG_SCHEMAS.DOWNLOAD_RECEIPT);
  const claimed = receipt.receipt_sha256;
  const unsigned = { ...receipt };
  delete unsigned.receipt_sha256;
  const observed = sha256(Buffer.from(canonicalJson(unsigned), 'utf8'));
  const archive = receipt.artifacts?.find((artifact) => artifact.name === 'nq_archive');
  if (receipt.source_lock_sha256 !== sourceLockSha256
    || claimed !== observed
    || archive?.file !== archiveFile
    || !/^[0-9a-f]{64}$/.test(String(archive?.sha256 || ''))) {
    throw new Error('nq_download_receipt_invalid');
  }
  return { file, receipt, archive };
}

function openZip(file) {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true, autoClose: true, validateEntrySizes: true }, (error, zip) => {
      if (error) reject(error);
      else resolve(zip);
    });
  });
}

function openEntry(zip, entry) {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error) reject(error);
      else resolve(stream);
    });
  });
}

async function resolveCorpusEntry(archiveFile, entryName, requiredIds) {
  const zip = await openZip(archiveFile);
  let found = false;
  const resolved = new Map();
  let corpusLines = 0;
  const corpusHash = createHash('sha256');

  await new Promise((resolve, reject) => {
    zip.once('error', reject);
    zip.once('end', () => {
      if (!found) reject(new Error(`nq_corpus_entry_missing:${entryName}`));
      else resolve();
    });
    zip.on('entry', async (entry) => {
      try {
        if (entry.fileName !== entryName) {
          zip.readEntry();
          return;
        }
        if (found || /\/$/.test(entry.fileName)) throw new Error('nq_corpus_entry_ambiguous');
        found = true;
        const stream = await openEntry(zip, entry);
        let pending = Buffer.alloc(0);
        for await (const chunk of stream) {
          const buffer = Buffer.from(chunk);
          corpusHash.update(buffer);
          pending = Buffer.concat([pending, buffer]);
          let newline;
          while ((newline = pending.indexOf(0x0a)) >= 0) {
            const line = pending.subarray(0, newline);
            pending = pending.subarray(newline + 1);
            if (!line.length) continue;
            corpusLines += 1;
            const idMatch = line.toString('utf8').match(/"_id"\s*:\s*"([^"]+)"/);
            if (!idMatch || !requiredIds.has(idMatch[1])) continue;
            if (resolved.has(idMatch[1])) throw new Error(`nq_document_duplicate:${idMatch[1]}`);
            const document = JSON.parse(line.toString('utf8'));
            if (document._id !== idMatch[1] || typeof document.text !== 'string') {
              throw new Error(`nq_document_shape_invalid:${idMatch[1]}`);
            }
            resolved.set(document._id, {
              document_id: document._id,
              title: typeof document.title === 'string' ? document.title : '',
              text: document.text,
              passage_sha256: sha256(Buffer.from(document.text, 'utf8')),
            });
          }
        }
        if (pending.length) {
          corpusHash.update(Buffer.alloc(0));
          corpusLines += 1;
          const document = JSON.parse(pending.toString('utf8'));
          if (requiredIds.has(document._id)) {
            if (resolved.has(document._id)) throw new Error(`nq_document_duplicate:${document._id}`);
            resolved.set(document._id, {
              document_id: document._id,
              title: typeof document.title === 'string' ? document.title : '',
              text: document.text,
              passage_sha256: sha256(Buffer.from(document.text, 'utf8')),
            });
          }
        }
        zip.readEntry();
      } catch (error) {
        zip.close();
        reject(error);
      }
    });
    zip.readEntry();
  });
  const missing = [...requiredIds].filter((id) => !resolved.has(id));
  if (missing.length) throw new Error(`nq_documents_missing:${missing.length}:${missing.slice(0, 5).join(',')}`);
  return { resolved, corpusLines, corpusSha256: corpusHash.digest('hex') };
}

function immutableText(file, encoded, mode = 0o600) {
  if (existsSync(file)) {
    const stat = lstatSync(file);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`regular_file_required:${file}`);
    if (readFileSync(file, 'utf8') !== encoded) throw new Error(`immutable_artifact_conflict:${file}`);
    return { file, reused: true };
  }
  writeFileSync(file, encoded, { flag: 'wx', mode });
  return { file, reused: false };
}

async function main() {
  const args = parseResolveArgs(process.argv.slice(2));
  const { lock, source_lock_sha256: sourceLockSha256 } = loadSourceLock(args.sourceLock);
  const manifest = assertManifest(
    readJsonFile(args.targetManifest),
    POISONEDRAG_SCHEMAS.PRIVATE_TARGET_MANIFEST,
  );
  if (manifest.source_lock_sha256 !== sourceLockSha256 || manifest.target_count !== 100) {
    throw new Error('target_manifest_source_binding_invalid');
  }
  const archiveSpec = lock.artifacts.nq_archive;
  const archiveFile = path.join(args.inputDir, archiveSpec.file);
  const download = verifiedNqReceipt(args.inputDir, archiveSpec.file, sourceLockSha256);
  const archiveObserved = await verifyPinnedFile(archiveFile, archiveSpec, ['sha256', 'md5']);
  if (archiveObserved.status !== 'verified'
    || archiveObserved.sha256 !== download.archive.sha256
    || archiveObserved.md5 !== archiveSpec.md5) {
    throw new Error('nq_archive_receipt_binding_invalid');
  }
  const requiredIds = new Set(manifest.targets.flatMap((target) => (
    target.candidate_documents.map((entry) => entry.document_id)
  )));
  const preflight = {
    mode: args.live ? 'LIVE' : 'DRY_RUN',
    target_count: manifest.target_count,
    candidate_references: manifest.target_count * manifest.clean_candidates_per_target,
    unique_candidate_documents: requiredIds.size,
    archive_sha256: archiveObserved.sha256,
    archive_md5: archiveObserved.md5,
    corpus_entry: archiveSpec.corpus_entry,
  };
  if (!args.live) {
    console.log(JSON.stringify(preflight, null, 2));
    return;
  }

  const resolution = await resolveCorpusEntry(archiveFile, archiveSpec.corpus_entry, requiredIds);
  const ordered = [...resolution.resolved.values()].sort((left, right) => (
    left.document_id.localeCompare(right.document_id)
  ));
  const candidateBytes = ordered.map((entry) => JSON.stringify(entry)).join('\n') + '\n';
  mkdirSync(path.dirname(args.candidateOutput), { recursive: true, mode: 0o700 });
  const candidateWrite = immutableText(args.candidateOutput, candidateBytes);
  const candidateHash = await hashFile(args.candidateOutput, ['sha256']);
  const receipt = {
    schema: POISONEDRAG_SCHEMAS.CORPUS_RESOLUTION,
    source_lock_sha256: sourceLockSha256,
    private_target_manifest_sha256: manifest.manifest_sha256,
    archive_sha256: archiveObserved.sha256,
    archive_md5: archiveObserved.md5,
    corpus_entry: archiveSpec.corpus_entry,
    corpus_entry_sha256: resolution.corpusSha256,
    corpus_line_count: resolution.corpusLines,
    candidate_reference_count: manifest.target_count * manifest.clean_candidates_per_target,
    unique_candidate_document_count: ordered.length,
    candidate_pool_file: path.basename(args.candidateOutput),
    candidate_pool_bytes: candidateHash.bytes,
    candidate_pool_sha256: candidateHash.sha256,
  };
  receipt.manifest_sha256 = manifestDigest(receipt);
  const receiptWrite = writeImmutableJson(args.receiptOutput, receipt);
  console.log(JSON.stringify({ success: true, ...preflight, candidate: candidateWrite, receipt: receiptWrite }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
