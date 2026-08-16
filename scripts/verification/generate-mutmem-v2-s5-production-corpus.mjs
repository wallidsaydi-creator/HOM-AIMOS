#!/usr/bin/env node

// One-shot generator for the complete V2-S5 conformance corpus. The output is
// immutable by default: an existing manifest aborts generation. Source custody
// and purge receipts are created by the disposable-Genesis runner, not here.

import { createHash } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../services/security/protocol/canonical-json.js';
import {
  buildS5Corpus,
  summarizeCorpus,
  verifyS5CorpusStructure,
} from './mutmem-v2-s5-corpus-factory.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_OUTPUT = path.join(ROOT, 'verifiers/mutmem-conformance/v1');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function argument(name, fallback = null) {
  const prefix = `--${name}=`;
  const value = process.argv.find((entry) => entry.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

async function main() {
  const output = path.resolve(argument('output', DEFAULT_OUTPUT));
  const replaceManifestSha256 = argument('replace-manifest-sha256');
  try {
    await stat(path.join(output, 'manifest.json'));
    const current = await readFile(path.join(output, 'manifest.json'));
    if (!replaceManifestSha256 || sha256(current) !== replaceManifestSha256) {
      throw new Error('mutmem_v2_s5_manifest_already_exists');
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const corpus = buildS5Corpus();
  verifyS5CorpusStructure(corpus);
  await mkdir(output, { recursive: true });
  const writeFlag = replaceManifestSha256 ? 'w' : 'wx';
  for (const member of corpus.members) {
    await writeFile(path.join(output, member.filename), member.raw, { flag: writeFlag, mode: 0o644 });
  }
  const manifest = summarizeCorpus(corpus);
  manifest.generator = {
    schema: 'hom.aimos.mutmem-v2-s5-generator/v1',
    source_file: 'scripts/verification/generate-mutmem-v2-s5-production-corpus.mjs',
    factory_file: 'scripts/verification/mutmem-v2-s5-corpus-factory.mjs',
    source_sha256: sha256(Buffer.from(
      await import('node:fs/promises').then(({ readFile }) => readFile(new URL(import.meta.url))),
    )),
    factory_sha256: sha256(Buffer.from(
      await import('node:fs/promises').then(({ readFile }) => readFile(
        new URL('./mutmem-v2-s5-corpus-factory.mjs', import.meta.url),
      )),
    )),
  };
  const rawManifest = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(path.join(output, 'manifest.json'), rawManifest, { flag: writeFlag, mode: 0o644 });
  await writeFile(
    path.join(output, 'manifest.json.sha256'),
    `${sha256(Buffer.from(rawManifest, 'utf8'))}  manifest.json\n`,
    { flag: writeFlag, mode: 0o644 },
  );
  const record = {
    success: true,
    output,
    intended_n: manifest.intended_n,
    observed_n: manifest.observed_n,
    required_class_count: manifest.required_class_count,
    corpus_root: manifest.corpus_root,
    manifest_sha256: sha256(Buffer.from(rawManifest, 'utf8')),
    canonical_manifest_sha256: sha256(Buffer.from(canonicalJson(manifest), 'utf8')),
  };
  process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
}

main().catch((error) => {
  console.error(`[FATAL] ${error?.message || error}`);
  process.exitCode = 1;
});
