#!/usr/bin/env node

import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildTargetManifests,
  loadSourceLock,
  readJsonFile,
  verifyPinnedFile,
  writeImmutableJson,
} from '../../eval/poisonedrag/protocol.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_LOCK = path.join(ROOT, 'eval', 'poisonedrag', 'source-lock.json');
const DEFAULT_INPUT_DIR = path.join(ROOT, 'eval', 'data', 'private', 'poisonedrag');
const DEFAULT_PRIVATE_OUTPUT = path.join(DEFAULT_INPUT_DIR, 'n100-private-target-manifest.json');
const DEFAULT_PUBLIC_OUTPUT = path.join(ROOT, 'eval', 'poisonedrag', 'n100-public-target-lock.json');

function cliValue(argv, name) {
  const inline = argv.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

export function parsePrepareArgs(argv) {
  const live = argv.includes('--live');
  return {
    live,
    sourceLock: path.resolve(cliValue(argv, '--source-lock') || DEFAULT_LOCK),
    inputDir: path.resolve(cliValue(argv, '--input-dir') || DEFAULT_INPUT_DIR),
    privateOutput: path.resolve(cliValue(argv, '--private-output') || DEFAULT_PRIVATE_OUTPUT),
    publicOutput: path.resolve(cliValue(argv, '--public-output') || DEFAULT_PUBLIC_OUTPUT),
  };
}

export async function prepareTargetManifests(args) {
  const { lock, source_lock_sha256: sourceLockSha256 } = loadSourceLock(args.sourceLock);
  const fixtureFile = path.join(args.inputDir, lock.artifacts.target_fixture.file);
  const rankingsFile = path.join(args.inputDir, lock.artifacts.contriever_top100.file);
  await verifyPinnedFile(fixtureFile, lock.artifacts.target_fixture, ['sha256']);
  await verifyPinnedFile(rankingsFile, lock.artifacts.contriever_top100, ['sha256']);
  if (!existsSync(fixtureFile) || !existsSync(rankingsFile)) {
    throw new Error('poisonedrag_core_inputs_missing_run_fetch_first');
  }
  return buildTargetManifests({
    sourceLock: lock,
    sourceLockSha256,
    fixture: readJsonFile(fixtureFile),
    rankings: readJsonFile(rankingsFile),
  });
}

async function main() {
  const args = parsePrepareArgs(process.argv.slice(2));
  const { privateManifest, publicManifest } = await prepareTargetManifests(args);
  const summary = {
    mode: args.live ? 'LIVE' : 'DRY_RUN',
    target_count: privateManifest.target_count,
    clean_references: privateManifest.target_count * privateManifest.clean_candidates_per_target,
    poison_passages: privateManifest.target_count * privateManifest.poison_passages_per_target,
    private_manifest_sha256: privateManifest.manifest_sha256,
    public_target_lock_sha256: publicManifest.manifest_sha256,
    private_output: args.privateOutput,
    public_output: args.publicOutput,
  };
  if (!args.live) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  mkdirSync(path.dirname(args.privateOutput), { recursive: true, mode: 0o700 });
  mkdirSync(path.dirname(args.publicOutput), { recursive: true, mode: 0o755 });
  const privateWrite = writeImmutableJson(args.privateOutput, privateManifest, 0o600);
  const publicWrite = writeImmutableJson(args.publicOutput, publicManifest, 0o644);
  console.log(JSON.stringify({ success: true, ...summary, private: privateWrite, public: publicWrite }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
