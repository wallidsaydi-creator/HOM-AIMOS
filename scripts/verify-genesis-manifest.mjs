#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const GENESIS_MANIFEST_SCHEMA = 'hom.aimos.genesis-manifest/v1';
export const GENESIS_MANIFEST_RELATIVE_PATH = 'Guide/GENESIS-MANIFEST.json';

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHA256_HEX = /^[a-f0-9]{64}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return sha256(value).toString('hex');
}

function leafPreimage(record) {
  return JSON.stringify({
    bytes: record.bytes,
    path: record.path,
    sha256: record.sha256,
  });
}

export function computeGenesisCorpusRoot(records = []) {
  const ordered = [...records].sort((a, b) => String(a.path) < String(b.path) ? -1 : String(a.path) > String(b.path) ? 1 : 0);
  if (ordered.length === 0) throw new Error('genesis_manifest_empty');
  let level = ordered.map((record) => sha256(leafPreimage(record)));
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(sha256(Buffer.concat([left, right])));
    }
    level = next;
  }
  return level[0].toString('hex');
}

function validateManifestShape(manifest) {
  if (!manifest || typeof manifest !== 'object') throw new Error('genesis_manifest_invalid');
  if (manifest.schema !== GENESIS_MANIFEST_SCHEMA) throw new Error('genesis_manifest_schema_mismatch');
  if (!Number.isInteger(manifest.version) || manifest.version < 1) throw new Error('genesis_manifest_version_invalid');
  if (manifest.hash_algorithm !== 'sha256') throw new Error('genesis_manifest_hash_algorithm_invalid');
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw new Error('genesis_manifest_files_invalid');
  if (!Array.isArray(manifest.dependencies) || manifest.dependencies.length === 0) {
    throw new Error('genesis_manifest_dependencies_invalid');
  }
  if (!SHA256_HEX.test(String(manifest.corpus_root || ''))) throw new Error('genesis_manifest_root_invalid');
  const merkle = manifest.merkle_contract || {};
  if (
    merkle.sort !== 'path_ascending_utf16'
    || merkle.leaf !== 'sha256(JCS({bytes,path,sha256}))'
    || merkle.parent !== 'sha256(left_bytes || right_bytes)'
    || merkle.odd_node !== 'duplicate_last'
  ) {
    throw new Error('genesis_manifest_merkle_contract_invalid');
  }
}

export function verifyGenesisManifest({ brainRoot = DEFAULT_ROOT } = {}) {
  const root = path.resolve(brainRoot);
  const manifestPath = path.join(root, GENESIS_MANIFEST_RELATIVE_PATH);
  if (!existsSync(manifestPath)) throw new Error(`genesis_manifest_missing:${manifestPath}`);

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    throw new Error(`genesis_manifest_parse_failed:${error.message}`);
  }
  validateManifestShape(manifest);

  const verifiedDependencies = [];
  const dependencyNames = new Set();
  for (const dependency of manifest.dependencies) {
    const name = String(dependency?.name || '');
    const version = String(dependency?.version || '');
    const relativePath = String(dependency?.path || '');
    if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(name) || dependencyNames.has(name)) {
      throw new Error(`genesis_manifest_dependency_name_invalid:${name}`);
    }
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
      throw new Error(`genesis_manifest_dependency_version_invalid:${name}`);
    }
    if (!relativePath.startsWith('scripts/db/') || path.extname(relativePath) !== '.json') {
      throw new Error(`genesis_manifest_dependency_path_invalid:${relativePath}`);
    }
    if (!Number.isInteger(dependency.bytes) || dependency.bytes < 1 || !SHA256_HEX.test(String(dependency.sha256 || ''))) {
      throw new Error(`genesis_manifest_dependency_proof_invalid:${name}`);
    }
    const absolutePath = path.resolve(root, relativePath);
    const dependencyRoot = path.resolve(root, 'scripts', 'db') + path.sep;
    if (!absolutePath.startsWith(dependencyRoot) || !existsSync(absolutePath) || !statSync(absolutePath).isFile()) {
      throw new Error(`genesis_manifest_dependency_missing:${name}`);
    }
    const bytes = readFileSync(absolutePath);
    if (bytes.length !== dependency.bytes || sha256Hex(bytes) !== dependency.sha256) {
      throw new Error(`genesis_manifest_dependency_mismatch:${name}`);
    }
    dependencyNames.add(name);
    verifiedDependencies.push({ ...dependency, absolutePath });
  }
  if (!dependencyNames.has('pgsodium')) throw new Error('genesis_manifest_pgsodium_lock_missing');

  const expectedPaths = new Set();
  const verifiedFiles = [];
  let previousPath = null;
  for (const record of manifest.files) {
    const relativePath = String(record?.path || '');
    if (!relativePath.startsWith('Guide/') || path.extname(relativePath) !== '.md') {
      throw new Error(`genesis_manifest_path_invalid:${relativePath}`);
    }
    if (expectedPaths.has(relativePath)) throw new Error(`genesis_manifest_duplicate_path:${relativePath}`);
    if (previousPath !== null && previousPath >= relativePath) {
      throw new Error(`genesis_manifest_order_invalid:${relativePath}`);
    }
    if (!Number.isInteger(record.bytes) || record.bytes < 1) {
      throw new Error(`genesis_manifest_bytes_invalid:${relativePath}`);
    }
    if (!SHA256_HEX.test(String(record.sha256 || ''))) {
      throw new Error(`genesis_manifest_file_hash_invalid:${relativePath}`);
    }

    const absolutePath = path.resolve(root, relativePath);
    const guideRoot = path.resolve(root, 'Guide') + path.sep;
    if (!absolutePath.startsWith(guideRoot)) throw new Error(`genesis_manifest_path_escape:${relativePath}`);
    if (!existsSync(absolutePath) || !statSync(absolutePath).isFile()) {
      throw new Error(`genesis_manifest_file_missing:${relativePath}`);
    }
    const bytes = readFileSync(absolutePath);
    const actualHash = sha256Hex(bytes);
    if (bytes.length !== record.bytes) {
      throw new Error(`genesis_manifest_size_mismatch:${relativePath}:expected=${record.bytes}:actual=${bytes.length}`);
    }
    if (actualHash !== record.sha256) {
      throw new Error(`genesis_manifest_hash_mismatch:${relativePath}:expected=${record.sha256}:actual=${actualHash}`);
    }

    expectedPaths.add(relativePath);
    previousPath = relativePath;
    verifiedFiles.push({ ...record, absolutePath });
  }

  const guideMarkdownPaths = readdirSync(path.join(root, 'Guide'))
    .filter((name) => name.endsWith('.md') && !name.startsWith('.'))
    .map((name) => `Guide/${name}`)
    .sort();
  const unmanifested = guideMarkdownPaths.filter((relativePath) => !expectedPaths.has(relativePath));
  if (unmanifested.length > 0) {
    throw new Error(`genesis_manifest_unlisted_files:${unmanifested.join(',')}`);
  }
  if (guideMarkdownPaths.length !== verifiedFiles.length) {
    throw new Error(`genesis_manifest_file_count_mismatch:manifest=${verifiedFiles.length}:disk=${guideMarkdownPaths.length}`);
  }

  const computedRoot = computeGenesisCorpusRoot(manifest.files);
  if (computedRoot !== manifest.corpus_root) {
    throw new Error(`genesis_manifest_corpus_root_mismatch:expected=${manifest.corpus_root}:actual=${computedRoot}`);
  }

  return {
    ok: true,
    brainRoot: root,
    manifestPath,
    schema: manifest.schema,
    version: manifest.version,
    corpusRoot: computedRoot,
    files: verifiedFiles,
    dependencies: verifiedDependencies,
  };
}

function main() {
  const rootArg = process.argv.slice(2).find((arg) => arg.startsWith('--brain-root='));
  const unknown = process.argv.slice(2).filter((arg) => !arg.startsWith('--brain-root='));
  if (unknown.length > 0) throw new Error(`unknown_argument:${unknown.join(',')}`);
  const result = verifyGenesisManifest({
    brainRoot: rootArg ? rootArg.slice('--brain-root='.length) : DEFAULT_ROOT,
  });
  console.log(`[OK] Genesis manifest verified: ${result.files.length} files`);
  console.log(`     schema:      ${result.schema}`);
  console.log(`     version:     ${result.version}`);
  console.log(`     corpus_root: ${result.corpusRoot}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`[FATAL] ${error.message}`);
    process.exitCode = 1;
  }
}
