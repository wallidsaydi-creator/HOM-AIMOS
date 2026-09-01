#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const TARGETS = [
  'verifiers/mutmem-v2/node/crypto-kernel.mjs',
  'verifiers/mutmem-v2/node/recall-verifier.mjs',
  'verifiers/mutmem-v2/node/mutation-verifier.mjs',
  'verifiers/mutmem-v2/python/crypto_kernel.py',
  'verifiers/mutmem-v2/python/recall_verifier.py',
  'verifiers/mutmem-v2/python/mutation_verifier.py',
];
const EXCLUDED = new Set(['.git', 'node_modules', 'artifacts', '.cache']);
const EXTENSIONS = ['.js', '.mjs', '.cjs', '.py'];
const sha = (value) => createHash('sha256').update(value).digest('hex');
const git = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
if (git.status !== 0) throw new Error('p2_import_census_source_commit_unavailable');
const sourceCommit = git.stdout.trim();
const canonical = (value) => {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (EXCLUDED.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(absolute));
    else if (EXTENSIONS.includes(path.extname(entry.name))) {
      output.push(path.relative(ROOT, absolute).split(path.sep).join('/'));
    }
  }
  return output;
}

function resolveSpecifier(owner, specifier, files) {
  if (specifier.startsWith('.')) {
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(owner), specifier));
    for (const candidate of [base, ...EXTENSIONS.map((extension) => `${base}${extension}`)]) {
      if (files.has(candidate)) return candidate;
    }
    return null;
  }
  if (owner.endsWith('.py') && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(specifier)) {
    const sibling = path.posix.join(path.posix.dirname(owner), `${specifier}.py`);
    return files.has(sibling) ? sibling : null;
  }
  return null;
}

function specifiers(source, file) {
  if (file.endsWith('.py')) {
    return [
      ...source.matchAll(/^\s*from\s+([.a-zA-Z_][.a-zA-Z0-9_]*)\s+import\s+/gm),
      ...source.matchAll(/^\s*import\s+([.a-zA-Z_][.a-zA-Z0-9_]*)/gm),
    ].map((match) => match[1].replace(/^\./, './'));
  }
  return [
    ...source.matchAll(/(?:from\s*|import\s*\()\s*['"]([^'"]+)['"]/g),
    ...source.matchAll(/export\s+[^;]*?from\s*['"]([^'"]+)['"]/g),
  ].map((match) => match[1]);
}

function production(file) {
  return file === 'server.js'
    || /^(?:routes|services|jobs|db|middleware)\//.test(file);
}

const sourceFiles = (await walk(ROOT)).sort();
const fileSet = new Set(sourceFiles);
const reverse = new Map(sourceFiles.map((file) => [file, new Set()]));
const sourceHashes = new Map();
for (const file of sourceFiles) {
  const bytes = await readFile(path.join(ROOT, file));
  sourceHashes.set(file, sha(bytes));
  const source = bytes.toString('utf8');
  for (const specifier of specifiers(source, file)) {
    const resolved = resolveSpecifier(file, specifier, fileSet);
    if (resolved) reverse.get(resolved).add(file);
  }
}

const census = TARGETS.map((target) => {
  if (!fileSet.has(target)) throw new Error(`p2_import_target_missing:${target}`);
  const direct = [...reverse.get(target)].sort();
  const visited = new Set();
  const queue = [...direct];
  while (queue.length) {
    const importer = queue.shift();
    if (visited.has(importer)) continue;
    visited.add(importer);
    queue.push(...reverse.get(importer));
  }
  const transitive = [...visited].sort();
  return {
    path: target,
    source_sha256: sourceHashes.get(target),
    direct_importer_count: direct.length,
    transitive_importer_count: transitive.length,
    production_runtime_direct_importers: direct.filter(production),
    production_runtime_transitive_importers: transitive.filter(production),
  };
});
const unsigned = {
  schema: 'hom.aimos.mutmem-p2-import-census/v1',
  source_commit: sourceCommit,
  source_file_count: sourceFiles.length,
  counting_method: 'resolved_relative_static_and_dynamic_import_reverse_bfs_v1',
  targets: census,
  zero_production_runtime_importers: census.every((entry) => (
    entry.production_runtime_direct_importers.length === 0
    && entry.production_runtime_transitive_importers.length === 0
  )),
};
const result = { ...unsigned, census_sha256: sha(Buffer.from(canonical(unsigned))) };
const output = process.argv.find((value) => value.startsWith('--output='))?.slice(9);
if (output) await writeFile(path.resolve(output), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o644 });
console.log(JSON.stringify(result, null, 2));
if (!result.zero_production_runtime_importers) process.exitCode = 1;
