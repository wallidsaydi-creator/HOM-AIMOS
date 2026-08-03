#!/usr/bin/env node

/**
 * Construct a public AIMOS source tree without carrying private Git history.
 * The destination must be new or empty. This script never deletes or rewrites
 * an existing tree and never pushes a repository.
 */

import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { canonicalJson } from '../../eval/poisonedrag/protocol.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MANIFEST_NAME = 'RELEASE-SOURCE-MANIFEST.json';
const EXTRA_PUBLIC_FILES = Object.freeze([
  '.github/dependabot.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/release-ceremony.yml',
  '.gitignore',
  '.npmignore',
  'package-lock.json',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function cliValue(argv, name) {
  const inline = argv.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
}

function parseArgs(argv) {
  const requested = String(cliValue(argv, '--output') || '').trim();
  if (!requested) throw new Error('public_release_output_required');
  const output = path.resolve(requested);
  if (output === ROOT || ROOT.startsWith(`${output}${path.sep}`)) {
    throw new Error('public_release_output_overlaps_source');
  }
  return {
    output,
    initializeGit: !argv.includes('--no-git-init'),
    commit: argv.includes('--commit'),
  };
}

function assertCleanSource() {
  const status = execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (status.trim()) throw new Error('public_release_source_worktree_not_clean');
}

function assertEmptyDestination(output) {
  if (!existsSync(output)) {
    mkdirSync(output, { recursive: true, mode: 0o755 });
    return;
  }
  const stat = lstatSync(output);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('public_release_output_not_directory');
  }
  if (readdirSync(output).length !== 0) throw new Error('public_release_output_not_empty');
}

function npmPackageFiles() {
  const result = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  }))[0];
  if (!result || !Array.isArray(result.files) || result.files.length < 1) {
    throw new Error('public_release_npm_pack_manifest_invalid');
  }
  return result.files.map((entry) => entry.path);
}

function copyRegularFile(relativePath, output, destinationPath = relativePath) {
  const source = path.resolve(ROOT, relativePath);
  if (!source.startsWith(`${ROOT}${path.sep}`) || !existsSync(source)) {
    throw new Error(`public_release_source_missing:${relativePath}`);
  }
  const stat = lstatSync(source);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`public_release_source_not_regular:${relativePath}`);
  }
  const destination = path.join(output, destinationPath);
  mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  copyFileSync(source, destination);
  chmodSync(destination, stat.mode & 0o777);
}

function stripImmutableMigrationNotes(output, relativePath) {
  if (!relativePath.startsWith('migrations/') || !relativePath.endsWith('.sql')) return;
  if (relativePath === 'migrations/029-rename-runtime-role.sql') return;
  const destination = path.join(output, relativePath);
  const lines = readFileSync(destination, 'utf8').split('\n');
  const sensitive = [
    /\[\[(?:hom-|feedback-)/i,
    new RegExp(['\\bthe', 'operator\\b|\\boperator[\'’]s\\b|\\boperator\\s+20\\d{2}\\b'].join(' '), 'i'),
    new RegExp(['Wa', 'lid'].join(''), 'i'),
    /\b(?:Claude|Fable|Sonnet|Opus|GLM[- ]?5|GPT[- ]?5\.6\s+SOL)\b/i,
    /(?:^|\s)plans\//i,
    /\bplan\s+[a-z]+-[a-z]+-[a-z]+\.md\b/i,
    /(?:\/Users\/|\/var\/folders\/|\/tmp\/hom)/i,
    new RegExp(['after architect', 'approval'].join(' '), 'i'),
    new RegExp(['\\bworkstream\\b|\\bincident', 'directive\\b|\\bR\\d+ report\\b|\\bTask\\s+\\d+\\b'].join(' '), 'i'),
  ];
  const containsSensitiveNote = (block) => sensitive.some((pattern) => pattern.test(block.join('\n')));
  const kept = [];
  for (let index = 0; index < lines.length;) {
    if (/^\s*--/.test(lines[index])) {
      const block = [];
      while (index < lines.length && /^\s*--/.test(lines[index])) block.push(lines[index++]);
      kept.push(...(containsSensitiveNote(block) ? block.map(() => '') : block));
      continue;
    }
    if (/^\s*COMMENT\s+ON\b/i.test(lines[index])) {
      const block = [];
      do {
        block.push(lines[index]);
      } while (!/;\s*$/.test(lines[index++]) && index < lines.length);
      kept.push(...(containsSensitiveNote(block) ? block.map(() => '') : block));
      continue;
    }
    kept.push(lines[index++]);
  }
  const sanitized = kept.join('\n');
  writeFileSync(destination, sanitized, { mode: 0o644 });
}

function publicFiles(output) {
  const files = [];
  function walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (directory === output && entry.name === '.git') continue;
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(output, absolute);
      if (relative === MANIFEST_NAME) continue;
      if (entry.isSymbolicLink()) throw new Error(`public_release_symlink_forbidden:${relative}`);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) {
        files.push({
          path: relative,
          bytes: statSync(absolute).size,
          sha256: sha256(readFileSync(absolute)),
        });
      }
    }
  }
  walk(output);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function writeSourceManifest(output) {
  const packageJson = JSON.parse(readFileSync(path.join(output, 'package.json'), 'utf8'));
  const files = publicFiles(output);
  const unsigned = {
    schema: 'hom.aimos.public-source-manifest/v1',
    product: packageJson.name,
    version: packageJson.version,
    license: packageJson.license,
    hash_algorithm: 'sha256',
    root_algorithm: 'sha256(canonical-json(files))',
    manifest_self_excluded: true,
    file_count: files.length,
    files_root_sha256: sha256(Buffer.from(canonicalJson(files), 'utf8')),
    files,
  };
  const manifest = {
    ...unsigned,
    manifest_sha256: sha256(Buffer.from(canonicalJson(unsigned), 'utf8')),
  };
  writeFileSync(
    path.join(output, MANIFEST_NAME),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { mode: 0o644 },
  );
  return manifest;
}

function initializeRepository(output, commit) {
  execFileSync('git', ['init', '-b', 'main'], { cwd: output, stdio: 'inherit' });
  if (!commit) return null;
  for (const key of ['user.name', 'user.email']) {
    const value = execFileSync('git', ['config', '--get', key], {
      cwd: output,
      encoding: 'utf8',
    }).trim();
    if (!value) throw new Error(`public_release_git_identity_missing:${key}`);
  }
  execFileSync('git', ['add', '--all'], { cwd: output, stdio: 'inherit' });
  execFileSync('git', ['commit', '-m', 'feat: release AIMOS backend v1.0.0'], {
    cwd: output,
    stdio: 'inherit',
  });
  const count = Number(execFileSync('git', ['rev-list', '--all', '--count'], {
    cwd: output,
    encoding: 'utf8',
  }).trim());
  const status = execFileSync('git', ['status', '--porcelain=v1'], {
    cwd: output,
    encoding: 'utf8',
  }).trim();
  if (count !== 1 || status) throw new Error('public_release_single_commit_invariant_failed');
  return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: output, encoding: 'utf8' }).trim();
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.commit && !args.initializeGit) throw new Error('public_release_commit_requires_git_init');
  assertCleanSource();
  assertEmptyDestination(args.output);
  const files = [...new Set([...npmPackageFiles(), ...EXTRA_PUBLIC_FILES])].sort();
  for (const relativePath of files) {
    copyRegularFile(relativePath, args.output);
    stripImmutableMigrationNotes(args.output, relativePath);
  }
  const manifest = writeSourceManifest(args.output);
  const publicCommit = args.initializeGit
    ? initializeRepository(args.output, args.commit)
    : null;
  console.log(JSON.stringify({
    success: true,
    output: args.output,
    copied_files: files.length,
    manifest_file_count: manifest.file_count,
    files_root_sha256: manifest.files_root_sha256,
    manifest_sha256: manifest.manifest_sha256,
    git_initialized: args.initializeGit,
    public_commit: publicCommit,
    pushed: false,
  }, null, 2));
}

main();
