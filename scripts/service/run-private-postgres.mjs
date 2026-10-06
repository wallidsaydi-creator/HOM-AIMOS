#!/usr/bin/env node

// Portable service launcher for the AIMOS-only PostgreSQL cluster. It starts
// the existing owner-controlled PGDATA when needed, then supervises server.js.
// It never opens an administrator connection or reads a database secret.

import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveAimosInstallationContext } from '../../services/installation-context.js';
import { secureClusterPaths, secureHbaText } from '../db/secure-cluster.mjs';

function cliValue(argv, name) {
  const index = argv.indexOf(name);
  return index < 0 ? null : argv[index + 1];
}

function privateDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
      || (stat.mode & 0o077) !== 0) {
    throw new Error('private_postgres_directory_custody_invalid');
  }
}

function startPrivatePostgres(argv) {
  const context = resolveAimosInstallationContext(argv);
  if (context.postgres_port === 5432) throw new Error('private_postgres_port_required');
  const pgBin = cliValue(argv, '--pg-bindir');
  if (!pgBin || !path.isAbsolute(pgBin)) throw new Error('private_postgres_bindir_required');
  const pgConfig = path.join(pgBin, 'pg_config');
  const pgCtl = path.join(pgBin, 'pg_ctl');
  const version = execFileSync(pgConfig, ['--version'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000,
  }).trim();
  if (!/^PostgreSQL 18\./.test(version)) throw new Error('private_postgres_version_invalid');
  const paths = secureClusterPaths(context.state_root);
  privateDirectory(context.state_root);
  privateDirectory(paths.root);
  privateDirectory(paths.data);
  if (fs.readFileSync(path.join(paths.data, 'PG_VERSION'), 'utf8').trim() !== '18') {
    throw new Error('private_postgres_data_version_invalid');
  }
  const hbaPath = path.join(paths.data, 'pg_hba.conf');
  const hba = fs.lstatSync(hbaPath);
  if (!hba.isFile() || hba.isSymbolicLink() || hba.uid !== process.getuid()
      || (hba.mode & 0o077) !== 0
      || fs.readFileSync(hbaPath, 'utf8') !== secureHbaText()) {
    throw new Error('private_postgres_hba_invalid');
  }
  try {
    execFileSync(pgCtl, ['-D', paths.data, 'status'], {
      stdio: ['ignore', 'ignore', 'ignore'], timeout: 10_000,
    });
  } catch {
    execFileSync(pgCtl, ['-D', paths.data, '-l', paths.log,
      '-w', '-t', '30', 'start'], {
      stdio: ['ignore', 'pipe', 'pipe'], timeout: 40_000,
    });
  }
}

async function main() {
  const argv = process.argv.slice(2);
  startPrivatePostgres(argv);
  const childArgs = argv.filter((value, index) =>
    value !== '--pg-bindir' && argv[index - 1] !== '--pg-bindir');
  const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const child = spawn(process.execPath, [path.join(sourceRoot, 'server.js'), ...childArgs], {
    cwd: sourceRoot, stdio: 'inherit',
  });
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.on(signal, () => { if (child.exitCode === null) child.kill(signal); });
  }
  const outcome = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  process.exitCode = outcome.code ?? (outcome.signal ? 1 : 0);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
