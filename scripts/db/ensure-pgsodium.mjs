#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { resolveAimosDatabaseUrl } from '../../services/core/runtime-config.js';

const { Pool } = pg;
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
export const PGSODIUM_LOCK_PATH = path.join(SCRIPT_DIR, 'pgsodium-lock.json');
const BUILD_SCRIPT = path.join(SCRIPT_DIR, 'build-pgsodium.sh');

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(file) {
  return sha256Bytes(fs.readFileSync(file));
}

function commandOutput(file, args, execFn = execFileSync) {
  return String(execFn(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })).trim();
}

export function readPgsodiumLock(lockPath = PGSODIUM_LOCK_PATH) {
  const bytes = fs.readFileSync(lockPath);
  const lock = JSON.parse(bytes.toString('utf8'));
  if (
    lock?.schema !== 'hom.aimos.dependency-lock/pgsodium/v1'
    || lock?.name !== 'pgsodium'
    || !/^\d+\.\d+\.\d+$/.test(String(lock?.version || ''))
    || !/^[0-9a-f]{40}$/.test(String(lock?.tag_object_commit || ''))
    || !/^https:\/\/codeload\.github\.com\/michelp\/pgsodium\//.test(String(lock?.source_url || ''))
    || !Number.isSafeInteger(lock?.source_bytes)
    || lock.source_bytes <= 0
    || !/^[0-9a-f]{64}$/.test(String(lock?.source_sha256 || ''))
    || lock.tag !== `v${lock.version}`
    || lock.source_url !== `https://codeload.github.com/michelp/pgsodium/tar.gz/refs/tags/${lock.tag}`
  ) {
    throw new Error('pgsodium_dependency_lock_invalid');
  }
  return Object.freeze({ ...lock, lock_sha256: sha256Bytes(bytes) });
}

function maintenanceUrls(databaseUrl) {
  const parsed = new URL(databaseUrl);
  return ['postgres', 'template1'].map((database) => {
    const url = new URL(parsed);
    url.pathname = `/${database}`;
    return url.toString();
  });
}

async function connectMaintenance(databaseUrl, PoolClass = Pool) {
  let lastError = null;
  for (const connectionString of maintenanceUrls(databaseUrl)) {
    const pool = new PoolClass({
      connectionString,
      ssl: false,
      connectionTimeoutMillis: 5_000,
    });
    try {
      await pool.query('SELECT 1');
      return pool;
    } catch (error) {
      lastError = error;
      await pool.end().catch(() => {});
    }
  }
  throw new Error(`pgsodium_preflight_postgres_unavailable:${lastError?.message || 'unknown'}`);
}

async function serverFacts(pool) {
  const [config, extensions] = await Promise.all([
    pool.query(
      `SELECT name, setting
         FROM pg_config
        WHERE name IN ('BINDIR','PKGLIBDIR','SHAREDIR','VERSION')`,
    ),
    pool.query(
      `SELECT name, default_version, installed_version
         FROM pg_available_extensions
        WHERE name IN ('pgsodium', 'vector')`,
    ),
  ]);
  const extensionByName = Object.fromEntries(extensions.rows.map((row) => [row.name, row]));
  const settings = Object.fromEntries(config.rows.map((row) => [row.name, row.setting]));
  const pgConfig = settings.BINDIR ? path.join(settings.BINDIR, 'pg_config') : null;
  if (!pgConfig || !fs.existsSync(pgConfig)) throw new Error('pgsodium_server_pg_config_unavailable');
  return {
    pgConfig: fs.realpathSync(pgConfig),
    pgVersion: settings.VERSION,
    pkgLibDir: settings.PKGLIBDIR,
    shareDir: settings.SHAREDIR,
    availableVersion: extensionByName.pgsodium?.default_version || null,
    installedVersion: extensionByName.pgsodium?.installed_version || null,
    pgvectorAvailableVersion: extensionByName.vector?.default_version || null,
    pgvectorInstalledVersion: extensionByName.vector?.installed_version || null,
  };
}

function artifactReceipt(facts, lock, execFn = execFileSync) {
  const control = path.join(facts.shareDir, 'extension', 'pgsodium.control');
  if (!fs.existsSync(control)) throw new Error('pgsodium_control_file_missing_after_preflight');
  const controlText = fs.readFileSync(control, 'utf8');
  const controlVersion = controlText.match(/^default_version\s*=\s*'([^']+)'\s*$/m)?.[1] || null;
  if (controlVersion !== lock.version) throw new Error('pgsodium_control_version_mismatch');

  const library = ['pgsodium.dylib', 'pgsodium.so', 'pgsodium.dll']
    .map((name) => path.join(facts.pkgLibDir, name))
    .find((candidate) => fs.existsSync(candidate));
  if (!library) throw new Error('pgsodium_library_missing_after_preflight');

  const extensionDir = path.join(facts.shareDir, 'extension');
  const sqlFiles = fs.readdirSync(extensionDir)
    .filter((name) => /^pgsodium--.*\.sql$/.test(name))
    .sort()
    .map((name) => path.join(extensionDir, name));
  if (!sqlFiles.length) throw new Error('pgsodium_sql_artifacts_missing_after_preflight');

  let libsodiumVersion = null;
  try {
    libsodiumVersion = commandOutput('pkg-config', ['--modversion', 'libsodium'], execFn);
  } catch {
    libsodiumVersion = 'unavailable';
  }

  return Object.freeze({
    schema: 'hom.aimos.genesis-dependency-receipt/v1',
    dependency: lock.name,
    locked_version: lock.version,
    source_url: lock.source_url,
    source_bytes: lock.source_bytes,
    source_sha256: lock.source_sha256,
    tag_object_commit: lock.tag_object_commit,
    lock_sha256: lock.lock_sha256,
    postgres_version: facts.pgVersion,
    node_version: process.version,
    pgvector_available_version: facts.pgvectorAvailableVersion,
    pgvector_installed_version: facts.pgvectorInstalledVersion,
    pg_config_path: facts.pgConfig,
    libsodium_version: libsodiumVersion,
    control_file: control,
    control_sha256: sha256File(control),
    library_file: library,
    library_sha256: sha256File(library),
    extension_sql_set_sha256: sha256Bytes(Buffer.from(sqlFiles.map((file) => (
      `${path.basename(file)}\0${sha256File(file)}`
    )).join('\n'), 'utf8')),
    extension_sql_files: sqlFiles.length,
  });
}

function attestationPath(facts) {
  return path.join(facts.shareDir, 'extension', 'aimos-pgsodium-source-attestation-v1.json');
}

function attestationBody(receipt) {
  return {
    schema: 'hom.aimos.pgsodium-source-attestation/v1',
    dependency: receipt.dependency,
    locked_version: receipt.locked_version,
    lock_sha256: receipt.lock_sha256,
    source_sha256: receipt.source_sha256,
    control_sha256: receipt.control_sha256,
    library_sha256: receipt.library_sha256,
    extension_sql_set_sha256: receipt.extension_sql_set_sha256,
  };
}

function readMatchingAttestation(facts, receipt) {
  const file = attestationPath(facts);
  if (!fs.existsSync(file)) return null;
  try {
    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    return JSON.stringify(stored) === JSON.stringify(attestationBody(receipt))
      ? { file, sha256: sha256File(file) }
      : null;
  } catch {
    return null;
  }
}

function writeAttestation(facts, receipt) {
  const file = attestationPath(facts);
  const bytes = Buffer.from(`${JSON.stringify(attestationBody(receipt), null, 2)}\n`, 'utf8');
  const directory = path.dirname(file);
  fs.accessSync(directory, fs.constants.W_OK);
  const temporary = `${file}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(temporary, bytes, { mode: 0o644 });
    fs.renameSync(temporary, file);
    return { file, sha256: sha256File(file) };
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

export async function ensurePgsodium({
  databaseUrl = resolveAimosDatabaseUrl(),
  lockPath = PGSODIUM_LOCK_PATH,
  PoolClass = Pool,
  execFn = execFileSync,
} = {}) {
  const lock = readPgsodiumLock(lockPath);
  const pool = await connectMaintenance(databaseUrl, PoolClass);
  try {
    let facts = await serverFacts(pool);
    if (!String(facts.pgVersion || '').startsWith('PostgreSQL 18.')) {
      throw new Error(`postgresql_18_required:${facts.pgVersion || 'missing'}`);
    }
    if (!facts.pgvectorAvailableVersion) throw new Error('pgvector_extension_unavailable');
    let sourceInstallPerformed = false;
    let receipt = null;
    let attestation = null;
    if (facts.availableVersion === lock.version) {
      try {
        receipt = artifactReceipt(facts, lock, execFn);
        attestation = readMatchingAttestation(facts, receipt);
      } catch {
        receipt = null;
        attestation = null;
      }
    }
    if (!attestation) {
      commandOutput('bash', [
        BUILD_SCRIPT,
        '--pg-config', facts.pgConfig,
        '--lock', lockPath,
      ], execFn);
      sourceInstallPerformed = true;
      facts = await serverFacts(pool);
      if (facts.availableVersion !== lock.version) {
        throw new Error(`pgsodium_locked_version_unavailable:${facts.availableVersion || 'missing'}`);
      }
      receipt = artifactReceipt(facts, lock, execFn);
      attestation = writeAttestation(facts, receipt);
    }
    if (facts.availableVersion !== lock.version) {
      throw new Error(`pgsodium_locked_version_unavailable:${facts.availableVersion || 'missing'}`);
    }
    return Object.freeze({
      ...receipt,
      source_attestation_file: attestation.file,
      source_attestation_sha256: attestation.sha256,
      source_install_performed: sourceInstallPerformed,
      available_version: facts.availableVersion,
      installed_in_maintenance_database: facts.installedVersion,
      verified_before_database_creation: true,
      reasoning: 'Genesis matched the server artifacts to a local locked-source installation attestation and re-hashed every observed artifact before creating the AIMOS database.',
    });
  } finally {
    await pool.end().catch(() => {});
  }
}

async function main() {
  const receipt = await ensurePgsodium();
  console.log(JSON.stringify(receipt, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error?.stack || error);
    process.exitCode = 1;
  });
}
