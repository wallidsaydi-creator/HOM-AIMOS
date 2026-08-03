// scripts/identity/keychain.js
// macOS Keychain primitives. Public credential writes use Apple's signed
// `security` command interpreter: secret bytes travel as hexadecimal data on
// stdin, never in argv or on disk. The retained pre-release v1 helper is read
// only when a v1 item actually exists.

import { execFileSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SECURITY = '/usr/bin/security';
const LEGACY_V1_SOURCE = fileURLToPath(new URL('./keychain-set.c', import.meta.url));
const LEGACY_V1_MANIFEST = fileURLToPath(new URL('./keychain-helper-manifest.json', import.meta.url));
const LEGACY_V1_HELPER = path.join(os.homedir(), '.aimos', 'bin', 'aimos-keychain-credential-v1');
const LEGACY_V1_SOURCE_HASH = `${LEGACY_V1_HELPER}.sha256`;

function validateIdentifier(value, label) {
  const normalized = String(value || '');
  if (!/^[A-Za-z0-9._-]{1,512}$/.test(normalized)) {
    throw new Error(`${label} is malformed`);
  }
  return normalized;
}

function removeSecurityLineEnding(value) {
  const output = Buffer.isBuffer(value) ? value.toString('utf8') : String(value || '');
  if (output.endsWith('\r\n')) return output.slice(0, -2);
  if (output.endsWith('\n')) return output.slice(0, -1);
  return output;
}

// `security` exit code 44 is errSecItemNotFound (-25300).
export function keychainGetSync(service, account, runner = execFileSync) {
  const normalizedService = validateIdentifier(service, 'keychain service');
  const normalizedAccount = validateIdentifier(account, 'keychain account');
  try {
    const output = runner(
      SECURITY,
      ['find-generic-password', '-w', '-s', normalizedService, '-a', normalizedAccount],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
    return removeSecurityLineEnding(output);
  } catch (error) {
    if (error.status === 44) return null;
    throw error;
  }
}

export function keychainItemExistsSync(service, account, runner = execFileSync) {
  const normalizedService = validateIdentifier(service, 'keychain service');
  const normalizedAccount = validateIdentifier(account, 'keychain account');
  try {
    runner(
      SECURITY,
      ['find-generic-password', '-s', normalizedService, '-a', normalizedAccount],
      { encoding: 'utf8', stdio: ['ignore', 'ignore', 'ignore'] },
    );
    return true;
  } catch (error) {
    if (error.status === 44) return false;
    throw error;
  }
}

// Current public credential reads deliberately use the same Apple-signed
// executable that creates v2 items, avoiding per-item ACL prompts.
export function keychainCredentialGetSync(service, account, runner = execFileSync) {
  return keychainGetSync(service, account, runner);
}

function readLegacyV1Manifest() {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(LEGACY_V1_MANIFEST, 'utf8'));
  } catch {
    throw new Error('legacy v1 keychain helper manifest is malformed');
  }
  const sourceHash = createHash('sha256').update(readFileSync(LEGACY_V1_SOURCE)).digest('hex');
  const target = `${process.platform}-${process.arch}`;
  const artifacts = manifest?.accepted_installed?.[target];
  if (manifest?.schema_version !== 'aimos.keychain-helper-legacy-manifest/v1'
      || manifest?.abi !== 'v1'
      || manifest?.source_sha256 !== sourceHash
      || !Array.isArray(artifacts)
      || artifacts.some(item => !/^[0-9a-f]{64}$/.test(String(item?.sha256 || ''))
        || !Number.isSafeInteger(item?.size)
        || item.size < 1)) {
    throw new Error('legacy v1 keychain helper authority is invalid');
  }
  return { artifacts, sourceHash };
}

function validateLegacyV1Helper() {
  const { artifacts, sourceHash } = readLegacyV1Manifest();
  if (!existsSync(LEGACY_V1_HELPER) || !existsSync(LEGACY_V1_SOURCE_HASH)) {
    throw new Error('retained v1 credential exists but its native reader is unavailable');
  }
  const helperStat = lstatSync(LEGACY_V1_HELPER);
  const sourceStat = lstatSync(LEGACY_V1_SOURCE_HASH);
  if (!helperStat.isFile() || helperStat.isSymbolicLink()
      || !sourceStat.isFile() || sourceStat.isSymbolicLink()) {
    throw new Error('legacy v1 keychain helper files are not regular files');
  }
  if (typeof process.getuid === 'function'
      && (helperStat.uid !== process.getuid() || sourceStat.uid !== process.getuid())) {
    throw new Error('legacy v1 keychain helper owner mismatch');
  }
  if ((helperStat.mode & 0o077) !== 0 || (helperStat.mode & 0o100) === 0
      || (sourceStat.mode & 0o077) !== 0 || sourceStat.size !== 65) {
    throw new Error('legacy v1 keychain helper permissions are invalid');
  }
  const binaryHash = createHash('sha256').update(readFileSync(LEGACY_V1_HELPER)).digest('hex');
  if (!artifacts.some(item => item.sha256 === binaryHash && item.size === helperStat.size)) {
    throw new Error('legacy v1 keychain helper hash mismatch');
  }
  if (readFileSync(LEGACY_V1_SOURCE_HASH, 'utf8').trim() !== sourceHash) {
    throw new Error('legacy v1 keychain helper source attestation mismatch');
  }
  return LEGACY_V1_HELPER;
}

export function keychainLegacyV1GetSync(service, account, runner = null) {
  const normalizedService = validateIdentifier(service, 'keychain service');
  const normalizedAccount = validateIdentifier(account, 'keychain account');
  if (!keychainItemExistsSync(normalizedService, normalizedAccount, runner || execFileSync)) return null;
  try {
    const executable = runner ? 'aimos-keychain-credential-v1' : validateLegacyV1Helper();
    const output = (runner || execFileSync)(
      executable,
      ['get', normalizedService, normalizedAccount],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return String(output);
  } catch (error) {
    if (error.status === 44) return null;
    throw error;
  }
}

export function keychainSetSync(service, account, value, runner = execFileSync) {
  const normalizedService = validateIdentifier(service, 'keychain service');
  const normalizedAccount = validateIdentifier(account, 'keychain account');
  const secret = String(value);
  if (!secret) throw new Error('keychain credential value is required');
  const secretBytes = Buffer.from(secret, 'utf8');
  if (secretBytes.length > 1024 * 1024) throw new Error('keychain credential exceeds 1 MiB');
  const command = [
    'add-generic-password',
    '-U',
    '-s', normalizedService,
    '-a', normalizedAccount,
    '-X', secretBytes.toString('hex'),
  ].join(' ');
  runner(
    SECURITY,
    ['-i'],
    {
      encoding: 'utf8',
      input: `${command}\n`,
      stdio: ['pipe', 'ignore', 'pipe'],
      maxBuffer: 2 * 1024 * 1024,
    },
  );

  // Interactive mode can exit zero after a command-level failure. The exact
  // read-after-write postcondition makes a silent no-op impossible.
  const stored = keychainGetSync(normalizedService, normalizedAccount, runner);
  const storedBytes = Buffer.from(stored == null ? '' : stored, 'utf8');
  if (storedBytes.length !== secretBytes.length || !timingSafeEqual(storedBytes, secretBytes)) {
    throw new Error('keychain credential write postcondition failed');
  }
}

export function keychainDeleteSync(service, account, runner = execFileSync) {
  const normalizedService = validateIdentifier(service, 'keychain service');
  const normalizedAccount = validateIdentifier(account, 'keychain account');
  try {
    runner(
      SECURITY,
      ['delete-generic-password', '-s', normalizedService, '-a', normalizedAccount],
      { encoding: 'utf8', stdio: ['ignore', 'ignore', 'ignore'] },
    );
    return true;
  } catch (error) {
    if (error.status === 44) return false;
    throw error;
  }
}

export async function keychainGet(service, account) {
  return keychainGetSync(service, account);
}

export async function keychainSet(service, account, value) {
  return keychainSetSync(service, account, value);
}

export async function keychainDelete(service, account) {
  return keychainDeleteSync(service, account);
}
