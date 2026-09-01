import { spawn } from 'node:child_process';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as scryptCallback,
} from 'node:crypto';
import fs from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { promisify } from 'node:util';

import { canonicalJson, sha256 } from './cr9-postgres.mjs';

const scrypt = promisify(scryptCallback);
const PRODUCTION_KDF = Object.freeze({ N: 2 ** 18, r: 8, p: 1, maxmem: 512 * 1024 * 1024 });
const ALGORITHM = 'aes-256-gcm';
const TAG_BYTES = 16;
const IV_BYTES = 12;
const SALT_BYTES = 32;

class HashingTransform extends Transform {
  constructor() {
    super();
    this.hash = createHash('sha256');
    this.bytes = 0;
  }

  _transform(chunk, encoding, callback) {
    this.hash.update(chunk);
    this.bytes += chunk.length;
    callback(null, chunk);
  }

  digest() {
    return this.hash.digest('hex');
  }
}

function assertKdf(kdf, { allowWeakForTest = false } = {}) {
  if (!Number.isInteger(kdf.N) || (kdf.N & (kdf.N - 1)) !== 0
      || !Number.isInteger(kdf.r) || !Number.isInteger(kdf.p)
      || kdf.r <= 0 || kdf.p <= 0 || kdf.N <= 1) {
    throw new Error('cr9_backup_kdf_invalid');
  }
  if (!allowWeakForTest && kdf.N < PRODUCTION_KDF.N) throw new Error('cr9_backup_kdf_below_production_floor');
}

async function deriveKey(passphrase, salt, kdf, options = {}) {
  assertKdf(kdf, options);
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('cr9_backup_passphrase_invalid');
  const key = await scrypt(passphrase, salt, 32, kdf);
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('cr9_backup_key_derivation_invalid');
  return key;
}

export function createBackupHeader({
  database = 'aimos',
  sourceSchemaSha256,
  sourceSemanticSchemaSha256,
  authorizationSha256,
  sourceCommit,
  createdAt = new Date().toISOString(),
  salt = randomBytes(SALT_BYTES),
  iv = randomBytes(IV_BYTES),
  kdf = PRODUCTION_KDF,
} = {}) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)
      || !/^[0-9a-f]{64}$/.test(String(sourceSchemaSha256 || ''))
      || !/^[0-9a-f]{64}$/.test(String(sourceSemanticSchemaSha256 || ''))
      || !/^[0-9a-f]{64}$/.test(String(authorizationSha256 || ''))
      || !/^[0-9a-f]{40}$/.test(String(sourceCommit || ''))
      || !Buffer.isBuffer(salt) || salt.length !== SALT_BYTES
      || !Buffer.isBuffer(iv) || iv.length !== IV_BYTES) {
    throw new Error('cr9_backup_header_invalid');
  }
  assertKdf(kdf);
  return Object.freeze({
    schema: 'hom.aimos.cr9-encrypted-backup-header/v1',
    database,
    source_schema_sha256: sourceSchemaSha256,
    source_semantic_schema_sha256: sourceSemanticSchemaSha256,
    authorization_sha256: authorizationSha256,
    source_commit: sourceCommit,
    created_at: createdAt,
    encryption: Object.freeze({
      algorithm: 'AES-256-GCM',
      iv_b64u: iv.toString('base64url'),
      tag_bytes: TAG_BYTES,
      aad_schema: 'canonical-json-header-exact-bytes',
    }),
    kdf: Object.freeze({
      algorithm: 'scrypt',
      rfc: 'RFC 7914',
      salt_b64u: salt.toString('base64url'),
      N: kdf.N,
      r: kdf.r,
      p: kdf.p,
      maxmem: kdf.maxmem,
    }),
    authenticated_encryption_authority: 'NIST SP 800-38D',
  });
}

function decodeHeaderCrypto(header) {
  const salt = Buffer.from(String(header?.kdf?.salt_b64u || ''), 'base64url');
  const iv = Buffer.from(String(header?.encryption?.iv_b64u || ''), 'base64url');
  if (header?.schema !== 'hom.aimos.cr9-encrypted-backup-header/v1'
      || header?.encryption?.algorithm !== 'AES-256-GCM'
      || header?.kdf?.algorithm !== 'scrypt'
      || salt.length !== SALT_BYTES || iv.length !== IV_BYTES
      || Number(header?.encryption?.tag_bytes) !== TAG_BYTES) {
    throw new Error('cr9_backup_manifest_crypto_invalid');
  }
  const kdf = {
    N: Number(header.kdf.N), r: Number(header.kdf.r), p: Number(header.kdf.p), maxmem: Number(header.kdf.maxmem),
  };
  assertKdf(kdf);
  return { salt, iv, kdf };
}

export async function encryptBufferForTest(plaintext, passphrase, header, { kdf = null } = {}) {
  const decoded = decodeHeaderCrypto(header);
  const effective = kdf || decoded.kdf;
  const key = await deriveKey(passphrase, decoded.salt, effective, { allowWeakForTest: Boolean(kdf) });
  try {
    const cipher = createCipheriv(ALGORITHM, key, decoded.iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(canonicalJson(header), 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    return Object.freeze({ ciphertext, tag: cipher.getAuthTag() });
  } finally {
    key.fill(0);
  }
}

export async function decryptBufferForTest(ciphertext, tag, passphrase, header, { kdf = null } = {}) {
  const decoded = decodeHeaderCrypto(header);
  const effective = kdf || decoded.kdf;
  const key = await deriveKey(passphrase, decoded.salt, effective, { allowWeakForTest: Boolean(kdf) });
  try {
    const decipher = createDecipheriv(ALGORITHM, key, decoded.iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(canonicalJson(header), 'utf8'));
    decipher.setAuthTag(Buffer.from(tag));
    return Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  } finally {
    key.fill(0);
  }
}

function childCompletion(child, label) {
  let stderr = '';
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-32_768);
  });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0) resolve({ code, signal, stderr });
      else reject(new Error(`${label}_failed:${code}:${signal || 'none'}:${stderr.replaceAll(/\s+/g, ' ').trim().slice(0, 600)}`));
    });
  });
}

export async function encryptPgDumpToFile({
  pgDump,
  database,
  outputPath,
  passphrase,
  header,
} = {}) {
  if (!pgDump || !database || !outputPath || fs.existsSync(outputPath) || fs.existsSync(`${outputPath}.partial`)) {
    throw new Error('cr9_backup_output_invalid');
  }
  const decoded = decodeHeaderCrypto(header);
  const key = await deriveKey(passphrase, decoded.salt, decoded.kdf);
  const partial = `${outputPath}.partial`;
  const dump = spawn(pgDump, [
    '--dbname', database,
    '--format=custom',
    '--compress=9',
    '--no-owner',
    '--no-privileges',
    '--serializable-deferrable',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  const plaintextHash = new HashingTransform();
  const ciphertextHash = new HashingTransform();
  const cipher = createCipheriv(ALGORITHM, key, decoded.iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(canonicalJson(header), 'utf8'));
  const writer = fs.createWriteStream(partial, { flags: 'wx', mode: 0o600 });
  try {
    const [completion] = await Promise.all([
      childCompletion(dump, 'cr9_pg_dump'),
      pipeline(dump.stdout, plaintextHash, cipher, ciphertextHash, writer),
    ]);
    const tag = cipher.getAuthTag();
    fs.renameSync(partial, outputPath);
    fs.chmodSync(outputPath, 0o600);
    return Object.freeze({
      plaintext_sha256: plaintextHash.digest(),
      plaintext_bytes: plaintextHash.bytes,
      ciphertext_sha256: ciphertextHash.digest(),
      ciphertext_bytes: ciphertextHash.bytes,
      auth_tag_b64u: tag.toString('base64url'),
      pg_dump_stderr_sha256: sha256(Buffer.from(completion.stderr || '', 'utf8')),
      plaintext_file_created: false,
    });
  } catch (error) {
    try { fs.unlinkSync(partial); } catch { /* absent or already renamed */ }
    throw error;
  } finally {
    key.fill(0);
  }
}

export async function restoreEncryptedBackup({
  pgRestore,
  database,
  encryptedPath,
  passphrase,
  header,
  authTagB64u,
  expectedCiphertextSha256,
} = {}) {
  const decoded = decodeHeaderCrypto(header);
  const actualCiphertextSha256 = await new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const reader = fs.createReadStream(encryptedPath);
    reader.on('data', (chunk) => hash.update(chunk));
    reader.once('error', reject);
    reader.once('end', () => resolve(hash.digest('hex')));
  });
  if (actualCiphertextSha256 !== expectedCiphertextSha256) throw new Error('cr9_backup_ciphertext_hash_mismatch');
  const tag = Buffer.from(String(authTagB64u || ''), 'base64url');
  if (tag.length !== TAG_BYTES) throw new Error('cr9_backup_auth_tag_invalid');
  const key = await deriveKey(passphrase, decoded.salt, decoded.kdf);
  const restore = spawn(pgRestore, [
    '--dbname', database,
    '--no-owner',
    '--no-privileges',
    '--exit-on-error',
    '--single-transaction',
  ], {
    stdio: ['pipe', 'ignore', 'pipe'],
    env: { ...process.env, PGOPTIONS: '-c pgsodium.enable_event_trigger=off' },
  });
  const decipher = createDecipheriv(ALGORITHM, key, decoded.iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(canonicalJson(header), 'utf8'));
  decipher.setAuthTag(tag);
  try {
    await Promise.all([
      childCompletion(restore, 'cr9_pg_restore'),
      pipeline(fs.createReadStream(encryptedPath), decipher, restore.stdin),
    ]);
    return Object.freeze({ restored: true, ciphertext_sha256: actualCiphertextSha256, plaintext_file_created: false });
  } finally {
    key.fill(0);
  }
}

export const CR9_BACKUP_CRYPTO_PROFILE = Object.freeze({
  algorithm: 'AES-256-GCM',
  ivBytes: IV_BYTES,
  tagBytes: TAG_BYTES,
  saltBytes: SALT_BYTES,
  kdf: PRODUCTION_KDF,
  standards: Object.freeze(['NIST SP 800-38D', 'RFC 7914']),
});
