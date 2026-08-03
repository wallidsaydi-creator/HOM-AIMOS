#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import pg from 'pg';

import { bootstrapDatabase } from '../bootstrap-db.mjs';
import { getMigrationFiles, runMigrations } from '../../migrations/run.js';
import { readPassphrase, readLine } from '../identity/passphrase.js';
import { keychainGet } from '../identity/keychain.js';
import { decryptMasterPrivkey, KC_SERVICE } from '../identity/lib.js';
import {
  pubkeyEquals,
  pubkeyFingerprint,
  signPayload,
} from '../../services/security/agent-identity.js';
import {
  createWholeBrainPurge,
  defaultPurgeFilesystemScope,
  writeDurableRetainedPurgeArtifact,
} from '../../services/security/whole-brain-purge.js';
import {
  resolveAimosDatabaseName,
  resolveAimosDatabaseUrl,
} from '../../services/core/runtime-config.js';

const { Pool } = pg;
const BRAIN_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const LIVE = process.argv.includes('--live');

function cliValue(name) {
  const inline = process.argv.find((arg) => arg.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

function cliValues(name) {
  const values = [];
  for (let index = 0; index < process.argv.length; index += 1) {
    const argument = process.argv[index];
    if (argument.startsWith(`${name}=`)) {
      values.push(argument.slice(name.length + 1));
    } else if (argument === name && process.argv[index + 1]) {
      values.push(process.argv[index + 1]);
      index += 1;
    }
  }
  return values;
}

function maintenanceUrl(databaseUrl) {
  const url = new URL(databaseUrl);
  url.pathname = '/postgres';
  return url.toString();
}

function publicKeyFromPrivate(privkeyB64u) {
  const privateKey = createPrivateKey({
    key: Buffer.from(privkeyB64u, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
}

function retainedArtifactPath({
  artifact,
  kind,
  databaseName,
  requestedReceiptPath,
  requestedReceiptDirectory,
}) {
  if (requestedReceiptPath) {
    const resolved = path.resolve(requestedReceiptPath);
    if (kind === 'receipt') return resolved;
    return resolved.endsWith('.json')
      ? `${resolved.slice(0, -5)}.intent.json`
      : `${resolved}.intent.json`;
  }
  if (requestedReceiptDirectory) {
    const suffix = kind === 'receipt' ? '.json' : '.intent.json';
    return path.join(path.resolve(requestedReceiptDirectory), `${databaseName}${suffix}`);
  }
  const suffix = kind === 'receipt' ? '.json' : '.intent.json';
  return path.join(BRAIN_ROOT, 'artifacts', 'purge-receipts', `${artifact.body.ceremony_id}${suffix}`);
}

async function resolveVerifiedMaster(targetPool, requestedAccount = null) {
  const result = await targetPool.query(
    `SELECT master_pubkey, fingerprint, keychain_service, keychain_account, created_at
       FROM aimos_master_identity
      ORDER BY created_at DESC
      LIMIT 1`
  );
  const master = result.rows[0];
  if (!master) throw new Error('master identity is not enrolled');
  const service = master.keychain_service || KC_SERVICE;
  let account = master.keychain_account || requestedAccount || null;
  if (!account) account = await readLine('Master Keychain account');
  if (!account) throw new Error('master Keychain account is required');
  const encrypted = await keychainGet(service, account);
  if (!encrypted) throw new Error('master_keychain_missing');
  const passphrase = await readPassphrase('Master passphrase: ');
  const privateKey = decryptMasterPrivkey(passphrase, encrypted);
  if (!privateKey) throw new Error('master_passphrase_invalid');
  const publicKey = publicKeyFromPrivate(privateKey);
  if (!pubkeyEquals(publicKey, master.master_pubkey)) throw new Error('master_public_key_mismatch');
  if (pubkeyFingerprint(publicKey) !== master.fingerprint) throw new Error('master_fingerprint_mismatch');
  return {
    privateKey,
    publicKey,
    fingerprint: master.fingerprint,
    epoch: new Date(master.created_at).toISOString(),
    keychainItem: { service, account },
  };
}

async function purgeTarget({
  databaseName,
  master,
  maintenancePool,
  packageVersion,
  confirmation,
  requestedReceiptPath,
  requestedReceiptDirectory,
}) {
  const databaseArgv = ['--aimos-db', databaseName];
  const databaseUrl = resolveAimosDatabaseUrl(databaseArgv);
  const scratchTarget = databaseName !== 'aimos';
  const targetPool = new Pool({ connectionString: databaseUrl, ssl: false });
  try {
    const purge = createWholeBrainPurge({
      targetPool,
      maintenancePool,
      completionMode: scratchTarget ? 'destroy' : 'reinitialize',
      filesystemScope: scratchTarget ? [] : defaultPurgeFilesystemScope(BRAIN_ROOT),
      keychainListFn: scratchTarget ? (() => []) : undefined,
      allowCanonical: true,
      recreateFn: scratchTarget
        ? undefined
        : async () => {
          await bootstrapDatabase({ databaseUrl, databaseName });
          const pool = new Pool({ connectionString: databaseUrl, ssl: false });
          await runMigrations(pool, { verbose: true });
          return { pool, migrationCount: getMigrationFiles().length };
        },
      signReceiptFn: async (body) => {
        const nonce = randomBytes(16).toString('base64url');
        const signedTs = Math.floor(Date.now() / 1000);
        return {
          signature: signPayload(master.privateKey, body, nonce, signedTs),
          publicKey: master.publicKey,
          nonce,
          signedTs,
        };
      },
      persistIntentFn: async (intent) => writeDurableRetainedPurgeArtifact(
        retainedArtifactPath({
          artifact: intent,
          kind: 'intent',
          databaseName,
          requestedReceiptPath,
          requestedReceiptDirectory,
        }),
        intent,
      ),
    });

    const receipt = await purge.execute({
      databaseName,
      companyId: 'hom',
      confirmation,
      actor: { fingerprint: master.fingerprint, epoch: master.epoch },
      softwareRelease: `HOM-AIMOS/${packageVersion}`,
      extraKeychainItems: scratchTarget ? [] : [master.keychainItem],
    });
    const receiptPath = retainedArtifactPath({
      artifact: receipt,
      kind: 'receipt',
      databaseName,
      requestedReceiptPath,
      requestedReceiptDirectory,
    });
    const persistedReceipt = writeDurableRetainedPurgeArtifact(receiptPath, receipt);
    console.log(JSON.stringify({
      success: true,
      receipt: receiptPath,
      receipt_sha256: persistedReceipt.artifact_sha256,
      intent_sha256: receipt.body.intent_sha256,
      ceremony_id: receipt.body.ceremony_id,
    }, null, 2));
  } finally {
    await targetPool.end().catch(() => {});
  }
}

async function inventoryTarget({ databaseName, master, maintenancePool }) {
  const databaseUrl = resolveAimosDatabaseUrl(['--aimos-db', databaseName]);
  const targetPool = new Pool({ connectionString: databaseUrl, ssl: false });
  try {
    const purge = createWholeBrainPurge({
      targetPool,
      maintenancePool,
      completionMode: databaseName === 'aimos' ? 'reinitialize' : 'destroy',
      filesystemScope: databaseName === 'aimos' ? defaultPurgeFilesystemScope(BRAIN_ROOT) : [],
      keychainListFn: databaseName === 'aimos' ? undefined : (() => []),
      allowCanonical: true,
      signReceiptFn: async () => {
        throw new Error('inventory cannot sign a purge receipt');
      },
      persistIntentFn: async () => {
        throw new Error('inventory cannot persist a purge intent');
      },
    });
    const inventory = await purge.inventory({ databaseName, companyId: 'hom' });
    console.log(JSON.stringify({
      mode: LIVE ? 'LIVE' : 'DRY_RUN',
      actor: { fingerprint: master.fingerprint, epoch: master.epoch },
      inventory,
    }, null, 2));
    return inventory;
  } finally {
    await targetPool.end().catch(() => {});
  }
}

function multiTargetConfirmation(databaseNames) {
  const targetManifest = JSON.stringify({
    domain: 'aimos-multi-target-purge/v1',
    company: 'hom',
    databases: databaseNames,
  });
  const targetManifestSha256 = createHash('sha256').update(targetManifest, 'utf8').digest('hex');
  return {
    expected: `PURGE AIMOS hom ${databaseNames.length} SCRATCH BRAINS ${targetManifestSha256}`,
    targetManifestSha256,
  };
}

async function main() {
  const requestedNames = cliValues('--aimos-db');
  const allScratch = process.argv.includes('--all-scratch');
  if (allScratch && requestedNames.length) {
    throw new Error('choose either --all-scratch or explicit --aimos-db targets');
  }
  let databaseNames = requestedNames.length
    ? requestedNames.map((name) => resolveAimosDatabaseName(['--aimos-db', name]))
    : allScratch ? [] : [resolveAimosDatabaseName()];
  const requestedReceiptPath = cliValue('--receipt-file');
  const requestedReceiptDirectory = cliValue('--receipt-dir');
  if (requestedReceiptPath && databaseNames.length > 1) {
    throw new Error('--receipt-file supports one target; use --receipt-dir for multiple targets');
  }
  if (requestedReceiptPath && requestedReceiptDirectory) {
    throw new Error('choose either --receipt-file or --receipt-dir');
  }

  const authorityUrl = resolveAimosDatabaseUrl(['--aimos-db', 'aimos']);
  const authorityPool = new Pool({ connectionString: authorityUrl, ssl: false });
  const maintenancePool = new Pool({ connectionString: maintenanceUrl(authorityUrl), ssl: false });
  let master;
  try {
    if (allScratch) {
      const result = await maintenancePool.query(
        `SELECT datname
           FROM pg_database
          WHERE datname ~ '^aimos_(test|benchmark|purge)_[A-Za-z0-9_]+$'
          ORDER BY datname`,
      );
      databaseNames = result.rows.map((row) => resolveAimosDatabaseName(['--aimos-db', row.datname]));
      if (!databaseNames.length) throw new Error('no AIMOS scratch brains found');
    }
    if (new Set(databaseNames).size !== databaseNames.length) {
      throw new Error('duplicate purge database target');
    }
    if (databaseNames.length > 1 && databaseNames.includes('aimos')) {
      throw new Error('canonical AIMOS cannot be included in a multi-target purge ceremony');
    }

    master = await resolveVerifiedMaster(authorityPool, cliValue('--keychain-account'));
    const packageJson = JSON.parse(fs.readFileSync(path.join(BRAIN_ROOT, 'package.json'), 'utf8'));
    for (const databaseName of databaseNames) {
      await inventoryTarget({ databaseName, master, maintenancePool });
    }
    if (!LIVE) return;

    let aggregateConfirmation = null;
    if (databaseNames.length > 1) {
      const aggregate = multiTargetConfirmation(databaseNames);
      console.log(JSON.stringify({
        multi_target_confirmation: {
          target_count: databaseNames.length,
          target_manifest_sha256: aggregate.targetManifestSha256,
          databases: databaseNames,
        },
      }, null, 2));
      aggregateConfirmation = await readLine(`Type exactly ${JSON.stringify(aggregate.expected)}`);
      if (aggregateConfirmation !== aggregate.expected) {
        throw new Error('multi-target purge confirmation mismatch');
      }
    }

    for (const databaseName of databaseNames) {
      const confirmation = databaseNames.length > 1
        ? `PURGE AIMOS hom ${databaseName}`
        : await readLine(`Type exactly ${JSON.stringify(`PURGE AIMOS hom ${databaseName}`)}`);
      await purgeTarget({
        databaseName,
        master,
        maintenancePool,
        packageVersion: packageJson.version,
        confirmation,
        requestedReceiptPath,
        requestedReceiptDirectory,
      });
    }
    if (LIVE && databaseNames.length > 1) {
      console.log(JSON.stringify({
        success: true,
        purged_databases: databaseNames,
        receipt_directory: requestedReceiptDirectory ? path.resolve(requestedReceiptDirectory) : null,
      }, null, 2));
    }
  } finally {
    if (master?.privateKey) master.privateKey = null;
    await Promise.allSettled([authorityPool.end(), maintenancePool.end()]);
  }
}

main().catch((error) => {
  console.error(`[purge-brain] ${error?.message || String(error)}`);
  process.exitCode = 1;
});
