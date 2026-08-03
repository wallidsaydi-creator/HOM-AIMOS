/**
 * whole-brain-purge.js — the sole destructive Aladdin exception.
 *
 * This owner is intentionally offline. It is not imported by server.js, any
 * route, MCP surface, tool registry, job, scheduler, or housekeeper loop.
 * Ordinary runtime roles retain no DELETE/TRUNCATE/DROP authority.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

import {
  canonicalJson,
  pubkeyFingerprint,
  verifyStoredPayloadSig,
} from './agent-identity.js';
import {
  CREDENTIAL_KEYCHAIN_ACCOUNT,
  listCredentialKeychainItemsSync,
} from './credential-store.js';
import { keychainDeleteSync } from '../../scripts/identity/keychain.js';

const DATABASE_NAME_RE = /^[a-z][a-z0-9_]{0,62}$/;
const SCRATCH_DATABASE_RE = /^aimos_(?:test|benchmark|purge)_[a-z0-9_]+$/;
const IDENTITY_FILE_RE = /(?:\.key|\.cert-cache\.json)$/;

const SENSITIVE_TABLES = Object.freeze([
  'aimos_memories',
  'aimos_memory_provenance',
  'aimos_save_envelope',
  'aimos_events',
  'aimos_credential_lifecycle',
  'aimos_authorization_events',
  'aimos_recall_authorization_events',
  'aimos_agent_revocation_events',
  'aimos_system_config',
  'agent_identity',
  'aimos_master_identity',
  'integration_tokens',
]);

function quoteIdentifier(value) {
  if (!DATABASE_NAME_RE.test(value)) throw new Error(`invalid database identifier: ${value}`);
  return `"${value}"`;
}

function classifyTable(tableName) {
  if (/memory|quim|codebook|embedding|entity|relation|graph|timeline|temporal|supersession/i.test(tableName)) return 'memory_and_index';
  if (/provenance|envelope|event|ledger|authorization|revocation|config/i.test(tableName)) return 'cryptographic_proof';
  if (/credential|integration_token/i.test(tableName)) return 'credential_reference';
  if (/agent|master|session|task|directive/i.test(tableName)) return 'identity_and_execution';
  return 'operational_projection';
}

async function inventoryDatabase(client) {
  const tables = await client.query(
    `SELECT tablename
       FROM pg_catalog.pg_tables
      WHERE schemaname = 'public'
      ORDER BY tablename`
  );
  const classes = new Map();
  for (const row of tables.rows) {
    const table = String(row.tablename);
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) throw new Error('unexpected table identifier');
    const count = await client.query(`SELECT count(*)::bigint AS count FROM "${table}"`);
    const className = classifyTable(table);
    classes.set(className, (classes.get(className) || 0) + Number(count.rows[0]?.count || 0));
  }
  return [...classes.entries()]
    .map(([className, rowCount]) => ({ class: className, row_count: rowCount }))
    .sort((left, right) => left.class.localeCompare(right.class));
}

function walkOwnedPath(targetPath, { identityOnly = false } = {}) {
  if (!fs.existsSync(targetPath)) return { path: targetPath, file_count: 0, byte_count: 0, unexpected_count: 0 };
  const root = path.resolve(targetPath);
  const stack = [root];
  let fileCount = 0;
  let byteCount = 0;
  let unexpectedCount = 0;
  while (stack.length) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      unexpectedCount++;
      continue;
    }
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) {
        const child = path.resolve(current, entry);
        if (child !== root && !child.startsWith(`${root}${path.sep}`)) throw new Error('owned path escape detected');
        stack.push(child);
      }
      continue;
    }
    if (!stat.isFile() || (identityOnly && !IDENTITY_FILE_RE.test(path.basename(current)))) {
      unexpectedCount++;
      continue;
    }
    fileCount++;
    byteCount += stat.size;
  }
  return { path: targetPath, file_count: fileCount, byte_count: byteCount, unexpected_count: unexpectedCount };
}

function removeOwnedPath(targetPath, { identityOnly = false } = {}) {
  if (!fs.existsSync(targetPath)) return 0;
  const root = path.resolve(targetPath);
  const entries = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error(`refusing purge symlink: ${current}`);
    if (stat.isDirectory()) {
      entries.push({ path: current, directory: true });
      for (const entry of fs.readdirSync(current)) {
        const child = path.resolve(current, entry);
        if (child !== root && !child.startsWith(`${root}${path.sep}`)) throw new Error('purge path escape detected');
        stack.push(child);
      }
    } else if (stat.isFile() && (!identityOnly || IDENTITY_FILE_RE.test(path.basename(current)))) {
      entries.push({ path: current, directory: false });
    } else {
      throw new Error(`unexpected purge filesystem entry: ${current}`);
    }
  }
  let removed = 0;
  for (const entry of entries.filter((item) => !item.directory)) {
    fs.unlinkSync(entry.path);
    removed++;
  }
  for (const entry of entries.filter((item) => item.directory).sort((a, b) => b.path.length - a.path.length)) {
    if (fs.readdirSync(entry.path).length === 0) fs.rmdirSync(entry.path);
  }
  return removed;
}

export function defaultPurgeFilesystemScope(brainRoot) {
  return Object.freeze([
    Object.freeze({ class: 'identity_keys', path: path.join(os.homedir(), '.aimos', 'agents'), identityOnly: true }),
    Object.freeze({ class: 'meta_improvement', path: path.join(brainRoot, 'state', 'meta-improvement'), identityOnly: false }),
    Object.freeze({ class: 'database_backups', path: path.join(brainRoot, 'db', 'backups'), identityOnly: false }),
    Object.freeze({ class: 'command_center_session', path: path.join(os.homedir(), '.hom', 'command-center-sessions.json'), identityOnly: false }),
    Object.freeze({ class: 'legacy_command_center_config', path: path.join(os.homedir(), '.hom', 'command-center-config.json'), identityOnly: false }),
    Object.freeze({ class: 'legacy_model_preferences', path: path.join(os.homedir(), '.hom', 'model-preferences.json'), identityOnly: false }),
    Object.freeze({ class: 'golem_findings', path: path.join(brainRoot, 'pentest-reports', 'golem', 'findings'), identityOnly: false }),
  ]);
}

export function createWholeBrainPurge(deps = {}) {
  const targetPool = deps.targetPool;
  const maintenancePool = deps.maintenancePool;
  const completionMode = deps.completionMode || 'reinitialize';
  if (!['reinitialize', 'destroy'].includes(completionMode)) {
    throw new Error('invalid purge completion mode');
  }
  const keychainListFn = deps.keychainListFn
    || (completionMode === 'destroy' ? (() => []) : listCredentialKeychainItemsSync);
  const keychainDeleteFn = deps.keychainDeleteFn || keychainDeleteSync;
  const recreateFn = deps.recreateFn;
  const signReceiptFn = deps.signReceiptFn;
  const persistIntentFn = deps.persistIntentFn;
  const nowFn = deps.nowFn || (() => new Date());
  const uuidFn = deps.uuidFn || randomUUID;
  const filesystemScope = deps.filesystemScope || [];
  const allowCanonical = deps.allowCanonical === true;

  function validateTarget(databaseName, companyId) {
    if (!DATABASE_NAME_RE.test(databaseName)) throw new Error('invalid purge database');
    if (companyId !== 'hom') throw new Error('whole-brain purge company must be hom');
    if (databaseName === 'aimos' && !allowCanonical) throw new Error('canonical purge is not enabled in this execution context');
    if (databaseName === 'aimos' && completionMode !== 'reinitialize') {
      throw new Error('canonical purge must reinitialize the empty brain');
    }
    if (databaseName !== 'aimos' && !SCRATCH_DATABASE_RE.test(databaseName)) throw new Error('unsafe disposable purge target');
  }

  async function inventory({ databaseName, companyId = 'hom' }) {
    validateTarget(databaseName, companyId);
    if (!targetPool) throw new Error('target pool required');
    const client = await targetPool.connect();
    try {
      const active = await client.query(
        `SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname = $1`,
        [databaseName]
      );
      const dbClasses = await inventoryDatabase(client);
      const keychainItems = keychainListFn();
      const derivedPaths = filesystemScope.map((entry) => ({
        class: entry.class,
        ...walkOwnedPath(entry.path, { identityOnly: entry.identityOnly }),
      }));
      return {
        target: { database: databaseName, company: companyId },
        db_table_classes: dbClasses,
        credential_slots: {
          item_count: keychainItems.length,
          logical_count: keychainItems.filter((item) => !/\.[0-9a-f]{64}$/.test(item.service)).length,
          version_count: keychainItems.filter((item) => /\.[0-9a-f]{64}$/.test(item.service)).length,
        },
        derived_paths: derivedPaths,
        active_connections: Number(active.rows[0]?.count || 0),
      };
    } finally {
      client.release();
    }
  }

  async function execute({
    databaseName,
    companyId = 'hom',
    confirmation,
    actor,
    softwareRelease,
    extraKeychainItems = [],
  }) {
    validateTarget(databaseName, companyId);
    if (!targetPool || !maintenancePool || typeof signReceiptFn !== 'function') {
      throw new Error('purge execution dependencies incomplete');
    }
    if (typeof persistIntentFn !== 'function') {
      throw new Error('purge intent persistence dependency missing');
    }
    if (completionMode === 'reinitialize' && typeof recreateFn !== 'function') {
      throw new Error('purge reinitialization dependency missing');
    }
    const expectedConfirmation = `PURGE AIMOS ${companyId} ${databaseName}`;
    if (confirmation !== expectedConfirmation) throw new Error('purge confirmation mismatch');
    if (!/^[0-9a-f]{64}$/.test(String(actor?.fingerprint || ''))
      || Number.isNaN(new Date(actor?.epoch).getTime())) {
      throw new Error('verified master actor required');
    }

    const databasePresent = await maintenancePool.query(
      'SELECT 1 FROM pg_database WHERE datname = $1',
      [databaseName],
    );
    if (databasePresent.rowCount !== 1) throw new Error('purge_target_absent');

    const ceremonyId = uuidFn();
    const startedAt = nowFn().toISOString();
    const preflight = await inventory({ databaseName, companyId });
    if (preflight.derived_paths.some((entry) => entry.unexpected_count > 0)) {
      throw new Error('purge filesystem scope contains unexpected entries');
    }

    const retained = await targetPool.connect();
    let connectionsDisabled = false;
    let dropped = false;
    let retainedReleased = false;
    try {
      const pidResult = await retained.query('SELECT pg_backend_pid()::int AS pid');
      const retainedPid = Number(pidResult.rows[0]?.pid);
      await maintenancePool.query(`ALTER DATABASE ${quoteIdentifier(databaseName)} WITH ALLOW_CONNECTIONS false`);
      connectionsDisabled = true;
      await maintenancePool.query(
        `SELECT pg_terminate_backend(pid)
           FROM pg_stat_activity
          WHERE datname = $1 AND pid <> $2`,
        [databaseName, retainedPid]
      );
      const remaining = await maintenancePool.query(
        `SELECT count(*)::int AS count
           FROM pg_stat_activity
          WHERE datname = $1 AND pid <> $2`,
        [databaseName, retainedPid]
      );
      if (Number(remaining.rows[0]?.count || 0) !== 0) throw new Error('failed to freeze all database writers');

      const frozenCounts = await inventoryDatabase(retained);

      const intentBody = {
        schema: 'aimos-whole-brain-purge-intent/v1',
        ceremony_id: ceremonyId,
        target: { brain: 'HOM-AIMOS', company: companyId, database: databaseName },
        software_release: softwareRelease,
        actor: { fingerprint: actor.fingerprint, epoch: actor.epoch },
        authorized_at: startedAt,
        affected_table_classes: frozenCounts,
        planned_postcondition: completionMode === 'reinitialize' ? 'reinitialized_empty' : 'destroyed',
      };
      const signedIntent = await signReceiptFn(intentBody);
      if (!signedIntent?.signature || !signedIntent?.publicKey || !signedIntent?.nonce
        || !Number.isInteger(signedIntent?.signedTs)) {
        throw new Error('purge intent signature missing');
      }
      const intent = {
        body: intentBody,
        canonical_body: canonicalJson(intentBody),
        signature: signedIntent.signature,
        public_key: signedIntent.publicKey,
        nonce: signedIntent.nonce,
        ts_signed: signedIntent.signedTs,
      };
      const intentVerification = verifyWholeBrainPurgeIntent(intent);
      if (!intentVerification.valid) {
        throw new Error(`purge intent verification failed:${intentVerification.reason}`);
      }
      const intentSha256 = hashRetainedPurgeArtifact(intent);
      const persistedIntent = await persistIntentFn(intent);
      if (persistedIntent?.durable !== true || persistedIntent?.artifact_sha256 !== intentSha256) {
        throw new Error('purge intent durable persistence failed');
      }

      retained.release(true);
      retainedReleased = true;
      await targetPool.end();
      const connectionCloseDeadline = Date.now() + 10_000;
      while (true) {
        const targetConnections = await maintenancePool.query(
          `SELECT count(*)::int AS count
             FROM pg_stat_activity
            WHERE datname = $1`,
          [databaseName],
        );
        if (Number(targetConnections.rows[0]?.count || 0) === 0) break;
        if (Date.now() >= connectionCloseDeadline) {
          throw new Error('purge target pool did not close before drop');
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      await maintenancePool.query(`DROP DATABASE ${quoteIdentifier(databaseName)}`);
      dropped = true;

      const keychainItems = [
        ...keychainListFn(),
        ...extraKeychainItems,
      ];
      const uniqueItems = new Map(keychainItems.map((item) => [`${item.service}\0${item.account}`, item]));
      let deletedKeychainItems = 0;
      for (const item of uniqueItems.values()) {
        if (keychainDeleteFn(item.service, item.account || CREDENTIAL_KEYCHAIN_ACCOUNT)) deletedKeychainItems++;
      }

      let deletedFiles = 0;
      for (const entry of filesystemScope) {
        deletedFiles += removeOwnedPath(entry.path, { identityOnly: entry.identityOnly });
      }

      let postcondition;
      if (completionMode === 'reinitialize') {
        const recreated = await recreateFn({ databaseName });
        if (!recreated?.pool) throw new Error('recreated database pool missing');
        const emptyState = await verifyEmptyBrain(recreated.pool, recreated.migrationCount);
        await recreated.pool.end();
        if (!emptyState.ok) throw new Error(`empty state verification failed: ${emptyState.reason}`);
        postcondition = {
          mode: 'reinitialized_empty',
          database_present: true,
          empty_verified: true,
          migration_count: emptyState.migration_count,
        };
      } else {
        const absent = await maintenancePool.query(
          'SELECT 1 FROM pg_database WHERE datname = $1',
          [databaseName],
        );
        if (absent.rowCount !== 0) throw new Error('destroyed database still exists');
        postcondition = {
          mode: 'destroyed',
          database_present: false,
          empty_verified: null,
          migration_count: null,
        };
      }

      const completedAt = nowFn().toISOString();
      const receiptBody = {
        schema: 'aimos-whole-brain-purge-receipt/v1',
        ceremony_id: ceremonyId,
        target: { brain: 'HOM-AIMOS', company: companyId, database: databaseName },
        software_release: softwareRelease,
        actor: { fingerprint: actor.fingerprint, epoch: actor.epoch },
        started_at: startedAt,
        completed_at: completedAt,
        affected_table_classes: frozenCounts,
        credential_items_deleted: deletedKeychainItems,
        derived_files_deleted: deletedFiles,
        postcondition,
        migration_count: postcondition.migration_count,
        completion_status: 'complete',
        intent_sha256: intentSha256,
      };
      const signed = await signReceiptFn(receiptBody);
      if (!signed?.signature || !signed?.publicKey || !signed?.nonce || !Number.isInteger(signed?.signedTs)) {
        throw new Error('purge receipt signature missing');
      }
      const receipt = {
        body: receiptBody,
        canonical_body: canonicalJson(receiptBody),
        signature: signed.signature,
        public_key: signed.publicKey,
        nonce: signed.nonce,
        ts_signed: signed.signedTs,
      };
      const verification = verifyWholeBrainPurgeReceipt(receipt);
      if (!verification.valid) {
        throw new Error(`purge receipt verification failed:${verification.reason}`);
      }
      return receipt;
    } catch (error) {
      if (!dropped && connectionsDisabled) {
        await maintenancePool.query(`ALTER DATABASE ${quoteIdentifier(databaseName)} WITH ALLOW_CONNECTIONS true`).catch(() => {});
      }
      throw error;
    } finally {
      if (!retainedReleased) {
        try { retained.release(true); } catch { /* already released */ }
      }
    }
  }

  return { inventory, execute };
}

export function hashRetainedPurgeArtifact(artifact) {
  return createHash('sha256').update(canonicalJson(artifact), 'utf8').digest('hex');
}

export function writeDurableRetainedPurgeArtifact(filePath, artifact) {
  const parent = path.dirname(filePath);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  if (fs.existsSync(filePath)) {
    if (fs.lstatSync(filePath).isSymbolicLink()) throw new Error('refusing purge artifact symlink');
    throw new Error('refusing to overwrite retained purge artifact');
  }
  const descriptor = fs.openSync(filePath, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const directoryDescriptor = fs.openSync(parent, 'r');
  try {
    fs.fsyncSync(directoryDescriptor);
  } finally {
    fs.closeSync(directoryDescriptor);
  }
  return {
    durable: true,
    path: filePath,
    artifact_sha256: hashRetainedPurgeArtifact(artifact),
  };
}

export function verifyWholeBrainPurgeIntent(intent) {
  try {
    if (!intent?.body || intent.body.schema !== 'aimos-whole-brain-purge-intent/v1') {
      return { valid: false, reason: 'intent_schema_invalid' };
    }
    const canonicalBody = canonicalJson(intent.body);
    if (intent.canonical_body !== canonicalBody) {
      return { valid: false, reason: 'intent_canonical_body_mismatch' };
    }
    if (!intent.public_key || pubkeyFingerprint(intent.public_key) !== intent.body.actor?.fingerprint) {
      return { valid: false, reason: 'intent_actor_fingerprint_mismatch' };
    }
    if (!intent.nonce || !Number.isInteger(intent.ts_signed) || !intent.signature) {
      return { valid: false, reason: 'intent_signature_material_missing' };
    }
    const verified = verifyStoredPayloadSig(
      intent.public_key,
      intent.body,
      intent.nonce,
      intent.ts_signed,
      intent.signature,
    );
    if (!verified.valid) return { valid: false, reason: `intent_signature_${verified.reason}` };
    return {
      valid: true,
      actor_fingerprint: intent.body.actor.fingerprint,
      database: intent.body.target?.database || null,
      planned_postcondition: intent.body.planned_postcondition || null,
      artifact_sha256: hashRetainedPurgeArtifact(intent),
    };
  } catch (error) {
    return { valid: false, reason: `intent_malformed:${error.message}` };
  }
}

export function verifyWholeBrainPurgeReceipt(receipt) {
  try {
    if (!receipt?.body || receipt.body.schema !== 'aimos-whole-brain-purge-receipt/v1') {
      return { valid: false, reason: 'receipt_schema_invalid' };
    }
    const canonicalBody = canonicalJson(receipt.body);
    if (receipt.canonical_body !== canonicalBody) {
      return { valid: false, reason: 'receipt_canonical_body_mismatch' };
    }
    if (!receipt.public_key || pubkeyFingerprint(receipt.public_key) !== receipt.body.actor?.fingerprint) {
      return { valid: false, reason: 'receipt_actor_fingerprint_mismatch' };
    }
    if (!receipt.nonce || !Number.isInteger(receipt.ts_signed) || !receipt.signature) {
      return { valid: false, reason: 'receipt_signature_material_missing' };
    }
    const verified = verifyStoredPayloadSig(
      receipt.public_key,
      receipt.body,
      receipt.nonce,
      receipt.ts_signed,
      receipt.signature,
    );
    if (!verified.valid) return { valid: false, reason: `receipt_signature_${verified.reason}` };
    return {
      valid: true,
      actor_fingerprint: receipt.body.actor.fingerprint,
      database: receipt.body.target?.database || null,
      postcondition: receipt.body.postcondition || null,
    };
  } catch (error) {
    return { valid: false, reason: `receipt_malformed:${error.message}` };
  }
}

export async function verifyEmptyBrain(pool, expectedMigrationCount = null) {
  const migrationResult = await pool.query('SELECT count(*)::int AS count FROM schema_migrations');
  const migrationCount = Number(migrationResult.rows[0]?.count || 0);
  if (Number.isInteger(expectedMigrationCount) && migrationCount !== expectedMigrationCount) {
    return { ok: false, reason: 'migration_count_mismatch', migration_count: migrationCount };
  }
  for (const table of SENSITIVE_TABLES) {
    const exists = await pool.query('SELECT to_regclass($1) AS relation', [`public.${table}`]);
    if (!exists.rows[0]?.relation) continue;
    const count = await pool.query(`SELECT count(*)::int AS count FROM "${table}"`);
    if (Number(count.rows[0]?.count || 0) !== 0) {
      return { ok: false, reason: `sensitive_table_not_empty:${table}`, migration_count: migrationCount };
    }
  }
  return { ok: true, migration_count: migrationCount };
}

export const WHOLE_BRAIN_PURGE_CONSTANTS = Object.freeze({
  SENSITIVE_TABLES,
  expectedConfirmation: (companyId, databaseName) => `PURGE AIMOS ${companyId} ${databaseName}`,
});
