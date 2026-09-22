#!/usr/bin/env node
/**
 * Migration runner for Aimos database schema.
 * Runs numbered SQL migration files in a deterministic total order.
 *
 * Guarantees (R2):
 *   - Transactional DDL and its schema_migrations record commit or fail
 *     together, on ONE checked-out pool client under a run-wide advisory lock.
 *   - CREATE INDEX ... CONCURRENTLY (which cannot run in a transaction) is
 *     parsed against the supported native index grammar, applied unwrapped,
 *     and recorded only after catalog validity and exact definition checks.
 *   - sha256 checksums are written at apply time and verified on every run.
 *     Inspection never writes. Legacy NULLs remain explicitly unverified unless
 *     a mutating run requests --backfill-legacy-checksums.
 *   - Ordering is machine-independent: (leading integer, filename) lexicographic.
 *   - An unnumbered .sql file is a HARD ERROR, never a silent skip.
 *
 * Usage:
 *   node migrations/run.js                 # Run all pending migrations
 *   node migrations/run.js --check         # Report which migrations are pending
 *   node migrations/run.js --print-order   # Print the apply order and exit (no DB)
 *   node migrations/run.js --dry-run       # DB-free listing of the apply order
 *   NODE_ENV=production node migrations/run.js
 */

import { readFileSync, readdirSync, existsSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = __dirname;
const RETAINED_UNCERTAINTY_FILE = join(
  __dirname,
  '..',
  'baselines',
  'live-canonical',
  'migration-098-099-uncertainty.json',
);
const SECURITY_TRANSITION_FILE = join(
  __dirname,
  'compatibility',
  '029-runtime-role-password-removal.json',
);

class MigrationError extends Error {
  constructor(filename, cause) {
    const raw = cause && cause.message ? cause.message : String(cause);
    super(`migration ${filename} failed: ${raw}`);
    this.name = 'MigrationError';
    this.filename = filename;
    this.cause = cause;
  }
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function sha256OnDisk(filename) {
  return sha256(readFileSync(join(MIGRATIONS_DIR, filename), 'utf8'));
}

/**
 * Two pre-runner migrations have irrecoverable applied-byte uncertainty that
 * was independently closed in CR9 by verifying the live schema semantics.
 * This is an exact two-value exception, not a general checksum bypass: the DB
 * checksum, recovered source checksum, filename, schema, and disposition must
 * all match the retained baseline byte-for-byte.
 */
function retainedHistoricalChecksumUncertainty(filename, recorded, onDisk) {
  if (!existsSync(RETAINED_UNCERTAINTY_FILE)) return false;
  let baseline;
  try {
    baseline = JSON.parse(readFileSync(RETAINED_UNCERTAINTY_FILE, 'utf8'));
  } catch {
    throw new Error('retained migration uncertainty baseline is malformed');
  }
  if (baseline?.schema !== 'hom.aimos.cr9-migration-byte-uncertainty/v1'
      || !Array.isArray(baseline.records) || baseline.records.length !== 2) {
    throw new Error('retained migration uncertainty baseline has invalid scope');
  }
  const record = baseline.records.find((entry) => entry.filename === filename);
  return Boolean(record
    && record.recorded_checksum === recorded
    && record.recovered_file_sha256 === onDisk
    && record.checksum_equal === false
    && record.disposition === 'HISTORICAL_APPLIED_BYTE_UNCERTAINTY_LIVE_SEMANTICS_VERIFIED');
}

/**
 * Version 1.0.4 shipped migration 029 with a public bootstrap password that
 * Genesis immediately replaced from Keychain before starting the runtime.
 * The current source removes that statement. Existing installations retain
 * the checksum of the bytes they actually applied; this exact transition lets
 * them advance without pretending that different bytes were applied. Every
 * other filename or hash pair remains ordinary migration drift and fails.
 */
function acceptedMigrationSecurityTransition(filename, recorded, onDisk) {
  let transition;
  try {
    transition = JSON.parse(readFileSync(SECURITY_TRANSITION_FILE, 'utf8'));
  } catch {
    throw new Error('migration security transition contract is malformed');
  }
  if (transition?.schema !== 'hom.aimos.migration-source-security-transition/v1'
      || transition.filename !== '029-rename-runtime-role.sql'
      || !/^[0-9a-f]{64}$/.test(transition.predecessor_sha256 || '')
      || !/^[0-9a-f]{64}$/.test(transition.successor_sha256 || '')
      || transition.predecessor_sha256 === transition.successor_sha256
      || transition.disposition !== 'PUBLIC_BOOTSTRAP_PASSWORD_REMOVED_KEYCHAIN_CREDENTIAL_RETAINED'
      || transition.recorded_checksum_rewritten !== false) {
    throw new Error('migration security transition contract has invalid scope');
  }
  return filename === transition.filename
    && recorded === transition.predecessor_sha256
    && onDisk === transition.successor_sha256;
}

function leadingInt(filename) {
  const m = filename.match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : NaN;
}

/**
 * Split a PostgreSQL migration into top-level statements without treating
 * semicolons inside strings, quoted identifiers, comments, or dollar-quoted
 * bodies as boundaries. Concurrent DDL must be sent as one protocol statement;
 * a multi-statement query is an implicit transaction block in PostgreSQL.
 */
function splitSqlStatements(sql) {
  const source = String(sql || '');
  const statements = [];
  let current = '';
  let mode = 'default';
  let dollarTag = null;
  let blockDepth = 0;

  const push = () => {
    const statement = current.trim();
    if (statement) statements.push(statement);
    current = '';
  };

  for (let index = 0; index < source.length; index++) {
    const char = source[index];
    const next = source[index + 1] || '';
    current += char;

    if (mode === 'line_comment') {
      if (char === '\n') mode = 'default';
      continue;
    }
    if (mode === 'block_comment') {
      if (char === '/' && next === '*') {
        current += next;
        index++;
        blockDepth++;
      } else if (char === '*' && next === '/') {
        current += next;
        index++;
        blockDepth--;
        if (blockDepth === 0) mode = 'default';
      }
      continue;
    }
    if (mode === 'single_quote') {
      if (char === '\\' && next) {
        current += next;
        index++;
      } else if (char === "'" && next === "'") {
        current += next;
        index++;
      } else if (char === "'") {
        mode = 'default';
      }
      continue;
    }
    if (mode === 'double_quote') {
      if (char === '"' && next === '"') {
        current += next;
        index++;
      } else if (char === '"') {
        mode = 'default';
      }
      continue;
    }
    if (mode === 'dollar_quote') {
      if (source.startsWith(dollarTag, index)) {
        current += dollarTag.slice(1);
        index += dollarTag.length - 1;
        mode = 'default';
        dollarTag = null;
      }
      continue;
    }

    if (char === '-' && next === '-') {
      current += next;
      index++;
      mode = 'line_comment';
    } else if (char === '/' && next === '*') {
      current += next;
      index++;
      mode = 'block_comment';
      blockDepth = 1;
    } else if (char === "'") {
      mode = 'single_quote';
    } else if (char === '"') {
      mode = 'double_quote';
    } else if (char === '$') {
      const match = source.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/);
      if (match) {
        dollarTag = match[0];
        current += dollarTag.slice(1);
        index += dollarTag.length - 1;
        mode = 'dollar_quote';
      }
    } else if (char === ';') {
      push();
    }
  }

  if (mode === 'single_quote' || mode === 'double_quote' || mode === 'dollar_quote' || mode === 'block_comment') {
    throw new Error(`migration_sql_unterminated_${mode}`);
  }
  push();
  return statements;
}

/**
 * Enumerate migration files in the canonical apply order.
 * HARD ERROR on any .sql file that does not begin with a number — silence is
 * exactly what let two orphaned migrations never run.
 * Total order: sort by (leading integer, then filename lexicographically) so
 * duplicate numbers (007/008/009, 017/017b/017c) resolve deterministically on
 * every machine, independent of readdir/filesystem order.
 */
function getMigrationFiles() {
  const all = readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql'));

  const unnumbered = all.filter(f => !/^\d+/.test(f));
  if (unnumbered.length > 0) {
    throw new Error(
      `Unnumbered migration file(s) would never run: ${unnumbered.sort().join(', ')}. ` +
      `Rename each to start with a number, or remove it. Refusing to run.`
    );
  }

  return all.sort((a, b) => {
    const na = leadingInt(a);
    const nb = leadingInt(b);
    if (na !== nb) return na - nb;
    // Deterministic byte-order tiebreak (ASCII filenames).
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

/**
 * Apply one migration on a single checked-out client, transactionally.
 * DDL and the schema_migrations INSERT commit or roll back together.
 * On any error: ROLLBACK and throw (aborts the whole run).
 */
async function applyMigration(client, filename, sql) {
  const checksum = sha256(sql);
  let statements = splitSqlStatements(sql);
  const contracts = statements.filter(isConcurrentIndexStatement).map(parseMigrationIndexContract);
  const controls = statements.map((statement, index) => ({ index, sql: leadingSql(statement) }))
    .filter(entry => /^(?:BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|END|ABORT|PREPARE\s+TRANSACTION)\b/i.test(entry.sql));
  if (controls.length) {
    // Four retained files contain their own outer BEGIN/COMMIT. The runner
    // owns that boundary so the applied-row insertion stays in the same tx.
    if (contracts.length || controls.length !== 2 || controls[0].index !== 0
        || controls[1].index !== statements.length - 1
        || !/^BEGIN\s*;?$/i.test(controls[0].sql)
        || !/^COMMIT\s*;?$/i.test(controls[1].sql)) {
      throw new MigrationError(filename, new Error('migration_transaction_control_unsupported'));
    }
    statements = statements.slice(1, -1);
  }

  if (contracts.length > 0) {
    // CONCURRENTLY cannot run inside a transaction block. Apply unwrapped,
    // one protocol statement at a time, then record. Sending CREATE INDEX and
    // COMMENT in one query creates an implicit transaction block and fails.
    // A crash between statements leaves the index built but unrecorded;
    // Existing indexes must match the intended definition and be valid before
    // a retry is allowed to record this migration as applied.
    try {
      if (statements.length === 0) throw new Error('migration_sql_empty');
      for (const contract of contracts) await verifyMigrationIndex(client, contract, { allowMissing: true });
      for (const statement of statements) {
        await client.query(statement);
        if (isConcurrentIndexStatement(statement)) await verifyMigrationIndex(client, parseMigrationIndexContract(statement));
      }
      // Later statements must not invalidate the object checked at CREATE.
      for (const contract of contracts) await verifyMigrationIndex(client, contract);
      await client.query(
        'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
        [filename, checksum]
      );
    } catch (err) {
      throw new MigrationError(filename, err);
    }
    return;
  }

  try {
    await client.query('BEGIN');
    await client.query(statements.join('\n'));
    await client.query(
      'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
      [filename, checksum]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw new MigrationError(filename, err);
  }
}

async function runMigrationsOnClient(pool, options = {}) {
  const { check = false, verbose = true } = options;

  const files = getMigrationFiles(); // throws on unnumbered files

  if (files.length === 0) {
    if (verbose) console.log('[migrations] No migration files found.');
    return { applied: [], skipped: [], pending: [], errors: [], backfilled: 0,
      retainedUncertainties: 0, legacyUnverified: [], trackingTableExists: null };
  }

  // Inspection never initializes metadata, backfills hashes, or applies SQL.
  let trackingTableExists = Boolean((await pool.query(
    "SELECT to_regclass('public.schema_migrations') AS tracking_table",
  )).rows[0]?.tracking_table);
  if (!check && !trackingTableExists) {
    await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id SERIAL PRIMARY KEY,
      filename TEXT NOT NULL UNIQUE,
      applied_at TIMESTAMPTZ DEFAULT NOW(),
      checksum TEXT
    )
    `);
    trackingTableExists = true;
  }

  // Load already-applied rows and their recorded checksums.
  const appliedRows = trackingTableExists
    ? await pool.query('SELECT filename, checksum FROM schema_migrations') : { rows: [] };
  const appliedChecksums = new Map();
  for (const row of appliedRows.rows) appliedChecksums.set(row.filename, row.checksum);

  // ── Drift verification (before applying anything) ──────────────────────────
  // NULL checksums remain unverified unless backfill was explicitly requested.
  let backfilled = 0;
  let retainedUncertainties = 0;
  let acceptedSecurityTransitions = 0;
  const legacyUnverified = [];
  const legacyBackfills = [];
  for (const [filename, recorded] of appliedChecksums) {
    if (!existsSync(join(MIGRATIONS_DIR, filename))) continue; // applied row for a file we no longer ship
    const onDisk = sha256OnDisk(filename);
    if (recorded == null) {
      if (check || options.backfillLegacyChecksums !== true) {
        legacyUnverified.push(filename);
        continue;
      }
      legacyBackfills.push([onDisk, filename]);
      continue;
    }
    if (recorded !== onDisk) {
      if (acceptedMigrationSecurityTransition(filename, recorded, onDisk)) {
        acceptedSecurityTransitions++;
        if (verbose) {
          console.warn(
            `[migrations] ACCEPTED SECURITY SOURCE TRANSITION: ${filename}; ` +
            'the applied predecessor checksum remains retained and the public bootstrap password is absent from current source.'
          );
        }
        continue;
      }
      if (retainedHistoricalChecksumUncertainty(filename, recorded, onDisk)) {
        retainedUncertainties++;
        if (verbose) {
          console.warn(
            `[migrations] RETAINED APPLIED-BYTE UNCERTAINTY: ${filename}; ` +
            'CR9 live semantics verified and the exact dual checksum remains unchanged.'
          );
        }
        continue;
      }
      throw new Error(
        `migration ${filename} was modified after it was applied\n` +
        `  recorded: ${recorded}\n` +
        `  on disk:  ${onDisk}\n` +
        `Migrations are immutable. Add a new migration instead.`
      );
    }
  }
  // An applied-row marker is not proof that its derived index still exists
  // or remains valid. Preflight every recorded concurrent contract before
  // backfill or new application, in both inspection and execution modes.
  for (const file of files.filter(file => appliedChecksums.has(file))) {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
    for (const statement of splitSqlStatements(sql).filter(isConcurrentIndexStatement)) {
      await verifyMigrationIndex(pool, parseMigrationIndexContract(statement));
    }
  }
  for (const [onDisk, filename] of legacyBackfills) {
    await pool.query('UPDATE schema_migrations SET checksum = $1 WHERE filename = $2', [onDisk, filename]);
    appliedChecksums.set(filename, onDisk);
    backfilled++;
  }
  if (backfilled > 0 && verbose) {
    console.log(
      `[migrations] Backfilled ${backfilled} legacy checksum(s) with no prior record. ` +
      `Drift detection is authoritative from this run forward (not retroactive).`
    );
  }

  const applied = [];
  const skipped = [];
  const errors = [];
  const pending = [];

  for (const file of files) {
    if (appliedChecksums.has(file)) {
      skipped.push(file);
      continue;
    }

    if (check) {
      pending.push(file);
      if (verbose) console.log(`[migrations] PENDING: ${file}`);
      continue;
    }

    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
    // applyMigration throws on any failure -> aborts the run (no swallowing).
    await applyMigration(pool, file, sql);
    applied.push(file);
    if (verbose) console.log(`[migrations] APPLIED: ${file}`);
  }

  // The existing schema initialization path consumes the same native writer
  // definitions as the canonical runtime. Historical numbered SQL/checksums
  // are untouched; do not make a second installer or copy a live database.
  if (!check) {
    const client = pool;
    try {
      await client.query('BEGIN');
      await client.query(readFileSync(join(__dirname, '..', 'db', 'request-target.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'signed-request-bytes.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'atomic-save-origin.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'signed-json-bytes.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'signed-event-bytes.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'cognitive-ancestry.sql'), 'utf8'));
      await client.query(readFileSync(join(__dirname, '..', 'db', 'memory-credit.sql'), 'utf8'));
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  }

  return { applied, skipped, pending, errors, backfilled, retainedUncertainties,
    acceptedSecurityTransitions, legacyUnverified, trackingTableExists };
}

async function runMigrations(pool, options = {}) {
  if (options.check === true) return runMigrationsOnClient(pool, options);
  const client = await pool.connect();
  let locked = false;
  let releaseError;
  try {
    const result = await client.query("SELECT pg_try_advisory_lock(hashtextextended('hom.aimos.migrations',0)) AS locked");
    locked = result.rows[0]?.locked === true;
    if (!locked) throw new Error('migration_runner_already_active');
    return await runMigrationsOnClient(client, options);
  } finally {
    if (locked) {
      try { await client.query("SELECT pg_advisory_unlock(hashtextextended('hom.aimos.migrations',0))"); }
      catch (error) { releaseError = error; }
    }
    client.release(releaseError);
  }
}

function leadingSql(statement) {
  return String(statement).replace(/^(?:\s|--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)+/, '').trim();
}

function isConcurrentIndexStatement(statement) {
  return /^CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b/i.test(leadingSql(statement));
}

function indexName(value) {
  if (!/^(?:[a-z_][a-z0-9_]*|"[a-z_][a-z0-9_]*")(?:\.(?:[a-z_][a-z0-9_]*|"[a-z_][a-z0-9_]*"))?$/.test(String(value))) {
    throw new Error('migration_index_identifier_unsupported');
  }
  const name = String(value).replaceAll('"', '');
  if (!/^(?:[a-z_][a-z0-9_]*\.)?[a-z_][a-z0-9_]*$/.test(name)) {
    throw new Error('migration_index_identifier_unsupported');
  }
  const parts = name.split('.');
  return parts.length === 1 ? ['public', parts[0]] : parts;
}

// This is the explicitly supported grammar of the shipped concurrent indexes:
// named columns/opclasses, numeric storage options, and simple predicates.
// New syntax fails for review rather than receiving an approximate comparison.
function parseMigrationIndexContract(statement) {
  const text = leadingSql(statement).replace(/;\s*$/, '');
  const match = text.match(/^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([\w".]+)\s+ON\s+([\w".]+)\s*(?:USING\s+(\w+)\s*)?\(([^()]+)\)\s*(?:WITH\s*\(([^()]+)\)\s*)?(?:WHERE\s+([\s\S]+))?$/i);
  if (!match) throw new Error('migration_index_contract_unsupported');
  const relation = indexName(match[3]);
  const columns = match[5].split(',').map((key) => {
    if (key.includes('""')) throw new Error('migration_index_identifier_unsupported');
    const unquoted = key.replace(/"([^"]*)"/g, (_token, identifier) => {
      if (!/^[a-z_][a-z0-9_]*$/.test(identifier)) throw new Error('migration_index_identifier_unsupported');
      return identifier;
    });
    if (unquoted.includes('"')) throw new Error('migration_index_identifier_unsupported');
    const normalized = unquoted.trim().replace(/\bpublic\./g, '').replace(/\s+/g, ' ');
    if (!/^[a-z_][a-z0-9_]*(?: [a-z_][a-z0-9_]*)?(?: (?:ASC|DESC))?(?: NULLS (?:FIRST|LAST))?$/i.test(normalized)) {
      throw new Error('migration_index_expression_unsupported');
    }
    return normalized;
  });
  const options = (match[6] || '').split(',').filter(Boolean).map((entry) => {
    const option = entry.trim().match(/^([a-z_][a-z0-9_]*)\s*=\s*'?(\d+)'?$/i);
    if (!option) throw new Error('migration_index_options_unsupported');
    return `${option[1]}=${Number(option[2])}`;
  }).sort();
  let predicate = (match[7] || '').trim();
  if (predicate.startsWith('(') && predicate.endsWith(')')) predicate = predicate.slice(1, -1).trim();
  if (predicate && !/^[a-z_][a-z0-9_]*\s*(?:=\s*\d+|IS\s+(?:NOT\s+)?NULL)$/i.test(predicate)) {
    throw new Error('migration_index_predicate_unsupported');
  }
  predicate = predicate.toLowerCase().replace(/\s+/g, ' ').replace(/\s*=\s*/g, '=');
  return { name: indexName(match[2]), relation, unique: Boolean(match[1]),
    method: String(match[4] || 'btree').toLowerCase(), columns, options, predicate };
}

async function verifyMigrationIndex(client, contract, { allowMissing = false } = {}) {
  const result = await client.query(`
    SELECT pg_get_indexdef(i.indexrelid) AS definition,
           i.indisvalid,i.indisready,i.indislive,i.indnullsnotdistinct,
           i.indnkeyatts=i.indnatts AS no_included_columns,
           i.indexprs IS NULL AS no_expression
      FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
      JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname=$1 AND c.relname=$2`, contract.name);
  if (result.rows.length === 0 && allowMissing) return false;
  const row = result.rows[0];
  if (result.rows.length !== 1 || !row.indisvalid || !row.indisready || !row.indislive
      || row.indnullsnotdistinct || !row.no_included_columns || !row.no_expression) {
    throw new Error(`migration_index_not_valid:${contract.name.join('.')}`);
  }
  const actual = parseMigrationIndexContract(row.definition);
  if (JSON.stringify(actual) !== JSON.stringify(contract)) {
    throw new Error(`migration_index_definition_mismatch:${contract.name.join('.')}`);
  }
  return true;
}

// CLI runner
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const printOrder = process.argv.includes('--print-order');
  const dryRun = process.argv.includes('--dry-run');

  // --print-order (and bare --dry-run) is a pure, DB-free listing of the apply
  // order. It still enforces the unnumbered-file hard error.
  // The whole order is printed on a SINGLE line so that comparing runs is a
  // trivial `sort -u | wc -l == 1`; the order is identical across machines.
  if (printOrder || (dryRun && !process.argv.includes('--check'))) {
    try {
      console.log(getMigrationFiles().join(','));
      process.exit(0);
    } catch (err) {
      console.error(`[migrations] ERROR: ${err.message}`);
      process.exit(1);
    }
  }

  const { resolveAimosDatabaseUrl } = await import('../services/core/runtime-config.js');
  const url = resolveAimosDatabaseUrl();

  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 5000 });

  const check = process.argv.includes('--check');

  try {
    const result = await runMigrations(pool, { check,
      backfillLegacyChecksums: process.argv.includes('--backfill-legacy-checksums') });
    if (check) {
      console.log(`[migrations] ${result.pending.length} pending, ${result.skipped.length} already applied; ${result.legacyUnverified.length} legacy checksum(s) unverified`);
    } else {
      console.log(`[migrations] Applied: ${result.applied.length}, Skipped: ${result.skipped.length}, Errors: ${result.errors.length}`);
    }
    process.exitCode = result.errors.length > 0 ? 1 : 0;
  } catch (err) {
    // Checksum drift, unnumbered files, or a failed migration all land here.
    console.error(`[migrations] ABORT: ${err.message}`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

export {
  runMigrations,
  getMigrationFiles,
  splitSqlStatements,
  retainedHistoricalChecksumUncertainty,
  acceptedMigrationSecurityTransition,
  parseMigrationIndexContract,
  verifyMigrationIndex,
  applyMigration,
};
