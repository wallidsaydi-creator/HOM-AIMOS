#!/usr/bin/env node
/**
 * Migration runner for Aimos database schema.
 * Runs numbered SQL migration files in a deterministic total order.
 *
 * Guarantees (R2):
 *   - Each migration's DDL and its schema_migrations record commit or fail
 *     together, on ONE checked-out pool client. Errors ROLLBACK and abort.
 *   - CREATE INDEX ... CONCURRENTLY (which cannot run in a transaction) is
 *     detected by a real regex on the statement, applied unwrapped, then
 *     recorded.
 *   - sha256 checksums are written at apply time and verified on every run.
 *     Legacy rows with NULL checksum are backfilled once (baseline), not
 *     treated as drift.
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
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = __dirname;

// CREATE INDEX [UNIQUE] CONCURRENTLY — must run OUTSIDE a transaction block.
// Match the statement form, not the mere appearance of the word (which shows
// up in comments and would false-positive under a substring scan).
const CONCURRENTLY_RE = /\bCREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\b/i;

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
async function applyMigration(pool, filename, sql) {
  const checksum = sha256(sql);

  if (CONCURRENTLY_RE.test(sql)) {
    // CONCURRENTLY cannot run inside a transaction block. Apply unwrapped,
    // one protocol statement at a time, then record. Sending CREATE INDEX and
    // COMMENT in one query creates an implicit transaction block and fails.
    // A crash between statements leaves the index built but unrecorded;
    // IF NOT EXISTS makes the retry idempotent.
    try {
      const statements = splitSqlStatements(sql);
      if (statements.length === 0) throw new Error('migration_sql_empty');
      for (const statement of statements) await pool.query(statement);
      await pool.query(
        'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
        [filename, checksum]
      );
    } catch (err) {
      throw new MigrationError(filename, err);
    }
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query(
      'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
      [filename, checksum]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw new MigrationError(filename, err);
  } finally {
    client.release();
  }
}

async function runMigrations(pool, options = {}) {
  const { check = false, verbose = true } = options;

  const files = getMigrationFiles(); // throws on unnumbered files

  if (files.length === 0) {
    if (verbose) console.log('[migrations] No migration files found.');
    return { applied: [], skipped: [], errors: [], backfilled: 0 };
  }

  // Tracking table.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id SERIAL PRIMARY KEY,
      filename TEXT NOT NULL UNIQUE,
      applied_at TIMESTAMPTZ DEFAULT NOW(),
      checksum TEXT
    )
  `);

  // Load already-applied rows and their recorded checksums.
  const appliedRows = await pool.query('SELECT filename, checksum FROM schema_migrations');
  const appliedChecksums = new Map();
  for (const row of appliedRows.rows) appliedChecksums.set(row.filename, row.checksum);

  // ── Drift verification (before applying anything) ──────────────────────────
  // NULL checksum == legacy, unverifiable: backfill once from disk to establish
  // the baseline, then continue. Only a NON-NULL mismatch is drift and aborts.
  let backfilled = 0;
  for (const [filename, recorded] of appliedChecksums) {
    if (!existsSync(join(MIGRATIONS_DIR, filename))) continue; // applied row for a file we no longer ship
    const onDisk = sha256OnDisk(filename);
    if (recorded == null) {
      await pool.query(
        'UPDATE schema_migrations SET checksum = $1 WHERE filename = $2',
        [onDisk, filename]
      );
      appliedChecksums.set(filename, onDisk);
      backfilled++;
      continue;
    }
    if (recorded !== onDisk) {
      throw new Error(
        `migration ${filename} was modified after it was applied\n` +
        `  recorded: ${recorded}\n` +
        `  on disk:  ${onDisk}\n` +
        `Migrations are immutable. Add a new migration instead.`
      );
    }
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

  for (const file of files) {
    if (appliedChecksums.has(file)) {
      skipped.push(file);
      continue;
    }

    if (check) {
      if (verbose) console.log(`[migrations] PENDING: ${file}`);
      continue;
    }

    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
    // applyMigration throws on any failure -> aborts the run (no swallowing).
    await applyMigration(pool, file, sql);
    applied.push(file);
    if (verbose) console.log(`[migrations] APPLIED: ${file}`);
  }

  return { applied, skipped, errors, backfilled };
}

// CLI runner
if (process.argv[1] && process.argv[1].includes('run.js')) {
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
  const pool = new pg.Pool({ connectionString: url });

  const check = process.argv.includes('--check');

  try {
    const result = await runMigrations(pool, { check });
    if (check) {
      console.log(`[migrations] ${result.applied.length} applied, ${result.skipped.length} already applied`);
    } else {
      console.log(`[migrations] Applied: ${result.applied.length}, Skipped: ${result.skipped.length}, Errors: ${result.errors.length}`);
    }
    process.exit(result.errors.length > 0 ? 1 : 0);
  } catch (err) {
    // Checksum drift, unnumbered files, or a failed migration all land here.
    console.error(`[migrations] ABORT: ${err.message}`);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

export { runMigrations, getMigrationFiles, splitSqlStatements };
