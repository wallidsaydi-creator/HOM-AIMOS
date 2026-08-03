/**
 * connection.js — Database access layer
 *
 * SERVICE CONNECTION GUIDE:
 * 1. ↔ Interacts with: aimos.js (Provides the 'secureQuery' interface for high-integrity saves)
 * 2. ↔ Interacts with: scheduler.js (Maintains connection pools for long-running cron jobs)
 * 3. → Pushes to: security.security_audit_log (Sets session-scoped 'app.current_knowledge_proof')
 * 4. → Benefits from: DR_URL (Automatic failover to read-only replica)
 *
 * ─── POOL DECISION (R3, locked) ─────────────────────────────────────────────
 * There are two pools, and the choice between them is NOT interchangeable:
 *
 *   `agentPool`  — connects as the restricted `agent_runtime` role. RLS and
 *                  privilege enforcement (including the R3 REVOKE DELETE in
 *                  migration 041) ONLY bind non-superusers, so this is the pool
 *                  that any security guarantee actually lives on. Use it for the
 *                  guarded proof-of-context path (`secureQuery`).
 *   `pool`       — connects as the DB superuser. RESERVED for migrations,
 *                  boot-time store loads, and superuser maintenance. A superuser
 *                  BYPASSES RLS and every REVOKE, so nothing routed through `pool`
 *                  is protected by those controls.
 *
 * Migration 045 removes the public SECURITY DEFINER memory writer and grants
 * `agent_runtime` the exact SELECT/INSERT statements used by the native
 * memory/provenance/envelope transaction. Canonical saves therefore use
 * `agentPool` with `app.current_client_id` set before any RLS-protected DML.
 * The superuser pool remains reserved for migrations, boot stores, diagnostics,
 * and maintenance; it is not the canonical memory mutation path.
 *
 * LOGIC GUIDE (Step-Up Connections): `secureQuery` runs on `agentPool` inside a
 * real transaction (BEGIN…COMMIT) so that `set_config('app.current_agent_id',…,
 * true)` is genuinely in force for the guarded statement. Aladdin Law (no-delete)
 * is enforced at the DB protocol level by migration 041 (REVOKE DELETE FROM
 * agent_runtime), NOT by the `vandalismCheck` string scan below.
 */
import pg from 'pg';
import {
  AIMOS_RUNTIME_CREDENTIAL_SERVICE,
  AIMOS_RUNTIME_ROLE,
  resolveAimosDatabaseUrl
} from '../services/core/runtime-config.js';
import { readCredentialSync } from '../services/security/credential-store.js';

const { Pool } = pg;

// ─── DR FAILOVER: automatic switch to replica when primary is unreachable ─────
// Aimos local DB access does not use PostgreSQL SSL. Agent trust is enforced by
// the cryptographic envelope/hash-chain ledger above this connection layer.
const PRIMARY_URL = resolveAimosDatabaseUrl();
// DR activation is a signed system-configuration operation. Until that lane is
// provisioned, there is intentionally no ambient override or silent failover.
const DR_URL = '';
let _activeUrl = PRIMARY_URL;
let _failoverActive = false;
let _consecutiveErrors = 0;
const FAILOVER_THRESHOLD = 3; // switch after 3 consecutive connection failures
const RECOVERY_CHECK_MS = 60_000; // try primary again every 60s during failover
let _recoveryTimer = null;

function createPool(url, label = 'database') {
  const p = new Pool({
    connectionString: url,
    ssl: false
  });
  p.on('connect', () => {
    console.error(`✅ Connected to ${label}` + (_failoverActive ? ' (DR REPLICA)' : '') + ' (no-ssl)');
  });
  p.on('error', (err) => {
    console.error(`[DB:${label}] Pool error:`, err.message);
  });
  return p;
}

export let pool = createPool(PRIMARY_URL, 'primary');

// ─── RESTRICTED RUNTIME POOL (Fortress Phase 1) ─────────────────────────────
// Constructed from PRIMARY_URL by swapping user/pass for agent_runtime.
function getRestrictedUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);
    const credential = readCredentialSync(AIMOS_RUNTIME_CREDENTIAL_SERVICE);
    if (!credential) {
      throw new Error(`missing keychain credential: ${AIMOS_RUNTIME_CREDENTIAL_SERVICE}`);
    }
    url.username = AIMOS_RUNTIME_ROLE;
    url.password = credential.value;
    return url.toString();
  } catch (err) {
    throw new Error(`Cannot construct restricted AIMOS database connection: ${err.message}`);
  }
}

function createLazyRestrictedPool() {
  let restrictedPool = null;
  function get() {
    if (!restrictedPool) {
      restrictedPool = createPool(getRestrictedUrl(PRIMARY_URL), 'agent_runtime');
    }
    return restrictedPool;
  }
  return Object.freeze({
    connect: (...args) => get().connect(...args),
    query: (...args) => get().query(...args),
    end: (...args) => restrictedPool ? restrictedPool.end(...args) : Promise.resolve()
  });
}

// Defer keychain resolution until the restricted lane is actually used. This
// keeps pure crypto tests and the pre-database installer importable, while the
// first restricted query still fails closed if genesis has not created the
// credential.
export const agentPool = createLazyRestrictedPool();

async function switchToFailover() {
  if (!DR_URL || _failoverActive) return;
  console.warn('[DB] ⚠️ FAILOVER: Switching to DR replica after', FAILOVER_THRESHOLD, 'consecutive failures');
  _failoverActive = true;
  _activeUrl = DR_URL;
  const oldPool = pool;
  pool = createPool(DR_URL);
  try { await oldPool.end(); } catch { /* best effort */ }

  // Periodically try to recover to primary
  if (!_recoveryTimer) {
    _recoveryTimer = setInterval(async () => {
      try {
        const testPool = createPool(PRIMARY_URL);
        await testPool.query('SELECT 1');
        await testPool.end();
        // Primary is back — switch back
        console.log('[DB] ✅ Primary recovered — switching back from DR');
        _failoverActive = false;
        _activeUrl = PRIMARY_URL;
        _consecutiveErrors = 0;
        const drPool = pool;
        pool = createPool(PRIMARY_URL);
        try { await drPool.end(); } catch { /* best effort */ }
        clearInterval(_recoveryTimer);
        _recoveryTimer = null;
      } catch {
        // Primary still down — stay on DR
      }
    }, RECOVERY_CHECK_MS);
  }
}

// ─── vandalismCheck — DEVELOPER CONVENIENCE ONLY, NOT A SECURITY CONTROL ──────
// This is a fast-fail sanity check that surfaces an obvious `DELETE FROM` /
// `is_active=false` in a query string with a clear error, EARLY, in development.
// It is NOT the enforcement of Aladdin Law and must never be described as such:
// it is a case-folded substring scan and is trivially bypassed by `DELETE\nFROM`,
// `delete  from`, `DELETE /*x*/ FROM`, or any dynamically assembled verb, and it
// false-positives on legitimate string literals that merely contain the words.
// The ACTUAL no-delete guarantee is enforced at the database protocol level by
// migration 041 (REVOKE DELETE ON ALL TABLES … FROM agent_runtime + ALTER
// DEFAULT PRIVILEGES … REVOKE DELETE), which binds the restricted role that the
// guarded write path connects as. Keep this check for its ergonomics; do not
// rely on it for integrity.
function vandalismCheck(text) {
  const sql = String(text).toUpperCase();
  if (sql.includes('DELETE FROM') || sql.includes('IS_ACTIVE = FALSE') || sql.includes('IS_ACTIVE=FALSE')) {
    throw new Error('[dev-convenience guard] Query looks like a DELETE / is_active=false and was rejected before reaching the DB. NOTE: this string scan is NOT the enforcement boundary — the real no-delete guarantee is REVOKE DELETE FROM agent_runtime (migration 041). This check is bypassable and exists only for fast local feedback.');
  }
}

export async function query(text, params) {
  vandalismCheck(text);
  try {
    const result = await pool.query(text, params);
    _consecutiveErrors = 0;
    return result;
  } catch (err) {
    // Only failover on connection errors, not query errors
    if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.code === '57P01' || err.code === '08006' || err.message?.includes('Connection terminated')) {
      _consecutiveErrors++;
      if (_consecutiveErrors >= FAILOVER_THRESHOLD && DR_URL && !_failoverActive) {
        await switchToFailover();
        // Retry on DR
        return await pool.query(text, params);
      }
    }
    throw err;
  }
}

/**
 * withTransaction(fn, options) — run `fn(client)` inside a single DB transaction
 * with the session-context GUCs (app.current_client_id / app.current_agent_id /
 * app.current_knowledge_proof) genuinely in force for the WHOLE transaction.
 *
 * Why this exists: the previous `secureQuery` issued `SET LOCAL …` with no
 * enclosing `BEGIN`. `SET LOCAL` is transaction-scoped; in autocommit each
 * statement is its own transaction, so the setting expired before the guarded
 * query ran — the security context was NEVER in force. This helper opens the
 * transaction first, then sets the context, then runs the caller's work, so the
 * context is live for every statement the caller issues on `client`.
 *
 * Two correctness details that are load-bearing (see R3 §Step 1):
 *   1. Options are accepted in BOTH snake_case AND camelCase. Every existing
 *      `secureQuery` caller passes snake_case (`agent_id`, `knowledge_proof`).
 *      Reading only camelCase would silently set NO context — reproducing the
 *      exact bug this replaces while appearing to work. `??` prefers snake_case
 *      (the real contract) and falls back to camelCase.
 *   2. We use `SELECT set_config($1,$2,true)` rather than `SET LOCAL <name> = $1`.
 *      `SET LOCAL` cannot take a bind parameter; `set_config(key,value,true)` is
 *      its parameterizable, transaction-local equivalent. This is precisely the
 *      form the original code needed and lacked.
 *
 * Pool selection (see POOL DECISION at the top of this file):
 *   options.restricted === true  → agentPool (agent_runtime, RLS/REVOKE bind here)
 *   otherwise                    → pool (superuser; migrations / boot / maintenance)
 *
 * @param {(client: import('pg').PoolClient) => Promise<any>} fn
 * @param {Object} [options]
 * @param {boolean} [options.restricted=false]  route through agentPool
 * @param {string}  [options.client_id|clientId]        → app.current_client_id
 * @param {string}  [options.agent_id|agentId]          → app.current_agent_id
 * @param {string}  [options.knowledge_proof|knowledgeProof] → app.current_knowledge_proof
 */
export async function withTransaction(fn, options = {}) {
  // Accept snake_case (the existing secureQuery contract) AND camelCase.
  // Prefer snake_case; never silently ignore one style.
  const clientId       = options.client_id       ?? options.clientId;
  const agentId        = options.agent_id        ?? options.agentId;
  const knowledgeProof = options.knowledge_proof ?? options.knowledgeProof;

  const p = options.restricted ? agentPool : pool;
  const client = await p.connect();
  try {
    await client.query('BEGIN');
    // set_config(key, value, true) === SET LOCAL, but parameterizable and
    // therefore safe against injection. The third arg (is_local=true) scopes it
    // to this transaction.
    if (clientId)       await client.query('SELECT set_config($1,$2,true)', ['app.current_client_id', String(clientId)]);
    if (agentId)        await client.query('SELECT set_config($1,$2,true)', ['app.current_agent_id', String(agentId)]);
    if (knowledgeProof) await client.query('SELECT set_config($1,$2,true)', ['app.current_knowledge_proof', String(knowledgeProof)]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* best effort — connection may be dead */ }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Executes a query using the restricted agent_runtime pool, WITH the agent
 * proof-of-context genuinely in force for the guarded statement.
 *
 * Now built on withTransaction: the query runs inside a real transaction on
 * agentPool with app.current_agent_id / app.current_knowledge_proof set via
 * transaction-local set_config. Callers pass snake_case options (agent_id,
 * knowledge_proof) exactly as before — the signature and contract are unchanged.
 */
export async function secureQuery(text, params, options = {}) {
  vandalismCheck(text);
  return withTransaction(
    (client) => client.query(text, params),
    { restricted: true, ...options }
  );
}

export function getDbHealth() {
  return { activeUrl: _activeUrl?.replace(/:[^@]+@/, ':***@'), failoverActive: _failoverActive, consecutiveErrors: _consecutiveErrors };
}
