/**
 * backend/middleware/client-context.js
 *
 * Client Context Middleware — enforces RLS by setting Postgres session variable.
 * Every DB connection that runs under this middleware will automatically have
 * app.current_client_id set, which the RLS policies read via current_setting().
 *
 * Extraction priority: header > query > body > default 'hom'
 * Sanitization: only alphanumeric, underscore, hyphen allowed (no SQL injection).
 */

/**
 * Extract client ID from an Express-style request object.
 * Priority: x-client-id header > client_id query param > company_id/client_id body > 'hom'
 *
 * @param {Object} req - Express request (or plain object with headers/query/body)
 * @returns {string} sanitized client ID, never empty
 */
export function extractClientId(req) {
  const raw =
    req.headers?.['x-client-id'] ||
    req.query?.client_id ||
    req.body?.company_id ||
    req.body?.client_id ||
    'hom';

  // Sanitize: allow only alphanumeric and underscore — strip everything else
  // (hyphens are excluded to prevent SQL comment injection via '--'),
  // then lowercase to normalise client IDs.
  const sanitized = String(raw).replace(/[^a-zA-Z0-9_]/g, '').toLowerCase().slice(0, 64);

  // If sanitization wiped everything out, fall back to 'hom'
  return sanitized || 'hom';
}

/**
 * Set Postgres session variable for RLS enforcement.
 * Must be called once per request, on the connection that will run subsequent queries.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} client - pg pool or client
 * @param {string} clientId - already-sanitized client identifier
 * @returns {Promise<void>}
 */
export async function setClientContext(client, clientId) {
  // Re-sanitize defensively in case caller skips extractClientId
  const sanitized = String(clientId).replace(/[^a-zA-Z0-9_]/g, '').toLowerCase().slice(0, 64) || 'hom';
  // Use set_config() instead of SET $1 — Postgres does not allow parameter binding
  // in SET statements (not valid SQL syntax). set_config() is the correct API.
  // Third argument false = session-level (not local to current transaction).
  await client.query(`SELECT set_config('app.current_client_id', $1, false)`, [sanitized]);
}

/**
 * Express middleware factory: attaches clientId to req and sets the Postgres
 * session variable before handing off to route handlers.
 *
 * Usage:
 *   import { pool } from '../db/connection.js';
 *   import { clientContextMiddleware } from '../middleware/client-context.js';
 *   app.use(clientContextMiddleware(() => pool));
 *
 * @param {Function|import('pg').Pool} getPool - pool instance or factory fn
 * @returns {Function} Express middleware (req, res, next)
 */
export function clientContextMiddleware(getPool) {
  return async (req, res, next) => {
    req.clientId = extractClientId(req);
    try {
      const pool = typeof getPool === 'function' ? getPool() : getPool;
      if (pool) await setClientContext(pool, req.clientId);
      next();
    } catch (err) {
      console.error('[client-context] Failed to set client context:', err.message);
      next(err);
    }
  };
}
