// ─── PIPELINE CONNECTIONS ────────────────────────────────────────────────────
// R1 Step 1/4 — single per-route authorization authority.
// Identity is taken ONLY from req.agentId (set by auth-gate.js from the
// verified cert). Body/query/header agent ids are NEVER trusted here.
// The catch path DENIES (503) — authorization must never fail open (H13).
// ← Called by: routes/tools.js, routes/setup.js, routes/permissions.js,
//              routes/mcp.js, routes/aimos-mcp-streamable.js
// → Calls: services/core/permissions.js (verified append-only authorization chain)
// ─────────────────────────────────────────────────────────────────────────────

import { getPermissions as defaultGetPermissions } from '../core/permissions.js';
import { logEvent } from '../observe/event-ledger.js';

/**
 * Express middleware factory. Requires that the cert-authenticated agent
 * (req.agentId) holds `capability` in the verified authorization event chain.
 *
 *   - No req.agentId              → 401 unauthenticated
 *   - capability not granted      → 403 forbidden (attributed to req.agentId)
 *   - permission lookup throws    → 503 authz_unavailable (FAIL CLOSED, H13)
 *
 * @param {string} capability  key in agent_permissions (e.g. 'email', 'admin_override')
 * @param {object} [deps]       native dependencies ({ getPermissions, logEvent })
 * @returns {import('express').RequestHandler}
 */
export function requireCapability(capability, deps = {}) {
  const getPermissions = typeof deps.getPermissions === 'function' ? deps.getPermissions : defaultGetPermissions;
  const logEventFn = typeof deps.logEvent === 'function' ? deps.logEvent : logEvent;
  return async function requireCapabilityMiddleware(req, res, next) {
    const agentId = req.agentId; // set by auth-gate from the verified cert. Never trust the body.
    if (!agentId) {
      return res.status(401).json({ error: { code: 'unauthenticated' } });
    }
    // H14: pass companyId explicitly so getPermissions does NOT fall back to
    // process.env.COMPANY_ID. Derive it from the request, defaulting to the
    // 'hom' literal (a constant, not an env var).
    const companyId = req.executionContext?.companyId || 'hom';
    const requestedCompany = req.body?.company_id || req.query?.company_id || companyId;
    if (String(requestedCompany) !== String(companyId)) {
      return res.status(403).json({ error: { code: 'company_scope_mismatch' } });
    }
    try {
      const perms = await getPermissions(agentId, companyId);
      if (!perms || perms[capability] !== true) {
        logEventFn(companyId, agentId, 'authz_denied', String(capability), {
          reasoning: `agent ${agentId} lacks capability ${capability}`,
          path: req.originalUrl,
          source_knowledge: 'require-capability.js — R1 per-route authz'
        }).catch(() => {});
        return res.status(403).json({ error: { code: 'forbidden', capability } });
      }
      return next();
    } catch (err) {
      // H13: authorization must never fail open. A DB error denies.
      console.error('[require-capability] capability check failed:', {
        agentId, capability, err: err?.message || String(err)
      });
      logEventFn(companyId, agentId, 'authz_unavailable', String(capability), {
        reasoning: `capability lookup threw — failing closed to 503`,
        error: err?.message || String(err),
        source_knowledge: 'require-capability.js — R1 H13 fail-closed'
      }).catch(() => {});
      return res.status(503).json({ error: { code: 'authz_unavailable' } });
    }
  };
}

export default requireCapability;
