-- Migration 029 — Rename the legacy runtime role → agent_runtime (Phase 4 of agent-free rebuild)
--
-- Traditional analog: agent_runtime is the Windows SYSTEM / Linux daemon analog —
-- a privileged *service account* the brain server uses to run its write path,
-- NOT an identity. It has no keypair, no cert, no row in agent_identity.
-- It's a PG role with RLS isolation (permission boundary).
--
-- The legacy role name baked an operator-specific identifier into the role;
-- renaming to `agent_runtime` makes it agent-agnostic (any operator's deployment
-- uses the same role name).
--
-- Idempotent: safe to re-run. The DO block catches undefined_object when the
-- legacy role was never created (fresh fork install) — the migration no-ops.
--
-- RLS isolation policy on the role survives RENAME — Postgres rewrites the role
-- reference in the policy's `roles` array to the new role name automatically.
-- The `secure_aimos_save` SECURITY DEFINER function survives (bound to OID,
-- not name).
--
-- Rollback (if a legacy install was upgraded and the operator wants to revert):
--   ALTER ROLE agent_runtime RENAME TO <legacy-runtime-role-name>;

DO $$ BEGIN
  ALTER ROLE piro_runtime RENAME TO agent_runtime;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER ROLE agent_runtime WITH PASSWORD 'agent_secure_access';
