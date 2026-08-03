-- Mutable identity columns are retained for historical schema compatibility,
-- but they cannot create or remove authority. Identity termination comes only
-- from a verified master-signed aimos_agent_revocation_events row. The sole
-- runtime UPDATE privilege on agent_identity remains the signed-envelope
-- chain_head projection granted by migration 045.

ALTER TABLE public.agent_identity
  ADD CONSTRAINT agent_identity_no_new_mutable_revocation
  CHECK (revoked_at IS NULL)
  NOT VALID;

DO $identity_projection_acl$
BEGIN
  REVOKE UPDATE (revoked_at, is_system_role) ON public.agent_identity FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE UPDATE (revoked_at, is_system_role) ON public.agent_identity FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE UPDATE (revoked_at, is_system_role) ON public.agent_identity FROM aimos_app;
  END IF;
END
$identity_projection_acl$;

COMMENT ON COLUMN public.agent_identity.revoked_at IS
  'Retained legacy metadata only. Never consulted for authorization; exact-epoch master-signed revocation events are authoritative.';

COMMENT ON COLUMN public.agent_identity.is_system_role IS
  'Retained compatibility projection only. System-self authority requires the verified housekeeper certificate envelope and cannot be conferred by this mutable column.';
