-- The token/TTL install-confirmation state machine was a second authorization
-- system beside the certificate envelope and signed capability ledgers. Retain
-- historical rows for audit, but remove all runtime mutation authority.

REVOKE ALL ON public.install_confirmations FROM PUBLIC;

DO $retire_install_authority$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.install_confirmations FROM agent_runtime;
    GRANT SELECT ON public.install_confirmations TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.install_confirmations FROM aimos_app;
  END IF;
END
$retire_install_authority$;

COMMENT ON TABLE public.install_confirmations IS
  'RETIRED retained historical token state. Never authorization authority. Canonical saves use the verified certificate envelope, signed request receipt, and signed capability/clearance ledgers.';
