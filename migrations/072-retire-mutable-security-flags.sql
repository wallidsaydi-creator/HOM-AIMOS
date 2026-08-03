-- The system_envelopes flag store could bypass terminal revocation and replay
-- rejection through a mutable single-row projection. Cryptographic admission
-- has no operator bypass. Retain all historical flag rows, remove mutation
-- authority, and leave typed signed configuration to aimos_system_config.

REVOKE ALL ON public.system_envelopes FROM PUBLIC;

DO $retire_security_flags$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.system_envelopes FROM agent_runtime;
    GRANT SELECT ON public.system_envelopes TO agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.system_envelopes FROM aimos_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_flag_signer') THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.system_envelopes FROM aimos_flag_signer;
    GRANT SELECT ON public.system_envelopes TO aimos_flag_signer;
  END IF;
END
$retire_security_flags$;

COMMENT ON TABLE public.system_envelopes IS
  'RETIRED retained historical flags. Never admission or authorization authority; revocation and replay rejection have no bypass.';
