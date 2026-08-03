-- AIMOS uses one pgsodium primitive internally from SECURITY DEFINER cognitive
-- functions. Runtime roles must not gain the extension's broader KMS/keymaker
-- surface. The extension and all retained objects remain installed.

BEGIN;

REVOKE ALL ON SCHEMA pgsodium FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pgsodium FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM PUBLIC;

DO $lock_pgsodium_runtime_surface$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_runtime') THEN
    REVOKE ALL ON SCHEMA pgsodium FROM agent_runtime;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pgsodium FROM agent_runtime;
    REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM agent_runtime;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM agent_runtime;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    REVOKE ALL ON SCHEMA pgsodium FROM aimos_app;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pgsodium FROM aimos_app;
    REVOKE ALL ON ALL TABLES IN SCHEMA pgsodium FROM aimos_app;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA pgsodium FROM aimos_app;
  END IF;
END
$lock_pgsodium_runtime_surface$;

COMMENT ON SCHEMA pgsodium IS
  'Installed locked dependency. Direct runtime access revoked; AIMOS invokes detached-signature verification only inside certified SECURITY DEFINER cognitive functions.';

COMMIT;
