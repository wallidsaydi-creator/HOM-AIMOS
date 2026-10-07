-- The historical aimos_app role was created with a fixed password in
-- migration 002. No serving or maintenance code connects as this role.
-- Retain the role and its historical grants for audit continuity, but remove
-- its ability to authenticate. Migration 002 remains immutable.

-- A logical pg_dump does not include global roles. A restored installation may
-- have no aimos_app role even when schema_migrations records migration 002.
-- Absence is already the desired authentication state; preserve that state
-- without creating a new legacy principal solely to retire it.
DO $retire_legacy_aimos_app$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aimos_app') THEN
    ALTER ROLE aimos_app NOLOGIN PASSWORD NULL;
  END IF;
  IF EXISTS (
    -- pg_roles masks role passwords; the offline migration administrator can
    -- inspect pg_authid for the actual null verifier postcondition.
    SELECT 1 FROM pg_authid
     WHERE rolname = 'aimos_app' AND (rolcanlogin OR rolpassword IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'legacy_aimos_app_authentication_retained';
  END IF;
END
$retire_legacy_aimos_app$;
