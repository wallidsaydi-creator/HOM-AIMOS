-- The installer lock and database extension must name the same exact release.
-- CREATE EXTENSION IF NOT EXISTS cannot silently preserve an older extversion.

DO $pgsodium_version_postcondition$
DECLARE
  v_installed text;
  v_available text;
BEGIN
  SELECT installed_version, default_version
    INTO v_installed, v_available
    FROM pg_available_extensions
   WHERE name = 'pgsodium';

  IF v_available IS DISTINCT FROM '3.1.11' THEN
    RAISE EXCEPTION 'pgsodium available version mismatch: expected 3.1.11, observed %', v_available;
  END IF;
  IF v_installed IS DISTINCT FROM '3.1.11' THEN
    RAISE EXCEPTION 'pgsodium installed version mismatch: expected 3.1.11, observed %', v_installed;
  END IF;
END
$pgsodium_version_postcondition$;
